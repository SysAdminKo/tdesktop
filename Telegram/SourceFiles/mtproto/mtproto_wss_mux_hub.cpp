#include "mtproto/mtproto_wss_mux_hub.h"

#include "mtproto/mtproto_wss_mux_stream_socket.h"
#include "mtproto/mtproto_wss_mux_tunnel.h"
#include "mtproto/mtproto_proxy_data.h"
#include "mtproto/mtproto_wss_connect_gate.h"
#include "mtproto/details/mtproto_wss_mux_framing.h"

#include "base/invoke_queued.h"
#include "base/qthelp_url.h"
#include "base/debug_log.h"
#include "crl/crl.h"

#include <QtCore/QEventLoop>
#include <QtNetwork/QHostInfo>
#include <QtCore/QMetaObject>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QPointer>
#include <QtCore/QRegularExpression>
#include <QtCore/QThread>
#include <QtCore/QTimer>
#include <QtNetwork/QAbstractSocket>

#include <deque>
#include <map>
#include <vector>

#include <range/v3/algorithm/shuffle.hpp>
#include <range/v3/algorithm/sort.hpp>

namespace MTP {
namespace {

Fn<void()> AuthRejectedHandler;

constexpr auto kDefaultTunnelCount = 6;
constexpr auto kDownloadTunnelSlots = 8;
constexpr auto kReconnectDelay = crl::time(2000);
constexpr auto kOpenRetryDelay = crl::time(250);
constexpr auto kIpUpdateDebounce = crl::time(3000);
constexpr auto kDeferResolveFallback = 10 * crl::time(1000);

[[nodiscard]] bool HostNeedsResolve(const QString &host) {
	static const auto RegExp = QRegularExpression(
		QStringLiteral("^\\d+\\.\\d+\\.\\d+\\.\\d+$"));
	return !qthelp::is_ipv6(host) && !RegExp.match(host).hasMatch();
}

[[nodiscard]] bool SameIpSet(
		const std::vector<QString> &a,
		const std::vector<QString> &b) {
	if (a.size() != b.size()) {
		return false;
	}
	auto sortedA = a;
	auto sortedB = b;
	ranges::sort(sortedA);
	ranges::sort(sortedB);
	return sortedA == sortedB;
}

[[nodiscard]] bool IpSetContains(
		const std::vector<QString> &set,
		const QString &ip) {
	return ranges::find(set, ip) != end(set);
}

[[nodiscard]] std::vector<QString> DedupeIps(std::vector<QString> ips) {
	ranges::sort(ips);
	ips.erase(ranges::unique(ips), end(ips));
	return ips;
}

struct PendingOpen {
	uint32 streamId = 0;
	QString host;
	int port = 0;
};

struct HubConfig {
	QString host;
	uint32 port = 0;
	QString path;
	QString sniHost;
	int tunnelCount = kDefaultTunnelCount;
	std::vector<QString> resolvedIPs;
	QString password;

	friend bool operator==(const HubConfig &a, const HubConfig &b) {
		return (a.host == b.host)
			&& (a.sniHost == b.sniHost)
			&& (a.port == b.port)
			&& (a.path == b.path)
			&& (a.tunnelCount == b.tunnelCount)
			&& (a.password == b.password);
	}
	friend bool operator!=(const HubConfig &a, const HubConfig &b) {
		return !(a == b);
	}
};

[[nodiscard]] HubConfig ConfigFromProxy(
		const ProxyData &proxy,
		int tunnelCount) {
	return {
		proxy.host,
		proxy.port,
		proxy.path,
		proxy.sniHost,
		std::max(1, tunnelCount),
		proxy.resolvedIPs,
		proxy.password,
	};
}

[[nodiscard]] ProxyData ProxyFromConfig(const HubConfig &config) {
	auto proxy = ProxyData();
	proxy.type = ProxyData::Type::WebSocket;
	proxy.host = config.host;
	proxy.port = config.port;
	proxy.path = config.path;
	proxy.sniHost = config.sniHost;
	proxy.resolvedIPs = config.resolvedIPs;
	proxy.password = config.password;
	return proxy;
}

[[nodiscard]] ProxyData ProxyForTunnel(
		const HubConfig &config,
		const std::vector<QString> &ips,
		int tunnelIndex) {
	auto proxy = ProxyFromConfig(config);
	if (ips.empty()) {
		return proxy;
	}
	proxy.resolvedIPs = ips;
	return ToDirectIpProxy(proxy, tunnelIndex % int(ips.size()));
}

[[nodiscard]] QString CheckSessionKey(const HubConfig &config) {
	const auto endpoint = config.sniHost.isEmpty()
		? config.host
		: config.sniHost;
	return endpoint
		+ u':' + QString::number(config.port)
		+ u':' + config.path
		+ u':' + config.password;
}

struct ProxyCheckSession {
	HubConfig config;
	std::unique_ptr<details::WssMuxTunnel> tunnel;
	std::map<uint32, details::MuxStreamSocket*> streams;
	std::deque<PendingOpen> pendingOpens;
};

} // namespace

struct WssMuxHub::Private : public QObject {
	QThread hubThread;
	HubConfig config;
	bool started = false;
	bool shuttingDown = false;
	bool proxyActive = false;
	bool authRejected = false;
	uint32 nextStreamId = 1;
	QMutex streamsMutex;
	QMutex countsCacheMutex;
	std::map<uint32, details::MuxStreamSocket*> streams;
	std::map<uint32, int> streamTunnel;
	std::vector<int> cachedTunnelStreamCounts;
	std::vector<std::unique_ptr<details::WssMuxTunnel>> tunnels;
	std::vector<QString> pendingResolvedIPs;
	bool ipUpdateScheduled = false;
	bool deferTunnelStartUntilResolve = false;
	bool tunnelStartFallbackScheduled = false;
	int fallbackGeneration = 0;
	bool systemResolveInFlight = false;
	int nextPickTunnel = 0;
	std::vector<QString> ipPickOrder;
	std::deque<PendingOpen> pendingOpens;

	std::map<QString, ProxyCheckSession> checkSessions;
	std::map<uint32, QString> checkStreamKeys;

	QMutex checkSetupMutex;
	base::flat_set<uint64> pendingCheckSetups;
	uint64 nextCheckSetupId = 0;

	[[nodiscard]] uint64 addCheckStreamSetup() {
		QMutexLocker lock(&checkSetupMutex);
		const auto id = ++nextCheckSetupId;
		pendingCheckSetups.insert(id);
		return id;
	}

	void cancelCheckStreamSetup(uint64 setupId) {
		QMutexLocker lock(&checkSetupMutex);
		pendingCheckSetups.remove(setupId);
	}

	[[nodiscard]] bool consumeCheckStreamSetup(uint64 setupId) {
		QMutexLocker lock(&checkSetupMutex);
		return pendingCheckSetups.remove(setupId);
	}

	[[nodiscard]] ProxyCheckSession *checkSessionByStream(uint32 streamId) {
		const auto i = checkStreamKeys.find(streamId);
		if (i == end(checkStreamKeys)) {
			return nullptr;
		}
		const auto j = checkSessions.find(i->second);
		return (j != end(checkSessions)) ? &j->second : nullptr;
	}

	[[nodiscard]] details::MuxStreamSocket *checkStreamSocket(uint32 streamId) const {
		const auto i = checkStreamKeys.find(streamId);
		if (i == end(checkStreamKeys)) {
			return nullptr;
		}
		const auto j = checkSessions.find(i->second);
		if (j == end(checkSessions)) {
			return nullptr;
		}
		const auto k = j->second.streams.find(streamId);
		return (k != end(j->second.streams)) ? k->second : nullptr;
	}

	void stopCheckSession(const QString &key) {
		const auto i = checkSessions.find(key);
		if (i == end(checkSessions)) {
			return;
		}
		auto &session = i->second;
		for (const auto &[streamId, socket] : session.streams) {
			checkStreamKeys.erase(streamId);
		}
		session.streams.clear();
		session.pendingOpens.clear();
		if (session.tunnel) {
			session.tunnel->prepareForDestroy();
		}
		session.tunnel.reset();
		checkSessions.erase(i);
	}

	void cleanupCheckSessionIfEmpty(const QString &key) {
		const auto i = checkSessions.find(key);
		if (i != end(checkSessions) && i->second.streams.empty()) {
			stopCheckSession(key);
		}
	}

	void postCheckStreamEvent(
			const QString &key,
			uint32 streamId,
			Fn<void(details::MuxStreamSocket*)> &&handler) {
		Q_UNUSED(key);
		const auto streamIdCopy = streamId;
		auto handlerCopy = std::move(handler);
		crl::on_main([=, handler = std::move(handlerCopy)]() mutable {
			details::MuxStreamSocket *socket = nullptr;
			{
				QMutexLocker lock(&streamsMutex);
				const auto i = streams.find(streamIdCopy);
				if (i != end(streams)) {
					socket = i->second;
				}
			}
			if (!socket || socket->streamId() != streamIdCopy) {
				return;
			}
			handler(socket);
		});
	}

	void handleCheckTunnelFrame(
			const QString &key,
			details::MuxFrame &&frame) {
		const auto streamId = frame.streamId;
		switch (frame.type) {
		case details::MuxFrameType::OpenOk:
			postCheckStreamEvent(key, streamId, [=](
					details::MuxStreamSocket *socket) {
				socket->handleOpenOk(0);
			});
			break;
		case details::MuxFrameType::OpenFail:
			postCheckStreamEvent(key, streamId, [](
					details::MuxStreamSocket *socket) {
				socket->handleOpenFail();
			});
			break;
		case details::MuxFrameType::Data: {
			auto data = bytes::vector(
				frame.payload.begin(),
				frame.payload.end());
			postCheckStreamEvent(key, streamId, [=, data = std::move(data)](
					details::MuxStreamSocket *socket) mutable {
				socket->handleData(std::move(data));
			});
		} break;
		case details::MuxFrameType::Close:
			postCheckStreamEvent(key, streamId, [](
					details::MuxStreamSocket *socket) {
				socket->handleRemoteClose();
			});
			break;
		case details::MuxFrameType::Ping:
			if (const auto i = checkSessions.find(key); i != end(checkSessions)) {
				if (const auto &tunnel = i->second.tunnel) {
					const auto pong = details::EncodeMuxFrame(
						details::MuxFrameType::Pong,
						streamId);
					tunnel->sendFrame(pong);
				}
			}
			break;
		}
	}

	void ensureCheckTunnel(const QString &key) {
		auto &session = checkSessions[key];
		if (session.tunnel && session.tunnel->isConnected()) {
			return;
		} else if (session.tunnel) {
			session.tunnel->prepareForDestroy();
			session.tunnel.reset();
		}
		auto ips = session.config.resolvedIPs;
		const auto tunnelProxy = ProxyForTunnel(session.config, ips, 0);
		auto tunnel = std::make_unique<details::WssMuxTunnel>(
			&hubThread,
			tunnelProxy,
			0);
		const auto raw = tunnel.get();
		raw->setFrameHandler([=, key = key](details::MuxFrame &&frame) {
			handleCheckTunnelFrame(key, std::move(frame));
		});
		raw->setStateHandler([=, key = key](bool connected) {
			if (!connected) {
				return;
			}
			flushCheckPendingOpens(key);
		});
		session.tunnel = std::move(tunnel);
		raw->connectTunnel();
	}

	void flushCheckPendingOpens(const QString &key) {
		const auto i = checkSessions.find(key);
		if (i == end(checkSessions)) {
			return;
		}
		auto pending = base::take(i->second.pendingOpens);
		for (const auto &open : pending) {
			checkRequestOpen(key, open.streamId, open.host, open.port);
		}
	}

	void beginProxyCheck(const ProxyData &proxy) {
		ensureHubThreadRunning();
		const auto config = ConfigFromProxy(proxy, 1);
		const auto key = CheckSessionKey(config);
		const auto i = checkSessions.find(key);
		if (i != end(checkSessions)) {
			if (i->second.config != config && i->second.tunnel) {
				stopCheckSession(key);
			} else if (i->second.tunnel && i->second.tunnel->isConnected()) {
				return;
			}
		}
		auto &session = checkSessions[key];
		session.config = config;
		ensureCheckTunnel(key);
	}

	uint32 acquireCheckStreamId(const ProxyData &proxy) {
		beginProxyCheck(proxy);
		QMutexLocker lock(&streamsMutex);
		return nextStreamId++;
	}

	void registerCheckStream(
			const ProxyData &proxy,
			uint32 streamId,
			not_null<details::MuxStreamSocket*> socket) {
		const auto key = CheckSessionKey(ConfigFromProxy(proxy, 1));
		auto &session = checkSessions[key];
		session.streams[streamId] = socket.get();
		checkStreamKeys[streamId] = key;
	}

	void unregisterCheckStream(uint32 streamId) {
		const auto i = checkStreamKeys.find(streamId);
		if (i == end(checkStreamKeys)) {
			return;
		}
		const auto key = i->second;
		checkStreamKeys.erase(i);
		if (const auto j = checkSessions.find(key); j != end(checkSessions)) {
			j->second.streams.erase(streamId);
			cleanupCheckSessionIfEmpty(key);
		}
	}

	void checkRequestOpen(
			const QString &key,
			uint32 streamId,
			const QString &host,
			int port) {
		const auto i = checkSessions.find(key);
		if (i == end(checkSessions)) {
			postCheckStreamEvent(key, streamId, [](
					details::MuxStreamSocket *socket) {
				socket->handleOpenFail();
			});
			return;
		}
		auto &session = i->second;
		if (!session.streams.contains(streamId)) {
			return;
		} else if (!session.tunnel || !session.tunnel->isConnected()) {
			session.pendingOpens.push_back({ streamId, host, port });
			const auto weak = QPointer<Private>(this);
			QTimer::singleShot(kOpenRetryDelay, this, [=] {
				if (!weak) {
					return;
				}
				weak->checkRequestOpen(key, streamId, host, port);
			});
			return;
		}
		const auto frame = details::EncodeMuxOpen(streamId, host, uint16(port));
		session.tunnel->sendFrame(frame);
	}

	void checkSendData(
			const QString &key,
			uint32 streamId,
			bytes::const_span data) {
		const auto i = checkSessions.find(key);
		if (i == end(checkSessions)
			|| !i->second.tunnel
			|| !i->second.streams.contains(streamId)) {
			return;
		}
		const auto frame = details::EncodeMuxFrame(
			details::MuxFrameType::Data,
			streamId,
			data);
		i->second.tunnel->sendFrame(frame);
	}

	void checkRequestCloseStream(const QString &key, uint32 streamId) {
		const auto i = checkSessions.find(key);
		if (i == end(checkSessions) || !i->second.tunnel) {
			return;
		}
		const auto frame = details::EncodeMuxFrame(
			details::MuxFrameType::Close,
			streamId);
		i->second.tunnel->sendFrame(frame);
	}

	void stopAllCheckSessions() {
		auto keys = std::vector<QString>();
		keys.reserve(checkSessions.size());
		for (const auto &[key, _] : checkSessions) {
			keys.push_back(key);
		}
		for (const auto &key : keys) {
			stopCheckSession(key);
		}
	}

	[[nodiscard]] bool shouldDeferTunnelStart() const {
		return HostNeedsResolve(config.host)
			&& (config.resolvedIPs.size() <= 1);
	}

	void tryStartAfterResolve() {
		if (!started
			&& deferTunnelStartUntilResolve
			&& config.resolvedIPs.size() > 1) {
			startTunnelsAfterResolve();
		}
	}

	void updateIpPickOrder(const std::vector<QString> &ips) {
		const auto normalized = DedupeIps(ips);
		if (normalized.size() <= 1) {
			ipPickOrder = normalized;
			return;
		} else if (SameIpSet(ipPickOrder, normalized)) {
			return;
		}
		ipPickOrder = normalized;
		ranges::shuffle(ipPickOrder);
	}

	void mergeResolvedIps(const std::vector<QString> &ips) {
		if (ips.empty()) {
			return;
		}
		const auto normalized = DedupeIps(ips);
		const auto applied = config.resolvedIPs.empty()
			|| normalized.size() > config.resolvedIPs.size()
			|| !SameIpSet(config.resolvedIPs, normalized);
		if (applied) {
			config.resolvedIPs = normalized;
		}
	}

	void startSystemResolve() {
		if (systemResolveInFlight
			|| !HostNeedsResolve(config.host)
			|| config.resolvedIPs.size() > 1) {
			return;
		}
		systemResolveInFlight = true;
		const auto host = config.host;
		const auto weak = QPointer<Private>(this);
		QHostInfo::lookupHost(host, this, [=](const QHostInfo &info) {
			if (!weak) {
				return;
			}
			weak->systemResolveInFlight = false;
			if (info.error() != QHostInfo::NoError) {
				return;
			}
			auto ips = std::vector<QString>();
			for (const auto &address : info.addresses()) {
				if (address.protocol() == QAbstractSocket::IPv4Protocol) {
					ips.push_back(address.toString());
				}
			}
			ranges::sort(ips);
			ips.erase(ranges::unique(ips), end(ips));
			if (ips.size() <= weak->config.resolvedIPs.size()) {
				return;
			}
			weak->applyResolvedIpsUpdate(std::move(ips));
		});
	}

	void removePendingOpen(uint32 streamId) {
		const auto i = ranges::find(
			pendingOpens,
			streamId,
			&PendingOpen::streamId);
		if (i != end(pendingOpens)) {
			pendingOpens.erase(i);
		}
	}

	void queuePendingOpen(uint32 streamId, const QString &host, int port) {
		removePendingOpen(streamId);
		pendingOpens.push_back({ streamId, host, port });
	}

	void flushPendingOpens() {
		if (connectedTunnelCount() == 0 || pendingOpens.empty()) {
			return;
		}
		auto pending = std::move(pendingOpens);
		pendingOpens.clear();
		for (const auto &open : pending) {
			{
				QMutexLocker lock(&streamsMutex);
				if (!streams.contains(open.streamId)) {
					continue;
				}
			}
			requestOpen(open.streamId, open.host, open.port);
		}
	}

	void scheduleTunnelStartFallback() {
		if (tunnelStartFallbackScheduled) {
			return;
		}
		tunnelStartFallbackScheduled = true;
		const auto generation = ++fallbackGeneration;
		const auto weak = QPointer<Private>(this);
		QTimer::singleShot(kDeferResolveFallback, this, [=] {
			if (!weak || weak->shuttingDown || !weak->proxyActive) {
				return;
			} else if (generation != weak->fallbackGeneration) {
				return;
			}
			weak->tunnelStartFallbackScheduled = false;
			if (!weak->started && weak->deferTunnelStartUntilResolve) {
				weak->deferTunnelStartUntilResolve = false;
				weak->startTunnels(true);
			}
		});
	}

	void startTunnelsAfterResolve() {
		deferTunnelStartUntilResolve = false;
		tunnelStartFallbackScheduled = false;
		startTunnels(false);
	}

	void resetTunnels() {
		++fallbackGeneration;
		for (auto i = 0; i != int(tunnels.size()); ++i) {
			failStreamsOnTunnel(i);
		}
		for (auto &tunnel : tunnels) {
			if (tunnel) {
				tunnel->prepareForDestroy();
			}
		}
		tunnels.clear();
		ipPickOrder.clear();
		started = false;
		deferTunnelStartUntilResolve = false;
		tunnelStartFallbackScheduled = false;
		systemResolveInFlight = false;
		pendingOpens.clear();
		refreshCachedTunnelStreamCounts();
	}

	void markAuthRejected() {
		if (authRejected) {
			return;
		}
		authRejected = true;
		started = false;
		crl::on_main([] {
			if (AuthRejectedHandler) {
				AuthRejectedHandler();
			}
		});
		const auto weak = QPointer<Private>(this);
		InvokeQueued(this, [=] {
			if (!weak) {
				return;
			}
			for (auto i = 0; i != int(weak->tunnels.size()); ++i) {
				weak->failStreamsOnTunnel(i);
			}
			for (auto &tunnel : weak->tunnels) {
				if (tunnel) {
					tunnel->prepareForDestroy();
				}
			}
			weak->tunnels.clear();
			weak->refreshCachedTunnelStreamCounts();
		});
	}

	[[nodiscard]] bool tunnelAuthRejected(int index) const {
		return index >= 0
			&& index < int(tunnels.size())
			&& tunnels[index]
			&& tunnels[index]->authRejected();
	}

	[[nodiscard]] std::unique_ptr<details::WssMuxTunnel> makeTunnel(
			int index,
			const ProxyData &proxy) {
		auto tunnel = std::make_unique<details::WssMuxTunnel>(
			&hubThread,
			proxy,
			index);
		const auto raw = tunnel.get();
		raw->setFrameHandler([=](details::MuxFrame &&frame) {
			handleTunnelFrame(index, std::move(frame));
		});
		raw->setStateHandler([=](bool connected) {
			if (connected) {
				flushPendingOpens();
				return;
			}
			failStreamsOnTunnel(index);
			if (authRejected) {
				return;
			} else if (tunnelAuthRejected(index)) {
				markAuthRejected();
				return;
			}
			scheduleReconnect(index);
		});
		return tunnel;
	}

	void replaceTunnel(int index, const ProxyData &proxy) {
		if (!proxyActive
			|| authRejected
			|| index < 0
			|| index >= config.tunnelCount) {
			return;
		}
		failStreamsOnTunnel(index);
		if (index < int(tunnels.size()) && tunnels[index]) {
			tunnels[index]->prepareForDestroy();
		} else if (index >= int(tunnels.size())) {
			tunnels.resize(index + 1);
		}
		auto tunnel = makeTunnel(index, proxy);
		const auto raw = tunnel.get();
		tunnels[index] = std::move(tunnel);
		raw->connectTunnel();
	}

	void syncTunnelsToResolvedIps() {
		if (shuttingDown || !proxyActive || !started || authRejected) {
			return;
		}
		auto ips = config.resolvedIPs;
		if (ips.empty()) {
			return;
		}
		updateIpPickOrder(ips);
		ips = ipPickOrder;
		const auto count = config.tunnelCount;
		if (int(tunnels.size()) != count) {
			resetTunnels();
			if (shouldDeferTunnelStart()) {
				deferTunnelStartUntilResolve = true;
				scheduleTunnelStartFallback();
				startSystemResolve();
				return;
			}
			startTunnels(false);
			return;
		}
		for (auto i = 0; i != count; ++i) {
			const auto &tunnel = tunnels[i];
			const auto host = tunnel ? tunnel->connectHost() : QString();
			const auto expected = ProxyForTunnel(config, ips, i).host;
			const auto skip = tunnel
				&& tunnel->isConnected()
				&& (host == expected);
			if (skip) {
				continue;
			}
			replaceTunnel(i, ProxyForTunnel(config, ips, i));
		}
	}

	void applyResolvedIpsUpdate(std::vector<QString> ips) {
		if (shuttingDown) {
			return;
		}
		ips = DedupeIps(std::move(ips));
		if (SameIpSet(config.resolvedIPs, ips)) {
			config.resolvedIPs = std::move(ips);
			tryStartAfterResolve();
			return;
		}
		config.resolvedIPs = std::move(ips);
		if (!started && deferTunnelStartUntilResolve) {
			tryStartAfterResolve();
			return;
		}
		syncTunnelsToResolvedIps();
	}

	void scheduleResolvedIpsUpdate(std::vector<QString> ips) {
		pendingResolvedIPs = std::move(ips);
		if (ipUpdateScheduled) {
			return;
		}
		ipUpdateScheduled = true;
		const auto weak = QPointer<Private>(this);
		QTimer::singleShot(kIpUpdateDebounce, this, [=] {
			if (!weak) {
				return;
			}
			weak->ipUpdateScheduled = false;
			weak->applyResolvedIpsUpdate(std::move(weak->pendingResolvedIPs));
		});
	}

	[[nodiscard]] bool matchesEndpoint(const QString &host) const {
		return (host == config.host)
			|| (!config.sniHost.isEmpty() && host == config.sniHost);
	}

	[[nodiscard]] int connectedTunnelCount() const {
		auto result = 0;
		for (const auto &tunnel : tunnels) {
			if (tunnel && tunnel->isConnected()) {
				++result;
			}
		}
		return result;
	}

	void refreshCachedTunnelStreamCounts() {
		auto counts = std::vector<int>();
		{
			QMutexLocker lock(&streamsMutex);
			counts = std::vector<int>(tunnels.size(), 0);
			for (const auto &[streamId, tunnel] : streamTunnel) {
				if (tunnel >= 0
					&& tunnel < int(counts.size())
					&& isLiveStream(streamId)) {
					++counts[tunnel];
				}
			}
		}
		QMutexLocker cacheLock(&countsCacheMutex);
		cachedTunnelStreamCounts = std::move(counts);
	}

	[[nodiscard]] bool isLiveStream(uint32 streamId) const {
		return streams.contains(streamId);
	}

	void eraseStreamTunnelEntry(uint32 streamId) {
		auto removed = false;
		{
			QMutexLocker lock(&streamsMutex);
			const auto i = streamTunnel.find(streamId);
			if (i == end(streamTunnel)) {
				return;
			}
			streamTunnel.erase(i);
			removed = true;
		}
		if (removed) {
			refreshCachedTunnelStreamCounts();
		}
	}

	[[nodiscard]] int tunnelStreamCount(int tunnelIndex) const {
		auto count = 0;
		for (const auto &[streamId, tunnel] : streamTunnel) {
			if (tunnel == tunnelIndex && isLiveStream(streamId)) {
				++count;
			}
		}
		return count;
	}

	[[nodiscard]] bool tunnelCarriesDownloadStreams(int tunnelIndex) const {
		for (const auto &[streamId, tunnel] : streamTunnel) {
			if (tunnel != tunnelIndex || !isLiveStream(streamId)) {
				continue;
			}
			const auto i = streams.find(streamId);
			if (i != end(streams)
				&& i->second
				&& i->second->tunnelAffinity() >= 0) {
				return true;
			}
		}
		return false;
	}

	[[nodiscard]] int pickLeastLoadedTunnelIndex(
			int startIndex,
			bool skipDownloadOccupied) {
		auto bestCount = int(streamTunnel.size()) + 1;
		auto tied = std::vector<int>();
		for (auto i = startIndex; i != int(tunnels.size()); ++i) {
			if (!tunnels[i] || !tunnels[i]->isConnected()) {
				continue;
			} else if (skipDownloadOccupied && tunnelCarriesDownloadStreams(i)) {
				continue;
			}
			const auto count = tunnelStreamCount(i);
			if (count < bestCount) {
				bestCount = count;
				tied.clear();
				tied.push_back(i);
			} else if (count == bestCount) {
				tied.push_back(i);
			}
		}
		if (tied.empty()) {
			return -1;
		}
		const auto offset = (nextPickTunnel++) % int(tied.size());
		return tied[offset];
	}

	[[nodiscard]] int pickTunnelIndex(int affinity = -1) {
		if (affinity >= 0) {
			if (tunnels.empty()) {
				return -1;
			}
			const auto hint = affinity % int(tunnels.size());
			if (hint >= 0
				&& hint < int(tunnels.size())
				&& tunnels[hint]
				&& tunnels[hint]->isConnected()) {
				return hint;
			}
			return -1;
		}
		const auto reservedEnd = (int(tunnels.size()) > kDownloadTunnelSlots)
			? std::min(kDownloadTunnelSlots, int(tunnels.size()))
			: 0;
		if (reservedEnd > 0) {
			const auto index = pickLeastLoadedTunnelIndex(reservedEnd, false);
			if (index >= 0) {
				return index;
			}
		}
		const auto preferred = pickLeastLoadedTunnelIndex(0, true);
		if (preferred >= 0) {
			return preferred;
		}
		return pickLeastLoadedTunnelIndex(0, false);
	}

	[[nodiscard]] details::WssMuxTunnel *pickTunnel(int affinity = -1) {
		const auto index = pickTunnelIndex(affinity);
		if (index < 0 || index >= int(tunnels.size())) {
			return nullptr;
		}
		return tunnels[index].get();
	}

	void scheduleReconnect(int index) {
		if (shuttingDown
			|| !proxyActive
			|| authRejected
			|| index < 0
			|| index >= int(tunnels.size())) {
			return;
		}
		const auto weak = QPointer<Private>(this);
		QTimer::singleShot(kReconnectDelay, this, [=] {
			if (!weak || weak->shuttingDown) {
				return;
			}
			weak->tryReconnectTunnel(index);
		});
	}

	void tryReconnectTunnel(int index) {
		if (shuttingDown
			|| !proxyActive
			|| authRejected
			|| index < 0
			|| index >= int(tunnels.size())
			|| !tunnels[index]
			|| tunnels[index]->isConnected()) {
			return;
		}
		tunnels[index]->connectTunnel();
	}

	void requestCloseStream(uint32 streamId) {
		if (shuttingDown) {
			return;
		}
		int tunnelIndex = -1;
		{
			QMutexLocker lock(&streamsMutex);
			const auto i = streamTunnel.find(streamId);
			if (i != end(streamTunnel)) {
				tunnelIndex = i->second;
				streamTunnel.erase(i);
			}
		}
		if (tunnelIndex >= 0) {
			refreshCachedTunnelStreamCounts();
		}
		if (tunnelIndex < 0
			|| tunnelIndex >= int(tunnels.size())
			|| !tunnels[tunnelIndex]) {
			return;
		}
		const auto frame = details::EncodeMuxFrame(
			details::MuxFrameType::Close,
			streamId);
		tunnels[tunnelIndex]->sendFrame(frame);
	}

	void failStreamsOnTunnel(int tunnelIndex) {
		std::vector<uint32> affected;
		{
			QMutexLocker lock(&streamsMutex);
			for (const auto &[streamId, tunnel] : streamTunnel) {
				if (tunnel == tunnelIndex) {
					affected.push_back(streamId);
				}
			}
		}
		for (const auto streamId : affected) {
			requestCloseStream(streamId);
			postStreamEvent(streamId, [](details::MuxStreamSocket *socket) {
				socket->handleTunnelDown();
			});
		}
	}

	void postStreamEvent(
			uint32 streamId,
			Fn<void(details::MuxStreamSocket*)> &&handler) {
		details::MuxStreamSocket *socket = nullptr;
		{
			QMutexLocker lock(&streamsMutex);
			const auto i = streams.find(streamId);
			if (i == end(streams)) {
				return;
			}
			socket = i->second;
		}
		const auto weak = QPointer<Private>(this);
		socket->invokeQueued([=, handler = std::move(handler)] {
			if (!weak) {
				return;
			}
			details::MuxStreamSocket *current = nullptr;
			{
				QMutexLocker lock(&weak->streamsMutex);
				const auto i = weak->streams.find(streamId);
				if (i == end(weak->streams)) {
					return;
				}
				current = i->second;
			}
			if (current->streamId() != streamId) {
				return;
			}
			handler(current);
		});
	}

	void handleTunnelFrame(int tunnelIndex, details::MuxFrame &&frame) {
		const auto streamId = frame.streamId;
		switch (frame.type) {
		case details::MuxFrameType::OpenOk:
			postStreamEvent(streamId, [=](details::MuxStreamSocket *socket) {
				socket->handleOpenOk(tunnelIndex);
			});
			break;
		case details::MuxFrameType::OpenFail:
			{
				QMutexLocker lock(&streamsMutex);
				streamTunnel.erase(streamId);
			}
			refreshCachedTunnelStreamCounts();
			postStreamEvent(streamId, [](details::MuxStreamSocket *socket) {
				socket->handleOpenFail();
			});
			break;
		case details::MuxFrameType::Data: {
			auto data = bytes::vector(
				frame.payload.begin(),
				frame.payload.end());
			postStreamEvent(streamId, [=, data = std::move(data)](
					details::MuxStreamSocket *socket) mutable {
				socket->handleData(std::move(data));
			});
		} break;
		case details::MuxFrameType::Close:
			{
				QMutexLocker lock(&streamsMutex);
				streamTunnel.erase(streamId);
			}
			refreshCachedTunnelStreamCounts();
			postStreamEvent(streamId, [](details::MuxStreamSocket *socket) {
				socket->handleRemoteClose();
			});
			break;
		case details::MuxFrameType::Ping:
			if (tunnelIndex >= 0
				&& tunnelIndex < int(tunnels.size())
				&& tunnels[tunnelIndex]) {
				const auto pong = details::EncodeMuxFrame(
					details::MuxFrameType::Pong,
					streamId);
				tunnels[tunnelIndex]->sendFrame(pong);
			}
			break;
		case details::MuxFrameType::Pong:
		case details::MuxFrameType::Open:
			break;
		}
	}

	void ensureHubThreadRunning() {
		if (hubThread.isRunning()) {
			return;
		}
		shuttingDown = false;
		started = false;
		hubThread.start();
	}

	void startTunnels(bool allowHostnameFallback = false) {
		if (started || shuttingDown || !proxyActive || authRejected) {
			return;
		}
		const auto needsMoreIps = HostNeedsResolve(config.host)
			&& (config.resolvedIPs.size() <= 1);
		if (needsMoreIps && !allowHostnameFallback) {
			deferTunnelStartUntilResolve = true;
			scheduleTunnelStartFallback();
			startSystemResolve();
			return;
		}
		deferTunnelStartUntilResolve = false;
		tunnelStartFallbackScheduled = false;
		started = true;
		updateIpPickOrder(config.resolvedIPs);
		const auto ips = ipPickOrder;
		const auto count = config.tunnelCount;
		tunnels.reserve(count);
		for (auto i = 0; i != count; ++i) {
			const auto tunnelProxy = ProxyForTunnel(config, ips, i);
			auto tunnel = makeTunnel(i, tunnelProxy);
			const auto raw = tunnel.get();
			tunnels.push_back(std::move(tunnel));
			raw->connectTunnel();
		}
		refreshCachedTunnelStreamCounts();
	}

	void requestOpen(uint32 streamId, const QString &host, int port) {
		if (shuttingDown) {
			return;
		} else if (!proxyActive) {
			postStreamEvent(streamId, [](details::MuxStreamSocket *socket) {
				socket->handleOpenFail();
			});
			return;
		} else if (authRejected) {
			postStreamEvent(streamId, [](details::MuxStreamSocket *socket) {
				socket->handleOpenFail();
			});
			return;
		}
		auto affinity = -1;
		{
			QMutexLocker lock(&streamsMutex);
			const auto i = streams.find(streamId);
			if (i == end(streams)) {
				return;
			} else if (const auto socket = i->second) {
				affinity = socket->tunnelAffinity();
			}
		}
		const auto tunnel = pickTunnel(affinity);
		if (!tunnel) {
			{
				QMutexLocker lock(&streamsMutex);
				if (!streams.contains(streamId)) {
					return;
				}
			}
			if (!started || connectedTunnelCount() == 0) {
				queuePendingOpen(streamId, host, port);
				return;
			}
			const auto weak = QPointer<Private>(this);
			QTimer::singleShot(kOpenRetryDelay, this, [=] {
				if (!weak || weak->shuttingDown) {
					return;
				} else if (!weak->proxyActive) {
					weak->postStreamEvent(streamId, [](
							details::MuxStreamSocket *socket) {
						socket->handleOpenFail();
					});
					return;
				}
				{
					QMutexLocker lock(&weak->streamsMutex);
					if (!weak->streams.contains(streamId)) {
						return;
					}
				}
				weak->requestOpen(streamId, host, port);
			});
			return;
		}
		auto previousTunnel = -1;
		{
			QMutexLocker lock(&streamsMutex);
			if (!streams.contains(streamId)) {
				return;
			}
			const auto tunnelIndex = tunnel->index();
			const auto previous = streamTunnel.find(streamId);
			previousTunnel = (previous != end(streamTunnel))
				? previous->second
				: -1;
			streamTunnel[streamId] = tunnelIndex;
			if (affinity < 0) {
				DEBUG_LOG(("WSS mux main pick stream=%1 tunnel=%2 target %3:%4"
					).arg(streamId
					).arg(tunnelIndex
					).arg(host
					).arg(port));
			}
		}
		refreshCachedTunnelStreamCounts();
		if (previousTunnel >= 0
			&& previousTunnel != tunnel->index()
			&& previousTunnel < int(tunnels.size())
			&& tunnels[previousTunnel]) {
			const auto closeFrame = details::EncodeMuxFrame(
				details::MuxFrameType::Close,
				streamId);
			tunnels[previousTunnel]->sendFrame(closeFrame);
		}
		const auto frame = details::EncodeMuxOpen(
			streamId,
			host,
			uint16(port));
		tunnel->sendFrame(frame);
	}
};

WssMuxHub &WssMuxHub::Instance() {
	static WssMuxHub instance;
	return instance;
}

void WssMuxHub::SetAuthRejectedHandler(Fn<void()> handler) {
	AuthRejectedHandler = std::move(handler);
}

WssMuxHub::WssMuxHub()
: _private(std::make_unique<Private>()) {
	_private->hubThread.setObjectName("WssMuxHub");
	_private->moveToThread(&_private->hubThread);
	_private->hubThread.start();
}

WssMuxHub::~WssMuxHub() {
	Shutdown();
}

void WssMuxHub::Configure(const ProxyData &proxy, int tunnelCount) {
	WssConnectGate::SetLimit(std::clamp(tunnelCount, 1, 9));
	const auto config = ConfigFromProxy(proxy, tunnelCount);
	InvokeQueued(_private.get(), [=, config = config]() mutable {
		if (!_private->proxyActive) {
			return;
		}
		_private->ensureHubThreadRunning();
		const auto sameEndpoint = (_private->config == config);
		if (!sameEndpoint) {
			if (_private->proxyActive && !_private->config.host.isEmpty()) {
				return;
			}
			_private->authRejected = false;
			_private->resetTunnels();
			_private->config = config;
			_private->config.resolvedIPs.clear();
		} else {
			_private->mergeResolvedIps(config.resolvedIPs);
		}
		if (sameEndpoint) {
			if (!_private->started) {
				_private->tryStartAfterResolve();
			}
			return;
		}
		_private->startTunnels(false);
	});
}

void WssMuxHub::ApplyResolvedIps(
		const QString &host,
		const std::vector<QString> &ips) {
	if (ips.empty()) {
		return;
	}
	InvokeQueued(_private.get(), [=, ips = ips]() mutable {
		if (_private->shuttingDown
			|| !_private->proxyActive
			|| !_private->matchesEndpoint(host)) {
			return;
		}
		_private->ensureHubThreadRunning();
		if (SameIpSet(_private->config.resolvedIPs, ips)) {
			_private->config.resolvedIPs = DedupeIps(std::move(ips));
			_private->tryStartAfterResolve();
			if (_private->started && _private->config.resolvedIPs.size() > 1) {
				_private->syncTunnelsToResolvedIps();
			}
			return;
		}
		_private->scheduleResolvedIpsUpdate(std::move(ips));
	});
}

void WssMuxHub::Bootstrap(const ProxyData &proxy) {
	UpdateFromAppSettings(true, proxy);
}

void WssMuxHub::UpdateFromAppSettings(
		bool enabled,
		const ProxyData &selected,
		FnMut<void()> &&done) {
	const auto runBootstrap = enabled
		&& (selected.type == ProxyData::Type::WebSocket);
	if (runBootstrap) {
		WssConnectGate::SetLimit(std::clamp(selected.wssMuxTunnels, 1, 9));
	}
	const auto config = runBootstrap
		? ConfigFromProxy(selected, selected.wssMuxTunnels)
		: HubConfig();
	InvokeQueued(_private.get(), [=,
			config = config,
			done = std::move(done)]() mutable {
		if (runBootstrap) {
			_private->proxyActive = true;
			_private->ensureHubThreadRunning();
			if (_private->config != config) {
				_private->authRejected = false;
				_private->resetTunnels();
				_private->config = config;
				_private->config.resolvedIPs.clear();
				_private->startTunnels(false);
			} else {
				_private->mergeResolvedIps(config.resolvedIPs);
				if (!_private->started) {
					_private->startTunnels(false);
				}
			}
		} else {
			WssConnectGate::Clear();
			_private->proxyActive = false;
			_private->ipUpdateScheduled = false;
			_private->pendingResolvedIPs.clear();
			_private->resetTunnels();
		}
		if (done) {
			crl::on_main(std::move(done));
		}
	});
}

void WssMuxHub::EnsureStarted() {
	InvokeQueued(_private.get(), [=] {
		if (!_private->proxyActive) {
			return;
		}
		_private->ensureHubThreadRunning();
		if (_private->deferTunnelStartUntilResolve && !_private->started) {
			return;
		}
		_private->startTunnels(false);
	});
}

std::vector<int> WssMuxHub::TunnelStreamCounts() const {
	QMutexLocker lock(&_private->countsCacheMutex);
	return _private->cachedTunnelStreamCounts;
}

void WssMuxHub::SetProxyActive(bool active) {
	if (!_private->hubThread.isRunning()) {
		return;
	}
	const auto apply = [=] {
		_private->proxyActive = active;
	};
	if (QThread::currentThread() == &_private->hubThread) {
		apply();
	} else {
		InvokeQueued(_private.get(), apply);
	}
}

void WssMuxHub::StopTunnels() {
	UpdateFromAppSettings(false, ProxyData());
}

void WssMuxHub::Shutdown() {
	if (!_private->hubThread.isRunning()) {
		return;
	}
	const auto cleanup = [=] {
		_private->shuttingDown = true;
		_private->stopAllCheckSessions();
		_private->resetTunnels();
		_private->started = false;
	};
	if (QThread::currentThread() == &_private->hubThread) {
		cleanup();
	} else {
		QEventLoop loop;
		InvokeQueued(_private.get(), [&] {
			cleanup();
			loop.quit();
		});
		loop.exec();
	}
	_private->hubThread.quit();
	_private->hubThread.wait();
	_private->shuttingDown = false;
}

std::unique_ptr<details::AbstractSocket> WssMuxHub::AcquireStream(
		not_null<QThread*> thread,
		const QString &host,
		int port,
		bool protocolForFiles,
		int tunnelAffinity) {
	Q_UNUSED(host);
	Q_UNUSED(port);
	Q_UNUSED(protocolForFiles);
	const auto streamId = [&] {
		QMutexLocker lock(&_private->streamsMutex);
		return _private->nextStreamId++;
	}();
	auto socket = std::make_unique<details::MuxStreamSocket>(thread, this);
	socket->setStreamId(streamId);
	socket->setTunnelAffinity(tunnelAffinity);
	RegisterStream(streamId, socket.get());
	EnsureStarted();
	return socket;
}

void WssMuxHub::BeginProxyCheck(const ProxyData &proxy) {
	InvokeQueued(_private.get(), [=] {
		_private->beginProxyCheck(proxy);
	});
}

void WssMuxHub::EndProxyCheck(const ProxyData &proxy) {
	InvokeQueued(_private.get(), [=] {
		const auto key = CheckSessionKey(ConfigFromProxy(proxy, 1));
		_private->stopCheckSession(key);
	});
}

std::unique_ptr<details::AbstractSocket> WssMuxHub::AcquireCheckStream(
		not_null<QThread*> thread,
		const ProxyData &proxy,
		const QString &host,
		int port,
		bool protocolForFiles,
		int tunnelAffinity,
		Fn<void(not_null<details::AbstractSocket*>)> whenRegistered) {
	Q_UNUSED(host);
	Q_UNUSED(port);
	Q_UNUSED(protocolForFiles);
	auto socket = std::make_unique<details::MuxStreamSocket>(thread, this);
	const auto raw = socket.get();
	const auto setupId = _private->addCheckStreamSetup();
	raw->setCheckSetupId(setupId);
	socket->setTunnelAffinity(tunnelAffinity);
	InvokeQueued(_private.get(), [this,
			whenRegistered,
			raw,
			setupId,
			proxy]() mutable {
		if (!_private->consumeCheckStreamSetup(setupId)) {
			return;
		} else if (_private->shuttingDown) {
			return;
		}
		const auto streamId = _private->acquireCheckStreamId(proxy);
		_private->registerCheckStream(proxy, streamId, raw);
		raw->invokeQueued([this,
				whenRegistered,
				raw,
				streamId]() mutable {
			raw->setCheckSetupId(0);
			raw->setStreamId(streamId);
			RegisterStream(streamId, raw);
			whenRegistered(raw);
		});
	});
	return socket;
}

void WssMuxHub::CancelCheckStreamSetup(uint64 setupId) {
	if (!_private->hubThread.isRunning()) {
		return;
	}
	const auto cancel = [=] {
		_private->cancelCheckStreamSetup(setupId);
	};
	if (QThread::currentThread() == &_private->hubThread) {
		cancel();
	} else {
		InvokeQueued(_private.get(), cancel);
	}
}

void WssMuxHub::RegisterStream(
		uint32 streamId,
		not_null<details::MuxStreamSocket*> socket) {
	QMutexLocker lock(&_private->streamsMutex);
	_private->streams[streamId] = socket;
}

void WssMuxHub::UnregisterStream(uint32 streamId) {
	{
		QMutexLocker lock(&_private->streamsMutex);
		_private->streams.erase(streamId);
	}
	if (!_private->hubThread.isRunning()) {
		return;
	}
	const auto cleanup = [=] {
		if (_private->checkStreamKeys.contains(streamId)) {
			_private->unregisterCheckStream(streamId);
		} else {
			_private->requestCloseStream(streamId);
			_private->removePendingOpen(streamId);
		}
	};
	if (QThread::currentThread() == &_private->hubThread) {
		cleanup();
		return;
	}
	InvokeQueued(_private.get(), cleanup);
}

void WssMuxHub::RequestOpen(
		uint32 streamId,
		const QString &host,
		int port) {
	InvokeQueued(_private.get(), [=] {
		const auto i = _private->checkStreamKeys.find(streamId);
		if (i != end(_private->checkStreamKeys)) {
			_private->checkRequestOpen(i->second, streamId, host, port);
			return;
		}
		_private->requestOpen(streamId, host, port);
	});
}

void WssMuxHub::SendData(uint32 streamId, bytes::const_span data) {
	auto copy = bytes::vector(data.begin(), data.end());
	InvokeQueued(_private.get(), [=, data = std::move(copy)]() mutable {
		const auto i = _private->checkStreamKeys.find(streamId);
		if (i != end(_private->checkStreamKeys)) {
			_private->checkSendData(i->second, streamId, data);
			return;
		}
		if (_private->shuttingDown || !_private->proxyActive) {
			return;
		}
		int tunnelIndex = -1;
		{
			QMutexLocker lock(&_private->streamsMutex);
			const auto i = _private->streamTunnel.find(streamId);
			if (i == end(_private->streamTunnel)) {
				return;
			}
			tunnelIndex = i->second;
		}
		if (tunnelIndex < 0
			|| tunnelIndex >= int(_private->tunnels.size())
			|| !_private->tunnels[tunnelIndex]) {
			return;
		}
		const auto frame = details::EncodeMuxFrame(
			details::MuxFrameType::Data,
			streamId,
			data);
		_private->tunnels[tunnelIndex]->sendFrame(frame);
	});
}

void WssMuxHub::RequestClose(uint32 streamId) {
	if (!_private->hubThread.isRunning()) {
		return;
	}
	const auto close = [=] {
		const auto i = _private->checkStreamKeys.find(streamId);
		if (i != end(_private->checkStreamKeys)) {
			_private->checkRequestCloseStream(i->second, streamId);
			return;
		}
		_private->requestCloseStream(streamId);
	};
	if (QThread::currentThread() == &_private->hubThread) {
		close();
		return;
	}
	InvokeQueued(_private.get(), close);
}

} // namespace MTP
