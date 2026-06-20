#include "mtproto/mtproto_wss_mux_hub.h"

#include "mtproto/mtproto_wss_mux_stream_socket.h"
#include "mtproto/mtproto_wss_mux_tunnel.h"
#include "mtproto/mtproto_proxy_data.h"
#include "mtproto/details/mtproto_wss_mux_framing.h"

#include "base/invoke_queued.h"
#include "crl/crl.h"

#include <QtCore/QEventLoop>
#include <QtCore/QMetaObject>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QPointer>
#include <QtCore/QThread>
#include <QtCore/QTimer>

#include <map>
#include <vector>

#include <range/v3/algorithm/shuffle.hpp>
#include <range/v3/algorithm/sort.hpp>

namespace MTP {
namespace {

Fn<void()> AuthRejectedHandler;

constexpr auto kDefaultTunnelCount = 6;
constexpr auto kReconnectDelay = crl::time(2000);
constexpr auto kOpenRetryDelay = crl::time(250);
constexpr auto kIpUpdateDebounce = crl::time(3000);

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

struct HubConfig {
	QString host;
	uint32 port = 0;
	QString path;
	QString sniHost;
	int tunnelCount = kDefaultTunnelCount;
	std::vector<QString> resolvedIPs;
	QString password;

	friend bool operator==(const HubConfig &a, const HubConfig &b) {
		const auto endpointA = a.sniHost.isEmpty() ? a.host : a.sniHost;
		const auto endpointB = b.sniHost.isEmpty() ? b.host : b.sniHost;
		return (endpointA == endpointB)
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

} // namespace

struct WssMuxHub::Private : public QObject {
	QThread hubThread;
	HubConfig config;
	bool started = false;
	bool shuttingDown = false;
	bool authRejected = false;
	uint32 nextStreamId = 1;
	QMutex streamsMutex;
	std::map<uint32, details::MuxStreamSocket*> streams;
	std::map<uint32, int> streamTunnel;
	std::vector<std::unique_ptr<details::WssMuxTunnel>> tunnels;
	std::vector<QString> pendingResolvedIPs;
	bool ipUpdateScheduled = false;

	void resetTunnels() {
		for (auto i = 0; i != int(tunnels.size()); ++i) {
			failStreamsOnTunnel(i);
		}
		for (auto &tunnel : tunnels) {
			if (tunnel) {
				tunnel->prepareForDestroy();
			}
		}
		tunnels.clear();
		started = false;
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
		if (authRejected || index < 0 || index >= config.tunnelCount) {
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
		if (shuttingDown || !started || authRejected) {
			return;
		}
		auto ips = config.resolvedIPs;
		if (ips.empty()) {
			return;
		} else if (ips.size() > 1) {
			ranges::shuffle(ips);
		}
		const auto count = config.tunnelCount;
		if (int(tunnels.size()) != count) {
			resetTunnels();
			startTunnels();
			return;
		}
		for (auto i = 0; i != count; ++i) {
			const auto &tunnel = tunnels[i];
			const auto host = tunnel ? tunnel->connectHost() : QString();
			if (tunnel
				&& tunnel->isConnected()
				&& IpSetContains(ips, host)) {
				continue;
			}
			replaceTunnel(i, ProxyForTunnel(config, ips, i));
		}
	}

	void applyResolvedIpsUpdate(std::vector<QString> ips) {
		if (shuttingDown) {
			return;
		} else if (SameIpSet(config.resolvedIPs, ips)) {
			config.resolvedIPs = std::move(ips);
			return;
		}
		config.resolvedIPs = std::move(ips);
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
		const auto endpoint = config.sniHost.isEmpty()
			? config.host
			: config.sniHost;
		return endpoint == host;
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

	[[nodiscard]] details::WssMuxTunnel *pickTunnel() {
		details::WssMuxTunnel *best = nullptr;
		auto bestCount = int(streamTunnel.size()) + 1;
		for (auto i = 0; i != int(tunnels.size()); ++i) {
			if (!tunnels[i] || !tunnels[i]->isConnected()) {
				continue;
			}
			auto count = 0;
			for (const auto &[streamId, tunnel] : streamTunnel) {
				if (tunnel == i) {
					++count;
				}
			}
			if (count < bestCount) {
				bestCount = count;
				best = tunnels[i].get();
			}
		}
		return best;
	}

	void scheduleReconnect(int index) {
		if (shuttingDown
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
			postStreamEvent(streamId, [](details::MuxStreamSocket *socket) {
				socket->handleOpenOk();
			});
			break;
		case details::MuxFrameType::OpenFail:
			{
				QMutexLocker lock(&streamsMutex);
				streamTunnel.erase(streamId);
			}
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

	void startTunnels() {
		if (started || shuttingDown || authRejected) {
			return;
		}
		started = true;
		auto ips = config.resolvedIPs;
		if (ips.size() > 1) {
			ranges::shuffle(ips);
		}
		const auto count = config.tunnelCount;
		tunnels.reserve(count);
		for (auto i = 0; i != count; ++i) {
			const auto tunnelProxy = ProxyForTunnel(config, ips, i);
			auto tunnel = makeTunnel(i, tunnelProxy);
			const auto raw = tunnel.get();
			tunnels.push_back(std::move(tunnel));
			raw->connectTunnel();
		}
	}

	void requestOpen(uint32 streamId, const QString &host, int port) {
		if (shuttingDown) {
			return;
		} else if (authRejected) {
			postStreamEvent(streamId, [](details::MuxStreamSocket *socket) {
				socket->handleOpenFail();
			});
			return;
		}
		const auto tunnel = pickTunnel();
		if (!tunnel) {
			const auto weak = QPointer<Private>(this);
			QTimer::singleShot(kOpenRetryDelay, this, [=] {
				if (!weak || weak->shuttingDown) {
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
		{
			QMutexLocker lock(&streamsMutex);
			if (!streams.contains(streamId)) {
				return;
			}
			streamTunnel[streamId] = tunnel->index();
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
	const auto config = ConfigFromProxy(proxy, tunnelCount);
	InvokeQueued(_private.get(), [=, config = config]() mutable {
		_private->ensureHubThreadRunning();
		const auto sameEndpoint = (_private->config == config);
		if (!config.resolvedIPs.empty()) {
			_private->config.resolvedIPs = config.resolvedIPs;
		}
		if (sameEndpoint) {
			if (!_private->started) {
				_private->config = config;
			}
			return;
		}
		_private->authRejected = false;
		_private->resetTunnels();
		_private->config = config;
	});
}

void WssMuxHub::ApplyResolvedIps(
		const QString &host,
		const std::vector<QString> &ips) {
	if (ips.size() < 2) {
		return;
	}
	InvokeQueued(_private.get(), [=, ips = ips]() mutable {
		if (_private->shuttingDown || !_private->matchesEndpoint(host)) {
			return;
		}
		_private->ensureHubThreadRunning();
		if (SameIpSet(_private->config.resolvedIPs, ips)) {
			_private->config.resolvedIPs = std::move(ips);
			return;
		}
		_private->scheduleResolvedIpsUpdate(std::move(ips));
	});
}

void WssMuxHub::EnsureStarted() {
	InvokeQueued(_private.get(), [=] {
		_private->ensureHubThreadRunning();
		_private->startTunnels();
	});
}

void WssMuxHub::Shutdown() {
	if (!_private->hubThread.isRunning()) {
		return;
	}
	const auto cleanup = [=] {
		_private->shuttingDown = true;
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
		bool protocolForFiles) {
	const auto streamId = [&] {
		QMutexLocker lock(&_private->streamsMutex);
		return _private->nextStreamId++;
	}();
	auto socket = std::make_unique<details::MuxStreamSocket>(thread, this);
	socket->setStreamId(streamId);
	RegisterStream(streamId, socket.get());
	EnsureStarted();
	return socket;
}

void WssMuxHub::RegisterStream(
		uint32 streamId,
		not_null<details::MuxStreamSocket*> socket) {
	QMutexLocker lock(&_private->streamsMutex);
	_private->streams[streamId] = socket;
}

void WssMuxHub::UnregisterStream(uint32 streamId) {
	QMutexLocker lock(&_private->streamsMutex);
	_private->streams.erase(streamId);
}

void WssMuxHub::RequestOpen(
		uint32 streamId,
		const QString &host,
		int port) {
	InvokeQueued(_private.get(), [=] {
		_private->requestOpen(streamId, host, port);
	});
}

void WssMuxHub::SendData(uint32 streamId, bytes::const_span data) {
	auto copy = bytes::vector(data.begin(), data.end());
	InvokeQueued(_private.get(), [=, data = std::move(copy)]() mutable {
		if (_private->shuttingDown) {
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
	} else if (QThread::currentThread() == &_private->hubThread) {
		_private->requestCloseStream(streamId);
		return;
	}
	QMetaObject::invokeMethod(_private.get(), [=] {
		_private->requestCloseStream(streamId);
	}, Qt::BlockingQueuedConnection);
}

} // namespace MTP
