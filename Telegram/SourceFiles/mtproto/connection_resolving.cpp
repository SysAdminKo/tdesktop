/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "mtproto/connection_resolving.h"

#include "mtproto/mtp_instance.h"

#include <algorithm>
#include <map>
#include <mutex>

namespace MTP {
namespace details {
namespace {

constexpr auto kOneConnectionTimeout = 6000;
constexpr auto kIpQuarantineDuration = 10 * crl::time(1000) * 60;
constexpr auto kEarlyDisconnectQuarantine = 30 * crl::time(1000);

[[nodiscard]] std::mutex &IpQuarantineMutex() {
	static auto mutex = std::mutex();
	return mutex;
}

[[nodiscard]] auto &IpQuarantineMap() {
	static auto map = std::map<QString, std::map<QString, crl::time>>();
	return map;
}

void QuarantineIp(
		const QString &host,
		const QString &ip,
		crl::time duration) {
	if (host.isEmpty() || ip.isEmpty()) {
		return;
	}
	const auto until = crl::now() + duration;
	const auto locker = std::lock_guard(IpQuarantineMutex());
	auto &slot = IpQuarantineMap()[host][ip];
	if (slot > until) {
		return;
	}
	slot = until;
}

void ClearIpQuarantine(const QString &host, const QString &ip) {
	const auto locker = std::lock_guard(IpQuarantineMutex());
	auto &byHost = IpQuarantineMap();
	const auto i = byHost.find(host);
	if (i == end(byHost)) {
		return;
	}
	i->second.erase(ip);
	if (i->second.empty()) {
		byHost.erase(i);
	}
}

[[nodiscard]] bool IsIpQuarantined(const QString &host, const QString &ip) {
	const auto locker = std::lock_guard(IpQuarantineMutex());
	auto &byHost = IpQuarantineMap();
	const auto i = byHost.find(host);
	if (i == end(byHost)) {
		return false;
	}
	const auto j = i->second.find(ip);
	if (j == end(i->second)) {
		return false;
	}
	if (j->second <= crl::now()) {
		i->second.erase(j);
		if (i->second.empty()) {
			byHost.erase(i);
		}
		return false;
	}
	return true;
}

void RotateResolvedIps(const QString &host, std::vector<QString> &ips) {
	const auto count = int(ips.size());
	if (count <= 1) {
		return;
	}
	static auto mutex = std::mutex();
	static auto next = std::map<QString, int>();
	const auto locker = std::lock_guard(mutex);
	const auto shift = next[host]++ % count;
	std::rotate(begin(ips), begin(ips) + shift, end(ips));
}

[[nodiscard]] int FindNextResolvedIpIndex(
		const QString &host,
		const std::vector<QString> &ips,
		int afterIndex) {
	const auto count = int(ips.size());
	for (auto i = afterIndex + 1; i < count; ++i) {
		if (!IsIpQuarantined(host, ips[i])) {
			return i;
		}
	}
	return -1;
}

[[nodiscard]] int FindSoonestQuarantinedIpIndex(
		const QString &host,
		const std::vector<QString> &ips) {
	const auto locker = std::lock_guard(IpQuarantineMutex());
	const auto now = crl::now();
	auto &byHost = IpQuarantineMap();
	const auto i = byHost.find(host);
	if (i == end(byHost)) {
		return ips.empty() ? -1 : 0;
	}
	auto bestIndex = -1;
	auto bestUntil = crl::time(0);
	for (auto index = 0; index < int(ips.size()); ++index) {
		const auto j = i->second.find(ips[index]);
		if (j == end(i->second) || j->second <= now) {
			continue;
		}
		if (bestIndex < 0 || j->second < bestUntil) {
			bestIndex = index;
			bestUntil = j->second;
		}
	}
	return bestIndex;
}

} // namespace

ResolvingConnection::ResolvingConnection(
	not_null<Instance*> instance,
	QThread *thread,
	const ProxyData &proxy,
	ConnectionPointer &&child)
: AbstractConnection(thread, proxy)
, _instance(instance)
, _timeoutTimer([=] { handleError(kErrorCodeOther); }) {
	setChild(std::move(child));
	if (proxy.type == ProxyData::Type::WebSocket
		&& proxy.wssMuxTunnels < 1
		&& _proxy.resolvedIPs.size() > 1) {
		_proxy.resolvedIPs.resize(1);
	}
	RotateResolvedIps(_proxy.host, _proxy.resolvedIPs);
	if (proxy.resolvedExpireAt < crl::now()) {
		const auto host = proxy.host;
		connect(
			instance,
			&Instance::proxyDomainResolved,
			this,
			&ResolvingConnection::domainResolved,
			Qt::QueuedConnection);
		InvokeQueued(instance, [=] {
			instance->resolveProxyDomain(host);
		});
	}
	if (!proxy.resolvedIPs.empty()) {
		refreshChild();
	}
}

ConnectionPointer ResolvingConnection::clone(const ProxyData &proxy) {
	Unexpected("ResolvingConnection::clone call.");
}

void ResolvingConnection::setChild(ConnectionPointer &&child) {
	_child = std::move(child);
	connect(
		_child,
		&AbstractConnection::receivedData,
		this,
		&ResolvingConnection::handleReceivedData);
	connect(
		_child,
		&AbstractConnection::receivedSome,
		this,
		&ResolvingConnection::receivedSome);
	connect(
		_child,
		&AbstractConnection::error,
		this,
		&ResolvingConnection::handleError);
	connect(_child,
		&AbstractConnection::connected,
		this,
		&ResolvingConnection::handleConnected);
	connect(_child,
		&AbstractConnection::disconnected,
		this,
		&ResolvingConnection::handleDisconnected);
	connect(
		_child,
		&AbstractConnection::packetReassemblyStall,
		this,
		&AbstractConnection::packetReassemblyStall);
	if (_protocolDcId) {
		_child->setWssTunnelAffinity(wssTunnelAffinity());
		_child->connectToServer(
			_address,
			_port,
			_protocolSecret,
			_protocolDcId,
			_protocolForFiles);
		CONNECTION_LOG_INFO("Resolving connected a new child: "
			+ _child->debugId());
	}
}

void ResolvingConnection::domainResolved(
		const QString &host,
		const QStringList &ips,
		qint64 expireAt) {
	if (host != _proxy.host || !_child) {
		return;
	}
	_proxy.resolvedExpireAt = expireAt;

	auto index = 0;
	for (const auto &ip : ips) {
		if (index >= _proxy.resolvedIPs.size()) {
			_proxy.resolvedIPs.push_back(ip);
		} else if (_proxy.resolvedIPs[index] != ip) {
			_proxy.resolvedIPs[index] = ip;
			if (_ipIndex >= index) {
				_ipIndex = index - 1;
				refreshChild();
			}
		}
		++index;
	}
	if (index < _proxy.resolvedIPs.size()) {
		_proxy.resolvedIPs.resize(index);
		if (_ipIndex >= index) {
			emitError(kErrorCodeOther);
		}
	}
	if (_proxy.type == ProxyData::Type::WebSocket
		&& _proxy.wssMuxTunnels < 1
		&& _proxy.resolvedIPs.size() > 1) {
		_proxy.resolvedIPs.resize(1);
	}
	if (_ipIndex < 0) {
		RotateResolvedIps(_proxy.host, _proxy.resolvedIPs);
		refreshChild();
	}
}

void ResolvingConnection::quarantineCurrentIp() {
	if (_ipIndex < 0 || _ipIndex >= int(_proxy.resolvedIPs.size())) {
		return;
	}
	QuarantineIp(
		_proxy.host,
		_proxy.resolvedIPs[_ipIndex],
		kIpQuarantineDuration);
}

bool ResolvingConnection::refreshChild() {
	if (!_child) {
		return true;
	}
	if (_proxy.type == ProxyData::Type::WebSocket && _ipIndex >= 0) {
		return false;
	}
	auto next = FindNextResolvedIpIndex(
		_proxy.host,
		_proxy.resolvedIPs,
		_ipIndex);
	if (next < 0) {
		next = FindSoonestQuarantinedIpIndex(
			_proxy.host,
			_proxy.resolvedIPs);
	}
	if (next < 0) {
		return false;
	}
	_ipIndex = next;
	setChild(_child->clone(ToDirectIpProxy(_proxy, _ipIndex)));
	_timeoutTimer.callOnce(kOneConnectionTimeout);
	return true;
}

void ResolvingConnection::emitError(int errorCode) {
	_ipIndex = -1;
	_connectedAt = 0;
	_child = nullptr;
	error(errorCode);
}

void ResolvingConnection::handleError(int errorCode) {
	if (_connected) {
		if (_connectedAt
			&& (crl::now() - _connectedAt) < kEarlyDisconnectQuarantine) {
			quarantineCurrentIp();
		}
		emitError(errorCode);
	} else if (!_proxy.resolvedIPs.empty()) {
		quarantineCurrentIp();
		if (!refreshChild()) {
			emitError(errorCode);
		}
	} else {
		// Wait for the domain to be resolved.
	}
}

void ResolvingConnection::handleDisconnected() {
	if (_connected) {
		if (_connectedAt
			&& (crl::now() - _connectedAt) < kEarlyDisconnectQuarantine) {
			quarantineCurrentIp();
		}
		disconnected();
	} else {
		handleError(kErrorCodeOther);
	}
}

void ResolvingConnection::handleReceivedData() {
	auto &my = received();
	auto &his = _child->received();
	for (auto &item : his) {
		my.push_back(std::move(item));
	}
	his.clear();
	receivedData();
}

void ResolvingConnection::handleConnected() {
	_connected = true;
	_connectedAt = crl::now();
	_timeoutTimer.cancel();
	if (_ipIndex >= 0) {
		const auto host = _proxy.host;
		const auto good = _proxy.resolvedIPs[_ipIndex];
		ClearIpQuarantine(host, good);
		const auto instance = _instance;
		InvokeQueued(_instance, [=] {
			instance->setGoodProxyDomain(host, good);
		});
	}
	connected();
}

crl::time ResolvingConnection::pingTime() const {
	Expects(_child != nullptr);

	return _child->pingTime();
}

crl::time ResolvingConnection::fullConnectTimeout() const {
	return kOneConnectionTimeout * qMax(int(_proxy.resolvedIPs.size()), 1);
}

void ResolvingConnection::sendData(mtpBuffer &&buffer) {
	Expects(_child != nullptr);

	_child->sendData(std::move(buffer));
}

void ResolvingConnection::disconnectFromServer() {
	if (!_connected) {
		quarantineCurrentIp();
	}
	_address = QString();
	_port = 0;
	_protocolSecret = bytes::vector();
	_protocolDcId = 0;
	_timeoutTimer.cancel();
	if (!_child) {
		return;
	}
	_child->disconnectFromServer();
}

void ResolvingConnection::timedOut() {
	if (!_connected) {
		quarantineCurrentIp();
	}
	if (_child) {
		_child->timedOut();
	}
}

void ResolvingConnection::connectToServer(
		const QString &address,
		int port,
		const bytes::vector &protocolSecret,
		int16 protocolDcId,
		bool protocolForFiles) {
	if (!_child) {
		InvokeQueued(this, [=] { emitError(kErrorCodeOther); });
		return;
	}
	_address = address;
	_port = port;
	_protocolSecret = protocolSecret;
	_protocolDcId = protocolDcId;
	_protocolForFiles = protocolForFiles;
	_child->setWssTunnelAffinity(wssTunnelAffinity());
	_child->connectToServer(
		address,
		port,
		protocolSecret,
		protocolDcId,
		protocolForFiles);
	CONNECTION_LOG_INFO("Resolving connected a child: " + _child->debugId());
}

bool ResolvingConnection::isConnected() const {
	return _child ? _child->isConnected() : false;
}

int32 ResolvingConnection::debugState() const {
	return _child ? _child->debugState() : -1;
}

QString ResolvingConnection::transport() const {
	return _child ? _child->transport() : QString();
}

QString ResolvingConnection::tag() const {
	return _child ? _child->tag() : QString();
}

} // namespace details
} // namespace MTP
