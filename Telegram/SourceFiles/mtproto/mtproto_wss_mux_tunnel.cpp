#include "mtproto/mtproto_wss_mux_tunnel.h"

#include "mtproto/details/mtproto_websocket_socket.h"

#include "base/invoke_queued.h"

namespace MTP::details {

WssMuxTunnel::WssMuxTunnel(
		not_null<QThread*> thread,
		const ProxyData &proxy,
		int index)
: _index(index)
, _connectHost(proxy.host)
, _socket(std::make_unique<WebSocketSocket>(thread, proxy, false, true)) {
	moveToThread(thread);
	_socket->setMuxFrameHandler([=](MuxFrame &&frame) {
		handleFrame(std::move(frame));
	});
	_socket->connected(
	) | rpl::on_next([=] {
		_connected = true;
		if (_stateHandler) {
			_stateHandler(true);
		}
	}, _lifetime);
	_socket->disconnected(
	) | rpl::on_next([=] {
		_connected = false;
		if (_stateHandler) {
			_stateHandler(false);
		}
	}, _lifetime);
	_socket->error(
	) | rpl::on_next([=] {
		_connected = false;
		if (_stateHandler) {
			_stateHandler(false);
		}
	}, _lifetime);
}

WssMuxTunnel::~WssMuxTunnel() {
	prepareForDestroy();
}

void WssMuxTunnel::prepareForDestroy() {
	_lifetime.destroy();
	_stateHandler = nullptr;
	_frameHandler = nullptr;
	_socket.reset();
}

void WssMuxTunnel::connectTunnel() {
	if (!_socket) {
		return;
	}
	_socket->connectMuxTunnel();
}

void WssMuxTunnel::sendFrame(bytes::const_span frame) {
	if (!_socket) {
		return;
	}
	_socket->sendMuxFrame(frame);
}

bool WssMuxTunnel::isConnected() const {
	return _connected && _socket->isConnected();
}

bool WssMuxTunnel::authRejected() const {
	return _socket && _socket->authRejected();
}

QString WssMuxTunnel::connectHost() const {
	return _connectHost;
}

int WssMuxTunnel::index() const {
	return _index;
}

void WssMuxTunnel::setFrameHandler(Fn<void(MuxFrame &&)> &&handler) {
	_frameHandler = std::move(handler);
}

void WssMuxTunnel::setStateHandler(Fn<void(bool connected)> &&handler) {
	_stateHandler = std::move(handler);
}

void WssMuxTunnel::invokeOnTunnel(Fn<void()> &&fn) {
	if (!_socket) {
		return;
	}
	_socket->invokeOnSocket(std::move(fn));
}

void WssMuxTunnel::handleFrame(MuxFrame &&frame) {
	if (_frameHandler) {
		_frameHandler(std::move(frame));
	}
}

} // namespace MTP::details
