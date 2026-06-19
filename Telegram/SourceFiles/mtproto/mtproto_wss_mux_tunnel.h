#pragma once

#include "base/basic_types.h"

#include "mtproto/details/mtproto_wss_mux_framing.h"
#include "mtproto/mtproto_proxy_data.h"

#include "rpl/lifetime.h"

#include <memory>

namespace MTP::details {

class WebSocketSocket;

class WssMuxTunnel final : public QObject {
public:
	WssMuxTunnel(
		not_null<QThread*> thread,
		const ProxyData &proxy,
		int index);
	~WssMuxTunnel();

	void connectTunnel();
	void sendFrame(bytes::const_span frame);
	[[nodiscard]] bool isConnected() const;
	[[nodiscard]] bool authRejected() const;
	[[nodiscard]] QString connectHost() const;
	[[nodiscard]] int index() const;

	void setFrameHandler(Fn<void(MuxFrame &&)> &&handler);
	void setStateHandler(Fn<void(bool connected)> &&handler);

	void invokeOnTunnel(Fn<void()> &&fn);
	void prepareForDestroy();

private:
	void handleFrame(MuxFrame &&frame);

	const int _index = 0;
	const QString _connectHost;
	bool _connected = false;
	std::unique_ptr<WebSocketSocket> _socket;
	Fn<void(MuxFrame &&)> _frameHandler;
	Fn<void(bool)> _stateHandler;
	rpl::lifetime _lifetime;

};

} // namespace MTP::details
