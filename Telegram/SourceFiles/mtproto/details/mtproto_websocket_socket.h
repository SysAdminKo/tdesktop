#pragma once

#include "mtproto/details/mtproto_abstract_socket.h"
#include "mtproto/details/mtproto_websocket_framing.h"
#include "mtproto/details/mtproto_wss_mux_framing.h"
#include "mtproto/mtproto_proxy_data.h"
#include "crl/crl.h"

#include <QtNetwork/QSslSocket>
#include <QtCore/QTimer>

namespace MTP::details {

class WebSocketSocket final : public AbstractSocket {
public:
	WebSocketSocket(
		not_null<QThread*> thread,
		const ProxyData &proxy,
		bool protocolForFiles,
		bool muxTunnelMode = false);
	~WebSocketSocket();

	void connectMuxTunnel();
	void sendMuxFrame(bytes::const_span frame);
	void setMuxFrameHandler(Fn<void(MuxFrame &&)> &&handler);
	[[nodiscard]] bool isMuxTunnelMode() const;
	[[nodiscard]] bool authRejected() const;

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;

	[[nodiscard]] bool canReturnToPool() const;
	void prepareForReuse();
	void invokeOnSocket(Fn<void()> &&fn);

private:
	enum class State {
		NotConnected,
		TlsConnecting,
		HttpUpgrading,
		Connected,
		Error,
	};

	[[nodiscard]] QString tlsHostName() const;
	[[nodiscard]] QString httpPath() const;
	[[nodiscard]] QString upstreamTargetHeader() const;
	[[nodiscard]] QByteArray buildUpgradeRequest();
	[[nodiscard]] bool checkUpgradeResponse(const QByteArray &response) const;

	void tlsConnected();
	void tlsDisconnected();
	void tlsReadyRead();
	void handleError(int errorCode = 0);
	void processIncoming();
	void handleMuxPayload(bytes::const_span payload);
	void pollIncoming();
	void sendPing();
	void scheduleReadyRead();
	void releaseConnectGate();
	void startHandshakeTimer();
	void stopHandshakeTimer();

	const ProxyData _proxy;
	QSslSocket _socket;
	QTimer _pingTimer;
	QTimer _readPumpTimer;
	QTimer _handshakeTimer;
	State _state = State::NotConnected;
	QByteArray _incomingHttp;
	WebSocketReader _reader;
	bytes::vector _readBuffer;
	int _readOffset = 0;
	QByteArray _webSocketKey;
	QString _upstreamHost;
	int _upstreamPort = 0;
	bool _inRead = false;
	bool _readyReadScheduled = false;
	bool _connectGateAcquired = false;
	bool _muxTunnelMode = false;
	bool _authRejected = false;
	bool _mtprotoWritten = false;
	Fn<void(MuxFrame &&)> _muxFrameHandler;
	MuxFrameDecoder _muxDecoder;
	crl::time _lastIncomingAt = 0;
	crl::time _lastOutgoingAt = 0;

};

} // namespace MTP::details
