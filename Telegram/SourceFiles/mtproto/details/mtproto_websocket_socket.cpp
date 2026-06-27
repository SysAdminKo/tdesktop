#include "mtproto/details/mtproto_websocket_socket.h"

#include "base/bytes.h"
#include "base/invoke_queued.h"
#include "base/qthelp_url.h"
#include "base/random.h"
#include "crl/crl.h"
#include "mtproto/mtproto_wss_connect_gate.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtNetwork/QSslConfiguration>
#include <QtNetwork/QNetworkProxy>

namespace MTP::details {
namespace {

constexpr auto kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
constexpr auto kMuxSubprotocol = "tdesktop-mux/1";
constexpr auto kIdleBeforePing = crl::time(2000);
constexpr auto kOutgoingQuietBeforePing = crl::time(1500);
constexpr auto kPingCheckInterval = crl::time(1000);
constexpr auto kReadPumpInterval = crl::time(25);
constexpr auto kHandshakeTimeout = crl::time(15000);
constexpr auto kErrorAuthRejected = 889;

[[nodiscard]] bool IsUnauthorizedResponse(const QByteArray &response) {
	return response.startsWith("HTTP/1.1 401")
		|| response.startsWith("HTTP/1.0 401");
}

[[nodiscard]] QByteArray RandomWebSocketKey() {
	auto bytes = QByteArray(16, Qt::Uninitialized);
	bytes::set_random(bytes::make_detached_span(bytes));
	return bytes.toBase64();
}

} // namespace

WebSocketSocket::WebSocketSocket(
	not_null<QThread*> thread,
	const ProxyData &proxy,
	bool protocolForFiles,
	bool muxTunnelMode)
: AbstractSocket(thread)
, _proxy(proxy)
, _muxTunnelMode(muxTunnelMode) {
	Expects(_proxy.type == ProxyData::Type::WebSocket);

	_socket.moveToThread(thread);
	_socket.setProxy(QNetworkProxy::NoProxy);
	_socket.setSocketOption(QAbstractSocket::LowDelayOption, 1);
	_socket.setSocketOption(
		QAbstractSocket::SendBufferSizeSocketOption,
		kFilesSendBufferSize);
	_socket.setSocketOption(
		QAbstractSocket::ReceiveBufferSizeSocketOption,
		kFilesReceiveBufferSize);

	_pingTimer.moveToThread(thread);
	_pingTimer.setInterval(kPingCheckInterval);
	_pingTimer.setSingleShot(false);
	connect(&_pingTimer, &QTimer::timeout, this, [=] { sendPing(); });

	_readPumpTimer.moveToThread(thread);
	_readPumpTimer.setInterval(kReadPumpInterval);
	_readPumpTimer.setSingleShot(false);
	connect(&_readPumpTimer, &QTimer::timeout, this, [=] { pollIncoming(); });

	_handshakeTimer.moveToThread(thread);
	_handshakeTimer.setSingleShot(true);
	connect(&_handshakeTimer, &QTimer::timeout, this, [=] {
		logError(889, "WebSocket handshake timeout.");
		handleError();
	});

	const auto wrap = [&](auto handler) {
		return [=](auto &&...args) {
			InvokeQueued(this, [=] { handler(args...); });
		};
	};
	using Error = QAbstractSocket::SocketError;
	connect(
		&_socket,
		&QSslSocket::encrypted,
		wrap([=] { tlsConnected(); }));
	connect(
		&_socket,
		&QSslSocket::disconnected,
		wrap([=] { tlsDisconnected(); }));
	connect(
		&_socket,
		&QSslSocket::readyRead,
		this,
		[=] { tlsReadyRead(); },
		Qt::DirectConnection);
	connect(
		&_socket,
		&QAbstractSocket::errorOccurred,
		wrap([=](Error e) { handleError(e); }));
}

WebSocketSocket::~WebSocketSocket() {
	_pingTimer.stop();
	_readPumpTimer.stop();
	stopHandshakeTimer();
	releaseConnectGate();
	_socket.abort();
}

QString WebSocketSocket::tlsHostName() const {
	return _proxy.sniHost.isEmpty() ? _proxy.host : _proxy.sniHost;
}

QString WebSocketSocket::httpPath() const {
	const auto path = _proxy.path.isEmpty() ? u"/ws"_q : _proxy.path;
	const auto base = path.startsWith('/') ? path : ('/' + path);
	if (_muxTunnelMode) {
		return base;
	}
	if (_upstreamHost.isEmpty() || !_upstreamPort) {
		return base;
	}
	const auto host = qthelp::is_ipv6(_upstreamHost)
		? (u"["_q + _upstreamHost + u"]"_q)
		: _upstreamHost;
	return base + u'/' + host + u'/' + QString::number(_upstreamPort);
}

QString WebSocketSocket::upstreamTargetHeader() const {
	if (_muxTunnelMode) {
		return QString();
	}
	if (_upstreamHost.isEmpty() || !_upstreamPort) {
		return QString();
	}
	const auto host = qthelp::is_ipv6(_upstreamHost)
		? (u"["_q + _upstreamHost + u"]"_q)
		: _upstreamHost;
	return host + u':' + QString::number(_upstreamPort);
}

QByteArray WebSocketSocket::buildUpgradeRequest() {
	auto request = QByteArray("GET ")
		+ httpPath().toUtf8()
		+ " HTTP/1.1\r\n"
		+ "Host: "
		+ tlsHostName().toUtf8()
		+ "\r\n"
		+ "Upgrade: websocket\r\n"
		+ "Connection: Upgrade\r\n"
		+ "Sec-WebSocket-Key: "
		+ _webSocketKey
		+ "\r\n"
		+ "Sec-WebSocket-Version: 13\r\n";
	if (_muxTunnelMode) {
		request += "Sec-WebSocket-Protocol: "
			+ QByteArray(kMuxSubprotocol)
			+ "\r\n";
	}
	const auto upstreamTarget = upstreamTargetHeader();
	if (!upstreamTarget.isEmpty()) {
		request += "X-Tg-Target: "
			+ upstreamTarget.toUtf8()
			+ "\r\n";
	}
	if (!_proxy.password.isEmpty()) {
		request += "Authorization: Bearer "
			+ _proxy.password.toUtf8()
			+ "\r\n";
	}
	request += "User-Agent: Mozilla/5.0\r\n\r\n";
	return request;
}

bool WebSocketSocket::checkUpgradeResponse(const QByteArray &response) const {
	const auto headerEnd = response.indexOf("\r\n\r\n");
	if (headerEnd < 0) {
		return false;
	}
	const auto header = QString::fromUtf8(response.constData(), headerEnd);
	if (!header.startsWith(u"HTTP/1.1 101"_q)
		&& !header.startsWith(u"HTTP/1.0 101"_q)) {
		return false;
	}
	const auto acceptPrefix = u"sec-websocket-accept: "_q;
	const auto lines = header.split(u"\r\n"_q);
	auto acceptValue = QString();
	for (const auto &line : lines) {
		if (line.startsWith(acceptPrefix, Qt::CaseInsensitive)) {
			acceptValue = line.mid(acceptPrefix.size()).trimmed();
			break;
		}
	}
	if (acceptValue.isEmpty()) {
		return false;
	}
	const auto digest = QCryptographicHash::hash(
		_webSocketKey + kWebSocketGuid,
		QCryptographicHash::Sha1).toBase64();
	return (acceptValue == QString::fromLatin1(digest));
}

bool WebSocketSocket::isMuxTunnelMode() const {
	return _muxTunnelMode;
}

void WebSocketSocket::setMuxFrameHandler(Fn<void(MuxFrame &&)> &&handler) {
	_muxFrameHandler = std::move(handler);
}

bool WebSocketSocket::authRejected() const {
	return _authRejected;
}

void WebSocketSocket::connectMuxTunnel() {
	Expects(_muxTunnelMode);
	if (_authRejected) {
		return;
	}
	if (_state == State::Connected
		|| _state == State::TlsConnecting
		|| _state == State::HttpUpgrading) {
		return;
	}
	if (_state == State::Error) {
		_socket.abort();
		_state = State::NotConnected;
	}
	Expects(_state == State::NotConnected);

	const auto weak = QPointer<QObject>(this);
	if (!WssConnectGate::tryAcquire([=] {
		if (!weak) {
			return;
		}
		InvokeQueued(weak.data(), [=] {
			if (!weak) {
				return;
			}
			static_cast<WebSocketSocket*>(weak.data())->connectMuxTunnel();
		});
	})) {
		return;
	}
	_connectGateAcquired = true;
	startHandshakeTimer();

	_state = State::TlsConnecting;
	_incomingHttp.clear();
	_readBuffer.clear();
	_readOffset = 0;
	_reader = WebSocketReader();
	_muxDecoder = MuxFrameDecoder();

	_socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
	_socket.setPeerVerifyName(tlsHostName());
	DEBUG_LOG(("Connection %1 WSS mux tunnel TLS connect proxy %2:%3 sni %4"
		).arg(_debugId
		).arg(_proxy.host
		).arg(_proxy.port
		).arg(tlsHostName()));
	_socket.connectToHostEncrypted(_proxy.host, _proxy.port);
}

void WebSocketSocket::sendMuxFrame(bytes::const_span frame) {
	Expects(_muxTunnelMode);
	if (_state != State::Connected) {
		return;
	}
	_lastOutgoingAt = crl::now();
	const auto encoded = EncodeClientBinaryFrame(frame);
	_socket.write(
		reinterpret_cast<const char*>(encoded.data()),
		encoded.size());
	pollIncoming();
}

void WebSocketSocket::handleMuxPayload(bytes::const_span payload) {
	if (!_muxFrameHandler) {
		return;
	}
	auto result = _muxDecoder.consume(payload);
	while (result == MuxDecodeResult::Ready) {
		const auto frame = _muxDecoder.frame();
		auto copy = bytes::vector(frame.payload.begin(), frame.payload.end());
		_muxFrameHandler(MuxFrame{
			frame.type,
			frame.streamId,
			copy,
		});
		_muxDecoder.consumeFrame();
		result = _muxDecoder.consume({});
	}
	if (result == MuxDecodeResult::Error) {
		handleError();
	}
}

void WebSocketSocket::releaseConnectGate() {
	if (_connectGateAcquired) {
		_connectGateAcquired = false;
		WssConnectGate::release();
	}
}

void WebSocketSocket::startHandshakeTimer() {
	_handshakeTimer.start(kHandshakeTimeout);
}

void WebSocketSocket::stopHandshakeTimer() {
	_handshakeTimer.stop();
}

void WebSocketSocket::connectToHost(const QString &address, int port) {
	Expects(_state == State::NotConnected || _state == State::Connected);

	if (_state == State::Connected
		&& _upstreamHost == address
		&& _upstreamPort == port) {
		InvokeQueued(this, [=] { _connected.fire({}); });
		return;
	}
	Expects(_state == State::NotConnected);

	const auto weak = QPointer<QObject>(this);
	if (!WssConnectGate::tryAcquire([=] {
		if (!weak) {
			return;
		}
		InvokeQueued(weak.data(), [=] {
			if (!weak) {
				return;
			}
			static_cast<WebSocketSocket*>(weak.data())->connectToHost(
				address,
				port);
		});
	})) {
		return;
	}
	_connectGateAcquired = true;
	startHandshakeTimer();

	_upstreamHost = address;
	_upstreamPort = port;
	_state = State::TlsConnecting;
	_incomingHttp.clear();
	_readBuffer.clear();
	_readOffset = 0;
	_reader = WebSocketReader();

	_socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
	_socket.setPeerVerifyName(tlsHostName());
	DEBUG_LOG(("Connection %1 WSS TLS connect proxy %2:%3 sni %4 target %5:%6"
		).arg(_debugId
		).arg(_proxy.host
		).arg(_proxy.port
		).arg(tlsHostName()
		).arg(address
		).arg(port));
	_socket.connectToHostEncrypted(_proxy.host, _proxy.port);
}

void WebSocketSocket::tlsConnected() {
	if (_state != State::TlsConnecting) {
		return;
	}
	const auto sslInfo =
#if QT_VERSION >= QT_VERSION_CHECK(6, 1, 0)
		_socket.activeBackend() + u" "_q + QSslSocket::sslLibraryVersionString();
#else
		QSslSocket::sslLibraryVersionString();
#endif
	DEBUG_LOG(("Connection %1 WSS TLS handshake ok sni %2 protocol %3 ssl %4"
		).arg(_debugId
		).arg(tlsHostName()
		).arg(int(_socket.sslConfiguration().protocol())
		).arg(sslInfo));
	_state = State::HttpUpgrading;
	_webSocketKey = RandomWebSocketKey();
	_socket.write(buildUpgradeRequest());
	releaseConnectGate();
}

void WebSocketSocket::tlsDisconnected() {
	_pingTimer.stop();
	_readPumpTimer.stop();
	stopHandshakeTimer();
	releaseConnectGate();
	_state = State::NotConnected;
	_readBuffer.clear();
	_readOffset = 0;
	_disconnected.fire({});
}

void WebSocketSocket::tlsReadyRead() {
	if (_state == State::HttpUpgrading) {
		_incomingHttp.append(_socket.readAll());
		if (!_incomingHttp.contains("\r\n\r\n")) {
			return;
		}
		if (IsUnauthorizedResponse(_incomingHttp)) {
			_authRejected = true;
			logError(kErrorAuthRejected, "WSS proxy access token rejected.");
			handleError();
			return;
		}
		if (!checkUpgradeResponse(_incomingHttp)) {
			logError(888, "Bad WebSocket upgrade response.");
			handleError();
			return;
		}
		const auto headerEnd = _incomingHttp.indexOf("\r\n\r\n") + 4;
		const auto extra = _incomingHttp.mid(headerEnd);
		_incomingHttp.clear();
		_state = State::Connected;
		stopHandshakeTimer();
		_lastIncomingAt = crl::now();
		_lastOutgoingAt = _lastIncomingAt;
		_pingTimer.start();
		_readPumpTimer.start();
		_connected.fire({});
		if (!extra.isEmpty()) {
			const auto chunk = bytes::make_span(
				reinterpret_cast<const bytes::type*>(extra.constData()),
				extra.size());
			auto event = _reader.consume(chunk);
			while (event != WebSocketReader::Event::None) {
				if (event == WebSocketReader::Event::PayloadReady) {
					const auto payload = _reader.payload();
					if (_muxTunnelMode) {
						handleMuxPayload(payload);
					} else {
						const auto offset = _readBuffer.size();
						_readBuffer.resize(offset + payload.size());
						bytes::copy(
							bytes::make_span(_readBuffer).subspan(offset),
							payload);
					}
					_reader.consumePayload();
					_lastIncomingAt = crl::now();
				} else if (event == WebSocketReader::Event::Ping) {
					const auto payload = _reader.payload();
					const auto frame = EncodeClientPongFrame(payload);
					_socket.write(
						reinterpret_cast<const char*>(frame.data()),
						frame.size());
					_reader.consumePayload();
				} else if (event == WebSocketReader::Event::Close
					|| event == WebSocketReader::Event::Error) {
					handleError();
					return;
				}
				event = _reader.consume({});
			}
			if (hasBytesAvailable()) {
				scheduleReadyRead();
			}
		}
		return;
	}
	while (_socket.bytesAvailable() > 0) {
		processIncoming();
	}
}

void WebSocketSocket::processIncoming() {
	if (_state != State::Connected) {
		return;
	}
	const auto data = _socket.readAll();
	if (data.isEmpty()) {
		return;
	}
	const auto chunk = bytes::make_span(
		reinterpret_cast<const bytes::type*>(data.constData()),
		data.size());
	auto gotPayload = false;
	auto event = _reader.consume(chunk);
	while (event != WebSocketReader::Event::None) {
		if (event == WebSocketReader::Event::PayloadReady) {
			const auto payload = _reader.payload();
			if (_muxTunnelMode) {
				handleMuxPayload(payload);
			} else {
				const auto offset = _readBuffer.size();
				_readBuffer.resize(offset + payload.size());
				bytes::copy(
					bytes::make_span(_readBuffer).subspan(offset),
					payload);
				gotPayload = true;
			}
			_reader.consumePayload();
		} else if (event == WebSocketReader::Event::Ping) {
			const auto payload = _reader.payload();
			const auto frame = EncodeClientPongFrame(payload);
			_socket.write(
				reinterpret_cast<const char*>(frame.data()),
				frame.size());
			_reader.consumePayload();
		} else if (event == WebSocketReader::Event::Close
			|| event == WebSocketReader::Event::Error) {
			handleError();
			return;
		}
		event = _reader.consume({});
	}
	if (gotPayload) {
		_lastIncomingAt = crl::now();
		if (!_inRead) {
			scheduleReadyRead();
		}
	}
}

void WebSocketSocket::scheduleReadyRead() {
	if (_readyReadScheduled) {
		return;
	}
	_readyReadScheduled = true;
	InvokeQueued(this, [=] {
		_readyReadScheduled = false;
		if (hasBytesAvailable()) {
			_readyRead.fire({});
		}
	});
}

void WebSocketSocket::pollIncoming() {
	if (_state != State::Connected) {
		return;
	}
	while (_socket.bytesAvailable() > 0) {
		processIncoming();
	}
}

void WebSocketSocket::sendPing() {
	if (_state != State::Connected) {
		return;
	}
	pollIncoming();
	const auto now = crl::now();
	if (now - _lastIncomingAt < kIdleBeforePing) {
		return;
	} else if (now - _lastOutgoingAt < kOutgoingQuietBeforePing) {
		return;
	}
	const auto frame = EncodeClientPingFrame({});
	_socket.write(
		reinterpret_cast<const char*>(frame.data()),
		frame.size());
	pollIncoming();
}

bool WebSocketSocket::isGoodStartNonce(bytes::const_span nonce) {
	Expects(nonce.size() >= 2 * sizeof(uint32));

	const auto bytes = nonce.data();
	const auto zero = *reinterpret_cast<const uchar*>(bytes);
	const auto first = *reinterpret_cast<const uint32*>(bytes);
	const auto second = *(reinterpret_cast<const uint32*>(bytes) + 1);
	const auto reserved01 = 0x000000EFU;
	const auto reserved11 = 0x44414548U;
	const auto reserved12 = 0x54534F50U;
	const auto reserved13 = 0x20544547U;
	const auto reserved14 = 0xEEEEEEEEU;
	const auto reserved15 = 0xDDDDDDDDU;
	const auto reserved16 = 0x02010316U;
	const auto reserved21 = 0x00000000U;
	return (zero != reserved01)
		&& (first != reserved11)
		&& (first != reserved12)
		&& (first != reserved13)
		&& (first != reserved14)
		&& (first != reserved15)
		&& (first != reserved16)
		&& (second != reserved21);
}

void WebSocketSocket::timedOut() {
}

bool WebSocketSocket::isConnected() {
	return (_state == State::Connected);
}

bool WebSocketSocket::hasBytesAvailable() {
	if (_readOffset < _readBuffer.size()) {
		return true;
	}
	return _socket.bytesAvailable() > 0;
}

int64 WebSocketSocket::read(bytes::span buffer) {
	const auto wasInRead = _inRead;
	_inRead = true;
	const auto guard = gsl::finally([&] { _inRead = wasInRead; });
	if (_readOffset >= _readBuffer.size() && _socket.bytesAvailable() > 0) {
		processIncoming();
	}
	auto written = int64(0);
	while (_readOffset < _readBuffer.size() && !buffer.empty()) {
		const auto available = _readBuffer.size() - _readOffset;
		const auto take = std::min(available, buffer.size());
		bytes::copy(
			buffer,
			bytes::make_span(_readBuffer).subspan(_readOffset, take));
		_readOffset += take;
		buffer = buffer.subspan(take);
		written += take;
	}
	if (_readOffset > 0 && _readOffset == _readBuffer.size()) {
		_readBuffer.clear();
		_readOffset = 0;
	}
	return written;
}

void WebSocketSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (_state != State::Connected) {
		return;
	}
	_mtprotoWritten = true;
	_lastOutgoingAt = crl::now();
	const auto total = prefix.size() + buffer.size();
	auto combined = bytes::vector(total);
	if (!prefix.empty()) {
		bytes::copy(bytes::make_span(combined), prefix);
	}
	bytes::copy(bytes::make_span(combined).subspan(prefix.size()), buffer);
	const auto frame = EncodeClientBinaryFrame(combined);
	_socket.write(
		reinterpret_cast<const char*>(frame.data()),
		frame.size());
	pollIncoming();
}

int32 WebSocketSocket::debugState() {
	return int32(_state);
}

QString WebSocketSocket::debugPostfix() const {
	return _muxTunnelMode ? u"_wssmux"_q : u"_wss"_q;
}

bool WebSocketSocket::canReturnToPool() const {
	return (_state == State::Connected) && !_mtprotoWritten;
}

void WebSocketSocket::prepareForReuse() {
	Expects(canReturnToPool());

	_readBuffer.clear();
	_readOffset = 0;
	_reader = WebSocketReader();
	_inRead = false;
	_readyReadScheduled = false;
	_mtprotoWritten = false;
	_lastIncomingAt = crl::now();
	_lastOutgoingAt = _lastIncomingAt;
}

void WebSocketSocket::invokeOnSocket(Fn<void()> &&fn) {
	InvokeQueued(this, std::move(fn));
}

void WebSocketSocket::handleError(int errorCode) {
	_pingTimer.stop();
	_readPumpTimer.stop();
	stopHandshakeTimer();
	releaseConnectGate();
	if (errorCode) {
		logError(errorCode, _socket.errorString());
	}
	_state = State::Error;
	_error.fire({});
}

} // namespace MTP::details
