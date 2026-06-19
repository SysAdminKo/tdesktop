#include "mtproto/mtproto_wss_mux_stream_socket.h"

#include "mtproto/mtproto_wss_mux_hub.h"

#include "mtproto/details/mtproto_wss_mux_framing.h"

#include "base/bytes.h"
#include "base/invoke_queued.h"

namespace MTP::details {
namespace {

constexpr auto kOpenTimeout = crl::time(15000);
constexpr auto kMuxChunkSize = kMuxMaxDataPayload;

} // namespace

MuxStreamSocket::MuxStreamSocket(
		not_null<QThread*> thread,
		not_null<WssMuxHub*> hub)
: AbstractSocket(thread)
, _hub(hub) {
	_openTimer.moveToThread(thread);
	_openTimer.setSingleShot(true);
	connect(&_openTimer, &QTimer::timeout, this, [=] { failOpen(); });
}

MuxStreamSocket::~MuxStreamSocket() {
	_openTimer.stop();
	const auto streamId = _streamId;
	_streamId = 0;
	if (streamId) {
		_hub->UnregisterStream(streamId);
		if (_state == State::Connected || _state == State::Opening) {
			_hub->RequestClose(streamId);
		}
	}
}

void MuxStreamSocket::setStreamId(uint32 streamId) {
	_streamId = streamId;
}

uint32 MuxStreamSocket::streamId() const {
	return _streamId;
}

void MuxStreamSocket::invokeQueued(Fn<void()> &&fn) {
	InvokeQueued(this, std::move(fn));
}

void MuxStreamSocket::connectToHost(const QString &address, int port) {
	Expects(_state == State::NotConnected);

	_host = address;
	_port = port;
	_state = State::Opening;
	_readBuffer.clear();
	_readOffset = 0;
	_openTimer.start(kOpenTimeout);
	_hub->RequestOpen(_streamId, address, port);
}

void MuxStreamSocket::handleOpenOk() {
	if (!_streamId || _state != State::Opening) {
		return;
	}
	_openTimer.stop();
	_state = State::Connected;
	_connected.fire({});
}

void MuxStreamSocket::handleOpenFail() {
	failOpen();
}

void MuxStreamSocket::handleData(bytes::vector data) {
	if (!_streamId || _state != State::Connected || data.empty()) {
		return;
	}
	const auto offset = _readBuffer.size();
	_readBuffer.resize(offset + data.size());
	bytes::copy(
		bytes::make_span(_readBuffer).subspan(offset),
		data);
	if (!_inRead) {
		if (_readyReadScheduled) {
			return;
		}
		_readyReadScheduled = true;
		const auto streamId = _streamId;
		InvokeQueued(this, [=] {
			if (_streamId != streamId || _state != State::Connected) {
				return;
			}
			_readyReadScheduled = false;
			if (hasBytesAvailable()) {
				_readyRead.fire({});
			}
		});
	}
}

void MuxStreamSocket::handleRemoteClose() {
	if (!_streamId || _state == State::NotConnected || _state == State::Error) {
		return;
	}
	_state = State::NotConnected;
	_disconnected.fire({});
}

void MuxStreamSocket::handleTunnelDown() {
	if (!_streamId || _state == State::NotConnected || _state == State::Error) {
		return;
	}
	_state = State::NotConnected;
	_disconnected.fire({});
}

void MuxStreamSocket::failOpen() {
	if (_state != State::Opening) {
		return;
	}
	_openTimer.stop();
	_state = State::Error;
	_error.fire({});
}

void MuxStreamSocket::sendClose() {
	if (!_streamId) {
		return;
	}
	_hub->RequestClose(_streamId);
}

bool MuxStreamSocket::isGoodStartNonce(bytes::const_span nonce) {
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

void MuxStreamSocket::timedOut() {
	sendClose();
	_state = State::Error;
	_error.fire({});
}

bool MuxStreamSocket::isConnected() {
	return (_state == State::Connected);
}

bool MuxStreamSocket::hasBytesAvailable() {
	return _readOffset < _readBuffer.size();
}

int64 MuxStreamSocket::read(bytes::span buffer) {
	const auto wasInRead = _inRead;
	_inRead = true;
	const auto guard = gsl::finally([&] { _inRead = wasInRead; });
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

void MuxStreamSocket::write(bytes::const_span prefix, bytes::const_span buffer) {
	Expects(!buffer.empty());

	if (_state != State::Connected) {
		return;
	}
	const auto total = prefix.size() + buffer.size();
	auto combined = bytes::vector(total);
	if (!prefix.empty()) {
		bytes::copy(bytes::make_span(combined), prefix);
	}
	bytes::copy(bytes::make_span(combined).subspan(prefix.size()), buffer);
	for (auto offset = 0; offset != combined.size();) {
		const auto chunk = std::min(
			combined.size() - offset,
			std::size_t(kMuxChunkSize));
		_hub->SendData(
			_streamId,
			bytes::make_span(combined).subspan(offset, chunk));
		offset += chunk;
	}
}

int32 MuxStreamSocket::debugState() {
	return int32(_state);
}

QString MuxStreamSocket::debugPostfix() const {
	return u"_wssmuxstream"_q;
}

} // namespace MTP::details
