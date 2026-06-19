#include "mtproto/details/mtproto_websocket_framing.h"

#include "base/random.h"

#include <QtCore/QtEndian>

namespace MTP::details {
namespace {

constexpr auto kMaskKeySize = 4;

void ApplyMask(bytes::span data, bytes::const_span mask) {
	Expects(mask.size() == kMaskKeySize);

	for (auto i = 0; i != data.size(); ++i) {
		data[i] ^= mask[i % kMaskKeySize];
	}
}

[[nodiscard]] bytes::vector EncodeClientFrame(
		WebSocketOpcode opcode,
		bytes::const_span payload,
		bool fin) {
	const auto size = payload.size();
	auto prefix = 2;
	if (size >= 126 && size <= 0xFFFF) {
		prefix += 2;
	} else if (size > 0xFFFF) {
		prefix += 8;
	}
	const auto total = prefix + kMaskKeySize + size;
	auto result = bytes::vector(total);
	const auto finBit = fin ? 0x80 : 0x00;
	result[0] = bytes::type(finBit | uchar(opcode));
	if (size < 126) {
		result[1] = bytes::type(0x80 | uchar(size));
	} else if (size <= 0xFFFF) {
		result[1] = bytes::type(0x80 | 126);
		const auto length = qToBigEndian(uint16(size));
		bytes::copy(bytes::make_span(result).subspan(2), bytes::object_as_span(&length));
	} else {
		result[1] = bytes::type(0x80 | 127);
		const auto length = qToBigEndian(uint64(size));
		bytes::copy(bytes::make_span(result).subspan(2), bytes::object_as_span(&length));
	}
	const auto mask = bytes::make_span(result).subspan(prefix, kMaskKeySize);
	bytes::set_random(mask);
	auto data = bytes::make_span(result).subspan(prefix + kMaskKeySize);
	bytes::copy(data, payload);
	ApplyMask(data, mask);
	return result;
}

} // namespace

bytes::vector EncodeClientBinaryFrame(bytes::const_span payload) {
	return EncodeClientFrame(WebSocketOpcode::Binary, payload, true);
}

bytes::vector EncodeClientPingFrame(bytes::const_span payload) {
	return EncodeClientFrame(WebSocketOpcode::Ping, payload, true);
}

bytes::vector EncodeClientPongFrame(bytes::const_span payload) {
	return EncodeClientFrame(WebSocketOpcode::Pong, payload, true);
}

WebSocketReader::Event WebSocketReader::consume(bytes::const_span chunk) {
	if (!chunk.empty()) {
		const auto offset = _buffer.size();
		_buffer.resize(offset + chunk.size());
		bytes::copy(bytes::make_span(_buffer).subspan(offset), chunk);
	}
	while (true) {
		switch (_state) {
		case ParseState::Header: {
			const auto event = parseHeader();
			if (event != Event::None) {
				return event;
			}
		} break;
		case ParseState::Extended16:
		case ParseState::Extended64:
		case ParseState::Payload: {
			const auto event = finishFrame();
			if (event != Event::None) {
				return event;
			}
		} break;
		}
		if (_state != ParseState::Header
			|| _buffer.size() < 2) {
			return Event::None;
		}
	}
}

bytes::const_span WebSocketReader::payload() const {
	return _currentPayload;
}

void WebSocketReader::consumePayload() {
	_currentPayload.clear();
}

WebSocketReader::Event WebSocketReader::parseHeader() {
	if (_buffer.size() < 2) {
		return Event::None;
	}
	const auto first = uchar(_buffer[0]);
	const auto second = uchar(_buffer[1]);
	if (second & 0x80) {
		return Event::Error;
	}
	_fin = (first & 0x80) != 0;
	_opcode = uchar(first & 0x0F);
	const auto lengthCode = second & 0x7F;
	if (lengthCode < 126) {
		_payloadLength = lengthCode;
		_payloadRead = 0;
		_currentPayload.clear();
		_state = ParseState::Payload;
		_buffer.erase(_buffer.begin(), _buffer.begin() + 2);
		return finishFrame();
	} else if (lengthCode == 126) {
		_state = ParseState::Extended16;
		_buffer.erase(_buffer.begin(), _buffer.begin() + 2);
		return Event::None;
	}
	_state = ParseState::Extended64;
	_buffer.erase(_buffer.begin(), _buffer.begin() + 2);
	return Event::None;
}

WebSocketReader::Event WebSocketReader::finishFrame() {
	if (_state == ParseState::Extended16) {
		if (_buffer.size() < 2) {
			return Event::None;
		}
		const auto length = qFromBigEndian(
			*reinterpret_cast<const uint16*>(_buffer.data()));
		_payloadLength = length;
		_payloadRead = 0;
		_currentPayload.clear();
		_state = ParseState::Payload;
		_buffer.erase(_buffer.begin(), _buffer.begin() + 2);
	}
	if (_state == ParseState::Extended64) {
		if (_buffer.size() < 8) {
			return Event::None;
		}
		const auto length = qFromBigEndian(
			*reinterpret_cast<const uint64*>(_buffer.data()));
		_payloadLength = length;
		_payloadRead = 0;
		_currentPayload.clear();
		_state = ParseState::Payload;
		_buffer.erase(_buffer.begin(), _buffer.begin() + 8);
	}
	if (_state != ParseState::Payload) {
		return Event::None;
	}
	const auto need = _payloadLength - _payloadRead;
	if (_buffer.size() < need) {
		return Event::None;
	}
	const auto offset = _currentPayload.size();
	_currentPayload.resize(offset + need);
	bytes::copy(
		bytes::make_span(_currentPayload).subspan(offset),
		bytes::make_span(_buffer).subspan(0, need));
	_buffer.erase(_buffer.begin(), _buffer.begin() + need);
	_payloadRead += need;
	if (_payloadRead < _payloadLength) {
		return Event::None;
	}
	_state = ParseState::Header;
	const auto opcode = WebSocketOpcode(_opcode);
	switch (opcode) {
	case WebSocketOpcode::Continuation: {
		if (!_fragmentedActive) {
			return Event::Error;
		}
		const auto appendOffset = _fragmented.size();
		_fragmented.resize(appendOffset + _currentPayload.size());
		bytes::copy(
			bytes::make_span(_fragmented).subspan(appendOffset),
			_currentPayload);
		if (!_fin) {
			_currentPayload.clear();
			return Event::None;
		}
		_currentPayload = std::move(_fragmented);
		_fragmented.clear();
		_fragmentedActive = false;
		return Event::PayloadReady;
	}
	case WebSocketOpcode::Binary:
	case WebSocketOpcode::Text: {
		if (!_fin) {
			_fragmented = std::move(_currentPayload);
			_fragmentedActive = true;
			_currentPayload.clear();
			return Event::None;
		}
		return Event::PayloadReady;
	}
	case WebSocketOpcode::Ping:
		return Event::Ping;
	case WebSocketOpcode::Close:
		return Event::Close;
	case WebSocketOpcode::Pong:
		_currentPayload.clear();
		return Event::None;
	}
	return Event::Error;
}

} // namespace MTP::details
