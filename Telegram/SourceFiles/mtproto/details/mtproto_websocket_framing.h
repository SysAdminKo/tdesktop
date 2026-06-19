#pragma once

#include "base/bytes.h"

namespace MTP::details {

enum class WebSocketOpcode : uchar {
	Continuation = 0x0,
	Text = 0x1,
	Binary = 0x2,
	Close = 0x8,
	Ping = 0x9,
	Pong = 0xA,
};

[[nodiscard]] bytes::vector EncodeClientBinaryFrame(bytes::const_span payload);
[[nodiscard]] bytes::vector EncodeClientPingFrame(bytes::const_span payload = {});
[[nodiscard]] bytes::vector EncodeClientPongFrame(bytes::const_span payload);

class WebSocketReader final {
public:
	enum class Event {
		None,
		PayloadReady,
		Ping,
		Close,
		Error,
	};

	[[nodiscard]] Event consume(bytes::const_span chunk);
	[[nodiscard]] bytes::const_span payload() const;
	void consumePayload();

private:
	enum class ParseState {
		Header,
		Extended16,
		Extended64,
		Payload,
	};

	[[nodiscard]] Event parseHeader();
	[[nodiscard]] Event finishFrame();

	bytes::vector _buffer;
	bytes::vector _fragmented;
	bool _fragmentedActive = false;
	uchar _opcode = 0;
	bool _fin = false;
	uint64 _payloadLength = 0;
	uint64 _payloadRead = 0;
	ParseState _state = ParseState::Header;
	bytes::vector _currentPayload;
};

} // namespace MTP::details
