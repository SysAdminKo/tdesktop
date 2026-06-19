#pragma once

#include "base/bytes.h"

namespace MTP::details {

enum class MuxFrameType : uchar {
	Open = 0x01,
	OpenOk = 0x02,
	OpenFail = 0x03,
	Data = 0x04,
	Close = 0x05,
	Ping = 0x06,
	Pong = 0x07,
};

enum class MuxOpenFailReason : uchar {
	Dial = 1,
	BadTarget = 2,
	Limit = 3,
};

constexpr auto kMuxVersion = uchar(1);
constexpr auto kMuxHeaderSize = 8;
constexpr auto kMuxMaxDataPayload = 64 * 1024;

struct MuxFrame {
	MuxFrameType type = MuxFrameType::Data;
	uint32 streamId = 0;
	bytes::const_span payload;
};

enum class MuxDecodeResult {
	NeedMore,
	Ready,
	Error,
};

class MuxFrameDecoder final {
public:
	[[nodiscard]] MuxDecodeResult consume(bytes::const_span chunk);
	[[nodiscard]] MuxFrame frame() const;
	void consumeFrame();

private:
	bytes::vector _buffer;
	MuxFrame _current;
};

[[nodiscard]] bytes::vector EncodeMuxFrame(
	MuxFrameType type,
	uint32 streamId,
	bytes::const_span payload = {});
[[nodiscard]] bytes::vector EncodeMuxOpen(
	uint32 streamId,
	const QString &host,
	uint16 port);
[[nodiscard]] std::optional<MuxOpenFailReason> ParseMuxOpenFail(
	bytes::const_span payload);
[[nodiscard]] std::optional<uint8> ParseMuxCloseReason(
	bytes::const_span payload);

} // namespace MTP::details
