#include "mtproto/details/mtproto_wss_mux_framing.h"

#include <QtCore/QtEndian>

namespace MTP::details {
namespace {

[[nodiscard]] bool ValidMuxType(uchar value) {
	switch (MuxFrameType(value)) {
	case MuxFrameType::Open:
	case MuxFrameType::OpenOk:
	case MuxFrameType::OpenFail:
	case MuxFrameType::Data:
	case MuxFrameType::Close:
	case MuxFrameType::Ping:
	case MuxFrameType::Pong:
		return true;
	}
	return false;
}

} // namespace

bytes::vector EncodeMuxFrame(
		MuxFrameType type,
		uint32 streamId,
		bytes::const_span payload) {
	Expects(payload.size() <= kMuxMaxDataPayload);

	const auto total = kMuxHeaderSize + payload.size();
	auto result = bytes::vector(total);
	result[0] = bytes::type(kMuxVersion);
	result[1] = bytes::type(uchar(type));
	const auto reserved = qToBigEndian(uint16(0));
	bytes::copy(bytes::make_span(result).subspan(2, 2), bytes::object_as_span(&reserved));
	const auto id = qToBigEndian(streamId);
	bytes::copy(bytes::make_span(result).subspan(4, 4), bytes::object_as_span(&id));
	if (!payload.empty()) {
		bytes::copy(bytes::make_span(result).subspan(kMuxHeaderSize), payload);
	}
	return result;
}

bytes::vector EncodeMuxOpen(
		uint32 streamId,
		const QString &host,
		uint16 port) {
	const auto hostUtf8 = host.toUtf8();
	Expects(hostUtf8.size() <= 0xFFFF);

	const auto openPayloadSize = 2 + hostUtf8.size() + 2;
	auto openPayload = bytes::vector(openPayloadSize);
	const auto hostLen = qToBigEndian(uint16(hostUtf8.size()));
	bytes::copy(bytes::make_span(openPayload).subspan(0, 2), bytes::object_as_span(&hostLen));
	bytes::copy(
		bytes::make_span(openPayload).subspan(2, hostUtf8.size()),
		bytes::make_span(hostUtf8));
	const auto portBe = qToBigEndian(port);
	bytes::copy(
		bytes::make_span(openPayload).subspan(2 + hostUtf8.size(), 2),
		bytes::object_as_span(&portBe));
	return EncodeMuxFrame(
		MuxFrameType::Open,
		streamId,
		openPayload);
}

std::optional<MuxOpenFailReason> ParseMuxOpenFail(bytes::const_span payload) {
	if (payload.empty()) {
		return MuxOpenFailReason::Dial;
	}
	return MuxOpenFailReason(uchar(payload[0]));
}

std::optional<uint8> ParseMuxCloseReason(bytes::const_span payload) {
	if (payload.empty()) {
		return std::nullopt;
	}
	return uchar(payload[0]);
}

MuxDecodeResult MuxFrameDecoder::consume(bytes::const_span chunk) {
	if (!chunk.empty()) {
		const auto offset = _buffer.size();
		_buffer.resize(offset + chunk.size());
		bytes::copy(bytes::make_span(_buffer).subspan(offset), chunk);
	}
	if (_buffer.size() < kMuxHeaderSize) {
		return MuxDecodeResult::NeedMore;
	}
	const auto version = uchar(_buffer[0]);
	if (version != kMuxVersion) {
		return MuxDecodeResult::Error;
	}
	const auto type = uchar(_buffer[1]);
	if (!ValidMuxType(type)) {
		return MuxDecodeResult::Error;
	}
	const auto streamId = qFromBigEndian(
		*reinterpret_cast<const uint32*>(_buffer.data() + 4));
	const auto payloadSize = _buffer.size() - kMuxHeaderSize;
	if (type == uchar(MuxFrameType::Data) && payloadSize > kMuxMaxDataPayload) {
		return MuxDecodeResult::Error;
	}
	_current = {
		MuxFrameType(type),
		streamId,
		bytes::make_span(_buffer).subspan(kMuxHeaderSize),
	};
	return MuxDecodeResult::Ready;
}

MuxFrame MuxFrameDecoder::frame() const {
	return _current;
}

void MuxFrameDecoder::consumeFrame() {
	_buffer.clear();
	_current = {};
}

} // namespace MTP::details
