#pragma once

#include "mtproto/details/mtproto_abstract_socket.h"

#include <QtCore/QTimer>

namespace MTP {

class WssMuxHub;

namespace details {

class MuxStreamSocket final : public AbstractSocket {
public:
	MuxStreamSocket(
		not_null<QThread*> thread,
		not_null<WssMuxHub*> hub);
	~MuxStreamSocket();

	void connectToHost(const QString &address, int port) override;
	bool isGoodStartNonce(bytes::const_span nonce) override;
	void timedOut() override;
	bool isConnected() override;
	bool hasBytesAvailable() override;
	int64 read(bytes::span buffer) override;
	void write(bytes::const_span prefix, bytes::const_span buffer) override;

	int32 debugState() override;
	QString debugPostfix() const override;

	void handleOpenOk();
	void handleOpenFail();
	void handleData(bytes::vector data);
	void handleRemoteClose();
	void handleTunnelDown();

	void setStreamId(uint32 streamId);
	[[nodiscard]] uint32 streamId() const;
	void invokeQueued(Fn<void()> &&fn);

private:
	enum class State {
		NotConnected,
		Opening,
		Connected,
		Error,
	};

	void failOpen();
	void sendClose();

	const not_null<WssMuxHub*> _hub;
	uint32 _streamId = 0;
	State _state = State::NotConnected;
	QString _host;
	int _port = 0;
	bytes::vector _readBuffer;
	int _readOffset = 0;
	bool _inRead = false;
	bool _readyReadScheduled = false;
	QTimer _openTimer;

};

} // namespace details
} // namespace MTP
