#pragma once

#include "base/basic_types.h"
#include "base/bytes.h"

#include <memory>

#include <QtCore/QObject>
#include <vector>

namespace MTP {
struct ProxyData;
namespace details {
class AbstractSocket;
class MuxStreamSocket;
} // namespace details

class WssMuxHub final : public QObject {
public:
	static WssMuxHub &Instance();

	static void SetAuthRejectedHandler(Fn<void()> handler);

	void Configure(const ProxyData &proxy, int tunnelCount);
	void ApplyResolvedIps(
		const QString &host,
		const std::vector<QString> &ips);
	void EnsureStarted();
	void Bootstrap(const ProxyData &proxy);
	void UpdateFromAppSettings(
		bool enabled,
		const ProxyData &selected,
		FnMut<void()> &&done = nullptr);
	[[nodiscard]] std::vector<int> TunnelStreamCounts() const;
	void SetProxyActive(bool active);
	void StopTunnels();
	void Shutdown();

	[[nodiscard]] std::unique_ptr<details::AbstractSocket> AcquireStream(
		not_null<QThread*> thread,
		const QString &host,
		int port,
		bool protocolForFiles,
		int tunnelAffinity = -1);

	void BeginProxyCheck(const ProxyData &proxy);
	void EndProxyCheck(const ProxyData &proxy);
	[[nodiscard]] std::unique_ptr<details::AbstractSocket> AcquireCheckStream(
		not_null<QThread*> thread,
		const ProxyData &proxy,
		const QString &host,
		int port,
		bool protocolForFiles,
		int tunnelAffinity = -1);

	void RegisterStream(
		uint32 streamId,
		not_null<details::MuxStreamSocket*> socket);
	void UnregisterStream(uint32 streamId);

	void RequestOpen(
		uint32 streamId,
		const QString &host,
		int port);
	void SendData(uint32 streamId, bytes::const_span data);
	void RequestClose(uint32 streamId);

private:
	WssMuxHub();
	~WssMuxHub();

	struct Private;
	const std::unique_ptr<Private> _private;

};

} // namespace MTP
