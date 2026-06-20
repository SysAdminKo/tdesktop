#pragma once

#include "mtproto/core_types.h"
#include "mtproto/mtproto_dc_options.h"
#include "mtproto/mtproto_proxy_data.h"

#include <functional>
#include <optional>

#include <QtCore/QByteArray>

namespace MTP {

class WssEndpointCache {
public:
	struct Entry {
		QString ip;
		int port = 0;
		bytes::vector secret;
		DcOptions::Variants::Protocol protocol = DcOptions::Variants::Tcp;
	};

	[[nodiscard]] static std::optional<Entry> lookup(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy,
		const QString &accountScope);

	static void store(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy,
		const QString &accountScope,
		const QString &ip,
		int port,
		const bytes::vector &secret,
		DcOptions::Variants::Protocol protocol);

	static void clear(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy,
		const QString &accountScope);

	static void markRejected(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy,
		const QString &accountScope,
		const Entry &entry);

	[[nodiscard]] static bool isRejected(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy,
		const QString &accountScope,
		const Entry &entry);

	[[nodiscard]] static bool clearRejected(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy,
		const QString &accountScope);

	struct Persistence {
		std::function<std::optional<QByteArray>(const QByteArray &prefKey)> read;
		std::function<void(const QByteArray &prefKey, const QByteArray &value)> write;
		std::function<void(const QByteArray &prefKey)> remove;
	};

	static void SetPersistence(Persistence persistence);

private:
	WssEndpointCache() = delete;
};

} // namespace MTP
