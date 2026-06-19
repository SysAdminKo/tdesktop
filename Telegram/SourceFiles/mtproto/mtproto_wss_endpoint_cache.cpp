#include "mtproto/mtproto_wss_endpoint_cache.h"

#include <functional>
#include <map>
#include <optional>
#include <tuple>

#include <QtCore/QDataStream>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>

namespace MTP {
namespace {

struct Key {
	ShiftedDcId shiftedDcId = 0;
	DcType dcType = DcType::Regular;
	QString proxyHost;
	uint32 proxyPort = 0;
	QString proxyPath;

	friend bool operator<(const Key &a, const Key &b) {
		return std::tie(
			a.shiftedDcId,
			a.dcType,
			a.proxyHost,
			a.proxyPort,
			a.proxyPath) < std::tie(
			b.shiftedDcId,
			b.dcType,
			b.proxyHost,
			b.proxyPort,
			b.proxyPath);
	}
};

QMutex Mutex;
std::map<Key, WssEndpointCache::Entry> Cache;
WssEndpointCache::Persistence PersistenceHandlers;

[[nodiscard]] QByteArray PrefKey(const Key &key) {
	auto blob = QByteArray();
	{
		QDataStream stream(&blob, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_1);
		stream
			<< qint32(key.shiftedDcId)
			<< qint32(int(key.dcType))
			<< key.proxyHost
			<< quint32(key.proxyPort)
			<< key.proxyPath;
	}
	return QByteArray("wss_ep.") + blob.toBase64(QByteArray::Base64UrlEncoding);
}

[[nodiscard]] QByteArray SerializeEntry(const WssEndpointCache::Entry &entry) {
	auto blob = QByteArray();
	QDataStream stream(&blob, QIODevice::WriteOnly);
	stream.setVersion(QDataStream::Qt_5_1);
	const auto secret = QByteArray(
		reinterpret_cast<const char*>(entry.secret.data()),
		entry.secret.size());
	stream
		<< entry.ip
		<< qint32(entry.port)
		<< qint32(int(entry.protocol))
		<< secret;
	return blob;
}

[[nodiscard]] std::optional<WssEndpointCache::Entry> DeserializeEntry(
		const QByteArray &blob) {
	QDataStream stream(blob);
	stream.setVersion(QDataStream::Qt_5_1);
	auto ip = QString();
	auto port = qint32(0);
	auto protocol = qint32(0);
	auto secret = QByteArray();
	stream >> ip >> port >> protocol >> secret;
	if (stream.status() != QDataStream::Ok || ip.isEmpty() || !port) {
		return std::nullopt;
	}
	auto result = WssEndpointCache::Entry{
		ip,
		int(port),
		bytes::make_vector(bytes::make_span(secret)),
		DcOptions::Variants::Protocol(protocol),
	};
	return result;
}

[[nodiscard]] std::optional<WssEndpointCache::Entry> LoadEntry(const Key &key) {
	if (!PersistenceHandlers.read) {
		return std::nullopt;
	}
	const auto prefKey = PrefKey(key);
	const auto blob = PersistenceHandlers.read(prefKey);
	if (!blob || blob->isEmpty()) {
		return std::nullopt;
	}
	return DeserializeEntry(*blob);
}

void SaveEntry(const Key &key, const WssEndpointCache::Entry &entry) {
	if (!PersistenceHandlers.write) {
		return;
	}
	PersistenceHandlers.write(PrefKey(key), SerializeEntry(entry));
}

void RemoveEntry(const Key &key) {
	if (!PersistenceHandlers.remove) {
		return;
	}
	PersistenceHandlers.remove(PrefKey(key));
}

[[nodiscard]] Key MakeKey(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy) {
	return {
		shiftedDcId,
		dcType,
		proxy.host,
		proxy.port,
		proxy.path,
	};
}

} // namespace

void WssEndpointCache::SetPersistence(Persistence persistence) {
	QMutexLocker lock(&Mutex);
	PersistenceHandlers = std::move(persistence);
}

std::optional<WssEndpointCache::Entry> WssEndpointCache::lookup(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy) {
	if (proxy.type != ProxyData::Type::WebSocket) {
		return std::nullopt;
	}
	const auto key = MakeKey(shiftedDcId, dcType, proxy);
	QMutexLocker lock(&Mutex);
	const auto i = Cache.find(key);
	if (i != end(Cache)) {
		return i->second;
	}
	if (const auto loaded = LoadEntry(key)) {
		Cache[key] = *loaded;
		return *loaded;
	}
	return std::nullopt;
}

void WssEndpointCache::store(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy,
		const QString &ip,
		int port,
		const bytes::vector &secret,
		DcOptions::Variants::Protocol protocol) {
	if (proxy.type != ProxyData::Type::WebSocket || ip.isEmpty() || !port) {
		return;
	}
	const auto key = MakeKey(shiftedDcId, dcType, proxy);
	const auto entry = Entry{ ip, port, secret, protocol };
	QMutexLocker lock(&Mutex);
	Cache[key] = entry;
	SaveEntry(key, entry);
}

void WssEndpointCache::clear(
		ShiftedDcId shiftedDcId,
		DcType dcType,
		const ProxyData &proxy) {
	if (proxy.type != ProxyData::Type::WebSocket) {
		return;
	}
	const auto key = MakeKey(shiftedDcId, dcType, proxy);
	QMutexLocker lock(&Mutex);
	Cache.erase(key);
	RemoveEntry(key);
}

} // namespace MTP
