#include "mtproto/mtproto_wss_endpoint_persist.h"

#include "core/application.h"
#include "core/core_settings.h"
#include "mtproto/mtproto_wss_endpoint_cache.h"

namespace MTP {
namespace {

[[nodiscard]] WssEndpointCache::Persistence MakeEndpointPersistence() {
	return {
		.read = [](const QByteArray &prefKey) {
			return Core::App().settings().readPrefBytes(prefKey.constData());
		},
		.write = [](const QByteArray &prefKey, const QByteArray &value) {
			Core::App().settings().writePrefBytes(prefKey.constData(), value);
		},
		.remove = [](const QByteArray &prefKey) {
			Core::App().settings().clearPref(prefKey.constData());
		},
	};
}

} // namespace

void RegisterWssEndpointCachePersistence() {
	static auto registered = false;
	if (registered) {
		return;
	}
	registered = true;
	WssEndpointCache::SetPersistence(MakeEndpointPersistence());
}

} // namespace MTP
