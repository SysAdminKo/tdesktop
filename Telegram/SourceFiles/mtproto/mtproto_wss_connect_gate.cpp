#include "mtproto/mtproto_wss_connect_gate.h"

#include <deque>

#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>

namespace MTP {
namespace {

constexpr auto kMaxConcurrentWssConnects = 6;

QMutex Mutex;
int Active = 0;
std::deque<Fn<void()>> Waiting;

} // namespace

bool WssConnectGate::tryAcquire(Fn<void()> &&whenAvailable) {
	QMutexLocker lock(&Mutex);
	if (Active < kMaxConcurrentWssConnects) {
		++Active;
		return true;
	}
	Waiting.push_back(std::move(whenAvailable));
	return false;
}

void WssConnectGate::release() {
	Fn<void()> next;
	{
		QMutexLocker lock(&Mutex);
		if (Active > 0) {
			--Active;
		}
		if (!Waiting.empty()) {
			next = std::move(Waiting.front());
			Waiting.pop_front();
		}
	}
	if (next) {
		next();
	}
}

void WssConnectGate::Clear() {
	QMutexLocker lock(&Mutex);
	Active = 0;
	Waiting.clear();
}

} // namespace MTP
