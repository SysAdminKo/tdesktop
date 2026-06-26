#include "mtproto/mtproto_wss_connect_gate.h"

#include <deque>

#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>

namespace MTP {
namespace {

constexpr auto kDefaultMaxConcurrentWssConnects = 9;

QMutex Mutex;
int MaxConcurrent = kDefaultMaxConcurrentWssConnects;
int Active = 0;
std::deque<Fn<void()>> Waiting;

} // namespace

void WssConnectGate::SetLimit(int limit) {
	QMutexLocker lock(&Mutex);
	MaxConcurrent = std::max(1, limit);
}

bool WssConnectGate::tryAcquire(Fn<void()> &&whenAvailable) {
	QMutexLocker lock(&Mutex);
	if (Active < MaxConcurrent) {
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
