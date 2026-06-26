#pragma once

#include "base/basic_types.h"

namespace MTP {

class WssConnectGate {
public:
	static void SetLimit(int limit);
	[[nodiscard]] static bool tryAcquire(Fn<void()> &&whenAvailable);
	static void release();
	static void Clear();

private:
	WssConnectGate() = delete;
};

} // namespace MTP
