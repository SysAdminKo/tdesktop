/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtNetwork/QNetworkProxy>

namespace MTP {

struct ProxyData {
	enum class Settings {
		System,
		Enabled,
		Disabled,
	};
	enum class Type {
		None,
		Socks5,
		Http,
		Mtproto,
	};
	enum class Status {
		Valid,
		Unsupported,
		IncorrectSecret,
		Invalid,
	};
	enum class CHelloType
	{
		Firefox, // JA3 & JA4 matches FF 151
		Chrome, // Chrome, vanilla default
		Custom,
		SafariMac, // Safari macOS 26.4 (with grease/alpn randomization)
		YandexGost, // Yandex Browser with GOST cipher suites
		RANDOM
	};

	Type type = Type::None;
	QString host;
	uint32 port = 0;
	QString user, password;

	std::vector<QString> resolvedIPs;
	crl::time resolvedExpireAt = 0;

	[[nodiscard]] bool valid() const;
	[[nodiscard]] Status status() const;
	[[nodiscard]] bool supportsCalls() const;
	[[nodiscard]] bool tryCustomResolve() const;
	[[nodiscard]] bytes::vector secretFromMtprotoPassword() const;
	[[nodiscard]] explicit operator bool() const;
	[[nodiscard]] bool operator==(const ProxyData &other) const;
	[[nodiscard]] bool operator!=(const ProxyData &other) const;

	[[nodiscard]] static bool ValidMtprotoPassword(const QString &password);
	[[nodiscard]] static Status MtprotoPasswordStatus(
		const QString &password);

	static void setGlobalClienHelloRulesType(const ProxyData::CHelloType ch_type);
	[[nodiscard]] static ProxyData::CHelloType globalClienHelloRulesType();

	static void setGlobalSlowMode(bool value);
	[[nodiscard]] static bool globalSlowMode();

	static void setGlobalSlowDelay(int value);
	[[nodiscard]] static int globalSlowDelay();

	static void setGlobalSlowJitter(int value);
	[[nodiscard]] static int globalSlowJitter();

private:
	static ProxyData::CHelloType global_ch_type;
	static bool global_slow_mode;
	static int global_slow_delay;
	static int global_slow_jitter;
};

[[nodiscard]] ProxyData ToDirectIpProxy(
	const ProxyData &proxy,
	int ipIndex = 0);
[[nodiscard]] QNetworkProxy ToNetworkProxy(const ProxyData &proxy);

} // namespace MTP
