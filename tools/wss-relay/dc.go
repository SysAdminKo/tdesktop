package main

import (
	"net"
	"strings"
)

type dcRange struct {
	network *net.IPNet
	label   string
}

// Telegram production DCs share /24 subnets between pairs (DC1/DC3 in Miami,
// DC2/DC4 in Amsterdam), so a single upstream IP cannot be resolved to one
// exact DC number. The label therefore identifies the subnet's DC group and
// region rather than a unique DC id.
var dcRanges = buildDcRanges([]struct {
	cidr  string
	label string
}{
	{"149.154.175.0/24", "DC1/3 Miami"},
	{"149.154.167.0/24", "DC2/4 Amsterdam"},
	{"95.161.76.0/24", "DC2 Amsterdam"},
	{"149.154.171.0/24", "DC5 Singapore"},
	{"91.108.56.0/22", "DC5 Singapore"},
	{"149.154.164.0/22", "Telegram media"},
	{"91.108.4.0/22", "Telegram"},
	{"91.108.8.0/22", "Telegram"},
	{"91.108.12.0/22", "Telegram"},
	{"91.108.16.0/22", "Telegram"},
	{"91.108.20.0/22", "Telegram"},
	{"91.105.192.0/23", "Telegram"},
	{"185.76.151.0/24", "Telegram"},
	{"2001:b28:f23d::/48", "DC1/3 Miami"},
	{"2001:67c:4e8::/48", "DC2/4 Amsterdam"},
	{"2001:b28:f23f::/48", "DC5 Singapore"},
	{"2001:b28:f23c::/48", "Telegram"},
	{"2a0a:f280::/32", "Telegram"},
})

func buildDcRanges(entries []struct {
	cidr  string
	label string
}) []dcRange {
	result := make([]dcRange, 0, len(entries))
	for _, entry := range entries {
		_, network, err := net.ParseCIDR(entry.cidr)
		if err != nil {
			continue
		}
		result = append(result, dcRange{network: network, label: entry.label})
	}
	return result
}

func dcLabelForTarget(target string) string {
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	for _, entry := range dcRanges {
		if entry.network.Contains(ip) {
			return entry.label
		}
	}
	return ""
}
