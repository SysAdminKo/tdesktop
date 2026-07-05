package main

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

var (
	egressBindMu      sync.RWMutex
	allowedEgressIPs  map[string]struct{}
)

func setAllowedEgressIPs(raw string) {
	egressBindMu.Lock()
	defer egressBindMu.Unlock()
	allowedEgressIPs = nil
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	parts := strings.Split(raw, ",")
	allowedEgressIPs = make(map[string]struct{}, len(parts))
	for _, part := range parts {
		ip := strings.TrimSpace(part)
		if parsed := net.ParseIP(ip); parsed != nil {
			allowedEgressIPs[parsed.String()] = struct{}{}
		}
	}
}

func egressIPFromRequest(r *http.Request) string {
	for _, header := range []string{
		"X-Relay-Local-IP",
		"X-Relay-Egress-IP",
	} {
		if ip := parseClientIP(strings.TrimSpace(r.Header.Get(header))); ip != "" {
			return normalizeEgressIP(ip)
		}
	}
	return ""
}

func normalizeEgressIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func isAllowedEgressIP(ip string) bool {
	normalized := normalizeEgressIP(ip)
	if normalized == "" {
		return false
	}
	egressBindMu.RLock()
	defer egressBindMu.RUnlock()
	if len(allowedEgressIPs) == 0 {
		return true
	}
	_, ok := allowedEgressIPs[normalized]
	return ok
}

func resolveEgressIP(requested string) string {
	normalized := normalizeEgressIP(requested)
	if normalized == "" {
		return ""
	}
	if !isAllowedEgressIP(normalized) {
		log.Printf("egress bind rejected: %s not in allowlist", normalized)
		return ""
	}
	return normalized
}
