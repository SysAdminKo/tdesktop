package main

import (
	"net"
	"net/http"
	"strings"
)

func parseClientIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "[") {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip.String()
			}
		}
		host := strings.Trim(raw, "[]")
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func clientIPFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		if ip := parseClientIP(v); ip != "" {
			return ip
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if ip := parseClientIP(v); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := parseClientIP(host); ip != "" {
		return ip
	}
	return host
}
