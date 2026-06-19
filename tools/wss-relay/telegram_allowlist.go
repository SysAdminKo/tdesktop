package main

import (
	_ "embed"
	"fmt"
	"net"
	"strings"
)

//go:embed telegram_cidrs.txt
var telegramCIDRsFile string

type telegramUpstreamAllowlist struct {
	nets    []*net.IPNet
	enabled bool
}

func newTelegramUpstreamAllowlist(enabled bool) (*telegramUpstreamAllowlist, error) {
	allowlist := &telegramUpstreamAllowlist{enabled: enabled}
	if !enabled {
		return allowlist, nil
	}
	for _, line := range strings.Split(telegramCIDRsFile, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("parse telegram cidr %q: %w", line, err)
		}
		allowlist.nets = append(allowlist.nets, network)
	}
	if len(allowlist.nets) == 0 {
		return nil, fmt.Errorf("telegram cidr list is empty")
	}
	return allowlist, nil
}

func (a *telegramUpstreamAllowlist) contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range a.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *telegramUpstreamAllowlist) allowsHost(host string) (bool, error) {
	if !a.enabled {
		return true, nil
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false, nil
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if ip := net.ParseIP(host); ip != nil {
		return a.contains(ip), nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false, err
	}
	if len(ips) == 0 {
		return false, nil
	}
	for _, ip := range ips {
		if !a.contains(ip) {
			return false, nil
		}
	}
	return true, nil
}

func (a *telegramUpstreamAllowlist) allowsAddress(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, err
	}
	return a.allowsHost(host)
}

func (a *telegramUpstreamAllowlist) verifyPeer(conn net.Conn) error {
	if !a.enabled || conn == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return fmt.Errorf("upstream peer address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !a.contains(ip) {
		return fmt.Errorf("upstream peer not allowed: %s", host)
	}
	return nil
}
