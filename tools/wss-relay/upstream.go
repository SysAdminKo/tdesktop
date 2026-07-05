package main

import (
	"fmt"
	"log"
	"net"
)

var telegramAllowlist *telegramUpstreamAllowlist

func dialUpstream(addr, clientIP, egressIP string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if telegramAllowlist != nil {
		allowed, allowErr := telegramAllowlist.allowsHost(host)
		if allowErr != nil {
			return nil, fmt.Errorf("upstream lookup %s: %w", host, allowErr)
		}
		if !allowed {
			relayStatistics.incUpstreamBlocked(clientIP)
			return nil, fmt.Errorf("upstream not allowed: %s", host)
		}
	}
	dialer := net.Dialer{}
	if egressIP = resolveEgressIP(egressIP); egressIP != "" {
		dialer.LocalAddr = &net.TCPAddr{
			IP:   net.ParseIP(egressIP),
			Port: 0,
		}
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		relayStatistics.incUpstreamDialError(addr)
		return nil, err
	}
	if telegramAllowlist != nil {
		if verifyErr := telegramAllowlist.verifyPeer(conn); verifyErr != nil {
			_ = conn.Close()
			relayStatistics.incUpstreamBlocked(clientIP)
			return nil, verifyErr
		}
	}
	tuneTCP(conn)
	return conn, nil
}

func rejectDisallowedUpstream(addr string) error {
	if telegramAllowlist == nil || !telegramAllowlist.enabled {
		return nil
	}
	allowed, err := telegramAllowlist.allowsAddress(addr)
	if err != nil {
		log.Printf("upstream allowlist check failed for %s: %v", addr, err)
		return fmt.Errorf("upstream lookup failed")
	}
	if !allowed {
		log.Printf("upstream blocked by telegram allowlist: %s", addr)
		relayStatistics.incUpstreamBlocked("")
		return fmt.Errorf("upstream not allowed")
	}
	return nil
}
