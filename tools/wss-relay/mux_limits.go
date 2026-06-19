package main

import "sync"

type muxTunnelLimiter struct {
	maxPerIP int
	counts   map[string]int
	mu       sync.Mutex
}

func newMuxTunnelLimiter(maxPerIP int) *muxTunnelLimiter {
	if maxPerIP <= 0 {
		return nil
	}
	return &muxTunnelLimiter{
		maxPerIP: maxPerIP,
		counts:   make(map[string]int),
	}
}

func (l *muxTunnelLimiter) tryAcquire(clientIP string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[clientIP] >= l.maxPerIP {
		return false
	}
	l.counts[clientIP]++
	return true
}

func (l *muxTunnelLimiter) release(clientIP string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	count := l.counts[clientIP] - 1
	if count <= 0 {
		delete(l.counts, clientIP)
		return
	}
	l.counts[clientIP] = count
}
