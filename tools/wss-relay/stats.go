package main

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type relayStats struct {
	mu        sync.RWMutex
	startedAt time.Time

	muxTunnels int
	muxStreams int

	clients   map[string]*clientStats
	upstreams map[string]int

	muxTunnelsTotal  atomic.Int64
	muxStreamsOpened atomic.Int64
	muxStreamsClosed atomic.Int64
	bytesToUpstream     atomic.Int64
	bytesFromUpstream   atomic.Int64
	upstreamDialErrors  atomic.Int64
	upstreamBlocked     atomic.Int64
	tunnelLimitRejected atomic.Int64
	muxOpenBad          atomic.Int64
	muxOpenLimit        atomic.Int64
}

type clientStats struct {
	activeTunnels     int
	activeStreams     int
	bytesToUpstream   int64
	bytesFromUpstream int64
}

type clientSnapshot struct {
	IP                string `json:"ip"`
	ActiveTunnels     int    `json:"active_tunnels"`
	ActiveStreams     int    `json:"active_streams"`
	BytesToUpstream   int64  `json:"bytes_to_upstream"`
	BytesFromUpstream int64  `json:"bytes_from_upstream"`
}

type upstreamSnapshot struct {
	Target        string `json:"target"`
	ActiveStreams int    `json:"active_streams"`
}

type statsSnapshot struct {
	Now                 string             `json:"now"`
	UptimeSec           float64            `json:"uptime_sec"`
	MuxTunnels       int                `json:"mux_tunnels"`
	MuxStreams       int                `json:"mux_streams"`
	MuxTunnelsTotal  int64              `json:"mux_tunnels_total"`
	MuxStreamsOpened int64              `json:"mux_streams_opened"`
	MuxStreamsClosed int64              `json:"mux_streams_closed"`
	BytesToUpstream     int64              `json:"bytes_to_upstream"`
	BytesFromUpstream   int64              `json:"bytes_from_upstream"`
	UpstreamDialErrors  int64              `json:"upstream_dial_errors"`
	UpstreamBlocked     int64              `json:"upstream_blocked"`
	TunnelLimitRejected int64              `json:"tunnel_limit_rejected"`
	MuxOpenBad          int64              `json:"mux_open_bad"`
	MuxOpenLimit        int64              `json:"mux_open_limit"`
	Clients             []clientSnapshot   `json:"clients"`
	Upstreams           []upstreamSnapshot `json:"upstreams"`
}

var relayStatistics = newRelayStats()

func newRelayStats() *relayStats {
	return &relayStats{
		startedAt: time.Now(),
		clients:   make(map[string]*clientStats),
		upstreams: make(map[string]int),
	}
}

func (s *relayStats) client(clientIP string) *clientStats {
	if clientIP == "" {
		clientIP = "unknown"
	}
	entry, ok := s.clients[clientIP]
	if !ok {
		entry = &clientStats{}
		s.clients[clientIP] = entry
	}
	return entry
}

func (s *relayStats) muxTunnelOpened(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.muxTunnels++
	s.client(clientIP).activeTunnels++
	s.muxTunnelsTotal.Add(1)
}

func (s *relayStats) muxTunnelClosed(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.muxTunnels > 0 {
		s.muxTunnels--
	}
	entry := s.client(clientIP)
	if entry.activeTunnels > 0 {
		entry.activeTunnels--
	}
	s.cleanupClientLocked(clientIP, entry)
}

func (s *relayStats) muxStreamOpened(clientIP, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.muxStreams++
	s.client(clientIP).activeStreams++
	if target != "" {
		s.upstreams[target]++
	}
	s.muxStreamsOpened.Add(1)
}

func (s *relayStats) muxStreamClosed(clientIP, target string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.muxStreams > 0 {
		s.muxStreams--
	}
	entry := s.client(clientIP)
	if entry.activeStreams > 0 {
		entry.activeStreams--
	}
	if target != "" {
		if count := s.upstreams[target] - 1; count <= 0 {
			delete(s.upstreams, target)
		} else {
			s.upstreams[target] = count
		}
	}
	s.cleanupClientLocked(clientIP, entry)
	s.muxStreamsClosed.Add(1)
}

func (s *relayStats) cleanupClientLocked(clientIP string, entry *clientStats) {
	if entry.activeTunnels == 0 &&
		entry.activeStreams == 0 &&
		entry.bytesToUpstream == 0 &&
		entry.bytesFromUpstream == 0 {
		delete(s.clients, clientIP)
	}
}

func (s *relayStats) addBytesToUpstream(clientIP string, n int) {
	if n <= 0 {
		return
	}
	s.bytesToUpstream.Add(int64(n))
	s.mu.Lock()
	s.client(clientIP).bytesToUpstream += int64(n)
	s.mu.Unlock()
}

func (s *relayStats) addBytesFromUpstream(clientIP string, n int) {
	if n <= 0 {
		return
	}
	s.bytesFromUpstream.Add(int64(n))
	s.mu.Lock()
	s.client(clientIP).bytesFromUpstream += int64(n)
	s.mu.Unlock()
}

func (s *relayStats) incUpstreamDialError() {
	s.upstreamDialErrors.Add(1)
}

func (s *relayStats) incUpstreamBlocked() {
	s.upstreamBlocked.Add(1)
}

func (s *relayStats) incTunnelLimitRejected() {
	s.tunnelLimitRejected.Add(1)
}

func (s *relayStats) incMuxOpenBad() {
	s.muxOpenBad.Add(1)
}

func (s *relayStats) incMuxOpenLimit() {
	s.muxOpenLimit.Add(1)
}

func (s *relayStats) snapshot() statsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := statsSnapshot{
		Now:                 time.Now().UTC().Format(time.RFC3339),
		UptimeSec:           time.Since(s.startedAt).Seconds(),
		MuxTunnels:          s.muxTunnels,
		MuxStreams:          s.muxStreams,
		MuxTunnelsTotal:     s.muxTunnelsTotal.Load(),
		MuxStreamsOpened:    s.muxStreamsOpened.Load(),
		MuxStreamsClosed:    s.muxStreamsClosed.Load(),
		BytesToUpstream:     s.bytesToUpstream.Load(),
		BytesFromUpstream:   s.bytesFromUpstream.Load(),
		UpstreamDialErrors:  s.upstreamDialErrors.Load(),
		UpstreamBlocked:     s.upstreamBlocked.Load(),
		TunnelLimitRejected: s.tunnelLimitRejected.Load(),
		MuxOpenBad:          s.muxOpenBad.Load(),
		MuxOpenLimit:        s.muxOpenLimit.Load(),
		Clients:             make([]clientSnapshot, 0, len(s.clients)),
		Upstreams:           make([]upstreamSnapshot, 0, len(s.upstreams)),
	}
	for ip, client := range s.clients {
		result.Clients = append(result.Clients, clientSnapshot{
			IP:                ip,
			ActiveTunnels:     client.activeTunnels,
			ActiveStreams:     client.activeStreams,
			BytesToUpstream:   client.bytesToUpstream,
			BytesFromUpstream: client.bytesFromUpstream,
		})
	}
	for target, count := range s.upstreams {
		result.Upstreams = append(result.Upstreams, upstreamSnapshot{
			Target:        target,
			ActiveStreams: count,
		})
	}
	sort.Slice(result.Clients, func(i, j int) bool {
		if result.Clients[i].ActiveStreams == result.Clients[j].ActiveStreams {
			return result.Clients[i].ActiveTunnels > result.Clients[j].ActiveTunnels
		}
		return result.Clients[i].ActiveStreams > result.Clients[j].ActiveStreams
	})
	sort.Slice(result.Upstreams, func(i, j int) bool {
		return result.Upstreams[i].ActiveStreams > result.Upstreams[j].ActiveStreams
	})
	return result
}
