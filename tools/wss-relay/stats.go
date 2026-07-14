package main

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const latencySampleCap = 512

type relayStats struct {
	mu        sync.RWMutex
	startedAt time.Time

	muxTunnels int
	muxStreams int

	clients        map[string]*clientStats
	upstreams      map[string]*upstreamGauge
	upstreamTotals map[string]*upstreamTotals
	abuseByIP      map[string]*abuseCounters

	config statsConfigSnapshot

	rateMu              sync.Mutex
	lastRateAt          time.Time
	lastBytesToUpstream   int64
	lastBytesFromUpstream int64
	lastStreamsOpened     int64
	lastTunnelsTotal      int64
	lastClientRates       map[string]clientRateBaseline

	muxTunnelsTotal  atomic.Int64
	muxStreamsOpened atomic.Int64
	muxStreamsClosed atomic.Int64
	bytesToUpstream     atomic.Int64
	bytesFromUpstream   atomic.Int64
	upstreamDialErrors  atomic.Int64
	upstreamBlocked     atomic.Int64
	tunnelLimitRejected atomic.Int64
	muxOpenBad          atomic.Int64
	muxOpenFailDial     atomic.Int64
	muxOpenLimit        atomic.Int64
	muxStreamIdle       atomic.Int64
	muxOpenCount        atomic.Int64
	muxOpenDialMsTotal  atomic.Int64
	muxOpenDialMsMax    atomic.Int64
	muxOpenSlow              atomic.Int64
	muxUpstreamReadStall     atomic.Int64
	muxUpstreamReadStallRotate atomic.Int64
	upstreamPoolHits         atomic.Int64
	upstreamPoolMisses       atomic.Int64
	upstreamPoolDialErrors   atomic.Int64
	muxWriteWaitUsTotal      atomic.Int64
	muxWriteWaitCount        atomic.Int64
	maxMuxWriteWaitUs        atomic.Int64
	authFailures             atomic.Int64
	wsUpgradeFailures        atomic.Int64
	wsBadSubprotocol           atomic.Int64
	muxDecodeErrors          atomic.Int64
	muxUnknownFrame          atomic.Int64
	tunnelsEndedWithStreams  atomic.Int64
	peakMuxTunnels           atomic.Int64
	peakMuxStreams           atomic.Int64

	dialMsSamples    latencySamples
	writeWaitSamples latencySamples
}

type clientStats struct {
	activeTunnels     int
	activeStreams     int
	bytesToUpstream   int64
	bytesFromUpstream int64
	peakStreams       int
	peakTunnels       int
	firstSeen         time.Time
	lastActivity      time.Time
}

type clientRateBaseline struct {
	bytesToUpstream   int64
	bytesFromUpstream int64
}

type abuseCounters struct {
	authFailures        int64
	tunnelLimitRejected int64
	upstreamBlocked     int64
}

type upstreamGauge struct {
	activeStreams int
}

type upstreamTotals struct {
	bytesToUpstream   int64
	bytesFromUpstream int64
	dialErrors        int64
	openCount         int64
	dialMsTotal       int64
	poolHits          int64
	poolMisses        int64
}

type latencySamples struct {
	mu     sync.Mutex
	values []int64
}

type clientRatesSnapshot struct {
	BytesToUpstreamPerSec   float64 `json:"bytes_to_upstream_per_sec"`
	BytesFromUpstreamPerSec float64 `json:"bytes_from_upstream_per_sec"`
}

type clientSnapshot struct {
	IP                string              `json:"ip"`
	ActiveTunnels     int                 `json:"active_tunnels"`
	ActiveStreams     int                 `json:"active_streams"`
	StreamsPeak       int                 `json:"streams_peak"`
	StreamsUtilPct    int                 `json:"streams_util_pct"`
	BytesToUpstream   int64               `json:"bytes_to_upstream"`
	BytesFromUpstream int64               `json:"bytes_from_upstream"`
	Rates             clientRatesSnapshot `json:"rates"`
	FirstSeen         string              `json:"first_seen,omitempty"`
	LastActivity      string              `json:"last_activity,omitempty"`
}

type abuseSnapshot struct {
	IP                  string `json:"ip"`
	AuthFailures        int64  `json:"auth_failures"`
	TunnelLimitRejected int64  `json:"tunnel_limit_rejected"`
	UpstreamBlocked     int64  `json:"upstream_blocked"`
}

type upstreamSnapshot struct {
	Target            string `json:"target"`
	DC                string `json:"dc"`
	ActiveStreams     int    `json:"active_streams"`
	BytesToUpstream   int64  `json:"bytes_to_upstream"`
	BytesFromUpstream int64  `json:"bytes_from_upstream"`
	DialErrors        int64  `json:"dial_errors"`
	OpenCount         int64  `json:"open_count"`
	OpenDialMsAvg     int64  `json:"open_dial_ms_avg"`
	PoolHits          int64  `json:"pool_hits"`
	PoolMisses        int64  `json:"pool_misses"`
	PoolHitPct        int64  `json:"pool_hit_pct"`
}

type statsConfigSnapshot struct {
	MaxStreams           int     `json:"max_streams"`
	MaxTunnelsPerIP      int     `json:"max_tunnels_per_ip"`
	StreamIdleTimeoutSec float64 `json:"stream_idle_timeout_sec"`
	WSPingIntervalSec    float64 `json:"ws_ping_interval_sec"`
	WSReadTimeoutSec     float64 `json:"ws_read_timeout_sec"`
	TelegramOnly         bool    `json:"telegram_only"`
	AuthEnabled          bool    `json:"auth_enabled"`
}

type statsLoadSnapshot struct {
	StreamsUtilPct       int     `json:"streams_util_pct"`
	ServerStreamsUtilPct int     `json:"server_streams_util_pct"`
	StreamsCapacity      int     `json:"streams_capacity"`
	TunnelsPerIPMax      int     `json:"tunnels_per_ip_max"`
	TunnelsPerIPAvg      float64 `json:"tunnels_per_ip_avg"`
}

type statsRatesSnapshot struct {
	BytesToUpstreamPerSec   float64 `json:"bytes_to_upstream_per_sec"`
	BytesFromUpstreamPerSec float64 `json:"bytes_from_upstream_per_sec"`
	StreamsOpenedPerMin     float64 `json:"streams_opened_per_min"`
	TunnelsOpenedPerMin     float64 `json:"tunnels_opened_per_min"`
}

type statsSnapshot struct {
	Now                      string                `json:"now"`
	UptimeSec                float64               `json:"uptime_sec"`
	Config                   statsConfigSnapshot   `json:"config"`
	Control                  statsControlSnapshot  `json:"control"`
	Load                     statsLoadSnapshot     `json:"load"`
	Rates                    statsRatesSnapshot    `json:"rates"`
	MuxTunnels               int                   `json:"mux_tunnels"`
	MuxStreams               int                   `json:"mux_streams"`
	MuxTunnelsPeak           int64                 `json:"mux_tunnels_peak"`
	MuxStreamsPeak           int64                 `json:"mux_streams_peak"`
	MuxTunnelsTotal          int64                 `json:"mux_tunnels_total"`
	MuxStreamsOpened         int64                 `json:"mux_streams_opened"`
	MuxStreamsClosed         int64                 `json:"mux_streams_closed"`
	MuxStreamsClosedGraceful int64                 `json:"mux_streams_closed_graceful"`
	BytesToUpstream          int64                 `json:"bytes_to_upstream"`
	BytesFromUpstream        int64                 `json:"bytes_from_upstream"`
	UpstreamDialErrors       int64                 `json:"upstream_dial_errors"`
	UpstreamBlocked          int64                 `json:"upstream_blocked"`
	TunnelLimitRejected      int64                 `json:"tunnel_limit_rejected"`
	AuthFailures             int64                 `json:"auth_failures"`
	WSUpgradeFailures        int64                 `json:"ws_upgrade_failures"`
	WSBadSubprotocol         int64                 `json:"ws_bad_subprotocol"`
	MuxDecodeErrors          int64                 `json:"mux_decode_errors"`
	MuxUnknownFrame          int64                 `json:"mux_unknown_frame"`
	TunnelsEndedWithStreams  int64                 `json:"tunnels_ended_with_streams"`
	MuxOpenBad               int64                 `json:"mux_open_bad"`
	MuxOpenFailDial          int64                 `json:"mux_open_fail_dial"`
	MuxOpenLimit             int64                 `json:"mux_open_limit"`
	MuxStreamIdle            int64                 `json:"mux_stream_idle_expired"`
	MuxOpenCount             int64                 `json:"mux_open_count"`
	MuxOpenDialMsAvg         int64                 `json:"mux_open_dial_ms_avg"`
	MuxOpenDialMsP95         int64                 `json:"mux_open_dial_ms_p95"`
	MuxOpenDialMsMax         int64                 `json:"mux_open_dial_ms_max"`
	MuxOpenSlow              int64                 `json:"mux_open_slow"`
	MuxUpstreamReadStall       int64                 `json:"mux_upstream_read_stall"`
	MuxUpstreamReadStallRotate int64                 `json:"mux_upstream_read_stall_rotate"`
	UpstreamPoolHits         int64                 `json:"upstream_pool_hits"`
	UpstreamPoolMisses       int64                 `json:"upstream_pool_misses"`
	UpstreamPoolHitPct       int64                 `json:"upstream_pool_hit_pct"`
	UpstreamPoolDialErrors   int64                 `json:"upstream_pool_dial_errors"`
	PoolBuckets              []poolBucketSnapshot  `json:"pool_buckets"`
	MuxWriteWaitUsAvg        int64                 `json:"mux_write_wait_us_avg"`
	MuxWriteWaitUsP95        int64                 `json:"mux_write_wait_us_p95"`
	MuxWriteWaitUsMax        int64                 `json:"mux_write_wait_us_max"`
	Clients                  []clientSnapshot      `json:"clients"`
	Upstreams                []upstreamSnapshot    `json:"upstreams"`
	Abuse                    []abuseSnapshot       `json:"abuse_by_ip"`
}

var relayStatistics = newRelayStats()

func newRelayStats() *relayStats {
	return &relayStats{
		startedAt:       time.Now(),
		clients:         make(map[string]*clientStats),
		upstreams:       make(map[string]*upstreamGauge),
		upstreamTotals:  make(map[string]*upstreamTotals),
		abuseByIP:       make(map[string]*abuseCounters),
		lastClientRates: make(map[string]clientRateBaseline),
	}
}

func (s *relayStats) setConfig(config statsConfigSnapshot) {
	s.mu.Lock()
	s.config = config
	s.mu.Unlock()
}

func (s *latencySamples) add(value int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.values) < latencySampleCap {
		s.values = append(s.values, value)
		return
	}
	copy(s.values, s.values[1:])
	s.values[len(s.values)-1] = value
}

func (s *latencySamples) percentile(p float64) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.values) == 0 {
		return 0
	}
	sorted := append([]int64(nil), s.values...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	index := int(math.Ceil(p*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func bumpPeak(peak *atomic.Int64, value int) {
	for {
		current := peak.Load()
		if int64(value) <= current {
			return
		}
		if peak.CompareAndSwap(current, int64(value)) {
			return
		}
	}
}

func (s *relayStats) client(clientIP string) *clientStats {
	if clientIP == "" {
		clientIP = "unknown"
	}
	entry, ok := s.clients[clientIP]
	if !ok {
		now := time.Now()
		entry = &clientStats{
			firstSeen:    now,
			lastActivity: now,
		}
		s.clients[clientIP] = entry
	}
	return entry
}

func (s *relayStats) touchClient(entry *clientStats) {
	now := time.Now()
	if entry.firstSeen.IsZero() {
		entry.firstSeen = now
	}
	entry.lastActivity = now
}

func (s *relayStats) abuse(clientIP string) *abuseCounters {
	if clientIP == "" {
		clientIP = "unknown"
	}
	entry, ok := s.abuseByIP[clientIP]
	if !ok {
		entry = &abuseCounters{}
		s.abuseByIP[clientIP] = entry
	}
	return entry
}

func bumpClientPeak(value *int, active int) {
	if active > *value {
		*value = active
	}
}

func (s *relayStats) upstreamTotal(target string) *upstreamTotals {
	if target == "" {
		return nil
	}
	entry, ok := s.upstreamTotals[target]
	if !ok {
		entry = &upstreamTotals{}
		s.upstreamTotals[target] = entry
	}
	return entry
}

func (s *relayStats) muxTunnelOpened(clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.muxTunnels++
	entry := s.client(clientIP)
	entry.activeTunnels++
	s.touchClient(entry)
	bumpClientPeak(&entry.peakTunnels, entry.activeTunnels)
	s.muxTunnelsTotal.Add(1)
	bumpPeak(&s.peakMuxTunnels, s.muxTunnels)
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
	entry := s.client(clientIP)
	entry.activeStreams++
	s.touchClient(entry)
	bumpClientPeak(&entry.peakStreams, entry.activeStreams)
	if target != "" {
		gauge, ok := s.upstreams[target]
		if !ok {
			gauge = &upstreamGauge{}
			s.upstreams[target] = gauge
		}
		gauge.activeStreams++
	}
	s.muxStreamsOpened.Add(1)
	bumpPeak(&s.peakMuxStreams, s.muxStreams)
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
		if gauge := s.upstreams[target]; gauge != nil {
			if gauge.activeStreams > 0 {
				gauge.activeStreams--
			}
			if gauge.activeStreams <= 0 {
				delete(s.upstreams, target)
			}
		}
	}
	s.cleanupClientLocked(clientIP, entry)
	s.muxStreamsClosed.Add(1)
}

func (s *relayStats) cleanupClientLocked(clientIP string, entry *clientStats) {
	if entry.activeTunnels == 0 && entry.activeStreams == 0 {
		delete(s.clients, clientIP)
	}
}

func (s *relayStats) addBytesToUpstream(clientIP, target string, n int) {
	if n <= 0 {
		return
	}
	s.bytesToUpstream.Add(int64(n))
	s.mu.Lock()
	entry := s.client(clientIP)
	entry.bytesToUpstream += int64(n)
	s.touchClient(entry)
	if total := s.upstreamTotal(target); total != nil {
		total.bytesToUpstream += int64(n)
	}
	s.mu.Unlock()
}

func (s *relayStats) addBytesFromUpstream(clientIP, target string, n int) {
	if n <= 0 {
		return
	}
	s.bytesFromUpstream.Add(int64(n))
	s.mu.Lock()
	entry := s.client(clientIP)
	entry.bytesFromUpstream += int64(n)
	s.touchClient(entry)
	if total := s.upstreamTotal(target); total != nil {
		total.bytesFromUpstream += int64(n)
	}
	s.mu.Unlock()
}

func (s *relayStats) incUpstreamDialError(target string) {
	s.upstreamDialErrors.Add(1)
	s.mu.Lock()
	if total := s.upstreamTotal(target); total != nil {
		total.dialErrors++
	}
	s.mu.Unlock()
}

func (s *relayStats) incUpstreamBlocked(clientIP string) {
	s.upstreamBlocked.Add(1)
	if clientIP == "" {
		return
	}
	s.mu.Lock()
	s.abuse(clientIP).upstreamBlocked++
	s.mu.Unlock()
}

func (s *relayStats) incTunnelLimitRejected(clientIP string) {
	s.tunnelLimitRejected.Add(1)
	s.mu.Lock()
	s.abuse(clientIP).tunnelLimitRejected++
	s.mu.Unlock()
}

func (s *relayStats) incAuthFailure(clientIP string) {
	s.authFailures.Add(1)
	s.mu.Lock()
	s.abuse(clientIP).authFailures++
	s.mu.Unlock()
}

func (s *relayStats) incWSUpgradeFailure() {
	s.wsUpgradeFailures.Add(1)
}

func (s *relayStats) incWSBadSubprotocol() {
	s.wsBadSubprotocol.Add(1)
}

func (s *relayStats) incMuxDecodeError() {
	s.muxDecodeErrors.Add(1)
}

func (s *relayStats) incMuxUnknownFrame() {
	s.muxUnknownFrame.Add(1)
}

func (s *relayStats) incTunnelEndedWithStreams() {
	s.tunnelsEndedWithStreams.Add(1)
}

func (s *relayStats) incMuxOpenBad() {
	s.muxOpenBad.Add(1)
}

func (s *relayStats) incMuxOpenFailDial() {
	s.muxOpenFailDial.Add(1)
}

func (s *relayStats) incMuxOpenLimit() {
	s.muxOpenLimit.Add(1)
}

func (s *relayStats) incMuxStreamIdle() {
	s.muxStreamIdle.Add(1)
}

func (s *relayStats) incMuxUpstreamReadStall() {
	s.muxUpstreamReadStall.Add(1)
}

func (s *relayStats) incMuxUpstreamReadStallRotate() {
	s.muxUpstreamReadStallRotate.Add(1)
}

func (s *relayStats) incUpstreamPoolHit(target string) {
	s.upstreamPoolHits.Add(1)
	if target == "" {
		return
	}
	s.mu.Lock()
	if total := s.upstreamTotal(target); total != nil {
		total.poolHits++
	}
	s.mu.Unlock()
}

func (s *relayStats) incUpstreamPoolMiss(target string) {
	s.upstreamPoolMisses.Add(1)
	if target == "" {
		return
	}
	s.mu.Lock()
	if total := s.upstreamTotal(target); total != nil {
		total.poolMisses++
	}
	s.mu.Unlock()
}

func (s *relayStats) incUpstreamPoolDialError() {
	s.upstreamPoolDialErrors.Add(1)
}

func (s *relayStats) incMuxWriteWait(dur time.Duration) {
	us := dur.Microseconds()
	s.muxWriteWaitUsTotal.Add(us)
	s.muxWriteWaitCount.Add(1)
	s.writeWaitSamples.add(us)
	for {
		current := s.maxMuxWriteWaitUs.Load()
		if us <= current {
			break
		}
		if s.maxMuxWriteWaitUs.CompareAndSwap(current, us) {
			break
		}
	}
}

func (s *relayStats) recordMuxOpenDial(target string, dialMs int64) {
	s.muxOpenCount.Add(1)
	s.muxOpenDialMsTotal.Add(dialMs)
	s.dialMsSamples.add(dialMs)
	s.mu.Lock()
	if total := s.upstreamTotal(target); total != nil {
		total.openCount++
		total.dialMsTotal += dialMs
	}
	s.mu.Unlock()
	for {
		current := s.muxOpenDialMsMax.Load()
		if dialMs <= current {
			break
		}
		if s.muxOpenDialMsMax.CompareAndSwap(current, dialMs) {
			break
		}
	}
	if dialMs > 100 {
		s.muxOpenSlow.Add(1)
	}
}

func (s *relayStats) snapshot() statsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	bytesToUpstream := s.bytesToUpstream.Load()
	bytesFromUpstream := s.bytesFromUpstream.Load()
	streamsOpened := s.muxStreamsOpened.Load()
	tunnelsTotal := s.muxTunnelsTotal.Load()

	result := statsSnapshot{
		Now:                 now.UTC().Format(time.RFC3339),
		UptimeSec:           now.Sub(s.startedAt).Seconds(),
		Config:              s.config,
		Control: statsControlSnapshot{
			RestartEnabled: true,
			AuthRequired:   s.config.AuthEnabled,
		},
		MuxTunnels:          s.muxTunnels,
		MuxStreams:          s.muxStreams,
		MuxTunnelsPeak:      s.peakMuxTunnels.Load(),
		MuxStreamsPeak:      s.peakMuxStreams.Load(),
		MuxTunnelsTotal:     tunnelsTotal,
		MuxStreamsOpened:    streamsOpened,
		MuxStreamsClosed:    s.muxStreamsClosed.Load(),
		BytesToUpstream:     bytesToUpstream,
		BytesFromUpstream:   bytesFromUpstream,
		UpstreamDialErrors:  s.upstreamDialErrors.Load(),
		UpstreamBlocked:     s.upstreamBlocked.Load(),
		TunnelLimitRejected: s.tunnelLimitRejected.Load(),
		AuthFailures:        s.authFailures.Load(),
		WSUpgradeFailures:   s.wsUpgradeFailures.Load(),
		WSBadSubprotocol:    s.wsBadSubprotocol.Load(),
		MuxDecodeErrors:     s.muxDecodeErrors.Load(),
		MuxUnknownFrame:     s.muxUnknownFrame.Load(),
		TunnelsEndedWithStreams: s.tunnelsEndedWithStreams.Load(),
		MuxOpenBad:          s.muxOpenBad.Load(),
		MuxOpenFailDial:     s.muxOpenFailDial.Load(),
		MuxOpenLimit:        s.muxOpenLimit.Load(),
		MuxStreamIdle:       s.muxStreamIdle.Load(),
		Clients:             make([]clientSnapshot, 0, len(s.clients)),
		Upstreams:           make([]upstreamSnapshot, 0, len(s.upstreamTotals)),
		Abuse:               make([]abuseSnapshot, 0, len(s.abuseByIP)),
	}
	openCount := s.muxOpenCount.Load()
	result.MuxOpenCount = openCount
	result.MuxOpenDialMsMax = s.muxOpenDialMsMax.Load()
	result.MuxOpenDialMsP95 = s.dialMsSamples.percentile(0.95)
	result.MuxOpenSlow = s.muxOpenSlow.Load()
	result.MuxUpstreamReadStall = s.muxUpstreamReadStall.Load()
	result.MuxUpstreamReadStallRotate = s.muxUpstreamReadStallRotate.Load()
	poolHits := s.upstreamPoolHits.Load()
	poolMisses := s.upstreamPoolMisses.Load()
	result.UpstreamPoolHits = poolHits
	result.UpstreamPoolMisses = poolMisses
	result.UpstreamPoolDialErrors = s.upstreamPoolDialErrors.Load()
	if total := poolHits + poolMisses; total > 0 {
		result.UpstreamPoolHitPct = poolHits * 100 / total
	}
	if upstreamConnPool != nil {
		result.PoolBuckets = upstreamConnPool.snapshotBuckets()
	}
	waitCount := s.muxWriteWaitCount.Load()
	if waitCount > 0 {
		result.MuxWriteWaitUsAvg = s.muxWriteWaitUsTotal.Load() / waitCount
		result.MuxWriteWaitUsMax = s.maxMuxWriteWaitUs.Load()
		result.MuxWriteWaitUsP95 = s.writeWaitSamples.percentile(0.95)
	}
	if openCount > 0 {
		result.MuxOpenDialMsAvg = s.muxOpenDialMsTotal.Load() / openCount
	}
	closed := result.MuxStreamsClosed
	idle := result.MuxStreamIdle
	if closed >= idle {
		result.MuxStreamsClosedGraceful = closed - idle
	}

	if s.muxTunnels > 0 && s.config.MaxStreams > 0 {
		capacity := s.muxTunnels * s.config.MaxStreams
		if capacity > 0 {
			util := s.muxStreams * 100 / capacity
			result.Load.StreamsCapacity = capacity
			result.Load.StreamsUtilPct = util
			result.Load.ServerStreamsUtilPct = util
		}
	}
	if len(s.clients) > 0 {
		tunnelsSum := 0
		tunnelsMax := 0
		for _, client := range s.clients {
			tunnelsSum += client.activeTunnels
			if client.activeTunnels > tunnelsMax {
				tunnelsMax = client.activeTunnels
			}
		}
		result.Load.TunnelsPerIPMax = tunnelsMax
		result.Load.TunnelsPerIPAvg = float64(tunnelsSum) / float64(len(s.clients))
	}

	s.rateMu.Lock()
	elapsed := 0.0
	if !s.lastRateAt.IsZero() {
		elapsed = now.Sub(s.lastRateAt).Seconds()
		if elapsed > 0 {
			result.Rates.BytesToUpstreamPerSec = float64(bytesToUpstream-s.lastBytesToUpstream) / elapsed
			result.Rates.BytesFromUpstreamPerSec = float64(bytesFromUpstream-s.lastBytesFromUpstream) / elapsed
			result.Rates.StreamsOpenedPerMin = float64(streamsOpened-s.lastStreamsOpened) / elapsed * 60
			result.Rates.TunnelsOpenedPerMin = float64(tunnelsTotal-s.lastTunnelsTotal) / elapsed * 60
		}
	}
	nextClientRates := make(map[string]clientRateBaseline, len(s.clients))
	for ip, client := range s.clients {
		entry := clientSnapshot{
			IP:                ip,
			ActiveTunnels:     client.activeTunnels,
			ActiveStreams:     client.activeStreams,
			StreamsPeak:       client.peakStreams,
			BytesToUpstream:   client.bytesToUpstream,
			BytesFromUpstream: client.bytesFromUpstream,
		}
		if client.activeTunnels > 0 && s.config.MaxStreams > 0 {
			capacity := client.activeTunnels * s.config.MaxStreams
			if capacity > 0 {
				entry.StreamsUtilPct = client.activeStreams * 100 / capacity
			}
		}
		if !client.firstSeen.IsZero() {
			entry.FirstSeen = client.firstSeen.UTC().Format(time.RFC3339)
		}
		if !client.lastActivity.IsZero() {
			entry.LastActivity = client.lastActivity.UTC().Format(time.RFC3339)
		}
		if elapsed > 0 {
			if prev, ok := s.lastClientRates[ip]; ok {
				entry.Rates.BytesToUpstreamPerSec = float64(client.bytesToUpstream-prev.bytesToUpstream) / elapsed
				entry.Rates.BytesFromUpstreamPerSec = float64(client.bytesFromUpstream-prev.bytesFromUpstream) / elapsed
			}
		}
		nextClientRates[ip] = clientRateBaseline{
			bytesToUpstream:   client.bytesToUpstream,
			bytesFromUpstream: client.bytesFromUpstream,
		}
		result.Clients = append(result.Clients, entry)
	}
	s.lastRateAt = now
	s.lastBytesToUpstream = bytesToUpstream
	s.lastBytesFromUpstream = bytesFromUpstream
	s.lastStreamsOpened = streamsOpened
	s.lastTunnelsTotal = tunnelsTotal
	s.lastClientRates = nextClientRates
	s.rateMu.Unlock()

	for ip, abuse := range s.abuseByIP {
		if abuse.authFailures == 0 && abuse.tunnelLimitRejected == 0 && abuse.upstreamBlocked == 0 {
			continue
		}
		result.Abuse = append(result.Abuse, abuseSnapshot{
			IP:                  ip,
			AuthFailures:        abuse.authFailures,
			TunnelLimitRejected: abuse.tunnelLimitRejected,
			UpstreamBlocked:     abuse.upstreamBlocked,
		})
	}
	sort.Slice(result.Abuse, func(i, j int) bool {
		left := result.Abuse[i].AuthFailures + result.Abuse[i].TunnelLimitRejected + result.Abuse[i].UpstreamBlocked
		right := result.Abuse[j].AuthFailures + result.Abuse[j].TunnelLimitRejected + result.Abuse[j].UpstreamBlocked
		return left > right
	})
	if len(result.Abuse) > 20 {
		result.Abuse = result.Abuse[:20]
	}
	for target, total := range s.upstreamTotals {
		entry := upstreamSnapshot{
			Target:            target,
			DC:                dcLabelForTarget(target),
			BytesToUpstream:   total.bytesToUpstream,
			BytesFromUpstream: total.bytesFromUpstream,
			DialErrors:        total.dialErrors,
			OpenCount:         total.openCount,
		}
		if gauge := s.upstreams[target]; gauge != nil {
			entry.ActiveStreams = gauge.activeStreams
		}
		if total.openCount > 0 {
			entry.OpenDialMsAvg = total.dialMsTotal / total.openCount
		}
		entry.PoolHits = total.poolHits
		entry.PoolMisses = total.poolMisses
		if poolTotal := total.poolHits + total.poolMisses; poolTotal > 0 {
			entry.PoolHitPct = total.poolHits * 100 / poolTotal
		}
		result.Upstreams = append(result.Upstreams, entry)
	}
	sort.Slice(result.Clients, func(i, j int) bool {
		if result.Clients[i].ActiveStreams != result.Clients[j].ActiveStreams {
			return result.Clients[i].ActiveStreams > result.Clients[j].ActiveStreams
		}
		if result.Clients[i].ActiveTunnels != result.Clients[j].ActiveTunnels {
			return result.Clients[i].ActiveTunnels > result.Clients[j].ActiveTunnels
		}
		return result.Clients[i].IP < result.Clients[j].IP
	})
	sort.Slice(result.Upstreams, func(i, j int) bool {
		if result.Upstreams[i].ActiveStreams == result.Upstreams[j].ActiveStreams {
			return result.Upstreams[i].BytesToUpstream > result.Upstreams[j].BytesToUpstream
		}
		return result.Upstreams[i].ActiveStreams > result.Upstreams[j].ActiveStreams
	})
	return result
}
