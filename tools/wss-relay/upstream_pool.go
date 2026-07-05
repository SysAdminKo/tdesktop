package main

import (
	"net"
	"sort"
	"sync"
	"time"
)

type poolBucketKey struct {
	egress string
	target string
}

type poolBucketState struct {
	size     int
	idle     []pooledConn
	lastUsed time.Time
	filling  bool

	windowHits   int64
	windowMisses int64
	lastAdjust   time.Time
	lastSizeChange time.Time
}

type poolBucketTotals struct {
	hits         int64
	misses       int64
	lastActivity time.Time
}

type pooledConn struct {
	conn     net.Conn
	dialedAt time.Time
}

type upstreamPoolConfig struct {
	minSize          int
	maxSize          int
	maxIdle          time.Duration
	bucketRetention  time.Duration
	targetHitPct     int
	highHitPct       int
	minWindowSamples int64
	adjustInterval   time.Duration
	scaleDownDelay   time.Duration
	globalMaxIdle    int
}

type upstreamPool struct {
	cfg upstreamPoolConfig

	mu      sync.Mutex
	buckets map[poolBucketKey]*poolBucketState
	totals  map[poolBucketKey]*poolBucketTotals
}

var upstreamConnPool *upstreamPool

func initUpstreamPool(cfg upstreamPoolConfig) {
	if cfg.minSize <= 0 || cfg.maxIdle <= 0 {
		upstreamConnPool = nil
		return
	}
	if cfg.maxSize < cfg.minSize {
		cfg.maxSize = cfg.minSize
	}
	if cfg.targetHitPct <= 0 {
		cfg.targetHitPct = 40
	}
	if cfg.highHitPct <= cfg.targetHitPct {
		cfg.highHitPct = cfg.targetHitPct + 30
	}
	if cfg.minWindowSamples <= 0 {
		cfg.minWindowSamples = 5
	}
	if cfg.adjustInterval <= 0 {
		cfg.adjustInterval = 5 * time.Second
	}
	if cfg.scaleDownDelay <= 0 {
		cfg.scaleDownDelay = 5 * time.Minute
	}
	if cfg.bucketRetention <= 0 {
		cfg.bucketRetention = 10 * time.Minute
	}
	if cfg.globalMaxIdle <= 0 {
		cfg.globalMaxIdle = 500
	}
	p := &upstreamPool{
		cfg:     cfg,
		buckets: make(map[poolBucketKey]*poolBucketState),
		totals:  make(map[poolBucketKey]*poolBucketTotals),
	}
	upstreamConnPool = p
	go p.maintainLoop()
}

func acquireUpstream(target, clientIP, egressIP string) (net.Conn, bool, error) {
	egressIP = resolveEgressIP(egressIP)
	if upstreamConnPool != nil {
		if conn := upstreamConnPool.get(egressIP, target); conn != nil {
			upstreamConnPool.recordHit(egressIP, target)
			relayStatistics.incUpstreamPoolHit(target)
			return conn, true, nil
		}
		upstreamConnPool.recordMiss(egressIP, target)
	}
	conn, err := dialUpstream(target, clientIP, egressIP)
	if err != nil {
		return nil, false, err
	}
	if upstreamConnPool != nil {
		upstreamConnPool.touch(egressIP, target)
	}
	relayStatistics.incUpstreamPoolMiss(target)
	return conn, false, nil
}

func (p *upstreamPool) bucket(egress, target string) *poolBucketState {
	key := poolBucketKey{egress: egress, target: target}
	entry, ok := p.buckets[key]
	if !ok {
		now := time.Now()
		entry = &poolBucketState{
			size:           p.cfg.minSize,
			lastAdjust:     now,
			lastSizeChange: now,
		}
		p.buckets[key] = entry
	}
	return entry
}

func (p *upstreamPool) get(egress, target string) net.Conn {
	for {
		p.mu.Lock()
		entry := p.bucket(egress, target)
		if len(entry.idle) == 0 {
			p.mu.Unlock()
			return nil
		}
		pc := entry.idle[len(entry.idle)-1]
		entry.idle = entry.idle[:len(entry.idle)-1]
		p.mu.Unlock()
		if time.Since(pc.dialedAt) > p.cfg.maxIdle || !upstreamConnHealthy(pc.conn) {
			_ = pc.conn.Close()
			continue
		}
		return pc.conn
	}
}

func (p *upstreamPool) touch(egress, target string) {
	p.mu.Lock()
	entry := p.bucket(egress, target)
	entry.lastUsed = time.Now()
	fill := len(entry.idle) < entry.size && !entry.filling
	if fill {
		entry.filling = true
	}
	p.mu.Unlock()
	if fill {
		go p.fill(egress, target)
	}
}

func (p *upstreamPool) totalsEntry(egress, target string) *poolBucketTotals {
	key := poolBucketKey{egress: egress, target: target}
	entry, ok := p.totals[key]
	if !ok {
		entry = &poolBucketTotals{}
		p.totals[key] = entry
	}
	return entry
}

func (p *upstreamPool) recordTotalsHit(egress, target string) {
	entry := p.totalsEntry(egress, target)
	entry.hits++
	entry.lastActivity = time.Now()
}

func (p *upstreamPool) recordTotalsMiss(egress, target string) {
	entry := p.totalsEntry(egress, target)
	entry.misses++
	entry.lastActivity = time.Now()
}

func (p *upstreamPool) recordHit(egress, target string) {
	p.mu.Lock()
	entry := p.bucket(egress, target)
	entry.windowHits++
	p.recordTotalsHit(egress, target)
	entry.lastUsed = time.Now()
	p.mu.Unlock()
}

func (p *upstreamPool) recordMiss(egress, target string) {
	p.mu.Lock()
	entry := p.bucket(egress, target)
	entry.windowMisses++
	p.recordTotalsMiss(egress, target)
	entry.lastUsed = time.Now()
	fill := len(entry.idle) < entry.size && !entry.filling
	if fill {
		entry.filling = true
	}
	p.mu.Unlock()
	if fill {
		go p.fill(egress, target)
	}
}

func (p *upstreamPool) fill(egress, target string) {
	defer func() {
		p.mu.Lock()
		entry := p.bucket(egress, target)
		entry.filling = false
		p.mu.Unlock()
	}()
	for {
		p.mu.Lock()
		entry := p.bucket(egress, target)
		deficit := entry.size - len(entry.idle)
		p.mu.Unlock()
		if deficit <= 0 {
			return
		}
		if p.totalIdle() >= p.cfg.globalMaxIdle {
			return
		}
		conn, err := dialUpstream(target, "pool", egress)
		if err != nil {
			relayStatistics.incUpstreamPoolDialError()
			return
		}
		p.mu.Lock()
		entry = p.bucket(egress, target)
		if len(entry.idle) >= entry.size || p.countIdleLocked() >= p.cfg.globalMaxIdle {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		entry.idle = append(entry.idle, pooledConn{
			conn:     conn,
			dialedAt: time.Now(),
		})
		p.mu.Unlock()
	}
}

func (p *upstreamPool) totalIdle() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.countIdleLocked()
}

func (p *upstreamPool) countIdleLocked() int {
	total := 0
	for _, entry := range p.buckets {
		total += len(entry.idle)
	}
	return total
}

func computePoolSizeAdjust(
	current, minSize, maxSize int,
	hits, misses int64,
	targetHitPct, highHitPct int,
	scaleDownAllowed bool,
) (newSize int, changed bool) {
	newSize = current
	total := hits + misses
	if total < 5 {
		return newSize, false
	}
	hitPct := int(hits * 100 / total)
	if hitPct < targetHitPct && current < maxSize {
		return current + 1, true
	}
	if scaleDownAllowed &&
		hitPct >= highHitPct &&
		misses == 0 &&
		current > minSize &&
		total >= 10 {
		return current - 1, true
	}
	return newSize, false
}

func (p *upstreamPool) adjustBuckets(now time.Time) {
	var refill []poolBucketKey
	p.mu.Lock()
	for key, entry := range p.buckets {
		if p.bucketExpired(entry, now) {
			for _, pc := range entry.idle {
				_ = pc.conn.Close()
			}
			delete(p.buckets, key)
			continue
		}
		if now.Sub(entry.lastAdjust) < p.cfg.adjustInterval {
			continue
		}
		scaleDownAllowed := now.Sub(entry.lastSizeChange) >= p.cfg.scaleDownDelay
		newSize, changed := computePoolSizeAdjust(
			entry.size,
			p.cfg.minSize,
			p.cfg.maxSize,
			entry.windowHits,
			entry.windowMisses,
			p.cfg.targetHitPct,
			p.cfg.highHitPct,
			scaleDownAllowed,
		)
		entry.windowHits = 0
		entry.windowMisses = 0
		entry.lastAdjust = now
		if changed {
			entry.size = newSize
			entry.lastSizeChange = now
			for len(entry.idle) > entry.size {
				pc := entry.idle[len(entry.idle)-1]
				entry.idle = entry.idle[:len(entry.idle)-1]
				_ = pc.conn.Close()
			}
		}
		if p.bucketNeedsRefill(entry) {
			entry.filling = true
			refill = append(refill, key)
		}
	}
	p.enforceGlobalIdleCapLocked()
	p.mu.Unlock()
	for _, key := range refill {
		go p.fill(key.egress, key.target)
	}
}

func (p *upstreamPool) bucketExpired(entry *poolBucketState, now time.Time) bool {
	return !entry.lastUsed.IsZero() && now.Sub(entry.lastUsed) > p.cfg.bucketRetention
}

func (p *upstreamPool) bucketNeedsRefill(entry *poolBucketState) bool {
	return len(entry.idle) < entry.size && !entry.filling
}

func (p *upstreamPool) enforceGlobalIdleCapLocked() {
	for p.countIdleLocked() > p.cfg.globalMaxIdle {
		var chosen poolBucketKey
		var chosenUsed time.Time
		found := false
		for key, entry := range p.buckets {
			if len(entry.idle) == 0 {
				continue
			}
			if !found || entry.lastUsed.Before(chosenUsed) {
				chosen = key
				chosenUsed = entry.lastUsed
				found = true
			}
		}
		if !found {
			return
		}
		entry := p.buckets[chosen]
		pc := entry.idle[len(entry.idle)-1]
		entry.idle = entry.idle[:len(entry.idle)-1]
		_ = pc.conn.Close()
	}
}

func (p *upstreamPool) pruneExpired(now time.Time) {
	var toClose []net.Conn
	var refill []poolBucketKey
	p.mu.Lock()
	for key, entry := range p.buckets {
		kept := entry.idle[:0]
		for _, pc := range entry.idle {
			if now.Sub(pc.dialedAt) > p.cfg.maxIdle {
				toClose = append(toClose, pc.conn)
				continue
			}
			kept = append(kept, pc)
		}
		entry.idle = kept
		if p.bucketExpired(entry, now) {
			for _, pc := range entry.idle {
				toClose = append(toClose, pc.conn)
			}
			delete(p.buckets, key)
			continue
		}
		if p.bucketNeedsRefill(entry) {
			entry.filling = true
			refill = append(refill, key)
		}
	}
	p.enforceGlobalIdleCapLocked()
	p.mu.Unlock()
	for _, conn := range toClose {
		_ = conn.Close()
	}
	for _, key := range refill {
		go p.fill(key.egress, key.target)
	}
}

func (p *upstreamPool) maintainLoop() {
	pruneTicker := time.NewTicker(2 * time.Second)
	adjustTicker := time.NewTicker(p.cfg.adjustInterval)
	defer pruneTicker.Stop()
	defer adjustTicker.Stop()
	for {
		select {
		case <-pruneTicker.C:
			p.pruneExpired(time.Now())
		case now := <-adjustTicker.C:
			p.adjustBuckets(now)
		}
	}
}

func (p *upstreamPool) snapshotBuckets() []poolBucketSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make([]poolBucketSnapshot, 0, len(p.totals))
	for key, totals := range p.totals {
		snap := poolBucketSnapshot{
			Egress:       key.egress,
			Target:       key.target,
			TotalHits:    totals.hits,
			TotalMisses:  totals.misses,
		}
		if !totals.lastActivity.IsZero() {
			snap.LastActivity = totals.lastActivity.UTC().Format(time.RFC3339)
		}
		if lifeTotal := totals.hits + totals.misses; lifeTotal > 0 {
			snap.TotalHitPct = int(totals.hits * 100 / lifeTotal)
		}
		if entry, ok := p.buckets[key]; ok {
			snap.Active = true
			snap.Size = entry.size
			snap.Idle = len(entry.idle)
			snap.WindowHits = entry.windowHits
			snap.WindowMiss = entry.windowMisses
			if windowTotal := entry.windowHits + entry.windowMisses; windowTotal > 0 {
				snap.WindowHitPct = int(entry.windowHits * 100 / windowTotal)
			}
		}
		result = append(result, snap)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Active != result[j].Active {
			return result[i].Active
		}
		if result[i].Target != result[j].Target {
			return result[i].Target < result[j].Target
		}
		return result[i].Egress < result[j].Egress
	})
	return result
}

type poolBucketSnapshot struct {
	Egress        string `json:"egress"`
	Target        string `json:"target"`
	Active        bool   `json:"active"`
	Size          int    `json:"size"`
	Idle          int    `json:"idle"`
	WindowHits    int64  `json:"window_hits"`
	WindowMiss    int64  `json:"window_misses"`
	WindowHitPct  int    `json:"window_hit_pct"`
	TotalHits     int64  `json:"total_hits"`
	TotalMisses   int64  `json:"total_misses"`
	TotalHitPct   int    `json:"total_hit_pct"`
	LastActivity  string `json:"last_activity,omitempty"`
}

func upstreamConnHealthy(conn net.Conn) bool {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return true
	}
	_ = tcp.SetReadDeadline(time.Now().Add(2 * time.Millisecond))
	var probe [1]byte
	n, err := tcp.Read(probe[:])
	_ = tcp.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true
		}
		return false
	}
	return n == 0
}
