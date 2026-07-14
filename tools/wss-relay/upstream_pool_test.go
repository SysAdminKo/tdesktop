package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestComputePoolSizeAdjustScaleUp(t *testing.T) {
	size, changed := computePoolSizeAdjust(2, 2, 15, 2, 8, 40, 80, false)
	if !changed || size != 3 {
		t.Fatalf("expected scale up to 3, got size=%d changed=%v", size, changed)
	}
}

func TestComputePoolSizeAdjustScaleDown(t *testing.T) {
	size, changed := computePoolSizeAdjust(5, 2, 15, 20, 0, 40, 80, true)
	if !changed || size != 4 {
		t.Fatalf("expected scale down to 4, got size=%d changed=%v", size, changed)
	}
}

func TestComputePoolSizeAdjustInsufficientSamples(t *testing.T) {
	size, changed := computePoolSizeAdjust(3, 2, 15, 1, 2, 40, 80, true)
	if changed {
		t.Fatalf("expected no change with low samples, got size=%d", size)
	}
}

func TestEgressIPFromRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws/mux", nil)
	req.Header.Set("X-Relay-Local-IP", "203.0.113.10")
	if got := egressIPFromRequest(req); got != "203.0.113.10" {
		t.Fatalf("unexpected egress ip: %q", got)
	}
}

func TestResolveEgressIPAllowlist(t *testing.T) {
	setAllowedEgressIPs("203.0.113.10,203.0.113.11")
	if got := resolveEgressIP("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("expected allowed ip, got %q", got)
	}
	if got := resolveEgressIP("203.0.113.99"); got != "" {
		t.Fatalf("expected rejected ip, got %q", got)
	}
	setAllowedEgressIPs("")
}

func TestAdjustBucketsScaleDownDelay(t *testing.T) {
	initUpstreamPool(upstreamPoolConfig{
		minSize:        2,
		maxSize:        15,
		maxIdle:        time.Minute,
		targetHitPct:   40,
		highHitPct:     70,
		adjustInterval: time.Second,
		scaleDownDelay: 5 * time.Minute,
		globalMaxIdle:  100,
	})
	defer func() { upstreamConnPool = nil }()

	p := upstreamConnPool
	now := time.Now()
	p.mu.Lock()
	key := poolBucketKey{egress: "203.0.113.1", target: "149.154.167.51:443"}
	entry := p.bucket(key.egress, key.target)
	entry.size = 5
	entry.lastUsed = now
	entry.lastAdjust = now.Add(-time.Second)
	entry.lastSizeChange = now.Add(-6 * time.Minute)
	entry.windowHits = 20
	entry.windowMisses = 0
	p.mu.Unlock()

	p.adjustBuckets(now)

	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.size != 4 {
		t.Fatalf("expected scale down to 4, got %d", entry.size)
	}
}

func TestAdjustBucketsScaleDownBlockedAfterSizeChange(t *testing.T) {
	initUpstreamPool(upstreamPoolConfig{
		minSize:        2,
		maxSize:        15,
		maxIdle:        time.Minute,
		targetHitPct:   40,
		highHitPct:     70,
		adjustInterval: time.Second,
		scaleDownDelay: 5 * time.Minute,
		globalMaxIdle:  100,
	})
	defer func() { upstreamConnPool = nil }()

	p := upstreamConnPool
	now := time.Now()
	p.mu.Lock()
	entry := p.bucket("203.0.113.1", "149.154.167.51:443")
	entry.size = 5
	entry.lastUsed = now
	entry.lastAdjust = now.Add(-time.Second)
	entry.lastSizeChange = now.Add(-time.Minute)
	entry.windowHits = 20
	entry.windowMisses = 0
	p.mu.Unlock()

	p.adjustBuckets(now)

	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.size != 5 {
		t.Fatalf("expected size unchanged at 5, got %d", entry.size)
	}
}

func TestBucketNeedsRefillIgnoresLastUsedAge(t *testing.T) {
	initUpstreamPool(upstreamPoolConfig{
		minSize:         2,
		maxSize:         4,
		maxIdle:         time.Minute,
		bucketRetention: 10 * time.Minute,
		adjustInterval:  time.Hour,
		globalMaxIdle:   100,
	})
	defer func() { upstreamConnPool = nil }()

	p := upstreamConnPool
	now := time.Now()
	p.mu.Lock()
	entry := p.bucket("203.0.113.1", "149.154.167.51:443")
	entry.lastUsed = now.Add(-5 * time.Minute)
	entry.size = 2
	p.mu.Unlock()

	if !p.bucketNeedsRefill(entry) {
		t.Fatal("expected refill for live bucket with idle deficit regardless of lastUsed age")
	}
}

func TestSnapshotBucketsKeepsHistoryAfterGC(t *testing.T) {
	initUpstreamPool(upstreamPoolConfig{
		minSize:        2,
		maxSize:        4,
		maxIdle:        time.Minute,
		targetHitPct:   40,
		adjustInterval: time.Hour,
		globalMaxIdle:  100,
	})
	defer func() { upstreamConnPool = nil }()

	p := upstreamConnPool
	p.recordMiss("203.0.113.1", "149.154.162.123:443")
	p.recordHit("203.0.113.1", "149.154.162.123:443")
	p.recordHit("203.0.113.1", "149.154.162.123:443")

	p.mu.Lock()
	key := poolBucketKey{egress: "203.0.113.1", target: "149.154.162.123:443"}
	delete(p.buckets, key)
	p.mu.Unlock()

	snap := p.snapshotBuckets()
	if len(snap) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(snap))
	}
	if snap[0].Active {
		t.Fatal("expected inactive history entry")
	}
	if snap[0].TotalHits != 2 || snap[0].TotalMisses != 1 {
		t.Fatalf("unexpected totals: hits=%d misses=%d", snap[0].TotalHits, snap[0].TotalMisses)
	}
	if snap[0].TotalHitPct != 66 {
		t.Fatalf("unexpected total hit pct: %d", snap[0].TotalHitPct)
	}
}

func TestPoolBucketAndUpstreamStatsConsistency(t *testing.T) {
	relayStatistics = newRelayStats()
	initUpstreamPool(upstreamPoolConfig{
		minSize:        2,
		maxSize:        4,
		maxIdle:        time.Minute,
		targetHitPct:   40,
		adjustInterval: time.Hour,
		globalMaxIdle:  100,
	})
	defer func() { upstreamConnPool = nil }()

	target := "149.154.167.91:443"
	upstreamConnPool.recordHit("203.0.113.1", target)
	relayStatistics.incUpstreamPoolHit(target)
	upstreamConnPool.recordMiss("203.0.113.1", target)
	relayStatistics.incUpstreamPoolMiss(target)
	upstreamConnPool.recordMiss("203.0.113.2", target)
	relayStatistics.incUpstreamPoolMiss(target)

	var bucketHits int64
	var bucketMisses int64
	for _, bucket := range upstreamConnPool.snapshotBuckets() {
		if bucket.Target != target {
			continue
		}
		bucketHits += bucket.TotalHits
		bucketMisses += bucket.TotalMisses
	}

	statsSnap := relayStatistics.snapshot()
	if statsSnap.UpstreamPoolHits != bucketHits || statsSnap.UpstreamPoolMisses != bucketMisses {
		t.Fatalf(
			"global pool stats mismatch: stats hits=%d misses=%d bucket hits=%d misses=%d",
			statsSnap.UpstreamPoolHits,
			statsSnap.UpstreamPoolMisses,
			bucketHits,
			bucketMisses,
		)
	}
	if len(statsSnap.Upstreams) != 1 {
		t.Fatalf("expected one upstream entry, got %+v", statsSnap.Upstreams)
	}
	upstream := statsSnap.Upstreams[0]
	if upstream.PoolHits != bucketHits || upstream.PoolMisses != bucketMisses {
		t.Fatalf(
			"per-target pool stats mismatch: upstream hits=%d misses=%d bucket hits=%d misses=%d",
			upstream.PoolHits,
			upstream.PoolMisses,
			bucketHits,
			bucketMisses,
		)
	}
}

func TestPoolBucketKeyIsolation(t *testing.T) {
	initUpstreamPool(upstreamPoolConfig{
		minSize:        2,
		maxSize:        4,
		maxIdle:        time.Minute,
		targetHitPct:   40,
		adjustInterval: time.Hour,
		globalMaxIdle:  100,
	})
	defer func() { upstreamConnPool = nil }()

	p := upstreamConnPool
	p.mu.Lock()
	p.bucket("203.0.113.1", "149.154.167.51:443").size = 3
	p.bucket("203.0.113.2", "149.154.167.51:443").size = 5
	p.mu.Unlock()

	if p.bucket("203.0.113.1", "149.154.167.51:443").size != 3 {
		t.Fatal("bucket sizes should be independent per egress ip")
	}
}
