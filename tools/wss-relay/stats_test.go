package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRelayStatsSnapshot(t *testing.T) {
	stats := newRelayStats()
	stats.setConfig(statsConfigSnapshot{MaxStreams: 256, MaxTunnelsPerIP: 12})
	stats.muxTunnelOpened("203.0.113.1")
	stats.muxStreamOpened("203.0.113.1", "149.154.167.91:443")
	stats.addBytesToUpstream("203.0.113.1", "149.154.167.91:443", 1024)
	stats.addBytesFromUpstream("203.0.113.1", "149.154.167.91:443", 2048)

	snapshot := stats.snapshot()
	if snapshot.MuxTunnels != 1 || snapshot.MuxStreams != 1 {
		t.Fatalf("unexpected gauges: tunnels=%d streams=%d", snapshot.MuxTunnels, snapshot.MuxStreams)
	}
	if snapshot.MuxTunnelsPeak != 1 || snapshot.MuxStreamsPeak != 1 {
		t.Fatalf("unexpected peaks: tunnels=%d streams=%d", snapshot.MuxTunnelsPeak, snapshot.MuxStreamsPeak)
	}
	if snapshot.BytesToUpstream != 1024 || snapshot.BytesFromUpstream != 2048 {
		t.Fatalf("unexpected bytes: up=%d down=%d", snapshot.BytesToUpstream, snapshot.BytesFromUpstream)
	}
	if len(snapshot.Clients) != 1 || snapshot.Clients[0].IP != "203.0.113.1" {
		t.Fatalf("unexpected clients: %+v", snapshot.Clients)
	}
	if len(snapshot.Upstreams) != 1 {
		t.Fatalf("unexpected upstreams: %+v", snapshot.Upstreams)
	}
	if snapshot.Upstreams[0].BytesToUpstream != 1024 || snapshot.Upstreams[0].BytesFromUpstream != 2048 {
		t.Fatalf("unexpected upstream bytes: %+v", snapshot.Upstreams[0])
	}
}

func TestRelayStatsClosedGraceful(t *testing.T) {
	stats := newRelayStats()
	stats.muxStreamOpened("203.0.113.1", "149.154.167.91:443")
	stats.muxStreamClosed("203.0.113.1", "149.154.167.91:443")
	stats.muxStreamOpened("203.0.113.1", "149.154.167.91:443")
	stats.incMuxStreamIdle()
	stats.muxStreamClosed("203.0.113.1", "149.154.167.91:443")

	snapshot := stats.snapshot()
	if snapshot.MuxStreamsClosed != 2 || snapshot.MuxStreamIdle != 1 {
		t.Fatalf("unexpected closed=%d idle=%d", snapshot.MuxStreamsClosed, snapshot.MuxStreamIdle)
	}
	if snapshot.MuxStreamsClosedGraceful != 1 {
		t.Fatalf("unexpected graceful=%d", snapshot.MuxStreamsClosedGraceful)
	}
}

func TestStatsPathEnabled(t *testing.T) {
	if !statsPathEnabled("/stats") {
		t.Fatal("expected /stats to be enabled")
	}
	if statsPathEnabled("") || statsPathEnabled("-") {
		t.Fatal("expected empty stats path to be disabled")
	}
}

func TestRelayStatsMuxOpenDial(t *testing.T) {
	stats := newRelayStats()
	stats.recordMuxOpenDial("149.154.167.91:443", 40)
	stats.recordMuxOpenDial("149.154.167.91:443", 150)
	stats.recordMuxOpenDial("149.154.167.91:443", 80)

	snapshot := stats.snapshot()
	if snapshot.MuxOpenCount != 3 {
		t.Fatalf("unexpected open count: %d", snapshot.MuxOpenCount)
	}
	if snapshot.MuxOpenDialMsAvg != 90 {
		t.Fatalf("unexpected avg: %d", snapshot.MuxOpenDialMsAvg)
	}
	if snapshot.MuxOpenDialMsMax != 150 {
		t.Fatalf("unexpected max: %d", snapshot.MuxOpenDialMsMax)
	}
	if snapshot.MuxOpenSlow != 1 {
		t.Fatalf("unexpected slow: %d", snapshot.MuxOpenSlow)
	}
	if len(snapshot.Upstreams) != 1 || snapshot.Upstreams[0].OpenDialMsAvg != 90 {
		t.Fatalf("unexpected upstream dial avg: %+v", snapshot.Upstreams)
	}
}

func TestRelayStatsRates(t *testing.T) {
	stats := newRelayStats()
	stats.addBytesToUpstream("203.0.113.1", "149.154.167.91:443", 1000)
	stats.muxTunnelOpened("203.0.113.1")
	_ = stats.snapshot()

	time.Sleep(20 * time.Millisecond)
	stats.addBytesToUpstream("203.0.113.1", "149.154.167.91:443", 1000)
	stats.muxTunnelOpened("203.0.113.1")
	snapshot := stats.snapshot()

	if snapshot.Rates.BytesToUpstreamPerSec <= 0 {
		t.Fatalf("expected positive upstream rate, got %v", snapshot.Rates.BytesToUpstreamPerSec)
	}
	if snapshot.Rates.TunnelsOpenedPerMin <= 0 {
		t.Fatalf("expected positive tunnel rate, got %v", snapshot.Rates.TunnelsOpenedPerMin)
	}
}

func TestLatencyPercentile(t *testing.T) {
	var samples latencySamples
	for _, value := range []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100} {
		samples.add(value)
	}
	if p95 := samples.percentile(0.95); p95 != 100 {
		t.Fatalf("unexpected p95: %d", p95)
	}
}

func TestRelayStatsAbuseByIP(t *testing.T) {
	stats := newRelayStats()
	stats.incAuthFailure("203.0.113.1")
	stats.incAuthFailure("203.0.113.1")
	stats.incTunnelLimitRejected("203.0.113.2")
	stats.incUpstreamBlocked("203.0.113.1")

	snapshot := stats.snapshot()
	if len(snapshot.Abuse) != 2 {
		t.Fatalf("unexpected abuse entries: %+v", snapshot.Abuse)
	}
	if snapshot.Abuse[0].IP != "203.0.113.1" || snapshot.Abuse[0].AuthFailures != 2 {
		t.Fatalf("unexpected top abuse entry: %+v", snapshot.Abuse[0])
	}
}

func TestRelayStatsClientRates(t *testing.T) {
	stats := newRelayStats()
	stats.setConfig(statsConfigSnapshot{MaxStreams: 256})
	stats.muxTunnelOpened("203.0.113.1")
	stats.addBytesToUpstream("203.0.113.1", "149.154.167.91:443", 1000)
	_ = stats.snapshot()

	time.Sleep(20 * time.Millisecond)
	stats.addBytesToUpstream("203.0.113.1", "149.154.167.91:443", 2000)
	snapshot := stats.snapshot()

	if len(snapshot.Clients) != 1 {
		t.Fatalf("unexpected clients: %+v", snapshot.Clients)
	}
	if snapshot.Clients[0].Rates.BytesToUpstreamPerSec <= 0 {
		t.Fatalf("expected client upstream rate, got %v", snapshot.Clients[0].Rates.BytesToUpstreamPerSec)
	}
}

func TestMetricsFormat(t *testing.T) {
	stats := newRelayStats()
	stats.muxTunnelOpened("203.0.113.1")
	snapshot := stats.snapshot()

	recorder := httptest.NewRecorder()
	handleMetrics(recorder, snapshot)
	body := recorder.Body.String()
	if !strings.Contains(body, "wss_relay_mux_tunnels") {
		t.Fatalf("unexpected metrics body: %s", body)
	}
}
