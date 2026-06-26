package main

import (
	"testing"
)

func TestRelayStatsSnapshot(t *testing.T) {
	stats := newRelayStats()
	stats.muxTunnelOpened("203.0.113.1")
	stats.muxStreamOpened("203.0.113.1", "149.154.167.91:443")
	stats.addBytesToUpstream("203.0.113.1", 1024)
	stats.addBytesFromUpstream("203.0.113.1", 2048)

	snapshot := stats.snapshot()
	if snapshot.MuxTunnels != 1 || snapshot.MuxStreams != 1 {
		t.Fatalf("unexpected gauges: tunnels=%d streams=%d", snapshot.MuxTunnels, snapshot.MuxStreams)
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
	stats.recordMuxOpenDial(40)
	stats.recordMuxOpenDial(150)
	stats.recordMuxOpenDial(80)

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
}
