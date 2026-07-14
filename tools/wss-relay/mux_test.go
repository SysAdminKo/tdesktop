package main

import (
	"encoding/binary"
	"net/http"
	"testing"
	"time"
)

func TestEncodeDecodeMuxOpen(t *testing.T) {
	host := "149.154.167.35"
	port := uint16(443)
	payload := make([]byte, 2+len(host)+2)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(host)))
	copy(payload[2:], host)
	binary.BigEndian.PutUint16(payload[2+len(host):], port)

	frame := encodeMuxFrame(muxTypeOpen, 42, payload)
	frameType, streamID, gotPayload, err := decodeMuxFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if frameType != muxTypeOpen || streamID != 42 {
		t.Fatalf("unexpected header: type=%d id=%d", frameType, streamID)
	}
	target, err := parseOpenTarget(gotPayload)
	if err != nil {
		t.Fatal(err)
	}
	if target != "149.154.167.35:443" {
		t.Fatalf("unexpected target: %s", target)
	}
}

func TestDecodeMuxRejectsOversizedData(t *testing.T) {
	payload := make([]byte, muxMaxDataPayload+1)
	frame := encodeMuxFrame(muxTypeData, 1, payload)
	_, _, _, err := decodeMuxFrame(frame)
	if err == nil {
		t.Fatal("expected error for oversized data")
	}
}

func TestClientIPFromRequest(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"X-Real-Ip": []string{"203.0.113.10"},
		},
		RemoteAddr: "127.0.0.1:8080",
	}
	if got := clientIPFromRequest(r); got != "203.0.113.10" {
		t.Fatalf("unexpected ip: %s", got)
	}

	r = &http.Request{
		Header: http.Header{
			"X-Forwarded-For": []string{"203.0.113.20, 10.0.0.1"},
		},
		RemoteAddr: "127.0.0.1:8080",
	}
	if got := clientIPFromRequest(r); got != "203.0.113.20" {
		t.Fatalf("unexpected ip: %s", got)
	}
}

func TestMuxTunnelLimiter(t *testing.T) {
	limiter := newMuxTunnelLimiter(2)
	if !limiter.tryAcquire("1.2.3.4") || !limiter.tryAcquire("1.2.3.4") {
		t.Fatal("expected first two acquires to succeed")
	}
	if limiter.tryAcquire("1.2.3.4") {
		t.Fatal("expected third acquire to fail")
	}
	if !limiter.tryAcquire("5.6.7.8") {
		t.Fatal("expected different ip to succeed")
	}
	limiter.release("1.2.3.4")
	if !limiter.tryAcquire("1.2.3.4") {
		t.Fatal("expected acquire after release")
	}
}

func TestTrackUpstreamReadWait(t *testing.T) {
	stream := &muxStream{
		id:            7,
		target:        "149.154.167.41:443",
		upstreamBytes: muxUpstreamReadStallMinBytes,
		lastReadAt:    time.Now().Add(-4 * time.Second),
	}
	if stream.trackUpstreamReadWait(0) {
		t.Fatal("expected rotate disabled with max=0")
	}
	if stream.consecutiveReadStalls != 0 {
		t.Fatalf("unexpected consecutive with max=0: %d", stream.consecutiveReadStalls)
	}
	for i := 1; i < 4; i++ {
		if stream.trackUpstreamReadWait(4) {
			t.Fatalf("unexpected rotate at stall %d", i)
		}
		if stream.consecutiveReadStalls != i {
			t.Fatalf("unexpected consecutive at stall %d: got %d", i, stream.consecutiveReadStalls)
		}
	}
	if !stream.trackUpstreamReadWait(4) {
		t.Fatal("expected rotate after 4 consecutive stalls")
	}
	if stream.consecutiveReadStalls != 4 {
		t.Fatalf("unexpected consecutive after rotate trigger: %d", stream.consecutiveReadStalls)
	}

	stream.noteUpstreamReadSuccess(time.Now(), muxUpstreamReadStallRecoverMinBytes)
	if stream.consecutiveReadStalls != 0 || stream.readStallLogged {
		t.Fatal("expected stall counters to reset after meaningful read")
	}
}

func TestTrickleReadDoesNotResetStallCounter(t *testing.T) {
	stream := &muxStream{
		id:                    8,
		target:                "149.154.167.41:443",
		upstreamBytes:         muxUpstreamReadStallMinBytes,
		lastReadAt:            time.Now().Add(-4 * time.Second),
		readStallLogged:       true,
		consecutiveReadStalls: 2,
	}
	stream.noteUpstreamReadSuccess(time.Now(), 512)
	if stream.consecutiveReadStalls != 2 || !stream.readStallLogged {
		t.Fatal("expected trickle read to keep stall state")
	}
	stream.lastReadAt = time.Now().Add(-4 * time.Second)
	if stream.trackUpstreamReadWait(4) {
		t.Fatal("unexpected rotate at consecutive=3")
	}
	if stream.consecutiveReadStalls != 3 {
		t.Fatalf("unexpected consecutive after trickle stall: %d", stream.consecutiveReadStalls)
	}
	stream.lastReadAt = time.Now().Add(-4 * time.Second)
	if !stream.trackUpstreamReadWait(4) {
		t.Fatal("expected rotate at consecutive=4")
	}
}
