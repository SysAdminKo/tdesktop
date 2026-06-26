package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	muxVersion         = 1
	muxHeaderSize      = 8
	muxMaxDataPayload  = 64 * 1024
	muxTypeOpen        = 0x01
	muxTypeOpenOk      = 0x02
	muxTypeOpenFail    = 0x03
	muxTypeData        = 0x04
	muxTypeClose       = 0x05
	muxTypePing        = 0x06
	muxTypePong        = 0x07
	muxSubprotocol     = "tdesktop-mux/1"
	muxOpenFailDial    = 1
	muxOpenFailBad     = 2
	muxOpenFailLimit   = 3

	muxUpstreamReadStallMinBytes = 32 * 1024
	muxUpstreamReadStallThreshold  = 3 * time.Second
	muxUpstreamReadStallResetGap   = 100 * time.Millisecond
)

type muxStream struct {
	id              uint32
	tcp             net.Conn
	done            chan struct{}
	target          string
	lastActivity    atomic.Int64
	upstreamBytes   int64
	lastReadAt      time.Time
	readStallLogged bool
	sentBytes       int64
	recvBytes       int64
}

type muxConfig struct {
	maxStreams        int
	streamIdleTimeout time.Duration
	wsPingInterval    time.Duration
	wsReadTimeout     time.Duration
}

type muxSession struct {
	conn              *websocket.Conn
	streams           map[uint32]*muxStream
	writeMu           sync.Mutex
	config            muxConfig
	clientIP          string
	closed            bool
	mu                sync.Mutex
}

func (st *muxStream) touchActivity() {
	st.lastActivity.Store(time.Now().UnixNano())
}

func (st *muxStream) idleSince(idleTimeout time.Duration) bool {
	if idleTimeout <= 0 {
		return false
	}
	last := time.Unix(0, st.lastActivity.Load())
	return time.Since(last) >= idleTimeout
}

var muxWSUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	EnableCompression: false,
	Subprotocols:      []string{muxSubprotocol},
}

func encodeMuxFrame(frameType byte, streamID uint32, payload []byte) []byte {
	result := make([]byte, muxHeaderSize+len(payload))
	result[0] = muxVersion
	result[1] = frameType
	binary.BigEndian.PutUint16(result[2:4], 0)
	binary.BigEndian.PutUint32(result[4:8], streamID)
	copy(result[muxHeaderSize:], payload)
	return result
}

func decodeMuxFrame(data []byte) (frameType byte, streamID uint32, payload []byte, err error) {
	if len(data) < muxHeaderSize {
		return 0, 0, nil, fmt.Errorf("short mux frame")
	}
	if data[0] != muxVersion {
		return 0, 0, nil, fmt.Errorf("bad mux version")
	}
	frameType = data[1]
	streamID = binary.BigEndian.Uint32(data[4:8])
	payload = data[muxHeaderSize:]
	if frameType == muxTypeData && len(payload) > muxMaxDataPayload {
		return 0, 0, nil, fmt.Errorf("mux data too large")
	}
	return frameType, streamID, payload, nil
}

func parseOpenTarget(payload []byte) (string, error) {
	if len(payload) < 4 {
		return "", fmt.Errorf("short open payload")
	}
	hostLen := int(binary.BigEndian.Uint16(payload[0:2]))
	if len(payload) < 2+hostLen+2 {
		return "", fmt.Errorf("short open host")
	}
	host := string(payload[2 : 2+hostLen])
	port := binary.BigEndian.Uint16(payload[2+hostLen : 2+hostLen+2])
	if host == "" || port == 0 {
		return "", fmt.Errorf("empty open target")
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func (s *muxSession) writeFrame(frameType byte, streamID uint32, payload []byte) error {
	waitStart := time.Now()
	s.writeMu.Lock()
	relayStatistics.incMuxWriteWait(time.Since(waitStart))
	defer s.writeMu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}
	frame := encodeMuxFrame(frameType, streamID, payload)
	return s.conn.WriteMessage(websocket.BinaryMessage, frame)
}

func (s *muxSession) removeStream(id uint32) {
	s.mu.Lock()
	stream, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	s.mu.Unlock()
	if !ok {
		return
	}
	target := stream.target
	select {
	case <-stream.done:
	default:
		close(stream.done)
	}
	_ = stream.tcp.Close()
	log.Printf(
		"mux stream close stream=%d client=%s target=%s sent=%d recv=%d",
		id,
		s.clientIP,
		target,
		stream.sentBytes,
		stream.recvBytes,
	)
	relayStatistics.muxStreamClosed(s.clientIP, target)
}

func (s *muxSession) closeAll() {
	s.mu.Lock()
	ids := make([]uint32, 0, len(s.streams))
	for id := range s.streams {
		ids = append(ids, id)
	}
	s.closed = true
	s.mu.Unlock()
	for _, id := range ids {
		s.removeStream(id)
	}
}

func (s *muxSession) handleOpen(streamID uint32, payload []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if _, exists := s.streams[streamID]; exists {
		s.mu.Unlock()
		relayStatistics.incMuxOpenBad()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailBad})
		return
	}
	if len(s.streams) >= s.config.maxStreams {
		s.mu.Unlock()
		relayStatistics.incMuxOpenLimit()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailLimit})
		return
	}
	s.mu.Unlock()

	target, err := parseOpenTarget(payload)
	if err != nil {
		relayStatistics.incMuxOpenBad()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailBad})
		return
	}
	go s.openStreamAsync(streamID, target)
}

func (s *muxSession) openStreamAsync(streamID uint32, target string) {
	dialStarted := time.Now()
	tcp, err := dialUpstream(target)
	dialMs := time.Since(dialStarted).Milliseconds()
	relayStatistics.recordMuxOpenDial(dialMs)
	if dialMs > 100 {
		log.Printf(
			"mux open slow stream=%d client=%s target=%s dial_ms=%d",
			streamID,
			s.clientIP,
			target,
			dialMs,
		)
	}
	if err != nil {
		log.Printf("mux open stream=%d dial %s failed: %v", streamID, target, err)
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailDial})
		return
	}
	stream := &muxStream{
		id:     streamID,
		tcp:    tcp,
		done:   make(chan struct{}),
		target: target,
	}
	stream.touchActivity()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = tcp.Close()
		return
	}
	if _, exists := s.streams[streamID]; exists {
		s.mu.Unlock()
		_ = tcp.Close()
		relayStatistics.incMuxOpenBad()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailBad})
		return
	}
	if len(s.streams) >= s.config.maxStreams {
		s.mu.Unlock()
		_ = tcp.Close()
		relayStatistics.incMuxOpenLimit()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailLimit})
		return
	}
	s.streams[streamID] = stream
	s.mu.Unlock()

	relayStatistics.muxStreamOpened(s.clientIP, target)
	if err := s.writeFrame(muxTypeOpenOk, streamID, nil); err != nil {
		s.removeStream(streamID)
		return
	}

	go s.pumpUpstream(stream)
}

func (s *muxSession) pumpUpstream(stream *muxStream) {
	buffer := make([]byte, muxMaxDataPayload)
	for {
		select {
		case <-stream.done:
			return
		default:
		}
		if stream.upstreamBytes >= muxUpstreamReadStallMinBytes && !stream.lastReadAt.IsZero() {
			gap := time.Since(stream.lastReadAt)
			if gap >= muxUpstreamReadStallThreshold && !stream.readStallLogged {
				stream.readStallLogged = true
				log.Printf(
					"mux upstream read stall stream=%d client=%s target=%s gap_ms=%d bytes=%d",
					stream.id,
					s.clientIP,
					stream.target,
					gap.Milliseconds(),
					stream.upstreamBytes,
				)
				relayStatistics.incMuxUpstreamReadStall()
			}
		}
		n, err := stream.tcp.Read(buffer)
		if err != nil {
			s.removeStream(stream.id)
			_ = s.writeFrame(muxTypeClose, stream.id, nil)
			return
		}
		now := time.Now()
		if !stream.lastReadAt.IsZero() {
			if now.Sub(stream.lastReadAt) < muxUpstreamReadStallResetGap {
				stream.readStallLogged = false
			}
		}
		stream.lastReadAt = now
		stream.upstreamBytes += int64(n)
		stream.sentBytes += int64(n)
		stream.touchActivity()
		if err := s.writeFrame(muxTypeData, stream.id, buffer[:n]); err != nil {
			s.removeStream(stream.id)
			return
		}
		relayStatistics.addBytesFromUpstream(s.clientIP, n)
	}
}

func (s *muxSession) expireIdleStream(id uint32) {
	log.Printf("mux stream idle timeout id=%d client=%s", id, s.clientIP)
	relayStatistics.incMuxStreamIdle()
	_ = s.writeFrame(muxTypeClose, id, nil)
	s.removeStream(id)
}

func (s *muxSession) runIdleSweeper(stop <-chan struct{}) {
	idle := s.config.streamIdleTimeout
	if idle <= 0 {
		return
	}
	tick := idle / 4
	if tick < time.Second {
		tick = time.Second
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.sweepIdleStreams(idle)
		}
	}
}

func (s *muxSession) sweepIdleStreams(idleTimeout time.Duration) {
	var stale []uint32
	s.mu.Lock()
	for id, stream := range s.streams {
		if stream.idleSince(idleTimeout) {
			stale = append(stale, id)
		}
	}
	s.mu.Unlock()
	for _, id := range stale {
		s.expireIdleStream(id)
	}
}

func (s *muxSession) runWSPing(interval time.Duration, stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.writeMu.Lock()
			err := s.conn.WriteMessage(websocket.PingMessage, nil)
			s.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (s *muxSession) refreshWSReadDeadline() {
	if s.config.wsReadTimeout <= 0 {
		return
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(s.config.wsReadTimeout))
}

func (s *muxSession) handleData(streamID uint32, payload []byte) {
	s.mu.Lock()
	stream, ok := s.streams[streamID]
	s.mu.Unlock()
	if !ok {
		_ = s.writeFrame(muxTypeClose, streamID, []byte{1})
		return
	}
	stream.recvBytes += int64(len(payload))
	stream.touchActivity()
	if _, err := stream.tcp.Write(payload); err != nil {
		s.removeStream(streamID)
		return
	}
	relayStatistics.addBytesToUpstream(s.clientIP, len(payload))
}

func (s *muxSession) handleClose(streamID uint32) {
	log.Printf("mux close stream=%d", streamID)
	s.removeStream(streamID)
}

func (s *muxSession) readLoop() {
	pingStop := make(chan struct{})
	defer close(pingStop)
	if s.config.wsReadTimeout > 0 {
		s.refreshWSReadDeadline()
		s.conn.SetPongHandler(func(string) error {
			return s.conn.SetReadDeadline(time.Now().Add(s.config.wsReadTimeout))
		})
	}
	if s.config.wsPingInterval > 0 {
		go s.runWSPing(s.config.wsPingInterval, pingStop)
	}
	if s.config.streamIdleTimeout > 0 {
		go s.runIdleSweeper(pingStop)
	}
	defer func() {
		s.mu.Lock()
		active := len(s.streams)
		s.mu.Unlock()
		if active > 0 {
			log.Printf(
				"mux tunnel ending with %d active streams client=%s",
				active,
				s.clientIP,
			)
		}
		s.closeAll()
	}()
	defer s.conn.Close()
	for {
		messageType, data, err := s.conn.ReadMessage()
		if err != nil {
			log.Printf("mux tunnel end: %v", err)
			return
		}
		s.refreshWSReadDeadline()
		if messageType == websocket.PingMessage {
			s.writeMu.Lock()
			err := s.conn.WriteMessage(websocket.PongMessage, data)
			s.writeMu.Unlock()
			if err != nil {
				return
			}
			continue
		}
		if messageType == websocket.CloseMessage {
			return
		}
		if messageType != websocket.BinaryMessage {
			continue
		}
		frameType, streamID, payload, err := decodeMuxFrame(data)
		if err != nil {
			log.Printf("mux decode error: %v", err)
			return
		}
		switch frameType {
		case muxTypeOpen:
			s.handleOpen(streamID, payload)
		case muxTypeData:
			s.handleData(streamID, payload)
		case muxTypeClose:
			s.handleClose(streamID)
		case muxTypePing:
			_ = s.writeFrame(muxTypePong, streamID, nil)
		case muxTypePong:
		default:
			log.Printf("mux unknown frame type=%d", frameType)
		}
	}
}

func handleMux(
	w http.ResponseWriter,
	r *http.Request,
	config muxConfig,
	limiter *muxTunnelLimiter,
	auth *tokenAuth,
) {
	if strings.TrimSpace(r.Header.Get("X-Tg-Target")) != "" {
		http.Error(w, "mux path does not accept X-Tg-Target", http.StatusBadRequest)
		return
	}
	authLabel, ok := auth.validate(r)
	if !ok {
		writeUnauthorized(w)
		return
	}
	clientIP := clientIPFromRequest(r)
	if !limiter.tryAcquire(clientIP) {
		log.Printf("mux tunnel limit reached for %s", clientIP)
		relayStatistics.incTunnelLimitRejected()
		http.Error(w, "too many mux tunnels", http.StatusTooManyRequests)
		return
	}
	relayStatistics.muxTunnelOpened(clientIP)
	defer relayStatistics.muxTunnelClosed(clientIP)
	defer limiter.release(clientIP)

	conn, err := muxWSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("mux upgrade failed: %v", err)
		return
	}
	if conn.Subprotocol() != muxSubprotocol {
		log.Printf("mux bad subprotocol: %q", conn.Subprotocol())
		_ = conn.Close()
		return
	}
	log.Printf("mux tunnel from %s client=%s auth=%s", r.RemoteAddr, clientIP, authLabel)
	session := &muxSession{
		conn:     conn,
		streams:  make(map[uint32]*muxStream),
		config:   config,
		clientIP: clientIP,
	}
	session.readLoop()
}
