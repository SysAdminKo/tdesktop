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
)

type muxStream struct {
	id     uint32
	tcp    net.Conn
	done   chan struct{}
	target string
}

type muxSession struct {
	conn       *websocket.Conn
	streams    map[uint32]*muxStream
	writeMu    sync.Mutex
	maxStreams int
	clientIP   string
	closed     bool
	mu         sync.Mutex
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
	s.writeMu.Lock()
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
	close(stream.done)
	_ = stream.tcp.Close()
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
	if len(s.streams) >= s.maxStreams {
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
	tcp, err := dialUpstream(target)
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
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = tcp.Close()
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
		n, err := stream.tcp.Read(buffer)
		if err != nil {
			s.removeStream(stream.id)
			_ = s.writeFrame(muxTypeClose, stream.id, nil)
			return
		}
		if err := s.writeFrame(muxTypeData, stream.id, buffer[:n]); err != nil {
			s.removeStream(stream.id)
			return
		}
		relayStatistics.addBytesFromUpstream(s.clientIP, n)
	}
}

func (s *muxSession) handleData(streamID uint32, payload []byte) {
	s.mu.Lock()
	stream, ok := s.streams[streamID]
	s.mu.Unlock()
	if !ok {
		_ = s.writeFrame(muxTypeClose, streamID, []byte{1})
		return
	}
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
	defer s.closeAll()
	defer s.conn.Close()
	for {
		messageType, data, err := s.conn.ReadMessage()
		if err != nil {
			log.Printf("mux tunnel end: %v", err)
			return
		}
		if messageType == websocket.PingMessage {
			_ = s.conn.WriteMessage(websocket.PongMessage, data)
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
	maxStreams int,
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
		conn:       conn,
		streams:    make(map[uint32]*muxStream),
		maxStreams: maxStreams,
		clientIP:   clientIP,
	}
	session.readLoop()
}
