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

	muxUpstreamReadStallMinBytes           = 32 * 1024
	muxUpstreamReadStallRecoverMinBytes    = 8 * 1024
	muxUpstreamReadStallThreshold          = 3 * time.Second
	muxUpstreamMaxConsecutiveReadStallsDef = 4
	muxUpstreamWriteTimeout                = 5 * time.Second
	muxWSWriteTimeout                      = 10 * time.Second
	muxClientWriteBufferBytes              = 16 * 1024
	muxClientWriteBufferLowLatencyBytes    = 4 * 1024
	muxPumpReadChunkBytes                  = 8 * 1024
	muxPumpReadChunkLowLatencyBytes        = 2 * 1024
	muxCtrlDrainPollInterval               = 2 * time.Millisecond
	muxWriteDataQueueSize                  = 256
	muxWriteCtrlQueueSize                  = 64
	muxMaxQueuedDataPerStream              = 2
	muxMaxQueuedDataPerStreamLowLatency    = 1
	muxMaxQueuedDataPerStreamPlain         = 4
	muxFairnessPollInterval                = 5 * time.Millisecond
	muxToDCQueueSize                       = 32
	muxSlowWriteQueueLog                   = 250 * time.Millisecond
	muxSlowFairnessWaitLog                 = 100 * time.Millisecond
	muxUpstreamReadGapLog                  = 500 * time.Millisecond
	muxSlowToDCWriteLog                    = 100 * time.Millisecond
	muxSlowToDCEnqueueLog                  = 100 * time.Millisecond
	muxSlowDataChEnqueueLog                = 100 * time.Millisecond
	muxSlowWSWriteLog                      = 250 * time.Millisecond
	muxSlowWriteFrameLog                   = 100 * time.Millisecond
)

type muxWriteJob struct {
	messageType   int
	data          []byte
	done          chan error
	enqueuedAt    time.Time
	queuedCounter *atomic.Int32
	accountBytes  int
	sentCounter   *atomic.Int64
	statsClient   string
	statsTarget   string
	streamID      uint32
}

type muxStream struct {
	id                    uint32
	tcp                   net.Conn
	done                  chan struct{}
	toDC                  chan []byte
	target                string
	opening               bool
	lastActivity          atomic.Int64
	upstreamBytes         int64
	lastReadAt            time.Time
	readStallLogged       bool
	consecutiveReadStalls int
	sentBytes             atomic.Int64
	recvBytes             int64
	queuedDataFrames      atomic.Int32
	lastUpstreamReadAt    time.Time
	upstreamGapLogCount   int
	lastWriteFrameMs      int64
	lastDataChWaitMs      int64
	consecutiveReadTimeouts int
	toDCEnqueueBlockLogs  int
}

type muxConfig struct {
	maxStreams               int
	streamIdleTimeout        time.Duration
	wsPingInterval           time.Duration
	wsReadTimeout            time.Duration
	maxConsecutiveReadStalls int
	lowLatencyTest           bool
	plain                    bool
}

type muxSession struct {
	conn        *websocket.Conn
	streams     map[uint32]*muxStream
	ctrlCh      chan muxWriteJob
	dataCh      chan muxWriteJob
	pendingData *muxWriteJob
	config      muxConfig
	clientIP    string
	egressIP    string
	closed      bool
	mu          sync.Mutex
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

func (s *muxSession) enqueueWrite(
	messageType int,
	data []byte,
	wait bool,
	stream *muxStream,
	isData bool,
	accountBytes int,
) error {
	job := muxWriteJob{
		messageType: messageType,
		data:        data,
		enqueuedAt:  time.Now(),
	}
	if wait {
		job.done = make(chan error, 1)
	}
	if isData && stream != nil {
		limit := int32(muxMaxQueuedDataPerStream)
		if s.config.lowLatencyTest {
			limit = muxMaxQueuedDataPerStreamLowLatency
		} else if s.config.plain {
			limit = muxMaxQueuedDataPerStreamPlain
		}
		fairWaitStart := time.Time{}
		for {
			if stream.queuedDataFrames.Load() < limit {
				break
			}
			if fairWaitStart.IsZero() {
				fairWaitStart = time.Now()
			}
			select {
			case <-stream.done:
				return io.ErrClosedPipe
			case <-time.After(muxFairnessPollInterval):
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return io.ErrClosedPipe
			}
		}
		if !fairWaitStart.IsZero() {
			waited := time.Since(fairWaitStart)
			if waited >= muxSlowFairnessWaitLog {
				log.Printf(
					"mux data fairness wait stream=%d client=%s target=%s wait_ms=%d queued=%d",
					stream.id,
					s.clientIP,
					stream.target,
					waited.Milliseconds(),
					stream.queuedDataFrames.Load(),
				)
			}
		}
		stream.queuedDataFrames.Add(1)
		job.queuedCounter = &stream.queuedDataFrames
		job.streamID = stream.id
		if accountBytes > 0 {
			job.accountBytes = accountBytes
			job.sentCounter = &stream.sentBytes
			job.statsClient = s.clientIP
			job.statsTarget = stream.target
		}
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if job.queuedCounter != nil {
			job.queuedCounter.Add(-1)
		}
		return io.ErrClosedPipe
	}
	ch := s.dataCh
	if !isData {
		ch = s.ctrlCh
	}
	depth := len(s.ctrlCh) + len(s.dataCh)
	s.mu.Unlock()
	relayStatistics.observeMuxWriteQueueDepth(depth)

	waitStart := time.Now()
	sent := false
	func() {
		defer func() {
			if recover() != nil {
				sent = false
			}
		}()
		if isData && stream != nil {
			select {
			case ch <- job:
				sent = true
			case <-stream.done:
				sent = false
			}
		} else {
			select {
			case ch <- job:
				sent = true
			case <-time.After(muxUpstreamWriteTimeout):
				sent = false
			}
		}
	}()
	enqueueWait := time.Since(waitStart)
	relayStatistics.incMuxWriteWait(enqueueWait)
	if isData && stream != nil {
		stream.lastDataChWaitMs = enqueueWait.Milliseconds()
		if enqueueWait >= muxSlowDataChEnqueueLog {
			log.Printf(
				"mux dataCh enqueue wait stream=%d client=%s target=%s wait_ms=%d data_q=%d ctrl_q=%d queued_data=%d",
				stream.id,
				s.clientIP,
				stream.target,
				enqueueWait.Milliseconds(),
				len(s.dataCh),
				len(s.ctrlCh),
				stream.queuedDataFrames.Load(),
			)
		}
	}
	if !sent {
		if job.queuedCounter != nil {
			job.queuedCounter.Add(-1)
		}
		return io.ErrClosedPipe
	}
	if !wait {
		return nil
	}
	err := <-job.done
	return err
}

func (s *muxSession) waitQueuedDataDrain(stream *muxStream) {
	if stream == nil {
		return
	}
	deadline := time.Now().Add(muxWSWriteTimeout)
	for stream.queuedDataFrames.Load() > 0 {
		if time.Now().After(deadline) {
			return
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(muxFairnessPollInterval)
	}
}

func (s *muxSession) writeCtrlClose(streamID uint32, payload []byte) error {
	frame := encodeMuxFrame(muxTypeClose, streamID, payload)
	return s.enqueueWrite(websocket.BinaryMessage, frame, true, nil, false, 0)
}

func (s *muxSession) writeFrame(frameType byte, streamID uint32, payload []byte) error {
	if frameType == muxTypeClose {
		s.mu.Lock()
		stream := s.streams[streamID]
		s.mu.Unlock()
		s.waitQueuedDataDrain(stream)
		return s.writeCtrlClose(streamID, payload)
	}
	frame := encodeMuxFrame(frameType, streamID, payload)
	isData := frameType == muxTypeData
	var stream *muxStream
	accountBytes := 0
	if isData {
		s.mu.Lock()
		stream = s.streams[streamID]
		s.mu.Unlock()
		if stream == nil {
			return io.ErrClosedPipe
		}
		accountBytes = len(payload)
	}
	wait := !isData
	return s.enqueueWrite(
		websocket.BinaryMessage,
		frame,
		wait,
		stream,
		isData,
		accountBytes,
	)
}

func (s *muxSession) nextWriteJob() (muxWriteJob, bool) {
	for {
		select {
		case job, ok := <-s.ctrlCh:
			if ok {
				return job, true
			}
			if s.pendingData != nil {
				job = *s.pendingData
				s.pendingData = nil
				return job, true
			}
			job, ok = <-s.dataCh
			return job, ok
		default:
		}
		if s.pendingData != nil {
			job := *s.pendingData
			s.pendingData = nil
			return job, true
		}
		select {
		case job, ok := <-s.ctrlCh:
			if ok {
				return job, true
			}
			job, ok = <-s.dataCh
			return job, ok
		case job, ok := <-s.dataCh:
			if !ok {
				job, ok = <-s.ctrlCh
				return job, ok
			}
			select {
			case ctrlJob, ctrlOk := <-s.ctrlCh:
				if ctrlOk {
					s.pendingData = &job
					return ctrlJob, true
				}
				return job, true
			default:
				return job, true
			}
		}
	}
}

func (s *muxSession) finishWriteJob(job muxWriteJob, err error) {
	if job.queuedCounter != nil {
		job.queuedCounter.Add(-1)
	}
	if !job.enqueuedAt.IsZero() {
		inQueue := time.Since(job.enqueuedAt)
		relayStatistics.incMuxWriteInQueue(inQueue)
		if job.accountBytes > 0 && inQueue >= muxSlowWriteQueueLog {
			log.Printf(
				"mux data write queue slow stream=%d client=%s target=%s queue_ms=%d bytes=%d err=%v",
				job.streamID,
				job.statsClient,
				job.statsTarget,
				inQueue.Milliseconds(),
				job.accountBytes,
				err,
			)
		}
	}
	if err == nil && job.accountBytes > 0 {
		if job.sentCounter != nil {
			job.sentCounter.Add(int64(job.accountBytes))
		}
		if job.statsTarget != "" {
			relayStatistics.addBytesFromUpstream(
				job.statsClient,
				job.statsTarget,
				job.accountBytes,
			)
		}
	}
	if job.done != nil {
		job.done <- err
	}
}

func (s *muxSession) writeLoop() {
	for {
		job, ok := s.nextWriteJob()
		if !ok {
			return
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		var err error
		if closed {
			err = io.ErrClosedPipe
		} else {
			_ = s.conn.SetWriteDeadline(time.Now().Add(muxWSWriteTimeout))
			writeStarted := time.Now()
			err = s.conn.WriteMessage(job.messageType, job.data)
			writeMs := time.Since(writeStarted).Milliseconds()
			_ = s.conn.SetWriteDeadline(time.Time{})
			if writeMs >= muxSlowWSWriteLog.Milliseconds() {
				log.Printf(
					"mux ws WriteMessage slow stream=%d client=%s bytes=%d write_ms=%d data_q=%d ctrl_q=%d err=%v",
					job.streamID,
					s.clientIP,
					len(job.data),
					writeMs,
					len(s.dataCh),
					len(s.ctrlCh),
					err,
				)
			}
			if err != nil {
				s.mu.Lock()
				s.closed = true
				s.mu.Unlock()
				_ = s.conn.Close()
			}
		}
		s.finishWriteJob(job, err)
		if err != nil {
			for {
				dropped, ok := s.nextWriteJob()
				if !ok {
					return
				}
				s.finishWriteJob(dropped, err)
			}
		}
	}
}

func (s *muxSession) removeStream(id uint32) {
	s.finishStream(id, false, nil)
}

func (s *muxSession) closeAndRemoveStream(id uint32, payload []byte) {
	s.finishStream(id, true, payload)
}

func (s *muxSession) finishStream(id uint32, sendClose bool, payload []byte) {
	s.mu.Lock()
	stream, ok := s.streams[id]
	if ok {
		delete(s.streams, id)
	}
	s.mu.Unlock()
	if !ok {
		if sendClose {
			_ = s.writeCtrlClose(id, payload)
		}
		return
	}
	target := stream.target
	wasOpening := stream.opening
	select {
	case <-stream.done:
	default:
		close(stream.done)
	}
	if stream.tcp != nil {
		_ = stream.tcp.Close()
	}
	if wasOpening {
		if sendClose {
			_ = s.writeCtrlClose(id, payload)
		}
		return
	}
	s.waitQueuedDataDrain(stream)
	if sendClose {
		_ = s.writeCtrlClose(id, payload)
	}
	log.Printf(
		"mux stream close stream=%d client=%s target=%s egress=%s sent=%d recv=%d last_write_frame_ms=%d toDC_blocks=%d",
		id,
		s.clientIP,
		target,
		s.egressIP,
		stream.sentBytes.Load(),
		stream.recvBytes,
		stream.lastWriteFrameMs,
		stream.toDCEnqueueBlockLogs,
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
	target, err := parseOpenTarget(payload)
	if err != nil {
		relayStatistics.incMuxOpenBad()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailBad})
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if _, exists := s.streams[streamID]; exists {
		n := len(s.streams)
		s.mu.Unlock()
		relayStatistics.incMuxOpenBad()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailBad})
		log.Printf(
			"mux open bad duplicate stream=%d client=%s streams=%d",
			streamID,
			s.clientIP,
			n,
		)
		return
	}
	if len(s.streams) >= s.config.maxStreams {
		n := len(s.streams)
		max := s.config.maxStreams
		s.mu.Unlock()
		relayStatistics.incMuxOpenLimit()
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailLimit})
		log.Printf(
			"mux open limit stream=%d client=%s streams=%d max=%d",
			streamID,
			s.clientIP,
			n,
			max,
		)
		return
	}
	placeholder := &muxStream{
		id:     streamID,
		done:   make(chan struct{}),
		toDC:   make(chan []byte, muxToDCQueueSize),
		target: target,
		opening: true,
	}
	placeholder.touchActivity()
	s.streams[streamID] = placeholder
	s.mu.Unlock()

	go s.openStreamAsync(streamID, target)
}

func (s *muxSession) openStreamAsync(streamID uint32, target string) {
	dialStarted := time.Now()
	tcp, fromPool, err := acquireUpstream(target, s.clientIP, s.egressIP)
	dialMs := time.Since(dialStarted).Milliseconds()
	relayStatistics.recordMuxOpenDial(target, dialMs)
	if !fromPool && dialMs > 100 {
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
		relayStatistics.incMuxOpenFailDial()
		s.removeStream(streamID)
		_ = s.writeFrame(muxTypeOpenFail, streamID, []byte{muxOpenFailDial})
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = tcp.Close()
		s.removeStream(streamID)
		return
	}
	existing, ok := s.streams[streamID]
	if !ok || !existing.opening {
		s.mu.Unlock()
		_ = tcp.Close()
		return
	}
	existing.tcp = tcp
	existing.opening = false
	existing.touchActivity()
	s.mu.Unlock()

	relayStatistics.muxStreamOpened(s.clientIP, target)
	payload := make([]byte, 5)
	binary.BigEndian.PutUint32(payload[0:4], uint32(dialMs))
	if fromPool {
		payload[4] = 1
	}
	writeStarted := time.Now()
	err = s.writeFrame(muxTypeOpenOk, streamID, payload)
	writeMs := time.Since(writeStarted).Milliseconds()
	if writeMs > 100 || dialMs > 100 {
		log.Printf(
			"mux open ok stream=%d client=%s target=%s dial_ms=%d pool=%v write_ms=%d",
			streamID,
			s.clientIP,
			target,
			dialMs,
			fromPool,
			writeMs,
		)
	}
	if err != nil {
		s.removeStream(streamID)
		return
	}

	go s.pumpToDC(existing)
	go s.pumpUpstream(existing)
}

func (st *muxStream) noteUpstreamReadSuccess(now time.Time, readBytes int) {
	st.lastReadAt = now
	if readBytes < muxUpstreamReadStallRecoverMinBytes {
		return
	}
	st.consecutiveReadStalls = 0
	st.readStallLogged = false
}

func (st *muxStream) trackUpstreamReadWait(maxConsecutive int) bool {
	if st.upstreamBytes < muxUpstreamReadStallMinBytes || st.lastReadAt.IsZero() {
		return false
	}
	gap := time.Since(st.lastReadAt)
	if gap < muxUpstreamReadStallThreshold {
		return false
	}
	if !st.readStallLogged {
		st.readStallLogged = true
		log.Printf(
			"mux upstream read stall stream=%d target=%s gap_ms=%d bytes=%d consecutive=1",
			st.id,
			st.target,
			gap.Milliseconds(),
			st.upstreamBytes,
		)
		relayStatistics.incMuxUpstreamReadStall()
		st.consecutiveReadStalls = 1
	} else {
		st.consecutiveReadStalls++
	}
	if maxConsecutive <= 0 {
		return false
	}
	return st.consecutiveReadStalls >= maxConsecutive
}

func (s *muxSession) rotateUpstreamStream(stream *muxStream, reason string) {
	log.Printf(
		"mux upstream read stall rotate stream=%d client=%s target=%s reason=%s consecutive=%d bytes=%d",
		stream.id,
		s.clientIP,
		stream.target,
		reason,
		stream.consecutiveReadStalls,
		stream.upstreamBytes,
	)
	relayStatistics.incMuxUpstreamReadStallRotate()
	s.closeAndRemoveStream(stream.id, nil)
}

func (s *muxSession) pumpToDC(stream *muxStream) {
	for {
		select {
		case <-stream.done:
			return
		case payload, ok := <-stream.toDC:
			if !ok {
				return
			}
			if stream.tcp == nil {
				continue
			}
			stream.touchActivity()
			qLen := len(stream.toDC)
			_ = stream.tcp.SetWriteDeadline(time.Now().Add(muxUpstreamWriteTimeout))
			writeStarted := time.Now()
			_, err := stream.tcp.Write(payload)
			writeMs := time.Since(writeStarted).Milliseconds()
			if writeMs >= muxSlowToDCWriteLog.Milliseconds() || qLen >= muxToDCQueueSize/2 {
				log.Printf(
					"mux toDC write stream=%d client=%s target=%s egress=%s bytes=%d write_ms=%d toDC_q=%d err=%v",
					stream.id,
					s.clientIP,
					stream.target,
					s.egressIP,
					len(payload),
					writeMs,
					qLen,
					err,
				)
			}
			if err != nil {
				s.closeAndRemoveStream(stream.id, nil)
				return
			}
			relayStatistics.addBytesToUpstream(s.clientIP, stream.target, len(payload))
		}
	}
}

func (s *muxSession) waitForCtrlDrain(stream *muxStream) error {
	for len(s.ctrlCh) > 0 {
		select {
		case <-stream.done:
			return io.ErrClosedPipe
		case <-time.After(muxCtrlDrainPollInterval):
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return io.ErrClosedPipe
		}
	}
	return nil
}

func (s *muxSession) pumpUpstream(stream *muxStream) {
	chunk := muxPumpReadChunkBytes
	if s.config.lowLatencyTest {
		chunk = muxPumpReadChunkLowLatencyBytes
	}
	buffer := make([]byte, chunk)
	plain := s.config.plain
	maxConsecutive := s.config.maxConsecutiveReadStalls
	for {
		select {
		case <-stream.done:
			return
		default:
		}
		if !plain {
			if err := s.waitForCtrlDrain(stream); err != nil {
				return
			}
		}
		if stream.trackUpstreamReadWait(maxConsecutive) {
			s.rotateUpstreamStream(stream, "consecutive_stalls")
			return
		}
		_ = stream.tcp.SetReadDeadline(time.Now().Add(muxUpstreamReadStallThreshold))
		readStarted := time.Now()
		n, err := stream.tcp.Read(buffer)
		readWaitMs := time.Since(readStarted).Milliseconds()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				stream.touchActivity()
				stream.consecutiveReadTimeouts++
				if stream.consecutiveReadTimeouts == 1 ||
					stream.consecutiveReadTimeouts%5 == 0 {
					log.Printf(
						"mux upstream read timeout stream=%d client=%s target=%s egress=%s timeouts=%d upstream_bytes=%d queued_data=%d toDC_q=%d prev_write_frame_ms=%d data_q=%d",
						stream.id,
						s.clientIP,
						stream.target,
						s.egressIP,
						stream.consecutiveReadTimeouts,
						stream.upstreamBytes,
						stream.queuedDataFrames.Load(),
						len(stream.toDC),
						stream.lastWriteFrameMs,
						len(s.dataCh),
					)
				}
				continue
			}
			s.closeAndRemoveStream(stream.id, nil)
			return
		}
		now := time.Now()
		timeouts := stream.consecutiveReadTimeouts
		stream.consecutiveReadTimeouts = 0
		if !stream.lastUpstreamReadAt.IsZero() &&
			stream.upstreamGapLogCount < 40 {
			gap := now.Sub(stream.lastUpstreamReadAt)
			if gap >= muxUpstreamReadGapLog {
				cause := "dc_idle"
				if stream.lastWriteFrameMs >= muxSlowWriteFrameLog.Milliseconds() &&
					stream.lastWriteFrameMs*2 >= gap.Milliseconds() {
					cause = "prev_write_frame"
				} else if timeouts >= 3 {
					cause = "dc_idle_timeouts"
				}
				log.Printf(
					"mux upstream read gap stream=%d client=%s target=%s egress=%s gap_ms=%d read_wait_ms=%d read=%d upstream_bytes=%d queued_data=%d toDC_q=%d data_q=%d ctrl_q=%d prev_write_frame_ms=%d prev_datach_wait_ms=%d timeouts=%d cause=%s",
					stream.id,
					s.clientIP,
					stream.target,
					s.egressIP,
					gap.Milliseconds(),
					readWaitMs,
					n,
					stream.upstreamBytes,
					stream.queuedDataFrames.Load(),
					len(stream.toDC),
					len(s.dataCh),
					len(s.ctrlCh),
					stream.lastWriteFrameMs,
					stream.lastDataChWaitMs,
					timeouts,
					cause,
				)
				stream.upstreamGapLogCount++
			}
		}
		stream.lastUpstreamReadAt = now
		if !plain {
			stream.noteUpstreamReadSuccess(now, n)
		} else {
			stream.lastReadAt = now
			if n >= muxUpstreamReadStallRecoverMinBytes {
				stream.consecutiveReadStalls = 0
				stream.readStallLogged = false
			}
		}
		stream.upstreamBytes += int64(n)
		stream.touchActivity()
		if !plain {
			if err := s.waitForCtrlDrain(stream); err != nil {
				return
			}
		}
		writeFrameStarted := time.Now()
		err = s.writeFrame(muxTypeData, stream.id, buffer[:n])
		stream.lastWriteFrameMs = time.Since(writeFrameStarted).Milliseconds()
		if stream.lastWriteFrameMs >= muxSlowWriteFrameLog.Milliseconds() {
			log.Printf(
				"mux writeFrame slow stream=%d client=%s target=%s write_frame_ms=%d datach_wait_ms=%d queued_data=%d data_q=%d bytes=%d",
				stream.id,
				s.clientIP,
				stream.target,
				stream.lastWriteFrameMs,
				stream.lastDataChWaitMs,
				stream.queuedDataFrames.Load(),
				len(s.dataCh),
				n,
			)
		}
		if err != nil {
			s.removeStream(stream.id)
			return
		}
	}
}

func (s *muxSession) expireIdleStream(id uint32) {
	log.Printf("mux stream idle timeout id=%d client=%s", id, s.clientIP)
	relayStatistics.incMuxStreamIdle()
	s.closeAndRemoveStream(id, nil)
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
			if err := s.enqueueWrite(websocket.PingMessage, nil, true, nil, false, 0); err != nil {
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
	buf := append([]byte(nil), payload...)
	stream.recvBytes += int64(len(payload))
	stream.touchActivity()
	select {
	case <-stream.done:
		return
	case stream.toDC <- buf:
		return
	default:
	}
	if stream.toDCEnqueueBlockLogs < 40 {
		stream.toDCEnqueueBlockLogs++
		log.Printf(
			"mux toDC enqueue block stream=%d client=%s target=%s toDC_q=%d/%d bytes=%d",
			stream.id,
			s.clientIP,
			stream.target,
			len(stream.toDC),
			cap(stream.toDC),
			len(payload),
		)
	}
	blockStarted := time.Now()
	select {
	case <-stream.done:
		return
	case stream.toDC <- buf:
		waited := time.Since(blockStarted)
		if waited >= muxSlowToDCEnqueueLog {
			log.Printf(
				"mux toDC enqueue wait stream=%d client=%s target=%s wait_ms=%d toDC_q=%d bytes=%d",
				stream.id,
				s.clientIP,
				stream.target,
				waited.Milliseconds(),
				len(stream.toDC),
				len(payload),
			)
		}
	}
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
		s.closed = true
		active := len(s.streams)
		s.mu.Unlock()
		close(s.ctrlCh)
		close(s.dataCh)
		if active > 0 {
			log.Printf(
				"mux tunnel ending with %d active streams client=%s",
				active,
				s.clientIP,
			)
			relayStatistics.incTunnelEndedWithStreams()
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
			if err := s.enqueueWrite(websocket.PongMessage, data, true, nil, false, 0); err != nil {
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
			relayStatistics.incMuxDecodeError()
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
			relayStatistics.incMuxUnknownFrame()
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
	clientIP := clientIPFromRequest(r)
	egressIP := egressIPFromRequest(r)
	authLabel, ok := auth.validate(r)
	if !ok {
		relayStatistics.incAuthFailure(clientIP)
		writeUnauthorized(w)
		return
	}
	if !limiter.tryAcquire(clientIP) {
		log.Printf("mux tunnel limit reached for %s", clientIP)
		relayStatistics.incTunnelLimitRejected(clientIP)
		http.Error(w, "too many mux tunnels", http.StatusTooManyRequests)
		return
	}
	relayStatistics.muxTunnelOpened(clientIP)
	defer relayStatistics.muxTunnelClosed(clientIP)
	defer limiter.release(clientIP)

	conn, err := muxWSUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("mux upgrade failed: %v", err)
		relayStatistics.incWSUpgradeFailure()
		return
	}
	if conn.Subprotocol() != muxSubprotocol {
		log.Printf("mux bad subprotocol: %q", conn.Subprotocol())
		relayStatistics.incWSBadSubprotocol()
		_ = conn.Close()
		return
	}
	writeBuf := 0
	if !config.plain {
		writeBuf = muxClientWriteBufferBytes
		if config.lowLatencyTest {
			writeBuf = muxClientWriteBufferLowLatencyBytes
		}
		if tcp, ok := conn.NetConn().(*net.TCPConn); ok {
			if err := tcp.SetWriteBuffer(writeBuf); err != nil {
				log.Printf("mux set write buffer failed client=%s: %v", clientIP, err)
			}
			_ = tcp.SetNoDelay(true)
		}
	}
	log.Printf(
		"mux tunnel from %s client=%s egress=%s auth=%s write_buf=%d low_latency=%v plain=%v",
		r.RemoteAddr,
		clientIP,
		egressIP,
		authLabel,
		writeBuf,
		config.lowLatencyTest,
		config.plain,
	)
	dataQueue := muxWriteDataQueueSize
	if config.lowLatencyTest {
		dataQueue = 2
	}
	session := &muxSession{
		conn:     conn,
		streams:  make(map[uint32]*muxStream),
		ctrlCh:   make(chan muxWriteJob, muxWriteCtrlQueueSize),
		dataCh:   make(chan muxWriteJob, dataQueue),
		config:   config,
		clientIP: clientIP,
		egressIP: egressIP,
	}
	go session.writeLoop()
	session.readLoop()
}
