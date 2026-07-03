package main

import (
	"net"
	"sync"
	"time"
)

type pooledConn struct {
	conn     net.Conn
	dialedAt time.Time
}

type upstreamPool struct {
	size    int
	maxIdle time.Duration

	mu       sync.Mutex
	idle     map[string][]pooledConn
	lastUsed map[string]time.Time
	filling  map[string]bool
}

var upstreamConnPool *upstreamPool

func initUpstreamPool(size int, maxIdle time.Duration) {
	if size <= 0 || maxIdle <= 0 {
		upstreamConnPool = nil
		return
	}
	p := &upstreamPool{
		size:     size,
		maxIdle:  maxIdle,
		idle:     make(map[string][]pooledConn),
		lastUsed: make(map[string]time.Time),
		filling:  make(map[string]bool),
	}
	upstreamConnPool = p
	go p.maintainLoop()
}

func acquireUpstream(target, clientIP string) (net.Conn, bool, error) {
	if upstreamConnPool != nil {
		if conn := upstreamConnPool.get(target); conn != nil {
			upstreamConnPool.markUsed(target)
			return conn, true, nil
		}
	}
	conn, err := dialUpstream(target, clientIP)
	if err != nil {
		return nil, false, err
	}
	if upstreamConnPool != nil {
		upstreamConnPool.markUsed(target)
	}
	return conn, false, nil
}

func (p *upstreamPool) get(target string) net.Conn {
	for {
		p.mu.Lock()
		list := p.idle[target]
		if len(list) == 0 {
			p.mu.Unlock()
			return nil
		}
		pc := list[len(list)-1]
		p.idle[target] = list[:len(list)-1]
		p.mu.Unlock()
		if time.Since(pc.dialedAt) > p.maxIdle || !upstreamConnHealthy(pc.conn) {
			_ = pc.conn.Close()
			continue
		}
		return pc.conn
	}
}

func (p *upstreamPool) markUsed(target string) {
	p.mu.Lock()
	p.lastUsed[target] = time.Now()
	fill := len(p.idle[target]) < p.size && !p.filling[target]
	if fill {
		p.filling[target] = true
	}
	p.mu.Unlock()
	if fill {
		go p.fill(target)
	}
}

func (p *upstreamPool) fill(target string) {
	defer func() {
		p.mu.Lock()
		p.filling[target] = false
		p.mu.Unlock()
	}()
	for {
		p.mu.Lock()
		deficit := p.size - len(p.idle[target])
		p.mu.Unlock()
		if deficit <= 0 {
			return
		}
		conn, err := dialUpstream(target, "pool")
		if err != nil {
			relayStatistics.incUpstreamPoolDialError()
			return
		}
		p.mu.Lock()
		if len(p.idle[target]) >= p.size {
			p.mu.Unlock()
			_ = conn.Close()
			return
		}
		p.idle[target] = append(p.idle[target], pooledConn{
			conn:     conn,
			dialedAt: time.Now(),
		})
		p.mu.Unlock()
	}
}

func (p *upstreamPool) maintainLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.prune()
	}
}

func (p *upstreamPool) prune() {
	now := time.Now()
	var toClose []net.Conn
	var refill []string
	p.mu.Lock()
	for target, list := range p.idle {
		kept := list[:0]
		for _, pc := range list {
			if now.Sub(pc.dialedAt) > p.maxIdle {
				toClose = append(toClose, pc.conn)
				continue
			}
			kept = append(kept, pc)
		}
		if len(kept) == 0 {
			delete(p.idle, target)
		} else {
			p.idle[target] = kept
		}
	}
	for target, used := range p.lastUsed {
		if now.Sub(used) > 2*p.maxIdle {
			for _, pc := range p.idle[target] {
				toClose = append(toClose, pc.conn)
			}
			delete(p.idle, target)
			delete(p.lastUsed, target)
			delete(p.filling, target)
			continue
		}
		if len(p.idle[target]) < p.size && !p.filling[target] {
			p.filling[target] = true
			refill = append(refill, target)
		}
	}
	p.mu.Unlock()
	for _, conn := range toClose {
		_ = conn.Close()
	}
	for _, target := range refill {
		go p.fill(target)
	}
}

// upstreamConnHealthy reports whether a pooled connection is still usable.
// Telegram DC connections stay silent until the client sends the transport
// handshake, so a healthy idle connection yields a read timeout. Any EOF or
// error means the peer closed it, and any unexpected bytes make it unsafe to
// hand off (they would corrupt the stream), so both cases discard the conn.
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
