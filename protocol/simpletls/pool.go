package simpletls

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
)

// connPool maintains a set of idle TLS connections that have already completed
// authentication. Each connection carries at most one logical stream at a
// time; once a stream finishes cleanly the connection is returned to the
// pool. Idle connections are aged out by a background sweeper.
//
// All exported methods are safe for concurrent use.
type connPool struct {
	idleTimeout time.Duration
	checkEvery  time.Duration

	mu     sync.Mutex
	idle   []pooledConn
	closed bool

	once sync.Once
	stop chan struct{}
}

type pooledConn struct {
	conn      net.Conn
	idleSince time.Time
}

func newConnPool(ctx context.Context, idleTimeout, checkEvery time.Duration) *connPool {
	p := &connPool{
		idleTimeout: idleTimeout,
		checkEvery:  checkEvery,
		stop:        make(chan struct{}),
	}
	go p.sweep(ctx)
	return p
}

// take returns an idle connection, or nil if the pool is empty.
func (p *connPool) take() net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.idle) == 0 {
		return nil
	}
	// Prefer the most-recently-returned connection so that the oldest
	// connections in the pool age out naturally.
	idx := len(p.idle) - 1
	c := p.idle[idx].conn
	p.idle = p.idle[:idx]
	return c
}

// put returns a healthy connection to the pool. If the pool is already
// closed, the connection is closed instead.
func (p *connPool) put(conn net.Conn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		common.Close(conn)
		return
	}
	p.idle = append(p.idle, pooledConn{conn: conn, idleSince: time.Now()})
	p.mu.Unlock()
}

func (p *connPool) Close() error {
	p.once.Do(func() { close(p.stop) })
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, e := range idle {
		common.Close(e.conn)
	}
	return nil
}

// Reset drops all idle connections. The pool remains usable; new dials may
// be pooled after Reset returns.
func (p *connPool) Reset() {
	p.mu.Lock()
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, e := range idle {
		common.Close(e.conn)
	}
}

func (p *connPool) sweep(ctx context.Context) {
	ticker := time.NewTicker(p.checkEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stop:
			return
		case <-ticker.C:
		}
		var expired []net.Conn
		cutoff := time.Now().Add(-p.idleTimeout)
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		kept := p.idle[:0]
		for _, e := range p.idle {
			if e.idleSince.Before(cutoff) {
				expired = append(expired, e.conn)
			} else {
				kept = append(kept, e)
			}
		}
		p.idle = kept
		p.mu.Unlock()
		for _, c := range expired {
			common.Close(c)
		}
	}
}
