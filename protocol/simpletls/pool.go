package simpletls

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
)

// Pool defaults match anytls (30s/30s); they're not exposed because no
// real-world need has been observed to tune them.
const (
	maxIdleConnections = 8
	poolIdleTimeout    = 30 * time.Second
	poolCheckEvery     = 30 * time.Second
)

// connPool maintains a set of idle TLS connections that have already completed
// authentication. Each connection carries at most one logical stream at a
// time; once a stream finishes cleanly the connection is returned to the
// pool. Idle connections are aged out by a background sweeper.
type connPool struct {
	mu       sync.Mutex
	idle     []pooledConn
	keepIdle bool
	closed   bool

	once sync.Once
	stop chan struct{}
}

type pooledConn struct {
	conn      net.Conn
	idleSince time.Time
}

func newConnPool(ctx context.Context) *connPool {
	p := &connPool{
		keepIdle: true,
		stop:     make(chan struct{}),
	}
	go p.sweep(ctx)
	return p
}

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

// put returns a healthy connection to the pool. The connection is closed
// instead when the pool is shut down or idle caching is disabled. When the
// idle cap is reached, the oldest connection is evicted so the pool keeps
// the connections most recently shown to be alive.
func (p *connPool) put(conn net.Conn) {
	p.mu.Lock()
	if p.closed || !p.keepIdle {
		p.mu.Unlock()
		common.Close(conn)
		return
	}
	var evicted net.Conn
	if len(p.idle) >= maxIdleConnections {
		evicted = p.idle[0].conn
		p.idle = p.idle[1:]
	}
	p.idle = append(p.idle, pooledConn{conn: conn, idleSince: time.Now()})
	p.mu.Unlock()
	common.Close(evicted)
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

// SetKeepIdleConnections enables or disables caching idle connections. When
// keep is false, existing idle connections are dropped and put closes the
// connection instead of caching it.
func (p *connPool) SetKeepIdleConnections(keep bool) {
	p.mu.Lock()
	p.keepIdle = keep
	var idle []pooledConn
	if !keep {
		idle = p.idle
		p.idle = nil
	}
	p.mu.Unlock()
	for _, e := range idle {
		common.Close(e.conn)
	}
}

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
	ticker := time.NewTicker(poolCheckEvery)
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
		cutoff := time.Now().Add(-poolIdleTimeout)
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
