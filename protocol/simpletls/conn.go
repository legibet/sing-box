package simpletls

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common"
)

// streamConn presents one logical proxy stream as a net.Conn on top of a
// shared TLS connection. It frames every Write (splitting at maxFrameData)
// and parses incoming frames in Read. The first paddedFrames frames in each
// direction carry random padding; see protocol.go.
//
// streamConn supports TCP-style half-close: CloseWrite sends an EOS marker in
// the write direction; Read returns io.EOF once the peer's EOS is observed.
// Close finalises the stream and reports through onClose whether the
// underlying conn ended cleanly enough to be reused (both halves reached EOS
// and no IO error occurred). When not reusable, Close also closes the
// underlying conn so that any concurrent Read or Write is unblocked.
type streamConn struct {
	conn net.Conn

	readMu  sync.Mutex
	readBuf []byte
	readEOS atomic.Bool

	writeMu  sync.Mutex
	writePad padding
	writeEOS atomic.Bool

	failed    atomic.Bool
	closeOnce sync.Once
	onClose   func(reusable bool)
}

// newStreamConn wraps conn with a streamConn whose onClose hook is invoked
// exactly once when the stream finishes. reusable indicates whether the
// underlying conn may be returned to a pool.
func newStreamConn(conn net.Conn, onClose func(reusable bool)) *streamConn {
	return &streamConn{conn: conn, onClose: onClose}
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	// Loop over empty data frames: a malicious peer may send frames with
	// dataLen=0, and returning (0, nil) to the caller would violate the
	// io.Reader contract.
	for len(c.readBuf) == 0 {
		if c.readEOS.Load() {
			return 0, io.EOF
		}
		data, err := readFrame(c.conn)
		switch {
		case err == nil:
			c.readBuf = data
		case errors.Is(err, errEOS):
			c.readEOS.Store(true)
			return 0, io.EOF
		default:
			// Anything else — including a bare io.EOF — means the
			// stream did not end cleanly; mark the conn unreusable.
			c.failed.Store(true)
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOS.Load() {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(p) > 0 {
		chunk := min(len(p), maxFrameData)
		if err := writeFrame(c.conn, &c.writePad, p[:chunk]); err != nil {
			c.failed.Store(true)
			return written, err
		}
		written += chunk
		p = p[chunk:]
	}
	return written, nil
}

func (c *streamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOS.Load() {
		return nil
	}
	c.writeEOS.Store(true)
	if err := writeEOS(c.conn); err != nil {
		c.failed.Store(true)
		return err
	}
	return nil
}

// HandshakeFailure is invoked by the sing-box routing layer when the upstream
// dial of the requested destination fails. The reason is forwarded to the
// peer as a frameErr marker so the client surfaces a meaningful error
// instead of a bare EOF. After this call the write side is finalised; Close
// will then tear the underlying conn down because the stream did not end
// cleanly.
func (c *streamConn) HandshakeFailure(err error) error {
	if err == nil {
		return nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeEOS.Load() {
		return nil
	}
	c.writeEOS.Store(true)
	if wErr := writeErr(c.conn, err.Error()); wErr != nil {
		c.failed.Store(true)
		return wErr
	}
	return nil
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		readEOS := c.readEOS.Load()
		writeEOS := c.writeEOS.Load()
		reusable := readEOS && writeEOS && !c.failed.Load()
		// When not reusable, eagerly close the underlying conn before
		// touching writeMu in CloseWrite: a Read or Write may be blocked
		// on it, and an unreusable connection has nothing to lose.
		if !reusable {
			common.Close(c.conn)
		}
		if !writeEOS {
			_ = c.CloseWrite()
		}
		c.onClose(reusable)
	})
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *streamConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// NeedAdditionalReadDeadline lets sing-box install per-read timeouts; streams
// share a long-lived TLS connection, so their idle behaviour differs from a
// raw TCP conn.
func (c *streamConn) NeedAdditionalReadDeadline() bool { return true }

func (c *streamConn) Upstream() any { return c.conn }
