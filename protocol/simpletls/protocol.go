// Package simpletls implements a lightweight proxy protocol over TLS.
//
// The wire format is intentionally minimal: a single TCP+TLS connection
// carries one logical proxy stream at a time, but the connection may be
// reused for subsequent streams (see outbound.go). Every stream starts with
// a header frame whose data is [auth?][SocksAddr] — the 32-byte auth token
// is present on the first stream of a connection and omitted afterwards.
// The header travels through the same frame format as payload data, so it
// picks up the per-stream random padding (first paddedFrames frames per
// direction; the same approach naive takes with its kFirstPaddings).
package simpletls

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

// errEOS is the sentinel returned by readFrame for a clean end-of-stream
// marker. It is distinct from io.EOF so callers can tell a protocol-level
// shutdown apart from the underlying connection dropping without one.
var errEOS = errors.New("simpletls: end of stream")

// Wire-format constants.
//
//	authSize       sha256 of password, sent once per TCP+TLS connection.
//	frameHeader    [2B data length][2B padding length].
//	maxFrameData   inclusive upper bound on data per frame; the next two
//	               values are reserved as control markers (frameErr, frameEOS).
//	frameErr       remote signalled stream failure; padding-length field
//	               carries the byte length of the utf-8 reason text that
//	               immediately follows the header.
//	frameEOS       clean end-of-stream; padding-length field must be zero.
//	paddedFrames   first N frames per direction per stream are padded; matches
//	               naive's kFirstPaddings, chosen to cover common initial
//	               handshake bursts. After N frames padding stops for the
//	               remaining lifetime of the stream.
const (
	authSize     = sha256.Size
	frameHeader  = 4
	maxFrameData = 0xFFFD
	frameErr     = 0xFFFE
	frameEOS     = 0xFFFF
	paddedFrames = 8
)

func passwordKey(password string) [authSize]byte {
	return sha256.Sum256([]byte(password))
}

// padding is the per-direction state for the padding scheme. The zero value
// represents a fresh stream: the next paddedFrames calls to next return a
// random padding length in [0, 255], after which padding is disabled.
type padding struct {
	frames uint8
}

func (p *padding) next() int {
	if p.frames >= paddedFrames {
		return 0
	}
	p.frames++
	var b [1]byte
	_, _ = rand.Read(b[:])
	return int(b[0])
}

// writeFrame serialises one frame to w. data must be at most maxFrameData
// bytes; callers split larger payloads beforehand.
func writeFrame(w io.Writer, p *padding, data []byte) error {
	padLen := p.next()
	frame := buf.NewSize(frameHeader + len(data) + padLen)
	defer frame.Release()
	binary.BigEndian.PutUint16(frame.Extend(2), uint16(len(data)))
	binary.BigEndian.PutUint16(frame.Extend(2), uint16(padLen))
	common.Must1(frame.Write(data))
	common.Must(frame.WriteZeroN(padLen))
	_, err := w.Write(frame.Bytes())
	return err
}

// writeEOS sends an end-of-stream marker: a zero-padding frame whose data
// length field is the reserved frameEOS value.
func writeEOS(w io.Writer) error {
	var hdr [frameHeader]byte
	binary.BigEndian.PutUint16(hdr[0:2], frameEOS)
	_, err := w.Write(hdr[:])
	return err
}

// writeErr sends a remote-failure marker carrying msg as the reason text.
// The peer's readFrame surfaces this as an error from Read, so the caller
// sees a meaningful reason instead of a bare EOF. msg is truncated to
// maxFrameData bytes since it has to fit in the uint16 length field.
func writeErr(w io.Writer, msg string) error {
	body := []byte(msg)
	if len(body) > maxFrameData {
		body = body[:maxFrameData]
	}
	frame := buf.NewSize(frameHeader + len(body))
	defer frame.Release()
	binary.BigEndian.PutUint16(frame.Extend(2), uint16(frameErr))
	binary.BigEndian.PutUint16(frame.Extend(2), uint16(len(body)))
	common.Must1(frame.Write(body))
	_, err := w.Write(frame.Bytes())
	return err
}

// readFrame reads one frame from r and returns its data. EOS markers surface
// as errEOS, frameErr markers as "remote: ..." errors, and any underlying
// I/O error (io.EOF, io.ErrUnexpectedEOF, ...) is propagated unchanged.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [frameHeader]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	dataLen := binary.BigEndian.Uint16(hdr[0:2])
	padLen := binary.BigEndian.Uint16(hdr[2:4])
	if dataLen == frameEOS {
		// Disallow padding on EOS so a peer cannot leave bytes in the
		// stream that the next ReadAddrPort would mis-parse.
		if padLen != 0 {
			return nil, E.New("simpletls: EOS frame with padding")
		}
		return nil, errEOS
	}
	if dataLen == frameErr {
		if padLen == 0 {
			return nil, E.New("remote: unspecified error")
		}
		msg := make([]byte, padLen)
		if _, err := io.ReadFull(r, msg); err != nil {
			return nil, err
		}
		return nil, E.New("remote: ", string(msg))
	}
	data := make([]byte, dataLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	if padLen > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(padLen)); err != nil {
			return nil, err
		}
	}
	return data, nil
}
