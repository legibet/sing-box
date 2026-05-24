package simpletls

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

// Pool defaults match anytls (30s/30s); they're not exposed because no
// real-world need has been observed to tune them.
const (
	poolIdleTimeout = 30 * time.Second
	poolCheckEvery  = 30 * time.Second
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SimpleTLSOutboundOptions](registry, C.TypeSimpleTLS, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger     logger.ContextLogger
	tlsDialer  tls.Dialer
	serverAddr M.Socksaddr
	key        [authSize]byte
	pool       *connPool
	uotClient  *uot.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SimpleTLSOutboundOptions) (adapter.Outbound, error) {
	if options.Password == "" {
		return nil, E.New("missing password")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	out := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeSimpleTLS, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:     logger,
		tlsDialer:  tls.NewDialer(outboundDialer, tlsConfig),
		serverAddr: options.ServerOptions.Build(),
		key:        passwordKey(options.Password),
		pool:       newConnPool(ctx, poolIdleTimeout, poolCheckEvery),
	}
	out.uotClient = &uot.Client{
		Dialer:  (*tcpDialer)(out),
		Version: uot.Version,
	}
	return out, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.dialStream(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	}
	return nil, E.Extend(N.ErrUnknownNetwork, network)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) Close() error {
	return h.pool.Close()
}

// InterfaceUpdated drops pooled connections that were established over a
// network interface that has just changed; they cannot be expected to remain
// usable. New dials after this point will create fresh connections.
func (h *Outbound) InterfaceUpdated() {
	h.pool.Reset()
}

// dialStream returns a streamConn ready for destination, reusing a pooled
// connection if one is available and otherwise dialling a fresh one.
func (h *Outbound) dialStream(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, withAuth, err := h.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	stream := h.wrapStream(conn)
	if err := h.openStream(stream, destination, withAuth); err != nil {
		common.Close(stream)
		return nil, err
	}
	return stream, nil
}

// acquireConn returns a TLS connection. withAuth is true for freshly dialled
// conns, signalling that the first stream's header must include the 32-byte
// auth token; pooled conns set it to false since auth has already been done
// once on this TLS connection.
func (h *Outbound) acquireConn(ctx context.Context) (net.Conn, bool, error) {
	if conn := h.pool.take(); conn != nil {
		return conn, false, nil
	}
	conn, err := h.tlsDialer.DialTLSContext(ctx, h.serverAddr)
	if err != nil {
		return nil, false, err
	}
	return conn, true, nil
}

// openStream writes the per-stream header [auth?][SocksAddr] through the
// streamConn so it travels as a padded frame, randomising its on-wire size.
func (h *Outbound) openStream(stream net.Conn, destination M.Socksaddr, withAuth bool) error {
	size := M.SocksaddrSerializer.AddrPortLen(destination)
	if withAuth {
		size += authSize
	}
	header := buf.NewSize(size)
	defer header.Release()
	if withAuth {
		common.Must1(header.Write(h.key[:]))
	}
	if err := M.SocksaddrSerializer.WriteAddrPort(header, destination); err != nil {
		return err
	}
	_, err := stream.Write(header.Bytes())
	return err
}

// wrapStream attaches the pool-return hook. The hook fires exactly once when
// the stream finishes: a clean shutdown returns the connection to the pool,
// otherwise it is closed.
func (h *Outbound) wrapStream(conn net.Conn) net.Conn {
	return newStreamConn(conn, func(reusable bool) {
		if reusable {
			h.pool.put(conn)
		} else {
			common.Close(conn)
		}
	})
}

// tcpDialer adapts Outbound.dialStream to the N.Dialer surface required by
// uot.Client; UDP packets are tunnelled through a TCP stream whose
// destination is uot.MagicAddress.
type tcpDialer Outbound

func (d *tcpDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	return (*Outbound)(d).dialStream(ctx, destination)
}

func (d *tcpDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
