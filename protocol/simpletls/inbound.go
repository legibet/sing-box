package simpletls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SimpleTLSInboundOptions](registry, C.TypeSimpleTLS, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	tlsConfig tls.ServerConfig
	users     map[[authSize]byte]string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SimpleTLSInboundOptions) (adapter.Inbound, error) {
	if len(options.Users) == 0 {
		return nil, E.New("missing users")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	users := make(map[[authSize]byte]string, len(options.Users))
	for _, u := range options.Users {
		if u.Password == "" {
			return nil, E.New("user ", u.Name, " has empty password")
		}
		users[passwordKey(u.Password)] = u.Name
	}
	in := &Inbound{
		Adapter:   inbound.NewAdapter(C.TypeSimpleTLS, tag),
		router:    uot.NewRouter(router, logger),
		logger:    logger,
		tlsConfig: tlsConfig,
		users:     users,
	}
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: in,
	})
	return in, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.tlsConfig.Start(); err != nil {
		return E.Cause(err, "create TLS config")
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener, h.tlsConfig)
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
		return
	}
	h.serveStreams(ctx, tlsConn, metadata, onClose)
}

// serveStreams runs the per-connection read loop, dispatching one logical
// stream at a time. Every stream starts with a header frame whose data is
// [auth?][SocksAddr]; the auth token is present only on the first stream of
// a connection. The TLS connection is reused for subsequent streams until
// either side signals a non-reusable shutdown.
func (h *Inbound) serveStreams(ctx context.Context, tlsConn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer func() {
		common.Close(tlsConn)
		if onClose != nil {
			onClose(nil)
		}
	}()
	var user string
	needAuth := true
	for {
		u, destination, err := h.readHeader(tlsConn, needAuth)
		if err != nil {
			// After the first stream a clean EOF or closed conn means the
			// client released the pooled connection without opening a new
			// stream — that's a normal teardown, not worth logging.
			if !needAuth && (errors.Is(err, io.EOF) || E.IsClosedOrCanceled(err)) {
				return
			}
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
			return
		}
		if needAuth {
			user = u
			ctx = auth.ContextWithUser(ctx, user)
			needAuth = false
		}

		streamMetadata := metadata
		streamMetadata.Inbound = h.Tag()
		streamMetadata.InboundType = h.Type()
		//nolint:staticcheck
		streamMetadata.InboundDetour = h.listener.ListenOptions().Detour
		streamMetadata.Destination = destination
		if user != "" {
			streamMetadata.User = user
			h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", destination)
		} else {
			h.logger.InfoContext(ctx, "inbound connection to ", destination)
		}

		// RouteConnectionEx is fire-and-forget; we block on the streamConn's
		// own close hook so the next iteration reads the next stream's
		// header from the same TLS connection without races.
		reusableCh := make(chan bool, 1)
		stream := newStreamConn(tlsConn, func(reusable bool) { reusableCh <- reusable })
		h.router.RouteConnectionEx(ctx, stream, streamMetadata, nil)
		if !<-reusableCh {
			return
		}
	}
}

// readHeader consumes a single header frame and parses its destination. When
// withAuth is true the frame data must start with the 32-byte auth token,
// which is validated against the user table and returned as the first value.
func (h *Inbound) readHeader(conn net.Conn, withAuth bool) (string, M.Socksaddr, error) {
	data, err := readFrame(conn)
	if err != nil {
		return "", M.Socksaddr{}, err
	}
	var user string
	if withAuth {
		if len(data) < authSize {
			return "", M.Socksaddr{}, E.New("header frame too short for auth")
		}
		var key [authSize]byte
		copy(key[:], data[:authSize])
		u, ok := h.users[key]
		if !ok {
			return "", M.Socksaddr{}, E.New("authentication failed")
		}
		user = u
		data = data[authSize:]
	}
	reader := bytes.NewReader(data)
	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return "", M.Socksaddr{}, E.Cause(err, "read destination")
	}
	if reader.Len() > 0 {
		return "", M.Socksaddr{}, E.New("header frame has trailing data")
	}
	return user, destination, nil
}
