package simpletls

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type lifecycleTestTLSConfig struct {
	tls.ServerConfig
	starts int
	closes int
}

func (c *lifecycleTestTLSConfig) Start() error {
	c.starts++
	return nil
}

func (c *lifecycleTestTLSConfig) Close() error {
	c.closes++
	return nil
}

func TestInboundScopeCleanup(t *testing.T) {
	for _, failListen := range []bool{false, true} {
		name := "started"
		if failListen {
			name = "listen_failed"
		}
		t.Run(name, func(t *testing.T) {
			logger := log.NewNOPFactory().Logger()
			scope := adapter.NewScope(t.Context(), logger)
			t.Cleanup(func() { require.NoError(t, scope.Close()) })
			listenOptions := option.ListenOptions{
				Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			}
			if failListen {
				occupied, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				defer occupied.Close()
				listenOptions.ListenPort = uint16(occupied.Addr().(*net.TCPAddr).Port)
			}
			tlsConfig := &lifecycleTestTLSConfig{}
			in := &Inbound{
				tlsConfig: tlsConfig,
				listener: listener.New(listener.Options{
					Context: t.Context(),
					Logger:  logger,
					Network: []string{N.NetworkTCP},
					Listen:  listenOptions,
				}),
			}
			require.NoError(t, in.Start(adapter.StartStateInitialize, scope))
			require.Zero(t, tlsConfig.starts)
			err := in.Start(adapter.StartStateStart, scope)
			if failListen {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, in.listener.TCPListener())
				require.NoError(t, in.listener.TCPListener().(*net.TCPListener).SetDeadline(time.Now().Add(time.Second)))
			}
			require.Equal(t, 1, tlsConfig.starts)
			require.NoError(t, scope.Close())
			require.Equal(t, 1, tlsConfig.closes)
			if !failListen {
				_, err = in.listener.TCPListener().Accept()
				require.ErrorIs(t, err, net.ErrClosed)
			}
		})
	}
}

func TestOutboundScopeCleanup(t *testing.T) {
	scope := adapter.NewScope(t.Context(), log.NewNOPFactory().Logger())
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	out := &Outbound{}
	require.NoError(t, out.Start(adapter.StartStateStart, scope))
	require.Nil(t, out.pool)
	require.NoError(t, out.Start(adapter.StartStateInitialize, scope))
	require.NotNil(t, out.pool)
	pool := out.pool
	for _, stage := range []adapter.StartStage{adapter.StartStateStart, adapter.StartStatePostStart, adapter.StartStateStarted} {
		require.NoError(t, out.Start(stage, scope))
		require.Same(t, pool, out.pool)
	}
	conn, peer := net.Pipe()
	defer peer.Close()
	pool.put(conn)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	require.NoError(t, scope.Close())
	require.ErrorIs(t, scope.Context().Err(), context.Canceled)
	_, err := peer.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
	require.Nil(t, pool.take())
	select {
	case <-pool.stop:
	default:
		t.Fatal("pool sweeper was not stopped")
	}
}
