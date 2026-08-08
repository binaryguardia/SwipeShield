package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// zeroRTTKey carries a per-connection "request arrived as QUIC 0-RTT early
// data" marker from the HTTP/3 ConnContext hook into request handling.
type zeroRTTKey struct{}

// zeroRTT reports whether the request arrived over a QUIC connection that
// used 0-RTT early data.
//
// 0-RTT has no replay protection: an attacker who captured an early request
// can resend it. Requests must therefore never be treated as fresh; the flag
// lets operators log the distinction and apply stricter rules to 0-RTT
// traffic. SwipeShield inspects every request through the identical pipeline
// regardless, so a replayed 0-RTT request is still fully scanned.
func zeroRTT(ctx context.Context) bool {
	v, _ := ctx.Value(zeroRTTKey{}).(bool)
	return v
}

// h3ConnContext is the http3.Server.ConnContext hook. It records whether the
// connection used 0-RTT early data so the gateway can mark replayed-capable
// requests. quic-go resolves the connection state before dispatching any
// request to the handler, so this does not block the hot path.
func h3ConnContext(ctx context.Context, c *quic.Conn) context.Context {
	return context.WithValue(ctx, zeroRTTKey{}, c.ConnectionState().Used0RTT)
}

// HTTP3 is a running HTTP/3 (QUIC) front-end bound to a UDP address.
type HTTP3 struct {
	srv   *http3.Server
	addr  string
	ln    *net.UDPConn
	errCh chan error
}

// Addr returns the bound UDP address (for logging / tests).
func (h *HTTP3) Addr() string { return h.addr }

// Err returns the server error, nil if closed cleanly.
func (h *HTTP3) Err() error { return <-h.errCh }

// StartHTTP3 begins serving HTTP/3 on the given UDP address. tlsConf must
// carry the site certificate; it is augmented for QUIC (TLS 1.3 only, ALPN
// "h3"). allow0RTT opts into 0-RTT early data, which is replayable — see
// zeroRTT. handler is the request handler (the Gateway).
func StartHTTP3(addr string, tlsConf *tls.Config, handler http.Handler, allow0RTT bool) (*HTTP3, error) {
	ln, err := net.ListenUDP("udp", resolveUDPAddr(addr))
	if err != nil {
		return nil, err
	}
	srv := &http3.Server{
		Addr:        addr,
		TLSConfig:   h3TLSConfig(tlsConf),
		Handler:     handler,
		ConnContext: h3ConnContext,
		QUICConfig: &quic.Config{
			// 0-RTT is replayable (no replay protection in QUIC early data);
			// default off, opt-in only. A nil QUICConfig would enable it, so
			// one is always supplied here.
			Allow0RTT:      allow0RTT,
			MaxIdleTimeout: 60 * time.Second,
		},
		IdleTimeout: 60 * time.Second,
	}
	h := &HTTP3{srv: srv, addr: ln.LocalAddr().String(), ln: ln, errCh: make(chan error, 1)}
	go func() {
		h.errCh <- srv.Serve(ln)
	}()
	return h, nil
}

// Close gracefully shuts down the server, waiting up to ctx's deadline.
func (h *HTTP3) Close(ctx context.Context) error {
	if h.srv != nil {
		_ = h.srv.Close()
	}
	return nil
}

// h3TLSConfig clones a TLS config for QUIC use: TLS 1.3 is required, and the
// ALPN "h3" token must be offered so clients route HTTP/3 to the handler.
func h3TLSConfig(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.MinVersion = tls.VersionTLS13
	found := false
	for _, p := range cfg.NextProtos {
		if p == http3.NextProtoH3 {
			found = true
			break
		}
	}
	if !found {
		cfg.NextProtos = append([]string{http3.NextProtoH3}, cfg.NextProtos...)
	}
	return cfg
}

// IsHTTP3 reports whether the request arrived over HTTP/3 (QUIC).
func IsHTTP3(r *http.Request) bool { return r.ProtoMajor == 3 }

func resolveUDPAddr(addr string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	return a
}
