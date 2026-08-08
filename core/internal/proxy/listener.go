package proxy

import (
	"context"
	"net"

	"github.com/binaryguardia/sentinelwaf/internal/fingerprint"
)

// fingerprintListener wraps accepted connections to peek the TLS ClientHello
// before crypto/tls consumes it. The peeked bytes are replayed transparently,
// so the handshake is unaffected and the request context carries the JA3/JA4
// fingerprint.
type fingerprintListener struct {
	net.Listener
	enabled bool
}

func (l *fingerprintListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !l.enabled {
		return c, nil
	}
	return fingerprint.WrapConn(c), nil
}

// WrapListener wraps ln so accepted connections have their TLS ClientHello
// captured for JA3/JA4 fingerprinting. Only meaningful for TLS listeners.
func WrapListener(ln net.Listener, enabled bool) net.Listener {
	return &fingerprintListener{Listener: ln, enabled: enabled}
}

// ConnContext is the http.Server.ConnContext hook that attaches the captured
// ClientHello to the per-connection context, so ServeHTTP can fingerprint the
// request. Wire it into every server that uses WrapListener.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if fc, ok := c.(*fingerprint.Conn); ok {
		if h := fc.Hello(); h != nil {
			ctx = context.WithValue(ctx, fpCtxKey{}, h)
		}
	}
	return ctx
}
