package fingerprint

import (
	"bufio"
	"net"
)

// Conn wraps a raw connection and captures the TLS ClientHello before it is
// consumed by crypto/tls. The peeked bytes are replayed so the TLS handshake
// proceeds normally; callers read the fingerprint via Hello().
type Conn struct {
	net.Conn
	reader    *bufio.Reader
	hello     *ClientHello
	lastHello *ClientHello
}

// WrapConn peeks at the first record. If it is a ClientHello it is parsed and
// retained; either way the returned Conn transparently replays the bytes so
// the underlying consumer sees an untouched stream.
func WrapConn(conn net.Conn) *Conn {
	c := &Conn{Conn: conn, reader: bufio.NewReader(conn)}
	if ok := c.capture(); ok {
		c.hello = c.lastHello
	}
	return c
}

// capture attempts to read a full TLS record from the buffered reader without
// consuming it. Returns true when a ClientHello was parsed.
func (c *Conn) capture() bool {
	header, err := c.reader.Peek(5)
	if err != nil {
		return false
	}
	if header[0] != 0x16 {
		// Not TLS handshake; nothing to fingerprint. Bytes stay buffered.
		return false
	}
	recLen := int(header[3])<<8 | int(header[4])
	if recLen <= 0 || recLen > 1<<20 {
		return false
	}
	full, err := c.reader.Peek(5 + recLen)
	if err != nil {
		return false
	}
	hello, err := ParseClientHello(full)
	if err != nil {
		c.lastHello = nil
		return false
	}
	c.lastHello = hello
	return true
}

// Hello returns the captured ClientHello, or nil when the connection was not
// TLS or the hello was malformed.
func (c *Conn) Hello() *ClientHello {
	return c.hello
}

// Read re-reads from the replay buffer first, so nothing is lost.
func (c *Conn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

// Peek exposes buffered bytes for callers that need them (tests).
func (c *Conn) Peek(n int) ([]byte, error) { return c.reader.Peek(n) }
