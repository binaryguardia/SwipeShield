// Package fingerprint implements JA3 and JA4 TLS ClientHello fingerprinting
// strictly against the published specifications, plus a best-effort HTTP/2
// fingerprinting signal.
//
// JA3: https://github.com/salesforce/ja3  (MD5 of
// version,ciphers,extensions,groups,point-formats)
//
// JA4: https://github.com/FoxIO-LLC/ja4  (t<ver><sni><#c><#e><alpn>_
// <sha256(ciphers sorted)>_<sha256(extensions sorted minus SNI/ALPN +
// signature algorithms)>)
//
// GREASE values are ignored wherever the specs require. All hashes are
// lower-case hex. HTTP/2 fingerprinting is heuristic (Go's stdlib HTTP/2
// server does not expose SETTINGS frames), so it records negotiated ALPN
// and a hash of observable client behavior rather than a spec-versioned
// JA4-H2 value.
package fingerprint

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// IsGREASE reports whether a 2-byte TLS value is a GREASE value
// (draft-davidben-tls-grease). A value is GREASE when each byte's low
// nibble is 0x0A (0x0a0a, 0x1a1a, ... 0xfafa).
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a
}

// ClientHello is a parsed TLS ClientHello.
type ClientHello struct {
	LegacyVersion       uint16
	RecordVersion       uint16
	Ciphers             []uint16
	Extensions          []uint16 // types in order of appearance (GREASE removed)
	ExtensionsRaw       []ext    // full extension data keyed by type
	SupportedVersions   []uint16
	Groups              []uint16
	PointFormats        []byte
	SignatureAlgorithms []uint16
	ALPN                []string
	SNI                 bool
}

type ext struct {
	Type uint16
	Data []byte
}

func (c *ClientHello) extData(t uint16) []byte {
	for _, e := range c.ExtensionsRaw {
		if e.Type == t {
			return e.Data
		}
	}
	return nil
}

// ParseClientHello parses a raw TLS record stream beginning with a
// ClientHello handshake message. It returns an error for structurally
// invalid input; the caller decides how to treat a malformed hello.
func ParseClientHello(pkt []byte) (*ClientHello, error) {
	if len(pkt) < 9 {
		return nil, fmt.Errorf("clienthello: packet too short (%d)", len(pkt))
	}
	if pkt[0] != 0x16 { // TLS handshake record
		return nil, fmt.Errorf("clienthello: not a handshake record (0x%02x)", pkt[0])
	}
	recLen := int(pkt[3])<<8 | int(pkt[4])
	if len(pkt) < 5+recLen {
		return nil, fmt.Errorf("clienthello: truncated record")
	}
	if pkt[5] != 0x01 { // ClientHello
		return nil, fmt.Errorf("clienthello: not a ClientHello (0x%02x)", pkt[5])
	}
	ch := &ClientHello{
		RecordVersion: uint16(pkt[1])<<8 | uint16(pkt[2]),
	}
	off := 9
	ch.LegacyVersion = uint16(pkt[off])<<8 | uint16(pkt[off+1])
	off += 2 + 32 // random

	sidLen := int(pkt[off])
	off += 1 + sidLen
	if off+2 > len(pkt) {
		return nil, fmt.Errorf("clienthello: truncated session id")
	}
	csLen := int(pkt[off])<<8 | int(pkt[off+1])
	off += 2
	if off+csLen > len(pkt) {
		return nil, fmt.Errorf("clienthello: truncated cipher suites")
	}
	for i := 0; i+1 < csLen; i += 2 {
		v := uint16(pkt[off+i])<<8 | uint16(pkt[off+i+1])
		if !IsGREASE(v) {
			ch.Ciphers = append(ch.Ciphers, v)
		}
	}
	off += csLen

	if off >= len(pkt) {
		return ch, nil
	}
	compLen := int(pkt[off])
	off += 1 + compLen
	if off+2 > len(pkt) {
		return ch, nil
	}
	extLen := int(pkt[off])<<8 | int(pkt[off+1])
	off += 2
	end := off + extLen
	if end > len(pkt) {
		end = len(pkt)
	}
	for off+4 <= end {
		etype := uint16(pkt[off])<<8 | uint16(pkt[off+1])
		elen := int(pkt[off+2])<<8 | int(pkt[off+3])
		off += 4
		if off+elen > end {
			break
		}
		data := pkt[off : off+elen]
		off += elen
		ch.ExtensionsRaw = append(ch.ExtensionsRaw, ext{Type: etype, Data: data})
		if !IsGREASE(etype) {
			ch.Extensions = append(ch.Extensions, etype)
		}
	}
	ch.parseExtensions()
	return ch, nil
}

func (c *ClientHello) parseExtensions() {
	if d := c.extData(0x0000); d != nil {
		c.SNI = len(d) > 0
	}
	if d := c.extData(0x0010); d != nil {
		if len(d) >= 2 {
			n := int(d[0])<<8 | int(d[1])
			i := 2
			for i < 2+n && i < len(d) {
				l := int(d[i])
				i++
				if i+l <= len(d) {
					c.ALPN = append(c.ALPN, string(d[i:i+l]))
				}
				i += l
			}
		}
	}
	if d := c.extData(0x002b); d != nil {
		// supported_versions: TLS1.3 style (1-byte length) or TLS1.2 style
		// (2-byte length). The 2-byte-length variant is only for the
		// legacy extension; the spec says the highest value in the
		// extension defines the version.
		if len(d) >= 1 {
			n := int(d[0])
			start := 1
			if n == len(d)-1 && n%2 == 0 {
				for i := start; i+1 < len(d); i += 2 {
					v := uint16(d[i])<<8 | uint16(d[i+1])
					if !IsGREASE(v) {
						c.SupportedVersions = append(c.SupportedVersions, v)
					}
				}
			} else if len(d) >= 3 {
				// 2-byte length form
				n2 := int(d[0])<<8 | int(d[1])
				for i := 2; i+1 < 2+n2 && i+1 < len(d); i += 2 {
					v := uint16(d[i])<<8 | uint16(d[i+1])
					if !IsGREASE(v) {
						c.SupportedVersions = append(c.SupportedVersions, v)
					}
				}
			}
		}
	}
	if d := c.extData(0x000d); d != nil {
		if len(d) >= 2 {
			n := int(d[0])<<8 | int(d[1])
			for i := 2; i+1 < 2+n && i+1 < len(d); i += 2 {
				c.SignatureAlgorithms = append(c.SignatureAlgorithms, uint16(d[i])<<8|uint16(d[i+1]))
			}
		}
	}
	if d := c.extData(0x000a); d != nil {
		if len(d) >= 2 {
			n := int(d[0])<<8 | int(d[1])
			for i := 2; i+1 < 2+n && i+1 < len(d); i += 2 {
				v := uint16(d[i])<<8 | uint16(d[i+1])
				if !IsGREASE(v) {
					c.Groups = append(c.Groups, v)
				}
			}
		}
	}
	if d := c.extData(0x000b); d != nil {
		if len(d) >= 1 {
			n := int(d[0])
			for i := 1; i <= n && i < len(d); i++ {
				c.PointFormats = append(c.PointFormats, d[i])
			}
		}
	}
}

// JA4 computes the JA4 fingerprint per the published spec.
func JA4(c *ClientHello) string {
	proto := "t"
	ver := tlsVersionString(c)
	sni := "i"
	if c.SNI {
		sni = "d"
	}
	cc := countStr(len(c.Ciphers))
	ec := countStr(len(c.Extensions))
	alpn := alpnPair(c)

	a := proto + ver + sni + cc + ec + alpn

	var ciphers []string
	for _, v := range c.Ciphers {
		ciphers = append(ciphers, fmt.Sprintf("%04x", v))
	}
	sort.Strings(ciphers)
	var b string
	if len(ciphers) == 0 {
		b = "000000000000"
	} else {
		b = hash12(strings.Join(ciphers, ","))
	}

	// Extensions minus SNI(0000) and ALPN(0010), sorted.
	var exts []string
	for _, v := range c.Extensions {
		if v == 0x0000 || v == 0x0010 {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", v))
	}
	sort.Strings(exts)
	var sigalgs []string
	for _, v := range c.SignatureAlgorithms {
		sigalgs = append(sigalgs, fmt.Sprintf("%04x", v))
	}
	var cpart string
	if len(exts) == 0 {
		cpart = "000000000000"
	} else {
		s := strings.Join(exts, ",")
		if len(sigalgs) > 0 {
			s += "_" + strings.Join(sigalgs, ",")
		}
		cpart = hash12(s)
	}
	return a + "_" + b + "_" + cpart
}

// JA4Raw returns the JA4_r raw fingerprint (sorted values, un-hashed).
func JA4Raw(c *ClientHello) string {
	var ciphers []string
	for _, v := range c.Ciphers {
		ciphers = append(ciphers, fmt.Sprintf("%04x", v))
	}
	sort.Strings(ciphers)
	var exts []string
	for _, v := range c.Extensions {
		if v == 0x0000 || v == 0x0010 {
			continue
		}
		exts = append(exts, fmt.Sprintf("%04x", v))
	}
	sort.Strings(exts)
	var sigalgs []string
	for _, v := range c.SignatureAlgorithms {
		sigalgs = append(sigalgs, fmt.Sprintf("%04x", v))
	}
	return tlsVersionString(c) + "_" + strings.Join(ciphers, ",") + "_" +
		strings.Join(exts, ",") + "_" + strings.Join(sigalgs, ",")
}

// JA3 computes the classic JA3 fingerprint (MD5 of
// version,ciphers,extensions,groups,point-formats, decimal, GREASE-free).
func JA3(c *ClientHello) string {
	ver := fmt.Sprintf("%d", c.LegacyVersion)
	var ciphers []string
	for _, v := range c.Ciphers {
		ciphers = append(ciphers, fmt.Sprintf("%d", v))
	}
	var exts []string
	for _, v := range c.Extensions {
		exts = append(exts, fmt.Sprintf("%d", v))
	}
	var groups []string
	for _, v := range c.Groups {
		groups = append(groups, fmt.Sprintf("%d", v))
	}
	var points []string
	for _, p := range c.PointFormats {
		points = append(points, fmt.Sprintf("%d", p))
	}
	s := strings.Join([]string{ver, strings.Join(ciphers, ","), strings.Join(exts, ","), strings.Join(groups, ","), strings.Join(points, ",")}, ",")
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func tlsVersionString(c *ClientHello) string {
	if len(c.SupportedVersions) > 0 {
		// highest value in the extension
		max := uint16(0)
		for _, v := range c.SupportedVersions {
			if v > max {
				max = v
			}
		}
		return versionToJA4(max)
	}
	return versionToJA4(c.LegacyVersion)
}

func versionToJA4(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

func countStr(n int) string {
	if n > 99 {
		return "99"
	}
	return fmt.Sprintf("%02d", n)
}

func alpnPair(c *ClientHello) string {
	if len(c.ALPN) == 0 {
		return "00"
	}
	first := c.ALPN[0]
	if len(first) == 0 {
		return "00"
	}
	if len(first) == 1 {
		if isAlnum(first[0]) {
			return string(first[0]) + string(first[0])
		}
		h := hex.EncodeToString([]byte(first))
		return h + h
	}
	a, b := first[0], first[len(first)-1]
	if isAlnum(a) && isAlnum(b) {
		return string(a) + string(b)
	}
	h := hex.EncodeToString([]byte(first))
	return h[0:1] + h[len(h)-1:]
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}
