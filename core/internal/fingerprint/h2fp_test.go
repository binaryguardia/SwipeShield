package fingerprint

import (
	"net/http"
	"testing"
)

// makeCH builds a ClientHello, applying the same GREASE filter the parser
// applies so hand-built structs mirror parsed ones.
func makeCH(t *testing.T, ciphers, extTypes []uint16, alpn []string, versions []uint16, groups []uint16) *ClientHello {
	t.Helper()
	ch := &ClientHello{LegacyVersion: 0x0303, ALPN: alpn}
	for _, v := range ciphers {
		if !IsGREASE(v) {
			ch.Ciphers = append(ch.Ciphers, v)
		}
	}
	for _, v := range extTypes {
		if !IsGREASE(v) {
			ch.Extensions = append(ch.Extensions, v)
		}
	}
	ch.SupportedVersions = versions
	ch.Groups = groups
	return ch
}

func TestJA4Format(t *testing.T) {
	ch := makeCH(t,
		[]uint16{0x1301, 0x1302, 0x1303, 0xc02f, 0xc030},
		[]uint16{0x0000, 0x0010, 0x002b, 0x000d, 0x0017, 0x000a},
		[]string{"h2", "http/1.1"},
		[]uint16{0x0304, 0x0303},
		[]uint16{0x001d, 0x0017},
	)
	ja4 := JA4(ch)
	// a=t13i0506h2 (10) + _ (1) + 12 hex + _ (1) + 12 hex = 36
	if len(ja4) != 36 {
		t.Fatalf("JA4 length %d: %s", len(ja4), ja4)
	}
	if !hasPrefix(ja4, "t13i0506h2") {
		t.Fatalf("JA4 prefix: %s", ja4)
	}
	// ALPN pair is derived from the first advertised protocol only.
	if !hasPrefix(ja4[8:], "h2") {
		t.Fatalf("ALPN pair: %s", ja4)
	}
}

func TestJA3Deterministic(t *testing.T) {
	ch := makeCH(t, []uint16{0xc02f, 0x1301, 0xc030}, []uint16{0x000a, 0x000d, 0x0010}, nil, nil, []uint16{0x001d})
	a := JA3(ch)
	b := JA3(makeCH(t, []uint16{0xc02f, 0x1301, 0xc030}, []uint16{0x000a, 0x000d, 0x0010}, nil, nil, []uint16{0x001d}))
	if a != b {
		t.Fatalf("JA3 not deterministic: %s != %s", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("JA3 not md5 hex: %s", a)
	}
}

func TestGREASEDValuesSkipped(t *testing.T) {
	// 0x0a0a and 0x1a1a are GREASE; they must be excluded.
	ch := makeCH(t, []uint16{0x1301, 0x0a0a, 0xc02f, 0x1a1a}, []uint16{0x0a0a, 0x000d, 0x1a1a, 0x000a}, nil, nil, nil)
	if len(ch.Ciphers) != 2 {
		t.Fatalf("GREASE ciphers not skipped: %v", ch.Ciphers)
	}
	if len(ch.Extensions) != 2 {
		t.Fatalf("GREASE extensions not skipped: %v", ch.Extensions)
	}
}

func TestParseClientHelloRoundTrip(t *testing.T) {
	// Construct a minimal real ClientHello wire format.
	var b []byte
	b = append(b, 0x16, 0x03, 0x01, 0x00, 0x00) // record header, length patched later
	chStart := len(b)
	b = append(b, 0x01, 0x00, 0x00, 0x00)             // handshake header (length patched later)
	b = append(b, 0x03, 0x03)                         // legacy version
	b = append(b, make([]byte, 32)...)                // random
	b = append(b, 0x00)                               // session id len
	b = append(b, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02) // 2 cipher suites
	b = append(b, 0x01, 0x00)                         // compression methods
	// ALPN extension: type 0x0010, length 5, data = list-len(0x0003),
	// proto-len(0x02) + "h2".
	exts := []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32}
	b = append(b, 0x00, byte(len(exts)))
	b = append(b, exts...)
	// patch lengths
	recLen := len(b) - chStart - 5
	b[3], b[4] = byte(recLen>>8), byte(recLen)
	hsLen := len(b) - chStart - 4
	b[chStart+1], b[chStart+2], b[chStart+3] = byte(hsLen>>16), byte(hsLen>>8), byte(hsLen)

	ch, err := ParseClientHello(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(ch.Ciphers) != 2 {
		t.Fatalf("ciphers: %v", ch.Ciphers)
	}
	if len(ch.ALPN) != 1 || ch.ALPN[0] != "h2" {
		t.Fatalf("alpn: %v", ch.ALPN)
	}
	if ja4 := JA4(ch); len(ja4) < 20 {
		t.Fatalf("ja4 too short: %s", ja4)
	}
}

func TestComputeH2Stable(t *testing.T) {
	// ComputeH2 takes an http.Request and an ALPN label; it must be stable
	// for identical header shapes.
	r1 := chReq()
	h1 := ComputeH2(r1, "h2")
	h2 := ComputeH2(chReq(), "h2")
	if h1 != h2 {
		t.Fatalf("H2 fingerprint unstable: %s != %s", h1, h2)
	}
	if len(h1) < 8 {
		t.Fatalf("H2 fingerprint too short: %s", h1)
	}
}

func chReq() *http.Request {
	return &http.Request{
		Method: "GET",
		Proto:  "HTTP/2.0",
		Header: map[string][]string{
			"User-Agent":    {"curl/8.0.0"},
			"Accept":        {"*/*"},
			"Cache-Control": {"no-cache"},
		},
	}
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
