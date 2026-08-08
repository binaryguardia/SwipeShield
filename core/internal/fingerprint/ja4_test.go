package fingerprint

import (
	"encoding/hex"
	"net"
	"net/http"
	"testing"
)

// testHello is a hand-crafted TLS 1.3 ClientHello over TCP with a known
// structure; expected JA4/JA3 values were computed by an independent Python
// implementation of the published specs (not by this package).
const testHello = "1603010075010000710303abababababababababababababababababababababababababababababababab000008130113021303c02b0100004000100005000202683200000010000b00000b6578616d706c652e636f6d002b00050403040303000d0006000404030804000a00060004001d0017000b00020100"

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return b
}

func TestJA4Reference(t *testing.T) {
	ch, err := ParseClientHello(mustDecode(t, testHello))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := JA4(ch)
	want := "t13d0406h2_39e807bd56df_fb71836bce29"
	if got != want {
		t.Fatalf("JA4 = %q, want %q", got, want)
	}
}

func TestJA3Reference(t *testing.T) {
	ch, err := ParseClientHello(mustDecode(t, testHello))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := JA3(ch)
	want := "71bad5aba2f2b8849e375002aff102ef"
	if got != want {
		t.Fatalf("JA3 = %q, want %q", got, want)
	}
}

func TestGREASEDoesNotCount(t *testing.T) {
	// Build a ClientHello that contains a GREASE cipher (0x1a1a) and GREASE
	// extension (0x3a3a); the parser must exclude them from counts and
	// hashes so the fingerprint matches the GREASE-free reference.
	pkt := buildHello(0x1a1a, 0x3a3a)
	ch, err := ParseClientHello(pkt)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ch.Ciphers {
		if IsGREASE(c) {
			t.Fatalf("GREASE cipher %04x survived parsing", c)
		}
	}
	for _, e := range ch.Extensions {
		if IsGREASE(e) {
			t.Fatalf("GREASE extension %04x survived parsing", e)
		}
	}
	want := "t13d0406h2_39e807bd56df_fb71836bce29"
	if got := JA4(ch); got != want {
		t.Fatalf("JA4 with GREASE = %q, want %q", got, want)
	}
}

// buildHello constructs a ClientHello with the same shape as testHello,
// optionally inserting a GREASE cipher and extension.
func buildHello(greaseCipher, greaseExt uint16) []byte {
	b := func(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
	ciphers := []uint16{0x1301, 0x1302, 0x1303, 0xc02b}
	if greaseCipher != 0 {
		ciphers = append([]uint16{greaseCipher}, ciphers...)
	}
	cs := []byte{byte(len(ciphers) * 2 >> 8), byte(len(ciphers) * 2)}
	for _, c := range ciphers {
		cs = append(cs, b(c)...)
	}
	exts := []byte{}
	addExt := func(t uint16, data []byte) {
		exts = append(exts, b(t)...)
		exts = append(exts, b(uint16(len(data)))...)
		exts = append(exts, data...)
	}
	if greaseExt != 0 {
		addExt(greaseExt, []byte{0x00, 0x00})
	}
	addExt(0x0010, []byte{0x00, 0x02, 0x02, 'h', '2'})
	name := []byte("example.com")
	addExt(0x0000, append([]byte{0x00, 0x0b, 0x00}, append(b(uint16(len(name))), name...)...))
	addExt(0x002b, append([]byte{0x04}, append(b(0x0304), b(0x0303)...)...))
	addExt(0x000d, append([]byte{0x00, 0x04}, append(b(0x0403), b(0x0804)...)...))
	addExt(0x000a, append([]byte{0x00, 0x04}, append(b(0x001d), b(0x0017)...)...))
	addExt(0x000b, []byte{0x01, 0x00})

	body := append(b(0x0303), []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")...)
	body = append(body, 0x00) // no session id
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression
	body = append(body, b(uint16(len(exts)))...)
	body = append(body, exts...)

	hs := append([]byte{0x01}, []byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}...)
	recLen := len(hs) + len(body)
	rec := append([]byte{0x16, 0x03, 0x01, byte(recLen >> 8), byte(recLen)}, hs...)
	return append(rec, body...)
}

func TestSameHelloSameFingerprint(t *testing.T) {
	a, _ := ParseClientHello(mustDecode(t, testHello))
	b, _ := ParseClientHello(mustDecode(t, testHello))
	if JA4(a) != JA4(b) {
		t.Fatal("identical hellos produced different JA4")
	}
	if JA3(a) != JA3(b) {
		t.Fatal("identical hellos produced different JA3")
	}
}

func TestDifferentHelloDifferentFingerprint(t *testing.T) {
	a, _ := ParseClientHello(mustDecode(t, testHello))
	// Change a cipher to a different suite.
	b := *a
	b.Ciphers = append([]uint16{}, a.Ciphers...)
	b.Ciphers[0] = 0x1304
	if JA4(a) == JA4(&b) {
		t.Fatal("different ciphers produced identical JA4")
	}
	if JA3(a) == JA3(&b) {
		t.Fatal("different ciphers produced identical JA3")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{
		"", "16030100", "00000000000000000000",
	} {
		if _, err := ParseClientHello(mustDecode(t, bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestCaptureConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	helloCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		c := WrapConn(raw)
		hello := c.Hello()
		buf := make([]byte, len(mustDecode(t, testHello)))
		if _, err := readFull(c, buf); err != nil {
			errCh <- err
			return
		}
		if hello == nil {
			errCh <- errNoHello
			return
		}
		helloCh <- JA4(hello)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(mustDecode(t, testHello)); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	select {
	case ja4 := <-helloCh:
		if ja4 != "t13d0406h2_39e807bd56df_fb71836bce29" {
			t.Fatalf("captured JA4 = %q", ja4)
		}
	case err := <-errCh:
		t.Fatalf("server: %v", err)
	}
}

var errNoHello = &netErrNoHello{}

type netErrNoHello struct{}

func (e *netErrNoHello) Error() string   { return "no hello captured" }
func (e *netErrNoHello) Timeout() bool   { return false }
func (e *netErrNoHello) Temporary() bool { return false }

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestH2FingerprintStable(t *testing.T) {
	req1, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	req1.Header.Set("Accept", "*/*")
	req1.Header.Set("Sec-Fetch-Site", "same-origin")
	f1 := ComputeH2(req1, "h2")

	req2, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	req2.Header.Set("Accept", "*/*")
	req2.Header.Set("Sec-Fetch-Site", "same-origin")
	f2 := ComputeH2(req2, "h2")

	if f1 != f2 {
		t.Fatalf("identical requests produced different H2 fingerprints: %q %q", f1, f2)
	}
}
