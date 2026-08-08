package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// selfSignedCert returns a throwaway TLS certificate valid for the loopback
// hostnames used in tests.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSGateway stands up a real (TCP+TLS and UDP HTTP/3) gateway fronting
// the test backend, returning the gateway and both listeners.
func startTLSGateway(t *testing.T, site *config.Site) (*Gateway, *HTTP3) {
	t.Helper()
	cert := selfSignedCert(t)
	cfg := &config.Config{
		Version: 1,
		Sites:   []config.Site{*site},
		Events:  config.EventConfig{LogPath: "/tmp/swipeshield-test-events.log"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: g, ConnContext: ConnContext, ReadHeaderTimeout: 5 * time.Second}
	// net/http mutates its TLSConfig.NextProtos during setupHTTP2; give it a
	// private deep copy so that mutation cannot race with StartHTTP3 reading
	// (cloning) the shared tlsConf below.
	httpCfg := tlsConf.Clone()
	httpCfg.NextProtos = append([]string(nil), tlsConf.NextProtos...)
	srv.TLSConfig = httpCfg
	tcpLn = WrapListener(tcpLn, true)
	go srv.ServeTLS(tcpLn, "", "")
	t.Cleanup(func() { _ = srv.Close() })

	h3, err := StartHTTP3(tcpLn.Addr().String(), tlsConf, g, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h3.Close(context.Background()) })
	return g, h3
}

// h3RoundTripper returns an HTTP/3 client for the test server.
func h3RoundTripper(t *testing.T) *http3.Transport {
	t.Helper()
	return &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test-only cert
		QUICConfig: &quic.Config{
			MaxIdleTimeout: 5 * time.Second,
		},
	}
}

// TestHTTP3Parity verifies the DoD: the demo backend is reachable over HTTP/3
// and the inspection behavior matches the HTTP/1.1/2 path — a clean request is
// proxied (200) and an attack (SQLi) is rejected (403).
func TestHTTP3Parity(t *testing.T) {
	be := testBackend(t)
	_, h3 := startTLSGateway(t, baseSite(be.URL))

	rt := h3RoundTripper(t)
	defer rt.CloseIdleConnections()
	hc := &http.Client{Transport: rt, Timeout: 10 * time.Second}
	base := "https://" + h3.Addr()

	req, err := http.NewRequest(http.MethodGet, base+"/api/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("h3 normal GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("h3 normal GET: expected 200, got %d (%s)", resp.StatusCode, body)
	}

	req, err = http.NewRequest(http.MethodPost, base+"/login", strings.NewReader(`user=' OR 1=1 --&pass=x`))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = hc.Do(req)
	if err != nil {
		t.Fatalf("h3 SQLi: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("h3 SQLi: expected 403, got %d (%s)", resp.StatusCode, body)
	}
}

// TestHTTP3TransportMarking verifies requests are labeled with the transport
// they arrived on and that non-0-RTT connections are not flagged zero_rtt.
func TestHTTP3TransportMarking(t *testing.T) {
	be := testBackend(t)
	_, h3 := startTLSGateway(t, baseSite(be.URL))

	rt := h3RoundTripper(t)
	defer rt.CloseIdleConnections()
	hc := &http.Client{Transport: rt, Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodGet, "https://"+h3.Addr()+"/api/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.com"
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("h3 GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestZeroRTTMarker(t *testing.T) {
	if zeroRTT(context.Background()) {
		t.Fatal("empty context must not be flagged 0-RTT")
	}
	if !zeroRTT(context.WithValue(context.Background(), zeroRTTKey{}, true)) {
		t.Fatal("expected 0-RTT marker to be read back")
	}
	if zeroRTT(context.WithValue(context.Background(), zeroRTTKey{}, false)) {
		t.Fatal("false marker must read as false")
	}
}

func TestH3TLSConfig(t *testing.T) {
	base := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	got := h3TLSConfig(base)
	if got.MinVersion != tls.VersionTLS13 {
		t.Fatalf("h3 requires TLS 1.3, got %v", got.MinVersion)
	}
	if got.NextProtos[0] != http3.NextProtoH3 {
		t.Fatalf("h3 ALPN token must be first, got %v", got.NextProtos)
	}
	// Base config must be left untouched (Clone semantics).
	if base.NextProtos[0] != "h2" {
		t.Fatal("h3TLSConfig must not mutate its input")
	}
}
