package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/binaryguardia/swipeshield/internal/fingerprint"
)

// TestCaptureE2E verifies the full listener -> ConnContext -> ServeTLS wiring
// attaches the parsed ClientHello to the request context, exactly as main.go
// wires it, for both HTTP/1.1 and HTTP/2 over TLS.
func TestCaptureE2E(t *testing.T) {
	cert := selfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}

	got := make(chan string, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h, ok := r.Context().Value(fpCtxKey{}).(*fingerprint.ClientHello); ok {
				got <- fingerprint.JA4(h) + " " + r.Proto
			} else {
				got <- "<none> " + r.Proto
			}
			w.WriteHeader(200)
		}),
		TLSConfig:   tlsConf,
		ConnContext: ConnContext,
	}
	wrapped := WrapListener(ln, true)
	go func() {
		_ = srv.ServeTLS(wrapped, "", "")
	}()

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))

	run := func(name string, h2 bool) {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "localhost"},
				ForceAttemptHTTP2: h2,
			}}
			resp, err := client.Get("https://127.0.0.1:" + strconv.Itoa(port) + "/api/hello")
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			select {
			case ja4 := <-got:
				t.Logf("captured: %s", ja4)
				if len(ja4) < 12 || ja4[:6] == "<none>" {
					t.Fatalf("no ClientHello in request context: %q", ja4)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("handler never ran")
			}
		})
	}
	run("http1", false)
	run("http2", true)
}
