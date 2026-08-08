package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/parsers/sse"
	"github.com/binaryguardia/swipeshield/internal/ruleengine"
)

// buildReverseProxy constructs the upstream proxy for a site. It wires a
// bounded transport, SSE stream inspection (when enabled), hop-by-hop header
// handling, and a fail-mode-aware error handler. engine is the site rule
// engine used to evaluate SSE data lines; onSSEViolation emits the finding.
func buildReverseProxy(target *url.URL, s *config.Site, g *Gateway, engine *ruleengine.Engine, onSSEViolation func(*http.Request, sse.Violation)) *httputilReverseProxy {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		if !s.PreserveHost {
			req.Host = target.Host
		}
		// Strip the site path prefix before forwarding.
		if s.PathPrefix != "" && (req.URL.Path == s.PathPrefix || strings.HasPrefix(req.URL.Path, s.PathPrefix+"/")) {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, s.PathPrefix)
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
		}
		// Preserve the true client address for upstream logging.
		if req.Header.Get("X-Forwarded-For") == "" {
			if ip := clientIP(req); ip != "" {
				req.Header.Set("X-Forwarded-For", ip)
			}
		}
	}

	rp := &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			status := http.StatusBadGateway
			msg := "upstream unavailable"
			if s.FailMode == config.FailClosed {
				status = http.StatusServiceUnavailable
			}
			log.Warn().Err(err).Str("site", s.ID).Str("path", r.URL.Path).Msg("upstream error")
			http.Error(w, msg, status)
		},
	}

	// SSE: inspect the response stream for suspicious data: lines.
	if s.SSE != nil && s.SSE.Enabled && onSSEViolation != nil {
		rp.Transport = &sseTransport{
			base:         transport,
			enabled:      true,
			engine:       engine,
			onViolation:  onSSEViolation,
		}
		rp.FlushInterval = -1
	}

	return rp
}

// sseTransport wraps the round trip and wraps event-stream bodies with a
// scanning reader that reports violations found in `data:` lines.
type sseTransport struct {
	base        http.RoundTripper
	enabled     bool
	engine      *ruleengine.Engine
	onViolation func(*http.Request, sse.Violation)
}

func (t *sseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if t.enabled && sse.IsEventStream(resp.Header) {
		insp := sse.NewInspector(t.engine)
		scanner := sse.NewStreamWriter(&voidWriter{}, insp)
		if t.onViolation != nil {
			scanner.OnViolation = func(v sse.Violation) { t.onViolation(req, v) }
		}
		resp.Body = &scanningBody{inner: resp.Body, scan: scanner}
	}
	return resp, nil
}

// scanningBody is an io.ReadCloser that tee-reads the SSE stream through the
// StreamWriter so data lines get inspected while bytes still flow through.
type scanningBody struct {
	inner ioReadCloser
	scan  *sse.StreamWriter
}

func (s *scanningBody) Read(p []byte) (int, error) {
	n, err := s.inner.Read(p)
	if n > 0 {
		_, _ = s.scan.Write(p[:n])
	}
	return n, err
}

func (s *scanningBody) Close() error { return s.inner.Close() }

type voidWriter struct{ h http.Header }

func (v voidWriter) Header() http.Header {
	if v.h == nil {
		return make(http.Header)
	}
	return v.h
}
func (voidWriter) Write(p []byte) (int, error) { return len(p), nil }
func (voidWriter) WriteHeader(int)             {}

type ioReadCloser = interface {
	Read([]byte) (int, error)
	Close() error
}

var _ = fmt.Sprintf
var _ = context.Background
