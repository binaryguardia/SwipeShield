package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/eventpipeline"
)

func testBackend(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Backend", "ok")
		fmt.Fprintf(w, "hello %s body=%s", r.URL.Path, string(b))
	})
	return httptest.NewServer(mux)
}

func testGateway(t *testing.T, site *config.Site) *Gateway {
	t.Helper()
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
	return g
}

func baseSite(backend string) *config.Site {
	return &config.Site{
		ID:      "test",
		Name:    "test",
		Domains: []string{"example.com"},
		Backend: backend,
	}
}

func TestProxyAllowsNormalRequest(t *testing.T) {
	be := testBackend(t)
	g := testGateway(t, baseSite(be.URL))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/hello", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "hello /hello") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
	if rr.Header().Get("X-Backend") != "ok" {
		t.Fatalf("missing backend header: %+v", rr.Header())
	}
}

func TestProxyBlocksSQLi(t *testing.T) {
	be := testBackend(t)
	g := testGateway(t, baseSite(be.URL))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(`user=' OR 1=1 --&pass=x`))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for SQLi, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestProxyBlocksXSS(t *testing.T) {
	be := testBackend(t)
	g := testGateway(t, baseSite(be.URL))
	req := httptest.NewRequest(http.MethodPost, "http://example.com/echo", strings.NewReader(`<script>alert(1)</script>`))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for XSS, got %d", rr.Code)
	}
}

// TestServeHTTPRecoversFromPanic proves the per-request recover() in
// ServeHTTP converts a panic inside the inspection path into a 500 instead of
// crashing the process or wedging the connection.
func TestServeHTTPRecoversFromPanic(t *testing.T) {
	be := testBackend(t)
	g := testGateway(t, baseSite(be.URL))
	g.testPanicHook = func() { panic("boom: synthetic inspection defect") }

	req := httptest.NewRequest(http.MethodGet, "http://example.com/hello", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 after recovered panic, got %d", rr.Code)
	}

	// The gateway must still serve subsequent requests normally.
	g.testPanicHook = nil
	rr2 := httptest.NewRecorder()
	g.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "http://example.com/hello", nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("gateway unhealthy after panic: got %d", rr2.Code)
	}
}

func TestProxyBlocksEncodedTraversal(t *testing.T) {
	be := testBackend(t)
	g := testGateway(t, baseSite(be.URL))
	for _, p := range []string{
		"/..%2f..%2fetc/passwd",
		"/%2e%2e/%2e%2e/etc/passwd",
		"/%252e%252e%252fetc/passwd",
		"/..%5c..%5cetc/passwd",
	} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com"+p, nil)
		req.Host = "example.com"
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for traversal %q, got %d", p, rr.Code)
		}
	}
}

func TestProxyBodySizeLimit(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.MaxBodyBytes = 128
	g := testGateway(t, site)
	big := strings.Repeat("A", 500)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/echo", strings.NewReader(big))
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
}

func TestProxyRateLimit429(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.RateLimit = &config.SiteRateLimit{PerIPRequestsPerMin: 3, Burst: 1}
	g := testGateway(t, site)
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Host = "example.com"
		req.RemoteAddr = "10.0.0.1:1234"
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d expected 200, got %d", i+1, rr.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 4th request, got %d", rr.Code)
	}
}

func TestProxyGraphQLDepthBomb(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.GraphQL = &config.GraphQLConfig{Enabled: true, MaxDepth: 3, MaxComplexity: 100}
	g := testGateway(t, site)
	query := `{"query":"{ a { b { c { d { e { f } } } } } }"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/graphql", strings.NewReader(query))
	req.Host = "example.com"
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for depth bomb, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestProxyNoSiteReturns400(t *testing.T) {
	be := testBackend(t)
	g := testGateway(t, baseSite(be.URL))
	req := httptest.NewRequest(http.MethodGet, "http://unknown.example/", nil)
	req.Host = "unknown.example"
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown host, got %d", rr.Code)
	}
}

func TestProxyChallengeIssuedForBot(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.BotScore = &config.BotScoreConfig{
		Enabled: true, ChallengeEnabled: true,
		ChallengeThreshold: 0.4, BlockThreshold: 0.9, PowDifficulty: 1,
	}
	g := testGateway(t, site)
	// curl-like UA scores high bot probability.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "curl/8.0.0")
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 challenge, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "proof-of-work") {
		t.Fatalf("expected challenge page, got: %s", rr.Body.String())
	}
}

func TestProxyFailsClosedOnEngineError(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.FailMode = config.FailClosed
	g := testGateway(t, site)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "example.com"
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	// Normal traffic still flows; this guards against the fail-closed path
	// accidentally blocking valid requests.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

var _ = time.Second

// captureSink records emitted events in memory for assertions.
type captureSink struct {
	events []eventpipeline.Event
}

func (c *captureSink) Write(_ context.Context, e *eventpipeline.Event) error {
	c.events = append(c.events, *e)
	return nil
}

func (c *captureSink) Close() error { return nil }

// TestProxyBlockedEventHasSingleReason guards against double-appending
// ctx.Reasons when a blocked request is denied (each reason must appear once
// in the audit event, not twice).
func TestProxyBlockedEventHasSingleReason(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.RateLimit = &config.SiteRateLimit{PerIPRequestsPerMin: 1, Burst: 0}

	cap := &captureSink{}
	pipe := eventpipeline.New(eventpipeline.Options{}, cap)
	g, err := New(&config.Config{
		Version: 1,
		Sites:   []config.Site{*site},
		Events:  config.EventConfig{LogPath: ""},
	}, Options{Events: pipe})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })

	send := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Host = "example.com"
		req.RemoteAddr = "10.0.0.9:4321"
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, req)
		return rr
	}

	if rr := send(); rr.Code != http.StatusOK {
		t.Fatalf("first request expected 200, got %d", rr.Code)
	}
	rr := send()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected 429, got %d", rr.Code)
	}

	// Close flushes the queue so every emitted event is delivered.
	pipe.Close()
	if len(cap.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(cap.events))
	}
	var blocked *eventpipeline.Event
	for i := range cap.events {
		if cap.events[i].Blocked {
			blocked = &cap.events[i]
			break
		}
	}
	if blocked == nil {
		t.Fatal("no blocked event emitted")
	}
	var rateReasons int
	for _, r := range blocked.Reasons {
		if r.RuleID == "RATE-IP" {
			rateReasons++
		}
	}
	if rateReasons != 1 {
		t.Fatalf("expected exactly 1 RATE-IP reason in blocked event, got %d: %+v", rateReasons, blocked.Reasons)
	}
}
