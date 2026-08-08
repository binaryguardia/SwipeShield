package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/fingerprint"
)

// cloneSite returns a copy of a site so tests can mutate per-case configs.
func cloneSite(s *config.Site) *config.Site {
	c := *s
	c.Domains = append([]string(nil), s.Domains...)
	c.CustomRules = append([]string(nil), s.CustomRules...)
	if s.CRS != nil {
		cc := *s.CRS
		c.CRS = &cc
	}
	return &c
}

func reloadCfg(sites []config.Site) *config.Config {
	return &config.Config{
		Version: 1,
		Sites:   sites,
		Events:  config.EventConfig{LogPath: "/tmp/swipeshield-test-events.log"},
	}
}

// TestReloadDisablesSite verifies that reloading a config with a site set to
// disabled takes effect immediately (P4 hot reload).
func TestReloadDisablesSite(t *testing.T) {
	be := testBackend(t)
	g := testGateway(t, baseSite(be.URL))

	req := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		r.Host = "example.com"
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, r)
		return rr
	}
	if rr := req(); rr.Code != http.StatusOK {
		t.Fatalf("baseline expected 200, got %d", rr.Code)
	}

	site := cloneSite(baseSite(be.URL))
	site.Status = "disabled"
	if err := g.Reload(reloadCfg([]config.Site{*site})); err != nil {
		t.Fatal(err)
	}
	if rr := req(); rr.Code != http.StatusBadRequest {
		t.Fatalf("disabled site expected 400, got %d", rr.Code)
	}
}

// TestReloadAddsProtection verifies that enabling CRS on reload starts
// blocking previously-allowed attacks (P4).
func TestReloadAddsProtection(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.CRS = &config.CRSConfig{Enabled: true}
	g := testGateway(t, site)

	post := func(body string) int {
		r := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(body))
		r.Host = "example.com"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		g.ServeHTTP(rr, r)
		return rr.Code
	}
	if code := post(`user=admin&pass=ok`); code != http.StatusOK {
		t.Fatalf("baseline expected 200, got %d", code)
	}
	// CRS disabled by default (Enabled: true but class toggles off).
	if code := post(`user=' OR 1=1 --&pass=x`); code != http.StatusOK {
		t.Fatalf("CRS off expected 200, got %d", code)
	}

	upd := cloneSite(baseSite(be.URL))
	upd.CRS = &config.CRSConfig{Enabled: true, SQLi: true, XSS: true, RCE: true, PathTraversal: true, LFI: true, Protocol: true}
	if err := g.Reload(reloadCfg([]config.Site{*upd})); err != nil {
		t.Fatal(err)
	}
	if code := post(`user=' OR 1=1 --&pass=x`); code != http.StatusForbidden {
		t.Fatalf("reloaded CRS expected 403, got %d", code)
	}
}

// TestPathPrefixStripped verifies the proxy strips Site.PathPrefix before
// forwarding (P4 / routing).
func TestPathPrefixStripped(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.PathPrefix = "/api"
	g := testGateway(t, site)

	r := httptest.NewRequest(http.MethodGet, "http://example.com/api/health", nil)
	r.Host = "example.com"
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// Backend echoes the path it saw: it must have been stripped to /health.
	if !strings.Contains(rr.Body.String(), "hello /health") {
		t.Fatalf("prefix not stripped, body: %s", rr.Body.String())
	}
}

// TestFingerprintBlocklistEnforced verifies JA4 blocklist enforcement before
// any upgrade/body inspection (P9).
func TestFingerprintBlocklistEnforced(t *testing.T) {
	be := testBackend(t)
	site := baseSite(be.URL)
	site.CRS = &config.CRSConfig{Enabled: true}

	// Build a real ClientHello and derive its JA4 so the blocklist matches
	// what the gateway computes from the injected connection fingerprint.
	ch := &fingerprint.ClientHello{
		LegacyVersion:     0x0303,
		Ciphers:           []uint16{0x1301, 0x1302, 0x1303},
		Extensions:        []uint16{0x000d, 0x0010, 0x002b, 0x0000},
		ALPN:              []string{"h2"},
		SupportedVersions: []uint16{0x0304, 0x0303},
		Groups:            []uint16{0x001d, 0x0017},
	}
	badJA4 := fingerprint.JA4(ch)

	cfg := reloadCfg([]config.Site{*site})
	cfg.Fingerprint = config.FingerprintConfig{Enabled: true, Blocklist: []string{badJA4}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	g, err := New(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })

	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r.Host = "example.com"
	r = r.WithContext(context.WithValue(r.Context(), fpCtxKey{}, ch))
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, r)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("blocked JA4 %s expected 403, got %d", badJA4, rr.Code)
	}

	// A different, non-blocked fingerprint must pass.
	r2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	r2.Host = "example.com"
	other := &fingerprint.ClientHello{Ciphers: []uint16{0xc02f}, Extensions: []uint16{0x000a}}
	r2 = r2.WithContext(context.WithValue(r2.Context(), fpCtxKey{}, other))
	rr2 := httptest.NewRecorder()
	g.ServeHTTP(rr2, r2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("non-blocked fingerprint expected 200, got %d", rr2.Code)
	}
}
