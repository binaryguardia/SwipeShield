package mgmtapi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/proxy"
)

func testServer(t *testing.T, sites []config.Site) (*httptest.Server, *proxy.Gateway) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Version: 1,
		Sites:   sites,
		Auth: config.AuthConfig{
			JWTSecret:         "test-secret",
			AdminUser:         "admin",
			AdminPasswordHash: "adminpass",
		},
		Events: config.EventConfig{LogPath: filepath.Join(dir, "events.log")},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validate: %v", err)
	}
	g, err := proxy.New(cfg, proxy.Options{})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	srv := New(Options{
		Backend:           g,
		RulesDir:          filepath.Join(dir, "rules-custom"),
		JWTSecret:         "test-secret",
		AdminUser:         "admin",
		AdminPasswordHash: "adminpass",
		RateLimitPerMin:   10000,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close() })
	t.Cleanup(func() { g.Close() })
	return ts, g
}

func testSite() []config.Site {
	return []config.Site{{
		ID: "site-1", Name: "demo", Domains: []string{"demo.test"},
		Backend: "http://127.0.0.1:9000", Status: "enabled",
		CRS: &config.CRSConfig{Enabled: true, SQLi: true},
	}}
}

func login(t *testing.T, base string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "adminpass"})
	resp, err := http.Post(base+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	var out struct{ Token string }
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("login decode: %v", err)
	}
	if out.Token == "" {
		t.Fatal("empty token")
	}
	return out.Token
}

func do(t *testing.T, method, url, token string, body any) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatalf("req: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, url, err)
	}
	return resp
}

func readBody(t *testing.T, r io.Reader) string {
	t.Helper()
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	ts, _ := testServer(t, testSite())
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	resp, err := http.Post(ts.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestSitesCRUD(t *testing.T) {
	ts, g := testServer(t, testSite())
	tok := login(t, ts.URL)
	base := ts.URL + "/api/v1"

	resp := do(t, "GET", base+"/sites", tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var sites []siteDTO
	json.NewDecoder(resp.Body).Decode(&sites)
	resp.Body.Close()
	if len(sites) != 1 || sites[0].ID != "site-1" {
		t.Fatalf("unexpected sites: %+v", sites)
	}

	resp = do(t, "POST", base+"/sites", tok, siteInput{Host: "api.example.com", Upstream: "10.0.0.5:8080", Status: "enabled"})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, readBody(t, resp.Body))
	}
	var created siteDTO
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" || created.Upstream != "http://10.0.0.5:8080" {
		t.Fatalf("created: %+v", created)
	}
	if cfg := g.Config(); cfg.SiteByDomain("api.example.com") == nil {
		t.Fatal("created site not routable")
	}

	resp = do(t, "PUT", base+"/sites/"+created.ID, tok, siteInput{Status: "disabled"})
	if resp.StatusCode != 200 {
		t.Fatalf("update: %d", resp.StatusCode)
	}
	resp.Body.Close()
	if cfg := g.Config(); cfg.SiteByDomain("api.example.com") != nil {
		t.Fatal("disabled site still routable")
	}

	resp = do(t, "DELETE", base+"/sites/"+created.ID, tok, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	resp.Body.Close()
	if cfg := g.Config(); cfg.SiteByID(created.ID) != nil {
		t.Fatal("site not removed")
	}

	resp = do(t, "DELETE", base+"/sites/site-1", tok, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("last-site delete: want 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRulesCRUD(t *testing.T) {
	ts, g := testServer(t, testSite())
	tok := login(t, ts.URL)
	base := ts.URL + "/api/v1"

	yaml := `- id: R-1001
  phase: request
  severity: HIGH
  action: block
  target: path
  operator: contains
  value: /admin/secret
`
	resp := do(t, "POST", base+"/sites/site-1/rules", tok, map[string]string{"yaml": yaml})
	if resp.StatusCode != 201 {
		t.Fatalf("create rule: %d %s", resp.StatusCode, readBody(t, resp.Body))
	}
	resp.Body.Close()

	req := httptest.NewRequest("GET", "http://demo.test/admin/secret", nil)
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("rule not enforced, status %d", rr.Code)
	}

	resp = do(t, "GET", base+"/sites/site-1/rules", tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list rules: %d", resp.StatusCode)
	}
	var rules []ruleDTO
	json.NewDecoder(resp.Body).Decode(&rules)
	resp.Body.Close()
	if len(rules) != 1 || rules[0].ID != "R-1001" {
		t.Fatalf("rules: %+v", rules)
	}

	bad := `- id: R-BAD
  phase: request
  action: block
  target: path
  operator: regex
  value: "[unclosed"
`
	resp = do(t, "POST", base+"/sites/site-1/rules", tok, map[string]string{"yaml": bad})
	if resp.StatusCode != 400 {
		t.Fatalf("bad rule: want 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = do(t, "DELETE", base+"/sites/site-1/rules/R-1001", tok, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete rule: %d", resp.StatusCode)
	}
	resp.Body.Close()
	req = httptest.NewRequest("GET", "http://demo.test/admin/secret", nil)
	rr = httptest.NewRecorder()
	g.ServeHTTP(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Fatal("rule still enforced after delete")
	}
}

func TestFingerprintBlocklist(t *testing.T) {
	ts, g := testServer(t, testSite())
	tok := login(t, ts.URL)
	base := ts.URL + "/api/v1"

	resp := do(t, "POST", base+"/fingerprint/blocklist", tok, map[string]string{"ja4": "zzzz"})
	if resp.StatusCode != 400 {
		t.Fatalf("invalid ja4: want 400, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	ja4 := "f2a1c0b3d4e5f6a7b8c9d0e1f2a3b4c5"
	resp = do(t, "POST", base+"/fingerprint/blocklist", tok, map[string]string{"ja4": ja4})
	if resp.StatusCode != 201 {
		t.Fatalf("add: %d", resp.StatusCode)
	}
	resp.Body.Close()
	if cfg := g.Config(); !contains(cfg.Fingerprint.Blocklist, ja4) {
		t.Fatal("ja4 not added to config")
	}

	resp = do(t, "GET", base+"/fingerprint/blocklist", tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d", resp.StatusCode)
	}
	var list []blocklistEntry
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list) != 1 || list[0].JA4 != ja4 {
		t.Fatalf("list: %+v", list)
	}

	resp = do(t, "DELETE", base+"/fingerprint/blocklist/"+ja4, tok, nil)
	if resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	resp.Body.Close()
	if cfg := g.Config(); contains(cfg.Fingerprint.Blocklist, ja4) {
		t.Fatal("ja4 still in config")
	}
}

func TestMetricsAndAuthGuard(t *testing.T) {
	ts, _ := testServer(t, testSite())
	base := ts.URL + "/api/v1"

	resp := do(t, "GET", base+"/metrics", "", nil)
	if resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	tok := login(t, ts.URL)
	resp = do(t, "GET", base+"/metrics", tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("metrics: %d", resp.StatusCode)
	}
	var m struct {
		Sites      int               `json:"sites"`
		Requests   uint64            `json:"requests_total"`
		Blocked    uint64            `json:"blocked_total"`
		ByProtocol map[string]uint64 `json:"by_protocol"`
	}
	json.NewDecoder(resp.Body).Decode(&m)
	resp.Body.Close()
	if m.Sites != 1 {
		t.Fatalf("metrics: %+v", m)
	}
}

func TestEventsStream(t *testing.T) {
	ts, g := testServer(t, testSite())
	tok := login(t, ts.URL)
	base := ts.URL + "/api/v1"

	resp, err := http.Get(base + "/events?token=" + tok)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("events: %d", resp.StatusCode)
	}

	req := httptest.NewRequest("GET", "http://demo.test/?q=%27%20OR%201=1", nil)
	rr := httptest.NewRecorder()
	g.ServeHTTP(rr, req)

	deadline := time.Now().Add(3 * time.Second)
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 512*1024)
	for time.Now().Before(deadline) && sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "data: ") {
			var ev map[string]any
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev) == nil && ev["decision"] == "block" {
				return
			}
		}
	}
	t.Fatal("did not receive a block event on the SSE stream")
}
