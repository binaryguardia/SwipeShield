package mgmtapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/proxy"
	"github.com/binaryguardia/swipeshield/internal/store"
)

func agentTestServer(t *testing.T, st *store.Store) (*httptest.Server, *proxy.Gateway) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Version: 1,
		Sites:   testSite(),
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
		Store:             st,
		AgentPort:         "9443",
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close() })
	t.Cleanup(func() { g.Close() })
	return ts, g
}

func doJSON(t *testing.T, method, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func loginToken(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp, b := doJSON(t, http.MethodPost, ts.URL+"/api/v1/auth/login", "", map[string]string{
		"username": "admin", "password": "adminpass",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: %d %s", resp.StatusCode, b)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out.Token
}

func TestAgentEndpoints(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/mgmt.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	ts, _ := agentTestServer(t, st)
	tok := loginToken(t, ts)

	// Create ("add server by IP").
	resp, b := doJSON(t, http.MethodPost, ts.URL+"/api/v1/agents", tok,
		map[string]string{"name": "web-01", "ip": "10.0.0.5"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create agent: %d %s", resp.StatusCode, b)
	}
	var created struct {
		Agent         store.Agent `json:"agent"`
		Token         string      `json:"token"`
		EnrollCommand string      `json:"enroll_command"`
	}
	if err := json.Unmarshal(b, &created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.EnrollCommand == "" {
		t.Fatalf("expected token and enroll command, got %s", b)
	}
	if !strings.Contains(created.EnrollCommand, "swipeshield-agent enroll -m") ||
		!strings.Contains(created.EnrollCommand, ":9443 -t") {
		t.Fatalf("enroll command malformed: %s", created.EnrollCommand)
	}

	// Seed an event, then list it back.
	if err := st.AddEvent(created.Agent.ID, "waf_block", map[string]string{"rule": "920170"}); err != nil {
		t.Fatal(err)
	}
	resp, b = doJSON(t, http.MethodGet, ts.URL+"/api/v1/agents/"+created.Agent.ID+"/events", tok, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events: %d %s", resp.StatusCode, b)
	}
	var evs []map[string]any
	if err := json.Unmarshal(b, &evs); err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 || evs[0]["rule"] != "920170" {
		t.Fatalf("unexpected events: %s", b)
	}

	// List agents.
	resp, b = doJSON(t, http.MethodGet, ts.URL+"/api/v1/agents", tok, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "web-01") {
		t.Fatalf("list agents: %d %s", resp.StatusCode, b)
	}

	// Delete.
	resp, _ = doJSON(t, http.MethodDelete, ts.URL+"/api/v1/agents/"+created.Agent.ID, tok, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete agent: %d", resp.StatusCode)
	}
}

func TestAgentEndpointsWithoutStore(t *testing.T) {
	ts, _ := agentTestServer(t, nil)
	tok := loginToken(t, ts)
	resp, b := doJSON(t, http.MethodPost, ts.URL+"/api/v1/agents", tok, map[string]string{"name": "x"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 without store, got %d %s", resp.StatusCode, b)
	}
}
