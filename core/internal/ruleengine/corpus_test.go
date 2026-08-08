package ruleengine

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// attackCase is one corpus row: a payload that MUST be blocked.
type attackCase struct {
	name string
	uri  string
	body string
	ct   string
}

// benignCase is one false-positive row: a payload that MUST NOT be blocked.
type benignCase struct {
	name string
	uri  string
	body string
	ct   string
}

func corpusEngine(t *testing.T) *Engine {
	t.Helper()
	e := New()
	err := e.SetCRSToggles(CRSToggles{
		SQLi: true, XSS: true, RCE: true, PathTraversal: true, LFI: true, Protocol: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func eval(t *testing.T, e *Engine, c attackCase) bool {
	t.Helper()
	var body []byte
	if c.body != "" {
		body = []byte(c.body)
	}
	req := &http.Request{
		Method:     http.MethodPost,
		URL:        parseURL(t, c.uri),
		Header:     http.Header{"Content-Type": {c.ct}},
		RemoteAddr: "203.0.113.7:5555",
	}
	res := e.Evaluate(req, body)
	if res.Err != nil {
		t.Fatalf("engine error: %v", res.Err)
	}
	return res.Blocked
}

func parseURL(t *testing.T, u string) *url.URL {
	t.Helper()
	parsed, err := url.Parse("http://example.com" + u)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCorpusBlockedAttacks(t *testing.T) {
	e := corpusEngine(t)
	cases := []attackCase{
		{name: "sql-or-1=1", uri: "/login", body: "user=' OR 1=1 --", ct: "application/x-www-form-urlencoded"},
		{name: "sql-union-select", uri: "/search", body: `id=1 UNION SELECT password FROM users`, ct: "application/x-www-form-urlencoded"},
		{name: "sql-sleep", uri: "/items", body: `q=1;SELECT SLEEP(5)`, ct: "application/x-www-form-urlencoded"},
		{name: "sqli-in-json", uri: "/api", body: `{"q":"1' OR '1'='1"}`, ct: "application/json"},
		{name: "xss-script", uri: "/echo", body: `<script>alert(document.cookie)</script>`, ct: "text/plain"},
		{name: "xss-img-onerror", uri: "/echo", body: `<img src=x onerror=alert(1)>`, ct: "text/html"},
		{name: "xss-in-json", uri: "/api", body: `{"name":"<script>alert(1)</script>"}`, ct: "application/json"},
		{name: "rce-cmd-injection", uri: "/ping", body: `host=127.0.0.1;cat /etc/passwd`, ct: "application/x-www-form-urlencoded"},
		{name: "rce-backticks", uri: "/exec", body: "cmd=whoami`id`", ct: "application/x-www-form-urlencoded"},
		{name: "lfi", uri: "/read?file=/etc/passwd", body: "", ct: ""},
		{name: "path-traversal", uri: "/download?p=../../etc/passwd", body: "", ct: ""},
		{name: "encoded-traversal", uri: "/download?p=..%2f..%2fetc%2fpasswd", body: "", ct: ""},
		{name: "mysql-comment-injection", uri: "/api", body: `{"user":"admin'#"}`, ct: "application/json"},
	}
	for _, c := range cases {
		if !eval(t, e, c) {
			t.Errorf("corpus: %s (%s) was NOT blocked", c.name, c.uri)
		}
	}
}

func TestCorpusBenignNoFalsePositives(t *testing.T) {
	e := corpusEngine(t)
	cases := []benignCase{
		{name: "normal-login", uri: "/login", body: "user=alice&pass=s3cr3t", ct: "application/x-www-form-urlencoded"},
		{name: "search-term", uri: "/search?q=hello+world", body: "", ct: ""},
		{name: "json-field", uri: "/api", body: `{"name":"Alice","email":"alice@example.com"}`, ct: "application/json"},
		{name: "html-fragment", uri: "/page", body: `<html><body><p>Welcome</p></body></html>`, ct: "text/html"},
		{name: "css-like", uri: "/style", body: `a { color: #ff0000; background: url('img.png'); }`, ct: "text/css"},
		{name: "plain-text", uri: "/notes", body: "the quick brown fox jumps over the lazy dog", ct: "text/plain"},
		{name: "timestamp-query", uri: "/events?after=2026-08-02T10:00:00Z", body: "", ct: ""},
		{name: "multipart-upload", uri: "/upload", body: "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\n\r\n%PDF-1.4\r\n--boundary--", ct: "multipart/form-data; boundary=boundary"},
		{name: "session-cookie", uri: "/profile", body: "", ct: ""},
		{name: "graphql-listing", uri: "/graphql", body: `{"query":"{ user(id: 1) { name email } }"}`, ct: "application/json"},
	}
	fp := 0
	for _, c := range cases {
		if evalAttackShape(t, e, c) {
			fp++
			t.Errorf("corpus FP: %s (%s) was blocked", c.name, c.uri)
		}
	}
	if fp > 2 {
		t.Fatalf("false-positive rate too high: %d/%d", fp, len(cases))
	}
}

// evalAttackShape reuses the attack evaluator with the benign shape.
func evalAttackShape(t *testing.T, e *Engine, c benignCase) bool {
	t.Helper()
	var body []byte
	if c.body != "" {
		body = []byte(c.body)
	}
	req := &http.Request{
		Method:     http.MethodPost,
		URL:        parseURL(t, c.uri),
		Header:     http.Header{"Content-Type": {c.ct}},
		RemoteAddr: "203.0.113.7:5555",
	}
	res := e.Evaluate(req, body)
	if res.Err != nil {
		t.Fatalf("engine error: %v", res.Err)
	}
	return res.Blocked
}

func TestCorpusBlockedByCustomRules(t *testing.T) {
	e := corpusEngine(t)
	rule := &Rule{
		ID: "CUST-1", Phase: PhaseRequest, Severity: "HIGH", Action: ActionBlock,
		Target: TargetPath, Operator: OpContains, Value: "/admin",
	}
	if err := e.SetCustomRules([]*Rule{rule}); err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Method: http.MethodGet, URL: parseURL(t, "/admin/settings"), Header: http.Header{}}
	res := e.Evaluate(req, nil)
	if !res.Blocked {
		t.Fatal("custom rule did not fire")
	}
	found := false
	for _, m := range res.Matches {
		if m.Engine == "custom" && m.RuleID == "CUST-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom match missing: %+v", res.Matches)
	}
}

func TestCorpusMalformedRuleRejected(t *testing.T) {
	bad := []byte(`- id: X
  phase: request
  action: block
  target: path
  operator: regex
  value: "[unclosed
`)
	if _, err := ParseRules(bad); err == nil {
		t.Fatal("malformed regex rule must be rejected")
	}
	dup := []byte(`- id: A
  phase: request
  action: log
  target: path
  value: /a
- id: A
  phase: request
  action: log
  target: path
  value: /b
`)
	if _, err := ParseRules(dup); err == nil {
		t.Fatal("duplicate rule ids must be rejected")
	}
	badAction := []byte(`- id: A
  phase: request
  action: explode
  target: path
  value: /a
`)
	if _, err := ParseRules(badAction); err == nil {
		t.Fatal("invalid action must be rejected")
	}
}

var _ = strings.TrimSpace
