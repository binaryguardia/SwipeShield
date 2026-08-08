package ruleengine

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTiming(t *testing.T) {
	e := New()
	if err := e.SetCRSToggles(CRSToggles{SQLi: true, XSS: true, RCE: true, PathTraversal: true, LFI: true, Protocol: true}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		body  string
		block bool
		ct    string
	}{
		{"clean GET", "", false, ""},
		{"SQLi", `user=' OR 1=1 --&pass=x`, true, "application/x-www-form-urlencoded"},
		{"XSS raw body", `<script>alert(1)</script>`, true, "text/plain"},
		{"SQLi raw body", `{"q":"SELECT * FROM users WHERE 1=1"}`, true, "application/json"},
		{"RCE raw body", `cmd=system('id')`, true, "text/plain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			method := "GET"
			var body io.Reader
			if c.body != "" {
				method = "POST"
				body = strings.NewReader(c.body)
			}
			req, err := http.NewRequest(method, "http://example.com/", body)
			if err != nil {
				t.Fatal(err)
			}
			if c.ct != "" {
				req.Header.Set("Content-Type", c.ct)
			}
			start := time.Now()
			res := e.Evaluate(req, []byte(c.body))
			if c.block && !res.Blocked {
				t.Fatalf("expected block, got matches=%d", len(res.Matches))
			}
			if !c.block && res.Blocked {
				t.Fatalf("unexpected block: %+v", res.Matches)
			}
			if time.Since(start) > time.Second {
				t.Fatalf("evaluation too slow: %s", time.Since(start))
			}
		})
	}
}
