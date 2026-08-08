//go:build webui

package webui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAssetsServedWithRealContent is the regression test for the SPA fallback
// bug: an existence check using a leading-slash path made fs.Stat always fail,
// so every /assets/* request returned index.html as text/html instead of the
// real JS/CSS. Assets must be served with their actual content and MIME type.
func TestAssetsServedWithRealContent(t *testing.T) {
	entries, err := dist.ReadDir("dist/assets")
	if err != nil {
		t.Fatalf("embedded dist has no assets dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("embedded dist has no assets")
	}

	js := ""
	css := ""
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".js"):
			js = e.Name()
		case strings.HasSuffix(e.Name(), ".css"):
			css = e.Name()
		}
	}
	if js == "" || css == "" {
		t.Fatalf("embedded dist missing js/css: %+v", entries)
	}

	check := func(path, wantContentType string, wantNotHTML bool) {
		t.Helper()
		h, err := Handler()
		if err != nil {
			t.Fatalf("Handler: %v", err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status=%d want 200", path, rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.HasPrefix(ct, wantContentType) {
			t.Fatalf("%s: Content-Type=%q want prefix %q", path, ct, wantContentType)
		}
		body, _ := io.ReadAll(rec.Result().Body)
		if wantNotHTML && strings.Contains(string(body), "<!doctype html>") {
			t.Fatalf("%s: served the SPA shell instead of the real file", path)
		}
	}

	check("/assets/"+js, "text/javascript", true)
	check("/assets/"+css, "text/css", true)
	check("/logo.jpeg", "image/jpeg", true)
}

// TestSpaFallbackStillServesAppShell keeps the client-route behavior: unknown
// paths (React Router routes) return the app shell, not a 404.
func TestSpaFallbackStillServesAppShell(t *testing.T) {
	rec := httptest.NewRecorder()
	h, err := Handler()
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sites/demo/not-a-file", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Fatal("unknown route should return the SPA app shell")
	}
}
