//go:build !webui

package webui

import (
	"fmt"
	"net/http"
)

// serve renders a stub page when the dashboard was not bundled (plain
// `go build` without -tags webui).
func serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html><html><head><meta charset="utf-8"><title>SentinelWAF</title></head>
<body style="font-family:system-ui;background:#0b1220;color:#cbd5e1;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<main style="text-align:center">
<h1 style="font-size:1.4rem">SentinelWAF dashboard not bundled</h1>
<p>This binary was built without <code>-tags webui</code>.</p>
<p>Build it with the dashboard bundled:</p>
<pre style="background:#111827;padding:1rem;border-radius:8px;color:#7dd3fc">cd dashboard && npm ci && npm run build
cd core && go build -tags webui -o sentinelwaf ./cmd/sentinelwaf</pre>
</main></body></html>`)
}
