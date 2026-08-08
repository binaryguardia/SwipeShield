package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

// H2Fingerprint is a best-effort HTTP/2 client fingerprint. Go's stdlib
// HTTP/2 server does not expose the SETTINGS frame, so this is a heuristic
// composed of the negotiated ALPN, the HTTP/2 protocol usage, and the
// observable pseudo-header/feature set of the first request. It is a
// secondary signal behind JA3/JA4, never a hard block input on its own.
type H2Fingerprint struct {
	ALPN     string
	Protocol string // "HTTP/2.0" or "HTTP/1.1"
	Features []string
}

// ComputeH2 builds the heuristic fingerprint from an HTTP request.
func ComputeH2(req *http.Request, alpn string) string {
	h := &H2Fingerprint{ALPN: alpn, Protocol: req.Proto}
	if strings.HasPrefix(req.Proto, "HTTP/2") {
		h.Features = append(h.Features, "h2")
	}
	// Pseudo-header/feature order isn't exposed by net/http, but we can
	// observe request shape signals that reliably differ between known
	// automation and browsers.
	for _, k := range []string{"User-Agent", "Accept", "Accept-Language", "Accept-Encoding"} {
		if v := req.Header.Get(k); v != "" {
			h.Features = append(h.Features, k+"="+stringKey(v))
		}
	}
	if req.Header.Get("Sec-Fetch-Site") != "" {
		h.Features = append(h.Features, "sec-fetch")
	}
	if req.Header.Get("Priority") != "" {
		h.Features = append(h.Features, "priority")
	}
	if req.Header.Get("Origin") != "" {
		h.Features = append(h.Features, "origin")
	}
	sort.Strings(h.Features)
	parts := append([]string{alpn, req.Proto}, h.Features...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "h2fp_" + hex.EncodeToString(sum[:8])
}

func stringKey(s string) string {
	// Keep feature stable: hash the header value so sensitive/user-specific
	// values don't leak, but identical clients cluster.
	if len(s) > 48 {
		s = s[:48]
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
