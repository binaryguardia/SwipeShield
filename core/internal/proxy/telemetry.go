package proxy

import (
	"bufio"
	"os"
	"strings"

	"github.com/binaryguardia/sentinelwaf/internal/eventpipeline"
	"github.com/binaryguardia/sentinelwaf/internal/telemetry"
)

// Stats returns a snapshot of gateway activity for the Management API.
func (g *Gateway) Stats() telemetry.Stats {
	s := g.stats.Snapshot()
	s.Sites = len(g.store.Get().Sites)
	return s
}

// SubscribeEvents registers a live event subscriber for the Management API
// /events stream. Returns the channel and an unsubscribe function.
func (g *Gateway) SubscribeEvents() (<-chan eventpipeline.Event, func()) {
	return g.feed.Subscribe(128)
}

// fpBlocked reports whether a JA4 fingerprint is on the global blocklist.
func (g *Gateway) fpBlocked(ja4 string) bool {
	if ja4 == "" {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.fpBlock[ja4]
}

// loadFingerprintBlocklist builds the blocked-JA4 set from inline config
// entries plus an optional newline-delimited file.
func loadFingerprintBlocklist(inline []string, file string) (map[string]bool, error) {
	block := make(map[string]bool, len(inline))
	for _, h := range inline {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			block[h] = true
		}
	}
	if file == "" {
		return block, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		h := strings.ToLower(strings.TrimSpace(sc.Text()))
		if h != "" && !strings.HasPrefix(h, "#") {
			block[h] = true
		}
	}
	return block, sc.Err()
}
