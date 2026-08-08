// Package sse provides streaming inspection of Server-Sent Events responses.
// Each data: line of an SSE stream is scanned and pattern rules are applied,
// so a single "allowed" long-lived stream cannot silently carry malicious
// payloads. Inspection is non-buffering: bytes flow through immediately.
package sse

import (
	"bufio"
	"bytes"
	"net/http"
	"sync"

	"github.com/binaryguardia/swipeshield/internal/decision"
	"github.com/binaryguardia/swipeshield/internal/ruleengine"
)

// IsEventStream reports whether a response is Server-Sent Events.
func IsEventStream(h http.Header) bool {
	return bytes.Contains([]byte(h.Get("Content-Type")), []byte("text/event-stream"))
}

// Inspector scans an SSE stream for rule matches.
type Inspector struct {
	rules *ruleengine.Engine
}

// NewInspector builds an SSE inspector over the shared rule engine.
func NewInspector(rules *ruleengine.Engine) *Inspector {
	return &Inspector{rules: rules}
}

// Violation is an SSE stream finding.
type Violation struct {
	Line   string `json:"line"`
	RuleID string `json:"rule_id"`
}

// StreamWriter wraps an http.ResponseWriter, scanning data: lines and
// reporting violations asynchronously.
type StreamWriter struct {
	http.ResponseWriter
	insp *Inspector
	mu   sync.Mutex
	// Violations are collected for the event log; blocking the stream is
	// not possible once headers are sent, so SSE inspection is log/flag
	// only (per RULES.md, an inline decision must happen pre-response).
	Violations []Violation
}

// NewStreamWriter wraps w.
func NewStreamWriter(w http.ResponseWriter, insp *Inspector) *StreamWriter {
	return &StreamWriter{ResponseWriter: w, insp: insp}
}

func (s *StreamWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.insp != nil && s.insp.rules != nil {
		s.scan(p)
	}
	return s.ResponseWriter.Write(p)
}

// scan splits input on newlines, evaluates data: lines against the rules.
func (s *StreamWriter) scan(p []byte) {
	sc := bufio.NewScanner(bytes.NewReader(p))
	sc.Buffer(make([]byte, 4096), 64<<10)
	for sc.Scan() {
		line := sc.Text()
		if !bytes.HasPrefix([]byte(line), []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace([]byte(line)[5:])
		if len(payload) == 0 {
			continue
		}
		req := &http.Request{Method: http.MethodGet, Header: http.Header{"Content-Type": {"text/plain"}}}
		res := s.insp.rules.Evaluate(req, payload)
		for _, m := range res.Matches {
			s.Violations = append(s.Violations, Violation{Line: truncate(string(payload), 256), RuleID: m.RuleID})
		}
	}
}

// TakeViolations returns and clears the accumulated violations.
func (s *StreamWriter) TakeViolations() []Violation {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.Violations
	s.Violations = nil
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

var _ = decision.Reason{}
