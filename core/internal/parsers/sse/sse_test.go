package sse

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/binaryguardia/swipeshield/internal/ruleengine"
)

func TestIsEventStream(t *testing.T) {
	if !IsEventStream(map[string][]string{"Content-Type": {"text/event-stream"}}) {
		t.Fatal("event-stream content type not detected")
	}
	if IsEventStream(map[string][]string{"Content-Type": {"application/json"}}) {
		t.Fatal("json content type misdetected")
	}
}

func TestStreamScanDetectsSQLiLine(t *testing.T) {
	eng := ruleengine.New()
	if err := eng.SetCRSToggles(ruleengine.CRSToggles{SQLi: true}); err != nil {
		t.Fatal(err)
	}
	insp := NewInspector(eng)
	rr := httptest.NewRecorder()
	sw := NewStreamWriter(rr, insp)
	_, _ = sw.Write([]byte("data: update complete\n\n"))
	_, _ = sw.Write([]byte("data: SELECT * FROM users WHERE id=' OR 1=1 --\n\n"))
	vs := sw.TakeViolations()
	if len(vs) == 0 {
		t.Fatalf("no violations: %q", rr.Body.String())
	}
}

func TestStreamScanAllowsBenignLines(t *testing.T) {
	eng := ruleengine.New()
	if err := eng.SetCRSToggles(ruleengine.CRSToggles{SQLi: true, XSS: true}); err != nil {
		t.Fatal(err)
	}
	insp := NewInspector(eng)
	sw := NewStreamWriter(httptest.NewRecorder(), insp)
	for i := 0; i < 100; i++ {
		_, _ = sw.Write([]byte("data: tick 1234 \"healthy\"\n\n"))
	}
	if vs := sw.TakeViolations(); len(vs) != 0 {
		t.Fatalf("false positives: %+v", vs)
	}
}

func TestStreamWriterPassesBytesThrough(t *testing.T) {
	eng := ruleengine.New()
	sw := NewStreamWriter(httptest.NewRecorder(), NewInspector(eng))
	n, err := sw.Write([]byte("data: hello\n\n"))
	if err != nil || n != 13 {
		t.Fatalf("write n=%d err=%v", n, err)
	}
}

func TestStreamScanSplitsAcrossWrites(t *testing.T) {
	eng := ruleengine.New()
	if err := eng.SetCRSToggles(ruleengine.CRSToggles{SQLi: true}); err != nil {
		t.Fatal(err)
	}
	sw := NewStreamWriter(httptest.NewRecorder(), NewInspector(eng))
	// Two writes: the first is benign, the second carries a complete
	// malicious data: line. Both must be scanned independently.
	_, _ = sw.Write([]byte("data: ping\n\n"))
	_, _ = sw.Write([]byte("data: 1 UNION SELECT password FROM users\n\n"))
	if vs := sw.TakeViolations(); len(vs) != 1 {
		t.Fatalf("expected 1 violation, got %+v", vs)
	}
}

var _ = strings.TrimSpace
