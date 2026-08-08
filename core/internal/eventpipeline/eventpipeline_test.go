package eventpipeline

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/binaryguardia/swipeshield/internal/decision"
)

func sampleEvent() Event {
	return Event{
		ID:        "evt-1",
		Timestamp: time.Now(),
		Schema:    "swipeshield",
		Protocol:  "rest",
		Decision:  "block",
		Blocked:   true,
		ClientIP:  "203.0.113.7",
		Path:      "/login",
		Method:    "POST",
		Body:      `{"username":"alice","password":"sup3rS3cret","note":"hello"}`,
		Reasons:   []decision.Reason{{Module: "crs", RuleID: "CRS-942100", Message: "SQLi", Score: 0.9}},
	}
}

func TestPipelineRedactsSensitiveFields(t *testing.T) {
	var mu sync.Mutex
	var got Event
	rec := &recSink{fn: func(e *Event) { mu.Lock(); got = *e; mu.Unlock() }}
	p := New(Options{RedactFields: []string{"username"}}, rec)
	defer p.Close()
	p.Emit(sampleEvent())
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return got.ID != "" })

	var m map[string]any
	if err := json.Unmarshal([]byte(got.Body), &m); err != nil {
		t.Fatal(err)
	}
	if v, _ := m["password"].(string); !strings.Contains(v, "REDACTED") {
		t.Fatalf("password not redacted: %v", m["password"])
	}
	if v, _ := m["note"].(string); v != "hello" {
		t.Fatalf("innocent field was clobbered: %q", v)
	}
}

// TestRedactLongJSONBody guards against truncation before JSON parsing: a body
// longer than the truncate limit must still get field-level redaction, not a
// mangled, unparseable prefix leaking credentials. The long value lives in a
// key that sorts after the sensitive ones so the redacted markers survive the
// truncation window.
func TestRedactLongJSONBody(t *testing.T) {
	body := `{"password":"sup3rS3cret","username":"alice","zzz":"` + strings.Repeat("x", 500) + `"}`
	r := NewRedactor([]string{"username"}, 200)
	out := r.RedactBody(body)
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("long JSON body lost field redaction: %q", out)
	}
	if !strings.Contains(out, "(truncated)") {
		t.Fatalf("long JSON body not truncated: %d bytes", len(out))
	}
	if strings.Contains(out, "sup3rS3cret") {
		t.Fatal("password leaked in long JSON body")
	}
}

// TestRedactCustomFieldMarker ensures a configured field outside the built-in
// special map is replaced with "[REDACTED]", not an empty string.
func TestRedactCustomFieldMarker(t *testing.T) {
	r := NewRedactor([]string{"email"}, 2048)
	out := r.RedactBody(`{"email":"alice@example.com","name":"alice"}`)
	if !strings.Contains(out, `"email":"[REDACTED]"`) {
		t.Fatalf("custom field not redacted with marker: %s", out)
	}
}

func TestPipelineTruncatesBody(t *testing.T) {
	rec := &recSink{fn: func(*Event) {}}
	p := New(Options{BodyTruncate: 16}, rec)
	defer p.Close()
	e := sampleEvent()
	e.Body = strings.Repeat("x", 100)
	p.Emit(e)
	waitFor(t, func() bool { return rec.count() >= 1 })
	if len(rec.last().Body) >= 100 {
		t.Fatalf("body not truncated: %d bytes", len(rec.last().Body))
	}
}

func TestPipelineDropsOnFullBuffer(t *testing.T) {
	block := make(chan struct{})
	rec := &recSink{fn: func(*Event) { <-block }}
	p := New(Options{BufferSize: 8}, rec)
	// Fill the buffer: the drain goroutine is blocked in the sink so queue
	// backs up and Emit starts dropping.
	for i := 0; i < 64; i++ {
		p.Emit(sampleEvent())
	}
	close(block)
	time.Sleep(100 * time.Millisecond)
	if p.Dropped() == 0 {
		t.Fatal("no events dropped under backpressure")
	}
	p.Close()
}

func TestWebhookSinkRetries(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewWebhookSink(srv.URL, "swipeshield", time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	evt := sampleEvent()
	err := s.Write(ctx, &evt)
	if err == nil {
		t.Fatal("expected failure after retries exhausted")
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts < 3 {
		t.Fatalf("expected >=3 retry attempts, got %d", attempts)
	}
}

func TestWebhookSinkSuccess(t *testing.T) {
	var got map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		json.NewDecoder(r.Body).Decode(&got)
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewWebhookSink(srv.URL, "wazuh", time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	evt := sampleEvent()
	if err := s.Write(ctx, &evt); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got["manager"] == nil {
		t.Fatalf("wazuh-shaped event missing manager: %+v", got)
	}
}

func TestFileSinkWritesAndRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	s, err := NewFileSink(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		evt := sampleEvent()
		if err := s.Write(context.Background(), &evt); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("file sink wrote nothing")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("corrupt JSON line: %v", err)
		}
	}
}

func TestLiveFeedRingAndFanout(t *testing.T) {
	f := NewLiveFeed(4)
	for i := 0; i < 10; i++ {
		e := sampleEvent()
		e.ID = string(rune('a' + i))
		if err := f.Write(context.Background(), &e); err != nil {
			t.Fatal(err)
		}
	}
	recent := f.Recent(4)
	if len(recent) != 4 {
		t.Fatalf("recent = %d", len(recent))
	}
	if recent[3].ID != "j" {
		t.Fatalf("last event = %q", recent[3].ID)
	}

	ch, unsub := f.Subscribe(10)
	defer unsub()
	n := 0
	for range ch {
		n++
		if n >= 4 {
			break
		}
	}
	if n != 4 {
		t.Fatalf("subscriber received %d replay events", n)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLiveFeedSlowSubscriberNeverBlocks(t *testing.T) {
	f := NewLiveFeed(2)
	ch, unsub := f.Subscribe(1)
	defer unsub()
	_ = ch // never drain: the ring writes must not block
	for i := 0; i < 100; i++ {
		e := sampleEvent()
		e.ID = "x"
		if err := f.Write(context.Background(), &e); err != nil {
			t.Fatalf("feed blocked on slow subscriber: %v", err)
		}
	}
}

func TestSchemaShaping(t *testing.T) {
	evt := sampleEvent()
	w := wazuhEvent(&evt)
	if w["agent"] == nil {
		t.Fatal("wazuh event missing agent")
	}
	p := prajnaEvent(&evt)
	threat, _ := p["threat"].(bool)
	if !threat {
		t.Fatal("prajna event did not mark block as threat")
	}
}

// --- helpers ---

type recSink struct {
	mu sync.Mutex
	es []Event
	fn func(*Event)
}

func (r *recSink) Write(_ context.Context, e *Event) error {
	r.mu.Lock()
	r.es = append(r.es, *e)
	r.mu.Unlock()
	if r.fn != nil {
		r.fn(e)
	}
	return nil
}

func (r *recSink) Close() error { return nil }

func (r *recSink) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.es)
}

func (r *recSink) last() Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.es[len(r.es)-1]
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}
