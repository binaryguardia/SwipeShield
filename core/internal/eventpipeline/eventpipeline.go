// Package eventpipeline provides an asynchronous, buffered pipeline that
// turns every WAF verdict into a structured JSON event, fanning out to
// local file and webhook/SIEM sinks. Emit never blocks the request path;
// sink failures are retried with bounded backoff and never crash the proxy.
package eventpipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/binaryguardia/swipeshield/internal/decision"
)

// Event is the canonical structured audit event.
type Event struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	Schema     string            `json:"schema"` // "swipeshield" | "wazuh" | "prajna"
	SiteID     string            `json:"site_id,omitempty"`
	SiteName   string            `json:"site_name,omitempty"`
	Protocol   string            `json:"protocol"`            // rest | graphql | grpc | websocket | sse
	Transport  string            `json:"transport,omitempty"` // h1 | h2 | h3
	ZeroRTT    bool              `json:"zero_rtt,omitempty"`
	Method     string            `json:"method,omitempty"`
	Host       string            `json:"host,omitempty"`
	Path       string            `json:"path,omitempty"`
	ClientIP   string            `json:"client_ip"`
	Status     int               `json:"status"`
	Decision   string            `json:"decision"` // allow | block | challenge | log
	Blocked    bool              `json:"blocked"`
	Reasons    []decision.Reason `json:"reasons"`
	JA3        string            `json:"ja3,omitempty"`
	JA4        string            `json:"ja4,omitempty"`
	H2FP       string            `json:"h2_fingerprint,omitempty"`
	BotScore   float64           `json:"bot_score"`
	MLScore    float64           `json:"ml_score,omitempty"`
	LLMScore   float64           `json:"llm_score,omitempty"`
	GraphQL    *GraphQLSnapshot  `json:"graphql,omitempty"`
	Body       string            `json:"request_body,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	DurationMS float64           `json:"duration_ms"`
}

// GraphQLSnapshot captures parsed-query telemetry for the dashboard.
type GraphQLSnapshot struct {
	Operation     string `json:"operation"`
	Depth         int    `json:"depth"`
	Complexity    int    `json:"complexity"`
	AliasCount    int    `json:"alias_count"`
	Introspection bool   `json:"introspection"`
}

// Sink receives events.
type Sink interface {
	Write(ctx context.Context, e *Event) error
	Close() error
}

// Pipeline drains a buffered channel of events into sinks.
type Pipeline struct {
	queue    chan Event
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	sinks    []Sink
	redactor *Redactor
	schema   string
	dropped  uint64
	closed   bool
}

// Options configures the pipeline.
type Options struct {
	BufferSize   int
	RedactFields []string
	BodyTruncate int
	Schema       string
}

// New creates a pipeline with the given sinks and starts draining.
func New(opts Options, sinks ...Sink) *Pipeline {
	if opts.BufferSize <= 0 {
		opts.BufferSize = 4096
	}
	if opts.BodyTruncate <= 0 {
		opts.BodyTruncate = 2048
	}
	if opts.Schema == "" {
		opts.Schema = "swipeshield"
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipeline{
		queue:    make(chan Event, opts.BufferSize),
		ctx:      ctx,
		cancel:   cancel,
		sinks:    sinks,
		redactor: NewRedactor(opts.RedactFields, opts.BodyTruncate),
		schema:   opts.Schema,
	}
	if p.schema == "" {
		p.schema = "swipeshield"
	}
	p.wg.Add(1)
	go p.drain()
	return p
}

// Emit queues an event for async delivery. Returns immediately.
func (p *Pipeline) Emit(e Event) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	e.Schema = p.schemaOrDefault(e.Schema)
	e.Body = p.redactor.RedactBody(e.Body)
	e.Reasons = redactReasons(e.Reasons)
	select {
	case p.queue <- e:
	default:
		p.mu.Lock()
		p.dropped++
		p.mu.Unlock()
		log.Warn().Str("event_id", e.ID).Msg("event pipeline buffer full; dropping event")
	}
}

func (p *Pipeline) schemaOrDefault(s string) string {
	if s == "" || s == "swipeshield" {
		return p.defaultSchema() // keep caller's override if set
	}
	return s
}

func (p *Pipeline) defaultSchema() string {
	return p.schema
}

func (p *Pipeline) drain() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case e, ok := <-p.queue:
			if !ok {
				return
			}
			p.dispatch(&e)
		}
	}
}

func (p *Pipeline) dispatch(e *Event) {
	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	defer cancel()
	p.mu.Lock()
	sinks := make([]Sink, len(p.sinks))
	copy(sinks, p.sinks)
	p.mu.Unlock()
	for _, s := range sinks {
		if err := s.Write(ctx, e); err != nil {
			log.Error().Err(err).Str("event_id", e.ID).Msg("event sink write failed")
		}
	}
}

// AddSink appends a sink after construction (e.g. the Management API live
// feed, wired at runtime).
func (p *Pipeline) AddSink(s Sink) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sinks = append(p.sinks, s)
}

// Close drains pending events and shuts down.
func (p *Pipeline) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()
	p.cancel()
	close(p.queue)
	// Drain what's left quickly so events aren't lost on graceful shutdown.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case e, ok := <-p.queue:
			if !ok {
				goto done
			}
			p.dispatch(&e)
		case <-deadline:
			goto done
		}
	}
done:
	p.wg.Wait()
	for _, s := range p.sinks {
		_ = s.Close()
	}
}

// Dropped returns the number of events dropped due to a full buffer.
func (p *Pipeline) Dropped() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dropped
}

// --- Sinks ---

// FileSink appends JSON-lines to a file, rotating at a size threshold.
type FileSink struct {
	path   string
	maxLen int64
	f      *os.File
	mu     sync.Mutex
}

// NewFileSink creates a file sink (creates parent dirs).
func NewFileSink(path string, maxBytes int64) (*FileSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		maxBytes = 100 << 20
	}
	return &FileSink{path: path, maxLen: maxBytes, f: f}, nil
}

// NewFileSinkSafe is like NewFileSink but never returns an error: a sink
// that cannot open degrades to a no-op rather than breaking proxy startup.
func NewFileSinkSafe(path string, maxBytes int64) Sink {
	s, err := NewFileSink(path, maxBytes)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("event file sink unavailable; using no-op sink")
		return noopSink{}
	}
	return s
}

// noopSink discards events (used when the file sink cannot be opened).
type noopSink struct{}

func (noopSink) Write(_ context.Context, _ *Event) error { return nil }
func (noopSink) Close() error                            { return nil }

func (s *FileSink) Write(_ context.Context, e *Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if info, err := s.f.Stat(); err == nil && info.Size() > s.maxLen {
		_ = s.f.Close()
		s.f, _ = os.Create(s.path)
	}
	_, err = s.f.Write(append(b, '\n'))
	return err
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// WebhookSink posts events to an HTTP endpoint with bounded retries.
type WebhookSink struct {
	url     string
	client  *httpClient
	retries int
	backoff time.Duration
	schema  string
}

// NewWebhookSink creates a sink posting to url with the given schema shape.
// A zero timeout defaults to 3s per attempt so a dead endpoint can never
// stall the event pipeline.
func NewWebhookSink(url, schema string, timeout time.Duration) *WebhookSink {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &WebhookSink{
		url:     url,
		client:  &httpClient{timeout: timeout},
		retries: 3,
		backoff: 200 * time.Millisecond,
		schema:  schema,
	}
}

func (s *WebhookSink) Write(ctx context.Context, e *Event) error {
	payload, err := json.Marshal(mapToSchema(e, s.schema))
	if err != nil {
		return err
	}
	var lastErr error
	for i := 0; i <= s.retries; i++ {
		if err := s.client.post(ctx, s.url, payload); err != nil {
			lastErr = err
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(s.backoff << i):
			}
			continue
		}
		return nil
	}
	return fmt.Errorf("webhook sink: %w", lastErr)
}

func (s *WebhookSink) Close() error { return nil }

// mapToSchema reshapes the generic event into SIEM-friendly shapes.
func mapToSchema(e *Event, schema string) any {
	switch schema {
	case "wazuh":
		return wazuhEvent(e)
	case "prajna":
		return prajnaEvent(e)
	default:
		return map[string]any{
			"timestamp": e.Timestamp.UTC().Format(time.RFC3339Nano),
			"source":    "swipeshield",
			"event":     e,
		}
	}
}

func wazuhEvent(e *Event) map[string]any {
	return map[string]any{
		"timestamp": e.Timestamp.UTC().Format(time.RFC3339Nano),
		"agent":     map[string]any{"name": e.SiteID},
		"manager":   map[string]any{"name": "swipeshield"},
		"rule": map[string]any{
			"level":       levelFor(e),
			"id":          e.Decision,
			"description": fmt.Sprintf("SwipeShield %s for %s", e.Decision, e.Path),
		},
		"decoder": map[string]any{"name": "swipeshield"},
		"data": map[string]any{
			"srcip":     e.ClientIP,
			"srcport":   0,
			"protocol":  e.Protocol,
			"transport": e.Transport,
			"zero_rtt":  e.ZeroRTT,
			"url":       e.Path,
			"method":    e.Method,
			"status":    e.Status,
			"reasons":   e.Reasons,
			"bot_score": e.BotScore,
			"ja4":       e.JA4,
		},
		"full_log": fmt.Sprintf("SwipeShield %s %s %s from %s", e.Decision, e.Method, e.Path, e.ClientIP),
	}
}

func prajnaEvent(e *Event) map[string]any {
	return map[string]any{
		"timestamp": e.Timestamp.UTC().Format(time.RFC3339Nano),
		"source":    "swipeshield",
		"threat":    e.Decision == "block" || e.Decision == "challenge",
		"rule":      e.Reasons,
		"event":     e,
	}
}

func levelFor(e *Event) int {
	switch e.Decision {
	case "block":
		return 8
	case "challenge":
		return 6
	case "log":
		return 4
	default:
		return 1
	}
}

func redactReasons(rs []decision.Reason) []decision.Reason {
	out := make([]decision.Reason, 0, len(rs))
	for _, r := range rs {
		out = append(out, r)
	}
	return out
}

var _ = strings.TrimSpace
