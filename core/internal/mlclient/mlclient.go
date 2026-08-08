// Package mlclient is a defensive HTTP client for the optional ML anomaly
// scoring service. It is optional: when the service is unreachable, the proxy
// fails per the site's fail mode, never blocks the hot path, and trips a
// circuit breaker after consecutive failures so a flapping ML backend cannot
// drag down latency.
package mlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/binaryguardia/sentinelwaf/internal/config"
)

// Features is the JSON payload sent to the ML service.
type Features struct {
	SiteID       string  `json:"site_id"`
	Method       string  `json:"method"`
	Path         string  `json:"path"`
	Protocol     string  `json:"protocol"`
	ClientIP     string  `json:"client_ip"`
	ContentType  string  `json:"content_type"`
	BodyLen      int     `json:"body_len"`
	HeaderCount  int     `json:"header_count"`
	HasAuth      bool    `json:"has_auth"`
	IsGraphQL    bool    `json:"is_graphql"`
	GraphQLDepth int     `json:"graphql_depth,omitempty"`
	GraphQLCost  int     `json:"graphql_cost,omitempty"`
	HasCookie    bool    `json:"has_cookie"`
	HasAPIKey    bool    `json:"has_api_key"`
	BotScore     float64 `json:"bot_score"`
	JA4          string  `json:"ja4,omitempty"`
}

// Result is the model output.
type Result struct {
	Anomaly bool    `json:"anomaly"`
	Score   float64 `json:"score"` // 0..1
	Label   string  `json:"label,omitempty"`
}

// Client scores requests against an HTTP ML service with a circuit breaker.
type Client struct {
	cfg      config.MLConfig
	hc       *http.Client
	mu       sync.Mutex
	failures int
	open     bool
	openedAt time.Time
}

// New builds a client from ML config.
func New(cfg config.MLConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = config.Duration(250 * time.Millisecond)
	}
	if cfg.CircuitOpen == 0 {
		cfg.CircuitOpen = 5
	}
	return &Client{
		cfg: cfg,
		hc:  &http.Client{Timeout: time.Duration(cfg.Timeout)},
	}
}

// Score sends features and returns the anomaly score. When the circuit is
// open it returns an error immediately (caller applies the fail mode).
func (c *Client) Score(ctx context.Context, f Features) (Result, error) {
	if c.cfg.URL == "" || !c.cfg.Enabled {
		return Result{}, nil
	}
	if c.breakerOpen() {
		return Result{}, errCircuitOpen
	}
	b, err := json.Marshal(f)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+"/score", bytes.NewReader(b))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		c.recordFailure()
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.recordFailure()
		return Result{}, errMLStatus
	}
	c.recordSuccess()
	var r Result
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return Result{}, err
	}
	if r.Score < 0 {
		r.Score = 0
	}
	if r.Score > 1 {
		r.Score = 1
	}
	return r, nil
}

func (c *Client) breakerOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.open {
		return false
	}
	// Half-open after 5s: allow one probe.
	if time.Since(c.openedAt) > 5*time.Second {
		c.open = false
		c.failures = 0
		return false
	}
	return true
}

func (c *Client) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures >= c.cfg.CircuitOpen {
		c.open = true
		c.openedAt = time.Now()
	}
}

func (c *Client) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.open = false
}
