// Package ratelimit provides per-key rate limiting with token-bucket and
// sliding-window algorithms, backed by an in-memory store (default) or
// Redis (multi-node / edge fleets). Keys are scoped per-IP, per-API-key,
// per-GraphQL-operation, and per-WebSocket-message.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Scope is the dimension a limit applies to.
type Scope string

const (
	ScopeIP        Scope = "ip"
	ScopeAPIKey    Scope = "api_key"
	ScopeGraphQLOp Scope = "graphql_op"
	ScopeWSMessage Scope = "ws_message"
)

// Policy describes one rate limit.
type Policy struct {
	Scope     Scope
	Key       string // key within the scope (e.g. the IP, the API key, the operation name)
	Limit     int
	Window    time.Duration
	Burst     int    // token bucket capacity; 0 disables burst
	Algorithm string // "sliding_window" | "token_bucket"
}

// Result is the outcome of a rate-limit check.
type Result struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Backend persists counter state.
type Backend interface {
	// Allow atomically checks and, if allowed, records a request.
	Allow(ctx context.Context, bucket string, policy Policy, now time.Time) (Result, error)
	Close() error
}

// Limiter wraps a Backend with a policy set.
type Limiter struct {
	backend Backend
	mu      sync.Mutex
	noop    bool
}

// NewLimiter returns a limiter over the given backend.
func NewLimiter(b Backend) *Limiter {
	return &Limiter{backend: b}
}

// Allow checks a single policy.
func (l *Limiter) Allow(ctx context.Context, p Policy, now time.Time) Result {
	if l == nil || l.backend == nil || p.Limit <= 0 {
		return Result{Allowed: true, Remaining: -1}
	}
	res, err := l.backend.Allow(ctx, bucketKey(p), p, now)
	if err != nil {
		// Fail-open on storage errors: never break the hot path for
		// rate-limit bookkeeping.
		return Result{Allowed: true, Remaining: -1}
	}
	return res
}

// Check runs multiple policies; the request is allowed only if all allow.
func (l *Limiter) Check(ctx context.Context, policies []Policy, now time.Time) (Result, string) {
	for _, p := range policies {
		r := l.Allow(ctx, p, now)
		if !r.Allowed {
			return r, string(p.Scope)
		}
	}
	return Result{Allowed: true, Remaining: -1}, ""
}

func bucketKey(p Policy) string {
	return "rl:" + string(p.Scope) + ":" + p.Key
}
