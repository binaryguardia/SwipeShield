package ratelimit

import (
	"context"
	"sync"
	"time"
)

// MemoryBackend stores counters in-process. Suitable for single-instance
// deployments; use RedisBackend for multi-node fleets.
type MemoryBackend struct {
	mu  sync.Mutex
	sw  map[string]*swEntry
	tb  map[string]*tbEntry
	now func() time.Time
}

type swEntry struct {
	window time.Time
	prev   int
	curr   int
}

type tbEntry struct {
	tokens float64
	last   time.Time
}

// NewMemoryBackend returns an in-memory backend.
func NewMemoryBackend() *MemoryBackend {
	return &MemoryBackend{
		sw:  make(map[string]*swEntry),
		tb:  make(map[string]*tbEntry),
		now: time.Now,
	}
}

// SetClock overrides the clock (tests).
func (m *MemoryBackend) SetClock(f func() time.Time) {
	m.mu.Lock()
	m.now = f
	m.mu.Unlock()
}

func (m *MemoryBackend) Allow(ctx context.Context, bucket string, p Policy, now time.Time) (Result, error) {
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	switch p.Algorithm {
	case "token_bucket":
		return m.tokenBucket(bucket, p, now)
	default:
		return m.slidingWindow(bucket, p, now)
	}
}

func (m *MemoryBackend) slidingWindow(bucket string, p Policy, now time.Time) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sw[bucket]
	if !ok || now.Sub(e.window) >= p.Window {
		e = &swEntry{window: now}
		m.sw[bucket] = e
	}
	elapsed := now.Sub(e.window).Seconds()
	weight := float64(e.prev) * (1 - elapsed/p.Window.Seconds())
	current := weight + float64(e.curr)
	if current >= float64(p.Limit) {
		retry := p.Window - now.Sub(e.window)
		return Result{Allowed: false, RetryAfter: retry}, nil
	}
	e.curr++
	remaining := int(float64(p.Limit) - current - 1)
	return Result{Allowed: true, Remaining: remaining}, nil
}

func (m *MemoryBackend) tokenBucket(bucket string, p Policy, now time.Time) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	burst := p.Burst
	if burst <= 0 {
		burst = p.Limit
	}
	rate := float64(p.Limit) / p.Window.Seconds() // tokens per second
	e, ok := m.tb[bucket]
	if !ok {
		e = &tbEntry{tokens: float64(burst), last: now}
		m.tb[bucket] = e
	}
	e.tokens += rate * now.Sub(e.last).Seconds()
	if e.tokens > float64(burst) {
		e.tokens = float64(burst)
	}
	e.last = now
	if e.tokens >= 1 {
		e.tokens--
		return Result{Allowed: true, Remaining: int(e.tokens)}, nil
	}
	return Result{Allowed: false, RetryAfter: time.Duration((1 - e.tokens) / rate * float64(time.Second))}, nil
}

// Prune drops expired entries to bound memory.
func (m *MemoryBackend) Prune(maxAge time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := m.now().Add(-maxAge)
	for k, e := range m.sw {
		if e.window.Before(cutoff) {
			delete(m.sw, k)
		}
	}
	for k, e := range m.tb {
		if e.last.Before(cutoff) {
			delete(m.tb, k)
		}
	}
}

func (m *MemoryBackend) Close() error { return nil }
