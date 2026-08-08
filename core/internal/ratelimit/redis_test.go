package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newRedisLimiter spins up an in-process Redis and returns a Limiter over the
// shared backend. Simulating two "instances" shares one Redis, which is the
// multi-instance guarantee we're asserting.
func newRedisLimiter(t *testing.T) (*Limiter, *Limiter) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	b := NewRedisBackendClient(rc)
	return NewLimiter(b), NewLimiter(b)
}

func TestRedisMultiInstanceSharedLimit(t *testing.T) {
	a, b := newRedisLimiter(t)
	ctx := context.Background()
	pol := p(ScopeIP, "shared-key", 2, time.Minute)
	now := time.Now()

	// Instance A takes the first two tokens.
	if r := a.Allow(ctx, pol, now); !r.Allowed {
		t.Fatal("A:1 denied")
	}
	if r := a.Allow(ctx, pol, now); !r.Allowed {
		t.Fatal("A:2 denied")
	}
	// Instance B must observe the shared counter.
	if r := b.Allow(ctx, pol, now); r.Allowed {
		t.Fatal("B:1 allowed despite shared limit exhausted")
	}
}

func TestRedisWindowSlides(t *testing.T) {
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	a := NewLimiter(NewRedisBackendClient(rc))
	b := NewLimiter(NewRedisBackendClient(rc))
	ctx := context.Background()
	pol := p(ScopeIP, "w", 1, time.Minute)
	now := time.Now()
	if r := a.Allow(ctx, pol, now); !r.Allowed {
		t.Fatal("w:1 denied")
	}
	if r := b.Allow(ctx, pol, now.Add(30*time.Second)); r.Allowed {
		t.Fatal("request in same window allowed")
	}
	// Advance miniredis's clock so the previous window's keys expire; a
	// request in the new window is then allowed.
	mr.FastForward(61 * time.Second)
	if r := a.Allow(ctx, pol, now.Add(61*time.Second)); !r.Allowed {
		t.Fatal("request after window roll allowed")
	}
}

func TestRedisPerKeyIsolation(t *testing.T) {
	a, _ := newRedisLimiter(t)
	ctx := context.Background()
	pol := p(ScopeAPIKey, "ka", 1, time.Minute)
	if r := a.Allow(ctx, pol, time.Now()); !r.Allowed {
		t.Fatal("ka:1 denied")
	}
	if r := a.Allow(ctx, p(ScopeAPIKey, "kb", 1, time.Minute), time.Now()); !r.Allowed {
		t.Fatal("kb:1 denied")
	}
	if r := a.Allow(ctx, pol, time.Now()); r.Allowed {
		t.Fatal("ka:2 allowed")
	}
}
