package ratelimit

import (
	"context"
	"testing"
	"time"
)

func p(scope Scope, key string, limit int, win time.Duration) Policy {
	return Policy{Scope: scope, Key: key, Limit: limit, Window: win, Algorithm: "sliding_window"}
}

func TestMemorySlidingWindow(t *testing.T) {
	b := NewMemoryBackend()
	l := NewLimiter(b)
	ctx := context.Background()
	pol := p(ScopeIP, "10.0.0.1", 5, time.Minute)
	for i := 0; i < 5; i++ {
		r := l.Allow(ctx, pol, time.Now())
		if !r.Allowed {
			t.Fatalf("request %d denied", i+1)
		}
	}
	if r := l.Allow(ctx, pol, time.Now()); r.Allowed {
		t.Fatal("6th request allowed")
	}
}

func TestMemoryWindowExpiry(t *testing.T) {
	b := NewMemoryBackend()
	l := NewLimiter(b)
	ctx := context.Background()
	pol := p(ScopeIP, "a", 1, time.Minute)
	now := time.Now()
	if r := l.Allow(ctx, pol, now); !r.Allowed {
		t.Fatal("first denied")
	}
	if r := l.Allow(ctx, pol, now); r.Allowed {
		t.Fatal("second within window allowed")
	}
	if r := l.Allow(ctx, pol, now.Add(61*time.Second)); !r.Allowed {
		t.Fatal("request after expiry denied")
	}
}

func TestMemoryPerKeyIsolation(t *testing.T) {
	b := NewMemoryBackend()
	l := NewLimiter(b)
	ctx := context.Background()
	now := time.Now()
	if r := l.Allow(ctx, p(ScopeIP, "a", 1, time.Minute), now); !r.Allowed {
		t.Fatal("a:1 denied")
	}
	if r := l.Allow(ctx, p(ScopeIP, "b", 1, time.Minute), now); !r.Allowed {
		t.Fatal("b:1 denied")
	}
	if r := l.Allow(ctx, p(ScopeIP, "a", 1, time.Minute), now); r.Allowed {
		t.Fatal("a:2 allowed")
	}
	if r := l.Allow(ctx, p(ScopeIP, "b", 1, time.Minute), now); r.Allowed {
		t.Fatal("b:2 allowed")
	}
}

func TestLimiterCheckAllPolicies(t *testing.T) {
	l := NewLimiter(NewMemoryBackend())
	ctx := context.Background()
	now := time.Now()
	pols := []Policy{
		p(ScopeIP, "9.9.9.9", 2, time.Minute),
		p(ScopeGraphQLOp, "GetUser", 1, time.Minute),
	}
	if _, denied := l.Check(ctx, pols, now); denied != "" {
		t.Fatal("first check denied")
	}
	r, denied := l.Check(ctx, pols, now)
	if denied == "" {
		t.Fatal("second check should trip GraphQLOp limit")
	}
	if denied != "graphql_op" {
		t.Fatalf("denied scope = %q, want graphql_op", denied)
	}
	_ = r
}

func TestTokenBucketBurst(t *testing.T) {
	b := NewMemoryBackend()
	l := NewLimiter(b)
	ctx := context.Background()
	pol := Policy{Scope: ScopeAPIKey, Key: "k1", Limit: 1, Window: time.Minute, Burst: 3, Algorithm: "token_bucket"}
	now := time.Now()
	for i := 0; i < 3; i++ {
		if r := l.Allow(ctx, pol, now); !r.Allowed {
			t.Fatalf("burst token %d denied", i+1)
		}
	}
	if r := l.Allow(ctx, pol, now); r.Allowed {
		t.Fatal("4th token allowed beyond burst")
	}
	if r := l.Allow(ctx, pol, now.Add(61*time.Second)); !r.Allowed {
		t.Fatal("refill token denied")
	}
}

func TestPrune(t *testing.T) {
	b := NewMemoryBackend()
	_, _ = b.Allow(context.Background(), "rl:ip:x", p(ScopeIP, "x", 1, time.Minute), time.Now())
	// A negative max-age prunes every entry regardless of age.
	b.Prune(-time.Hour)
	if len(b.sw) != 0 {
		t.Fatal("prune did not clear entry")
	}
}
