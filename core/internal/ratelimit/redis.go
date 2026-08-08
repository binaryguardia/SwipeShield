package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBackend is a multi-node safe fixed-window counter using INCR + EXPIRE.
// Fixed-window has minor edge-skew versus sliding-window but is correct
// across instances, which is what distributed deployment requires. Use
// Algorithm "sliding_window" semantics approximated via two keys per window
// (current + previous) for smoother edges.
type RedisBackend struct {
	client *redis.Client
}

// NewRedisBackend connects to Redis at addr.
func NewRedisBackend(addr, password string, db int) (*RedisBackend, error) {
	c := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})
	if err := c.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("ratelimit: redis ping: %w", err)
	}
	return &RedisBackend{client: c}, nil
}

// NewRedisBackendClient wraps an existing client (tests).
func NewRedisBackendClient(c *redis.Client) *RedisBackend {
	return &RedisBackend{client: c}
}

func (r *RedisBackend) Allow(ctx context.Context, bucket string, p Policy, now time.Time) (Result, error) {
	windowMs := p.Window.Milliseconds()
	cur := fmt.Sprintf("%s:%d", bucket, now.UnixMilli()/windowMs)
	prev := fmt.Sprintf("%s:%d", bucket, now.UnixMilli()/windowMs-1)

	pipe := r.client.Pipeline()
	curC := pipe.Incr(ctx, cur)
	pipe.Expire(ctx, cur, p.Window)
	prevC := pipe.Get(ctx, prev)
	if _, err := pipe.Exec(ctx); err != nil && err != redis.Nil {
		return Result{}, err
	}
	prevVal := atoi(prevC.Val())
	curVal := int(curC.Val())
	elapsedFrac := float64(now.UnixMilli()%windowMs) / float64(windowMs)
	weighted := float64(prevVal)*(1-elapsedFrac) + float64(curVal)
	if weighted > float64(p.Limit) {
		return Result{Allowed: false, RetryAfter: p.Window - time.Duration(now.UnixMilli()%windowMs)*time.Millisecond}, nil
	}
	return Result{Allowed: true, Remaining: p.Limit - int(weighted)}, nil
}

func (r *RedisBackend) Close() error { return r.client.Close() }

func atoi(s string) int {
	n := 0
	neg := false
	for i, c := range []byte(s) {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		return -n
	}
	return n
}
