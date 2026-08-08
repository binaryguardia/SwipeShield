package websocket

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/decision"
	"github.com/binaryguardia/swipeshield/internal/ratelimit"
	"github.com/binaryguardia/swipeshield/internal/ruleengine"
)

// Inspector applies per-message rate limits and pattern rules to the frames
// of a persistent WebSocket connection.
type Inspector struct {
	rules   *ruleengine.Engine
	limiter *ratelimit.Limiter
	cfg     *config.WebSocketConfig
}

// NewInspector wires the inspector to shared rule/rate-limit engines.
func NewInspector(rules *ruleengine.Engine, limiter *ratelimit.Limiter, cfg *config.WebSocketConfig) *Inspector {
	return &Inspector{rules: rules, limiter: limiter, cfg: cfg}
}

// IsUpgrade reports whether a request is a WebSocket upgrade handshake.
func IsUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Connection"), "Upgrade") {
		return false
	}
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

// Policies returns the per-connection message rate-limit policies.
func (i *Inspector) Policies(clientIP, apiKey string) []ratelimit.Policy {
	var out []ratelimit.Policy
	if i.cfg == nil || !i.cfg.Enabled {
		return out
	}
	if i.cfg.MaxMessagesPerMin > 0 {
		out = append(out, ratelimit.Policy{
			Scope:     ratelimit.ScopeWSMessage,
			Key:       clientIP,
			Limit:     i.cfg.MaxMessagesPerMin,
			Window:    time.Minute,
			Algorithm: "token_bucket",
		})
	}
	return out
}

// InspectMessage evaluates one frame's payload. It returns the verdict
// reasons and whether the message may be forwarded.
func (i *Inspector) InspectMessage(ctx context.Context, clientIP, apiKey string, payload []byte, frameType byte) ([]decision.Reason, bool) {
	var reasons []decision.Reason

	if i.cfg != nil && i.cfg.MaxMessageBytes > 0 && len(payload) > i.cfg.MaxMessageBytes {
		reasons = append(reasons, decision.Reason{
			Module:  "websocket",
			Message: "message exceeds per-message size limit",
			Status:  1008, // policy violation
		})
		return reasons, false
	}

	// Per-message rate limiting.
	if i.limiter != nil {
		for _, p := range i.Policies(clientIP, apiKey) {
			if res := i.limiter.Allow(ctx, p, time.Now()); !res.Allowed {
				reasons = append(reasons, decision.Reason{
					Module:  "websocket",
					RuleID:  "WS-RATE",
					Message: "websocket message rate limit exceeded",
					Status:  1008,
				})
				return reasons, false
			}
		}
	}

	// Pattern rules on the message payload.
	if i.rules != nil {
		synth := &http.Request{
			Method:     http.MethodPost,
			RemoteAddr: clientIP,
			Header:     make(http.Header),
		}
		synth.Header.Set("Content-Type", "application/octet-stream")
		if apiKey != "" {
			synth.Header.Set("X-Api-Key", apiKey)
		}
		if frameType == OpText {
			synth.Header.Set("Content-Type", "text/plain")
		}
		res := i.rules.Evaluate(synth, payload)
		for _, m := range res.Matches {
			reasons = append(reasons, decision.Reason{
				Module:  "websocket",
				RuleID:  m.RuleID,
				Message: "websocket message matched rule: " + m.Message,
				Status:  1008,
			})
		}
		if res.Blocked || res.Challenged {
			return reasons, false
		}
	}
	return reasons, true
}
