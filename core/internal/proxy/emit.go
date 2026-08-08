package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/binaryguardia/sentinelwaf/internal/decision"
	"github.com/binaryguardia/sentinelwaf/internal/eventpipeline"
)

func newEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// emit publishes a structured audit event for one request. It never blocks.
func (g *Gateway) emit(ctx *decision.InspectContext, start time.Time, status int, action decision.Action, blocked bool) {
	reasons := make([]decision.Reason, 0, len(ctx.Reasons))
	reasons = append(reasons, ctx.Reasons...)

	e := eventpipeline.Event{
		ID:         newEventID(),
		Timestamp:  time.Now(),
		SiteID:     siteID(ctx),
		SiteName:   siteName(ctx),
		Protocol:   ctx.Protocol,
		Transport:  ctx.Transport,
		ZeroRTT:    ctx.ZeroRTT,
		Method:     ctx.Method,
		Host:       ctx.Host,
		Path:       ctx.Path,
		ClientIP:   ctx.ClientIP,
		Status:     status,
		Decision:   string(action),
		Blocked:    blocked,
		Reasons:    reasons,
		JA3:        ctx.JA3,
		JA4:        ctx.JA4,
		H2FP:       ctx.H2Fingerprint,
		BotScore:   ctx.BotScore,
		MLScore:    ctx.MLScore,
		LLMScore:   ctx.LLMScore,
		DurationMS: float64(time.Since(start).Microseconds()) / 1000.0,
	}
	if ctx.GraphQL != nil {
		e.GraphQL = &eventpipeline.GraphQLSnapshot{
			Operation:     ctx.GraphQL.OperationName,
			Depth:         ctx.GraphQL.Depth,
			Complexity:    ctx.GraphQL.Complexity,
			AliasCount:    ctx.GraphQL.AliasCount,
			Introspection: ctx.GraphQL.Introspection,
		}
	}
	if len(ctx.Body) > 0 {
		e.Body = string(ctx.Body)
	}
	g.stats.AddRequest(ctx.Protocol)
	if ctx.GraphQL != nil {
		g.stats.AddGraphQL(uint64(ctx.GraphQL.Depth), uint64(ctx.GraphQL.Complexity))
	}
	if blocked {
		if action == decision.Challenge {
			g.stats.AddChallenged()
		} else {
			g.stats.AddBlocked()
		}
	}
	g.events.Emit(e)
}

func siteID(ctx *decision.InspectContext) string {
	if ctx.Site != nil {
		return ctx.Site.ID
	}
	return ""
}

func siteName(ctx *decision.InspectContext) string {
	if ctx.Site != nil {
		return ctx.Site.Name
	}
	return ""
}
