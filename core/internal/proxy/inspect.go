package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/binaryguardia/swipeshield/internal/botscoring"
	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/decision"
	"github.com/binaryguardia/swipeshield/internal/fingerprint"
	"github.com/binaryguardia/swipeshield/internal/llmprotect"
	"github.com/binaryguardia/swipeshield/internal/mlclient"
	"github.com/binaryguardia/swipeshield/internal/parsers/graphql"
	"github.com/binaryguardia/swipeshield/internal/ratelimit"
	"github.com/binaryguardia/swipeshield/internal/ruleengine"
	"github.com/binaryguardia/swipeshield/internal/wasmplugins"
)

// inspect runs the full protection pipeline against one buffered request and
// returns the verdict. A returned error means the pipeline itself failed
// (never a normal block) — the caller applies the site fail mode.
func (g *Gateway) inspect(ctx *decision.InspectContext) (*decision.InspectContext, decision.Verdict, error) {
	site := ctx.Site
	ctx.Protocol = "rest"

	// 1. OWASP CRS + custom rules.
	if res := g.rt(site.ID).engine.Evaluate(ctx.Request, ctx.Body); res.Err != nil {
		return ctx, decision.Verdict{}, fmt.Errorf("rule engine: %w", res.Err)
	} else {
		for _, m := range res.Matches {
			status := 0
			action := decision.Log
			switch m.Action {
			case ruleengine.ActionBlock:
				status = http.StatusForbidden
				action = decision.Block
			case ruleengine.ActionChallenge:
				status = http.StatusTooManyRequests
				action = decision.Challenge
			}
			ctx.AddReason(decision.Reason{
				Module:  "rules",
				RuleID:  m.RuleID,
				Message: m.Message,
				Score:   severityScore(m.Severity),
				Status:  status,
				Data:    map[string]any{"action": action, "engine": m.Engine},
			})
		}
	}

	// 2. Protocol-aware parsers.
	g.inspectProtocol(ctx)

	// 3. Rate limiting.
	g.inspectRateLimit(ctx)

	// 4. Bot scoring + proof-of-work challenge.
	g.inspectBot(ctx)

	// 5. WASM plugins (fail-open per plugin; site fail mode on host error).
	g.inspectPlugins(ctx)

	// 6. LLM protection (only for operator-flagged AI routes).
	g.inspectLLM(ctx)

	// 7. ML anomaly scoring.
	g.inspectML(ctx)

	// 8. Aggregation.
	verdict := summarize(ctx.Reasons, site)
	return ctx, verdict, nil
}

// Evaluate runs the full protection pipeline against a synthetic request
// without proxying. It is the public entry point used by the Envoy ext_proc
// sidecar (deploy/envoy): Envoy streams request headers/body fragments here and
// receives the verdict to enforce (allow / block / challenge).
func (g *Gateway) Evaluate(r *http.Request, body []byte) (decision.Verdict, error) {
	start := time.Now()
	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}
	site := g.store.Get().SiteByDomain(host)
	if site == nil {
		return decision.Verdict{Decision: decision.Block, StatusCode: http.StatusBadRequest}, nil
	}
	ctx := &decision.InspectContext{
		Request:  r,
		Site:     site,
		ClientIP: clientIP(r),
		Host:     host,
		Path:     r.URL.Path,
		Method:   r.Method,
		Body:     body,
		Protocol: "rest",
		APIKey:   apiKey(r),
	}
	switch r.ProtoMajor {
	case 3:
		ctx.Transport = "h3"
	case 2:
		ctx.Transport = "h2"
	default:
		ctx.Transport = "h1"
	}
	// TLS fingerprints are set from the underlying connection in ServeHTTP;
	// in ext_proc mode Envoy owns the connection, so JA4 is unknown here.
	if h, ok := r.Context().Value(fpCtxKey{}).(*fingerprint.ClientHello); ok && h != nil {
		ctx.JA4 = fingerprint.JA4(h)
		ctx.JA3 = fingerprint.JA3(h)
	}
	_, verdict, err := g.inspect(ctx)
	if err != nil {
		return decision.Verdict{}, err
	}
	switch verdict.Decision {
	case decision.Block:
		status := verdict.StatusCode
		if status == 0 {
			status = http.StatusForbidden
		}
		g.emit(ctx, start, status, decision.Block, true)
	case decision.Challenge:
		// ext_proc has no challenge page; the data plane just sees a block.
		status := verdict.StatusCode
		if status == 0 {
			status = http.StatusForbidden
		}
		g.emit(ctx, start, status, decision.Challenge, true)
	default:
		status := verdict.StatusCode
		if status == 0 {
			status = http.StatusOK
		}
		g.emit(ctx, start, status, decision.Allow, false)
	}
	return verdict, nil
}

// inspectProtocol runs GraphQL / gRPC parsers and updates ctx.Protocol.
func (g *Gateway) inspectProtocol(ctx *decision.InspectContext) {
	site := ctx.Site
	ct := strings.ToLower(ctx.Request.Header.Get("Content-Type"))
	bodyStr := string(ctx.Body)

	if site.GraphQL != nil && site.GraphQL.Enabled && looksLikeGraphQL(ct, bodyStr) {
		ctx.Protocol = "graphql"
		req, err := graphql.ExtractQuery(ctx.Body, ctx.Request.URL.Query().Get("query"), ctx.Request.Header.Get("Content-Type"))
		if err != nil {
			ctx.AddReason(decision.Reason{Module: "graphql", RuleID: "GQL-PARSE", Message: "could not extract GraphQL query: " + err.Error(), Status: http.StatusBadRequest})
			return
		}
		rep := graphql.Inspect(req, site.GraphQL)
		if rep.Malformed {
			ctx.AddReason(decision.Reason{Module: "graphql", RuleID: "GQL-MALFORMED", Message: strings.Join(rep.Issues, "; "), Status: http.StatusBadRequest})
			return
		}
		ctx.GraphQL = &decision.GraphQLInfo{
			OperationName: rep.Info.OperationName,
			Depth:         rep.Info.Depth,
			Complexity:    rep.Info.Complexity,
			AliasCount:    rep.Info.AliasCount,
			Introspection: rep.Info.Introspection,
			Query:         rep.Info.Query,
		}
		for _, issue := range rep.Issues {
			status := http.StatusBadRequest
			if strings.Contains(issue, "introspection") || strings.Contains(issue, "batching") {
				status = http.StatusForbidden
			}
			ctx.AddReason(decision.Reason{Module: "graphql", RuleID: "GQL-POLICY", Message: issue, Status: status})
		}
		return
	}

	if site.GRPC != nil && site.GRPC.Enabled && strings.HasPrefix(ct, "application/grpc") {
		ctx.Protocol = "grpc"
		rt := g.rt(site.ID)
		if rt.grpc != nil {
			fullMethod := ctx.Request.URL.Path
			rep := rt.grpc.Inspect(fullMethod, ctx.Body)
			if rep.Malformed {
				ctx.AddReason(decision.Reason{Module: "grpc", RuleID: "GRPC-MALFORMED", Message: "protobuf payload does not match schema", Status: http.StatusBadRequest})
				return
			}
			ctx.GRPC = &decision.GRPCInfo{ServiceName: rep.ServiceName, MethodName: rep.MethodName}
			// Field-level rule evaluation: concatenate flat field values so
			// CRS rules still match SQLi/XSS living inside protobuf strings.
			if len(rep.Flat) > 0 {
				var sb strings.Builder
				for k, v := range rep.Flat {
					sb.WriteString(k)
					sb.WriteString("=")
					sb.WriteString(v)
					sb.WriteString(";")
				}
				synth := ctx.Request.Clone(ctx.Request.Context())
				synth.Header.Set("Content-Type", "text/plain")
				if res := g.rt(site.ID).engine.Evaluate(synth, []byte(sb.String())); res.Err == nil {
					for _, m := range res.Matches {
						if m.Action == ruleengine.ActionBlock {
							ctx.AddReason(decision.Reason{Module: "grpc", RuleID: m.RuleID, Message: "grpc field matched: " + m.Message, Status: http.StatusForbidden})
						}
					}
				}
			}
		}
		return
	}
}

// looksLikeGraphQL decides whether a request is a GraphQL query.
func looksLikeGraphQL(ct, body string) bool {
	if strings.Contains(ct, "graphql") {
		return true
	}
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") {
		var env struct {
			Query string `json:"query"`
		}
		if json.Unmarshal([]byte(trimmed), &env) == nil && strings.TrimSpace(env.Query) != "" {
			return true
		}
	}
	return false
}

// inspectRateLimit applies per-IP / per-API-key / per-GraphQL-op limits.
func (g *Gateway) inspectRateLimit(ctx *decision.InspectContext) {
	site := ctx.Site
	rl := site.RateLimit
	if rl == nil {
		return
	}
	var policies []ratelimit.Policy
	if rl.PerIPRequestsPerMin > 0 {
		policies = append(policies, ratelimit.Policy{
			Scope: ratelimit.ScopeIP, Key: ctx.ClientIP,
			Limit: rl.PerIPRequestsPerMin, Window: time.Minute,
			Burst: rl.Burst, Algorithm: "sliding_window",
		})
	}
	if rl.PerAPIKeyPerMin > 0 && ctx.APIKey != "" {
		policies = append(policies, ratelimit.Policy{
			Scope: ratelimit.ScopeAPIKey, Key: ctx.APIKey,
			Limit: rl.PerAPIKeyPerMin, Window: time.Minute,
			Burst: rl.Burst, Algorithm: "sliding_window",
		})
	}
	if rl.PerGraphQLOpPerMin > 0 && ctx.Protocol == "graphql" && ctx.GraphQL != nil && ctx.GraphQL.OperationName != "" {
		policies = append(policies, ratelimit.Policy{
			Scope: ratelimit.ScopeGraphQLOp, Key: ctx.GraphQL.OperationName,
			Limit: rl.PerGraphQLOpPerMin, Window: time.Minute,
			Burst: rl.Burst, Algorithm: "sliding_window",
		})
	}
	if len(policies) == 0 {
		return
	}
	res, scope := g.limiter.Check(context.Background(), policies, time.Now())
	if !res.Allowed {
		ctx.AddReason(decision.Reason{
			Module: "ratelimit", RuleID: "RATE-" + strings.ToUpper(string(scope)),
			Message: fmt.Sprintf("rate limit exceeded (%s)", scope),
			Status:  http.StatusTooManyRequests,
		})
	}
}

// inspectBot computes the bot score and, when configured, issues challenges.
func (g *Gateway) inspectBot(ctx *decision.InspectContext) {
	bc := ctx.Site.BotScore
	if bc == nil || !bc.Enabled {
		return
	}
	// A previously-solved proof-of-work grants passage without re-scoring.
	if solvedCookie(ctx.Request) {
		return
	}
	sig := botscoringSignal(ctx)
	score := g.bots.Score(sig)
	ctx.BotScore = score
	if score >= bc.BlockThreshold {
		ctx.AddReason(decision.Reason{
			Module: "botscoring", RuleID: "BOT-BLOCK",
			Message: fmt.Sprintf("bot score %.2f exceeds block threshold", score),
			Score:   score, Status: http.StatusForbidden,
		})
		return
	}
	if bc.ChallengeEnabled && score >= bc.ChallengeThreshold {
		ctx.AddReason(decision.Reason{
			Module: "botscoring", RuleID: "BOT-CHALLENGE",
			Message: fmt.Sprintf("bot score %.2f triggers proof-of-work challenge", score),
			Score:   score, Status: http.StatusTooManyRequests,
		})
	}
}

func solvedCookie(r *http.Request) bool {
	c, err := r.Cookie("_sentinel_ok")
	return err == nil && c.Value != ""
}

func botscoringSignal(ctx *decision.InspectContext) botscoring.Signal {
	return botscoring.Signal{
		ClientIP:  ctx.ClientIP,
		JA4:       ctx.JA4,
		H2FP:      ctx.H2Fingerprint,
		UserAgent: ctx.Request.Header.Get("User-Agent"),
		Method:    ctx.Method,
		HasAccept: ctx.Request.Header.Get("Accept") != "",
		HasCookie: ctx.Request.Header.Get("Cookie") != "",
	}
}

// inspectPlugins runs WASM plugins. A host-level plugin failure follows the
// site fail mode; individual plugin verdicts are always honored.
func (g *Gateway) inspectPlugins(ctx *decision.InspectContext) {
	if g.plugins == nil {
		return
	}
	req := wasmplugins.PluginRequest{
		Method:   ctx.Method,
		Path:     ctx.Path,
		Query:    ctx.Request.URL.RawQuery,
		Host:     ctx.Host,
		ClientIP: ctx.ClientIP,
		Protocol: ctx.Protocol,
		Headers:  flattenHeaders(ctx.Request.Header),
		Body:     string(ctx.Body),
		SiteID:   ctx.Site.ID,
	}
	verdicts, err := g.plugins.Evaluate(req)
	if err != nil && ctx.Site.FailMode == config.FailClosed {
		ctx.AddReason(decision.Reason{
			Module: "wasm", RuleID: "PLUGIN-ERR",
			Message: "wasm plugin host error: " + err.Error(),
			Status:  http.StatusServiceUnavailable,
		})
	}
	for _, v := range verdicts {
		status := 0
		switch v.Action {
		case wasmplugins.ActionBlock:
			status = http.StatusForbidden
		case wasmplugins.ActionChallenge:
			status = http.StatusTooManyRequests
		case wasmplugins.ActionLog:
			status = 0 // informational; recorded but does not block
		default:
			continue // allow: nothing to report
		}
		ctx.AddReason(decision.Reason{
			Module: "wasm", RuleID: v.RuleID,
			Message: "wasm plugin: " + v.Message,
			Score:   v.Score, Status: status,
		})
	}
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

// inspectLLM flags prompt-injection patterns on operator-flagged AI routes.
func (g *Gateway) inspectLLM(ctx *decision.InspectContext) {
	if !g.llmEnabled || !ctx.Site.LLMProtectEnabled() {
		return
	}
	if !llmprotect.IsLLMRoute(ctx.Path, ctx.Site.LLMRoutes) {
		return
	}
	reasons := g.llm.Inspect(ctx.Body)
	for _, r := range reasons {
		r.Status = http.StatusForbidden
		ctx.AddReason(r)
	}
}

// inspectML calls the optional ML scoring service. On service error the site
// fail mode decides; the score is added to the event either way.
func (g *Gateway) inspectML(ctx *decision.InspectContext) {
	if !g.mlEnabled {
		return
	}
	features := mlclient.Features{
		SiteID:      ctx.Site.ID,
		Method:      ctx.Method,
		Path:        ctx.Path,
		Protocol:    ctx.Protocol,
		ClientIP:    ctx.ClientIP,
		ContentType: ctx.Request.Header.Get("Content-Type"),
		BodyLen:     len(ctx.Body),
		HeaderCount: len(ctx.Request.Header),
		HasAuth:     ctx.APIKey != "" || ctx.Request.Header.Get("Authorization") != "",
		IsGraphQL:   ctx.Protocol == "graphql",
		HasCookie:   ctx.Request.Header.Get("Cookie") != "",
		HasAPIKey:   ctx.APIKey != "",
		BotScore:    ctx.BotScore,
		JA4:         ctx.JA4,
	}
	if ctx.GraphQL != nil {
		features.GraphQLDepth = ctx.GraphQL.Depth
		features.GraphQLCost = ctx.GraphQL.Complexity
	}
	ctx2, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	res, err := g.ml.Score(ctx2, features)
	if err != nil {
		if ctx.Site.FailMode == config.FailClosed {
			ctx.AddReason(decision.Reason{
				Module: "ml", RuleID: "ML-ERR", Message: "ML service unavailable (fail-closed)",
				Status: http.StatusServiceUnavailable,
			})
		}
		return
	}
	ctx.MLScore = res.Score
	if res.Anomaly || res.Score >= g.mlThreshold {
		ctx.AddReason(decision.Reason{
			Module: "ml", RuleID: "ML-SCORE", Message: "anomaly detected by ML model",
			Score: res.Score, Status: http.StatusForbidden,
		})
	}
}

// summarize folds reasons into a single verdict. Block wins over challenge
// wins over log/allow. Status is the most severe blocking status.
func summarize(reasons []decision.Reason, site *config.Site) decision.Verdict {
	v := decision.Verdict{Decision: decision.Allow, StatusCode: http.StatusOK}
	blockStatus := 0
	hasChallenge := false
	for _, r := range reasons {
		isChallenge := r.Module == "botscoring" && r.RuleID == "BOT-CHALLENGE"
		if isChallenge {
			hasChallenge = true
			continue
		}
		if r.Status >= 400 && r.Status > blockStatus {
			blockStatus = r.Status
		}
	}
	if blockStatus >= 400 {
		v.Decision = decision.Block
		v.StatusCode = blockStatus
		v.Reasons = reasons
		return v
	}
	if hasChallenge {
		v.Decision = decision.Challenge
		v.StatusCode = http.StatusTooManyRequests
		v.Reasons = reasons
		return v
	}
	if len(reasons) > 0 {
		v.Decision = decision.Log
	}
	v.Reasons = reasons
	return v
}

// severityScore maps CRS severity to a 0..1 confidence.
func severityScore(sev string) float64 {
	switch strings.ToLower(sev) {
	case "critical":
		return 1.0
	case "error":
		return 0.8
	case "warning":
		return 0.6
	case "notice":
		return 0.4
	}
	return 0.3
}

var _ = strconv.Itoa
var _ = fingerprint.JA4
