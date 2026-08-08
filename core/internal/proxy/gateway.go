// Package proxy implements the SwipeShield reverse-proxy gateway. It
// terminates TLS (capturing JA3/JA4 from the ClientHello), routes by Host to
// the matching site, buffers bounded bodies, runs the full inspection chain
// (rule engine, protocol parsers, rate limits, bot scoring + proof-of-work
// challenges, WASM plugins, LLM protection, ML scoring), emits an audit event
// per request, and proxies approved traffic to the upstream. Every stage is
// fail-open/fail-closed per site config, and nothing here can panic the
// process or block indefinitely.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/binaryguardia/swipeshield/internal/botscoring"
	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/decision"
	"github.com/binaryguardia/swipeshield/internal/eventpipeline"
	"github.com/binaryguardia/swipeshield/internal/fingerprint"
	"github.com/binaryguardia/swipeshield/internal/llmprotect"
	"github.com/binaryguardia/swipeshield/internal/mlclient"
	"github.com/binaryguardia/swipeshield/internal/parsers/grpcproto"
	"github.com/binaryguardia/swipeshield/internal/parsers/websocket"
	"github.com/binaryguardia/swipeshield/internal/ratelimit"
	"github.com/binaryguardia/swipeshield/internal/ruleengine"
	"github.com/binaryguardia/swipeshield/internal/telemetry"
	"github.com/binaryguardia/swipeshield/internal/wasmplugins"
)

// Gateway is a running instance of the WAF proxy.
type Gateway struct {
	store   *config.Store
	events  *eventpipeline.Pipeline
	limiter *ratelimit.Limiter
	bots    *botscoring.Scorer
	chall   *botscoring.Store
	plugins *wasmplugins.Manager
	llm     *llmprotect.Detector
	ml      *mlclient.Client

	mlEnabled   bool
	mlThreshold float64

	stats telemetry.Collector
	feed  *eventpipeline.LiveFeed

	mu      sync.RWMutex
	sites   map[string]*siteRT
	fpBlock map[string]bool // blocked JA4 fingerprints

	// testPanicHook is a fault-injection seam used only by tests to prove
	// ServeHTTP recovers from panics in the inspection path.
	testPanicHook func()
}

// Options carries optional shared runtime pieces for New.
type Options struct {
	Events   *eventpipeline.Pipeline
	Limiter  *ratelimit.Limiter
	Plugins  *wasmplugins.Manager
	ML       *mlclient.Client
	BotStore *botscoring.Store
}

// New builds a Gateway from a config, wiring shared engines and per-site
// rule engines. A missing pipeline/limiter is created lazily with safe
// defaults so a minimal config always serves.
// defaultMaxBodyBytes returns a sensible body ceiling for the LLM detector
// when the config declares no sites (manager-only deployments).
func defaultMaxBodyBytes(cfg *config.Config) int {
	if len(cfg.Sites) > 0 {
		return int(cfg.Sites[0].MaxBodyBytes)
	}
	return 4 << 20
}

func New(cfg *config.Config, opts Options) (*Gateway, error) {
	if opts.Limiter == nil {
		switch cfg.RateLimit.Backend {
		case "redis":
			rb, err := ratelimit.NewRedisBackend(cfg.RateLimit.RedisAddress, cfg.RateLimit.RedisPassword, cfg.RateLimit.RedisDB)
			if err != nil {
				log.Warn().Err(err).Msg("redis rate-limit backend unavailable; falling back to memory")
				opts.Limiter = ratelimit.NewLimiter(ratelimit.NewMemoryBackend())
			} else {
				opts.Limiter = ratelimit.NewLimiter(rb)
			}
		default:
			opts.Limiter = ratelimit.NewLimiter(ratelimit.NewMemoryBackend())
		}
	}
	if opts.BotStore == nil {
		opts.BotStore = botscoring.NewStore(10 * time.Minute)
	}
	g := &Gateway{
		store:   config.NewStore(""),
		events:  opts.Events,
		limiter: opts.Limiter,
		bots:    botscoring.NewScorer(),
		chall:   opts.BotStore,
		plugins: opts.Plugins,
		llm:     llmprotect.NewDetector(cfg.LLMProtect.FailMode, defaultMaxBodyBytes(cfg)),
		ml:      opts.ML,
		sites:   map[string]*siteRT{},
		fpBlock: map[string]bool{},
		feed:    eventpipeline.NewLiveFeed(512),
	}
	if g.ml == nil {
		g.ml = mlclient.New(cfg.ML)
	}
	g.mlEnabled = cfg.ML.Enabled
	g.mlThreshold = cfg.ML.Threshold
	if err := g.reload(cfg); err != nil {
		return nil, err
	}
	if g.events == nil {
		g.events = eventpipeline.New(eventpipeline.Options{
			RedactFields: cfg.Events.RedactFields,
			BodyTruncate: cfg.Events.BodyTruncate,
			Schema:       cfg.Events.WebhookSchema,
		}, eventpipeline.NewFileSinkSafe(cfg.Events.LogPath, 100<<20), g.feed)
	} else {
		g.events.AddSink(g.feed)
	}
	g.store.Set(cfg)
	return g, nil
}

// Store returns the config store (Management API / reload integration).
func (g *Gateway) Store() *config.Store { return g.store }

// Config returns the current config snapshot (Management API backend).
func (g *Gateway) Config() *config.Config { return g.store.Get() }

// Apply hot-applies a config (Management API backend).
func (g *Gateway) Apply(cfg *config.Config) error { return g.Reload(cfg) }

// Events returns the audit pipeline (used for tests and telemetry).
func (g *Gateway) Events() *eventpipeline.Pipeline { return g.events }

// Reload rebuilds per-site runtimes from a fresh config snapshot.
func (g *Gateway) Reload(cfg *config.Config) error {
	if err := g.reload(cfg); err != nil {
		return err
	}
	g.store.Set(cfg)
	return nil
}

func (g *Gateway) reload(cfg *config.Config) error {
	block, err := loadFingerprintBlocklist(cfg.Fingerprint.Blocklist, cfg.Fingerprint.BlocklistFile)
	if err != nil {
		return fmt.Errorf("proxy: fingerprint blocklist: %w", err)
	}
	sites := make(map[string]*siteRT, len(cfg.Sites))
	for i := range cfg.Sites {
		s := &cfg.Sites[i]
		rt, err := g.buildSiteRT(s)
		if err != nil {
			return fmt.Errorf("proxy: site %s: %w", s.ID, err)
		}
		sites[s.ID] = rt
	}
	g.mu.Lock()
	g.sites = sites
	g.fpBlock = block
	g.mu.Unlock()
	return nil
}

func (g *Gateway) buildSiteRT(s *config.Site) (*siteRT, error) {
	rt := &siteRT{cfg: s}

	// Rule engine per site: CRS toggles + custom YAML rules.
	engine := ruleengine.New()
	engine.SetFailMode(string(s.FailMode))
	toggles := ruleengine.CRSToggles{}
	if s.CRS != nil && s.CRS.Enabled {
		toggles.SQLi = s.CRS.SQLi
		toggles.XSS = s.CRS.XSS
		toggles.RCE = s.CRS.RCE
		toggles.PathTraversal = s.CRS.PathTraversal
		toggles.LFI = s.CRS.LFI
		toggles.Protocol = s.CRS.Protocol
	}
	if err := engine.SetCRSToggles(toggles); err != nil {
		return nil, err
	}
	if len(s.CustomRules) > 0 {
		var rules []*ruleengine.Rule
		for _, p := range s.CustomRules {
			r, err := ruleengine.LoadRules(p)
			if err != nil {
				return nil, err
			}
			rules = append(rules, r...)
		}
		if err := engine.SetCustomRules(rules); err != nil {
			return nil, err
		}
	}
	rt.engine = engine

	// gRPC registry for schema-aware inspection.
	if s.GRPC != nil && s.GRPC.Enabled && s.GRPC.SchemaDir != "" {
		reg, err := grpcproto.NewRegistry(context.Background(), []string{s.GRPC.SchemaDir}, s.GRPC.ImportDirs)
		if err != nil {
			return nil, err
		}
		rt.grpc = reg
	}

	// Reverse proxy to the upstream.
	target, err := url.Parse(s.Backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend %q: %w", s.Backend, err)
	}
	rt.proxy = buildReverseProxy(target, s, g)

	// WebSocket per-message inspector.
	if s.WebSocket != nil && s.WebSocket.Enabled {
		rt.ws = websocket.NewInspector(engine, g.limiter, s.WebSocket)
	}

	return rt, nil
}

// siteRT is the per-site runtime state.
type siteRT struct {
	cfg    *config.Site
	engine *ruleengine.Engine
	proxy  *httputilReverseProxy
	grpc   *grpcproto.Registry
	ws     *websocket.Inspector
}

// Close shuts down shared runtimes (plugins, events).
func (g *Gateway) Close() error {
	if g.plugins != nil {
		_ = g.plugins.Close()
	}
	g.events.Close()
	return nil
}

// ServeHTTP is the entry point for every request.
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Per-request panic recovery: a defect in any inspection module must
	// never take down the proxy. The request is failed closed with a 500
	// and the panic is logged for triage.
	defer func() {
		if rec := recover(); rec != nil {
			log.Error().Interface("panic", rec).Str("host", r.Host).
				Str("path", r.URL.Path).Msg("gateway recovered from panic")
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()

	start := time.Now()

	if g.testPanicHook != nil {
		g.testPanicHook()
	}

	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}
	cfg := g.store.Get()
	site := cfg.SiteByDomain(host)
	if site == nil {
		http.Error(w, "no site configured for host", http.StatusBadRequest)
		return
	}

	ctx := &decision.InspectContext{
		Request:  r,
		Site:     site,
		ClientIP: clientIP(r),
		Host:     host,
		Path:     r.URL.Path,
		Method:   r.Method,
		Protocol: "rest",
		ZeroRTT:  zeroRTT(r.Context()),
	}
	switch r.ProtoMajor {
	case 3:
		ctx.Transport = "h3"
	case 2:
		ctx.Transport = "h2"
	default:
		ctx.Transport = "h1"
	}
	ctx.APIKey = apiKey(r)

	// TLS fingerprint from the connection (JA3/JA4), H2 heuristic.
	if h, ok := r.Context().Value(fpCtxKey{}).(*fingerprint.ClientHello); ok && h != nil {
		ctx.JA4 = fingerprint.JA4(h)
		ctx.JA3 = fingerprint.JA3(h)
	}
	if ctx.JA4 != "" {
		alpn := "http/1.1"
		if r.ProtoMajor == 2 {
			alpn = "h2"
		}
		ctx.H2Fingerprint = fingerprint.ComputeH2(r, alpn)
	}

	// Fingerprint blocklist: drop known-bad JA4 hashes outright, before any
	// protocol upgrade or body inspection.
	if ctx.JA4 != "" && g.fpBlocked(ctx.JA4) {
		g.deny(ctx, w, r, start, decision.Block, http.StatusForbidden, decision.Reason{
			Module: "fingerprint", RuleID: "FP-BLOCKLIST",
			Message: "client TLS fingerprint is blocked",
		})
		return
	}

	// Protocol upgrade (WebSocket) — handled as a persistent connection.
	if site.WebSocket != nil && site.WebSocket.Enabled && websocket.IsUpgrade(r) {
		ctx.Protocol = "websocket"
		g.handleWebSocket(ctx, w, r)
		g.emit(ctx, start, 101, decision.Allow, false)
		return
	}

	// Buffer a bounded body for inspection.
	body, overflow, err := readBody(r, site.MaxBodyBytes)
	if err != nil {
		g.deny(ctx, w, r, start, decision.Block, 400, decision.Reason{
			Module: "proxy", RuleID: "PROXY-READ", Message: "failed reading request body",
		})
		return
	}
	if overflow {
		g.deny(ctx, w, r, start, decision.Block, http.StatusRequestEntityTooLarge, decision.Reason{
			Module: "proxy", RuleID: "PROXY-SIZE", Message: "request body exceeds max_body_bytes",
		})
		return
	}
	ctx.Body = body

	// Full inspection chain.
	ctx, verdict, err := g.inspect(ctx)
	if err != nil {
		// Inspection itself failed — apply the site fail mode.
		msg := fmt.Sprintf("inspection failed: %v", err)
		if site.FailMode == config.FailClosed {
			g.deny(ctx, w, r, start, decision.Block, http.StatusServiceUnavailable, decision.Reason{
				Module: "engine", RuleID: "ENGINE-ERR", Message: msg,
			})
		} else {
			g.deny(ctx, w, r, start, decision.Log, http.StatusOK, decision.Reason{
				Module: "engine", RuleID: "ENGINE-ERR", Message: msg,
			})
			g.serve(ctx, w, r, start, decision.Allow)
		}
		return
	}

	switch verdict.Decision {
	case decision.Block:
		g.deny(ctx, w, r, start, decision.Block, verdict.StatusCode, ctx.Reasons...)
		return
	case decision.Challenge:
		g.handleChallenge(ctx, w, r, start)
		return
	case decision.Log:
		g.emit(ctx, start, http.StatusOK, decision.Log, false)
	}

	// Approved: restore the body for proxying and forward.
	g.serve(ctx, w, r, start, decision.Allow)
}

// serve proxies an approved request to the upstream.
func (g *Gateway) serve(ctx *decision.InspectContext, w http.ResponseWriter, r *http.Request, start time.Time, action decision.Action) {
	rt := g.rt(ctx.Site.ID)
	if rt == nil {
		g.deny(ctx, w, r, start, decision.Block, http.StatusServiceUnavailable, decision.Reason{
			Module: "proxy", RuleID: "PROXY-NOSITE", Message: "site runtime unavailable",
		})
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(ctx.Body))
	r.ContentLength = int64(len(ctx.Body))
	if r.ContentLength == 0 {
		r.ContentLength = -1
	}
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	rt.proxy.ServeHTTP(rec, r)
	ctx.Status = rec.status
	g.emit(ctx, start, rec.status, action, false)
}

// rt returns the site runtime for an id, or nil.
func (g *Gateway) rt(id string) *siteRT {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.sites[id]
}

func (g *Gateway) deny(ctx *decision.InspectContext, w http.ResponseWriter, r *http.Request, start time.Time, action decision.Action, status int, reasons ...decision.Reason) {
	if status == 0 {
		status = http.StatusForbidden
	}
	ctx.Reasons = append(ctx.Reasons, reasons...)
	ctx.Status = status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := fmt.Sprintf(`{"error":"request blocked by WAF","status":%d}`, status)
	_, _ = io.WriteString(w, body)
	g.emit(ctx, start, status, action, true)
}

// handleChallenge serves the proof-of-work challenge page (or validates an
// already-solved challenge and forwards the original request).
func (g *Gateway) handleChallenge(ctx *decision.InspectContext, w http.ResponseWriter, r *http.Request, start time.Time) {
	site := ctx.Site
	bc := site.BotScore

	// Solved challenge via POST _pow form -> verify, then continue.
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		proof := r.Form.Get("_pow")
		id := r.Header.Get("Cookie")
		id = strings.TrimPrefix(id, "_sentinel_pow=")
		if proof != "" && id != "" && g.chall.Redeem(id, proof) {
			http.SetCookie(w, &http.Cookie{Name: "_sentinel_ok", Value: "1", Path: "/", MaxAge: int((time.Hour).Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, ctx.Path, http.StatusSeeOther)
			g.emit(ctx, start, http.StatusSeeOther, decision.Challenge, false)
			return
		}
	}

	c, err := g.chall.Issue(bc.PowDifficulty)
	if err != nil {
		g.deny(ctx, w, r, start, decision.Block, http.StatusTooManyRequests, decision.Reason{
			Module: "botscoring", RuleID: "BOT-CHALLENGE-ERR", Message: "could not issue challenge",
		})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "_sentinel_pow", Value: c.ID, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = io.WriteString(w, c.HTML(ctx.Path))
	g.emit(ctx, start, http.StatusTooManyRequests, decision.Challenge, true)
}

// handleWebSocket performs an inspected WebSocket relay to the backend.
func (g *Gateway) handleWebSocket(ctx *decision.InspectContext, w http.ResponseWriter, r *http.Request) {
	rt := g.rt(ctx.Site.ID)
	if rt == nil || rt.ws == nil {
		http.Error(w, "websocket inspection unavailable", http.StatusServiceUnavailable)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	backend, err := net.DialTimeout("tcp", upstreamHost(rt.cfg.Backend), 5*time.Second)
	if err != nil {
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer backend.Close()

	// Forward the upgrade request verbatim to the backend.
	reqBytes := formatUpgradeRequest(r, rt.cfg)
	if _, err := backend.Write(reqBytes); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(backend), r)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		return
	}
	if _, err := clientConn.Write(formatUpgradeRequestResponse(resp)); err != nil {
		return
	}

	// Relay frames with per-message inspection (client->server direction).
	relayCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opt := websocket.RelayOption{OnViolation: func(reasons []decision.Reason) {
		g.emitWebsocketViolation(ctx, reasons)
	}}
	if err := websocket.Relay(relayCtx, clientConn, backend, rt.ws, ctx.ClientIP, ctx.APIKey, opt); err != nil {
		log.Debug().Err(err).Str("site", ctx.Site.ID).Msg("websocket relay ended")
	}
}

// emitWebsocketViolation logs a dropped WS message as a challenge event.
func (g *Gateway) emitWebsocketViolation(ctx *decision.InspectContext, reasons []decision.Reason) {
	g.emit(ctx, time.Now(), 1008, decision.Block, true)
	_ = reasons
}

func (g *Gateway) rtErr() error { return errors.New("site runtime not found") }

// readBody reads up to max bytes; returns overflow=true when the body was
// larger than max (the request is rejected by the caller).
func readBody(r *http.Request, max int64) ([]byte, bool, error) {
	if r.Body == nil {
		return nil, false, nil
	}
	defer r.Body.Close()
	if max <= 0 {
		max = 4 << 20
	}
	lr := &io.LimitedReader{R: r.Body, N: max + 1}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, false, err
	}
	if int64(len(b)) > max {
		return b, true, nil
	}
	return b, false, nil
}

// clientIP extracts the real client IP, honoring X-Forwarded-For when
// present (set by trusted LBs); otherwise the socket address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			xff = xff[:i]
		}
		if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// apiKey extracts an API key from common header conventions.
func apiKey(r *http.Request) string {
	for _, h := range []string{"X-Api-Key", "X-Api-Key-Id", "X-APIKEY"} {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// upstreamHost returns host:port of a backend URL for dialing.
func upstreamHost(backend string) string {
	u, err := url.Parse(backend)
	if err != nil {
		return strings.TrimPrefix(backend, "http://")
	}
	h := u.Host
	if u.Scheme == "http" && !strings.Contains(h, ":") {
		h += ":80"
	}
	if u.Scheme == "https" && !strings.Contains(h, ":") {
		h += ":443"
	}
	return h
}

// formatUpgradeRequest rebuilds the raw upgrade request for the backend.
func formatUpgradeRequest(r *http.Request, s *config.Site) []byte {
	var b strings.Builder
	target := r.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, target)
	host := r.Host
	if !s.PreserveHost {
		if u, err := url.Parse(s.Backend); err == nil && u.Host != "" {
			host = u.Host
		}
	}
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	for k, vs := range r.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// formatUpgradeRequestResponse flattens a 101 response to raw bytes.
func formatUpgradeRequestResponse(resp *http.Response) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

// fpCtxKey is the context key for per-connection TLS fingerprint data.
type fpCtxKey struct{}

// httputilReverseProxy aliases the stdlib reverse proxy used for upstreams.
type httputilReverseProxy = httputil.ReverseProxy

// statusRecorder captures the status code written to the client so audit
// events carry the final HTTP status.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Flush implements http.Flusher when the underlying writer supports it.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
