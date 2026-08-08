// Package mgmtapi implements the SwipeShield Management API: a JWT-protected
// REST surface for managing sites, custom rules, and the fingerprint
// blocklist, plus live metrics and an SSE event stream. All mutations are
// validated against the config schema and hot-applied through the gateway so
// a bad change is rejected without ever taking the proxy down.
//
// Endpoints (all under /api/v1):
//
//	POST   /auth/login                  -> {"token": "..."}
//	GET    /sites                       -> site list
//	POST   /sites                       -> create site
//	GET    /sites/{id}                  -> site detail
//	PUT    /sites/{id}                  -> update site
//	DELETE /sites/{id}                  -> remove site
//	GET    /sites/{id}/rules            -> custom rules
//	POST   /sites/{id}/rules            -> add custom rule(s) (YAML body)
//	DELETE /sites/{id}/rules/{rule_id}  -> remove custom rule
//	GET    /fingerprint/blocklist       -> blocked JA4 list
//	POST   /fingerprint/blocklist       -> block a JA4
//	DELETE /fingerprint/blocklist/{ja4} -> unblock a JA4
//	GET    /metrics                     -> traffic snapshot
//	GET    /events?token=...            -> SSE stream of audit events
package mgmtapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/eventpipeline"
	"github.com/binaryguardia/swipeshield/internal/store"
	"github.com/binaryguardia/swipeshield/internal/telemetry"
)

// Backend is the gateway surface the API drives. Implemented by proxy.Gateway.
type Backend interface {
	Config() *config.Config
	Apply(cfg *config.Config) error
	Stats() telemetry.Stats
	SubscribeEvents() (<-chan eventpipeline.Event, func())
}

// Options configures the management server.
type Options struct {
	Backend Backend
	// RulesDir is where managed custom-rule YAML files are persisted.
	RulesDir string
	// Auth.
	JWTSecret         string
	AdminUser         string
	AdminPasswordHash string // argon2id hash, or plaintext (dev only)
	// RateLimitPerMin caps API requests per client IP.
	RateLimitPerMin int
	// Store backs the agent registry and streamed events. When nil, the agent
	// endpoints return 503.
	Store *store.Store
	// AgentPort is the manager's agent gRPC port, used to render the enroll
	// command shown to the operator (host is taken from the dashboard URL).
	AgentPort string
}

// Server is the Management API.
type Server struct {
	opts Options
	log  *slog.Logger

	mu      sync.Mutex
	ratings map[string]*window // per-IP request windows
}

type window struct {
	start time.Time
	count int
}

// New builds a Management API server.
func New(opts Options) *Server {
	if opts.RulesDir == "" {
		opts.RulesDir = "rules/custom"
	}
	if opts.RateLimitPerMin <= 0 {
		opts.RateLimitPerMin = 120
	}
	return &Server{opts: opts, log: slog.Default(), ratings: map[string]*window{}}
}

// Handler returns the routed /api/v1 handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/v1/sites", s.auth(s.handleListSites))
	mux.HandleFunc("POST /api/v1/sites", s.auth(s.handleCreateSite))
	mux.HandleFunc("GET /api/v1/sites/{id}", s.auth(s.handleGetSite))
	mux.HandleFunc("PUT /api/v1/sites/{id}", s.auth(s.handleUpdateSite))
	mux.HandleFunc("DELETE /api/v1/sites/{id}", s.auth(s.handleDeleteSite))
	mux.HandleFunc("GET /api/v1/sites/{id}/rules", s.auth(s.handleListRules))
	mux.HandleFunc("POST /api/v1/sites/{id}/rules", s.auth(s.handleCreateRules))
	mux.HandleFunc("DELETE /api/v1/sites/{id}/rules/{rule_id}", s.auth(s.handleDeleteRule))
	mux.HandleFunc("GET /api/v1/fingerprint/blocklist", s.auth(s.handleListBlocklist))
	mux.HandleFunc("POST /api/v1/fingerprint/blocklist", s.auth(s.handleAddBlocklist))
	mux.HandleFunc("DELETE /api/v1/fingerprint/blocklist/{ja4}", s.auth(s.handleDeleteBlocklist))
	mux.HandleFunc("GET /api/v1/metrics", s.auth(s.handleMetrics))
	mux.HandleFunc("GET /api/v1/events", s.handleEvents)
	mux.HandleFunc("GET /api/v1/agents", s.auth(s.handleListAgents))
	mux.HandleFunc("POST /api/v1/agents", s.auth(s.handleCreateAgent))
	mux.HandleFunc("DELETE /api/v1/agents/{id}", s.auth(s.handleDeleteAgent))
	mux.HandleFunc("GET /api/v1/agents/{id}/events", s.auth(s.handleAgentEvents))
	return s.limit(mux)
}

// rateLimit enforces a per-IP window on all API calls.
func (s *Server) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		now := time.Now()
		s.mu.Lock()
		wd, ok := s.ratings[ip]
		if !ok || now.Sub(wd.start) > time.Minute {
			wd = &window{start: now}
			s.ratings[ip] = wd
		}
		wd.count++
		over := wd.count > s.opts.RateLimitPerMin
		s.mu.Unlock()
		if over {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "api rate limit exceeded"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// auth verifies the JWT from the Authorization header or ?token= query param.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		token = strings.TrimPrefix(token, "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing token"})
			return
		}
		if _, err := verifyJWT(s.opts.JWTSecret, token); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
			return
		}
		next(w, r)
	}
}

// handleLogin exchanges admin credentials for a JWT.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return
	}
	if req.Username != s.opts.AdminUser {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	if !verifyPassword(req.Password, s.opts.AdminPasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
		return
	}
	token, err := issueJWT(s.opts.JWTSecret, req.Username, 8*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "token issue failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

func (s *Server) handleListSites(w http.ResponseWriter, r *http.Request) {
	cfg := s.opts.Backend.Config()
	out := make([]siteDTO, 0, len(cfg.Sites))
	for i := range cfg.Sites {
		out = append(out, toSiteDTO(&cfg.Sites[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetSite(w http.ResponseWriter, r *http.Request) {
	cfg := s.opts.Backend.Config()
	st := cfg.SiteByID(r.PathValue("id"))
	if st == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "site not found"})
		return
	}
	writeJSON(w, http.StatusOK, toSiteDTO(st))
}

func (s *Server) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	var in siteInput
	if err := readJSON(w, r, &in); err != nil {
		return
	}
	cfg := s.opts.Backend.Config()
	st := config.Site{
		ID:         "site-" + randID(6),
		Name:       in.Name,
		Domains:    normalizeDomains(in.Host),
		Backend:    normalizeBackend(in.Upstream),
		PathPrefix: in.PathPrefix,
		Status:     "enabled",
		CRS:        &config.CRSConfig{Enabled: true, SQLi: true, XSS: true, RCE: true, PathTraversal: true, LFI: true, Protocol: true},
	}
	cfg.Sites = append(cfg.Sites, st)
	if err := s.apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, toSiteDTO(s.opts.Backend.Config().SiteByID(st.ID)))
}

func (s *Server) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	var in siteInput
	if err := readJSON(w, r, &in); err != nil {
		return
	}
	cfg := s.opts.Backend.Config()
	st := cfg.SiteByID(r.PathValue("id"))
	if st == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "site not found"})
		return
	}
	if in.Name != "" {
		st.Name = in.Name
	}
	if in.Host != "" {
		st.Domains = normalizeDomains(in.Host)
	}
	if in.Upstream != "" {
		st.Backend = normalizeBackend(in.Upstream)
	}
	if in.PathPrefix != "" {
		st.PathPrefix = in.PathPrefix
	}
	if in.Status != "" {
		st.Status = in.Status
	}
	if err := s.apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, toSiteDTO(s.opts.Backend.Config().SiteByID(st.ID)))
}

func (s *Server) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	cfg := s.opts.Backend.Config()
	id := r.PathValue("id")
	st := cfg.SiteByID(id)
	if st == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "site not found"})
		return
	}
	kept := cfg.Sites[:0]
	for i := range cfg.Sites {
		if cfg.Sites[i].ID != id {
			kept = append(kept, cfg.Sites[i])
		}
	}
	cfg.Sites = kept
	if err := s.apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apply validates and hot-applies a mutated config.
func (s *Server) apply(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config rejected: %w", err)
	}
	return s.opts.Backend.Apply(cfg)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid body"})
		return err
	}
	return nil
}

func normalizeBackend(b string) string {
	if b == "" {
		return ""
	}
	if !strings.Contains(b, "://") {
		return "http://" + b
	}
	return b
}

func normalizeDomains(host string) []string {
	var out []string
	for _, h := range strings.Split(host, ",") {
		h = strings.TrimSpace(h)
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			xff = xff[:i]
		}
		return strings.TrimSpace(xff)
	}
	if h, _, err := splitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func splitHostPort(a string) (string, string, error) {
	i := strings.LastIndexByte(a, ':')
	if i < 0 {
		return "", "", errors.New("no port")
	}
	return a[:i], a[i+1:], nil
}
