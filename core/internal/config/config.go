// Package config defines the SentinelWAF configuration model and loader.
//
// Configuration is loaded from a JSON or YAML file, overlaid with environment
// variables, validated, and made available for atomic hot-reload. A malformed
// config is always rejected loudly and never silently drops protection —
// the previous known-good config keeps serving.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// FailMode controls behavior when a module errors at runtime.
type FailMode string

// Duration is a time.Duration that unmarshals from both a string ("100ms")
// and a raw integer (nanoseconds) in JSON and YAML, and always serializes
// back as a string.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		*d = Duration(time.Duration(n))
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	if n, err := strconv.ParseInt(value.Value, 10, 64); err == nil {
		*d = Duration(time.Duration(n))
		return nil
	}
	v, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

const (
	// FailClosed blocks the request when a module errors.
	FailClosed FailMode = "closed"
	// FailOpen allows the request when a module errors.
	FailOpen FailMode = "open"
)

// Action is a rule/decision action.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionLog       Action = "log"
)

// Config is the top-level SentinelWAF configuration.
type Config struct {
	Version     int               `json:"version" yaml:"version"`
	Listeners   []Listener        `json:"listeners" yaml:"listeners"` // front-end listeners
	Sites       []Site            `json:"sites" yaml:"sites"`
	Admin       AdminConfig       `json:"admin" yaml:"admin"` // management UI + API
	Agent       AgentConfig       `json:"agent" yaml:"agent"` // agent enrollment/streaming
	DB          DBConfig          `json:"db" yaml:"db"`       // persistent store
	Auth        AuthConfig        `json:"auth" yaml:"auth"`
	RateLimit   RateLimitConfig   `json:"rate_limit" yaml:"rate_limit"`
	Events      EventConfig       `json:"events" yaml:"events"`
	Plugins     PluginConfig      `json:"plugins" yaml:"plugins"`
	Fingerprint FingerprintConfig `json:"fingerprint" yaml:"fingerprint"`
	ML          MLConfig          `json:"ml" yaml:"ml"`
	LLMProtect  LLMProtectConfig  `json:"llm_protection" yaml:"llm_protection"`
	EBPF        EBPFConfig        `json:"ebpf" yaml:"ebpf"`
	Envoy       EnvoyConfig       `json:"envoy" yaml:"envoy"`
}

// Listener configures a front-end listener.
type Listener struct {
	Address  string `json:"address" yaml:"address"`
	TLS      bool   `json:"tls" yaml:"tls"`
	CertPath string `json:"cert_path" yaml:"cert_path"`
	KeyPath  string `json:"key_path" yaml:"key_path"`
	ClientCA string `json:"client_ca" yaml:"client_ca"` // mTLS: require client cert signed by this CA
	HTTP3    bool   `json:"http3" yaml:"http3"`
	// Allow0RTT enables QUIC 0-RTT early data. 0-RTT requests have no replay
	// protection: a captured early request can be re-sent verbatim. Default
	// off; when enabled, requests are flagged zero_rtt in events so rules can
	// treat replayed-capable traffic specially.
	Allow0RTT bool `json:"allow_0rtt" yaml:"allow_0rtt"`
}

// Site is one protected upstream application.
type Site struct {
	ID           string   `json:"id" yaml:"id"`
	Name         string   `json:"name" yaml:"name"`
	Domains      []string `json:"domains" yaml:"domains"`
	Backend      string   `json:"backend" yaml:"backend"` // e.g. http://127.0.0.1:9000
	PreserveHost bool     `json:"preserve_host" yaml:"preserve_host"`
	MaxBodyBytes int64    `json:"max_body_bytes" yaml:"max_body_bytes"`
	FailMode     FailMode `json:"fail_mode" yaml:"fail_mode"`     // module default override
	Status       string   `json:"status" yaml:"status"`           // "enabled" | "disabled"; empty = enabled
	PathPrefix   string   `json:"path_prefix" yaml:"path_prefix"` // optional path prefix stripped before proxying

	CRS         *CRSConfig       `json:"crs,omitempty" yaml:"crs,omitempty"`
	CustomRules []string         `json:"custom_rules" yaml:"custom_rules"` // paths to YAML rule files
	GraphQL     *GraphQLConfig   `json:"graphql,omitempty" yaml:"graphql,omitempty"`
	GRPC        *GRPCConfig      `json:"grpc,omitempty" yaml:"grpc,omitempty"`
	WebSocket   *WebSocketConfig `json:"websocket,omitempty" yaml:"websocket,omitempty"`
	SSE         *SSEConfig       `json:"sse,omitempty" yaml:"sse,omitempty"`
	RateLimit   *SiteRateLimit   `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`
	BotScore    *BotScoreConfig  `json:"bot_score,omitempty" yaml:"bot_score,omitempty"`
	LLMRoutes   []string         `json:"llm_routes" yaml:"llm_routes"` // paths flagged as AI backends
}

// LLMProtectEnabled reports whether LLM protection applies to this site.
func (s *Site) LLMProtectEnabled() bool { return len(s.LLMRoutes) > 0 }

// CRSConfig toggles OWASP CRS rule classes on a site.
type CRSConfig struct {
	Enabled       bool `json:"enabled" yaml:"enabled"`
	SQLi          bool `json:"sqli" yaml:"sqli"`
	XSS           bool `json:"xss" yaml:"xss"`
	RCE           bool `json:"rce" yaml:"rce"`
	PathTraversal bool `json:"path_traversal" yaml:"path_traversal"`
	LFI           bool `json:"lfi" yaml:"lfi"`
	Protocol      bool `json:"protocol" yaml:"protocol"` // malformed requests / protocol violations
}

// GraphQLConfig enables GraphQL-aware inspection.
type GraphQLConfig struct {
	Enabled            bool `json:"enabled" yaml:"enabled"`
	MaxDepth           int  `json:"max_depth" yaml:"max_depth"`
	MaxComplexity      int  `json:"max_complexity" yaml:"max_complexity"`
	BlockIntrospection bool `json:"block_introspection" yaml:"block_introspection"`
	BlockBatching      bool `json:"block_batching" yaml:"block_batching"`
	MaxAliases         int  `json:"max_aliases" yaml:"max_aliases"`
}

// GRPCConfig enables schema-aware protobuf field-level inspection.
type GRPCConfig struct {
	Enabled    bool     `json:"enabled" yaml:"enabled"`
	SchemaDir  string   `json:"schema_dir" yaml:"schema_dir"` // .proto files
	ImportDirs []string `json:"import_dirs" yaml:"import_dirs"`
}

// WebSocketConfig enables per-message inspection of persistent connections.
type WebSocketConfig struct {
	Enabled           bool `json:"enabled" yaml:"enabled"`
	MaxMessagesPerMin int  `json:"max_messages_per_min" yaml:"max_messages_per_min"`
	MaxMessageBytes   int  `json:"max_message_bytes" yaml:"max_message_bytes"`
}

// SSEConfig enables response-stream inspection.
type SSEConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// SiteRateLimit configures rate limits scoped to a site.
type SiteRateLimit struct {
	PerIPRequestsPerMin int `json:"per_ip_requests_per_min" yaml:"per_ip_requests_per_min"`
	PerAPIKeyPerMin     int `json:"per_api_key_per_min" yaml:"per_api_key_per_min"`
	PerGraphQLOpPerMin  int `json:"per_graphql_op_per_min" yaml:"per_graphql_op_per_min"`
	Burst               int `json:"burst" yaml:"burst"`
}

// BotScoreConfig configures behavioral scoring and challenge issuance.
type BotScoreConfig struct {
	Enabled            bool    `json:"enabled" yaml:"enabled"`
	ChallengeEnabled   bool    `json:"challenge_enabled" yaml:"challenge_enabled"`
	ChallengeThreshold float64 `json:"challenge_threshold" yaml:"challenge_threshold"` // 0..1 bot score
	BlockThreshold     float64 `json:"block_threshold" yaml:"block_threshold"`
	PowDifficulty      int     `json:"pow_difficulty" yaml:"pow_difficulty"` // leading zero hex nibbles
	MaxChallengesPerIP int     `json:"max_challenges_per_ip" yaml:"max_challenges_per_ip"`
}

// RateLimitConfig is the global rate limiting setup.
type RateLimitConfig struct {
	Backend       string `json:"backend" yaml:"backend"` // "memory" or "redis"
	RedisAddress  string `json:"redis_address" yaml:"redis_address"`
	RedisPassword string `json:"redis_password" yaml:"redis_password"`
	RedisDB       int    `json:"redis_db" yaml:"redis_db"`
}

// EventConfig configures the event pipeline sinks.
type EventConfig struct {
	LogPath        string   `json:"log_path" yaml:"log_path"`
	WebhookURL     string   `json:"webhook_url" yaml:"webhook_url"`
	WebhookSchema  string   `json:"webhook_schema" yaml:"webhook_schema"` // "wazuh" | "prajna" | "generic"
	WebhookTimeout Duration `json:"webhook_timeout" yaml:"webhook_timeout"`
	RedactFields   []string `json:"redact_fields" yaml:"redact_fields"`
	BodyTruncate   int      `json:"body_truncate" yaml:"body_truncate"`
}

// PluginConfig configures WASM plugin loading.
type PluginConfig struct {
	Dir       string   `json:"dir" yaml:"dir"`
	Timeout   Duration `json:"timeout" yaml:"timeout"`
	MaxMemory uint64   `json:"max_memory" yaml:"max_memory"` // bytes
}

// FingerprintConfig configures JA3/JA4 and HTTP/2 fingerprinting.
type FingerprintConfig struct {
	Enabled       bool     `json:"enabled" yaml:"enabled"`
	Blocklist     []string `json:"blocklist" yaml:"blocklist"` // JA4 hashes to block
	BlocklistFile string   `json:"blocklist_file" yaml:"blocklist_file"`
}

// MLConfig configures the optional anomaly-scoring service.
type MLConfig struct {
	Enabled     bool     `json:"enabled" yaml:"enabled"`
	URL         string   `json:"url" yaml:"url"`
	Timeout     Duration `json:"timeout" yaml:"timeout"`
	FailMode    FailMode `json:"fail_mode" yaml:"fail_mode"`
	Threshold   float64  `json:"threshold" yaml:"threshold"`
	CircuitOpen int      `json:"circuit_open" yaml:"circuit_open"` // consecutive failures to trip breaker
}

// LLMProtectConfig configures LLM-endpoint protection.
type LLMProtectConfig struct {
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	FailMode FailMode `json:"fail_mode" yaml:"fail_mode"`
	Rules    []string `json:"rules" yaml:"rules"` // paths to pattern rule files
}

// EBPFConfig configures the optional eBPF pre-filter.
type EBPFConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Device   string `json:"device" yaml:"device"` // interface to attach
	DropPort int    `json:"drop_port" yaml:"drop_port"`
}

// EnvoyConfig configures the Envoy ext_proc sidecar build.
type EnvoyConfig struct {
	Listen string `json:"listen" yaml:"listen"` // gRPC address for ext_proc
}

// AdminConfig configures the management web UI + API listener. This is the
// operator's entry point: the embedded dashboard and /api/v1 are served here,
// separate from the proxy listeners so the UI is never exposed to the proxy
// front door by default.
type AdminConfig struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Address string `json:"address" yaml:"address"` // e.g. ":9090"
}

// AgentConfig configures the agent enrollment and streaming service. Agents
// on monitored servers dial out to this listener (NAT-friendly); no inbound
// ports are needed on the monitored hosts.
type AgentConfig struct {
	Enabled  bool     `json:"enabled" yaml:"enabled"`
	Listen   string   `json:"listen" yaml:"listen"` // gRPC/TLS address, e.g. ":9443"
	TLSCert  string   `json:"tls_cert" yaml:"tls_cert"`
	TLSKey   string   `json:"tls_key" yaml:"tls_key"`
	TokenTTL Duration `json:"token_ttl" yaml:"token_ttl"` // enrollment token lifetime
}

// DBConfig configures the persistent SQLite store backing agents and events.
type DBConfig struct {
	Path string `json:"path" yaml:"path"` // e.g. "/var/lib/sentinelwaf/sentinelwaf.db"
}

// AuthConfig configures Management API authentication.
type AuthConfig struct {
	JWTSecret         string   `json:"jwt_secret" yaml:"jwt_secret"`
	AdminUser         string   `json:"admin_user" yaml:"admin_user"`
	AdminPasswordHash string   `json:"admin_password_hash" yaml:"admin_password_hash"` // argon2id
	TokenTTL          Duration `json:"token_ttl" yaml:"token_ttl"`
}

// Store is a hot-reloadable configuration holder.
type Store struct {
	mu       sync.RWMutex
	cfg      *Config
	path     string
	onChange []func(*Config)
}

// NewStore returns a Store backed by the given config path.
func NewStore(path string) *Store {
	return &Store{path: path}
}

// Load reads, validates and returns a Config from a JSON or YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := &Config{}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", path, err)
		}
	}
	applyEnvOverrides(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Reload re-reads the config file, validates, and swaps atomically.
func (s *Store) Reload() error {
	cfg, err := Load(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	for _, f := range s.onChange {
		f(cfg)
	}
	return nil
}

// Get returns the current config snapshot.
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Set installs a config directly (used by tests / Management API).
func (s *Store) Set(cfg *Config) {
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	for _, f := range s.onChange {
		f(cfg)
	}
}

// OnChange registers a callback invoked after a reload.
func (s *Store) OnChange(f func(*Config)) {
	s.mu.Lock()
	s.onChange = append(s.onChange, f)
	s.mu.Unlock()
}

// Validate checks the configuration for structural errors.
func (c *Config) Validate() error {
	if c.Version == 0 {
		c.Version = 1
	}
	if len(c.Sites) == 0 && len(c.Listeners) == 0 && !c.Admin.Enabled && !c.Agent.Enabled {
		return fmt.Errorf("config: configure at least one site, listener, admin, or agent")
	}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Address == "" {
			return fmt.Errorf("config: listener %d has no address", i+1)
		}
		if l.HTTP3 && !l.TLS {
			return fmt.Errorf("config: http/3 listener %s requires tls", l.Address)
		}
		if l.TLS && (l.CertPath == "" || l.KeyPath == "") {
			return fmt.Errorf("config: tls listener %s requires cert_path and key_path", l.Address)
		}
	}
	seen := map[string]bool{}
	for i := range c.Sites {
		s := &c.Sites[i]
		if s.ID == "" {
			s.ID = fmt.Sprintf("site-%d", i+1)
		}
		if s.Name == "" {
			s.Name = s.ID
		}
		if s.Backend == "" {
			return fmt.Errorf("config: site %q has no backend", s.ID)
		}
		if seen[s.ID] {
			return fmt.Errorf("config: duplicate site id %q", s.ID)
		}
		seen[s.ID] = true
		if s.FailMode == "" {
			s.FailMode = FailClosed
		}
		if s.Status == "" {
			s.Status = "enabled"
		}
		if s.MaxBodyBytes == 0 {
			s.MaxBodyBytes = 4 << 20 // 4 MiB default
		}
		if s.CRS == nil {
			s.CRS = &CRSConfig{Enabled: true, SQLi: true, XSS: true, RCE: true, PathTraversal: true, LFI: true, Protocol: true}
		}
		if s.GraphQL != nil && s.GraphQL.MaxDepth == 0 {
			s.GraphQL.MaxDepth = 10
		}
		if s.GraphQL != nil && s.GraphQL.MaxComplexity == 0 {
			s.GraphQL.MaxComplexity = 1000
		}
		if s.RateLimit != nil {
			if s.RateLimit.Burst == 0 {
				s.RateLimit.Burst = 20
			}
			if s.RateLimit.PerIPRequestsPerMin == 0 {
				s.RateLimit.PerIPRequestsPerMin = 120
			}
		}
		if s.BotScore != nil {
			if s.BotScore.ChallengeThreshold == 0 {
				s.BotScore.ChallengeThreshold = 0.5
			}
			if s.BotScore.BlockThreshold == 0 {
				s.BotScore.BlockThreshold = 0.9
			}
			if s.BotScore.PowDifficulty == 0 {
				s.BotScore.PowDifficulty = 3
			}
		}
		if s.WebSocket != nil && s.WebSocket.MaxMessagesPerMin == 0 {
			s.WebSocket.MaxMessagesPerMin = 60
		}
		if s.WebSocket != nil && s.WebSocket.MaxMessageBytes == 0 {
			s.WebSocket.MaxMessageBytes = 64 << 10
		}
	}
	if c.Auth.JWTSecret == "" && (c.Auth.AdminUser != "" || c.Auth.AdminPasswordHash != "") {
		return fmt.Errorf("config: auth.jwt_secret is required when auth is configured")
	}
	if c.RateLimit.Backend == "" {
		c.RateLimit.Backend = "memory"
	}
	if c.Events.LogPath == "" {
		c.Events.LogPath = "data/events.log"
	}
	if c.Events.WebhookTimeout == 0 {
		c.Events.WebhookTimeout = Duration(5 * time.Second)
	}
	if c.Events.BodyTruncate == 0 {
		c.Events.BodyTruncate = 2048
	}
	if c.Plugins.Timeout == 0 {
		c.Plugins.Timeout = Duration(100 * time.Millisecond)
	}
	if c.Plugins.MaxMemory == 0 {
		c.Plugins.MaxMemory = 32 << 20
	}
	if c.ML.Timeout == 0 {
		c.ML.Timeout = Duration(250 * time.Millisecond)
	}
	if c.ML.CircuitOpen == 0 {
		c.ML.CircuitOpen = 5
	}
	if c.Auth.TokenTTL == 0 {
		c.Auth.TokenTTL = Duration(8 * time.Hour)
	}
	if c.Admin.Enabled && c.Admin.Address == "" {
		c.Admin.Address = ":9090"
	}
	if c.Agent.Enabled && c.Agent.Listen == "" {
		c.Agent.Listen = ":9443"
	}
	if c.Agent.TokenTTL == 0 {
		c.Agent.TokenTTL = Duration(24 * time.Hour)
	}
	if c.DB.Path == "" && (c.Admin.Enabled || c.Agent.Enabled) {
		c.DB.Path = "data/sentinelwaf.db"
	}
	return nil
}

// ListenerList returns the front-end listeners. When none are configured, a
// default plain-HTTP listener on :8080 is used so a minimal config always
// serves.
func (c *Config) ListenerList() []Listener {
	if len(c.Listeners) == 0 {
		return []Listener{{Address: ":8080", TLS: false}}
	}
	return c.Listeners
}

// SiteByDomain finds the first site matching a Host header (or SNI).
func (c *Config) SiteByDomain(host string) *Site {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	for i := range c.Sites {
		s := &c.Sites[i]
		for _, d := range s.Domains {
			if strings.ToLower(d) == h {
				if s.Status == "disabled" {
					return nil
				}
				return s
			}
		}
	}
	return nil
}

// SiteByID returns a site by ID.
func (c *Config) SiteByID(id string) *Site {
	for i := range c.Sites {
		if c.Sites[i].ID == id {
			return &c.Sites[i]
		}
	}
	return nil
}
