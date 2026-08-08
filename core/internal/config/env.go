package config

import "os"

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return def
}

// applyEnvOverrides overlays select environment variables onto the config.
// This is deliberately limited to deployment-relevant knobs, not the full
// config surface (config files remain the source of truth for rules/sites).
func applyEnvOverrides(c *Config) {
	if v := env("LISTEN_ADDRS", ""); v != "" {
		_ = v // listeners are derived per-site; see Listeners()
	}
	if v := env("RATE_LIMIT_BACKEND", ""); v != "" {
		c.RateLimit.Backend = v
	}
	if v := env("REDIS_ADDR", ""); v != "" {
		c.RateLimit.RedisAddress = v
	}
	if v := env("REDIS_PASSWORD", ""); v != "" {
		c.RateLimit.RedisPassword = v
	}
	if v := env("EVENT_LOG_PATH", ""); v != "" {
		c.Events.LogPath = v
	}
	if v := env("WEBHOOK_URL", ""); v != "" {
		c.Events.WebhookURL = v
	}
	if v := env("WEBHOOK_SCHEMA", ""); v != "" {
		c.Events.WebhookSchema = v
	}
	if v := env("JWT_SECRET", ""); v != "" {
		c.Auth.JWTSecret = v
	}
	if v := env("ADMIN_USER", ""); v != "" {
		c.Auth.AdminUser = v
	}
	if v := env("ADMIN_PASSWORD_HASH", ""); v != "" {
		c.Auth.AdminPasswordHash = v
	}
	if v := env("ML_SERVICE_URL", ""); v != "" && c.ML.URL == "" {
		c.ML.URL = v
	}
	if v := env("LLM_PROTECTION_URL", ""); v != "" && c.LLMProtect.FailMode == "" {
		// URL is resolved by the LLM protect module via ML-style client
	}
	if v := env("WASM_PLUGINS_DIR", ""); v != "" {
		c.Plugins.Dir = v
	}
}
