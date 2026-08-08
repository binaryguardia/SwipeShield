# SentinelWAF

A self-hosted web application firewall built on an Envoy proxy with CRS
(OWASP ModSecurity Core Rule Set) rule engine, bot fingerprinting, rate
limiting, an eBPF/LSM kernel helper, LLM protections for prompt-injection
attacks, and a manager + agent fleet architecture.

```
                          ┌─────────────────────────────┐
                          │  Manager (sentinelwaf)      │
   ┌───────────┐          │  · admin UI + /api/v1 :9090 │
   │  Browser  │──HTTP───▶│  · agent channel   :9443    │
   └───────────┘          │  · embedded dashboard       │
         │                │  · per-agent registry       │
         ▼                └───────────▲─────────────────┘
   ┌──────────────────────────┐       │  dial OUT (NAT-friendly)
   │  SentinelWAF gateway      │       │
   │  Envoy + CRS + botscore   │  gRPC/TLS
   └──────────────────────────┘       │
         │                            │
   ┌─────▼─────┐              ┌───────┴────────┐
   │  origin   │              │  sentinelwaf-  │
   │  backend  │              │  agent         │
   └───────────┘              └────────────────┘
```

- **Gateway** — the per-host WAF fronting your origin servers: Envoy-based
  proxy (`internal/proxy`, `internal/envoy`), OWASP CRS rule engine
  (`internal/ruleengine`), bot scoring with JS proof-of-work challenges
  (`internal/botscoring`, `internal/fingerprint`), rate limiting
  (`internal/ratelimit`), WebSocket/SSE/GraphQL/gRPC body parsers
  (`internal/parsers`), LLM prompt-injection protection (`internal/llmprotect`),
  eBPF/LSM hooks (`internal/ebpf`), and WASM plugins (`internal/wasmplugins`).
- **Manager** — central control plane. Serves the operator dashboard and a
  REST API on `/api/v1` (sites, rules, blocklist, metrics, events, agents), and
  hosts the agent gRPC channel for monitored servers.
- **Agent** — `sentinelwaf-agent` runs on each monitored server. It dials OUT
  to the manager (no inbound ports needed), enrolls with a one-time token, and
  streams heartbeats plus the local WAF events log back home.

## Quick start

```sh
# Build
go build ./...

# Run a manager with admin UI, agent channel, and an example site
go run ./cmd/sentinelwaf -config config.example.json
```

### Configuration

SentinelWAF uses a single JSON or YAML config file (`-config`, default
`config.json`). Key sections:

| Key | Purpose |
| --- | --- |
| `proxy.listen` | gateway listener (default `:8080`) |
| `admin.enabled` | enable the operator UI + API listener |
| `agent.enabled` | enable the agent channel (auto-generates a self-signed TLS cert) |
| `db.path` | SQLite store for agents, events, enroll tokens |
| `sites[].domains` | virtual-host match for a protected site |
| `sites[].backend` | origin URL to proxy to |
| `events.log_path` | JSONL events log (tailed by agents) |
| `auth.admin_user` / `auth.admin_password_hash` | dashboard login |

### Adding a monitored server

1. In the dashboard (or `POST /api/v1/agents`), register the server by name/IP.
   The response includes a one-time enrollment token.
2. On the server, run the returned command:
   ```sh
   sentinelwaf-agent enroll -m manager.example.com:9443 -t <one-time-token>
   ```
3. Run the agent (typically as a systemd service):
   ```sh
   sentinelwaf-agent run -waf-log /var/log/sentinelwaf/events.log
   ```

## Development

```sh
go test ./...       # full test suite
go vet ./...        # static checks

# Regenerate the agent protobuf after editing internal/agent/agentpb/agent.proto:
protoc -I internal/agent/agentpb \
  --go_out=. --go_opt=module=github.com/binaryguardia/sentinelwaf \
  --go-grpc_out=. --go-grpc_opt=module=github.com/binaryguardia/sentinelwaf \
  internal/agent/agentpb/agent.proto
```

## License

See [LICENSE](../LICENSE).
