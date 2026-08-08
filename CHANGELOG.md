# Changelog

All notable changes to SwipeShield are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Manager control plane** (`core/cmd/swipeshield` + `core/internal/agent`,
  `core/internal/store`, `core/internal/mgmtapi`): persistent SQLite store for
  monitored servers, "add by IP" enrollment with one-time tokens, agent
  registry (pending/online/offline) and per-agent event feed served under
  `/api/v1/agents`.
- **Agent channel** (`core/internal/agent`, `core/cmd/swipeshield-agent`):
  dial-out gRPC/TLS enrollment and streaming so monitored hosts need no
  inbound ports. Self-signed TLS is auto-generated when no certificates are
  configured; the agent (`enroll` / `run`) tails the local WAF events log and
  streams heartbeats + security events home with reconnect backoff.
- **Dashboard bundling** (`core/internal/webui`, `scripts/build-dashboard.sh`):
  build the React dashboard into the manager binary with `-tags webui`; the
  operator UI is served on the admin listener (`admin.address`) with SPA
  fallback.
- **Compose manager service** (`core/Dockerfile.manager`,
  `deploy/compose/manager.json`): one-command control plane — dashboard on
  :9090, agent channel on :9443 — alongside the existing gateway + demo.
- **Manager E2E test** (`scripts/test-manager.sh`): verifies dashboard, auth,
  management API, agent enrollment, liveness, and event streaming against the
  compose stack.

### Changed

- Module path renamed to `github.com/binaryguardia/swipeshield`; agent
  protobuf regenerated for the new package path.
- `core/config.example.json` added showing the full gateway + manager
  configuration.

## [v0.1.0] - 2026-08-02

Initial open-source release. First phase-complete milestone; see
`docs/PHASES.md` for the roadmap this release tracks.

### Added

- **Reverse proxy gateway** (`core/`): multi-listener HTTP/1.1+HTTP/2, TLS 1.3
  termination, optional HTTP/3 (QUIC) with 0-RTT awareness, host-based
  multi-site routing, fail-open/fail-closed per site, body buffering with size
  limits.
- **Classic rule engine**: ModSecurity-style CRS groups (SQLi, XSS, RCE, path
  traversal, LFI, protocol), anomaly scoring, and site-level custom rules
  (`core/internal/ruleengine`). RE2-only regex (ReDoS-safe).
- **Rate limiting** (`core/internal/ratelimit`): per-IP, per-API-key, and
  per-GraphQL-operation buckets with burst allowance; memory backend.
- **Bot scoring + PoW challenge** (`core/internal/botscoring`): UA and
  heuristic scoring with configurable challenge/block thresholds and
  proof-of-work challenges.
- **Client fingerprinting** (`core/internal/fingerprint`): JA3/JA4 and H2
  fingerprint capture feeding bot scoring and events.
- **Protocol parsers** (`core/internal/parsers`): GraphQL (depth, complexity,
  aliases, introspection/batching blocking), gRPC protobuf field inspection,
  WebSocket per-message inspection, SSE.
- **ML payload classification** (`core/internal/mlclient`): optional,
  off by default, configurable fail-open/fail-closed with circuit breaker.
- **LLM protection** (`core/internal/llmprotect`): prompt-injection and
  LLM-route abuse detection, fail-closed by default.
- **WASM plugin host** (`core/internal/wasmplugins`): sandboxed `wazero`
  plugins with host-enforced execution timeout and memory limits.
- **eBPF pre-filter** (`core/internal/ebpf`): experimental kernel-adjacent
  pre-filter that degrades to a no-op on unsupported hosts.
- **Envoy `ext_proc` sidecar** (`core/internal/envoy`): run the decision engine
  as a service-mesh sidecar; reference configs in `deploy/envoy/`.
- **Events pipeline** (`core/internal/eventpipeline`): JSONL event log and
  webhook delivery with per-attempt timeouts and body truncation.
- **Management API** (`core/internal/mgmtapi`): admin endpoints under
  `/api/v1/`.
- **Panic recovery**: fail-closed per-request recovery in the proxy and a
  top-level process guard with `os.Exit(1)` for supervisor restart.
- **Quickstart stack**: `docker-compose.yml`, hardened multi-stage `core/
  Dockerfile` (non-root, stripped, no debug symbols), reference demo app
  (`test/demoapp`) with REST + GraphQL + WebSocket endpoints, and a 12-check
  e2e smoke suite (`scripts/smoke-test.sh`).
- **Dashboard** (`dashboard/`): Node app for viewing events and health.
- **CI** (`.github/workflows/ci.yml`): Go 1.25 build, vet, `go test -race`,
  gitleaks secret scan, and govulncheck dependency scan.
- **Docs**: `docs/threat-model.md` (protects / does-not-protect matrix),
  `docs/PHASES.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR
  templates.

### Changed

- Rule 920170 (protocol group): corrected the Content-Length validation
  negation so valid POSTs with a body are not blocked.
- Management API routes narrowed from `/api/` to `/api/v1/` so backend
  `/api/*` paths are no longer shadowed.
- Webhook sink defaults to a 3-second per-attempt timeout.
- CI `go-version` bumped to 1.25 (required by `cilium/ebpf`).

### Security

- No secrets in code or committed config; gitleaks runs in CI.
- Every external call is time-bounded with an explicit `fail_mode`
  (see `docs/threat-model.md` §6).
- WASM plugins run sandboxed with no raw filesystem/network access.

[Unreleased]: https://github.com/swipeshield/swipeshield/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/swipeshield/swipeshield/releases/tag/v0.1.0
