# PHASES.md — SwipeShield Build Phases (v2)

Feed the agent one phase at a time. Don't start a phase until the previous
one's Definition of Done is actually verified, not just "code exists."

---

## P0. Repo Scaffold & Planning
- Init monorepo per Architecture.md folder structure
- LICENSE, README skeleton, CONTRIBUTING.md, .gitignore, .env.example
- GitHub Actions CI skeleton (lint + build; govulncheck + gitleaks wired in
  from day one, not bolted on later)
- **DoD:** `go build ./...` succeeds on an empty core, CI green on push

## P1. Core Reverse Proxy — HTTP/1.1 & HTTP/2
- Basic Go reverse proxy: HTTP/1.1 and HTTP/2, TLS 1.3 termination
- Config file loading (single site, YAML/env)
- Structured pass-through logging (no decisions yet)
- **DoD:** Fronts a demo app (e.g. OWASP Juice Shop), traffic flows
  unmodified over both HTTP/1.1 and HTTP/2

## P2. HTTP/3 (QUIC) Support
- Integrate `quic-go`, add HTTP/3 listener alongside 1.1/2
- Verify correctness: connection migration, 0-RTT handling (with replay-
  attack awareness — 0-RTT requests are replayable, decide/document how
  rules treat them)
- **DoD:** Demo app reachable over HTTP/3 from a QUIC-capable client,
  behavior matches HTTP/1.1/2 path for equivalent requests

## P3. Rule Engine — Classic HTTP Signatures
- Integrate/vendor Coraza, load OWASP CRS base rules
- Block/log-only modes per rule
- Run against `go-ftw` OWASP CRS test corpus
- **DoD:** Passes CRS test suite at an acceptable rate; blocks known
  SQLi/XSS payloads against the demo app; false-positive rate measured on
  a benign traffic sample

## P4. Custom Rule DSL
- YAML custom rule format layered on top of CRS
- Rule validation on load (malformed = reject + log, never crash)
- Hot-reload without downtime
- **DoD:** Write a custom rule, hot-reload, verify it takes effect with
  zero restart/downtime

## P5. GraphQL-Aware Inspection
- Integrate a Go GraphQL AST parser
- Implement depth limiting, query complexity/cost scoring, batching-attack
  detection, optional introspection blocking
- Build a dedicated GraphQL-attack test corpus (depth bombs, alias-based
  batching, introspection probes)
- **DoD:** Demo GraphQL endpoint correctly blocks/flags depth-bomb and
  batching-attack test payloads; legitimate queries pass through with
  correctly computed cost scores logged

## P6. gRPC / Protobuf Field-Level Inspection
- Accept operator-supplied `.proto` schema
- Parse gRPC messages field-level against schema, apply rules on specific
  fields (not opaque-blob pass-through)
- Build a gRPC test fixture set
- **DoD:** Demo gRPC service has a custom rule targeting a specific field,
  verified to trigger correctly on malicious field content and stay silent
  on legitimate traffic

## P7. WebSocket & SSE Inspection
- Inspect upgrade handshake + per-message inspection on persistent
  connections
- Per-message rate limiting, pattern rules
- **DoD:** Demo WebSocket endpoint correctly rate-limits/flags a message-
  flood test and a malicious-payload-in-message test, without breaking
  normal connection lifecycle

## P8. Rate Limiting & Behavioral Bot Defense (baseline)
- Token-bucket / sliding-window rate limiter: per-IP, per-API-key, per-
  GraphQL-operation
- Basic bot heuristics (timing/sequencing anomalies)
- **DoD:** Load test proves correct triggering at threshold across REST,
  GraphQL-operation, and WebSocket-message rate limits independently

## P9. TLS/HTTP Fingerprinting (JA3/JA4)
- Implement JA3 and JA4 against their published specs, tested against
  known reference fingerprints
- HTTP/2 fingerprinting (SETTINGS/pseudo-header ordering) as secondary
  signal
- Feed into bot-scoring; support fingerprint-based rule conditions and
  blocklists
- **DoD:** Correctly fingerprints and distinguishes curl / Python-requests
  / headless-browser / real-browser traffic in a test harness; a
  fingerprint-based block rule works end-to-end

## P10. Proof-of-Work / Invisible Challenge for Bot Traffic
- Issue a lightweight self-hosted challenge (PoW or invisible JS check) for
  medium-confidence bot-scored traffic instead of a hard block
- **DoD:** Bot-scored test traffic receives and must pass the challenge;
  legitimate browser traffic passes transparently with no visible friction

## P11. WASM Plugin System
- Define the host-function interface (request/response context in,
  verdict+annotations out)
- Integrate `wazero`, enforce per-plugin timeout and resource limits
- Ship 1–2 example community plugins
- **DoD:** A third-party-style WASM plugin (written independently of the
  core codebase) loads, executes within its resource budget, and its
  verdict correctly influences the decision engine; a deliberately
  slow/misbehaving test plugin is correctly killed by the timeout without
  affecting the proxy

## P12. Event Pipeline & Logging (protocol-aware)
- Async structured JSON events for every verdict, across all protocols
  (REST/GraphQL/gRPC/WebSocket)
- Local file sink + webhook sink (Wazuh/Prajna-compatible schema)
- Sensitive-field redaction, including for LLM-endpoint traffic (see P15)
- **DoD:** Every decision across every protocol produces a well-formed,
  explainable event; webhook delivery is retried/non-blocking

## P13. Management API
- REST API: sites, rules, WASM plugin registration, API keys, users/auth
  (JWT), fingerprint blocklists
- Input validation, rate limiting on the API itself
- **DoD:** Full configuration of a protected site — including GraphQL/gRPC/
  WebSocket-specific rules and plugin registration — achievable via API
  alone, auth enforced

## P14. Dashboard (Admin UI)
- Auth/login, site + rule management, live traffic feed with protocol
  breakdown and bot-score/fingerprint columns
- GraphQL query-complexity view, per-protocol analytics
- **DoD:** Everything from P13 achievable through the UI; a new user can
  protect a site (REST + GraphQL demo) end-to-end via dashboard in under
  15 minutes

## P15. ML Anomaly Scoring Service (should-have)
- Standalone Python FastAPI service, lightweight statistical/gradient-
  boosted model on request-shape features
- Async call with strict timeout + circuit breaker, fail-open, log-only
  mode initially
- **DoD:** Fully disable-able with zero core-function impact; when
  enabled, flags anomalies without breaching the latency budget in
  Architecture.md

## P16. LLM-Endpoint Protection Module (should-have)
- Pattern/heuristic detection for prompt injection, system-prompt-
  exfiltration attempts, jailbreak signatures, on routes flagged as AI
  backends
- Log-only mode first; optional local-model classifier upgrade as a
  separate, later increment
- **DoD:** Correctly flags a curated set of known prompt-injection test
  payloads against a demo LLM-backed endpoint, with an acceptable false-
  positive rate on legitimate prompts; module fully disable-able

## P17. eBPF Pre-Filter (optional, should-have)
- XDP/TC hook via `cilium/ebpf` to drop malformed/volumetric junk before
  L7
- Must degrade gracefully to "disabled" on hosts without the right
  kernel/capabilities
- **DoD:** Measurable reduction in L7 load under a synthetic junk-traffic
  test, zero impact on legitimate traffic, safe no-op on unsupported hosts

## P18. Multi-Node & Redis-Backed Rate Limiting
- Swap in-memory rate limiter for Redis/Redis Cluster-backed version
- Verify correctness across 2+ proxy instances, including per-GraphQL-
  operation and per-WebSocket-message limits
- **DoD:** Rate limits hold correctly across nodes under a distributed
  load test

## P19. Sidecar / Service-Mesh Deployment Mode
- Build the Envoy ext_proc or WASM-filter target so core logic can run as
  a mesh sidecar
- Reference Envoy/Istio config in `deploy/envoy/`
- **DoD:** Reference k8s manifest deploys SwipeShield as an Istio sidecar,
  correctly inspects traffic within the mesh

## P20. Hardening, Testing, Docs
- Panic recovery, full timeout audit across every external/async call and
  every WASM plugin invocation
- Secret-scan (gitleaks) + dependency vuln scan (govulncheck, npm audit) in
  CI, blocking on findings
- Full README quickstart validated by a genuinely fresh clone → running
  stack test, including the GraphQL and WebSocket demo endpoints
- Threat-model doc: explicit "protects against / does not protect against"
  matrix per protocol and module
- **DoD:** Fresh clone → `docker-compose up` → protecting a demo app
  (REST + GraphQL + WebSocket) in under 15 minutes, verified by someone
  other than you

## P21. Open-Source Release Prep
- Final license decision, CODE_OF_CONDUCT.md, issue/PR templates
- Versioned release (v0.1.0), changelog
- Public README with architecture diagram, quickstart, protocol-coverage
  matrix, and clear "what this is / isn't" section
- **DoD:** Repo is genuinely ready for external contributors — including
  WASM plugin authors — to open a PR without hand-holding

---

### Suggested sequencing note
P1–P4 (core proxy + classic rule engine) remain the non-negotiable
foundation — same as v1. P5–P7 (GraphQL/gRPC/WebSocket) are what actually
makes this a *2026-relevant* WAF rather than a ModSecurity clone; don't
skip to bot-fingerprinting or AI modules before these protocol parsers are
solid, since they're the biggest real differentiator. P9–P11
(fingerprinting/bot/WASM) and P15–P17 (ML/LLM-protection/eBPF) are all
should-have, genuinely optional for a v1 ship — sequence them by what your
target users actually ask for first, not by what's most fun to build.
