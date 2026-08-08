# SwipeShield Threat Model

This document is the honest, explicit security claim for SwipeShield. It exists
so operators don't over-trust us (and we don't over-claim). Read it before
deploying in front of anything you care about.

## 1. What SwipeShield is

A self-hostable, protocol-aware Web Application & API Protection (WAAP)
gateway. It terminates client connections and inspects application-layer
traffic (HTTP/1.1, HTTP/2, HTTP/3 via TLS listeners, GraphQL, gRPC, WebSocket,
SSE) against layered defenses: a classic ModSecurity-style rule engine, rate
limits, bot detection + proof-of-work challenges, fingerprinting, and
optional ML / LLM-protection and WASM plugin modules. It can run inline as a
reverse proxy or as an Envoy `ext_proc` sidecar in a service mesh.

## 2. Trust boundary

```
Client ──TLS──▶ SwipeShield ──plaintext-or-TLS──▶ Origin application
                     │
                     ├──▶ events pipeline (log / webhook)
                     ├──▶ optional: ML service, LLM-protection service
                     ├──▶ optional: WASM plugins (sandboxed wazero)
                     └──▶ optional: eBPF pre-filter (kernel, off by default)
```

- Everything the client sends is **untrusted** until the inspection pipeline
  has produced a verdict.
- The origin application, ML/LLM services, and any configured webhooks sit on
  the **trusted** side and are assumed to be reachable and accountable.
- The WASM plugin host is a sandbox boundary; plugins are untrusted code and
  must never bypass it (see §5).

## 3. Protects against

| # | Threat | Defense | Notes / status codes |
|---|--------|---------|----------------------|
| 1 | Classic web attacks — SQLi, XSS, RCE, path traversal, LFI, protocol smuggling | CRS-style rule engine (`core/internal/ruleengine`), regex + anomaly scoring; `sqli`, `xss`, `rce`, `path_traversal`, `lfi`, `protocol` rule groups | 403 on match; rules are RE2-only (ReDoS-safe). Per-rule toggles per site. |
| 2 | Abuse of request semantics (bad Content-Length, malformed framing, header conflicts) | Protocol rule group, e.g. 920170 rejecting malformed Content-Length | 400/403 |
| 3 | Request-rate abuse from one IP / API key / GraphQL operation | Distributed-safe rate limiter (`core/internal/ratelimit`); per-IP, per-API-key, per-GraphQL-op buckets, burst allowance | 429 with retry-after |
| 4 | Automated/bot traffic (scrapers, credential stuffing, naive bots) | Bot scoring (`core/internal/botscoring`): UA + heuristics → score; score above threshold → PoW challenge or block (`bot_score.challenge_threshold` / `.block_threshold`) | challenge → 429 + proof-of-work; block → 403 |
| 5 | GraphQL abuse — deep queries, high complexity, alias bombs, introspection disclosure, query batching | GraphQL parser (`core/internal/parsers`): depth / complexity / alias limits; introspection and batching blocked on demand | 400 (parse/limit) or 403 (policy) |
| 6 | gRPC payload abuse | Protobuf field-level parser + rules on service/method/field values | 403 |
| 7 | WebSocket message abuse — malicious or oversized frames, message flooding | WS parser + per-message rule inspection; `websocket.max_message_bytes`, `max_messages_per_min`; policy-violation close | 1008 policy close |
| 8 | Bad/missing application data (payload classification) | Optional ML service (`ml.*`): model scores payloads; configurable fail-open/fail-closed and circuit breaker (`circuit_open`) | off by default |
| 9 | Prompt-injection / LLM-route abuse | LLM-protection module (`core/internal/llmprotect`) | 403; on by default, fail-closed |
| 10 | Zero-day / org-specific attack patterns | WASM plugins (`core/internal/wasmplugins`): sandboxed, time-boxed, memory-limited | plugin verdict |
| 11 | Client fingerprinting to raise attacker cost | JA3/JA4/H2 fingerprint capture (`core/internal/fingerprint`) feeds bot scoring and events | informational + scoring |
| 12 | Low-level pre-filter (kernel-adjacent, experimental) | eBPF probe (`core/internal/ebpf`): graceful no-op on unsupported hosts | disabled without root/BPFFS |
| 13 | Crash-induced service outage | Panic recovery in the request path + top-level process handler (fail-closed 500) | 500 |
| 14 | Unbounded external calls stalling requests | Timeouts + defaults on every external/async call: ML, LLM-protection, WASM, webhooks (`eventpipeline`) | timeout → configured fail mode |
| 15 | Mesh deployment blind spots | Envoy `ext_proc` sidecar (`core/internal/envoy`) evaluates in-band; allow/block/challenge via `ImmediateResponse` | 400/403/413/429/500 |

## 4. Does NOT protect against

| # | Not protected | Why / what to use instead |
|---|---------------|---------------------------|
| 1 | **Volumetric (L3/L4) DDoS** — SYN floods, UDP amplification, link saturation | SwipeShield is application-layer; it never sees packets your infra drops. Use a network/L3-L4 DDoS scrubber. |
| 2 | **Origin bypass** — attackers hitting the origin IP, port, or an alternate hostname directly | SwipeShield is not a network firewall. Restrict the origin to the gateway (network ACL / security group). |
| 3 | **Business-logic flaws** — IDOR, price/balance manipulation, flawed authz, insecure direct object access | A WAF cannot infer intent. Covered only if you author a WASM plugin / rule, or fix it in the app. |
| 4 | **Compromised origin / supply-chain compromise** of the app itself | SwipeShield can't detect a trojaned dependency. Runtime protection (e.g. seccomp, signing) required. |
| 5 | **Cryptographic breaking or TLS interception of pinned clients** | We terminate TLS, we don't break it. Mutual TLS client-auth, key management, pinning are yours. |
| 6 | **Full DLP / content classification of stored data** | We inspect transit payloads only (size-limited); no at-rest scanning, no PII taxonomy. |
| 7 | **Sophisticated botnets with distributed IP pools and browser-grade spoofing** | PoW challenges and fingerprinting raise cost; they are deterrence, not a CAPTCHA/botnet-fighting product. JA3/JA4 can be forged by advanced tooling. |
| 8 | **Complete rule coverage** | The corpus is finite and evolving. Use the ModSecurity rule reference (920170 etc.) as guidance, tune to your app, and don't treat a clean pass as a proof of safety. |
| 9 | **Protocols we don't parse** | FTP, SMTP, custom binary protocols, anything on non-HTTP ports. Our parsers cover REST, GraphQL, gRPC, WebSocket, SSE. |
| 10 | **Replay within QUIC 0-RTT / early data** | 0-RTT is replayable by design; we surface it in the context (`ZeroRTT`) and you should treat it as non-idempotent-unsafe. |
| 11 | **Client-side / browser attacks** | XSS *reflected into the client's own browser* is mitigated (403 on known patterns) but DOM-based XSS, malicious JS, or compromised third-party scripts are out of scope. |
| 12 | **Encrypted payloads / E2E-encrypted API bodies** | If the body is opaque to us (e.g. client-side encryption), rule-based inspection is blind to its contents. |
| 13 | **Dependence on a single rule engine** | SwipeShield is defense-in-depth, not a silver bullet. Run it behind or alongside edge WAF/CDN and an RASP agent if your threat model demands. |

## 5. Assumed-threat list (adversaries)

What an operator should assume an attacker can and cannot do:

- An attacker can send arbitrary HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC,
  or GraphQL traffic to the gateway at high volume. They cannot access the
  origin directly (that's your job — §4.2).
- An attacker can fingerprint us, probe rule gaps, and fuzz the parsers. This
  is why parsers and rules are fuzzed/benchmarked in CI and why
  `fail_mode` matters.
- An attacker **cannot** observe our traffic at the transport layer unless they
  have already broken TLS (assume we are not the weakest link, but don't
  assume we are the only link).
- WASM plugins are assumed adversarial. The sandbox must guarantee: no raw
  filesystem, no raw network, bounded memory, bounded CPU (enforced timeout),
  and no access to other tenants' data. If a plugin can escape, the plugin
  author and reviewer are on the hook — treat plugin review like code review.
- The ML and LLM-protection services are treated as either trusted internal
  services (when enabled) or absent (disabled by default). Their verdicts are
  advisory and governed by `fail_mode`.

## 6. Failure modes

Every optional dependency has an explicit, documented failure behavior. The
defaults below are what you get unless you change them:

| Component | Default fail behavior | Config |
|-----------|----------------------|--------|
| ML service | fail-**open** (skip scoring, allow) | `ml.fail_mode` |
| LLM protection | fail-**closed** (block) | `llm_protection.fail_mode` |
| WASM plugin | fail-**open** on timeout (log reason) | `plugins.timeout`, plugin hook |
| Webhook sink | per-attempt timeout (3 s), errors logged, never blocks the request path | `events.webhook_timeout` |
| eBPF | no-op (disabled) unless supported | runtime probe |
| Envoy ext_proc eval error | fail-**closed** 500 | `envoy` module |

If you operate under a stricter security posture, set `ml.fail_mode=closed`.
Read your module's section of `config.example.json` before trusting defaults.

## 7. Assumptions & how to keep them true

1. **The gateway process itself is trusted.** If the host is compromised, all
   bets are off. Run SwipeShield as a non-root container (`core/Dockerfile`),
   keep it patched, and watch its logs.
2. **Secrets never live in config.** TLS keys, API keys, webhook tokens come
   from env/secrets manager. gitleaks runs in CI and blocks committed secrets.
3. **Every outbound call is bounded.** If you add an integration, add a timeout
   and a `fail_mode` — this is a review requirement (see `CONTRIBUTING.md`).
4. **Rule changes are tested.** The request-inspection path is where bugs
   become vulnerabilities. `go test -race ./...` plus the e2e smoke suite run
   before every release.
5. **You have audited `deploy/compose/config.json`** before exposing the
   gateway beyond `127.0.0.1`.

## 8. Reviews

This threat model is a living document. Update it whenever a capability is
added or removed, and whenever a CVE or incident changes our assumptions.
Section 3 and Section 4 must both change together — "we now also block X"
without "we still don't block Y" is how over-claims sneak in.
