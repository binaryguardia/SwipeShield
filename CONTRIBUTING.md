# Contributing to SwipeShield

Thanks for your interest. SwipeShield is an open-source, self-hostable Web
Application & API Protection platform (WAAP). We welcome contributions —
especially WASM plugin authors, protocol-parser reviewers, and rule authors.

## Ground rules

- **One phase at a time.** We work from `docs/PHASES.md`. Don't push ahead of
  the verified Definition of Done of the current phase.
- **Tests before merge**, especially for anything in the request-inspection
  path: rule matching, GraphQL/gRPC parsing, fingerprinting. Bugs here are
  vulnerabilities, not just bugs.
- **RE2 regex only.** Go's built-in `regexp` everywhere user input touches
  matching logic. No PCRE/backtracking engines in the request path (ReDoS
  defense). This constraint applies inside WASM plugins too.
- **No custom crypto.** TLS via `crypto/tls` only.
- **No secrets in code or committed config.** Env vars / secret manager only;
  gitleaks runs in CI and blocks on findings.
- **Every external call is time-bounded** with a defined fallback. No
  unbounded waits on ML, LLM-protection, fingerprint-DB, Redis, or WASM
  plugin invocations.

## Development setup

```sh
# Core (Go 1.25+)
cd core
go build ./...
go test ./...

# Dashboard (Node 20+)
cd dashboard
npm install
npm run dev

# ML service (Python 3.12+)
cd ml-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Submitting changes

1. Fork the repo and branch from `main`.
2. Keep changes scoped; add tests alongside code.
3. Run `go vet ./...` and `go test ./...` in `core/`.
4. Open a PR. The CI pipeline runs vet/build/test, gitleaks, and
   govulncheck on every PR.

## WASM plugin authors

- Plugins run in a sandboxed `wazero` host with a minimal host interface:
  read request metadata, return a verdict+score. No raw filesystem/network
  access is exposed.
- Use RE2-compatible regex if you match on strings (no backtracking engines —
  WASM sandboxing bounds memory/syscalls, not CPU-time amplification).
- Respect the per-plugin execution timeout; the host enforces it
  independently of your code.

## Code of conduct

See `CODE_OF_CONDUCT.md`.
