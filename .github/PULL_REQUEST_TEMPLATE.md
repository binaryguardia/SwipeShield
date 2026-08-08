---
name: Pull request
about: Submit changes to SwipeShield
title: ''
labels: ''
assignees: ''
---

<!-- Thank you for contributing. Read CONTRIBUTING.md first, especially the
"Ground rules". -->

## What & why

Short description of the change and the problem it solves. Reference any
related issue (`Fixes #123`).

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Rule / rule-group change
- [ ] Docs / CI / release
- [ ] Security-relevant change (see below)

## Tests

- [ ] `cd core && go vet ./... && go test -race ./...` passes
- [ ] e2e smoke suite passes (`./scripts/smoke-test.sh`) if the change touches
      the proxy, parsers, or rules
- [ ] Added/updated unit tests for new behavior

## Checklist

- [ ] No secrets in code or committed config (gitleaks runs in CI)
- [ ] RE2 regex only in the request path — no PCRE/backtracking engines
- [ ] Any new external call is time-bounded and has an explicit `fail_mode`
- [ ] `docs/threat-model.md` updated if the request-inspection behavior changed
      (protects/does-not-protect must stay in sync)
- [ ] WASM plugins: sandbox constraints (no FS/network, bounded memory/CPU)
      respected if the plugin host interface changed

## Notes for reviewers

Anything tricky, risky, or worth extra scrutiny — especially anything in the
inspection path where a bug is a vulnerability.
