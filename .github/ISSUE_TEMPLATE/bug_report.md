---
name: Bug report
about: Report a defect in SwipeShield
title: "[bug] "
labels: bug
assignees: ''
---

## Summary

One or two sentences describing the bug.

## Environment

- Deployment mode: reverse proxy / Envoy ext_proc / both
- Version or commit: (e.g. v0.1.0, or the `git rev-parse HEAD`)
- Go / Docker versions if relevant:
- Platform:

## Reproduction

Steps to trigger the bug. A minimal request (headers + body) or a minimal
config is ideal — bugs in the inspection path are much faster to fix when the
payload is included.

```bash
# example curl, or a link to a failing test case
```

Expected behavior:
Actual behavior (include response headers/status if relevant):

## Impact

What an attacker or operator stands to lose (bypass, false positive, crash,
data leak). If this is a security-relevant finding, use our [security reporting
process](../../SECURITY.md) instead of filing it publicly.

## Logs / events

Relevant `events.log` lines or webhook payloads (redact anything sensitive).

## Checks

- [ ] Reproduced against `main`
- [ ] Reproduced with a minimal config (`deploy/compose/config.json`)
- [ ] Confirmed the exact rule / module / status code if possible
