---
name: Feature request
about: Propose a new capability for SwipeShield
title: "[feature] "
labels: enhancement
assignees: ''
---

## Problem

What can't you do today, or what's painful? A short narrative beats a list.

## Proposed capability

What should SwipeShield do, and where does it fit?

- Layer / module affected (rules, parsers, bot scoring, ML, LLM protection,
  WASM plugins, Envoy sidecar, dashboard, deployment)
- Protocol(s) involved (REST, GraphQL, gRPC, WebSocket, SSE)
- Desired config surface (new fields, per-site toggles, fail modes)

## Alternatives considered

What else have you tried or considered?

## Prior art

Pointers to how other projects (ModSecurity, Traefik, envoy, cloud WAFs)
handle this, if relevant.

## Acceptance criteria

What would make you call this done? (e.g. "a new `max_depth` knob on
`site.graphql`" — fine. "Better security" — too vague.)

## Notes for contributors

If this touches the request-inspection path, flag it: it changes the threat
model and needs tests (`go test -race ./...`) plus a `docs/threat-model.md`
update per [CONTRIBUTING](../../CONTRIBUTING.md).
