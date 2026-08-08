#!/usr/bin/env bash
# Smoke test for a fresh clone: builds the compose stack, waits for the gateway
# healthcheck, and runs the protocol-aware checks in test/e2e/smoke.
#
# Usage: ./scripts/smoke-test.sh [--build]
set -euo pipefail

cd "$(dirname "$0")/.."

BUILD=""
if [[ "${1:-}" == "--build" ]]; then
  BUILD="--build"
fi

echo "==> Bringing up the SentinelWAF stack (waf + demo)..."
if [[ -n "$BUILD" ]]; then
  # Registry/DNS hiccups can make an otherwise-correct build fail once;
  # retry a couple of times before giving up.
  for attempt in 1 2 3; do
    if docker compose build; then
      break
    fi
    echo "!! docker compose build failed (attempt $attempt/3); retrying in 5s..." >&2
    sleep 5
    if [[ $attempt -eq 3 ]]; then
      echo "!! docker compose build failed after 3 attempts" >&2
      exit 1
    fi
  done
fi
docker compose up -d

echo "==> Waiting for gateway health..."
for i in $(seq 1 60); do
  if docker compose ps waf | grep -q healthy; then
    break
  fi
  sleep 2
done

if ! docker compose ps waf | grep -q healthy; then
  echo "!! Gateway did not become healthy within 120s" >&2
  docker compose ps
  docker compose logs waf --tail 50 || true
  docker compose down -v
  exit 1
fi

echo "==> Running smoke checks..."
set +e
( cd test/e2e/smoke && go run . -base http://127.0.0.1:8080 -host localhost )
STATUS=$?
set -e

echo "==> Tearing down..."
docker compose down -v

if [[ $STATUS -ne 0 ]]; then
  echo "SMOKE TEST FAILED" >&2
  exit $STATUS
fi
echo "SMOKE TEST PASSED"
