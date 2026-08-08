#!/usr/bin/env bash
# End-to-end test of the manager control plane against the compose stack:
# dashboard, auth, management API, and the agent channel (enroll → online →
# stream a WAF event → verified via the API).
#
# Usage: ./scripts/test-manager.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> Bringing up the SwipeShield stack (gateway + manager + demo)..."
docker compose up -d

echo "==> Waiting for manager health..."
for i in $(seq 1 60); do
  if docker compose ps manager | grep -q healthy; then
    break
  fi
  sleep 2
done
if ! docker compose ps manager | grep -q healthy; then
  echo "!! Manager did not become healthy within 120s" >&2
  docker compose ps
  docker compose logs manager --tail 50 || true
  docker compose down -v
  exit 1
fi

BASE=http://127.0.0.1:9090
echo "==> Dashboard"
DASH=$(curl -s -o /tmp/manager-dash.html -w '%{http_code}' "$BASE/")
echo "GET / -> $DASH"
grep -qi swipeshield /tmp/manager-dash.html || { echo "!! dashboard content missing" >&2; docker compose down -v; exit 1; }

echo "==> Auth"
TOK=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' "$BASE/api/v1/auth/login" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOK" ] || { echo "!! login failed" >&2; docker compose down -v; exit 1; }
echo "login token: ${TOK:0:12}..."

echo "==> Management API"
curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/sites" | grep -q '"id"' \
  && echo "PASS: sites API" || echo "FAIL: sites API"

echo "==> Register server (add by IP)"
RESP=$(curl -s -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  -d '{"name":"web-01","ip":"10.0.0.9"}' "$BASE/api/v1/agents")
AGENT_ID=$(echo "$RESP" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1)
AGENT_TOKEN=$(echo "$RESP" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p' | head -1)
echo "agent=$AGENT_ID token=${AGENT_TOKEN:0:8}..."

echo "==> Agent enroll + stream"
(cd core && go build -o /tmp/swipeshield-agent ./cmd/swipeshield-agent)
/tmp/swipeshield-agent enroll -m 127.0.0.1:9443 -t "$AGENT_TOKEN" -config /tmp/manager-agent.json >/dev/null
mkdir -p /tmp/manager-events && : > /tmp/manager-events/events.log
/tmp/swipeshield-agent run -config /tmp/manager-agent.json -waf-log /tmp/manager-events/events.log > /tmp/manager-agent.log 2>&1 &
AGENT=$!
sleep 2
echo '{"event":"blocked","rule":"933100","status":403,"host":"web-01"}' >> /tmp/manager-events/events.log
sleep 4

echo "==> Agent status (while live) + streamed event"
curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/agents" > /tmp/manager-agents.json
grep -q '"online"' /tmp/manager-agents.json && echo "PASS: agent online" || echo "FAIL: agent not online"
kill $AGENT 2>/dev/null || true
curl -s -H "Authorization: Bearer $TOK" "$BASE/api/v1/agents/$AGENT_ID/events" > /tmp/manager-agent-events.json
grep -q '933100' /tmp/manager-agent-events.json && echo "PASS: WAF event streamed to manager" || echo "FAIL: event not streamed"

echo "==> Tearing down..."
docker compose down -v
