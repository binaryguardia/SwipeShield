#!/usr/bin/env bash
# Builds the React dashboard and bundles its static output into the Go
# webui package so the manager binary can be compiled with `-tags webui`
# and serve the UI from the embedded filesystem.
#
#   ./scripts/build-dashboard.sh
#   (cd core && go build -tags webui -o swipeshield ./cmd/swipeshield)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DST="$ROOT/core/internal/webui/dist"

echo "==> Installing dashboard dependencies..."
(cd dashboard && npm ci --no-audit --no-fund)

echo "==> Building dashboard..."
(cd dashboard && npm run build)

echo "==> Bundling into core/internal/webui/dist..."
rm -rf "$DST"
mkdir -p "$DST"
cp -r dashboard/dist/. "$DST/"
echo "Bundled $(find "$DST" -type f | wc -l) files into internal/webui/dist"

echo "==> Building manager with dashboard..."
(cd core && go build -tags webui -o "$ROOT/swipeshield" ./cmd/swipeshield)
echo "Done. Run ./swipeshield -config core/config.example.json"
