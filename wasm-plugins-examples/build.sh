#!/usr/bin/env bash
# Builds the WASI plugins into wasm-plugins-examples/dist.
# Requires Go 1.21+ (WASI support).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$ROOT/dist"
for d in "$ROOT"/*/; do
  name="$(basename "$d")"
  [[ -f "$d/main.go" ]] || continue
  echo "building $name"
  (cd "$d" && GOOS=wasip1 GOARCH=wasm go build -o "$ROOT/dist/$name.wasm" .)
done
echo "done: $ROOT/dist"
