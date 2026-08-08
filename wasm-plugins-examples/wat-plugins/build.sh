#!/usr/bin/env bash
# Builds the WAT plugins into wasm-plugins-examples/wat-plugins/dist.
# Requires wabt (wat2wasm). If wat2wasm is unavailable, the committed
# dist/*.wasm binaries are used instead.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$ROOT/dist"
if command -v wat2wasm >/dev/null 2>&1; then
  for f in "$ROOT"/*.wat; do
    name="$(basename "$f" .wat)"
    echo "building $name.wasm"
    wat2wasm "$f" -o "$ROOT/dist/$name.wasm"
  done
else
  echo "wat2wasm not found; using committed dist binaries" >&2
fi
echo "done: $ROOT/dist"
