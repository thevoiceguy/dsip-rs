#!/usr/bin/env bash
# Build the WASM endpoint into demos/browser/pkg (needs wasm32 target + wasm-pack).
set -euo pipefail
cd "$(dirname "$0")/../../crates/dsip-wasm"
wasm-pack build --target web --release --out-dir ../../demos/browser/pkg
