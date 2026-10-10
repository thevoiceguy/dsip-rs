#!/usr/bin/env bash
# Build the WASM engine into web/pkg (needs the wasm32 target from rust-toolchain.toml + wasm-pack).
set -euo pipefail
cd "$(dirname "$0")/../crates/dsip-wasm"
wasm-pack build --target web --release --out-dir ../../web/pkg
