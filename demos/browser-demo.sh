#!/usr/bin/env bash
# Phase 2 browser demo: the relay serves the page over the same TLS port it speaks wss on.
# 1. builds dsip-wasm (wasm-pack)  2. starts the relay with --www  3. prints what to open.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --workspace
[ -f demos/browser/pkg/dsip_wasm.js ] || demos/browser/build.sh
D=${DEMO_DIR:-/tmp/dsip-browser-demo}; mkdir -p "$D"
LISTEN=${LISTEN:-127.0.0.1:8443}
echo "relay + page:  https://$LISTEN/?as=alice   and   https://$LISTEN/?as=bob   (two tabs)"
echo "certificate:   self-signed — accept the browser warning once; it covers both the page and wss://"
echo "media:         WebRTC getUserMedia needs a secure context — https:// or localhost qualifies"
echo "flow:          copy Bob's identity DID from his tab into Alice's 'callee DID' → call → Bob sees the verified"
echo "               invite (identity ✓, display name = claim, policy) → accept/screen → WebRTC media; add video = §12.8 update"
exec target/debug/dsip-relay --listen "$LISTEN" --state "$D/relay" --www demos/browser
