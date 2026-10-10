#!/usr/bin/env bash
# Browser client, served locally: the relay serves impl/web over the same TLS port it speaks wss on.
# 1. builds dsip-wasm (wasm-pack)  2. starts the relay with --www  3. prints what to open.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --workspace
[ -f web/pkg/dsip_wasm.js ] || web/build.sh
D=${DEMO_DIR:-/tmp/dsip-browser-demo}; mkdir -p "$D"
LISTEN=${LISTEN:-127.0.0.1:8443}
echo "relay + client: https://$LISTEN/?as=alice   and   https://$LISTEN/?as=bob   (two tabs; ?as= keeps two identities apart on one origin)"
echo "certificate:   self-signed — accept the browser warning once; it covers both the page and wss://"
echo "media:         WebRTC getUserMedia needs a secure context — https:// or localhost qualifies"
echo "flow:          each tab makes an identity; add the other's DID as a contact → Call → the incoming screen shows the"
echo "               caller's verification basis (§18.1) → Answer or Screen → WebRTC media; Add video = §12.8 update"
exec target/debug/dsip-relay --listen "$LISTEN" --state "$D/relay" --www web
