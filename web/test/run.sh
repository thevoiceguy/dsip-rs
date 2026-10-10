#!/usr/bin/env bash
# The headless call test: a relay serves the client; two browsers (two storage contexts) call each other through it.
# Usage: web/test/run.sh [firefox|chromium|all]   (default: firefox; CI runs both). Needs `npm ci` in web/ and
# `npx playwright install [--with-deps] <browser>`.
set -euo pipefail
cd "$(dirname "$0")/../.."
BROWSERS=${1:-firefox}
cargo build -q -p dsip-relay
[ -f web/pkg/dsip_wasm.js ] || web/build.sh
D=${DEMO_DIR:-$(mktemp -d)}; mkdir -p "$D"
LISTEN=${LISTEN:-127.0.0.1:8443}
target/debug/dsip-relay --listen "$LISTEN" --state "$D/relay" --www web >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT
for i in $(seq 1 80); do grep -q 'listening on' "$D/relay.log" && break; sleep 0.25; done
grep -q 'listening on' "$D/relay.log" || { echo "relay did not start"; cat "$D/relay.log"; exit 1; }
rc=0
for b in $(echo "$BROWSERS" | sed 's/all/firefox chromium/; s/,/ /g'); do
  echo "== $b"
  (cd web && BROWSER=$b URL="https://$LISTEN/" node test/call.mjs) || rc=1
done
exit $rc
