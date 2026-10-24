#!/usr/bin/env bash
# A second hello from a device the relay already binds replaces the prior connection (§13.2), and only that one: the
# relay closes the old connection and keeps the new one bound. Bob's phone binds, is frozen (so it cannot reconnect),
# and Bob's phone binds again from another process: the relay must close the first connection and leave the second
# bound, not drop both and unbind a device that is still connected. Self-verifying.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-relay-rebind-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8466/dsip
$B/dsip identity init --dir "$D/bob" --name Bob >/dev/null
$B/dsip-relay --listen 127.0.0.1:8466 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill -CONT $FIRST 2>/dev/null || true; kill $(jobs -p) 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"
fail() { echo "FAIL: $*"; for f in "$D"/*.log; do echo "--- $f"; cat "$f"; done; exit 1; }
plain() { sed 's/\x1b\[[0-9;]*m//g' "$D/relay.log"; }

echo "=== Bob's phone binds"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --script "sleep 20; quit" >"$D/first.log" 2>&1 & FIRST=$!
for _ in $(seq 1 40); do plain | grep -q "bound device" && break; sleep 0.25; done
plain | grep -q "bound device" || fail "the first connection did not bind"
OLD=$(plain | grep "bound device" | head -1 | sed -E 's/.*dsip_relay: ([0-9.:]+): bound.*/\1/')
echo "  bound from $OLD"
kill -STOP $FIRST   # frozen: it cannot see its connection close, nor reconnect

echo "=== the same device binds again from another process (§13.2: the new hello replaces the prior connection)"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --script "sleep 4; quit" >"$D/second.log" 2>&1
NEW=$(plain | grep "rebinding" | head -1 | sed -E 's/.*dsip_relay: ([0-9.:]+): rebinding.*/\1/')
[ -n "$NEW" ] || fail "the relay did not see a rebinding"
echo "  rebound from $NEW, replacing $OLD"
plain | grep -q "$OLD: replaced connection" || fail "the relay did not close the replaced connection"
echo "  the relay closed $OLD as replaced"
! grep -q "reconnected" "$D/second.log" || fail "the new connection was dropped with the old one and had to reconnect"
[ "$(plain | grep -c "unbound")" -eq 1 ] || fail "expected one unbind (the second process quitting), got: $(plain | grep unbound)"
plain | grep -q "$NEW: unbound" || fail "the unbind was not the new connection's"
echo "  the new connection stayed bound until it quit: one unbind, no reconnect"
echo
echo "PASS: a second hello from a bound device replaced the prior connection only: the relay closed the old one,"
echo "      kept the new one bound and unbound the device once, when the new connection ended."
