#!/usr/bin/env bash
# Phase 1 demo (plan §6): two identities, a relay, a signed call — screened, answered,
# renegotiated, hung up; then a forked call to two devices. Every envelope verified,
# every transition printed with its spec section.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --workspace
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-demo}; rm -rf "$D"; mkdir -p "$D"
RELAY_URL=wss://127.0.0.1:8443/dsip

$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob-phone" --name "Bob" >/dev/null
$B/dsip identity init --dir "$D/bob-laptop" --name "Bob" --controller-from "$D/bob-phone" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob-phone/identity.json'))['identity'])")

$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" >"$D/relay.log" 2>&1 &
RELAY=$!; trap 'kill $RELAY 2>/dev/null || true' EXIT; sleep 1.5
CA="$D/relay/cert.pem"

echo "════════ 1. screened call: bob screens, escalates; alice answers the update; alice hangs up"
$B/dsip answer --identity "$D/bob-phone" --relay $RELAY_URL --ca "$CA" --auto screen --script "sleep 4; escalate; sleep 6; quit" >"$D/bob1.log" 2>&1 &
P=$!; sleep 1.5
$B/dsip call --identity "$D/alice" --relay $RELAY_URL --ca "$CA" --to "$BOB" --script "sleep 6; answer-update; sleep 2; hangup; sleep 1; quit"
wait $P; echo "──── bob's side:"; cat "$D/bob1.log"

echo; echo "════════ 2. forked call: phone answers, laptop must stop ringing with no missed call"
$B/dsip answer --identity "$D/bob-phone" --relay $RELAY_URL --ca "$CA" --auto accept --script "sleep 8; quit" >"$D/phone.log" 2>&1 &
P1=$!
$B/dsip answer --identity "$D/bob-laptop" --relay $RELAY_URL --ca "$CA" --auto none --script "sleep 8; quit" >"$D/laptop.log" 2>&1 &
P2=$!; sleep 1.5
$B/dsip call --identity "$D/alice" --relay $RELAY_URL --ca "$CA" --to "$BOB" --script "sleep 3; hangup; sleep 1; quit"
wait $P1 $P2; echo "──── laptop's side:"; cat "$D/laptop.log"
echo "──── relay:"; grep -oE "(fork invite|per-leg cancel|attempt).*" "$D/relay.log"
