#!/usr/bin/env bash
# Phase 2 — relay store-and-forward (§13.3): bob is known to the relay but offline when alice calls;
# the invite is held, delivered when bob's phone binds, and bob's laptop binding mid-attempt becomes a leg.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --workspace
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-sf-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8443/dsip
$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
$B/dsip identity init --dir "$D/bob-laptop" --name "Bob" --controller-from "$D/bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"

echo "════════ 0. bob's phone binds once (so the relay knows bob) and goes offline"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --script "sleep 1; quit" | grep -E "capabilities"

echo; echo "════════ 1. alice calls while bob is offline: the invite is queued (no error); 4 s later bob's phone binds and rings"
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --t-establish 20 --script "sleep 12; hangup; sleep 1; quit" >"$D/alice.log" 2>&1 & P=$!
sleep 4
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --auto none --script "sleep 3; accept; sleep 8; quit" >"$D/bob.log" 2>&1 & P2=$!
sleep 1.5
echo "      (bob's laptop binds 1.5 s after the phone, while the attempt is still ringing → added as a leg)"
$B/dsip answer --identity "$D/bob-laptop" --relay $R --ca "$CA" --auto none --script "sleep 9; quit" >"$D/laptop.log" 2>&1 & P3=$!
wait $P $P2 $P3
echo "──── alice:";  grep -E "^(→|←|  ◆|  ⏱)" "$D/alice.log"
echo "──── bob phone:"; grep -E "^(→|←|  ◆)" "$D/bob.log"
echo "──── bob laptop:"; grep -E "^(→|←|  ◆)" "$D/laptop.log"
echo "──── relay:"; grep -oE "(queued|deliver stored|dequeued|invite .* → leg|per-leg cancel|attempt).*" "$D/relay.log" | cut -c1-110

echo; echo "════════ 2. alice calls; nobody binds: the queued invite expires with the invite (30 s) — alice's T-Establish fires first"
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --t-establish 5 --script "sleep 7; quit" | grep -E "^(→|←|  ◆|  ⏱)"
