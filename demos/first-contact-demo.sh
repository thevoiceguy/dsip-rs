#!/usr/bin/env bash
# Phase 2 — first contact (§19.4): an unknown caller is refused with policy.first-contact-required,
# sends an introduction (which lands in a requests surface, never rings), receives a signed grant,
# and the next invite (carrying the grant id) rings through. Then the relay's mandatory rate limit.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --workspace
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-fc-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8443/dsip

$B/dsip identity init --dir "$D/carol" --name "Carol" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" --intro-limit 2 --intro-window 60 >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"

echo "════════ 1. bob enforces first contact; carol (unknown) calls → policy.first-contact-required, bob's phone never rings"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --first-contact --auto accept --script "sleep 14; grant; sleep 8; quit" >"$D/bob.log" 2>&1 & P=$!
sleep 1.5
$B/dsip call --identity "$D/carol" --relay $R --ca "$CA" --to "$BOB" --script "sleep 3; quit" | grep -E "^(→|←|  ◆|  ⏱|  ──)"

echo; echo "════════ 2. carol introduces herself; bob grants (scripted after a pause); carol holds the grant"
$B/dsip introduce --identity "$D/carol" --relay $R --ca "$CA" --to "$BOB" --purpose "We met at the mesh-networking meetup" --wait 25 | grep -E "^(→|←|  ◆|·)"

echo; echo "════════ 3. carol calls again — the invite carries the grant id — and bob answers"
$B/dsip call --identity "$D/carol" --relay $R --ca "$CA" --to "$BOB" --script "sleep 3; hangup; sleep 1; quit" | grep -E "^(→|←|  ◆|  ♫|contacts)"
wait $P
echo; echo "──── bob's side:"; grep -E "^(policy|→|←|  ◆|  ✉|  ♫)" "$D/bob.log"

echo; echo "════════ 4. relay rate limit (2 per 60 s in this demo): a third introduction from carol is refused with retry_after"
for i in 1 2 3; do
  $B/dsip introduce --identity "$D/carol" --relay $R --ca "$CA" --to "did:key:z6MkNobodyHereAtAll11111111111111111111111111" --wait 2 2>&1 | grep -E "^(·|  ◆|✗)" | sed "s/^/  [$i] /"
done
echo "──── relay:"; grep -oE "(queued introduction|rate).*" "$D/relay.log" | head -5
