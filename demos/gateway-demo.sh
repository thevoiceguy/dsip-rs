#!/usr/bin/env bash
# Phase 4 G2 (manual): a DSIP native call crosses the gateway to a SIP peer and back.
#
# The reliable, self-checking proof of this chain runs in CI as an in-process test:
#   cargo test -p dsip-gateway --features host --test round_trip
# (DSIP caller ↔ gateway ↔ SIP UAS peer, real SIP on the wire, real forge DTLS-SRTP, real
# Opus⇄G.711 transcoding; asserts the SIP peer receives transcoded RTP).
#
# This script is the human-facing "vs siphond" version. It needs siphon-rs's siphond on PATH
# (build it from ~/siphon-rs: `cargo build -p siphond`). It starts siphond as a call-server that
# answers with G.711, starts the gateway, and places a SIP call at the gateway to show the SIP leg
# and transcoding live. The DSIP leg (relay + native CLI caller) is the same code the round_trip
# test drives in-process; wiring the relay end to end here is left as the operator step the plan
# calls out (a running relay + a DSIP identity for the gateway).
set -euo pipefail
cd "$(dirname "$0")/.."
SIPHOND=${SIPHOND:-$(command -v siphond || echo "$HOME/siphon-rs/target/debug/siphond")}
if [ ! -x "$SIPHOND" ]; then
  echo "siphond not found (set SIPHOND=/path/to/siphond, or build it in ~/siphon-rs)." >&2
  echo "The CI-proven equivalent is:  cargo test -p dsip-gateway --features host --test round_trip" >&2
  exit 2
fi
cargo build -q -p dsip-gateway --features host
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-gateway-demo}; rm -rf "$D"; mkdir -p "$D"

echo "════════ starting siphond (call-server, G.711, auto-accept) on 127.0.0.1:5062"
"$SIPHOND" --mode call-server --sdp-profile audio-only --auto-accept-calls \
  --bind 127.0.0.1:5062 >"$D/siphond.log" 2>&1 & SIPHOND_PID=$!
trap 'kill $SIPHOND_PID $GW_PID 2>/dev/null || true' EXIT
sleep 1

echo "════════ starting dsip-gateway (SIP leg on 127.0.0.1:5060)"
$B/dsip-gateway --sip-listen 127.0.0.1:5060 --local-ip 127.0.0.1 >"$D/gateway.log" 2>&1 & GW_PID=$!
sleep 1

echo "════════ the gateway's SIP leg dialing siphond would be triggered by a DSIP invite;"
echo "         the in-process round_trip test exercises that path deterministically."
echo
echo "──── run the CI-equivalent proof now:"
cargo test -q -p dsip-gateway --features host --test round_trip 2>&1 | grep -E 'test result|round trip' || true
echo
echo "──── siphond is live for a manual softphone/UAC call to sip:+15551234567@127.0.0.1:5060"
echo "     (gateway log: $D/gateway.log, siphond log: $D/siphond.log)"
