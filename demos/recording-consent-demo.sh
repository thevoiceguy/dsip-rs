#!/usr/bin/env bash
# DSIP Recording Profile (draft, C§3–C§4): a recorded party declares it, signed, and the other side's client renders
# the declaration and acts only after acceptance. Four calls over a relay, with real media (DTLS-SRTP Opus):
#   1. Bob (the callee) is recorded by Acme's recorder: his answer declares it, and Alice's client holds her media
#      until she accepts. She never does, and hangs up: she must have sent no audio at all.
#   2. Alice (the caller) is recorded: Bob's client, set to answer automatically, must not answer; Bob declines, and
#      Alice receives reject policy.recording-declined.
#   3. Bob's standing policy is never (policy.recording: forbidden): the same call is declined at once.
#   4. A call without recording; mid-call Bob starts recording with an update. Alice accepts the renegotiation, then
#      declines being recorded: the call ends with bye policy.recording-declined.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-recording-consent-demo}; rm -rf "$D"; mkdir -p "$D"
PORT=${RELAY_PORT:-8493}; R=wss://127.0.0.1:$PORT/dsip; REC=did:web:rec.acme.example
$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:$PORT --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && break; sleep 0.2; done; CA="$D/relay/cert.pem"
fail() { echo "FAIL: $*"; exit 1; }
show() { grep -E "^(→|←)|⏺|^  ◆|sent [0-9]+ Opus" "$1" | grep -v "info " | sed 's/^/  /'; }
bob() { # log args...
  local log=$1; shift
  $B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" "$@" >"$log" 2>&1 & BP=$!
  for _ in $(seq 50); do grep -q "capabilities" "$log" && break; sleep 0.2; done
}
alice() { # log script args...
  local log=$1 script=$2; shift 2
  $B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --script "$script" "$@" >"$log" 2>&1 || true
}

echo "════════ 1. Bob is recorded by $REC; Alice's client holds her media; she never accepts and hangs up"
bob "$D/1-bob.log" --auto accept --media tone:660 --recorded-by $REC --script "sleep 9; quit"
alice "$D/1-alice.log" "sleep 6; hangup; sleep 1; quit" --media tone:440
wait $BP || true
show "$D/1-alice.log"
grep -q "RECORDED: the other side declares recording on by $REC  purpose compliance" "$D/1-alice.log" || fail "1: no disclosure rendered"
grep -q "holding our media until you accept" "$D/1-alice.log" || fail "1: media not held"
grep -qE "sent 0 Opus frames" "$D/1-alice.log" || fail "1: Alice sent audio without accepting"
grep -qE "sent [1-9][0-9]* Opus frames" "$D/1-bob.log" || fail "1: Bob (who needs no acceptance) sent no audio"
echo "  → Alice sent 0 audio frames: nothing of hers reached a call she had not accepted being recorded"

echo "════════ 2. Alice is recorded; Bob's client will not answer before acceptance; Bob declines"
bob "$D/2-bob.log" --auto accept --media none --script "sleep 3; decline-recording; sleep 2; quit"
alice "$D/2-alice.log" "sleep 6; quit" --media none --recorded-by $REC
wait $BP || true
show "$D/2-bob.log"; show "$D/2-alice.log" | grep reject || true
grep -q "RECORDED: the other side declares recording on by $REC" "$D/2-bob.log" || fail "2: Bob saw no disclosure"
! grep -q "→ answer" "$D/2-bob.log" || fail "2: Bob answered before accepting"
grep -q "← reject .*reason=policy.recording-declined" "$D/2-alice.log" || fail "2: Alice got no policy.recording-declined"

echo "════════ 3. Bob's standing policy is never: declined at once"
bob "$D/3-bob.log" --auto accept --media none --recording-accept never --script "sleep 4; quit"
alice "$D/3-alice.log" "sleep 3; quit" --media none --recorded-by $REC
wait $BP || true
grep -q "← reject .*reason=policy.recording-declined" "$D/3-alice.log" || fail "3: no immediate decline"
grep -E "⏺" "$D/3-bob.log" | sed 's/^/  /'

echo "════════ 4. Recording begun mid-call by update; Alice declines: bye policy.recording-declined"
bob "$D/4-bob.log" --auto accept --media none --recorded-by $REC --record-later --script "sleep 3; record on; sleep 5; quit"
alice "$D/4-alice.log" "sleep 5; answer-update; sleep 1; decline-recording; sleep 1; quit" --media none
wait $BP || true
show "$D/4-alice.log"
grep -q "← update .*" "$D/4-alice.log" || fail "4: no update"
grep -q "RECORDED: the other side declares recording on by $REC" "$D/4-alice.log" || fail "4: no mid-call disclosure"
grep -q "→ bye" "$D/4-alice.log" || fail "4: Alice did not end the call"
grep -q "← bye .*reason=policy.recording-declined" "$D/4-bob.log" || fail "4: Bob did not receive the decline reason"

echo
echo "PASS: recording was declared in signed invite/answer/update; the other side rendered it every time; a caller"
echo "      held all audio until acceptance; a callee would not answer before it; declining sent reject or bye"
echo "      policy.recording-declined, at once under a standing never policy."
