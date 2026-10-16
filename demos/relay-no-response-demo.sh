#!/usr/bin/env bash
# A forking relay tells the caller when nobody answers (§12.7 rule 6; spec-gaps 76, 132), over the wire.
#
# Self-verifying. Bob's device binds and then freezes (SIGSTOP): its connection stays open, but it never processes the
# invite. Once the invite has expired (the reference endpoint signs it for 30 s) the relay expires the silent leg and,
# with no leg left, tells Alice transport.no-response in its own voice; her call ends with that reason, before her own
# T-Establish (set to 60 s here) would have fired. Then the other half: a device that rings is not cut off when the
# invite expires; its call is still alive well past 30 s.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-no-response-demo}
rm -rf "$DIR"; mkdir -p "$DIR"
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug
S=127.0.0.1:9473

cleanup() { kill -CONT $(jobs -p) 2>/dev/null || true; kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }
wait_for() { # file pattern seconds
  for _ in $(seq $((${3:-20} * 5))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$2/ in $1"; tail -30 "$1"; return 1
}

$B/dsip identity init --dir "$DIR/alice" --name Alice >/dev/null
$B/dsip identity init --dir "$DIR/bob" --name Bob >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$DIR/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8483 --state "$DIR/relay" --status-listen $S >"$DIR/relay.log" 2>&1 &
wait_for "$DIR/relay.log" "status on http://$S" 20
U=wss://127.0.0.1:8483/dsip; CA="$DIR/relay/cert.pem"

echo "=== Bob's device binds, then freezes; Alice calls"
$B/dsip answer --identity "$DIR/bob" --relay $U --ca "$CA" --auto accept --script "sleep 90; quit" >"$DIR/bob1.log" 2>&1 &
BOB_PID=$!
wait_for "$DIR/relay.log" "bound device" 20
kill -STOP $BOB_PID
T0=$(date +%s)
$B/dsip call --identity "$DIR/alice" --relay $U --ca "$CA" --to "$BOB" --t-establish 60 --script "sleep 50; quit" >"$DIR/alice1.log" 2>&1 &
A1=$!
wait_for "$DIR/alice1.log" "ended reason=transport.no-response" 45
took=$(( $(date +%s) - T0 ))
[ $took -ge 30 ] && [ $took -le 40 ] || fail "no-response after ${took} s, expected just past the invite's 30 s"
grep -q "outcome: no leg responded" "$DIR/relay.log" || fail "the relay did not log the outcome"
echo "    ok: after ${took} s the relay said transport.no-response; Alice's call ended with it"
# one device key binds once: both of these go before the next call binds the same devices (§13.2 rebinding)
kill -CONT $BOB_PID; kill $BOB_PID $A1 2>/dev/null || true; wait $BOB_PID $A1 2>/dev/null || true

echo "=== a device that rings is not cut off when the invite expires"
$B/dsip answer --identity "$DIR/bob" --relay $U --ca "$CA" --auto none --script "sleep 50; quit" >"$DIR/bob2.log" 2>&1 &
sleep 2
$B/dsip call --identity "$DIR/alice" --relay $U --ca "$CA" --to "$BOB" --t-establish 60 --script "sleep 42; hangup; sleep 1; quit" >"$DIR/alice2.log" 2>&1 &
A=$!
wait_for "$DIR/alice2.log" "progress" 15
sleep 38
grep -q "transport.no-response" "$DIR/alice2.log" && fail "a ringing leg was expired with the invite"
[ "$(curl -sf "http://$S/status" | python3 -c "import json,sys; print(json.load(sys.stdin)['sessions']['ringing'])")" = 1 ] \
  || fail "the ringing session is not ringing at ~40 s"
echo "    ok: still ringing ~40 s after the invite (its 30 s expiry passed); the caller hangs up"
wait $A || true
ended=$(curl -sf "http://$S/status" | python3 -c "import json,sys; print(json.load(sys.stdin)['sessions']['ended_total'])")
echo "    ok: sessions ended so far: $ended"

echo
echo "PASS: a silent leg expires with its invite and the caller hears transport.no-response; a ringing leg rings on"
