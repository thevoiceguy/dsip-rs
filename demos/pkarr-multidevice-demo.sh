#!/usr/bin/env bash
# DSIP reachability hints on Pkarr for a multi-device identity (DHT Hints Profile §9.1; spec-gap 105 option (b)).
#
# Alice's identity key signs, once, a pointer listing her two devices — and then takes no further part: each device
# publishes its own zone, signed by its device key, with its endpoint and the delegation that makes it Alice's. Bob
# knows only Alice's identity did:key. Self-verifying:
#   1. the phone is up on relay R1: Bob resolves pointer → phone zone → delegation, and calls; the phone answers;
#   2. the phone goes away (its hourly hint lapses); the laptop comes up on relay R2: Bob's lookup skips the phone and
#      reaches the laptop, which answers;
#   3. the identity key signed exactly one packet in all of this.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-pkarr-multidevice-demo}; rm -rf "$D"; mkdir -p "$D"
PK_PORT=${PKARR_PORT:-15451}; P1=${R1_PORT:-8531}; P2=${R2_PORT:-8532}
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }
short() { echo "${1:0:16}…${1: -6}"; }  # as the call log abbreviates a DID
did() { python3 -c "import json;print(json.load(open('$1/identity.json'))['$2'])"; }

$B/dsip identity init --dir "$D/alice-phone" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/alice-laptop" --name "Alice" --controller-from "$D/alice-phone" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
ALICE=$(did "$D/alice-phone" identity); PHONE=$(did "$D/alice-phone" device); LAPTOP=$(did "$D/alice-laptop" device)

python3 demos/pkarr_relay.py "$PK_PORT" >"$D/pkarr.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do grep -q "^listening" "$D/pkarr.log" 2>/dev/null && break; sleep 0.2; done
PK=(--pkarr-relay "http://127.0.0.1:$PK_PORT")
for p in $P1 $P2; do $B/dsip-relay --listen 127.0.0.1:$p --state "$D/relay-$p" >"$D/relay-$p.log" 2>&1 & PIDS+=($!); done
for p in $P1 $P2; do for _ in $(seq 50); do [ -s "$D/relay-$p/cert.pem" ] && break; sleep 0.2; done; done
cat "$D/relay-$P1/cert.pem" "$D/relay-$P2/cert.pem" > "$D/ca.pem"; CA="$D/ca.pem"

echo "════════ Alice's identity key signs one pointer listing her phone then her laptop (valid 7 days), then goes offline"
$B/dsip pkarr-pointer --identity "$D/alice-phone" --device "$PHONE" --device "$LAPTOP" "${PK[@]}" | sed 's/^/  /'

echo "════════ 1. the phone is up on relay R1 and publishes its own zone (device key, with its delegation)"
$B/dsip answer --identity "$D/alice-phone" --relay wss://127.0.0.1:$P1/dsip --ca "$CA" "${PK[@]}" --publish-pkarr --pkarr-device \
  --hint-ttl 6 --auto accept --script "sleep 8; quit" >"$D/phone.log" 2>&1 & PH=$!; PIDS+=($PH)
for _ in $(seq 50); do grep -q "^hint .*published device zone" "$D/phone.log" && break; sleep 0.2; done
grep -E "^hint" "$D/phone.log" | head -1 | sed 's/^/  phone: /' | cut -c1-170
$B/dsip call --identity "$D/bob" --ca "$CA" "${PK[@]}" --to "$ALICE" --script "sleep 2; hangup; sleep 1; quit" >"$D/bob1.log" 2>&1 || true
grep -E "^(pointer|hint)" "$D/bob1.log" | sed 's/^/  bob: /' | cut -c1-170
grep -q "^hint .*pkarr device .*wss://127.0.0.1:$P1/dsip" "$D/bob1.log" || fail "1: Bob did not reach the phone's relay through the pointer"
grep -q "answered" "$D/bob1.log" || fail "1: the call was not answered"
grep -q "device $(short "$PHONE")" "$D/bob1.log" || fail "1: the call was not answered by the phone"
wait "$PH" || true

echo "════════ 2. the phone is gone (its 6 s hint lapses); the laptop comes up on relay R2"
sleep 7
$B/dsip answer --identity "$D/alice-laptop" --relay wss://127.0.0.1:$P2/dsip --ca "$CA" "${PK[@]}" --publish-pkarr --pkarr-device \
  --hint-ttl 6 --auto accept --script "sleep 8; quit" >"$D/laptop.log" 2>&1 & LP=$!; PIDS+=($LP)
for _ in $(seq 50); do grep -q "^hint .*published device zone" "$D/laptop.log" && break; sleep 0.2; done
$B/dsip call --identity "$D/bob" --ca "$CA" "${PK[@]}" --to "$ALICE" --script "sleep 2; hangup; sleep 1; quit" >"$D/bob2.log" 2>&1 || true
grep -E "^(pointer|hint)" "$D/bob2.log" | sed 's/^/  bob: /' | cut -c1-170
grep -q "^hint .*pkarr device .*: not usable (expired)" "$D/bob2.log" || fail "2: the phone's lapsed hint was not passed over"
grep -q "^hint .*pkarr device .*wss://127.0.0.1:$P2/dsip" "$D/bob2.log" || fail "2: Bob did not reach the laptop's relay"
grep -q "device $(short "$LAPTOP")" "$D/bob2.log" || fail "2: the call was not answered by the laptop"
wait "$LP" || true

echo "════════ 3. the identity key signed one packet; the devices signed their own"
N_ID=$( (grep -ch "signed by the identity key" "$D/phone.log" "$D/laptop.log" || true) | awk '{s+=$1} END {print s+0}')
[ "$N_ID" = 0 ] || fail "3: a device published with the identity key"
echo "  devices published $( (grep -ch 'published device zone' "$D/phone.log" "$D/laptop.log" || true) | awk '{s+=$1} END {print s+0}') zone packet(s), none with the identity key"

echo
echo "PASS: one identity-signed pointer, then each device's own hint with its delegation: Bob, knowing only Alice's"
echo "      did:key, reached her phone, and after the phone went away, her laptop — without her identity key online."
