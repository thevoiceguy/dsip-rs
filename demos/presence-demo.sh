#!/usr/bin/env bash
# Presence Profile (P§3–P§5): two of Bob's devices publish their own signed presence records to his relay (the
# authority); Alice watches his presence, verifies each record herself and combines them (P§4). Bob's phone is busy,
# so Bob is busy; the phone leaves, its record outlives the unbind by T-Presence-Grace and is then dropped, so Bob is
# what his laptop says; the laptop switches to a state newer than Alice's client knows, shown as available with the
# token raw (P§5). Self-verifying.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-presence-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8463/dsip
$B/dsip identity init --dir "$D/alice" --name Alice >/dev/null
$B/dsip identity init --dir "$D/bob-phone" --name Bob >/dev/null
$B/dsip identity init --dir "$D/bob-laptop" --name Bob --controller-from "$D/bob-phone" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob-phone/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8463 --state "$D/relay" --presence-grace 2 >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"
fail() { echo "FAIL: $*"; echo "--- watch"; cat "$D/watch.log"; exit 1; }

echo "=== Bob's phone publishes busy (it binds, so the relay knows Bob), his laptop away; Alice watches Bob"
$B/dsip presence publish --identity "$D/bob-phone" --relay $R --ca "$CA" --state busy --lifetime 60 --wait 8 >"$D/phone.log" 2>&1 & PHONE=$!
sleep 1
$B/dsip presence publish --identity "$D/bob-laptop" --relay $R --ca "$CA" --state away --then 13:focusing --lifetime 60 --wait 20 \
  >"$D/laptop.log" 2>&1 & LAPTOP=$!
sleep 1
$B/dsip presence watch --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --wait 18 >"$D/watch.log" 2>&1

grep -E "presence:|device |assertion:" "$D/watch.log" | sed 's/^ */  /'
grep -q "presence: busy  (from a device's signed record)" "$D/watch.log" || fail "Bob was not busy while his phone was"
grep -q "presence: away  (from a device's signed record)" "$D/watch.log" || fail "Bob did not become away once the phone's record was dropped"
grep -q "presence: available (shown raw: focusing)" "$D/watch.log" || fail "the unknown state was not shown as available with its token"
[ "$(grep -c '✓ verified' "$D/watch.log")" -ge 3 ] || fail "records were not verified by the watcher"
! grep -q "did not verify" "$D/watch.log" || fail "a record did not verify"
# order: busy, then away, then focusing
python3 - "$D/watch.log" <<'EOF' || fail "the states came in the wrong order"
import sys, re
seen = [m.group(1) for m in re.finditer(r"presence: (\S+)", open(sys.argv[1]).read())]
firsts = [s for i, s in enumerate(seen) if s not in seen[:i]]
assert firsts.index("busy") < firsts.index("away") < firsts.index("available"), firsts
EOF
wait $PHONE $LAPTOP
! grep -q "^← error" "$D/phone.log" "$D/laptop.log" || fail "the authority refused a record"
echo
echo "PASS: each device signed its own record; the watcher verified them and combined them (busy > away), the phone's"
echo "      record outlived its unbind by the grace and was then dropped, and an unknown state showed as available."
