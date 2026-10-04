#!/usr/bin/env bash
# Private relay (§13.6): a relay serving only Bob. Outsiders still reach Bob — live or queued — but the relay carries
# nothing between outsiders, holds nothing for them, and refuses the queue budget's overflow (§13.3). Self-verifying.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-relay -p dsip-cli
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-private-relay-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8447/dsip
for n in alice bob carol; do $B/dsip identity init --dir "$D/$n" --name "$n" >/dev/null; done
did() { python3 -c "import json;print(json.load(open('$D/$1/identity.json'))['identity'])"; }
ALICE=$(did alice); BOB=$(did bob); CAROL=$(did carol)
$B/dsip-relay --listen 127.0.0.1:8447 --state "$D/relay" --serve "$BOB" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"
call() { # from to log
  $B/dsip call --identity "$D/$1" --relay $R --ca "$CA" --to "$2" --t-establish 4 --script "sleep 5; quit" >"$D/$3" 2>&1 || true
}
expect() { # log pattern what
  if grep -qE "$2" "$D/$1"; then echo "  ok: $3"; else echo "FAIL: $3"; echo "--- $1"; tail -20 "$D/$1"; exit 1; fi
}
refused() { grep -qE "reason=transport.routing-refused" "$D/$1"; }

echo "════════ 1. alice (not served) calls bob (served, online): it rings"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --script "sleep 8; quit" >"$D/bob.log" 2>&1 & P=$!
sleep 1; call alice "$BOB" alice1.log; wait $P
expect alice1.log "status=ringing" "an outsider reaches the served identity"
refused alice1.log && { echo "FAIL: refused a call to a served identity"; exit 1; }

echo "════════ 2. alice calls carol (both outsiders, carol online): refused"
$B/dsip answer --identity "$D/carol" --relay $R --ca "$CA" --script "sleep 8; quit" >"$D/carol.log" 2>&1 & P=$!
sleep 1; call alice "$CAROL" alice2.log; wait $P
expect alice2.log "reason=transport.routing-refused" "the relay carries nothing between outsiders"
grep -qE "← invite" "$D/carol.log" && { echo "FAIL: carol was rung"; exit 1; }

echo "════════ 3. alice calls bob while he is offline: queued for him (no refusal)"
call alice "$BOB" alice3.log
refused alice3.log && { echo "FAIL: refused to hold for a served identity"; exit 1; }
expect relay.log "queued invite for $BOB" "envelopes are held for the served identity"

echo "════════ 4. carol (offline) is called by bob: refused, nothing held for outsiders"
call bob "$CAROL" bob4.log
expect bob4.log "reason=transport.routing-refused" "nothing is held for an outsider"
grep -qE "queued invite for $CAROL" "$D/relay.log" && { echo "FAIL: held an envelope for an outsider"; exit 1; }

echo "════════ 5. alice introduces herself to carol (an outsider): dropped silently, no refusal (§19.4)"
$B/dsip introduce --identity "$D/alice" --relay $R --ca "$CA" --to "$CAROL" --purpose "hello" --wait 3 >"$D/alice5.log" 2>&1 || true
refused alice5.log && { echo "FAIL: a refused introduction is distinguishable"; exit 1; }
expect relay.log "private relay: refusing introduction from $ALICE for $CAROL" "dropped, indistinguishable from silence"
echo "PASS private relay"
