#!/usr/bin/env bash
# The relay's store-and-forward queue survives a restart (§13.3; service-nodes plan S3). Bob is known to the relay
# but offline when Alice calls, so her invite is queued; the relay is killed (SIGKILL: no clean shutdown) and
# restarted on the same state directory. Self-verifying:
#   1. The restarted relay holds the invite, and delivers it when Bob's phone binds.
#   2. Killed and restarted again, it still knows Bob: a call to him, offline, is queued, not refused
#      `transport.unknown-recipient` as a call to an identity it never saw is.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-relay-restart-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8624/dsip
fail() { echo "FAIL: $*"; for f in "$D"/*.log; do echo "--- $f"; tail -15 "$f"; done; exit 1; }
plain() { sed 's/\x1b\[[0-9;]*m//g' "$D/relay.log"; }
wait_relay() { # pattern seconds
  for _ in $(seq $(($2 * 5))); do plain | grep -E >/dev/null "$1" && return 0; sleep 0.2; done
  fail "timeout waiting for /$1/ in the relay log"
}
RELAY=
relay() { $B/dsip-relay --listen 127.0.0.1:8624 --state "$D/relay" >>"$D/relay.log" 2>&1 & RELAY=$!; }
restart() { # count: the relay's (count)th start
  kill -9 $RELAY; wait $RELAY 2>/dev/null || true
  relay; for _ in $(seq 50); do [ "$(plain | grep -c "listening on")" -ge "$1" ] && break; sleep 0.2; done
  plain | grep "queue store:" | tail -1 | sed -E 's/.*dsip_relay[^ ]*: /  /'
}
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT
for who in alice bob carol; do $B/dsip identity init --dir "$D/$who" --name "$who" >/dev/null; done
id() { python3 -c "import json;print(json.load(open('$D/$1/identity.json'))['identity'])"; }
BOB=$(id bob); CAROL=$(id carol)
relay; wait_relay "listening on" 10; CA="$D/relay/cert.pem"

echo "════════ Bob's phone binds once (the relay knows him) and goes offline; Alice calls him"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --script "sleep 1; quit" >"$D/bob-0.log" 2>&1
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --media none --script "sleep 2; quit" >"$D/alice-1.log" 2>&1 || true
wait_relay "queued invite for $BOB" 5
plain | grep -oE "queued invite for .*" | sed 's/^/  /'

echo "════════ 1. The relay is killed and restarted: it still holds the invite, and Bob's phone gets it when it binds"
restart 2
plain | grep >/dev/null "queue store: 1 envelopes held for 1 recipients" || fail "1: the restarted relay does not hold the invite"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --auto none --media none --script "sleep 3; quit" >"$D/bob-1.log" 2>&1 || true
grep -E "^← invite" "$D/bob-1.log" | sed 's/^/  /'
grep -q "^← invite" "$D/bob-1.log" || fail "1: Bob did not get the queued invite"
plain | grep >/dev/null "deliver stored invite" || fail "1: the relay did not deliver from its store"
echo "  ok: delivered after the restart"

echo "════════ 2. Killed and restarted again: Bob, offline, is still known; Carol, never seen, is not"
restart 3
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --media none --script "sleep 2; quit" >"$D/alice-2.log" 2>&1 || true
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$CAROL" --media none --script "sleep 2; quit" >"$D/alice-3.log" 2>&1 || true
[ "$(plain | grep -c "queued invite for $BOB")" -ge 2 ] || fail "2: the call to Bob was not queued after the restart"
! grep -q "unknown-recipient" "$D/alice-2.log" || fail "2: Bob was unknown after the restart"
grep -q "unknown-recipient" "$D/alice-3.log" || fail "2: Carol, never seen, was not refused"
echo "  ok: Bob's call queued; Carol's refused transport.unknown-recipient"
echo "════════ relay restart demo passed"
