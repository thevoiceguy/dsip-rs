#!/usr/bin/env bash
# The relay and the mailbox verify did:web identities by fetching their documents over HTTPS (§7.2, §8.1), with no
# document files of their own. A relay serves the documents at https://localhost:8621/<name>/did.json, under its
# self-signed certificate, which the services trust with --did-web-ca. Self-verifying:
#   1. Alice (did:web) binds to a relay that fetches: it binds her device for her identity, and Bob's call to her
#      identity is answered.
#   2. The same on a relay started with --no-fetch-did-web: her hello is refused (`delegation-invalid`: without her
#      document her device's delegation cannot be verified, §7.4, §8.1), and she cannot bind.
#   3. Carol (did:web) enrols with a mailbox that fetches (M§4.1): her identity is enrolled, not her bare device.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay -p dsip-mailbox
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-did-web-demo}; rm -rf "$D"; mkdir -p "$D"/{www/alice,www/carol,mbx,dev-c}
HOST=localhost%3A8621; ALICE=did:web:$HOST:alice; CAROL=did:web:$HOST:carol
fail() { echo "FAIL: $*"; for f in "$D"/*.log; do echo "--- $f"; tail -20 "$f"; done; exit 1; }
plain() { sed 's/\x1b\[[0-9;]*m//g' "$1"; }
wait_for() { # file pattern seconds
  for _ in $(seq $(($3 * 5))); do plain "$1" | grep -qE "$2" && return 0; sleep 0.2; done
  fail "timeout waiting for /$2/ in $1"
}
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT

echo "════════ the document host, two relays (one fetching, one not) and a mailbox"
$B/dsip identity init --dir "$D/alice" --name Alice --did-web $ALICE >/dev/null
$B/dsip identity init --dir "$D/bob" --name Bob >/dev/null
cp "$D/alice/did.json" "$D/www/alice/did.json"
$B/dsip-relay --listen 127.0.0.1:8621 --state "$D/host" --www "$D/www" >"$D/host.log" 2>&1 &
for _ in $(seq 50); do [ -s "$D/host/cert.pem" ] && break; sleep 0.2; done
HOST_CA="$D/host/cert.pem"
$B/dsip-relay --listen 127.0.0.1:8622 --state "$D/relay" --did-web-ca "$HOST_CA" >"$D/relay.log" 2>&1 &
$B/dsip-relay --listen 127.0.0.1:8623 --state "$D/nofetch" --no-fetch-did-web >"$D/nofetch.log" 2>&1 &
$B/dsip-mailbox --state "$D/mbx" --listen 127.0.0.1:9621 --serve-any 1 --did-web-ca "$HOST_CA" >"$D/mbx.log" 2>&1 &
wait_for "$D/host.log" "listening on" 10; wait_for "$D/relay.log" "listening on" 10; wait_for "$D/nofetch.log" "listening on" 10
wait_for "$D/mbx.log" "mailbox did:key" 20

answer() { # name port: Alice answers on the relay at port
  $B/dsip answer --identity "$D/alice" --relay "wss://127.0.0.1:$2/dsip" --ca "$D/$1/cert.pem" --auto accept --media none \
    --script "sleep 6; quit" >"$D/$1-alice.log" 2>&1 & AP=$!
}
call() { # name port: Alice answers on the relay at port; Bob calls her identity there
  local n=$1 r=wss://127.0.0.1:$2/dsip ca=$D/$1/cert.pem
  answer "$n" "$2"; local ap=$AP
  wait_for "$D/$n.log" "bound device" 10
  $B/dsip call --identity "$D/bob" --relay "$r" --ca "$ca" --to $ALICE --did-document "$D/alice/did.json" --media none \
    --script "sleep 3; hangup; sleep 1; quit" >"$D/$n-bob.log" 2>&1 || true
  kill $ap 2>/dev/null || true; wait $ap 2>/dev/null || true
}

echo "════════ 1. A relay that fetches: Alice binds for $ALICE, and Bob's call reaches her"
call relay 8622
plain "$D/relay.log" | grep "did:web .*fetched\|bound device" | sed -E 's/.*dsip_(relay|transport)[^ ]*: /  /'
plain "$D/relay.log" | grep -q "did:web $ALICE: document fetched" || fail "1: the relay did not fetch Alice's document"
plain "$D/relay.log" | grep -q "for identity $ALICE" || fail "1: Alice's device was not bound for her identity"
grep -q "← answer" "$D/relay-bob.log" || fail "1: Alice did not answer"
echo "  ok: answered"

echo "════════ 2. A relay with --no-fetch-did-web: Alice's hello is refused"
answer nofetch 8623
wait_for "$D/nofetch.log" "hello rejected" 10; wait $AP 2>/dev/null || true
plain "$D/nofetch.log" | grep "hello rejected" | sed -E 's/.*dsip_relay[^ ]*: /  /'
plain "$D/nofetch.log" | grep -q "hello rejected: delegation-invalid" || fail "2: not refused for her delegation"
! plain "$D/nofetch.log" | grep -q "bound device" || fail "2: Alice bound without her document"
grep -q "transport.hello-rejected" "$D/nofetch-alice.log" || fail "2: Alice was not told"
echo "  ok: Alice told transport.hello-rejected"

echo "════════ 3. A mailbox that fetches: Carol enrols as $CAROL"
MBX_DID=$(cat "$D/mbx/service.did")
$B/dsip-msg --state "$D/dev-c" --identity $CAROL --write-doc "$D/www/carol/did.json" \
  --mailbox-did "$MBX_DID" --mailbox-uri wss://127.0.0.1:9621/dsip >/dev/null
mkfifo "$D/c.in"
$B/dsip-msg --state "$D/dev-c" --identity $CAROL --resolver-file "$D/www/carol/did.json" --ca "$D/mbx/cert.pem" \
  <"$D/c.in" >"$D/carol.log" 2>&1 & exec 3>"$D/c.in"
wait_for "$D/carol.log" "OK connected" 20
echo "kp 2" >&3; wait_for "$D/carol.log" "OK uploaded" 10
wait_for "$D/mbx.log" "enrolled $CAROL \(serve-any 1/1\)" 10
plain "$D/mbx.log" | grep "did:web .*fetched\|enrolled" | sed -E 's/.*dsip_(mailbox|transport)[^ ]*: /  /'
echo "quit" >&3; exec 3>&-
echo "  ok: enrolled from her fetched document"
echo "════════ did:web demo passed"
