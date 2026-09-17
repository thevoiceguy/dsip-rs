#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: joining by external commit (M§6.8; spec-gap 62).
#
# Two situations where no welcome can come. Bob's new tablet appears while his phone — the only device that could add
# it — is offline: the tablet syncs Bob's mailbox, finds the latest GroupInfo of each of Bob's groups, and joins them by
# external commit; the hub and Alice's device each check that the joiner's identity is already a member (or that it is
# Bob's own personal group) before applying it. Then Bob's phone loses its whole MLS state: with the same device key it
# rejoins, and its external commit removes its own stale leaf. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-external-join-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,dev-a,dev-bp,dev-bt,docs}

cargo build -q -p dsip-mailbox
MBX=target/debug/dsip-mailbox
MSG=target/debug/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/alice.json" --resolver-file "$DIR/docs/bob.json")

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}

echo "=== mailboxes, documents, Alice and Bob's phone"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9551 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9552 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9551/dsip" >/dev/null
$MSG --state "$DIR/dev-bp" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9552/dsip" >/dev/null
mkfifo "$DIR/a.in" "$DIR/bp1.in" "$DIR/bp2.in" "$DIR/bt.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-bp" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/bp1.in" >"$DIR/bp1.log" 2>&1 &
PHONE_PID=$!
exec 3>"$DIR/a.in"; exec 4>"$DIR/bp1.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/bp1.log" "OK connected" 20
PHONE=$(grep -m1 "^DEVICE " "$DIR/bp1.log" | cut -d' ' -f2)

echo "=== Bob's personal group and a conversation with Alice"
echo "personal" >&4; wait_for "$DIR/bp1.log" "^OK archive-key" 30
echo "kp 2" >&4; wait_for "$DIR/bp1.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/bp1.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/bp1.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/bp1.log" "^JOINED .* kind=direct" 30
echo "live" >&3
echo "send Dinner at 7?" >&3; wait_for "$DIR/bp1.log" "^RECV $ALICE: Dinner at 7\?" 30
echo "send Yes" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Yes" 30
sleep 1

echo "=== the phone goes offline; Bob's new tablet has nobody to add it"
echo "offline" >&4; wait_for "$DIR/bp1.log" "OK offline" 10
$MSG --state "$DIR/dev-bt" --identity "$BOB" --controller "$DIR/dev-bp/controller.key" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  <"$DIR/bt.in" >"$DIR/bt.log" 2>&1 &
exec 5>"$DIR/bt.in"
wait_for "$DIR/bt.log" "OK connected" 20
TABLET=$(grep -m1 "^DEVICE " "$DIR/bt.log" | cut -d' ' -f2)
echo "sync" >&5; sleep 2
echo "available" >&5
wait_for "$DIR/bt.log" "^AVAILABLE group=.* kind=personal" 10; wait_for "$DIR/bt.log" "^AVAILABLE group=.* kind=direct" 10
PERSONAL=$(grep -m1 "^AVAILABLE .*kind=personal" "$DIR/bt.log" | sed -E 's/.*group=([^ ]+).*/\1/')
DIRECT=$(grep -m1 "^AVAILABLE .*kind=direct" "$DIR/bt.log" | sed -E 's/.*group=([^ ]+).*/\1/')

echo "=== the tablet joins both by external commit (M§6.8)"
echo "rejoin $PERSONAL" >&5; wait_for "$DIR/bt.log" "^OK rejoined .* kind=personal" 30
echo "rejoin $DIRECT" >&5; wait_for "$DIR/bt.log" "^OK rejoined .* kind=direct" 30
echo "live" >&5
wait_for "$DIR/a.log" "^EPOCH [0-9]+ kind=direct by=$BOB added=\[\"$BOB#$TABLET\"\] removed=\[\]" 30
echo "send Hello from Bob's tablet" >&5; wait_for "$DIR/a.log" "^RECV $BOB: Hello from Bob's tablet" 30
echo "send Welcome, tablet" >&3; wait_for "$DIR/bt.log" "^RECV $ALICE: Welcome, tablet" 30

echo "=== the phone loses its MLS state and rejoins with the same device key"
kill -9 "$PHONE_PID"; wait "$PHONE_PID" 2>/dev/null || true; exec 4>&-
rm -f "$DIR/dev-bp/device.sqlite"*
$MSG --state "$DIR/dev-bp" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/bp2.in" >"$DIR/bp2.log" 2>&1 &
exec 4>"$DIR/bp2.in"
wait_for "$DIR/bp2.log" "OK connected" 20
[ "$(grep -m1 "^DEVICE " "$DIR/bp2.log" | cut -d' ' -f2)" = "$PHONE" ] || { echo "FAIL: the phone came back with another key"; exit 1; }
echo "sync" >&4; sleep 3
echo "rejoin $DIRECT" >&4; wait_for "$DIR/bp2.log" "^OK rejoined .* kind=direct" 30
echo "live" >&4
wait_for "$DIR/a.log" "^EPOCH [0-9]+ kind=direct by=$BOB added=\[\"$BOB#$PHONE\"\] removed=\[\"$BOB#$PHONE\"\]" 30
wait_for "$DIR/bt.log" "^EPOCH [0-9]+ kind=direct by=$BOB added=\[\"$BOB#$PHONE\"\] removed=\[\"$BOB#$PHONE\"\]" 30
echo "send The phone is back" >&4
wait_for "$DIR/a.log" "^RECV $BOB: The phone is back" 30; wait_for "$DIR/bt.log" "^RECV $BOB: The phone is back" 30
echo "send Good" >&3
wait_for "$DIR/bp2.log" "^RECV $ALICE: Good" 30; wait_for "$DIR/bt.log" "^RECV $ALICE: Good" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
if grep -HE "^(DROP|ERR)" "$DIR"/a.log "$DIR"/bt.log "$DIR"/bp2.log; then echo "FAIL: a device refused or failed an item"; exit 1; fi
echo "=== Alice saw:"; grep -E "^(EPOCH|RECV)" "$DIR/a.log" | sed 's/^/  /'
echo "=== the hub (Alice's mailbox):"; grep -E "sequenced handshake" "$DIR/mbx-a.log" | sed 's/.*dsip_mailbox[^ ]* /  /'
echo
echo "PASS: a new device with no sibling online and a device that lost its state both joined by external commit from"
echo "      the latest GroupInfo, checked by the hub and by every member; the stale leaf was replaced."
