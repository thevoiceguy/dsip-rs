#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: a welcome waits for the mailbox it is addressed to (M§6.5 rule 5; spec-gap 66).
#
# Alice adds Carol to a group while Carol's mailbox is down. The hub queues the welcome for Carol like any other
# fan-out and keeps retrying it, and holds back everything sequenced after it: until Carol's mailbox has the welcome
# it has no registration for the group and would refuse those items. Alice keeps talking to Bob meanwhile. When
# Carol's mailbox comes back the welcome lands, her device joins, and the messages she missed follow in order.
# A second copy of the welcome (a retry whose acknowledgement was lost) is a duplicate, not a second invitation.
# Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-welcome-retry-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
CAROL=did:web:carol.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,mbx-c,dev-a,dev-b,dev-c,docs}

cargo build -q -p dsip-mailbox
MBX=target/debug/dsip-mailbox
MSG=target/debug/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/alice.json" --resolver-file "$DIR/docs/bob.json" --resolver-file "$DIR/docs/carol.json")

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}
count() { grep -cE "$2" "$1" || true; }

echo "=== three mailboxes, documents, devices"
declare -A PORT=([a]=9581 [b]=9582 [c]=9583) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL) NAME=([a]=alice [b]=bob [c]=carol)
start_c() { $MBX --state "$DIR/mbx-c" --listen 127.0.0.1:9583 --owner "$CAROL" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >>"$DIR/mbx-c.log" 2>&1 & MBX_C=$!; }
for x in a b; do
  $MBX --state "$DIR/mbx-$x" --listen 127.0.0.1:${PORT[$x]} --owner "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-$x.log" 2>&1 &
done
start_c
for x in a b c; do wait_for "$DIR/mbx-$x.log" "mailbox did:key" 20; done
cat "$DIR"/mbx-{a,b,c}/cert.pem > "$DIR/ca.pem"
for x in a b c; do
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" --write-doc "$DIR/docs/${NAME[$x]}.json" \
    --mailbox-did "$(cat "$DIR/mbx-$x/service.did")" --mailbox-uri "wss://127.0.0.1:${PORT[$x]}/dsip" >/dev/null
  mkfifo "$DIR/$x.in"
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/$x.in" >"$DIR/$x.log" 2>&1 &
done
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"; exec 5>"$DIR/c.in"
for x in a b c; do wait_for "$DIR/$x.log" "OK connected" 20; done

echo "=== Alice's group with Bob, hubbed at Alice's mailbox; Carol's key package fetched ahead of the add"
echo "kp 2" >&4; wait_for "$DIR/b.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/b.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/b.log" | cut -d' ' -f2 > "$DIR/grant-bob.txt"
echo "kp 2" >&5; wait_for "$DIR/c.log" "OK uploaded" 10
echo "grant $ALICE" >&5; wait_for "$DIR/c.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/c.log" | cut -d' ' -f2 > "$DIR/grant-carol.txt"
echo "live" >&4; echo "live" >&5
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create group $BOB $DIR/grant-bob.txt" >&3; wait_for "$DIR/b.log" "^JOINED .* kind=group" 30
echo "live" >&3
echo "prefetch $CAROL $DIR/grant-carol.txt" >&3; wait_for "$DIR/a.log" "^OK prefetched a key package for $CAROL" 20

echo "=== Carol's mailbox goes down; Alice adds her anyway"
echo "offline" >&5; wait_for "$DIR/c.log" "OK offline" 10
kill -9 "$MBX_C"; wait "$MBX_C" 2>/dev/null || true
echo "add $CAROL $DIR/grant-carol.txt" >&3; wait_for "$DIR/a.log" "^OK added $CAROL" 30
wait_for "$DIR/mbx-a.log" "re-sending welcome seq [0-9]+ in .* to $CAROL" 30

echo "=== Alice and Bob carry on; what is sequenced after the add waits for Carol's mailbox"
echo "send Carol will catch up" >&3; wait_for "$DIR/b.log" "^RECV $ALICE: Carol will catch up" 30
echo "send Looking forward to it" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Looking forward to it" 30
sleep 2

echo "=== Carol's mailbox comes back: the welcome lands, then everything that waited, in order"
start_c; wait_for "$DIR/mbx-c.log" "restored state" 20
echo "online" >&5; wait_for "$DIR/c.log" "OK connected" 20
echo "live" >&5
wait_for "$DIR/c.log" "^JOINED .* kind=group" 60
wait_for "$DIR/c.log" "^RECV $ALICE: Carol will catch up" 60
wait_for "$DIR/c.log" "^RECV $BOB: Looking forward to it" 60
echo "send Made it" >&5
wait_for "$DIR/a.log" "^RECV $CAROL: Made it" 30; wait_for "$DIR/b.log" "^RECV $CAROL: Made it" 30
sleep 2

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
[ "$(count "$DIR/c.log" "^JOINED ")" = 1 ] || { echo "FAIL: Carol joined more than once (a retried welcome was stored twice)"; exit 1; }
[ "$(count "$DIR/mbx-a.log" "refused our deposit: \"mailbox.unknown-group\"")" = 0 ] || { echo "FAIL: an item reached Carol's mailbox before the welcome"; exit 1; }
if grep -HE "^(\?\?|DROP)" "$DIR"/[abc].log; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== Carol saw:"; grep -E "^(JOINED|RECV)" "$DIR/c.log" | sed 's/^/  /'
echo "=== the hub:"; grep -E "re-sending welcome|sequenced" "$DIR/mbx-a.log" | sed 's/.*dsip_mailbox[^ ]* /  /' | head -8
echo
echo "PASS: a welcome to a mailbox that was down was retried until it landed; nothing sequenced after it overtook it,"
echo "      and a retried welcome did not become a second invitation."
