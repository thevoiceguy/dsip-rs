#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: a hub's fan-out to a member that has gone is bounded by mls_retention_s (M§4.4,
# M§6.5 rule 5; spec-gap 119).
#
# Alice adds Carol to a group while Carol's mailbox is down, and it never comes back. The hub queues the welcome and
# retries it, holding back what is sequenced after it (spec-gap 66). Alice's mailbox runs with an 8 s retention bound
# for the demo (30 days by default): once Carol has acknowledged nothing for that long, the hub drops everything it
# queued for her, welcome included, stops retrying, and lets the payloads go. Carol stays in the group's roster: a
# device of hers that had joined would re-join by external commit; one that never got the welcome must be added again.
# Alice and Bob carry on throughout. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-hub-retention-demo}
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
declare -A PORT=([a]=9591 [b]=9592 [c]=9593) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL) NAME=([a]=alice [b]=bob [c]=carol)
start_c() { $MBX --state "$DIR/mbx-c" --listen 127.0.0.1:9593 --owner "$CAROL" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >>"$DIR/mbx-c.log" 2>&1 & MBX_C=$!; }
declare -A RETAIN=([a]="--mls-retention 8" [b]="")   # only Alice's mailbox hubs the group
for x in a b; do
  $MBX --state "$DIR/mbx-$x" --listen 127.0.0.1:${PORT[$x]} --owner "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" ${RETAIN[$x]} >"$DIR/mbx-$x.log" 2>&1 &
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

echo "=== Carol's mailbox goes down for good; Alice adds her anyway"
echo "offline" >&5; wait_for "$DIR/c.log" "OK offline" 10
kill -9 "$MBX_C"; wait "$MBX_C" 2>/dev/null || true
echo "add $CAROL $DIR/grant-carol.txt" >&3; wait_for "$DIR/a.log" "^OK added $CAROL" 30
wait_for "$DIR/mbx-a.log" "re-sending welcome seq [0-9]+ in .* to $CAROL" 30

echo "=== Alice and Bob carry on; Carol acknowledges nothing"
echo "send Carol is not here yet" >&3; wait_for "$DIR/b.log" "^RECV $ALICE: Carol is not here yet" 30

echo "=== past the retention bound the hub drops Carol's queue and stops retrying"
wait_for "$DIR/mbx-a.log" "$CAROL acknowledged nothing for mls_retention_s: dropped its queue" 40
DROP_LINE=$(grep -n "acknowledged nothing for mls_retention_s" "$DIR/mbx-a.log" | head -1 | cut -d: -f1)
sleep 6
LATER=$(tail -n +"$((DROP_LINE + 1))" "$DIR/mbx-a.log" | grep -cE "re-sending (welcome|fan-out) seq [0-9]+ in .* to $CAROL" || true)
[ "$LATER" = 0 ] || { echo "FAIL: the hub kept retrying Carol after dropping her queue ($LATER retries)"; exit 1; }

echo "=== Alice and Bob are unaffected"
echo "send Still here" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Still here" 30

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
if grep -HE "^(\?\?|DROP)" "$DIR"/[ab].log; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== the hub:"; grep -E "re-sending welcome|acknowledged nothing" "$DIR/mbx-a.log" | sed 's/.*dsip_mailbox[^ ]* /  /' | head -8
echo
echo "PASS: a member that acknowledged nothing for mls_retention_s had its queue dropped, welcome included; the hub"
echo "      stopped retrying what it held (later items are queued afresh, under the same bound), and the others carried on."
