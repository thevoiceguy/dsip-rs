#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: a group conversation across three identities and three mailboxes.
#
# Alice's mailbox hubs the group. Bob and Carol reach it only through their own mailboxes, which
# forward their deposits to the hub registered for the group (M§5.2); the hub fans every item out to
# every member's mailbox (M§6.5) and sends welcomes carrying the adder's own deposit as `origin`, which
# the new member's mailbox verifies against its grant (M§14.2). Membership changes while members are
# away: Bob adds Carol while Alice's device process is dead, and Alice removes Bob while Bob is
# disconnected. Self-verifying: every expected line must appear, no device may hit an item it cannot
# process, and Bob must not read anything sent after his removal.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-group-demo}
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

echo "=== three mailboxes"
declare -A PORT=([a]=9461 [b]=9462 [c]=9463) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL) NAME=([a]=alice [b]=bob [c]=carol)
for x in a b c; do
  $MBX --state "$DIR/mbx-$x" --listen 127.0.0.1:${PORT[$x]} --owner "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
    >"$DIR/mbx-$x.log" 2>&1 &
done
for x in a b c; do wait_for "$DIR/mbx-$x.log" "mailbox did:key" 20; done
cat "$DIR"/mbx-{a,b,c}/cert.pem > "$DIR/ca.pem"

echo "=== DID documents (M§4.2)"
for x in a b c; do
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" --write-doc "$DIR/docs/${NAME[$x]}.json" \
    --mailbox-did "$(cat "$DIR/mbx-$x/service.did")" --mailbox-uri "wss://127.0.0.1:${PORT[$x]}/dsip" >/dev/null
done

device() { # x generation
  local x=$1 g=$2
  mkfifo "$DIR/$x$g.in"
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/$x$g.in" >"$DIR/$x$g.log" 2>&1 &
  eval "PID_$x=$!"
}
echo "=== devices"
device a 1; exec 3>"$DIR/a1.in"
device b 1; exec 4>"$DIR/b1.in"
device c 1; exec 5>"$DIR/c1.in"
for x in a b c; do wait_for "$DIR/${x}1.log" "OK connected" 20; done

echo "=== first contact: Bob grants Alice, Carol grants Bob (M§14)"
echo "kp 2" >&4; wait_for "$DIR/b1.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/b1.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/b1.log" | cut -d' ' -f2 > "$DIR/grant-bob-to-alice.txt"
echo "kp 2" >&5; wait_for "$DIR/c1.log" "OK uploaded" 10
echo "grant $BOB" >&5; wait_for "$DIR/c1.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/c1.log" | cut -d' ' -f2 > "$DIR/grant-carol-to-bob.txt"
echo "live" >&4; echo "live" >&5

echo "=== Alice creates the group with Bob; her mailbox hubs it (M§7.3)"
echo "kp 1" >&3; wait_for "$DIR/a1.log" "OK uploaded" 10
echo "create group $BOB $DIR/grant-bob-to-alice.txt" >&3
wait_for "$DIR/a1.log" "^OK added $BOB" 30
wait_for "$DIR/b1.log" "^JOINED .*alice.*bob" 30
echo "live" >&3
echo "send Welcome to the group" >&3
wait_for "$DIR/b1.log" "^RECV $ALICE: Welcome to the group" 30

echo "=== Bob posts: his mailbox forwards to Alice's hub (M§5.2)"
echo "send Bob here" >&4
wait_for "$DIR/b1.log" "^OK sent seq=" 30
wait_for "$DIR/a1.log" "^RECV $BOB: Bob here" 30

echo "=== Alice's device process dies; Bob adds Carol meanwhile (M§7.3, M§14.2 origin)"
kill -9 "$PID_a"; wait "$PID_a" 2>/dev/null || true; exec 3>&-
echo "add $CAROL $DIR/grant-carol-to-bob.txt" >&4
wait_for "$DIR/b1.log" "^OK added $CAROL" 30
wait_for "$DIR/c1.log" "^JOINED .*alice.*bob.*carol" 30
echo "send Hi both, thanks Bob" >&5
wait_for "$DIR/b1.log" "^RECV $CAROL: Hi both, thanks Bob" 30

echo "=== Alice restarts: she applies Bob's commit, then reads Carol"
device a 2; exec 3>"$DIR/a2.in"
wait_for "$DIR/a2.log" "OK connected" 20
echo "live" >&3
wait_for "$DIR/a2.log" "^EPOCH 2 kind=group by=$BOB added=\[\"$CAROL#" 30
wait_for "$DIR/a2.log" "^RECV $CAROL: Hi both, thanks Bob" 30

echo "=== Bob disconnects; Alice removes him; Alice and Carol carry on"
echo "offline" >&4; wait_for "$DIR/b1.log" "OK offline" 10
echo "remove $BOB" >&3
wait_for "$DIR/a2.log" "^OK removed $BOB" 30
wait_for "$DIR/c1.log" "^EPOCH 3 kind=group by=$ALICE added=\[\] removed=\[\"$BOB#" 30
echo "send Just the two of us now" >&3
wait_for "$DIR/c1.log" "^RECV $ALICE: Just the two of us now" 30

echo "=== Bob returns and learns he was removed"
echo "online" >&4; wait_for "$DIR/b1.log" "OK connected.*" 15
echo "sync" >&4
wait_for "$DIR/b1.log" "^REMOVED from .* by=$ALICE" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
if grep -q "Just the two of us now" "$DIR/b1.log"; then
  echo "FAIL: Bob read a message sent after his removal"; exit 1
fi
if grep -HE "^(\?\?|ERR)" "$DIR"/[abc][12].log; then
  echo "FAIL: a device hit an item it could not process"; exit 1
fi
for x in a b c; do
  echo "=== ${NAME[$x]}'s devices saw:"
  grep -hE "^(JOINED|RECV|EPOCH|REMOVED|SELF|OK (added|removed|sent))" "$DIR/$x"[12].log 2>/dev/null
done
echo "=== hub (Alice's mailbox):"
grep -E "hub sequenced|hubbing" "$DIR/mbx-a.log" | sed 's/.*dsip_mailbox[^ ]* //'
echo
echo "PASS: three identities, three mailboxes, forwarding to the hub, welcomes proven by origin,"
echo "      an add while a member's device was dead, and a removal while the removed member was away."
