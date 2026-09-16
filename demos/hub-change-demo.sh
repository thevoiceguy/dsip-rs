#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: moving a group to another hub (M§7.4; spec-gap 60).
#
# Alice's mailbox hubs a group of three. Bob moves it to his own mailbox with a GroupContextExtensions commit:
# Alice's hub orders that commit and refuses the group from then on; Bob bootstraps his mailbox as the new hub with
# the GroupInfo and the commit's seq, so numbering continues. Each member's device, on processing the move, points its
# own mailbox at the new hub. Carol's device is offline throughout: the new hub's fan-out to her mailbox is refused
# until she returns, and retried. Back online, Carol posts before syncing — the old hub refuses with
# mailbox.unknown-group, her device syncs, sees the move, and re-sends to the new hub. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-hub-change-demo}
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

echo "=== three mailboxes, documents, devices"
declare -A PORT=([a]=9531 [b]=9532 [c]=9533) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL) NAME=([a]=alice [b]=bob [c]=carol)
for x in a b c; do
  $MBX --state "$DIR/mbx-$x" --listen 127.0.0.1:${PORT[$x]} --owner "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
    >"$DIR/mbx-$x.log" 2>&1 &
done
for x in a b c; do wait_for "$DIR/mbx-$x.log" "mailbox did:key" 20; done
cat "$DIR"/mbx-{a,b,c}/cert.pem > "$DIR/ca.pem"
for x in a b c; do
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" --write-doc "$DIR/docs/${NAME[$x]}.json" \
    --mailbox-did "$(cat "$DIR/mbx-$x/service.did")" --mailbox-uri "wss://127.0.0.1:${PORT[$x]}/dsip" >/dev/null
done
MBX_A=$(cat "$DIR/mbx-a/service.did"); MBX_B=$(cat "$DIR/mbx-b/service.did")
for x in a b c; do
  mkfifo "$DIR/$x.in"
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/$x.in" >"$DIR/$x.log" 2>&1 &
done
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"; exec 5>"$DIR/c.in"
for x in a b c; do wait_for "$DIR/$x.log" "OK connected" 20; done

echo "=== Alice creates a group with Bob and Carol, hubbed at her mailbox"
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
echo "add $CAROL $DIR/grant-carol.txt" >&3; wait_for "$DIR/c.log" "^JOINED .* kind=group" 30
echo "send Hello from the first hub" >&3
wait_for "$DIR/b.log" "^RECV $ALICE: Hello from the first hub" 30; wait_for "$DIR/c.log" "^RECV $ALICE: Hello from the first hub" 30

echo "=== Carol's device goes offline; Bob moves the group to his mailbox (M§7.4)"
echo "offline" >&5; wait_for "$DIR/c.log" "OK offline" 10
echo "move-hub" >&4
wait_for "$DIR/b.log" "^OK moved to $MBX_B epoch=[0-9]+ seq=[0-9]+" 30
MOVE_SEQ=$(grep -oE "^OK moved to .* seq=[0-9]+" "$DIR/b.log" | grep -oE "[0-9]+$")
wait_for "$DIR/mbx-a.log" "moves to hub \"$MBX_B\": ordered here" 10
wait_for "$DIR/mbx-b.log" "hubbing group .* at seq $((MOVE_SEQ + 1))" 20
wait_for "$DIR/a.log" "^HUB-MOVED .* to $MBX_B at seq=$MOVE_SEQ" 30

echo "=== the new hub orders; Carol's mailbox refuses its fan-out until her device follows the move"
echo "send Now via Bob's hub" >&3; wait_for "$DIR/a.log" "^OK sent seq=$((MOVE_SEQ + 1))" 30
wait_for "$DIR/b.log" "^RECV $ALICE: Now via Bob's hub" 30
wait_for "$DIR/mbx-b.log" "refused our deposit: \"mailbox.unknown-group\"" 20

echo "=== Carol returns and posts before syncing: the old hub refuses, she syncs, sees the move, re-sends"
echo "online" >&5; wait_for "$DIR/c.log" "OK connected" 15
echo "send Carol missed the move" >&5
wait_for "$DIR/c.log" "^RETRY send: \"?mailbox.unknown-group\"? from $MBX_A" 30
wait_for "$DIR/c.log" "^HUB-MOVED .* to $MBX_B at seq=$MOVE_SEQ" 30
wait_for "$DIR/c.log" "^OK sent seq=" 30
wait_for "$DIR/a.log" "^RECV $CAROL: Carol missed the move" 30
wait_for "$DIR/b.log" "^RECV $CAROL: Carol missed the move" 30
echo "live" >&5
wait_for "$DIR/c.log" "^RECV $ALICE: Now via Bob's hub" 60

echo "=== the new hub validates commits; the old hub orders nothing more"
echo "rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=" 30
EPOCH=$(grep -oE "^OK rekeyed epoch=[0-9]+" "$DIR/a.log" | grep -oE "[0-9]+$")
wait_for "$DIR/b.log" "^EPOCH $EPOCH kind=group by=$ALICE" 30; wait_for "$DIR/c.log" "^EPOCH $EPOCH kind=group by=$ALICE" 30
echo "send All on the new hub" >&5
wait_for "$DIR/a.log" "^RECV $CAROL: All on the new hub" 30; wait_for "$DIR/b.log" "^RECV $CAROL: All on the new hub" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
after=$(grep -oE "hub sequenced [a-z-]+ seq [0-9]+" "$DIR/mbx-a.log" | awk -v m="$MOVE_SEQ" '$5 > m' | wc -l)
[ "$after" = 0 ] || { echo "FAIL: the old hub sequenced $after items after the move"; exit 1; }
if grep -HE "^(\?\?|DROP|ERR)" "$DIR"/[abc].log; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== Carol saw:"; grep -E "^(RETRY|HUB-MOVED|OK sent|RECV|EPOCH)" "$DIR/c.log" | sed 's/^/  /'
echo "=== the old hub:"; grep -E "moves to hub|hub refused" "$DIR/mbx-a.log" | sed 's/.*dsip_mailbox[^ ]* /  /'
echo "=== the new hub:"; grep -E "hubbing|hub sequenced" "$DIR/mbx-b.log" | sed 's/.*dsip_mailbox[^ ]* /  /' | head -6
echo
echo "PASS: the group moved hubs by commit — ordered by the old hub, numbering continued at the new one, each mailbox"
echo "      followed its owner's device, and a member who missed the move was redirected by the old hub's refusal."
