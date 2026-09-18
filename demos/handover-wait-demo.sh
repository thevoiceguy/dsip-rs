#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: a hub move whose old hub dies before it finishes delivering (M§7.4; spec-gap 71).
#
# A three-member group is hubbed at a dedicated hub service. Bob moves it to his own mailbox: the hub service orders
# the commit, fans it out to Alice's and Carol's mailboxes, and dies before Bob's mailbox gets its copy (fault injection:
# --drop-fanout-to). Bob's device has the commit (its own, from `accepted`) and names the new hub, so his mailbox now
# waits for the old hub's items through handover_seq — items that will never come. Under spec-gap 60 alone it would
# refuse its own hub forever. Under spec-gap 71 it holds the new hub off for handover_wait, then admits it: Bob's own
# message is stored, Alice's reply reaches him, and the group carries on. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-handover-wait-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
CAROL=did:web:carol.example
WAIT=${HANDOVER_WAIT:-8} # handover_wait for the demo (300 s RECOMMENDED); HANDOVER_WAIT=100000 is the "never releases" mutation
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,mbx-c,mbx-h,dev-a,dev-b,dev-c,docs}

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

echo "=== three member mailboxes (handover_wait ${WAIT} s) and a hub service that will never deliver to Bob's mailbox"
declare -A PORT=([a]=9551 [b]=9552 [c]=9553 [h]=9554) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL [h]=did:web:hub.example) NAME=([a]=alice [b]=bob [c]=carol)
for x in a b c; do
  $MBX --state "$DIR/mbx-$x" --listen 127.0.0.1:${PORT[$x]} --owner "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
    --handover-wait $WAIT >"$DIR/mbx-$x.log" 2>&1 &
done
for x in a b c; do wait_for "$DIR/mbx-$x.log" "mailbox did:key" 20; done
MBX_B=$(cat "$DIR/mbx-b/service.did")
$MBX --state "$DIR/mbx-h" --listen 127.0.0.1:${PORT[h]} --owner "${ID[h]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  --drop-fanout-to "$MBX_B" >"$DIR/mbx-h.log" 2>&1 &
PID_h=$!
wait_for "$DIR/mbx-h.log" "mailbox did:key" 20
cat "$DIR"/mbx-{a,b,c,h}/cert.pem > "$DIR/ca.pem"
for x in a b c; do
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" --write-doc "$DIR/docs/${NAME[$x]}.json" \
    --mailbox-did "$(cat "$DIR/mbx-$x/service.did")" --mailbox-uri "wss://127.0.0.1:${PORT[$x]}/dsip" >/dev/null
done
HUB=$(cat "$DIR/mbx-h/service.did")
for x in a b c; do
  mkfifo "$DIR/$x.in"
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/$x.in" >"$DIR/$x.log" 2>&1 &
done
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"; exec 5>"$DIR/c.in"
for x in a b c; do wait_for "$DIR/$x.log" "OK connected" 20; done

echo "=== Alice creates a group with Bob and Carol and moves it to the hub service"
echo "kp 3" >&4; wait_for "$DIR/b.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/b.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/b.log" | cut -d' ' -f2 > "$DIR/grant-bob.txt"
echo "kp 3" >&5; wait_for "$DIR/c.log" "OK uploaded" 10
echo "grant $ALICE" >&5; wait_for "$DIR/c.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/c.log" | cut -d' ' -f2 > "$DIR/grant-carol.txt"
echo "live" >&4; echo "live" >&5
echo "kp 3" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create group $BOB $DIR/grant-bob.txt" >&3; wait_for "$DIR/b.log" "^JOINED .* kind=group" 30
echo "live" >&3
echo "add $CAROL $DIR/grant-carol.txt" >&3; wait_for "$DIR/c.log" "^JOINED .* kind=group" 30
echo "send Hello before any move" >&3
wait_for "$DIR/b.log" "^RECV $ALICE: Hello before any move" 30; wait_for "$DIR/c.log" "^RECV $ALICE: Hello before any move" 30
# receipts are sequenced items too: let them land before the move so the hub service orders only Bob's commit
wait_for "$DIR/a.log" "^RECEIPT $BOB delivered" 30; wait_for "$DIR/a.log" "^RECEIPT $CAROL delivered" 30
echo "move-hub $HUB wss://127.0.0.1:${PORT[h]}/dsip" >&3
for x in b c; do wait_for "$DIR/$x.log" "^HUB-MOVED .* to $HUB" 30; done

echo "=== Bob moves the group to his own mailbox; the hub service orders it, delivers to Alice and Carol, not to Bob"
echo "move-hub" >&4
wait_for "$DIR/b.log" "^OK moved to $MBX_B epoch=[0-9]+ seq=[0-9]+" 30
MOVE_SEQ=$(grep -oE "^OK moved to .* seq=[0-9]+" "$DIR/b.log" | grep -oE "[0-9]+$")
wait_for "$DIR/mbx-h.log" "moves to hub \"$MBX_B\": ordered here" 10
wait_for "$DIR/mbx-h.log" "dropping fan-out to $MBX_B" 10
wait_for "$DIR/a.log" "^HUB-MOVED .* to $MBX_B at seq=$MOVE_SEQ" 30
wait_for "$DIR/c.log" "^HUB-MOVED .* to $MBX_B at seq=$MOVE_SEQ" 30
wait_for "$DIR/mbx-b.log" "hubbing group .* at seq $((MOVE_SEQ + 1))" 20

echo "=== the hub service dies for good"
kill -9 "$PID_h"; wait "$PID_h" 2>/dev/null || true; rm -rf "$DIR/mbx-h"

echo "=== Bob posts on his hub: Alice and Carol get it; his own mailbox refuses its own hub (the move never arrived)"
echo "send Anyone there?" >&4; wait_for "$DIR/b.log" "^OK sent seq=$((MOVE_SEQ + 1))" 30
wait_for "$DIR/a.log" "^RECV $BOB: Anyone there\?" 30; wait_for "$DIR/c.log" "^RECV $BOB: Anyone there\?" 30
wait_for "$DIR/mbx-b.log" "our own mailbox refused hub fan-out application seq $((MOVE_SEQ + 1)) .*mailbox.unknown-group" 20
echo "send Yes, on your hub" >&3; wait_for "$DIR/c.log" "^RECV $ALICE: Yes, on your hub" 30
if grep -q "^RECV $ALICE: Yes, on your hub" "$DIR/b.log"; then echo "FAIL: Bob received before the handover wait expired"; exit 1; fi

echo "=== after handover_wait the mailbox admits the new hub; the queued fan-out is retried and Bob catches up"
wait_for "$DIR/mbx-b.log" "handover wait expired for group .*: admitting the new hub without the old hub \"$HUB\"'s seqs \[$MOVE_SEQ\]" 60
wait_for "$DIR/b.log" "^RECV $ALICE: Yes, on your hub" 60
echo "send All three on the new hub" >&5
wait_for "$DIR/a.log" "^RECV $CAROL: All three on the new hub" 30; wait_for "$DIR/b.log" "^RECV $CAROL: All three on the new hub" 30
echo "rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=" 30
EPOCH=$(grep -oE "^OK rekeyed epoch=[0-9]+" "$DIR/a.log" | grep -oE "[0-9]+$")
wait_for "$DIR/b.log" "^EPOCH $EPOCH kind=group by=$ALICE" 30; wait_for "$DIR/c.log" "^EPOCH $EPOCH kind=group by=$ALICE" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
refused=$(grep -n "our own mailbox refused hub fan-out" "$DIR/mbx-b.log" | head -1 | cut -d: -f1)
expired=$(grep -n "handover wait expired" "$DIR/mbx-b.log" | head -1 | cut -d: -f1)
[ "$refused" -lt "$expired" ] || { echo "FAIL: the refusal did not precede the expiry"; exit 1; }
if grep -HE "^(\?\?|DROP|ERR)" "$DIR"/[abc].log; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== the hub service:"; grep -E "moves to hub|dropping fan-out" "$DIR/mbx-h.log" 2>/dev/null | sed 's/.*dsip_mailbox[^ ]* /  /' || true
echo "=== Bob's mailbox:"; grep -E "refused hub fan-out|handover wait expired|hubbing" "$DIR/mbx-b.log" | sed 's/.*dsip_mailbox[^ ]* /  /'
echo "=== Bob saw:"; grep -E "^(OK moved|OK sent|RECV|EPOCH)" "$DIR/b.log" | sed 's/^/  /'
echo
echo "PASS: the old hub died before delivering the move to the committer's own mailbox; the mailbox held the new hub"
echo "      off for handover_wait, then admitted it, and the queued fan-out (retried in-process) caught Bob up."
