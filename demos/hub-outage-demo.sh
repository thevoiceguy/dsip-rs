#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: the hub cannot be reached (M§9.4; spec-gap 72).
#
# A three-member group is hubbed at a dedicated hub service, which then dies for good. Alice sends: her mailbox cannot
# hand the deposit to the hub and answers mailbox.hub-unreachable, so her device keeps the message pending and
# re-deposits the same bytes with the §13.2 backoff (1 s, doubling). Nothing is ever deposited into Bob's or Carol's
# mailboxes directly. When the hub has been unreachable for hub_timeout (24 h RECOMMENDED; seconds here) her device
# creates the successor group itself (M§7.5), re-adds Bob and Carol, and re-sends the pending message there; the
# others converge on it and the conversation carries on. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-hub-outage-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
CAROL=did:web:carol.example
HUB_TIMEOUT=${HUB_TIMEOUT:-12} # HUB_TIMEOUT=100000 is the "never gives up on the dead hub" mutation
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

echo "=== three member mailboxes and a hub service"
declare -A PORT=([a]=9561 [b]=9562 [c]=9563 [h]=9564) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL [h]=did:web:hub.example) NAME=([a]=alice [b]=bob [c]=carol)
for x in a b c h; do
  $MBX --state "$DIR/mbx-$x" --listen 127.0.0.1:${PORT[$x]} --owner "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
    >"$DIR/mbx-$x.log" 2>&1 &
  eval "PID_$x=$!"
done
for x in a b c h; do wait_for "$DIR/mbx-$x.log" "mailbox did:key" 20; done
cat "$DIR"/mbx-{a,b,c,h}/cert.pem > "$DIR/ca.pem"
for x in a b c; do
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" --write-doc "$DIR/docs/${NAME[$x]}.json" \
    --mailbox-did "$(cat "$DIR/mbx-$x/service.did")" --mailbox-uri "wss://127.0.0.1:${PORT[$x]}/dsip" >/dev/null
done
HUB=$(cat "$DIR/mbx-h/service.did")
for x in a b c; do
  mkfifo "$DIR/$x.in"
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" --hub-timeout "$HUB_TIMEOUT" \
    <"$DIR/$x.in" >"$DIR/$x.log" 2>&1 &
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
echo "move-hub $HUB wss://127.0.0.1:${PORT[h]}/dsip" >&3
for x in b c; do wait_for "$DIR/$x.log" "^HUB-MOVED .* to $HUB" 30; done
echo "send Hello via the hub service" >&3
wait_for "$DIR/b.log" "^RECV $ALICE: Hello via the hub service" 30; wait_for "$DIR/c.log" "^RECV $ALICE: Hello via the hub service" 30
wait_for "$DIR/a.log" "^RECEIPT $BOB delivered" 30; wait_for "$DIR/a.log" "^RECEIPT $CAROL delivered" 30
PRED=$(grep -m1 "hubbing group" "$DIR/mbx-h.log" | grep -oE "group [A-Za-z0-9_-]+ from epoch" | cut -d' ' -f2)

echo "=== the hub service dies and its state is gone"
kill -9 "$PID_h"; wait "$PID_h" 2>/dev/null || true; rm -rf "$DIR/mbx-h"

echo "=== Alice sends: pending, retried with backoff (M§9.4); nothing reaches Bob or Carol directly"
echo "send Anyone still there?" >&3
wait_for "$DIR/a.log" "^PENDING [A-Z0-9]+ retry_in=1$" 30
wait_for "$DIR/mbx-a.log" "unreachable: answering .* mailbox.hub-unreachable" 10
wait_for "$DIR/a.log" "^PENDING [A-Z0-9]+ retry_in=2$" 30
wait_for "$DIR/a.log" "^PENDING [A-Z0-9]+ retry_in=4$" 30
echo "send And this one waits behind it" >&3
wait_for "$DIR/a.log" "^PENDING [A-Z0-9]+ queued$" 10
if grep -q "^RECV $ALICE: Anyone still there" "$DIR/b.log" "$DIR/c.log"; then echo "FAIL: content reached a member without the hub"; exit 1; fi

echo "=== after hub_timeout (${HUB_TIMEOUT} s) Alice's device creates the successor itself and re-sends what was pending"
wait_for "$DIR/a.log" "^OUTAGE-SUCCESSOR group=$PRED pending=2" 60
wait_for "$DIR/a.log" "^SUCCESSOR created group=" 30
SUCC=$(grep -oE "^SUCCESSOR created group=[A-Za-z0-9_-]+" "$DIR/a.log" | cut -d= -f2)
wait_for "$DIR/a.log" "^RESENT [A-Z0-9]+ in=$SUCC seq=" 60
[ "$(grep -c "^RESENT " "$DIR/a.log")" = 2 ] || { echo "FAIL: expected both pending items re-sent"; grep "^RESENT" "$DIR/a.log"; exit 1; }
for x in b c; do
  wait_for "$DIR/$x.log" "^SUCCESSOR (joined|exists) group=$SUCC of=$PRED" 60
  wait_for "$DIR/$x.log" "^RECV $ALICE: Anyone still there\?" 60
  wait_for "$DIR/$x.log" "^RECV $ALICE: And this one waits behind it" 60
done
echo "send Back in business" >&5
wait_for "$DIR/a.log" "^RECV $CAROL: Back in business" 30; wait_for "$DIR/b.log" "^RECV $CAROL: Back in business" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
[ "$(grep -h "^SUCCESSOR created" "$DIR"/[abc].log | wc -l)" = 1 ] || { echo "FAIL: more than one successor was created"; exit 1; }
pending=$(grep -n "^PENDING" "$DIR/a.log" | head -1 | cut -d: -f1); succ=$(grep -n "^OUTAGE-SUCCESSOR" "$DIR/a.log" | cut -d: -f1)
[ "$pending" -lt "$succ" ] || { echo "FAIL: the outage was not pending before the successor"; exit 1; }
for x in b c; do
  n=$(grep -c "^RECV $ALICE: Anyone still there" "$DIR/$x.log"); [ "$n" = 1 ] || { echo "FAIL: $x received the pending message $n times"; exit 1; }
done
if grep -HE "^(\?\?|DROP|ERR)" "$DIR"/[abc].log; then echo "FAIL: a device hit an error"; exit 1; fi
echo "=== Alice saw:"; grep -E "^(PENDING|OUTAGE-SUCCESSOR|SUCCESSOR|RESENT|RECV)" "$DIR/a.log" | sed 's/^/  /'
echo "=== Alice's mailbox:"; grep -E "hub-unreachable" "$DIR/mbx-a.log" | head -3 | sed 's/.*dsip_mailbox[^ ]* /  /'
echo
echo "PASS: with the hub dead, the device kept its content pending, retried with the §13.2 backoff, created the"
echo "      successor group itself after hub_timeout, and re-sent the pending content there; the others converged."
