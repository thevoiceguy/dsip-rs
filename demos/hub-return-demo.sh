#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: the hub comes back (M§9.4; spec-gap 72).
#
# A three-member group is hubbed at a dedicated hub service, which stops. Alice sends twice: the first is pending and
# re-deposited with the §13.2 backoff, the second waits behind it. The hub service restarts with its state; the next
# retry is accepted and the outbox flushes the rest in order, each re-deposit's answer handled as it arrives. Bob and
# Carol receive each message exactly once, and Alice's next message goes out at once. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-hub-return-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
CAROL=did:web:carol.example
HUB_TIMEOUT=100000 # the outage never reaches the successor trigger
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
declare -A PORT=([a]=9601 [b]=9602 [c]=9603 [h]=9604) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL [h]=did:web:hub.example) NAME=([a]=alice [b]=bob [c]=carol)
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

echo "=== the hub service stops; its state is kept"
kill -9 "$PID_h"; wait "$PID_h" 2>/dev/null || true

echo "=== Alice sends twice: the first pending and retried with backoff (M§9.4), the second queued behind it"
echo "send Anyone still there?" >&3
wait_for "$DIR/a.log" "^PENDING [A-Z0-9]+ retry_in=1$" 30
wait_for "$DIR/a.log" "^PENDING [A-Z0-9]+ retry_in=2$" 30
echo "send And this one waits behind it" >&3
wait_for "$DIR/a.log" "^PENDING [A-Z0-9]+ queued$" 10

echo "=== the hub service is back: the head's retry is accepted and the rest follows in order"
$MBX --state "$DIR/mbx-h" --listen 127.0.0.1:${PORT[h]} --owner "${ID[h]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  >>"$DIR/mbx-h.log" 2>&1 &
for _ in $(seq 300); do [ "$(grep -c "^SENT-AFTER-OUTAGE " "$DIR/a.log")" -ge 2 ] && break; sleep 0.2; done
sent=$(grep -c "^SENT-AFTER-OUTAGE " "$DIR/a.log" || true)
[ "$sent" = 2 ] || { echo "FAIL: expected both pending items sent after the outage, saw $sent"; tail -10 "$DIR/a.log"; exit 1; }
first=$(grep -m1 "^PENDING .* retry_in=1$" "$DIR/a.log" | cut -d' ' -f2); second=$(grep -m1 "^PENDING .* queued$" "$DIR/a.log" | cut -d' ' -f2)
order=$(grep "^SENT-AFTER-OUTAGE " "$DIR/a.log" | cut -d' ' -f2 | tr '\n' ' ')
[ "$order" = "$first $second " ] || { echo "FAIL: sent out of order: $order (expected $first $second)"; exit 1; }
for x in b c; do
  wait_for "$DIR/$x.log" "^RECV $ALICE: Anyone still there\?" 60
  wait_for "$DIR/$x.log" "^RECV $ALICE: And this one waits behind it" 60
done
echo "send Back in business" >&3
wait_for "$DIR/a.log" "^OK sent seq=" 30
for x in b c; do wait_for "$DIR/$x.log" "^RECV $ALICE: Back in business" 30; done
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
for x in b c; do
  for m in "Anyone still there" "And this one waits behind it"; do
    n=$(grep -c "^RECV $ALICE: $m" "$DIR/$x.log"); [ "$n" = 1 ] || { echo "FAIL: $x received '$m' $n times"; exit 1; }
  done
done
if grep -q "^OUTAGE-SUCCESSOR" "$DIR/a.log"; then echo "FAIL: a successor was triggered"; exit 1; fi
if grep -HE "^(\?\?|DROP|ERR)" "$DIR"/[abc].log; then echo "FAIL: a device hit an error"; exit 1; fi
echo "=== Alice saw:"; grep -E "^(PENDING|SENT-AFTER-OUTAGE|OK sent)" "$DIR/a.log" | sed 's/^/  /'
echo
echo "PASS: the hub came back; the pending items went out in order, once each"
