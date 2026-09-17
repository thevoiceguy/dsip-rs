#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: successor groups when the hub is gone for good (M§7.5; spec-gap 61).
#
# A three-member group is hubbed at a dedicated hub service (moved there by commit, M§7.4). The hub dies and its
# state is lost, so nothing can be ordered. Bob and Carol each create a successor group at the same moment: same
# conversation, their own mailbox as hub, the last known roster re-added. KeyPackage fetches and welcomes are admitted
# because every member mailbox has the dead group registered. Every device checks a successor against the dead group
# (creator and members were members) and converges on the lowest group_id: whoever joined or created the other one
# leaves it. The conversation carries on in one group. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-successor-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
CAROL=did:web:carol.example
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
ulid_of() { python3 -c "import base64,sys; s=sys.argv[1]; print(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)).decode())" "$1"; }

echo "=== three member mailboxes and a hub service"
declare -A PORT=([a]=9541 [b]=9542 [c]=9543 [h]=9544) ID=([a]=$ALICE [b]=$BOB [c]=$CAROL [h]=did:web:hub.example) NAME=([a]=alice [b]=bob [c]=carol)
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
echo "move-hub $HUB wss://127.0.0.1:${PORT[h]}/dsip" >&3
for x in b c; do wait_for "$DIR/$x.log" "^HUB-MOVED .* to $HUB" 30; done
echo "send Hello via the hub service" >&3
wait_for "$DIR/b.log" "^RECV $ALICE: Hello via the hub service" 30; wait_for "$DIR/c.log" "^RECV $ALICE: Hello via the hub service" 30
wait_for "$DIR/b.log" "^SENT-RECEIPT delivered" 30; wait_for "$DIR/c.log" "^SENT-RECEIPT delivered" 30
wait_for "$DIR/a.log" "^RECEIPT $BOB delivered" 30; wait_for "$DIR/a.log" "^RECEIPT $CAROL delivered" 30
PRED=$(grep -m1 "hubbing group" "$DIR/mbx-h.log" | grep -oE "group [A-Za-z0-9_-]+ from epoch" | cut -d' ' -f2)

echo "=== the hub service dies and its state is gone"
kill -9 "$PID_h"; wait "$PID_h" 2>/dev/null || true; rm -rf "$DIR/mbx-h"

echo "=== Bob and Carol each create a successor at the same moment (M§7.5)"
echo "successor" >&4; echo "successor" >&5
wait_for "$DIR/b.log" "^SUCCESSOR (created|exists) group=" 30; wait_for "$DIR/c.log" "^SUCCESSOR (created|exists) group=" 30
sleep 8
CREATED=$(grep -hoE "^SUCCESSOR created group=[A-Za-z0-9_-]+" "$DIR/b.log" "$DIR/c.log" | cut -d= -f2)
[ -n "$CREATED" ] || { echo "FAIL: no successor was created"; exit 1; }
W=""; WU=""
for g in $CREATED; do u=$(ulid_of "$g"); if [ -z "$WU" ] || [[ "$u" < "$WU" ]]; then W=$g; WU=$u; fi; done
echo "    successors created: $(echo $CREATED | wc -w); the lowest is $W ($WU)"

echo "=== everyone converges on the lowest and the conversation carries on there"
for x in a b c; do
  # the creator of the winner never joins it; everyone else does
  grep -qE "^SUCCESSOR created group=$W" "$DIR/$x.log" || wait_for "$DIR/$x.log" "^SUCCESSOR (joined|exists) group=$W of=$PRED" 60
done
for g in $CREATED; do
  [ "$g" = "$W" ] && continue
  for x in a b c; do
    if grep -qE "^(JOINED|SUCCESSOR created group=$g)" "$DIR/$x.log" && grep -qE "^SUCCESSOR (created|joined) group=$g" "$DIR/$x.log"; then
      wait_for "$DIR/$x.log" "^LEFT group=$g .*converged elsewhere" 60
    fi
  done
done
sleep 2
echo "send Back in business" >&3
wait_for "$DIR/b.log" "^RECV $ALICE: Back in business" 30; wait_for "$DIR/c.log" "^RECV $ALICE: Back in business" 30
echo "send Same group for all of us" >&5
wait_for "$DIR/a.log" "^RECV $CAROL: Same group for all of us" 30; wait_for "$DIR/b.log" "^RECV $CAROL: Same group for all of us" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
for x in a b c; do
  n=$(grep -c "^RECV .*Back in business\|^RECV .*Same group for all of us" "$DIR/$x.log" || true)
  [ "$n" -le 2 ] || { echo "FAIL: $x received a message twice (two groups still live)"; exit 1; }
done
if grep -HE "^(\?\?|DROP|ERR)" "$DIR"/[abc].log; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
for x in a b c; do echo "=== ${NAME[$x]}:"; grep -E "^(SUCCESSOR|LEFT)" "$DIR/$x.log" | sed 's/^/  /'; done
echo
echo "PASS: with the hub gone, concurrent successor groups were created, checked against the dead group, and every"
echo "      member converged on the lowest group_id; the conversation continued in one group."
