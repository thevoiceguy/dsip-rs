#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: call history across devices, and receipts that survive onto a new device
# (M§13.3, M§12.2; spec-gaps 63, 64).
#
# Alice discloses read receipts. Bob's phone shows her delivered and read receipts on his message and archives them
# (they changed what it renders). Alice's call rings Bob's phone and goes unanswered: the phone reports a missed call
# to Bob's personal group, archived too. Bob adds a laptop: from archive it restores the conversation, Alice's
# receipts (without sending receipts of its own for old history) and the missed call. With both devices ringing,
# a call answered on the laptop leaves no event on either; one both miss is reported by both and shown once; one
# declined on the phone is recorded as declined. The laptop's timeline for Alice interleaves calls with messages.
# Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-call-history-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,dev-a,dev-bp,dev-bl,docs}

cargo build -q -p dsip-mailbox
MBX=target/debug/dsip-mailbox
MSG=target/debug/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/alice.json" --resolver-file "$DIR/docs/bob.json")

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -40 "$f"; return 1
}
sid() { python3 -c "import time,random; t=int(time.time()*1000); A='0123456789ABCDEFGHJKMNPQRSTVWXYZ'; n=(t<<80)|random.getrandbits(80); print(''.join(A[(n>>(5*i))&31] for i in reversed(range(26))))"; }

echo "=== mailboxes, documents, Alice (read receipts on) and Bob's phone"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9561 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9562 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9561/dsip" >/dev/null
$MSG --state "$DIR/dev-bp" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9562/dsip" >/dev/null
mkfifo "$DIR/a.in" "$DIR/bp.in" "$DIR/bl.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --disclose read "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-bp" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/bp.in" >"$DIR/bp.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/bp.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/bp.log" "OK connected" 20

echo "=== Bob's personal group and archive key; a conversation with Alice"
echo "personal" >&4; wait_for "$DIR/bp.log" "^OK archive-key" 30
echo "kp 3" >&4; wait_for "$DIR/bp.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/bp.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/bp.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/bp.log" "^JOINED .* kind=direct" 30
echo "live" >&3

echo "=== Alice's receipts on Bob's message change what the phone renders, so it archives them (M§12.2)"
echo "send Are we still on for 7?" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Are we still on for 7\?" 30
wait_for "$DIR/bp.log" "^RECEIPT $ALICE delivered" 30
echo "read" >&3; wait_for "$DIR/bp.log" "^RECEIPT $ALICE read" 30
sleep 2
[ "$(grep -c '^ARCHIVED seq=' "$DIR/bp.log")" -ge 3 ] || { echo "FAIL: the phone did not archive the receipts"; exit 1; }

echo "=== a call rings the phone and is not answered: a missed call in the personal group (M§13.3)"
S1=$(sid); sleep 2
echo "call-ended $S1 $ALICE 1 0 remote session.cancelled" >&4; wait_for "$DIR/bp.log" "^SENT-CALL-EVENT missed session=$S1" 20
sleep 2
echo "send Call me back" >&3; wait_for "$DIR/bp.log" "^RECV $ALICE: Call me back" 30
sleep 2

echo "=== Bob adds a laptop; it restores the conversation, Alice's receipts and the missed call from archive"
$MSG --state "$DIR/dev-bl" --identity "$BOB" --controller "$DIR/dev-bp/controller.key" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  <"$DIR/bl.in" >"$DIR/bl.log" 2>&1 &
exec 5>"$DIR/bl.in"
wait_for "$DIR/bl.log" "OK connected" 20
LAPTOP=$(grep -m1 "^DEVICE " "$DIR/bl.log" | cut -d' ' -f2)
echo "kp 4" >&5; wait_for "$DIR/bl.log" "OK uploaded" 10
echo "add-device $LAPTOP" >&4
wait_for "$DIR/bp.log" "^OK added device .* to direct" 30
echo "live" >&5
wait_for "$DIR/bl.log" "^HISTORY seq=[0-9]+ $BOB: Are we still on for 7\?" 30
wait_for "$DIR/bl.log" "^HISTORY-RECEIPT seq=[0-9]+ $ALICE delivered" 30
wait_for "$DIR/bl.log" "^HISTORY-RECEIPT seq=[0-9]+ $ALICE read" 30
wait_for "$DIR/bl.log" "^HISTORY-CALL missed $ALICE session=$S1" 30
wait_for "$DIR/bl.log" "^HISTORY seq=[0-9]+ $ALICE: Call me back" 30
wait_for "$DIR/bl.log" "^JOINED .* kind=direct" 30
sleep 2
echo "status" >&5; wait_for "$DIR/bl.log" "^STATUS " 10
grep "^STATUS " "$DIR/bl.log" | tail -1 | grep -q "\"read_through\":{\"$ALICE\"" || { echo "FAIL: the laptop did not restore Alice's read receipt"; exit 1; }
if grep -q "^SENT-RECEIPT delivered" "$DIR/bl.log"; then echo "FAIL: the laptop sent receipts for restored history"; exit 1; fi

echo "=== both devices ring: answered on the laptop → no event anywhere"
S2=$(sid)
echo "call-ended $S2 $ALICE 1 1 remote session.ended" >&5; wait_for "$DIR/bl.log" "^NO-CALL-EVENT session=$S2" 10
echo "call-ended $S2 $ALICE 1 0 remote session.answered-elsewhere" >&4; wait_for "$DIR/bp.log" "^NO-CALL-EVENT session=$S2" 10
sleep 2

echo "=== both miss one call: both report it, each device shows it once"
S3=$(sid)
echo "call-ended $S3 $ALICE 1 0 remote session.cancelled" >&4; echo "call-ended $S3 $ALICE 1 0 remote session.cancelled" >&5
for f in bp bl; do
  # whichever arrives second — its own report or its sibling's — is recognised as the same call
  wait_for "$DIR/$f.log" "^SENT-CALL-EVENT missed session=$S3" 20
  wait_for "$DIR/$f.log" "^DUP-CALL session=$S3|^SENT-CALL-EVENT missed session=$S3 \(already recorded\)" 20
done

echo "=== declined on the phone: the laptop records it as declined"
S4=$(sid); sleep 1
echo "call-ended $S4 $ALICE 1 0 local user.declined" >&4; wait_for "$DIR/bp.log" "^SENT-CALL-EVENT declined session=$S4" 20
wait_for "$DIR/bl.log" "^CALL declined inbound $ALICE session=$S4" 20
sleep 1

echo "=== the laptop's timeline with Alice (M§13.3)"
echo "timeline $ALICE" >&5; wait_for "$DIR/bl.log" "^PEER-TIMELINE $ALICE " 10
sleep 0.5
ORDER=$(sed -n "/^PEER-TIMELINE $ALICE/,\$p" "$DIR/bl.log" | grep -E "^  (MSG|CALL)" | sed -E 's/^  MSG [^:]+:[^:]+: /M:/; s/^  MSG .*: /M:/; s/^  CALL ([a-z]+) session=.*/C:\1/' | paste -sd'|')
echo "    $ORDER"
[ "$ORDER" = "M:Are we still on for 7?|C:missed|M:Call me back|C:missed|C:declined" ] || { echo "FAIL: timeline order $ORDER"; exit 1; }

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
if grep -HE "^(\?\?|ERR|DROP)" "$DIR/a.log" "$DIR/bp.log" "$DIR/bl.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
for f in bp bl; do
  n=$(grep -cE "^CALL .*session=$S3\$|^SENT-CALL-EVENT missed session=$S3\$" "$DIR/$f.log" || true)
  [ "$n" = 1 ] || { echo "FAIL: $f recorded the shared missed call $n times"; exit 1; }
done
echo
echo "PASS: missed and declined calls reached every device once (answered-elsewhere left none); receipts and call history"
echo "      were archived and restored onto a device added later, which sent nothing for old history."
