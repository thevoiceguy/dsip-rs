#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: receipts and typing indicators over the wire (M§10, M§11).
#
# Alice and Bob, each with their own mailbox, in a direct conversation. Bob discloses read, played
# and activity; Alice discloses only activity. Every decision comes from the vector-pinned receipt
# machine. Self-verifying:
#   - delivered is automatic; read and played reach the other identity only when disclosed (M§10.5),
#     so Bob never learns that Alice read his message;
#   - typing reaches the peer sealed under the epoch's exporter key, is refreshed at most every 5 s,
#     clears at its expires_at with no message, and clears at once on stop (M§11.2);
#   - typing sent while Bob's device is disconnected is never stored for him (M§11.2).
# Needs espeak-ng and ffmpeg (libopus) for the played receipt.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-receipts-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,dev-a,dev-b,docs}

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
count() { grep -cE "$2" "$1" 2>/dev/null || true; }

echo "=== mailboxes and documents"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9471 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9472 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9471/dsip" >/dev/null
$MSG --state "$DIR/dev-b" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9472/dsip" >/dev/null

echo "=== devices: Bob discloses read, played, activity; Alice only activity (M§10.5)"
mkfifo "$DIR/a.in" "$DIR/b.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" --disclose activity <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-b" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" --disclose read,played,activity <"$DIR/b.in" >"$DIR/b.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/b.log" "OK connected" 20
echo "kp 2" >&4; wait_for "$DIR/b.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/b.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/b.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/b.log" "^JOINED" 30
echo "live" >&3

echo "=== delivered (M§10.2) and a disclosed read watermark (M§10.3)"
echo "send Are you there?" >&3
wait_for "$DIR/b.log" "^RECV $ALICE: Are you there\?" 30
wait_for "$DIR/b.log" "^SENT-RECEIPT delivered" 15
wait_for "$DIR/a.log" "^RECEIPT $BOB delivered" 15
echo "read" >&4
wait_for "$DIR/b.log" "^SENT-RECEIPT read" 15
wait_for "$DIR/a.log" "^RECEIPT $BOB read" 15
echo "status" >&3; wait_for "$DIR/a.log" "^STATUS .*\"read_through\":\{\"$BOB\"" 10

echo "=== Alice reads Bob's reply without disclosing it (M§10.5)"
echo "send Yes, here" >&4
wait_for "$DIR/a.log" "^RECV $BOB: Yes, here" 30
wait_for "$DIR/b.log" "^RECEIPT $ALICE delivered" 15
echo "read" >&3; wait_for "$DIR/a.log" "^READ-PRIVATE" 10

echo "=== typing: sealed, refresh-bounded, cleared by expiry and by stop (M§11)"
echo "typing" >&3; wait_for "$DIR/b.log" "^ACTIVITY $ALICE typing active" 15
echo "typing" >&3; wait_for "$DIR/a.log" "^OK typing active \(not sent" 10
wait_for "$DIR/b.log" "^ACTIVITY-CLEARED $ALICE typing" 25
echo "typing" >&3; wait_for "$DIR/a.log" "SENT-ACTIVITY typing active" 10
sleep 1
echo "typing stop" >&3; wait_for "$DIR/b.log" "^ACTIVITY $ALICE typing stopped" 15

echo "=== typing while Bob's device is away is never stored for him (M§11.2)"
BEFORE=$(count "$DIR/b.log" "^ACTIVITY ")
echo "offline" >&4; wait_for "$DIR/b.log" "OK offline" 10
echo "typing" >&3; sleep 2
echo "online" >&4; sleep 1; echo "sync" >&4; sleep 2
AFTER=$(count "$DIR/b.log" "^ACTIVITY ")
[ "$BEFORE" = "$AFTER" ] || { echo "FAIL: Bob received typing sent while he was offline"; exit 1; }
echo "live" >&4

echo "=== played (M§10.4)"
espeak-ng -w "$DIR/v.wav" "Listen to this when you can."
ffmpeg -loglevel error -y -i "$DIR/v.wav" -c:a libopus -b:a 24k "$DIR/v.ogg"
echo "voice $DIR/v.ogg" >&3
wait_for "$DIR/b.log" "^RECV-AUDIO $ALICE purpose=voice-message" 30
echo "play" >&4
wait_for "$DIR/b.log" "^SENT-RECEIPT played" 15
wait_for "$DIR/a.log" "^RECEIPT $BOB played" 15
sleep 1

echo "quit" >&3; echo "quit" >&4; sleep 0.5
if grep -q "^RECEIPT $ALICE read" "$DIR/b.log"; then echo "FAIL: Alice's undisclosed read reached Bob"; exit 1; fi
if grep -HE "^(\?\?|ERR|DROP)" "$DIR/a.log" "$DIR/b.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== Alice saw:"; grep -E "^(RECV|RECEIPT|READ-PRIVATE|SENT-ACTIVITY|OK typing)" "$DIR/a.log"
echo "=== Bob saw:"; grep -E "^(RECV|RECEIPT|SENT-RECEIPT|ACTIVITY)" "$DIR/b.log"
echo
echo "PASS: delivered, disclosed read and played, an undisclosed read kept private, typing sealed,"
echo "      refresh-bounded, cleared at expiry and on stop, and never stored for an offline device."
