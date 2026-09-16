#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: one identity, two devices (M§7.1, M§12).
#
# Bob's phone creates his personal group and archive key, then talks with Alice; everything it shows
# (Alice's messages and its own) is archived to Bob's mailbox. Bob's laptop is delegated by the same
# identity key and uploads KeyPackages; the phone adds it to the personal group (re-sending the archive
# key) and to the conversation. The laptop, syncing from null, holds the archive records it meets before
# the key, then shows that history once the key arrives, skips MLS items from before it joined, and
# ignores its sibling's welcomes. Both devices then take part live; the laptop's undisclosed read
# watermark reaches the phone through the personal group, so the phone sends nothing. Finally the phone
# removes the laptop from every group and rotates the archive key, and the laptop reads nothing after.
# Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-multidevice-demo}
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

echo "=== mailboxes and documents"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9481 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9482 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9481/dsip" >/dev/null
$MSG --state "$DIR/dev-bp" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9482/dsip" >/dev/null

echo "=== Alice and Bob's phone"
mkfifo "$DIR/a.in" "$DIR/bp.in" "$DIR/bl.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-bp" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/bp.in" >"$DIR/bp.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/bp.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/bp.log" "OK connected" 20

echo "=== the phone creates Bob's personal group and first archive key (M§7.1, M§12.1)"
echo "personal" >&4; wait_for "$DIR/bp.log" "^OK archive-key" 30
echo "kp 3" >&4; wait_for "$DIR/bp.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/bp.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/bp.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4

echo "=== a conversation, archived by the phone as it goes (M§12.2)"
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/bp.log" "^JOINED .* kind=direct" 30
echo "live" >&3
echo "send Dinner at 7?" >&3; wait_for "$DIR/bp.log" "^RECV $ALICE: Dinner at 7\?" 30
echo "send Yes, see you there" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Yes, see you there" 30
wait_for "$DIR/bp.log" "^ARCHIVED seq=.*" 15
sleep 1

echo "=== Bob's laptop: same identity, its own device key (M§12.3 steps 1–2)"
$MSG --state "$DIR/dev-bl" --identity "$BOB" --controller "$DIR/dev-bp/controller.key" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  <"$DIR/bl.in" >"$DIR/bl.log" 2>&1 &
exec 5>"$DIR/bl.in"
wait_for "$DIR/bl.log" "OK connected" 20
LAPTOP=$(grep -m1 "^DEVICE " "$DIR/bl.log" | cut -d' ' -f2)
echo "kp 4" >&5; wait_for "$DIR/bl.log" "OK uploaded" 10

echo "=== the phone adds the laptop: personal group first, archive key re-sent, then the conversation (M§12.3 steps 3–4)"
echo "add-device $LAPTOP" >&4
wait_for "$DIR/bp.log" "^OK added device .* to personal" 30
wait_for "$DIR/bp.log" "^OK re-sent 1 archive key" 30
wait_for "$DIR/bp.log" "^OK added device .* to direct" 30

echo "=== the laptop syncs from null: held archive, key, history, its own joins (M§12.3 step 5)"
echo "live" >&5
wait_for "$DIR/bl.log" "^JOINED .* kind=personal" 30
wait_for "$DIR/bl.log" "^ARCHIVE-KEY " 30
wait_for "$DIR/bl.log" "^HISTORY seq=[0-9]+ $ALICE: Dinner at 7\?" 30
wait_for "$DIR/bl.log" "^HISTORY seq=[0-9]+ $BOB: Yes, see you there" 30
wait_for "$DIR/bl.log" "^JOINED .* kind=direct" 30
grep -q "^HELD archive" "$DIR/bl.log" || { echo "FAIL: the laptop never met archive before its key (the hold path went unexercised)"; exit 1; }
grep -q "^SIBLING welcome" "$DIR/bl.log" || { echo "FAIL: the laptop never met its sibling's welcome"; exit 1; }
grep -q "^PREJOIN " "$DIR/bl.log" || { echo "FAIL: the laptop did not recognise MLS items from before it joined"; exit 1; }

echo "=== both devices live; Alice sees Bob's roster change (M§7.3)"
wait_for "$DIR/a.log" "^EPOCH [0-9]+ kind=direct by=$BOB added=\[\"$BOB#$LAPTOP\"\]" 30
echo "send Great" >&3
wait_for "$DIR/bp.log" "^RECV $ALICE: Great" 30
wait_for "$DIR/bl.log" "^RECV $ALICE: Great" 30
echo "send Sent from my laptop" >&5
wait_for "$DIR/a.log" "^RECV $BOB: Sent from my laptop" 30
wait_for "$DIR/bp.log" "^RECV $BOB: Sent from my laptop" 30

echo "=== an undisclosed read on the laptop reaches the phone through the personal group (M§10.5)"
echo "read" >&5
wait_for "$DIR/bl.log" "^SENT-RECEIPT read .*\(personal group\)" 15
wait_for "$DIR/bp.log" "^RECEIPT $BOB read .*\(personal group\)" 15
echo "read" >&4
wait_for "$DIR/bp.log" "^OK read through=.* \(0 to send\)" 10

echo "=== the laptop's timeline: archive and live, in seq order (M§8.5)"
echo "history" >&5; wait_for "$DIR/bl.log" "^OK history" 10
grep "^TIMELINE" "$DIR/bl.log" | sed 's/^/  /'
ORDER=$(grep "^TIMELINE" "$DIR/bl.log" | sed -E 's/^TIMELINE [0-9]+ [^ ]+: //' | tr '\n' '|')
[ "$ORDER" = "Dinner at 7?|Yes, see you there|Great|Sent from my laptop|" ] || { echo "FAIL: laptop timeline is $ORDER"; exit 1; }

echo "=== the phone removes the laptop everywhere and rotates the archive key (M§12.4)"
echo "remove-device $LAPTOP" >&4
wait_for "$DIR/bp.log" "^OK removed device .* from personal" 30
wait_for "$DIR/bp.log" "^OK removed device .* from direct" 30
wait_for "$DIR/bp.log" "^OK archive-key" 30
wait_for "$DIR/bl.log" "^REMOVED from .* kind=personal" 30
wait_for "$DIR/bl.log" "^REMOVED from .* kind=direct" 30
echo "send Just your phone now" >&3
wait_for "$DIR/bp.log" "^RECV $ALICE: Just your phone now" 30
sleep 2

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
if grep -q "Just your phone now" "$DIR/bl.log"; then echo "FAIL: the removed laptop read a later message"; exit 1; fi
NEWKEY=$(grep "^OK archive-key" "$DIR/bp.log" | tail -1 | cut -d' ' -f3)
if grep -q "^ARCHIVE-KEY $NEWKEY" "$DIR/bl.log"; then echo "FAIL: the removed laptop received the rotated archive key"; exit 1; fi
if grep -HE "^(\?\?|ERR|DROP)" "$DIR/a.log" "$DIR/bp.log" "$DIR/bl.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== laptop:"; grep -E "^(HELD|SIBLING|JOINED|ARCHIVE-KEY|HISTORY|PREJOIN|RECV|SENT-RECEIPT|REMOVED)" "$DIR/bl.log" | sed 's/^/  /'
echo
echo "PASS: personal group and archive key, a second device added with history from archive (held until its key),"
echo "      live on both, a private read synced to the sibling, and the device removed with the key rotated."
