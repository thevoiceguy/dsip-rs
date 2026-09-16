#!/usr/bin/env bash
# DSIP: revoking a device delegation ends the device's access (spec-gap 57; M§4.3, M§7.3, M§12.4).
#
# Bob's laptop is a full member: delegated by Bob, in his personal group and in his conversation with
# Alice. The laptop is lost. Bob's phone revokes its delegation — a record signed by Bob's identity key,
# published in Bob's DID document and sent to Bob's mailbox. The mailbox closes the laptop's live
# connection at once and refuses its next hello; Alice's mailbox, reading Bob's document, refuses it too.
# Before the revocation Alice may not remove the laptop's leaf (only Bob may); after it, its delegation no
# longer verifies and she may (M§7.3), and Bob's phone removes it from his personal group and rotates the
# archive key (M§12.4). Nothing sent afterwards reaches the laptop. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-revocation-demo}
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
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}

echo "=== mailboxes, documents, devices"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9501 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9502 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9501/dsip" >/dev/null
$MSG --state "$DIR/dev-bp" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9502/dsip" >/dev/null
mkfifo "$DIR/a.in" "$DIR/bp.in" "$DIR/bl.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-bp" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/bp.in" >"$DIR/bp.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/bp.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/bp.log" "OK connected" 20

echo "=== Bob's phone: personal group; Alice and Bob talk"
echo "personal" >&4; wait_for "$DIR/bp.log" "^OK archive-key" 30
echo "kp 3" >&4; wait_for "$DIR/bp.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/bp.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/bp.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/bp.log" "^JOINED .* kind=direct" 30
echo "live" >&3

echo "=== Bob's laptop joins both groups"
$MSG --state "$DIR/dev-bl" --identity "$BOB" --controller "$DIR/dev-bp/controller.key" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  <"$DIR/bl.in" >"$DIR/bl.log" 2>&1 &
exec 5>"$DIR/bl.in"
wait_for "$DIR/bl.log" "OK connected" 20
LAPTOP=$(grep -m1 "^DEVICE " "$DIR/bl.log" | cut -d' ' -f2)
echo "kp 4" >&5; wait_for "$DIR/bl.log" "OK uploaded" 10
echo "add-device $LAPTOP" >&4; wait_for "$DIR/bp.log" "^OK added device .* to direct" 45
echo "live" >&5; wait_for "$DIR/bl.log" "^JOINED .* kind=direct" 30
echo "send Hello, both of Bob's devices" >&3
wait_for "$DIR/bl.log" "^RECV $ALICE: Hello, both of Bob's devices" 30

echo "=== while its delegation verifies, Alice may not remove the laptop's leaf (M§7.3)"
echo "remove-leaf $LAPTOP" >&3; wait_for "$DIR/a.log" "^ERR the leaf's delegation still verifies" 15

echo "=== the laptop is lost: Bob's phone revokes its delegation (spec-gap 57)"
echo "revoke-device $LAPTOP" >&4
wait_for "$DIR/bp.log" "^OK revoked $LAPTOP published=.*bob.json mailbox=accepted" 15
grep -q dsipDelegationRevocations "$DIR/docs/bob.json" || { echo "FAIL: the revocation is not in Bob's document"; exit 1; }
wait_for "$DIR/bl.log" "^DISCONNECTED by the mailbox" 15
wait_for "$DIR/mbx-b.log" "closed the binding of revoked device $LAPTOP" 5

echo "=== the laptop cannot come back, to Bob's mailbox or to Alice's (M§4.3)"
echo "online" >&5; wait_for "$DIR/bl.log" "^ERR hello refused: transport.hello-rejected delegation-revoked" 15
wait_for "$DIR/mbx-b.log" "hello rejected: delegation-revoked" 10
echo "introduce $ALICE Please let me back in" >&5
wait_for "$DIR/mbx-a.log" "hello rejected: delegation-revoked" 15
sleep 1
[ "$(grep -c '^ERR hello refused: transport.hello-rejected delegation-revoked' "$DIR/bl.log")" -ge 2 ] \
  || { echo "FAIL: Alice's mailbox did not refuse the revoked laptop"; exit 1; }
wait_for "$DIR/mbx-a.log" "hello rejected: delegation-revoked" 10

echo "=== now any member may remove the lapsed leaf; Bob's phone removes it everywhere and rotates the key (M§12.4)"
echo "remove-leaf $LAPTOP" >&3; wait_for "$DIR/a.log" "^OK removed lapsed leaf $LAPTOP" 30
wait_for "$DIR/bp.log" "^EPOCH [0-9]+ kind=direct by=$ALICE added=\[\] removed=\[\"unverified#$LAPTOP\"\]" 30
echo "remove-device $LAPTOP" >&4
wait_for "$DIR/bp.log" "^OK removed device .* from personal" 30
wait_for "$DIR/bp.log" "^OK archive-key" 30
echo "send Just your phone now" >&3
wait_for "$DIR/bp.log" "^RECV $ALICE: Just your phone now" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; echo "quit" >&5; sleep 0.5
if grep -q "Just your phone now" "$DIR/bl.log"; then echo "FAIL: the revoked laptop read a later message"; exit 1; fi
if grep -HE "^(\?\?|DROP)" "$DIR/a.log" "$DIR/bp.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== laptop:"; grep -E "^(JOINED|RECV|DISCONNECTED|ERR)" "$DIR/bl.log" | sed 's/^/  /'
echo "=== mailboxes:"; grep -hE "revoked|hello rejected|closed the binding" "$DIR"/mbx-*.log | sed 's/.*dsip_mailbox[^ ]* /  /'
echo
echo "PASS: a revoked device is disconnected, refused by its own and a foreign mailbox, removable by any member,"
echo "      removed from its identity's groups with the archive key rotated, and reads nothing afterwards."
