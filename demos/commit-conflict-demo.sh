#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: two members commit at the same epoch (M§6.5; spec-gap 58).
#
# MLS needs every member to apply the same commit per epoch; the group's hub accepts the first valid
# commit and refuses the rest. Bob disconnects, so he misses Alice's rekey; back online but not yet
# synced, he rekeys from the old epoch. The hub refuses him (mailbox.commit-conflict); his device
# discards the pending commit, syncs past Alice's, and re-proposes — accepted at the next epoch. Then
# the same two epochs behind (mailbox.stale-epoch). Afterwards both sides still read each other: no
# fork. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-commit-conflict-demo}
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
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -8 "$f"
  # the hub (Alice's mailbox) and Bob's mailbox tell where a fan-out stalled; CI shows the last 25 lines
  for m in mbx-a mbx-b; do echo "--- $DIR/$m.log"; tail -6 "$DIR/$m.log" | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-160; done
  return 1
}

echo "=== mailboxes, documents, devices, a direct conversation hubbed at Alice's mailbox"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9511 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9512 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9511/dsip" >/dev/null
$MSG --state "$DIR/dev-b" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9512/dsip" >/dev/null
mkfifo "$DIR/a.in" "$DIR/b.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-b" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/b.in" >"$DIR/b.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/b.log" "OK connected" 20
echo "kp 2" >&4; wait_for "$DIR/b.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/b.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/b.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/b.log" "^JOINED .* kind=direct" 30
echo "live" >&3

echo "=== one epoch behind: Bob misses Alice's rekey and rekeys from the old epoch (mailbox.commit-conflict)"
echo "offline" >&4; wait_for "$DIR/b.log" "OK offline" 10
echo "rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=2 " 30
echo "online" >&4; wait_for "$DIR/b.log" "OK connected" 15
echo "rekey" >&4
wait_for "$DIR/b.log" "^CONFLICT rekeyed: mailbox.commit-conflict at epoch 1" 30
wait_for "$DIR/b.log" "^EPOCH 2 kind=direct by=$ALICE" 30
wait_for "$DIR/b.log" "^REPROPOSE rekeyed attempt=2 epoch=2" 30
wait_for "$DIR/b.log" "^OK rekeyed epoch=3 " 30
wait_for "$DIR/a.log" "^EPOCH 3 kind=direct by=$BOB" 30

echo "=== two epochs behind (mailbox.stale-epoch)"
echo "offline" >&4; wait_for "$DIR/b.log" "OK offline" 10
echo "rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=4 " 30
echo "rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=5 " 30
echo "online" >&4; sleep 1
echo "rekey" >&4
wait_for "$DIR/b.log" "^CONFLICT rekeyed: mailbox.stale-epoch at epoch 3" 30
wait_for "$DIR/b.log" "^OK rekeyed epoch=6 " 30
wait_for "$DIR/a.log" "^EPOCH 6 kind=direct by=$BOB" 30

echo "=== no fork: both still read each other"
echo "send Still with me?" >&3; wait_for "$DIR/b.log" "^RECV $ALICE: Still with me\?" 30
echo "send Same epoch, same group" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Same epoch, same group" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; sleep 0.5
if grep -HE "^(\?\?|DROP|ERR)" "$DIR/a.log" "$DIR/b.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== Bob saw:"; grep -E "^(CONFLICT|REPROPOSE|OK rekeyed|EPOCH|RECV)" "$DIR/b.log" | sed 's/^/  /'
echo "=== the hub:"; grep -E "refused handshake|sequenced handshake" "$DIR/mbx-a.log" | sed 's/.*dsip_mailbox[^ ]* /  /'
echo
echo "PASS: concurrent commits resolved by the hub — the loser re-proposed after a conflict and after a stale epoch,"
echo "      and both members stayed in one group."
