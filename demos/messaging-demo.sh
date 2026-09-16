#!/usr/bin/env bash
# DSIP Messaging Profile 1.0 over the wire: two identities, two mailboxes, real MLS.
#
# Alice and Bob each have their own mailbox service. Alice's mailbox is the hub for the
# conversation, so every message crosses a mailbox-to-mailbox federation hop (M§6.5 rule 5).
# The script is self-verifying: it fails unless the text arrives end to end, and unless a message
# sent while Bob is disconnected reaches him when he returns (M§9.1).
#
# Offline here means "Bob's device drops its connection", not "Bob's device restarts": MLS state
# lives in the process, so restart-persistence is future work.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-messaging-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,dev-a,dev-b,docs}

cargo build -q -p dsip-mailbox
MBX=target/debug/dsip-mailbox
MSG=target/debug/dsip-msg
DOCS=("$DIR/docs/alice.json" "$DIR/docs/bob.json")
RESOLVER=(--resolver-file "${DOCS[0]}" --resolver-file "${DOCS[1]}")

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}

echo "=== mailboxes"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9451 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9452 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "listening|mailbox did:key" 20
wait_for "$DIR/mbx-b.log" "listening|mailbox did:key" 20
MBX_A=$(cat "$DIR/mbx-a/service.did"); MBX_B=$(cat "$DIR/mbx-b/service.did")
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"     # both self-signed roots
echo "alice mailbox $MBX_A"; echo "bob   mailbox $MBX_B"

echo "=== DID documents (discovery, M§4.2)"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "${DOCS[0]}" \
  --mailbox-did "$MBX_A" --mailbox-uri "wss://127.0.0.1:9451/dsip" >/dev/null
$MSG --state "$DIR/dev-b" --identity "$BOB" --write-doc "${DOCS[1]}" \
  --mailbox-did "$MBX_B" --mailbox-uri "wss://127.0.0.1:9452/dsip" >/dev/null

echo "=== devices"
mkfifo "$DIR/a.in" "$DIR/b.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-b" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/b.in" >"$DIR/b.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"
wait_for "$DIR/a.log" "OK connected" 20
wait_for "$DIR/b.log" "OK connected" 20

echo "=== Bob publishes KeyPackages and grants Alice first contact (M§5.5, M§14)"
echo "kp 3" >&4; wait_for "$DIR/b.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/b.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/b.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4

echo "=== Alice creates the conversation and sends"
echo "kp 2" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create $BOB $DIR/grant.txt" >&3; wait_for "$DIR/a.log" "^OK conversation" 30
wait_for "$DIR/b.log" "^JOINED" 30
echo "send Dinner at 7?" >&3
wait_for "$DIR/b.log" "^RECV .*Dinner at 7" 30

echo "=== store and forward: Bob disconnects, Alice sends, Bob returns (M§9.1)"
echo "offline" >&4; wait_for "$DIR/b.log" "OK offline" 10
echo "send Second one while you were away" >&3
sleep 1
echo "online" >&4; wait_for "$DIR/b.log" "OK connected" 15
echo "sync" >&4
wait_for "$DIR/b.log" "^RECV .*Second one while you were away" 30

echo "quit" >&3; echo "quit" >&4; sleep 0.5
echo
echo "=== Bob's device saw:"; grep -E "^(JOINED|RECV|EPOCH)" "$DIR/b.log"
echo "=== hub (Alice's mailbox) sequenced:"; grep -E "hubbing|federating" "$DIR/mbx-a.log" || true
echo
echo "PASS: two mailboxes, federated hub fan-out, MLS-encrypted text delivered live and after a disconnect."
