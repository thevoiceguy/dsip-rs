#!/usr/bin/env bash
# The echo bot of the dsip-rs guide (crates/dsip-messenger/examples/echo_bot.rs), run against two mailboxes: the bot
# grants Alice first contact (M§14), Alice (dsip-msg) creates a conversation with it and writes, and the bot answers
# each text with the same text. Self-verifying: exits non-zero unless both answers arrive.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-echo-bot-demo}
ALICE=did:web:alice.example
BOT=did:web:bot.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,dev-a,docs}

cargo build -q -p dsip-mailbox -p dsip-cli
cargo build -q -p dsip-messenger --example echo_bot
MBX=target/debug/dsip-mailbox
MSG=target/debug/dsip-msg
ECHO=target/debug/examples/echo_bot
DOCS=("$DIR/docs/alice.json" "$DIR/docs/bot.json")
RESOLVER=(--resolver-file "${DOCS[0]}" --resolver-file "${DOCS[1]}")

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}

echo "=== mailboxes"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9611 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9612 --owner "$BOT" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "listening|mailbox did:key" 20
wait_for "$DIR/mbx-b.log" "listening|mailbox did:key" 20
MBX_A=$(cat "$DIR/mbx-a/service.did"); MBX_B=$(cat "$DIR/mbx-b/service.did")
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"     # both self-signed roots

echo "=== identities and DID documents (M§4.2)"
target/debug/dsip identity init --dir "$DIR/bot" --name "Echo bot" --did-web "$BOT" >/dev/null
$ECHO doc "$DIR/bot" "$MBX_B" "wss://127.0.0.1:9612/dsip" > "${DOCS[1]}"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "${DOCS[0]}" \
  --mailbox-did "$MBX_A" --mailbox-uri "wss://127.0.0.1:9611/dsip" >/dev/null

echo "=== the bot connects, publishes KeyPackages and grants Alice (M§5.5, M§14)"
$ECHO run "$DIR/bot" "$DIR/ca.pem" "${DOCS[@]}" -- "$ALICE" >"$DIR/bot.log" 2>&1 &
wait_for "$DIR/bot.log" "^GRANT " 20
grep -m1 "^GRANT " "$DIR/bot.log" | cut -d' ' -f2 > "$DIR/grant.txt"

echo "=== Alice creates the conversation and writes"
mkfifo "$DIR/a.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
exec 3>"$DIR/a.in"
wait_for "$DIR/a.log" "OK connected" 20
echo "kp 2" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "live" >&3   # the bot's answers are delivered as they arrive (M§5.4)
echo "create direct $BOT $DIR/grant.txt" >&3; wait_for "$DIR/a.log" "^OK conversation" 30
wait_for "$DIR/bot.log" "^JOINED" 30
echo "send hello bot" >&3
wait_for "$DIR/bot.log" "^RECV $ALICE: \"hello bot\"" 30
wait_for "$DIR/a.log" "^RECV .*$BOT.*hello bot" 30
echo "send and again" >&3
wait_for "$DIR/a.log" "^RECV .*$BOT.*and again" 30

echo "ECHO BOT DEMO PASSED"
