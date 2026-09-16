#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: first contact over the wire (M§14.1, M§6.9, core §19.4).
#
# Alice has never talked to Bob and holds no grant. She sends him an introduction whose purpose is sealed
# with HPKE to the key agreement key in Bob's DID document; it travels as a deposit to Bob's mailbox
# (spec-gap 54), which rate-limits it and holds it. Bob's device shows it as a request — not a message —
# and opens the purpose; the purpose never appears in the signed envelope on the wire. Bob grants
# `dsip.message`; the grant travels back to Alice's mailbox; Alice's device holds it and presents it when
# she creates the conversation, with no grant passed out of band. Along the way: an introduction to an
# identity Bob's mailbox does not serve is accepted exactly like a delivered one (anti-enumeration), and a
# third introduction inside the window is refused policy.rate-limited with retry_after. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-messaging-first-contact-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
NOBODY=did:web:nobody.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,dev-a,dev-b,dev-n,docs}

cargo build -q -p dsip-mailbox
MBX=target/debug/dsip-mailbox
MSG=target/debug/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/alice.json" --resolver-file "$DIR/docs/bob.json" --resolver-file "$DIR/docs/nobody.json")

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}

echo "=== mailboxes: Bob's allows 2 introductions per sender per hour (§19.4)"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9491 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9492 --owner "$BOB" --intro-limit 2 "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
MB=$(cat "$DIR/mbx-b/service.did")
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9491/dsip" >/dev/null
$MSG --state "$DIR/dev-b" --identity "$BOB" --write-doc "$DIR/docs/bob.json" --mailbox-did "$MB" --mailbox-uri "wss://127.0.0.1:9492/dsip" >/dev/null
# An identity whose document names Bob's mailbox, which does not serve it.
$MSG --state "$DIR/dev-n" --identity "$NOBODY" --write-doc "$DIR/docs/nobody.json" --mailbox-did "$MB" --mailbox-uri "wss://127.0.0.1:9492/dsip" >/dev/null
grep -q '"keyAgreement"' "$DIR/docs/bob.json" || { echo "FAIL: Bob's document publishes no key agreement key"; exit 1; }

echo "=== devices (no grants exchanged out of band)"
mkfifo "$DIR/a.in" "$DIR/b.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-b" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/b.in" >"$DIR/b.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/b.log" "OK connected" 20
echo "kp 2" >&4; wait_for "$DIR/b.log" "OK uploaded" 10
echo "live" >&4; echo "live" >&3
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10

echo "=== without a grant, Alice cannot reach Bob (M§14.2)"
echo "create direct $BOB" >&3; wait_for "$DIR/a.log" "^ERR key-package-fetch refused: .*first-contact-required" 15

PURPOSE="We met at the Syracuse mesh meetup - following up about the antenna group buy"
echo "=== Alice introduces herself, the purpose sealed to Bob's key (M§14.1, M§6.9)"
echo "introduce $BOB $PURPOSE" >&3
wait_for "$DIR/a.log" "^OK introduction [0-9A-Z]+ to $BOB accepted sealed=true" 15
wait_for "$DIR/b.log" "^REQUEST [0-9A-Z]+ from $ALICE: \"$PURPOSE\" sealed=true purpose_on_wire=false" 15
REQ=$(grep -m1 "^REQUEST " "$DIR/b.log" | cut -d' ' -f2)
if grep -q "RECV" "$DIR/b.log"; then echo "FAIL: an introduction was rendered as a message"; exit 1; fi

echo "=== anti-enumeration and rate limits at the mailbox (§19.4)"
echo "introduce $NOBODY Hello whoever you are" >&3
wait_for "$DIR/a.log" "^OK introduction [0-9A-Z]+ to $NOBODY accepted sealed=true" 15
echo "introduce $BOB Sorry, me again" >&3
wait_for "$DIR/a.log" "^ERR introduction [0-9A-Z]+ refused: \"policy.rate-limited\" retry_after=[0-9]+" 15
sleep 1
[ "$(grep -c '^REQUEST ' "$DIR/b.log")" = 1 ] || { echo "FAIL: Bob should hold exactly one request"; exit 1; }

echo "=== Bob grants dsip.message; the grant reaches Alice through her mailbox"
echo "accept-request $REQ" >&4
wait_for "$DIR/b.log" "^OK granted $ALICE dsip.message for request $REQ" 15
wait_for "$DIR/a.log" "^GRANTED by $BOB scope=\[\"dsip.message\"\] request=$REQ" 15

echo "=== Alice creates the conversation, presenting the held grant"
echo "create direct $BOB" >&3
wait_for "$DIR/a.log" "^OK added $BOB" 30
wait_for "$DIR/b.log" "^JOINED .* kind=direct" 30
echo "send Thanks for accepting!" >&3
wait_for "$DIR/b.log" "^RECV $ALICE: Thanks for accepting!" 30

echo "quit" >&3; echo "quit" >&4; sleep 0.5
if grep -HE "^(\?\?|DROP)" "$DIR/a.log" "$DIR/b.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== Alice saw:"; grep -E "^(OK introduction|ERR introduction|ERR key-package|GRANTED|OK added)" "$DIR/a.log" | sed 's/^/  /'
echo "=== Bob saw:"; grep -E "^(REQUEST|OK granted|JOINED|RECV)" "$DIR/b.log" | sed 's/^/  /'
echo "=== Bob's mailbox:"; grep -E "held |accepted, not held|refused" "$DIR/mbx-b.log" | sed 's/.*dsip_mailbox[^ ]* /  /'
echo
echo "PASS: a sealed introduction delivered as a request, anti-enumeration and rate limiting at the mailbox,"
echo "      a dsip.message grant returned over the wire, and the conversation created with it."
