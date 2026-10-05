#!/usr/bin/env bash
# DSIP Recording Profile (draft, C§5): a compliance recorder device in an end-to-end encrypted conversation.
#
# Alice and Bob talk. Bob's organisation then adds a recorder device to Bob's identity: its delegation carries
# dsip.record, so every member sees it in the MLS group and renders the conversation as recorded. Self-verifying:
# - the recorder joins the conversation only, never Bob's personal group: it gets no archive key, so the message sent
#   before it joined stays out of its archive;
# - Alice cannot send until she accepts; Bob, whose own identity is recorded, needs no acceptance;
# - the recorder cannot send (receive-only), and when a misbehaving one does, both members drop it;
# - after acceptance the recorder archives the conversation; when it is removed, the recording ends for everyone.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-recorder-device-demo}
ALICE=did:web:alice.example
BOB=did:web:bob.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-a,mbx-b,dev-a,dev-bp,dev-br,docs}
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
fail() { echo "FAIL: $*"; exit 1; }

echo "=== mailboxes, documents, Alice and Bob's phone"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9491 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9492 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9491/dsip" >/dev/null
$MSG --state "$DIR/dev-bp" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9492/dsip" >/dev/null
mkfifo "$DIR/a.in" "$DIR/bp.in" "$DIR/br.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-bp" --identity "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/bp.in" >"$DIR/bp.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/bp.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/bp.log" "OK connected" 20
echo "personal" >&4; wait_for "$DIR/bp.log" "^OK archive-key" 30
echo "kp 3" >&4; wait_for "$DIR/bp.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/bp.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/bp.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/bp.log" "^JOINED .* kind=direct" 30
echo "live" >&3
echo "=== before any recording"
echo "send A private word, before any recording" >&3
wait_for "$DIR/bp.log" "^RECV $ALICE: A private word, before any recording" 30

echo "=== Bob's organisation adds a recorder device to Bob's identity (its delegation carries dsip.record)"
start_recorder() { # extra flags
  $MSG --state "$DIR/dev-br" --identity "$BOB" --controller "$DIR/dev-bp/controller.key" --recorder "$@" "${RESOLVER[@]}" \
    --ca "$DIR/ca.pem" <"$DIR/br.in" >>"$DIR/br.log" 2>&1 & BR=$!
  exec 5>"$DIR/br.in"
}
start_recorder
wait_for "$DIR/br.log" "OK connected" 20
REC=$(grep -m1 "^DEVICE " "$DIR/br.log" | cut -d' ' -f2)
echo "kp 2" >&5; wait_for "$DIR/br.log" "OK uploaded" 10
echo "add-device $REC" >&4
wait_for "$DIR/bp.log" "^RECORDER $REC: conversations only" 20
wait_for "$DIR/bp.log" "^OK added device $REC to direct" 30
! grep -q "^OK added device $REC to personal" "$DIR/bp.log" || fail "the recorder joined the personal group"
echo "live" >&5
wait_for "$DIR/br.log" "^JOINED .* kind=direct" 30
wait_for "$DIR/a.log" "^RECORDED group=.* by recorder device $REC of $BOB — type accept-recording" 20
wait_for "$DIR/bp.log" "^RECORDED group=.* by recorder device $REC of $BOB \(this identity's own recording\)" 20
grep -m1 "^RECORDED" "$DIR/a.log" | sed 's/^/  alice: /'

echo "=== Alice cannot send before accepting; Bob (recorded himself) can; the recorder cannot send at all"
echo "send Is this recorded?" >&3; wait_for "$DIR/a.log" "^ERR recorded conversation: type accept-recording first" 10
echo "send Yes, by my firm, from here on" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Yes, by my firm, from here on" 30
echo "send I am the recorder" >&5; wait_for "$DIR/br.log" "^ERR a recorder device is receive-only" 10
echo "  alice: $(grep -m1 '^ERR recorded' "$DIR/a.log")"
echo "  recorder: $(grep -m1 '^ERR a recorder' "$DIR/br.log")"

echo "=== Alice accepts; the conversation goes on, and the recorder archives it"
echo "accept-recording" >&3; wait_for "$DIR/a.log" "^OK recording accepted" 10
echo "send Understood, go ahead" >&3; wait_for "$DIR/bp.log" "^RECV $ALICE: Understood, go ahead" 30
wait_for "$DIR/br.log" "^ARCHIVED $ALICE: Understood, go ahead" 30
wait_for "$DIR/br.log" "^ARCHIVED $BOB: Yes, by my firm, from here on" 30
python3 - "$DIR/dev-br/recorder-archive.jsonl" <<'PY' || fail "the archive is not what was disclosed"
import sys, json
lines = [json.loads(l) for l in open(sys.argv[1])]
texts = [l["object"].get("text") for l in lines]
assert "Understood, go ahead" in texts and "Yes, by my firm, from here on" in texts, texts
assert not any("before any recording" in (t or "") for t in texts), texts
print(f"  recorder archive: {len(lines)} message(s), none from before it joined")
PY
! grep -qE "^(ARCHIVE-KEY|HISTORY)" "$DIR/br.log" || fail "the recorder obtained Bob's archive"

echo "=== a misbehaving recorder sends anyway: both members drop it (C§5: receive-only)"
kill $BR; wait $BR 2>/dev/null || true
start_recorder --recorder-misbehave
wait_for "$DIR/br.log" "OK connected" 20
echo "live" >&5; sleep 2
echo "send Speaking for Bob" >&5
wait_for "$DIR/a.log" "^DROP recorder content from $REC" 30
wait_for "$DIR/bp.log" "^DROP recorder content from $REC" 30
! grep -q "Speaking for Bob" "$DIR/a.log" || fail "Alice rendered the recorder's message"
echo "  alice: $(grep -m1 '^DROP recorder' "$DIR/a.log")"

echo "=== Bob's firm removes the recorder: the recording ends for everyone"
echo "remove-device $REC" >&4
wait_for "$DIR/a.log" "^RECORDING ENDED group=" 30
wait_for "$DIR/bp.log" "^RECORDING ENDED group=" 30
echo "  alice: $(grep -m1 '^RECORDING ENDED' "$DIR/a.log")"

echo
echo "PASS: the recorder device was visible to every member, joined the conversation but never Bob's personal group"
echo "      (so nothing from before it joined reached it), held Alice's sending until she accepted, never spoke —"
echo "      a misbehaving one was dropped by both members — archived what was sent while disclosed, and its removal"
echo "      ended the recording for everyone."
