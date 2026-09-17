#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: blob replication to member mailboxes (M§8.4 rule 6; spec-gap 65).
#
# Alice sends Bob a voice message while his device is offline. The audio is an encrypted blob in Alice's mailbox; the
# deposit's manifest names it. Bob's mailbox (sync mode) fetches it on receipt, verifies the hash and size, keeps a
# copy, and names its own copy in the items it serves. Alice's mailbox then crashes: Bob's device comes back and plays
# the message from his own mailbox. With Alice's mailbox back, a replicated copy that has been damaged fails the
# device's hash check and the device falls back to the original; a fetch that finds nothing to serve is tried again
# until it succeeds; and a message larger than Bob's mailbox accepts is not replicated at all. Needs ffmpeg (libopus).
# Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-blob-replication-demo}
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
wait_nth() { # file pattern n seconds
  for _ in $(seq $(($4 * 5))); do [ "$(grep -cE "$2" "$1" || true)" -ge "$3" ] && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for match $3 of /$2/ in $1"; tail -20 "$1"; return 1
}

start_a() { $MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9571 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >>"$DIR/mbx-a.log" 2>&1 & MBX_A=$!; }
start_b() { $MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9572 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" "$@" >>"$DIR/mbx-b.log" 2>&1 & MBX_B=$!; }
crash() { kill -9 "$1"; wait "$1" 2>/dev/null || true; }

echo "=== two voice messages (Ogg Opus)"
ffmpeg -loglevel error -y -f lavfi -i "sine=frequency=440:duration=2" -c:a libopus -b:a 24k "$DIR/short.ogg"
ffmpeg -loglevel error -y -f lavfi -i "sine=frequency=550:duration=2" -c:a libopus -b:a 24k "$DIR/second.ogg"
ffmpeg -loglevel error -y -f lavfi -i "sine=frequency=660:duration=2" -c:a libopus -b:a 24k "$DIR/third.ogg"
ffmpeg -loglevel error -y -f lavfi -i "sine=frequency=330:duration=6" -c:a libopus -b:a 48k "$DIR/long.ogg"
SHORT_SHA=$(sha256sum "$DIR/short.ogg" | cut -d' ' -f1); LONG_SHA=$(sha256sum "$DIR/long.ogg" | cut -d' ' -f1)
LONG_SIZE=$(stat -c %s "$DIR/long.ogg")

echo "=== mailboxes, documents, a direct conversation hubbed at Alice's mailbox"
start_a; start_b
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9571/dsip" >/dev/null
$MSG --state "$DIR/dev-b" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9572/dsip" >/dev/null
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

echo "=== Bob is offline; Alice sends a voice message; Bob's mailbox replicates the blob on receipt"
echo "offline" >&4; wait_for "$DIR/b.log" "OK offline" 10
echo "voice $DIR/short.ogg" >&3; wait_for "$DIR/a.log" "^OK sent" 30
wait_for "$DIR/mbx-b.log" "replicated blob [0-9a-f]{64} \([0-9]+ bytes\) from https://127.0.0.1:9571/blobs/" 20

echo "=== Alice's mailbox crashes; Bob plays the message from his own mailbox"
crash "$MBX_A"
echo "live" >&4
wait_for "$DIR/b.log" "^RECV-AUDIO $ALICE purpose=voice-message .* from=https://127.0.0.1:9572/blobs/" 30
[ "$(grep -m1 '^RECV-AUDIO' "$DIR/b.log" | sed -E 's/.* sha256=([0-9a-f]+) .*/\1/')" = "$SHORT_SHA" ] || { echo "FAIL: Bob's audio differs from what Alice sent"; exit 1; }

echo "=== Alice's mailbox is back; Bob's copy of the next message is damaged: his device falls back to the original"
start_a; wait_for "$DIR/mbx-a.log" "restored state" 20
echo "offline" >&4; wait_nth "$DIR/b.log" "^OK offline" 2 45  # after a receipt to the crashed hub times out
echo "live" >&3; sleep 2
echo "voice $DIR/second.ogg" >&3; wait_nth "$DIR/a.log" "^OK sent" 2 30
wait_nth "$DIR/mbx-b.log" "replicated blob [0-9a-f]{64}" 2 20
COPY=$(grep "replicated blob" "$DIR/mbx-b.log" | tail -1 | grep -oE "blob [0-9a-f]{64}" | cut -d' ' -f2)
printf 'damaged' | dd of="$DIR/mbx-b/blobs/$COPY" bs=1 seek=100 conv=notrunc status=none
echo "live" >&4
wait_nth "$DIR/b.log" "^RECV-AUDIO $ALICE purpose=voice-message" 2 30
wait_for "$DIR/b.log" "^BLOB-SOURCE-REJECTED https://127.0.0.1:9572/blobs/$COPY: " 10
grep "^RECV-AUDIO" "$DIR/b.log" | tail -1 | grep -q "from=https://127.0.0.1:9571/blobs/$COPY" || { echo "FAIL: the damaged copy was not rejected in favour of the original"; exit 1; }

echo "=== a fetch that finds nothing to serve is tried again until the blob is there (spec-gap 67)"
crash "$MBX_B"
echo "voice $DIR/third.ogg" >&3; wait_nth "$DIR/a.log" "^OK sent" 3 30
THIRD=$(grep "^OK sent audio" "$DIR/a.log" | tail -1 | sed -E 's/.*blob=([0-9a-f]+).*/\1/')
mv "$DIR/mbx-a/blobs/$THIRD" "$DIR/third.blob"          # the origin has nothing to serve for it, for now
start_b; wait_nth "$DIR/mbx-b.log" "restored state" 1 20
wait_for "$DIR/mbx-b.log" "not replicating https://127.0.0.1:9571/blobs/$THIRD: \"unavailable\" \(attempt 1, again in [0-9]+s\)" 40
mv "$DIR/third.blob" "$DIR/mbx-a/blobs/$THIRD"          # …and now it has
wait_for "$DIR/mbx-b.log" "replicated blob $THIRD " 60
echo "live" >&4
wait_nth "$DIR/b.log" "^RECV-AUDIO $ALICE purpose=voice-message" 3 60
grep "^RECV-AUDIO" "$DIR/b.log" | tail -1 | grep -q "from=https://127.0.0.1:9572/blobs/$THIRD" || { echo "FAIL: the retried copy was not used"; exit 1; }

echo "=== Bob's mailbox now takes blobs only up to 4 KiB, so the next one is not replicated"
echo "offline" >&4; wait_nth "$DIR/b.log" "^OK offline" 3 20; crash "$MBX_B"
start_b --max-blob-bytes 4096; wait_nth "$DIR/mbx-b.log" "restored state" 1 20
sleep 2
echo "voice $DIR/long.ogg" >&3; wait_nth "$DIR/a.log" "^OK sent" 4 30
wait_for "$DIR/mbx-b.log" "not replicating https://127.0.0.1:9571/blobs/[0-9a-f]+: \"too-large\"" 60
echo "live" >&4
wait_nth "$DIR/b.log" "^RECV-AUDIO $ALICE purpose=voice-message" 4 60
grep "^RECV-AUDIO" "$DIR/b.log" | tail -1 | grep -q "from=https://127.0.0.1:9571/blobs/" || { echo "FAIL: the second message did not come from the original"; exit 1; }
[ "$(grep '^RECV-AUDIO' "$DIR/b.log" | tail -1 | sed -E 's/.* sha256=([0-9a-f]+) .*/\1/')" = "$LONG_SHA" ] || { echo "FAIL: second audio differs"; exit 1; }
sleep 1

echo "quit" >&3; echo "quit" >&4; sleep 0.5
if grep -HE "^(\?\?|DROP)" "$DIR/a.log" "$DIR/b.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== Bob played:"; grep "^RECV-AUDIO" "$DIR/b.log" | sed -E 's/ file=[^ ]+//; s/^/  /'
echo "=== Bob's mailbox:"; grep -E "replicated blob|not replicating" "$DIR/mbx-b.log" | sed 's/.*dsip_mailbox[^ ]* /  /'
echo
echo "PASS: a member mailbox replicated a verified blob and served its own copy while the origin was down; a damaged copy"
echo "      failed the device's check and the original served it; a fetch with nothing to serve was retried until it"
echo "      succeeded; a blob over the limit ($LONG_SIZE bytes) stayed at the origin."
