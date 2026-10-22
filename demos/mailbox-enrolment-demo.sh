#!/usr/bin/env bash
# A mailbox with room for one enrolled identity (M§4.1; spec-gaps 115, 130), over the wire.
#
# The mailbox serves no configured owner and enrols at most one identity (--serve-any 1), with idle expiry on and a
# retention of a few seconds (--release-idle --mls-retention). The script is self-verifying: it fails unless Bob
# enrols with his first owner operation; Carol, arriving while the place is taken, is refused mailbox.not-served
# instead of being silently dropped; Bob's mailbox-config release: true is accepted, deletes what the mailbox held for
# him and closes his binding; Carol then enrols in the freed place; once no device of Carol's has said hello for
# longer than the retention, the mailbox releases her for idleness; and Bob, coming back, enrols afresh with nothing
# kept. The enrolment survives a mailbox restart.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-enrolment-demo}
BOB=did:web:bob.example
CAROL=did:web:carol.example
RETENTION=4
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx,dev-b,dev-bl,dev-c,docs}

cargo build -q -p dsip-mailbox
MBX=target/debug/dsip-mailbox
MSG=target/debug/dsip-msg
DOCS=("$DIR/docs/bob.json" "$DIR/docs/carol.json")
RESOLVER=(--resolver-file "${DOCS[0]}" --resolver-file "${DOCS[1]}")

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "--- $f"; tail -12 "$f"; echo "TIMEOUT waiting for /$pat/ in $f"; return 1
}
wait_more() { # file pattern count seconds: wait until the log holds more than `count` matching lines (one already
  # there from an earlier step must not count again)
  local f=$1 pat=$2 k=$3 n=${4:-20}
  for _ in $(seq $((n * 5))); do [ "$(grep -cE "$pat" "$f" 2>/dev/null || true)" -gt "$k" ] && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for a new /$pat/ in $f"; echo "--- $f"; tail -8 "$f"; return 1
}
seen() { grep -cE "$2" "$1" 2>/dev/null || true; } # file pattern: how many matching lines the log holds now
count() { grep -cE "$2" "$1" 2>/dev/null || true; }
wait_more() { # file pattern count-before seconds: wait until the pattern appears more often than before
  for _ in $(seq $(($4 * 5))); do [ "$(count "$1" "$2")" -gt "$3" ] && return 0; sleep 0.2; done
  tail -12 "$1"; echo "TIMEOUT waiting for another /$2/ in $1"; return 1
}

mailbox() {
  $MBX --state "$DIR/mbx" --listen 127.0.0.1:9461 --serve-any 1 --release-idle --mls-retention $RETENTION \
    "${RESOLVER[@]}" >>"$DIR/mbx.log" 2>&1 &
  MBX_PID=$!
}

echo "=== the mailbox: no configured owner, one place, idle expiry after ${RETENTION} s"
mailbox
wait_for "$DIR/mbx.log" "mailbox did:key" 20
MBX_DID=$(cat "$DIR/mbx/service.did")
cp "$DIR/mbx/cert.pem" "$DIR/ca.pem"
for who in bob carol; do
  id=did:web:$who.example
  $MSG --state "$DIR/dev-${who:0:1}" --identity "$id" --write-doc "$DIR/docs/$who.json" \
    --mailbox-did "$MBX_DID" --mailbox-uri "wss://127.0.0.1:9461/dsip" >/dev/null
done

device() { # who fifo log
  $MSG --state "$DIR/dev-${1:0:1}" --identity "did:web:$1.example" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$2" >>"$3" 2>&1 &
  LAST_PID=$!
}

echo "=== Bob enrols with his first owner operation"
mkfifo "$DIR/b.in" "$DIR/c.in" "$DIR/bl.in"
device bob "$DIR/b.in" "$DIR/b.log"; BOB_PID=$LAST_PID; exec 3>"$DIR/b.in"
wait_for "$DIR/b.log" "OK connected" 20
# Bob's laptop (the same identity, its own device key) binds before the phone enrols him: not yet served, so not
# registered at its hello
$MSG --state "$DIR/dev-bl" --identity "$BOB" --controller "$DIR/dev-b/controller.key" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  <"$DIR/bl.in" >>"$DIR/bl.log" 2>&1 &
LAPTOP_PID=$!; exec 5>"$DIR/bl.in"
wait_for "$DIR/bl.log" "OK connected" 20
echo "kp 2" >&3; wait_for "$DIR/b.log" "OK uploaded" 10
wait_for "$DIR/mbx.log" "enrolled $BOB \(serve-any 1/1\)" 10
echo "    ok: $BOB enrolled, the bound is full"

echo "=== the laptop, bound before the enrolment, is registered by its own owner operation (M§4.4)"
LAPTOP=$(grep -m1 "^DEVICE " "$DIR/bl.log" | cut -d' ' -f2)
# the answers come in order on the binding: once the mailbox has handled the sync after it, the upload's is out
echo "kp 2" >&5; echo "sync" >&5
wait_for "$DIR/mbx.log" "sync from $LAPTOP " 10; sleep 1
if grep -q "^ERR" "$DIR/bl.log"; then tail -3 "$DIR/bl.log"; echo "FAIL: the laptop was refused"; exit 1; fi
grep -q "enrolled $BOB " "$DIR/mbx.log" && [ "$(count "$DIR/mbx.log" "enrolled $BOB ")" = 1 ]
echo "    ok: the laptop's key packages accepted, one enrolment"
echo "quit" >&5; exec 5>&-; wait $LAPTOP_PID 2>/dev/null || true

echo "=== Carol, arriving while the place is taken, is refused mailbox.not-served (not dropped)"
device carol "$DIR/c.in" "$DIR/c.log"; CAROL_PID=$LAST_PID; exec 4>"$DIR/c.in"
wait_for "$DIR/c.log" "OK connected|ERR" 20
echo "sync" >&4
wait_for "$DIR/c.log" "ERR \"mailbox.not-served\"" 10
grep -q "not serving $CAROL" "$DIR/mbx.log"
echo "    ok: $(grep -m1 'ERR "mailbox.not-served"' "$DIR/c.log")"

echo "=== the enrolment survives a mailbox restart"
N=$(seen "$DIR/b.log" "OK connected")
kill $MBX_PID; wait $MBX_PID 2>/dev/null || true
mailbox
wait_for "$DIR/mbx.log" "restored state: 1 owner" 20
echo "    ok: $(grep 'restored state' "$DIR/mbx.log" | tail -1 | sed 's/.*restored/restored/')"
wait_more "$DIR/b.log" "OK connected" "$N" 30   # the devices reconnect on their own
sleep 3

echo "=== Bob releases: accepted, everything held for him deleted, his binding closed"
echo "release" >&3
wait_for "$DIR/mbx.log" "released $BOB \(owner\)" 10
grep "released $BOB (owner)" "$DIR/mbx.log" | sed 's/^.*released/    ok: released/'
kill $BOB_PID; exec 3>&-   # Bob's device stops

echo "=== Carol enrols in the freed place"
echo "sync" >&4
wait_for "$DIR/mbx.log" "enrolled $CAROL \(serve-any 1/1\)" 15
echo "    ok: $CAROL enrolled"

echo "=== Carol goes away; past the retention the mailbox releases her for idleness"
kill $CAROL_PID; exec 4>&-
wait_for "$DIR/mbx.log" "released $CAROL \(idle\)" $((RETENTION + 15))
echo "    ok: $(grep "released $CAROL (idle)" "$DIR/mbx.log" | sed 's/^.*released/released/')"

echo "=== Bob comes back and enrols afresh, with nothing kept"
before=$(count "$DIR/mbx.log" "enrolled $BOB ")
mkfifo "$DIR/b2.in"
device bob "$DIR/b2.in" "$DIR/b2.log"; exec 5>"$DIR/b2.in"
wait_for "$DIR/b2.log" "OK connected" 20
echo "sync" >&5
wait_more "$DIR/mbx.log" "enrolled $BOB " "$before" 10
echo "    ok: $BOB enrolled again"
echo "quit" >&5; exec 5>&-

echo
echo "PASS: one place in the bound; refused with a reason when full; released by the owner and for idleness; freed places reused"
