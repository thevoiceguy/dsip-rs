#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: a device that falls behind re-joins by itself (M§6.5, M§6.8; spec-gap 69).
#
# Bob's device is away while Alice rekeys and talks. His mailbox then loses an item — what `mls_retention_s` does to
# anything a device has not acknowledged in time — so when Bob comes back there is a seq gap. He holds the commit
# beyond it (and everything after), and because the gap cannot fill he re-joins the group by external commit, treats
# every seq he has seen as passed, and carries on: Alice renders his device joining, and the next message reaches him.
# Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-auto-rejoin-demo}
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

echo "=== mailboxes, documents, devices; Bob's device re-joins a gap after 5 s instead of the RECOMMENDED 300"
$MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9591 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >"$DIR/mbx-a.log" 2>&1 &
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9592 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >>"$DIR/mbx-b.log" 2>&1 & MBX_B=$!
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9591/dsip" >/dev/null
$MSG --state "$DIR/dev-b" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9592/dsip" >/dev/null
mkfifo "$DIR/a.in" "$DIR/b.in"
$MSG --state "$DIR/dev-a" --identity "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/a.in" >"$DIR/a.log" 2>&1 &
$MSG --state "$DIR/dev-b" --identity "$BOB" --gap-timeout 5 "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/b.in" >"$DIR/b.log" 2>&1 &
exec 3>"$DIR/a.in"; exec 4>"$DIR/b.in"
wait_for "$DIR/a.log" "OK connected" 20; wait_for "$DIR/b.log" "OK connected" 20
echo "kp 3" >&4; wait_for "$DIR/b.log" "OK uploaded" 10
echo "grant $ALICE" >&4; wait_for "$DIR/b.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/b.log" | cut -d' ' -f2 > "$DIR/grant.txt"
echo "live" >&4
echo "kp 1" >&3; wait_for "$DIR/a.log" "OK uploaded" 10
echo "create direct $BOB $DIR/grant.txt" >&3; wait_for "$DIR/b.log" "^JOINED .* kind=direct" 30
echo "live" >&3
echo "send Before you left" >&3; wait_for "$DIR/b.log" "^RECV $ALICE: Before you left" 30

echo "=== Bob goes away; Alice sends, rekeys, and sends again"
echo "offline" >&4; wait_for "$DIR/b.log" "OK offline" 10
echo "send While you were away" >&3; wait_for "$DIR/a.log" "^OK sent seq=" 30
echo "rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=2 " 30
echo "send After the rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=2 seq=" 30

echo "=== Bob's mailbox loses the message he never acknowledged (mls_retention_s)"
sleep 2
kill -9 "$MBX_B"; wait "$MBX_B" 2>/dev/null || true
python3 - "$DIR/mbx-b/mailbox-state.json" "$DIR/gap.txt" <<'PY'
import json, sys
path, out = sys.argv[1], sys.argv[2]
s = json.load(open(path))
items = s["mailbox"]["items"]
commit = max(i["seq"] for i in items if i["class"] == "handshake" and i.get("seq"))      # the rekey
lost = max(i["seq"] for i in items if i["class"] == "application" and i.get("seq", 0) < commit)
gone = [i["cursor"] for i in items if i.get("seq") == lost and i["class"] == "application"]
s["mailbox"]["items"] = [i for i in items if i["cursor"] not in gone]
for c in gone:
    s["store"]["items"].pop(c, None)
json.dump(s, open(path, "w"))
open(out, "w").write(str(commit))
print(f"    dropped the item at seq {lost}; the rekey at seq {commit} now sits beyond a gap")
PY
COMMIT=$(cat "$DIR/gap.txt")
$MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9592 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >>"$DIR/mbx-b.log" 2>&1 &
wait_for "$DIR/mbx-b.log" "restored state" 20

echo "=== Bob comes back: the gap cannot fill, so he re-joins by external commit"
echo "online" >&4; wait_for "$DIR/b.log" "OK connected" 20
echo "live" >&4
wait_for "$DIR/b.log" "^HOLD handshake seq=$COMMIT" 30
wait_for "$DIR/b.log" "^GAP-TIMEOUT group=.* re-joining by external commit" 60
wait_for "$DIR/b.log" "^OK rejoined .* kind=direct" 60
wait_for "$DIR/a.log" "^EPOCH [0-9]+ kind=direct by=$BOB" 60

echo "=== and the conversation carries on"
echo "send Welcome back" >&3; wait_for "$DIR/b.log" "^RECV $ALICE: Welcome back" 30
echo "send Thanks, I lost a bit there" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Thanks, I lost a bit there" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; sleep 0.5
if grep -HE "^(\?\?|DROP)" "$DIR/a.log" "$DIR/b.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
echo "=== Bob saw:"; grep -E "^(HOLD|GAP-TIMEOUT|OK rejoined|RECV|EPOCH)" "$DIR/b.log" | sed 's/^/  /'
echo
echo "PASS: a device whose mailbox had lost an item held what it could not read, re-joined by external commit when the"
echo "      gap did not fill, and carried on from the current epoch."
