#!/usr/bin/env bash
# DSIP Messaging Profile 1.0: mailbox and hub services survive a crash (M§5.4, M§6.5; spec-gap 59).
#
# A mailbox is where a device's messages wait, and a hub is the only thing that orders a group, so neither may
# forget on restart. Bob's mailbox is killed (-9) with a message waiting and restarted: Bob syncs from his old
# cursor and gets it, once. Then Bob's mailbox goes down, Alice sends two messages, and Alice's mailbox — the
# group's hub — is killed with both fan-outs unacknowledged and restarted: it reloads its queues and re-sends
# the head until Bob's mailbox is back, then the rest in order. Alice rekeys: the hub validates the commit
# against the public group view it reloaded. Bob's first restart is an upgrade: from the state file a mailbox kept
# before its database, imported once. Self-verifying.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-mailbox-restart-demo}
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
wait_more() { # file pattern count seconds: wait until the log holds more than `count` matching lines (one already
  # there from an earlier step must not count again)
  local f=$1 pat=$2 k=$3 n=${4:-20}
  for _ in $(seq $((n * 5))); do [ "$(grep -cE "$pat" "$f" 2>/dev/null || true)" -gt "$k" ] && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for a new /$pat/ in $f"; echo "--- $f"; tail -8 "$f"; return 1
}
seen() { grep -cE "$2" "$1" 2>/dev/null || true; } # file pattern: how many matching lines the log holds now
count() { grep -cE "$2" "$1" || true; }
wait_nth() { # file pattern n seconds: the n-th matching line (logs are appended across restarts)
  for _ in $(seq $(($4 * 5))); do [ "$(count "$1" "$2")" -ge "$3" ] && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for match $3 of /$2/ in $1"; tail -20 "$1"; return 1
}
send_a() { # text → waits for the hub's seq and prints it
  local n; n=$(count "$DIR/a.log" "^OK sent seq=")
  echo "send $1" >&3
  for _ in $(seq 150); do [ "$(count "$DIR/a.log" "^OK sent seq=")" -gt "$n" ] && break; sleep 0.2; done
  grep "^OK sent seq=" "$DIR/a.log" | tail -1 | cut -d= -f2
}

start_a() { $MBX --state "$DIR/mbx-a" --listen 127.0.0.1:9521 --owner "$ALICE" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >>"$DIR/mbx-a.log" 2>&1 & MBX_A=$!; }
start_b() { $MBX --state "$DIR/mbx-b" --listen 127.0.0.1:9522 --owner "$BOB" "${RESOLVER[@]}" --ca "$DIR/ca.pem" >>"$DIR/mbx-b.log" 2>&1 & MBX_B=$!; }
crash() { kill -9 "$1"; wait "$1" 2>/dev/null || true; }

echo "=== mailboxes, documents, devices, a direct conversation hubbed at Alice's mailbox"
start_a; start_b
wait_for "$DIR/mbx-a.log" "mailbox did:key" 20; wait_for "$DIR/mbx-b.log" "mailbox did:key" 20
cat "$DIR/mbx-a/cert.pem" "$DIR/mbx-b/cert.pem" > "$DIR/ca.pem"
$MSG --state "$DIR/dev-a" --identity "$ALICE" --write-doc "$DIR/docs/alice.json" \
  --mailbox-did "$(cat "$DIR/mbx-a/service.did")" --mailbox-uri "wss://127.0.0.1:9521/dsip" >/dev/null
$MSG --state "$DIR/dev-b" --identity "$BOB" --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$(cat "$DIR/mbx-b/service.did")" --mailbox-uri "wss://127.0.0.1:9522/dsip" >/dev/null
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
echo "send Before anything breaks" >&3; wait_for "$DIR/b.log" "^RECV $ALICE: Before anything breaks" 30

echo "=== Bob's mailbox crashes with a message waiting, and comes back"
echo "offline" >&4; wait_for "$DIR/b.log" "OK offline" 10
send_a "While you were away" >/dev/null
sleep 1
crash "$MBX_B"
# Bob's mailbox comes back as an upgrade would: from the state file a mailbox kept before its database, which it
# imports once (service-nodes plan S4). The file is written from the database, in that file's format.
python3 - "$DIR/mbx-b" <<'PY'
import json, os, sqlite3, sys
d = sys.argv[1]
db = sqlite3.connect(os.path.join(d, "mailbox.sqlite"))
state = {"format": 2, "owners": {}, "hubs": {}, "views": {}}
for key, text in db.execute("SELECT key, value FROM parts"):
    kind, _, rest = key.partition("/")
    v = json.loads(text)
    if kind == "owner":
        state["owners"][rest] = {"mailbox": v["mailbox"], "store": {"items": {}, "key_packages": v["key_packages"], "last_resort": v["last_resort"]}}
    elif kind in ("hub", "view"):
        state[kind + "s"][rest] = v
    else:
        state[key] = v
for o in state["owners"].values():
    o["mailbox"]["items"] = []
for owner, cursor, record, item in db.execute("SELECT owner, cursor, record, item FROM items ORDER BY n"):
    state["owners"][owner]["mailbox"]["items"].append(json.loads(record))
    if item is not None:
        state["owners"][owner]["store"]["items"][cursor] = json.loads(item)
db.close()
json.dump(state, open(os.path.join(d, "mailbox-state.json"), "w"))
for f in ("mailbox.sqlite", "mailbox.sqlite-wal", "mailbox.sqlite-shm"):
    if os.path.exists(os.path.join(d, f)):
        os.remove(os.path.join(d, f))
PY
start_b; wait_nth "$DIR/mbx-b.log" "restored state: " 1 20
grep -q "imported .*mailbox-state.json into mailbox.sqlite" "$DIR/mbx-b.log" || { echo "FAIL: the state file was not imported"; exit 1; }
[ -f "$DIR/mbx-b/mailbox-state.json.imported" ] && [ ! -f "$DIR/mbx-b/mailbox-state.json" ] || { echo "FAIL: the state file was not set aside"; exit 1; }
echo "    imported the state file once (kept as mailbox-state.json.imported)"
echo "live" >&4; wait_for "$DIR/b.log" "^RECV $ALICE: While you were away" 30
sleep 1
[ "$(count "$DIR/b.log" "^RECV $ALICE: Before anything breaks")" = 1 ] || { echo "FAIL: Bob's resync replayed an old message"; exit 1; }

echo "=== the hub crashes with fan-out to a mailbox that is down"
N=$(seen "$DIR/b.log" "OK offline"); echo "offline" >&4; wait_more "$DIR/b.log" "OK offline" "$N" 10
crash "$MBX_B"
SEQ=$(send_a "Queued at the hub")
send_a "And queued behind it" >/dev/null
echo "offline" >&3; wait_for "$DIR/a.log" "OK offline" 10
crash "$MBX_A"
start_a; wait_for "$DIR/mbx-a.log" "restored state: .* 1 hubbed groups" 20
wait_for "$DIR/mbx-a.log" "re-sending fan-out seq $SEQ in .* to $BOB" 20
sleep 3
start_b; wait_nth "$DIR/mbx-b.log" "restored state: " 2 20
echo "live" >&4
wait_for "$DIR/b.log" "^RECV $ALICE: Queued at the hub" 90
wait_for "$DIR/b.log" "^RECV $ALICE: And queued behind it" 30

echo "=== the reloaded hub still validates commits"
N=$(seen "$DIR/a.log" "OK connected"); echo "live" >&3; wait_more "$DIR/a.log" "OK connected" "$N" 15
echo "rekey" >&3; wait_for "$DIR/a.log" "^OK rekeyed epoch=2 " 30
wait_for "$DIR/b.log" "^EPOCH 2 kind=direct by=$ALICE" 30
echo "send After the rekey" >&3; wait_for "$DIR/b.log" "^RECV $ALICE: After the rekey" 30
echo "send Loud and clear" >&4; wait_for "$DIR/a.log" "^RECV $BOB: Loud and clear" 30
sleep 1

echo "quit" >&3; echo "quit" >&4; sleep 0.5
if grep -HE "^(\?\?|DROP)" "$DIR/a.log" "$DIR/b.log"; then echo "FAIL: a device hit an item it could not process"; exit 1; fi
order=$(grep -E "^RECV $ALICE: " "$DIR/b.log" | sed "s/^RECV $ALICE: //" | paste -sd'|')
[ "$order" = "Before anything breaks|While you were away|Queued at the hub|And queued behind it|After the rekey" ] \
  || { echo "FAIL: Bob's messages, in order: $order"; exit 1; }
echo "=== Bob saw:"; grep -E "^(RECV|EPOCH|OK connected)" "$DIR/b.log" | sed 's/^/  /'
echo "=== the hub after its restart:"; grep -E "restored state|re-sending|already had" "$DIR/mbx-a.log" | sed "s/.*dsip_mailbox[^ ]* /  /"
echo
echo "PASS: a crashed mailbox kept its items and cursors, a crashed hub kept its queues and group view and"
echo "      re-sent until the member mailbox was back — nothing lost, nothing replayed, same order."
