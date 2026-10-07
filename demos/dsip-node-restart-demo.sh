#!/usr/bin/env bash
# dsip-node, stage 2: a restarted bootstrap node rejoins at once. On the WAN testbed a restarted bootstrap node with
# nothing kept took minutes to see its peers again (impl/docs/dht-findings.md, "WAN results"); a dsip-node keeps its
# identity, learned peers, held records and Mainline routing nodes in its state directory. Self-verifying:
#   1. node A (config file + state directory) is the overlay's bootstrap; B and C join it; Bob publishes through A;
#   2. A restarts with an EMPTY state directory, as before: a new PeerId, no peers, nothing held;
#   3. A restarts with ITS state directory: the same PeerId, peers within seconds, Bob's packet and overlay hint
#      served from what it kept — each checked again on the way back in.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay -p dsip-node
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-node-restart-demo}; rm -rf "$D"; mkdir -p "$D"
RELAY_PORT=${RELAY_PORT:-8495}; HA=18191; HB=18192; HC=18193; OA=46291
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }
wait_for() { for _ in $(seq $((${3:-20} * 5))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "TIMEOUT /$2/ in $1"; tail -20 "$1"; return 1; }
info() { curl -s http://127.0.0.1:$HA/dsip/v1/node; }
field() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

$B/dsip mainline-testnet --nodes 10 >"$D/testnet.log" 2>&1 & PIDS+=($!)
wait_for "$D/testnet.log" '^bootstrap ' 10
BOOT=$(grep -m1 '^bootstrap ' "$D/testnet.log" | cut -d' ' -f2)
cat > "$D/a.toml" <<EOF
[node]
state_dir = "$D/a-state"
[overlay]
listen = ["/ip4/127.0.0.1/tcp/$OA"]
[mainline]
enabled = true
server = true
bootstrap = [$(echo "$BOOT" | sed 's/[^,]*/"&"/g')]
[http]
listen = "127.0.0.1:$HA"
EOF
start_a() { $B/dsip-node --config "$D/a.toml" "$@" >>"$D/a.log" 2>&1 & A=$!; PIDS+=($A); }

echo "════════ 1. node A from its config file (state in $D/a-state); B and C join it; Bob publishes through A"
start_a
wait_for "$D/a.log" '^http: ' 20
OBOOT=$(grep -m1 "^overlay: /ip4/127.0.0.1/tcp/$OA/p2p/" "$D/a.log" | cut -d' ' -f2)
PEER1=${OBOOT##*/}
for n in b:$HB c:$HC; do
  $B/dsip-node --http 127.0.0.1:${n#*:} --state-dir "$D/${n%%:*}-state" --overlay-listen /ip4/127.0.0.1/tcp/0 \
    --overlay-bootstrap "$OBOOT" --mainline --mainline-bootstrap "$BOOT" >"$D/${n%%:*}.log" 2>&1 & PIDS+=($!)
done
for n in b c; do wait_for "$D/$n.log" '^http: ' 20; done
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
ZBOB=$(python3 -c "import sys;sys.path.insert(0,'tools');from dsipvec.pkarr import did_key_public,z32_encode;print(z32_encode(did_key_public('$BOB')))")
$B/dsip-relay --listen 127.0.0.1:$RELAY_PORT --state "$D/relay" >"$D/relay.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && break; sleep 0.2; done
$B/dsip answer --identity "$D/bob" --relay wss://127.0.0.1:$RELAY_PORT/dsip --ca "$D/relay/cert.pem" \
  --pkarr-relay http://127.0.0.1:$HA --publish-pkarr --hint-ttl 600 --dht "$OBOOT" --publish-hint \
  --auto accept --script "sleep 3; quit" >"$D/bob.log" 2>&1 || true
grep -q '^hint .*pkarr published' "$D/bob.log" || fail "Bob did not publish"
for _ in $(seq 100); do [ "$(info | field 'd["overlay"]["peers"]')" -ge 2 ] && break; sleep 0.2; done
echo "  node A: PeerId ${PEER1:0:16}…, $(info | field 'd["overlay"]["peers"]') overlay peers, Bob's packet and hint held"
sleep 61  # one republish tick: peers, records and Mainline nodes reach the state directory
[ -s "$D/a-state/overlay-records.jsonl" ] && [ -s "$D/a-state/overlay-peers" ] || fail "A's state was not written"

echo; echo "════════ 2. A restarts with an EMPTY state directory (as before stage 2)"
kill $A; wait $A 2>/dev/null || true
mv "$D/a-state" "$D/a-state.kept"
start_a
wait_for "$D/a.log" '^http: .*' 20
sleep 10
PEER2=$(grep "^overlay: /ip4/127.0.0.1/tcp/$OA/p2p/" "$D/a.log" | tail -1 | sed 's|.*/p2p/||')
P=$(info | field 'd["overlay"]["peers"]'); H=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$HA/$ZBOB)
echo "  after 10 s: PeerId ${PEER2:0:16}… (new), $P overlay peer(s); Bob's packet: HTTP $H, fetched back from Mainline, not kept"
[ "$PEER2" != "$PEER1" ] && [ "$P" = 0 ] || fail "expected a new PeerId and no peers without state"

echo; echo "════════ 3. A restarts with ITS state directory"
kill $A; wait $A 2>/dev/null || true
rm -rf "$D/a-state"; mv "$D/a-state.kept" "$D/a-state"
T0=$(date +%s.%N)
start_a
wait_for "$D/a.log" "restored [0-9]+ packet" 20
for _ in $(seq 150); do [ "$(info 2>/dev/null | field 'd["overlay"]["peers"]' 2>/dev/null || echo 0)" -ge 2 ] && break; sleep 0.1; done
T=$(python3 -c "import time;print(f'{time.time()-$T0:.1f}')")
PEER3=$(grep "^overlay: /ip4/127.0.0.1/tcp/$OA/p2p/" "$D/a.log" | tail -1 | sed 's|.*/p2p/||')
P=$(info | field 'd["overlay"]["peers"]')
[ "$PEER3" = "$PEER1" ] || fail "the PeerId changed: $PEER3"
[ "$P" -ge 2 ] || fail "A did not rejoin its peers"
echo "  PeerId ${PEER3:0:16}… (kept), $P overlay peers after ${T} s"
grep -E "^pkarr: restored|restored .* record" "$D/a.log" | tail -2 | sed 's/^.*dsip_dht::node: //; s/^/  /' | cut -c1-140
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$HA/$ZBOB)" = 200 ] || fail "A did not serve Bob's packet from its state"
N=$(curl -s "http://127.0.0.1:$HA/dsip/v1/hints/$BOB" | field 'len(d["hints"])')
[ "$N" = 1 ] || fail "A did not serve Bob's overlay hint after the restart"
echo "  Bob's packet: HTTP 200 from disk; his overlay hint: served"

echo
echo "PASS: with its state directory a restarted bootstrap node kept its PeerId, rejoined its peers in ${T} s, and"
echo "      served the hints it held at once; without it, a new PeerId and no peers — the WAN finding, answered."
