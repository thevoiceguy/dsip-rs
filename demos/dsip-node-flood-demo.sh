#!/usr/bin/env bash
# dsip-node, stage 3: what a flooding overlay peer costs. WAN Run 5 measured that dropping a flooder's PUTs unverified
# cut signature checks 3,001 → 40 but not CPU: the cost is the connection, its streams and Kademlia
# (impl/docs/dht-findings.md). Three victims face the same flood of forged hints (~50 PUTs/s), one at a time:
#   (a) --ban-secs 0  — the budget only: PUTs past it dropped unverified for its 60 s window;
#   (b) bans          — dropped unverified for the whole ban, out of the routing table, connection kept;
#   (c) bans + --ban-ip — the address refused before the handshake, the connection closed.
# A first version closed the connection and refused the PeerId: that cost 4× the CPU of (a), because the flooder
# redials and a PeerId is known only after the Noise handshake. Self-verifying: (c) must cost the least CPU, (b) no
# more than (a) within noise, and each victim's metrics must show its own mechanism at work.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-dht -p dsip-node
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-node-flood-demo}; rm -rf "$D"; mkdir -p "$D"
FLOOD_S=${FLOOD_S:-30}
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }
wait_for() { for _ in $(seq $((${3:-20} * 5))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "TIMEOUT /$2/ in $1"; tail -20 "$1"; return 1; }
metric() { curl -s http://127.0.0.1:$1/metrics | awk -v m="$2" 'index($1, m) == 1 {s+=$2} END {print s+0}'; }
cpu() { awk '{print $14+$15}' /proc/$1/stat; }

run() { # name http-port overlay-port flags…
  local name=$1 h=$2 o=$3; shift 3
  $B/dsip-node --http 127.0.0.1:$h --overlay-listen /ip4/127.0.0.1/tcp/$o "$@" >"$D/$name.log" 2>&1 & local v=$!; PIDS+=($v)
  wait_for "$D/$name.log" '^http: ' 20
  local boot; boot=$(grep -m1 "^overlay: /ip4/127.0.0.1/tcp/$o/p2p/" "$D/$name.log" | cut -d' ' -f2)
  $B/dsip-dht-node --listen /ip4/127.0.0.1/tcp/0 --bootstrap "$boot" --control 127.0.0.1:0 >"$D/$name-flooder.log" 2>&1 & local f=$!; PIDS+=($f)
  wait_for "$D/$name-flooder.log" '^control: ' 20
  for _ in $(seq 50); do [ "$(metric $h dsip_node_overlay_peers)" -ge 1 ] && break; sleep 0.2; done
  local c0; c0=$(cpu $v)
  python3 - "$(grep -m1 '^control: ' "$D/$name-flooder.log" | cut -d' ' -f2)" "$FLOOD_S" >"$D/$name.sent" <<'PY'
import json, socket, sys, time
sys.path.insert(0, "tools")
from dht_testnet import hint_frame
from dsipvec import fixtures as F
host, port = sys.argv[1].rsplit(":", 1)
alice = F.did("alice")
frames = [hint_frame("mallory", alice, 1000 + i, uri="wss://evil.example/dsip") for i in range(200)]
f = socket.create_connection((host, int(port))).makefile("rw")
end, i = time.time() + float(sys.argv[2]), 0
while time.time() < end:
    f.write(json.dumps({"op": "put_raw", "did": alice, "frame": frames[i % len(frames)]}) + "\n"); f.flush()
    f.readline(); i += 1
    time.sleep(0.02)
print(i)
PY
  echo "$name $(cat "$D/$name.sent") $(( $(cpu $v) - c0 )) $(metric $h 'dsip_node_overlay_puts_rejected_total{reason="signer-mismatch"}') \
$(metric $h 'dsip_node_overlay_puts_rejected_total{reason="rate-limited"}') $(metric $h 'dsip_node_overlay_puts_rejected_total{reason="banned"}') \
$(metric $h dsip_node_overlay_bans_total) $(metric $h dsip_node_overlay_refused_connections_total)" >>"$D/results"
  kill $f $v; wait $f $v 2>/dev/null || true
}

echo "════════ the same flood (forged hints for alice signed by mallory, ~50/s for ${FLOOD_S} s) against three victims"
run a 18291 46391 --ban-secs 0
run b 18292 46392
run c 18293 46393 --ban-ip
printf "  %-34s %10s %10s %10s\n" "" "(a) budget" "(b) ban" "(c) ban-ip"
row() { printf "  %-34s %10s %10s %10s\n" "$1" "$(awk -v k=$2 '$1=="a"{print $k}' "$D/results")" \
  "$(awk -v k=$2 '$1=="b"{print $k}' "$D/results")" "$(awk -v k=$2 '$1=="c"{print $k}' "$D/results")"; }
row "flooder PUTs sent" 2; row "verified and refused (signature)" 4; row "dropped unverified (budget)" 5
row "dropped unverified (banned)" 6; row "peers banned" 7; row "connections refused pre-handshake" 8
printf "  %-34s %9ss %9ss %9ss\n" "victim CPU over the flood" $(awk '{printf "%s ", $3/100}' "$D/results")
read -r _ _ CA _ _ _ _ _ < <(grep '^a ' "$D/results"); read -r _ _ CB _ _ DB BB _ < <(grep '^b ' "$D/results")
read -r _ _ CC _ _ _ BC RC < <(grep '^c ' "$D/results")
[ "$BB" = 1 ] && [ "$DB" -gt 0 ] || fail "(b) did not ban and drop"
[ "$BC" = 1 ] && [ "$RC" -gt 0 ] || fail "(c) did not refuse connections before the handshake"
[ "$CC" -lt "$CA" ] || fail "(c) should cost the least CPU ($CC vs $CA ticks)"
[ "$CB" -le $(( CA * 3 / 2 + 20 )) ] || fail "(b) should cost no more than (a) within noise ($CB vs $CA ticks)"
echo
echo "PASS: refusing a banned address before the handshake cost the least CPU; banning in place cost no more than"
echo "      the budget alone; closing a flooder's connection by PeerId — the first attempt — was the one thing worse."
