#!/usr/bin/env bash
# dsip-node, stage 1 (DHT Hints Profile §10, v0.11): three deployable hints nodes that are overlay members, Mainline
# DHT participants and HTTP hints APIs at once. DSIP's own clients use them unchanged:
#   1. Bob publishes his Pkarr packet to node A's relay interface (PUT /<z32>) and his overlay hint to the overlay;
#   2. Alice resolves Bob through node C's relay interface — C holds nothing, so it fetches from the Mainline DHT,
#      verifies, and serves — and her call is answered;
#   3. a "browser" (curl, no UDP, no libp2p) reads Bob's overlay hint from node C over HTTP, CORS allowed;
#   4. a forged packet for Bob's key is refused (400 signature), and Bob's own older packet is kept out (409 older).
# The Mainline DHT is a local testnet (`dsip mainline-testnet`): nothing reaches the public DHT.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay -p dsip-node
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-node-demo}; rm -rf "$D"; mkdir -p "$D"
RELAY_PORT=${RELAY_PORT:-8493}; HA=18091; HB=18092; HC=18093; OA=46191
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }
wait_for() { for _ in $(seq $((${3:-20} * 5))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.2; done; echo "TIMEOUT /$2/ in $1"; tail -20 "$1"; return 1; }

echo "════════ a local Mainline DHT (10 nodes), and three dsip-nodes joining it and forming the overlay"
$B/dsip mainline-testnet --nodes 10 >"$D/testnet.log" 2>&1 & PIDS+=($!)
wait_for "$D/testnet.log" '^bootstrap ' 10
BOOT=$(grep -m1 '^bootstrap ' "$D/testnet.log" | cut -d' ' -f2)
ML=(--mainline --mainline-server --mainline-bootstrap "$BOOT")
$B/dsip-node --http 127.0.0.1:$HA --overlay-listen /ip4/127.0.0.1/tcp/$OA "${ML[@]}" >"$D/a.log" 2>&1 & PIDS+=($!)
wait_for "$D/a.log" '^http: ' 20
OBOOT=$(grep -m1 "^overlay: /ip4/127.0.0.1/tcp/$OA/p2p/" "$D/a.log" | cut -d' ' -f2)
for n in b:$HB c:$HC; do
  $B/dsip-node --http 127.0.0.1:${n#*:} --overlay-listen /ip4/127.0.0.1/tcp/0 --overlay-bootstrap "$OBOOT" "${ML[@]}" \
    >"$D/${n%%:*}.log" 2>&1 & PIDS+=($!)
done
for n in a b c; do wait_for "$D/$n.log" '^http: ' 20; grep -E '^(mainline|http):' "$D/$n.log" | tr '\n' ' ' | sed "s/^/  node $n: /"; echo; done

$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
ZBOB=$(python3 -c "import sys;sys.path.insert(0,'tools');from dsipvec.pkarr import did_key_public,z32_encode;print(z32_encode(did_key_public('$BOB')))")
$B/dsip-relay --listen 127.0.0.1:$RELAY_PORT --state "$D/relay" >"$D/relay.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && break; sleep 0.2; done; CA="$D/relay/cert.pem"

echo; echo "════════ 1. Bob publishes through node A: Pkarr (its relay interface) and the overlay"
$B/dsip answer --identity "$D/bob" --relay wss://127.0.0.1:$RELAY_PORT/dsip --ca "$CA" \
  --pkarr-relay http://127.0.0.1:$HA --publish-pkarr --hint-ttl 15 --dht "$OBOOT" --publish-hint \
  --auto accept --script "sleep 24; quit" >"$D/bob.log" 2>&1 & PIDS+=($!)
wait_for "$D/bob.log" '^hint .*pkarr published' 20
FIRST=$(curl -sf http://127.0.0.1:$HA/$ZBOB | xxd -p | tr -d '\n') || fail "node A does not hold Bob's packet"
grep -E '^hint .*(pkarr published|published)' "$D/bob.log" | head -2 | cut -c1-150 | sed 's/^/  bob: /'

echo; echo "════════ 2. Alice resolves Bob through node C, which holds nothing: C fetches from Mainline and verifies"
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$HC/dsip/v1/node)" = 200 ] || fail "node C is not serving"
$B/dsip call --identity "$D/alice" --ca "$CA" --pkarr-relay http://127.0.0.1:$HC --to "$BOB" \
  --script "sleep 2; hangup; sleep 1; quit" >"$D/alice.log" 2>&1 || true
grep -E '^hint ' "$D/alice.log" | head -1 | cut -c1-150 | sed 's/^/  alice: /'
grep -q "^hint .*pkarr wss://127.0.0.1:$RELAY_PORT/dsip .*from pkarr relay http://127.0.0.1:$HC" "$D/alice.log" \
  || fail "Alice did not get Bob's hint from node C"
grep -q "answered" "$D/alice.log" || fail "the call was not answered"
echo "  alice: the call was answered; node C now holds $(curl -s http://127.0.0.1:$HC/dsip/v1/node | python3 -c 'import json,sys;print(json.load(sys.stdin)["pkarr_held"])') packet(s), fetched from Mainline"

echo; echo "════════ 3. a browser (curl: no UDP, no libp2p) reads Bob's overlay hint from node C over HTTP"
H=$(curl -s -D "$D/headers" "http://127.0.0.1:$HC/dsip/v1/hints/$BOB")
N=$(echo "$H" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["hints"]))')
[ "$N" = 1 ] || fail "node C should serve Bob's one overlay hint once: $H"
grep -qi '^access-control-allow-origin: \*' "$D/headers" || fail "no CORS header"
echo "  browser: $N verified hint(s) for Bob from node C, Access-Control-Allow-Origin: *"

echo; echo "════════ 4. node A refuses a forgery for Bob's key, and Bob's own older packet once he has re-signed"
FORGED=$(python3 - "$BOB" <<'PY'
import sys, time, struct
sys.path.insert(0, "tools")
from nacl.signing import SigningKey
from dsipvec.gen.pkarr import dns, txt
from dsipvec.pkarr import bep44_signable, did_key_public
class Pub:
    def __init__(self, pk): self.public = pk
d = dns([("_dsip", 16, 3600, txt("uri=wss://127.0.0.1:9666/evil", "b=ws/1.0"))], Pub(did_key_public(sys.argv[1])))
ts = int(time.time() * 1_000_000) + 30_000_000
print((SigningKey(b"\x66" * 32).sign(bep44_signable(ts, d)).signature + struct.pack("!Q", ts) + d).hex())
PY
)
put() { echo "$1" | xxd -r -p | curl -s -o "$D/put.out" -w '%{http_code}' -X PUT --data-binary @- http://127.0.0.1:$HA/$ZBOB; }
[ "$(put "$FORGED") $(cat "$D/put.out")" = "400 signature" ] || fail "the forgery was not refused: $(cat "$D/put.out")"
echo "  forged packet for Bob's key: 400 signature"
wait_for "$D/bob.log" '^hint .*pkarr published.*' 20
for _ in $(seq 75); do [ "$(curl -sf http://127.0.0.1:$HA/$ZBOB | xxd -p | tr -d '\n')" != "$FIRST" ] && break; sleep 0.2; done
[ "$(put "$FIRST") $(cat "$D/put.out")" = "409 older" ] || fail "Bob's older packet was not kept out: $(cat "$D/put.out")"
echo "  Bob's first packet, after he re-signed: 409 older (§8.3)"

echo
echo "PASS: three dsip-nodes served DSIP's unchanged clients: Bob published through A, Alice's call resolved"
echo "      through C via the Mainline DHT, a browser read the overlay hint from C over HTTP, and forged and older"
echo "      packets were refused — every answer verified by the client, the node never authoritative."
