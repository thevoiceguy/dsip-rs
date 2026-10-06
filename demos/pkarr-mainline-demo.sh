#!/usr/bin/env bash
# DSIP reachability hints on the Mainline DHT directly (v0.9, DHT Hints Profile §9; spec-gap 105): no Pkarr relay
# in Bob's path at all. Bob's device runs a Mainline node and puts his `_dsip` packet, signed by his did:key identity
# key, as a BEP 44 mutable item; Alice's device runs its own node, gets it, reads it offline, and calls him.
#
# The DHT is a local testnet (`dsip mainline-testnet`, 10 nodes on 127.0.0.1): nothing reaches the public DHT.
# Alice is also given a hostile Pkarr relay serving a forged, newer packet for Bob: relays and the DHT are sources of
# the same candidates, and each is read offline (§8.1: a claim is never authority). Self-verifying: the forgery must
# be rejected, the hint must come from the DHT, the call must be answered, and Bob's re-publishes must raise the seq.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-pkarr-mainline-demo}; rm -rf "$D"; mkdir -p "$D"
HOSTILE=${PKARR_HOSTILE_PORT:-15432}; RELAY_PORT=${RELAY_PORT:-8483}
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }

echo "════════ a local Mainline DHT (10 nodes on 127.0.0.1)"
$B/dsip mainline-testnet --nodes 10 >"$D/testnet.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do grep -q '^bootstrap ' "$D/testnet.log" && break; sleep 0.2; done
BOOT=$(grep -m1 '^bootstrap ' "$D/testnet.log" | cut -d' ' -f2) || fail "the testnet did not start"
echo "  bootstrap ${BOOT%%,*} (+ 9 more)"
ML=(--mainline --mainline-bootstrap "$BOOT")

$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")

# a forgery for Bob's key, signed by someone else, naming an attacker's relay with a newer timestamp
read -r ZBOB FORGED < <(python3 - "$BOB" <<'PY'
import sys, time, struct
sys.path.insert(0, "tools")
from nacl.signing import SigningKey
from dsipvec.gen.pkarr import dns, txt
from dsipvec.pkarr import bep44_signable, did_key_public, z32_encode
class Pub:
    def __init__(self, pk): self.public = pk
bob = Pub(did_key_public(sys.argv[1]))
evil = SigningKey(b"\x66" * 32)
ts = int(time.time() * 1_000_000) + 30_000_000
d = dns([("_dsip", 16, 3600, txt("uri=wss://127.0.0.1:9666/evil", "b=ws/1.0"))], bob)
print(z32_encode(bob.public), (evil.sign(bep44_signable(ts, d)).signature + struct.pack("!Q", ts) + d).hex())
PY
)
python3 demos/pkarr_relay.py "$HOSTILE" --hostile "$ZBOB=$FORGED" >"$D/pkarr-hostile.log" 2>&1 & PIDS+=($!)
for _ in $(seq 100); do grep -q "^listening" "$D/pkarr-hostile.log" 2>/dev/null && break; sleep 0.2; done
grep -q "^listening" "$D/pkarr-hostile.log" || fail "the hostile relay did not start"

$B/dsip-relay --listen 127.0.0.1:$RELAY_PORT --state "$D/relay" >"$D/relay.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && break; sleep 0.2; done; CA="$D/relay/cert.pem"

echo; echo "════════ Bob binds to his relay and puts _dsip on the DHT himself (ttl 15 s, so he re-signs every 10 s)"
$B/dsip answer --identity "$D/bob" --relay wss://127.0.0.1:$RELAY_PORT/dsip --ca "$CA" "${ML[@]}" --publish-pkarr \
  --hint-ttl 15 --auto accept --script "sleep 23; quit" >"$D/bob.log" 2>&1 & BOBP=$!; PIDS+=($BOBP)
for _ in $(seq 100); do grep -q "^hint .*pkarr published" "$D/bob.log" && break; sleep 0.2; done
grep -E "^(dht|hint)" "$D/bob.log" | head -2
grep -q "^hint .*pkarr published .* to the mainline DHT" "$D/bob.log" || fail "Bob did not put to the DHT"

echo; echo "════════ Alice knows only Bob's did:key; her sources: the DHT, and a hostile Pkarr relay"
$B/dsip call --identity "$D/alice" --ca "$CA" "${ML[@]}" --pkarr-relay "http://127.0.0.1:$HOSTILE" --to "$BOB" \
  --script "sleep 2; hangup; sleep 1; quit" >"$D/alice.log" 2>&1 || true
grep -E "^(dht|hint)|answered" "$D/alice.log" | head -6
grep -q "pkarr relay http://127.0.0.1:$HOSTILE: rejected (signature)" "$D/alice.log" || fail "the forgery was not rejected"
grep -q "^hint .*pkarr wss://127.0.0.1:$RELAY_PORT/dsip .* from mainline DHT" "$D/alice.log" || fail "no hint from the DHT"
! grep -q "9666" "$D/alice.log" || fail "Alice followed the forgery"
grep -q "answered" "$D/alice.log" || fail "the call was not answered"

echo; echo "════════ Bob re-signs before expiry"
wait "$BOBP" || true
SEQS=$(grep -oE "pkarr published .* seq [0-9]+" "$D/bob.log" | grep -oE "[0-9]+$")
N=$(echo "$SEQS" | wc -l)
[ "$N" -ge 3 ] || fail "expected at least 3 publishes, saw $N"
echo "$SEQS" | sort -c -n -u 2>/dev/null || fail "seq did not rise: $SEQS"
echo "  $N puts to the DHT, seq strictly rising"
echo "════════ a fresh node, after Bob left, still finds the newest hint until it expires"
$B/dsip resolve "$BOB" "${ML[@]}" >"$D/resolve.log" 2>&1
grep -E "^hint" "$D/resolve.log"
LAST=$(echo "$SEQS" | tail -1)
grep -q "seq $LAST .*from mainline DHT" "$D/resolve.log" || fail "the DHT did not return Bob's newest packet"

echo
echo "PASS: with no Pkarr relay in his path, Bob put his signed _dsip packet on the Mainline DHT; Alice got it from"
echo "      the DHT, rejected a hostile relay's forged newer packet, and called him; Bob re-signed with a rising seq,"
echo "      and the DHT served the newest packet to a fresh node after he left."
