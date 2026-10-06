#!/usr/bin/env bash
# DSIP reachability hints on Pkarr (v0.9, DHT Hints Profile §9; spec-gap 105): Bob publishes his relay as `_dsip`
# TXT records signed by his did:key identity key; Alice, knowing only his did:key, finds the relay through Pkarr
# relays and completes a signed call.
#
# Two Pkarr relays (local stand-ins speaking Pkarr's HTTP API, demos/pkarr_relay.py): one honest, one hostile that
# serves a forged, newer packet for Bob pointing at an attacker's relay. Self-verifying: the forgery must be rejected
# (§8.1: a relay's claim is never authority), the call must reach Bob's real relay, Bob's re-publish must raise the
# seq before expiry, and a record another application put in Bob's zone must survive his publishes (one slot per
# key).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-pkarr-demo}; rm -rf "$D"; mkdir -p "$D"
HONEST=${PKARR_HONEST_PORT:-15421}; HOSTILE=${PKARR_HOSTILE_PORT:-15422}; RELAY_PORT=${RELAY_PORT:-8453}
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
fail() { echo "FAIL: $*"; exit 1; }

$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")

# Packets built outside DSIP: a record of another application in Bob's zone (signed by Bob's own key — it is his
# zone), and a forgery for Bob's key (signed by someone else) naming an attacker's relay with a newer timestamp.
read -r ZBOB IROH FORGED < <(python3 - "$D/bob/controller.key" <<'PY'
import sys, time, struct
sys.path.insert(0, "tools")
from nacl.signing import SigningKey
from dsipvec.gen.pkarr import dns, txt
from dsipvec.pkarr import bep44_signable, z32_encode
class K:  # the generator's key shape
    def __init__(self, sk): self.sk, self.public = sk, bytes(sk.verify_key)
    def sign(self, m): return self.sk.sign(m).signature
bob = K(SigningKey(bytes.fromhex(open(sys.argv[1]).read().strip())))
evil = K(SigningKey(b"\x66" * 32))
now = int(time.time() * 1_000_000)
def pl(records, ts, signer):
    d = dns(records, bob)
    return (signer.sign(bep44_signable(ts, d)) + struct.pack("!Q", ts) + d).hex()
# another application's records: a TXT, and a CNAME whose target is compressed into the zone name (spec-gap 105: the
# publisher must re-encode it, not drop it)
from dsipvec.gen.pkarr import _rr
z = z32_encode(bob.public)
d = (struct.pack("!HHHHHH", 0, 0x8400, 0, 2, 0, 0) + _rr(b"\x05_iroh" + bytes([len(z)]) + z.encode() + b"\x00", 16, txt("relay=https://iroh.example"))
     + _rr(b"\x03www\xc0\x12", 5, b"\x04edge\xc0\x12"))
ts0 = now - 5_000_000
iroh = (bob.sign(bep44_signable(ts0, d)) + struct.pack("!Q", ts0) + d).hex()
forged = pl([("_dsip", 16, 3600, txt("uri=wss://127.0.0.1:9666/evil", "b=ws/1.0"))], now + 30_000_000, evil)
print(z32_encode(bob.public), iroh, forged)
PY
)

echo "════════ two Pkarr relays: an honest one already holding another application's record in Bob's zone, and a"
echo "         hostile one serving a forged, newer _dsip packet for Bob (pointing at wss://127.0.0.1:9666/evil)"
python3 demos/pkarr_relay.py "$HONEST" "$ZBOB=$IROH" >"$D/pkarr-honest.log" 2>&1 & PIDS+=($!)
python3 demos/pkarr_relay.py "$HOSTILE" --hostile "$ZBOB=$FORGED" >"$D/pkarr-hostile.log" 2>&1 & PIDS+=($!)
PK=(--pkarr-relay "http://127.0.0.1:$HONEST" --pkarr-relay "http://127.0.0.1:$HOSTILE")

$B/dsip-relay --listen 127.0.0.1:$RELAY_PORT --state "$D/relay" >"$D/relay.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && break; sleep 0.2; done; CA="$D/relay/cert.pem"

echo; echo "════════ Bob binds to his relay and publishes _dsip (ttl 6 s, so he re-signs every 4 s)"
$B/dsip answer --identity "$D/bob" --relay wss://127.0.0.1:$RELAY_PORT/dsip --ca "$CA" "${PK[@]}" --publish-pkarr \
  --hint-ttl 6 --auto accept --script "sleep 16; quit" >"$D/bob.log" 2>&1 & BOBP=$!; PIDS+=($BOBP)
for _ in $(seq 50); do grep -q "^hint .*pkarr published" "$D/bob.log" && break; sleep 0.2; done
grep -E "^hint" "$D/bob.log" | head -3 || fail "Bob did not publish"

echo; echo "════════ Alice knows only Bob's did:key: no DID document ⇒ hints tier ⇒ Pkarr ⇒ his relay ⇒ a signed call"
$B/dsip call --identity "$D/alice" --ca "$CA" "${PK[@]}" --to "$BOB" --script "sleep 2; hangup; sleep 1; quit" \
  >"$D/alice.log" 2>&1 || true
grep -E "^hint|answered|ended|signature" "$D/alice.log" | head -8
grep -q "pkarr relay http://127.0.0.1:$HOSTILE: rejected" "$D/alice.log" || fail "the forged packet was not rejected"
grep -q "^hint .*pkarr wss://127.0.0.1:$RELAY_PORT/dsip" "$D/alice.log" || fail "Alice did not find Bob's relay"
! grep -q "9666" "$D/alice.log" || fail "Alice followed the forgery"
grep -qiE "answered|accepted" "$D/alice.log" || fail "the call was not answered"

echo; echo "════════ Bob re-signs before expiry; another application's records in his zone survive, re-encoded where needed"
wait "$BOBP" || true
SEQS=$(grep -oE "pkarr published .* seq [0-9]+" "$D/bob.log" | grep -oE "[0-9]+$")
N=$(echo "$SEQS" | wc -l)
[ "$N" -ge 3 ] || fail "expected at least 3 publishes, saw $N"
echo "$SEQS" | sort -c -n -u 2>/dev/null || fail "seq did not rise: $SEQS"
echo "  $N publishes, seq strictly rising"
python3 - "http://127.0.0.1:$HONEST/$ZBOB" <<'PY' || fail "the zone lost a record"
import sys, urllib.request
sys.path.insert(0, "tools")
from dsipvec.pkarr import parse_dns
p = urllib.request.urlopen(sys.argv[1]).read()
from dsipvec.pkarr import carry, z32_encode
recs = parse_dns(p[72:])
names = sorted({".".join(l.decode() for l in r[0][:1]) for r in recs})
print("  honest relay's packet for Bob now holds:", ", ".join(names))
assert names == ["_dsip", "_iroh", "www"], names
zone = sys.argv[1].rsplit("/", 1)[1]
cname = [k for k in carry(zone, p[72:])["keep"] if k["type"] == 5]
target = bytes.fromhex(cname[0]["rdata"])
assert target == b"\x04edge" + bytes([len(zone)]) + zone.encode() + b"\x00", target
print(f"  www CNAME still points at edge.{zone[:8]}…: carried over and re-encoded")
PY

echo
echo "PASS: Alice found Bob's relay from his did:key alone through Pkarr, rejected a hostile relay's forged newer"
echo "      packet, and called him; Bob re-signed before expiry with a rising seq, and kept another application's"
echo "      record in his zone."
