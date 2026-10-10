#!/usr/bin/env bash
# DSIP Number Attestation Profile (draft, N§6–N§7): calling a phone number reaches the DSIP identity it is bound
# to, found on the hints tier and verified end to end. A dsip-node serves number bindings over HTTP; Bob dials
# tel:+15551234567 and his client verifies what the node returns before it places the call.
#   1. Nothing published (discoverability is opt-in): the lookup finds nothing, and no call is placed.
#   2. Alice publishes her carrier's binding; Bob dials the number and reaches Alice's DID, which claims it back.
#   3. The node refuses a forged binding (wrong key) and one for a number the certificate does not cover (400).
#   4. Mallory publishes a newer, valid binding for the number from another carrier, but her document does not
#      claim it: Bob's lookup still reaches Alice (both directions, or nothing).
#   5. The number is ported: Mallory's document now claims it too. The newer binding wins, and Bob's client says
#      that the number is also bound to Alice (N§7).
#   6. Route 2: Carrier A serves Alice's binding itself, at its .well-known; Bob, configured with the authority and no
#      node, reaches Alice, and his client names the authority that served the answer; a number the authority does
#      not hold finds nothing (the log entry that makes the authority's answer auditable is staged with T§ stage 2).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay -p dsip-node
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-number-discovery-demo}; rm -rf "$D"; mkdir -p "$D"
PORT=${RELAY_PORT:-8497}; R=wss://127.0.0.1:$PORT/dsip; NPORT=${NODE_PORT:-8098}; NODE=http://127.0.0.1:$NPORT
APORT=${AUTHORITY_PORT:-8097}; AUTHORITY=http://127.0.0.1:$APORT
TN=+15551234567; ALICE=did:web:alice.example; MALLORY=did:web:mallory.example
fail() { echo "FAIL: $*"; exit 1; }

echo "════════ identities, the test number authority, a relay and a dsip-node serving numbers"
$B/dsip identity init --dir "$D/alice" --name "Alice" --did-web $ALICE --also-known-as "tel:$TN" >/dev/null
$B/dsip identity init --dir "$D/mallory" --name "Mallory" --did-web $MALLORY >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
python3 demos/tn_issuer.py policy "$D/policy.json"
python3 demos/tn_issuer.py bind A $TN $ALICE "$D/alice.jws" 600
python3 demos/tn_issuer.py bind B $TN $MALLORY "$D/mallory.jws" 60
python3 demos/tn_issuer.py bind A +15559990000 $ALICE "$D/uncovered.jws"
python3 - "$D/alice.jws" "$D/forged.jws" <<'EOF'
import sys; h, p, s = open(sys.argv[1]).read().strip().split("."); open(sys.argv[2], "w").write(f"{h}.{p}.{s[::-1]}\n")
EOF
$B/dsip-relay --listen 127.0.0.1:$PORT --state "$D/relay" \
  --did-document "$D/alice/did.json" --did-document "$D/mallory/did.json" >"$D/relay.log" 2>&1 & RELAY=$!
$B/dsip-node --http 127.0.0.1:$NPORT --tn-policy "$D/policy.json" >"$D/node.log" 2>&1 & NODEP=$!
mkdir -p "$D/carrier-a"; cp "$D/alice.jws" "$D/carrier-a/$TN.jws"   # what Carrier A issued, served by Carrier A
python3 demos/tn_authority.py 127.0.0.1:$APORT "$D/carrier-a" >"$D/authority.log" 2>&1 & AUTHP=$!
trap 'kill $RELAY $NODEP $AUTHP 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && grep -q "^http:" "$D/node.log" && grep -q "^http:" "$D/authority.log" && break; sleep 0.2; done
CA="$D/relay/cert.pem"; grep "numbers:" "$D/node.log" | sed 's/^/  node: /'

dial() { # n — Alice answers; Bob dials the number
  local n=$1
  $B/dsip answer --identity "$D/alice" --relay $R --ca "$CA" --auto accept --media none \
    --script "sleep 6; quit" >"$D/$n-alice.log" 2>&1 & AP=$!
  for _ in $(seq 50); do grep -q "capabilities" "$D/$n-alice.log" && break; sleep 0.2; done
  $B/dsip call --identity "$D/bob" --relay $R --ca "$CA" --to "tel:$TN" --tn-node $NODE --tn-policy "$D/policy.json" \
    --did-document "$D/alice/did.json" --did-document "$D/mallory/did.json" --media none \
    --script "sleep 3; hangup; sleep 1; quit" >"$D/$n-bob.log" 2>&1 || true
  kill $AP 2>/dev/null || true; wait $AP 2>/dev/null || true
  grep -E "^number|⚠|^→ invite|^← answer|Error|error:" "$D/$n-bob.log" | sed 's/^/  /' || true
}

echo "════════ 1. Nothing published: tel:$TN finds nothing"
dial 1
grep -q "no binding verified" "$D/1-bob.log" || fail "1: a lookup with nothing published did not fail"
! grep -q "→ invite" "$D/1-bob.log" || fail "1: a call was placed"

echo "════════ 2. Alice publishes her binding (opt-in); Bob dials the number"
$B/dsip tn-publish --binding "$D/alice.jws" --node $NODE | sed 's/^/  /'
dial 2
grep -q "number    $TN → $ALICE  (attested by Carrier Example" "$D/2-bob.log" || fail "2: number not resolved to Alice"
grep -q "← answer" "$D/2-bob.log" || fail "2: Alice did not answer"

echo "════════ 3. The node refuses a forged binding and an uncovered number"
! $B/dsip tn-publish --binding "$D/forged.jws" --node $NODE >"$D/3-forged.log" 2>&1 || fail "3: forged binding stored"
! $B/dsip tn-publish --binding "$D/uncovered.jws" --node $NODE >"$D/3-uncovered.log" 2>&1 || fail "3: uncovered stored"
grep -h "tn-publish" "$D/3-forged.log" "$D/3-uncovered.log" | sed 's/^/  /'
grep -q "400 signature" "$D/3-forged.log" || fail "3: forged binding not refused for its signature"
grep -q "400 not-authorized-for-tn" "$D/3-uncovered.log" || fail "3: uncovered number not refused"

echo "════════ 4. Mallory publishes a newer binding from Carrier B, but her document does not claim the number"
$B/dsip tn-publish --binding "$D/mallory.jws" --node $NODE | sed 's/^/  /'
dial 4
grep -q "binding(s) from" "$D/4-bob.log" && grep -q "2 binding(s)" "$D/4-bob.log" || fail "4: the node did not return both"
grep -q "number    $TN → $ALICE" "$D/4-bob.log" || fail "4: an unclaimed binding won"

echo "════════ 5. Ported: Mallory's document now claims the number too; the newer binding wins, and Bob is told"
python3 - "$D/mallory/did.json" <<EOF
import json, sys
d = json.load(open(sys.argv[1])); d["alsoKnownAs"] = ["tel:$TN"]; json.dump(d, open(sys.argv[1], "w"), indent=1)
EOF
$B/dsip call --identity "$D/bob" --relay $R --ca "$CA" --to "tel:$TN" --tn-node $NODE --tn-policy "$D/policy.json" \
  --did-document "$D/alice/did.json" --did-document "$D/mallory/did.json" --media none \
  --script "sleep 2; quit" >"$D/5-bob.log" 2>&1 || true
grep -E "^number|⚠" "$D/5-bob.log" | sed 's/^/  /'
grep -q "number    $TN → $MALLORY  (attested by Carrier B" "$D/5-bob.log" || fail "5: the ported binding did not win"
grep -q "⚠  $TN is also bound to $ALICE — the newer binding is used" "$D/5-bob.log" || fail "5: no N§7 notice"

echo "════════ 6. Route 2: Carrier A serves the binding itself; Bob asks the authority, not a node"
$B/dsip answer --identity "$D/alice" --relay $R --ca "$CA" --auto accept --media none --script "sleep 6; quit" >"$D/6-alice.log" 2>&1 & AP=$!
for _ in $(seq 50); do grep -q "capabilities" "$D/6-alice.log" && break; sleep 0.2; done
$B/dsip call --identity "$D/bob" --relay $R --ca "$CA" --to "tel:$TN" --tn-authority $AUTHORITY --tn-policy "$D/policy.json" \
  --did-document "$D/alice/did.json" --did-document "$D/mallory/did.json" --media none \
  --script "sleep 3; hangup; sleep 1; quit" >"$D/6-bob.log" 2>&1 || true
kill $AP 2>/dev/null || true; wait $AP 2>/dev/null || true
grep -E "^number|← answer" "$D/6-bob.log" | sed 's/^/  /'
grep -q "number    $TN: 1 binding(s) from authority $AUTHORITY" "$D/6-bob.log" || fail "6: the authority served nothing"
grep -q "number    $TN → $ALICE  (attested by Carrier Example; the DID claims it back; served by $AUTHORITY)" "$D/6-bob.log" \
  || fail "6: the served binding did not win, or the authority was not named"
grep -q "← answer" "$D/6-bob.log" || fail "6: Alice did not answer"
$B/dsip call --identity "$D/bob" --relay $R --ca "$CA" --to "tel:+15559990000" --tn-authority $AUTHORITY --tn-policy "$D/policy.json" \
  --did-document "$D/alice/did.json" --media none --script "sleep 1; quit" >"$D/6-none.log" 2>&1 || true
grep -E "^number|error" "$D/6-none.log" | head -3 | sed 's/^/  /'
grep -q "authority $AUTHORITY answered 404" "$D/6-none.log" && grep -q "no binding verified" "$D/6-none.log" || fail "6: a number the authority does not hold was not refused"

echo
echo "PASS: a number was dialled through a dsip-node and reached the DID it is bound to, verified end to end; nothing"
echo "      unpublished was found; forged and uncovered bindings were refused at the node; a binding whose DID does"
echo "      not claim the number never won; after a port the newer binding won and the client said so; and the"
echo "      number's own authority served the binding at its .well-known, named on the answer (route 2)."
