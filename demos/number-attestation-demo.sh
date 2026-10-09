#!/usr/bin/env bash
# DSIP Number Attestation Profile (draft, N§3–N§5): a caller shows a phone number only when its carrier has bound
# the number to the caller's DID and the DID claims the number back. Four calls to Bob over a relay:
#   1. Alice (did:web:alice.example, alsoKnownAs tel:+15551234567) presents Carrier Example's binding: Bob sees
#      "+15551234567 · number attested by Carrier Example for this identity".
#   2. Alice presents a binding for +15559990000, which Carrier Example's certificate does not cover: refused
#      (not-authorized-for-tn); the number is shown only as "(unverified)".
#   3. Mallory copies Alice's binding into her own invite: refused (did-mismatch). A binding names one DID.
#   4. The number is ported: Carrier B binds +15551234567 to Mallory's DID, and Mallory's document claims it. Bob's
#      client attests the number for Mallory, and warns that it now belongs to a different identity than his
#      contact "Alice" (N§5): the number moved; Alice's identity did not.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-number-attestation-demo}; rm -rf "$D"; mkdir -p "$D"
PORT=${RELAY_PORT:-8495}; R=wss://127.0.0.1:$PORT/dsip; TN=+15551234567
ALICE=did:web:alice.example; MALLORY=did:web:mallory.example
fail() { echo "FAIL: $*"; exit 1; }

echo "════════ identities, the test number authority, Bob's address book"
$B/dsip identity init --dir "$D/alice" --name "Alice" --did-web $ALICE --also-known-as "tel:$TN" >/dev/null
$B/dsip identity init --dir "$D/mallory" --name "Alice" --did-web $MALLORY >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
python3 demos/tn_issuer.py policy "$D/policy.json"
python3 demos/tn_issuer.py bind A $TN $ALICE "$D/alice.jws"
python3 demos/tn_issuer.py bind A +15559990000 $ALICE "$D/alice-uncovered.jws"
python3 demos/tn_issuer.py bind B $TN $MALLORY "$D/mallory-ported.jws"
echo "[{\"name\": \"Alice\", \"did\": \"$ALICE\", \"numbers\": [\"$TN\"]}]" > "$D/contacts.json"
echo "  Alice  $ALICE  alsoKnownAs tel:$TN    Mallory  $MALLORY (display name \"Alice\")    Bob  $BOB"

$B/dsip-relay --listen 127.0.0.1:$PORT --state "$D/relay" \
  --did-document "$D/alice/did.json" --did-document "$D/mallory/did.json" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && break; sleep 0.2; done; CA="$D/relay/cert.pem"
DOCS=(--did-document "$D/alice/did.json" --did-document "$D/mallory/did.json")

call() { # n caller binding [mallory-doc]
  local n=$1 who=$2 binding=$3
  $B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --auto reject --media none "${DOCS[@]}" \
    --tn-policy "$D/policy.json" --contacts "$D/contacts.json" --script "sleep 5; quit" >"$D/$n-bob.log" 2>&1 & BP=$!
  for _ in $(seq 50); do grep -q "capabilities" "$D/$n-bob.log" && break; sleep 0.2; done
  $B/dsip call --identity "$D/$who" --relay $R --ca "$CA" --to "$BOB" --media none "${DOCS[@]}" \
    --tn-binding "$binding" --script "sleep 3; quit" >"$D/$n-$who.log" 2>&1 || true
  wait $BP || true
  grep -E "^← invite|☎|⚠|🔎" "$D/$n-bob.log" | sed 's/^/  /'
}

echo "════════ 1. Alice presents Carrier Example's binding for her number"
call 1 alice "$D/alice.jws"
grep -q "☎  $TN · number attested by Carrier Example for this identity" "$D/1-bob.log" || fail "1: not attested"
grep -q "🔎 trust: Domain verified ($ALICE)" "$D/1-bob.log" || fail "1: the basis changed"
! grep -q "⚠" "$D/1-bob.log" || fail "1: warned about the contact's own number"

echo "════════ 2. A binding for a number Carrier Example's certificate does not cover"
call 2 alice "$D/alice-uncovered.jws"
grep -q "☎  +15559990000 (unverified) — number binding refused: not-authorized-for-tn" "$D/2-bob.log" || fail "2: not refused"

echo "════════ 3. Mallory replays Alice's binding"
call 3 mallory "$D/alice.jws"
grep -q "☎  $TN (unverified) — number binding refused: did-mismatch" "$D/3-bob.log" || fail "3: replay not refused"

echo "════════ 4. The number is ported to Mallory's identity (Carrier B)"
python3 - "$D/mallory/did.json" <<EOF
import json, sys
d = json.load(open(sys.argv[1])); d["alsoKnownAs"] = ["tel:$TN"]; json.dump(d, open(sys.argv[1], "w"), indent=1)
EOF
call 4 mallory "$D/mallory-ported.jws"
grep -q "☎  $TN · number attested by Carrier B for this identity" "$D/4-bob.log" || fail "4: ported number not attested"
grep -q "⚠  $TN now belongs to a different identity (number attested by Carrier B since $(date -u +%Y-%m-%d -d @$(( $(date +%s) - 60 )))). Your contact \"Alice\" is $ALICE." "$D/4-bob.log" \
  || fail "4: no identity-change warning"

echo
echo "PASS: a number was shown as attested only with its carrier's binding to the caller's DID and the DID's claim"
echo "      back; an uncovered number and a replayed binding were refused and shown as unverified; a ported number"
echo "      was attested for its new identity with a warning that it no longer belongs to the stored contact."
