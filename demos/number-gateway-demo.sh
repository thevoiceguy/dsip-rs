#!/usr/bin/env bash
# DSIP Number Attestation Profile (draft, N§4.1, N§6.1): a bound number crosses the PSTN with a SHAKEN PASSporT, and
# a PSTN call to a bound number reaches its DID. Two gateways stand on either side of a SIP trunk:
#
#   Alice (DSIP) ──invite {to: gw-a, destination: tel:+…, tel claim + binding}──▶ gw-a ──INVITE From +… Identity──▶ gw-b
#   gw-b ──invite {to: Bob's DID, G§5 tel claim: attestation A (verified)}──▶ Bob (DSIP)
#
#   1. Alice presents Carrier Example's binding for +15551234567. gw-a verifies it against her DID, and signs a
#      PASSporT (attest A, orig her number, dest Bob's) under its RFC 9060 delegate certificate. gw-b verifies the
#      PASSporT, looks the dialled number up on a dsip-node (Bob published his binding), and invites Bob, who sees
#      "PSTN caller +15551234567 · Gateway attested by gw-b.example · STIR attestation A (verified)".
#   2. Mallory presents no binding: gw-a presents its own From, no Identity, and the crossing is downgraded
#      identity-not-assertable (G§7); Bob sees "no attestation".
#   3. Alice dials a number nobody published: gw-b finds no route and refuses identity.unknown (404); Alice's call is
#      rejected identity.unknown.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay -p dsip-node
cargo build -q -p dsip-gateway --features host
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-number-gateway-demo}; rm -rf "$D"; mkdir -p "$D"
PORT=${RELAY_PORT:-8499}; R=wss://127.0.0.1:$PORT/dsip; NPORT=${NODE_PORT:-8099}; NODE=http://127.0.0.1:$NPORT
SIPA=${SIP_A:-127.0.0.1:5082}; SIPB=${SIP_B:-127.0.0.1:5084}
ALICE_TN=+15551234567; BOB_TN=+15552000001; NOBODY_TN=+15552000777
ALICE=did:web:alice.example; MALLORY=did:web:mallory.example; BOB=did:web:bob.example
GWA=did:web:gw-a.example; GWB=did:web:gw-b.example
fail() { echo "FAIL: $*"; exit 1; }

echo "════════ identities, the test number authority, the gateway's delegate certificate, a relay and a dsip-node"
$B/dsip identity init --dir "$D/alice" --name "Alice" --did-web $ALICE --also-known-as "tel:$ALICE_TN" >/dev/null
$B/dsip identity init --dir "$D/mallory" --name "Mallory" --did-web $MALLORY >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" --did-web $BOB --also-known-as "tel:$BOB_TN" >/dev/null
$B/dsip identity init --dir "$D/gw-a" --name "Gateway A" --did-web $GWA >/dev/null
$B/dsip identity init --dir "$D/gw-b" --name "Gateway B" --did-web $GWB >/dev/null
python3 demos/tn_issuer.py policy "$D/policy.json"
python3 demos/tn_issuer.py gateway-key "$D/gw-a.key"
python3 demos/tn_issuer.py bind A $ALICE_TN $ALICE "$D/alice.jws"
python3 demos/tn_issuer.py bind A $BOB_TN $BOB "$D/bob.jws"
DOCS=(--did-document "$D/alice/did.json" --did-document "$D/mallory/did.json" --did-document "$D/bob/did.json"
      --did-document "$D/gw-a/did.json" --did-document "$D/gw-b/did.json")
$B/dsip-relay --listen 127.0.0.1:$PORT --state "$D/relay" "${DOCS[@]}" >"$D/relay.log" 2>&1 & RELAY=$!
$B/dsip-node --http 127.0.0.1:$NPORT --tn-policy "$D/policy.json" >"$D/node.log" 2>&1 & NODEP=$!
trap 'kill $RELAY $NODEP ${GWAP:-} ${GWBP:-} 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && grep -q "^http:" "$D/node.log" && break; sleep 0.2; done
CA="$D/relay/cert.pem"
$B/dsip tn-publish --binding "$D/bob.jws" --node $NODE | sed 's/^/  /'

echo "════════ gateway A (Alice's side: asserts under its delegate certificate) and gateway B (Bob's side: verifies, routes)"
$B/dsip-gateway --sip-listen $SIPA --sip-peer $SIPB --local-ip 127.0.0.1 --sip-user gw-a \
  --identity "$D/gw-a" --relay $R --ca "$CA" "${DOCS[@]}" --tn-policy "$D/policy.json" \
  --sti-x5u https://gw.example/sti.pem --sti-key "$D/gw-a.key" >"$D/gw-a.log" 2>&1 & GWAP=$!
$B/dsip-gateway --sip-listen $SIPB --sip-peer $SIPA --local-ip 127.0.0.1 --sip-user gw-b \
  --identity "$D/gw-b" --relay $R --ca "$CA" "${DOCS[@]}" --tn-policy "$D/policy.json" \
  --tn-node $NODE >"$D/gw-b.log" 2>&1 & GWBP=$!
for _ in $(seq 50); do grep -q "DSIP leg" "$D/gw-a.log" && grep -q "DSIP leg" "$D/gw-b.log" && break; sleep 0.2; done
grep -h "^gateway\|^numbers\|^sti " "$D/gw-a.log" "$D/gw-b.log" | sed 's/^/  /' || true

call() { # n caller number [extra caller args]
  local n=$1 who=$2 number=$3; shift 3
  $B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --auto accept --media none "${DOCS[@]}" \
    --script "sleep 8; quit" >"$D/$n-bob.log" 2>&1 & BP=$!
  for _ in $(seq 50); do grep -q "capabilities" "$D/$n-bob.log" && break; sleep 0.2; done
  $B/dsip call --identity "$D/$who" --relay $R --ca "$CA" --to "tel:$number" --gateway $GWA --media none "${DOCS[@]}" \
    "$@" --script "sleep 4; hangup; sleep 1; quit" >"$D/$n-$who.log" 2>&1 || true
  kill $BP 2>/dev/null || true; wait $BP 2>/dev/null || true
  grep -E "^number|^claims|^← (answer|reject)|⚠" "$D/$n-$who.log" | sed "s/^/  $who: /" || true
  grep -E "^(assert|route|passport|← |→ )" "$D/gw-a.log" | tail -4 | sed 's/^/  gw-a: /' || true
  grep -E "^(assert|route|passport|← |→ )" "$D/gw-b.log" | tail -4 | sed 's/^/  gw-b: /' || true
  grep -E "^← invite|☎|🔎|⚠" "$D/$n-bob.log" | sed 's/^/  bob: /' || true
}

echo "════════ 1. Alice's bound number crosses to the PSTN attested, and reaches Bob through his binding"
call 1 alice $BOB_TN --tn-binding "$D/alice.jws"
grep -q "assert    $ALICE_TN · PASSporT attest A" "$D/gw-a.log" || fail "1: gateway A did not assert"
grep -q "passport  $ALICE_TN · STIR attestation A (verified)" "$D/gw-b.log" || fail "1: gateway B did not verify the PASSporT"
grep -q "route     $BOB_TN → $BOB  (binding" "$D/gw-b.log" || fail "1: gateway B did not route by the binding"
grep -q "☎  PSTN caller $ALICE_TN" "$D/1-bob.log" || fail "1: Bob saw no PSTN caller"
grep -q "🔎 trust: Gateway attested by gw-b.example · STIR attestation A (verified)" "$D/1-bob.log" || fail "1: Bob's basis is not the verified attestation"
grep -q "← answer" "$D/1-alice.log" || fail "1: Alice's call was not answered"

echo "════════ 2. Mallory has no binding: the gateway presents its own identity, and the crossing is downgraded"
call 2 mallory $BOB_TN
grep -q "assert    not assertable (no-binding)" "$D/gw-a.log" || fail "2: gateway A asserted without a binding"
grep -q "⚠  Trust downgraded crossing the gateway (§6.3): media is not encrypted on the PSTN trunk; your identity could not be asserted into the PSTN" "$D/2-mallory.log" \
  || fail "2: Mallory was not told the crossing was downgraded"
grep -q "🔎 trust: Gateway attested by gw-b.example · no attestation" "$D/2-bob.log" || fail "2: Bob's basis is not 'no attestation'"

echo "════════ 3. A number nobody published: no route, identity.unknown"
call 3 alice $NOBODY_TN --tn-binding "$D/alice.jws"
grep -q "route     $NOBODY_TN → nothing configured, no binding: identity.unknown (404)" "$D/gw-b.log" || fail "3: gateway B did not refuse"
grep -q "← reject .* reason=identity.unknown" "$D/3-alice.log" || fail "3: Alice's call was not rejected identity.unknown"

echo
echo "PASS: a DSIP caller's bound number crossed to the PSTN with a SHAKEN PASSporT (attestation A) signed under the"
echo "      gateway's RFC 9060 delegate certificate; the far gateway verified it and reached the callee through the"
echo "      binding he published; a caller without a binding crossed downgraded with no attestation; a number nobody"
echo "      published was refused identity.unknown."
