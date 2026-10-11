#!/usr/bin/env bash
# The headless client tests: a relay serves the client; browsers (one storage context each) call each other through
# it, and the gateway fixture (the two-gateway demo's setup: did:web identities, the test number authority, a
# dsip-node, two gateways over a SIP trunk) stands behind it for the stage 4 test.
# Usage: web/test/run.sh [firefox|chromium|all]   (default: firefox; CI runs both). Needs `npm ci` in web/ and
# `npx playwright install [--with-deps] <browser>`. TESTS="devices gateway" runs a subset.
set -euo pipefail
cd "$(dirname "$0")/../.."
BROWSERS=${1:-firefox}
cargo build -q -p dsip-relay -p dsip-cli -p dsip-node
cargo build -q -p dsip-gateway --features host
[ -f web/pkg/dsip_wasm.js ] || web/build.sh
D=${DEMO_DIR:-$(mktemp -d)}; mkdir -p "$D"
LISTEN=${LISTEN:-127.0.0.1:8443}
B=target/debug

# --- the gateway fixture (stage 4): identities the browsers enrol as devices of, bindings, documents
ALICE=did:web:alice.example; BOB=did:web:bob.example; CAROL=did:web:carol.example
GWA=did:web:gw-a.example; GWB=did:web:gw-b.example
$B/dsip identity init --dir "$D/alice" --name Alice --did-web $ALICE --also-known-as tel:+15551234567 >/dev/null
$B/dsip identity init --dir "$D/bob" --name Bob --did-web $BOB --also-known-as tel:+15552000001 >/dev/null
$B/dsip identity init --dir "$D/carol" --name Carol --did-web $CAROL --also-known-as tel:+15551234567 >/dev/null
$B/dsip identity init --dir "$D/gw-a" --name "Gateway A" --did-web $GWA >/dev/null
$B/dsip identity init --dir "$D/gw-b" --name "Gateway B" --did-web $GWB >/dev/null
python3 demos/tn_issuer.py policy "$D/policy.json"
python3 demos/tn_issuer.py gateway-key "$D/gw-a.key"
python3 demos/tn_issuer.py bind A +15551234567 $ALICE "$D/alice.jws"
python3 demos/tn_issuer.py bind A +15552000001 $BOB "$D/bob.jws"
python3 demos/tn_issuer.py bind B +15551234567 $CAROL "$D/carol.jws"      # the number, ported to another identity (N§5)
DOCS=(); for n in alice bob carol gw-a gw-b; do DOCS+=(--did-document "$D/$n/did.json"); done

# --- the relay (serving the client), a dsip-node holding Bob's binding, the two gateways
$B/dsip-relay --listen "$LISTEN" --state "$D/relay" --www web "${DOCS[@]}" >"$D/relay.log" 2>&1 & RELAY=$!
NPORT=${NODE_PORT:-8099}; NODE=http://127.0.0.1:$NPORT
$B/dsip-node --http 127.0.0.1:$NPORT --tn-policy "$D/policy.json" >"$D/node.log" 2>&1 & NODEP=$!
trap 'kill $RELAY $NODEP ${GWAP:-} ${GWBP:-} 2>/dev/null || true' EXIT
for i in $(seq 1 80); do grep -q 'listening on' "$D/relay.log" && [ -s "$D/relay/cert.pem" ] && grep -q "^http:" "$D/node.log" && break; sleep 0.25; done
grep -q 'listening on' "$D/relay.log" || { echo "relay did not start"; cat "$D/relay.log"; exit 1; }
grep -q "^http:" "$D/node.log" || { echo "dsip-node did not start"; cat "$D/node.log"; exit 1; }
CA="$D/relay/cert.pem"
$B/dsip tn-publish --binding "$D/bob.jws" --node $NODE >/dev/null
SIPA=${SIP_A:-127.0.0.1:5082}; SIPB=${SIP_B:-127.0.0.1:5084}
$B/dsip-gateway --sip-listen $SIPA --sip-peer $SIPB --local-ip 127.0.0.1 --sip-user gw-a \
  --identity "$D/gw-a" --relay "wss://$LISTEN/dsip" --ca "$CA" "${DOCS[@]}" --tn-policy "$D/policy.json" \
  --sti-x5u https://gw.example/sti.pem --sti-key "$D/gw-a.key" >"$D/gw-a.log" 2>&1 & GWAP=$!
$B/dsip-gateway --sip-listen $SIPB --sip-peer $SIPA --local-ip 127.0.0.1 --sip-user gw-b \
  --identity "$D/gw-b" --relay "wss://$LISTEN/dsip" --ca "$CA" "${DOCS[@]}" --tn-policy "$D/policy.json" \
  --tn-node $NODE >"$D/gw-b.log" 2>&1 & GWBP=$!
for _ in $(seq 50); do grep -q "DSIP leg" "$D/gw-a.log" && grep -q "DSIP leg" "$D/gw-b.log" && break; sleep 0.2; done
grep -q "DSIP leg" "$D/gw-a.log" && grep -q "DSIP leg" "$D/gw-b.log" || { echo "the gateways did not start"; tail -20 "$D/gw-a.log" "$D/gw-b.log"; exit 1; }

rc=0
for b in $(echo "$BROWSERS" | sed 's/all/firefox chromium/; s/,/ /g'); do
  echo "== $b"
  for t in ${TESTS:-call first-contact devices gateway}; do
    (cd web && BROWSER=$b URL="https://$LISTEN/" FIXTURE="$D" node test/$t.mjs) || rc=1
  done
done
exit $rc
