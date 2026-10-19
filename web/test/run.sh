#!/usr/bin/env bash
# The headless client tests: a relay serves the client; browsers (one storage context each) call each other through
# it, and the gateway fixture (the two-gateway demo's setup: did:web identities, the test number authority, a
# dsip-node, two gateways over a SIP trunk) stands behind it for the stage 4 test.
# Usage: web/test/run.sh [firefox|chromium|all]   (default: firefox; CI runs both). Needs `npm ci` in web/ and
# `npx playwright install [--with-deps] <browser>`. TESTS="devices gateway" runs a subset. Stage 5 adds a second relay
# and the deployment routes on the first (config.json, /turn, the node proxied at /dsip/v1/). Stage 6 adds two
# mailboxes (one per operator, each enrolling the did:key identities that bind, spec-gap 115), the first served as
# relay A's operator default; a hub finds the other side's mailbox through the node's hints (M§4.2).
set -euo pipefail
cd "$(dirname "$0")/../.."
BROWSERS=${1:-firefox}
cargo build -q -p dsip-relay -p dsip-cli -p dsip-node -p dsip-mailbox
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

# --- relay A (serving the client, with the stage 5 deployment routes: the operator's config.json, TURN credentials
# minted at /turn, the dsip-node proxied at /dsip/v1/), relay B (another operator: calls between the two go through
# the hints the nodes hold), the dsip-node (an overlay of one, holding hints and Bob's binding), the two gateways
NPORT=${NODE_PORT:-8099}; NODE=http://127.0.0.1:$NPORT
LISTEN_B=${LISTEN_B:-127.0.0.1:8444}
TURN_SECRET=${TURN_SECRET:-$(openssl rand -hex 16)}
# --- the mailboxes (stage 6): A is relay A's operator default; B is another operator's, set in Bob's settings. Each
# serves the identities that enrol by binding; each finds the other's members through the node's hints. The cap is
# for both browsers' runs together (every test makes fresh identities: about 35 at A per browser), with room to grow.
MBX_A=${MAILBOX_A:-127.0.0.1:9443}; MBX_B=${MAILBOX_B:-127.0.0.1:9444}
rm -rf "$D/mbx-a" "$D/mbx-b"   # fresh mailboxes: enrolment is bounded, and a reused DEMO_DIR would fill it
$B/dsip-mailbox --listen "$MBX_A" --state "$D/mbx-a" --serve-any 256 --hints-node $NODE --ca "$D/mbx-ca.pem" >"$D/mbx-a.log" 2>&1 & MBXA=$!
$B/dsip-mailbox --listen "$MBX_B" --state "$D/mbx-b" --serve-any 256 --hints-node $NODE --ca "$D/mbx-ca.pem" >"$D/mbx-b.log" 2>&1 & MBXB=$!
for i in $(seq 1 80); do [ -s "$D/mbx-a/service.did" ] && [ -s "$D/mbx-b/service.did" ] && grep -q "mailbox did:key" "$D/mbx-a.log" && grep -q "mailbox did:key" "$D/mbx-b.log" && break; sleep 0.25; done
[ -s "$D/mbx-a/service.did" ] && [ -s "$D/mbx-b/service.did" ] || { echo "the mailboxes did not start"; cat "$D/mbx-a.log" "$D/mbx-b.log"; exit 1; }
cat "$D/mbx-a/cert.pem" "$D/mbx-b/cert.pem" > "$D/mbx-ca.pem"
MAILBOX_A_DID=$(cat "$D/mbx-a/service.did"); MAILBOX_B_DID=$(cat "$D/mbx-b/service.did")
printf '{"nodes": ["https://%s"], "publish_hint": true, "mailbox": {"uri": "wss://%s/dsip", "did": "%s"}}\n' "$LISTEN" "$MBX_A" "$MAILBOX_A_DID" > "$D/client.json"
$B/dsip-relay --listen "$LISTEN" --state "$D/relay" --www web "${DOCS[@]}" --client-config "$D/client.json" \
  --turn-uri turn:127.0.0.1:3478 --turn-secret "$TURN_SECRET" --turn-ttl 600 --node-proxy 127.0.0.1:$NPORT >"$D/relay.log" 2>&1 & RELAY=$!
$B/dsip-relay --listen "$LISTEN_B" --state "$D/relay-b" "${DOCS[@]}" >"$D/relay-b.log" 2>&1 & RELAYB=$!
$B/dsip-node --http 127.0.0.1:$NPORT --overlay-listen /ip4/127.0.0.1/tcp/${OVERLAY_PORT:-4699} --tn-policy "$D/policy.json" >"$D/node.log" 2>&1 & NODEP=$!
trap 'kill $RELAY $RELAYB $NODEP $MBXA $MBXB ${GWAP:-} ${GWBP:-} 2>/dev/null || true' EXIT
for i in $(seq 1 80); do grep -q 'listening on' "$D/relay.log" && [ -s "$D/relay/cert.pem" ] && grep -q 'listening on' "$D/relay-b.log" && grep -q "^http:" "$D/node.log" && break; sleep 0.25; done
grep -q 'listening on' "$D/relay.log" || { echo "relay did not start"; cat "$D/relay.log"; exit 1; }
grep -q 'listening on' "$D/relay-b.log" || { echo "relay B did not start"; cat "$D/relay-b.log"; exit 1; }
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
  for t in ${TESTS:-call first-contact devices gateway deploy messaging messaging-devices messaging-voice messaging-voicemail messaging-rejoin messaging-successor messaging-pending messaging-rebind messaging-group messaging-hub-move messaging-interop call-records call-recording}; do
    (cd web && BROWSER=$b URL="https://$LISTEN/" RELAY_B="wss://$LISTEN_B/dsip" TURN_SECRET="$TURN_SECRET" FIXTURE="$D" \
       MAILBOX_A="wss://$MBX_A/dsip" MAILBOX_A_DID="$MAILBOX_A_DID" MAILBOX_B="wss://$MBX_B/dsip" MAILBOX_B_DID="$MAILBOX_B_DID" \
       MAILBOX_BIN="$(cd .. && pwd)/$B/dsip-mailbox" DSIP_BIN="$(cd .. && pwd)/$B/dsip" NODE_URL="$NODE" node test/$t.mjs) || rc=1
  done
done
exit $rc
