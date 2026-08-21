#!/usr/bin/env bash
# Phase 3 — Verified Broadcast (§22, §27): bob publishes a signed record to his relay (the authority);
# carol (a CDN) attaches a derivative-bound provenance statement; alice subscribes, verifies the
# publisher independently of the relay, selects a variant, and sees the delivery path. Then presence.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --workspace
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-bcast-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8443/dsip
for who in alice bob carol; do $B/dsip identity init --dir "$D/$who" --name "${who^}" >/dev/null; done
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"
STREAM="$BOB:radio:main"

echo "════════ 1. bob publishes (two variants: Opus/WebRTC and AAC/HLS), policy allows transcoding"
$B/dsip broadcast publish --identity "$D/bob" --relay $R --ca "$CA" --stream radio:main --title "Bob Live Radio" \
  --variant "main-opus,codec:audio/opus,transport:webrtc,wss://live.bob.example/dsip/webrtc/main" \
  --variant "main-aac-hls,codec:audio/aac,transport:hls,https://live.bob.example/main.m3u8" \
  --policy transcoding=allowed --policy redistribution=allowed-with-attribution
PUB=$(python3 -c "import json;print(json.load(open('$D/bob/last-publication.json'))['publication'])")

echo; echo "════════ 2. alice subscribes (receiver supports Opus/WebRTC): first notify carries the record; she verifies bob's signature herself"
$B/dsip broadcast subscribe --identity "$D/alice" --relay $R --ca "$CA" --target "$STREAM" --wait 3

echo; echo "════════ 3. carol (CDN) transcodes main-opus → main-aac-hls and signs a provenance statement; an HLS-only receiver sees the full path"
$B/dsip broadcast provenance --identity "$D/carol" --relay $R --ca "$CA" --stream "$STREAM" --publication "$PUB" \
  --operation transcode --input main-opus --output main-aac-hls --uri https://cdn.carol.example/bob/main.m3u8
$B/dsip broadcast subscribe --identity "$D/alice" --relay $R --ca "$CA" --target "$STREAM" --wait 3 \
  --codec codec:audio/aac --transport transport:hls | grep -vE "^(identity|authority)"

echo; echo "════════ 4. live subscription: alice stays subscribed while bob ends the stream, then withdraws it"
$B/dsip broadcast subscribe --identity "$D/alice" --relay $R --ca "$CA" --target "$STREAM" --wait 8 \
  | grep -E "notify|publication state|terminated" & P=$!
sleep 2; $B/dsip broadcast publish --identity "$D/bob" --relay $R --ca "$CA" --stream radio:main --state ended --title "Bob Live Radio" >/dev/null
sleep 2; $B/dsip broadcast unpublish --identity "$D/bob" --relay $R --ca "$CA" --stream radio:main >/dev/null
wait $P

echo; echo "════════ 5. anti-enumeration: subscribing to a stream that does not exist is indistinguishable from one you may not see"
$B/dsip broadcast subscribe --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB:radio:secret" --wait 3 | grep -E "reject"

echo; echo "════════ 6. presence (§9.3 event class, 3,600 s cap): a 7200 s request is refused at the boundary; 3600 s works, and bob's device binding is reported"
$B/dsip broadcast subscribe --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --events presence --expires-in 7200 --wait 3 | grep -E "error"
$B/dsip broadcast subscribe --identity "$D/alice" --relay $R --ca "$CA" --target "$BOB" --events presence --expires-in 3600 --wait 7 \
  | grep -E "notify|presence" & P=$!
sleep 2; $B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --script "sleep 2; quit" >/dev/null 2>&1
wait $P
