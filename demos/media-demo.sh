#!/usr/bin/env bash
# Phase 2 native media: two CLI endpoints complete a signed call and exchange DTLS-SRTP Opus audio.
# Alice sends a 440 Hz tone and records Bob; Bob sends 660 Hz and records Alice.
# SDP rides in transports[].sdp, ICE candidates in signed info after ACTIVE (§12.12, spec-gap 16).
#
# Usage: media-demo.sh [CALLER_BACKEND [CALLEE_BACKEND]]   backends: webrtc-rs (default) | forge
# Any `forge` argument builds the CLI with the `forge` feature (forge-media via git; vendored OpenSSL).
set -euo pipefail
cd "$(dirname "$0")/.."
BA=${1:-webrtc-rs}; BB=${2:-$BA}
FEAT=(); case "$BA$BB" in *forge*) FEAT=(--features dsip-cli/forge);; esac
cargo build -q -p dsip-cli -p dsip-relay "${FEAT[@]}"
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-media-demo}; rm -rf "$D"; mkdir -p "$D"
R=wss://127.0.0.1:8443/dsip
$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT; sleep 1.5; CA="$D/relay/cert.pem"

$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --auto accept --media tone:660 --record "$D/bob-heard-alice.ogg" \
  --media-backend "$BB" --script "sleep 16; quit" >"$D/bob.log" 2>&1 & P=$!
sleep 1.5
echo "════════ alice ($BA) calls bob ($BB) with media (tone 440 Hz), talks 8 s, hangs up"
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --media tone:440 --record "$D/alice-heard-bob.ogg" --media-backend "$BA" \
  --script "sleep 8; hangup; sleep 1; quit" | grep -E "^(→|←|  ◆|  ♫|  media|media)"
wait $P
echo; echo "──── bob's side:"; grep -E "^(→|←|  ◆|  ♫|  media|media)" "$D/bob.log"
echo; echo "──── recordings:"; ls -la "$D"/*.ogg
python3 - "$D" <<'PY'
import sys, pathlib
for f in sorted(pathlib.Path(sys.argv[1]).glob("*.ogg")):
    b = f.read_bytes()
    print(f"{f.name}: {len(b)} bytes, {b.count(b'OggS')} Ogg pages, {'OpusHead ok' if b'OpusHead' in b else 'no OpusHead'}")
PY
