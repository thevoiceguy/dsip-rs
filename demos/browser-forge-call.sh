#!/usr/bin/env bash
# Browser ↔ native-on-forge, by hand — the one interop path the headless suite can't reach.
#
# The conformance suite pairs forge-media against webrtc-rs (both Rust). A real browser is a
# THIRD WebRTC stack (Chrome/Firefox libwebrtc): different DTLS cert defaults, cipher order and
# ICE timing. This script stands up everything but the human — relay + served page + a native
# `dsip answer` on the forge backend that auto-accepts, PLAYS speech (so you hear forge → browser)
# and RECORDS the browser's mic (so we can prove browser → forge decoded) — then, on exit,
# checks the recording is real audio: forge completed DTLS-SRTP with the browser and decoded its
# Opus RTP. The forge↔browser DTLS/cipher path itself is already de-risked upstream (forge PRs
# #117/#118 made the DTLS cert ECDSA/P-256 and fixed the SRTP cipher order precisely so browsers
# interoperate); this is the live confirmation.
#
# Needs: espeak-ng + ffmpeg (speech + ogg→pcm); numpy for the energy check. Degrades gracefully.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
[ -f demos/browser/pkg/dsip_wasm.js ] || demos/browser/build.sh
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-browser-forge}; rm -rf "$D"; mkdir -p "$D"
LISTEN=${LISTEN:-127.0.0.1:8443}
HOLD=${HOLD:-40}   # seconds the native endpoint stays up for you to place the call

# ---- Bob's line (forge plays this; you should hear it in the browser) --------
BOB_LINE="Hi there. This is the native endpoint, running on the forge media stack, talking to your browser."
if command -v espeak-ng >/dev/null && command -v ffmpeg >/dev/null; then
  espeak-ng -v en-us+f3 -s 150 -w "$D/bob-src.wav" "$BOB_LINE" 2>/dev/null
  ffmpeg -y -loglevel error -i "$D/bob-src.wav" -ar 48000 -ac 1 -c:a libopus -b:a 24k "$D/bob.ogg"
  BMEDIA="file:$D/bob.ogg"
else
  echo "espeak-ng/ffmpeg not found — forge will send a 660 Hz tone instead of speech."
  BMEDIA="tone:660"
fi

# ---- relay (serves the page over the same TLS port it speaks wss on) ---------
$B/dsip-relay --listen "$LISTEN" --state "$D/relay" --www demos/browser >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY ${BOBPID:-} 2>/dev/null || true' EXIT
for i in $(seq 1 40); do grep -q 'listening on' "$D/relay.log" && break; sleep 0.25; done
CA="$D/relay/cert.pem"

# ---- Bob: native endpoint on the FORGE backend, auto-accepting ---------------
$B/dsip identity init --dir "$D/bob" --name Bob >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
$B/dsip answer --identity "$D/bob" --relay "wss://$LISTEN/dsip" --ca "$CA" \
  --media-backend forge --media "$BMEDIA" --record "$D/browser-heard.ogg" \
  --auto accept --script "sleep $HOLD; quit" >"$D/bob.log" 2>&1 & BOBPID=$!

cat <<TXT

  ════════════════════════════════════════════════════════════════════════════
   BROWSER ↔ NATIVE-ON-FORGE — do these three things in a real browser now:

   1. Open:            https://$LISTEN/?as=alice
                       (accept the self-signed cert warning once — covers page + wss)
   2. Callee DID:      paste this, then click  call (audio)
                       $BOB
   3. Grant the mic when asked, then talk for ~10 seconds and click hang up.

   You should HEAR the native endpoint say a sentence  → that is forge → browser.
   Your speech is recorded on the native side           → that is browser → forge.

   The native endpoint holds the line for ${HOLD}s, then this script verifies the
   captured audio. Watching the signaling: tail -f $D/bob.log
  ════════════════════════════════════════════════════════════════════════════

TXT

wait $BOBPID 2>/dev/null || true
kill $RELAY 2>/dev/null || true

# ---- what the wire showed ----------------------------------------------------
echo "──── signaling / media the native (forge) side saw:"
grep -iE 'hello bound|ice connected|dtls|first inbound RTP|answer|active|closed' "$D/bob.log" | sed 's/^/     /' | head -20 || true

# ---- prove forge decoded live browser audio ---------------------------------
echo; echo "──── browser → forge audio (proves DTLS-SRTP + Opus decode across stacks):"
if [ -s "$D/browser-heard.ogg" ] && command -v ffmpeg >/dev/null; then
  ffmpeg -y -loglevel error -i "$D/browser-heard.ogg" -ar 16000 -ac 1 -f s16le "$D/browser-heard.pcm" 2>/dev/null || true
  python3 - "$D/browser-heard.pcm" <<'PY' || true
import sys, os
try: import numpy as np
except Exception: print("     (numpy absent — recording exists, energy check skipped)"); sys.exit(0)
p=sys.argv[1]
if not os.path.exists(p) or os.path.getsize(p)==0: print("     ✗ no decoded audio — did the call connect and did you grant the mic?"); sys.exit(0)
x=np.fromfile(p,dtype=np.int16).astype(np.float32); secs=len(x)/16000
rms=float(np.sqrt(np.mean(x**2))); active=float((np.abs(x)>200).mean())
ok = secs>2 and rms>50 and active>0.05
print(f"     heard {secs:.1f}s from the browser, RMS {rms:.0f}, {active*100:.0f}% active")
print("     ✓ forge completed DTLS-SRTP with the browser and decoded its Opus RTP" if ok
      else "     ✗ recording too short/quiet — connection or mic issue (see $D/bob.log)")
PY
else
  echo "     (no recording — the call may not have connected; see $D/bob.log)"
fi
echo; echo "  Artifacts in $D — bob.log (signaling), browser-heard.ogg (what forge received)."
