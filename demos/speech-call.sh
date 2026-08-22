#!/usr/bin/env bash
# Real speech over a DSIP call: two identities, a signed call, DTLS-SRTP Opus, and actual
# recorded speech verified to have crossed intact — proving the fixed Ogg file source
# (dsip-media/src/ogg.rs) plays standard multi-frame-per-page Ogg/Opus files.
#
# Needs: espeak-ng, ffmpeg, python3 (numpy). Degrades to tones if espeak-ng is absent.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-speech-call}; rm -rf "$D"; mkdir -p "$D"; R=wss://127.0.0.1:8443/dsip

ALICE_LINE="Hi Bob, this is Alice. Can you hear me clearly over this DSIP call?"
BOB_LINE="Hi Alice, yes I hear you perfectly. This is a real end to end conversation."
if command -v espeak-ng >/dev/null && command -v ffmpeg >/dev/null; then
  espeak-ng -v en-us    -s 150 -w "$D/alice-src.wav" "$ALICE_LINE" 2>/dev/null
  espeak-ng -v en-us+f3 -s 150 -w "$D/bob-src.wav"   "$BOB_LINE"   2>/dev/null
  for w in alice bob; do ffmpeg -y -loglevel error -i "$D/$w-src.wav" -ar 48000 -ac 1 -c:a libopus -b:a 24k "$D/$w.ogg"; done
  AMEDIA="file:$D/alice.ogg"; BMEDIA="file:$D/bob.ogg"
  echo "Alice says: \"$ALICE_LINE\""; echo "Bob says:   \"$BOB_LINE\""
else
  echo "espeak-ng/ffmpeg not found — using tones (440/660 Hz)."
  AMEDIA="tone:440"; BMEDIA="tone:660"
fi

$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT; sleep 2; CA="$D/relay/cert.pem"
$B/dsip identity init --dir "$D/alice" --name Alice >/dev/null
$B/dsip identity init --dir "$D/bob"   --name Bob   >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")

echo "════ Bob answers (records what he hears); Alice calls (records what she hears)"
$B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --auto accept --media "$BMEDIA" --record "$D/bob-heard.ogg" \
  --script "sleep 14; quit" >"$D/bob.log" 2>&1 & P=$!
sleep 2
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" --media "$AMEDIA" --record "$D/alice-heard.ogg" \
  --script "sleep 10; hangup; sleep 1; quit" >"$D/alice.log" 2>&1
wait $P 2>/dev/null
grep -E 'closed —|ice connected' "$D/alice.log" "$D/bob.log"

command -v ffmpeg >/dev/null || { echo "(install ffmpeg+numpy to verify the audio)"; exit 0; }
for f in alice bob alice-heard bob-heard; do [ -f "$D/$f.ogg" ] && ffmpeg -y -loglevel error -i "$D/$f.ogg" -ar 16000 -ac 1 -f s16le "$D/$f.pcm" 2>/dev/null || true; done
python3 - "$D" <<'PY'
import sys, numpy as np, os
D=sys.argv[1]
def load(p):
    f=f"{D}/{p}.pcm"; return np.fromfile(f,dtype=np.int16).astype(np.float32) if os.path.exists(f) else None
def env(x,win=320):
    n=len(x)//win; return np.array([np.sqrt(np.mean(x[i*win:(i+1)*win]**2)) for i in range(n)])
def match(sent,heard,secs=2.5):
    es=env(sent)[:int(secs*50)]; eh=env(heard)
    if len(es)<20 or len(eh)<len(es): return 0.0
    es=(es-es.mean())/(es.std()+1e-9)
    return max((float(np.dot(es,(w:=eh[l:l+len(es)]-eh[l:l+len(es)].mean())/(eh[l:l+len(es)].std()+1e-9))/len(es))) for l in range(len(eh)-len(es)))
ok=True
for who,s,h in [("Alice→Bob","alice","bob-heard"),("Bob→Alice","bob","alice-heard")]:
    S,H=load(s),load(h)
    if S is None or H is None: print(f"{who}: missing audio"); ok=False; continue
    c=match(S,H); good=c>0.6; ok&=good
    print(f"{who}: heard {len(H)/16000:.1f}s, speech-rhythm match {c:.2f}  {'✓ came through intact' if good else '✗'}")
print("REAL SPEECH CROSSED THE DSIP CALL ✓" if ok else "verification failed"); sys.exit(0 if ok else 1)
PY
