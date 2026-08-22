#!/usr/bin/env bash
# The whole thing, end to end: two fresh DIDs discover each other through the DHT (no DNS, no
# DID document, no directory) and hold a real conversation — signed DSIP signaling, DTLS-SRTP
# Opus media, and actual recorded speech verified to have crossed intact both ways.
#
# Combines the Workstream-D DHT discovery demo and the media/speech demo into one proof.
# Needs: espeak-ng + ffmpeg + python3(numpy) for the speech + verification; degrades to tones
# (frequency-checked) without espeak-ng, and skips the audio check without ffmpeg/numpy.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay -p dsip-dht
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-real-call-dht}; rm -rf "$D"; mkdir -p "$D"
FAIL=0

# ---- speech (or tones) -------------------------------------------------------
ALICE_LINE="Hi Bob, this is Alice, calling you over the DSIP decentralized network."
BOB_LINE="Hi Alice, I hear you clearly. We found each other through the hash table, no phone company."
SPEECH=0
if command -v espeak-ng >/dev/null && command -v ffmpeg >/dev/null; then
  SPEECH=1
  espeak-ng -v en-us    -s 150 -w "$D/alice-src.wav" "$ALICE_LINE" 2>/dev/null
  espeak-ng -v en-us+f3 -s 150 -w "$D/bob-src.wav"   "$BOB_LINE"   2>/dev/null
  for w in alice bob; do ffmpeg -y -loglevel error -i "$D/$w-src.wav" -ar 48000 -ac 1 -c:a libopus -b:a 24k "$D/$w.ogg"; done
  AMEDIA="file:$D/alice.ogg"; BMEDIA="file:$D/bob.ogg"
  echo "Alice will say: \"$ALICE_LINE\""; echo "Bob   will say: \"$BOB_LINE\""; echo
else
  echo "espeak-ng/ffmpeg not found — using tones (Alice 440 Hz, Bob 660 Hz)."; echo
  AMEDIA="tone:440"; BMEDIA="tone:660"
fi

# ---- 1. a three-node hints overlay ------------------------------------------
$B/dsip-dht-node --listen /ip4/127.0.0.1/tcp/4001 --control 127.0.0.1:4101 >"$D/n0.log" 2>&1 & N0=$!
sleep 1; BOOT=$(grep -m1 '^listening: ' "$D/n0.log" | cut -d' ' -f2)
$B/dsip-dht-node --listen /ip4/127.0.0.1/tcp/4002 --control 127.0.0.1:4102 --bootstrap "$BOOT" >"$D/n1.log" 2>&1 & N1=$!
$B/dsip-dht-node --listen /ip4/127.0.0.1/tcp/4003 --control 127.0.0.1:4103 --bootstrap "$BOOT" >"$D/n2.log" 2>&1 & N2=$!
$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $N0 $N1 $N2 $RELAY 2>/dev/null || true' EXIT
sleep 1.5; CA="$D/relay/cert.pem"
echo "════ 1. DHT overlay up (bootstrap $BOOT); relay up (wss, self-signed)"

# ---- 2. two fresh DIDs -------------------------------------------------------
$B/dsip identity init --dir "$D/alice" --name Alice >/dev/null
$B/dsip identity init --dir "$D/bob"   --name Bob   >/dev/null
ALICE=$(python3 -c "import json;print(json.load(open('$D/alice/identity.json'))['identity'])")
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")
echo "════ 2. two fresh did:key identities"
echo "        Alice  $ALICE"
echo "        Bob    $BOB"

# ---- 3. Bob binds + publishes a signed reachability hint into the DHT --------
$B/dsip answer --identity "$D/bob" --relay wss://127.0.0.1:8443/dsip --ca "$CA" --dht "$BOOT" --publish-hint --auto accept \
  --media "$BMEDIA" --record "$D/bob-heard.ogg" --script "sleep 18; quit" >"$D/bob.log" 2>&1 & P=$!
sleep 4
echo; echo "════ 3. Bob published a signed, expiring reachability hint into the DHT (§8.3)"
grep -E '^(dht|hint)' "$D/bob.log" | sed 's/^/        /'
grep -q '^hint .*published' "$D/bob.log" || { echo "        ✗ hint not published"; FAIL=1; }

# ---- 4. Alice resolves Bob's did:key via the DHT — no DNS, no DID document ---
echo; echo "════ 4. Alice resolves Bob's did:key through the DHT (no DNS, no directory)"
$B/dsip resolve "$BOB" --dht "$BOOT" >"$D/resolve.log" 2>&1 || true
grep -E '^(method|authority|hints)' "$D/resolve.log" | sed 's/^/        /'
grep -q 'reachability-hint' "$D/resolve.log" || { echo "        ✗ no hint resolved from DHT"; FAIL=1; }

# ---- 5. Alice calls over the DHT-discovered relay, with media ---------------
echo; echo "════ 5. Alice places a real media call over the DHT-discovered relay"
$B/dsip call --identity "$D/alice" --ca "$CA" --dht "$BOOT" --to "$BOB" \
  --media "$AMEDIA" --record "$D/alice-heard.ogg" --script "sleep 10; hangup; sleep 1; quit" >"$D/alice.log" 2>&1
wait $P 2>/dev/null
grep -E 'ice connected|closed —' "$D/alice.log" | sed 's/^/        /'
grep -q 'first inbound RTP' "$D/alice.log" || { echo "        ✗ no media received"; FAIL=1; }

# ---- 6. verify the audio crossed intact -------------------------------------
echo; echo "════ 6. verify the conversation crossed the call"
if command -v ffmpeg >/dev/null; then
  for f in alice bob alice-heard bob-heard; do [ -f "$D/$f.ogg" ] && ffmpeg -y -loglevel error -i "$D/$f.ogg" -ar 16000 -ac 1 -f s16le "$D/$f.pcm" 2>/dev/null || true; done
  python3 - "$D" "$SPEECH" <<'PY' || FAIL=1
import sys, numpy as np, os
D, speech = sys.argv[1], sys.argv[2] == "1"
def load(p):
    f=f"{D}/{p}.pcm"; return np.fromfile(f,dtype=np.int16).astype(np.float32) if os.path.exists(f) else None
def env(x,win=320):
    n=len(x)//win; return np.array([np.sqrt(np.mean(x[i*win:(i+1)*win]**2)) for i in range(n)])
def rhythm(sent,heard,secs=2.5):
    es=env(sent)[:int(secs*50)]; eh=env(heard)
    if len(es)<20 or len(eh)<len(es): return 0.0
    es=(es-es.mean())/(es.std()+1e-9)
    return max(float(np.dot(es,(lambda w:(w-w.mean())/(w.std()+1e-9))(eh[l:l+len(es)]))/len(es)) for l in range(len(eh)-len(es)))
def dominant(x):
    seg=x[24000:72000]; seg=seg-seg.mean()
    sp=np.abs(np.fft.rfft(seg*np.hanning(len(seg)))); fr=np.fft.rfftfreq(len(seg),1/48000)
    # x is 16k here → recompute at its rate
    sp=np.abs(np.fft.rfft(seg*np.hanning(len(seg)))); fr=np.fft.rfftfreq(len(seg),1/16000)
    return fr[np.argmax(sp)]
ok=True
for who,s,h,hz in [("Alice→Bob","alice","bob-heard",440),("Bob→Alice","bob","alice-heard",660)]:
    S,H=load(s),load(h)
    if S is None or H is None: print(f"        {who}: missing audio"); ok=False; continue
    if speech:
        c=rhythm(S,H); good=c>0.6
        print(f"        {who}: heard {len(H)/16000:.1f}s, speech-rhythm match {c:.2f}  {'✓ words crossed intact' if good else '✗'}")
    else:
        f=dominant(H); good=abs(f-hz)<20
        print(f"        {who}: heard {len(H)/16000:.1f}s, dominant {f:.0f} Hz (sent {hz})  {'✓ tone crossed faithfully' if good else '✗'}")
    ok&=good
sys.exit(0 if ok else 1)
PY
else
  echo "        (install ffmpeg + numpy to verify the audio; recordings are in $D)"
fi

echo
if [ "$FAIL" = 0 ]; then
  echo "════ ✓ TWO DIDs FOUND EACH OTHER ON THE DHT AND HELD A REAL CONVERSATION — no DNS, no carrier"
else
  echo "════ ✗ something did not check out — see logs in $D"; exit 1
fi
