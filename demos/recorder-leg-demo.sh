#!/usr/bin/env bash
# DSIP Recording Profile (draft, C§6): the recorder leg. Bob's organisation records his calls with its recorder, a
# DSIP identity whose delegation carries dsip.record. Bob's side declares the recording in the call (C§3), and from a
# second device of Bob's identity opens recording sessions to that recorder, one per voice, sendonly, forwarding the
# call's Opus unchanged, end to end (DTLS-SRTP). No relay sees media; nothing is decrypted in the middle.
#   1. A full call: the recorder ends with two Ogg/Opus files, Bob's voice and Alice's, and RFC 7865-shaped metadata.
#   2. Alice never accepts being recorded (C§4): her client holds her audio, so the recorder gets none of it.
#   3. Bob's side declares a "recorder" whose delegation lacks dsip.record: the recording party refuses it before
#      sending anything (bye policy.blocked).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p dsip-cli -p dsip-relay
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-recorder-leg-demo}; rm -rf "$D"; mkdir -p "$D"
PORT=${RELAY_PORT:-8513}; R=wss://127.0.0.1:$PORT/dsip; MB=(--media-backend "${MEDIA_BACKEND:-forge}")
fail() { echo "FAIL: $*"; exit 1; }
did() { python3 -c "import json;print(json.load(open('$1/identity.json'))['identity'])"; }
$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
$B/dsip identity init --dir "$D/bob-rec" --name "Bob (recording device)" --controller-from "$D/bob" >/dev/null
$B/dsip identity init --dir "$D/rec" --name "Acme compliance recorder" --capability dsip.record >/dev/null
$B/dsip identity init --dir "$D/fake" --name "Not a recorder" >/dev/null
BOB=$(did "$D/bob"); REC=$(did "$D/rec"); FAKE=$(did "$D/fake")
$B/dsip-relay --listen 127.0.0.1:$PORT --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true; kill $(jobs -p) 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -s "$D/relay/cert.pem" ] && break; sleep 0.2; done; CA="$D/relay/cert.pem"
recorder() { # identity dir log seconds
  $B/dsip recorder --identity "$1" --relay $R --ca "$CA" --dir "$2" --seconds "$4" "${MB[@]}" >"$3" 2>&1 & RP=$!
  for _ in $(seq 50); do grep -q "bound" "$3" && break; sleep 0.2; done
}
bob() { # log recorder
  $B/dsip answer --identity "$D/bob" --relay $R --ca "$CA" --auto accept --media tone:660 --recorded-by "$2" \
    --record-device "$D/bob-rec" "${MB[@]}" --script "sleep 13; quit" >"$1" 2>&1 & BP=$!
  for _ in $(seq 50); do grep -q "capabilities" "$1" && break; sleep 0.2; done
}

echo "════════ 1. Bob is recorded by $REC; Alice accepts (standing policy); a 8 s call"
recorder "$D/rec" "$D/out1" "$D/1-rec.log" 22
bob "$D/1-bob.log" "$REC"
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" "${MB[@]}" --media tone:440 --recording-accept always \
  --script "sleep 8; hangup; sleep 1; quit" >"$D/1-alice.log" 2>&1 || true
wait $BP || true; wait $RP || true
grep -E "⏺" "$D/1-bob.log" | sed 's/^/  bob: /'
grep -E "^(RECORDING session|RECORDED)" "$D/1-rec.log" | sed 's/^/  recorder: /' | cut -c1-170
grep -q "verified (dsip.record)" "$D/1-bob.log" || fail "1: the recorder was not verified"
python3 - "$D/out1" "$BOB" "$(did "$D/alice")" <<'PY' || fail "1: the recordings are not what was sent"
import sys, json, pathlib
d, bob, alice = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
metas = list(d.glob("*.json")); assert len(metas) == 1, metas
m = json.loads(metas[0].read_text())
assert {p["identity"] for p in m["participants"]} == {bob, alice}, m["participants"]
assert sorted(s["participant"] for s in m["streams"]) == sorted([bob, alice]), m["streams"]
for s in m["streams"]:
    b = (d / s["file"]).read_bytes(); pages = b.count(b"OggS")
    assert b"OpusHead" in b and pages >= 50, (s, pages)
    print(f"  {s['file']}: {'Bob' if s['participant'] == bob else 'Alice'}'s voice, {pages} Ogg pages, OpusHead")
print(f"  metadata: of {m['of'][-8:]}, recording party Bob, participants Bob (self) and Alice (peer)")
PY

echo "════════ 2. Alice never accepts: her audio is held, so the recorder receives none of it"
recorder "$D/rec" "$D/out2" "$D/2-rec.log" 22
bob "$D/2-bob.log" "$REC"
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" "${MB[@]}" --media tone:440 --recording-accept ask \
  --script "sleep 7; hangup; sleep 1; quit" >"$D/2-alice.log" 2>&1 || true
wait $BP || true; wait $RP || true
ALICE=$(did "$D/alice")
grep -E "forwarded [0-9]+ frames" "$D/2-bob.log" | sed 's/^/  bob: /'
grep -q "forwarded 0 frames of $ALICE" "$D/2-bob.log" || fail "2: Alice's audio reached the recorder without her acceptance"
grep -qE "forwarded [1-9][0-9]* frames of $BOB" "$D/2-bob.log" || fail "2: Bob's own audio was not recorded"
grep -q "sent 0 Opus frames" "$D/2-alice.log" || fail "2: Alice sent audio"

echo "════════ 3. A declared 'recorder' without dsip.record is refused before any media"
recorder "$D/fake" "$D/out3" "$D/3-fake.log" 20
bob "$D/3-bob.log" "$FAKE"
$B/dsip call --identity "$D/alice" --relay $R --ca "$CA" --to "$BOB" "${MB[@]}" --media tone:440 --recording-accept always \
  --script "sleep 6; hangup; sleep 1; quit" >"$D/3-alice.log" 2>&1 || true
wait $BP || true; wait $RP || true
grep -E "REFUSED" "$D/3-bob.log" | head -2 | sed 's/^/  bob: /' | cut -c1-160
[ "$(grep -c "REFUSED: \"missing-capability\"" "$D/3-bob.log")" = 2 ] || fail "3: the uncapable recorder was not refused"
! grep -qE "RECORDED session .*: [1-9][0-9]* packets" "$D/3-fake.log" || fail "3: media reached a recorder without dsip.record"
echo "  the impostor received no media"

echo
echo "PASS: Bob's side forked both voices, unchanged and end to end, to the declared recorder after checking its"
echo "      dsip.record delegation; the recorder kept one Ogg/Opus file per voice with RFC 7865-shaped metadata;"
echo "      a counterparty who never accepted contributed nothing; and an uncapable 'recorder' got no media."
