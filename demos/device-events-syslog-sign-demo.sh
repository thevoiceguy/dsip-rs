#!/usr/bin/env bash
# DSIP Device Events Profile (draft, E§3 v0.10): signed syslog (RFC 5848, syslog-sign). A signer's messages are held
# at the gateway until a verified Signature Block lists them, then become signed device events with basis
# syslog-signed; anything not signed in time is deposited with its transport's basis, claiming no more than that.
#
# Two identities: the site gateway (gw) and the NOC operator Ann, whose mailbox hubs the alarm group. The signer is
# demos/syslog_sign_send.py (DSA-2048, a key blob type C certificate); the vectors carry RFC 5848's own examples.
# Self-verifying:
# - a Certificate Block in three fragments establishes the session; two linkDowns, then their Signature Block, reach
#   Ann as syslog-signed with message numbers 1 and 2;
# - a message claiming to be from the signer's host but never signed is deposited after the hold as syslog-udp;
# - a Signature Block from another key is refused (bad-signature), and the message it lists stays unsigned;
# - (v0.11) gaps: the refused block's number was never covered by a verified block, and a lost message is signed but
#   never arrives — each raises dsip-syslog-gap, one alarm counted twice.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-device-events-syslog-sign-demo}
GW=did:web:gw.example
ANN=did:web:ann.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-g,mbx-n,dev-g,dev-n,docs,pki}

cargo build -q -p dsip-mailbox
B=target/debug
MBX=$B/dsip-mailbox
MSG=$B/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/gw.json" --resolver-file "$DIR/docs/ann.json")
SYSLOG_PORT=${SYSLOG_PORT:-15160}

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}
count() { grep -cE "$2" "$1" 2>/dev/null || true; }
fail() { echo "FAIL: $*"; exit 1; }

echo "=== the signer's DSA-2048 key and self-signed certificate (key blob type C); a second key it does not own"
P="$DIR/pki"
openssl dsaparam -out "$P/params.pem" 2048 2>/dev/null
for k in sw1 rogue; do openssl gendsa -out "$P/$k.key" "$P/params.pem" 2>/dev/null; done
openssl req -x509 -new -key "$P/sw1.key" -sha256 -days 2 -subj "/CN=sw1.example" -out "$P/sw1.pem" 2>/dev/null
openssl req -x509 -new -key "$P/rogue.key" -sha256 -days 2 -subj "/CN=sw1.example" -out "$P/rogue.pem" 2>/dev/null
KEY_SHA=$(openssl x509 -in "$P/sw1.pem" -outform DER | sha256sum | cut -c1-64)
echo "[{\"hostname\": \"sw1.example\", \"certificate\": \"$P/sw1.pem\", \"gaps\": true}]" > "$DIR/signers.json"
cat > "$DIR/rules.json" <<'EOF'
[{"syslog": {"app_name": "linkd", "msgid": "LINKDOWN"}, "action": "raise", "type": "link-down", "severity": "major",
  "resource_sd": {"id": "if@32473", "param": "ifIndex"}}]
EOF
send() { python3 demos/syslog_sign_send.py 127.0.0.1:$SYSLOG_PORT "$DIR/signer.json" --hostname sw1.example "$@" | sed 's/^/  signer: /'; }

echo "=== two mailboxes, DID documents"
declare -A PORT=([g]=9501 [n]=9502) ID=([g]=$GW [n]=$ANN) NAME=([g]=gw [n]=ann)
for x in g n; do
  $MBX --state "$DIR/mbx-$x" --listen 127.0.0.1:${PORT[$x]} --owner "${ID[$x]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
    >"$DIR/mbx-$x.log" 2>&1 &
done
for x in g n; do wait_for "$DIR/mbx-$x.log" "mailbox did:key" 20; done
cat "$DIR"/mbx-{g,n}/cert.pem > "$DIR/ca.pem"
for x in g n; do
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" --write-doc "$DIR/docs/${NAME[$x]}.json" \
    --mailbox-did "$(cat "$DIR/mbx-$x/service.did")" --mailbox-uri "wss://127.0.0.1:${PORT[$x]}/dsip" >/dev/null
done

for x in g n; do mkfifo "$DIR/$x.in"; done
$MSG --state "$DIR/dev-g" --identity "$GW" "${RESOLVER[@]}" --ca "$DIR/ca.pem" --event-rules "$DIR/rules.json" \
  --syslog-listen 127.0.0.1:$SYSLOG_PORT --syslog-signers "$DIR/signers.json" --syslog-sign-hold 4 <"$DIR/g.in" >"$DIR/g.log" 2>&1 &
$MSG --state "$DIR/dev-n" --identity "$ANN" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/n.in" >"$DIR/n.log" 2>&1 &
exec 3>"$DIR/g.in"; exec 4>"$DIR/n.in"
for x in g n; do wait_for "$DIR/$x.log" "OK connected" 20; done
grep -E "^GATEWAY" "$DIR/g.log" | sed 's/^/  /'

echo "=== the alarm group: Ann's mailbox hubs it; the gateway joins (M§14 grant)"
echo "kp 2" >&3; wait_for "$DIR/g.log" "OK uploaded" 10
echo "grant $ANN" >&3; wait_for "$DIR/g.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/g.log" | cut -d' ' -f2 > "$DIR/grant-gw.txt"
echo "live" >&3
echo "kp 1" >&4; wait_for "$DIR/n.log" "OK uploaded" 10
echo "create group $GW $DIR/grant-gw.txt" >&4; wait_for "$DIR/n.log" "^OK added $GW" 30
echo "live" >&4
wait_for "$DIR/g.log" "^JOINED .* kind=group" 30

echo "=== the signer: its certificate in three Certificate Block fragments, then two linkDowns and their Signature Block"
send --key "$P/sw1.key" --cert "$P/sw1.pem" cert --fragment 520
wait_for "$DIR/g.log" "^SYSLOG-SIGN session sw1.example/syslogd/.* rsid 1 established, key ${KEY_SHA:0:16}" 10
grep -m1 "^SYSLOG-SIGN session" "$DIR/g.log" | sed 's/^/  gateway: /'
send msg linkd LINKDOWN "port 5 down" --sd '[if@32473 ifIndex="5"]'
send msg linkd LINKDOWN "port 6 down" --sd '[if@32473 ifIndex="6"]'
wait_for "$DIR/g.log" "held for its signature" 10
sleep 1
[ "$(count "$DIR/n.log" "^EVENT ")" = 0 ] || fail "a held message was deposited before its signature"
echo "  gateway: both held, nothing deposited yet"
send --key "$P/sw1.key" sign
wait_for "$DIR/n.log" "^EVENT .*basis=syslog-signed signed=sw1.example/syslogd rsid=1 #2 key=${KEY_SHA:0:16}" 20
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/6/link-down severity=major" 20
grep "basis=syslog-signed" "$DIR/n.log" | cut -c1-190 | sed 's/^/  ann sees: /'

echo "=== a message claiming sw1.example that no Signature Block lists: held, then deposited as syslog-udp"
python3 demos/syslog_sign_send.py 127.0.0.1:$SYSLOG_PORT "$DIR/forger.json" --hostname sw1.example \
  msg linkd LINKDOWN "port 7 down" --sd '[if@32473 ifIndex="7"]' | sed 's/^/  forger: /'
wait_for "$DIR/n.log" "^EVENT .*basis=syslog-udp .*port 7 down" 20
grep "port 7 down" "$DIR/n.log" | head -1 | cut -c1-160 | sed 's/^/  ann sees: /'

echo "=== a Signature Block from another key over a new message: refused, and the message stays unsigned"
send msg linkd LINKDOWN "port 8 down" --sd '[if@32473 ifIndex="8"]'
send --key "$P/rogue.key" sign
wait_for "$DIR/g.log" "^SYSLOG-SIGN ssign refused: bad-signature" 10
grep -m1 "bad-signature" "$DIR/g.log" | sed 's/^/  gateway: /'
wait_for "$DIR/n.log" "^EVENT .*basis=syslog-udp .*port 8 down" 20
! grep -E "basis=syslog-signed.*port [78] down" "$DIR/n.log" || fail "an unsigned message was deposited as signed"
[ "$(count "$DIR/n.log" "basis=syslog-signed")" = 2 ] || fail "expected exactly two signed events"

echo "=== (v0.11) gaps: message 4 is lost on the way, 5 arrives; their Signature Block covers 4–5 (3 was never covered)"
send msg linkd LINKDOWN "port 9 down" --sd '[if@32473 ifIndex="9"]' --lose
send msg linkd LINKDOWN "port 10 down" --sd '[if@32473 ifIndex="10"]'
send --key "$P/sw1.key" sign
wait_for "$DIR/g.log" "^SYSLOG-SIGN gap sw1.example/syslogd/0/0 rsid 1: messages 3–3 lost" 10
wait_for "$DIR/n.log" "^EVENT .*basis=syslog-signed .*#5 .*port 10 down" 20
wait_for "$DIR/g.log" "^SYSLOG-SIGN gap sw1.example/syslogd/0/0 rsid 1: messages 4–4 lost" 15
grep "^SYSLOG-SIGN gap" "$DIR/g.log" | sed 's/^/  gateway: /'
wait_for "$DIR/n.log" "^EVENT .*basis=gateway .*syslog_gap=sw1.example/syslogd rsid=1 sg=0 spri=0 lost=4–4" 20
grep "syslog_gap=" "$DIR/n.log" | cut -c1-170 | sed 's/^/  ann sees: /'
wait_for "$DIR/n.log" "^ALARM raised sw1.example/dsip-syslog-gap severity=warning" 10
[ "$(count "$DIR/n.log" "^ALARM raised sw1.example/dsip-syslog-gap")" = 1 ] || fail "the gaps were more than one alarm"
echo "  one dsip-syslog-gap alarm for the signer, raised by the first gap and repeated by the second"

echo
echo "PASS: two messages held until their verified Signature Block became syslog-signed events with their signer,"
echo "      session and message numbers; an unsigned message from the signer's host and one listed by a foreign"
echo "      key were deposited as syslog-udp, after the hold — never as signed; and the numbers that never arrived or"
echo "      were never covered raised one dsip-syslog-gap alarm."
