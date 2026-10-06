#!/usr/bin/env bash
# DSIP Device Events Profile (draft, E§3 v0.10): SNMPv3 over TLS (RFC 6353) with the Transport Security Model
# (RFC 5591). Real traps and informs from net-snmp's snmptrap/snmpinform over TLS become signed device events in an
# MLS alarm group, with basis snmpv3-tls, the device's certificate and the security name the gateway's table gave it.
#
# Two identities: the site gateway (gw) and the NOC operator Ann, whose mailbox hubs the alarm group. Self-verifying:
# - sw1's certificate is named by its own fingerprint (row 10, specified "core-switch"); its trap raises an alarm;
# - sw2's certificate falls to the CA's row (row 20, san-dns): its inform first runs RFC 5343 discovery, which the
#   gateway answers with its engine ID, then is answered once stored, and deposited once;
# - sw3's certificate (same CA, only an IP SAN) maps to no name: the connection is closed, nothing is accepted;
# - a client without a certificate is refused at the handshake.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-device-events-snmp-tls-demo}
GW=did:web:gw.example
ANN=did:web:ann.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-g,mbx-n,dev-g,dev-n,docs,pki}

cargo build -q -p dsip-mailbox
B=target/debug
MBX=$B/dsip-mailbox
MSG=$B/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/gw.json" --resolver-file "$DIR/docs/ann.json")
TLS_PORT=${SNMP_TLS_PORT:-16162}
source demos/netsnmp_tls.sh
echo "=== net-snmp: $(env "${NETSNMP_ENV[@]}" "$SNMPTRAP" --version 2>&1 | head -1)"

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}
count() { grep -cE "$2" "$1" 2>/dev/null || true; }
fail() { echo "FAIL: $*"; exit 1; }

echo "=== PKI: a device CA, the gateway's certificate, and three device certificates"
P="$DIR/pki"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=NOC device CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$P/ca.key" -out "$P/ca.pem" 2>/dev/null
declare -A SAN=([gateway]="DNS:localhost,IP:127.0.0.1" [sw1]="DNS:sw1.example" [sw2]="DNS:SW2.Example.NET" [sw3]="IP:192.0.2.13")
for who in gateway sw1 sw2 sw3; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$who" -keyout "$P/$who.key" -out "$P/$who.csr" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n' \
    "${SAN[$who]}" > "$P/$who.ext"
  openssl x509 -req -in "$P/$who.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial -days 2 -extfile "$P/$who.ext" \
    -out "$P/$who.pem" 2>/dev/null
done
fp() { openssl x509 -in "$1" -outform DER | sha256sum | cut -c1-64; }
SW1_SHA=$(fp "$P/sw1.pem"); SW2_SHA=$(fp "$P/sw2.pem"); CA_SHA=$(fp "$P/ca.pem")
# each device's net-snmp configuration: its certificate and key, and the CA it trusts the gateway by
for who in sw1 sw2 sw3; do
  mkdir -p "$DIR/$who/.snmp/tls/"{certs,private,ca-certs} "$DIR/$who/persist/cert_indexes"
  cp "$P/$who.pem" "$DIR/$who/.snmp/tls/certs/$who.crt"; cp "$P/$who.key" "$DIR/$who/.snmp/tls/private/$who.key"
  cp "$P/ca.pem" "$DIR/$who/.snmp/tls/ca-certs/ca.crt"
done
netsnmp() { # device tool args...
  local who=$1 tool=$2; shift 2
  env "${NETSNMP_ENV[@]}" HOME="$DIR/$who" SNMPCONFPATH="$DIR/$who/.snmp" SNMP_PERSISTENT_DIR="$DIR/$who/persist" MIBS= \
    "$tool" -t 5 -r 2 -v 3 --defSecurityModel=tsm -l authPriv -T localCert="$who" -T trustCert=ca -T their_hostname=localhost \
    "tls:localhost:$TLS_PORT" "$@"
}

echo "=== the gateway's certificate-to-name table (RFC 6353): sw1 by its own fingerprint, then anything under the CA by dNSName"
cat > "$DIR/tsm-map.json" <<EOF
[{"id": 20, "fingerprint": "$CA_SHA", "map": "san-dns"},
 {"id": 10, "fingerprint": "$SW1_SHA", "map": "specified", "data": "core-switch"}]
EOF
cat > "$DIR/rules.json" <<'EOF'
[{"trap_oid": "1.3.6.1.6.3.1.1.5.3", "action": "raise", "type": "link-down", "severity": "major", "resource_varbind": "1.3.6.1.2.1.2.2.1.1"},
 {"trap_oid": "1.3.6.1.4.1.9999.1.0.30", "action": "raise", "type": "fan-failed", "severity": "minor"}]
EOF

echo "=== two mailboxes, DID documents"
declare -A PORT=([g]=9491 [n]=9492) ID=([g]=$GW [n]=$ANN) NAME=([g]=gw [n]=ann)
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
  --snmp-tls-listen 127.0.0.1:$TLS_PORT --snmp-tls-cert "$P/gateway.pem" --snmp-tls-key "$P/gateway.key" \
  --snmp-tls-ca "$P/ca.pem" --snmp-tls-map "$DIR/tsm-map.json" <"$DIR/g.in" >"$DIR/g.log" 2>&1 &
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

echo "=== sw1: snmptrap over TLS, a linkDown on ifIndex 3"
netsnmp sw1 "$SNMPTRAP" 1234 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.3 i 3
wait_for "$DIR/g.log" "^SNMP tls connection .*security name \"core-switch\" \(row 10\)" 10
wait_for "$DIR/n.log" "^EVENT .*basis=snmpv3-tls tsm=\"core-switch\" cert=${SW1_SHA:0:16}" 20
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/3/link-down severity=major" 20
grep -m1 "^SNMP tls connection" "$DIR/g.log" | sed 's/^/  gateway: /'
grep -m1 "basis=snmpv3-tls" "$DIR/n.log" | cut -c1-200 | sed 's/^/  ann sees: /'

echo "=== sw2: snmpinform over TLS — RFC 5343 discovery first, then the inform, answered once stored"
N=$(count "$DIR/n.log" "^EVENT ")
netsnmp sw2 "$SNMPINFORM" 0 1.3.6.1.4.1.9999.1.0.30 1.3.6.1.2.1.2.2.1.2.9 s "Gi0/9" > "$DIR/inform.log" 2>&1 \
  || { cat "$DIR/inform.log"; fail "snmpinform got no Response"; }
wait_for "$DIR/g.log" "^SNMP tls discovery .*\(sw2.example.net\): answered with our engine ID" 5
wait_for "$DIR/g.log" "^SNMP inform tls:sw2.example.net rid=.*: stored, answered" 10
wait_for "$DIR/n.log" "^EVENT .*basis=snmpv3-tls tsm=\"sw2.example.net\" cert=${SW2_SHA:0:16}" 20
grep -E "^SNMP (tls discovery|inform tls:)" "$DIR/g.log" | sed 's/^/  gateway: /'
echo "  snmpinform exited 0: it received the gateway's Response"
sleep 2
[ "$(count "$DIR/n.log" "^EVENT ")" = $((N + 1)) ] || fail "the inform was deposited more than once"

echo "=== sw3: a certificate from the same CA that no row names (only an IP SAN) — closed, nothing accepted"
N=$(count "$DIR/n.log" "^EVENT ")
netsnmp sw3 "$SNMPTRAP" 1234 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.3 i 13 > "$DIR/sw3.log" 2>&1 || true
wait_for "$DIR/g.log" "^SNMP tls closed .*: no-security-name" 10
grep -m1 "no-security-name" "$DIR/g.log" | sed 's/^/  gateway: /'

echo "=== a TLS client without a certificate is refused at the handshake"
python3 demos/syslog_tls_send.py 127.0.0.1:$TLS_PORT "$P/ca.pem" "x" > "$DIR/nocert.log" 2>&1 || true
wait_for "$DIR/g.log" "^SNMP tls refused from" 10
grep -m1 "^SNMP tls refused" "$DIR/g.log" | cut -c1-120 | sed 's/^/  gateway: /'
sleep 2
[ "$(count "$DIR/n.log" "^EVENT ")" = "$N" ] || fail "an unnamed or uncertified device's message reached the group"

echo
echo "PASS: net-snmp traps and informs over TLS became signed device events with basis snmpv3-tls, each with its"
echo "      certificate and the security name RFC 6353's table gave it; the inform's RFC 5343 discovery was answered"
echo "      and the inform answered once stored; an unnamed certificate and an uncertified client were refused."
