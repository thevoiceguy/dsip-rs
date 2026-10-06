#!/usr/bin/env bash
# DSIP Device Events Profile (draft, E§2–E§4): the authenticated inputs. Real SNMPv3 traps and informs from pysnmp
# (an independent USM implementation) and real syslog from util-linux `logger` and a TLS client become signed device
# events in an MLS alarm group, each with the basis and the identity that basis verified.
#
# Two identities: the site gateway (gw) and the NOC operator Ann, whose mailbox hubs the alarm group. Self-verifying:
# - an authPriv v3 trap arrives as basis snmpv3-authpriv with its engine and user, and raises its alarm;
# - a trap under the wrong password is refused (wrong-digest), and deposits nothing;
# - after the device reboots (boots + 1), a replay of its pre-reboot trap is refused (not-in-time-window);
# - a v3 inform runs discovery against the gateway (a Report) and is answered only once stored, one event;
# - RFC 5424 and RFC 3164 syslog over UDP map through the rules and the severity table;
# - syslog over TLS with a device certificate arrives as syslog-tls with the certificate's SHA-256, and a client
#   without a certificate is refused;
# - no USM password appears anywhere past the gateway;
# - (v0.10) the gateway names sw1's certificate "sw1-core", rendered beside its fingerprint;
# - (v0.10, E§4 hold-down) a link flapping faster than the hold-down is one alarm: its clear is held, the re-raise
#   cancels it, and only the final clear, once it has held, reaches the group.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-device-events-v3-demo}
GW=did:web:gw.example
ANN=did:web:ann.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-g,mbx-n,dev-g,dev-n,docs,pki}

cargo build -q -p dsip-mailbox
B=target/debug
MBX=$B/dsip-mailbox
MSG=$B/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/gw.json" --resolver-file "$DIR/docs/ann.json")
SNMP_PORT=11630; SYSLOG_PORT=15140; TLS_PORT=16514
DEV_ENGINE=80001f8880d5e1ce0000000001   # the switch's SNMP engine

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}
count() { grep -cE "$2" "$1" 2>/dev/null || true; }
fail() { echo "FAIL: $*"; exit 1; }
v3() { python3 demos/snmpv3_send.py "$@"; }

echo "=== PKI for syslog over TLS: a CA for the devices, the gateway's certificate, one device certificate"
P="$DIR/pki"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=NOC device CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$P/ca.key" -out "$P/ca.pem" 2>/dev/null
for who in gateway sw1; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$who" -keyout "$P/$who.key" -out "$P/$who.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n' \
    "$who" > "$P/$who.ext"
  openssl x509 -req -in "$P/$who.csr" -CA "$P/ca.pem" -CAkey "$P/ca.key" -CAcreateserial -days 2 -extfile "$P/$who.ext" \
    -out "$P/$who.pem" 2>/dev/null
done
SW1_SHA=$(openssl x509 -in "$P/sw1.pem" -outform DER | sha256sum | cut -c1-64)

echo "=== two mailboxes, DID documents, the gateway's rules and USM users"
declare -A PORT=([g]=9481 [n]=9482) ID=([g]=$GW [n]=$ANN) NAME=([g]=gw [n]=ann)
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
cat > "$DIR/rules.json" <<'EOF'
[{"trap_oid": "1.3.6.1.6.3.1.1.5.3", "action": "raise", "type": "link-down", "severity": "major", "resource_varbind": "1.3.6.1.2.1.2.2.1.1"},
 {"trap_oid": "1.3.6.1.4.1.9999.1.0.30", "action": "raise", "type": "fan-failed", "severity": "minor"},
 {"syslog": {"app_name": "linkd", "msgid": "LINKDOWN"}, "action": "raise", "type": "link-down",
  "resource_sd": {"id": "if@32473", "param": "ifIndex"}},
 {"syslog": {"app_name": "linkd", "msgid": "LINKUP"}, "action": "clear", "type": "link-down",
  "resource_sd": {"id": "if@32473", "param": "ifIndex"}},
 {"syslog": {"app_name": "psu"}, "action": "raise", "type": "power-supply-failed", "severity": "critical"}]
EOF
echo "{\"$SW1_SHA\": \"sw1-core\"}" > "$DIR/names.json"
cat > "$DIR/users.json" <<'EOF'
[{"engine_id": null, "user": "noc-v3", "auth": "sha256", "auth_password": "authpass-noc-123", "priv": "aes128",
  "priv_password": "privpass-noc-456"}]
EOF

for x in g n; do mkfifo "$DIR/$x.in"; done
$MSG --state "$DIR/dev-g" --identity "$GW" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  --snmp-listen 127.0.0.1:$SNMP_PORT --snmp-users "$DIR/users.json" --event-rules "$DIR/rules.json" \
  --syslog-listen 127.0.0.1:$SYSLOG_PORT \
  --syslog-tls-listen 127.0.0.1:$TLS_PORT --syslog-tls-cert "$P/gateway.pem" --syslog-tls-key "$P/gateway.key" \
  --syslog-tls-ca "$P/ca.pem" --syslog-tls-names "$DIR/names.json" --hold-down 3 <"$DIR/g.in" >"$DIR/g.log" 2>&1 &
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

echo "=== an SNMPv3 authPriv linkDown (SHA-256, AES-128) from the switch's engine, boots 5"
v3 trap 127.0.0.1:$SNMP_PORT $DEV_ENGINE 5 noc-v3 sha256 authpass-noc-123 privpass-noc-456 1.3.6.1.6.3.1.1.5.3 \
  1.3.6.1.2.1.2.2.1.1.3=i:3 --save "$DIR/boots5-trap.hex" | sed 's/^/  pysnmp: /'
wait_for "$DIR/n.log" "^EVENT .*basis=snmpv3-authpriv usm=noc-v3@$DEV_ENGINE trap=1.3.6.1.6.3.1.1.5.3" 20
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/3/link-down severity=major" 20
grep -m1 "basis=snmpv3-authpriv" "$DIR/n.log" | sed 's/^/  ann sees: /'

echo "=== the same trap type under the wrong password: refused, nothing deposited"
N=$(count "$DIR/n.log" "^EVENT ")
v3 trap 127.0.0.1:$SNMP_PORT $DEV_ENGINE 5 noc-v3 sha256 not-the-password privpass-noc-456 1.3.6.1.6.3.1.1.5.3 \
  1.3.6.1.2.1.2.2.1.1.3=i:4 >/dev/null
wait_for "$DIR/g.log" "^SNMPv3 refused from .*: wrong-digest" 10
grep -m1 "wrong-digest" "$DIR/g.log" | sed 's/^/  gateway: /'

echo "=== the switch reboots (boots 6); an attacker replays its pre-reboot trap byte for byte"
v3 trap 127.0.0.1:$SNMP_PORT $DEV_ENGINE 6 noc-v3 sha256 authpass-noc-123 privpass-noc-456 1.3.6.1.4.1.9999.1.0.30 >/dev/null
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/fan-failed severity=minor" 20
v3 raw 127.0.0.1:$SNMP_PORT "$DIR/boots5-trap.hex" >/dev/null
wait_for "$DIR/g.log" "^SNMPv3 refused from .*: not-in-time-window" 10
grep -m1 "not-in-time-window" "$DIR/g.log" | sed 's/^/  gateway: /'
sleep 2
[ "$(count "$DIR/n.log" "^EVENT ")" = $((N + 1)) ] || fail "a refused message reached the group"

echo "=== an SNMPv3 inform: discovery against the gateway's engine, then answered once stored (E§3)"
INFORM_TIMEOUT=3 INFORM_RETRIES=5 v3 inform 127.0.0.1:$SNMP_PORT $DEV_ENGINE 6 noc-v3 sha256 authpass-noc-123 \
  privpass-noc-456 1.3.6.1.4.1.9999.1.0.30 1.3.6.1.2.1.2.2.1.1.9=i:9 > "$DIR/inform.log" 2>&1 || true
grep -q "^RESPONSE" "$DIR/inform.log" || { cat "$DIR/inform.log"; fail "the v3 inform was not answered"; }
wait_for "$DIR/g.log" "^SNMPv3 refused from .*: unknown-engine-id \(Report sent\)" 5
wait_for "$DIR/g.log" "^SNMP inform .*: stored, answered" 10
echo "  pysnmp: $(cat "$DIR/inform.log")   gateway: discovery Report sent, then the Response after the hub stored it"
[ "$(count "$DIR/g.log" "^SNMP inform .*: 1.3.6.1.4.1.9999.1.0.30")" = 1 ] || fail "the inform was deposited more than once"

echo "=== syslog over UDP: RFC 5424 from logger, matched by a rule (linkd LINKDOWN, resource from structured data)"
logger --rfc5424 -n 127.0.0.1 -P $SYSLOG_PORT -d -t linkd --msgid LINKDOWN --sd-id if@32473 --sd-param 'ifIndex="5"' \
  -p local7.err "port 5 down"
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/5/link-down severity=major" 20
grep -m1 "syslog=rfc5424" "$DIR/n.log" | sed 's/^/  ann sees: /'
echo "=== RFC 3164 from logger, no rule: the severity table makes a warning an alarm (source, syslog, sshd)"
logger --rfc3164 -n 127.0.0.1 -P $SYSLOG_PORT -d -t sshd -p auth.warning "too many authentication failures"
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/syslog severity=warning" 20
grep -m1 "syslog=rfc3164" "$DIR/n.log" | sed 's/^/  ann sees: /'
logger --rfc3164 -n 127.0.0.1 -P $SYSLOG_PORT -d -t cron -p cron.info "job ran"
wait_for "$DIR/n.log" "^EVENT .*app=cron" 20
echo "  an informational message is an event, not an alarm"

echo "=== syslog over TLS with sw1's certificate: basis syslog-tls, the certificate's SHA-256 in the claim"
python3 demos/syslog_tls_send.py 127.0.0.1:$TLS_PORT "$P/ca.pem" --cert "$P/sw1.pem" --key "$P/sw1.key" \
  "<130>1 - sw1 psu - - - power supply 2 failed" | sed 's/^/  client: /'
wait_for "$DIR/n.log" "^EVENT .*basis=syslog-tls cert=${SW1_SHA:0:16}… name=\"sw1-core\" \(gateway's claim\)" 20
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/power-supply-failed severity=critical" 20
grep -m1 "basis=syslog-tls" "$DIR/n.log" | sed 's/^/  ann sees: /'
echo "=== a TLS client without a certificate is refused"
python3 demos/syslog_tls_send.py 127.0.0.1:$TLS_PORT "$P/ca.pem" "<130>1 - evil psu - - - fake" > "$DIR/nocert.log" 2>&1 || true
wait_for "$DIR/g.log" "^SYSLOG tls refused from" 10
grep -m1 "^SYSLOG tls refused" "$DIR/g.log" | cut -c1-120 | sed 's/^/  gateway: /'
sleep 2
! grep -q "fake" "$DIR/n.log" || fail "an unauthenticated TLS client's message reached the group"

echo "=== (E§4 hold-down, 3 s) port 7 flaps: down, up, down within the hold-down, then up for good"
lk() { logger --rfc5424 -n 127.0.0.1 -P $SYSLOG_PORT -d -t linkd --msgid "$1" --sd-id if@32473 --sd-param 'ifIndex="7"' -p local7.err "port 7 $2"; }
lk LINKDOWN down; wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/7/link-down" 20
lk LINKUP up;     wait_for "$DIR/g.log" "^HELD clear of 127.0.0.1/7/link-down" 10
lk LINKDOWN down; wait_for "$DIR/g.log" "^CANCELLED held clear of 127.0.0.1/7/link-down" 10
lk LINKUP up
for _ in $(seq 50); do [ "$(count "$DIR/g.log" "^HELD clear of 127.0.0.1/7/")" = 2 ] && break; sleep 0.2; done
[ "$(count "$DIR/g.log" "^HELD clear of 127.0.0.1/7/")" = 2 ] || fail "the second clear was not held"
grep -E "^(HELD|CANCELLED)" "$DIR/g.log" | sed 's/^/  gateway: /'
! grep -q "^ALARM cleared 127.0.0.1/7/link-down" "$DIR/n.log" || fail "a clear inside the hold-down reached the group"
wait_for "$DIR/g.log" "^RELEASED held clear of 127.0.0.1/7/link-down" 15
wait_for "$DIR/n.log" "^ALARM cleared 127.0.0.1/7/link-down" 20
grep -m1 "^RELEASED" "$DIR/g.log" | sed 's/^/  gateway: /'
[ "$(count "$DIR/n.log" "^ALARM raised 127.0.0.1/7/link-down")" = 1 ] || fail "the flap was more than one alarm"
[ "$(count "$DIR/n.log" "^ALARM cleared 127.0.0.1/7/link-down")" = 1 ] || fail "more than one clear reached the group"
echo "  ann saw one raise and one clear: the flap was one alarm"

echo "=== the USM passwords never leave the gateway"
for f in "$DIR"/n.log "$DIR"/dev-n "$DIR"/mbx-g "$DIR"/mbx-n; do
  ! grep -rqaE "authpass-noc|privpass-noc" "$f" || fail "a USM password appears in $f"
done
echo "  not in Ann's log, Ann's device state, or either mailbox"

echo
echo "PASS: SNMPv3 traps and informs from pysnmp and syslog from logger and a TLS client became signed device events,"
echo "      each with its basis and verified identity; a wrong digest, a pre-reboot replay and an uncertified TLS client"
echo "      were refused; the v3 inform was answered once stored after discovery; syslog mapped through the rules and"
echo "      the severity table; no USM password left the gateway; sw1 was named beside its certificate; and a flapping"
echo "      link was one alarm under the hold-down."
