#!/usr/bin/env bash
# DSIP Device Events Profile (draft, E§n) alongside SNMP: real SNMPv1/v2c traps → a site gateway → signed device
# events in an MLS alarm group → every member's alarm list → an operator's acknowledgement → an escalation agent
# that calls the on-call person when nobody acknowledges.
#
# Three identities: the gateway (gw), the NOC operator Ann (whose mailbox hubs the alarm group) and the escalation
# agent. The gateway's DSIP device runs in gateway mode: it receives the traps and informs on UDP itself, signs each
# as a device event, and answers an inform only once the hub has stored its event (E§3). Self-verifying: every
# expected line must appear, a repeated trap must page nobody, an acknowledged alarm must not escalate, an inform must
# be answered only once stored and never deposit twice across a hub outage, the community string must appear nowhere
# past the gateway, and the escalation must ring the on-call phone over a DSIP relay.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-device-events-demo}
GW=did:web:gw.example
ANN=did:web:ann.example
AGENT=did:web:agent.example
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx-g,mbx-n,mbx-e,dev-g,dev-n,dev-e,docs}

cargo build -q -p dsip-mailbox -p dsip-cli -p dsip-relay
B=target/debug
MBX=$B/dsip-mailbox
MSG=$B/dsip-msg
RESOLVER=(--resolver-file "$DIR/docs/gw.json" --resolver-file "$DIR/docs/ann.json" --resolver-file "$DIR/docs/agent.json")
TRAP_PORT=11620

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

wait_for() { # file pattern seconds
  local f=$1 pat=$2 n=${3:-20}
  for _ in $(seq $((n * 5))); do grep -qE "$pat" "$f" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$pat/ in $f"; echo "--- $f"; tail -30 "$f"; return 1
}
count() { grep -cE "$2" "$1" 2>/dev/null || true; }
send_trap() { python3 demos/snmp_trap.py "$@"; }

echo "=== the on-call phone: a DSIP identity answering on a relay"
$B/dsip-relay --listen 127.0.0.1:8459 --state "$DIR/relay" >"$DIR/relay.log" 2>&1 &
sleep 1.5
R=wss://127.0.0.1:8459/dsip; CA_R="$DIR/relay/cert.pem"
$B/dsip identity init --dir "$DIR/oncall" --name "Ann's phone" >/dev/null
$B/dsip identity init --dir "$DIR/agent-call" --name "Escalation agent" >/dev/null
ONCALL=$(python3 -c "import json;print(json.load(open('$DIR/oncall/identity.json'))['identity'])")
$B/dsip answer --identity "$DIR/oncall" --relay $R --ca "$CA_R" --script "sleep 240; quit" >"$DIR/oncall.log" 2>&1 &
wait_for "$DIR/oncall.log" "capabilities|bound|hello" 15

echo "=== three mailboxes and DID documents"
declare -A PORT=([g]=9471 [n]=9472 [e]=9473) ID=([g]=$GW [n]=$ANN [e]=$AGENT) NAME=([g]=gw [n]=ann [e]=agent)
mailbox() { # x
  $MBX --state "$DIR/mbx-$1" --listen 127.0.0.1:${PORT[$1]} --owner "${ID[$1]}" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
    >>"$DIR/mbx-$1.log" 2>&1 &
  eval "MBX_$1=$!"
}
for x in g n e; do mailbox $x; done
for x in g n e; do wait_for "$DIR/mbx-$x.log" "mailbox did:key" 20; done
cat "$DIR"/mbx-{g,n,e}/cert.pem > "$DIR/ca.pem"
for x in g n e; do
  $MSG --state "$DIR/dev-$x" --identity "${ID[$x]}" --write-doc "$DIR/docs/${NAME[$x]}.json" \
    --mailbox-did "$(cat "$DIR/mbx-$x/service.did")" --mailbox-uri "wss://127.0.0.1:${PORT[$x]}/dsip" >/dev/null
done

echo "=== devices: the gateway (SNMP on UDP $TRAP_PORT, heartbeat every 3 s), Ann, and the escalation agent"
echo "    (the agent escalates major-or-worse alarms unacknowledged for 12 s → a call)"
cat > "$DIR/rules.json" <<'EOF'
[{"trap_oid": "1.3.6.1.6.3.1.1.5.3", "action": "raise", "type": "link-down", "severity": "major", "resource_varbind": "1.3.6.1.2.1.2.2.1.1"},
 {"trap_oid": "1.3.6.1.6.3.1.1.5.4", "action": "clear", "type": "link-down", "resource_varbind": "1.3.6.1.2.1.2.2.1.1"},
 {"trap_oid": "1.3.6.1.4.1.9999.1.0.17", "action": "raise", "type": "power-supply-failed", "severity": "critical"},
 {"trap_oid": "1.3.6.1.4.1.9999.1.0.30", "action": "raise", "type": "fan-failed", "severity": "minor"}]
EOF
for x in g n e; do mkfifo "$DIR/$x.in"; done
$MSG --state "$DIR/dev-g" --identity "$GW" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  --snmp-listen 127.0.0.1:$TRAP_PORT --snmp-rules "$DIR/rules.json" --heartbeat 3 <"$DIR/g.in" >"$DIR/g.log" 2>&1 &
GW_PID=$!
$MSG --state "$DIR/dev-n" --identity "$ANN" "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/n.in" >"$DIR/n.log" 2>&1 &
$MSG --state "$DIR/dev-e" --identity "$AGENT" "${RESOLVER[@]}" --ca "$DIR/ca.pem" \
  --escalate-min major --escalate-after 12 \
  --escalate-cmd "$B/dsip call --identity $DIR/agent-call --relay $R --ca $CA_R --to $ONCALL --t-establish 10 --script 'sleep 6; quit' >>$DIR/escalation-call.log 2>&1" \
  <"$DIR/e.in" >"$DIR/e.log" 2>&1 &
exec 3>"$DIR/g.in"; exec 4>"$DIR/n.in"; exec 5>"$DIR/e.in"
for x in g n e; do wait_for "$DIR/$x.log" "OK connected" 20; done

echo "=== the alarm group: Ann's mailbox hubs it; the gateway and the agent join (M§14 grants)"
echo "kp 2" >&3; wait_for "$DIR/g.log" "OK uploaded" 10
echo "grant $ANN" >&3; wait_for "$DIR/g.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/g.log" | cut -d' ' -f2 > "$DIR/grant-gw.txt"
echo "kp 2" >&5; wait_for "$DIR/e.log" "OK uploaded" 10
echo "grant $ANN" >&5; wait_for "$DIR/e.log" "^GRANT " 10
grep -m1 "^GRANT " "$DIR/e.log" | cut -d' ' -f2 > "$DIR/grant-agent.txt"
echo "live" >&3; echo "live" >&5
echo "kp 1" >&4; wait_for "$DIR/n.log" "OK uploaded" 10
echo "create group $GW $DIR/grant-gw.txt" >&4; wait_for "$DIR/n.log" "^OK added $GW" 30
echo "add $AGENT $DIR/grant-agent.txt" >&4; wait_for "$DIR/n.log" "^OK added $AGENT" 30
echo "live" >&4
wait_for "$DIR/g.log" "^JOINED .* kind=group" 30
wait_for "$DIR/e.log" "^JOINED .* kind=group" 30

echo "=== an SNMPv2c linkDown on port 3 → a signed device event → a major alarm on every member's list (E§5)"
send_trap v2c 127.0.0.1:$TRAP_PORT public 123400 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.3=i:3
wait_for "$DIR/g.log" "^OK sent event" 20
wait_for "$DIR/n.log" "^ALARM raised 127.0.0.1/3/link-down severity=major" 20
wait_for "$DIR/e.log" "^ALARM raised 127.0.0.1/3/link-down severity=major" 20
grep -m1 "^EVENT " "$DIR/n.log" | sed 's/^/  ann sees: /'

echo "=== the same trap again: counted, pages nobody"
send_trap v2c 127.0.0.1:$TRAP_PORT public 123500 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.3=i:3
wait_for "$DIR/n.log" "^EVENT .*" 20
sleep 3
[ "$(count "$DIR/n.log" "^ALARM raised 127.0.0.1/3/")" = 1 ] || { echo "FAIL: a repeated trap raised the alarm again"; exit 1; }
echo "  still one raise on Ann's list"

echo "=== Ann acknowledges within the 12 s (so it must never escalate); an SNMPv1 linkUp (with its community) clears it"
echo "alarm-ack 127.0.0.1/3 link-down ack" >&4
wait_for "$DIR/e.log" "^ALARM ack 127.0.0.1/3/link-down by $ANN" 20
send_trap v1 127.0.0.1:$TRAP_PORT s3cret-community 4200 1.3.6.1.4.1.9999.1 192.0.2.7 3 0 1.3.6.1.2.1.2.2.1.1.3=i:3
wait_for "$DIR/n.log" "^ALARM cleared 127.0.0.1/3/link-down" 20
wait_for "$DIR/e.log" "^ALARM cleared 127.0.0.1/3/link-down" 20

echo "=== a critical enterprise trap nobody acknowledges: the agent escalates after 12 s and calls the on-call phone (E§6)"
send_trap v2c 127.0.0.1:$TRAP_PORT public 123900 1.3.6.1.4.1.9999.1.0.17
wait_for "$DIR/e.log" "^ALARM raised 127.0.0.1/power-supply-failed severity=critical" 20
wait_for "$DIR/e.log" "^ESCALATE 127.0.0.1/power-supply-failed severity=critical" 30
wait_for "$DIR/oncall.log" "← invite" 30
echo "  the on-call phone rang:"; grep -m2 -E "← invite|ringing" "$DIR/oncall.log" | sed 's/^/    /'
[ "$(count "$DIR/e.log" "^ESCALATE 127.0.0.1/3/")" = 0 ] || { echo "FAIL: the acknowledged alarm escalated"; exit 1; }

echo "=== an SNMPv2c inform: answered once its event is stored (E§3)"
send_trap inform 127.0.0.1:$TRAP_PORT public 124000 1.3.6.1.4.1.9999.1.0.30 rid=41 > "$DIR/inform-41.log"
grep -q "RESPONSE after 1 attempt" "$DIR/inform-41.log" || { echo "FAIL: the inform was not answered"; cat "$DIR/inform-41.log"; exit 1; }
wait_for "$DIR/g.log" "^SNMP inform .* rid=41: stored, answered" 10
echo "  $(cat "$DIR/inform-41.log")"

echo "=== the hub (Ann's mailbox) goes down: an inform stays unanswered, its retransmissions deposit nothing more"
kill -9 "$MBX_n"; wait "$MBX_n" 2>/dev/null || true
INFORM_TIMEOUT=2 INFORM_RETRIES=40 python3 demos/snmp_trap.py inform 127.0.0.1:$TRAP_PORT public 124100 \
  1.3.6.1.4.1.9999.1.0.30 rid=42 1.3.6.1.2.1.2.2.1.1.42=i:42 > "$DIR/inform-42.log" &
SENDER=$!
wait_for "$DIR/g.log" "^SNMP inform .* rid=42: pending, not answered" 30
wait_for "$DIR/g.log" "^SNMP inform .* rid=42: retransmission while pending" 15
wait_for "$DIR/inform-42.log" "no response \\(attempt 2\\)" 15
echo "  the device has retransmitted; nothing answered it"
echo "=== the hub comes back: the gateway's outbox delivers, and the next retransmission is answered (M§9.4)"
mailbox n; wait_for "$DIR/mbx-n.log" "restored state" 20
wait "$SENDER" || { echo "FAIL: the inform was never answered"; cat "$DIR/inform-42.log"; exit 1; }
grep "RESPONSE" "$DIR/inform-42.log" | sed 's/^/  /'
wait_for "$DIR/g.log" "^SNMP inform .* rid=42: stored, answered" 10
sleep 3
N42=$(grep -c "rid=42: 1.3.6.1.4.1.9999.1.0.30" "$DIR/g.log" || true)
[ "$N42" = 1 ] || { echo "FAIL: the inform's event was deposited $N42 times"; exit 1; }
echo "  one deposit for the inform, across $(grep -c 'no response' "$DIR/inform-42.log") unanswered retransmission(s)"

echo "=== the gateway goes silent: no heartbeat for 2 × 3 s raises dsip-gateway-silent (E§5)"
kill -9 "$GW_PID"; wait "$GW_PID" 2>/dev/null || true
wait_for "$DIR/n.log" "^ALARM raised $GW/dsip-gateway-silent severity=major" 30

echo "=== the community string never left the gateway (E§3)"
if grep -rl "s3cret-community" "$DIR"/{n.log,e.log,g.log,mbx-g,mbx-n,mbx-e} 2>/dev/null; then
  echo "FAIL: the community string was carried"; exit 1
fi
echo "  absent from every device log and every mailbox's state"

echo
echo "=== Ann's alarm log:"; grep -E "^(ALARM|EVENT)" "$DIR/n.log" | sed 's/^/  /'
echo "=== the agent:"; grep -E "^(ALARM|ESCALATE)" "$DIR/e.log" | sed 's/^/  /'
echo
echo "PASS: traps from SNMPv1 and v2c became signed device events; every member kept the same alarm list; a repeat"
echo "      paged nobody; an acknowledged alarm did not escalate; an unacknowledged critical one rang the on-call phone;"
echo "      an inform was answered only once stored, and across a hub outage its retransmissions deposited nothing more;"
echo "      a silent gateway raised its own alarm; and the community string never left the gateway."
