#!/usr/bin/env bash
# The operator's status pages (--status-listen on dsip-relay and dsip-mailbox), over the wire.
#
# Spec: none (infrastructure). Self-verifying: a relay with a status port follows a call from ringing to answered to
# ended by bye, counts the frames it routed and the refusal it signed for a recipient it never saw, and lists the
# answered session with ?detail=1 while it lasts; a mailbox with a status port reports its one --serve-any place
# taken, the enrolled owner's KeyPackages and bound device, the identity it refused mailbox.not-served, and a blob
# GET it answered 404. /metrics carries the same numbers in the Prometheus text format.
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-status-demo}
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx,dev-b,dev-c,docs}
cargo build -q -p dsip-cli -p dsip-relay -p dsip-mailbox
B=target/debug
RS=127.0.0.1:9471; MS=127.0.0.1:9472

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }
wait_for() { # file pattern seconds
  for _ in $(seq $((${3:-20} * 5))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.2; done
  echo "TIMEOUT waiting for /$2/ in $1"; tail -30 "$1"; return 1
}
# jq-like reads with python: q <url> <python expression over d>
q() { curl -sf "http://$1" | python3 -c "import json,sys; d=json.load(sys.stdin); print($2)"; }

echo "=== a relay with a status port"
$B/dsip identity init --dir "$DIR/alice" --name Alice >/dev/null
$B/dsip identity init --dir "$DIR/bob" --name Bob >/dev/null
$B/dsip identity init --dir "$DIR/nobody" --name Nobody >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$DIR/bob/identity.json'))['identity'])")
NOBODY=$(python3 -c "import json;print(json.load(open('$DIR/nobody/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8473 --state "$DIR/relay" --status-listen $RS >"$DIR/relay.log" 2>&1 &
wait_for "$DIR/relay.log" "status on http://$RS" 20
U=wss://127.0.0.1:8473/dsip; CA="$DIR/relay/cert.pem"
[ "$(q $RS/status "d['sessions']['ringing'], d['connections']['devices_bound']")" = "0 0" ] || fail "a fresh relay should follow nothing"
echo "    ok: $(q $RS/status "d['scope'], d['queues']['budget_bytes']") (scope, queue budget)"

echo "=== a call: answered while it lasts, ended by bye after"
$B/dsip answer --identity "$DIR/bob" --relay $U --ca "$CA" --auto accept --script "sleep 8; quit" >"$DIR/bob.log" 2>&1 &
P=$!; sleep 1.5
$B/dsip call --identity "$DIR/alice" --relay $U --ca "$CA" --to "$BOB" --script "sleep 4; hangup; sleep 1; quit" >"$DIR/alice.log" 2>&1 &
A=$!
for _ in $(seq 40); do [ "$(q $RS/status "d['sessions']['answered']")" = 1 ] && break; sleep 0.2; done
during=$(q "$RS/status?detail=1" "d['sessions']['answered'], d['sessions']['list'][0]['state'], d['sessions']['list'][0]['to'] == '$BOB', d['connections']['devices_bound']")
[ "$during" = "1 answered True 2" ] || fail "during the call: $during"
echo "    ok: during the call: 1 answered session, to Bob, 2 devices bound"
wait $A $P
after=$(q $RS/status "d['sessions']['answered'], d['sessions']['started_total'], d['sessions']['answered_total'], d['sessions']['ended_total']")
[ "$after" = "0 1 1 {'bye': 1}" ] || fail "after the call: $after"
echo "    ok: after: started 1, answered 1, ended by bye 1"

echo "=== a refusal is counted with its reason"
$B/dsip call --identity "$DIR/alice" --relay $U --ca "$CA" --to "$NOBODY" --script "sleep 2; quit" >"$DIR/alice2.log" 2>&1 || true
refused=$(q $RS/status "sum(r['count'] for r in d['totals']['refused'] if r['reason'] == 'transport.unknown-recipient')")
[ "$refused" -ge 1 ] || fail "no transport.unknown-recipient counted"
curl -sf "http://$RS/metrics" >"$DIR/relay.metrics"
grep -q '^dsip_relay_refused_total{reason="transport.unknown-recipient",detail=""} ' "$DIR/relay.metrics" || fail "metrics: refusal"
grep -q '^dsip_relay_sessions_ended_total{how="bye"} 1$' "$DIR/relay.metrics" || fail "metrics: ended"
grep -q '^dsip_relay_frames_in_total{type="invite"} 2$' "$DIR/relay.metrics" || fail "metrics: invites"
echo "    ok: transport.unknown-recipient counted; /metrics agrees ($(grep -vc '^#' "$DIR/relay.metrics") samples)"

echo "=== a mailbox with a status port: one --serve-any place"
BOBM=did:web:bob.example; CAROL=did:web:carol.example
RESOLVER=(--resolver-file "$DIR/docs/bob.json" --resolver-file "$DIR/docs/carol.json")
$B/dsip-mailbox --state "$DIR/mbx" --listen 127.0.0.1:9462 --serve-any 1 --release-idle "${RESOLVER[@]}" \
  --status-listen $MS >"$DIR/mbx.log" 2>&1 &
wait_for "$DIR/mbx.log" "status on http://$MS" 20
MBX_DID=$(cat "$DIR/mbx/service.did"); cp "$DIR/mbx/cert.pem" "$DIR/ca.pem"
for who in bob carol; do
  $B/dsip-msg --state "$DIR/dev-${who:0:1}" --identity "did:web:$who.example" --write-doc "$DIR/docs/$who.json" \
    --mailbox-did "$MBX_DID" --mailbox-uri "wss://127.0.0.1:9462/dsip" >/dev/null
done
[ "$(q $MS/status "d['enrolment']['enrolled'], d['enrolment']['free']")" = "0 1" ] || fail "a fresh mailbox should have its place free"
mkfifo "$DIR/b.in" "$DIR/c.in"
$B/dsip-msg --state "$DIR/dev-b" --identity $BOBM "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/b.in" >>"$DIR/b.log" 2>&1 &
exec 3>"$DIR/b.in"; wait_for "$DIR/b.log" "OK connected" 20
echo "kp 2" >&3; wait_for "$DIR/b.log" "OK uploaded" 10
enrol=$(q "$MS/status?detail=1" "d['enrolment']['enrolled'], d['enrolment']['free'], d['owners']['$BOBM']['one_time_key_packages'], d['owners']['$BOBM']['devices_bound'], d['owners']['$BOBM']['quota_pct']")
[ "$enrol" = "1 0 2 1 0.0" ] || fail "after Bob enrolled: $enrol"
echo "    ok: Bob enrolled (1/1, none free), 2 KeyPackages, 1 device bound, 0.0% of his quota"

echo "=== Carol, refused mailbox.not-served, is counted"
$B/dsip-msg --state "$DIR/dev-c" --identity $CAROL "${RESOLVER[@]}" --ca "$DIR/ca.pem" <"$DIR/c.in" >>"$DIR/c.log" 2>&1 &
exec 4>"$DIR/c.in"; wait_for "$DIR/c.log" "OK connected|ERR" 20
echo "sync" >&4; wait_for "$DIR/c.log" 'ERR "mailbox.not-served"' 10
ns=$(q $MS/status "sum(r['count'] for r in d['totals']['refused'] if r['reason'] == 'mailbox.not-served')")
[ "$ns" -ge 1 ] || fail "mailbox.not-served not counted"
echo "    ok: mailbox.not-served counted ($ns)"

echo "=== a blob GET for nothing stored: 404, counted"
curl -sk -o /dev/null "https://127.0.0.1:9462/blobs/$(printf '0%.0s' $(seq 64))" || true
curl -sf "http://$MS/metrics" >"$DIR/mbx.metrics"
grep -q '^dsip_mailbox_blob_requests_total{method="GET",status="404"} 1$' "$DIR/mbx.metrics" || fail "metrics: blob GET"
grep -q '^dsip_mailbox_identities{how="enrolled"} 1$' "$DIR/mbx.metrics" || fail "metrics: enrolled"
grep -q '^dsip_mailbox_quota_bytes 10737418240$' "$DIR/mbx.metrics" || fail "metrics: quota"
echo "    ok: /metrics agrees ($(grep -vc '^#' "$DIR/mbx.metrics") samples)"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://$MS/")" = 404 ] || fail "only /status and /metrics are served"
echo "quit" >&3; echo "quit" >&4; exec 3>&- 4>&-

echo
echo "PASS: the relay follows sessions and counts refusals; the mailbox reports enrolment, storage against quota, refusals and blob requests"
