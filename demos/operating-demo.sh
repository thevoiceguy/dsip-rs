#!/usr/bin/env bash
# Operating the services (service-nodes plan S5): a certificate renewed under a running relay, and the admin commands.
#
# Spec: none (infrastructure). Self-verifying:
#   1. `dsip-relay admin bindings` lists Bob's bound device, by --status and by --config.
#   2. The relay's certificate is renewed on disk and the relay sent SIGHUP: the new certificate is served from the
#      next handshake, while Bob's device stays bound on its connection, and a call reaches him over it.
#   3. A renewal that is not a certificate (a half-written file) is refused on SIGHUP: the relay keeps serving the
#      one it had.
#   4. `dsip-mailbox admin enrolments` lists Bob, enrolled within --serve-any; `dsip-mailbox admin release` ends his
#      enrolment: everything held for him deleted, his binding closed, the place free. Releasing him again, or a
#      configured owner, is refused, and so is an admin POST without its header (a web page cannot send one).
set -euo pipefail

cd "$(dirname "$0")/.."
DIR=${DEMO_DIR:-/tmp/dsip-operating-demo}
rm -rf "$DIR"; mkdir -p "$DIR"/{mbx,dev-b,docs}
cargo build -q -p dsip-cli -p dsip-relay -p dsip-mailbox
B=target/debug
RS=127.0.0.1:9493; MS=127.0.0.1:9495
U=wss://127.0.0.1:8625/dsip

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; for f in "$DIR"/*.log; do echo "--- $f"; tail -12 "$f"; done; exit 1; }
wait_for() { # file pattern seconds
  for _ in $(seq $((${3:-20} * 5))); do sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | grep -qE "$2" && return 0; sleep 0.2; done
  fail "timeout waiting for /$2/ in $1"
}
count() { sed 's/\x1b\[[0-9;]*m//g' "$1" | grep -cE "$2" || true; }
served() { # the SHA-256 fingerprint of the certificate the relay serves now
  openssl s_client -connect 127.0.0.1:8625 -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
}
fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256; }

echo "════════ a relay with a status port; Bob's device binds and stays"
for who in alice bob; do $B/dsip identity init --dir "$DIR/$who" --name "$who" >/dev/null; done
BOB=$(python3 -c "import json;print(json.load(open('$DIR/bob/identity.json'))['identity'])")
$B/dsip-relay --listen 127.0.0.1:8625 --state "$DIR/relay" --status-listen $RS --log stderr >"$DIR/relay.log" 2>&1 &
wait_for "$DIR/relay.log" "listening on" 20
cp "$DIR/relay/cert.pem" "$DIR/old.pem"
$B/dsip answer --identity "$DIR/bob" --relay $U --ca "$DIR/old.pem" --auto reject --media none --script "sleep 25; quit" >"$DIR/bob.log" 2>&1 &
wait_for "$DIR/relay.log" "bound device .* for identity $BOB" 20

echo "════════ 1. dsip-relay admin bindings"
$B/dsip-relay admin --status $RS bindings | tee "$DIR/bindings.txt" | sed 's/^/  /'
grep -q "^$BOB$" "$DIR/bindings.txt" || fail "1: Bob is not listed"
printf 'listen = "127.0.0.1:8625"\nstatus_listen = "%s"\n' $RS >"$DIR/relay.toml"
[ "$($B/dsip-relay admin --config "$DIR/relay.toml" --json bindings | python3 -c 'import json,sys; print(json.load(sys.stdin)["devices_bound"])')" = 1 ] \
  || fail "1: --config --json does not show one device"
echo "  ok: Bob's device listed (--status, and --config with --json)"

echo "════════ 2. the certificate is renewed and the relay sent SIGHUP"
[ "$(served)" = "$(fingerprint "$DIR/old.pem")" ] || fail "2: the relay does not serve its certificate"
# a leaf certificate (no CA extensions: a minimal config instead of openssl's default v3_ca section)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=DSIP renewed localhost" \
  -config <(printf '[req]\ndistinguished_name = dn\n[dn]\n') -addext "basicConstraints = critical,CA:FALSE" \
  -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" -keyout "$DIR/new-key.pem" -out "$DIR/new.pem" 2>/dev/null
cp "$DIR/new.pem" "$DIR/relay/cert.pem"; cp "$DIR/new-key.pem" "$DIR/relay/key.pem"
RELAY=$(pgrep -f "dsip-relay --listen 127.0.0.1:8625")
kill -HUP "$RELAY"
wait_for "$DIR/relay.log" "SIGHUP: certificate reloaded" 10
[ "$(served)" = "$(fingerprint "$DIR/new.pem")" ] || fail "2: the renewed certificate is not served"
echo "  ok: the next handshake gets the renewed certificate"
[ "$(count "$DIR/relay.log" "bound device .* for identity $BOB")" = 1 ] || fail "2: Bob bound again"
$B/dsip-relay admin --status $RS bindings | grep -q "^$BOB$" || fail "2: Bob is no longer bound"
$B/dsip call --identity "$DIR/alice" --relay $U --ca "$DIR/new.pem" --to "$BOB" --media none --script "sleep 2; quit" >"$DIR/alice.log" 2>&1 || true
grep -q "^← invite" "$DIR/bob.log" || fail "2: the call did not reach Bob on his binding"
echo "  ok: Bob still bound on his first connection; Alice's call (trusting only the new certificate) reached him"

echo "════════ 3. a half-written renewal: refused, the relay keeps its certificate"
head -c 100 "$DIR/new.pem" >"$DIR/relay/cert.pem"
kill -HUP "$RELAY"
wait_for "$DIR/relay.log" "SIGHUP: certificate not reloaded" 10
sed 's/\x1b\[[0-9;]*m//g' "$DIR/relay.log" | grep -oE "SIGHUP: certificate not reloaded.*" | sed 's/^/  /'
[ "$(served)" = "$(fingerprint "$DIR/new.pem")" ] || fail "3: the relay stopped serving its certificate"
echo "  ok: still serving the renewed certificate"

echo "════════ 4. a mailbox: dsip-mailbox admin enrolments | release"
BOBM=did:web:bob.example; OWNER=did:web:owner.example
$B/dsip-mailbox --state "$DIR/mbx" --listen 127.0.0.1:9494 --owner $OWNER --serve-any 2 --release-idle \
  --resolver-file "$DIR/docs/bob.json" --status-listen $MS --log stderr >"$DIR/mbx.log" 2>&1 &
wait_for "$DIR/mbx.log" "status on http://$MS" 20
MBX_DID=$(cat "$DIR/mbx/service.did"); cp "$DIR/mbx/cert.pem" "$DIR/mbx-ca.pem"
$B/dsip-msg --state "$DIR/dev-b" --identity $BOBM --write-doc "$DIR/docs/bob.json" \
  --mailbox-did "$MBX_DID" --mailbox-uri "wss://127.0.0.1:9494/dsip" >/dev/null
mkfifo "$DIR/b.in"
$B/dsip-msg --state "$DIR/dev-b" --identity $BOBM --resolver-file "$DIR/docs/bob.json" --ca "$DIR/mbx-ca.pem" <"$DIR/b.in" >>"$DIR/b.log" 2>&1 &
exec 3>"$DIR/b.in"; wait_for "$DIR/b.log" "OK connected" 20
echo "kp 2" >&3; wait_for "$DIR/b.log" "OK uploaded" 10
$B/dsip-mailbox admin --status $MS enrolments | tee "$DIR/enrolments.txt" | sed 's/^/  /'
grep -q "serve-any 2: 1 enrolled, 1 free" "$DIR/enrolments.txt" || fail "4: not one enrolled"
grep -qE "^  $BOBM .* 1/1 devices bound" "$DIR/enrolments.txt" || fail "4: Bob not listed bound"
$B/dsip-mailbox admin --status $MS release $BOBM | tee "$DIR/release.txt" | sed 's/^/  /'
grep -q "released $BOBM: .* closed 1 binding(s); 2 free" "$DIR/release.txt" || fail "4: release"
wait_for "$DIR/mbx.log" "released $BOBM \(operator\): deleted its mailbox" 5
[ "$($B/dsip-mailbox admin --status $MS --json enrolments | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["enrolled"]), d["free"])')" = "0 2" ] \
  || fail "4: the place was not freed"
echo "  ok: released by the operator, the place free"
if $B/dsip-mailbox admin --status $MS release $BOBM 2>"$DIR/again.txt"; then fail "4: a second release succeeded"; fi
grep -q "not enrolled here" "$DIR/again.txt" || fail "4: the second release: $(cat "$DIR/again.txt")"
if $B/dsip-mailbox admin --status $MS release $OWNER 2>"$DIR/owner.txt"; then fail "4: a configured owner was released"; fi
grep -q "is configured" "$DIR/owner.txt" || fail "4: the configured owner: $(cat "$DIR/owner.txt")"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://$MS/admin/release?identity=$BOBM")
[ "$code" = 403 ] || fail "4: a POST without the admin header got $code"
echo "  ok: refused: Bob again (not enrolled), the configured owner, and an admin POST without its header (403)"
echo "════════ operating demo passed"
