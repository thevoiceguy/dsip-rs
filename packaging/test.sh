#!/usr/bin/env bash
# Test the dsip-relay and dsip-mailbox packages as an operator runs them (after packaging/build.sh --image):
#   1. both .debs on one Debian trixie host booted with systemd: installed, enabled and started by dpkg; the hardened
#      units active (a sandbox setting the binary trips over only shows at run time) at systemd's exposure score;
#      state that survives a crash and a restart (the relay's queued invite and certificate, the mailbox's enrolment
#      and service key); a certificate installed by install-certificate, as certbot's deploy hook, and renewed under
#      the running relay; removal keeps the edited configs (conffiles);
#   2. the container images: non-root, read-only root filesystem, no capabilities; the same state survives a
#      container restart through the state volume.
# The clients are this workspace's own, on the host: `dsip` (calls) and `dsip-msg` (a messaging device).
#
# Spec: none (infrastructure).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD; ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
RELAY_DEB=$(ls crates/dsip-relay/dist/dsip-relay_*_"$ARCH".deb); MBX_DEB=$(ls crates/dsip-mailbox/dist/dsip-mailbox_*_"$ARCH".deb)
cargo build -q -p dsip-cli --bin dsip -p dsip-mailbox --bin dsip-msg
B=$ROOT/target/debug
D=${PKGTEST_DIR:-/tmp/dsip-services-pkgtest}; rm -rf "$D"; mkdir -p "$D"
SD=dsip-services-pkgtest; RC=dsip-relay-ctest; MC=dsip-mailbox-ctest
# the host's ports: the systemd host's relay and mailbox, then the containers'
SR=${SR_PORT:-18443}; SM=${SM_PORT:-19443}; CR=${CR_PORT:-18444}; CM=${CM_PORT:-19444}
cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  docker rm -f $SD $RC $MC >/dev/null 2>&1 || true; docker volume rm -f $RC $MC >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
fail() {
  echo "FAIL: $*"; for f in "$D"/*.log; do [ -f "$f" ] && { echo "--- $f"; tail -12 "$f"; }; done
  for svc in dsip-relay dsip-mailbox; do
    docker exec $SD journalctl -u $svc -o cat --no-pager 2>/dev/null | tail -15 | sed "1i--- journal of $svc" || true
  done
  for c in $RC $MC; do docker logs $c 2>&1 | tail -25 | sed "1i--- log of container $c" || true; done
  exit 1
}
until_ok() { # seconds command...: retry a check every 0.2 s
  local n=$(($1 * 5)); shift
  for _ in $(seq $n); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
  return 1
}
served() { # port: the SHA-256 fingerprint of the certificate served there
  openssl s_client -connect 127.0.0.1:"$1" -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
}
fingerprint() { openssl x509 -in "$1" -noout -fingerprint -sha256; }
leaf() { # dir: a leaf certificate for localhost in certbot's layout (fullchain.pem, privkey.pem)
  mkdir -p "$1"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=DSIP pkgtest $(basename "$1")" \
    -config <(printf '[req]\ndistinguished_name = dn\n[dn]\n') -addext "basicConstraints = critical,CA:FALSE" \
    -addext "subjectAltName = DNS:localhost,IP:127.0.0.1" -keyout "$1/privkey.pem" -out "$1/fullchain.pem" 2>/dev/null
}
for who in alice bob; do $B/dsip identity init --dir "$D/$who" --name "$who" >/dev/null; done
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")

# The relay keeps its queue (§13.3) and its key and certificate: Bob binds once and goes offline, Alice calls him and
# the invite is queued; the relay is restarted by $restart; it serves the same certificate, still holds the invite,
# and delivers it when Bob binds. $logs prints the relay's log, $starts counts its starts so far.
relay_keeps_state() { # tag port ca restart-command logs-command
  local tag=$1 port=$2 ca=$3 restart=$4 logs=$5 url=wss://127.0.0.1:$2/dsip before
  before=$(served "$port")
  $B/dsip answer --identity "$D/bob" --relay "$url" --ca "$ca" --script "sleep 1; quit" >"$D/$tag-bob-0.log" 2>&1
  $B/dsip call --identity "$D/alice" --relay "$url" --ca "$ca" --to "$BOB" --media none --script "sleep 2; quit" \
    >"$D/$tag-alice.log" 2>&1 || true
  until_ok 10 sh -c "$logs | grep -q 'queued invite for $BOB'" || fail "$tag: the invite to offline Bob was not queued"
  local starts; starts=$(eval "$logs" | grep -c "listening on")
  eval "$restart"
  until_ok 30 sh -c "[ \$($logs | grep -c 'listening on') -gt $starts ]" || fail "$tag: the relay did not come back"
  eval "$logs" | grep -q "queue store: 1 envelopes held for 1 recipients" || fail "$tag: the restarted relay does not hold the invite"
  [ "$(served "$port")" = "$before" ] || fail "$tag: the certificate changed across the restart"
  $B/dsip answer --identity "$D/bob" --relay "$url" --ca "$ca" --auto none --media none --script "sleep 3; quit" \
    >"$D/$tag-bob-1.log" 2>&1 || true
  grep -q "^← invite" "$D/$tag-bob-1.log" || fail "$tag: Bob did not get the queued invite after the restart"
}

# The mailbox keeps its enrolments and its service key (M§4.1; its state in mailbox.sqlite): Bob's device enrols with
# its KeyPackages, the mailbox is restarted by $restart, and Bob is still enrolled with his KeyPackages, under the
# same service DID. $publish puts Bob's document where the mailbox reads it; $admin runs `dsip-mailbox admin`.
mailbox_keeps_state() { # tag port ca did-file docs-dir publish-command restart-command admin-command
  local tag=$1 port=$2 ca=$3 did=$4 docs=$5 publish=$6 restart=$7 admin=$8 dev=$D/$1-dev
  local bobm=did:web:bob-$1.example
  $B/dsip-msg --state "$dev" --identity "$bobm" --write-doc "$docs/bob.json" --mailbox-did "$(cat "$did")" \
    --mailbox-uri "wss://127.0.0.1:$port/dsip" >/dev/null
  chmod 644 "$docs/bob.json"  # read by the service's own user
  eval "$publish"
  device() { # n: Bob's device connects and uploads n KeyPackages, then goes offline
    rm -f "$D/$tag-b.in"; mkfifo "$D/$tag-b.in"; : >"$D/$tag-b.log"
    $B/dsip-msg --state "$dev" --identity "$bobm" --resolver-file "$docs/bob.json" --ca "$ca" <"$D/$tag-b.in" >>"$D/$tag-b.log" 2>&1 &
    exec 3>"$D/$tag-b.in"
    until_ok 20 grep -q "OK connected" "$D/$tag-b.log" || fail "$tag: Bob's device did not connect"
    echo "kp $1" >&3
    until_ok 10 grep -q "OK uploaded" "$D/$tag-b.log" || fail "$tag: Bob's KeyPackages were not uploaded"
    exec 3>&-
  }
  device 2
  local before; before=$(cat "$did")
  enrolled() { eval "$admin --json enrolments" | python3 -c 'import json,sys; print(" ".join(e["identity"] for e in json.load(sys.stdin)["enrolled"]))'; }
  [ "$(enrolled)" = "$bobm" ] || fail "$tag: Bob is not enrolled: $(enrolled)"
  eval "$restart"
  until_ok 30 sh -c "$admin enrolments" || fail "$tag: the mailbox did not come back"
  [ "$(enrolled)" = "$bobm" ] || fail "$tag: Bob's enrolment did not survive the restart: $(enrolled)"
  [ "$(cat "$did")" = "$before" ] || fail "$tag: the service DID changed across the restart"
  device 1  # and his device carries on where it was, with the same mailbox and service key
}

echo "════════ 1. the .debs under systemd ($(basename "$RELAY_DEB"), $(basename "$MBX_DEB"))"
# the base image, retried across two registries: both have answered CI runners' anonymous pulls with HTTP 429
BASE=dsip-services-test-base:trixie
for i in 1 2 3 4; do
  for src in public.ecr.aws/docker/library/debian:trixie mirror.gcr.io/library/debian:trixie; do
    if docker pull -q "$src" >/dev/null 2>&1; then docker tag "$src" $BASE; break 2; fi
  done
  [ "$i" = 4 ] && fail "no registry served debian:trixie"
  sleep $((i * 15))
done
docker build -q --build-arg BASE=$BASE -f packaging/systemd-test.Containerfile -t dsip-services-systemd-test packaging >/dev/null
docker run -d --name $SD --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -p 127.0.0.1:$SR:8443 -p 127.0.0.1:$SM:9443 dsip-services-systemd-test >/dev/null
docker exec $SD systemctl is-system-running --wait >/dev/null 2>&1 || true
sd() { docker exec $SD "$@"; }
# a real host's behaviour: Debian's container images forbid maintainer scripts to start or stop services
sd rm -f /usr/sbin/policy-rc.d
docker cp "$RELAY_DEB" $SD:/root/relay.deb; docker cp "$MBX_DEB" $SD:/root/mailbox.deb
sd dpkg -i /root/relay.deb /root/mailbox.deb >"$D/dpkg.log" 2>&1 || fail "dpkg -i failed"
for svc in dsip-relay dsip-mailbox; do
  [ "$(sd systemctl is-enabled $svc)" = enabled ] || fail "$svc is not enabled"
done
until_ok 20 sd test -s /var/lib/private/dsip-relay/cert.pem || fail "the relay made no certificate"
until_ok 20 sd test -s /var/lib/private/dsip-mailbox/service.did || fail "the mailbox made no service key"
until_ok 20 sd curl -sf 127.0.0.1:9101/status || fail "the relay's status port does not answer"
for svc in dsip-relay dsip-mailbox; do
  [ "$(sd systemctl is-active $svc)" = active ] || { sd journalctl -u $svc --no-pager | tail -20; fail "$svc is not active"; }
  score=$(sd systemd-analyze security $svc --no-pager 2>/dev/null | awk '/Overall exposure level/ {print $(NF-2)}')
  python3 -c "import sys; sys.exit(0 if float('$score') <= 2.0 else 1)" || fail "$svc: exposure $score > 2.0"
  [ "$(sd stat -c %U /var/lib/private/$svc)" = "$svc" ] || fail "$svc: its state is not its DynamicUser's"
  echo "  $svc: installed, enabled and started by dpkg; active under DynamicUser, exposure $score (systemd-analyze security)"
done
[ "$(sd stat -c %a /var/lib/private/dsip-relay/key.pem)" = 600 ] || fail "the relay's TLS key is not private"

journal() { echo "docker exec $SD journalctl -u $1 -o cat --no-pager"; }
docker cp $SD:/var/lib/private/dsip-relay/cert.pem "$D/sd-relay-ca.pem"
# a crash: SIGKILL, and Restart=on-failure brings it back
relay_keeps_state sd-relay $SR "$D/sd-relay-ca.pem" "docker exec $SD systemctl kill -s KILL dsip-relay" "$(journal dsip-relay)"
echo "  dsip-relay: killed, restarted by systemd: the same certificate, the queued invite held and delivered"
sd dsip-relay admin --config /etc/dsip-relay/relay.toml bindings >/dev/null || fail "dsip-relay admin --config"

# the operator's certificate: certbot's deploy hook installs it, the config names it
leaf "$D/le-1"; leaf "$D/le-2"
sd mkdir -p /etc/letsencrypt/live; docker cp "$D/le-1" $SD:/etc/letsencrypt/live/le-1; docker cp "$D/le-2" $SD:/etc/letsencrypt/live/le-2
sd env RENEWED_LINEAGE=/etc/letsencrypt/live/le-1 /usr/libexec/dsip-relay/install-certificate >"$D/hook-1.log" 2>&1 \
  || fail "install-certificate: $(cat "$D/hook-1.log")"
[ "$(sd stat -c '%a %U' /var/lib/private/dsip-relay/tls/privkey.pem)" = "600 dsip-relay" ] || fail "the installed key is not the service's alone"
sd sed -i -e 's|^# cert = "/var/lib/dsip-relay/tls/|cert = "/var/lib/dsip-relay/tls/|' \
  -e 's|^# key = "/var/lib/dsip-relay/tls/|key = "/var/lib/dsip-relay/tls/|' /etc/dsip-relay/relay.toml
sd systemctl restart dsip-relay
until_ok 20 sh -c "[ \"\$(openssl s_client -connect 127.0.0.1:$SR </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256)\" = \"$(fingerprint "$D/le-1/fullchain.pem")\" ]" \
  || fail "the relay does not serve the installed certificate"
PID=$(sd systemctl show -p MainPID --value dsip-relay)
# the renewal: the hook again, and the running relay serves the new one from its next handshake
sd sh -c 'cd /etc/letsencrypt/live/le-2 && RENEWED_LINEAGE=$PWD /usr/libexec/dsip-relay/install-certificate' >"$D/hook-2.log" 2>&1 \
  || fail "install-certificate (renewal): $(cat "$D/hook-2.log")"
grep -q "reloaded" "$D/hook-2.log" || fail "the hook did not reload the relay: $(cat "$D/hook-2.log")"
until_ok 10 sh -c "[ \"\$(openssl s_client -connect 127.0.0.1:$SR </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256)\" = \"$(fingerprint "$D/le-2/fullchain.pem")\" ]" \
  || fail "the renewed certificate is not served"
[ "$(sd systemctl show -p MainPID --value dsip-relay)" = "$PID" ] || fail "the renewal restarted the relay"
echo "  dsip-relay: install-certificate (certbot's deploy hook) installed a certificate, then a renewal reloaded it in place"

# the mailbox: enrolment open for two, Bob's document beside its config
sd mkdir -p /etc/dsip-mailbox/docs
docker cp $SD:/var/lib/private/dsip-mailbox/service.did "$D/sd-mbx.did"
docker cp $SD:/var/lib/private/dsip-mailbox/cert.pem "$D/sd-mbx-ca.pem"
mkdir -p "$D/sd-docs"
sd sed -i 's|^serve_any = 0 .*|serve_any = 2\nresolver_file = ["/etc/dsip-mailbox/docs/bob.json"]|' /etc/dsip-mailbox/mailbox.toml
sd systemctl restart dsip-mailbox
until_ok 20 sd dsip-mailbox admin --config /etc/dsip-mailbox/mailbox.toml enrolments || fail "the mailbox did not restart"
# the device writes Bob's document; the mailbox reads it as a file (resolver_file, re-read when resolving)
mailbox_keeps_state sd-mbx $SM "$D/sd-mbx-ca.pem" "$D/sd-mbx.did" "$D/sd-docs" \
  "docker cp $D/sd-docs/bob.json $SD:/etc/dsip-mailbox/docs/bob.json" \
  "docker exec $SD systemctl kill -s KILL dsip-mailbox; docker cp $SD:/var/lib/private/dsip-mailbox/service.did $D/sd-mbx.did" \
  "docker exec $SD dsip-mailbox admin --config /etc/dsip-mailbox/mailbox.toml"
echo "  dsip-mailbox: killed, restarted by systemd: Bob still enrolled, the same service DID, his device carries on"

sd dpkg -r dsip-relay dsip-mailbox >/dev/null 2>&1
for svc in dsip-relay dsip-mailbox; do
  [ "$(sd systemctl is-active $svc || true)" != active ] || fail "removal left $svc running"
done
sd grep -q '^cert = "/var/lib/dsip-relay/tls/fullchain.pem"' /etc/dsip-relay/relay.toml || fail "removal did not keep the relay's edited config"
sd grep -q '^serve_any = 2' /etc/dsip-mailbox/mailbox.toml || fail "removal did not keep the mailbox's edited config"
echo "  removal stopped both and kept their edited configs"

echo; echo "════════ 2. the container images (dsip-relay:dev, dsip-mailbox:dev)"
locked() { echo --read-only --cap-drop ALL --security-opt no-new-privileges:true; }
docker volume create $RC >/dev/null; docker volume create $MC >/dev/null
# shellcheck disable=SC2046
docker run -d --name $RC $(locked) -p 127.0.0.1:$CR:8443 -v $RC:/var/lib/dsip-relay dsip-relay:dev >/dev/null
until_ok 20 docker cp $RC:/var/lib/dsip-relay/cert.pem "$D/ct-relay-ca.pem" || fail "the relay container made no certificate"
until_ok 20 sh -c "docker logs $RC 2>&1 | grep -q 'listening on'" || fail "the relay container did not start"
[ "$(docker inspect $RC --format '{{.Config.User}}')" = 65532:65532 ] || fail "the relay image does not run as non-root"
relay_keeps_state ct-relay $CR "$D/ct-relay-ca.pem" "docker restart $RC >/dev/null" "docker logs $RC 2>&1"
docker exec $RC dsip-relay admin --config /etc/dsip-relay/relay.toml bindings >/dev/null || fail "admin in the relay container"
echo "  dsip-relay: non-root (65532), read-only root, no capabilities; restarted: the same certificate, the queued invite delivered"

mkdir -p "$D/ct-docs"; chmod 755 "$D/ct-docs"
# shellcheck disable=SC2046
docker run -d --name $MC $(locked) -p 127.0.0.1:$CM:9443 -v $MC:/var/lib/dsip-mailbox -v "$D/ct-docs:/docs:ro" \
  dsip-mailbox:dev --serve-any 2 --resolver-file /docs/bob.json >/dev/null
until_ok 20 docker cp $MC:/var/lib/dsip-mailbox/service.did "$D/ct-mbx.did" || fail "the mailbox container made no service key"
docker cp $MC:/var/lib/dsip-mailbox/cert.pem "$D/ct-mbx-ca.pem"
until_ok 20 docker exec $MC dsip-mailbox admin --config /etc/dsip-mailbox/mailbox.toml enrolments || fail "the mailbox container did not start"
mailbox_keeps_state ct-mbx $CM "$D/ct-mbx-ca.pem" "$D/ct-mbx.did" "$D/ct-docs" true \
  "docker restart $MC >/dev/null; docker cp $MC:/var/lib/dsip-mailbox/service.did $D/ct-mbx.did" \
  "docker exec $MC dsip-mailbox admin --config /etc/dsip-mailbox/mailbox.toml"
echo "  dsip-mailbox: non-root, read-only root, no capabilities; restarted: Bob still enrolled, the same service DID"
echo
echo "PASS: the .debs install, start under their sandboxes, keep their state and take a renewed certificate in place;"
echo "      the images run locked down and keep their state."
