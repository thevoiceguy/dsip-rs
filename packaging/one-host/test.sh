#!/usr/bin/env bash
# Test the one-host recipe (docs/one-host.md) both ways, for the name dsip.test with a certificate of its own:
#   1. the three .debs and coturn on one Debian trixie host booted with systemd, set up by packaging/one-host/configure:
#      the relay on 443 (the drop-in's one capability) serving the client, /config.json naming the mailbox by its
#      service DID, the hints node at /dsip/v1/ and TURN credentials at /turn; the mailbox on 9443 under the same
#      certificate; configure run again changes nothing; a renewal through the certbot hook reaches both services
#      without restarting either;
#   2. packaging/one-host/compose with the images: the same checks, through ./init, and a restarted relay or node
#      still reaching the other on loopback (the shared network namespace).
# Run after packaging/build.sh --image dsip-relay dsip-mailbox dsip-web and crates/dsip-node/packaging/build.sh --image.
#
# Spec: none (infrastructure).
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD; ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
DEBS=(crates/dsip-relay/dist/dsip-relay_*_"$ARCH".deb crates/dsip-mailbox/dist/dsip-mailbox_*_"$ARCH".deb
      crates/dsip-node/dist/dsip-node_*_"$ARCH".deb)
WEB=$(ls web/dist/dsip-web-*.tar.gz)
D=${ONEHOST_DIR:-/tmp/dsip-one-host-test}; rm -rf "$D"; mkdir -p "$D"
SD=dsip-one-host-test; NAME=dsip.test
# the host's ports: the systemd host's relay and mailbox, then the compose's (and its node's, kept off the defaults)
SR=${SR_PORT:-18445}; SM=${SM_PORT:-19445}; CR=${CR_PORT:-18446}; CM=${CM_PORT:-19446}
P=dsip-one-host-test; CC="docker compose --project-directory $D/compose -p $P"
cleanup() {
  docker rm -f $SD >/dev/null 2>&1 || true
  docker compose -p $P down -v --remove-orphans >/dev/null 2>&1 || true
}
[ -n "${KEEP:-}" ] || trap cleanup EXIT
fail() {
  echo "FAIL: $*"
  for svc in dsip-relay dsip-mailbox dsip-node coturn; do
    docker exec $SD journalctl -u $svc -o cat --no-pager 2>/dev/null | tail -12 | sed "1i--- journal of $svc" || true
  done
  [ ! -f "$D/compose/compose.yaml" ] || $CC logs --tail 12 2>/dev/null || true
  exit 1
}
until_ok() { # seconds command...: retry a check every 0.2 s
  local n=$(($1 * 5)); shift
  for _ in $(seq $n); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
  return 1
}
served() { # port: the SHA-256 fingerprint of the certificate served there for $NAME
  openssl s_client -connect 127.0.0.1:"$1" -servername $NAME </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
}
fingerprint() { openssl x509 -in "$1/fullchain.pem" -noout -fingerprint -sha256; }
leaf() { # dir: a self-signed certificate for $NAME in certbot's layout
  mkdir -p "$1"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=$NAME" \
    -config <(printf '[req]\ndistinguished_name = dn\n[dn]\n') -addext "basicConstraints = critical,CA:TRUE" \
    -addext "subjectAltName = DNS:$NAME" -keyout "$1/privkey.pem" -out "$1/fullchain.pem" 2>/dev/null
}
leaf "$D/tls"; leaf "$D/tls-renewed"
get() { # port path [ca]: GET https://dsip.test:<port><path>, trusting only the certificate
  curl -sf --max-time 5 --resolve "$NAME:$1:127.0.0.1" --cacert "${3:-$D/tls/fullchain.pem}" "https://$NAME:$1$2"
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# The recipe's checks, from outside: the relay's and the mailbox's host ports, the mailbox's service DID, and the origin
# and mailbox port the client config must name
one_host() { # tag relay-port mailbox-port service-did origin mailbox-port-in-its-uri
  local tag=$1 rp=$2 mp=$3 did=$4 origin=$5 muri=$6 c
  # the hints node opens its HTTP API once it has joined Mainline
  until_ok 60 get "$rp" /dsip/v1/node || fail "$tag: the hints node is not at /dsip/v1/"
  get "$rp" / | grep >/dev/null '<script type="module" src="app.js"' || fail "$tag: the client is not served at /"
  get "$rp" /pkg/dsip_wasm_bg.wasm >"$D/$tag.wasm" && [ "$(od -An -c -N4 "$D/$tag.wasm" | tr -d ' ')" = '\0asm' ] \
    || fail "$tag: the engine is not served"
  c=$(get "$rp" /config.json) || fail "$tag: no /config.json"
  [ "$(echo "$c" | json 'd["mailbox"]["did"]')" = "$did" ] || fail "$tag: /config.json does not name the mailbox ($did): $c"
  [ "$(echo "$c" | json 'd["mailbox"]["uri"]')" = "wss://$NAME:$muri/dsip" ] || fail "$tag: the mailbox's uri: $c"
  [ "$(echo "$c" | json 'd["nodes"][0]')" = "$origin" ] || fail "$tag: the client's hints node is not $origin: $c"
  get "$rp" /dsip/v1/node | json 'd["peer_id"]' | grep >/dev/null '^12D3' || fail "$tag: the hints node is not at /dsip/v1/"
  c=$(get "$rp" /turn) || fail "$tag: no TURN credentials at /turn"
  echo "$c" | json '" ".join(d["iceServers"][0]["urls"]), d["iceServers"][0]["credential"]' | grep >/dev/null "^turn:$NAME:3478 ." \
    || fail "$tag: /turn: $c"
  [ "$(served "$rp")" = "$(served "$mp")" ] || fail "$tag: the relay and the mailbox serve different certificates"
  [ "$(served "$rp")" = "$(fingerprint "$D/tls")" ] || fail "$tag: the relay does not serve the installed certificate"
  echo "$tag: the client, /config.json (mailbox $did), /dsip/v1/node, /turn on :$rp; the mailbox on :$mp; one certificate"
}

echo "════════ 1. the .debs under systemd, set up by configure"
BASE=dsip-services-test-base:trixie
for i in 1 2 3 4; do
  for src in public.ecr.aws/docker/library/debian:trixie mirror.gcr.io/library/debian:trixie; do
    if docker pull -q "$src" >/dev/null 2>&1; then docker tag "$src" $BASE; break 2; fi
  done
  [ "$i" = 4 ] && fail "no registry served debian:trixie"
  sleep $((i * 15))
done
docker build -q --build-arg BASE=$BASE -f packaging/systemd-test.Containerfile -t dsip-services-systemd-test packaging >/dev/null
cleanup
docker run -d --name $SD --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -p 127.0.0.1:$SR:443 -p 127.0.0.1:$SM:9443 dsip-services-systemd-test >/dev/null
docker exec $SD systemctl is-system-running --wait >/dev/null 2>&1 || true
sd() { docker exec $SD "$@"; }
sd rm -f /usr/sbin/policy-rc.d   # a real host: maintainer scripts start services
for f in "${DEBS[@]}"; do docker cp "$f" $SD:/root/; done
sd sh -c 'apt-get update -qq && apt-get install -y -qq /root/*.deb coturn' >"$D/apt.log" 2>&1 || { tail "$D/apt.log"; fail "apt install failed"; }
docker cp packaging/one-host/configure $SD:/root/configure
docker cp "$WEB" $SD:/root/dsip-web.tar.gz
sd sh -c 'mkdir -p /usr/local/share/dsip-web && tar -xzf /root/dsip-web.tar.gz --strip-components 1 -C /usr/local/share/dsip-web'
sd mkdir -p /etc/letsencrypt/live
docker cp "$D/tls" $SD:/etc/letsencrypt/live/$NAME
IP=$(sd hostname -I | awk '{print $1}')
CONFIGURE=(/root/configure --name $NAME --cert-dir /etc/letsencrypt/live/$NAME --www /usr/local/share/dsip-web
           --serve-any 4 --release-idle --coturn --public-ip "$IP")
sd "${CONFIGURE[@]}" >"$D/configure.log" 2>&1 || { cat "$D/configure.log"; fail "configure failed"; }
for svc in dsip-relay dsip-mailbox dsip-node coturn; do
  [ "$(sd systemctl is-active $svc)" = active ] || fail "$svc is not active"
done
one_host debs $SR $SM "$(sd cat /var/lib/dsip-mailbox/service.did)" "https://$NAME" 9443
# the relay's sandbox, with port 443's capability and outside the private user namespace
score=$(sd systemd-analyze security dsip-relay --no-pager | awk '/Overall exposure level/ {print $(NF-2)}')
awk -v s="$score" 'BEGIN { exit !(s <= 2.0) }' || fail "dsip-relay's exposure with the 443 drop-in is $score"
echo "debs: dsip-relay on 443, systemd-analyze security $score"
sd grep -qi ':0D96 ' /proc/net/udp || fail "coturn is not listening on 3478/udp"
pids() { for svc in dsip-relay dsip-mailbox dsip-node coturn; do sd systemctl show -p MainPID --value $svc; done | tr '\n' ' '; }
before=$(pids)
sd "${CONFIGURE[@]}" >"$D/configure-again.log" 2>&1 || { cat "$D/configure-again.log"; fail "configure (again) failed"; }
! grep -q '^wrote\|^restarted' "$D/configure-again.log" || { cat "$D/configure-again.log"; fail "configure again changed something"; }
[ "$(pids)" = "$before" ] || fail "configure again restarted a service: $before -> $(pids)"
echo "debs: configure again changes nothing and restarts nothing"
# certbot's renewal: the new pair in live/<name>/, then the deploy hooks with RENEWED_LINEAGE
docker cp "$D/tls-renewed/." $SD:/etc/letsencrypt/live/$NAME/
sd env RENEWED_LINEAGE=/etc/letsencrypt/live/other.example /etc/letsencrypt/renewal-hooks/deploy/dsip-one-host
[ "$(served $SR)" = "$(fingerprint "$D/tls")" ] || fail "the hook acted on another name's renewal"
sd env RENEWED_LINEAGE=/etc/letsencrypt/live/$NAME /etc/letsencrypt/renewal-hooks/deploy/dsip-one-host >/dev/null
until_ok 10 test "$(served $SR)" = "$(fingerprint "$D/tls-renewed")" || fail "the relay does not serve the renewed certificate"
until_ok 10 test "$(served $SM)" = "$(fingerprint "$D/tls-renewed")" || fail "the mailbox does not serve the renewed certificate"
[ "$(pids)" = "$before" ] || fail "the renewal restarted a service"
echo "debs: a renewal reaches the relay and the mailbox, neither restarted"
docker rm -f $SD >/dev/null

echo "════════ 2. the compose, set up by ./init"
cp -r packaging/one-host/compose "$D/compose"
cat > "$D/compose/.env" <<ENV
COMPOSE_PROJECT_NAME=$P
DSIP_NAME=$NAME
PUBLIC_IP=127.0.0.1
DSIP_SERVE_ANY=4
DSIP_IMAGES=
DSIP_VERSION=dev
DSIP_HTTPS_PORT=$CR
DSIP_MAILBOX_PORT=$CM
DSIP_OVERLAY_PORT=${CO_PORT:-14610}
DSIP_MAINLINE_PORT=${CL_PORT:-16881}
ENV
mkdir -p "$D/compose/www"; tar -xzf "$WEB" --strip-components 1 -C "$D/compose/www"
# coturn's image from Docker Hub, or Google's mirror of it (CI runners' anonymous pulls meet HTTP 429)
for i in 1 2 3 4; do
  for src in coturn/coturn:4.18 mirror.gcr.io/coturn/coturn:4.18; do
    if docker pull -q "$src" >/dev/null 2>&1; then echo "DSIP_COTURN_IMAGE=$src" >> "$D/compose/.env"; break 2; fi
  done
  [ "$i" = 4 ] && fail "no registry served coturn/coturn:4.18"
  sleep $((i * 15))
done
"$D/compose/init" --certificate "$D/tls" >"$D/init.log" 2>&1 || { cat "$D/init.log"; fail "./init failed"; }
did() { $CC cp dsip-mailbox:/var/lib/dsip-mailbox/service.did - | tar -xO; }
until_ok 20 get $CR /config.json || fail "the relay did not come up"
one_host compose $CR $CM "$(did)" "https://$NAME:$CR" $CM
$CC ps --format '{{.Service}} {{.State}}' | grep >/dev/null '^coturn running' || fail "coturn is not running"
# the shared namespace: each restarted, the relay still reaches the node on loopback
for svc in dsip-relay dsip-node; do
  $CC restart $svc >/dev/null
  until_ok 20 get $CR /dsip/v1/node || fail "after restarting $svc, the relay does not reach the hints node"
done
echo "compose: after restarting the relay and then the node, /dsip/v1/node still answers"
started() { $CC ps -q dsip-relay dsip-mailbox | xargs docker inspect -f '{{.State.StartedAt}}' | tr '\n' ' '; }
before=$(started)
"$D/compose/init" --certificate "$D/tls-renewed" >"$D/init-renew.log" 2>&1 || { cat "$D/init-renew.log"; fail "./init (renewal) failed"; }
until_ok 10 test "$(served $CR)" = "$(fingerprint "$D/tls-renewed")" || fail "the relay does not serve the renewed certificate"
until_ok 10 test "$(served $CM)" = "$(fingerprint "$D/tls-renewed")" || fail "the mailbox does not serve the renewed certificate"
[ "$(started)" = "$before" ] || fail "the renewal restarted a container"
echo "compose: a renewal through ./init --certificate reaches both, neither restarted"
echo "PASS"
