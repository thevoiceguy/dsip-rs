#!/usr/bin/env bash
# Test the dsip-push package and image as an operator runs them (after packaging/build.sh --image dsip-push):
#   1. the .deb on a Debian trixie host booted with systemd: installed disabled (it needs a DID and its apps first);
#      configured and started, the hardened unit active at systemd's exposure score; it serves its did:web document
#      naming its DSIPWake endpoint and refuses what is not a signed envelope; its signing key survives a crash; an
#      FCM service account installed by install-credential is read under the sandbox; removal keeps the edited config
#      (a conffile);
#   2. the container image: non-root, read-only root filesystem, no capabilities; its key survives a container restart
#      through the state volume.
#
# Spec: none (infrastructure).
set -euo pipefail
cd "$(dirname "$0")/../../.."
ROOT=$PWD; ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
DEB=$(ls crates/dsip-push/dist/dsip-push_*_"$ARCH".deb)
D=${PKGTEST_DIR:-/tmp/dsip-push-pkgtest}; rm -rf "$D"; mkdir -p "$D"
SD=dsip-push-pkgtest; PC=dsip-push-ctest
SP=${SP_PORT:-18445}; CP=${CP_PORT:-18446}
cleanup() {
  docker rm -f $SD $PC >/dev/null 2>&1 || true; docker volume rm -f $PC >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
fail() {
  echo "FAIL: $*"
  docker exec $SD journalctl -u dsip-push -o cat --no-pager 2>/dev/null | tail -15 | sed "1i--- journal of dsip-push" || true
  docker logs $PC 2>&1 | tail -25 | sed "1i--- log of container $PC" || true
  exit 1
}
until_ok() { # seconds command...: retry a check every 0.2 s
  local n=$(($1 * 5)); shift
  for _ in $(seq $n); do "$@" >/dev/null 2>&1 && return 0; sleep 0.2; done
  return 1
}
document() { curl -sfk "https://127.0.0.1:$1/.well-known/did.json"; }
# port did: the document is the DID's, names https://localhost:<the DID's port>/wake, and has one key; prints the key
checked_key() {
  document "$1" | python3 -c '
import json, sys
d = json.load(sys.stdin); did, port = sys.argv[1], sys.argv[1].split("%3A")[1]
assert d["id"] == did, d["id"]
eps = [s["serviceEndpoint"] for s in d["service"] if s["type"] == "DSIPWake"]
assert eps == ["https://localhost:%s/wake" % port], eps
print(json.dumps(d["verificationMethod"], sort_keys=True))' "$2"
}
refuses_junk() { # port: a POST that is not a signed envelope is not answered 200 (W§2.1)
  local code; code=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/dsip+json' \
    --data 'not an envelope' "https://127.0.0.1:$1/wake")
  [ "$code" != 200 ] && [ "$code" != 000 ]
}

echo "════════ 1. the .deb under systemd ($(basename "$DEB"))"
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
  -p 127.0.0.1:$SP:8445 dsip-services-systemd-test >/dev/null
docker exec $SD systemctl is-system-running --wait >/dev/null 2>&1 || true
sd() { docker exec $SD "$@"; }
sd rm -f /usr/sbin/policy-rc.d   # a real host's behaviour: maintainer scripts may start services
docker cp "$DEB" $SD:/root/push.deb
sd dpkg -i /root/push.deb >"$D/dpkg.log" 2>&1 || { cat "$D/dpkg.log"; fail "dpkg -i failed"; }
[ "$(sd systemctl is-enabled dsip-push || true)" = disabled ] || fail "dsip-push is not installed disabled"
[ "$(sd systemctl is-active dsip-push || true)" != active ] || fail "dsip-push started before it was configured"
echo "  installed disabled and not started: it has no DID or apps yet"

# configured as the operator would: its DID (here at the published port, so the document names what curl reaches)
DID="did:web:localhost%3A$SP"
sd sed -i -e "s|^did = .*|did = \"$DID\"|" -e 's|^app = .*|app = ["fcm:dsip-pkgtest"]|' \
  -e 's|^# record_to = |record_to = |' /etc/dsip-push/push.toml
sd systemctl enable --now dsip-push >/dev/null 2>&1 || fail "systemctl enable --now dsip-push"
until_ok 20 document $SP || fail "the gateway does not serve its document"
[ "$(sd systemctl is-active dsip-push)" = active ] || fail "dsip-push is not active"
score=$(sd systemd-analyze security dsip-push --no-pager 2>/dev/null | awk '/Overall exposure level/ {print $(NF-2)}')
python3 -c "import sys; sys.exit(0 if float('$score') <= 2.0 else 1)" || fail "dsip-push: exposure $score > 2.0"
[ "$(sd stat -c %U /var/lib/private/dsip-push)" = dsip-push ] || fail "its state is not its DynamicUser's"
[ "$(sd stat -c %a /var/lib/private/dsip-push/push.key)" = 600 ] || fail "its signing key is not private"
v=$(sd dpkg-query -W -f='${Version}' dsip-push); v=${v%-*}
[ "$(sd dsip-push --version)" = "dsip-push $v" ] || fail "dsip-push --version does not print its package's version $v"
KEY=$(checked_key $SP "$DID") || fail "its document is not its DID's, naming its endpoint"
refuses_junk $SP || fail "a POST that is not an envelope was answered 200"
echo "  enabled: active under DynamicUser, exposure $score; --version $v; serves $DID's document naming its endpoint; refuses junk"

sd systemctl kill -s KILL dsip-push
until_ok 30 sh -c "[ \"\$(docker exec $SD systemctl show -p NRestarts --value dsip-push)\" -ge 1 ]" || fail "systemd did not restart it"
until_ok 20 document $SP || fail "the gateway did not come back"
[ "$(checked_key $SP "$DID")" = "$KEY" ] || fail "its key changed across the restart"
echo "  killed, restarted by systemd: the same key"

# an FCM service account installed by install-credential: readable by the service alone, parsed at start
python3 -c 'import json,sys; print(json.dumps({"type": "service_account", "client_email": "pkgtest@dsip-pkgtest.iam.gserviceaccount.com",
  "private_key": open(sys.argv[1]).read(), "token_uri": "https://oauth2.googleapis.com/token"}))' \
  crates/dsip-push/tests/fcm-test-key.pem > "$D/fcm.json"
docker cp "$D/fcm.json" $SD:/root/fcm.json
sd /usr/libexec/dsip-push/install-credential /root/fcm.json fcm.json >/dev/null || fail "install-credential"
[ "$(sd stat -c '%a %U' /var/lib/private/dsip-push/credentials/fcm.json)" = "600 dsip-push" ] || fail "the credential is not the service's alone"
sd sed -i -e 's|^record_to = |# record_to = |' \
  -e 's|^# fcm_service_account = |fcm_service_account = |' /etc/dsip-push/push.toml
sd systemctl restart dsip-push
until_ok 20 document $SP || fail "the gateway did not start with the FCM credential"
[ "$(sd systemctl is-active dsip-push)" = active ] || fail "dsip-push is not active with the FCM credential"
run=$(sd journalctl -o cat --no-pager _SYSTEMD_INVOCATION_ID="$(sd systemctl show -p InvocationID --value dsip-push)")
echo "$run" | grep -q "push gateway $DID" || fail "this run did not start: $run"
if echo "$run" | grep -q "recording pushes"; then fail "still recording, not delivering"; fi
echo "  install-credential: the FCM service account, the service's alone, read under the sandbox"

sd dpkg -r dsip-push >/dev/null 2>&1
[ "$(sd systemctl is-active dsip-push || true)" != active ] || fail "removal left dsip-push running"
sd grep -q "^did = \"$DID\"" /etc/dsip-push/push.toml || fail "removal did not keep the edited config"
echo "  removal stopped it and kept its edited config"

echo; echo "════════ 2. the container image (dsip-push:dev)"
docker volume create $PC >/dev/null
CDID="did:web:localhost%3A$CP"
docker run -d --name $PC --read-only --cap-drop ALL --security-opt no-new-privileges:true -p 127.0.0.1:$CP:8445 \
  -v $PC:/var/lib/dsip-push dsip-push:dev --did "$CDID" --app fcm:dsip-pkgtest --record-to /var/lib/dsip-push/pushes.jsonl >/dev/null
until_ok 20 document $CP || fail "the gateway container does not serve its document"
[ "$(docker inspect $PC --format '{{.Config.User}}')" = 65532:65532 ] || fail "the image does not run as non-root"
KEY=$(checked_key $CP "$CDID") || fail "the container's document is not its DID's"
refuses_junk $CP || fail "the container answered junk 200"
docker restart $PC >/dev/null
until_ok 20 document $CP || fail "the gateway container did not come back"
[ "$(checked_key $CP "$CDID")" = "$KEY" ] || fail "the container's key changed across the restart"
echo "  non-root (65532), read-only root, no capabilities; restarted: the same key"
echo
echo "PASS: the .deb installs disabled, runs configured under its sandbox with its credential, keeps its key;"
echo "      the image runs locked down and keeps its key."
