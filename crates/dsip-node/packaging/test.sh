#!/usr/bin/env bash
# Test the dsip-node packages as an operator would run them (after packaging/build.sh --image):
#   1. the .deb in a Debian trixie container booted with systemd: installed and enabled; the hardened unit starts
#      (a sandbox setting the binary trips over only shows at run time); systemd's exposure score; the identity key
#      private; a held packet and the PeerId survive a restart; removal keeps the config (a conffile);
#   2. the container image: non-root, read-only root filesystem, no capabilities; a held packet and the PeerId survive
#      a container restart through the state volume.
# Mainline is turned off in both, so nothing here touches the public DHT.
#
# Spec: none (infrastructure).
set -euo pipefail
cd "$(dirname "$0")/.."
IMPL=$(cd ../.. && pwd)
ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
DEB=$(ls dist/dsip-node_*_"$ARCH".deb)
SD=dsip-node-pkgtest; CT=dsip-node-ctest; VOL=dsip-node-ctest-state; PORT=${PORT:-18480}
cleanup() { docker rm -f $SD $CT >/dev/null 2>&1 || true; docker volume rm -f $VOL >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
fail() { echo "FAIL: $*"; exit 1; }
# a Pkarr packet (a fixture key's _dsip hint): its z32 key and its bytes
read -r Z HEX < <(cd "$IMPL" && python3 -c '
import sys; sys.path.insert(0, "tools")
from dsipvec.gen.pkarr import payload, EP, K
from dsipvec.pkarr import z32_encode
print(z32_encode(K.public), payload([EP]))')
echo "$HEX" | xxd -r -p > dist/.packet

echo "════════ 1. the .deb under systemd ($(basename "$DEB"))"
docker build -q -f packaging/systemd-test.Containerfile -t dsip-node-systemd-test . >/dev/null
docker run -d --name $SD --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  dsip-node-systemd-test >/dev/null
docker exec $SD systemctl is-system-running --wait >/dev/null 2>&1 || true
docker cp "$DEB" $SD:/root/pkg.deb; docker cp dist/.packet $SD:/root/packet
sd() { docker exec $SD "$@"; }
# a real host's behaviour: Debian's container images forbid maintainer scripts to start or stop services
sd rm -f /usr/sbin/policy-rc.d
# the operator's config, in place before the package (a conffile: dpkg keeps it); no public Mainline for a test
dpkg-deb --fsys-tarfile "$DEB" | tar -xO ./etc/dsip-node/config.toml \
  | sed '/^\[mainline\]/,/^\[/ s/^enabled = true/enabled = false/' > dist/.config.toml
sd mkdir -p /etc/dsip-node; docker cp dist/.config.toml $SD:/etc/dsip-node/config.toml
sd dpkg -i --force-confold /root/pkg.deb >/dev/null 2>&1 || fail "dpkg -i failed"
[ "$(sd systemctl is-enabled dsip-node)" = enabled ] || fail "the unit is not enabled"
for _ in $(seq 50); do sd curl -sf localhost:8080/dsip/v1/node >/dev/null 2>&1 && break; sleep 0.2; done
[ "$(sd systemctl is-active dsip-node)" = active ] || { sd journalctl -u dsip-node --no-pager | tail -20; fail "the unit is not active"; }
SCORE=$(sd systemd-analyze security dsip-node --no-pager 2>/dev/null | awk '/Overall exposure level/ {print $(NF-2)}')
python3 -c "import sys; sys.exit(0 if float('$SCORE') <= 2.0 else 1)" || fail "exposure $SCORE > 2.0"
PEER=$(sd curl -s localhost:8080/dsip/v1/node | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer_id"])')
[ "$(sd stat -c '%a %U' /var/lib/private/dsip-node/overlay.key)" = "600 dsip-node" ] || fail "the identity key is not private"
[ "$(sd curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @/root/packet localhost:8080/$Z)" = 204 ] || fail "PUT"
sd systemctl restart dsip-node
for _ in $(seq 50); do sd curl -sf localhost:8080/dsip/v1/node >/dev/null 2>&1 && break; sleep 0.2; done
[ "$(sd curl -s localhost:8080/dsip/v1/node | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer_id"])')" = "$PEER" ] \
  || fail "the PeerId changed across a restart"
sd sh -c "curl -s localhost:8080/$Z | cmp -s - /root/packet" || fail "the packet did not survive the restart"
sd dpkg -r dsip-node >/dev/null 2>&1
[ "$(sd systemctl is-active dsip-node || true)" != active ] || fail "removal left the service running"
sd grep -q '^enabled = false' /etc/dsip-node/config.toml || fail "removal did not keep the edited conffile"
echo "  installed, enabled and started by dpkg; active under DynamicUser, exposure $SCORE (systemd-analyze security); key 0600"
echo "  PeerId ${PEER:0:16}… and the held packet survived a restart; removal stopped it and kept the edited config"

echo; echo "════════ 2. the container image (dsip-node:dev)"
cat > dist/.ct.toml <<'EOF'
[node]
state_dir = "/var/lib/dsip-node"
[overlay]
listen = ["/ip4/0.0.0.0/tcp/4610"]
[mainline]
enabled = false
[http]
listen = "0.0.0.0:8080"
EOF
docker volume create $VOL >/dev/null
docker run -d --name $CT --read-only --cap-drop ALL --security-opt no-new-privileges:true -p 127.0.0.1:$PORT:8080 \
  -v $VOL:/var/lib/dsip-node -v "$PWD/dist/.ct.toml:/etc/dsip-node/config.toml:ro" dsip-node:dev >/dev/null
for _ in $(seq 50); do curl -sf localhost:$PORT/dsip/v1/node >/dev/null 2>&1 && break; sleep 0.2; done
[ "$(docker inspect $CT --format '{{.Config.User}}')" = 65532:65532 ] || fail "the image does not run as non-root"
PEER=$(curl -s localhost:$PORT/dsip/v1/node | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer_id"])')
[ "$(curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @dist/.packet localhost:$PORT/$Z)" = 204 ] || fail "PUT"
docker restart $CT >/dev/null
for _ in $(seq 50); do curl -sf localhost:$PORT/dsip/v1/node >/dev/null 2>&1 && break; sleep 0.2; done
[ "$(curl -s localhost:$PORT/dsip/v1/node | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer_id"])')" = "$PEER" ] \
  || fail "the PeerId changed across a container restart"
curl -s localhost:$PORT/$Z | cmp -s - dist/.packet || fail "the packet did not survive the container restart"
curl -s localhost:$PORT/metrics | grep -q '^dsip_node_pkarr_held 1$' || fail "metrics"
echo "  non-root (65532), read-only root, no capabilities; PeerId ${PEER:0:16}… and the held packet survived a restart"
rm -f dist/.packet dist/.ct.toml dist/.config.toml
echo
echo "PASS: the .deb installs, starts under its sandbox and keeps its state; the image runs locked down and keeps its state."
