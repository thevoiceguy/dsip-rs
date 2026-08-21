#!/usr/bin/env bash
# Workstream D demo (plan §10.4 deliverable 2): two did:key endpoints discover each other's relay
# through the hints DHT and complete a signed call — no DNS, no Web PKI, no directory.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --workspace
B=target/debug; D=${DEMO_DIR:-/tmp/dsip-dht-demo}; rm -rf "$D"; mkdir -p "$D"

# 1. a three-node hints overlay (node 0 is the configured bootstrap — a centralization point, measured not hidden)
$B/dsip-dht-node --listen /ip4/127.0.0.1/tcp/4001 --control 127.0.0.1:4101 >"$D/n0.log" 2>&1 & N0=$!
sleep 1; BOOT=$(grep -m1 '^listening: ' "$D/n0.log" | cut -d' ' -f2)
$B/dsip-dht-node --listen /ip4/127.0.0.1/tcp/4002 --control 127.0.0.1:4102 --bootstrap "$BOOT" >"$D/n1.log" 2>&1 & N1=$!
$B/dsip-dht-node --listen /ip4/127.0.0.1/tcp/4003 --control 127.0.0.1:4103 --bootstrap "$BOOT" >"$D/n2.log" 2>&1 & N2=$!
trap 'kill $N0 $N1 $N2 $RELAY 2>/dev/null || true' EXIT
echo "bootstrap: $BOOT"

# 2. bob's relay (did:key identity, self-signed wss)
$B/dsip-relay --listen 127.0.0.1:8443 --state "$D/relay" >"$D/relay.log" 2>&1 & RELAY=$!
sleep 1.5; CA="$D/relay/cert.pem"

# 3. identities — did:key only
$B/dsip identity init --dir "$D/alice" --name "Alice" >/dev/null
$B/dsip identity init --dir "$D/bob" --name "Bob" >/dev/null
BOB=$(python3 -c "import json;print(json.load(open('$D/bob/identity.json'))['identity'])")

echo; echo "════════ bob binds to his relay and publishes a signed reachability hint into the DHT"
$B/dsip answer --identity "$D/bob" --relay wss://127.0.0.1:8443/dsip --ca "$CA" --dht "$BOOT" --publish-hint --auto accept \
  --script "sleep 12; quit" >"$D/bob.log" 2>&1 & P=$!
sleep 4; grep -E "^(dht|hint|relay)" "$D/bob.log"

echo; echo "════════ alice knows only bob's did:key. Resolution: no DID document ⇒ hints tier ⇒ bob's relay ⇒ signed call"
$B/dsip resolve "$BOB" --dht "$BOOT"
echo "────"
$B/dsip call --identity "$D/alice" --ca "$CA" --dht "$BOOT" --to "$BOB" --script "sleep 3; hangup; sleep 1; quit" | grep -vE "^\(commands"
wait $P
echo; echo "──── DHT node 0 stats:"; printf '{"op":"stats"}\n' | timeout 5 python3 -c "
import socket,sys,json; s=socket.create_connection(('127.0.0.1',4101)); s.sendall(sys.stdin.buffer.read()); print(json.dumps(json.loads(s.makefile().readline())['stats']))"
