# dsip-node

A DSIP reachability-hints node. One process, three faces:

- **a member of the DSIP overlay** (libp2p Kademlia, `/dsip/hints/0.6`): device-signed and `did:web` hints;
- **a participant in the BitTorrent Mainline DHT**, holding Pkarr packets: `did:key` hints, and any other Pkarr
  application's packets;
- **an HTTP hints API** (DHT Reachability Hints Profile §10), for clients that join neither DHT, such as browsers.
  It speaks Pkarr's relay interface (`GET`/`PUT /<z32>`), so existing Pkarr clients use it unchanged.

**It is a hints tier, never an authority** (DSIP core §8.1). It verifies every record before storing or serving it,
and clients verify again. A node can withhold a hint or serve an older one; it cannot forge one. It carries no
messages, media or presence. Design and measurements: `impl/docs/dsip-node-plan.md`, `impl/docs/dht-findings.md`.

## Install

| | |
|---|---|
| **Debian / Ubuntu** | `apt install ./dsip-node_<version>_<arch>.deb`. This installs `/usr/bin/dsip-node`, `/etc/dsip-node/config.toml` (a conffile, kept on upgrade) and `dsip-node.service`, enabled and started. |
| **Any Linux** | Unpack `dsip-node-<version>-linux-<arch>.tar.gz` (a static binary, no dependencies). Install `dsip-node.service` and `config.example.toml` from the tarball by hand. |
| **Container** | `docker run -d -p 8080:8080 -p 4610:4610 -p 6881:6881/udp -v dsip-node:/var/lib/dsip-node ghcr.io/thevoiceguy/dsip-node`, or `compose.yaml`. |

The package starts at once with its default config. To start with your own instead (another HTTP port, bootstrap
nodes), put `/etc/dsip-node/config.toml` in place first and install with `-o Dpkg::Options::=--force-confold`.

Releases carry `SHA256SUMS`. To build everything yourself, run `packaging/build.sh --image`; to test it as an
operator would, run `packaging/test.sh`.

## Ports

| port | what | expose? |
|---|---|---|
| 4610/tcp | the DSIP overlay | yes, for peers to reach you |
| 6881/udp | the Mainline DHT | yes, for server mode (`[mainline] server = true`) |
| 8080/tcp | the HTTP hints API and `/metrics` | through a TLS reverse proxy; the package binds it to 127.0.0.1 |

## Configure

Edit `/etc/dsip-node/config.toml`; every key is explained in `config.example.toml`. A flag of the same name overrides
a key (`dsip-node --help`), and a misspelt key is an error.
- **Join an overlay:** add its bootstrap nodes to `[overlay] bootstrap`, as `/dns4/<name>/tcp/4610/p2p/<PeerId>`.
- **Find your node's PeerId:** `curl localhost:8080/dsip/v1/node`, or look in the log at start.
- **Behind a reverse proxy:** set `[limits] trust_x_forwarded_for = true`, so rate limits apply per client, not per
  proxy.

## Security posture

- **Package:** the systemd unit runs under `DynamicUser` with no capabilities, `ProtectSystem=strict`, a
  `@system-service` syscall filter, W^X memory and a private `/var/lib/dsip-node`. `systemd-analyze security
  dsip-node` rates it 1.1, "OK".
- **Container:** distroless, non-root (65532); it runs with a read-only root and `cap_drop: [ALL]`.
- **The identity key** (`overlay.key`) is created with mode 0600. Keep the state directory: it holds the node's
  PeerId, learned peers, held records, and its Mainline routing nodes and public address, so a restart rejoins in
  seconds on both DHTs. Every record read back from it is verified again.
- **Held Pkarr packets** are served at once, and looked for again on Mainline at most once a minute; one past its
  TTL is looked for before it is served, so a publisher's re-signed packet replaces it.
- **Flooding peers:** a peer that fails 20 verifications in 60 s is banned for `ban_secs`. Its PUTs are dropped
  unverified and it leaves the routing table.
  - `ban_ip = true` also refuses its address **before** the handshake. Measured, this cuts a flood's CPU by about
    70%, but it refuses honest peers behind the same NAT as well.
  - Closing a flooder's connection by PeerId was measured to cost **more**: it redials, and each refusal costs a
    handshake.
- **HTTP:** 120 requests per client IP per minute (429 beyond); `/metrics` is never limited.

## Operate

- **`GET /metrics`** (Prometheus) reports:
  - overlay peers, records, PUTs by reason, bans and refused connections;
  - Mainline mode and size;
  - Pkarr packets held and PUT outcomes;
  - HTTP requests by route and status.
- **`GET /dsip/v1/node`** reports the PeerId, overlay and Mainline status, packets held and the version.
- **Logs** go to the journal, or to stdout in a container: plain text, one line per refusal with its reason.
