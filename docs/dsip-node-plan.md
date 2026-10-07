# `dsip-node` — a deployable DSIP hints node (plan)

Decided with the user, 2026-10-06:
- **"Both, one service":** one install that is a member of DSIP's own overlay and a participant in the Mainline
  DHT, and that serves hints over HTTP.
- **Packaging:** all three — a static binary with a systemd unit, a container image, and a Debian package.

This note is the design. Each stage below is its own PR. The raising note is the memory "DSIP DHT node idea"
(2026-08-23), and the measured problems it must answer are in `dht-findings.md` ("WAN results").

## 1. What it is, and what it is not

`dsip-node` stores and serves **reachability hints** (core §8.5; the DHT Reachability Hints Profile). It is a hints
tier and nothing more:
- **It is never authoritative** (§8.1). It verifies every record before storing or serving it (profile §4), and every
  client verifies again: a node can withhold or serve an older hint, but it cannot forge one.
- **It carries no messages, media or presence.** It is not a relay (§13), a mailbox (M§9) or a TURN server.
- **It solves no Sybil problem.** It instruments one (§3.2, plan §10.5): per-peer budgets, counters and limits,
  stated as limits.

## 2. The three faces of one process

| face | what | spec |
|---|---|---|
| **Overlay member** | libp2p Kademlia on `/dsip/hints/0.6`, verify-before-store; device-signed JOSE hints, `did:web` subjects | profile §2–§5 |
| **Mainline participant** | a BEP 5/44 node on the BitTorrent Mainline DHT (`mainline` crate), in server mode when reachable. As a DHT server it stores other nodes' items by BEP 44's own rules, which the crate applies; what it accepts over HTTP passes `check: "store"` first (§3) | profile §9, §9.1 |
| **HTTP hints API** | lookups and publishes for clients that cannot speak UDP or libp2p (browsers, light clients) | new profile §10 (v0.11) |

The overlay and Mainline faces are the existing code (`dsip-dht::node`, `dsip_cli::pkarr_cli`), hardened and run
side by side in one tokio runtime. They share one verification path (`dsip_core::pkarr` and `dsip-dht::record`).

## 3. HTTP hints API (profile §10, v0.11)

It is plain HTTP/1.1 and HTTP/2 over TLS, or behind a reverse proxy, with
`Access-Control-Allow-Origin: *` so browsers can call it.

| method and path | body / answer | notes |
|---|---|---|
| `GET /<z32>` | 200 with the Pkarr relay payload (`sig ‖ seq ‖ packet`), or 404 | Pkarr relay compatible: existing Pkarr clients and DSIP's `--pkarr-relay` work unchanged |
| `PUT /<z32>` | 204, 400 or 409 | Pkarr relay compatible. A node serves every application's packets, so it checks what every packet must pass (canonical key, frame, signature, timestamp, DNS) and §8.3's `ts` rule (`check: "store"`), then puts it on Mainline. `_dsip` content is judged by readers |
| `GET /dsip/v1/hints/<did>` | `{"hints": ["<frame>", …]}` | overlay hints for a DID; every frame verified, expired ones dropped |
| `POST /dsip/v1/hints` | a frame; 202 or 400 | verified, stored, put on the overlay |
| `GET /dsip/v1/node` | `{peer_id, overlay: {peers, records}, mainline: {routing, server_mode}, version}` | for operators and directories |
| `GET /metrics` | Prometheus text | §6 |

The normative core of §10 is small:
- the four hint routes and their status codes;
- the rule that a client verifies everything it receives, exactly as from the DHT;
- **withholding is the node's only power** — the same statement the profile makes for Pkarr relays;
- rate limits are the operator's, and answer 429.

The rest of this note is implementation.

## 4. Configuration

A config file, `/etc/dsip-node/config.toml`, with every key also available as a command-line flag:

```toml
[node]
state_dir = "/var/lib/dsip-node"          # identity seed, peers, held records
[overlay]
listen = ["/ip4/0.0.0.0/tcp/4610"]
bootstrap = ["/dns4/boot1.example/tcp/4610/p2p/12D3…"]
[mainline]
enabled = true
port = 6881                                # UDP
[http]
listen = "0.0.0.0:8080"
tls_cert = ""                              # empty: plain HTTP, for a reverse proxy
tls_key = ""
[limits]
put_per_peer_per_min = 60
verify_failures_before_ban = 20            # then disconnect and ban (the WAN finding)
ban_secs = 600
http_requests_per_ip_per_min = 120
```

## 5. State and restart

The state directory holds:
- **the node's libp2p identity**, generated once, so the PeerId is stable;
- **learned peers**, rewritten every re-announce (#60). Bootstrap nodes keep them too, which answers the WAN finding
  of a restarted bootstrap with no peers for over 3 minutes;
- **held records:** overlay frames and Pkarr payloads, restored at start and dropped as they expire;
- **Mainline routing-table nodes,** used as the next start's bootstrap.

A restart therefore rejoins without waiting for the network. A **bootstrap directory** is plain configuration:
`bootstrap` entries may be `/dns4/` multiaddrs, so an operator can rotate nodes behind a name. No DSIP-run registry
is assumed.

## 6. Limits and observability (the WAN findings)

- **Per-peer verification budget** (exists): 20 failures in 60 s drops a peer's PUTs unverified.
- **Bans** (stage 3, measured; `demos/dsip-node-flood-demo.sh`):
  - **What was planned, and failed:** disconnect the peer and refuse its PeerId. That cost **4×** the CPU of the
    budget alone. The flooder redials, and libp2p learns a PeerId only after the Noise handshake, so every refused
    redial is a TCP accept plus a key exchange.
  - **What shipped:**
    - a banned peer's PUTs are dropped unverified for the whole ban;
    - it leaves the routing table;
    - its connection stays open (the default).
  - **With `ban_ip`:** its address is refused before the handshake (`IpGate`, `handle_pending_inbound_connection`)
    and the connection is closed. Its redials then cost a TCP accept.
  - **Measured over 30 s at ~50 PUTs/s,** victim CPU, three runs:

    | victim | CPU |
    |---|---|
    | budget only | 2.4–2.5 s |
    | ban in place | 2.4–2.8 s |
    | `ban_ip` | 0.66–0.93 s |

  - **`ban_ip` is the operator's choice:** PeerIds are free to mint, addresses are not, but honest peers behind the
    same NAT are refused too.
- **HTTP rate limit** per client IP, answered with 429.
- **Prometheus metrics:** peers, records held, puts accepted and refused by reason, verification failures, bans,
  HTTP requests by route and status, Mainline routing size.
- **Logs:** structured, one line per refusal with its reason token.

## 7. Packaging (stage 4)

- **Static binaries:** musl, x86_64 and aarch64, built in CI on tags and attached to the GitHub release.
- **systemd:** `dsip-node.service` with `DynamicUser=`, `StateDirectory=dsip-node`, `ProtectSystem=strict` and the
  rest of the usual hardening; config in `/etc/dsip-node/`.
- **Container:** a distroless image, published to GHCR on tags, plus a `compose.yaml` example (UDP 6881, TCP 4610,
  8080).
- **Debian package:** built with `cargo-deb`. It ships the unit, a default config and a `dsip-node` system user. It
  is attached to releases; no APT repository is planned.

## 8. Stages

1. **Spec and API core.** Profile §10 text, the HTTP API on top of today's overlay and Pkarr code, and verify-before-
   store on every route. A Rust integration test drives each route. Demo: a 3-node local network (overlay plus a
   Mainline testnet), where a "browser" (curl) publishes and looks up hints only over HTTP, and a forged `PUT` and
   an older `seq` are refused.
2. **Config, state, restart.** TOML config, the state directory, held records restored. Demo: kill and restart a
   bootstrap node; it rejoins in seconds, not minutes.
3. **Limits and metrics.** Connection-level bans, HTTP rate limits, `/metrics`. Demo: a flooding peer is banned and
   CPU falls, measured as the WAN run did.
4. **Packaging.** musl binaries, the systemd unit, the container and the `.deb`, built in CI. The demo runs inside
   the container.
5. **WAN** (needs the user's Linodes). Deploy the `.deb` on the four hosts; a browser on a laptop looks up a hint
   through the HTTP API of a node across the Atlantic; results go into `dht-findings.md`.

## 9. Spec impact

- **DHT Reachability Hints Profile §10, HTTP access** (new, v0.11): routes, statuses, and "verify everything;
  withholding is the only power".
- **Core A.8:** one item.
- **Spec-gap 105's open item, "browsers are relay-only":** answered. Browsers still never join a DHT, but any
  `dsip-node` serves them over HTTP with the same offline verification. A relay-hosted lookup is no longer the only
  path.
