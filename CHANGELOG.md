# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases follow `RELEASING.md`:
CalVer workspace tags over per-crate [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Config files for the relay and the mailbox** (service-nodes plan S1). `dsip-relay --config <file>` and
  `dsip-mailbox --config <file>` read a TOML file whose keys are their flags in `snake_case`. A flag on the command
  line wins, and a repeatable one replaces the file's list. An unknown key is an error. Each crate has a
  `config.example.toml` explaining every key, which a test checks against the binary. The mechanism is
  `dsip_transport::config_file`, behind dsip-transport's new `cli` feature.
- **`did:web` over HTTPS in the relay and the mailbox** (S2). Both fetch the `did:web` documents a frame needs (its
  signer, its delegations' issuers, and the grants a `subscribe` presents) before verifying it, after their document
  files, which still answer first (§8.1). A document is reused for `--did-web-ttl` (300 s). A DID whose fetch failed
  is not fetched again for 60 s, and fetches are capped per frame and in flight. `--did-web-ca` adds PEM roots and
  `--no-fetch-did-web` turns fetching off. `dsip_transport::resolver` gains `WebDocuments`, `Over`, `web_documents`,
  `DidWebResolver::with_ca` and `DidWebResolver::cached`. `demos/did-web-demo.sh` runs in CI.
- **The relay's queue on disk** (S3). `dsip-relay` keeps its store-and-forward queue and the recipients it knows
  in `<state>/queue.redb`. A restarted relay, even one that was killed, delivers what it held within each
  envelope's deadline, and a known, offline recipient stays known (§13.3). After each step only the queues it touched
  are rewritten, durably. `dsip_relay::store::QueueStore`; `dsip_session::fork::Relay` gains `known_recipients` and
  `restore` (`Known`; `Queued` is now serde). `demos/relay-restart-demo.sh` runs in CI.

### Changed

- **Breaking:** `dsip_relay::RelayConfig` and `dsip_mailbox::MailboxConfig` gain a `did_web` field (`None` by
  default: the library fetches nothing unless asked), and `RelayConfig` a `queue_store` field (`None`: in memory, as
  before). Struct literals need them, or `..Default::default()`.

## [2026-10-29] — workspace release

The first release. DSIP spec: `poc-v1.0` (DSIP Core 1.0 and its profiles; 2,323 vectors, 0 failures).

| Crate | Version |
|---|---|
| `dsip-broadcast` | 0.1.0 |
| `dsip-cli` | 0.1.0 |
| `dsip-core` | 0.1.0 |
| `dsip-dht` | 0.1.0 |
| `dsip-endpoint` | 0.1.0 |
| `dsip-events` | 0.1.0 |
| `dsip-gateway` | 0.1.0 |
| `dsip-kt` | 0.1.0 |
| `dsip-mailbox` | 0.1.0 |
| `dsip-media` | 0.1.0 |
| `dsip-messaging` | 0.1.0 |
| `dsip-messaging-device` | 0.1.0 |
| `dsip-messenger` | 0.1.0 |
| `dsip-mls` | 0.1.0 |
| `dsip-node` | 0.1.0 |
| `dsip-number` | 0.1.0 |
| `dsip-phone` | 0.1.0 |
| `dsip-recording` | 0.1.0 |
| `dsip-relay` | 0.1.0 |
| `dsip-schema` | 0.1.0 |
| `dsip-session` | 0.1.0 |
| `dsip-testkit` | 0.1.0 |
| `dsip-transport` | 0.1.0 |
| `dsip-wasm` | 0.1.0 |
| `dsip-webrtc-binding` | 0.1.0 |

**Breaking changes:** none; this is the first release.

### Added

- **The move from DSIP.** Every crate of the DSIP reference implementation, its workspace, `demos/`, the browser
  client (`web/`) and the stack's documents (`docs/`) come from DSIP's `impl/`, with their history (`git
  filter-repo`). Every crate is 0.1.0.
- **`spec/`.** DSIP as a git submodule at `poc-v1.0`: DSIP Core 1.0 and its profiles (`spec/v1.0/`), the schemas
  the crates embed, and the conformance suite (`spec/impl/vectors/`: 2,323 vectors, 0 failures).
- **Docs:** `README.md`, `CLAUDE.md`, `RELEASING.md` (siphon-rs's model), and `CHANGELOG.md`.
- **Public before the first release.** The repository went public on 2026-10-29, so that CI runs.
- **CI:** build, clippy, tests, docs, the vector suite and every demo; the wasm build and the browser client's
  tests; the dsip-node packages, and their release on a `dsip-node-v*` tag.
