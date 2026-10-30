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
- **The mailbox's state in SQLite** (S4). `dsip-mailbox` keeps its state in `<state>/mailbox.sqlite` instead of
  `mailbox-state.json`, which was rewritten whole after every change (spec-gap 59). Each stored item is a row,
  holding the machine's record and the payload. It is written when the item is stored and deleted when the machine
  drops it. The rest is saved as parts (per owner, per hubbed group, per kind), and only the parts that changed are
  written, in one durable transaction. A mailbox upgraded from the JSON file imports it once and renames it
  `mailbox-state.json.imported`. A save's cost no longer grows with the items held: `store_stress` measures about
  42,000 deposits/s at 1,000, 10,000 and 100,000 items held, and about 1.45 KB on disk per 1 KB item.
  `dsip_messaging::mailbox::Mailbox` gains `changes`, `saved`, `all_stored`, `record` and
  `full_state_without_items`.
- **Operating the relay and the mailbox** (S5).
  - **Certificate reload on `SIGHUP`.** Both binaries read their certificate and key again on `SIGHUP`. New TLS
    handshakes get the renewed certificate, and connections already open, and the devices bound on them, are
    untouched. A renewal that does not load (a half-written file, a key that is not the certificate's) is logged
    and the previous certificate stays in service. `dsip_transport::tls::Certificates`.
  - **Admin commands on the status port.** `dsip-relay admin bindings` lists the bound devices, each with the
    address it bound from and for how long. `dsip-mailbox admin enrolments` lists the enrolled identities against
    `--serve-any` (storage, devices bound, last `hello`, when idle expiry releases them) and the configured owners.
    `dsip-mailbox admin release <did>` ends an enrolment: everything held for the identity is deleted and its
    bindings closed, as when it releases itself (M§4.1 "By its operator", spec-gap 164). The
    commands find the service from `--status <addr>`, or from `status_listen` in its `--config` file, and print
    JSON with `--json`. A command that changes state is a `POST` carrying an `x-dsip-admin` header, so a web page
    cannot send one. `dsip_transport::admin`, `dsip_transport::status::request`;
    `dsip_messaging::enrolment::Enrolment` gains `operator_release`, the `enrolment-trace` event
    `operator_release`, and `is_configured`.
  - **journald.** `--log auto|journald|stderr`. When standard error is the journal (`JOURNAL_STREAM` names it),
    `auto` logs to the journal natively, with each line's level as its priority, so `journalctl -p warning` works.
    Elsewhere it logs to standard error, as before.
    `dsip_transport::logging`.
  - `demos/operating-demo.sh` runs in CI.
- **Packages for the relay and the mailbox** (S6). `packaging/build.sh [--image]` builds, for `dsip-relay` and
  `dsip-mailbox`:
  - static musl binaries for x86_64 and aarch64, and their tarballs;
  - a `.deb` for each architecture, and `SHA256SUMS`;
  - with `--image`, a distroless image.

  Each `.deb` installs:
  - the config `/etc/dsip-relay/relay.toml` or `/etc/dsip-mailbox/mailbox.toml`, a conffile kept on upgrade and
    removal;
  - a `DynamicUser` unit with the same sandbox as dsip-node's, whose `ExecReload` sends SIGHUP;
  - `/usr/libexec/<service>/install-certificate`. As certbot's `--deploy-hook`, it copies the renewed pair into the
    service's state directory (the service cannot read `/etc/letsencrypt`) and reloads the service in place.

  `packaging/build.sh dsip-web` packs the browser client as `dsip-web-<version>.tar.gz` for the relay's `--www`.
  `packaging/test.sh` runs in CI. It installs both `.debs` on one systemd host and runs the images locked down. In
  both it checks that the relay's queued invite and certificate, and the mailbox's enrolment and service key,
  survive a crash and a restart. It also checks that a certificate renewal reaches the running relay. dsip-mailbox
  gains the feature `static`: SQLite and OpenSSL compiled in.

### Fixed

- **The mailbox kept every item's payload forever.** When the machine dropped an item (queue-mode deletion,
  retention, pending-group expiry), its payload stayed in memory and in the saved state. It now goes with the item.

### Changed

- `dsip_mailbox::store::Store::retain` takes a predicate. `Store` no longer has to be saved whole.
- **Breaking:** `dsip_relay::RelayConfig` and `dsip_mailbox::MailboxConfig` gain a `did_web` field (`None` by
  default: the library fetches nothing unless asked), and `RelayConfig` a `queue_store` field (`None`: in memory, as
  before). Struct literals need them, or `..Default::default()`.
- **Breaking:** `dsip_transport::status::Page` gains `Admin` and is no longer `Copy`; a service's status renderer
  answers it.

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
