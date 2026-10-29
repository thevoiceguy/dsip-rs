# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases follow `RELEASING.md`:
CalVer workspace tags over per-crate [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
