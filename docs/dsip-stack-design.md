# A DSIP stack for developers — design note

**Status:** a design note, written 2026-10-17 at poc-v0.16, for when the specs settle. It does not start work. It
records what a developer-facing DSIP stack would contain, how it relates to siphon-rs, what in today's PoC is and is
not library-shaped, and the order to build it in. The decisions it needs are in [§9](#9-decisions-for-the-owner).

## 1. The goal

A set of Rust crates (with a browser build) that a developer uses to build a DSIP application — a softphone, a
chat client, a contact-centre agent, a relay or mailbox operator's service — without reading the spec first. The
model is siphon-rs for SIP: layered crates, an integrated high-level API over a low-level one, pluggable storage
and transport, and a reference daemon.

What the stack is measured against is already built: the 2,130 vectors in `impl/vectors` and the second
implementation that passes them. A stack crate that implements normative behaviour passes the vectors for it;
that rule carries over unchanged.

## 2. What exists today

About 40k lines of Rust in 21 crates (all 0.1.0, none published) and about 2,300 lines of browser JavaScript.

**Already in good shape for a library:**
- **A sans-I/O core.** `dsip_session::Endpoint::step(&Event) -> Vec<Emission>` and `fork::Relay::step` are pure;
  time enters as an `Advance` event; `next_deadline()` says when to call again. `dsip_endpoint::Core` adds framing,
  verification and signing on top, still without I/O (`inbound(frame, now)`, `local(event, now)`, `tick(now)`).
  This is a stronger base than siphon-rs has: there, only the transaction FSMs are sans-I/O and everything above
  them runs on tokio.
- **Pure rule crates.** `dsip-messaging` (the client, hub and mailbox state machines), `dsip-webrtc-binding`,
  `dsip-broadcast`, `dsip-number`, `dsip-recording`, `dsip-events` and `dsip-kt` hold the rules with no I/O, and are
  pinned by vectors.
- **Every public item documented** (`#![deny(missing_docs)]`), with `Spec:` lines.
- **Runtime splits that already work:** a `wasm` feature on dsip-core and dsip-endpoint, `node` on dsip-dht, `host`
  on dsip-gateway.

**Not library-shaped:**

1. **Each host reimplements the same protocol glue.** The CLI (`dsip-cli/src/console.rs`, 976 lines), the browser
   (`web/app.js`, 1,967 lines) and the gateway (`dsip-gateway/src/host/call.rs`) each drive `Core`/`Agent`
   themselves. Each one does its own:
   - ICE candidate buffering until the session is active, and the signed `info` that carries the candidates
     (§12.12; console.rs:253–263, app.js:500–523);
   - SDP plumbing: reading `/transports/0/sdp` out of a JSON payload, then accept-offer or set-answer;
   - media gating on `Emission::Media("start")` (§14.1);
   - relay discovery, hint publishing and re-signing, number lookups.

   Some logic lives in only one host:
   - **CLI only:** the seal fallback (resend once in clear after `session.unsupported-critical-extension`, §10.4;
     console.rs:599–615) and call-recording consent (C§4; console.rs:629–665).
   - **Browser only:** the trust UI for incoming calls.

   So the hosts already behave differently, and a new application would have to write all of this a fourth time.
   This is the main thing a stack fixes.
2. **The messaging client is written twice, and neither copy is a library:**
   - the native `dsip-msg` binary (a private `struct Client`, plus stdin commands, plus an SNMP/syslog gateway in the
     same 4,324-line file);
   - the wasm `Messenger` (2,946 lines).

   The mailbox service is likewise binary-only.
3. **The API is stringly typed:**
   - **Errors:** `anyhow::Result` is returned from `Core`, `Agent`, `MediaLeg` and `Identity`.
   - **Emissions:** `Emission::Media(&'static str)`, timer actions as `&'static str`, and
     `Ui { kind, fields: Vec<(&str, Value)> }`.
   - **Rejections:** `CoreEvent::Rejected { code: String }`.
   - **Payloads:** `Received { payload: Value }`, read with JSON pointers.
   - **Messaging:** about 100 `dsip-messaging` functions take or return `serde_json::Value`.
   - **Parameters through setters:** `set_sdp` fills a single pending slot before `local(Accept)`, and `set_info_data`,
     `set_claims` and `set_invite_patch` work the same way. `LocalEvent::Info` itself carries no data.
4. **Nothing is pluggable:**
   - **Resolver:** `Core::new` and `Agent::connect` take a concrete `StaticResolver`. `did:web` documents are
     prefetched into it, and `Resolver::resolve` is synchronous and returns an `Option`.
   - **Transport:** `Agent` is wired to tokio-tungstenite, with no transport trait.
   - **Storage:** contacts are a `contacts.json` that `Agent` reads and writes itself, and seen-ids reset on reconnect.
     The only storage abstraction is OpenMLS's provider.
5. **Key custody is a PoC shortcut.**
   - `dsip_transport::Identity` is a directory holding the controller key next to the device key.
   - `Agent` derives the identity's unseal key from the controller seed (agent.rs:108–111).
   - A real device should hold only its device key and its delegation (§7.3–7.5). That is how the browser client
     already works, which is why it cannot be sealed to at the identity.
   - The identity bundle has three shapes: the CLI directory, `IdentityKeys`, and the wasm identity JSON.
6. **Few examples and a few panics.**
   - **Examples:** module docs map spec sections rather than show usage. Apart from one dsip-dht stress example there
     are no `examples/`.
   - **Panics:** `unreachable!` in `Endpoint` (endpoint.rs:534, :665) and a schema-compile `panic!`.

## 3. Relationship to siphon-rs

siphon-rs is the user's production SIP stack (18 crates, CalVer workspace tags over per-crate SemVer, consumed as
git dependencies). It and DSIP already meet in two places:
- the gateway, which uses siphon-rs UAC/UAS (`dsip-gateway`'s `host` feature);
- `forge-sdp`, which builds on siphon-rs's SDP.

**Options:**

| | What it means | For | Against |
|---|---|---|---|
| **A. A separate stack with the same conventions** | Its own workspace. It copies siphon-rs's release model and API patterns, and depends on the few siphon-rs crates that genuinely fit. | The protocols share little code: SIP is text over UDP/TCP with transactions; DSIP is signed JSON envelopes over a WebSocket binding with sans-I/O state machines. Each keeps its own pace. | Two release trains to keep in step for the gateway. |
| **B. Extract shared crates first** | Move the generic parts of siphon-rs (rate limiting, metrics traits, TLS config, SDP) into a common workspace both depend on. | One copy of each. | A refactor of a production stack, for parts that are small and not the hard part. siphon-rs's metrics and HEP hooks are set-once process globals, which a library should not copy. |
| **C. DSIP inside the siphon-rs workspace** | dsip-* crates beside sip-*. | One repository, one release. | Couples DSIP's spec-driven churn to a production SIP stack's releases. The vectors, three-way parity and impl-ts would move with it or split from it. |

**Recommendation: A.**
- **Copy from siphon-rs:**
  - the release model (`RELEASING.md`: CalVer workspace tags, per-crate SemVer, minor = breaking before 1.0, a
    CHANGELOG listing every crate's version and its breaking changes);
  - the two-tier API (low-level builders plus a builder-configured `Integrated*` facade);
  - store traits with sync and async adapters;
  - a testkit crate;
  - the doc rules it shares with this repo (`///` on everything, citations in comments).
- **Reuse:** `sip-sdp` through `forge-sdp` for SDP, as the media path already does; `sip-identity` for the
  STIR/PASSporT work in `dsip-number` and the gateway.
- **Don't copy:** process-global hooks (`set_transport_metrics`, `set_emitter`, global rate limits). Inject them.

## 4. Layering

From the bottom up. The rule `core → schema → session` (a message reaching session has passed signature, replay and
shape checks) stays as it is.

| Layer | Crates (today's names) | Changes for the stack |
|---|---|---|
| 0. Identity and wire | dsip-core, dsip-schema | Typed errors; an async `Resolver` with errors (`did:web` fetches on demand, with caching); one `Identity` / `DeviceCredentials` type that never needs the controller key on a device; the controller key behind a `Signer` trait so it can live in a vault or hardware. |
| 1. Engines (sans-I/O) | dsip-session, dsip-messaging, dsip-webrtc-binding, dsip-broadcast, dsip-recording | Typed `Emission` and `Ui` enums. Registry-governed values stay open (CLAUDE.md: no closed enums for reason tokens, `answered_by`, `progress.status`): newtypes with known constants, never a closed enum. Parameters travel on the event (`Accept { sdp, answered_by }`), not through setters. |
| 2. Endpoint core (sans-I/O) | dsip-endpoint | The one place the host glue in §2 item 1 moves to: candidate buffering, SDP offer/answer, media gating, seal fallback, recording consent, auto-answer policy, first-contact grants. The host gives it frames, time and media events, and gets back frames to send, media commands and app events. |
| 3. Runtimes | dsip-transport (tokio), a wasm host | A `Transport` trait (ws/1.0 today, others later) with a tokio-tungstenite implementation and a browser one. Reconnect and backoff, and storage traits for contacts, seen-ids and the session store. |
| 4. Features | dsip-media, discovery (dsip-dht record side, Pkarr, dsip-number), dsip-mls, dsip-events | Each behind a feature flag. Discovery as one `Discover` interface over DID document → alias → cache → hints, keeping §8.1's order inside the crate where an app cannot reorder it. |
| 5. Facades | new: `dsip-phone`, `dsip-messenger` | What most apps hold: `Phone::builder()…build()`, `phone.call(did) -> CallHandle` (await progress, answer, end; a stream of events), an `IncomingCall` to accept, screen, decline or let ring. `Messenger` for groups, direct chats, blobs and history. |
| Services | dsip-relay, dsip-mailbox, dsip-node | Each a library with a thin binary, so an operator can embed a relay, or a relay and mailbox in one process. |
| Test | new: `dsip-testkit` | Because the engines are sans-I/O, an in-memory network (endpoints, relays, mailboxes, a clock) is easy to build: deterministic multi-party tests with no sockets. siphon-rs cannot do this above the transaction layer. Plus the vector runner as a library, so a downstream implementation can run the suite. |

The browser gets the same layers 0–2 and the facades through wasm, with a typed TypeScript API generated from the
Rust types in place of today's JSON strings. Its host shrinks to a socket, a timer, IndexedDB and `RTCPeerConnection`.

## 5. What stays out

- **The spec process.** The vector generator, the Python harness, parity, fuzzing and `impl-ts` stay where they are.
  The stack is measured by them, as the PoC is.
- **Draft profiles by default.** The RTP/SRTP binding, alias transparency, device events, recording, number
  attestation and the hints profile are drafts. They are off-by-default features until each reaches 1.0.
- **Anything the PoC leaves out of scope:** gateway work past Gateway Profile 1.0, DHT authority, Sybil
  defences (CLAUDE.md).

## 6. Build order

Everything before stage 4 can happen in this workspace, where three-way parity keeps applying. Stages 1–3 make the
PoC better on their own terms: each removes duplicated glue from the reference client and the CLI.

1. **Typed core APIs.**
   - typed errors in place of `anyhow` in library crates;
   - typed `Emission`, `Ui` and `CoreEvent`;
   - parameters on events instead of setters;
   - an async resolver trait;
   - no panics on input paths.

   The vectors and parity show nothing regressed.
2. **The host glue moves into `dsip-endpoint`.** It takes console.rs's candidate, SDP, gating, seal, consent and
   policy logic; the CLI becomes a thin host. The browser moves onto it next, which gives it the seal fallback and
   recording consent it lacks today. Then the gateway.
3. **One messaging client.** A library client extracted from `dsip-msg` and the wasm `Messenger`, over storage
   traits (SQLite natively, IndexedDB in the browser). `dsip-msg` keeps the device-events gateway as its own
   module.
4. **Facades, testkit, examples.** `dsip-phone`, `dsip-messenger`, `dsip-testkit`; runnable examples (a
   20-line softphone, a chat bot, an embedded relay); a usage guide.
5. **Its own repository and release.** Move the stack crates (or the whole of `impl/`) out when core reaches 1.0,
   tag the first CalVer release, and switch the gateway to git dependencies on it. The vectors move with the spec,
   not the stack.

**When to start:** stages 1 and 2 are worth doing once the next spec version shows no core churn. The endpoint
state machine and envelope rules have not changed after v0.12. v0.13–v0.16 changed the profiles, added one core
message (`alias-monitor`, v0.14) and changed relay behaviour (§12.7, §13.3 in v0.16; Appendix A.10–A.13). Stage 4 waits for the core spec's 1.0.

## 7. Risks

- **Parity during refactors.** Stages 1–3 move code that vectors pin. Each stage lands with the full suite,
  three-way parity and the fuzz seeds green, and no vector changes, since the stack must not change behaviour.
- **API churn ahead of spec churn.** A facade designed before the spec settles gets redesigned. That is why stage 4
  waits.
- **wasm size.** dsip-wasm already carries OpenMLS. Feature flags must keep a calls-only browser build small.
- **MSRV.** dsip-mls needs Rust 1.91 for OpenMLS while the rest is 1.85; the messaging feature sets the stack's MSRV
  unless it is split out.

## 8. What a developer would write (target, not today)

```rust
let phone = dsip_phone::Phone::builder()
    .credentials(DeviceCredentials::load(&store)?)   // device key + delegation; no controller key
    .relay("wss://relay.example:8443/dsip")
    .discovery(Discovery::default())                 // DID document → alias → cache → hints (§8.1)
    .media(WebRtc::audio())
    .build().await?;

let call = phone.call("did:web:bob.example").await?;
match call.outcome().await? {
    Outcome::Answered { answered_by, .. } => { /* media is flowing */ call.hang_up().await?; }
    Outcome::Ended(reason) => println!("not reached: {reason}"),   // e.g. transport.no-response
}
```

Today the equivalent is the select loop in `console.rs`, around 500 lines.

## 9. Decisions for the owner

1. **Relationship to siphon-rs:** A (separate, same conventions; recommended), B or C ([§3](#3-relationship-to-siphon-rs)).
2. **Where it grows:** in this workspace until core 1.0 (recommended, so parity applies), or a new repository now.
3. **The first consumer**, which shapes the facades: the browser client, the gateway, siphon-ai, or a third party.
4. **The browser API:** generated TypeScript types over wasm (recommended), or keep the JSON-string boundary.
5. **Name.** The licence needs no decision: the workspace is already `MIT OR Apache-2.0`, as siphon-rs is.
