# DSIP Client Plan — a reference client a person can use (M7)

**Status:** plan, 2026-10-09. Written after v0.11 froze at `poc-v0.11` (1,924 vectors) and v0.12 opened. Decided with
the user: build it, as a reference client, not a product.

**Spec:** none (infrastructure). The client is a host of the pure crates, like `dsip-cli` and the daemons; every
normative decision it renders is one the vectors already pin.

---

## 1. Why now, and what changed

The plan's third purpose is to demo the story, and the story has outrun the demos. Everything that exists is driven
by scripts: `dsip call` needs `--script "sleep 3; hangup"`, the browser demo is a 431-line page around the wasm
engine, and the Messaging Profile's only client is a stdin console. Nobody outside this repository has placed a
call on the DSIP network. Two things make a client the right next step:

- **The protocol surface is complete for calls.** Identity, first contact, forked ringing, media over the WebRTC
  binding, the gateway with attested PSTN callers, and number attestation are all pinned and demonstrated. Nothing a
  calling client needs is still a draft decision.
- **The bugs that remain are the concurrent ones.** The independent review of the gateway daemon (PR #129) found
  the single pending-SDP slot, the lost RTP channel, the orphaned session on a retransmitted INVITE: each appears
  only when two things happen at once. Demos are sequential by construction; people are not.

What exists to build on:

| piece | state |
|---|---|
| `dsip-wasm` | the engine, verifier, schemas and contacts compiled for the browser; 22 exported functions (`create_identity`, `hello_frame`, `relay_hello`, `verify_frame`, `local`, `inbound`, `tick`, `verification_basis`, `tel_caller_line`, `downgrade_summary`, …); a Node smoke test in CI |
| `impl/demos/browser/` | one page: an identity in `localStorage`, a relay WebSocket, audio and video calls over the browser's WebRTC, `update` to add video, a first-contact checkbox, the unknown-identity warning |
| `dsip-relay` | `ws/1.0` relay with introduction rate limits, store-and-forward with a per-recipient cap and a memory budget, a private mode (`--serve`), offline retention, and static file serving on its own TLS port (one origin, one certificate) |
| `dsip-gateway` | DSIP ↔ SIP with media both ways, PSTN caller claims, number attestation in and out |
| `dsip-node` | the hints node, packaged (static binaries, `.deb`, container) |
| WAN testbed | L1 (relay, mailbox, bootstrap), L2 (relay, mailbox, DHT), L3 (DHT), L4 (DHT, coturn TURN); no `did:web` host, no public app origin |

## 2. Goals and non-goals

**Goals.**

1. A person opens a URL, gets an identity, adds a contact, and calls them, audio or video, through the network.
2. Everything the protocol says about trust is on the screen the way the spec says: the verification basis
   (§18.1), never a badge; the first-contact state (§19.4); a PSTN caller as the gateway's claim with its STIR
   level (G§5); a caller's attested number (N§4), the number-moved warning (N§5), and the downgrade a crossing
   loses (G§7).
3. Two devices of one identity ring together and one answers (§12.7, §9.1 as the identity's devices).
4. The client is a host: the engine, verifier and schemas are `dsip-wasm`, unchanged; the client adds a UI, browser
   storage, the WebSocket and WebRTC. Where it must decide something the spec leaves open, the decision is an
   `Impl:` note and a spec-gap, as everywhere else.
5. It runs on a network an operator can stand up from this repository: a relay serving the app, TURN, hints nodes,
   optionally a `did:web` host.

**Non-goals (this round).**

- A product: no accounts, no recovery service, no push notifications, no app-store packaging. The browser must be
  open to be reachable; a PWA with wake-ups is a later step.
- Messaging. The Messaging Profile needs MLS, which `dsip-mailbox`/`dsip-msg` have in Rust and the browser does
  not. It is stage 6, after calls, and only if OpenMLS compiles to wasm at an acceptable size; it never blocks the
  calling client.
- Group calls. The Interactive Media Profile's small-group sessions are a later round; the client is one-to-one.
- Native or mobile apps. The browser is first because the engine is already there, WebRTC is native, and nothing is
  installed. A desktop shell around the same page can come later.

## 3. Architecture

```
  browser tab (one origin, served by the relay)
  ┌──────────────────────────────────────────────────────────────────────┐
  │  ui/            screens: identity, contacts, call, incoming, settings │
  │  app/           state machine of the screens; drives the engine       │
  │  host/          WebSocket (ws/1.0), WebRTC (B§), storage, clock       │
  │  dsip-wasm      engine + verifier + schemas + contacts (unchanged)    │
  └──────────────────────────────────────────────────────────────────────┘
        │ wss (envelopes)             │ WebRTC (DTLS-SRTP, ICE via STUN/TURN)
        ▼                             ▼
   dsip-relay (+ static app)     the other endpoint (browser, dsip-cli, gateway)
```

- **One engine, every platform** (plan §2): the client calls `dsip-wasm` with JSON strings and acts on its
  emissions, exactly as `dsip-cli`'s console does with `Agent`. No signaling logic lives in JavaScript. The
  `host/` layer is the browser's: `Date.now()/1000` for the clock, a `WebSocket` for the relay, `RTCPeerConnection`
  for media, `IndexedDB` for the identity and contacts.
- **The identity.** `create_identity` makes an identity key, a device key and the delegation (§7.3, §7.4). The
  identity key is the person's root; the browser holds it because there is nowhere else yet. The client exports it
  as a file the person keeps, and imports it on a second device, which then makes its own device key and a
  delegation signed by the identity key (stage 3). A `did:web` identity is the same keys with a document the person
  hosts; the client writes that document for them.
- **Contacts and first contact.** The engine's contact file (grants issued and held, §19.4) is the client's
  address book, extended with names and numbers the person types. Unknown callers are shown as the spec requires
  and are admitted, screened or declined by the person; introductions are sent and answered from the UI.
- **Media.** The WebRTC Media Binding (B§) as the demo already does it: the SDP rides in `transports[].sdp`,
  candidates in signed `info` after ACTIVE (§12.12), one answer per offer (B§6.1), `update` for escalation. ICE
  servers come from the client's settings; the default set is the operator's (see §9).
- **Rendering trust** is `dsip_core::trust` through the wasm exports (`verification_basis`, `tel_caller_line`,
  `downgrade_summary`): the same lines the `trust` vectors pin, so the client cannot invent a badge.

Where it lives: `impl/web/` (the app) replacing `impl/demos/browser/`, whose page becomes the app's first screen.
`dsip-wasm` stays where it is. The build is `wasm-pack` plus a few static files; no bundler is required to start,
and the CI job that builds `dsip-wasm` grows a headless-browser test of the app's first flow.

## 4. The flows a person sees

1. **First run.** Open the URL. The app makes an identity (`did:key`), shows its DID and a plain explanation of what
   it is, offers to name it, and offers the export of the identity key with a warning that it is the only copy.
2. **Connect.** The app binds to the relay that served it (`hello`, the relay's capabilities, the anti-splicing
   check, §13.2). The relay's DID and its limits are shown in settings, not hidden.
3. **Add a contact.** Paste a DID, or scan one. For a stranger, the app sends an introduction with a purpose and
   waits (§19.4); for someone who already granted us, it just calls. Received introductions appear as requests to
   grant or ignore; silence is a valid outcome and the UI says so.
4. **Call.** Audio or video. The screen shows the callee's basis line while ringing, the engine's state as it
   changes (inviting, proceeding, active), and the §12.9 timers as plain words ("no answer in 60 s").
5. **Receive.** The incoming screen shows the caller's basis (self-issued, domain-verified, gateway-attested with
   the STIR level, or unverified), the first-contact state (granted, introduced, unknown), any attested number and
   the N§5 warning, and offers answer, screen (§14.4) or decline. When the call came through a gateway, the
   downgrade line (G§7) is shown when it arrives.
6. **Two devices.** The same identity on a second browser: both ring, one answers, the other stops ringing without a
   missed call (§12.7). The devices are listed in settings with their delegations.
7. **A phone number.** Call `tel:+…`: the app looks the number up (N§6, the nodes and authorities in settings), and
   if nothing resolves it, goes through the operator's gateway with the number as `destination` (N§4.1). A person
   with a bound number (a binding file from their carrier, N§3) presents it on their calls.

## 5. Identity, storage and the second device

- **Keys in the browser.** The identity and device keys live in `IndexedDB`, unextractable where the WebCrypto API
  allows it (Ed25519 support varies; where it does not, the raw seed is stored and the limitation is stated). The
  export is a file with the identity seed, encrypted with a passphrase the person chooses; the device key is never
  exported, since a second device makes its own.
- **Enrolling a device** (stage 3): import the identity file on the new browser; it generates a device key and the
  identity key signs the delegation (§7.4) locally. No server is involved. A `did:web` identity also needs its
  document updated with the new device, which the app writes out for the person to publish.
- **Revocation** (§7.5): a device the person removes gets a `delegation-revocation`, published where the identity's
  revocations go (its document for `did:web`; for `did:key`, carried to the relay). The client shows what each
  method can and cannot do here rather than pretending they are equal.
- **Loss.** With the identity file, a person recovers everything but their contacts' grants, which live with the
  contacts. Without it, the identity is gone; the client says so at first run and again at every export reminder.

## 6. Trust on the screen

Every line is one the suite pins. The client never composes its own:

| what | source | pinned by |
|---|---|---|
| the basis of an identity | `verification_basis` (§18.1) | `trust/basis-*` |
| a PSTN caller through a gateway | `tel_caller_line` (G§5) | `trust/basis-tel-*`, `gateway/claims-*` |
| a caller's attested number, and a refused binding shown "(unverified)" | `check_claim` (N§4) | `tn-binding/claim-*` |
| a number that moved to another identity | `identity_change` (N§5) | `tn-binding/contact-*` |
| what a gateway crossing lost | `downgrade_summary` (G§7) | `gateway/downgrade-*` |
| the first-contact state | the engine's contacts (§19.4) | `state/first-contact-*` |

Trust tiers (§19.1) are policy: the client ships the spec's examples (a self-issued identity needs first contact; a
domain-bound one may call business endpoints; a verified number is Tier 3 by default, spec-gap 110 D) and shows
which tier applied and why. It never shows a checkmark.

## 7. Media

- The browser's `RTCPeerConnection`, as the demo does today. Opus audio; VP8 or AV1 video where the browser has
  it (§17.1 names the codec ids; the client offers what the browser can do and the engine's selection rules apply).
- ICE servers from settings. STUN alone fails behind symmetric NATs, which the WAN runs measured; the operator's
  TURN (L4's coturn today) is the fallback, and the client shows which path a call took.
- No early media, no re-negotiation beyond `update` for escalation and hold; both as the binding defines them.
- Recording (C§) is rendered when the other side declares it, and the consent flow is the console's (accept, hold
  media, decline); the client does not record in this round.

## 8. Conformance: vectors before code

The client is a host, so calls need no new vectors: the engine it embeds already passes the suite in the Node smoke
test, and the lines it renders are vector-pinned. What the client adds that could diverge is UI state: which screen
follows which emission, and what a person may press in each state. Those are stage decisions, not protocol, and are
tested by the headless-browser flow (stage 1). Where the client must decide a protocol-visible thing the spec leaves
open, it lands as a vector first:

- the identity export file (a format, its encryption, and its versioning): a `payload`-kind schema and vectors if it
  is specified at all, else an `Impl:` note and a spec-gap proposing it;
- device enrolment without a server: the delegation the new device presents is already pinned (§7.4 vectors); the
  document update for `did:web` is the existing document rules;
- the lookup order for `tel:` (nodes, authorities, then the gateway): N§6's pooling is pinned by `authority` and
  `select`; the gateway fallback is `dsip call --gateway`'s rule, written into N§4.1 already.

## 9. The network it runs on

A client needs somewhere to run. This is deployment, decided deliberately, because it is where abuse and key
management arrive:

| piece | what | where | notes |
|---|---|---|---|
| relay | `dsip-relay` serving the app's static files on its TLS port | L1, L2 | public (not `--serve`), introduction limits at their defaults, retention 24 h; a real certificate (Let's Encrypt), not the self-signed one |
| TURN | coturn with short-lived credentials | L4 | credentials minted by the relay? no: by a tiny token endpoint beside it, or static per-operator credentials to start; stated in the plan as an open point |
| hints | `dsip-node` | L1–L4 | already live; the app's lookups (`tel:`, hints) go to them |
| `did:web` | a static host for documents people choose to publish | new, or the relay's static dir under `/.well-known/` | optional; `did:key` needs none |
| gateway | `dsip-gateway` with a SIP trunk | later | needs a trunk and a number; the demo gateways stand in until then |

Abuse posture: the relay's §19.4 limits and queue caps are the first line; the app rate-limits its own
introductions; a public relay logs counts, not content. The relay cannot read calls (the envelopes are signed, the
media is end-to-end), which is the point, and the plan says so where the operator's obligations are listed.

## 10. Stages

Each stage ends in something a person can do, and lands as one PR with its demo in CI (a headless browser driving
the app against a local relay, the way the wire demos drive the CLI).

1. **Call.** `impl/web/` from the demo page: a persistent identity, a contact list, audio and video calls between
   two browsers through a relay, the basis line on both screens, export and import of the identity. Headless test:
   two pages call each other and exchange media.
2. **First contact.** Introductions sent and received, grants, the unknown-caller screen, screening (§14.4), the
   relay's rate limits surfaced as what they are. Headless test: a stranger's call is refused until introduced.
3. **Two devices.** Enrolment from the identity file, forked ringing, answered elsewhere, device list and
   revocation. Headless test: three pages, one identity on two of them.
4. **The gateway.** A PSTN caller with the STIR level and the downgrade line; `tel:` out through the operator's
   gateway with `destination`; a bound number presented and verified; the N§5 warning. Headless test: the two-gateway
   demo with a browser as Alice and another as Bob.
5. **Deployment.** The app served by L1's relay under a real certificate, TURN credentials, the hints nodes in
   settings, a runbook for an operator (`impl/web/README.md`), and the WAN run record extended with a browser call
   across NATs. The first stage anyone outside the repository can use.
6. **Messaging** (conditional). OpenMLS to wasm; the Messaging Profile's client rules are pinned (`messaging/`
   client traces) and the mailbox exists; the question is size and the key-package lifecycle in a browser. Decided
   after stage 5, not before.

## 11. Risks

| risk | consequence | mitigation |
|---|---|---|
| identity keys in a browser | loss or theft of a person's root key | export with a passphrase at first run; unextractable keys where WebCrypto allows; a `did:web` identity can rotate (§7.5) |
| a public relay invites abuse | spam introductions, queue floods | the §19.4 limits exist and are tested; private mode is one flag; start with a relay that serves listed identities and open it when the limits have been watched |
| symmetric NATs | calls that connect in the lab fail in the field | TURN from stage 1 settings; the WAN run measures STUN-only honestly |
| browser WebRTC differences | a flow that works in one browser fails in another | the binding is pinned; test the headless flow in two engines in CI; keep the SDP the engine's, not the browser's defaults |
| wasm size and load time | a slow first open | the engine is small today; measure at each stage; no framework |
| UI logic drifting from the engine | screens that lie about state | screens render engine state only; every state the UI shows comes from `session` |
| scope creep into a product | the PoC loses its shape | §2's non-goals are the line; anything past them is a new plan |

## 12. Spec gaps expected

- **Identity export and enrolment** (§7.3–§7.4): the spec says what a delegation is, not how a person moves an
  identity between devices without a server. Propose a format, or state that it is deployment.
- **TURN credentials** (B§, §13.2 capabilities): whether a relay may advertise ICE servers in its `hello`
  capabilities, and how short-lived TURN credentials reach a client. Today they are configuration.
- **Reachability of a browser** (§9, §13.3): a closed tab is an offline device; store-and-forward holds an invite for
  the relay's retention, and the invite's own `expires_at` bounds pre-alerting delivery. Whether a client should
  publish a hint that says "browser, best effort" is open.
- **Revocation for `did:key`** (§7.5): where a `did:key` identity's device revocations live when it has no document.
  The relay carries them today; the spec should say whether that is enough.
