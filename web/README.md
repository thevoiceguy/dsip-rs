# DSIP reference client (browser)

A client a person can use on the DSIP network, and a host of the pure crates: the verifier, the §12 engine, the
payload builder and the first-contact state are `dsip-wasm`, unchanged. This directory adds the screens, browser
storage, the relay WebSocket and WebRTC. No signaling decision is made in JavaScript: a screen changes only when the
engine emits, and every trust line on screen comes from the vector-pinned renderers (`verification_basis`,
`tel_caller_line`, `downgrade_summary`). Plan: `impl/docs/dsip-client-plan.md`.

**Stage 1:** a persistent identity, a contact list, audio and video calls between two browsers through a relay,
the verification basis on both screens, export and import of the identity. Nothing is hosted: the deliverable is the
local setup.

**Stage 2:** first contact (§19.4). With "require first contact" on, a stranger's call is refused without ringing and
the caller is told to introduce themselves; introductions carry a purpose and land under Requests (never a ring, with
the introducer's basis), where they are granted or ignored; a contact's row shows the grant state; a contact link
(Settings) carries a single-use token that grants the introduction at once; screening (§14.4) answers without sending
anything and can be escalated to a real answer; the relay's introduction rate limit is shown as what it is.

**Stage 3:** two devices. Importing the identity file on another browser enrols it: a fresh device key is made there
and the identity key signs its delegation (§7.4), with no server involved; the file carries the exporter's device list.
A call to the identity forks to every bound device (§12.7): the first answer wins and the other legs end as answered
elsewhere, never a missed call (§12.11). Settings lists the devices this browser knows (a `did:key` identity has no
document and no registry of devices: one enrolled elsewhere is added by its DID) and revokes one: a
`delegation-revocation` signed by the identity key (§7.4) goes to the relay, which ends that device's binding and
refuses its next hello (spec-gap 113 for the carriage), and this engine holds it too. What a `did:key` identity
cannot do, publish the revocation where every verifier finds it, is said on the screen rather than hidden.

## Run it locally

```bash
# once: the wasm32 target comes from impl/rust-toolchain.toml; wasm-pack from `cargo install wasm-pack`
web/build.sh                 # wasm-pack → web/pkg
demos/browser-demo.sh        # the relay serves the client: https://127.0.0.1:8443/
```

Open the URL twice with different `?as=` names (`?as=alice`, `?as=bob`) to be two people on one machine, or from
two machines on a LAN with `LISTEN=0.0.0.0:8443`. Accept the self-signed certificate once; it covers the page and
the `wss://` signaling. The browser needs a secure context (`https://` or `localhost`) for the camera, microphone
and WebCrypto, and refuses wasm from `file://`.

The app is static files: any origin can serve it, and Settings → Network points it at any relay. Only the relay must
be reachable by both ends. Hosting (a public relay with a real certificate, TURN, a `did:web` host) is stage 5.

## Layout

```
index.html, style.css   the screens: welcome, contacts, call, incoming, settings, log
app.js                  the screens' logic and the one current call; drives the host layer
host/engine.js          the wasm Endpoint behind callbacks (send, received, emission, rejected)
host/relay.js           the WebSocket: hello first, the relay's hello verified by the engine, reconnect
host/media.js           RTCPeerConnection per call; candidate buffering (§12.12: info is ACTIVE-only)
host/store.js           IndexedDB (localStorage fallback) for identity, contacts, engine state, settings
host/identity-file.js   the identity export: PBKDF2 + AES-GCM under a passphrase, version 1
test/engine.mjs         Node: two wasm endpoints run a call + first contact in memory (no browser)
test/lib.mjs            Playwright helpers: launch with fake media, a person (fresh context = fresh identity), waits
test/call.mjs           stage 1: two headless browsers call each other through a local relay (audio, video), export/import
test/first-contact.mjs  stage 2: refusal until introduced, requests, grants, screening + escalation, contact link, ignore
test/devices.mjs        stage 3: one identity on two browsers (enrolled from the file), forked ringing, answered elsewhere, revocation
test/run.sh             starts a relay on 127.0.0.1:8443 and runs the Playwright tests in the browser(s) named
```

## Tests

```bash
node web/test/engine.mjs                 # the engine in Node
(cd web && npm ci && npx playwright install firefox)   # once; `--with-deps` on a bare CI host
web/test/run.sh firefox                  # or chromium, or all; starts a relay on 127.0.0.1:8443
```

The headless tests drive the DOM like a person. `call.mjs`: two identities are made, one adds the other as a contact
and calls, the incoming screen shows the caller's basis and that the identity is unknown, the call is answered, both
sides are ACTIVE on one session and receive RTP, no frame is refused by the relay, hangup ends both, a second call is
declined, a video call carries video both ways, the identity is exported and imported into a third browser, and a
reload keeps identity and contacts. `first-contact.mjs`: a stranger's call is refused until introduced, the request
shows the purpose and basis, a grant lets the call ring, screening then escalation, a contact link grants at once, an
ignored introduction is reported, and a request survives a reload. `devices.mjs`: a second browser enrols from the
identity file as a new device of the same identity, a call rings both devices and whichever answers wins while the
other ends without a missed call (both ways round), the first device adds the second by DID and revokes it, the
revoked device is dropped by the relay and refused at its next hello (after a reload too), and the next call rings
only the remaining device. CI runs all three in Firefox and Chromium.

## Identity

The identity key is made in the browser at first run and lives in its storage. Export (Settings) writes an
`.dsip-identity` file: JSON with the identity seed encrypted under a passphrase (PBKDF2-SHA-256, 600,000
iterations, AES-256-GCM), with the exporter's device list and the revocations it issued. Importing it on another
browser enrols that browser as a device of the identity: a device key of its own, delegated by the identity key
locally (§7.4). Importing it on the same browser replaces its device key the same way. Without the file, a lost
browser profile is a lost identity; the client says so at first run. A lost device is revoked from another one
(Settings): the revocation reaches the relay, not the world, which is what a `did:key` identity can do.
