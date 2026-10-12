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

**Stage 4:** the gateway. A PSTN caller arrives as the gateway's `tel` claim and the incoming screen shows the caller
line and the basis with the STIR level (G§5); what a crossing lost arrives as `gateway.downgraded` and is shown (G§7).
"Call number" looks a `tel:` up on the number nodes in Settings (N§6, each binding verified against its own DID's
document held here, the newest winning, N§7) and dials a number nothing resolves through the gateway in Settings as the
invite's `destination` (N§4.1). A binding from the person's carrier (Settings, N§3) is presented on every call as a
`tel` claim; a callee checks it against the caller's document (N§4, `check_claim`) and shows the attested number, or
the number "(unverified)" with the refusal; a number that a stored contact lists but that now belongs to another
identity is said out loud (N§5, `identity_change`). A bound number needs a `did:web` identity whose document lists it
(N§3.3): Settings rehomes the identity to a `did:web` name (the same keys, §7.2) and gives the document to host. DID
documents of `did:web` peers are held in Settings as the CLI holds `--did-document`; the browser does not fetch them.

**Stage 5:** deployment. The relay serves the client under a real certificate (`--cert`/`--key`, Let's Encrypt on
the WAN testbed) and, beside it, what a deployed client needs from its origin and nothing in the protocol carries
(spec-gap 114): the operator's defaults as `config.json` (`--client-config`: nodes, gateway, policy, ICE), short-lived
TURN credentials minted at `/turn` from the secret coturn holds (`--turn-uri`, `--turn-secret-file`; TURN REST API
credentials, fetched again at half-life), and the co-located `dsip-node` proxied at `/dsip/v1/` (`--node-proxy`), so a
page served over `https` reaches a node that speaks plain HTTP on the loopback. Settings → Network shows what is in
effect and where each value came from; `none` overrides an operator default. The client publishes its reachability
on the nodes (a signed, expiring hint naming its relay, DHT Hints Profile §10, re-signed at ⅔ of its life and on every
bind) and looks a callee up before the invite (§8.1): the frames the nodes return go through the same §8.3 selection a
node applies (`hint_select`, the DHT crate's `record` module compiled to wasm), and a callee whose hint names another
relay is called through that relay on a connection opened for the call, labelled hint-sourced on the call screen. The
media path in use (candidate types, TURN or direct) is shown once connected. Runbook below; the WAN record in
`impl/docs/dht-findings.md` ("The browser client on the WAN").

**Stage 6:** messaging. The Messaging Profile's device side runs in the browser: `dsip-wasm::messaging` is OpenMLS
(on its rust-crypto provider, `js` for the browser's randomness) and the profile's vector-pinned client rules behind a
`Messenger` driven like the §12 engine — frames in, frames and events out — and the Messages screen renders what it
returns. Its MLS state (OpenMLS's memory storage) and its delivery state (the ack cursor and seq positions, the
outbox, the thread) are one record the host saves after every step and restores on load (spec-gap 44): a reload
keeps the groups, the KeyPackages' private halves and the history. The identity's mailbox comes from Settings → Network
or the operator's `config.json` (`mailbox: {uri, did}`); the device binds there with the same `hello` (the mailbox's
is verified under the DID the entry names, M§4.2), the mailbox enrols the identity on its first owner operation
(`dsip-mailbox --serve-any`, spec-gap 115), fresh KeyPackages go up on every bind (M§5.5), the personal group is
created with its first archive key (M§7.1, M§12.1), and the hint the client publishes names the mailbox beside the
relay (a `DSIPMailbox` endpoint, M§4.2). "Message" on a contact finds their mailbox (their document, else their hint:
hint-sourced, said so), fetches a KeyPackage there presenting the grant they issued (M§5.5, M§14.2: the Grant button
now issues `dsip.message` beside `dsip.invite`), creates the group at our mailbox and adds them once the hub holds it
(M§7.2, M§6.5: committed on `accepted`, discarded and re-proposed after a conflict). The welcome reaches them
through hub fan-out to a mailbox the hub resolves the same way (spec-gap 116); text is an MLS application message
(M§8.1), delivered receipts are decided per sync batch (M§10.2) and shown on our own messages.

**Round 2, part A — history, a second device, read watermarks.** Every content item a device shows from MLS, its own
included, and every receipt that changes rendering is archived: an archive record sealed under the identity's current
archive key (AES-256-GCM, AAD the group id and seq) and deposited to the mailbox as `class: archive` (M§12.2). A
browser enrolled from the identity file does not create a personal group of its own (M§7.1): it uploads KeyPackages
and waits; the device that holds the Devices list adds it, personal group first, then every conversation (the "Add
device" form or any bind runs the reconciliation), and re-sends every live archive key after the personal-group add
(M§12.3, M§6.7). The new device opens the archive records its mailbox holds as history, keeping sealed any whose key
has not arrived yet (M§12.3 step 5), restores them into its receipt state without sending anything (spec-gap 64),
and takes part live: a sibling's message is the identity's own on every device. Read watermarks follow M§10.3: the
thread on screen reports its last content read, at most one watermark per 5 s; with "disclose read receipts" off
(the default, M§10.5) it goes to the personal group, where siblings pick it up and a device added later finds it in
the archive (spec-gap 68); on, it goes to the conversation and the other side's thread shows how far you read.
Still with the Rust console only: joining by external commit when no sibling is available (M§6.8), voice and blobs,
successor groups.

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
be reachable by both ends. Hosting is the runbook below.

## Runbook: hosting it (stage 5)

What the WAN testbed runs (`impl/tools/wan/README.md`), as an operator would set it up. Everything below is
`impl/tools/wan/node-setup.sh` with its stage 5 variables; the units it writes are the reference.

1. **A name and a certificate.** The relay's `wss://` and the page share one origin, so one certificate covers both
   (§13.2: validated against the advertised hostname). Any name that resolves to the host works; a Linode's reverse
   DNS name (`<ip-dashed>.ip.linodeusercontent.com`) is on the public suffix list, so Let's Encrypt issues for it
   without a domain of your own:
   ```bash
   apt install certbot
   certbot certonly --standalone -d <name>          # port 80 open for the HTTP-01 challenge; nothing listens between renewals
   ```
   `node-setup.sh` installs a deploy hook that restarts the relay when the certificate renews.
2. **TURN.** A call across two NATs needs it (`impl/docs/dht-findings.md`, Run 3: symmetric NAT fails without). coturn
   with `use-auth-secret` and a `static-auth-secret` (`ROLE=turn`, the secret in `/var/lib/dsip/turn.secret`; the relay
   ports 49160–49200/udp open). Copy the secret file to every relay host: the relay mints credentials from it, valid
   `--turn-ttl` seconds, for whoever loads the page. coturn allows one credential mechanism at a time, so the CLI
   mints its own with `dsipctl turn-cred`.
3. **The client and the relay.** Build the wasm (`web/build.sh`) and copy `index.html`, `style.css`, `app.js`,
   `host/` and `pkg/` to the host (5.0 MB, 1 MB compressed). Write the operator's defaults, served as `config.json`:
   ```json
   {"nodes": ["https://<this relay>:8443", "https://<another relay>:8443"], "publish_hint": true}
   ```
   (`gateway`, `tn_policy`, `ice` and `relay` are the other keys; a person's own Settings override every one.) Then:
   ```bash
   ROLE=relay PREBUILT=<dir with the binaries> RELAY_HOST=<name> \
     RELAY_CERT=/etc/letsencrypt/live/<name>/fullchain.pem RELAY_KEY=/etc/letsencrypt/live/<name>/privkey.pem \
     RELAY_WWW=/var/lib/dsip/www TURN_URI=turn:<turn host>:3478 ./node-setup.sh
   ```
   which runs `dsip-relay --cert --key --www --client-config /var/lib/dsip/client.json --turn-uri --turn-secret-file
   --node-proxy 127.0.0.1:8090`. The relay is open (§13.6) with the §19.4 introduction limits at their defaults and
   24 h retention; `--serve` makes it private.
4. **A hints node** beside it (`dsip-node`, its own README): the relay forwards `/dsip/v1/*` to it, so the page's
   lookups and publishes stay on the page's origin. Nodes find each other over the overlay; a client needs only one or
   two in `config.json`. They are a hints tier: a client verifies every record it gets back, and nothing a node says is
   authority (§8.1).
5. **Check it:**
   ```bash
   curl https://<name>:8443/config.json      # the defaults
   curl https://<name>:8443/turn             # {"iceServers":[{"urls":[…],"username":"<expiry>:dsip","credential":"…"}],"ttl":3600}
   curl https://<name>:8443/dsip/v1/node     # the node through the relay
   ```
   then open the page in two browsers on two networks: each publishes its hint on bind (the log says where and whether
   the node accepted it), and a call to the other's DID says on the call screen which relay it went through and, once
   connected, which media path (host, srflx or relay candidates) carries it.

What the operator can and cannot see: the relay routes signed envelopes it cannot alter and media it never carries;
it sees who talks to whom and when, as any relay does (§20). The node sees who publishes a hint and who looks one up.
TURN sees the media's endpoints, not its content (DTLS-SRTP). A public relay logs counts, not content.

6. **A mailbox for messaging (stage 6).** `ROLE=…,mailbox MAILBOX_SERVE_ANY=<n>` with the same `RELAY_CERT`/`RELAY_KEY`:
   the mailbox serves under the relay's certificate on port 9443, enrols up to `n` identities that bind to it
   (spec-gap 115), and reaches a member on another operator through the hint on the co-located node (`--hints-node`).
   Put it in the client's defaults: `"mailbox": {"uri": "wss://<name>:9443/dsip", "did": "<$STATE/mailbox/service.did>"}`
   in `/var/lib/dsip/client.json`, and restart the relay. A person on another origin sets the mailbox by hand under
   Settings → Network. The hub a conversation uses is the creator's mailbox; the other side's mailbox sees group ids,
   sizes and timing, never content (M§15.1).

## Layout

```
index.html, style.css   the screens: welcome, contacts, call, incoming, settings, log
app.js                  the screens' logic and the one current call; drives the host layer
host/engine.js          the wasm Endpoint behind callbacks (send, received, emission, rejected)
host/relay.js           the WebSocket: hello first, the relay's hello verified by the engine, reconnect
host/media.js           RTCPeerConnection per call; candidate buffering (§12.12: info is ACTIVE-only)
host/store.js           IndexedDB (localStorage fallback) for identity, contacts, engine state, settings
host/identity-file.js   the identity export: PBKDF2 + AES-GCM under a passphrase, version 1
../crates/dsip-wasm/src/messaging.rs   the messaging device (stage 6): OpenMLS + the profile's client rules, driven by app.js
test/engine.mjs         Node: two wasm endpoints run a call + first contact in memory (no browser)
test/lib.mjs            Playwright helpers: launch with fake media, a person (fresh context = fresh identity), waits
test/call.mjs           stage 1: two headless browsers call each other through a local relay (audio, video), export/import
test/first-contact.mjs  stage 2: refusal until introduced, requests, grants, screening + escalation, contact link, ignore
test/devices.mjs        stage 3: one identity on two browsers (enrolled from the file), forked ringing, answered elsewhere, revocation
test/gateway.mjs        stage 4: the two-gateway demo with browsers: attested crossing, downgrade, no route, N§4 claim, N§5 warning
test/deploy.mjs         stage 5: config.json in effect, minted TURN credentials verified, hints published and looked up, a
                        call through the relay the callee's hint names (both ways), none without a hint, a reload
test/messaging.mjs      stage 6: two browsers on two operators enrol at two mailboxes, personal groups, hints naming the
                        mailboxes, a conversation from a KeyPackage fetched at the peer's mailbox with the grant, the welcome
                        federated through the hint, text both ways, delivered receipts, a reload keeping MLS state and history
test/messaging-devices.mjs  round 2A: archive records, a second browser of the same identity added by the first (personal group,
                        conversation, archive keys re-sent) reading the history both sides in seq order, read watermarks private
                        and disclosed, three devices live, a reload
test/run.sh             makes the gateway fixture, starts two mailboxes (A is relay A's operator default), relay A (serving the
                        client, with config.json, /turn and the node proxied) on 127.0.0.1:8443, relay B on 8444, a dsip-node
                        and two gateways, and runs the Playwright tests in the browser(s) named
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
only the remaining device. `gateway.mjs` (the two-gateway demo's fixture, made by `run.sh`: did:web identities the
browsers enrol as devices of, the test number authority, a dsip-node holding Bob's binding, two gateways over a SIP
trunk): Alice's binding verifies in her Settings, her call to Bob's number crosses gateway A attested (A, under its
delegate certificate) and gateway B (PASSporT verified, routed by Bob's published binding), Bob sees the PSTN caller
with the verified attestation and audio crosses both gateways both ways; Mallory, without a binding, crosses
downgraded and Bob sees no attestation; a number nobody published is refused `identity.unknown`; on a direct call Bob
sees Alice's own number attested (N§4) and her basis unchanged; Carol presents Carrier B's binding of the same number
and Bob, who stored Alice with it, is warned (N§5); a did:web name whose document nobody serves cannot bind.
`deploy.mjs`: the operator's `config.json` is in effect and Settings says so, `/turn` mints credentials that verify
under the secret and the client uses them, Bob on relay B publishes a hint the node holds, Alice's lookup verifies it
and her call goes through relay B on a connection for the call (both ACTIVE, media both ways, the media path
reported, the connection closed after), Bob calls her back through relay A the same way, a DID with no hint is called
through our own relay, and a reload keeps Bob's relay and re-publishes his hint. `messaging.mjs`: Alice binds to the
operator's mailbox, is enrolled, creates her personal group and uploads KeyPackages, and her hint names the mailbox;
first contact over the relay; Bob moves to relay B and mailbox B (enrolled there, his hint follows); Alice's
"Message" finds Bob's mailbox through his hint, fetches his KeyPackage there with his grant, creates the conversation
at her mailbox and commits the add on the hub's accepted; Bob joins from the welcome his mailbox received (the hub
found it through his hint); text both ways, the hub's accepted back through Bob's mailbox's forwarding, a delivered
receipt shown on Alice's message, each message once with its hub seq; Bob reloads and the thread, the MLS state and
the delivery state survive, a message after the reload decrypts, nothing is shown twice. `messaging-devices.mjs`: Alice
and Bob exchange four messages and both archive them; Bob's read position goes to his personal group only and Alice
sees no mark, Alice opts in and Bob sees how far she read; Alice's second browser, enrolled from her file, is added
by the first to the personal group and the conversation with the archive keys re-sent, shows the five earlier
messages from archive with both sides and the right seqs and the identity's read position, sends nothing for them;
Bob's next message reaches both of her devices, the second device's reply reaches Bob and shows as her own on the
first, Bob's delivered marks stay one per identity; a reload keeps it all and the next message decrypts. CI runs all
seven in Firefox and Chromium.

## Identity

The identity key is made in the browser at first run and lives in its storage. Export (Settings) writes an
`.dsip-identity` file: JSON with the identity seed encrypted under a passphrase (PBKDF2-SHA-256, 600,000
iterations, AES-256-GCM), with the exporter's device list and the revocations it issued. Importing it on another
browser enrols that browser as a device of the identity: a device key of its own, delegated by the identity key
locally (§7.4). Importing it on the same browser replaces its device key the same way. Without the file, a lost
browser profile is a lost identity; the client says so at first run. A lost device is revoked from another one
(Settings): the revocation reaches the relay, not the world, which is what a `did:key` identity can do.

## Numbers and did:web

A `did:key` identity cannot present a bound number: the binding's DID must list the number in its document
(N§3.3), and `did:key` has none. Settings rehomes the identity to a `did:web` name: the same identity key, the
device delegation re-signed under `<did>#key-1`, and a `did.json` to host at the DID's URL (with `alsoKnownAs` for the
bound number). Until it is served there, a verifier that does not hold the document refuses the identity, and the
client says so. Documents of `did:web` peers (a gateway, a contact) are held in Settings, as the CLI holds
`--did-document`: the browser does not fetch `did.json` files (CORS and a host's TLS are the host's to arrange).
The number policy (the STI-CA trust list and `x5u` chains, N§3.2) is pasted the same way; without it every binding is
`untrusted-certificate`, which is shown rather than hidden. The wasm package is 5.0 MB uncompressed with the number
crate in it (stage 4); the plan's size risk is measured at each stage.
