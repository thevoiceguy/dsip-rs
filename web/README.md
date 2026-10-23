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
documents of `did:web` peers are held in Settings as the CLI holds `--did-document`, and a signer whose document is not
held is fetched from where its DID says (§8.4) while its frame waits (see "Numbers and did:web").

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
**Round 2, part B — voice messages and blobs.** A voice message is recorded in the browser (`MediaRecorder`, Opus in
Ogg or WebM), sealed under a fresh single-use key (AES-256-GCM, no AAD, `nonce ‖ ciphertext ‖ tag`) and uploaded to
the identity's mailbox at `PUT {blob_endpoint}/{sha256}` with a signed `blob-put` as `Authorization: DSIP …`
(M§8.4 rules 1–2, M§5.6; the mailbox answers cross-origin requests, since the page is served by the relay). The
`audio` content carries the key, the deposit's manifest does not (rules 3–4). A receiver fetches from the sources the
pinned rule orders — its own mailbox's replicated copy first, then the origin (rule 6) — verifies size and SHA-256
before decrypting (rule 7), tries again when nothing was served yet (spec-gap 106), and plays it in the thread; a
`played` receipt goes out under the same opt-in as `read` (M§10.4, M§10.5).

**Round 2, part C — voicemail, call history, external join.** A callee leg that alerted and was not answered on this
device sends a `call-event` to the personal group, by the pinned decision: `declined` on this device's own decline,
`missed` otherwise, nothing for a leg answered elsewhere (M§13.3, spec-gap 63). Every device collapses them by
session, archives them, and interleaves them with the peer's conversation in one timeline (the pinned
`peer_timeline`). A caller whose attempt ended unanswered is offered a voicemail by the pinned M§13.2 rule: the
callee's `DSIPMailbox` entry carries `voicemail` (the client's own hint now advertises it, with `audio`), the caller
can send to them, and the outcome is one the rule lists (not the caller's own hang-up). The recording stops at the
callee's `max_duration_s` and goes out as `audio` content with `purpose: voicemail` and the invite's `session`, end
to end like any voice message (M§13.1). A device that knows of siblings and is not added within 30 s joins by
external commit every group its mailbox holds a GroupInfo for, personal group first (M§6.8; the wait is spec-gap
120); the hub and every member check that its identity already had a leaf there, and no archive key comes with it.

**Round 2, part D — hub outages, successor groups, moving mailbox.** A deposit the hub cannot take
(`mailbox.hub-unreachable`, `mailbox.quota-exceeded`, or no answer within 60 s) starts an outage, run by the pinned
outbox (M§9.4): new content queues behind the pending head, the head is re-deposited as the same bytes with the
§13.2 backoff, and an `accepted` flushes the rest. When the hub has been gone past the device's threshold (24 h by
default; `setHubTimeout` changes it), the device fetches the KeyPackages of the dead group's other identities from
their mailboxes with `successor_of` (served without a grant where the group is registered for them, spec-gap 61),
creates the successor at its own mailbox for the same conversation, and re-encrypts the pending items into it once
it holds its members. A device welcomed to a successor checks it by the pinned tracker (its creator, leaf 0, was in
the dead group, and it adds nobody new) and joins, declines, or leaves a higher one so that everyone converges on
the lowest group id (M§7.5). The thread keeps the dead group's history before the successor's, and the dead group is
no longer listed. An identity that moves to another mailbox registers every group it is in there and syncs it from
the start (spec-gap 122), which is what lets a successor's creator find it.

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
host/engine.js          the wasm Endpoint behind callbacks (send, received, emission, rejected, call, mediaRequest, resolve)
host/relay.js           the WebSocket: hello first, the relay's hello verified by the engine, reconnect
host/media.js           RTCPeerConnection per call: offers, answers, remote candidates, hold/resume (C§4)
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
                        and disclosed, three devices live, a reload, a sibling's private read applied to the conversation
test/messaging-voice.mjs    round 2B: a voice message recorded, sealed, uploaded with a signed blob-put, received through the
                        mailbox's replica, verified, decrypted and played, a played receipt, a reload, a voice reply
test/messaging-voicemail.mjs  round 2C: a missed and a declined call recorded as call events, a voicemail offered after the
                        decline and not after the caller's own hang-up, recorded, received with its session, one timeline
test/messaging-rejoin.mjs   round 2C: a new device that nobody adds joins the personal group and the conversation by external
                        commit; the peer verifies the join; messages flow; no history comes with it
test/messaging-gaps.mjs     a push lost on its way leaves a commit beyond a seq gap: held, then re-joined by external commit
                        when the gap stays open (M§6.5, M§6.8); a message from an epoch the receiver moved two past is
                        unprocessable, rolled back and acknowledged, never redelivered (spec-gaps 44, 138)
test/messaging-successor.mjs  round 2D: a conversation hubbed at a third mailbox the test starts and kills; Bob moves to
                        mailbox B; Alice's message waits out the outage, her device creates the successor and re-adds
                        Bob without a grant; Bob checks it and joins; the message arrives; the thread is kept
test/messaging-pending.mjs  a lost answer: the personal group's GroupInfo deposit is dropped; a reload, and a move to
                        mailbox B, send it again and the personal group comes up (M§9.3, spec-gap 122)
test/messaging-rebind.mjs  a device binds again while its old connection is still open (a reload, or a second
                        tab); the connection that syncs live keeps being pushed to after the old one closes (M§5.4)
test/messaging-group.mjs  group conversations (M§7.3): Alice creates a group with Bob and Carol, all write; she
                        removes Carol and adds her back into the same group (spec-gap 127); Bob leaves; every
                        roster change is rendered to every member, attributed, and survives a reload
test/messaging-hub-move.mjs  moving a live hub (M§7.4): Bob hosts Alice's conversation at his mailbox, both mailboxes
                        follow, text flows; Alice moves it back while Bob's page holds its pushes, so his message
                        meets the old hub and is re-sent to the new one; the group returns to a hub it left (spec-gap 128);
                        Alice reaches a new hub before the GroupInfo that sets it up and waits for it (spec-gap 129)
test/messaging-interop.mjs  the browser and the native client, dsip-msg, in one conversation at a mailbox the test
                        starts: the browser opens it with dsip-msg's did:web identity, which joins; text, delivered
                        receipts and a voice message each way (M§5.5, M§6.7, M§8.4, M§10.2)
test/call-recording.mjs  the call glue against the CLI: a recorded caller is answered only once accepted, or declined
                        (policy.recording-declined); a recorded callee holds our media until accepted (C§4); a
                        sealed call between browsers (§10.4)
test/call-records.mjs   call records (C§9): a record-keeper opens the conversation with each party, every call leg
                        yields a record, held until that conversation exists (spec-gaps 121, 123); a party accepts
                        the recorder before writing there (C§5)
test/presence.mjs       presence (Presence Profile draft): automatic shows the relay's claim, marked as a claim; Bob's
                        busy, away and invisible come as his device's signed records, verified and combined in Alice's
                        browser (P§3–P§5); Carol on relay B is watched at her relay, found through her hint (spec-gap 143);
                        private by default until a grant (P§6), and removing a contact revokes it at the relay (P§7)
test/presence-audiences.mjs
                        audiences and shares (P§6, P§7): Bob's family audience is a second signed record; Alice, granted
                        family, sees busy, Carol with a 30 s share and no audience sees available; the share ends her watch
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
first, Bob's delivered marks stay one per identity; a reload keeps it all and the next message decrypts.
`messaging-voice.mjs`: Alice records a voice message; it is sealed (ciphertext 28 bytes longer than the recording),
uploaded with a signed blob-put and accepted, the mailbox logs the ciphertext's hash and never sees a plaintext, the
content carries the key and duration; Bob fetches it from the source the pinned rule orders, verifies size and hash,
decrypts and plays it, his played receipt shows on Alice's message; after a reload the blob opens again and his voice
reply reaches Alice. `messaging-voicemail.mjs`: Alice calls and hangs up while it rings, Bob's device records a
missed call and Alice is offered nothing; she calls again and Bob declines, Bob's device records a declined call and
Alice is offered a voicemail up to Bob's advertised limit; it reaches Bob as audio with purpose voicemail and the
declined call's session, its blob verified; Bob's timeline reads missed call, declined call, voicemail, and a reload
keeps the call log. `messaging-rejoin.mjs`: Alice's only device goes away; a new one enrolled from her identity file
waits for a sibling, then joins her personal group and the conversation by external commit; Bob verifies the join
and sees the new device; messages flow both ways, and nothing from before the join is shown.
`messaging-gaps.mjs`: the test library's socket tap (an init script on every page: `window.__tap.hold`, `release`,
`drop`) loses one of Alice's messages on its way to Bob, whose gap timeout is set to 5 s; Alice rekeys, Bob holds the
commit beyond the gap, then re-joins by external commit and the conversation carries on without the lost message.
Then Alice's page keeps Bob's next message back while she rekeys twice: it cannot be decrypted, is committed as
handled, and after a reload it is not delivered again.
`messaging-successor.mjs`: Bob's mailbox is a third one the test starts; he opens the conversation there and the
test kills it. Bob moves to mailbox B and registers his groups. Alice's next message is refused as hub-unreachable and
kept pending; past her 12 s threshold her device fetches Bob's KeyPackages from B without a grant and creates the
successor at A; Bob checks it and joins; the pending message arrives, re-encrypted; both see one conversation whose
thread runs from the dead group into the successor; Bob's reply arrives; a reload keeps it all.
`messaging-pending.mjs`: the page drops its own group-info deposits while a flag is set, so neither Alice's nor Bob's
personal group is confirmed. Deposits awaiting an answer are saved, and every binding sends them again under fresh
envelopes (M§9.3): Alice reloads and hers comes up, once; Bob moves to mailbox B and his comes up there, still hubbed
at A. `call-records.mjs`: Kim's device is re-delegated with `dsip.record` and makes no personal group (C§5). Alice and
Bob name her as record-keeper, and she opens a conversation with Alice; Alice's client shows it as recorded by Kim and
sends no content there. Alice calls Bob, Bob answers, Alice hangs up: Alice's record goes out, Bob's is held until
Kim opens his conversation, then sent. Bob calls Alice and she declines. Kim holds four records (answered/local,
answered/remote, declined/local, declined/remote), each naming its sending device and the relay. The two sides'
evidence for a call shares the hashes of the frames the relay carried, and a reload keeps them. Alice is then asked
to accept Kim's recorder; she accepts, the acceptance goes to her personal group, her message reaches Kim's
recorder device, and after a reload the conversation stays accepted. Bob declines instead, which is leaving
(M§7.3): his device proposes the removal of his leaf, Kim's device commits it, and his device finds itself removed.
`messaging-rebind.mjs`: a second tab of the same device binds to the mailbox and syncs live, then the first tab
closes; the mailbox must keep pushing to the second (it found the mailbox handing the binding to a connection it then
never pushed to). `messaging-group.mjs`: a group of three made from "New group…"; a removal, a re-add into the same
group and a leave, each rendered to every member as a line attributed to the identity that committed it (M§7.3), every
commit checked against the roster rules before it is merged (spec-gap 126). `messaging-hub-move.mjs`: "Host here" moves
a conversation's hub to the member's own mailbox (M§7.4); every member's device tells its mailbox the new hub and
`handover_seq`, so the mailbox admits the new hub's fan-out; a device that writes before it has seen a move syncs on
`mailbox.unknown-group` and re-sends to the new hub; a group can move back to a hub it left (spec-gap 128); and a
member that reaches the new hub before the committer's GroupInfo has set it up retries the same deposit with the
§13.2 backoff until the hub hosts the group (spec-gap 129). `messaging-interop.mjs` holds the two messaging clients,
the browser's Messenger and dsip-msg, to the same wire while dsip-rs stage 3 moves both onto one library; its mailbox
admits KeyPackage fetches without a grant (M§5.7 `open`), and `test/tone.ogg` is the Ogg Opus file dsip-msg sends. CI
runs all eighteen in Firefox and Chromium.

**Call records (v0.13, Recording Profile C§9).** With a record-keeper named in Settings, the client sends a
`call-record` after every session leg. It holds the leg's frames as sent or accepted (`evidence` is the SHA-256 of
each), the invite's and the applied answer's `issued_at`, the answer's media and the relay. `ended_by` and `reason`
come from the frame that ended the leg (sent: `local`; received: `remote`). The Messenger derives `outcome` by the
pinned order, checks the record as the record-keeper will, and holds it until the record-keeper has opened the
conversation (spec-gap 123). "Make this identity a record-keeper" re-delegates the device with `dsip.record` and
starts its messaging afresh with no personal group; its Messages screen lists the records received. A conversation
recorded by another identity is labelled as recorded, naming each recorder device. Until the user accepts every
recorder present ("Accept recording"), no content and no receipt is sent there. The acceptance goes to the personal
group as a `recording-acceptance`, so the identity's other devices accept them too, and a recorder that joins later
asks again (C§5). Declining is leaving: "Leave" (also on any conversation's header) proposes the removal of every
leaf of the identity, since MLS forbids committing one's own removal, and another member's device commits it
(M§7.3, spec-gap 125). Not done: `ended_by: transport` (a relay that drops mid-call does not end the session here)
and declaring recording (the browser declares none; it renders and consents to the other side's, below).

**The call glue (dsip-rs stage 2b).** The calls run on `dsip_endpoint::calls` inside the wasm, as the CLI's do: the
page is the media host. The glue asks for an SDP offer or answer, for remote candidates to be applied, for sending to
start, hold or stop, and the page hands back the SDP and its local candidates; the glue sends those in signed `info`
once the call is ACTIVE (§12.12), starts media on the signed answer (§14.1), rings or declines by policy (one call at a
time: a second invite is declined `user.busy`), and runs recording consent (C§3–C§4): the other side's declaration is
shown on the incoming and call screens, a callee cannot answer before accepting it, a caller's media is held until it
accepts, and declining rejects the call or ends it with `policy.recording-declined` ("when the other side records a
call" in Settings: ask, accept or decline). "Seal call bodies" (Settings) seals session bodies to the callee's key
(§10.4); sealed bodies addressed to this identity or device open here, and a sealed call refused as an unknown critical
extension is placed once more in clear, as a new session (§10.4, §11.3).

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
`--did-document`. A frame from a `did:web` signer whose document is not held waits (up to 10 s) while the page fetches
the DID's `did.json` (§8.4); the document is then held for the session (§8.1), or, when the fetch fails (CORS and a
host's TLS are the host's to arrange), the frame is verified without it and refused, as before.
The number policy (the STI-CA trust list and `x5u` chains, N§3.2) is pasted the same way; without it every binding is
`untrusted-certificate`, which is shown rather than hidden. The wasm package is 5.0 MB uncompressed with the number
crate in it (stage 4); the plan's size risk is measured at each stage.
