# Building on dsip-rs — a usage guide

This is a guide for application developers. It covers placing and answering calls, sending messages, running a
relay or a mailbox inside your own process, and testing all of it without sockets. dsip-rs is the set of `dsip-*`
crates in this workspace. It implements DSIP Core 1.0 (`v1.0/`) and its profiles. The design behind it, and what
is still to come, are in [`dsip-stack-design.md`](dsip-stack-design.md).

Every example named here is built in CI, by `cargo clippy --all-targets`. The chat bot also runs end to end in CI
(`demos/echo-bot-demo.sh`).

## 1. Which crate to use

Most applications need only a facade, plus a service crate if they run their own infrastructure.

| You want to… | Use | Start from |
|---|---|---|
| place and answer calls, with or without native audio | `dsip-phone` | `examples/softphone.rs` |
| send and receive messages: direct chats, groups, blobs, receipts | `dsip-messenger` | `examples/echo_bot.rs` |
| run a relay in your process | `dsip-relay` (`RelayServer`) | `examples/embedded_relay.rs` |
| run a mailbox in your process | `dsip-mailbox` (`MailboxServer`) | `tests/in_process.rs` |
| test several parties in one process, with no ports | `dsip-testkit` | `tests/network.rs`, `dsip-phone/tests/phone.rs` |
| build a browser client | `dsip-wasm`, with its generated TypeScript types | `impl/web/` |
| drive the protocol yourself | `dsip-transport` (`Agent`), `dsip-endpoint` (`Core`) | `dsip-cli`'s console |

The layers underneath have the same split as the spec:
- `dsip-core` and `dsip-schema` check envelopes: signature, replay and shape.
- `dsip-session` holds the call state machine.
- `dsip-endpoint` is the sans-I/O endpoint, with grants, SDP and the answer policy.
- `dsip-transport` is the tokio runtime: the `wss` binding (§13.2), reconnects and the `Agent`.
- `dsip-media` carries native audio and video.
- `dsip-messaging`, `dsip-mls` and `dsip-messaging-device` are the Messaging Profile engine.

A message reaching session code has already passed signature, replay and shape checks. No facade reorders that.

The MSRV is Rust 1.85, except for the messaging crates. Those need 1.91, which is OpenMLS's floor.

## 2. Identities

A DSIP identity is a DID with a controller key. Each device has its own key and a delegation signed by the
controller (§7.3–§7.4). `dsip-transport::identity::Identity` is a directory that holds all three.

```sh
dsip identity init --dir alice --name Alice                                  # did:key: nothing to host
dsip identity init --dir bob --name Bob --did-web did:web:bob.example        # writes did.json to serve
dsip identity init --dir bob-laptop --controller-from bob                    # a second device of Bob
```

In code, `Identity::load(dir)` reads one, and `Identity::init(dir, name, None, None)` makes one.

Which kind of DID you need:
- **Calls** need only the DID. A `did:key` resolves from itself.
- **Messaging** needs a `did:web` (or any DID with a document): the document names the identity's mailbox
  (M§4.2), and the key that sealed introductions are encrypted to (M§6.9). `dsip_messenger::did_document`
  builds that document.

## 3. Calls: `dsip-phone`

```rust
use dsip_phone::{AnswerPolicy, Identity, Media, Outcome, Phone};

let phone = Phone::builder()
    .identity(Identity::load("alice".as_ref())?)
    .relay("wss://relay.example:8443/dsip")
    .tls(dsip_transport::tls::client_config(Some("ca.pem".as_ref()))?.unwrap()) // only for a private CA
    .answer(AnswerPolicy::Ring)
    .build()
    .await?;

let mut call = phone.call("did:web:bob.example").await?;
match call.outcome().await {
    Outcome::Answered { answered_by } => { /* media flows */ call.hang_up(); }
    Outcome::Ended { reason } => println!("not reached: {reason}"),
}
```

`build()` binds the phone to its relay. It also starts one task that owns the protocol agent and the media leg of
every call. Reconnects with backoff (§13.2) happen inside the phone.

### `Call`

- **`state()`** returns the call's current `CallState`: Calling, Ringing, `Answered { answered_by }` or
  `Ended { reason }`. **`changed().await`** waits for the next change.
- **`outcome().await`** resolves once the call is answered or ends. **`ended().await`** resolves with the end
  reason.
- **`hang_up()`** does what the state calls for (§12.11): a cancel before the answer, a decline while ringing, a
  bye after.
- **`command(CallCommand)`** sends any other command: renegotiation, DTMF and the rest.
- **`error()`** returns the last `error` the peer or relay sent about this call. An `error` changes no call state
  (§12.7 rule 6), so a call to an identity that isn't bound still ends by T-Establish. `error()` tells you why,
  for example `transport.unknown-recipient`.

### Incoming calls

**`phone.incoming().await`** yields an `IncomingCall`. Its `from` (the verified caller) and `display_name` (a claim,
§18.2) say who is calling. Then do one of these:
- `.accept()` answers;
- `.screen()` answers as `answered_by: screening` (§14.4);
- `.decline()` refuses;
- dropping it lets the call ring.

The answer policy decides what happens without you: `Ring` waits for you, `Accept` and `Screen` answer at once,
`Decline` refuses, and `Silent` lets the leg expire.

### Media

`Media::Native(MediaConfig)` runs the call's audio through `dsip-media`, and media starts on the signed answer.
The `source` field sets what is sent:
- `Source::None` sends nothing (the default);
- `Source::Tone { hz }` sends a test tone;
- `Source::File(path)` sends a file;
- `Source::Feed(Feed)` sends the media your application pushes into it.

`record` saves what is received.
**`call.media_received()`** reports whether anything has arrived.

Without the `media` feature (it is on by default), a phone does signalling only. That suits a gateway or a bot.

### Other builder options

- `.dialer(...)` replaces the `wss` connection. The testkit uses it (§7).
- `.recording(...)` sets the recording policy (Recording Profile, C§).
- `.configure(|cfg| ...)` exposes the underlying `AgentConfig`.

## 4. Messaging: `dsip-messenger`

The Messaging Profile engine (`Engine`, the `Messenger` of `dsip-messaging-device`) decides everything a device
does: MLS groups, hubs, receipts, history, first contact. `dsip_messenger::Messenger<S>` does what a native
application does around the engine:
- holds the `wss` connection to the device's mailbox, and reconnects it (§13.2);
- runs requests that wait for their answers;
- fetches KeyPackages from other identities' mailboxes;
- fetches, verifies and retries blobs (spec-gap 106);
- creates successor groups when a hub is gone (M§7.5, M§9.4);
- writes the state after every step.

### Setting up

1. Serve your identity's DID document: `dsip_messenger::did_document(identity, controller, mailbox_did, mailbox_uri)`.
2. Open the engine from the identity:

```rust
let id = Identity::load(dir)?;
let resolver_files = vec!["docs/bot.json".into(), "docs/alice.json".into()];
let mailbox = dsip_messenger::mailbox_of(&id.meta.identity, &dsip_messenger::resolver(&resolver_files))?; // M§4.2
let identity = dsip_messenger::engine_identity(&id.meta.identity, &id.device, &id.controller, &id.delegation, "Bot");
let engine = Engine::open(&identity, &mailbox.0, &mailbox.1, store, &saved_state, now)?;
let cfg = Config { identity: id.meta.identity.clone(), device: id.device.clone(), delegation: id.delegation.clone(),
                   mailbox, resolver_files, ca: None, media_dir: "media".into(), host_key: "my-app".into() };
let mut mx = Messenger::new(engine, cfg, vec![])?;
```

The store is any `dsip_messaging_device::Store`:
- `MemoryStore` keeps nothing between runs.
- `dsip_mls::sqlite::SqliteProvider` (feature `sqlite`) persists the MLS state and the engine's state in one file.
  Writes within an item are atomic (spec-gap 44).

On restart, pass what the store holds under `messenger` as `saved_state`. dsip-msg shows how.

### The `Host` trait

Your application implements `Host<S>`. Every `Output` reaches `output(&mut self, engine, out)` in order, as it
happens, with the engine to read from. The outputs are:
- `Event(Event::Ui(...))`: a message, a join, a roster change, a receipt, a call event;
- `Connected` and `Disconnected`;
- blob progress;
- successor events.

`saved()` returns what you want stored beside the engine's state. `frame_in` and `frame_done` bracket each frame,
which is useful for logging.

### The loop

Shape it like `echo_bot.rs`:

```rust
mx.connect(&mut host).await?;
mx.send_frame(&mut host, &mx.engine_mut().key_packages_frame(4, now)?).await?; // others can add this device (M§5.5)
mx.sync(&mut host, true).await?;                                               // catch up, then live delivery (M§5.4)
let mut clock = tokio::time::interval(Duration::from_secs(1));
loop {
    tokio::select! {
        Some(frame) = mx.recv() => mx.received(&mut host, frame).await,   // pending while offline
        _ = clock.tick() => { mx.tick(&mut host).await; mx.check_reconnect(&mut host).await?; }
    }
    // act with mx.engine_mut() (send, create, grant, …) and send what it returns with mx.send_frame(s)
    mx.settle(&mut host).await;
}
```

Actions go through the engine. Each returns the frames to send:
- `engine_mut().send(group, &content, now)` sends content;
- `grant(did, ...)` lets someone write to you first (M§14);
- `create_direct` and `create_group` start conversations;
- receipts, history and devices have their own calls.

The `Messenger` sends those frames with `send_frame` and handles the answers. After anything that starts deposits,
call `settle`.

### First contact

Before someone you have never talked to can create a conversation with you, they need your grant. In
`echo_bot.rs`, the bot prints `GRANT <grant>` for each DID it is given, and `demos/echo-bot-demo.sh` hands that
grant to dsip-msg, which runs `create direct <bot> <grant file>`. In a real application the grant reaches the
other person out of band, or as a sealed introduction (M§6.9).

### dsip-msg

`crates/dsip-mailbox/src/bin/dsip-msg.rs` is a complete host. It is a console client with every command, an SQLite
store, and a `Console` that implements `Host`. Read it for anything this guide leaves out.

## 5. Running a relay

```rust
let relay = RelayServer::new(KeyPair::generate(), StaticResolver::default(), RelayConfig::default());
relay.spawn_clock();                                   // timers: invite expiry, presence, rate limits
relay.serve_tls(listener, dsip_transport::tls::acceptor(&cert, &key)?, Arc::new(www::Routes::default())).await?;
```

- `RelayConfig` holds what the `dsip-relay` binary's flags set: introduction limits, presence, queue budgets, which identities it serves and offline retention.
- `relay.accept(stream, peer)` serves one connection over any byte stream, so a relay and its devices can share a
  process.
- `spawn_status(addr)` adds the status port that `dsipctl relay-status` reads.

The relay is the binary in a library. What the binary runs in production, the library runs the same way.

## 6. Running a mailbox

```rust
let mut cfg = MailboxConfig::new(state_dir, "https://mailbox.example/blobs".into());
cfg.owners = vec!["did:web:alice.example".into()];     // or cfg.serve_any = Some(n), as an operator
let mailbox = MailboxServer::open(cfg)?;               // loads saved state
mailbox.spawn_tasks();                                 // fan-out retries, idle release, blob replication
mailbox.serve_tls(listener, acceptor).await?;
```

`MailboxServer::accept(stream)` serves one WebSocket or blob request over any stream. Its DID (`mailbox.did()`) is
what identities name in their documents.

## 7. Testing: `dsip-testkit`

`Network::new()` is an in-process relay. Its devices bind over in-memory pipes, so there are no sockets or ports,
and tests can run in parallel.

```rust
let net = Network::new();
let mut alice = net.device("Alice").await;            // a did:key identity and its Agent, bound
let mut bob = net.device("Bob").await;
let sid = alice.call(&bob.identity()).await;
bob.expect("ringing", |e| matches!(e, AgentEvent::Call(CallEvent::Ringing { .. })).then_some(())).await;
bob.command(CallCommand::Accept { session: sid.clone() }).await;
alice.until(&sid, SessionState::Active).await;
```

- **More parties:** `net.identity(name)` makes an identity without connecting it, and `net.device_of(&id, name)`
  makes a second device of that identity.
- **Phones:** connect a `Phone` with `.dialer(net.dialer())` to put it on the testkit network.
- **Relay settings:** `Network::with(RelayConfig)` tests a relay configured your way.
- **Timeouts:** every wait gives up after `TIMEOUT` (10 s) with a message naming what it waited for.

The testkit has no mailbox yet. Messaging is tested by the demos, against `dsip-mailbox` processes.

## 8. Conformance

dsip-rs is measured against the language-neutral test vectors in `impl/vectors/`: 2,323 of them, run by the Rust
runner, the Python harness and the independent TypeScript implementation, which must all agree. A change to the
stack that changes behaviour shows up there first. If you build your own DSIP implementation, run the vectors
(`impl/vectors/README.md`). They are the contract, not this code.

## 9. Not yet

These are tracked in the design note, §4 and §8:
- **Device credentials without the controller key.** Devices currently hold the controller key, and
  `Engine::open` takes the controller seed.
- **An async resolver everywhere.** `dsip_transport::resolver` fetches `did:web` documents (`DidWebResolver`,
  `build_resolver`). `dsip-messenger` still takes its documents as files (`Config::resolver_files`).
- **One `Discover` interface** over document, alias, cache and hints.
- **A mailbox in the testkit.**
- **A release outside this workspace (stage 5).** Until then, depend on the crates by git path.
