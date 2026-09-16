//! The mailbox/hub service.
//!
//! Spec: M§4.3 (bind with `hello`, advertise mailbox capabilities), M§5 (the profile message set),
//! M§6.5–M§6.6 (hub ordering, fan-out, group registration), M§9.1 (deposit once, push to bound
//! devices), M§14.2 (first-contact authorization).
//!
//! Impl: every decision comes from `dsip_messaging::{mailbox::Mailbox, hub::Hub}` and, for commits,
//! `dsip_mls::HubView`; this binary only moves bytes and keeps the payloads the cursors name.
//! One instance serves one owner identity and hubs the groups whose deposits name it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use dsip_core::envelope::{self, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::did::StaticResolver;
use dsip_core::version::Supported;
use dsip_mailbox::store::{Item, Store};
use dsip_mailbox::verify::verify_frame;
use dsip_mailbox::{wire, HELLO_TIMEOUT_S};
use dsip_messaging::client::select_mailbox;
use dsip_messaging::hub::Hub;
use dsip_messaging::mailbox::Mailbox;
use dsip_mls::{digest, message_header, HubView};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::verify::SeenIds;
use dsip_transport::{now_s, tls};

#[derive(Parser)]
#[command(name = "dsip-mailbox", about = "DSIP mailbox and hub service (Messaging Profile 1.0)")]
struct Args {
    /// State directory: service key, TLS certificate.
    #[arg(long)]
    state: PathBuf,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:9443")]
    listen: SocketAddr,
    /// The identity this mailbox serves.
    #[arg(long)]
    owner: String,
    /// DID document files (re-read when resolving, so documents may be written after startup).
    #[arg(long = "resolver-file")]
    resolver_files: Vec<PathBuf>,
    /// Trust anchor for dialling peer mailboxes.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Admit policy (M§5.7): `grant` (default) or `open`.
    #[arg(long, default_value = "grant")]
    admit: String,
}

/// What a handled message produces.
enum Out {
    /// To a bound device of the owner, if connected.
    Device(String, Envelope),
    /// To another identity's mailbox (federation, M§6.5 rule 5).
    Identity(String, Envelope),
}

struct Service {
    key: KeyPair,
    owner: String,
    resolver_files: Vec<PathBuf>,
    ca: Option<PathBuf>,
    seen: SeenIds,
    supported: Supported,
    mailbox: Mailbox,
    hubs: HashMap<String, Hub>,
    views: HashMap<String, HubView>,
    store: Store,
    /// Items the hub has sequenced but whose fan-out is still in flight, by (group, seq).
    fanout: HashMap<(String, i64), Item>,
    bound: HashMap<String, mpsc::UnboundedSender<String>>,
    peers: HashMap<String, mpsc::UnboundedSender<Envelope>>,
}

fn ctx_of<'a>(resolver: &'a StaticResolver, seen: &SeenIds, supported: &Supported) -> Context<'a> {
    let mut ctx = Context::new(now_s(), resolver);
    ctx.seen_ids = seen.set();
    ctx.supported = supported.clone();
    ctx
}

impl Service {
    fn resolver(&self) -> StaticResolver {
        let mut r = StaticResolver::default();
        for f in &self.resolver_files {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
            if v.get("id").is_some() {
                if let Ok(doc) = serde_json::from_value(v) {
                    r.insert(doc);
                }
            }
        }
        r
    }

    /// Mailbox emissions → envelopes (M§5.3, M§5.4, M§5.5).
    fn mailbox_out(&mut self, emissions: Vec<Value>, now: i64) -> Vec<Out> {
        let mut out = vec![];
        for e in emissions {
            let (kind, body) = e.as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap_or_default();
            let to = body["to"].as_str().unwrap_or("").to_string();
            match kind.as_str() {
                "accepted" => {
                    let mut extra = json!({});
                    for k in ["cursor", "duplicate", "seq"] {
                        if let Some(v) = body.get(k) {
                            extra[k] = v.clone();
                        }
                    }
                    let env = wire::accepted(&self.key, &to, now, body["in_reply_to"].as_str().unwrap_or(""), extra);
                    out.push(Out::Device(to, env));
                }
                "error" => {
                    let env = wire::error(&self.key, &to, now, body["in_reply_to"].as_str(), body["reason"].as_str().unwrap_or(""), None);
                    out.push(Out::Device(to, env));
                }
                "items" => {
                    let list: Vec<Value> = body["cursors"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|c| c.as_str())
                        .filter_map(|c| self.store.get(c).map(|it| it.to_value(c)))
                        .collect();
                    let env = wire::items(&self.key, &to, now, body["in_reply_to"].as_str(), list, body["next"].clone());
                    out.push(Out::Device(to, env));
                }
                "push" => {
                    if let Some(c) = body["cursor"].as_str() {
                        if let Some(it) = self.store.get(c) {
                            let env = wire::items(&self.key, &to, now, None, vec![it.to_value(c)], Value::Null);
                            out.push(Out::Device(to, env));
                        }
                    }
                }
                "key_packages" => {
                    let mut packages = vec![];
                    let mut last_resort = None;
                    for (device, kind) in body["devices"].as_object().into_iter().flatten() {
                        if let Some(bytes) = self.store.take_key_package(device, kind.as_str().unwrap_or("")) {
                            if kind == "last-resort" {
                                last_resort = Some(bytes);
                            } else {
                                packages.push(json!(bytes));
                            }
                        }
                    }
                    let mut fields = json!({"in_reply_to": body["in_reply_to"], "subject": self.owner, "key_packages": packages});
                    if let Some(lr) = last_resort {
                        fields["last_resort"] = json!(lr);
                    }
                    out.push(Out::Device(to.clone(), wire::message(&self.key, "key-packages", &to, now, wire::TTL_S, fields)));
                }
                _ => {}
            }
        }
        out
    }

    /// Hub emissions → envelopes, with fan-out routed locally or federated (M§6.5 rule 5).
    fn hub_out(&mut self, group: &str, emissions: Vec<Value>, now: i64) -> Vec<Out> {
        let mut out = vec![];
        for e in emissions {
            let (kind, body) = e.as_object().and_then(|m| m.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap_or_default();
            let to = body["to"].as_str().unwrap_or("").to_string();
            match kind.as_str() {
                "accepted" => {
                    let mut extra = json!({"group": group});
                    for k in ["seq", "duplicate"] {
                        if let Some(v) = body.get(k) {
                            extra[k] = v.clone();
                        }
                    }
                    out.push(Out::Device(to.clone(), wire::accepted(&self.key, &to, now, body["in_reply_to"].as_str().unwrap_or(""), extra)));
                }
                "error" => {
                    let env = wire::error(&self.key, &to, now, body["in_reply_to"].as_str(), body["reason"].as_str().unwrap_or(""), None);
                    out.push(Out::Device(to, env));
                }
                "fanout" | "forward" => {
                    let class = body["class"].as_str().unwrap_or("application").to_string();
                    let seq = body["seq"].as_i64();
                    let item = match seq.and_then(|s| self.fanout.get(&(group.to_string(), s)).cloned()) {
                        Some(i) => i,
                        None => match self.fanout.get(&(group.to_string(), -1)).cloned() {
                            Some(i) => i, // group-info and ephemeral: the latest deposit of that class
                            None => continue,
                        },
                    };
                    let mut fields = json!({"recipient": to, "class": class});
                    if let Some(s) = seq {
                        fields["seq"] = json!(s);
                    }
                    for (k, v) in [("mls", &item.mls), ("archive", &item.archive)] {
                        if let Some(s) = v {
                            fields[k] = json!(s);
                        }
                    }
                    if let Some(h) = &item.hub {
                        fields["hub"] = h.clone();
                    }
                    out.push(Out::Identity(to, wire::deposit(&self.key, "", now, group, &class, fields)));
                }
                _ => {}
            }
        }
        out
    }

    /// Feed a hub fan-out addressed to our own owner straight into the mailbox (no socket).
    fn local_deposit(&mut self, dep: &Value, now: i64) -> Vec<Out> {
        let item = Item::from_deposit(dep, &self.key.did(), now);
        let event = json!({"hub_deposit": {"id": dep["id"], "from": self.key.did(), "recipient": self.owner,
            "group": dep["group"], "seq": dep["seq"], "class": dep["class"]}});
        let emissions = self.mailbox.step(&event);
        self.absorb(&emissions, item);
        self.mailbox_out(emissions, now)
    }

    /// Record the payload behind whatever cursor the machine just assigned.
    fn absorb(&mut self, emissions: &[Value], item: Item) {
        for e in emissions {
            if let Some(c) = e.get("accepted").and_then(|a| a.get("cursor")).and_then(Value::as_str) {
                if e["accepted"]["duplicate"] != json!(true) {
                    self.store.put(c, item.clone());
                }
                return;
            }
        }
    }
}

fn grant_payload(compact: &str, ctx: &Context) -> Option<Value> {
    // A grant is a credential, not a delivery envelope: verified like a delegation (§19.4, §7.4),
    // so its own replay window does not apply when it is presented later.
    let mut parts = compact.split('.');
    let env = Envelope {
        protected: parts.next()?.to_string(),
        payload: parts.next()?.to_string(),
        signature: parts.next()?.to_string(),
    };
    let ver = envelope::verify_raw(&env, ctx, false).ok()?;
    (ver.payload.get("type")? == "grant").then(|| ver.payload.clone())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();
    let args = Args::parse();
    std::fs::create_dir_all(&args.state)?;
    let key_path = args.state.join("service.key");
    let key = if key_path.exists() {
        let hex = std::fs::read_to_string(&key_path)?;
        let mut seed = [0u8; 32];
        for (i, c) in hex.trim().as_bytes().chunks(2).enumerate() {
            seed[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
        }
        KeyPair::from_seed(seed)
    } else {
        let k = KeyPair::generate();
        std::fs::write(&key_path, k.seed().iter().map(|b| format!("{b:02x}")).collect::<String>())?;
        k
    };
    std::fs::write(args.state.join("service.did"), key.did())?;
    let (cert, keyfile) = tls::ensure_self_signed(&args.state, &["localhost".into(), "127.0.0.1".into()])?;
    let acceptor = tls::acceptor(&cert, &keyfile)?;
    tracing::info!("mailbox {} for {} on wss://{}/dsip (ca {})", key.did(), args.owner, args.listen, cert.display());

    let mailbox = Mailbox::new(&json!({"now": now_s(), "owner": args.owner, "serves": [args.owner], "devices": [],
        "admit": args.admit}));
    let service = Arc::new(Mutex::new(Service {
        key,
        owner: args.owner.clone(),
        resolver_files: args.resolver_files.clone(),
        ca: args.ca.clone(),
        seen: SeenIds::default(),
        supported: Supported::all_known(),
        mailbox,
        hubs: HashMap::new(),
        views: HashMap::new(),
        store: Store::default(),
        fanout: HashMap::new(),
        bound: HashMap::new(),
        peers: HashMap::new(),
    }));

    let listener = tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = service.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    if let Err(e) = serve(tls, service).await {
                        tracing::info!("{peer}: {e}");
                    }
                }
                Err(e) => tracing::info!("{peer}: TLS handshake failed: {e}"),
            }
        });
    }
}

/// One client connection: `hello`, then profile messages until it closes (M§4.3).
async fn serve(tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>, service: Arc<Mutex<Service>>) -> Result<()> {
    let mut ws = tokio_tungstenite::accept_async_with_config(tls, Some(dsip_transport::conn::ws_config())).await?;
    let first = match tokio::time::timeout(std::time::Duration::from_secs(HELLO_TIMEOUT_S), ws.next()).await {
        Ok(Some(Ok(WsMessage::Text(t)))) => t.to_string(),
        _ => anyhow::bail!("no hello"),
    };
    let (device, identity, hello_env) = {
        let mut st = service.lock().await;
        let resolver = st.resolver();
        let ctx = ctx_of(&resolver, &st.seen, &st.supported);
        let inb = verify_frame(&first, &ctx).map_err(|r| anyhow::anyhow!("hello rejected: {r}"))?;
        anyhow::ensure!(inb.msg_type() == "hello", "first envelope was {}", inb.msg_type());
        let (device, identity) = (inb.device().to_string(), inb.identity().to_string());
        let id = inb.payload()["id"].as_str().unwrap_or("").to_string();
        let hub = true;
        let env = wire::service_hello(&st.key, &id, now_s(), wire::mailbox_capabilities(hub));
        st.seen.insert(&id, now_s(), now_s());
        (device, identity, env)
    };
    ws.send(WsMessage::Text(hello_env.frame().into())).await?;
    tracing::info!("bound {device} (for {identity})");

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        let mut st = service.lock().await;
        if identity == st.owner {
            st.bound.insert(device.clone(), tx);
            let devices: Vec<String> = st.bound.keys().cloned().collect();
            // The owner's registered devices are the ones that have bound (M§4.4).
            st.mailbox.register_devices(&devices);
        }
    }

    loop {
        tokio::select! {
            outbound = rx.recv() => match outbound {
                Some(frame) => ws.send(WsMessage::Text(frame.into())).await?,
                None => break,
            },
            inbound = ws.next() => match inbound {
                Some(Ok(WsMessage::Text(t))) => {
                    let replies = handle(&service, t.to_string(), &device, &identity).await;
                    for frame in replies {
                        ws.send(WsMessage::Text(frame.into())).await?;
                    }
                }
                Some(Ok(WsMessage::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e.into()),
            },
        }
    }
    let mut st = service.lock().await;
    st.bound.remove(&device);
    st.mailbox.step(&json!({"unbind": {"device": device}}));
    tracing::info!("unbound {device}");
    Ok(())
}

/// Verify one frame and run it through the state machines; returns frames for this connection.
async fn handle(service: &Arc<Mutex<Service>>, frame: String, sender: &str, bound_identity: &str) -> Vec<String> {
    let now = now_s();
    let mut st = service.lock().await;
    let resolver = st.resolver();
    let inb = {
        let ctx = ctx_of(&resolver, &st.seen, &st.supported);
        match verify_frame(&frame, &ctx) {
            Ok(i) => i,
            Err(r) => {
                tracing::info!("refused frame from {sender}: {r}");
                let env = wire::error(&st.key, sender, now, None, r.token(), Some(&r.code));
                return vec![env.frame()];
            }
        }
    };
    st.seen.insert(inb.payload()["id"].as_str().unwrap_or(""), now, now);
    let outs = dispatch(&mut st, &inb, bound_identity, &resolver, now);
    let mut replies = vec![];
    for out in outs {
        match out {
            Out::Device(to, env) => {
                if to == sender {
                    replies.push(env.frame());
                } else if let Some(tx) = st.bound.get(&to) {
                    let _ = tx.send(env.frame());
                }
            }
            Out::Identity(identity, env) => federate(service, &mut st, &identity, env, &resolver),
        }
    }
    replies
}

/// Route one verified message to the right state machine (M§5, M§6.5, M§6.6).
fn dispatch(
    st: &mut Service,
    inb: &dsip_mailbox::verify::Inbound,
    bound_identity: &str,
    resolver: &StaticResolver,
    now: i64,
) -> Vec<Out> {
    let p = inb.payload().clone();
    let device = inb.device().to_string();
    // §13.2: a device acts for the identity it bound as, not for the DID that signs each envelope
    // (a profile message's `from` is the device, M§5.1).
    let identity = bound_identity.to_string();
    let id = p["id"].as_str().unwrap_or("").to_string();
    match inb.msg_type() {
        "deposit" => {
            let class = p["class"].as_str().unwrap_or("");
            let group = p["group"].as_str().unwrap_or("").to_string();
            let item = Item::from_deposit(&p, &device, now);
            if class == "welcome" && p["recipient"].as_str() == Some(st.owner.as_str()) {
                let ctx = ctx_of(resolver, &st.seen, &st.supported);
                let grant = p["grants"].as_array().into_iter().flatten().filter_map(Value::as_str)
                    .find_map(|g| grant_payload(g, &ctx)).unwrap_or(Value::Null);
                let event = json!({"welcome": {"id": id, "from": device, "adder_identity": identity,
                    "recipient": st.owner, "group": group, "hub": p["hub"]["did"], "grant": grant,
                    "successor_of": p["successor_of"]}});
                let emissions = st.mailbox.step(&event);
                st.absorb(&emissions, item);
                return st.mailbox_out(emissions, now);
            }
            if class == "archive" {
                let event = json!({"archive": {"id": id, "device": device, "ref_group": p["ref_group"], "ref_seq": p["ref_seq"]}});
                let emissions = st.mailbox.step(&event);
                st.absorb(&emissions, item);
                return st.mailbox_out(emissions, now);
            }
            if p["recipient"].as_str() == Some(st.owner.as_str()) {
                // Fan-out from another hub for our owner.
                let event = json!({"hub_deposit": {"id": id, "from": identity, "recipient": st.owner,
                    "group": group, "seq": p["seq"], "class": class}});
                let emissions = st.mailbox.step(&event);
                st.absorb(&emissions, item);
                return st.mailbox_out(emissions, now);
            }
            hub_deposit(st, &p, &device, &identity, item, resolver, now)
        }
        "sync" => {
            let mut e = json!({"id": id, "device": device, "since": p["since"], "live": p["live"] == json!(true)});
            if let Some(a) = p.get("ack_through") {
                e["ack_through"] = a.clone();
            }
            if let Some(l) = p.get("limit") {
                e["limit"] = l.clone();
            }
            let emissions = st.mailbox.step(&json!({"sync": e}));
            st.mailbox_out(emissions, now)
        }
        "key-packages" => {
            let packages: Vec<String> = p["key_packages"].as_array().into_iter().flatten().filter_map(Value::as_str).map(String::from).collect();
            let count = packages.len() as i64;
            let last = p["last_resort"].as_str().map(String::from);
            st.store.add_key_packages(&device, packages, last.clone());
            let event = json!({"kp_upload": {"id": id, "device": device, "count": count, "last_resort": last.is_some()}});
            let emissions = st.mailbox.step(&event);
            st.mailbox_out(emissions, now)
        }
        "key-package-fetch" => {
            let ctx = ctx_of(resolver, &st.seen, &st.supported);
            let grant = p["grant"].as_str().and_then(|g| grant_payload(g, &ctx)).unwrap_or(Value::Null);
            let event = json!({"kp_fetch": {"id": id, "from": device, "from_identity": identity,
                "target": p["target"], "grant": grant}});
            let emissions = st.mailbox.step(&event);
            st.mailbox_out(emissions, now)
        }
        "mailbox-config" => {
            let mut e = json!({"id": id, "device": device});
            for k in ["mode", "admit", "groups", "revoked_grants"] {
                if let Some(v) = p.get(k) {
                    e[k] = v.clone();
                }
            }
            let emissions = st.mailbox.step(&json!({"config": e}));
            st.mailbox_out(emissions, now)
        }
        other => {
            tracing::info!("no handler for {other}");
            vec![]
        }
    }
}

/// Hub path: bootstrap the public view from a GroupInfo, validate commits, sequence, fan out.
fn hub_deposit(
    st: &mut Service,
    p: &Value,
    device: &str,
    identity: &str,
    item: Item,
    resolver: &StaticResolver,
    now: i64,
) -> Vec<Out> {
    let group = p["group"].as_str().unwrap_or("").to_string();
    let class = p["class"].as_str().unwrap_or("").to_string();
    let id = p["id"].as_str().unwrap_or("").to_string();
    let mls = p["mls"].as_str().unwrap_or("");
    let bytes = dsip_core::b64::decode(mls).unwrap_or_default();
    let ctx = ctx_of(resolver, &st.seen, &st.supported);

    if class == "group-info" {
        // Bootstrap or refresh the public view (M§6.5 rule 6).
        match HubView::from_group_info(&bytes) {
            Ok(view) => {
                if !st.hubs.contains_key(&group) {
                    let roster = view.roster(&ctx).unwrap_or(json!({}));
                    let hub = Hub::new(&json!({"now": now, "kind": "direct", "epoch": view.epoch(), "roster": roster}));
                    st.hubs.insert(group.clone(), hub);
                    tracing::info!("hubbing group {group} from epoch {}", view.epoch());
                }
                st.views.insert(group.clone(), view);
            }
            Err(e) => tracing::info!("group-info refused: {e}"),
        }
    }
    let Some(_) = st.hubs.get_mut(&group) else {
        let env = wire::error(&st.key, device, now, Some(&id), "mailbox.unknown-group", None);
        return vec![Out::Device(device.to_string(), env)];
    };
    let mut deposit = json!({"id": id, "device": device, "identity": identity, "class": class, "digest": digest(&bytes)});
    if let Ok((_, epoch, _)) = message_header(&bytes) {
        deposit["epoch"] = json!(epoch);
    }
    if class == "ephemeral" {
        deposit["expires_at"] = p["expires_at"].clone();
        deposit["digest"] = json!(id);
    }
    if class == "handshake" {
        let view = st.views.get_mut(&group);
        let commit = view.map(|v| v.observe_commit(&bytes, &ctx).unwrap_or(json!({"adds": [], "removes": [], "valid": false})));
        if let Some(c) = commit {
            if c.get("adds").is_some() {
                deposit["commit"] = c;
            }
        }
    }
    let hub = st.hubs.get_mut(&group).expect("hub");
    let emissions = hub.step(&json!({"deposit": deposit}));
    // Remember the payload so the fan-out can carry it: by seq, or as the latest of its class.
    let seq = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq")).and_then(Value::as_i64));
    st.fanout.insert((group.clone(), seq.unwrap_or(-1)), item);
    let outs = st.hub_out(&group, emissions, now);
    // Fan-out addressed to our own owner never leaves the process.
    let mut result = vec![];
    for o in outs {
        match o {
            Out::Identity(to, env) if to == st.owner => {
                let dep = wire::payload_of(&env).unwrap_or(json!({}));
                result.extend(st.local_deposit(&dep, now));
                if let Some(h) = st.hubs.get_mut(&group) {
                    if let Some(s) = dep["seq"].as_i64() {
                        h.step(&json!({"ack": {"identity": st.owner, "seq": s}}));
                    }
                }
            }
            other => result.push(other),
        }
    }
    result
}

/// Deposit into another identity's mailbox, found through its DID document (M§4.2, M§6.5 rule 5).
fn federate(service: &Arc<Mutex<Service>>, st: &mut Service, identity: &str, env: Envelope, resolver: &StaticResolver) {
    let doc = dsip_core::did::Resolver::resolve(resolver, identity);
    let entries: Vec<Value> = doc
        .map(|d| d.service.iter().filter(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).collect())
        .unwrap_or_default();
    let choice = select_mailbox(&json!({"document_entries": entries}));
    let Some(mailbox_did) = choice["selected"].as_str().map(String::from) else {
        tracing::info!("no mailbox for {identity}: {}", choice);
        return;
    };
    let uri = entries
        .iter()
        .find(|e| e["mailbox"] == json!(mailbox_did))
        .and_then(|e| e["uri"].as_str())
        .unwrap_or_default()
        .to_string();
    if !st.peers.contains_key(&mailbox_did) {
        let (tx, rx) = mpsc::unbounded_channel();
        st.peers.insert(mailbox_did.clone(), tx);
        let (key, ca, service2, target) = (st.key.clone(), st.ca.clone(), service.clone(), mailbox_did.clone());
        tokio::spawn(async move {
            let name = target.clone();
            if let Err(e) = peer_task(key, ca, uri, target, rx, service2).await {
                tracing::info!("federation to {name} ended: {e}");
            }
        });
    }
    let mut env = env;
    // The deposit is addressed to the peer mailbox; re-sign with the resolved `to` (M§5.2).
    if let Some(mut p) = wire::payload_of(&env) {
        p["to"] = json!(mailbox_did);
        env = envelope::sign(&p, &st.key, &st.key.kid());
    }
    if let Some(tx) = st.peers.get(&mailbox_did) {
        let _ = tx.send(env);
    }
}

/// One outbound connection to a peer mailbox: send deposits, feed acceptances back to the hub.
async fn peer_task(
    key: KeyPair,
    ca: Option<PathBuf>,
    uri: String,
    mailbox_did: String,
    mut rx: mpsc::UnboundedReceiver<Envelope>,
    service: Arc<Mutex<Service>>,
) -> Result<()> {
    let tls = tls::client_config(ca.as_deref())?;
    let mut seen = SeenIds::default();
    let params = ConnectParams {
        url: uri,
        tls,
        device: &key,
        on_behalf_of: None,
        delegations: vec![],
        supported: Supported::all_known(),
    };
    // The resolver is built and dropped inside the call: `&dyn Resolver` is not Send across awaits.
    let mut conn = {
        let resolver = StaticResolver::default();
        Connection::connect(&params, &resolver, &mut seen).await?
    };
    // deposit id → (group, recipient identity, seq): an `accepted` names only what it answers, but the
    // hub's fan-out queue is per identity (M§6.5 rule 5), so the recipient has to be remembered here.
    let mut inflight: HashMap<String, (String, String, i64)> = HashMap::new();
    anyhow::ensure!(conn.relay.did == mailbox_did, "peer mailbox is {} not {mailbox_did}", conn.relay.did);
    tracing::info!("federating to {mailbox_did}");
    loop {
        tokio::select! {
            next = rx.recv() => match next {
                Some(env) => {
                    if let Some(p) = wire::payload_of(&env) {
                        if let (Some(id), Some(group), Some(to)) =
                            (p["id"].as_str(), p["group"].as_str(), p["recipient"].as_str())
                        {
                            inflight.insert(id.into(), (group.into(), to.into(), p["seq"].as_i64().unwrap_or(-1)));
                        }
                    }
                    conn.send(&env).await?
                }
                None => break,
            },
            frame = conn.recv() => match frame? {
                Some(text) => {
                    let Ok(env) = Envelope::from_frame(&text) else { continue };
                    let Some(p) = wire::payload_of(&env) else { continue };
                    if p["type"] == "accepted" {
                        let Some((group, identity, seq)) = p["in_reply_to"].as_str().and_then(|id| inflight.remove(id)) else {
                            continue;
                        };
                        if seq < 0 {
                            continue; // group-info and ephemeral are not sequenced
                        }
                        let mut st = service.lock().await;
                        if let Some(hub) = st.hubs.get_mut(&group) {
                            let more = hub.step(&json!({"ack": {"identity": identity, "seq": seq}}));
                            // The ack may release the next queued item for that mailbox.
                            let outs = st.hub_out(&group, more, now_s());
                            for out in outs {
                                if let Out::Identity(to, env) = out {
                                    let resolver = st.resolver();
                                    federate(&service, &mut st, &to, env, &resolver);
                                }
                            }
                        }
                    }
                }
                None => break,
            },
        }
    }
    Ok(())
}
