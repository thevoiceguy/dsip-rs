//! The mailbox/hub service.
//!
//! Spec: M§4.3 (bind with `hello`, advertise mailbox capabilities), M§5 (the profile message set),
//! M§6.5–M§6.6 (hub ordering, fan-out, group registration), M§9.1 (deposit once, push to bound
//! devices), M§14.2 (first-contact authorization).
//!
//! Impl: every decision comes from `dsip_messaging::{mailbox::Mailbox, hub::Hub}` and, for commits,
//! `dsip_mls::HubView`; this binary only moves bytes and keeps the payloads the cursors name.
//! One instance serves one owner identity and hubs the groups whose deposits name it. An owner
//! device's deposit for a group hubbed elsewhere is forwarded unchanged to the hub registered for that
//! group, and the hub's answer comes back on the same path (M§5.2, spec-gap 45); the hub takes the
//! acting identity of a forwarded deposit from the delegation in its header, since the connection it
//! arrived on belongs to a mailbox. Welcomes a hub fans out carry the adder's deposit as `origin`,
//! which the receiving mailbox verifies (M§14.2, spec-gap 46).

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
use dsip_mailbox::verify::{delegated_identity, verify_frame};
use dsip_mailbox::{http, wire, HELLO_TIMEOUT_S};
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
    /// Largest blob accepted on the blob endpoint, bytes (M§4.3 `max_blob_bytes`).
    #[arg(long, default_value_t = 16_777_216)]
    max_blob_bytes: i64,
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
    /// `dsip_conversation` of each hubbed group: its kind and the hub reference welcomes carry.
    conversations: HashMap<String, Value>,
    /// Hub `{did, uri}` of each group registered for the owner, from its welcome (M§6.6): where to forward.
    hub_refs: HashMap<String, Value>,
    bound: HashMap<String, mpsc::UnboundedSender<String>>,
    peers: HashMap<String, mpsc::UnboundedSender<PeerMsg>>,
    /// Ciphertext blobs, one file per SHA-256 (M§8.4).
    blob_dir: PathBuf,
    /// `https://…/blobs` as advertised (M§4.3).
    blob_endpoint: String,
    max_blob_bytes: i64,
}

/// What goes out on a connection to a peer service.
enum PeerMsg {
    /// Hub fan-out we originate; its `accepted` releases the next queued item (M§6.5 rule 5).
    Fanout(Envelope),
    /// An owner device's deposit, forwarded unchanged; the answer goes back to that device (M§5.2).
    Forward(Envelope, String),
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
        let batch_seq = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq")).and_then(Value::as_i64));
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
                "fanout" if body["class"] == "welcome" => {
                    // M§6.5 rule 5, M§14.2: the welcome the commit carried, with the grants and the
                    // committer's own deposit as `origin`, so the new member's mailbox can verify the adder.
                    let Some(item) = batch_seq.and_then(|s| self.fanout.get(&(group.to_string(), s)).cloned()) else { continue };
                    let Some(welcome) = item.welcome else { continue };
                    let mut fields = json!({"recipient": to, "mls": welcome,
                        "hub": self.conversations.get(group).map(|c| c["hub"].clone()).unwrap_or(Value::Null)});
                    if let Some(g) = item.grants {
                        fields["grants"] = g;
                    }
                    if let Some(o) = item.origin {
                        fields["origin"] = json!(o);
                    }
                    out.push(Out::Identity(to, wire::deposit(&self.key, "", now, group, "welcome", fields)));
                }
                "forward" if body["class"] == "ephemeral" => {
                    // M§11.2: never stored, no seq, no accepted; the envelope never outlives the originating
                    // deposit (spec-gap 49), so an expired activity is dropped here.
                    let Some(item) = self.fanout.get(&(group.to_string(), -1)).cloned() else { continue };
                    let (Some(sealed), Some(exp)) = (item.sealed, item.expires_at) else { continue };
                    if exp <= now {
                        continue;
                    }
                    let fields = json!({"recipient": to, "group": group, "class": "ephemeral", "sealed": sealed});
                    out.push(Out::Identity(to, wire::message(&self.key, "deposit", "", now, exp - now, fields)));
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
                    if let Some(b) = &item.blobs {
                        fields["blobs"] = b.clone();
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
            "group": dep["group"], "seq": dep["seq"], "class": dep["class"], "expires_at": dep["expires_at"]}});
        let emissions = self.mailbox.step(&event);
        let mut out = self.ephemeral_pushes(&emissions, dep, &self.key.did(), now);
        self.absorb(&emissions, item);
        out.extend(self.mailbox_out(emissions, now));
        out
    }

    /// Ephemeral pushes (no cursor) become `items` carrying the sealed activity and its originating expiry.
    ///
    /// Spec: M§11.2. Impl (spec-gap 49): the pushed item is `{class, group, source, sealed, expires_at}`.
    fn ephemeral_pushes(&self, emissions: &[Value], dep: &Value, source: &str, now: i64) -> Vec<Out> {
        let exp = dep["expires_at"].as_i64().unwrap_or(0);
        let Some(sealed) = dep["sealed"].as_str() else { return vec![] };
        emissions
            .iter()
            .filter_map(|e| e.get("push"))
            .filter(|p| p["class"] == "ephemeral" && exp > now)
            .map(|p| {
                let to = p["to"].as_str().unwrap_or("").to_string();
                let item = json!({"class": "ephemeral", "group": dep["group"], "source": source, "sealed": sealed, "expires_at": exp});
                let env = wire::message(&self.key, "items", &to, now, exp - now, json!({"items": [item], "next": null}));
                Out::Device(to, env)
            })
            .collect()
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

/// Verify a hub-forwarded welcome's `origin`: the adder device's signed `handshake` deposit, with its
/// delegation (M§14.2). Returns what the mailbox machine checks: identity, group, `issued_at`.
fn origin_of(compact: &str, ctx: &Context) -> Option<Value> {
    let mut parts = compact.split('.');
    let env = Envelope {
        protected: parts.next()?.to_string(),
        payload: parts.next()?.to_string(),
        signature: parts.next()?.to_string(),
    };
    // Verified as a credential: it is presented after its own delivery, so the replay window does not apply;
    // the machine bounds its age against the hub deposit instead.
    let ver = envelope::verify_raw(&env, ctx, false).ok()?;
    let p = &ver.payload;
    if p["type"] != "deposit" || p["class"] != "handshake" {
        return None;
    }
    let identity = delegated_identity(&ver, ctx)?;
    Some(json!({"identity": identity, "group": p["group"], "issued_at": p["issued_at"]}))
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
        conversations: HashMap::new(),
        hub_refs: HashMap::new(),
        bound: HashMap::new(),
        peers: HashMap::new(),
        blob_dir: args.state.join("blobs"),
        blob_endpoint: format!("https://{}/blobs", args.listen),
        max_blob_bytes: args.max_blob_bytes,
    }));
    std::fs::create_dir_all(args.state.join("blobs"))?;

    let listener = tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("binding {}", args.listen))?;
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = service.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(tls) => {
                    let result = match http::classify(tls).await {
                        Ok(http::First::WebSocket(stream)) => serve(stream, service).await,
                        Ok(http::First::Http(req)) => blob_request(req, service).await,
                        Err(e) => Err(e.into()),
                    };
                    if let Err(e) = result {
                        tracing::info!("{peer}: {e}");
                    }
                }
                Err(e) => tracing::info!("{peer}: TLS handshake failed: {e}"),
            }
        });
    }
}

/// One client connection: `hello`, then profile messages until it closes (M§4.3).
type Tls = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

/// One blob request: `PUT` authorized by a `blob-put` envelope, or `GET` by hash (M§5.6, M§8.4).
async fn blob_request(mut req: http::Request<Tls>, service: Arc<Mutex<Service>>) -> Result<()> {
    let Some(sha) = req.path.strip_prefix(http::BLOB_PATH).map(String::from) else {
        return Ok(http::respond(&mut req.stream, 404, "text/plain", b"not found").await?);
    };
    let valid_name = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    match req.method.as_str() {
        "GET" => {
            let (path, stored) = {
                let st = service.lock().await;
                let path = st.blob_dir.join(&sha);
                (path.clone(), valid_name && path.exists())
            };
            let verdict = dsip_messaging::mailbox::blob_get(&json!({"path_sha256": sha, "stored": if stored { vec![sha.clone()] } else { vec![] }}));
            if verdict["status"] == 200 {
                let body = std::fs::read(&path)?;
                http::respond(&mut req.stream, 200, "application/octet-stream", &body).await?;
            } else {
                http::respond(&mut req.stream, 404, "text/plain", b"not found").await?;
            }
            Ok(())
        }
        "PUT" => {
            let now = now_s();
            // The credential: the full envelope pipeline, the device's delegation, the message rules (M§5.1).
            let (authorization, mbx, stored) = {
                let mut st = service.lock().await;
                let resolver = st.resolver();
                let ctx = ctx_of(&resolver, &st.seen, &st.supported);
                let auth = req
                    .header("authorization")
                    .and_then(|h| h.strip_prefix("DSIP "))
                    .and_then(|compact| {
                        let mut parts = compact.trim().split('.');
                        let env = Envelope {
                            protected: parts.next()?.to_string(),
                            payload: parts.next()?.to_string(),
                            signature: parts.next()?.to_string(),
                        };
                        let ver = envelope::verify(&env, &ctx, None).ok()?;
                        if ver.msg_type() != "blob-put" || dsip_messaging::checks::check_message(&ver.payload)["verdict"] != "accept" {
                            return None;
                        }
                        let identity = delegated_identity(&ver, &ctx)?;
                        Some(json!({"identity": identity, "payload": ver.payload}))
                    });
                if let Some(a) = &auth {
                    let id = a["payload"]["id"].as_str().unwrap_or("").to_string();
                    st.seen.insert(&id, now, now);
                }
                let mbx = json!({"did": st.key.did(), "serves": [st.owner], "max_blob_bytes": st.max_blob_bytes});
                let stored = valid_name && st.blob_dir.join(&sha).exists();
                (auth.unwrap_or(Value::Null), mbx, stored)
            };
            let stored_list = if stored { vec![sha.clone()] } else { vec![] };
            // Decide everything that does not need the body first (413 before reading it).
            let declared = authorization["payload"]["size"].as_i64().unwrap_or(-1);
            let pre = dsip_messaging::mailbox::blob_put(&json!({"mailbox": mbx, "authorization": authorization, "stored": stored_list,
                "request": {"path_sha256": sha, "body_size": authorization["payload"]["size"], "body_sha256": authorization["payload"]["sha256"]}}));
            let verdict = if pre["status"].as_i64().is_some_and(|s| s >= 400) {
                pre
            } else {
                let content_length: i64 = req.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(-1);
                let body = if content_length == declared { http::read_body(&mut req, declared as usize).await? } else { vec![] };
                let body_sha = hex_sha256(&body);
                let v = dsip_messaging::mailbox::blob_put(&json!({"mailbox": mbx, "authorization": authorization, "stored": stored_list,
                    "request": {"path_sha256": sha, "body_size": body.len(), "body_sha256": body_sha}}));
                if v["status"] == 201 {
                    let st = service.lock().await;
                    let tmp = st.blob_dir.join(format!(".{sha}.part"));
                    std::fs::write(&tmp, &body)?;
                    std::fs::rename(&tmp, st.blob_dir.join(&sha))?;
                    tracing::info!("stored blob {sha} ({} bytes) for {}", body.len(), authorization["identity"]);
                }
                v
            };
            let st = service.lock().await;
            let to = authorization["payload"]["from"].as_str().unwrap_or("").to_string();
            let status = verdict["status"].as_u64().unwrap_or(500) as u16;
            let env = match verdict.get("accepted") {
                Some(a) => {
                    let mut extra = json!({});
                    if a.get("duplicate").is_some() {
                        extra["duplicate"] = json!(true);
                    }
                    wire::accepted(&st.key, &to, now, a["in_reply_to"].as_str().unwrap_or(""), extra)
                }
                None => {
                    tracing::info!("blob PUT {sha} refused: {status} {}", verdict["reason"]);
                    let in_reply_to = authorization["payload"]["id"].as_str();
                    wire::error(&st.key, &to, now, in_reply_to, verdict["reason"].as_str().unwrap_or("policy.blocked"), None)
                }
            };
            drop(st);
            http::respond(&mut req.stream, status, "application/json", env.frame().as_bytes()).await?;
            Ok(())
        }
        _ => Ok(http::respond(&mut req.stream, 405, "text/plain", b"method not allowed").await?),
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

async fn serve(tls: http::Prefixed<Tls>, service: Arc<Mutex<Service>>) -> Result<()> {
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
        let env = wire::service_hello(&st.key, &id, now_s(), wire::mailbox_capabilities(hub, &st.blob_endpoint, st.max_blob_bytes));
        st.seen.insert(&id, now_s(), now_s());
        (device, identity, env)
    };
    ws.send(WsMessage::Text(hello_env.frame().into())).await?;
    tracing::info!("bound {device} (for {identity})");

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    {
        let mut st = service.lock().await;
        if identity == st.owner {
            st.bound.insert(device.clone(), tx.clone());
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
    // A device may hold a second, short-lived connection; only its own binding ends here.
    if st.bound.get(&device).is_some_and(|t| t.same_channel(&tx)) {
        st.bound.remove(&device);
        st.mailbox.step(&json!({"unbind": {"device": device}}));
        tracing::info!("unbound {device}");
    }
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
    let signer = inb.device().to_string();
    let outs = dispatch(service, &mut st, &inb, &frame, sender, bound_identity, &resolver, now);
    let mut replies = vec![];
    for out in outs {
        match out {
            Out::Device(to, env) => {
                // A forwarded deposit's signer is not bound here: its answer returns on this connection (M§5.2).
                if to == sender || to == signer {
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
#[allow(clippy::too_many_arguments)]
fn dispatch(
    service: &Arc<Mutex<Service>>,
    st: &mut Service,
    inb: &dsip_mailbox::verify::Inbound,
    frame: &str,
    hello_device: &str,
    bound_identity: &str,
    resolver: &StaticResolver,
    now: i64,
) -> Vec<Out> {
    let p = inb.payload().clone();
    let device = inb.device().to_string();
    // §13.2: a device acts for the identity it bound as, not for the DID that signs each envelope
    // (a profile message's `from` is the device, M§5.1). A deposit forwarded by a mailbox is signed by a
    // device that did not bind here: it acts for the identity its header delegation proves (M§5.1, M§5.2).
    let identity = if device == hello_device {
        bound_identity.to_string()
    } else {
        let ctx = ctx_of(resolver, &st.seen, &st.supported);
        delegated_identity(&inb.verified, &ctx).unwrap_or_else(|| device.clone())
    };
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
                let mut w = json!({"id": id, "from": device, "adder_identity": identity,
                    "recipient": st.owner, "group": group, "hub": p["hub"]["did"], "grant": grant,
                    "successor_of": p["successor_of"]});
                // A service-signed welcome (no delegation) came from a hub: only `origin` names the adder (M§14.2).
                if device == hello_device && bound_identity == device {
                    w["via_hub"] = json!(true);
                    w["issued_at"] = p["issued_at"].clone();
                    w.as_object_mut().expect("object").remove("adder_identity");
                    if let Some(o) = p["origin"].as_str().and_then(|o| origin_of(o, &ctx)) {
                        w["origin"] = o;
                    }
                }
                let emissions = st.mailbox.step(&json!({"welcome": w}));
                if let Some(e) = emissions.iter().find_map(|e| e.get("error")) {
                    tracing::info!("welcome for {group} refused: {} (origin {})", e["reason"], w.get("origin").is_some());
                }
                if emissions.iter().any(|e| e.get("accepted").is_some()) {
                    st.hub_refs.insert(group.clone(), p["hub"].clone());
                }
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
                    "group": group, "seq": p["seq"], "class": class, "expires_at": p["expires_at"]}});
                let emissions = st.mailbox.step(&event);
                let mut out = st.ephemeral_pushes(&emissions, &p, &identity, now);
                st.absorb(&emissions, item);
                out.extend(st.mailbox_out(emissions, now));
                return out;
            }
            if p["to"].as_str() != Some(st.key.did().as_str()) {
                // Addressed to another service: forward to the group's hub, or refuse (M§5.2, spec-gap 45).
                let event = json!({"forward": {"id": id, "device": device, "identity": identity, "group": group, "to": p["to"]}});
                let emissions = st.mailbox.step(&event);
                if emissions.iter().any(|e| e.get("forward").is_some()) {
                    let uri = st.hub_refs.get(&group).and_then(|h| h["uri"].as_str()).map(String::from);
                    let target = p["to"].as_str().unwrap_or("").to_string();
                    match (uri, Envelope::from_frame(frame)) {
                        (Some(uri), Ok(env)) => {
                            peer_send(service, st, &target, uri, PeerMsg::Forward(env, device.clone()));
                            return vec![];
                        }
                        _ => {
                            let env = wire::error(&st.key, &device, now, Some(&id), "mailbox.unknown-group", Some("hub not reachable"));
                            return vec![Out::Device(device, env)];
                        }
                    }
                }
                return st.mailbox_out(emissions, now);
            }
            let mut item = item;
            if class == "handshake" {
                item.origin = Envelope::from_frame(frame).ok().map(|e| format!("{}.{}.{}", e.protected, e.payload, e.signature));
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
                let conv = view.conversation().unwrap_or(Value::Null);
                if !st.hubs.contains_key(&group) {
                    let roster = view.roster(&ctx).unwrap_or(json!({}));
                    let kind = conv["kind"].as_str().unwrap_or("direct");
                    let hub = Hub::new(&json!({"now": now, "kind": kind, "epoch": view.epoch(), "roster": roster}));
                    st.hubs.insert(group.clone(), hub);
                    tracing::info!("hubbing {kind} group {group} from epoch {}", view.epoch());
                }
                st.conversations.insert(group.clone(), conv);
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
    for e in &emissions {
        if let Some(err) = e.get("error") {
            tracing::info!("hub refused {class} from {identity}: {}", err["reason"]);
        }
    }
    if let Some(seq) = emissions.iter().find_map(|e| e.get("accepted").and_then(|a| a.get("seq"))) {
        tracing::info!("hub sequenced {class} seq {seq} from {identity} in {group}");
    }
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
                        // A local ack may release the owner's next queued item; deliver it the same way.
                        let more = h.step(&json!({"ack": {"identity": st.owner, "seq": s}}));
                        if !more.is_empty() {
                            tracing::info!("local fan-out released {} more", more.len());
                        }
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
    let mut env = env;
    // The deposit is addressed to the peer mailbox; re-sign with the resolved `to` (M§5.2).
    if let Some(mut p) = wire::payload_of(&env) {
        p["to"] = json!(mailbox_did);
        env = envelope::sign(&p, &st.key, &st.key.kid());
    }
    peer_send(service, st, &mailbox_did, uri, PeerMsg::Fanout(env));
}

/// Send on the connection to a peer service, dialling it first if needed.
fn peer_send(service: &Arc<Mutex<Service>>, st: &mut Service, peer_did: &str, uri: String, msg: PeerMsg) {
    if st.peers.get(peer_did).is_none_or(|tx| tx.is_closed()) {
        let (tx, rx) = mpsc::unbounded_channel();
        st.peers.insert(peer_did.to_string(), tx);
        let (key, ca, service2, target) = (st.key.clone(), st.ca.clone(), service.clone(), peer_did.to_string());
        tokio::spawn(async move {
            let name = target.clone();
            if let Err(e) = peer_task(key, ca, uri, target, rx, service2).await {
                tracing::info!("connection to {name} ended: {e}");
            }
        });
    }
    if let Some(tx) = st.peers.get(peer_did) {
        let _ = tx.send(msg);
    }
}

/// One outbound connection to a peer mailbox: send deposits, feed acceptances back to the hub.
async fn peer_task(
    key: KeyPair,
    ca: Option<PathBuf>,
    uri: String,
    mailbox_did: String,
    mut rx: mpsc::UnboundedReceiver<PeerMsg>,
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
    // forwarded deposit id → the owner device waiting for the hub's answer (M§5.2)
    let mut forwarded: HashMap<String, String> = HashMap::new();
    anyhow::ensure!(conn.relay.did == mailbox_did, "peer mailbox is {} not {mailbox_did}", conn.relay.did);
    tracing::info!("federating to {mailbox_did}");
    loop {
        tokio::select! {
            next = rx.recv() => match next {
                Some(PeerMsg::Fanout(env)) => {
                    if let Some(p) = wire::payload_of(&env) {
                        if let (Some(id), Some(group), Some(to)) =
                            (p["id"].as_str(), p["group"].as_str(), p["recipient"].as_str())
                        {
                            inflight.insert(id.into(), (group.into(), to.into(), p["seq"].as_i64().unwrap_or(-1)));
                        }
                    }
                    conn.send(&env).await?
                }
                Some(PeerMsg::Forward(env, device)) => {
                    if let Some(id) = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)) {
                        forwarded.insert(id, device);
                    }
                    tracing::info!("forwarding a deposit to hub {mailbox_did}");
                    conn.send(&env).await?
                }
                None => break,
            },
            frame = conn.recv() => match frame? {
                Some(text) => {
                    let Ok(env) = Envelope::from_frame(&text) else { continue };
                    let Some(p) = wire::payload_of(&env) else { continue };
                    if let Some(device) = p["in_reply_to"].as_str().and_then(|id| forwarded.remove(id)) {
                        // The hub's answer to a forwarded deposit, passed through to the device (M§5.2).
                        let st = service.lock().await;
                        if let Some(tx) = st.bound.get(&device) {
                            let _ = tx.send(text.clone());
                        }
                        continue;
                    }
                    if p["type"] == "error" {
                        tracing::info!("{mailbox_did} refused our deposit: {} {}", p["reason"], p["detail"]);
                    }
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
