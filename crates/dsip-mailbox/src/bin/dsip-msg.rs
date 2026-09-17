//! A messaging device: one identity's device, its MLS groups, and a connection to its mailbox.
//!
//! Spec: M§4.2 (find the mailbox in the DID document), M§5.4–M§5.5 (sync, KeyPackages), M§6.2–M§6.7
//! (leaves, groups, welcomes), M§7.1–M§7.3 (personal group, direct and group conversations, adds and removes
//! rendered with their committer), M§8.1 (content objects), M§9.1 (deposit once), M§12 (archive key,
//! archiving, adding and removing a device), M§14.1–M§14.2 (grants), M§5.4, M§8.5 (durable delivery state).
//!
//! Impl: commands on stdin, events on stdout, so a demo script can drive several of these. MLS state and
//! the delivery state ([`Resume`]: ack cursor, seq positions, joined groups) live in one SQLite database
//! under `--state`, and each inbound item is processed and committed in one transaction (spec-gap 44), so
//! the process can be killed at any point and restarted. A device holds any number of groups: its identity's
//! personal group and its conversations; commands act on the most recent conversation. Every group deposit
//! goes to the hub through this device's own mailbox with the delegation in its header (spec-gap 45); a
//! commit is applied only after the hub's `accepted` and refusals are handled by the vector-pinned `CommitRetry` (spec-gap 58);
//! the device's own items fanned back to it are recognised
//! by that `accepted` seq or by their bytes (spec-gap 47). Audio (`voice`, `voicemail`) is an Ogg Opus file
//! sealed under a fresh key, uploaded to the mailbox blob endpoint and referenced from the content object
//! (M§8.2, M§8.4, M§5.6). Receipts and activity (M§10, M§11) are decided by the vector-pinned
//! `dsip_messaging::client::Client`, one per conversation; an undisclosed read watermark goes to the personal
//! group (M§10.5, spec-gap 52) and siblings apply it. History (M§12) is decided by the vector-pinned
//! `dsip_messaging::client::History`: content shown from MLS is archived under the current archive key,
//! archive records are shown once, MLS items from before this device joined a group are skipped, and archive
//! records under a key the device does not hold yet are kept (durably, encrypted) until the key arrives
//! (spec-gap 51). A second device of an identity is started with `--controller` pointing at the identity key.
//! First contact (M§14.1, spec-gap 54): `introduce` sends a core §19.4 introduction, its purpose sealed with HPKE
//! to the recipient's key agreement key (M§6.9), as a deposit to the recipient's mailbox; the recipient sees it as a
//! request — never as a message — and `accept-request` returns a `dsip.message` grant the same way, which the
//! requester holds and presents when it creates the conversation. Grants carry the signing device's delegation.
//! The identity's key agreement key is derived from its identity key (spec-gap 55). `revoke-device` (spec-gap 57)
//! signs a `delegation-revocation` with the identity key, publishes it in the identity's DID document and sends it
//! to the mailbox, which ends the device's binding; `remove-leaf` lets any member remove a leaf whose delegation no
//! longer verifies (M§7.3, M§12.4).
//! `offline` only drops the connection; `crash-next` exits after processing the next new item and before
//! committing it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, BufReader};

use dsip_core::delegation::delegation_payload;
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{sign, Context, Envelope};
use dsip_core::keys::KeyPair;
use dsip_core::version::Supported;
use dsip_mailbox::wire;
use dsip_messaging::checks::check_object;
use dsip_messaging::client::{select_mailbox, CommitRetry, History, Resume, SuccessorTracker};
use dsip_messaging::mls_wire::{open, seal, SealUse};
use dsip_mls::sqlite::SqliteProvider;
use dsip_mls::{authenticate_key_package, authenticate_members, conversation_extension, conversation_update, digest, member_identity, message_header, Device, MlsError};
use dsip_transport::conn::{ConnectParams, Connection};
use dsip_transport::verify::SeenIds;
use dsip_transport::{now_s, tls};

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;

#[derive(Parser)]
#[command(name = "dsip-msg", about = "A DSIP messaging device (Messaging Profile 1.0)")]
struct Args {
    /// State directory (keys, and `device.sqlite`: MLS and delivery state).
    #[arg(long)]
    state: PathBuf,
    /// This device's identity, a `did:web` whose document is published.
    #[arg(long)]
    identity: String,
    /// The identity's controller key (hex seed file), for a second device of an existing identity (M§12.3 step 1).
    #[arg(long)]
    controller: Option<PathBuf>,
    /// DID document files to resolve from.
    #[arg(long = "resolver-file")]
    resolver_files: Vec<PathBuf>,
    /// Trust anchor for the mailboxes.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Write this identity's DID document (with its DSIPMailbox entry) and exit.
    #[arg(long)]
    write_doc: Option<PathBuf>,
    /// Mailbox service DID, for `--write-doc`.
    #[arg(long)]
    mailbox_did: Option<String>,
    /// Mailbox `wss://` URI, for `--write-doc`.
    #[arg(long)]
    mailbox_uri: Option<String>,
    /// Behavior disclosed to other identities (M§10.5): any of `read`, `played`, `activity`. `delivered` is on
    /// unless `--no-delivered`.
    #[arg(long, value_delimiter = ',')]
    disclose: Vec<String>,
    /// Do not send `delivered` receipts.
    #[arg(long)]
    no_delivered: bool,
}

/// The device's persistent keys: an identity controller key and a device key.
struct Keys {
    controller: KeyPair,
    device: KeyPair,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    let s = s.trim();
    anyhow::ensure!(s.len() == 64, "expected 64 hex chars");
    let mut out = [0u8; 32];
    for (i, c) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(c)?, 16)?;
    }
    Ok(out)
}

impl Keys {
    fn load_or_create(dir: &Path, controller: Option<&Path>) -> Result<Keys> {
        std::fs::create_dir_all(dir)?;
        let read = |p: PathBuf| -> Result<KeyPair> {
            if p.exists() {
                Ok(KeyPair::from_seed(unhex(&std::fs::read_to_string(&p)?)?))
            } else {
                let k = KeyPair::generate();
                std::fs::write(&p, hex(&k.seed()))?;
                Ok(k)
            }
        };
        let controller = match controller {
            Some(p) => KeyPair::from_seed(unhex(&std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)?),
            None => read(dir.join("controller.key"))?,
        };
        Ok(Keys { controller, device: read(dir.join("device.key"))? })
    }
}

/// The `did:web` document for this identity, carrying its mailbox entry (M§4.2).
fn did_document(identity: &str, controller: &KeyPair, mailbox_did: &str, mailbox_uri: &str) -> Value {
    // M§6.9: the key sealed introductions are encrypted to (spec-gap 55: derived from the identity key).
    let x25519 = dsip_messaging::first_contact::x25519_public(&dsip_messaging::first_contact::x25519_from_ed25519_seed(&controller.seed()));
    json!({
        "keyAgreement": [{
            "id": format!("{identity}#key-agreement-1"), "type": "Multikey", "controller": identity,
            "publicKeyMultibase": dsip_core::did::multibase_x25519(&x25519),
        }],
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        "id": identity,
        "verificationMethod": [{
            "id": format!("{identity}#key-1"), "type": "Multikey", "controller": identity,
            "publicKeyMultibase": dsip_core::did::multibase_ed25519(&controller.public()),
        }],
        "authentication": [format!("{identity}#key-1")],
        "assertionMethod": [format!("{identity}#key-1")],
        "service": [{
            "id": format!("{identity}#dsip-mailbox"), "type": "DSIPMailbox",
            "serviceEndpoint": {
                "uri": mailbox_uri, "bindings": ["ws/1.0"], "mailbox": mailbox_did, "priority": 0,
                "profiles": [wire::PROFILE], "accepts": ["text", "audio", "image", "file"],
                "voicemail": {"max_duration_s": 180},
            },
        }],
    })
}

fn resolver(files: &[PathBuf]) -> StaticResolver {
    let mut r = StaticResolver::default();
    for f in files {
        if let Ok(text) = std::fs::read_to_string(f) {
            if let Ok(doc) = serde_json::from_str(&text) {
                r.insert(doc);
            }
        }
    }
    r
}

/// The mailbox an identity advertises, chosen by the profile's rules (M§4.2).
fn mailbox_of(identity: &str, resolver: &StaticResolver) -> Result<(String, String)> {
    let doc = dsip_core::did::Resolver::resolve(resolver, identity).with_context(|| format!("no document for {identity}"))?;
    let entries: Vec<Value> =
        doc.service.iter().filter(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).collect();
    let choice = select_mailbox(&json!({"document_entries": entries}));
    let did = choice["selected"].as_str().with_context(|| format!("no usable mailbox for {identity}: {choice}"))?.to_string();
    let uri = entries
        .iter()
        .find(|e| e["mailbox"] == json!(did))
        .and_then(|e| e["uri"].as_str())
        .context("entry without uri")?
        .to_string();
    Ok((did, uri))
}

fn compact(e: &Envelope) -> String {
    format!("{}.{}.{}", e.protected, e.payload, e.signature)
}

fn from_compact(c: &str) -> Envelope {
    let mut parts = c.split('.');
    let mut next = || parts.next().unwrap_or("").to_string();
    Envelope { protected: next(), payload: next(), signature: next() }
}

fn b64(bytes: &[u8]) -> String {
    dsip_core::b64::encode(bytes)
}

fn unb64(v: &Value) -> Vec<u8> {
    v.as_str().and_then(dsip_core::b64::decode).unwrap_or_default()
}

/// M§8.5: the deduplication key of an object.
fn object_key(o: &Value) -> String {
    format!("{}|{}|{}", o["conversation"].as_str().unwrap_or(""), o["sender"].as_str().unwrap_or(""), o["id"].as_str().unwrap_or(""))
}

fn display(o: &Value) -> String {
    match o["kind"].as_str() {
        Some("text") => o["text"].as_str().unwrap_or("").to_string(),
        Some(k) => format!("[{k}]"),
        None => String::new(),
    }
}

/// One group this device is a member of.
struct Conv {
    group: MlsGroup,
    conversation: String,
    kind: String,
    hub: (String, String),
    /// Receipt and activity decisions for this conversation (M§10, M§11).
    receipts: dsip_messaging::client::Client,
    last_media: Option<String>,
}

struct Client {
    keys: Keys,
    identity: String,
    delegation: Envelope,
    mls: Device<SqliteProvider>,
    resolver_files: Vec<PathBuf>,
    ca: Option<PathBuf>,
    conn: Option<Connection>,
    mailbox: (String, String),
    seen: SeenIds,
    /// Groups by base64url group id.
    convs: BTreeMap<String, Conv>,
    /// The conversation commands act on.
    active: Option<String>,
    /// This identity's personal group (M§7.1).
    personal: Option<String>,
    /// Archive keys by `akid`: `(key, created_at)` (M§12.1).
    archive_keys: BTreeMap<String, ([u8; 32], i64)>,
    /// Archive items under a key this device does not hold yet, by cursor (spec-gap 51).
    held: BTreeMap<String, Value>,
    history: History,
    /// Display text of shown history, by object key.
    lines: HashMap<String, String>,
    /// Digests of this device's own deposits: their fan-out copies come back and cannot be decrypted (spec-gap 47).
    own: HashSet<String>,
    resume: Resume,
    /// Successor groups per dead group (M§7.5, spec-gap 61).
    successors: SuccessorTracker,
    grants: HashMap<String, String>,
    /// Grants other identities issued to this one, by granter (M§14.1): presented when creating a conversation.
    grants_held: BTreeMap<String, String>,
    /// Introductions received and not yet answered, by id (M§14.1: requests, never messages).
    requests: BTreeMap<String, Value>,
    crash_next: bool,
    state: PathBuf,
    http: reqwest::Client,
    policy: Value,
    /// Content and receipt objects of the sync batch being processed, by group (M§10.2 decides per batch).
    batch: Vec<(String, Value)>,
    /// What the receipt and history machines asked to send, by group, sent outside frame processing.
    outbox: Vec<(String, Value)>,
}

/// A membership or key change a device commits (M§6.5, M§7.3, M§12.3–M§12.4).
enum CommitOp {
    /// Add a KeyPackage's device: a new identity, or `device` of an existing one.
    Add { kp: Box<KeyPackage>, grants: Vec<String>, identity: String, device: Option<String> },
    /// Remove every leaf of an identity.
    RemoveIdentity(String),
    /// Remove the leaves whose credential names a device (whether or not they still authenticate).
    RemoveDevice(String),
    /// Refresh this device's own leaf key material (post-compromise security).
    Update,
    /// Move the group to another hub, `{did, uri}` (M§7.4).
    MoveHub(Value),
}

/// What processing one inbound item produced, reported only once it is committed.
enum Outcome {
    Joined { members: Vec<String>, group: String, conv: Value, epoch: u64 },
    /// A welcome for another device of this identity: it holds none of our KeyPackages (M§12.3 step 5).
    NotForDevice,
    Object { sender: String, sender_device: String, object: Value },
    Dropped(String),
    /// M§7.3: every roster change is rendered, attributed to the committing identity. `hub` is set when the commit
    /// changed the group's hub reference (M§7.4).
    Epoch { epoch: u64, by: String, added: Vec<String>, removed: Vec<String>, hub: Option<Value> },
    /// This device was removed; `remaining` are the member identities left in the group.
    Removed { by: String, remaining: Vec<String> },
    Nothing,
}

impl Client {
    fn ctx<'a>(&self, resolver: &'a StaticResolver) -> Context<'a> {
        let mut ctx = Context::new(now_s(), resolver);
        ctx.delegations = vec![self.delegation.clone()];
        ctx.supported = Supported::all_known();
        ctx
    }

    fn state_err(e: MlsError) -> anyhow::Error {
        anyhow::anyhow!("{e}")
    }

    async fn connect(&mut self) -> Result<()> {
        if self.conn.is_some() {
            return Ok(());
        }
        let tls = tls::client_config(self.ca.as_deref())?;
        let params = ConnectParams {
            url: self.mailbox.1.clone(),
            tls,
            device: &self.keys.device,
            on_behalf_of: Some(self.identity.clone()),
            delegations: vec![self.delegation.clone()],
            supported: Supported::all_known(),
        };
        let conn = {
            let r = resolver(&self.resolver_files);
            Connection::connect(&params, &r, &mut self.seen).await?
        };
        anyhow::ensure!(conn.relay.did == self.mailbox.0, "mailbox is {} not {}", conn.relay.did, self.mailbox.0);
        println!("OK connected {} mailbox={}", self.identity, self.mailbox.0);
        self.conn = Some(conn);
        Ok(())
    }

    async fn send(&mut self, env: &Envelope) -> Result<()> {
        self.connect().await?;
        self.conn.as_mut().context("offline")?.send(env).await
    }

    /// A short-lived connection to another identity's mailbox (M§5.5 fetch).
    async fn peer_connect(&mut self, identity: &str) -> Result<Connection> {
        let r = resolver(&self.resolver_files);
        let (did, uri) = mailbox_of(identity, &r)?;
        let tls = tls::client_config(self.ca.as_deref())?;
        let params = ConnectParams {
            url: uri,
            tls,
            device: &self.keys.device,
            on_behalf_of: Some(self.identity.clone()),
            delegations: vec![self.delegation.clone()],
            supported: Supported::all_known(),
        };
        let conn = Connection::connect(&params, &r, &mut self.seen).await?;
        anyhow::ensure!(conn.relay.did == did, "peer mailbox is {} not {did}", conn.relay.did);
        Ok(conn)
    }

    /// Issue a contact grant for `peer` (§19.4, scope `dsip.message`), answering introduction `session` if any. The
    /// device's delegation rides in the header, so a verifier can bind the signer to the granting identity (§7.4).
    fn grant(&self, peer: &str, session: Option<&str>) -> Envelope {
        let now = now_s();
        let p = json!({"dsip": wire::version_block(), "type": "grant", "id": wire::new_id(now), "from": self.identity,
            "to": peer, "session": session.map(String::from).unwrap_or_else(|| wire::new_id(now)), "scope": ["dsip.message"],
            "valid_until": now + 30 * 86400, "issued_at": now, "expires_at": now + 30});
        self.sign_delegated(&p)
    }

    fn sign_delegated(&self, p: &Value) -> Envelope {
        dsip_core::envelope::sign_bytes(&dsip_core::envelope::encode_payload(p), &self.keys.device, &self.keys.device.kid(), vec![self.delegation.clone()])
    }

    /// Deposit a first-contact envelope for `recipient` at that identity's mailbox (spec-gap 54); the mailbox's answer.
    async fn deposit_first_contact(&mut self, class: &str, recipient: &str, envelope: &Envelope) -> Result<Value> {
        let mut conn = self.peer_connect(recipient).await?;
        let dep = wire::message(&self.keys.device, "deposit", &conn.relay.did.clone(), now_s(), wire::TTL_S,
            json!({"class": class, "recipient": recipient, "envelope": compact(envelope)}));
        conn.send(&dep).await?;
        let reply = conn.recv().await?.context("no answer from the mailbox")?;
        conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "done").await;
        wire::payload_of(&Envelope::from_frame(&reply).map_err(|v| anyhow::anyhow!("{:?}", v.code))?).context("bad answer")
    }

    /// M§14.1: ask `target` for permission to message, the purpose sealed to its key agreement key unless `plain`.
    async fn introduce(&mut self, target: &str, purpose: &str, plain: bool) -> Result<()> {
        let now = now_s();
        let mut p = json!({"dsip": wire::version_block(), "type": "introduction", "id": wire::new_id(now), "from": self.identity,
            "to": target, "identity": {"display_name": self.identity}, "purpose": purpose, "issued_at": now,
            "expires_at": now + 7 * 86_400});
        if !plain {
            let r = resolver(&self.resolver_files);
            let doc = dsip_core::did::Resolver::resolve(&r, target).with_context(|| format!("no document for {target}"))?;
            let pk = doc.x25519_key_agreement().context("the recipient publishes no key agreement key: use introduce-plain")?;
            dsip_messaging::first_contact::seal_introduction(&mut p, purpose, &pk, &rand::random());
        }
        let env = self.sign_delegated(&p);
        let id = p["id"].as_str().unwrap_or("").to_string();
        let answer = self.deposit_first_contact("introduction", target, &env).await?;
        match answer["type"].as_str() {
            Some("accepted") => println!("OK introduction {id} to {target} accepted sealed={}", !plain),
            _ => println!("ERR introduction {id} refused: {} retry_after={}", answer["reason"], answer["retry_after"]),
        }
        Ok(())
    }

    /// M§14.1: answer a request with a `dsip.message` grant, deposited at the requester's mailbox.
    async fn accept_request(&mut self, id: &str) -> Result<()> {
        let intro = self.requests.get(id).cloned().context("no such request")?;
        let requester = intro["from"].as_str().unwrap_or("").to_string();
        let grant = self.grant(&requester, Some(id));
        let answer = self.deposit_first_contact("grant", &requester, &grant).await?;
        anyhow::ensure!(answer["type"] == "accepted", "grant refused: {}", answer["reason"]);
        self.requests.remove(id);
        self.mls.provider().put_state("requests", &json!(self.requests)).map_err(Self::state_err)?;
        println!("OK granted {requester} dsip.message for request {id}");
        Ok(())
    }

    /// A signed introduction or grant from the mailbox, verified as a credential: its signature and the binding of
    /// its signer to `from` (§7.4); it was checked fresh when deposited, and has been held since (spec-gap 54).
    fn first_contact_in(&mut self, item: &Value) -> Result<()> {
        let class = item["class"].as_str().unwrap_or("");
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let env = from_compact(item["envelope"].as_str().unwrap_or(""));
        let checked = dsip_core::envelope::verify_raw(&env, &ctx, false).ok().filter(|ver| {
            let from = ver.payload["from"].as_str().unwrap_or("");
            ver.payload["type"] == class
                && ver.payload["to"] == json!(self.identity)
                // an introduction lives until its expires_at; a grant's delivery expiry has passed, its valid_until has not (§19.4)
                && ver.payload[if class == "grant" { "valid_until" } else { "expires_at" }].as_i64().unwrap_or(0) >= now_s()
                && dsip_core::delegation::check_binding(from, &ver.signer_did, &ver.header.delegations, &ctx).ok()
        });
        let Some(ver) = checked else {
            println!("DROP-{} {}: does not verify", class.to_uppercase(), item["cursor"]);
            return Ok(());
        };
        let p = ver.payload;
        let from = p["from"].as_str().unwrap_or("").to_string();
        if class == "introduction" {
            let opened = dsip_messaging::first_contact::open_sealed_introduction(&p, &self.keys.controller.seed());
            if opened["verdict"] != "accept" {
                println!("DROP-INTRODUCTION {} from {from}: {}", p["id"], opened["code"]);
                return Ok(());
            }
            let purpose = opened["purpose"].as_str().unwrap_or("").to_string();
            let on_wire = String::from_utf8(dsip_core::b64::decode(&env.payload).unwrap_or_default()).unwrap_or_default();
            let id = p["id"].as_str().unwrap_or("").to_string();
            println!("REQUEST {id} from {from}: \"{purpose}\" sealed={} purpose_on_wire={}", p.get("sealed").is_some(),
                !purpose.is_empty() && on_wire.contains(&purpose));
            self.requests.insert(id, p);
            self.mls.provider().put_state("requests", &json!(self.requests)).map_err(Self::state_err)?;
        } else {
            let scope = p["scope"].clone();
            if !scope.as_array().is_some_and(|s| s.iter().any(|x| x == "dsip.message")) {
                println!("DROP-GRANT {} from {from}: no dsip.message scope", p["id"]);
                return Ok(());
            }
            self.grants_held.insert(from.clone(), compact(&env));
            self.mls.provider().put_state("grants_held", &json!(self.grants_held)).map_err(Self::state_err)?;
            println!("GRANTED by {from} scope={scope} request={}", p["session"].as_str().unwrap_or(""));
        }
        Ok(())
    }

    async fn upload_key_packages(&mut self, n: usize) -> Result<()> {
        let mut packages = vec![];
        for _ in 0..n {
            packages.push(json!(b64(&self.mls.key_package()?)));
        }
        let last = b64(&self.mls.key_package()?);
        let env = wire::message(&self.keys.device, "key-packages", &self.mailbox.0, now_s(), wire::TTL_S,
            json!({"subject": self.identity, "key_packages": packages, "last_resort": last}));
        self.send(&env).await?;
        println!("OK uploaded {n} key packages");
        Ok(())
    }

    /// Fetch and authenticate a KeyPackage of `target` from its mailbox (M§5.5, M§6.2, M§14.2); with `device`, only
    /// that device's. The identity's own mailbox is asked over the bound connection, so no second binding
    /// displaces it.
    async fn fetch_key_package(&mut self, target: &str, grant: Option<&str>, device: Option<&str>) -> Result<KeyPackage> {
        self.fetch_key_package_for(target, grant, device, None).await
    }

    /// As [`Client::fetch_key_package`]; `successor_of` names the dead group a successor is being created for, which
    /// authorizes the fetch at a mailbox that has it registered (M§7.5, spec-gap 61).
    async fn fetch_key_package_for(&mut self, target: &str, grant: Option<&str>, device: Option<&str>, successor_of: Option<&str>) -> Result<KeyPackage> {
        let mut fields = json!({"target": target});
        if let Some(g) = grant {
            fields["grant"] = json!(g);
        }
        if let Some(g) = successor_of {
            fields["successor_of"] = json!(g);
        }
        let payload = if target == self.identity {
            let env = wire::message(&self.keys.device, "key-package-fetch", &self.mailbox.0, now_s(), wire::TTL_S, fields);
            let id = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)).context("id")?;
            self.send(&env).await?;
            self.await_reply(&id).await?
        } else {
            let mut peer_conn = self.peer_connect(target).await?;
            let env = wire::message(&self.keys.device, "key-package-fetch", &peer_conn.relay.did.clone(), now_s(), wire::TTL_S, fields);
            peer_conn.send(&env).await?;
            let reply = peer_conn.recv().await?.context("no reply to key-package-fetch")?;
            peer_conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "done").await;
            wire::payload_of(&Envelope::from_frame(&reply).map_err(|v| anyhow::anyhow!("{:?}", v.code))?).context("bad reply")?
        };
        if payload["type"] != "key-packages" {
            bail!("key-package-fetch refused: {} {}", payload["type"], payload["reason"]);
        }
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let candidates = payload["key_packages"].as_array().cloned().unwrap_or_default().into_iter().chain(payload.get("last_resort").cloned());
        for c in candidates {
            let Ok((kp, who)) = authenticate_key_package(&unb64(&c), self.mls.provider(), &ctx) else { continue };
            if who.identity == target && device.is_none_or(|d| d == who.device) && who.device != self.keys.device.did() {
                return Ok(kp);
            }
        }
        bail!("no key package for {target}{}", device.map(|d| format!(" device {d}")).unwrap_or_default())
    }

    fn conv(&self, group: &str) -> Result<&Conv> {
        self.convs.get(group).context("not a member of that group")
    }

    fn active(&self) -> Result<String> {
        self.active.clone().context("no conversation")
    }

    fn save_groups(&self) -> Result<()> {
        let p = self.mls.provider();
        p.put_state("groups", &json!(self.convs.keys().collect::<Vec<_>>())).map_err(Self::state_err)?;
        p.put_state("active", &json!(self.active)).map_err(Self::state_err)?;
        p.put_state("personal", &json!(self.personal)).map_err(Self::state_err)
    }

    fn save_archive(&self) -> Result<()> {
        let keys: serde_json::Map<String, Value> =
            self.archive_keys.iter().map(|(a, (k, at))| (a.clone(), json!({"key": b64(k), "created_at": at}))).collect();
        let p = self.mls.provider();
        p.put_state("archive_keys", &Value::Object(keys)).map_err(Self::state_err)?;
        p.put_state("held", &json!(self.held)).map_err(Self::state_err)
    }

    fn new_receipts(&self) -> dsip_messaging::client::Client {
        dsip_messaging::client::Client::new(&json!({"now": now_s(), "me": self.identity, "member_identities": 2, "policy": self.policy}))
    }

    fn add_conv(&mut self, group: MlsGroup, conv: &Value) -> String {
        let gid = b64(group.group_id().as_slice());
        let kind = conv["kind"].as_str().unwrap_or("direct").to_string();
        let hub = (conv["hub"]["did"].as_str().unwrap_or("").to_string(), conv["hub"]["uri"].as_str().unwrap_or("").to_string());
        let c = Conv {
            group,
            conversation: conv["conversation"].as_str().unwrap_or("").to_string(),
            kind: kind.clone(),
            hub,
            receipts: self.new_receipts(),
            last_media: None,
        };
        self.convs.insert(gid.clone(), c);
        if kind == "personal" {
            self.personal = Some(gid.clone());
        } else {
            self.active = Some(gid.clone());
        }
        gid
    }

    /// Deposit to a group's hub through this device's mailbox and wait for the hub's answer (M§5.2, M§9.2). The
    /// delegation rides in the header because a hub reached by forwarding has not seen it (M§5.1).
    async fn hub_deposit(&mut self, group: &str, class: &str, fields: Value) -> Result<Value> {
        let hub = self.conv(group)?.hub.0.clone();
        if let Some(bytes) = fields["mls"].as_str().and_then(dsip_core::b64::decode) {
            self.own.insert(digest(&bytes));
        }
        let env = wire::deposit_delegated(&self.keys.device, vec![self.delegation.clone()], &hub, now_s(), group, class, fields);
        let id = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)).context("deposit id")?;
        self.send(&env).await?;
        let reply = self.await_reply(&id).await?;
        if let Some(seq) = reply["seq"].as_i64() {
            // The hub's `accepted` seq marks this device's own copy as processed (spec-gap 47).
            self.resume.sent(group, seq);
            self.save_resume()?;
        }
        Ok(reply)
    }

    /// Read frames until the answer to `id` arrives, processing everything else as it comes.
    async fn await_reply(&mut self, id: &str) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let conn = self.conn.as_mut().context("offline")?;
            let frame = tokio::time::timeout_at(deadline, conn.recv()).await.context("no answer")??.context("mailbox closed")?;
            let p = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
            if p["in_reply_to"] == json!(id) && p["type"] != "items" {
                return Ok(p);
            }
            if let Err(e) = self.inbound(&frame).await {
                println!("ERR {e}");
            }
        }
    }

    /// Encrypt an application object for a group and deposit it; returns the hub's answer.
    ///
    /// A refusal is handled as the vector-pinned [`CommitRetry`] decides: in particular `mailbox.unknown-group` from a
    /// hub the group has left is followed by a sync and, if it shows the move, the object is encrypted again and sent to
    /// the new hub (M§7.4, spec-gap 60).
    async fn send_object(&mut self, group: &str, obj: &Value, extra: Value) -> Result<Value> {
        let mut retry = CommitRetry::new(&json!({}));
        loop {
            let hub_before = self.conv(group)?.hub.0.clone();
            let c = self.convs.get_mut(group).context("not a member of that group")?;
            let msg = c
                .group
                .create_message(self.mls.provider(), &self.mls.signer(), &serde_json::to_vec(obj)?)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                .tls_serialize_detached()?;
            let mut fields = json!({"mls": b64(&msg)});
            for (k, v) in extra.as_object().into_iter().flatten() {
                fields[k.as_str()] = v.clone();
            }
            let reply = self.hub_deposit(group, "application", fields).await?;
            let reason = (reply["type"] != "accepted").then(|| reply["reason"].as_str().unwrap_or("session.failed").to_string());
            let actions = retry.answer(reason.as_deref());
            if !actions.iter().any(|a| a.get("sync").is_some()) {
                return Ok(reply); // accepted, or surfaced to the caller
            }
            println!("RETRY send: {} from {hub_before}; syncing", reason.as_deref().unwrap_or(""));
            self.sync_all().await?;
            let moved = self.conv(group)?.hub.0 != hub_before;
            if retry.synced(true, moved).iter().any(|a| a.get("surface").is_some()) {
                return Ok(reply);
            }
        }
    }

    /// Build a commit for `op` against the group's current epoch: `(commit, welcome)`.
    fn build_commit(&mut self, group: &str, op: &CommitOp) -> Result<(MlsMessageOut, Option<MlsMessageOut>)> {
        let leaves = match op {
            CommitOp::RemoveIdentity(identity) => self.leaves_where(group, |w| w.identity == *identity)?,
            CommitOp::RemoveDevice(device) => self.device_leaves(group, device)?,
            _ => vec![],
        };
        let c = self.convs.get_mut(group).context("group")?;
        let (provider, signer) = (self.mls.provider(), self.mls.signer());
        let e = |x: &dyn std::fmt::Debug| anyhow::anyhow!("{x:?}");
        Ok(match op {
            CommitOp::Add { kp, .. } => {
                let (commit, welcome, _) = c.group.add_members(provider, &signer, std::slice::from_ref(kp.as_ref())).map_err(|x| e(&x))?;
                (commit, Some(welcome))
            }
            CommitOp::RemoveIdentity(_) | CommitOp::RemoveDevice(_) => {
                let (commit, welcome, _) = c.group.remove_members(provider, &signer, &leaves).map_err(|x| e(&x))?;
                (commit, welcome)
            }
            CommitOp::Update => {
                let (commit, welcome, _) =
                    c.group.self_update(provider, &signer, LeafNodeParameters::default()).map_err(|x| e(&x))?.into_messages();
                (commit, welcome)
            }
            CommitOp::MoveHub(hub) => (self.mls.move_hub_commit(&mut c.group, hub).map_err(|x| e(&x))?, None),
        })
    }

    /// Whether `op` still needs doing after the device caught up with a winning commit (M§6.5 "if still needed").
    fn still_needed(&self, group: &str, op: &CommitOp) -> Result<bool> {
        Ok(match op {
            CommitOp::Add { identity, device, .. } => match device {
                Some(d) => self.device_leaves(group, d)?.is_empty(),
                None => self.leaves_where(group, |w| w.identity == *identity)?.is_empty(),
            },
            CommitOp::RemoveIdentity(identity) => !self.leaves_where(group, |w| w.identity == *identity)?.is_empty(),
            CommitOp::RemoveDevice(device) => !self.device_leaves(group, device)?.is_empty(),
            CommitOp::Update => true,
            CommitOp::MoveHub(hub) => self.conv(group)?.hub.0 != hub["did"].as_str().unwrap_or(""),
        })
    }

    /// Commit `op` to a group, applying it only once the hub has accepted it, and handling refusals as the vector-pinned
    /// [`CommitRetry`] decides (M§6.5, spec-gap 58): a conflict or stale epoch is discarded, the device syncs past the
    /// winning commit and re-proposes while still needed, boundedly; any other refusal is surfaced.
    async fn commit_op(&mut self, group: &str, op: CommitOp, what: &str) -> Result<()> {
        let mut retry = CommitRetry::new(&json!({}));
        loop {
            let hub_before = self.conv(group)?.hub.0.clone();
            let (commit, welcome) = self.build_commit(group, &op)?;
            let epoch = self.conv(group)?.group.epoch().as_u64();
            let mut fields = json!({"mls": b64(&commit.tls_serialize_detached()?)});
            if let Some(w) = welcome {
                fields["welcome"] = json!(b64(&w.tls_serialize_detached()?));
            }
            if let CommitOp::Add { grants, .. } = &op {
                if !grants.is_empty() {
                    fields["grants"] = json!(grants);
                }
            }
            let reply = self.hub_deposit(group, "handshake", fields).await?;
            let reason = (reply["type"] != "accepted").then(|| reply["reason"].as_str().unwrap_or("session.failed").to_string());
            let mut must_sync = false;
            for action in retry.answer(reason.as_deref()) {
                let c = self.convs.get_mut(group).context("group")?;
                if action.get("merge").is_some() {
                    c.group.merge_pending_commit(self.mls.provider()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    println!("OK {what} epoch={} seq={}", c.group.epoch().as_u64(), reply["seq"]);
                    if let CommitOp::MoveHub(hub) = &op {
                        // M§7.4 (spec-gap 60): our mailbox follows the move, then the new hub is bootstrapped with the
                        // GroupInfo and the seq the old hub gave this commit, so it continues the numbering
                        let seq = reply["seq"].as_i64().unwrap_or(0);
                        self.hub_moved(group, hub, seq).await?;
                        return self.publish_group_info_at(group, Some(seq)).await;
                    }
                    return self.publish_group_info(group).await;
                } else if action.get("discard").is_some() {
                    c.group.clear_pending_commit(self.mls.provider().storage()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                } else if let Some(r) = action.get("surface") {
                    bail!("{what} refused by the hub: {}", r.as_str().unwrap_or(""));
                } else if action.get("sync").is_some() {
                    must_sync = true;
                }
            }
            let unknown_group = reason.as_deref() == Some("mailbox.unknown-group");
            if must_sync && unknown_group {
                // spec-gap 60: the hub may have handed the group on; everything stored shows whether it did
                println!("MOVED? {what}: mailbox.unknown-group from {hub_before}; syncing");
                self.sync_all().await?;
            } else if must_sync {
                println!("CONFLICT {what}: {} at epoch {epoch}; syncing past the winning commit", reason.as_deref().unwrap_or(""));
                self.catch_up(group, epoch).await?;
            }
            let needed = self.still_needed(group, &op)?;
            let moved = self.conv(group)?.hub.0 != hub_before;
            for action in retry.synced(needed, moved) {
                if action.get("done").is_some() {
                    println!("OK {what} no longer needed after the winning commit");
                    return Ok(());
                }
                if let Some(r) = action.get("surface") {
                    bail!("{what} refused by the hub: {}", r.as_str().unwrap_or(""));
                }
                if let Some(a) = action.get("repropose") {
                    println!("REPROPOSE {what} attempt={} epoch={}", a["attempt"], self.conv(group)?.group.epoch().as_u64());
                }
            }
        }
    }

    /// The group moved to `hub` (`{did, uri}`) at `seq`: use it from now on and have this identity's mailbox follow, so it
    /// admits the new hub's fan-out and forwards to it (M§7.4, M§6.6; spec-gap 60).
    async fn hub_moved(&mut self, group: &str, hub: &Value, seq: i64) -> Result<()> {
        let (did, uri) = (hub["did"].as_str().unwrap_or("").to_string(), hub["uri"].as_str().unwrap_or("").to_string());
        let c = self.convs.get_mut(group).context("group")?;
        let moved = c.hub.0 != did;
        c.hub = (did.clone(), uri.clone());
        let mut g = json!({"group": group, "state": "joined", "hub": did});
        if uri.starts_with("wss://") {
            g["hub_uri"] = json!(uri);
        }
        if moved {
            g["handover_seq"] = json!(seq);
            println!("HUB-MOVED {} to {did} at seq={seq}", c.conversation);
        }
        let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now_s(), wire::TTL_S,
            json!({"subject": self.identity, "groups": [g]}));
        self.send(&env).await
    }

    /// Sync and process everything stored, until the mailbox has no more (M§5.4).
    async fn sync_all(&mut self) -> Result<()> {
        self.sync(false).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let conn = self.conn.as_mut().context("offline")?;
            let frame = tokio::time::timeout_at(deadline, conn.recv()).await.context("sync never completed")??.context("mailbox closed")?;
            let p = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
            let last_page = p["type"] == "items" && p["in_reply_to"].is_string() && p["next"].is_null();
            if let Err(e) = self.inbound(&frame).await {
                println!("ERR {e}");
            }
            if last_page {
                return Ok(());
            }
        }
    }

    /// Sync and process frames until the group has moved past `epoch` (the winning commit is applied).
    async fn catch_up(&mut self, group: &str, epoch: u64) -> Result<()> {
        self.sync(false).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        while self.conv(group)?.group.epoch().as_u64() <= epoch {
            let conn = self.conn.as_mut().context("offline")?;
            let frame = tokio::time::timeout_at(deadline, conn.recv()).await.context("the winning commit never arrived")??.context("mailbox closed")?;
            if let Err(e) = self.inbound(&frame).await {
                println!("ERR {e}");
            }
        }
        Ok(())
    }

    /// Republish the GroupInfo after a commit, for the hub and for external joins (M§6.5 rule 6, M§6.8).
    async fn publish_group_info(&mut self, group: &str) -> Result<()> {
        self.publish_group_info_at(group, None).await
    }

    /// The GroupInfo deposit; `handover_seq` bootstraps a group's new hub (M§7.4, spec-gap 60).
    async fn publish_group_info_at(&mut self, group: &str, handover_seq: Option<i64>) -> Result<()> {
        let c = self.conv(group)?;
        let gi = c.group.export_group_info(self.mls.provider().crypto(), &self.mls.signer(), true).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut fields = json!({"mls": b64(&gi.tls_serialize_detached()?)});
        if let Some(h) = handover_seq {
            fields["handover_seq"] = json!(h);
        }
        let reply = self.hub_deposit(group, "group-info", fields).await?;
        anyhow::ensure!(reply["type"] == "accepted", "group-info refused: {}", reply["reason"]);
        Ok(())
    }

    /// Create a group hubbed at this identity's own mailbox (M§6.5 rule 6, M§6.6).
    async fn new_group(&mut self, kind: &str) -> Result<String> {
        let conversation = wire::new_id(now_s());
        self.new_group_for(&conversation, kind, None).await
    }

    /// A group for `conversation`, hubbed at this identity's mailbox; `successor_of` for a successor group (M§7.5).
    async fn new_group_for(&mut self, conversation: &str, kind: &str, successor_of: Option<&str>) -> Result<String> {
        let now = now_s();
        let group_id = wire::new_id(now).into_bytes();
        let conv = json!({"conversation": conversation, "kind": kind, "hub": {"did": self.mailbox.0, "uri": self.mailbox.1}, "successor_of": successor_of});
        let group = self.mls.create_group(&group_id, &serde_json::to_vec(&conv)?).map_err(|e| anyhow::anyhow!("{e}"))?;
        let gid = self.add_conv(group, &conv);
        self.save_groups()?;
        // Our own mailbox hubs the group and must admit its fan-out for us (M§6.6).
        let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S,
            json!({"subject": self.identity, "groups": [{"group": gid, "state": "joined", "hub": self.mailbox.0}]}));
        self.send(&env).await?;
        self.publish_group_info(&gid).await?;
        println!("OK conversation {conversation} kind={kind}");
        Ok(gid)
    }

    /// Create a conversation of `kind` with `peer` (M§7.2, M§7.3), presenting a held grant when none is given.
    async fn create(&mut self, kind: &str, peer: &str, grant: Option<String>) -> Result<()> {
        let grant = grant.or_else(|| self.grants_held.get(peer).cloned());
        let kp = self.fetch_key_package(peer, grant.as_deref(), None).await?;
        let gid = self.new_group(kind).await?;
        self.add(&gid, peer, grant, Some(kp)).await
    }

    /// The personal group and the first archive key (M§7.1, M§12.1).
    async fn create_personal(&mut self) -> Result<()> {
        anyhow::ensure!(self.personal.is_none(), "this identity already has a personal group here");
        let gid = self.new_group("personal").await?;
        self.rotate_archive_key(&gid).await
    }

    /// Create an archive key and send it to the personal group (M§12.1, M§12.4).
    async fn rotate_archive_key(&mut self, personal: &str) -> Result<()> {
        let now = now_s();
        let akid = wire::new_id(now);
        let key: [u8; 32] = rand::random();
        self.store_archive_key(&akid, key, now)?;
        let obj = json!({"object": "archive-key", "akid": akid, "key": b64(&key), "created_at": now});
        let reply = self.send_object(personal, &obj, json!({})).await?;
        anyhow::ensure!(reply["type"] == "accepted", "archive key refused: {}", reply["reason"]);
        println!("OK archive-key {akid}");
        Ok(())
    }

    fn store_archive_key(&mut self, akid: &str, key: [u8; 32], created_at: i64) -> Result<()> {
        self.archive_keys.insert(akid.to_string(), (key, created_at));
        self.history.step(&json!({"archive_key": {"akid": akid, "created_at": created_at}}));
        self.save_archive()
    }

    /// Add `peer` to a conversation: the hub fans the welcome out with our deposit as `origin` (M§7.3, M§14.2).
    /// Refresh the tracker's rosters (by identity) from the groups this device is in (M§7.5: "last known roster").
    fn track_rosters(&mut self) {
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        for (gid, c) in &self.convs {
            if let Ok(members) = authenticate_members(&c.group, &ctx) {
                let mut ids: Vec<String> = members.into_iter().map(|m| m.identity).collect();
                ids.sort();
                ids.dedup();
                self.successors.member_of(gid, &ids);
            }
        }
    }

    fn save_successors(&self) -> Result<()> {
        let v = serde_json::to_value(&self.successors)?;
        self.mls.provider().put_state("successors", &v).map_err(Self::state_err)
    }

    /// Stop taking part in a group: forget it here and unregister it at the mailbox (M§5.7, M§7.5).
    async fn leave_group(&mut self, gid: &str, why: &str) -> Result<()> {
        let Some(c) = self.convs.remove(gid) else { return Ok(()) };
        println!("LEFT group={gid} conversation={} ({why})", c.conversation);
        if self.active.as_deref() == Some(gid) {
            self.active = self.convs.iter().find(|(_, c)| c.kind != "personal").map(|(g, _)| g.clone());
        }
        self.save_groups()?;
        let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now_s(), wire::TTL_S,
            json!({"subject": self.identity, "groups": [{"group": gid, "state": "left"}]}));
        self.send(&env).await
    }

    /// Act on what the successor tracker decided (spec-gap 61).
    async fn apply_successor(&mut self, emissions: Vec<Value>, of: &str) -> Result<()> {
        self.save_successors()?;
        for e in emissions {
            if let Some(g) = e["join"].as_str() {
                println!("SUCCESSOR joined group={g} of={of}");
                self.active = Some(g.to_string());
                self.save_groups()?;
            } else if let Some(g) = e["leave"].as_str().or(e["decline"].as_str()) {
                self.leave_group(g, &format!("successor of {of} converged elsewhere")).await?;
            } else if let Some(g) = e["first_contact"].as_str() {
                // M§7.5: not a valid successor; its mailbox admitted it only as one, so it is not kept
                self.leave_group(g, "not a valid successor: first contact required").await?;
            }
        }
        // The conversation continues in the successor converged on, never in the dead group or a left one.
        if let Some(w) = self.successors.successor(of).filter(|w| self.convs.contains_key(*w)).map(String::from) {
            if self.active.as_deref() != Some(w.as_str()) {
                self.active = Some(w);
                self.save_groups()?;
            }
        }
        Ok(())
    }

    /// Create a successor for the active group, whose hub is gone: same conversation, this mailbox as hub, the last
    /// known roster re-added (M§7.5). If a successor already exists, use it instead.
    async fn create_successor(&mut self) -> Result<()> {
        let pred = self.active()?;
        self.track_rosters();
        let decision = self.successors.step(&json!({"create": {"predecessor": pred}}));
        let Some(d) = decision.first() else { bail!("successor tracker said nothing") };
        if let Some(g) = d["use"].as_str() {
            println!("SUCCESSOR exists group={g} of={pred}");
            self.active = Some(g.to_string());
            return self.save_groups();
        }
        let Some(create) = d.get("create") else { bail!("successor refused: {}", d["refuse"]) };
        let (conversation, kind) = {
            let c = self.conv(&pred)?;
            (c.conversation.clone(), c.kind.clone())
        };
        let gid = self.new_group_for(&conversation, &kind, Some(&pred)).await?;
        println!("SUCCESSOR created group={gid} of={pred}");
        let emissions = self.successors.step(&json!({"created": {"group": gid, "successor_of": pred}}));
        self.apply_successor(emissions, &pred).await?;
        let others: Vec<String> = create["roster"].as_array().into_iter().flatten().filter_map(Value::as_str)
            .filter(|i| *i != self.identity).map(String::from).collect();
        for peer in others {
            if !self.convs.contains_key(&gid) {
                return Ok(()); // a lower successor arrived meanwhile and this one was left
            }
            match self.fetch_key_package_for(&peer, None, None, Some(&pred)).await {
                Ok(kp) => {
                    let op = CommitOp::Add { kp: Box::new(kp), grants: vec![], identity: peer.clone(), device: None };
                    if let Err(e) = self.commit_op(&gid, op, &format!("added {peer}")).await {
                        if !self.convs.contains_key(&gid) {
                            return Ok(()); // converged on another successor while adding
                        }
                        println!("ERR successor add {peer}: {e}");
                    }
                }
                Err(e) => println!("ERR successor add {peer}: {e}"),
            }
        }
        Ok(())
    }

    async fn add(&mut self, group: &str, peer: &str, grant: Option<String>, kp: Option<KeyPackage>) -> Result<()> {
        let kp = match kp {
            Some(k) => k,
            None => self.fetch_key_package(peer, grant.as_deref(), None).await?,
        };
        let op = CommitOp::Add { kp: Box::new(kp), grants: grant.into_iter().collect(), identity: peer.to_string(), device: None };
        self.commit_op(group, op, &format!("added {peer}")).await
    }

    fn leaves_where(&self, group: &str, pred: impl Fn(&dsip_messaging::mls_wire::LeafIdentity) -> bool) -> Result<Vec<LeafNodeIndex>> {
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let c = self.conv(group)?;
        Ok(c.group.members().filter(|m| member_identity(&c.group, m.index, &ctx).is_ok_and(|w| pred(&w))).map(|m| m.index).collect())
    }

    /// The leaves whose credential names `device`, whether or not their delegation still verifies.
    fn device_leaves(&self, group: &str, device: &str) -> Result<Vec<LeafNodeIndex>> {
        let c = self.conv(group)?;
        Ok(c.group
            .members()
            .filter(|m| BasicCredential::try_from(m.credential.clone()).is_ok_and(|b| b.identity() == device.as_bytes()))
            .map(|m| m.index)
            .collect())
    }

    /// Remove every leaf of `identity` from the active conversation (M§7.3).
    async fn remove(&mut self, identity: &str) -> Result<()> {
        let group = self.active()?;
        anyhow::ensure!(!self.leaves_where(&group, |w| w.identity == identity)?.is_empty(), "{identity} is not a member");
        self.commit_op(&group, CommitOp::RemoveIdentity(identity.to_string()), &format!("removed {identity}")).await
    }

    /// M§12.3: add a new device of this identity, first to the personal group (re-sending every archive key in the
    /// epoch after the commit), then to each conversation group.
    async fn add_device(&mut self, device: &str) -> Result<()> {
        let personal = self.personal.clone().context("no personal group: create it first (M§7.1)")?;
        let mut order = vec![personal.clone()];
        order.extend(self.convs.keys().filter(|g| **g != personal).cloned());
        for group in order {
            let kp = self.fetch_key_package(&self.identity.clone(), None, Some(device)).await?;
            let what = format!("added device {device} to {}", self.conv(&group)?.kind);
            let op = CommitOp::Add { kp: Box::new(kp), grants: vec![], identity: self.identity.clone(), device: Some(device.to_string()) };
            self.commit_op(&group, op, &what).await?;
            if group == personal {
                // M§12.3 step 3: a new member cannot read earlier epochs, so every live archive key is re-sent.
                let keys: Vec<(String, [u8; 32], i64)> = self.archive_keys.iter().map(|(a, (k, t))| (a.clone(), *k, *t)).collect();
                for (akid, key, at) in keys {
                    let obj = json!({"object": "archive-key", "akid": akid, "key": b64(&key), "created_at": at});
                    self.send_object(&personal, &obj, json!({})).await?;
                }
                println!("OK re-sent {} archive key(s)", self.archive_keys.len());
            }
        }
        Ok(())
    }

    /// Revoke a device's delegation (spec-gap 57): a `delegation-revocation` signed by the identity key, published in
    /// the identity's DID document (authoritative, §8.1) and sent to its mailbox, which closes the device's binding.
    async fn revoke_device(&mut self, device: &str) -> Result<()> {
        let now = now_s();
        let p = json!({"dsip": wire::version_block(), "type": "delegation-revocation", "id": wire::new_id(now), "from": self.identity,
            "subject": self.identity, "device": device, "revoked_at": now, "reason": "lost", "issued_at": now, "expires_at": now + 300});
        let rev = sign(&p, &self.keys.controller, &format!("{}#key-1", self.identity));
        // Publish: the identity's document is one of the files this device resolves from.
        let doc_file = self.resolver_files.iter().find(|f| {
            std::fs::read_to_string(f).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).is_some_and(|d| d["id"] == json!(self.identity))
        });
        let doc_file = doc_file.cloned().context("this identity's DID document is not among --resolver-file")?;
        let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&doc_file)?)?;
        let list = doc.as_object_mut().context("document")?.entry("dsipDelegationRevocations").or_insert(json!([]));
        list.as_array_mut().context("revocations")?.push(json!(compact(&rev)));
        std::fs::write(&doc_file, serde_json::to_string_pretty(&doc)?)?;
        let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S,
            json!({"subject": self.identity, "revoked_delegations": [compact(&rev)]}));
        let id = wire::payload_of(&env).and_then(|q| q["id"].as_str().map(String::from)).context("id")?;
        self.send(&env).await?;
        let reply = self.await_reply(&id).await?;
        anyhow::ensure!(reply["type"] == "accepted", "mailbox refused the revocation: {}", reply["reason"]);
        println!("OK revoked {device} published={} mailbox=accepted", doc_file.display());
        Ok(())
    }

    /// M§7.3, M§12.4: remove another member's leaf whose delegation no longer verifies (any member MAY). Refused
    /// locally while it still verifies: then only its own identity may remove it.
    async fn remove_leaf(&mut self, device: &str) -> Result<()> {
        let group = self.active()?;
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let c = self.conv(&group)?;
        let leaf = c
            .group
            .members()
            .find(|m| BasicCredential::try_from(m.credential.clone()).is_ok_and(|b| b.identity() == device.as_bytes()))
            .context("no leaf for that device")?;
        if member_identity(&c.group, leaf.index, &ctx).is_ok() {
            bail!("the leaf's delegation still verifies: only its own identity may remove it (M§7.3)");
        }
        self.commit_op(&group, CommitOp::RemoveDevice(device.to_string()), &format!("removed lapsed leaf {device}")).await
    }

    /// M§12.4: remove a device of this identity from every group, then rotate the archive key.
    async fn remove_device(&mut self, device: &str) -> Result<()> {
        let personal = self.personal.clone().context("no personal group")?;
        let groups: Vec<String> = self.convs.keys().cloned().collect();
        for group in groups {
            // By credential, not by authentication: a revoked device's leaf no longer authenticates (spec-gap 57).
            let leaves = self.device_leaves(&group, device)?;
            if leaves.is_empty() {
                continue;
            }
            let what = format!("removed device {device} from {}", self.conv(&group)?.kind);
            self.commit_op(&group, CommitOp::RemoveDevice(device.to_string()), &what).await?;
        }
        self.rotate_archive_key(&personal).await
    }

    /// Send an Ogg Opus recording: seal, upload, reference (M§8.2, M§8.4, M§5.6).
    async fn send_audio(&mut self, path: &str, purpose: &str, session: Option<String>, max_duration_s: Option<i64>) -> Result<()> {
        let group = self.active()?;
        let conversation = self.conv(&group)?.conversation.clone();
        let plain = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        let duration_ms = ogg_opus_duration_ms(&plain).context("not an Ogg Opus file")?;
        if let Some(max) = max_duration_s {
            // M§13.2: recording stops at the callee's max_duration_s.
            anyhow::ensure!(duration_ms <= max * 1000, "recording is {duration_ms} ms, over the callee's {max} s");
        }
        // M§8.4 rule 1: a fresh single-use key, AES-256-GCM, nonce ‖ ciphertext ‖ tag.
        let key: [u8; 32] = rand::random();
        let nonce: [u8; 12] = rand::random();
        let sealed = seal(&key, &nonce, &plain, SealUse::Blob);
        let sha = digest(&sealed);
        let conn = self.conn.as_ref().context("offline")?;
        let endpoint = conn.relay.capabilities["mailbox"]["blob_endpoint"].as_str().context("mailbox advertises no blob_endpoint")?;
        let uri = format!("{endpoint}/{sha}");
        // M§5.6: one upload, authorized by a signed blob-put carrying the device's delegation.
        let auth = wire::message_delegated(&self.keys.device, vec![self.delegation.clone()], "blob-put", &self.mailbox.0, now_s(),
            wire::TTL_S, json!({"sha256": sha, "size": sealed.len()}));
        let resp = self.http.put(&uri).header("Authorization", format!("DSIP {}", compact(&auth))).body(sealed.clone()).send().await?;
        let status = resp.status().as_u16();
        let answer = Envelope::from_frame(&resp.text().await?).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
        anyhow::ensure!(matches!(status, 200 | 201) && answer["type"] == "accepted", "blob upload refused: {status} {}", answer["reason"]);

        let now = now_s();
        let mut obj = json!({"object": "content", "id": wire::new_id(now), "conversation": conversation,
            "sender": self.identity, "sent_at": now, "kind": "audio", "purpose": purpose, "duration_ms": duration_ms,
            "blob": {"uri": uri, "sha256": sha, "size": sealed.len(), "key": b64(&key), "alg": "A256GCM",
                     "content_type": "audio/ogg; codecs=opus"}});
        if let Some(s) = session {
            obj["session"] = json!(s);
        }
        // M§8.4 rule 4: the deposit's manifest names the blob without its key.
        let manifest = json!([{"uri": uri, "sha256": sha, "size": sealed.len()}]);
        let reply = self.send_object(&group, &obj, json!({"blobs": manifest})).await?;
        self.sent(&group, &reply, &obj);
        match reply["type"].as_str() {
            Some("accepted") => println!("OK sent audio purpose={purpose} duration_ms={duration_ms} blob={sha} seq={}", reply["seq"]),
            _ => println!("ERR send refused: {}", reply["reason"]),
        }
        Ok(())
    }

    /// M§13.2: after a call attempt to the conversation's peer ended with `reason`, may we leave a voicemail?
    async fn voicemail(&mut self, session: &str, reason: &str, path: &str) -> Result<()> {
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let group = self.active()?;
        let peer = authenticate_members(&self.conv(&group)?.group, &ctx)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .into_iter()
            .map(|m| m.identity)
            .find(|i| *i != self.identity)
            .context("no callee in the conversation")?;
        let doc = dsip_core::did::Resolver::resolve(&r, &peer).with_context(|| format!("no document for {peer}"))?;
        let entry = doc.service.iter().find(|s| s.service_type == "DSIPMailbox").map(|s| s.service_endpoint.clone()).unwrap_or_default();
        let outcome_type = if reason == "session.timeout" { "cancel" } else { "reject" };
        let offer = dsip_messaging::client::voicemail_offer(&json!({"voicemail": entry["voicemail"], "can_send": true,
            "outcome": {"type": outcome_type, "reason": reason}}));
        if offer["offer"] != json!(true) {
            println!("NO-OFFER {reason}");
            return Ok(());
        }
        println!("OFFER {reason} max_duration_s={}", offer["max_duration_s"]);
        self.send_audio(path, "voicemail", Some(session.to_string()), offer["max_duration_s"].as_i64()).await
    }

    /// Fetch, verify and decrypt a content object's blob into `--state`/media (M§8.4 rule 7).
    async fn fetch_media(&self, object: &Value) -> Result<(PathBuf, String)> {
        let b = &object["blob"];
        let uri = b["uri"].as_str().context("blob without uri")?;
        let key: [u8; 32] = unb64(&b["key"]).try_into().ok().context("blob key")?;
        let resp = self.http.get(uri).send().await?;
        anyhow::ensure!(resp.status().is_success(), "GET {uri}: {}", resp.status());
        let stored = resp.bytes().await?;
        let plain = dsip_messaging::mls_wire::open_blob(&key, &stored, b["size"].as_u64().unwrap_or(0) as usize, b["sha256"].as_str().unwrap_or(""))
            .map_err(|c| anyhow::anyhow!("{c}"))?;
        let dir = self.state.join("media");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.ogg", object["id"].as_str().unwrap_or("blob")));
        std::fs::write(&path, &plain)?;
        Ok((path, digest(&plain)))
    }

    /// Our own content, accepted by the hub: known to the receipt rules (M§10.2) and archived (M§12.2, spec-gap 51).
    fn sent(&mut self, group: &str, reply: &Value, obj: &Value) {
        if reply["type"] != "accepted" {
            return;
        }
        self.tick();
        if let Some(c) = self.convs.get_mut(group) {
            c.receipts.step(&json!({"sync": {"items": [{"seq": reply["seq"], "object": obj}]}}));
        }
        let key = object_key(obj);
        self.lines.insert(key.clone(), format!("{}: {}", self.identity, display(obj)));
        let emissions = self.history.step(&json!({"sent": {"group": group, "seq": reply["seq"], "id": key}}));
        self.archive_requests(group, &emissions, obj, &self.identity.clone(), &self.keys.device.did(), reply["seq"].as_i64().unwrap_or(0));
    }

    /// Queue archive records the history machine asked for (M§12.2).
    fn archive_requests(&mut self, group: &str, emissions: &[Value], obj: &Value, sender: &str, sender_device: &str, seq: i64) {
        let Some(conversation) = self.convs.get(group).map(|c| c.conversation.clone()) else { return };
        for e in emissions {
            if let Some(a) = e.get("archive") {
                let record = json!({"object": "archive-record", "conversation": conversation, "group": group, "seq": seq,
                    "sender": sender, "sender_device": sender_device, "received_at": now_s(), "payload": obj});
                self.outbox.push((group.to_string(), json!({"archive": {"akid": a["akid"], "record": record}})));
            }
        }
    }

    /// Advance each conversation's receipt machine to wall time; report indicators that expired (M§10.3, M§11.2).
    fn tick(&mut self) {
        let now = now_s();
        for (gid, c) in self.convs.iter_mut() {
            let before = c.receipts.snapshot()["activity"].clone();
            let delta = now - c.receipts.now();
            if delta > 0 {
                let emissions = c.receipts.step(&json!({"advance": delta}));
                self.outbox.extend(emissions.into_iter().map(|e| (gid.clone(), e)));
            }
            let after = &c.receipts.snapshot()["activity"];
            for (who, acts) in before.as_object().into_iter().flatten() {
                for a in acts.as_object().into_iter().flatten().map(|(a, _)| a) {
                    if after[who.as_str()].get(a).is_none() {
                        println!("ACTIVITY-CLEARED {who} {a}");
                    }
                }
            }
        }
    }

    /// Send what the machines emitted: receipts as MLS application messages (an undisclosed read watermark to the
    /// personal group), activity as sealed ephemeral deposits, archive records to the mailbox. Never called while a
    /// frame is being processed.
    async fn flush_outbox(&mut self) -> Result<()> {
        while !self.outbox.is_empty() {
            let (group, e) = self.outbox.remove(0);
            if let Some(a) = e.get("archive") {
                self.deposit_archive(&group, a).await?;
                continue;
            }
            let send = &e["send"];
            if let Some(a) = send["activity"].as_str() {
                self.send_activity(&group, a, send["state"].as_str().unwrap_or("active")).await?;
                continue;
            }
            let kind = send["receipt"].as_str().unwrap_or("").to_string();
            let conversation = self.conv(&group)?.conversation.clone();
            let target = if send["to"] == "personal" {
                // M§10.5: an undisclosed watermark goes only to this identity's personal group (spec-gap 52).
                match self.personal.clone() {
                    Some(p) => p,
                    None => {
                        println!("READ-PRIVATE through={} (no personal group: kept on this device)", send["through"]);
                        continue;
                    }
                }
            } else {
                group.clone()
            };
            let now = now_s();
            let mut obj = json!({"object": "receipt", "id": wire::new_id(now), "conversation": conversation,
                "sender": self.identity, "sent_at": now, "kind": kind});
            for k in ["targets", "through"] {
                if let Some(v) = send.get(k) {
                    obj[k] = v.clone();
                }
            }
            let reply = self.send_object(&target, &obj, json!({})).await?;
            let what = if kind == "read" { obj["through"].clone() } else { obj["targets"].clone() };
            let via = if target == group { "" } else { " (personal group)" };
            match reply["type"].as_str() {
                Some("accepted") => println!("SENT-RECEIPT {kind} {what}{via}"),
                _ => println!("ERR receipt refused: {}", reply["reason"]),
            }
        }
        Ok(())
    }

    /// Seal an archive record under its key, AAD `group_id ‖ seq`, and deposit it to this identity's mailbox (M§12.2).
    async fn deposit_archive(&mut self, group: &str, a: &Value) -> Result<()> {
        let akid = a["akid"].as_str().unwrap_or("").to_string();
        let Some((key, _)) = self.archive_keys.get(&akid).copied() else { return Ok(()) };
        let record = &a["record"];
        let seq = record["seq"].as_u64().unwrap_or(0);
        let group_bytes = dsip_core::b64::decode(group).context("group id")?;
        let nonce: [u8; 12] = rand::random();
        let sealed = seal(&key, &nonce, &serde_json::to_vec(record)?, SealUse::Archive { group: &group_bytes, seq });
        let env = wire::deposit_delegated(&self.keys.device, vec![self.delegation.clone()], &self.mailbox.0, now_s(), group, "archive",
            json!({"archive": b64(&sealed), "akid": akid, "ref_group": group, "ref_seq": seq}));
        self.send(&env).await?;
        println!("ARCHIVED seq={seq} akid={akid}");
        Ok(())
    }

    /// Seal and deposit one activity (M§11.1): signed by the device key, AES-256-GCM under the epoch's exporter
    /// key, AAD `group_id ‖ epoch`, 10 s lifetime, no `accepted` expected.
    async fn send_activity(&mut self, group: &str, activity: &str, state: &str) -> Result<()> {
        let c = self.conv(group)?;
        let obj = json!({"object": "activity", "conversation": c.conversation, "sender": self.identity, "activity": activity, "state": state});
        let signed = sign(&obj, &self.keys.device, &self.keys.device.kid());
        let key = dsip_mls::activity_key(&c.group, self.mls.provider()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let nonce: [u8; 12] = rand::random();
        let use_ = SealUse::Activity { group: c.group.group_id().as_slice(), epoch: c.group.epoch().as_u64() };
        let sealed = seal(&key, &nonce, compact(&signed).as_bytes(), use_);
        let env = wire::deposit_delegated(&self.keys.device, vec![self.delegation.clone()], &c.hub.0.clone(), now_s(), group,
            "ephemeral", json!({"sealed": b64(&sealed)}));
        self.send(&env).await?;
        println!("SENT-ACTIVITY {activity} {state}");
        Ok(())
    }

    /// Open a pushed activity: the epoch's exporter key, then the device signature, then the leaf it belongs to.
    fn activity_in(&mut self, item: &Value) -> Result<()> {
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let gid = item["group"].as_str().unwrap_or("").to_string();
        let Some(c) = self.convs.get(&gid) else { return Ok(()) };
        let sealed = unb64(&item["sealed"]);
        let key = dsip_mls::activity_key(&c.group, self.mls.provider()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let use_ = SealUse::Activity { group: c.group.group_id().as_slice(), epoch: c.group.epoch().as_u64() };
        let Ok(plain) = open(&key, &sealed, use_) else {
            println!("DROP activity: not sealed for this epoch");
            return Ok(());
        };
        let Ok(ver) = dsip_core::envelope::verify_raw(&from_compact(&String::from_utf8(plain).unwrap_or_default()), &ctx, false) else {
            println!("DROP activity: bad signature");
            return Ok(());
        };
        // M§11.1: the signature attributes it; the signing device must be a leaf of the group.
        let leaf = c.group.members().filter_map(|m| member_identity(&c.group, m.index, &ctx).ok()).find(|w| w.device == ver.signer_did).map(|w| w.identity);
        let octx = json!({"conversation": c.conversation, "conversation_kind": c.kind, "leaf_identity": leaf});
        let obj = ver.payload;
        if check_object(&obj, &octx)["verdict"] != "accept" {
            println!("DROP activity from {}: not a member's device", ver.signer_did);
            return Ok(());
        }
        self.tick();
        if let Some(c) = self.convs.get_mut(&gid) {
            c.receipts.step(&json!({"activity_in": {"sender": obj["sender"], "activity": obj["activity"], "state": obj["state"], "expires_at": item["expires_at"]}}));
        }
        println!("ACTIVITY {} {} {}", obj["sender"].as_str().unwrap_or(""), obj["activity"].as_str().unwrap_or(""), obj["state"].as_str().unwrap_or(""));
        Ok(())
    }

    async fn send_text(&mut self, text: &str) -> Result<()> {
        let group = self.active()?;
        let now = now_s();
        let obj = json!({"object": "content", "id": wire::new_id(now), "conversation": self.conv(&group)?.conversation,
            "sender": self.identity, "sent_at": now, "kind": "text", "purpose": "message", "content_type": "text/plain", "text": text});
        let reply = self.send_object(&group, &obj, json!({})).await?;
        self.sent(&group, &reply, &obj);
        match reply["type"].as_str() {
            Some("accepted") => println!("OK sent seq={}", reply["seq"]),
            _ => println!("ERR send refused: {}", reply["reason"]),
        }
        Ok(())
    }

    async fn sync(&mut self, live: bool) -> Result<()> {
        // M§5.4: `ack_through` is the last committed item, never ahead of it (spec-gap 44).
        let mut fields = self.resume.sync_fields();
        fields["live"] = json!(live);
        let env = wire::message(&self.keys.device, "sync", &self.mailbox.0, now_s(), wire::TTL_S, fields);
        self.send(&env).await
    }

    /// Process one inbound frame from the mailbox.
    async fn inbound(&mut self, frame: &str) -> Result<()> {
        let env = Envelope::from_frame(frame).map_err(|v| anyhow::anyhow!("{:?}", v.code))?;
        let p = wire::payload_of(&env).context("bad frame")?;
        match p["type"].as_str().unwrap_or("") {
            "items" => {
                for item in p["items"].as_array().into_iter().flatten() {
                    self.item(item).await?;
                }
                // M§10.2: receipts are decided once per batch (a live push is a batch of one), per conversation.
                if !self.batch.is_empty() {
                    let batch = std::mem::take(&mut self.batch);
                    self.tick();
                    let mut by_group: BTreeMap<String, Vec<Value>> = BTreeMap::new();
                    for (g, it) in batch {
                        by_group.entry(g).or_default().push(it);
                    }
                    for (g, items) in by_group {
                        if let Some(c) = self.convs.get_mut(&g) {
                            let emissions = c.receipts.step(&json!({"sync": {"items": items}}));
                            self.outbox.extend(emissions.into_iter().map(|e| (g.clone(), e)));
                        }
                    }
                }
                if p["next"].is_string() {
                    self.sync(false).await?;
                }
            }
            "accepted" => {}
            "error" if p["reason"] == "mailbox.cursor-invalid" => {
                // M§5.4: re-sync from null; seq positions make the redelivery collapse (M§8.5).
                self.resume.cursor_invalid();
                self.save_resume()?;
                println!("RESYNC from null");
                self.sync(false).await?;
            }
            "error" => println!("ERR {} {}", p["reason"], p["detail"]),
            other => println!("?? {other}"),
        }
        Ok(())
    }

    fn save_resume(&self) -> Result<()> {
        self.mls.provider().put_state("resume", &self.resume.snapshot()).map_err(Self::state_err)
    }

    /// An archive item (M§12.2): opened and shown once, or kept until its key arrives (spec-gap 51).
    fn archive_in(&mut self, item: &Value) -> Result<()> {
        let akid = item["akid"].as_str().unwrap_or("").to_string();
        if !self.archive_keys.contains_key(&akid) {
            let cursor = item["cursor"].as_str().unwrap_or("").to_string();
            self.held.insert(cursor.clone(), item.clone());
            self.resume.commit(item, false);
            let p = self.mls.provider();
            p.atomically(|| {
                p.put_state("held", &json!(self.held))?;
                p.put_state("resume", &self.resume.snapshot())
            })
            .map_err(Self::state_err)?;
            println!("HELD archive {cursor} akid={akid}");
            return Ok(());
        }
        self.open_archive(item);
        self.resume.commit(item, false);
        self.save_resume()
    }

    fn open_archive(&mut self, item: &Value) {
        let akid = item["akid"].as_str().unwrap_or("");
        let Some((key, _)) = self.archive_keys.get(akid).copied() else { return };
        let group = item["group"].as_str().unwrap_or("").to_string();
        let seq = item["seq"].as_u64().unwrap_or(0);
        let group_bytes = dsip_core::b64::decode(&group).unwrap_or_default();
        let Ok(plain) = open(&key, &unb64(&item["archive"]), SealUse::Archive { group: &group_bytes, seq }) else {
            println!("DROP archive {}: does not open for group/seq", item["cursor"]);
            return;
        };
        let Ok(record) = serde_json::from_slice::<Value>(&plain) else { return };
        let obj = &record["payload"];
        let key_id = object_key(obj);
        let e = self.history.step(&json!({"archive": {"cursor": item["cursor"], "akid": akid, "group": group, "seq": seq, "id": key_id}}));
        if e.iter().any(|x| x.get("show").is_some()) {
            let line = format!("{}: {}", record["sender"].as_str().unwrap_or(""), display(obj));
            println!("HISTORY seq={seq} {line}");
            self.lines.insert(key_id, line);
        }
    }

    /// Process one item and commit it with the delivery state, or not at all (M§5.4, spec-gap 44).
    async fn item(&mut self, item: &Value) -> Result<()> {
        let cursor = item["cursor"].as_str().unwrap_or("").to_string();
        let class = item["class"].as_str().unwrap_or("").to_string();
        if class == "ephemeral" {
            // Never stored, no cursor: nothing to commit (M§11.2).
            return self.activity_in(item);
        }
        if self.resume.is_duplicate(item) {
            // M§8.5: already durably processed; collapse silently, but acknowledge it.
            self.resume.commit(item, true);
            self.save_resume()?;
            println!("DUP {class} {cursor}");
            return Ok(());
        }
        if class == "archive" {
            return self.archive_in(item);
        }
        if matches!(class.as_str(), "introduction" | "grant") {
            self.first_contact_in(item)?;
            self.resume.commit(item, false);
            return self.save_resume();
        }
        if !matches!(class.as_str(), "welcome" | "handshake" | "application") {
            self.resume.commit(item, false);
            return self.save_resume();
        }
        let gid = item["group"].as_str().unwrap_or("").to_string();
        let bytes = unb64(&item["mls"]);
        if class != "welcome" && self.own.contains(&digest(&bytes)) {
            // Our own deposit fanned back to our identity (M§6.5 rule 5); arrived before its `accepted` (spec-gap 47).
            self.resume.commit(item, false);
            self.save_resume()?;
            println!("SELF {class} seq={}", item["seq"]);
            return Ok(());
        }
        if class != "welcome" {
            // M§12.3 step 5: MLS items from before this device joined the group are history, read from archive.
            let pre = match message_header(&bytes) {
                Ok((_, epoch, _)) => !self.convs.contains_key(&gid) || self.history.is_prejoin(&gid, epoch as i64),
                Err(_) => false,
            };
            if pre {
                self.resume.commit(item, false);
                self.save_resume()?;
                println!("PREJOIN {class} seq={}", item["seq"]);
                return Ok(());
            }
        }
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let before = self.resume.clone();
        let crash = std::mem::take(&mut self.crash_next);
        let mut slot = if class == "welcome" { None } else { self.convs.remove(&gid) };
        let (mls, resume) = (&self.mls, &mut self.resume);
        let result = mls.provider().atomically(|| {
            let target = slot.as_mut().map(|c| {
                let Conv { group, conversation, kind, .. } = c;
                (group, conversation.as_str(), kind.as_str())
            });
            let outcome = process(mls, target, &class, &bytes, &ctx)?;
            if crash {
                // Processed, MLS state written inside the transaction, never committed.
                println!("CRASH {class} {cursor} processed, not committed");
                let _ = std::io::stdout().flush();
                std::process::exit(137);
            }
            // A sibling's welcome is acknowledged without counting as a join (spec-gap 51).
            resume.commit(item, matches!(outcome, Outcome::NotForDevice));
            mls.provider().put_state("resume", &resume.snapshot())?;
            Ok(outcome)
        });
        if let Some(c) = slot {
            self.convs.insert(gid.clone(), c);
        }
        let outcome = match result {
            Ok(o) => o,
            Err(e) => {
                // Rolled back: OpenMLS's in-memory group may be ahead of the database, so reload it.
                self.resume = before;
                if let Some(c) = self.convs.get_mut(&gid) {
                    if let Some(g) = self.mls.load_group(&dsip_core::b64::decode(&gid).unwrap_or_default()).map_err(Self::state_err)? {
                        c.group = g;
                    }
                }
                // Not processable at all (not a duplicate by seq): record it as handled so it is acknowledged.
                println!("?? unprocessable {class} {cursor}: {e}");
                self.resume.commit(item, false);
                return self.save_resume();
            }
        };
        match outcome {
            Outcome::Joined { members, group, conv, epoch } => {
                let joined = self.mls.load_group(&dsip_core::b64::decode(&group).unwrap_or_default()).map_err(Self::state_err)?.context("joined group not stored")?;
                self.add_conv(joined, &conv);
                self.history.step(&json!({"joined": {"group": group, "epoch": epoch}}));
                self.save_groups()?;
                self.mls.provider().put_state(&format!("joined:{group}"), &json!(epoch)).map_err(Self::state_err)?;
                println!("JOINED {} kind={} members={members:?}", conv["conversation"].as_str().unwrap_or(""), conv["kind"].as_str().unwrap_or(""));
                // Confirm the pending group registration (M§6.6).
                let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now_s(), wire::TTL_S,
                    json!({"subject": self.identity, "groups": [{"group": group, "state": "joined"}]}));
                self.send(&env).await?;
                if let Some(pred) = conv["successor_of"].as_str() {
                    // M§7.5: check the successor against the predecessor as this device last knew it, then converge
                    let r = resolver(&self.resolver_files);
                    let ctx = self.ctx(&r);
                    let creator = self.conv(&group).ok()
                        .and_then(|c| member_identity(&c.group, LeafNodeIndex::new(0), &ctx).ok())
                        .map(|w| w.identity).unwrap_or_default();
                    let mut roster = members.clone();
                    roster.sort();
                    roster.dedup();
                    self.track_rosters();
                    let emissions =
                        self.successors.step(&json!({"welcome": {"group": group, "successor_of": pred, "creator": creator, "roster": roster}}));
                    let pred = pred.to_string();
                    self.apply_successor(emissions, &pred).await?;
                }
            }
            Outcome::Object { sender, sender_device, object } => self.object_in(&gid, item, &sender, &sender_device, object).await?,
            Outcome::Dropped(why) => println!("DROP {why}"),
            Outcome::NotForDevice => println!("SIBLING welcome {cursor}"),
            Outcome::Epoch { epoch, by, added, removed, hub } => {
                let kind = self.conv(&gid).map(|c| c.kind.clone()).unwrap_or_default();
                println!("EPOCH {epoch} kind={kind} by={by} added={added:?} removed={removed:?}");
                if let Some(h) = hub {
                    self.hub_moved(&gid, &h, item["seq"].as_i64().unwrap_or(0)).await?;
                }
            }
            Outcome::Removed { by, remaining } => {
                let c = self.convs.remove(&gid);
                let kind = c.as_ref().map(|c| c.kind.clone()).unwrap_or_default();
                println!("REMOVED from {} kind={kind} by={by}", c.map(|c| c.conversation).unwrap_or_default());
                if self.active.as_deref() == Some(gid.as_str()) {
                    self.active = self.convs.iter().find(|(_, c)| c.kind != "personal").map(|(g, _)| g.clone());
                }
                if self.personal.as_deref() == Some(gid.as_str()) {
                    self.personal = None;
                }
                self.save_groups()?;
                // The registration is the identity's: a sibling still in the group keeps receiving (spec-gap 53).
                let decision = dsip_messaging::client::registration_on_removal(&json!({"me": self.identity, "remaining_identities": remaining}));
                if decision["left"] == json!(true) {
                    let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now_s(), wire::TTL_S,
                        json!({"subject": self.identity, "groups": [{"group": gid, "state": "left"}]}));
                    self.send(&env).await?;
                }
            }
            Outcome::Nothing => {}
        }
        Ok(())
    }

    /// A decrypted application object, already committed.
    async fn object_in(&mut self, gid: &str, item: &Value, sender: &str, sender_device: &str, object: Value) -> Result<()> {
        let seq = item["seq"].as_i64().unwrap_or(0);
        match object["object"].as_str() {
            Some("archive-key") => {
                // M§12.1: an identity-level key, personal group only (enforced by the object check).
                let akid = object["akid"].as_str().unwrap_or("").to_string();
                let key: [u8; 32] = unb64(&object["key"]).try_into().unwrap_or([0; 32]);
                let fresh = !self.archive_keys.contains_key(&akid);
                self.store_archive_key(&akid, key, object["created_at"].as_i64().unwrap_or(0))?;
                if fresh {
                    println!("ARCHIVE-KEY {akid} from {sender}");
                }
                // Records kept for this key are opened now (spec-gap 51).
                let release: Vec<String> = self.held.iter().filter(|(_, h)| h["akid"] == json!(akid)).map(|(c, _)| c.clone()).collect();
                for c in release {
                    if let Some(h) = self.held.remove(&c) {
                        self.open_archive(&h);
                    }
                }
                self.save_archive()?;
            }
            Some("receipt") => {
                let what = if object["kind"] == "read" { object["through"].clone() } else { object["targets"].clone() };
                let personal = self.personal.as_deref() == Some(gid);
                println!("RECEIPT {sender} {} {what}{}", object["kind"].as_str().unwrap_or(""), if personal { " (personal group)" } else { "" });
                // A sibling's undisclosed watermark describes another conversation (spec-gap 52).
                let target = if personal {
                    self.convs.iter().find(|(_, c)| json!(c.conversation) == object["conversation"]).map(|(g, _)| g.clone())
                } else {
                    Some(gid.to_string())
                };
                if let Some(t) = target {
                    self.batch.push((t, json!({"seq": seq, "object": object})));
                }
            }
            Some("content") => {
                let key = object_key(&object);
                let emissions = self.history.step(&json!({"mls": {"group": gid, "seq": seq, "epoch": self.conv(gid)?.group.epoch().as_u64(), "id": key}}));
                if emissions.iter().any(|e| e.get("duplicate").is_some()) {
                    println!("DUP-HISTORY seq={seq}");
                    return Ok(());
                }
                self.lines.insert(key, format!("{sender}: {}", display(&object)));
                self.archive_requests(gid, &emissions, &object, sender, sender_device, seq);
                self.batch.push((gid.to_string(), json!({"seq": seq, "object": object.clone()})));
                if object.get("blob").is_some() {
                    if let Some(c) = self.convs.get_mut(gid) {
                        c.last_media = object["id"].as_str().map(String::from);
                    }
                    // The item is committed; a failed fetch leaves the content visible and the blob re-fetchable.
                    match self.fetch_media(&object).await {
                        Ok((path, sha)) => println!(
                            "RECV-AUDIO {sender} purpose={} duration_ms={} session={} file={} sha256={sha}",
                            object["purpose"].as_str().unwrap_or("message"), object["duration_ms"],
                            object["session"].as_str().unwrap_or("-"), path.display()
                        ),
                        Err(e) => println!("ERR blob {}: {e}", object["id"]),
                    }
                } else {
                    println!("RECV {sender}: {}", object["text"].as_str().unwrap_or(""));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn mls_err<E: std::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> MlsError {
    move |x| MlsError(format!("{what}: {x:?}"))
}

/// Duration of an Ogg Opus file from its last granule position less the pre-skip (RFC 7845 §4).
fn ogg_opus_duration_ms(bytes: &[u8]) -> Option<i64> {
    let mut pos = 0;
    let (mut last_granule, mut pre_skip) = (None, None);
    while pos + 27 <= bytes.len() && &bytes[pos..pos + 4] == b"OggS" {
        let granule = i64::from_le_bytes(bytes[pos + 6..pos + 14].try_into().ok()?);
        let segments = bytes[pos + 26] as usize;
        let table = bytes.get(pos + 27..pos + 27 + segments)?;
        let data = pos + 27 + segments;
        let len: usize = table.iter().map(|&b| b as usize).sum();
        if pre_skip.is_none() {
            let head = bytes.get(data..data + 19)?;
            if &head[..8] != b"OpusHead" {
                return None;
            }
            pre_skip = Some(u16::from_le_bytes([head[10], head[11]]) as i64);
        }
        if granule >= 0 {
            last_granule = Some(granule);
        }
        pos = data + len;
    }
    Some((last_granule? - pre_skip?).max(0) * 1000 / 48_000)
}

/// The MLS side of one item, with no I/O, so it can run inside the item's transaction. `group` is the target group
/// with its conversation id and kind; a welcome needs none.
fn process(mls: &Device<SqliteProvider>, group: Option<(&mut MlsGroup, &str, &str)>, class: &str, bytes: &[u8], ctx: &Context) -> Result<Outcome, MlsError> {
    if class == "welcome" {
        let joined = match mls.join(bytes) {
            Ok(g) => g,
            Err(e) if e.0.contains("NoMatchingKeyPackage") => return Ok(Outcome::NotForDevice),
            Err(e) => return Err(e),
        };
        let members: Vec<String> = authenticate_members(&joined, ctx)?.into_iter().map(|m| m.identity).collect();
        let conv: Value = serde_json::from_slice(&conversation_extension(&joined).ok_or_else(|| MlsError("no dsip_conversation".into()))?)
            .map_err(mls_err("dsip_conversation"))?;
        return Ok(Outcome::Joined { members, group: b64(joined.group_id().as_slice()), conv, epoch: joined.epoch().as_u64() });
    }
    let Some((group, conversation, kind)) = group else { return Ok(Outcome::Nothing) };
    let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(mls_err("mls bytes"))?;
    let pm = msg.try_into_protocol_message().map_err(mls_err("protocol message"))?;
    let processed = group.process_message(mls.provider(), pm).map_err(mls_err("undecryptable"))?;
    let who = match processed.sender() {
        Sender::Member(idx) => member_identity(group, *idx, ctx).ok(),
        _ => None,
    };
    let (sender, sender_device) = who.map(|w| (w.identity, w.device)).unwrap_or_default();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let obj: Value = serde_json::from_slice(&app.into_bytes()).map_err(mls_err("content json"))?;
            let octx = json!({"conversation": conversation, "conversation_kind": kind, "leaf_identity": sender});
            let verdict = check_object(&obj, &octx);
            if verdict["verdict"] != "accept" {
                return Ok(Outcome::Dropped(format!("{} {}", verdict["code"], obj["id"])));
            }
            if verdict["effective"]["render"] == "ignore" {
                return Ok(Outcome::Nothing); // M§8.1: unknown objects and receipt kinds are ignored
            }
            Ok(Outcome::Object { sender, sender_device, object: obj })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            let added: Vec<String> = staged
                .add_proposals()
                .filter_map(|a| dsip_mls::authenticate_leaf_node(a.add_proposal().key_package().leaf_node(), ctx).ok())
                .map(|w| format!("{}#{}", w.identity, w.device))
                .collect();
            let removed_leaves: Vec<LeafNodeIndex> = staged.remove_proposals().map(|r| r.remove_proposal().removed()).collect();
            // A removed leaf may no longer authenticate (a revoked delegation, spec-gap 57): render it by its credential.
            let removed: Vec<String> = removed_leaves
                .iter()
                .map(|i| match member_identity(group, *i, ctx) {
                    Ok(w) => format!("{}#{}", w.identity, w.device),
                    Err(_) => {
                        let device = group
                            .public_group()
                            .leaf(*i)
                            .and_then(|l| BasicCredential::try_from(l.credential().clone()).ok())
                            .map(|b| String::from_utf8_lossy(b.identity()).into_owned())
                            .unwrap_or_default();
                        format!("unverified#{device}")
                    }
                })
                .collect();
            let remaining: Vec<String> = group
                .members()
                .filter(|m| !removed_leaves.contains(&m.index))
                .filter_map(|m| member_identity(group, m.index, ctx).ok())
                .map(|w| w.identity)
                .collect();
            let before = conversation_extension(group);
            let mut hub = None;
            if let Some(update) = conversation_update(before.as_deref(), &staged) {
                // M§6.3, M§7.4 (spec-gap 60): a commit may change the hub and nothing else in dsip_conversation
                if update["verdict"] != "accept" {
                    return Ok(Outcome::Dropped(format!("commit {} dsip_conversation", update["code"])));
                }
                hub = Some(update["effective"]["hub"].clone());
            }
            group.merge_staged_commit(mls.provider(), *staged).map_err(mls_err("merge commit"))?;
            if !group.is_active() {
                return Ok(Outcome::Removed { by: sender, remaining });
            }
            Ok(Outcome::Epoch { epoch: group.epoch().as_u64(), by: sender, added, removed, hub })
        }
        _ => Ok(Outcome::Nothing),
    }
}

/// HTTPS for blobs, trusting the same anchors as the `wss` connections (M§5.6: TLS as in §13.2).
fn http_client(ca: Option<&Path>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder().use_rustls_tls().https_only(true);
    if let Some(ca) = ca {
        for cert in reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)? {
            b = b.add_root_certificate(cert);
        }
    }
    Ok(b.build()?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let keys = Keys::load_or_create(&args.state, args.controller.as_deref())?;
    if let Some(path) = &args.write_doc {
        let doc = did_document(&args.identity, &keys.controller, args.mailbox_did.as_deref().context("--mailbox-did")?,
            args.mailbox_uri.as_deref().context("--mailbox-uri")?);
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
        println!("OK wrote {}", path.display());
        return Ok(());
    }

    let now = now_s();
    let deleg = delegation_payload(&args.identity, &keys.device.did(), now - 60, now + 365 * 86_400, &["dsip.signaling", "dsip.messaging"]);
    let delegation = sign(&deleg, &keys.controller, &format!("{}#key-1", args.identity));
    let provider = SqliteProvider::open(&args.state.join("device.sqlite")).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mls = Device::with_provider(KeyPair::from_seed(keys.device.seed()), compact(&delegation), provider);
    let r = resolver(&args.resolver_files);
    let mailbox = mailbox_of(&args.identity, &r)?;
    println!("DEVICE {}", keys.device.did());

    let policy = json!({"delivered": !args.no_delivered, "read": args.disclose.iter().any(|d| d == "read"),
        "played": args.disclose.iter().any(|d| d == "played"), "activity": args.disclose.iter().any(|d| d == "activity")});
    let get = |k: &str| mls.provider().get_state(k).map_err(|e| anyhow::anyhow!("{e}"));
    let resume = Resume::new(&get("resume")?.unwrap_or(Value::Null));
    let mut client = Client {
        keys,
        identity: args.identity.clone(),
        delegation,
        resolver_files: args.resolver_files.clone(),
        ca: args.ca.clone(),
        conn: None,
        mailbox,
        seen: SeenIds::default(),
        convs: BTreeMap::new(),
        active: None,
        personal: None,
        archive_keys: BTreeMap::new(),
        held: BTreeMap::new(),
        history: History::default(),
        lines: HashMap::new(),
        own: HashSet::new(),
        resume,
        successors: get("successors")?.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default(),
        grants: HashMap::new(),
        grants_held: BTreeMap::new(),
        requests: BTreeMap::new(),
        crash_next: false,
        state: args.state.clone(),
        http: http_client(args.ca.as_deref())?,
        policy,
        batch: vec![],
        outbox: vec![],
        mls,
    };

    // Restart: everything below comes from the database, exactly as last committed.
    let mut groups: Vec<String> = get_state_list(&client, "groups")?;
    if let Some(g) = client.mls.provider().get_state("group").map_err(Client::state_err)?.and_then(|g| g.as_str().map(String::from)) {
        groups.push(g); // state written before devices held several groups
    }
    for g in groups {
        let Some(group) = client.mls.load_group(&dsip_core::b64::decode(&g).unwrap_or_default()).map_err(Client::state_err)? else { continue };
        let Some(conv) = conversation_extension(&group).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { continue };
        if !group.is_active() {
            continue;
        }
        client.add_conv(group, &conv);
        if let Some(e) = client.mls.provider().get_state(&format!("joined:{g}")).map_err(Client::state_err)? {
            client.history.step(&json!({"joined": {"group": g, "epoch": e}}));
        }
        println!("RESTORED {} kind={} since={}", conv["conversation"].as_str().unwrap_or(""), conv["kind"].as_str().unwrap_or(""), client.resume.sync_fields()["since"]);
    }
    if let Some(a) = client.mls.provider().get_state("active").map_err(Client::state_err)?.and_then(|a| a.as_str().map(String::from)) {
        if client.convs.contains_key(&a) {
            client.active = Some(a);
        }
    }
    for (akid, k) in client.mls.provider().get_state("archive_keys").map_err(Client::state_err)?.unwrap_or_default().as_object().cloned().unwrap_or_default() {
        let key: [u8; 32] = unb64(&k["key"]).try_into().unwrap_or([0; 32]);
        client.archive_keys.insert(akid.clone(), (key, k["created_at"].as_i64().unwrap_or(0)));
        client.history.step(&json!({"archive_key": {"akid": akid, "created_at": k["created_at"]}}));
    }
    if let Some(Value::Object(h)) = client.mls.provider().get_state("held").map_err(Client::state_err)? {
        client.held = h.into_iter().collect();
    }
    if let Some(Value::Object(g)) = client.mls.provider().get_state("grants_held").map_err(Client::state_err)? {
        client.grants_held = g.into_iter().filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string()))).collect();
    }
    if let Some(Value::Object(r)) = client.mls.provider().get_state("requests").map_err(Client::state_err)? {
        client.requests = r.into_iter().collect();
    }
    client.connect().await?;

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        let recv = async {
            match client.conn.as_mut() {
                Some(c) => c.recv().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            line = stdin.next_line() => {
                let Some(line) = line? else { break };
                let line = line.trim().to_string();
                let (cmd, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
                let result = match cmd {
                    "quit" => break,
                    _ => command(&mut client, cmd, rest).await,
                };
                if let Err(e) = result {
                    println!("ERR {e}");
                }
                if let Err(e) = client.flush_outbox().await {
                    println!("ERR {e}");
                }
                std::io::stdout().flush()?;
            }
            _ = ticker.tick() => {
                client.tick();
                if let Err(e) = client.flush_outbox().await {
                    println!("ERR {e}");
                }
                std::io::stdout().flush()?;
            }
            frame = recv => {
                match frame {
                    Ok(Some(text)) => {
                        if let Err(e) = client.inbound(&text).await {
                            println!("ERR {e}");
                        }
                        if let Err(e) = client.flush_outbox().await {
                            println!("ERR {e}");
                        }
                        std::io::stdout().flush()?;
                    }
                    Ok(None) => {
                        println!("DISCONNECTED by the mailbox");
                        client.conn = None;
                    }
                    Err(e) => {
                        println!("ERR connection {e}");
                        client.conn = None;
                    }
                }
            }
        }
    }
    Ok(())
}

fn get_state_list(client: &Client, key: &str) -> Result<Vec<String>> {
    Ok(client
        .mls
        .provider()
        .get_state(key)
        .map_err(Client::state_err)?
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect())
}

async fn command(client: &mut Client, cmd: &str, rest: &str) -> Result<()> {
    match cmd {
        "" => Ok(()),
        "kp" => client.upload_key_packages(rest.trim().parse().unwrap_or(2)).await,
        "introduce" | "introduce-plain" => {
            // introduce <did> <purpose…>: sealed to the recipient's key agreement key; introduce-plain: not sealed
            let (target, purpose) = rest.trim().split_once(' ').context("usage: introduce <did> <purpose>")?;
            client.introduce(target, purpose.trim(), cmd == "introduce-plain").await
        }
        "requests" => {
            for (id, p) in &client.requests {
                println!("PENDING {id} from {}", p["from"].as_str().unwrap_or(""));
            }
            Ok(())
        }
        "accept-request" => client.accept_request(rest.trim()).await,
        "grant" => {
            let g = client.grant(rest.trim(), None);
            client.grants.insert(rest.trim().to_string(), compact(&g));
            println!("GRANT {}", compact(&g));
            Ok(())
        }
        "create" | "add" => {
            // create <direct|group> <peer> [grant-file]  /  add <peer> [grant-file]
            let mut words = rest.split_whitespace();
            let kind = if cmd == "create" { words.next().unwrap_or("direct").to_string() } else { String::new() };
            let peer = words.next().unwrap_or("").to_string();
            let grant = match words.next() {
                Some(f) => Some(std::fs::read_to_string(f)?.trim().to_string()),
                None => None,
            };
            if cmd == "create" {
                client.create(&kind, &peer, grant).await
            } else {
                let group = client.active()?;
                client.add(&group, &peer, grant, None).await
            }
        }
        "personal" => client.create_personal().await,
        "add-device" => client.add_device(rest.trim()).await,
        "remove-device" => client.remove_device(rest.trim()).await,
        "revoke-device" => client.revoke_device(rest.trim()).await,
        "remove-leaf" => client.remove_leaf(rest.trim()).await,
        "remove" => client.remove(rest.trim()).await,
        "successor" => client.create_successor().await,
        "move-hub" => {
            // M§7.4: move the active group to another hub, by default this identity's own mailbox
            let group = client.active()?;
            let w: Vec<&str> = rest.split_whitespace().collect();
            let hub = match w.as_slice() {
                [did, uri] => json!({"did": did, "uri": uri}),
                [] => json!({"did": client.mailbox.0, "uri": client.mailbox.1}),
                _ => bail!("usage: move-hub [<hub did> <wss uri>]"),
            };
            let what = format!("moved to {}", hub["did"].as_str().unwrap_or(""));
            client.commit_op(&group, CommitOp::MoveHub(hub), &what).await
        }
        "rekey" => {
            // M§6.5: a self-update commit, applied only once the hub accepts it
            let group = client.active()?;
            client.commit_op(&group, CommitOp::Update, "rekeyed").await
        }
        "send" => client.send_text(rest).await,
        "voice" => client.send_audio(rest.trim(), "voice-message", None, None).await,
        "voicemail" => {
            // voicemail <session> <call outcome reason> <file.ogg>
            let w: Vec<&str> = rest.split_whitespace().collect();
            match w.as_slice() {
                [session, reason, file] => client.voicemail(session, reason, file).await,
                _ => Err(anyhow::anyhow!("usage: voicemail <session> <reason> <file.ogg>")),
            }
        }
        "sync" => client.sync(false).await,
        "live" => client.sync(true).await,
        "offline" => {
            client.conn = None;
            println!("OK offline");
            Ok(())
        }
        "online" => client.connect().await,
        "read" => {
            // M§10.3: the local user has read everything up to the latest content of the active conversation.
            let group = client.active()?;
            client.tick();
            let c = client.convs.get_mut(&group).context("group")?;
            let through = c.receipts.snapshot()["timeline"].as_array().and_then(|t| t.last().cloned()).context("nothing to read")?;
            let e = c.receipts.step(&json!({"read": {"through": through}}));
            println!("OK read through={through} ({} to send)", e.len());
            client.outbox.extend(e.into_iter().map(|x| (group.clone(), x)));
            Ok(())
        }
        "play" => {
            // M§10.4: the local user played a media item (default: the latest received).
            let group = client.active()?;
            let c = client.convs.get_mut(&group).context("group")?;
            let id = if rest.trim().is_empty() { c.last_media.clone() } else { Some(rest.trim().to_string()) };
            let id = id.context("nothing to play")?;
            let e = c.receipts.step(&json!({"play": {"id": id}}));
            println!("OK played {id} ({} to send)", e.len());
            client.outbox.extend(e.into_iter().map(|x| (group.clone(), x)));
            Ok(())
        }
        "typing" | "uploading" | "recording-audio" | "recording-video" => {
            let group = client.active()?;
            let state = if rest.trim() == "stop" { "stopped" } else { "active" };
            client.tick();
            let c = client.convs.get_mut(&group).context("group")?;
            let e = c.receipts.step(&json!({"activity": {"activity": cmd, "state": state}}));
            if e.is_empty() {
                println!("OK {cmd} {state} (not sent: refresh bound or not disclosed)");
            }
            client.outbox.extend(e.into_iter().map(|x| (group.clone(), x)));
            Ok(())
        }
        "status" => {
            client.tick();
            let group = client.active()?;
            println!("STATUS {}", client.conv(&group)?.receipts.snapshot());
            Ok(())
        }
        "history" => {
            // M§8.5: the conversation timeline in hub seq order, from MLS and archive alike.
            let snap = client.history.snapshot();
            for (i, k) in snap["timeline"].as_array().into_iter().flatten().enumerate() {
                println!("TIMELINE {i} {}", client.lines.get(k.as_str().unwrap_or("")).cloned().unwrap_or_default());
            }
            println!("OK history {} item(s), {} held, current key {}", snap["timeline"].as_array().map_or(0, Vec::len), client.held.len(), snap["current_akid"]);
            Ok(())
        }
        "crash-next" => {
            client.crash_next = true;
            println!("OK crash-next");
            Ok(())
        }
        other => {
            println!("?? unknown command {other}");
            Ok(())
        }
    }
}
