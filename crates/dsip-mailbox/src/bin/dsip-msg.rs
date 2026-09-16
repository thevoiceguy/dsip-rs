//! A messaging device: one identity's device, its MLS state, and a connection to its mailbox.
//!
//! Spec: M§4.2 (find the mailbox in the DID document), M§5.4–M§5.5 (sync, KeyPackages), M§6.2–M§6.7
//! (leaves, groups, welcomes), M§7.2–M§7.3 (direct and group conversations, adds and removes rendered
//! with their committer), M§8.1 (content objects), M§9.1 (deposit once), M§14.1–M§14.2 (grants).
//!
//! M§5.4, M§8.5 (durable delivery state across restarts).
//!
//! Impl: commands on stdin, events on stdout, so a demo script can drive two of these. MLS state and
//! the delivery state ([`Resume`]: ack cursor, seq positions, joined groups) live in one SQLite
//! database under `--state`, and each inbound item is processed and committed in one transaction
//! (spec-gap 44), so the process can be killed at any point and restarted. Every group deposit goes to
//! the hub through this device's own mailbox with the delegation in its header (spec-gap 45); a commit
//! is applied only after the hub's `accepted`; the device's own items fanned back to it are recognised
//! by that `accepted` seq or by their bytes (spec-gap 47). Audio (`voice`, `voicemail`) is an Ogg Opus
//! file sealed under a fresh key, uploaded to this identity's mailbox blob endpoint and referenced from
//! the content object (M§8.2, M§8.4, M§5.6); a receiver fetches, verifies and decrypts it into
//! `--state`/media. `voicemail` is offered only when M§13.2 allows it for the given call outcome.
//! Receipts and activity (M§10, M§11) are decided by the vector-pinned `dsip_messaging::client::Client`:
//! the device feeds it each committed sync batch, its own accepted content, local reads, plays and
//! typing, and received activity; whatever it emits is sent. Activity travels as an `ephemeral`
//! deposit sealed under the epoch's exporter key and signed by the device, and reaches devices as a
//! pushed item carrying the originating `expires_at` (spec-gap 49). `read` and `played` go to the
//! conversation only with `--disclose`; without a personal group (M§7.1, not built here) a private read
//! watermark stays on the device. `offline` only drops the
//! connection; `crash-next` exits after processing the next new item and before committing it.

use std::collections::{HashMap, HashSet};
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
use dsip_messaging::client::{select_mailbox, Resume};
use dsip_mls::sqlite::SqliteProvider;
use dsip_mls::{authenticate_key_package, authenticate_members, conversation_extension, digest, member_identity, Device, MlsError};
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
    fn load_or_create(dir: &Path) -> Result<Keys> {
        std::fs::create_dir_all(dir)?;
        let read = |n: &str| -> Result<KeyPair> {
            let p = dir.join(n);
            if p.exists() {
                Ok(KeyPair::from_seed(unhex(&std::fs::read_to_string(&p)?)?))
            } else {
                let k = KeyPair::generate();
                std::fs::write(&p, hex(&k.seed()))?;
                Ok(k)
            }
        };
        Ok(Keys { controller: read("controller.key")?, device: read("device.key")? })
    }
}

/// The `did:web` document for this identity, carrying its mailbox entry (M§4.2).
fn did_document(identity: &str, controller: &KeyPair, mailbox_did: &str, mailbox_uri: &str) -> Value {
    json!({
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
    group: Option<MlsGroup>,
    conversation: Option<String>,
    group_id: Option<Vec<u8>>,
    /// `dsip_conversation.kind` and `.hub` (`{did, uri}`) of the conversation (M§6.3).
    kind: String,
    hub: Option<(String, String)>,
    /// Digests of this device's own deposits: their fan-out copies come back and cannot be decrypted (spec-gap 47).
    own: HashSet<String>,
    resume: Resume,
    grants: HashMap<String, String>,
    crash_next: bool,
    state: PathBuf,
    http: reqwest::Client,
    /// Receipt and activity decisions (M§10, M§11).
    receipts: dsip_messaging::client::Client,
    /// Content and receipt objects of the sync batch being processed (M§10.2 decides per batch).
    batch: Vec<Value>,
    /// What the receipt machine asked to send, sent outside frame processing.
    outbox: Vec<Value>,
    last_media: Option<String>,
}

/// What processing one inbound item produced, reported only once it is committed.
enum Outcome {
    Joined { conversation: String, members: Vec<String>, group: String, conv: Value },
    Text { sender: String, object: Value },
    Receipt { sender: String, object: Value },
    /// Content carrying a blob: fetched and decrypted once the item is committed (M§8.4).
    Media { sender: String, object: Value },
    Dropped(String),
    /// M§7.3: every roster change is rendered, attributed to the committing identity.
    Epoch { epoch: u64, by: String, added: Vec<String>, removed: Vec<String> },
    Removed { by: String },
    Nothing,
}

impl Client {
    fn ctx<'a>(&self, resolver: &'a StaticResolver) -> Context<'a> {
        let mut ctx = Context::new(now_s(), resolver);
        ctx.delegations = vec![self.delegation.clone()];
        ctx.supported = Supported::all_known();
        ctx
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

    /// A short-lived connection to another identity's mailbox (M§5.5 fetch, M§6.6 welcome).
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

    /// Issue a contact grant for `peer` (§19.4, scope `dsip.message`).
    fn grant(&self, peer: &str) -> Envelope {
        let now = now_s();
        let p = json!({"dsip": wire::version_block(), "type": "grant", "id": wire::new_id(now), "from": self.identity,
            "to": peer, "session": wire::new_id(now), "scope": ["dsip.message"], "valid_until": now + 30 * 86400,
            "issued_at": now, "expires_at": now + 30});
        sign(&p, &self.keys.device, &self.keys.device.kid())
    }

    async fn upload_key_packages(&mut self, n: usize) -> Result<()> {
        let mut packages = vec![];
        for _ in 0..n {
            packages.push(json!(dsip_core::b64::encode(&self.mls.key_package()?)));
        }
        let last = dsip_core::b64::encode(&self.mls.key_package()?);
        let env = wire::message(
            &self.keys.device,
            "key-packages",
            &self.mailbox.0,
            now_s(),
            wire::TTL_S,
            json!({"subject": self.identity, "key_packages": packages, "last_resort": last}),
        );
        self.send(&env).await?;
        println!("OK uploaded {n} key packages");
        Ok(())
    }

    /// Fetch and authenticate one KeyPackage of `peer` from its mailbox (M§5.5, M§6.2, M§14.2).
    async fn fetch_key_package(&mut self, peer: &str, grant: Option<&str>) -> Result<KeyPackage> {
        let mut peer_conn = self.peer_connect(peer).await?;
        let mut fields = json!({"target": peer});
        if let Some(g) = grant {
            fields["grant"] = json!(g);
        }
        let fetch = wire::message(&self.keys.device, "key-package-fetch", &peer_conn.relay.did.clone(), now_s(), wire::TTL_S, fields);
        peer_conn.send(&fetch).await?;
        let reply = peer_conn.recv().await?.context("no reply to key-package-fetch")?;
        peer_conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "done").await;
        let payload = wire::payload_of(&Envelope::from_frame(&reply).map_err(|v| anyhow::anyhow!("{:?}", v.code))?)
            .context("bad reply")?;
        if payload["type"] != "key-packages" {
            bail!("key-package-fetch refused: {} {}", payload["type"], payload["reason"]);
        }
        let kp_b64 = payload["key_packages"]
            .as_array()
            .and_then(|a| a.first())
            .or(payload.get("last_resort"))
            .and_then(Value::as_str)
            .context("no key package")?;
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let (kp, who) = authenticate_key_package(&dsip_core::b64::decode(kp_b64).context("bad base64")?, self.mls.provider(), &ctx)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(who.identity == peer, "key package belongs to {}", who.identity);
        Ok(kp)
    }

    fn group_b64(&self) -> Result<String> {
        Ok(dsip_core::b64::encode(self.group_id.as_deref().context("no conversation")?))
    }

    /// Deposit to the group's hub through this device's mailbox and wait for the hub's answer (M§5.2,
    /// M§9.2). The delegation rides in the header because a hub reached by forwarding has not seen it (M§5.1).
    async fn hub_deposit(&mut self, class: &str, fields: Value) -> Result<Value> {
        let hub = self.hub.clone().context("no hub")?;
        let group = self.group_b64()?;
        if let Some(bytes) = fields["mls"].as_str().and_then(dsip_core::b64::decode) {
            self.own.insert(digest(&bytes));
        }
        let env = wire::deposit_delegated(&self.keys.device, vec![self.delegation.clone()], &hub.0, now_s(), &group, class, fields);
        let id = wire::payload_of(&env).and_then(|p| p["id"].as_str().map(String::from)).context("deposit id")?;
        self.send(&env).await?;
        let reply = self.await_reply(&id).await?;
        if let Some(seq) = reply["seq"].as_i64() {
            // The hub's `accepted` seq marks this device's own copy as processed (spec-gap 47).
            self.resume.sent(&group, seq);
            self.save_resume()?;
        }
        Ok(reply)
    }

    /// Read frames until the answer to `id` arrives, processing everything else as it comes.
    async fn await_reply(&mut self, id: &str) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let conn = self.conn.as_mut().context("offline")?;
            let frame = tokio::time::timeout_at(deadline, conn.recv()).await.context("no answer from the hub")??.context("mailbox closed")?;
            let p = Envelope::from_frame(&frame).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
            if p["in_reply_to"] == json!(id) && (p["type"] == "accepted" || p["type"] == "error") {
                return Ok(p);
            }
            if let Err(e) = self.inbound(&frame).await {
                println!("ERR {e}");
            }
        }
    }

    /// Deposit a commit and apply it only once the hub has accepted it (M§6.5).
    async fn commit(&mut self, commit: MlsMessageOut, welcome: Option<MlsMessageOut>, grants: Vec<String>, what: &str) -> Result<()> {
        let mut fields = json!({"mls": dsip_core::b64::encode(&commit.tls_serialize_detached()?)});
        if let Some(w) = welcome {
            fields["welcome"] = json!(dsip_core::b64::encode(&w.tls_serialize_detached()?));
        }
        if !grants.is_empty() {
            fields["grants"] = json!(grants);
        }
        let reply = self.hub_deposit("handshake", fields).await?;
        let group = self.group.as_mut().context("no group")?;
        if reply["type"] != "accepted" {
            // M§6.5: a refused commit is discarded; on commit-conflict the device syncs and re-proposes.
            group.clear_pending_commit(self.mls.provider().storage()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
            bail!("{what} refused by the hub: {}", reply["reason"]);
        }
        group.merge_pending_commit(self.mls.provider()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        println!("OK {what} epoch={} seq={}", group.epoch().as_u64(), reply["seq"]);
        self.publish_group_info().await
    }

    /// Republish the GroupInfo after a commit, for the hub and for external joins (M§6.5 rule 6, M§6.8).
    async fn publish_group_info(&mut self) -> Result<()> {
        let group = self.group.as_ref().context("no group")?;
        let gi = group.export_group_info(self.mls.provider().crypto(), &self.mls.signer(), true).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let reply = self.hub_deposit("group-info", json!({"mls": dsip_core::b64::encode(&gi.tls_serialize_detached()?)})).await?;
        anyhow::ensure!(reply["type"] == "accepted", "group-info refused: {}", reply["reason"]);
        Ok(())
    }

    /// Create a conversation of `kind` with `peer`, hubbed at this identity's own mailbox (M§7.2, M§7.3).
    async fn create(&mut self, kind: &str, peer: &str, grant: Option<String>) -> Result<()> {
        let kp = self.fetch_key_package(peer, grant.as_deref()).await?;
        let now = now_s();
        let conversation = wire::new_id(now);
        let group_id = wire::new_id(now).into_bytes();
        let conv = json!({"conversation": conversation, "kind": kind,
            "hub": {"did": self.mailbox.0, "uri": self.mailbox.1}, "successor_of": null});
        let group = self.mls.create_group(&group_id, &serde_json::to_vec(&conv)?).map_err(|e| anyhow::anyhow!("{e}"))?;
        self.group = Some(group);
        self.conversation = Some(conversation.clone());
        self.group_id = Some(group_id);
        self.kind = kind.to_string();
        self.hub = Some(self.mailbox.clone());
        let group_b64 = self.group_b64()?;
        self.mls.provider().put_state("group", &json!(group_b64)).map_err(|e| anyhow::anyhow!("{e}"))?;

        // Our own mailbox hubs the group and must admit its fan-out for us (M§6.6).
        let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now, wire::TTL_S,
            json!({"subject": self.identity, "groups": [{"group": group_b64, "state": "joined", "hub": self.mailbox.0}]}));
        self.send(&env).await?;
        // The hub's public view is bootstrapped from the group's first GroupInfo (M§6.5 rule 6).
        self.publish_group_info().await?;
        println!("OK conversation {conversation} kind={kind}");
        self.add(peer, grant, Some(kp)).await
    }

    /// Add `peer` to the conversation: the hub fans the welcome out with our deposit as `origin` (M§7.3, M§14.2).
    async fn add(&mut self, peer: &str, grant: Option<String>, kp: Option<KeyPackage>) -> Result<()> {
        let kp = match kp {
            Some(k) => k,
            None => self.fetch_key_package(peer, grant.as_deref()).await?,
        };
        let group = self.group.as_mut().context("no conversation")?;
        let (commit, welcome, _) =
            group.add_members(self.mls.provider(), &self.mls.signer(), &[kp]).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        self.commit(commit, Some(welcome), grant.into_iter().collect(), &format!("added {peer}")).await
    }

    /// Remove every leaf of `identity` (M§7.3).
    async fn remove(&mut self, identity: &str) -> Result<()> {
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let group = self.group.as_mut().context("no conversation")?;
        let leaves: Vec<LeafNodeIndex> = group
            .members()
            .filter(|m| member_identity(group, m.index, &ctx).is_ok_and(|w| w.identity == identity))
            .map(|m| m.index)
            .collect();
        anyhow::ensure!(!leaves.is_empty(), "{identity} is not a member");
        let (commit, _, _) =
            group.remove_members(self.mls.provider(), &self.mls.signer(), &leaves).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        self.commit(commit, None, vec![], &format!("removed {identity}")).await
    }

    /// Send an Ogg Opus recording: seal, upload, reference (M§8.2, M§8.4, M§5.6).
    async fn send_audio(&mut self, path: &str, purpose: &str, session: Option<String>, max_duration_s: Option<i64>) -> Result<()> {
        let conversation = self.conversation.clone().context("no conversation")?;
        let plain = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        let duration_ms = ogg_opus_duration_ms(&plain).context("not an Ogg Opus file")?;
        if let Some(max) = max_duration_s {
            // M§13.2: recording stops at the callee's max_duration_s.
            anyhow::ensure!(duration_ms <= max * 1000, "recording is {duration_ms} ms, over the callee's {max} s");
        }
        // M§8.4 rule 1: a fresh single-use key, AES-256-GCM, nonce ‖ ciphertext ‖ tag.
        let key: [u8; 32] = rand::random();
        let nonce: [u8; 12] = rand::random();
        let sealed = dsip_messaging::mls_wire::seal(&key, &nonce, &plain, dsip_messaging::mls_wire::SealUse::Blob);
        let sha = digest(&sealed);
        let conn = self.conn.as_ref().context("offline")?;
        let endpoint = conn.relay.capabilities["mailbox"]["blob_endpoint"].as_str().context("mailbox advertises no blob_endpoint")?;
        let uri = format!("{endpoint}/{sha}");

        // M§5.6: one upload, authorized by a signed blob-put carrying the device's delegation.
        let auth = wire::message_delegated(&self.keys.device, vec![self.delegation.clone()], "blob-put", &self.mailbox.0, now_s(),
            wire::TTL_S, json!({"sha256": sha, "size": sealed.len()}));
        let resp = self
            .http
            .put(&uri)
            .header("Authorization", format!("DSIP {}.{}.{}", auth.protected, auth.payload, auth.signature))
            .body(sealed.clone())
            .send()
            .await?;
        let status = resp.status().as_u16();
        let answer = Envelope::from_frame(&resp.text().await?).ok().and_then(|e| wire::payload_of(&e)).unwrap_or_default();
        anyhow::ensure!(matches!(status, 200 | 201) && answer["type"] == "accepted", "blob upload refused: {status} {}", answer["reason"]);

        let now = now_s();
        let mut obj = json!({"object": "content", "id": wire::new_id(now), "conversation": conversation,
            "sender": self.identity, "sent_at": now, "kind": "audio", "purpose": purpose, "duration_ms": duration_ms,
            "blob": {"uri": uri, "sha256": sha, "size": sealed.len(), "key": dsip_core::b64::encode(&key), "alg": "A256GCM",
                     "content_type": "audio/ogg; codecs=opus"}});
        if let Some(s) = session {
            obj["session"] = json!(s);
        }
        let group = self.group.as_mut().context("no group")?;
        let msg = group
            .create_message(self.mls.provider(), &self.mls.signer(), &serde_json::to_vec(&obj)?)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
            .tls_serialize_detached()?;
        // M§8.4 rule 4: the deposit's manifest names the blob without its key.
        let manifest = json!([{"uri": uri, "sha256": sha, "size": sealed.len()}]);
        let reply = self.hub_deposit("application", json!({"mls": dsip_core::b64::encode(&msg), "blobs": manifest})).await?;
        if reply["type"] == "accepted" {
            self.tick();
            self.receipts.step(&json!({"sync": {"items": [{"seq": reply["seq"], "object": obj}]}}));
        }
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
        let group = self.group.as_ref().context("no conversation with the callee")?;
        let peer = authenticate_members(group, &ctx)
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
        let key: [u8; 32] = b["key"].as_str().and_then(dsip_core::b64::decode).and_then(|k| k.try_into().ok()).context("blob key")?;
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

    /// Advance the receipt machine to wall time; report indicators that expired (M§10.3 pending reads, M§11.2).
    fn tick(&mut self) {
        let before = self.receipts.snapshot()["activity"].clone();
        let delta = now_s() - self.receipts.now();
        if delta > 0 {
            let emissions = self.receipts.step(&json!({"advance": delta}));
            self.outbox.extend(emissions);
        }
        let after = &self.receipts.snapshot()["activity"];
        for (who, acts) in before.as_object().into_iter().flatten() {
            for a in acts.as_object().into_iter().flatten().map(|(a, _)| a) {
                if after[who.as_str()].get(a).is_none() {
                    println!("ACTIVITY-CLEARED {who} {a}");
                }
            }
        }
    }

    /// Send what the receipt machine emitted: receipts as MLS application messages, activity as sealed
    /// ephemeral deposits (M§10, M§11). Never called while a frame is being processed.
    async fn flush_outbox(&mut self) -> Result<()> {
        while !self.outbox.is_empty() {
            let e = self.outbox.remove(0);
            let send = &e["send"];
            if let Some(a) = send["activity"].as_str() {
                self.send_activity(a, send["state"].as_str().unwrap_or("active")).await?;
                continue;
            }
            let kind = send["receipt"].as_str().unwrap_or("");
            if send["to"] == "personal" {
                // M§10.5: an undisclosed watermark goes only to the identity's personal group (M§7.1), which this
                // device does not have; it stays local.
                println!("READ-PRIVATE through={}", send["through"]);
                continue;
            }
            let conversation = self.conversation.clone().context("no conversation")?;
            let now = now_s();
            let mut obj = json!({"object": "receipt", "id": wire::new_id(now), "conversation": conversation,
                "sender": self.identity, "sent_at": now, "kind": kind});
            for k in ["targets", "through"] {
                if let Some(v) = send.get(k) {
                    obj[k] = v.clone();
                }
            }
            let group = self.group.as_mut().context("no group")?;
            let msg = group
                .create_message(self.mls.provider(), &self.mls.signer(), &serde_json::to_vec(&obj)?)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?
                .tls_serialize_detached()?;
            let reply = self.hub_deposit("application", json!({"mls": dsip_core::b64::encode(&msg)})).await?;
            let what = if kind == "read" { obj["through"].clone() } else { obj["targets"].clone() };
            match reply["type"].as_str() {
                Some("accepted") => println!("SENT-RECEIPT {kind} {what}"),
                _ => println!("ERR receipt refused: {}", reply["reason"]),
            }
        }
        Ok(())
    }

    /// Seal and deposit one activity (M§11.1): signed by the device key, AES-256-GCM under the epoch's
    /// exporter key, AAD `group_id ‖ epoch`, 10 s lifetime, no `accepted` expected.
    async fn send_activity(&mut self, activity: &str, state: &str) -> Result<()> {
        let conversation = self.conversation.clone().context("no conversation")?;
        let group = self.group.as_ref().context("no group")?;
        let obj = json!({"object": "activity", "conversation": conversation, "sender": self.identity,
            "activity": activity, "state": state});
        let signed = sign(&obj, &self.keys.device, &self.keys.device.kid());
        let compact = format!("{}.{}.{}", signed.protected, signed.payload, signed.signature);
        let key = dsip_mls::activity_key(group, self.mls.provider()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let nonce: [u8; 12] = rand::random();
        let use_ = dsip_messaging::mls_wire::SealUse::Activity { group: group.group_id().as_slice(), epoch: group.epoch().as_u64() };
        let sealed = dsip_messaging::mls_wire::seal(&key, &nonce, compact.as_bytes(), use_);
        let hub = self.hub.clone().context("no hub")?;
        let env = wire::deposit_delegated(&self.keys.device, vec![self.delegation.clone()], &hub.0, now_s(), &self.group_b64()?,
            "ephemeral", json!({"sealed": dsip_core::b64::encode(&sealed)}));
        self.send(&env).await?;
        println!("SENT-ACTIVITY {activity} {state}");
        Ok(())
    }

    /// Open a pushed activity: the epoch's exporter key, then the device signature, then the leaf it belongs to.
    fn activity_in(&mut self, item: &Value) -> Result<()> {
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let Some(group) = self.group.as_ref() else { return Ok(()) };
        if item["group"].as_str().and_then(dsip_core::b64::decode).as_deref() != Some(group.group_id().as_slice()) {
            return Ok(());
        }
        let sealed = item["sealed"].as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
        let key = dsip_mls::activity_key(group, self.mls.provider()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let use_ = dsip_messaging::mls_wire::SealUse::Activity { group: group.group_id().as_slice(), epoch: group.epoch().as_u64() };
        let Ok(plain) = dsip_messaging::mls_wire::open(&key, &sealed, use_) else {
            println!("DROP activity: not sealed for this epoch");
            return Ok(());
        };
        let compact = String::from_utf8(plain).unwrap_or_default();
        let mut parts = compact.split('.');
        let env = Envelope {
            protected: parts.next().unwrap_or("").to_string(),
            payload: parts.next().unwrap_or("").to_string(),
            signature: parts.next().unwrap_or("").to_string(),
        };
        let Ok(ver) = dsip_core::envelope::verify_raw(&env, &ctx, false) else {
            println!("DROP activity: bad signature");
            return Ok(());
        };
        // M§11.1: the signature attributes it; the signing device must be a leaf of the group.
        let leaf = group
            .members()
            .filter_map(|m| member_identity(group, m.index, &ctx).ok())
            .find(|w| w.device == ver.signer_did)
            .map(|w| w.identity);
        let octx = json!({"conversation": self.conversation, "conversation_kind": self.kind, "leaf_identity": leaf});
        let obj = ver.payload;
        if check_object(&obj, &octx)["verdict"] != "accept" {
            println!("DROP activity from {}: not a member's device", ver.signer_did);
            return Ok(());
        }
        self.tick();
        self.receipts.step(&json!({"activity_in": {"sender": obj["sender"], "activity": obj["activity"], "state": obj["state"],
            "expires_at": item["expires_at"]}}));
        println!("ACTIVITY {} {} {}", obj["sender"].as_str().unwrap_or(""), obj["activity"].as_str().unwrap_or(""),
            obj["state"].as_str().unwrap_or(""));
        Ok(())
    }

    async fn send_text(&mut self, text: &str) -> Result<()> {
        let conversation = self.conversation.clone().context("no conversation")?;
        let now = now_s();
        let obj = json!({"object": "content", "id": wire::new_id(now), "conversation": conversation,
            "sender": self.identity, "sent_at": now, "kind": "text", "purpose": "message",
            "content_type": "text/plain", "text": text});
        let group = self.group.as_mut().context("no group")?;
        let msg = group
            .create_message(self.mls.provider(), &self.mls.signer(), &serde_json::to_vec(&obj)?)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
            .tls_serialize_detached()?;
        let reply = self.hub_deposit("application", json!({"mls": dsip_core::b64::encode(&msg)})).await?;
        if reply["type"] == "accepted" {
            // Our own content is part of the conversation the receipt rules reason about (M§10.2, M§10.3).
            self.tick();
            self.receipts.step(&json!({"sync": {"items": [{"seq": reply["seq"], "object": obj}]}}));
        }
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
                // M§10.2: receipts are decided once per batch (a live push is a batch of one).
                if !self.batch.is_empty() {
                    let items = std::mem::take(&mut self.batch);
                    self.tick();
                    let emissions = self.receipts.step(&json!({"sync": {"items": items}}));
                    self.outbox.extend(emissions);
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

    fn set_conversation(&mut self, conv: &Value) {
        self.kind = conv["kind"].as_str().unwrap_or("direct").to_string();
        self.hub = match (conv["hub"]["did"].as_str(), conv["hub"]["uri"].as_str()) {
            (Some(d), Some(u)) => Some((d.to_string(), u.to_string())),
            _ => None,
        };
    }

    fn save_resume(&self) -> Result<()> {
        self.mls.provider().put_state("resume", &self.resume.snapshot()).map_err(|e| anyhow::anyhow!("{e}"))
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
        if !matches!(class.as_str(), "welcome" | "handshake" | "application") {
            self.resume.commit(item, false);
            return self.save_resume();
        }
        let bytes = item["mls"].as_str().and_then(dsip_core::b64::decode).unwrap_or_default();
        if class != "welcome" && self.own.contains(&digest(&bytes)) {
            // Our own deposit fanned back to our identity (M§6.5 rule 5); arrived before its `accepted` (spec-gap 47).
            self.resume.commit(item, false);
            self.save_resume()?;
            println!("SELF {class} seq={}", item["seq"]);
            return Ok(());
        }
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let before = self.resume.clone();
        let crash = std::mem::take(&mut self.crash_next);
        let (mls, group, resume, conversation, kind) = (&self.mls, &mut self.group, &mut self.resume, &self.conversation, &self.kind);
        let result = mls.provider().atomically(|| {
            let outcome = process(mls, group, conversation, kind, &class, &bytes, &ctx)?;
            if crash {
                // Processed, MLS state written inside the transaction, never committed.
                println!("CRASH {class} {cursor} processed, not committed");
                let _ = std::io::stdout().flush();
                std::process::exit(137);
            }
            resume.commit(item, false);
            mls.provider().put_state("resume", &resume.snapshot())?;
            if let Outcome::Joined { group, .. } = &outcome {
                mls.provider().put_state("group", &json!(group))?;
            }
            Ok(outcome)
        });
        let outcome = match result {
            Ok(o) => o,
            Err(e) => {
                // Rolled back: OpenMLS's in-memory group may be ahead of the database, so reload it.
                self.resume = before;
                if let Some(gid) = self.group_id.clone() {
                    self.group = self.mls.load_group(&gid).map_err(|e| anyhow::anyhow!("{e}"))?;
                }
                // Not processable at all (not a duplicate by seq): record it as handled so it is acknowledged.
                println!("?? unprocessable {class} {cursor}: {e}");
                self.resume.commit(item, false);
                return self.save_resume();
            }
        };
        match outcome {
            Outcome::Joined { conversation, members, group, conv } => {
                self.conversation = Some(conversation.clone());
                self.group_id = dsip_core::b64::decode(&group);
                self.set_conversation(&conv);
                println!("JOINED {conversation} members={members:?}");
                // Confirm the pending group registration (M§6.6).
                let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now_s(), wire::TTL_S,
                    json!({"subject": self.identity, "groups": [{"group": group, "state": "joined"}]}));
                self.send(&env).await?;
            }
            Outcome::Text { sender, object } => {
                println!("RECV {sender}: {}", object["text"].as_str().unwrap_or(""));
                self.batch.push(json!({"seq": item["seq"], "object": object}));
            }
            Outcome::Receipt { sender, object } => {
                let what = if object["kind"] == "read" { object["through"].clone() } else { object["targets"].clone() };
                println!("RECEIPT {sender} {} {what}", object["kind"].as_str().unwrap_or(""));
                self.batch.push(json!({"seq": item["seq"], "object": object}));
            }
            Outcome::Media { sender, object } => {
                self.last_media = object["id"].as_str().map(String::from);
                self.batch.push(json!({"seq": item["seq"], "object": object.clone()}));
                // The item is committed; a failed fetch leaves the content visible and the blob re-fetchable.
                match self.fetch_media(&object).await {
                    Ok((path, sha)) => println!(
                        "RECV-AUDIO {sender} purpose={} duration_ms={} session={} file={} sha256={sha}",
                        object["purpose"].as_str().unwrap_or("message"), object["duration_ms"],
                        object["session"].as_str().unwrap_or("-"), path.display()
                    ),
                    Err(e) => println!("ERR blob {}: {e}", object["id"]),
                }
            }
            Outcome::Dropped(why) => println!("DROP {why}"),
            Outcome::Epoch { epoch, by, added, removed } => {
                println!("EPOCH {epoch} by={by} added={added:?} removed={removed:?}");
            }
            Outcome::Removed { by } => {
                println!("REMOVED from {} by={by}", self.conversation.clone().unwrap_or_default());
                let group = self.group_b64()?;
                let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now_s(), wire::TTL_S,
                    json!({"subject": self.identity, "groups": [{"group": group, "state": "left"}]}));
                self.send(&env).await?;
            }
            Outcome::Nothing => {}
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

/// The MLS side of one item, with no I/O, so it can run inside the item's transaction.
fn process(
    mls: &Device<SqliteProvider>,
    slot: &mut Option<MlsGroup>,
    conversation: &Option<String>,
    kind: &str,
    class: &str,
    bytes: &[u8],
    ctx: &Context,
) -> Result<Outcome, MlsError> {
    if class == "welcome" {
        let group = mls.join(bytes)?;
        let members: Vec<String> = authenticate_members(&group, ctx)?.into_iter().map(|m| m.identity).collect();
        let conv: Value = serde_json::from_slice(&conversation_extension(&group).ok_or_else(|| MlsError("no dsip_conversation".into()))?)
            .map_err(mls_err("dsip_conversation"))?;
        let out = Outcome::Joined {
            conversation: conv["conversation"].as_str().unwrap_or_default().to_string(),
            members,
            group: dsip_core::b64::encode(group.group_id().as_slice()),
            conv,
        };
        *slot = Some(group);
        return Ok(out);
    }
    let Some(group) = slot.as_mut() else { return Ok(Outcome::Nothing) };
    let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(mls_err("mls bytes"))?;
    let pm = msg.try_into_protocol_message().map_err(mls_err("protocol message"))?;
    let processed = group.process_message(mls.provider(), pm).map_err(mls_err("undecryptable"))?;
    let sender = match processed.sender() {
        Sender::Member(idx) => member_identity(group, *idx, ctx).map(|w| w.identity).unwrap_or_default(),
        _ => String::new(),
    };
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
            match obj["object"].as_str() {
                Some("receipt") => Ok(Outcome::Receipt { sender, object: obj }),
                Some("content") if obj.get("blob").is_some() => Ok(Outcome::Media { sender, object: obj }),
                Some("content") => Ok(Outcome::Text { sender, object: obj }),
                _ => Ok(Outcome::Nothing),
            }
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            let added: Vec<String> = staged
                .add_proposals()
                .filter_map(|a| dsip_mls::authenticate_leaf_node(a.add_proposal().key_package().leaf_node(), ctx).ok())
                .map(|w| w.identity)
                .collect();
            let removed: Vec<String> = staged
                .remove_proposals()
                .filter_map(|r| member_identity(group, r.remove_proposal().removed(), ctx).ok())
                .map(|w| w.identity)
                .collect();
            group.merge_staged_commit(mls.provider(), *staged).map_err(mls_err("merge commit"))?;
            if !group.is_active() {
                return Ok(Outcome::Removed { by: sender });
            }
            Ok(Outcome::Epoch { epoch: group.epoch().as_u64(), by: sender, added, removed })
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
    let keys = Keys::load_or_create(&args.state)?;
    if let Some(path) = &args.write_doc {
        let doc = did_document(
            &args.identity,
            &keys.controller,
            args.mailbox_did.as_deref().context("--mailbox-did")?,
            args.mailbox_uri.as_deref().context("--mailbox-uri")?,
        );
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)?;
        println!("OK wrote {}", path.display());
        return Ok(());
    }

    let now = now_s();
    let deleg = delegation_payload(&args.identity, &keys.device.did(), now - 60, now + 365 * 86_400,
        &["dsip.signaling", "dsip.messaging"]);
    let delegation = sign(&deleg, &keys.controller, &format!("{}#key-1", args.identity));
    let compact = format!("{}.{}.{}", delegation.protected, delegation.payload, delegation.signature);
    let provider = SqliteProvider::open(&args.state.join("device.sqlite")).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mls = Device::with_provider(KeyPair::from_seed(keys.device.seed()), compact, provider);
    let r = resolver(&args.resolver_files);
    let mailbox = mailbox_of(&args.identity, &r)?;

    // Restart: everything below comes from the database, exactly as last committed.
    let get = |k: &str| mls.provider().get_state(k).map_err(|e| anyhow::anyhow!("{e}"));
    let resume = Resume::new(&get("resume")?.unwrap_or(Value::Null));
    let group_id = get("group")?.and_then(|g| g.as_str().and_then(dsip_core::b64::decode));
    let group = match &group_id {
        Some(gid) => mls.load_group(gid).map_err(|e| anyhow::anyhow!("{e}"))?,
        None => None,
    };
    let conv = group.as_ref().and_then(conversation_extension).and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let conversation = conv.as_ref().and_then(|c| c["conversation"].as_str().map(String::from));
    if let Some(c) = &conversation {
        println!("RESTORED {c} since={}", resume.sync_fields()["since"]);
    }

    let mut client = Client {
        keys,
        identity: args.identity.clone(),
        delegation,
        mls,
        resolver_files: args.resolver_files.clone(),
        ca: args.ca.clone(),
        conn: None,
        mailbox,
        seen: SeenIds::default(),
        group,
        conversation,
        group_id,
        kind: "direct".into(),
        hub: None,
        own: HashSet::new(),
        resume,
        grants: HashMap::new(),
        crash_next: false,
        state: args.state.clone(),
        http: http_client(args.ca.as_deref())?,
        receipts: dsip_messaging::client::Client::new(&json!({"now": now_s(), "me": args.identity, "member_identities": 2,
            "policy": {"delivered": !args.no_delivered, "read": args.disclose.iter().any(|d| d == "read"),
                       "played": args.disclose.iter().any(|d| d == "played"),
                       "activity": args.disclose.iter().any(|d| d == "activity")}})),
        batch: vec![],
        outbox: vec![],
        last_media: None,
    };
    if let Some(c) = &conv {
        client.set_conversation(c);
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
                    "" => Ok(()),
                    "kp" => client.upload_key_packages(rest.trim().parse().unwrap_or(2)).await,
                    "grant" => {
                        let g = client.grant(rest.trim());
                        let compact = format!("{}.{}.{}", g.protected, g.payload, g.signature);
                        client.grants.insert(rest.trim().to_string(), compact.clone());
                        println!("GRANT {compact}");
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
                        if cmd == "create" { client.create(&kind, &peer, grant).await } else { client.add(&peer, grant, None).await }
                    }
                    "remove" => client.remove(rest.trim()).await,
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
                        // M§10.3: the local user has read everything up to the latest content.
                        let through = client.receipts.snapshot()["timeline"].as_array().and_then(|t| t.last().cloned());
                        match through {
                            Some(t) => {
                                client.tick();
                                let e = client.receipts.step(&json!({"read": {"through": t}}));
                                println!("OK read through={t} ({} to send)", e.len());
                                client.outbox.extend(e);
                                Ok(())
                            }
                            None => Err(anyhow::anyhow!("nothing to read")),
                        }
                    }
                    "play" => {
                        // M§10.4: the local user played a media item (default: the latest received).
                        let id = if rest.trim().is_empty() { client.last_media.clone() } else { Some(rest.trim().to_string()) };
                        match id {
                            Some(id) => {
                                let e = client.receipts.step(&json!({"play": {"id": id}}));
                                println!("OK played {id} ({} to send)", e.len());
                                client.outbox.extend(e);
                                Ok(())
                            }
                            None => Err(anyhow::anyhow!("nothing to play")),
                        }
                    }
                    "typing" | "uploading" | "recording-audio" | "recording-video" => {
                        let state = if rest.trim() == "stop" { "stopped" } else { "active" };
                        client.tick();
                        let e = client.receipts.step(&json!({"activity": {"activity": cmd, "state": state}}));
                        if e.is_empty() {
                            println!("OK {cmd} {state} (not sent: refresh bound or not disclosed)");
                        }
                        client.outbox.extend(e);
                        Ok(())
                    }
                    "status" => {
                        client.tick();
                        println!("STATUS {}", client.receipts.snapshot());
                        Ok(())
                    }
                    "crash-next" => {
                        client.crash_next = true;
                        println!("OK crash-next");
                        Ok(())
                    }
                    "quit" => break,
                    other => {
                        println!("?? unknown command {other}");
                        Ok(())
                    }
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
                    Ok(None) => client.conn = None,
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
