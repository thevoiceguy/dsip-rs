//! A messaging device: one identity's device, its MLS state, and a connection to its mailbox.
//!
//! Spec: M§4.2 (find the mailbox in the DID document), M§5.4–M§5.5 (sync, KeyPackages), M§6.2–M§6.7
//! (leaves, groups, welcomes), M§8.1 (content objects), M§9.1 (deposit once), M§14.1–M§14.2 (grants).
//!
//! M§5.4, M§8.5 (durable delivery state across restarts).
//!
//! Impl: commands on stdin, events on stdout, so a demo script can drive two of these. MLS state and
//! the delivery state ([`Resume`]: ack cursor, seq positions, joined groups) live in one SQLite
//! database under `--state`, and each inbound item is processed and committed in one transaction
//! (spec-gap 44), so the process can be killed at any point and restarted. `offline` only drops the
//! connection; `crash-next` exits after processing the next new item and before committing it.

use std::collections::HashMap;
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
use dsip_mls::{authenticate_key_package, authenticate_members, conversation_extension, member_identity, Device, MlsError};
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
    resume: Resume,
    grants: HashMap<String, String>,
    crash_next: bool,
}

/// What processing one inbound item produced, reported only once it is committed.
enum Outcome {
    Joined { conversation: String, members: Vec<String>, group: String },
    Text { sender: String, text: String },
    Dropped(String),
    Epoch(u64),
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

    /// Create the direct conversation with `peer`: fetch its KeyPackage, commit, welcome it (M§6.7, M§7.2).
    async fn create(&mut self, peer: &str, grant: Option<String>) -> Result<()> {
        let mut peer_conn = self.peer_connect(peer).await?;
        let mut fields = json!({"target": peer});
        if let Some(g) = &grant {
            fields["grant"] = json!(g);
        }
        let fetch = wire::message(&self.keys.device, "key-package-fetch", &peer_conn.relay.did.clone(), now_s(), wire::TTL_S, fields);
        peer_conn.send(&fetch).await?;
        let reply = peer_conn.recv().await?.context("no reply to key-package-fetch")?;
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

        let now = now_s();
        let conversation = wire::new_id(now);
        let group_id = wire::new_id(now).into_bytes();
        let conv = json!({"conversation": conversation, "kind": "direct",
            "hub": {"did": self.mailbox.0, "uri": self.mailbox.1}, "successor_of": null});
        let mut group = self.mls.create_group(&group_id, &serde_json::to_vec(&conv)?).map_err(|e| anyhow::anyhow!("{e}"))?;
        let group_b64 = dsip_core::b64::encode(&group_id);

        // The hub's public view is bootstrapped from the group's first GroupInfo (M§6.5 rule 6).
        let gi = group
            .export_group_info(self.mls.provider().crypto(), &self.mls.signer(), true)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let env = wire::deposit(&self.keys.device, &self.mailbox.0, now, &group_b64, "group-info",
            json!({"mls": dsip_core::b64::encode(&gi.tls_serialize_detached()?)}));
        self.send(&env).await?;

        let (commit, welcome, _) = group
            .add_members(self.mls.provider(), &self.mls.signer(), &[kp])
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let (commit, welcome) = (commit.tls_serialize_detached()?, welcome.tls_serialize_detached()?);
        let env = wire::deposit(&self.keys.device, &self.mailbox.0, now, &group_b64, "handshake",
            json!({"mls": dsip_core::b64::encode(&commit)}));
        self.send(&env).await?;
        group.merge_pending_commit(self.mls.provider()).map_err(|e| anyhow::anyhow!("{e:?}"))?;

        // The welcome goes straight into the peer's mailbox, with the grant that admits it (M§14.2).
        let mut fields = json!({"recipient": peer, "mls": dsip_core::b64::encode(&welcome),
            "hub": {"did": self.mailbox.0, "uri": self.mailbox.1}});
        if let Some(g) = grant {
            fields["grants"] = json!([g]);
        }
        let env = wire::deposit(&self.keys.device, &peer_conn.relay.did.clone(), now, &group_b64, "welcome", fields);
        peer_conn.send(&env).await?;
        let _ = peer_conn.recv().await?;
        peer_conn.close(tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal, "done").await;

        self.mls.provider().put_state("group", &json!(group_b64)).map_err(|e| anyhow::anyhow!("{e}"))?;
        self.group = Some(group);
        self.conversation = Some(conversation.clone());
        self.group_id = Some(group_id);
        println!("OK conversation {conversation} with {peer}");
        Ok(())
    }

    async fn send_text(&mut self, text: &str) -> Result<()> {
        let (Some(conversation), Some(group_id)) = (self.conversation.clone(), self.group_id.clone()) else {
            bail!("no conversation");
        };
        let now = now_s();
        let obj = json!({"object": "content", "id": wire::new_id(now), "conversation": conversation,
            "sender": self.identity, "sent_at": now, "kind": "text", "purpose": "message",
            "content_type": "text/plain", "text": text});
        let group = self.group.as_mut().context("no group")?;
        let msg = group
            .create_message(self.mls.provider(), &self.mls.signer(), &serde_json::to_vec(&obj)?)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
            .tls_serialize_detached()?;
        let env = wire::deposit(&self.keys.device, &self.mailbox.0, now, &dsip_core::b64::encode(&group_id), "application",
            json!({"mls": dsip_core::b64::encode(&msg)}));
        self.send(&env).await?;
        println!("OK sent");
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
        self.mls.provider().put_state("resume", &self.resume.snapshot()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// Process one item and commit it with the delivery state, or not at all (M§5.4, spec-gap 44).
    async fn item(&mut self, item: &Value) -> Result<()> {
        let cursor = item["cursor"].as_str().unwrap_or("").to_string();
        let class = item["class"].as_str().unwrap_or("").to_string();
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
        let r = resolver(&self.resolver_files);
        let ctx = self.ctx(&r);
        let before = self.resume.clone();
        let crash = std::mem::take(&mut self.crash_next);
        let (mls, group, resume, conversation) = (&self.mls, &mut self.group, &mut self.resume, &self.conversation);
        let result = mls.provider().atomically(|| {
            let outcome = process(mls, group, conversation, &class, &bytes, &ctx)?;
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
            Outcome::Joined { conversation, members, group } => {
                self.conversation = Some(conversation.clone());
                self.group_id = dsip_core::b64::decode(&group);
                println!("JOINED {conversation} members={members:?}");
                // Confirm the pending group registration (M§6.6).
                let env = wire::message(&self.keys.device, "mailbox-config", &self.mailbox.0, now_s(), wire::TTL_S,
                    json!({"subject": self.identity, "groups": [{"group": group, "state": "joined"}]}));
                self.send(&env).await?;
            }
            Outcome::Text { sender, text } => println!("RECV {sender}: {text}"),
            Outcome::Dropped(why) => println!("DROP {why}"),
            Outcome::Epoch(e) => println!("EPOCH {e}"),
            Outcome::Nothing => {}
        }
        Ok(())
    }
}

fn mls_err<E: std::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> MlsError {
    move |x| MlsError(format!("{what}: {x:?}"))
}

/// The MLS side of one item, with no I/O, so it can run inside the item's transaction.
fn process(
    mls: &Device<SqliteProvider>,
    slot: &mut Option<MlsGroup>,
    conversation: &Option<String>,
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
            let octx = json!({"conversation": conversation, "conversation_kind": "direct", "leaf_identity": sender});
            let verdict = check_object(&obj, &octx);
            if verdict["verdict"] != "accept" {
                return Ok(Outcome::Dropped(format!("{} {}", verdict["code"], obj["id"])));
            }
            Ok(Outcome::Text { sender, text: obj["text"].as_str().unwrap_or("").to_string() })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group.merge_staged_commit(mls.provider(), *staged).map_err(mls_err("merge commit"))?;
            Ok(Outcome::Epoch(group.epoch().as_u64()))
        }
        _ => Ok(Outcome::Nothing),
    }
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
    let conversation = group
        .as_ref()
        .and_then(conversation_extension)
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|c| c["conversation"].as_str().map(String::from));
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
        resume,
        grants: HashMap::new(),
        crash_next: false,
    };
    client.connect().await?;

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
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
                    "create" => {
                        let (peer, grant) = rest.split_once(' ').unwrap_or((rest, ""));
                        let grant = if grant.trim().is_empty() {
                            None
                        } else {
                            Some(std::fs::read_to_string(grant.trim())?.trim().to_string())
                        };
                        client.create(peer.trim(), grant).await
                    }
                    "send" => client.send_text(rest).await,
                    "sync" => client.sync(false).await,
                    "live" => client.sync(true).await,
                    "offline" => {
                        client.conn = None;
                        println!("OK offline");
                        Ok(())
                    }
                    "online" => client.connect().await,
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
                std::io::stdout().flush()?;
            }
            frame = recv => {
                match frame {
                    Ok(Some(text)) => {
                        if let Err(e) = client.inbound(&text).await {
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
