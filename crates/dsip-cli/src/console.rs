//! Interactive `call` / `answer` console over the transport agent.
//!
//! Spec: §25.1 "CLI test tool"; §26 example flow. Every transition is printed
//! with the spec section it implements.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use dsip_core::ulid::Ulid;
use dsip_session::{Emission, LocalEvent};
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use dsip_transport::resolver::build_resolver;
use dsip_transport::tls;

/// Shared connection options.
pub struct ConsoleOpts {
    /// Identity directory.
    pub identity: PathBuf,
    /// Relay URL (None = default or hint-discovered).
    pub relay: Option<String>,
    /// CA/self-signed cert to trust.
    pub ca: Option<PathBuf>,
    /// Offer video.
    pub video: bool,
    /// Scripted commands (`;`-separated, `sleep N` allowed) instead of stdin.
    pub script: Option<String>,
    /// DID document files for the resolver.
    pub did_documents: Vec<PathBuf>,
    /// Timer overrides.
    pub t_establish: Option<i64>,
    /// T-Ring.
    pub t_ring: Option<i64>,
    /// T-Ring-Local.
    pub t_ring_local: Option<i64>,
    /// DHT bootstrap peers.
    pub dht: Vec<libp2p::Multiaddr>,
    /// Publish our reachability hint after binding.
    pub publish_hint: bool,
    /// Hint TTL.
    pub hint_ttl: i64,
}

const DEFAULT_RELAY: &str = "wss://127.0.0.1:8443/dsip";

/// Role-specific behavior.
pub enum Mode {
    /// Place a call to this DID.
    Call {
        /// Callee identity or device DID.
        to: String,
    },
    /// Wait for calls; `auto` = accept | screen | decline | none.
    Answer {
        /// Automatic policy.
        auto: String,
        /// §19.4 policy.
        first_contact: bool,
        /// Pre-authorized contact tokens.
        tokens: Vec<String>,
    },
    /// Send an introduction and wait for the outcome.
    Introduce {
        /// Recipient identity.
        to: String,
        /// Purpose.
        purpose: String,
        /// Contact token.
        token: Option<String>,
        /// Seconds to wait before reporting silence.
        wait: u64,
    },
}

fn short(did: &str) -> String {
    if did.len() > 24 { format!("{}…{}", &did[..16], &did[did.len() - 6..]) } else { did.to_string() }
}

fn sid8(s: &str) -> &str {
    &s[s.len().saturating_sub(8)..]
}

fn print_emission(e: &Emission) {
    match e {
        Emission::Timer { action, name, seconds } => match seconds {
            Some(s) => println!("  ⏱  {name} {action} ({s} s)                      §12.9"),
            None => println!("  ⏱  {name} {action}                             §12.9"),
        },
        Emission::Media(m) => println!("  ♫  media {m}                                   §14.1"),
        Emission::Ui { kind, fields } => {
            let f = fields.iter().map(|(k, v)| format!("{k}={}", v.as_str().map(String::from).unwrap_or_else(|| v.to_string()))).collect::<Vec<_>>().join(" ");
            let sec = match *kind {
                "progress" => "§12.10",
                "answered" => "§14.3",
                "offered" => "§12.4",
                "update_offered" | "update_rejected" => "§12.8",
                "missed_call" => "§12.11",
                "ended" => "§12.4",
                "glare_retry" => "§12.6",
                "introduction_received" | "granted" | "introduction_rejected" => "§19.4",
                "error" => "§15",
                _ => "§12",
            };
            let extra = if *kind == "answered" && f == "answered_by=screening" { "  ← SCREENING MODE (§14.4)" } else { "" };
            println!("  ◆  {kind} {f}{extra}                         {sec}");
        }
        Emission::Info { about } => println!("  ℹ  info for {about}                          §12.12"),
        Emission::Refused(r) => println!("  ✗  refused: {r}"),
        Emission::Drop(r) => println!("  ·  dropped: {r}"),
        Emission::Send(_) | Emission::Deliver { .. } | Emission::Forward { .. } | Emission::Queue { .. } => {}
    }
}

fn print_state(agent: &Agent, sid: &str) {
    if let Some(s) = agent.endpoint().session(sid) {
        let sub = if s.renegotiating() { " [RENEGOTIATING]" } else { "" };
        println!("  ── session …{} {:?} {:?}{sub}", sid8(sid), s.role, s.state);
    }
}

/// Run the console.
pub async fn run(opts: ConsoleOpts, mode: Mode) -> Result<()> {
    let id = Identity::load(&opts.identity)?;
    println!("identity  {}  (\"{}\")", id.meta.identity, id.meta.display_name);
    println!("device    {}", id.meta.device);
    let fetch: Vec<String> = match &mode {
        Mode::Call { to } | Mode::Introduce { to, .. } => vec![to.clone()],
        _ => vec![],
    };
    let resolver = build_resolver(&opts.did_documents, &fetch).await?;

    // Discovery (§8.1): DID document first; did:key has none, so the hints tier may name the peer's relay.
    let dht = if opts.dht.is_empty() { None } else { Some(crate::hints::join(&opts.dht).await?) };
    let mut relay_url = opts.relay.clone();
    if let (Mode::Call { to }, Some(h)) = (&mode, &dht) {
        if relay_url.is_none() {
            if let Some(hint) = crate::hints::discover(h, to).await? {
                relay_url = hint.endpoints.first().map(|e| e.uri.clone());
            }
        }
    }
    let relay_url = relay_url.unwrap_or_else(|| DEFAULT_RELAY.to_string());
    let cfg = AgentConfig {
        relay_url: relay_url.clone(),
        tls: tls::client_config(opts.ca.as_deref())?,
        video: opts.video,
        t_establish: opts.t_establish,
        t_ring: opts.t_ring,
        t_ring_local: opts.t_ring_local,
        first_contact_required: matches!(&mode, Mode::Answer { first_contact: true, .. }),
    };
    let mut agent = Agent::connect(id, cfg, resolver).await?;
    if let Mode::Answer { first_contact, tokens, .. } = &mode {
        if *first_contact {
            println!("policy    first contact required — ungranted invites are rejected policy.first-contact-required   §19.4");
        }
        for t in tokens {
            agent.local(LocalEvent::IssueToken { token: t.clone(), grant_id: Ulid::generate().to_string() }).await?;
            println!("policy    contact token pre-authorized (auto-grant once)   §19.4");
        }
        let held = agent.endpoint().contacts.grants_issued.len();
        if held > 0 {
            println!("contacts  {held} grant(s) issued previously (contacts.json)");
        }
    }
    println!("relay     {}  capabilities {}   §13.2 hello bound", short(&agent.relay().did), agent.relay().capabilities);
    if opts.publish_hint {
        let Some(h) = &dht else { anyhow::bail!("--publish-hint needs --dht <bootstrap>") };
        crate::hints::publish(h, &Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl).await?;
    }
    let mut republish = tokio::time::interval(Duration::from_secs((opts.hint_ttl.max(3) as u64) * 2 / 3));
    republish.tick().await;

    // command source: script or stdin
    let (ctx, mut crx) = mpsc::unbounded_channel::<String>();
    if let Some(script) = opts.script.clone() {
        tokio::spawn(async move {
            for cmd in script.split(';').map(str::trim).filter(|c| !c.is_empty()) {
                if let Some(n) = cmd.strip_prefix("sleep ") {
                    tokio::time::sleep(Duration::from_secs_f64(n.trim().parse().unwrap_or(1.0))).await;
                } else if ctx.send(cmd.to_string()).is_err() {
                    break;
                }
            }
        });
    } else {
        tokio::spawn(async move {
            let mut lines = BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                if ctx.send(l).is_err() {
                    break;
                }
            }
        });
    }

    let mut current: Option<String> = None;
    let mut pending_update: Option<String> = None;
    let auto = match &mode {
        Mode::Answer { auto, .. } => auto.clone(),
        _ => String::new(),
    };
    let mut intro_deadline: Option<tokio::time::Instant> = None;
    let mut cmds_closed = false;
    match &mode {
        Mode::Call { to } => {
            if let Some(g) = agent.endpoint().contacts.held_from(to, dsip_transport::now_s()) {
                println!("contacts  holding grant …{} from {} — attached to the invite   §19.4", sid8(&g), short(to));
            }
            let sid = agent.place_call(to).await?;
            current = Some(sid);
            println!("(commands: cancel | update | answer-update | reject-update | info | hangup | quit)");
        }
        Mode::Introduce { to, purpose, token, wait } => {
            agent.local(LocalEvent::Introduce { id: Ulid::generate().to_string(), to: to.clone(), purpose: Some(purpose.clone()),
                                                 contact_token: token.clone() }).await?;
            println!("   purpose \"{purpose}\" — no session, no media; may not ring; silence is a valid outcome   §19.4");
            intro_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(*wait));
        }
        Mode::Answer { .. } => {
            println!("waiting… (commands: accept | screen | decline | escalate | answer-update | reject-update | info | hangup | requests | grant [id] | reject-intro [id] | revoke <grant> | quit)");
        }
    }

    loop {
        tokio::select! {
            events = agent.next() => {
                for ev in events? {
                    match ev {
                        AgentEvent::Sent { msg_type, session, to } => {
                            println!("→ {msg_type:<8} to {}  session …{}", short(&to), sid8(&session));
                            print_state(&agent, &session);
                        }
                        AgentEvent::Received { message, identity, display_name } => {
                            let name = display_name.map(|n| format!(" \"{n}\"")).unwrap_or_default();
                            let extra = match message.msg_type.as_str() {
                                "progress" => format!(" status={}", message.status.clone().unwrap_or_default()),
                                "answer" => format!(" answered_by={}", message.answered_by.clone().unwrap_or_default()),
                                "reject" | "cancel" | "bye" | "error" => format!(" reason={}", message.reason.clone().unwrap_or_default()),
                                _ => String::new(),
                            };
                            println!("← {:<8} from {}{name} (device {}){extra}   ✓ signature, delegation, replay, schema",
                                     message.msg_type, short(&identity), short(&message.from));
                            let sid = message.session_id().to_string();
                            print_state(&agent, &sid);
                            let offered = agent.endpoint().session(&sid).map(|s| s.state) == Some(dsip_session::SessionState::Offered);
                            if message.msg_type == "invite" && offered {
                                current = Some(sid.clone());
                                match auto.as_str() {
                                    "accept" | "screen" => {
                                        agent.local(LocalEvent::Alert { session: sid.clone(), ring_timeout: Some(60) }).await?;
                                        let ab = if auto == "screen" { "screening" } else { "user" };
                                        agent.local(LocalEvent::Accept { session: sid.clone(), answered_by: Some(ab.into()) }).await?;
                                    }
                                    "decline" => {
                                        agent.local(LocalEvent::Alert { session: sid.clone(), ring_timeout: Some(60) }).await?;
                                        agent.local(LocalEvent::Decline { session: sid.clone() }).await?;
                                    }
                                    _ => {
                                        agent.local(LocalEvent::Alert { session: sid.clone(), ring_timeout: Some(120) }).await?;
                                        println!("  ☎  RINGING — type accept / screen / decline");
                                    }
                                }
                            }
                            if message.msg_type == "update" {
                                pending_update = Some(message.id.clone());
                                println!("  ☎  update offered — type answer-update / reject-update");
                            }
                            if message.msg_type == "introduction" {
                                println!("  ✉  REQUEST (not a call): \"{}\" — type grant / reject-intro, or ignore (silence is a valid outcome)",
                                         message.purpose.clone().unwrap_or_default());
                            }
                        }
                        AgentEvent::Emission(e) => {
                            print_emission(&e);
                            if let Emission::Ui { kind, .. } = &e {
                                if matches!(*kind, "granted" | "introduction_rejected") && intro_deadline.is_some() {
                                    agent.save_contacts()?;
                                    agent.close().await;
                                    println!("bye.");
                                    return Ok(());
                                }
                            }
                        }
                        AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                        AgentEvent::Reconnected { attempts } => println!("↻ reconnected after {attempts} attempt(s)           §13.2"),
                    }
                }
                agent.save_contacts()?;
            }
            _ = async { tokio::time::sleep_until(intro_deadline.unwrap()).await }, if intro_deadline.is_some() => {
                println!("·  no response — silence is the default outcome and means nothing (§19.4)");
                break;
            }
            _ = republish.tick(), if opts.publish_hint => {
                // Re-sign before expiry (§8.3: expired records are invalid); the node re-announces in between.
                if let Some(h) = &dht {
                    crate::hints::publish(h, &Identity::load(&opts.identity)?, &relay_url, opts.hint_ttl).await?;
                }
            }
            cmd = crx.recv(), if !cmds_closed => {
                let Some(cmd) = cmd else {
                    // Script finished (without `quit`) → done. Stdin EOF with no script → keep serving.
                    if opts.script.is_some() { break }
                    cmds_closed = true;
                    continue;
                };
                let mut parts = cmd.splitn(2, ' ');
                let verb = parts.next().unwrap_or("");
                let arg = parts.next().map(str::trim).filter(|a| !a.is_empty()).map(String::from);
                let latest_request = || agent.requests().last().map(|(id, _)| id.clone());
                let year = dsip_transport::now_s() + 31_536_000;
                match verb {
                    "requests" => {
                        for (id, identity) in agent.requests() { println!("  ✉  …{}  from {}", sid8(&id), short(&identity)); }
                        continue;
                    }
                    "grant" => {
                        if let Some(intro) = arg.clone().or_else(latest_request) {
                            agent.local(LocalEvent::Grant { introduction: intro, id: Ulid::generate().to_string(), scope: vec!["dsip.invite".into()], valid_until: year }).await?;
                        } else { println!("no pending request"); }
                        agent.save_contacts()?;
                        continue;
                    }
                    "reject-intro" => {
                        if let Some(intro) = arg.clone().or_else(latest_request) {
                            agent.local(LocalEvent::RejectIntroduction { introduction: intro, reason: Some("user.declined".into()) }).await?;
                        } else { println!("no pending request"); }
                        continue;
                    }
                    "revoke" => {
                        if let Some(g) = arg.clone() { agent.local(LocalEvent::Revoke { grant: g }).await?; agent.save_contacts()?; }
                        continue;
                    }
                    "token" => {
                        if let Some(t) = arg.clone() { agent.local(LocalEvent::IssueToken { token: t, grant_id: Ulid::generate().to_string() }).await?; }
                        continue;
                    }
                    "quit" => break,
                    _ => {}
                }
                let Some(sid) = current.clone() else {
                    if cmd == "quit" { break }
                    println!("no session yet");
                    continue;
                };
                let ev = match cmd.as_str() {
                    "cancel" => Some(LocalEvent::Cancel { session: sid }),
                    "hangup" => Some(LocalEvent::Hangup { session: sid }),
                    "accept" => Some(LocalEvent::Accept { session: sid, answered_by: Some("user".into()) }),
                    "screen" => Some(LocalEvent::Accept { session: sid, answered_by: Some("screening".into()) }),
                    "decline" => Some(LocalEvent::Decline { session: sid }),
                    "update" => Some(LocalEvent::Update { session: sid, id: Ulid::generate().to_string(), answered_by: None }),
                    "escalate" => Some(LocalEvent::Update { session: sid, id: Ulid::generate().to_string(), answered_by: Some("user".into()) }),
                    "answer-update" => pending_update.take().map(|u| LocalEvent::AnswerUpdate { session: sid, in_reply_to: u, answered_by: Some("user".into()) }),
                    "reject-update" => pending_update.take().map(|u| LocalEvent::RejectUpdate { session: sid, in_reply_to: u, reason: "media.unsupported".into() }),
                    "info" => Some(LocalEvent::Info { session: sid }),
                    "quit" => break,
                    other => { println!("unknown command {other}"); None }
                };
                if let Some(ev) = ev {
                    agent.local(ev).await?;
                }
            }
        }
    }
    agent.close().await;
    if let Some(h) = dht {
        h.shutdown().await;
    }
    println!("bye.");
    Ok(())
}
