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
    /// Relay URL.
    pub relay: String,
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
}

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
        Emission::Ui { kind, field } => {
            let f = field.as_ref().map(|(k, v)| format!("{k}={v}")).unwrap_or_default();
            let sec = match *kind {
                "progress" => "§12.10",
                "answered" => "§14.3",
                "offered" => "§12.4",
                "update_offered" | "update_rejected" => "§12.8",
                "missed_call" => "§12.11",
                "ended" => "§12.4",
                "glare_retry" => "§12.6",
                _ => "§12",
            };
            let extra = if *kind == "answered" && f == "answered_by=screening" { "  ← SCREENING MODE (§14.4)" } else { "" };
            println!("  ◆  {kind} {f}{extra}                         {sec}");
        }
        Emission::Info { about } => println!("  ℹ  info for {about}                          §12.12"),
        Emission::Refused(r) => println!("  ✗  refused: {r}"),
        Emission::Drop(r) => println!("  ·  dropped: {r}"),
        Emission::Send(_) | Emission::Deliver { .. } | Emission::Forward { .. } => {}
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
        Mode::Call { to } => vec![to.clone()],
        _ => vec![],
    };
    let resolver = build_resolver(&opts.did_documents, &fetch).await?;
    let cfg = AgentConfig {
        relay_url: opts.relay.clone(),
        tls: tls::client_config(opts.ca.as_deref())?,
        video: opts.video,
        t_establish: opts.t_establish,
        t_ring: opts.t_ring,
        t_ring_local: opts.t_ring_local,
    };
    let mut agent = Agent::connect(id, cfg, resolver).await?;
    println!("relay     {}  capabilities {}   §13.2 hello bound", short(&agent.relay().did), agent.relay().capabilities);

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
        Mode::Answer { auto } => auto.clone(),
        _ => String::new(),
    };
    if let Mode::Call { to } = &mode {
        let sid = agent.place_call(to).await?;
        current = Some(sid);
    } else {
        println!("waiting for invites… (commands: accept | screen | decline | escalate | answer-update | reject-update | info | hangup | quit)");
    }
    if matches!(mode, Mode::Call { .. }) {
        println!("(commands: cancel | update | answer-update | reject-update | info | hangup | quit)");
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
                            if message.msg_type == "invite" {
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
                        }
                        AgentEvent::Emission(e) => print_emission(&e),
                        AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                        AgentEvent::Reconnected { attempts } => println!("↻ reconnected after {attempts} attempt(s)           §13.2"),
                    }
                }
            }
            cmd = crx.recv() => {
                let Some(cmd) = cmd else { break };
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
    println!("bye.");
    Ok(())
}
