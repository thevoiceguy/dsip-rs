//! Verified Broadcast roles on the command line: publisher, receiver, processor.
//!
//! Spec: §22.1 (publish a signed record to the publisher's authority), §9.3
//! (subscribe; first notify carries current state; renewal), §22.2–§22.3
//! (receiver verifies the publisher and every provenance statement, selects a
//! compatible variant, and displays the delivery path honestly), §27 (flow).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, Result};
use serde_json::{json, Value};

use dsip_broadcast::{evaluate_publication, PROFILE, PROVENANCE_EXTENSION};
use dsip_core::did::StaticResolver;
use dsip_core::envelope::{Context, Envelope};
use dsip_schema::SemanticContext;
use dsip_transport::agent::{Agent, AgentConfig, AgentEvent};
use dsip_transport::identity::Identity;
use dsip_transport::{now_s, tls};

/// Connection options shared by the broadcast roles.
pub struct Conn {
    /// Identity directory.
    pub identity: PathBuf,
    /// Relay (authority) URL.
    pub relay: String,
    /// CA/self-signed cert.
    pub ca: Option<PathBuf>,
}

fn short(did: &str) -> String {
    if did.len() > 28 { format!("{}…{}", &did[..18], &did[did.len() - 6..]) } else { did.to_string() }
}

fn bcast_version() -> Value {
    json!({"core": "1.0", "min_core": "1.0", "profiles": [PROFILE], "extensions": [PROVENANCE_EXTENSION], "critical": []})
}

async fn connect(c: &Conn) -> Result<Agent> {
    let id = Identity::load(&c.identity)?;
    let cfg = AgentConfig {
        relay_url: c.relay.clone(),
        tls: tls::client_config(c.ca.as_deref())?,
        video: false,
        t_establish: None,
        t_ring: None,
        t_ring_local: None,
        first_contact_required: false,
    };
    let agent = Agent::connect(id, cfg, StaticResolver::default()).await?;
    println!("identity  {}", agent.identity_did());
    println!("authority {} (this relay)   §9.3", short(&agent.relay().did));
    Ok(agent)
}

/// Listen briefly for signed relay errors (no silent drops, §13.2) and print them.
async fn drain(agent: &mut Agent, ms: u64) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
    loop {
        let events = tokio::select! {
            ev = agent.next() => ev?,
            _ = tokio::time::sleep_until(deadline) => return Ok(()),
        };
        for ev in events {
            match ev {
                AgentEvent::Received { message, payload, .. } if message.msg_type == "error" => {
                    println!("← error    {} {}", payload["reason"], payload.get("detail").and_then(Value::as_str).unwrap_or(""));
                }
                AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                _ => {}
            }
        }
    }
}

/// A variant spec `id,codec,transport,uri[,integrity]`.
pub fn parse_variant(s: &str) -> Result<Value> {
    let parts: Vec<&str> = s.split(',').map(str::trim).collect();
    anyhow::ensure!(parts.len() >= 4, "variant must be id,codec,transport,uri[,integrity]");
    let media = if parts[1].starts_with("codec:video/") { json!(["audio", "video"]) } else { json!(["audio"]) };
    Ok(json!({"id": parts[0], "media": media, "codec": parts[1], "transport": parts[2], "uri": parts[3],
              "integrity": parts.get(4).copied().unwrap_or("metadata-only")}))
}

/// `dsip publish`: sign and send a publication record to the authority; returns the publication id.
pub async fn publish(c: &Conn, stream_suffix: &str, title: &str, state: &str, variants: Vec<Value>, ttl: i64, policy: Value) -> Result<()> {
    let mut agent = connect(c).await?;
    let stream = format!("{}:{}", agent.identity_did(), stream_suffix);
    let p = json!({
        "dsip": bcast_version(), "type": "publish", "from": agent.identity_did(), "publisher": agent.identity_did(), "stream_id": stream,
        "title": title, "state": state, "variants": variants, "policy": policy,
    });
    let frame = agent.send_payload(p, ttl).await?;
    let env = Envelope::from_frame(&frame).map_err(|v| anyhow::anyhow!("{:?}", v.code))?;
    let payload: Value = serde_json::from_slice(&dsip_core::b64::decode(&env.payload).context("payload")?)?;
    println!("→ publish  stream {stream}  state {state}  publication {}  ttl {ttl} s   §22.1", payload["id"]);
    println!("           variants: {}", payload["variants"].as_array().map(|a| a.iter().map(|v| format!("{} ({} over {})", v["id"].as_str().unwrap_or(""), v["codec"].as_str().unwrap_or(""), v["transport"].as_str().unwrap_or(""))).collect::<Vec<_>>().join(", ")).unwrap_or_default());
    std::fs::write(c.identity.join("last-publication.json"), json!({"stream": stream, "publication": payload["id"]}).to_string())?;
    drain(&mut agent, 400).await?;
    agent.close().await;
    Ok(())
}

/// `dsip unpublish`: withdraw the last (or given) publication.
pub async fn unpublish(c: &Conn, stream_suffix: &str, publication: Option<String>) -> Result<()> {
    let mut agent = connect(c).await?;
    let stream = format!("{}:{}", agent.identity_did(), stream_suffix);
    let pid = match publication {
        Some(p) => p,
        None => {
            let last: Value = serde_json::from_slice(&std::fs::read(c.identity.join("last-publication.json")).context("no last publication; pass --publication")?)?;
            last["publication"].as_str().unwrap_or("").to_string()
        }
    };
    let p = json!({"dsip": bcast_version(), "type": "unpublish", "from": agent.identity_did(), "publisher": agent.identity_did(), "stream_id": stream, "publication": pid});
    agent.send_payload(p, 30).await?;
    println!("→ unpublish stream {stream} publication {pid}   §22.1");
    drain(&mut agent, 400).await?;
    agent.close().await;
    Ok(())
}

/// `dsip provenance`: a processor (relay/transcoder) attaches its signed statement to a publication.
pub async fn provenance(c: &Conn, stream: &str, publication: &str, operation: &str, input: &str, output: &str, uri: Option<String>) -> Result<()> {
    let mut agent = connect(c).await?;
    let mut p = json!({
        "dsip": bcast_version(), "type": "broadcast.provenance", "from": agent.identity_did(), "original_stream": stream, "original_publication": publication,
        "processor": agent.identity_did(), "operation": operation, "input_variant": input, "output_variant": output,
    });
    if let Some(u) = uri {
        p["output_uri"] = u.into();
    }
    agent.send_payload(p, 3600).await?;
    println!("→ provenance  {operation} {input} → {output} on {}/{}  signed by processor {}   §22.3", short(stream), &publication[publication.len().saturating_sub(8)..], short(agent.identity_did()));
    drain(&mut agent, 400).await?;
    agent.close().await;
    Ok(())
}

/// `dsip subscribe`: subscribe to publication or presence events and verify what arrives.
pub async fn subscribe(c: &Conn, target: &str, events: Vec<String>, expires_in: i64, wait: u64, codecs: Vec<String>, transports: Vec<String>) -> Result<()> {
    let mut agent = connect(c).await?;
    let authority = agent.relay().did.clone();
    let p = json!({"dsip": bcast_version(), "type": "subscribe", "to": authority, "target": target, "events": events, "expires_in": expires_in});
    let frame = agent.send_payload(p, 30).await?;
    let sub_id = Envelope::from_frame(&frame)
        .ok()
        .and_then(|e| dsip_core::b64::decode(&e.payload))
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v["id"].as_str().map(String::from))
        .unwrap_or_default();
    println!("→ subscribe  target {}  events {:?}  expires_in {expires_in}  (subscription …{})   §9.3", short(target), events, &sub_id[sub_id.len().saturating_sub(8)..]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    let resolver = StaticResolver::default();
    let mut seq_seen = 0u64;
    loop {
        let events = tokio::select! {
            ev = agent.next() => ev?,
            _ = tokio::time::sleep_until(deadline) => break,
        };
        for ev in events {
            match ev {
                AgentEvent::Received { message, identity, payload, .. } if message.msg_type == "notify" => {
                    let seq = payload["seq"].as_u64().unwrap_or(0);
                    if seq <= seq_seen {
                        println!("· dropped notify seq {seq} (stale)   §9.3");
                        continue;
                    }
                    seq_seen = seq;
                    let state = payload["state"].as_str().unwrap_or("");
                    println!("← notify   seq {seq} {state} from authority {}{}", short(&identity),
                             payload.get("reason").and_then(Value::as_str).map(|r| format!("  reason {r}")).unwrap_or_default());
                    let body = &payload["body"];
                    if body["event"] == "presence" {
                        println!("           presence: {}   (authority-asserted, §9.2/§9.4)", body["state"]);
                    } else {
                        println!("           publication state: {}", body["state"]);
                        if let Some(record) = body["record"].as_str() {
                            show_record(record, body["statements"].as_array().cloned().unwrap_or_default(), &resolver, &codecs, &transports);
                        }
                    }
                    if state == "terminated" {
                        println!("           subscription terminated — final (§9.3)");
                        agent.close().await;
                        return Ok(());
                    }
                }
                AgentEvent::Received { message, payload, .. } if message.msg_type == "error" => {
                    println!("← error    {} {}   (signed by the relay; e.g. a subscribe above the per-event cap is refused, §9.3)", payload["reason"], payload.get("detail").and_then(Value::as_str).unwrap_or(""));
                    agent.close().await;
                    return Ok(());
                }
                AgentEvent::Received { message, identity, payload, .. } if message.msg_type == "reject" => {
                    println!("← reject   {} from {}   (uniform for unauthorized and nonexistent targets, §9.3)", payload["reason"], short(&identity));
                    agent.close().await;
                    return Ok(());
                }
                AgentEvent::Rejected(code, detail) => println!("✗ inbound rejected: {code} {detail}"),
                _ => {}
            }
        }
    }
    println!("· wait over");
    agent.close().await;
    Ok(())
}

/// Verify an embedded record (and statements) independently of the relay and print the §22.3 display.
fn show_record(record: &str, statements: Vec<Value>, resolver: &StaticResolver, codecs: &[String], transports: &[String]) {
    let Ok(env) = Envelope::from_frame(record) else { return println!("           record: malformed") };
    let prov: Vec<Envelope> = statements.iter().filter_map(Value::as_str).filter_map(|f| Envelope::from_frame(f).ok()).collect();
    let ctx = Context::new(now_s(), resolver);
    let sem = SemanticContext { supported: dsip_core::version::Supported::from_json(Some(&json!({"core": "1.0", "profiles": [PROFILE, "interactive-media/1.0"], "extensions": [PROVENANCE_EXTENSION]}))), ..Default::default() };
    match evaluate_publication(&env, &prov, codecs, transports, &ctx, &sem) {
        Ok((signer, r)) => {
            let p = &r.publication;
            println!("           ✓ record verified: publisher {}  (signed by {})   §22.1", short(&r.publisher), short(&signer));
            println!("             title \"{}\"  state {}  policy {}", p["title"].as_str().unwrap_or(""), p["state"], p["policy"]);
            for v in p["variants"].as_array().into_iter().flatten() {
                let pick = if r.selected_variant.as_deref() == v["id"].as_str() { "  ← selected" } else { "" };
                println!("             variant {}: {} over {} @ {}{pick}", v["id"].as_str().unwrap_or(""), v["codec"].as_str().unwrap_or(""), v["transport"].as_str().unwrap_or(""), v["uri"].as_str().unwrap_or(""));
            }
            if r.selected_variant.is_none() {
                println!("             (no variant matches this receiver's codecs/transports)");
            }
            for s in &r.provenance {
                if s["verdict"] == "accept" {
                    println!("             provenance ✓ {} by {}{}", s["operation"].as_str().unwrap_or(""), short(s["processor"].as_str().unwrap_or("")),
                             s.get("policy_violation").and_then(Value::as_str).map(|v| format!("  ⚠ violates publisher policy: {v}")).unwrap_or_default());
                } else {
                    println!("             provenance ✗ {}", s["code"]);
                }
            }
            println!("             Original publisher: {}", short(&r.publisher));
            println!("             Delivered by:       {}", if r.delivered_by.is_empty() { "(direct)".to_string() } else { r.delivered_by.iter().map(|d| short(d)).collect::<Vec<_>>().join(", ") });
            println!("             Transcoded by:      {}", if r.transcoded_by.is_empty() { "—".to_string() } else { r.transcoded_by.iter().map(|d| short(d)).collect::<Vec<_>>().join(", ") });
            println!("             Integrity mode:     {}   §22.2", r.integrity_mode());
        }
        Err(v) => println!("           ✗ record rejected: {:?} {}", v.code, v.detail.unwrap_or_default()),
    }
}
