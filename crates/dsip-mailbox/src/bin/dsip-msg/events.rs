//! Device events in a messaging device: the gateway that turns SNMP and syslog from the LAN into signed
//! `device-event` content (E§3–E§4), and the alarm lists an operator's device keeps from what it receives
//! (E§5–E§6). Only dsip-msg has these; the messaging client it hosts knows nothing of them.
//!
//! Spec: E§2 (the device claim and its basis, rendered), E§3 (gateway mode: SNMP v1/v2c/v3 USM, SNMP over
//! TLS and DTLS, syslog over UDP and TLS, signed syslog; an inform answered once its event is accepted), E§4
//! (hold-down), E§5 (alarm lists, heartbeats, `alarm-ack`), E§6 (escalation).
//!
//! Impl: listener tasks feed one channel ([`GatewayInput`]) that the main loop drains; all the gateway's state
//! is in [`Events`], and its deposits go through the device's own outbox like any other content.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::{json, Value};

use dsip_mailbox::wire;
use dsip_transport::now_s;

use super::{Args, Client};

/// The device-events state of one device: its alarm lists, and in gateway mode everything the gateway holds.
pub(super) struct Events {
    /// The alarm list of each group carrying device events (E§5), and when it was last advanced.
    alarms: BTreeMap<String, (dsip_events::AlarmList, i64)>,
    /// The escalation policy when this device is an escalation agent (E§6), and its command.
    escalation: Option<(Value, Option<String>)>,
    /// Gateway mode (E§3): the SNMP socket and the rule table.
    snmp: Option<std::sync::Arc<tokio::net::UdpSocket>>,
    snmp_rules: Value,
    /// E§4 hold-down (v0.10) and the events whose clears it holds, by alarm key.
    hold_down: dsip_events::HoldDown,
    held_events: HashMap<(String, String, String), Value>,
    /// E§3 signed syslog: the collector, its clock, and each held message's transport (address, TLS certificate).
    syslog_sign: Option<(dsip_events::syslog_sign::Collector, i64)>,
    syslog_held: HashMap<String, std::collections::VecDeque<(std::net::SocketAddr, Option<String>)>>,
    /// The address each signer HOSTNAME (lowercase) last sent from, for a gap found by the clock (E§5).
    syslog_signer_at: HashMap<String, std::net::SocketAddr>,
    /// E§2 certificate names.
    tls_names: Value,
    /// SNMPv3 (E§3): the USM receiver, when users are configured.
    usm: Option<dsip_events::usm::UsmReceiver>,
    syslog_table: Value,
    /// The informs, their responses and the outbox items whose acceptance answers them (E§3).
    informs: dsip_events::InformTracker,
    inform_responses: HashMap<(String, i64), (Vec<u8>, ReplyTo)>,
    inform_items: HashMap<String, (String, i64)>,
    inform_clock: i64,
    /// The gateway's snmpEngineID, for RFC 5343 discovery over TLS (E§3).
    snmp_engine: Vec<u8>,
    /// The heartbeat (E§5): interval, last sent.
    heartbeat: Option<(i64, i64)>,
}

impl Events {
    /// The device-events state the command line asks for; binds the SNMP socket in gateway mode.
    pub(super) async fn new(args: &Args) -> Result<Events> {
        Ok(Events {
            alarms: BTreeMap::new(),
            escalation: args.escalate_min.as_ref().map(|min| {
                (json!({"min_severity": min, "after_s": args.escalate_after}), args.escalate_cmd.clone())
            }),
            snmp: match &args.snmp_listen {
                Some(a) => Some(std::sync::Arc::new(tokio::net::UdpSocket::bind(a).await.with_context(|| format!("binding {a}"))?)),
                None => None,
            },
            hold_down: dsip_events::HoldDown::new(now_s(), args.hold_down),
            syslog_sign: match &args.syslog_signers {
                Some(p) => Some((dsip_events::syslog_sign::Collector::new(now_s(), args.syslog_sign_hold, &syslog_signers(p)?), now_s())),
                None => None,
            },
            syslog_held: HashMap::new(),
            syslog_signer_at: HashMap::new(),
            held_events: HashMap::new(),
            tls_names: match &args.syslog_tls_names {
                Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?).context("--syslog-tls-names")?,
                None => json!({}),
            },
            snmp_rules: match &args.snmp_rules {
                Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?).context("snmp rules")?,
                None => json!([]),
            },
            usm: match &args.snmp_users {
                Some(p) => Some(usm_receiver(&args.state, args.snmp_engine_id.as_deref(), p)?),
                None => None,
            },
            syslog_table: match &args.syslog_table {
                Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?).context("syslog table")?,
                None => json!({}),
            },
            informs: dsip_events::InformTracker::new(&json!({"now": now_s()})),
            inform_responses: HashMap::new(),
            snmp_engine: match (&args.snmp_tls_listen, &args.snmp_users) {
                (Some(_), _) | (_, Some(_)) => snmp_engine_id(&args.state, args.snmp_engine_id.as_deref())?.0,
                _ => vec![],
            },
            inform_items: HashMap::new(),
            inform_clock: now_s(),
            heartbeat: args.heartbeat.map(|n| (n, 0)),
        })
    }

    /// Whether the ticker has gateway work: a socket, a heartbeat, held clears or a signed-syslog clock.
    pub(super) fn gateway_due(&self) -> bool {
        self.snmp.is_some() || self.heartbeat.is_some() || !self.held_events.is_empty() || self.syslog_sign.is_some()
    }

    /// Start the gateway listeners the command line asks for; what they receive comes out of the channel.
    pub(super) async fn listen(&self, args: &Args) -> Result<tokio::sync::mpsc::UnboundedReceiver<GatewayInput>> {
        let (gw_tx, gw_rx) = tokio::sync::mpsc::unbounded_channel::<GatewayInput>();
        if let Some(s) = self.snmp.clone() {
            println!("GATEWAY listening for SNMP on {}{}", s.local_addr()?, if self.usm.is_some() { " (v1, v2c, v3 USM)" } else { " (v1, v2c)" });
            spawn_udp(s, gw_tx.clone(), false);
        }
        if let Some(a) = &args.syslog_listen {
            let s = std::sync::Arc::new(tokio::net::UdpSocket::bind(a).await.with_context(|| format!("binding {a}"))?);
            println!("GATEWAY listening for syslog on udp {}", s.local_addr()?);
            spawn_udp(s, gw_tx.clone(), true);
        }
        if let Some(a) = &args.syslog_tls_listen {
            let l = tokio::net::TcpListener::bind(a).await.with_context(|| format!("binding {a}"))?;
            let cfg = tls_server_config("syslog-tls", args.syslog_tls_cert.as_deref(), args.syslog_tls_key.as_deref(), args.syslog_tls_ca.as_deref())?;
            println!("GATEWAY listening for syslog on tls {} (client certificates required)", l.local_addr()?);
            spawn_syslog_tls(l, cfg, gw_tx.clone());
        }
        if let Some(a) = &args.snmp_tls_listen {
            let l = tokio::net::TcpListener::bind(a).await.with_context(|| format!("binding {a}"))?;
            let cfg = tls_server_config("snmp-tls", args.snmp_tls_cert.as_deref(), args.snmp_tls_key.as_deref(), args.snmp_tls_ca.as_deref())?;
            let ca_path = args.snmp_tls_ca.as_deref().context("--snmp-tls-ca")?;
            let cas = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(ca_path)?))
                .map(|c| c.map(|c| c.as_ref().to_vec())).collect::<Result<Vec<_>, _>>()?;
            let map_path = args.snmp_tls_map.as_deref().context("--snmp-tls-map")?;
            let table: Value = serde_json::from_str(&std::fs::read_to_string(map_path)?).context("--snmp-tls-map")?;
            anyhow::ensure!(table.is_array(), "--snmp-tls-map: a JSON array of rows");
            println!("GATEWAY listening for SNMP on tls {} (client certificates required, {} name row(s))   RFC 6353",
                     l.local_addr()?, table.as_array().map_or(0, Vec::len));
            spawn_snmp_tls(l, cfg, cas, table, gw_tx.clone());
        }
        if let Some(a) = &args.snmp_dtls_listen {
            let sock = std::net::UdpSocket::bind(a).with_context(|| format!("binding {a}"))?;
            let ca_path = args.snmp_tls_ca.as_deref().context("--snmp-tls-ca")?;
            let cas = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(ca_path)?))
                .map(|c| c.map(|c| c.as_ref().to_vec())).collect::<Result<Vec<_>, _>>()?;
            let map_path = args.snmp_tls_map.as_deref().context("--snmp-tls-map")?;
            let table: Value = serde_json::from_str(&std::fs::read_to_string(map_path)?).context("--snmp-tls-map")?;
            anyhow::ensure!(table.is_array(), "--snmp-tls-map: a JSON array of rows");
            println!("GATEWAY listening for SNMP on dtls {} (client certificates required, {} name row(s))   RFC 6353",
                     sock.local_addr()?, table.as_array().map_or(0, Vec::len));
            spawn_snmp_dtls(sock, args.snmp_tls_cert.as_deref().context("--snmp-tls-cert")?, args.snmp_tls_key.as_deref().context("--snmp-tls-key")?,
                            ca_path, cas, table, gw_tx.clone())?;
        }
        drop(gw_tx);
        Ok(gw_rx)
    }
}

impl Client {
    /// One input from a gateway listener.
    pub(super) async fn gateway_input(&mut self, input: GatewayInput) -> Result<()> {
        match input {
            GatewayInput::Snmp(d, from) => self.snmp_in(&d, from).await,
            GatewayInput::Syslog(d, from, cert) => self.syslog_in(&d, from, cert).await,
            GatewayInput::SnmpTls(d, from, peer) => self.snmp_tls_in(&d, from, peer).await,
        }
    }

    /// A received `device-event` or `alarm-ack` (E§5) applied to its group's alarm list; false for other content.
    pub(super) fn event_in(&mut self, gid: &str, sender: &str, object: &Value) -> bool {
        if object["kind"] == "device-event" {
            // E§5: the gateway signed it; the device is a claim with its basis
            let ev = &object["event"];
            if let Some(h) = ev.get("heartbeat") {
                self.alarm_step(gid, &json!({"heartbeat": {"gateway": sender, "interval_s": h["interval_s"]}}));
            } else {
                println!("EVENT {sender} {}", render_event(ev));
                if let Some(a) = ev.get("alarm") {
                    self.alarm_step(gid, &json!({"report": a}));
                }
            }
        } else if object["kind"] == "alarm-ack" {
            self.alarm_step(gid, &json!({"ack": {"alarm": object["alarm"], "state": object["state"], "by": sender}}));
        } else {
            return false;
        }
        true
    }
    /// Send a `device-event` (E§5) given as JSON: this device is the gateway that signs it.
    pub(super) async fn send_device_event(&mut self, event_json: &str) -> Result<()> {
        let event: Value = serde_json::from_str(event_json.trim()).context("device-event: not JSON")?;
        self.deposit_event(event).await.map(|_| ())
    }

    /// Deposit a gateway event through the E§4 hold-down: a clear may be held, a raise cancels its held clear.
    async fn gateway_deposit(&mut self, event: Value) -> Result<()> {
        let Some(alarm) = event.get("alarm").cloned() else { return self.deposit_event(event).await.map(|_| ()) };
        let key = (
            alarm["resource"].as_str().unwrap_or("").to_string(),
            alarm["type"].as_str().unwrap_or("").to_string(),
            alarm["qualifier"].as_str().unwrap_or("").to_string(),
        );
        if self.events.hold_down.report(&alarm).is_empty() {
            println!("HELD clear of {}/{} for hold-down   E§4", key.0, key.1);
            self.events.held_events.entry(key).or_insert(event);
            return Ok(());
        }
        if self.events.held_events.remove(&key).is_some() {
            println!("CANCELLED held clear of {}/{}: re-raised within the hold-down (a flap)   E§4", key.0, key.1);
        }
        self.deposit_event(event).await.map(|_| ())
    }

    /// Deposit one `device-event`; the hub's answer (`accepted`, `pending` with the outbox id, or a refusal).
    async fn deposit_event(&mut self, event: Value) -> Result<Value> {
        let group = self.active()?;
        let now = now_s();
        let obj = json!({"object": "content", "id": wire::new_id(now), "conversation": self.conv(&group)?.conversation,
            "sender": self.identity, "sent_at": now, "kind": "device-event", "purpose": "message", "event": event});
        let reply = self.send_object(&group, &obj, json!({})).await?;
        self.sent(&group, &reply, &obj);
        match reply["type"].as_str() {
            Some("accepted") => println!("OK sent event seq={}", reply["seq"]),
            Some("pending") => {}
            _ => println!("ERR send refused: {}", reply["reason"]),
        }
        Ok(reply)
    }

    /// Gateway mode (E§3): one SNMP datagram from the LAN → a signed `device-event`; an inform is answered only
    /// once the hub has accepted its event, and its retransmissions never deposit a second one.
    async fn snmp_in(&mut self, datagram: &[u8], from: std::net::SocketAddr) -> Result<()> {
        let address = from.ip().to_string();
        let (trap, source, response) = if dsip_events::usm::is_v3(datagram) {
            let Some(usm) = self.events.usm.as_mut() else {
                println!("SNMP dropped from {from}: SNMPv3, and no --snmp-users");
                return Ok(());
            };
            usm.set_now(now_s());
            match usm.receive(datagram) {
                dsip_events::usm::Verdict::Accepted { trap, usm, response } => {
                    // E§2: the authenticated identity is the engine and the user, not the address
                    let basis = if usm["level"] == "authPriv" { "snmpv3-authpriv" } else { "snmpv3-auth" };
                    let source = json!({"address": address, "basis": basis,
                                        "usm": {"engine_id": usm["engine_id"], "user": usm["user"]}});
                    (trap, source, response)
                }
                dsip_events::usm::Verdict::Refused { reason, report } => {
                    // E§3: only discovery and time synchronization are answered
                    let sent = match (&report, &self.events.snmp) {
                        (Some(r), Some(sock)) => sock.send_to(r, from).await.is_ok(),
                        _ => false,
                    };
                    println!("SNMPv3 refused from {from}: {reason}{}", if sent { " (Report sent)" } else { "" });
                    return Ok(());
                }
            }
        } else {
            let trap = match dsip_events::ber::decode_trap(datagram) {
                Ok(t) => t,
                Err(e) => {
                    println!("SNMP dropped from {from}: {}", e.0);
                    return Ok(());
                }
            };
            let basis = if trap["version"] == "v1" { "snmpv1" } else { "snmpv2c" }; // E§2: community only, unauthenticated
            let response = dsip_events::ber::inform_response(datagram);
            (trap, json!({"address": address, "basis": basis}), response)
        };
        self.snmp_event(trap, source, response.map(|r| (r, ReplyTo::Udp(from))), from.to_string()).await
    }

    /// Gateway mode (E§3, v0.10): one SNMP message from a verified TLS connection. Discovery is answered at once;
    /// a trap or inform becomes a `device-event` with basis `snmpv3-tls`.
    async fn snmp_tls_in(&mut self, message: &[u8], from: std::net::SocketAddr, peer: TlsPeer) -> Result<()> {
        let r = match dsip_events::tsm::receive(message) {
            Ok(r) => r,
            Err(reason) => {
                println!("SNMP tls refused from {from} ({}): {reason}", peer.security_name);
                return Ok(());
            }
        };
        if r.kind == dsip_events::tsm::Kind::Discovery {
            let _ = peer.reply.send(r.discovery_response(&self.events.snmp_engine));
            println!("SNMP tls discovery from {from} ({}): answered with our engine ID   RFC 5343", peer.security_name);
            return Ok(());
        }
        let mut trap = json!({"version": "v3", "varbinds": r.varbinds});
        let response = if r.kind == dsip_events::tsm::Kind::Inform {
            trap["inform"] = json!({"request_id": r.request_id});
            Some((r.response(), ReplyTo::Tls(peer.reply.clone())))
        } else {
            None
        };
        // E§2: the authenticated identity is the certificate and the name it mapped to
        let mut source = json!({"address": from.ip().to_string(), "basis": "snmpv3-tls", "certificate_sha256": peer.certificate_sha256,
                                "tsm": {"security_name": peer.security_name, "transport": peer.transport}});
        if let Some(name) = self.events.tls_names.get(&peer.certificate_sha256).and_then(Value::as_str) {
            source["name"] = json!(name);
        }
        // informs are remembered by security name, so a retransmission on a new connection is not stored twice
        self.snmp_event(trap, source, response, format!("tls:{}", peer.security_name)).await
    }

    /// A decoded notification → an event: map it, deposit a trap, or run an inform through E§3's memory.
    async fn snmp_event(&mut self, trap: Value, source: Value, response: Option<(Vec<u8>, ReplyTo)>, from: String) -> Result<()> {
        let address = source["address"].as_str().unwrap_or("").to_string();
        let raw = dsip_events::normalize_trap(&trap);
        if raw.get("error").is_some() {
            println!("SNMP dropped from {from}: malformed");
            return Ok(());
        }
        let mut event = json!({"source": source, "raw": raw});
        if let Some(alarm) = dsip_events::map_alarm(&raw, &self.events.snmp_rules, &address).get("alarm") {
            event["alarm"] = alarm.clone();
        }
        let Some(rid) = trap["inform"]["request_id"].as_i64() else {
            println!("SNMP trap from {from}: {}", raw["snmp"]["trap_oid"].as_str().unwrap_or("-"));
            return self.gateway_deposit(event).await;
        };
        let key = (from.clone(), rid);
        // the response to the latest copy: a v3 retransmission may carry a new msgID, which its sender matches on
        if let Some(resp) = response {
            self.events.inform_responses.insert(key.clone(), resp);
        }
        let emitted = self.events.informs.step(&json!({"inform": {"source": key.0, "request_id": rid}}));
        if emitted.is_empty() {
            println!("SNMP inform {from} rid={rid}: retransmission while pending, not answered yet");
        }
        for e in emitted {
            if e.get("respond").is_some() {
                println!("SNMP inform {from} rid={rid}: retransmission, answered again");
                self.inform_respond(&key).await;
            } else if e.get("deposit").is_some() {
                println!("SNMP inform {from} rid={rid}: {}", raw["snmp"]["trap_oid"].as_str().unwrap_or("-"));
                let reply = self.deposit_event(event.clone()).await?;
                match reply["type"].as_str() {
                    Some("accepted") => self.inform_outcome_key(&key, true).await,
                    Some("pending") => {
                        // M§9.4: the hub is unreachable; the inform is answered when the outbox's deposit is accepted
                        if let Some(id) = reply["id"].as_str() {
                            self.events.inform_items.insert(id.to_string(), key.clone());
                        }
                        println!("SNMP inform {from} rid={rid}: pending, not answered");
                    }
                    _ => self.inform_outcome_key(&key, false).await,
                }
            }
        }
        Ok(())
    }

    /// Gateway mode (E§3): one syslog message, over UDP or (with the device's verified certificate) TLS → a signed
    /// `device-event`.
    async fn syslog_in(&mut self, message: &[u8], from: std::net::SocketAddr, certificate: Option<String>) -> Result<()> {
        let Some((col, _)) = self.events.syslog_sign.as_mut() else { return self.syslog_event(message, from, certificate, None).await };
        let outs = col.receive(message);
        if let Some(h) = dsip_events::syslog::parse_syslog(message)["syslog"]["hostname"].as_str() {
            self.events.syslog_signer_at.insert(h.to_ascii_lowercase(), from);
        }
        if outs.is_empty() {
            // E§3: held for its Signature Block; remember how it came, for an unsigned deposit later
            use sha2::Digest as _;
            let sha: String = sha2::Sha256::digest(message).iter().map(|b| format!("{b:02x}")).collect();
            self.events.syslog_held.entry(sha).or_default().push_back((from, certificate.clone()));
            println!("SYSLOG from {from}: held for its signature   E§3");
        }
        self.syslog_sign_out(outs, Some((from, certificate))).await
    }

    /// What the signed-syslog collector released: deposits (signed, or with the transport's basis) and block verdicts.
    async fn syslog_sign_out(&mut self, outs: dsip_events::syslog_sign::Emits,
                             current: Option<(std::net::SocketAddr, Option<String>)>) -> Result<()> {
        use dsip_events::syslog_sign::Out;
        use sha2::Digest as _;
        for o in outs {
            match o {
                Out::Deposit { message, signed } => {
                    let sha: String = sha2::Sha256::digest(&message).iter().map(|b| format!("{b:02x}")).collect();
                    // a held message deposits with the transport it came by; the current one with its own
                    let held = self.events.syslog_held.get_mut(&sha).and_then(|q| q.pop_front());
                    if self.events.syslog_held.get(&sha).is_some_and(|q| q.is_empty()) {
                        self.events.syslog_held.remove(&sha);
                    }
                    let Some((from, cert)) = held.or_else(|| current.clone()) else { continue };
                    self.syslog_event(&message, from, cert, signed).await?;
                }
                Out::Session(s) => println!("SYSLOG-SIGN session {}/{}/{} rsid {} established, key {}…   RFC 5848",
                                            s["hostname"].as_str().unwrap_or(""), s["app_name"].as_str().unwrap_or(""),
                                            s["procid"].as_str().unwrap_or(""), s["rsid"], &s["key_sha256"].as_str().unwrap_or("")[..16]),
                Out::Refused(r) => println!("SYSLOG-SIGN {} refused: {}", r["block"].as_str().unwrap_or(""), r["reason"].as_str().unwrap_or("")),
                Out::Gap(g) => {
                    // E§3/E§5 (v0.11): a gateway event raising (signer, dsip-syslog-gap, "app/sg/spri")
                    let host = g["hostname"].as_str().unwrap_or("").to_ascii_lowercase();
                    let address = current.as_ref().map(|(a, _)| *a).or_else(|| self.events.syslog_signer_at.get(&host).copied())
                        .map(|a| a.ip().to_string()).unwrap_or_default();
                    let (from, to) = (g["from"].as_u64().unwrap_or(0), g["to"].as_u64().unwrap_or(0));
                    let qualifier = format!("{}/{}/{}", g["app_name"].as_str().unwrap_or(""), g["sg"], g["spri"]);
                    println!("SYSLOG-SIGN gap {}/{} rsid {}: messages {from}–{to} lost   E§3", g["hostname"].as_str().unwrap_or(""),
                             qualifier, g["rsid"]);
                    let event = json!({"source": {"address": address, "basis": "gateway"}, "syslog_gap": g,
                                       "alarm": {"resource": g["hostname"], "type": "dsip-syslog-gap", "qualifier": qualifier,
                                                 "severity": "warning", "cleared": false, "text": format!("messages {from}–{to} lost")}});
                    self.deposit_event(event).await?;
                }
            }
        }
        Ok(())
    }

    /// One syslog message → a `device-event`: basis `syslog-signed` with E§2's `signed` claim when a Signature Block
    /// verified it, otherwise the transport's.
    async fn syslog_event(&mut self, message: &[u8], from: std::net::SocketAddr, certificate: Option<String>,
                          signed: Option<Value>) -> Result<()> {
        let raw = dsip_events::syslog::parse_syslog(message);
        if raw.get("error").is_some() {
            println!("SYSLOG dropped from {from}: malformed");
            return Ok(());
        }
        let address = from.ip().to_string();
        let mut source = json!({"address": address, "basis": if certificate.is_some() { "syslog-tls" } else { "syslog-udp" }});
        if let Some(c) = certificate {
            // E§2 (v0.10): the gateway's configured name for this certificate, as its claim
            if let Some(name) = self.events.tls_names.get(&c).and_then(Value::as_str) {
                source["name"] = json!(name);
            }
            source["certificate_sha256"] = json!(c);
        }
        if let Some(s) = signed {
            source["basis"] = json!("syslog-signed");
            source["signed"] = s;
        }
        let mut event = json!({"source": source, "raw": raw});
        if let Some(alarm) = dsip_events::syslog::map_syslog(&raw, &self.events.snmp_rules, &address, &self.events.syslog_table).get("alarm") {
            event["alarm"] = alarm.clone();
        }
        let sl = &raw["syslog"];
        println!("SYSLOG from {from} ({}): severity {} {} {}", event["source"]["basis"].as_str().unwrap_or("-"),
                 sl["severity"], sl["app_name"].as_str().unwrap_or("-"), sl["msg"].as_str().unwrap_or(""));
        self.gateway_deposit(event).await
    }

    /// The hub's verdict on an inform's event (E§3): answer it, or forget it so its next retransmission deposits anew.
    async fn inform_outcome_key(&mut self, key: &(String, i64), accepted: bool) {
        let verdict = if accepted { "accepted" } else { "refused" };
        for e in self.events.informs.step(&json!({verdict: {"key": [key.0, key.1]}})) {
            if e.get("respond").is_some() {
                println!("SNMP inform {} rid={}: stored, answered", key.0, key.1);
                self.inform_respond(key).await;
            }
        }
    }

    /// An outbox item was finally accepted or refused (M§9.4): if it carried an inform's event, settle the inform.
    pub(super) async fn inform_outcome(&mut self, item_id: &str, accepted: bool) {
        if let Some(key) = self.events.inform_items.remove(item_id) {
            self.inform_outcome_key(&key, accepted).await;
        }
    }

    async fn inform_respond(&mut self, key: &(String, i64)) {
        match self.events.inform_responses.get(key) {
            Some((resp, ReplyTo::Udp(to))) => {
                if let Some(sock) = &self.events.snmp {
                    if let Err(e) = sock.send_to(resp, to).await {
                        println!("ERR SNMP response to {to}: {e}");
                    }
                }
            }
            // E§3: on the connection the inform came on
            Some((resp, ReplyTo::Tls(tx))) if tx.send(resp.clone()).is_err() => {
                println!("ERR SNMP response for {}: the TLS connection is gone", key.0);
            }
            _ => {}
        }
    }

    /// Gateway mode, from the ticker: the heartbeat (E§5) and the inform memory's clock (E§3).
    pub(super) async fn gateway_tick(&mut self) -> Result<()> {
        let now = now_s();
        // E§3 signed syslog: messages whose signature did not come in time are deposited with their transport's basis
        if let Some((col, last)) = self.events.syslog_sign.as_mut() {
            let outs = col.advance(now - *last);
            *last = now;
            self.syslog_sign_out(outs, None).await?;
        }
        // E§4 hold-down: the clears that held long enough are deposited now
        for r in self.events.hold_down.advance_to(now) {
            let key = (r["resource"].as_str().unwrap_or("").to_string(), r["type"].as_str().unwrap_or("").to_string(),
                       r["qualifier"].as_str().unwrap_or("").to_string());
            if let Some(event) = self.events.held_events.remove(&key) {
                println!("RELEASED held clear of {}/{} after the hold-down   E§4", key.0, key.1);
                self.deposit_event(event).await?;
            }
        }
        if now > self.events.inform_clock {
            self.events.informs.step(&json!({"advance": now - self.events.inform_clock}));
            self.events.inform_clock = now;
        }
        if let Some((every, last)) = self.events.heartbeat {
            if now - last >= every {
                self.events.heartbeat = Some((every, now));
                self.deposit_event(json!({"heartbeat": {"interval_s": every}})).await?;
            }
        }
        Ok(())
    }

    /// Send an `alarm-ack` (E§5): this operator owns the alarm (`ack`) or has finished with it (`closed`).
    pub(super) async fn send_alarm_ack(&mut self, resource: &str, kind: &str, state: &str) -> Result<()> {
        let group = self.active()?;
        let now = now_s();
        let obj = json!({"object": "content", "id": wire::new_id(now), "conversation": self.conv(&group)?.conversation,
            "sender": self.identity, "sent_at": now, "kind": "alarm-ack", "purpose": "message",
            "alarm": {"resource": resource, "type": kind, "qualifier": ""}, "state": state});
        let reply = self.send_object(&group, &obj, json!({})).await?;
        self.sent(&group, &reply, &obj);
        // our own acknowledgement counts in our own alarm list too (it is fanned back to us as SELF)
        self.alarm_step(&group, &json!({"ack": {"alarm": obj["alarm"], "state": state, "by": self.identity}}));
        match reply["type"].as_str() {
            Some("accepted") => println!("OK sent alarm-ack seq={}", reply["seq"]),
            Some("pending") => {}
            _ => println!("ERR send refused: {}", reply["reason"]),
        }
        Ok(())
    }

    /// Apply one event to a group's alarm list (E§5) and act on what it emits: print each transition, and as an
    /// escalation agent run the escalation command (E§6).
    fn alarm_step(&mut self, group: &str, event: &Value) {
        let now = now_s();
        let policy = self.events.escalation.as_ref().map(|(p, _)| p.clone());
        let (list, last) = self.events.alarms.entry(group.to_string()).or_insert_with(|| {
            let mut ctx = json!({"now": now});
            if let Some(p) = policy {
                ctx["escalation"] = p;
            }
            (dsip_events::AlarmList::new(&ctx), now)
        });
        let mut emitted = list.step(&json!({"advance": now - *last}));
        *last = now;
        emitted.extend(list.step(event));
        self.alarm_out(emitted);
    }

    fn alarm_out(&self, emitted: Vec<Value>) {
        for e in emitted {
            let (what, body) = match e.as_object().and_then(|o| o.iter().next()) {
                Some((k, v)) => (k.clone(), v.clone()),
                None => continue,
            };
            let key = &body["key"];
            let k = format!("{}/{}", key[0].as_str().unwrap_or(""), key[1].as_str().unwrap_or(""));
            match what.as_str() {
                "raised" => println!("ALARM raised {k} severity={} reopened={}", body["severity"].as_str().unwrap_or(""), body["reopened"]),
                "changed" => println!("ALARM changed {k} severity={}", body["severity"].as_str().unwrap_or("")),
                "cleared" => println!("ALARM cleared {k}"),
                "operator" => println!("ALARM {} {k} by {}", body["state"].as_str().unwrap_or(""), body["by"].as_str().unwrap_or("")),
                "escalate" => {
                    println!("ESCALATE {k} severity={}", body["severity"].as_str().unwrap_or(""));
                    if let Some((_, Some(cmd))) = &self.events.escalation {
                        let spawned = std::process::Command::new("sh")
                            .arg("-c")
                            .arg(cmd)
                            .env("ALARM_RESOURCE", key[0].as_str().unwrap_or(""))
                            .env("ALARM_TYPE", key[1].as_str().unwrap_or(""))
                            .env("ALARM_SEVERITY", body["severity"].as_str().unwrap_or(""))
                            .spawn();
                        if let Err(e) = spawned {
                            println!("ERR escalation command: {e}");
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Advance every alarm list to now (E§6 timers, E§5 gateway silence), from the ticker.
    pub(super) fn tick_alarms(&mut self) {
        let groups: Vec<String> = self.events.alarms.keys().cloned().collect();
        for g in groups {
            let now = now_s();
            let emitted = match self.events.alarms.get_mut(&g) {
                Some((list, last)) if now > *last => {
                    let e = list.step(&json!({"advance": now - *last}));
                    *last = now;
                    e
                }
                _ => continue,
            };
            self.alarm_out(emitted);
        }
    }}

/// One input to a Device Events gateway (E§3), from the listener tasks.
pub(super) enum GatewayInput {
    /// An SNMP datagram.
    Snmp(Vec<u8>, std::net::SocketAddr),
    /// A syslog message, with the SHA-256 of the device's verified TLS certificate when it came over TLS.
    Syslog(Vec<u8>, std::net::SocketAddr, Option<String>),
    /// An SNMP message from a TLS connection (E§3, v0.10), with the connection's verified peer.
    SnmpTls(Vec<u8>, std::net::SocketAddr, TlsPeer),
}

/// A verified SNMP-over-TLS connection or DTLS session: its certificate, the security name it mapped to, the
/// transport (`tls` or `dtls`, E§2) and the way back.
#[derive(Clone)]
pub(super) struct TlsPeer {
    certificate_sha256: String,
    security_name: String,
    transport: &'static str,
    reply: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

/// Where an inform's Response goes.
enum ReplyTo {
    Udp(std::net::SocketAddr),
    Tls(tokio::sync::mpsc::UnboundedSender<Vec<u8>>),
}

fn spawn_udp(sock: std::sync::Arc<tokio::net::UdpSocket>, tx: tokio::sync::mpsc::UnboundedSender<GatewayInput>, syslog: bool) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let d = buf[..n].to_vec();
            let input = if syslog { GatewayInput::Syslog(d, from, None) } else { GatewayInput::Snmp(d, from) };
            if tx.send(input).is_err() {
                break;
            }
        }
    });
}

/// The largest syslog frame accepted over TLS (RFC 5425 §4.3.1 requires at least 2048; 8192 SHOULD).
const SYSLOG_TLS_MAX: usize = 65536;

/// TLS for syslog (RFC 5425): the gateway's certificate, and client certificates required, chaining to `ca`.
fn tls_server_config(flag: &str, cert: Option<&Path>, key: Option<&Path>, ca: Option<&Path>) -> Result<std::sync::Arc<tokio_rustls::rustls::ServerConfig>> {
    use tokio_rustls::rustls;
    let (cert, key, ca) = (cert.with_context(|| format!("--{flag}-cert"))?, key.with_context(|| format!("--{flag}-key"))?,
                           ca.with_context(|| format!("--{flag}-ca"))?);
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert)?)).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key)?))?.context("no private key")?;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(ca)?)) {
        roots.add(c?)?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(roots)).build()?;
    Ok(std::sync::Arc::new(rustls::ServerConfig::builder().with_client_cert_verifier(verifier).with_single_cert(certs, key)?))
}

/// The certificate fields RFC 6353's name table reads (README `check: "tsm-name"`), from the presented chain.
///
/// Impl: the verified path's CAs are the certificates the client sent above its leaf, plus each configured CA whose
/// subject is the issuer of the top one (rustls verified the path; it does not report it).
fn tls_cert_fields(presented: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>], cas: &[Vec<u8>]) -> Option<Value> {
    use sha2::Digest as _;
    use x509_parser::prelude::*;
    let sha = |d: &[u8]| -> String { sha2::Sha256::digest(d).iter().map(|b| format!("{b:02x}")).collect() };
    let leaf_der = presented.first()?;
    let (_, leaf) = X509Certificate::from_der(leaf_der.as_ref()).ok()?;
    let mut chain: Vec<String> = presented[1..].iter().map(|c| sha(c.as_ref())).collect();
    let top_der = presented.last()?;
    let (_, top) = X509Certificate::from_der(top_der.as_ref()).ok()?;
    for ca in cas {
        if let Ok((_, c)) = X509Certificate::from_der(ca) {
            if c.subject().as_raw() == top.issuer().as_raw() {
                chain.push(sha(ca));
            }
        }
    }
    let mut san = vec![];
    if let Ok(Some(ext)) = leaf.subject_alternative_name() {
        for g in &ext.value.general_names {
            san.push(match g {
                GeneralName::RFC822Name(v) => json!({"type": "rfc822", "value": v}),
                GeneralName::DNSName(v) => json!({"type": "dns", "value": v}),
                GeneralName::IPAddress(v) => json!({"type": "ip", "value": v.iter().map(|b| format!("{b:02x}")).collect::<String>()}),
                _ => json!({"type": "other", "value": ""}),
            });
        }
    }
    let cn: Vec<String> = leaf.subject().iter_common_name().filter_map(|a| a.as_str().ok().map(str::to_string)).collect();
    Some(json!({"sha256": sha(leaf_der.as_ref()), "chain": chain, "san": san, "cn": cn}))
}

/// Accept SNMP-over-TLS connections (E§3, v0.10): each verified certificate maps to a security name through the
/// table, or the connection is closed; its stream is split into whole messages; replies go back on it.
fn spawn_snmp_tls(l: tokio::net::TcpListener, cfg: std::sync::Arc<tokio_rustls::rustls::ServerConfig>, cas: Vec<Vec<u8>>,
                  table: Value, tx: tokio::sync::mpsc::UnboundedSender<GatewayInput>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        while let Ok((tcp, from)) = l.accept().await {
            let (acceptor, tx, cas, table) = (acceptor.clone(), tx.clone(), cas.clone(), table.clone());
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(e) => {
                        println!("SNMP tls refused from {from}: {e}");
                        return;
                    }
                };
                let Some(fields) = tls.get_ref().1.peer_certificates().and_then(|c| tls_cert_fields(c, &cas)) else { return };
                let mapped = dsip_events::tsm::security_name(&fields, &table);
                let Some(name) = mapped["security_name"].as_str() else {
                    // RFC 6353 §5.3.2: no name, no messages
                    println!("SNMP tls closed {from}: no-security-name for certificate {}", &fields["sha256"].as_str().unwrap_or("")[..16]);
                    return;
                };
                println!("SNMP tls connection {from}: security name {name:?} (row {})", mapped["row"]);
                let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                let peer = TlsPeer { certificate_sha256: fields["sha256"].as_str().unwrap_or("").to_string(),
                                     security_name: name.to_string(), transport: "tls", reply: reply_tx };
                let (mut rd, mut wr) = tokio::io::split(tls);
                tokio::spawn(async move {
                    while let Some(m) = reply_rx.recv().await {
                        if wr.write_all(&m).await.is_err() || wr.flush().await.is_err() {
                            return;
                        }
                    }
                });
                let mut buf = vec![];
                let mut chunk = vec![0u8; 16384];
                loop {
                    let Ok(n) = rd.read(&mut chunk).await else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let f = dsip_events::tsm::split_frames(&buf);
                    for m in f.messages {
                        if tx.send(GatewayInput::SnmpTls(m, from, peer.clone())).is_err() {
                            return;
                        }
                    }
                    if f.close {
                        println!("SNMP tls from {from}: unframeable stream, closing   E§3");
                        return;
                    }
                    buf.drain(..f.consumed);
                }
            });
        }
    });
}

/// One DTLS peer's datagrams as a blocking stream for OpenSSL: reads pop the demultiplexer's queue (a short wait
/// gives `WouldBlock`, so the session loop can send replies), writes go to the peer.
struct DtlsPeerIo {
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    sock: std::sync::Arc<std::net::UdpSocket>,
    peer: std::net::SocketAddr,
}

/// How long a DTLS session may stay silent before the gateway shuts it down (RFC 6353 §5.1.2 leaves the policy to
/// the implementation; net-snmp's own default is 5 minutes).
const DTLS_IDLE_S: u64 = 300;
/// How many DTLS sessions may be in their handshake at once. Each unseen source address costs a thread until the
/// cookie exchange and the certificate check are done, so a flood of spoofed addresses is bounded here: beyond it,
/// datagrams from new addresses are dropped until a handshake ends.
const DTLS_HANDSHAKES_MAX: usize = 64;
/// How long a handshake may take before its session is dropped.
const DTLS_HANDSHAKE_S: u64 = 10;

/// Run OpenSSL's DTLS retransmission timer for a session: `DTLSv1_handle_timeout`, which the `openssl` crate does not
/// wrap. It resends the last handshake flight when its timer has expired and does nothing otherwise.
fn dtls_handle_timeout(ssl: &openssl::ssl::SslRef) {
    use foreign_types::ForeignTypeRef as _;
    const DTLS_CTRL_HANDLE_TIMEOUT: std::os::raw::c_int = 74; // ssl.h; a macro over SSL_ctrl
    // SAFETY: `ssl` is a live SSL object this thread owns; the control takes no pointer argument.
    unsafe { openssl_sys::SSL_ctrl(ssl.as_ptr(), DTLS_CTRL_HANDLE_TIMEOUT, 0, std::ptr::null_mut()) };
}

impl std::io::Read for DtlsPeerIo {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        match self.rx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(d) => {
                let n = d.len().min(out.len());
                out[..n].copy_from_slice(&d[..n]);
                Ok(n)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(std::io::ErrorKind::WouldBlock.into()),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(0),
        }
    }
}

impl std::io::Write for DtlsPeerIo {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.sock.send_to(b, self.peer)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Accept SNMP over DTLS (RFC 6353 over UDP; E§3, v0.11): one UDP socket, OpenSSL's DTLS server with the cookie
/// exchange (RFC 6347 §4.2.1), a session per peer address, the client certificate verified against the CA and
/// named by the table, and each DTLS record exactly one message (`dsip_events::tsm::dtls_record`).
///
/// Impl: a blocking thread per session over a demultiplexed queue (OpenSSL's DTLS needs a datagram at a time). A
/// lost handshake flight is retransmitted by OpenSSL's own DTLS timer, run from the session thread whenever a read
/// times out (`DTLSv1_handle_timeout`); a session idle for [`DTLS_IDLE_S`] is shut down, and the peer's next
/// datagram starts a new one.
fn spawn_snmp_dtls(sock: std::net::UdpSocket, cert: &Path, key: &Path, ca: &Path, cas: Vec<Vec<u8>>, table: Value,
                   tx: tokio::sync::mpsc::UnboundedSender<GatewayInput>) -> Result<()> {
    use openssl::ssl::{Ssl, SslContext, SslFiletype, SslMethod, SslOptions, SslRef, SslVerifyMode};
    use sha2::Digest as _;
    let mut b = SslContext::builder(SslMethod::dtls_server())?;
    b.set_certificate_chain_file(cert)?;
    b.set_private_key_file(key, SslFiletype::PEM)?;
    b.set_ca_file(ca)?;
    b.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    b.set_options(SslOptions::COOKIE_EXCHANGE | SslOptions::NO_QUERY_MTU); // the MTU below is ours to set: the stream is not a datagram BIO
    let idx = Ssl::new_ex_index::<std::net::SocketAddr>()?;
    let secret: [u8; 32] = rand::random();
    let cookie = move |ssl: &SslRef| -> Vec<u8> {
        let addr = ssl.ex_data(idx).map(|a| a.to_string()).unwrap_or_default();
        sha2::Sha256::digest([&secret[..], addr.as_bytes()].concat()).to_vec()
    };
    b.set_cookie_generate_cb(move |ssl, buf| {
        let c = cookie(ssl);
        buf[..c.len()].copy_from_slice(&c);
        Ok(c.len())
    });
    b.set_cookie_verify_cb(move |ssl, given| given == cookie(ssl).as_slice());
    let ctx = b.build();
    let sock = std::sync::Arc::new(sock);
    let handshakes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::spawn(move || {
        use std::sync::atomic::Ordering;
        let mut peers: std::collections::HashMap<std::net::SocketAddr, std::sync::mpsc::Sender<Vec<u8>>> = std::collections::HashMap::new();
        let mut buf = vec![0u8; 65536];
        let mut refused_at_cap = 0u64;
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let d = buf[..n].to_vec();
            if let Some(p) = peers.get(&from) {
                if p.send(d.clone()).is_ok() {
                    continue;
                }
                peers.remove(&from); // its session ended: this datagram starts a new one
            }
            if handshakes.load(Ordering::SeqCst) >= DTLS_HANDSHAKES_MAX {
                refused_at_cap += 1;
                if refused_at_cap.is_power_of_two() {
                    println!("SNMP dtls: {DTLS_HANDSHAKES_MAX} handshakes in flight, dropping datagrams from new addresses ({refused_at_cap} so far)");
                }
                continue;
            }
            let (ptx, prx) = std::sync::mpsc::channel();
            let _ = ptx.send(d);
            peers.insert(from, ptx);
            handshakes.fetch_add(1, Ordering::SeqCst);
            let (ctx, sock, cas, table, tx, handshakes) = (ctx.clone(), sock.clone(), cas.clone(), table.clone(), tx.clone(), handshakes.clone());
            std::thread::spawn(move || {
                // the handshake slot is given back when the handshake ends, however it ends
                struct Slot(std::sync::Arc<std::sync::atomic::AtomicUsize>);
                impl Drop for Slot {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                let slot = Slot(handshakes);
                let mut ssl = match Ssl::new(&ctx) {
                    Ok(s) => s,
                    Err(e) => {
                        println!("SNMP dtls {from}: {e}");
                        return;
                    }
                };
                ssl.set_ex_data(idx, from);
                let _ = ssl.set_mtu(1400);
                let io = DtlsPeerIo { rx: prx, sock, peer: from };
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(DTLS_HANDSHAKE_S);
                let mut hs = ssl.accept(io);
                let mut stream = loop {
                    match hs {
                        Ok(s) => {
                            drop(slot);
                            break s;
                        }
                        Err(openssl::ssl::HandshakeError::WouldBlock(mid)) if std::time::Instant::now() < deadline => {
                            dtls_handle_timeout(mid.ssl()); // a read timed out: resend the flight if OpenSSL's timer says so
                            hs = mid.handshake();
                        }
                        Err(e) => {
                            println!("SNMP dtls refused from {from}: {}", match &e { openssl::ssl::HandshakeError::Failure(m) => m.error().to_string(), _ => "handshake timed out".into() });
                            return;
                        }
                    }
                };
                let leaf = stream.ssl().peer_certificate().and_then(|c| c.to_der().ok());
                let chain: Vec<Vec<u8>> = stream.ssl().peer_cert_chain().into_iter().flatten().filter_map(|c| c.to_der().ok()).collect();
                let presented: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> =
                    leaf.into_iter().chain(chain).map(tokio_rustls::rustls::pki_types::CertificateDer::from).collect();
                let Some(fields) = (!presented.is_empty()).then(|| tls_cert_fields(&presented, &cas)).flatten() else { return };
                let mapped = dsip_events::tsm::security_name(&fields, &table);
                let Some(name) = mapped["security_name"].as_str() else {
                    // RFC 6353 §5.3.2: no name, no messages; the session is shut down
                    println!("SNMP dtls closed {from}: no-security-name for certificate {}", &fields["sha256"].as_str().unwrap_or("")[..16]);
                    let _ = stream.shutdown();
                    return;
                };
                println!("SNMP dtls session {from}: security name {name:?} (row {})", mapped["row"]);
                let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                let peer = TlsPeer { certificate_sha256: fields["sha256"].as_str().unwrap_or("").to_string(),
                                     security_name: name.to_string(), transport: "dtls", reply: reply_tx };
                let mut rec = vec![0u8; 65536];
                let mut last = std::time::Instant::now();
                loop {
                    while let Ok(m) = reply_rx.try_recv() {
                        if stream.ssl_write(&m).is_err() {
                            return;
                        }
                    }
                    match stream.ssl_read(&mut rec) {
                        Ok(0) => return,
                        Ok(n) => {
                            last = std::time::Instant::now();
                            match dsip_events::tsm::dtls_record(&rec[..n]) {
                                Some(m) => {
                                    if tx.send(GatewayInput::SnmpTls(m, from, peer.clone())).is_err() {
                                        return;
                                    }
                                }
                                None => println!("SNMP dtls from {from}: a record that is not one message, dropped   E§3"),
                            }
                        }
                        Err(e) if e.code() == openssl::ssl::ErrorCode::WANT_READ => {
                            if last.elapsed() > std::time::Duration::from_secs(DTLS_IDLE_S) {
                                println!("SNMP dtls session {from}: idle for {DTLS_IDLE_S} s, closed");
                                let _ = stream.shutdown();
                                return;
                            }
                            continue;
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    Ok(())
}

/// Accept syslog-over-TLS connections; each verified connection's octet-counted frames (RFC 5425 §4.3:
/// `MSG-LEN SP SYSLOG-MSG`) become inputs carrying its leaf certificate's SHA-256.
fn spawn_syslog_tls(l: tokio::net::TcpListener, cfg: std::sync::Arc<tokio_rustls::rustls::ServerConfig>, tx: tokio::sync::mpsc::UnboundedSender<GatewayInput>) {
    use sha2::Digest as _;
    use tokio::io::AsyncReadExt as _;
    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        while let Ok((tcp, from)) = l.accept().await {
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(e) => {
                        println!("SYSLOG tls refused from {from}: {e}");
                        return;
                    }
                };
                let Some(leaf) = tls.get_ref().1.peer_certificates().and_then(|c| c.first()) else { return };
                let fp: String = sha2::Sha256::digest(leaf.as_ref()).iter().map(|b| format!("{b:02x}")).collect();
                loop {
                    let mut len = 0usize;
                    let mut digits = 0;
                    loop {
                        let Ok(c) = tls.read_u8().await else { return };
                        match c {
                            b'0'..=b'9' if digits < 9 && !(digits == 0 && c == b'0') => {
                                len = len * 10 + (c - b'0') as usize;
                                digits += 1;
                            }
                            b' ' if digits > 0 => break,
                            _ => {
                                println!("SYSLOG tls from {from}: bad frame, closing");
                                return;
                            }
                        }
                    }
                    if len > SYSLOG_TLS_MAX {
                        println!("SYSLOG tls from {from}: frame of {len} bytes, closing");
                        return;
                    }
                    let mut msg = vec![0u8; len];
                    if tls.read_exact(&mut msg).await.is_err() || tx.send(GatewayInput::Syslog(msg, from, Some(fp.clone()))).is_err() {
                        return;
                    }
                }
            });
        }
    });
}

/// The gateway's USM receiver (E§3): its engine ID (given, or generated once and kept in `state`), its boots (kept in
/// `state`, one more at every start, RFC 3414 §2.2), and the users file.
/// `--syslog-signers` → the collector's signers (`{hostname, type, key}`, key base64): a certificate's DER for `C`,
/// the KeyID and OpenPGP certificate for `P` (E§3, v0.11).
fn syslog_signers(path: &Path) -> Result<Value> {
    use base64::Engine as _;
    let list: Value = serde_json::from_str(&std::fs::read_to_string(path)?).context("--syslog-signers")?;
    let mut out = vec![];
    for s in list.as_array().context("--syslog-signers: a JSON array")? {
        let host = s["hostname"].as_str().context("--syslog-signers: each entry needs a hostname")?;
        if let Some(pem) = s["certificate"].as_str() {
            let der = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(pem)?)).next()
                .context("--syslog-signers: no certificate in the PEM file")??;
            out.push(json!({"hostname": host, "type": "C", "key": base64::engine::general_purpose::STANDARD.encode(der.as_ref()),
                            "gaps": s["gaps"] == true}));
        } else if let Some(path) = s["openpgp"].as_str() {
            let blob = std::fs::read_to_string(path).with_context(|| format!("--syslog-signers: {path}"))?;
            out.push(json!({"hostname": host, "type": "P", "key": blob.trim(), "gaps": s["gaps"] == true}));
        } else {
            out.push(json!({"hostname": host, "type": "K", "key": s["key"].as_str().context("--syslog-signers: certificate or key")?,
                            "gaps": s["gaps"] == true}));
        }
    }
    println!("GATEWAY syslog-sign: {} signer(s)   RFC 5848", out.len());
    Ok(Value::Array(out))
}

/// The gateway's snmpEngineID: given, or generated once and kept in `state`. USM and TSM (discovery) share it.
fn snmp_engine_id(state: &Path, engine: Option<&str>) -> Result<(Vec<u8>, String)> {
    let unhex = |h: &str| -> Option<Vec<u8>> { (0..h.len() / 2).map(|i| u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()).collect() };
    std::fs::create_dir_all(state)?;
    let id_file = state.join("snmp-engine-id");
    let engine_hex = match engine {
        Some(h) => h.to_lowercase(),
        None => match std::fs::read_to_string(&id_file) {
            Ok(h) => h.trim().to_string(),
            Err(_) => {
                // RFC 3411 §5 SnmpEngineID, format 5 (octets): 0x80 | enterprise 0, then 8 random bytes
                let r: [u8; 8] = rand::random();
                let h = format!("8000000005{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>());
                std::fs::write(&id_file, &h)?;
                h
            }
        },
    };
    let engine = unhex(&engine_hex).filter(|e| (5..=32).contains(&e.len())).context("--snmp-engine-id: 5–32 bytes of hex")?;
    Ok((engine, engine_hex))
}

fn usm_receiver(state: &Path, engine: Option<&str>, users: &Path) -> Result<dsip_events::usm::UsmReceiver> {
    let (engine, engine_hex) = snmp_engine_id(state, engine)?;
    let boots_file = state.join("snmp-engine-boots");
    let boots = std::fs::read_to_string(&boots_file).ok().and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0) + 1;
    std::fs::write(&boots_file, boots.to_string())?;
    let list: Value = serde_json::from_str(&std::fs::read_to_string(users)?).context("--snmp-users")?;
    let mut parsed = vec![];
    for u in list.as_array().context("--snmp-users: a JSON array")? {
        anyhow::ensure!(u["priv"].is_null() || u["priv"] == "aes128", "--snmp-users: privacy must be aes128 (DES is refused, E§3)");
        parsed.push(dsip_events::usm::User::from_json(u).with_context(|| format!("--snmp-users: bad entry {u}"))?);
    }
    println!("GATEWAY SNMP engine {engine_hex} boots {boots}, {} USM user(s)", parsed.len());
    Ok(dsip_events::usm::UsmReceiver::new(engine, boots.min((1 << 31) - 1), 0, now_s(), parsed))
}

/// One received device event as a line: the device claim with its basis (E§2: a client MUST render the basis; an
/// unknown basis renders as unauthenticated), the authenticated identity the basis adds, and what happened.
fn render_event(ev: &Value) -> String {
    let src = &ev["source"];
    let basis = src["basis"].as_str().unwrap_or("");
    let known = ["snmpv1", "snmpv2c", "snmpv3-auth", "snmpv3-authpriv", "snmpv3-tls", "syslog-signed", "syslog-tls", "syslog-udp", "gateway"];
    let mut out = format!("source={} basis={}", src["address"].as_str().unwrap_or(""),
                          if known.contains(&basis) { basis.to_string() } else { format!("{basis}(unauthenticated)") });
    if let Some(u) = src.get("usm") {
        out += &format!(" usm={}@{}", u["user"].as_str().unwrap_or(""), u["engine_id"].as_str().unwrap_or(""));
    }
    if let Some(s) = src.get("signed") {
        out += &format!(" signed={}/{} rsid={} #{} key={}…", s["hostname"].as_str().unwrap_or(""), s["app_name"].as_str().unwrap_or(""),
                        s["rsid"], s["message_number"], s["key_sha256"].as_str().unwrap_or("").get(..16).unwrap_or(""));
    }
    if let Some(t) = src["tsm"]["security_name"].as_str() {
        out += &format!(" tsm={t:?}");
        if src.pointer("/tsm/transport").and_then(Value::as_str) == Some("dtls") {
            out += " dtls";
        }
    }
    if let Some(c) = src["certificate_sha256"].as_str() {
        out += &format!(" cert={}…", c.get(..16).unwrap_or(c));
    }
    // E§2 (v0.10): the gateway's name for that identity, only beside the identity it names
    if let Some(n) = src["name"].as_str().filter(|_| src.get("certificate_sha256").is_some() || src.get("usm").is_some()) {
        out += &format!(" name={n:?} (gateway's claim)");
    }
    let raw = &ev["raw"];
    if let Some(t) = raw["snmp"]["trap_oid"].as_str() {
        out += &format!(" trap={t}");
    } else if let Some(sl) = raw.get("syslog") {
        out += &format!(" syslog={} severity={} app={} msg={:?}", sl["format"].as_str().unwrap_or(""), sl["severity"],
                        sl["app_name"].as_str().unwrap_or("-"), sl["msg"].as_str().unwrap_or(""));
    }
    // E§5 (v0.11): a signed-syslog gap, the gateway's own observation
    if let Some(g) = ev.get("syslog_gap") {
        out += &format!(" syslog_gap={}/{} rsid={} sg={} spri={} lost={}–{}", g["hostname"].as_str().unwrap_or(""),
                        g["app_name"].as_str().unwrap_or(""), g["rsid"], g["sg"], g["spri"], g["from"], g["to"]);
    }
    out
}
