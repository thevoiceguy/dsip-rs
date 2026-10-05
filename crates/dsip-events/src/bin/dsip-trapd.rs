//! `dsip-trapd` — the receiving half of a Device Events gateway: SNMPv1/v2c traps on UDP in, one
//! `device-event <json>` line per trap out, for the gateway's DSIP device (`dsip-msg`) to sign and deposit.
//!
//! Spec: E§2 (the gateway is the signer, the device a claim with a basis), E§3 (translation, the community never
//! carried), E§4 (the rule table), E§5 (the `device-event` object and the gateway heartbeat).
//!
//! Impl: the DSIP side is `dsip-msg`, fed on its stdin, so this process holds no DSIP keys. Informs and SNMPv3
//! are not handled yet (see `dsip_events::ber`).

use std::io::Write as _;
use std::net::UdpSocket;
use std::time::Duration;

use serde_json::{json, Value};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn emit(event: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "device-event {event}");
    let _ = out.flush();
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let listen = arg(&args, "--listen").unwrap_or_else(|| "127.0.0.1:1162".into());
    let rules: Value = match arg(&args, "--rules") {
        Some(path) => serde_json::from_str(&std::fs::read_to_string(path)?).unwrap_or(json!([])),
        None => json!([]),
    };
    let sock = UdpSocket::bind(&listen)?;
    eprintln!("dsip-trapd listening on {listen}");
    // E§5: the gateway's liveness, so the NOC can raise dsip-gateway-silent when it stops
    if let Some(n) = arg(&args, "--heartbeat").and_then(|n| n.parse::<u64>().ok()) {
        std::thread::spawn(move || loop {
            emit(&json!({"heartbeat": {"interval_s": n}}));
            std::thread::sleep(Duration::from_secs(n));
        });
    }
    let mut buf = [0u8; 65535];
    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        let trap = match dsip_events::ber::decode_trap(&buf[..n]) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("dropped a datagram from {from}: {}", e.0);
                continue;
            }
        };
        let raw = dsip_events::normalize_trap(&trap);
        if raw.get("error").is_some() {
            eprintln!("dropped a malformed trap from {from}");
            continue;
        }
        let address = from.ip().to_string();
        let basis = if trap["version"] == "v1" { "snmpv1" } else { "snmpv2c" }; // E§2: community only, unauthenticated
        let mut event = json!({"source": {"address": address, "basis": basis}, "raw": raw});
        if let Some(alarm) = dsip_events::map_alarm(&raw, &rules, &address).get("alarm") {
            event["alarm"] = alarm.clone();
        }
        eprintln!("trap from {from}: {}", raw["snmp"]["trap_oid"]);
        emit(&event);
    }
}
