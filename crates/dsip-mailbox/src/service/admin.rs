//! The mailbox's admin commands (`dsip-mailbox admin …`, on the status port): the enrolments against `--serve-any`,
//! and releasing one.
//!
//! Spec: none (infrastructure). Releasing an enrolment does what M§4.1 says an ended one does (everything held for
//! the identity deleted, its bindings closed, its place freed): the operator's end of it is spec-gap 164.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::status::{owners, quota_pct};
use super::Service;

/// The commands, for the binary's `admin` subcommand.
pub const COMMANDS: &[dsip_transport::admin::Command] = &[
    dsip_transport::admin::Command {
        name: "enrolments",
        about: "The identities enrolled within --serve-any, and the configured ones",
        arg: None,
        write: false,
        show: show_enrolments,
    },
    dsip_transport::admin::Command {
        name: "release",
        about: "End an enrolment: delete everything held for the identity, close its bindings, free its place",
        arg: Some(("identity", "DID")),
        write: true,
        show: show_released,
    },
];

/// Answer one admin command.
pub(super) fn answer(st: &mut Service, command: &str, args: &BTreeMap<String, String>, write: bool, now: i64) -> Value {
    match (command, write) {
        ("enrolments", _) => enrolments(st, now),
        ("release", true) => {
            let Some(identity) = args.get("identity") else { return json!({"error": "release needs identity=<did>"}) };
            if st.enrolment.is_configured(identity) {
                return json!({"error": format!("{identity} is configured (--owner), not enrolled: remove it from the configuration")});
            }
            if st.enrolment.operator_release(identity).is_empty() {
                return json!({"error": format!("{identity} is not enrolled here")});
            }
            let row = owners(st, now).into_iter().find(|r| &r.identity == identity);
            st.end_enrolment(identity, "operator");
            json!({"released": identity, "items": row.as_ref().map(|r| r.items), "used_bytes": row.as_ref().map(|r| r.used_bytes),
                "devices_closed": row.as_ref().map(|r| r.devices_bound), "free": free(st)})
        }
        ("release", false) => json!({"error": "release changes state: send it as a POST (dsip-mailbox admin release <did>)"}),
        _ => json!({"error": format!("no admin command {command:?} (enrolments, release)")}),
    }
}

fn free(st: &Service) -> Option<usize> {
    st.serve_any.map(|n| n.saturating_sub(st.enrolment.entries().len()))
}

fn enrolments(st: &Service, now: i64) -> Value {
    let rows: BTreeMap<String, _> = owners(st, now).into_iter().map(|r| (r.identity.clone(), r)).collect();
    let row = |identity: &str| {
        let r = rows.get(identity);
        json!({"identity": identity, "items": r.map(|r| r.items), "used_bytes": r.map(|r| r.used_bytes),
            "quota_pct": r.map(|r| quota_pct(r.used_bytes, st.quota_bytes)), "devices": r.map(|r| r.devices),
            "devices_bound": r.map(|r| r.devices_bound)})
    };
    let enrolled: Vec<Value> = st
        .enrolment
        .entries()
        .iter()
        .map(|(identity, seen)| {
            let mut v = row(identity);
            v["last_hello_s"] = json!(now - seen);
            v["released_in_s"] = json!(st.release_idle.then(|| st.mls_retention - (now - seen)));
            v
        })
        .collect();
    json!({
        "serve_any": st.serve_any, "free": free(st), "release_idle": st.release_idle, "mls_retention_s": st.mls_retention,
        "enrolled": enrolled,
        "configured": st.configured.iter().map(|c| row(c)).collect::<Vec<_>>(),
    })
}

fn ago(s: i64) -> String {
    match s {
        s if s < 120 => format!("{s} s"),
        s if s < 7200 => format!("{} min", s / 60),
        s if s < 172_800 => format!("{} h", s / 3600),
        s => format!("{} d", s / 86_400),
    }
}

fn show_enrolments(v: &Value) -> String {
    let mut out = match v["serve_any"].as_u64() {
        Some(n) => format!("serve-any {n}: {} enrolled, {} free", v["enrolled"].as_array().map_or(0, Vec::len), v["free"]),
        None => "serve-any off: configured owners only".to_string(),
    };
    if v["release_idle"] == json!(true) {
        out += &format!("; released after {} without a hello", ago(v["mls_retention_s"].as_i64().unwrap_or(0)));
    }
    out += "\n";
    let line = |r: &Value, extra: String| {
        format!("  {}  {} items, {} bytes, {}/{} devices bound{extra}\n", r["identity"].as_str().unwrap_or("?"),
            r["items"].as_u64().unwrap_or(0), r["used_bytes"].as_i64().unwrap_or(0),
            r["devices_bound"].as_u64().unwrap_or(0), r["devices"].as_u64().unwrap_or(0))
    };
    for r in v["enrolled"].as_array().into_iter().flatten() {
        let mut extra = format!(", last hello {} ago", ago(r["last_hello_s"].as_i64().unwrap_or(0)));
        if let Some(n) = r["released_in_s"].as_i64() {
            extra += &format!(", released in {}", ago(n.max(0)));
        }
        out += &line(r, extra);
    }
    let configured = v["configured"].as_array().map_or(&[][..], Vec::as_slice);
    if !configured.is_empty() {
        out += "configured:\n";
        for r in configured {
            out += &line(r, String::new());
        }
    }
    out
}

fn show_released(v: &Value) -> String {
    format!("released {}: deleted {} items ({} bytes), closed {} binding(s); {} free\n", v["released"].as_str().unwrap_or("?"),
        v["items"].as_u64().unwrap_or(0), v["used_bytes"].as_i64().unwrap_or(0), v["devices_closed"].as_u64().unwrap_or(0),
        v["free"].as_u64().map_or("no serve-any".to_string(), |n| n.to_string()))
}
