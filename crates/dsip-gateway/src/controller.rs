//! The B2BUA controller for one call (plan §5): where the §12 state machine (hosted, never
//! re-implemented) meets the SIP dialog. Emissions name what each leg is told.
//!
//! Spec: §14.1 (the gateway answers `answered_by: gateway`), §12.5 (a 2xx crossing our CANCEL
//! is ACKed and torn down with `bye session.cancelled` on the SIP leg), §14.4 (a screening answer
//! makes the SIP leg `sendonly` toward the PSTN), §15.5 (mapped reasons on refusal and teardown),
//! §19.4 (first-contact refusals cross as 403), Appendix C (early media), §12.8 (hold ⇄ update).
//! Impl: REFER is declined (603) in round one; SIP 3xx is not followed as forking.

use serde_json::{json, Value};

use crate::{map_inbound, map_outbound, tel_claim, GATEWAY_DID};

/// One call's controller state.
#[derive(Debug)]
pub struct GatewayCall {
    direction: String,
    early_media: String,
    dsip: &'static str,
    sip: &'static str,
    answered: bool,
    cancelled: bool,
}

impl GatewayCall {
    /// From a vector `context` (`direction`, `early_media`).
    pub fn new(ctx: &Value) -> Self {
        GatewayCall {
            direction: ctx.get("direction").and_then(Value::as_str).unwrap_or("outbound").to_string(),
            early_media: ctx.get("early_media").and_then(Value::as_str).unwrap_or("auto").to_string(),
            dsip: "idle",
            sip: "idle",
            answered: false,
            cancelled: false,
        }
    }

    /// `{dsip, sip}` leg states.
    pub fn snapshot(&self) -> Value {
        json!({"dsip": self.dsip, "sip": self.sip})
    }

    fn bye_to_sip(&self, token: &str) -> Value {
        let r = map_outbound(token, "active");
        json!({"sip": {"request": "BYE", "q850": r["q850"], "reason_header": r["reason_header"]}})
    }

    /// Apply one event (vector vocabulary) and return the emissions.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let mut out = vec![];
        let outbound = self.direction == "outbound";
        if let Some(m) = ev.get("dsip") {
            let t = m.get("type").and_then(Value::as_str).unwrap_or("");
            match (t, outbound) {
                ("invite", true) => {
                    self.dsip = "inviting";
                    self.sip = "calling";
                    out.push(json!({"sip": "INVITE"}));
                }
                ("cancel", true) => {
                    self.cancelled = true;
                    if matches!(self.sip, "calling" | "early") {
                        out.push(json!({"sip": "CANCEL"}));
                    }
                    self.dsip = "ended";
                }
                ("progress", false) => {
                    self.dsip = "alerting";
                    out.push(json!({"sip": {"response": 180}}));
                }
                ("answer", false) => {
                    self.dsip = "active";
                    self.sip = "confirmed";
                    self.answered = true;
                    let direction = if m.get("answered_by").and_then(Value::as_str) == Some("screening") { "sendonly" } else { "sendrecv" };
                    out.push(json!({"sip": {"response": 200, "direction": direction}}));
                    out.push(json!({"media": "bridge"}));
                }
                ("reject", false) => {
                    let r = map_outbound(m.get("reason").and_then(Value::as_str).unwrap_or("session.failed"), "pre-answer");
                    self.dsip = "ended";
                    self.sip = "terminated";
                    out.push(json!({"sip": {"response": r["status"], "q850": r.get("q850").cloned().unwrap_or(Value::Null), "reason_header": r["reason_header"]}}));
                }
                ("update", _) => {
                    let direction = m.get("direction").and_then(Value::as_str).unwrap_or("sendrecv");
                    out.push(json!({"sip": {"request": "re-INVITE", "direction": direction}}));
                }
                ("bye", _) => {
                    self.dsip = "ended";
                    if matches!(self.sip, "calling" | "early" | "confirmed") {
                        out.push(self.bye_to_sip(m.get("reason").and_then(Value::as_str).unwrap_or("user.hangup")));
                        self.sip = "terminated";
                    }
                    out.push(json!({"media": "release"}));
                }
                _ => out.push(json!({"ignore": format!("dsip {t} in {}", self.dsip)})),
            }
        } else if let Some(s) = ev.get("sip") {
            if let (Some(st), true) = (s.get("status").and_then(Value::as_u64), outbound) {
                if self.cancelled {
                    if (200..300).contains(&st) {
                        out.push(json!({"sip": "ACK"}));
                        out.push(self.bye_to_sip("session.cancelled"));
                    }
                    self.sip = "terminated";
                } else if (100..200).contains(&st) {
                    if st >= 180 {
                        self.sip = "early";
                        if self.dsip == "inviting" {
                            self.dsip = "proceeding";
                            out.push(json!({"dsip": {"local": "alert"}}));
                        }
                    }
                    let has_sdp = s.get("sdp").and_then(Value::as_bool).unwrap_or(false);
                    if has_sdp && st == 183 && !self.answered && s.get("announcement").is_none()
                        && matches!(self.early_media.as_str(), "auto" | "always")
                    {
                        self.answered = true;
                        self.dsip = "active";
                        out.push(json!({"dsip": {"local": "accept", "answered_by": "gateway"}}));
                        out.push(json!({"media": "bridge"}));
                    }
                } else if (200..300).contains(&st) {
                    self.sip = "confirmed";
                    out.push(json!({"sip": "ACK"}));
                    if !self.answered {
                        self.answered = true;
                        self.dsip = "active";
                        out.push(json!({"dsip": {"local": "accept", "answered_by": "gateway"}}));
                        out.push(json!({"media": "bridge"}));
                    }
                } else {
                    self.sip = "terminated";
                    if self.dsip != "ended" {
                        let phase = if self.answered { "active" } else { "pre-answer" };
                        let r = map_inbound(Some(st as u32), s.get("q850").and_then(Value::as_u64).map(|c| c as u32), phase, s.get("moved_to").and_then(Value::as_str));
                        self.dsip = "ended";
                        if r["carry"] == "reject" {
                            let mut e = json!({"local": "auto_reject", "reason": r["reason"]});
                            if let Some(d) = r.get("detail") {
                                e["detail"] = d.clone();
                            }
                            out.push(json!({"dsip": e}));
                        } else {
                            out.push(json!({"dsip": {"local": "hangup", "reason": r["reason"]}}));
                            out.push(json!({"media": "release"}));
                        }
                    }
                }
            } else {
                match (s.get("request").and_then(Value::as_str), outbound) {
                    (Some("INVITE"), false) => {
                        self.dsip = "offered";
                        self.sip = "early";
                        let tc = tel_claim(s.get("from_tn").and_then(Value::as_str).unwrap_or(""), s.get("identity"), s.get("cnam").and_then(Value::as_str), GATEWAY_DID);
                        out.push(json!({"dsip": {"local": "place_call", "claims": [tc["claim"]], "trust_basis": tc["trust_basis"]}}));
                        out.push(json!({"sip": {"response": 100}}));
                    }
                    (Some("CANCEL"), false) => {
                        self.sip = "terminated";
                        out.push(json!({"sip": {"response": 200}}));
                        if matches!(self.dsip, "offered" | "alerting") {
                            self.dsip = "ended";
                            out.push(json!({"dsip": {"local": "cancel"}}));
                            out.push(json!({"sip": {"response": 487}}));
                        }
                    }
                    (Some("ACK"), _) => {}
                    (Some("BYE"), _) => {
                        self.sip = "terminated";
                        out.push(json!({"sip": {"response": 200}}));
                        if self.dsip != "ended" {
                            let r = map_inbound(None, s.get("q850").and_then(Value::as_u64).map(|c| c as u32), "active", None);
                            self.dsip = "ended";
                            out.push(json!({"dsip": {"local": "hangup", "reason": r["reason"]}}));
                            out.push(json!({"media": "release"}));
                        }
                    }
                    (Some("REFER"), _) => out.push(json!({"sip": {"response": 603}})),
                    (Some("re-INVITE"), _) => {
                        let direction = s.get("direction").and_then(Value::as_str).unwrap_or("sendrecv");
                        out.push(json!({"dsip": {"local": "update", "direction": direction}}));
                    }
                    _ => out.push(json!({"ignore": format!("sip {s}")})),
                }
            }
        } else if ev.get("timer").and_then(Value::as_str) == Some("C") && matches!(self.sip, "calling" | "early") && !self.answered {
            self.sip = "terminated";
            self.dsip = "ended";
            out.push(json!({"sip": "CANCEL"}));
            out.push(json!({"dsip": {"local": "auto_reject", "reason": "gateway.unreachable", "detail": "SIP Timer C"}}));
        }
        out
    }
}
