//! Renegotiation at the media layer.
//!
//! Spec: B§5.1 (a re-offer is a full offer on the same transport, same ICE credentials),
//! B§5.2 (the sender keeps its current description until the answer applies; rollback on
//! reject), B§5.4 (a remote re-offer that changes the ICE credentials is an ICE restart and is
//! refused with `media.unsupported`; a local one is a sender bug and is never sent).

use serde_json::{json, Value};

/// Local-description state for one established transport.
#[derive(Debug, Default)]
pub struct Renegotiation {
    ufrag: Option<String>,
    pending: bool,
}

impl Renegotiation {
    /// `ufrag` = the established transport's ICE username fragment.
    pub fn new(ufrag: Option<&str>) -> Self {
        Renegotiation { ufrag: ufrag.map(String::from), pending: false }
    }

    /// Apply one event (vector vocabulary) and return the emissions.
    pub fn step(&mut self, ev: &Value) -> Vec<Value> {
        let ufrag_of = |k: &str| ev.get(k).and_then(|o| o.get("ufrag")).and_then(Value::as_str).map(String::from);
        if ev.get("local_reoffer").is_some() {
            if ufrag_of("local_reoffer") != self.ufrag {
                return vec![json!({"error": "binding-ice-restart", "detail": "a re-offer MUST keep the ICE credentials"})];
            }
            self.pending = true;
            return vec![json!({"local_description": "pending"})];
        }
        if ev.get("remote_answer").is_some() {
            if !self.pending {
                return vec![json!({"ignore": "no-pending-offer"})];
            }
            self.pending = false;
            return vec![json!({"apply": "answer"}), json!({"local_description": "current"})];
        }
        if ev.get("remote_reject").is_some() {
            if !self.pending {
                return vec![json!({"ignore": "no-pending-offer"})];
            }
            self.pending = false;
            return vec![json!({"rollback": true}), json!({"local_description": "current"})];
        }
        if ev.get("remote_reoffer").is_some() {
            if ufrag_of("remote_reoffer") != self.ufrag {
                return vec![json!({"reject": {"reason": "media.unsupported", "detail": "ice-restart"}})];
            }
            return vec![json!({"ui": "update_offered"})];
        }
        if ev.get("answer_update").is_some() {
            return vec![json!({"apply": "remote-offer+answer"})];
        }
        vec![json!({"ignore": "unknown-event"})]
    }
}
