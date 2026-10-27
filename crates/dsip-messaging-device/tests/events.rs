//! The typed events serialize as the JSON the hosts read: a `{send}` frame, `{ui: kind, …}` with the kind's fields,
//! and the other one-key outputs, with no key a shape leaves out.
//!
//! Spec: none (infrastructure): M§6.5 (`self`, `conflict`), M§6.8 (`joined` by external commit), M§9.4 (`hub_retry`,
//! `refused` pending), M§13.3 (`call_event`).

use serde_json::{json, to_value};

use dsip_messaging_device::events::Rejected;
use dsip_messaging_device::{Event, OpInfo, Ui};

#[test]
fn one_key_outputs() {
    assert_eq!(to_value(Event::send("f")).unwrap(), json!({"send": "f"}));
    assert_eq!(to_value(Event::Sync { sync: true }).unwrap(), json!({"sync": true}));
    assert_eq!(to_value(Event::refused("no")).unwrap(), json!({"refused": "no"}));
    let pending = Event::Refused { refused: "m".into(), group: Some("g".into()), item: Some("i".into()), pending: Some(true) };
    assert_eq!(to_value(pending).unwrap(), json!({"refused": "m", "group": "g", "item": "i", "pending": true}));
    let mailbox = Event::Error { error: "e".into(), group: None, reason: Some(json!("mailbox.x")), detail: Some(json!(null)) };
    assert_eq!(to_value(mailbox).unwrap(), json!({"error": "e", "reason": "mailbox.x", "detail": null}));
    let rejected = Event::Rejected { rejected: Rejected { code: "signature-invalid".into(), reason: None } };
    assert_eq!(to_value(rejected).unwrap(), json!({"rejected": {"code": "signature-invalid", "reason": null}}));
}

#[test]
fn ui_kinds_and_their_fields() {
    let own: Event = Ui::Own { class: "handshake".into(), seq: Some(4) }.into();
    assert_eq!(to_value(own).unwrap(), json!({"ui": "self", "class": "handshake", "seq": 4}));
    let retry: Event = Ui::HubRetry { group: "g".into(), in_s: 8, item: None }.into();
    assert_eq!(to_value(retry).unwrap(), json!({"ui": "hub_retry", "group": "g", "in": 8, "item": null}));
    let conflict: Event = Ui::Conflict { group: "g".into(), reason: "r".into(), epoch: Some(2), op: Some(OpInfo::Update) }.into();
    assert_eq!(to_value(conflict).unwrap(), json!({"ui": "conflict", "group": "g", "reason": "r", "epoch": 2, "op": {"op": "update"}}));
    let add = OpInfo::Add { peer: "p".into(), device: None, devices: 2 };
    assert_eq!(to_value(add).unwrap(), json!({"op": "add", "peer": "p", "device": null, "devices": 2}));
    assert_eq!(to_value(Event::from(Ui::Resync)).unwrap(), json!({"ui": "resync"}));

    // a shape's absent keys stay absent: a welcome's join has no seq, an external one no successor
    let welcome: Event = Ui::Joined { group: "g".into(), conversation: json!("c"), kind: "direct".into(), members: vec![], epoch: 1,
                                      external: None, seq: None, successor_of: Some(json!(null)) }.into();
    assert_eq!(to_value(welcome).unwrap(),
               json!({"ui": "joined", "group": "g", "conversation": "c", "kind": "direct", "members": [], "epoch": 1, "successor_of": null}));
    let external: Event = Ui::Joined { group: "g".into(), conversation: json!("c"), kind: "group".into(), members: vec![], epoch: 3,
                                       external: Some(true), seq: Some(None), successor_of: None }.into();
    assert_eq!(to_value(external).unwrap(),
               json!({"ui": "joined", "group": "g", "conversation": "c", "kind": "group", "members": [], "epoch": 3, "external": true, "seq": null}));
    let archived: Event = Ui::CallEvent { session: json!("s"), peer: json!("p"), outcome: json!("missed"), direction: json!("inbound"),
                                          from_device: None, collapsed: None, from_archive: Some(true) }.into();
    assert_eq!(to_value(archived).unwrap(),
               json!({"ui": "call_event", "session": "s", "peer": "p", "outcome": "missed", "direction": "inbound", "from_archive": true}));
}
