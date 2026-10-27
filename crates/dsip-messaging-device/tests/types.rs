//! The typed results and inputs serialize, and are read, as the JSON the hosts used before they existed: a policy's
//! missing keys take their defaults, a source that served nothing has no `sha256` or `size`, and a fetch decision is
//! `{action, …}`.
//!
//! Spec: none (infrastructure): M§8.4 rule 7 (`blob_fetch`, spec-gap 106), M§10.5 (the receipt policy), M§13.3
//! (`call_ended_item`).

use serde_json::{from_value, json, to_value};

use dsip_messaging_device::blob::{self, Fetch, Tried};
use dsip_messaging_device::{CallEnded, CallLeg, FetchDecision, ReceiptPolicy, Sent};

#[test]
fn inputs_read_as_the_hosts_wrote_them() {
    let p: ReceiptPolicy = from_value(json!({"activity": true})).unwrap();
    assert_eq!(p, ReceiptPolicy { delivered: true, read: false, played: false, activity: true });
    let leg: CallLeg = from_value(json!({"session": "s", "peer": "p", "alerted": true, "ended_by": "remote"})).unwrap();
    assert_eq!(leg, CallLeg { session: "s".into(), peer: "p".into(), alerted: true, answered_here: false, ended_by: "remote".into(),
                              reason: String::new() });
    let tried: Vec<Tried> = from_value(json!([{"uri": "u", "status": 404}, {"uri": "v", "status": 200, "sha256": "00", "size": 1}])).unwrap();
    assert_eq!(tried[1].size, Some(1));
}

#[test]
fn results_serialize_as_before() {
    assert_eq!(to_value(blob::tried("u", 0, None)).unwrap(), json!({"uri": "u", "status": 0}));
    assert_eq!(to_value(FetchDecision::from(Fetch::Retry)).unwrap(), json!({"action": "retry", "reason": "unavailable"}));
    assert_eq!(to_value(FetchDecision::from(Fetch::GiveUp("mismatch".into()))).unwrap(), json!({"action": "give-up", "reason": "mismatch"}));
    assert_eq!(to_value(FetchDecision::from(Fetch::Play("u".into()))).unwrap(), json!({"action": "play", "source": "u"}));
    let none = CallEnded { event: None, item: None, send: String::new(), fresh: false };
    assert_eq!(to_value(none).unwrap(), json!({"event": null, "item": null, "send": "", "fresh": false}));
    assert_eq!(to_value(Sent { item: None, send: String::new() }).unwrap(), json!({"item": null, "send": ""}));
}
