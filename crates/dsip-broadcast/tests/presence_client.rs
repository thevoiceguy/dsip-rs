//! The device's and the subscriber's presence helpers (client behaviour; the authority's side is pinned by vectors).

use dsip_broadcast::presence::{Publisher, Watch};
use serde_json::{json, Value};

const T: i64 = 1_760_000_000;

#[test]
fn publisher_sends_at_once_then_refreshes_at_two_thirds() {
    let mut p = Publisher::new("did:web:bob.example", "did:key:zPhone", "did:key:zRelay", 300);
    let r = p.set(Some("busy"), T).expect("sent at once");
    assert_eq!(
        (r["type"].as_str(), r["state"].as_str(), r["device"].as_str(), r["to"].as_str()),
        (Some("presence"), Some("busy"), Some("did:key:zPhone"), Some("did:key:zRelay"))
    );
    assert_eq!(r["seq"], json!(T));
    assert_eq!(p.next_deadline(), Some(T + 200));
    assert!(p.tick(T + 199).is_none());
    let again = p.tick(T + 200).expect("refreshed");
    assert!(again["seq"].as_i64() > r["seq"].as_i64());
}

#[test]
fn publisher_keeps_the_publish_interval_and_seq_grows() {
    let mut p = Publisher::new("did:web:bob.example", "did:key:zPhone", "did:key:zRelay", 300);
    let a = p.set(Some("busy"), T).unwrap();
    assert!(p.set(Some("away"), T + 2).is_none(), "P§8: held back inside 5 s");
    assert_eq!(p.next_deadline(), Some(T + 5));
    let b = p.tick(T + 5).expect("sent once the interval has passed");
    assert_eq!(b["state"], "away");
    assert!(b["seq"].as_i64() > a["seq"].as_i64());
}

#[test]
fn publisher_follows_refusals() {
    let mut p = Publisher::new("did:web:bob.example", "did:key:zPhone", "did:key:zRelay", 300);
    let a = p.set(Some("busy"), T).unwrap();
    p.refused("policy.rate-limited", Some(4), T);
    assert!(p.tick(T + 3).is_none());
    assert!(p.tick(T + 5).is_some());
    p.refused("presence.stale", None, T + 5);
    let c = p.tick(T + 5).expect("stale: again at once");
    assert!(c["seq"].as_i64() > a["seq"].as_i64());
    p.refused("presence.signer-mismatch", None, T + 5);
    assert!(p.tick(T + 500).is_none(), "P§9: not sent again until the user picks a state");
    assert!(p.set(Some("dnd"), T + 500).is_some());
}

#[test]
fn publisher_lifetime_is_clamped_to_p8() {
    assert_eq!(Publisher::new("i", "d", "a", 10).lifetime(), 60);
    assert_eq!(Publisher::new("i", "d", "a", 9999).lifetime(), 3600);
}

fn notify(seq: i64, asserted: &str, frames: &[&str]) -> Value {
    json!({"type": "notify", "seq": seq, "state": "active",
           "body": {"event": "presence", "state": asserted, "records": frames.iter().map(|f| json!({"frame": f})).collect::<Vec<_>>()}})
}

fn rec(device: &str, subject: &str, state: &str, exp: i64) -> Value {
    json!({"type": "presence", "from": device, "device": device, "subject": subject, "state": state, "seq": 1, "expires_at": exp})
}

#[test]
fn watch_keeps_only_records_that_verify_and_belong_to_the_target() {
    let bob = "did:web:bob.example";
    let mut w = Watch::new(bob);
    let verify = |f: &str| -> Option<(Value, String)> {
        match f {
            "phone" => Some((rec("did:key:zPhone", bob, "busy", T + 60), bob.into())),
            "other-subject" => Some((rec("did:key:zX", "did:web:eve.example", "dnd", T + 60), bob.into())),
            "signed-by-another-identity" => Some((rec("did:key:zY", bob, "dnd", T + 60), "did:web:eve.example".into())),
            _ => None,
        }
    };
    assert!(w.notify(&notify(1, "offline", &["phone", "other-subject", "signed-by-another-identity", "forged"]), verify));
    assert_eq!(w.records().len(), 1);
    let c = w.combined(T);
    assert_eq!((c.state.as_str(), c.source), ("busy", "record"));
    assert_eq!(w.combined(T + 60).source, "none", "P§4: an expired record is no candidate");
}

#[test]
fn watch_ignores_a_stale_notify_and_ends_on_terminated() {
    let mut w = Watch::new("did:web:bob.example");
    assert!(w.notify(&notify(2, "available", &[]), |_| None));
    assert!(!w.notify(&notify(2, "offline", &[]), |_| None), "§9.3: seq order");
    assert_eq!(w.combined(T).source, "assertion");
    let mut end = notify(3, "offline", &[]);
    end["state"] = "terminated".into();
    assert!(w.notify(&end, |_| None));
    assert!(w.terminated());
}
