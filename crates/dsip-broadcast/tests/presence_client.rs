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
    // spec-gap 160: a second past the interval, so the authority, on its own clock, sees 5 s between the two
    assert_eq!(p.next_deadline(), Some(T + 6));
    assert!(p.tick(T + 5).is_none(), "not at exactly 5 s");
    let b = p.tick(T + 6).expect("sent once the interval and its margin have passed");
    assert_eq!(b["state"], "away");
    assert!(b["seq"].as_i64() > a["seq"].as_i64());
}

#[test]
fn publisher_follows_refusals() {
    let mut p = Publisher::new("did:web:bob.example", "did:key:zPhone", "did:key:zRelay", 300);
    let a = p.set(Some("busy"), T).unwrap();
    p.refused("policy.rate-limited", Some(4), T);
    assert!(p.tick(T + 5).is_none(), "spec-gap 160: not at exactly retry_after, nor inside the hold-back");
    assert!(p.tick(T + 6).is_some());
    p.refused("presence.stale", None, T + 6);
    let c = p.tick(T + 6).expect("stale: again at once");
    assert!(c["seq"].as_i64() > a["seq"].as_i64());
    p.refused("presence.signer-mismatch", None, T + 6);
    assert!(p.tick(T + 500).is_none(), "P§9: not sent again until the user picks a state");
    assert!(p.set(Some("dnd"), T + 500).is_some());
}

#[test]
fn publisher_lifetime_is_clamped_to_p8() {
    assert_eq!(Publisher::new("i", "d", "a", 10).lifetime(), 60);
    assert_eq!(Publisher::new("i", "d", "a", 9999).lifetime(), 3600);
}

#[test]
fn publisher_keeps_one_record_per_audience_each_with_its_own_interval_and_seq() {
    let mut p = Publisher::new("did:web:bob.example", "did:key:zPhone", "did:key:zRelay", 300);
    let plain = p.set(Some("available"), T).expect("sent at once");
    assert!(plain.get("audience").is_none(), "P§6: the record with no audience carries none");
    // P§6, P§8: the interval runs per (device, audience), so a family record in the same second is not held back
    let fam = p.set_for(Some("family"), Some("busy"), T).expect("another audience is not held back");
    assert_eq!((fam["audience"].as_str(), fam["state"].as_str()), (Some("family"), Some("busy")));
    assert!(p.set_for(Some("family"), Some("dnd"), T + 1).is_none(), "but the same audience is, inside 5 s");
    assert_eq!(p.next_deadline(), Some(T + 6));
    assert_eq!(p.tick(T + 6).expect("the held family record")["state"], "dnd");
    assert!(p.tick(T + 6).is_none(), "nothing else is due");
    assert_eq!(p.states().collect::<Vec<_>>(), vec![(None, "available"), (Some("family"), "dnd")]);
}

#[test]
fn publisher_rebinds_every_audience_and_a_refusal_holds_only_its_own() {
    let mut p = Publisher::new("did:web:bob.example", "did:key:zPhone", "did:key:zRelay", 300);
    p.set(Some("available"), T);
    p.set_for(Some("work"), Some("away"), T);
    let first = p.rebind("did:key:zOther", T + 100).expect("no audience first");
    assert!(first.get("audience").is_none() && first["to"] == "did:key:zOther");
    let second = p.tick(T + 100).expect("then work");
    assert_eq!(second["audience"], "work");
    assert!(p.tick(T + 100).is_none());
    p.refused_for(Some("work"), "presence.lifetime", None, T + 101);
    assert_eq!(p.next_deadline(), Some(T + 100 + 200), "work is held until the user picks again; the plain one still refreshes");
    p.set_for(Some("work"), None, T + 102);
    assert_eq!(p.state_for(Some("work")), None, "stopped: that record lapses at its expires_at");
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

#[test]
fn watch_opens_sealed_records_with_the_keys_held_and_lists_the_unreadable() {
    use dsip_core::presence_seal::{seal_record, RecordFields};
    let bob = "did:web:bob.example";
    let key = [7u8; 32];
    let sealed = |device: &str, kid: &str| {
        let mut r = json!({"type": "presence", "from": device, "device": device, "subject": bob, "kid": kid, "seq": 1, "expires_at": T + 60});
        let s = seal_record(&RecordFields::of(&r).unwrap(), "dnd", &key, &[1u8; 12]);
        r["sealed_state"] = s.into();
        r
    };
    let mut w = Watch::new(bob);
    let verify = |f: &str| -> Option<(Value, String)> {
        match f {
            "phone" => Some((sealed("did:key:zPhone", "main.1"), bob.into())),
            "laptop" => Some((sealed("did:key:zLaptop", "main.2"), bob.into())),
            "tablet" => Some((rec("did:key:zTablet", bob, "away", T + 60), bob.into())),
            _ => None,
        }
    };
    assert!(w.notify(&notify(1, "offline", &["phone", "laptop", "tablet"]), verify));
    assert_eq!(w.combined(T).state, "away", "a sealed record takes no part unopened");
    let (c, unreadable) = w.view(T, |kid| (kid == "main.1").then_some(key));
    assert_eq!((c.state.as_str(), c.source), ("dnd", "record"), "P§12.4: opened with the key held");
    assert_eq!(unreadable, vec!["did:key:zLaptop".to_string()], "no key for main.2");
}
