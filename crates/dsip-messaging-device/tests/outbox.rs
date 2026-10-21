//! The outbox both messaging clients share: items pending until accepted, an unreachable hub queueing them and
//! retrying the head, an accepted flushing the rest in order, the successor trigger past the threshold, and an outage
//! that starts when the hub stopped answering however long the machine has existed.
//!
//! Spec: M§9.2–M§9.4 (spec-gap 72).

use serde_json::{json, Value};

use dsip_messaging_device::{Deposit, Outbox};

const G: &str = "group-1";

fn item(id: &str) -> Value {
    json!({"id": id, "mls": "AAAA", "obj": {"object": "content", "id": id}})
}

fn forwards(ems: &[Value]) -> Vec<&str> {
    ems.iter().filter_map(|e| e["forward"].as_str()).collect()
}

#[test]
fn an_outage_starts_when_the_hub_stops_answering() {
    // a deposit at t=0, accepted
    let mut o = Outbox::new(3600);
    assert_eq!(o.deposit(G, item("a")), Deposit::Send);
    o.answered(G, "a", None);
    o.remove(G, "a");
    // the host's clock ticks while the hub is up
    for t in [60, 1800, 7199] {
        assert!(o.due(t).is_empty());
    }
    // two hours on, the hub stops answering: the outage starts now, so the next tick retries the head
    assert_eq!(o.deposit(G, item("b")), Deposit::Send);
    let (started, ems) = o.unreachable(G, "b", false, 7200);
    assert!(started);
    assert_eq!(ems, vec![json!({"retry_in": 1})]);
    // not the time of the first deposit, two hours before
    assert_eq!(o.outages[G].down_since(), Some(7200));
    let due = o.due(7201);
    assert_eq!(due.len(), 1);
    assert_eq!(forwards(&due[0].1), vec!["b"], "a retry, not the successor trigger: {due:?}");
}

#[test]
fn queued_flushed_then_abandoned() {
    // the machine made only when the hub first proves unreachable (the browser's way)
    let mut o = Outbox::new(30);
    assert_eq!(o.deposit(G, item("a")), Deposit::Send);
    assert!(o.outages.is_empty());
    let (started, ems) = o.unreachable(G, "a", false, 100);
    assert!(started && o.is_down(G));
    assert_eq!(ems, vec![json!({"retry_in": 1})]);
    // while down, new items wait behind the head (M§9.4)
    assert_eq!(o.deposit(G, item("b")), Deposit::Queued);
    assert_eq!(o.pending(G), 2);
    // the head's retry, then an accepted: the hub is back and the rest goes out in order
    assert_eq!(forwards(&o.due(101)[0].1), vec!["a"]);
    let ems = o.answered(G, "a", None);
    o.remove(G, "a");
    assert_eq!(forwards(&ems), vec!["b"]);
    assert!(!o.is_down(G));

    // down again, for longer than the threshold: the successor trigger takes the pending items (M§7.5)
    let (started, _) = o.unreachable(G, "b", true, 200);
    assert!(started);
    let due = o.due(231);
    assert_eq!(due[0].1, vec![json!({"successor": {"pending": ["b"]}})]);
    assert!(o.is_abandoned(G));
    assert_eq!(o.take(G).len(), 1);
    // the dead group takes nothing more
    assert_eq!(o.deposit(G, item("c")), Deposit::Abandoned);
    assert_eq!(o.pending(G), 0);
    o.forget(G);
    assert!(!o.is_abandoned(G) && o.outages.is_empty());
}

#[test]
fn a_restored_outage_retries_at_once() {
    let mut o = Outbox::new(3600);
    o.items.insert(G.into(), vec![item("a"), item("b")]);
    o.restore_outage(G, Some(500), 900);
    assert!(o.is_down(G));
    // the first retry is due on the first tick, even within the same second
    let due = o.due(900);
    assert_eq!(forwards(&due[0].1), vec!["a"]);
    // a group whose hub was up gets a machine that is up
    o.restore_outage("group-2", None, 900);
    assert!(!o.is_down("group-2"));
    assert_eq!(o.item(G, "b").map(|i| i["id"].clone()), Some(json!("b")));
    o.item_mut(G, "b").unwrap()["mls"] = json!("BBBB");
    assert_eq!(o.item(G, "b").unwrap()["mls"], "BBBB");
}
