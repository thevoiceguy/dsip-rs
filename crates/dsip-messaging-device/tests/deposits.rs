//! The deposits both messaging clients await answers to: an answer returns what the deposit was and the hub it went
//! to, a watched deposit with no answer counts as the hub unreachable, and a deferred deposit comes back when due.
//!
//! Spec: M§5.3, M§9.2, M§9.4 (spec-gap 72), M§7.4 (spec-gap 129).

use dsip_messaging_device::Deposits;

#[test]
fn an_answer_is_judged_against_the_hub_it_went_to() {
    let mut d = Deposits::new(60);
    d.addressed("d1".into(), "did:web:old-hub".into());
    d.insert("d1".into(), "commit");
    assert!(d.contains("d1"));
    // the group moved since: the answer still names the hub the deposit was addressed to (M§7.4)
    assert_eq!(d.answer("d1"), Some(("commit", Some("did:web:old-hub".to_string()))));
    // answered once: a second answer is not ours
    assert_eq!(d.answer("d1"), None);
    // a deposit to the mailbox has no hub
    d.insert("d2".into(), "config");
    assert_eq!(d.answer("d2"), Some(("config", None)));
}

#[test]
fn no_answer_counts_as_unreachable() {
    let mut d = Deposits::new(60);
    for (id, at) in [("a", 100), ("b", 130)] {
        d.addressed(id.into(), "did:web:hub".into());
        d.watch(id.into(), at);
        d.insert(id.into(), id);
    }
    // a deposit not watched (a commit) never goes silent
    d.insert("c".into(), "c");
    assert!(d.silent(159).is_empty());
    assert_eq!(d.silent(160), vec![("a".to_string(), "a")]);
    assert!(!d.contains("a"));
    // an answered deposit is no longer watched
    assert!(d.answer("b").is_some());
    assert!(d.silent(1000).is_empty());
    assert!(d.contains("c"));
}

#[test]
fn deferred_deposits_come_back_when_due() {
    let mut d = Deposits::new(60);
    d.insert("a".into(), "a");
    let (p, _) = d.answer("a").unwrap();
    // the new hub does not host the group yet: the same deposit again in 5 s (spec-gap 129)
    d.defer(p, 105);
    d.defer("b", 110);
    assert!(d.due(104).is_empty());
    assert_eq!(d.due(105), vec!["a"]);
    assert_eq!(d.due(200), vec!["b"]);
    assert!(d.due(300).is_empty());
}
