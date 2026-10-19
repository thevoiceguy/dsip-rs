//! A device's deposits awaiting an answer, by deposit id: what each was, the hub it was addressed to, when an
//! application deposit went out (one with no answer at all counts as the hub unreachable), and the deposits due again
//! at a time.
//!
//! Spec: M§5.3 (a deposit is answered `accepted` or `error`, `in_reply_to` its id), M§9.2 (pending until the answer),
//! M§9.4 (no answer at all: the hub unreachable), M§7.4 (an answer is judged against the hub the deposit was addressed
//! to, not the group's current one; a new hub not hosting the group yet: the same deposit again later, spec-gap 129).
//!
//! Impl (spec-gap 72): the no-answer timeout is the device's own. What a deposit was (`P`) is the host's; this keeps
//! the bookkeeping every host repeats, and the host persists what it chooses of it.

use std::collections::BTreeMap;

/// Deposits awaiting an answer, by deposit id.
#[derive(Debug)]
pub struct Deposits<P> {
    pending: BTreeMap<String, P>,
    /// The hub each group deposit was addressed to.
    hubs: BTreeMap<String, String>,
    /// When each watched deposit went out.
    sent_at: BTreeMap<String, i64>,
    /// Deposits due again at a time, taken out of the registry until then.
    later: Vec<(i64, P)>,
    /// Seconds after which a watched deposit with no answer counts as the hub unreachable.
    pub no_answer: i64,
}

impl<P> Deposits<P> {
    /// An empty registry.
    pub fn new(no_answer: i64) -> Deposits<P> {
        Deposits { pending: BTreeMap::new(), hubs: BTreeMap::new(), sent_at: BTreeMap::new(), later: vec![], no_answer }
    }

    /// Deposit `id` was `p`, awaiting its answer.
    pub fn insert(&mut self, id: String, p: P) {
        self.pending.insert(id, p);
    }

    /// Deposit `id` was addressed to `hub` (M§7.4).
    pub fn addressed(&mut self, id: String, hub: String) {
        self.hubs.insert(id, hub);
    }

    /// Deposit `id` went out at `now`: no answer within [`Deposits::no_answer`] counts as the hub unreachable (M§9.4).
    pub fn watch(&mut self, id: String, now: i64) {
        self.sent_at.insert(id, now);
    }

    /// Whether `id` is awaiting an answer.
    pub fn contains(&self, id: &str) -> bool {
        self.pending.contains_key(id)
    }

    /// What deposit `id` was.
    pub fn get(&self, id: &str) -> Option<&P> {
        self.pending.get(id)
    }

    /// Every deposit awaiting an answer.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &P)> {
        self.pending.iter()
    }

    /// Forget deposit `id`: what it was, if it was awaiting an answer.
    pub fn remove(&mut self, id: &str) -> Option<P> {
        self.hubs.remove(id);
        self.sent_at.remove(id);
        self.pending.remove(id)
    }

    /// Deposit `id` was answered (M§5.3): what it was and the hub it was addressed to, if it was ours.
    pub fn answer(&mut self, id: &str) -> Option<(P, Option<String>)> {
        let hub = self.hubs.remove(id);
        self.sent_at.remove(id);
        self.pending.remove(id).map(|p| (p, hub))
    }

    /// Make `p` again at `at` (spec-gap 129); [`Deposits::due`] hands it back.
    pub fn defer(&mut self, p: P, at: i64) {
        self.later.push((at, p));
    }

    /// The deferred deposits due by `now`, oldest first.
    pub fn due(&mut self, now: i64) -> Vec<P> {
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.later).into_iter().partition(|(at, _)| *at <= now);
        self.later = later;
        due.into_iter().map(|(_, p)| p).collect()
    }

    /// The watched deposits with no answer by `now`, taken out of the registry: each counts as the hub unreachable
    /// (M§9.4).
    pub fn silent(&mut self, now: i64) -> Vec<(String, P)> {
        let expired: Vec<String> = self.sent_at.iter().filter(|(_, at)| now - **at >= self.no_answer).map(|(id, _)| id.clone()).collect();
        let out = expired.into_iter().filter_map(|id| self.remove(&id).map(|p| (id, p))).collect();
        let pending = &self.pending;
        self.sent_at.retain(|id, _| pending.contains_key(id));
        self.hubs.retain(|id, _| pending.contains_key(id));
        out
    }
}
