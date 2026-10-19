//! Commits a device makes: built for a change of the group, deposited with their welcome and grants, and retried as the
//! vector-pinned `CommitRetry` decides when the hub refuses them.
//!
//! Spec: M§6.5 (a commit is applied only on the hub's `accepted`; on a conflict the device syncs past the winning commit
//! and re-proposes while still needed), M§7.2 (an identity's devices added in one commit), M§7.3 (another identity removed
//! whole, every leaf of it; leaving by committing the leaver's Remove proposals), M§7.4 (a commit moving the hub),
//! M§14.2 (an Add carries the grants that admitted it).
//!
//! Impl (spec-gap 58, spec-gap 60): the decisions are `dsip_messaging::client::CommitRetry`'s; [`Retry`] reads them as
//! types. When a host re-proposes, and what it calls still needed, stays the host's.

use dsip_core::envelope::Context;
use dsip_messaging::client::CommitRetry;
use dsip_mls::{member_identity, Device};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

/// A change of the group a commit makes.
pub enum Change<'a> {
    /// Add these devices' KeyPackages, already authenticated (M§5.5, M§7.2).
    Add(&'a [KeyPackage]),
    /// Remove these leaves (M§7.3).
    Remove(&'a [LeafNodeIndex]),
    /// Refresh this device's own leaf key material (post-compromise security).
    Update,
    /// Move the group to another hub, `{did, uri}`: `dsip_conversation.hub` and nothing else (M§7.4).
    MoveHub(&'a Value),
    /// Commit the pending proposals: a leave, by the leaver's Remove proposals (M§7.3 "Leaving").
    Proposals,
}

/// A commit staged in the group, and its welcome if it adds anyone.
#[derive(Debug)]
pub struct Built {
    /// The commit's MLS bytes.
    pub commit: Vec<u8>,
    /// The welcome's MLS bytes.
    pub welcome: Option<Vec<u8>>,
}

impl Built {
    /// The handshake deposit's fields (M§5.2): the commit, its welcome, and the grants that admitted the devices it adds
    /// (M§14.2), when there are any.
    pub fn fields(&self, grants: &[String]) -> Value {
        let mut fields = json!({"mls": dsip_core::b64::encode(&self.commit)});
        if let Some(w) = &self.welcome {
            fields["welcome"] = json!(dsip_core::b64::encode(w));
        }
        if !grants.is_empty() {
            fields["grants"] = json!(grants);
        }
        fields
    }
}

/// Stage a commit for `change` in `group` (M§6.5: merged only once the hub accepts it).
pub fn build<P: OpenMlsProvider>(mls: &Device<P>, group: &mut MlsGroup, change: Change) -> Result<Built, String> {
    let (provider, signer) = (mls.provider(), mls.signer());
    let e = |x: &dyn std::fmt::Debug| format!("{x:?}");
    let (commit, welcome) = match change {
        Change::Add(kps) => {
            let (commit, welcome, _) = group.add_members(provider, &signer, kps).map_err(|x| e(&x))?;
            (commit, Some(welcome))
        }
        Change::Remove(leaves) => {
            let (commit, welcome, _) = group.remove_members(provider, &signer, leaves).map_err(|x| e(&x))?;
            (commit, welcome)
        }
        Change::Update => {
            let (commit, welcome, _) = group.self_update(provider, &signer, LeafNodeParameters::default()).map_err(|x| e(&x))?.into_messages();
            (commit, welcome)
        }
        Change::MoveHub(hub) => (mls.move_hub_commit(group, hub).map_err(|x| x.0)?, None),
        Change::Proposals => {
            let (commit, welcome, _) = group.commit_to_pending_proposals(provider, &signer).map_err(|x| e(&x))?;
            (commit, welcome)
        }
    };
    Ok(Built {
        commit: commit.tls_serialize_detached().map_err(|x| e(&x))?,
        welcome: welcome.map(|w| w.tls_serialize_detached()).transpose().map_err(|x| e(&x))?,
    })
}

/// The leaves of `group` that authenticate as `identity` (M§6.2), every device of it.
pub fn identity_leaves(group: &MlsGroup, ctx: &Context, identity: &str) -> Vec<LeafNodeIndex> {
    group.members().filter(|m| member_identity(group, m.index, ctx).is_ok_and(|w| w.identity == identity)).map(|m| m.index).collect()
}

/// The leaves of `group` whose credential names `device`, whether or not their delegation still verifies: a lapsed
/// device is removed by its credential.
pub fn device_leaves(group: &MlsGroup, device: &str) -> Vec<LeafNodeIndex> {
    group.members()
        .filter(|m| BasicCredential::try_from(m.credential.clone()).is_ok_and(|b| b.identity() == device.as_bytes()))
        .map(|m| m.index)
        .collect()
}

/// Whether `group` has a leaf that authenticates as `identity` (M§6.2), and as `device` of it when one is named.
pub fn has_member(group: &MlsGroup, ctx: &Context, identity: &str, device: Option<&str>) -> bool {
    group.members().any(|m| {
        member_identity(group, m.index, ctx).ok().is_some_and(|w| w.identity == identity && device.is_none_or(|d| w.device == d))
    })
}

/// What to do with the hub's answer to a commit.
#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// Accepted: merge the staged commit.
    Merge,
    /// Refused: discard the staged commit, then either sync past the winning commit and ask [`Retry::synced`]
    /// (`surface` `None`) or give up with `surface`.
    Discard {
        /// The reason to surface, when the commit is given up.
        surface: Option<String>,
    },
}

/// What to do once synced after a refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum Synced {
    /// The change is no longer needed: a winning commit made it.
    Done,
    /// Give up with this reason.
    Surface(String),
    /// Propose it again; this is attempt `n`.
    Repropose(i64),
}

/// One commit's retries: `CommitRetry`'s decisions as types.
#[derive(Debug, Clone)]
pub struct Retry(CommitRetry);

impl Default for Retry {
    fn default() -> Retry {
        Retry(CommitRetry::new(&json!({})))
    }
}

impl Retry {
    /// The hub answered: `reason` `None` for `accepted`.
    pub fn answer(&mut self, reason: Option<&str>) -> Answer {
        let actions = self.0.answer(reason);
        if actions.iter().any(|a| a.get("merge").is_some()) {
            return Answer::Merge;
        }
        Answer::Discard { surface: actions.iter().find_map(|a| a["surface"].as_str().map(String::from)) }
    }

    /// Synced after a refusal: whether the change is `still_needed`, and whether the group's hub moved (M§7.4).
    pub fn synced(&mut self, still_needed: bool, hub_moved: bool) -> Synced {
        let actions = self.0.synced(still_needed, hub_moved);
        if let Some(r) = actions.iter().find_map(|a| a["surface"].as_str()) {
            return Synced::Surface(r.to_string());
        }
        match actions.iter().find_map(|a| a["repropose"]["attempt"].as_i64()) {
            Some(n) => Synced::Repropose(n),
            None => Synced::Done,
        }
    }
}
