//! Where the two messaging clients still behave differently: each behaviour behind an option, so that one client can
//! carry both until each is decided (dsip-rs stage 3i). `Config::DSIP_MSG` and `Config::BROWSER` are what each client
//! did; an option goes once it is decided, with a vector where a rule is involved.
//!
//! Spec: M§8.5 (duplicates collapse), M§9.4 (no answer at all: the hub unreachable), M§6.5 ("if still needed"), M§7.2
//! (a welcome for the devices an Add adds), M§7.5 (the last roster this device processed), M§12.1 (archive keys),
//! M§6.5 (a gap that does not fill in time: the device re-joins, M§6.8; spec-gap 69), M§5.4 (an item that cannot be
//! processed: spec-gaps 44 and 138).
//!
//! Impl: none of these is a reading of the spec the other contradicts; each is a choice the spec leaves to the device
//! (the no-answer timeout is spec-gap 72's). They are listed with the rest in `impl/docs/dsip-stack-design.md` §6.

use dsip_core::envelope::Context;
use dsip_mls::{authenticate_members, member_identity};
use openmls::prelude::MlsGroup;
use serde_json::Value;

use crate::commits;

/// The key a received object is shown and deduplicated by (M§8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKey {
    /// `conversation|sender|id`; a call event `call|session` (dsip-msg).
    WithSender,
    /// `conversation:id`; a call event `call:session` (browser).
    WithoutSender,
}

/// When an Add of one named device is still needed after a lost conflict (M§6.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedDevice {
    /// While no leaf's credential names the device (dsip-msg).
    ByCredential,
    /// While no leaf authenticates as that device of the identity (browser).
    Authenticated,
}

/// Which roster a device records for a group, for the successor checks (M§7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Roster {
    /// The identities of all its leaves, recorded only when every leaf authenticates (dsip-msg).
    AllLeaves,
    /// The identities of the leaves that authenticate (browser).
    Authenticated,
}

/// The options where the clients differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Seconds after which a deposit with no answer at all counts as the hub unreachable (M§9.4, spec-gap 72).
    pub no_answer_s: i64,
    /// The key received objects are shown and deduplicated by.
    pub object_key: ObjectKey,
    /// Whether a commit other than an Add deposits the welcome it produced (dsip-msg) or drops it (browser).
    pub other_welcomes: bool,
    /// When an Add of a named device is still needed.
    pub named_device: NamedDevice,
    /// Which roster is recorded for the successor checks.
    pub roster: Roster,
    /// Whether a received archive key replaces one already held under its `akid` (dsip-msg) or is ignored (browser).
    pub replace_archive_keys: bool,
    /// Whether a seq gap that has not filled in time makes this device re-join by external commit (dsip-msg), or it
    /// stays held and reported (browser).
    pub rejoin_gaps: bool,
    /// Whether an item that fails processing is rolled back with its delivery state and then committed as handled, so
    /// it is acknowledged (dsip-msg), or left as processing left it, uncommitted (browser).
    pub roll_back_unprocessable: bool,
}

impl Config {
    /// What dsip-msg did.
    pub const DSIP_MSG: Config = Config {
        no_answer_s: 20,
        object_key: ObjectKey::WithSender,
        other_welcomes: true,
        named_device: NamedDevice::ByCredential,
        roster: Roster::AllLeaves,
        replace_archive_keys: true,
        rejoin_gaps: true,
        roll_back_unprocessable: true,
    };

    /// What the browser did.
    pub const BROWSER: Config = Config {
        no_answer_s: 60,
        object_key: ObjectKey::WithoutSender,
        other_welcomes: false,
        named_device: NamedDevice::Authenticated,
        roster: Roster::Authenticated,
        replace_archive_keys: false,
        rejoin_gaps: false,
        roll_back_unprocessable: false,
    };

    /// The key `obj` is shown and deduplicated by.
    pub fn object_key(&self, obj: &Value) -> String {
        let s = |k: &str| obj[k].as_str().unwrap_or("").to_string();
        match (self.object_key, obj["object"] == "call-event") {
            // M§13.3 (spec-gap 63): one call event per session, whichever device reported it
            (ObjectKey::WithSender, true) => format!("call|{}", s("session")),
            (ObjectKey::WithoutSender, true) => format!("call:{}", s("session")),
            (ObjectKey::WithSender, false) => format!("{}|{}|{}", s("conversation"), s("sender"), s("id")),
            (ObjectKey::WithoutSender, false) => format!("{}:{}", s("conversation"), s("id")),
        }
    }

    /// Whether a commit's welcome is deposited: always for an Add (M§7.2), for anything else per
    /// [`Config::other_welcomes`].
    pub fn deposits_welcome(&self, add: bool) -> bool {
        add || self.other_welcomes
    }

    /// Whether an Add of `identity` (of its `device`, when one is named) is still needed in `group` (M§6.5).
    pub fn add_needed(&self, group: &MlsGroup, ctx: &Context, identity: &str, device: Option<&str>) -> bool {
        match (device, self.named_device) {
            (Some(d), NamedDevice::ByCredential) => commits::device_leaves(group, d).is_empty(),
            _ => !commits::has_member(group, ctx, identity, device),
        }
    }

    /// The roster of `group` by identity, sorted, to record for the successor checks (M§7.5); `None` records nothing.
    pub fn roster(&self, group: &MlsGroup, ctx: &Context) -> Option<Vec<String>> {
        let ids: Option<Vec<String>> = match self.roster {
            Roster::AllLeaves => authenticate_members(group, ctx).ok().map(|m| m.into_iter().map(|w| w.identity).collect()),
            Roster::Authenticated => Some(group.members().filter_map(|m| member_identity(group, m.index, ctx).ok()).map(|w| w.identity).collect()),
        };
        let mut ids = ids.filter(|i| !i.is_empty())?;
        ids.sort();
        ids.dedup();
        Some(ids)
    }
}
