//! The MLS side of one inbound item, with no I/O, so a host can run it inside the item's transaction: a welcome
//! joined and its members authenticated; a commit's sender, adds, removes and conversation change checked, then
//! merged; an application message's object checked; a proposal stored.
//!
//! Spec: M§6.2 (every leaf authenticated; a lapsed leaf's content is unauthenticated), M§6.5, M§6.8 and spec-gap 62
//! (an external join checked as the hub checked it), M§7.3 and spec-gap 126 (a commit failing the roster rules is not
//! merged), M§7.3 "Leaving" and spec-gap 125 (a member's own Remove proposals), M§7.4 and spec-gap 60 (a commit may
//! change the hub and nothing else in `dsip_conversation`), M§8.1 (unknown objects are ignored), C§5, C§9.

use dsip_core::envelope::Context;
use dsip_messaging::checks::check_object;
use dsip_mls::{authenticate_members, conversation_extension, conversation_update, external_commit, member_identity, Device, MlsError};
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

/// What processing one inbound item produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// A welcome joined; `by` is the identity whose commit added this device (the GroupInfo's signer).
    Joined {
        /// The member identities.
        members: Vec<String>,
        /// The group id (base64url).
        group: String,
        /// The `dsip_conversation` extension.
        conv: Value,
        /// The epoch joined at.
        epoch: u64,
        /// Who added this device (M§7.3).
        by: String,
    },
    /// A welcome for another device of this identity: it holds none of our KeyPackages (M§12.3 step 5).
    NotForDevice,
    /// An application object that passed its checks.
    Object {
        /// The sender's identity.
        sender: String,
        /// The sender's device.
        sender_device: String,
        /// The object.
        object: Value,
    },
    /// Not merged or not shown, with why.
    Dropped(String),
    /// M§6.2: content from a member leaf whose delegation no longer verifies (revoked, expired) — not rendered, not
    /// archived. Expected, not an error: a device can send just before its revocation is known.
    Unauthenticated(String),
    /// C§5: `content` from a recorder leaf, treated as from an unauthenticated leaf: not rendered, not archived. Its
    /// other objects are processed as any member's (dsip-rs 3j-3c: dsip-msg dropped them too).
    RecorderContent {
        /// The recorder device.
        device: String,
        /// The content's `id`.
        id: Value,
    },
    /// M§7.3: a commit merged, attributed to the committing identity; `hub` is set when it changed the group's hub
    /// reference (M§7.4); `left` names the identities it removed by their own Remove proposals (M§7.3 "Leaving").
    Epoch {
        /// The new epoch.
        epoch: u64,
        /// The committing identity.
        by: String,
        /// `identity#device` of each leaf added.
        added: Vec<String>,
        /// `identity#device` of each leaf removed (`unverified#device` when it no longer authenticates).
        removed: Vec<String>,
        /// The identities that left by their own proposals.
        left: Vec<String>,
        /// The new hub reference.
        hub: Option<Value>,
    },
    /// This device was removed; `remaining` are the member identities left in the group.
    Removed {
        /// Who removed it.
        by: String,
        /// The identities left.
        remaining: Vec<String>,
    },
    /// A proposal stored for the next commit (M§7.3 "Leaving", [`ProcessOptions::store_proposals`]): the proposer's
    /// pending proposals in this epoch, Remove ones as `{identity, device}` and the count of others, with the roster.
    Proposal {
        /// `{identity, device}` of the proposer.
        proposer: Value,
        /// The leaves its Remove proposals name.
        removes: Vec<Value>,
        /// Its other proposals.
        others: usize,
        /// `{identity, device}` of every member.
        roster: Vec<Value>,
    },
    /// Nothing to act on.
    Nothing,
}

/// Where the two clients differ today; stage 3 keeps each client's behaviour, and each option goes once it is decided.
///
/// Impl: the browser sets every option, `dsip-msg` none (the stage 3 plan's behaviour differences 12 and 13); each
/// client's are in its [`crate::Config`] preset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcessOptions {
    /// Give the object check the sender's device (`leaf_device`) as well as its identity.
    pub leaf_device_in_check: bool,
    /// C§9: keep call records (`store: call-record`), which render nothing, as objects for a record-keeper.
    pub keep_call_records: bool,
    /// M§7.3 "Leaving": store a member's proposals for the next commit and report them (else they are ignored).
    pub store_proposals: bool,
}

fn mls_err<E: std::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> MlsError {
    move |e| MlsError(format!("{what}: {e:?}"))
}

/// The device name in a leaf's credential, for a leaf that no longer authenticates.
fn leaf_device(group: &MlsGroup, idx: LeafNodeIndex) -> String {
    group
        .public_group()
        .leaf(idx)
        .and_then(|l| BasicCredential::try_from(l.credential().clone()).ok())
        .map(|b| String::from_utf8_lossy(b.identity()).into_owned())
        .unwrap_or_default()
}

/// Process one MLS item: `group` is the target group with its conversation id and kind (a welcome needs none),
/// `class` the item's class (`welcome`, else a handshake or application message), `me` this device's identity.
pub fn process<P: OpenMlsProvider>(mls: &Device<P>, group: Option<(&mut MlsGroup, &str, &str)>, class: &str, bytes: &[u8], ctx: &Context,
                                   me: &str, opts: ProcessOptions) -> Result<Outcome, MlsError> {
    if class == "welcome" {
        let (joined, adder) = match mls.join_from(bytes) {
            Ok(g) => g,
            Err(e) if e.0.contains("NoMatchingKeyPackage") => return Ok(Outcome::NotForDevice),
            Err(e) => return Err(e),
        };
        let members: Vec<String> = authenticate_members(&joined, ctx)?.into_iter().map(|m| m.identity).collect();
        let conv: Value = serde_json::from_slice(&conversation_extension(&joined).ok_or_else(|| MlsError("no dsip_conversation".into()))?)
            .map_err(mls_err("dsip_conversation"))?;
        let by = member_identity(&joined, adder, ctx).map(|w| w.identity).unwrap_or_default();
        return Ok(Outcome::Joined { members, group: dsip_core::b64::encode(joined.group_id().as_slice()), conv, epoch: joined.epoch().as_u64(), by });
    }
    let Some((group, conversation, kind)) = group else { return Ok(Outcome::Nothing) };
    let msg = MlsMessageIn::tls_deserialize_exact(bytes).map_err(mls_err("mls bytes"))?;
    let pm = msg.try_into_protocol_message().map_err(mls_err("protocol message"))?;
    let processed = group.process_message(mls.provider(), pm).map_err(mls_err("undecryptable"))?;
    let who = match processed.sender() {
        Sender::Member(idx) => member_identity(group, *idx, ctx).ok(),
        _ => None,
    };
    // M§6.2: a member leaf whose credential no longer authenticates (delegation revoked or expired)
    let lapsed_leaf = match processed.sender() {
        Sender::Member(idx) if who.is_none() => Some(leaf_device(group, *idx)),
        _ => None,
    };
    let external = matches!(processed.sender(), Sender::NewMemberCommit);
    let from_recorder = who.as_ref().is_some_and(|w| w.is_recorder());
    let (mut sender, sender_device) = who.map(|w| (w.identity, w.device)).unwrap_or_default();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let obj: Value = serde_json::from_slice(&app.into_bytes()).map_err(mls_err("content json"))?;
            if let Some(device) = lapsed_leaf {
                return Ok(Outcome::Unauthenticated(format!("{} from {device}: its delegation no longer verifies", obj["id"])));
            }
            let mut octx = json!({"conversation": conversation, "conversation_kind": kind, "leaf_identity": sender});
            if opts.leaf_device_in_check {
                octx["leaf_device"] = json!(sender_device);
            }
            let verdict = check_object(&obj, &octx);
            if verdict["verdict"] != "accept" {
                return Ok(Outcome::Dropped(format!("{} {}", verdict["code"], obj["id"])));
            }
            if from_recorder && obj["object"] == "content" {
                // C§5: content from a recorder leaf is treated as from an unauthenticated leaf: not rendered, not archived
                return Ok(Outcome::RecorderContent { device: sender_device, id: obj["id"].clone() });
            }
            if opts.keep_call_records && verdict["effective"]["store"] == "call-record" {
                return Ok(Outcome::Object { sender, sender_device, object: obj }); // C§9: kept, never rendered
            }
            if verdict["effective"]["render"] == "ignore" {
                return Ok(Outcome::Nothing); // M§8.1: unknown objects and receipt kinds are ignored
            }
            Ok(Outcome::Object { sender, sender_device, object: obj })
        }
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            let mut joined_externally = vec![];
            if external {
                // M§6.8 (spec-gap 62): every member checks an external join as the hub did, before applying it
                let described = match external_commit(group, &staged, ctx) {
                    Ok(d) => d,
                    Err(e) => return Ok(Outcome::Dropped(format!("external commit: {e}"))),
                };
                let mut roster: Vec<String> = group.members().filter_map(|m| member_identity(group, m.index, ctx).ok()).map(|w| w.identity).collect();
                roster.sort();
                roster.dedup();
                let mut inp = described.clone();
                inp["kind"] = json!(kind);
                inp["owner"] = json!(if kind == "personal" { me } else { "" });
                inp["roster"] = json!(roster);
                let v = dsip_messaging::checks::check_external_join(&inp);
                if v["verdict"] != "accept" {
                    return Ok(Outcome::Dropped(format!("external join refused: {}", v["code"])));
                }
                sender = described["joiner"]["identity"].as_str().unwrap_or("").to_string();
                joined_externally.push(format!("{}#{}", sender, described["joiner"]["device"].as_str().unwrap_or("")));
            }
            let rc = dsip_messaging::checks::check_roster_change(&dsip_mls::roster_change(group, &staged, ctx, &sender));
            if rc["verdict"] != "accept" {
                // M§7.3 (spec-gap 126): every member enforces the roster rules itself; a commit failing them is not merged
                return Ok(Outcome::Dropped(format!("commit refused: {}", rc["code"])));
            }
            let added: Vec<String> = joined_externally
                .into_iter()
                .chain(
                    staged
                        .add_proposals()
                        .filter_map(|a| dsip_mls::authenticate_leaf_node(a.add_proposal().key_package().leaf_node(), ctx).ok())
                        .map(|w| format!("{}#{}", w.identity, w.device)),
                )
                .collect();
            let removed_leaves: Vec<LeafNodeIndex> = staged.remove_proposals().map(|r| r.remove_proposal().removed()).collect();
            let left = left_identities(group, &staged, ctx);
            // A removed leaf may no longer authenticate (a revoked delegation, spec-gap 57): render it by its credential.
            let removed: Vec<String> = removed_leaves
                .iter()
                .map(|i| match member_identity(group, *i, ctx) {
                    Ok(w) => format!("{}#{}", w.identity, w.device),
                    Err(_) => format!("unverified#{}", leaf_device(group, *i)),
                })
                .collect();
            let remaining: Vec<String> = group
                .members()
                .filter(|m| !removed_leaves.contains(&m.index))
                .filter_map(|m| member_identity(group, m.index, ctx).ok())
                .map(|w| w.identity)
                .collect();
            let before = conversation_extension(group);
            let mut hub = None;
            if let Some(update) = conversation_update(before.as_deref(), &staged) {
                // M§6.3, M§7.4 (spec-gap 60): a commit may change the hub and nothing else in dsip_conversation
                if update["verdict"] != "accept" {
                    return Ok(Outcome::Dropped(format!("commit {} dsip_conversation", update["code"])));
                }
                hub = Some(update["effective"]["hub"].clone());
            }
            group.merge_staged_commit(mls.provider(), *staged).map_err(mls_err("merge commit"))?;
            if !group.is_active() {
                return Ok(Outcome::Removed { by: sender, remaining });
            }
            Ok(Outcome::Epoch { epoch: group.epoch().as_u64(), by: sender, added, removed, left, hub })
        }
        ProcessedMessageContent::ProposalMessage(qp) if opts.store_proposals => {
            // M§7.3 "Leaving" (spec-gap 125): stored for the commit that covers it; the decision is the caller's
            group.store_pending_proposal(mls.provider().storage(), *qp).map_err(mls_err("store proposal"))?;
            let leaf = |idx: LeafNodeIndex| member_identity(group, idx, ctx).ok().map(|w| json!({"identity": w.identity, "device": w.device}));
            let (mut removes, mut others) = (vec![], 0);
            for q in group.pending_proposals() {
                let by = match q.sender() {
                    Sender::Member(i) => member_identity(group, *i, ctx).ok().map(|w| w.identity),
                    _ => None,
                };
                if sender.is_empty() || by.as_deref() != Some(sender.as_str()) {
                    continue;
                }
                match q.proposal() {
                    Proposal::Remove(r) => removes.push(leaf(r.removed()).unwrap_or(json!({"identity": "", "device": ""}))),
                    _ => others += 1,
                }
            }
            let roster: Vec<Value> = group.members().filter_map(|m| leaf(m.index)).collect();
            Ok(Outcome::Proposal { proposer: json!({"identity": sender, "device": sender_device}), removes, others, roster })
        }
        _ => Ok(Outcome::Nothing),
    }
}

/// The identities a staged commit removes by their own Remove proposals: a leave (M§7.3 "Leaving"), told apart from a
/// removal by another member when the roster change is rendered.
pub fn left_identities(group: &MlsGroup, staged: &StagedCommit, ctx: &Context) -> Vec<String> {
    let mut out: Vec<String> = staged
        .remove_proposals()
        .filter_map(|q| {
            let removed = member_identity(group, q.remove_proposal().removed(), ctx).ok()?.identity;
            let Sender::Member(by) = q.sender() else { return None };
            (member_identity(group, *by, ctx).ok()?.identity == removed).then_some(removed)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}
