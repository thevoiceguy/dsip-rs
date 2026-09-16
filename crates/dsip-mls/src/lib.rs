//! `dsip-mls` — the DSIP Messaging Profile 1.0 (v0.8 draft, cited `M§n`) on real MLS (RFC 9420)
//! via OpenMLS.
//!
//! Spec: sections owned by this crate — M§6.1 (mandatory ciphersuite
//! `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`), M§6.2 (the leaf credential is a basic credential
//! naming the device DID, the leaf signature key *is* the device's DSIP Ed25519 key —
//! [`DeviceSigner`] — and `dsip_delegation` carries its delegation; leaves are authenticated by
//! [`authenticate_leaf_node`]), M§6.3 (`dsip_conversation` in the GroupContext, required by
//! `RequiredCapabilities`), M§6.4 (handshake messages as PublicMessage, application messages as
//! PrivateMessage), M§6.5 (the hub validates commits against the public group state without group
//! secrets — [`HubView`]), M§11.1 (the activity key is `MLS-Exporter("dsip activity", group_id, 32)`
//! — [`activity_key`]).
//!
//! Impl: the protocol rules themselves (extension encoding, the authentication service, the hub and
//! mailbox state machines, AES-GCM formats) live in `dsip-messaging` and are pinned by
//! `impl/vectors/messaging/`; this crate binds them to OpenMLS objects and is exercised end to end by
//! `tests/e2e.rs`. OpenMLS 0.9 needs Rust 1.91, so this crate carries its own `rust-version`.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use dsip_core::envelope::Context;
use dsip_core::keys::KeyPair;
use dsip_messaging::mls_wire::{authenticate_leaf, LeafIdentity, EXT_DSIP_CONVERSATION, EXT_DSIP_DELEGATION};

/// The mandatory-to-implement ciphersuite.
///
/// Spec: M§6.1.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Exporter label for the per-epoch activity key.
///
/// Spec: M§11.1.
pub const ACTIVITY_EXPORTER_LABEL: &str = "dsip activity";

/// An error from the MLS layer, carried as text.
///
/// Spec: none (infrastructure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlsError(pub String);

impl std::fmt::Display for MlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MlsError {}

fn err<E: std::fmt::Debug>(what: &str) -> impl FnOnce(E) -> MlsError + '_ {
    move |e| MlsError(format!("{what}: {e:?}"))
}

/// A DSIP device key used directly as the MLS leaf signer.
///
/// Spec: M§6.2 — the leaf `signature_key` MUST be the device's Ed25519 key; MLS's labelled signatures
/// provide the domain separation from DSIP-JOSE signatures by the same key.
pub struct DeviceSigner<'a>(pub &'a KeyPair);

impl Signer for DeviceSigner<'_> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

/// Leaf capabilities advertising the DSIP extensions and the basic credential.
///
/// Spec: M§6.1, M§6.2, M§6.3.
pub fn capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[ExtensionType::Unknown(EXT_DSIP_DELEGATION), ExtensionType::Unknown(EXT_DSIP_CONVERSATION)]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// One messaging device: its DSIP key, its compact `dsip.messaging` delegation, and its MLS provider.
///
/// Spec: M§6.2, M§6.7.
pub struct Device {
    key: KeyPair,
    delegation: String,
    provider: OpenMlsRustCrypto,
}

impl Device {
    /// A device from its key and the compact delegation envelope that authorizes it.
    pub fn new(key: KeyPair, delegation_compact: String) -> Device {
        Device { key, delegation: delegation_compact, provider: OpenMlsRustCrypto::default() }
    }

    /// The device DID (the credential identity).
    pub fn did(&self) -> String {
        self.key.did()
    }

    /// The MLS provider (crypto and storage) of this device.
    pub fn provider(&self) -> &OpenMlsRustCrypto {
        &self.provider
    }

    /// The MLS signer: the device key itself.
    pub fn signer(&self) -> DeviceSigner<'_> {
        DeviceSigner(&self.key)
    }

    fn credential_with_key(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.did().into_bytes()).into(),
            signature_key: self.key.public().to_vec().into(),
        }
    }

    fn leaf_extensions(&self) -> Result<Extensions<LeafNode>, MlsError> {
        Extensions::single(Extension::Unknown(EXT_DSIP_DELEGATION, UnknownExtension(self.delegation.clone().into_bytes())))
            .map_err(err("leaf extensions"))
    }

    /// A fresh KeyPackage for upload to the mailbox (M§5.5), TLS-serialized.
    pub fn key_package(&self) -> Result<Vec<u8>, MlsError> {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .leaf_node_extensions(self.leaf_extensions()?)
            .build(CIPHERSUITE, &self.provider, &self.signer(), self.credential_with_key())
            .map_err(err("key package"))?;
        bundle.key_package().tls_serialize_detached().map_err(err("serialize key package"))
    }

    /// Create a group whose GroupContext carries `dsip_conversation` and requires the DSIP extensions.
    ///
    /// Spec: M§6.3, M§6.4 (handshake as PublicMessage), M§7.2.
    pub fn create_group(&self, group_id: &[u8], conversation_json: &[u8]) -> Result<MlsGroup, MlsError> {
        let required = RequiredCapabilitiesExtension::new(
            &[ExtensionType::Unknown(EXT_DSIP_DELEGATION), ExtensionType::Unknown(EXT_DSIP_CONVERSATION)],
            &[],
            &[CredentialType::Basic],
        );
        let gc = Extensions::from_vec(vec![
            Extension::RequiredCapabilities(required),
            Extension::Unknown(EXT_DSIP_CONVERSATION, UnknownExtension(conversation_json.to_vec())),
        ])
        .map_err(err("group context extensions"))?;
        MlsGroup::builder()
            .with_group_id(GroupId::from_slice(group_id))
            .ciphersuite(CIPHERSUITE)
            .with_wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .with_capabilities(capabilities())
            .with_leaf_node_extensions(self.leaf_extensions()?)
            .map_err(err("leaf node extensions"))?
            .with_group_context_extensions(gc)
            .build(&self.provider, &self.signer(), self.credential_with_key())
            .map_err(err("create group"))
    }

    /// Join a group from a TLS-serialized Welcome message.
    ///
    /// Spec: M§6.6, M§6.7. The caller authenticates every member afterwards ([`authenticate_members`]).
    pub fn join(&self, welcome: &[u8]) -> Result<MlsGroup, MlsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut &welcome[..]).map_err(err("welcome bytes"))?;
        let MlsMessageBodyIn::Welcome(w) = msg.extract() else { return Err(MlsError("not a welcome".into())) };
        let config = MlsGroupJoinConfig::builder()
            .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .build();
        StagedWelcome::new_from_welcome(&self.provider, &config, w, None)
            .map_err(err("stage welcome"))?
            .into_group(&self.provider)
            .map_err(err("join"))
    }
}

/// Authenticate one leaf node with the DSIP authentication service.
///
/// Spec: M§6.2.
pub fn authenticate_leaf_node(leaf: &LeafNode, ctx: &Context) -> Result<LeafIdentity, &'static str> {
    let cred = leaf.credential();
    let identity = BasicCredential::try_from(cred.clone()).map(|b| b.identity().to_vec()).unwrap_or_default();
    let exts: Vec<(u16, Vec<u8>)> = leaf
        .extensions()
        .iter()
        .filter_map(|e| match e {
            Extension::Unknown(t, UnknownExtension(d)) => Some((*t, d.clone())),
            _ => None,
        })
        .collect();
    authenticate_leaf(u16::from(cred.credential_type()), &identity, leaf.signature_key().as_slice(), &exts, ctx)
}

/// Validate a serialized KeyPackage and authenticate its leaf before adding it (M§5.5, M§6.2).
pub fn authenticate_key_package(bytes: &[u8], provider: &OpenMlsRustCrypto, ctx: &Context) -> Result<(KeyPackage, LeafIdentity), MlsError> {
    let kp_in = KeyPackageIn::tls_deserialize(&mut &bytes[..]).map_err(err("key package bytes"))?;
    let kp = kp_in.validate(provider.crypto(), ProtocolVersion::Mls10).map_err(err("key package"))?;
    let who = authenticate_leaf_node(kp.leaf_node(), ctx).map_err(|c| MlsError(format!("leaf authentication: {c}")))?;
    Ok((kp, who))
}

/// Authenticate every member of a group; the first failure is returned with its leaf index.
///
/// Spec: M§6.2 — every member MUST validate credentials when they enter the group.
pub fn authenticate_members(group: &MlsGroup, ctx: &Context) -> Result<Vec<LeafIdentity>, MlsError> {
    group
        .members()
        .map(|m| {
            let leaf = group.public_group().leaf(m.index).ok_or_else(|| MlsError(format!("no leaf {}", m.index.u32())))?;
            authenticate_leaf_node(leaf, ctx).map_err(|c| MlsError(format!("leaf {}: {c}", m.index.u32())))
        })
        .collect()
}

/// The identity of the member at a leaf index, authenticated (M§8.1: `content.sender` must equal it).
pub fn member_identity(group: &MlsGroup, index: LeafNodeIndex, ctx: &Context) -> Result<LeafIdentity, MlsError> {
    let leaf = group.public_group().leaf(index).ok_or_else(|| MlsError("unknown sender leaf".into()))?;
    authenticate_leaf_node(leaf, ctx).map_err(|c| MlsError(format!("sender leaf: {c}")))
}

/// The `dsip_conversation` extension bytes of a group, if present.
///
/// Spec: M§6.3.
pub fn conversation_extension(group: &MlsGroup) -> Option<Vec<u8>> {
    group.extensions().unknown(EXT_DSIP_CONVERSATION).map(|u| u.0.clone())
}

/// The per-epoch activity key.
///
/// Spec: M§11.1 — `MLS-Exporter("dsip activity", group_id, 32)`.
pub fn activity_key(group: &MlsGroup, provider: &OpenMlsRustCrypto) -> Result<[u8; 32], MlsError> {
    let k = group
        .export_secret(provider.crypto(), ACTIVITY_EXPORTER_LABEL, group.group_id().as_slice(), 32)
        .map_err(err("export activity key"))?;
    k.try_into().map_err(|_| MlsError("exporter length".into()))
}

/// Epoch and group id read from a serialized MLS protocol message's cleartext header — what a hub
/// observes on any deposit (M§6.5).
pub fn message_header(bytes: &[u8]) -> Result<(Vec<u8>, u64, bool), MlsError> {
    let msg = MlsMessageIn::tls_deserialize(&mut &bytes[..]).map_err(err("message bytes"))?;
    let pm = msg.try_into_protocol_message().map_err(err("protocol message"))?;
    let handshake = matches!(pm, ProtocolMessage::PublicMessage(_));
    Ok((pm.group_id().as_slice().to_vec(), pm.epoch().as_u64(), handshake))
}

/// SHA-256 hex of MLS bytes: the digest the hub uses for idempotent re-deposit (M§9.3).
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The hub's public view of one group: validates commits without any group secret.
///
/// Spec: M§6.5 — the hub tracks the epoch and public tree from accepted commits and validates each
/// commit (framing signature by a member leaf, credentials per M§6.2) before sequencing it.
pub struct HubView {
    group: PublicGroup,
    provider: OpenMlsRustCrypto,
}

impl HubView {
    /// Start tracking a group from a GroupInfo that carries the ratchet tree extension.
    pub fn from_group_info(group_info: &[u8]) -> Result<HubView, MlsError> {
        let provider = OpenMlsRustCrypto::default();
        let msg = MlsMessageIn::tls_deserialize(&mut &group_info[..]).map_err(err("group info bytes"))?;
        let MlsMessageBodyIn::GroupInfo(gi) = msg.extract() else { return Err(MlsError("not a group info".into())) };
        let tree = gi
            .extensions()
            .ratchet_tree()
            .map(|t| t.ratchet_tree().clone())
            .ok_or_else(|| MlsError("group info without ratchet tree".into()))?;
        let (group, _) = PublicGroup::from_external(provider.crypto(), provider.storage(), tree, gi, ProposalStore::new())
            .map_err(err("public group"))?;
        Ok(HubView { group, provider })
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }

    /// Validate a commit and describe it as the hub state machine's `deposit.commit` (M§6.5, M§7.3):
    /// `{adds: [{identity, device}], removes: [{identity, device, delegation_valid}], valid, external}`.
    /// A commit that fails MLS validation or leaf authentication is `valid: false`; a valid one is merged.
    pub fn observe_commit(&mut self, bytes: &[u8], ctx: &Context) -> Result<Value, MlsError> {
        let msg = MlsMessageIn::tls_deserialize(&mut &bytes[..]).map_err(err("commit bytes"))?;
        let pm = msg.try_into_protocol_message().map_err(err("protocol message"))?;
        let processed = match self.group.process_message(self.provider.crypto(), pm) {
            Ok(p) => p,
            Err(_) => return Ok(json!({"adds": [], "removes": [], "valid": false})),
        };
        let external = !matches!(processed.sender(), Sender::Member(_));
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(MlsError("not a commit".into()));
        };
        let mut adds = vec![];
        for add in staged.add_proposals() {
            match authenticate_leaf_node(add.add_proposal().key_package().leaf_node(), ctx) {
                Ok(who) => adds.push(json!({"identity": who.identity, "device": who.device})),
                Err(_) => return Ok(json!({"adds": [], "removes": [], "valid": false})),
            }
        }
        let mut removes = vec![];
        for rm in staged.remove_proposals() {
            let index = rm.remove_proposal().removed();
            let Some(leaf) = self.group.leaf(index) else { continue };
            let identity = BasicCredential::try_from(leaf.credential().clone()).map(|b| b.identity().to_vec()).unwrap_or_default();
            match authenticate_leaf_node(leaf, ctx) {
                Ok(who) => removes.push(json!({"identity": who.identity, "device": who.device})),
                Err(_) => removes.push(json!({"identity": "", "device": String::from_utf8_lossy(&identity), "delegation_valid": false})),
            }
        }
        self.group.merge_commit(self.provider.storage(), *staged).map_err(err("merge commit"))?;
        Ok(json!({"adds": adds, "removes": removes, "valid": true, "external": external}))
    }
}
