//! The typed values that cross the browser boundary (dsip-rs B1, `impl/docs/dsip-stack-design.md` §6): what the
//! page passes in and gets back as JavaScript objects, with TypeScript declarations generated from these types and
//! from the library types they carry (`tsify`, `Ts<T>` on every parameter and return).
//!
//! Spec: none (infrastructure).
//!
//! Impl: the engine's `Emission` keeps the vectors' JSON shape (`impl/vectors/README.md`, kind `state`), which is
//! flattened per kind and cannot be derived; its declaration below is written by hand, and `web/test/types`
//! checks it with `tsc` against every emission in the state vectors.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tsify::Tsify;
use wasm_bindgen::prelude::*;

use dsip_endpoint::{CallOut, Command, InvitePatch};
use dsip_session::LocalEvent;

#[wasm_bindgen(typescript_custom_section)]
const EMISSION: &'static str = r#"
/** An engine emission, in the vectors' shape (README, kind `state`). Tokens a registry governs are `string`. */
export type Emission =
    | { send: SendEmission }
    | { timer: "start"; name: TimerName; seconds: number }
    | { timer: "stop" | "fire"; name: TimerName }
    | { media: "start" | "stop" | "apply_update" }
    | UiEmission
    | { queue: { to: string; type: string } }
    | { info: { about: string } }
    | { refused: "invalid-state" | "unknown-session" | "unknown-introduction" | "invalid-audience" | "unknown-grant" | "update-pending" | "no-pending-update" }
    | { revoke: string[] }
    | { keys: "rotated" | "seen"; scope: string; epoch: number }
    | { drop: "ended-session" | "duplicate-introduction" | "unknown-introduction" | "stale-update-reply" | "unknown-about" | "leg-terminated" | "not-attempt-scoped" }
    | { deliver: { leg: string; type: string; reason?: string; id?: string } }
    | { dequeue: { to: string; type: string; why: "expired" | "cancelled" } }
    | { forward: { type: string; status?: string; reason?: string; from: string } };

/** The §12.9 timers. */
export type TimerName = "T-Establish" | "T-Ring" | "T-Queue" | "T-Ring-Local";

/** A message the engine sends: its type, addressee and the fields its transitions set. */
export interface SendEmission {
    type: string;
    to: string;
    session?: string;
    id?: string;
    reason?: string;
    status?: string;
    ring_timeout?: number;
    answered_by?: string;
    in_reply_to?: string;
    grant?: string;
    scope?: string[];
    valid_until?: number;
    purpose?: string;
    contact_token?: string;
    presence_audience?: string;
    presence_keys?: unknown;
}

/** What the application shows. */
export type UiEmission =
    | { ui: "progress"; status: string }
    | { ui: "answered"; answered_by: string }
    | { ui: "offered" | "update_offered" | "missed_call" | "glare_retry" }
    | { ui: "update_rejected" | "ended" | "error" | "introduction_rejected"; reason: string }
    | { ui: "introduction_received"; from: string; token?: true }
    | { ui: "granted"; by: string };
"#;

/// What a call-path method returns: the call glue's outputs, in order.
#[derive(Serialize, Tsify)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct CallOuts(pub Vec<CallOut>);

/// What [`crate::Endpoint::place`] returns: the session id at once, and the first outputs (the request for the SDP
/// offer; the invite goes out when the page hands it back).
#[derive(Serialize, Tsify)]
#[tsify(hashmap_as_object, missing_as_null)]
pub struct Placed {
    /// The session (= invite) id.
    pub session: String,
    /// The outputs.
    pub events: Vec<CallOut>,
}

/// A local event (README vocabulary), with what the host supplies for its message beside it.
#[derive(Deserialize, Tsify)]
// tsify writes a flattened union as `interface … extends`, which TypeScript refuses
#[tsify(type = "LocalEvent & { sdp?: string; claims?: unknown[]; patch?: InvitePatch; data?: unknown }")]
pub struct LocalCommand {
    /// The engine event.
    #[serde(flatten)]
    pub event: LocalEvent,
    /// The SDP (`place_call`, `accept`, `update`, `answer_update`).
    #[serde(default)]
    #[tsify(optional)]
    pub sdp: Option<String>,
    /// `identity.claims` (`place_call`, §18.1).
    #[serde(default)]
    #[tsify(type = "unknown[]", optional)]
    pub claims: Vec<Value>,
    /// Changes to the offer (`place_call`: C§6, N§4.1).
    #[serde(default)]
    #[tsify(optional)]
    pub patch: Option<InvitePatch>,
    /// The `info` data (B§4); without it, an empty `info`.
    #[serde(default)]
    #[tsify(type = "unknown", optional)]
    pub data: Option<Value>,
}

impl LocalCommand {
    /// As the core's [`Command`].
    pub fn into_command(self) -> Command {
        let LocalCommand { event, sdp, claims, patch, data } = self;
        match event {
            LocalEvent::PlaceCall { session, to } => {
                Command::PlaceCall { session, to, invite: dsip_endpoint::Invite { sdp, claims, patch: patch.unwrap_or_default() } }
            }
            LocalEvent::Accept { session, answered_by } => Command::Accept { session, answered_by, sdp },
            LocalEvent::Update { session, id, answered_by } => Command::Update { session, id, answered_by, sdp },
            LocalEvent::AnswerUpdate { session, in_reply_to, answered_by } => Command::AnswerUpdate { session, in_reply_to, answered_by, sdp },
            LocalEvent::Info { session } => match data {
                Some(data) => Command::Info { session, data },
                None => Command::Engine(LocalEvent::Info { session }),
            },
            other => Command::Engine(other),
        }
    }
}
