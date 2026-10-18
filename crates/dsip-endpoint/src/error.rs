//! The errors [`crate::Core`] returns. A refused frame is not an error: it comes back as
//! [`crate::CoreEvent::Rejected`]. An error means the core could not do what the host asked.
//!
//! Spec: none (infrastructure)

/// Why a [`crate::Core`] call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A verified payload could not be read as a [`dsip_session::Message`].
    #[error("payload shape: {0}")]
    PayloadShape(&'static str),
    /// The engine asked the core to send a message type the core cannot build.
    #[error("engine asked to send unsupported type {0}")]
    UnsupportedType(String),
    /// A payload could not be serialized.
    #[error("serializing payload: {0}")]
    Json(#[from] serde_json::Error),
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
