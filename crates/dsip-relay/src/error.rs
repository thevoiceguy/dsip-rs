//! The errors a relay connection or listener ends with. Each names what failed, so `{e}` alone is a complete log
//! line.
//!
//! Spec: none (infrastructure)

/// Why a connection or the listener ended.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The WebSocket failed.
    #[error("websocket: {0}")]
    Ws(Box<tokio_tungstenite::tungstenite::Error>),
    /// Accepting a connection failed.
    #[error("accept: {0}")]
    Io(#[from] std::io::Error),
    /// The connection closed, or sent a non-text frame, before its `hello` (§13.2).
    #[error("no hello")]
    NoHello,
    /// No `hello` within this many seconds (§13.2).
    #[error("no hello within {0} s")]
    HelloTimeout(u64),
    /// The first envelope verified but was not a client `hello` (§13.2: refused `transport.hello-required`).
    #[error("first envelope was {0} not a client hello")]
    NotHello(String),
    /// The `hello` did not verify (closed `transport.hello-rejected`).
    #[error("hello rejected: {code} {detail}")]
    HelloRejected {
        /// The verdict's code token, as the vectors spell it.
        code: String,
        /// The verdict's detail.
        detail: String,
    },
}

impl From<tokio_tungstenite::tungstenite::Error> for Error {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Error {
        Error::Ws(Box::new(e))
    }
}

/// A relay result.
pub type Result<T> = std::result::Result<T, Error>;
