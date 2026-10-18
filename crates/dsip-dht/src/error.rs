//! The errors a running node returns.
//!
//! Spec: none (infrastructure)

/// Why a node call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The node's event loop has stopped.
    #[error("node stopped")]
    Stopped,
    /// A publish of a hint that does not verify (§8.3): the node never stores what it would refuse from a peer.
    #[error("refusing to publish an unverifiable hint: {0}")]
    Unverifiable(String),
    /// A publish superseded by a newer record already held (§8.3).
    #[error("refusing to publish: superseded by a record already held ({0})")]
    Superseded(String),
    /// A control request naming no known operation.
    #[error("unknown op {0}")]
    UnknownOp(String),
    /// The record store failed.
    #[error("record store {at}: {detail}")]
    Store {
        /// The store's path, or `(memory)`.
        at: String,
        /// redb's message.
        detail: String,
    },
    /// Listening on an address failed.
    #[error("listen on {addr}: {source}")]
    Listen {
        /// The address.
        addr: String,
        /// libp2p's error.
        source: libp2p::TransportError<std::io::Error>,
    },
    /// The swarm could not be built.
    #[error("swarm: {0}")]
    Swarm(String),
    /// A socket failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
