//! The errors the daemon half returns. Each message names what failed and includes its cause.
//!
//! Impl: siphon-rs and forge-media each return several error types; they are carried as their text, labelled with
//! the step that failed, so one variant covers each library.
//!
//! Spec: none (infrastructure)

use std::path::PathBuf;

/// Why a gateway leg or host call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The DSIP agent failed.
    #[error(transparent)]
    Agent(#[from] dsip_transport::Error),
    /// A SIP message could not be built or parsed (siphon-rs).
    #[error("sip {what}: {detail}")]
    Sip {
        /// The step that failed.
        what: &'static str,
        /// siphon-rs's message.
        detail: String,
    },
    /// The WebRTC leg failed (forge-media).
    #[error("webrtc {what}: {detail}")]
    WebRtc {
        /// The step that failed.
        what: &'static str,
        /// forge-media's message.
        detail: String,
    },
    /// A SIP call id this leg does not hold.
    #[error("unknown call {0}")]
    UnknownCall(String),
    /// An in-dialog request before the dialog exists.
    #[error("no dialog yet for {0}")]
    NoDialog(&'static str),
    /// A SIP target that is not `ip:port` (round one routes no DNS).
    #[error("sip target {0} must be ip:port in round one")]
    SipTarget(String),
    /// Binding a socket failed.
    #[error("bind {what} {addr}: {source}")]
    Bind {
        /// Which socket.
        what: &'static str,
        /// The address.
        addr: String,
        /// The I/O failure.
        source: std::io::Error,
    },
    /// A configuration value that does not parse.
    #[error("config: {0}")]
    Config(String),
    /// Reading a file failed.
    #[error("{}: {source}", path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The I/O failure.
        source: std::io::Error,
    },
    /// Any other I/O failure (sockets).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON that does not parse.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The HTTP client could not be built.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

/// `Result` with [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Label a siphon-rs failure: `SipUri::parse(s).sip("target uri")?`.
pub(crate) trait Sip<T> {
    fn sip(self, what: &'static str) -> Result<T>;
}

impl<T, E: std::fmt::Display> Sip<T> for std::result::Result<T, E> {
    fn sip(self, what: &'static str) -> Result<T> {
        self.map_err(|e| Error::Sip { what, detail: e.to_string() })
    }
}

/// Label a forge-media failure: `pc.create_offer().await.webrtc("offer")?`.
pub(crate) trait WebRtc<T> {
    fn webrtc(self, what: &'static str) -> Result<T>;
}

impl<T, E: std::fmt::Display> WebRtc<T> for std::result::Result<T, E> {
    fn webrtc(self, what: &'static str) -> Result<T> {
        self.map_err(|e| Error::WebRtc { what, detail: e.to_string() })
    }
}
