//! Where a service binary's log lines go: the systemd journal, or standard error. Feature `cli`.
//!
//! Spec: none (infrastructure).
//!
//! Impl (service-nodes plan S5): under systemd (`JOURNAL_STREAM` set: standard error is the journal) lines go to
//! journald natively, each with its level as the journal priority (`journalctl -p warning` shows warnings and
//! errors), its target and its source location as fields. Elsewhere they go to standard error, as before. `RUST_LOG`
//! filters either way (default `info`).

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

/// The `--log` choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum LogTo {
    /// journald when standard error is the journal (`JOURNAL_STREAM`), else standard error.
    #[default]
    Auto,
    /// The systemd journal; standard error when it cannot be reached.
    Journald,
    /// Standard error.
    Stderr,
}

/// Install the process's log subscriber; once, before the first line is logged.
pub fn init(to: LogTo) {
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let journal = match to {
        LogTo::Stderr => false,
        LogTo::Journald => true,
        LogTo::Auto => std::env::var_os("JOURNAL_STREAM").is_some(),
    };
    if journal {
        match tracing_journald::layer() {
            Ok(layer) => {
                tracing_subscriber::registry().with(filter()).with(layer).init();
                return;
            }
            Err(e) => {
                tracing_subscriber::fmt().with_env_filter(filter()).init();
                tracing::warn!("journald not reachable ({e}): logging to standard error");
                return;
            }
        }
    }
    tracing_subscriber::fmt().with_env_filter(filter()).init();
}
