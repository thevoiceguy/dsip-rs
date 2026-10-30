//! Where a service binary's log lines go: the systemd journal, or standard error. Feature `cli`.
//!
//! Spec: none (infrastructure).
//!
//! Impl (service-nodes plan S5): under systemd, when standard error is the journal, lines go to journald natively, each with its level as the journal priority (`journalctl -p warning` shows warnings and
//! errors), its target and its source location as fields. Elsewhere they go to standard error, as before. `RUST_LOG`
//! filters either way (default `info`).

use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::EnvFilter;

/// The `--log` choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum LogTo {
    /// journald when standard error is the journal, else standard error.
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
        LogTo::Auto => stderr_is_journal(),
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

/// Whether standard error is the journal: `JOURNAL_STREAM` (`<device>:<inode>`) names the stream systemd connected,
/// and it is inherited by children whose standard error goes elsewhere (a CI runner's steps, a redirect to a file),
/// so the stream is compared with standard error itself, as systemd.exec(5) says.
fn stderr_is_journal() -> bool {
    let Some(v) = std::env::var_os("JOURNAL_STREAM") else { return false };
    let Some((dev, ino)) = v.to_str().and_then(|s| s.split_once(':')) else { return false };
    #[cfg(unix)]
    {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::MetadataExt as _;
        let Ok(fd) = std::io::stderr().as_fd().try_clone_to_owned() else { return false };
        let Ok(m) = std::fs::File::from(fd).metadata() else { return false };
        dev.parse() == Ok(m.dev()) && ino.parse() == Ok(m.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = (dev, ino);
        false
    }
}
