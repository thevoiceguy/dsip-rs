//! A service binary's exit on `SIGTERM` or `SIGINT`. Feature `cli`.
//!
//! Spec: none (infrastructure).
//!
//! Impl (service-nodes plan S7): as PID 1 in a container a process that installs no handler ignores `SIGTERM`, so
//! `docker stop` waited out its 10 s and killed it; under systemd the default action ended it at once. Both services
//! write each change as it happens (the relay's queue, the mailbox's database), so leaving at once loses nothing.

/// Exit the process (status 0) on the first `SIGTERM` or `SIGINT`, logging which.
#[cfg(unix)]
pub fn exit_on_terminate() -> std::io::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let (mut term, mut int) = (signal(SignalKind::terminate())?, signal(SignalKind::interrupt())?);
    Ok(tokio::spawn(async move {
        let which = tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = int.recv() => "SIGINT",
        };
        tracing::info!("{which}: exiting");
        std::process::exit(0);
    }))
}
