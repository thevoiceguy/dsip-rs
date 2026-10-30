//! A service binary's `admin` subcommand: `dsip-mailbox admin enrolments`, `dsip-relay admin bindings`, … Each
//! command is a request to the service's own status port ([`crate::status`], `/admin/<command>`), found from
//! `--status <addr>` or from the `status_listen` key of the service's `--config` file. Feature `cli`.
//!
//! Spec: none (infrastructure).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgAction};
use serde_json::Value;

use crate::status;

/// One admin command a service offers.
#[derive(Debug, Clone, Copy)]
pub struct Command {
    /// Its name: the subcommand and the `/admin/<name>` path.
    pub name: &'static str,
    /// One line for `--help`.
    pub about: &'static str,
    /// The positional argument it takes, if any: the query key it is sent as and its name in `--help`.
    pub arg: Option<(&'static str, &'static str)>,
    /// Whether it changes state (sent as a `POST`).
    pub write: bool,
    /// The answer for a reader (without `--json`).
    pub show: fn(&Value) -> String,
}

/// Whether the process was started as `<binary> admin …`.
pub fn invoked() -> bool {
    std::env::args().nth(1).as_deref() == Some("admin")
}

/// Run `<binary> admin …` from the process's arguments: parse them, send the command, print the answer. Exit status
/// 1 when the service refused the command or could not be reached, 2 on a usage error.
pub async fn run(binary: &str, commands: &[Command]) -> ExitCode {
    let mut cli = clap::Command::new("admin")
        .bin_name(format!("{binary} admin"))
        .about(format!("Operate a running {binary} through its status port (--status-listen)"))
        .subcommand_required(true)
        .arg(Arg::new("status").long("status").global(true).value_name("ADDR")
            .help("The service's status address (its --status-listen)"))
        .arg(Arg::new("config").long("config").global(true).value_name("FILE")
            .help("The service's config file: its status_listen is the address"))
        .arg(Arg::new("json").long("json").global(true).action(ArgAction::SetTrue).help("Print the answer as JSON"));
    for c in commands {
        let mut sub = clap::Command::new(c.name).about(c.about);
        if let Some((_, value)) = c.arg {
            sub = sub.arg(Arg::new("value").value_name(value).required(true));
        }
        cli = cli.subcommand(sub);
    }
    let m = cli.get_matches_from(std::env::args().skip(1));
    let (name, sub) = m.subcommand().expect("subcommand_required");
    let command = commands.iter().find(|c| c.name == name).expect("a declared subcommand");
    let addr = match address(m.get_one::<String>("status"), m.get_one::<String>("config").map(PathBuf::from)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{binary} admin: {e}");
            return ExitCode::from(2);
        }
    };
    let mut target = format!("/admin/{}", command.name);
    if let Some((key, _)) = command.arg {
        let v = sub.get_one::<String>("value").expect("a required argument");
        target = format!("{target}?{key}={}", status::encode(v));
    }
    let answer = match status::request(addr, if command.write { "POST" } else { "GET" }, &target).await {
        Ok((200, body)) => serde_json::from_str::<Value>(&body).map_err(|e| format!("{addr}: not JSON ({e}): {body}")),
        Ok((code, body)) => Err(format!("{addr}: HTTP {code}: {}", body.trim())),
        Err(e) => Err(format!("{addr}: {e} (is the service running with --status-listen {addr}?)")),
    };
    match answer {
        Ok(v) if v.get("error").is_some() => {
            eprintln!("{binary} admin {name}: {}", v["error"].as_str().unwrap_or_default());
            ExitCode::from(1)
        }
        Ok(v) => {
            if m.get_flag("json") {
                println!("{v:#}");
            } else {
                print!("{}", (command.show)(&v));
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{binary} admin {name}: {e}");
            ExitCode::from(1)
        }
    }
}

fn address(status: Option<&String>, config: Option<PathBuf>) -> Result<SocketAddr, String> {
    let text = match (status, config) {
        (Some(s), _) => s.clone(),
        (None, Some(path)) => {
            let doc: toml::Table = std::fs::read_to_string(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .parse()
                .map_err(|e| format!("{}: {e}", path.display()))?;
            doc.get("status_listen")
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("{} sets no status_listen: the service has no status port", path.display()))?
                .to_string()
        }
        (None, None) => return Err("give --status <addr> (the service's --status-listen) or --config <file>".into()),
    };
    text.parse().map_err(|e| format!("status address {text:?}: {e}"))
}
