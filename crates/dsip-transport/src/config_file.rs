//! A service's TOML config file, read as flags: `--config <file>` names a file whose every key is one of the
//! binary's long flags, written in `snake_case` (`intro_limit = 5` is `--intro-limit 5`). The file's keys go before
//! the command line, so a flag given there wins; a repeatable flag given there replaces the file's list rather than
//! adding to it. An unknown key is an error, so a misspelt one is never silently ignored. Feature `cli`.
//!
//! Spec: none (infrastructure).
//!
//! Values: a string or a number is the flag's value; an array repeats the flag once per element; `true` on a switch
//! (`--release-idle`) sets it and `false` leaves it unset. Paths are taken as written, so a file read by a systemd
//! unit should use absolute ones.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Command};

/// Why a config file could not be turned into flags.
#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    /// The file could not be read.
    #[error("config file {0}: {1}")]
    Read(PathBuf, std::io::Error),
    /// The file is not valid TOML.
    #[error("config file {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    /// A key names no flag of this binary.
    #[error("config file {0}: unknown key `{1}` (each key is a flag of `{2} --help`, in snake_case)")]
    UnknownKey(PathBuf, String, String),
    /// A key's value has a shape its flag cannot take.
    #[error("config file {0}: key `{1}`: {2}")]
    Value(PathBuf, String, String),
    /// `--config` was given without a path.
    #[error("--config needs a file")]
    MissingPath,
}

/// Parse `T` from the process's arguments, with the keys of its `--config` file (if any) before them. `T` declares
/// `--config` itself, so that `--help` lists it. On a config file error, prints it and exits with status 2, as clap
/// does for a bad flag.
pub fn parse<T: clap::Parser>() -> T {
    match with_config_file(&T::command(), std::env::args_os().collect()) {
        Ok(argv) => T::parse_from(argv),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2)
        }
    }
}

/// `argv` with the flags of its `--config` file inserted after the program name. Without `--config`, `argv` as given.
pub fn with_config_file(cmd: &Command, argv: Vec<OsString>) -> Result<Vec<OsString>, ConfigFileError> {
    let Some(path) = config_path(&argv)? else { return Ok(argv) };
    let text = std::fs::read_to_string(&path).map_err(|e| ConfigFileError::Read(path.clone(), e))?;
    let table: toml::Table = text.parse().map_err(|e| ConfigFileError::Parse(path.clone(), e))?;
    let mut flags = vec![];
    for (key, value) in &table {
        let long = key.replace('_', "-");
        let arg = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some(long.as_str()) && long != "config")
            .ok_or_else(|| ConfigFileError::UnknownKey(path.clone(), key.clone(), cmd.get_name().to_string()))?;
        if on_command_line(&argv, &long) {
            continue;
        }
        let switch = matches!(arg.get_action(), ArgAction::SetTrue);
        let bad = |why: &str| ConfigFileError::Value(path.clone(), key.clone(), why.to_string());
        let values = match value {
            toml::Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        if values.len() > 1 && !matches!(arg.get_action(), ArgAction::Append) {
            return Err(bad("a list, for a flag that takes one value"));
        }
        for v in values {
            match (v, switch) {
                (toml::Value::Boolean(true), true) => flags.push(OsString::from(format!("--{long}"))),
                (toml::Value::Boolean(false), true) => {}
                (_, true) => return Err(bad("a switch takes true or false")),
                (toml::Value::String(s), false) => flags.push(OsString::from(format!("--{long}={s}"))),
                (toml::Value::Integer(n), false) => flags.push(OsString::from(format!("--{long}={n}"))),
                (toml::Value::Float(x), false) => flags.push(OsString::from(format!("--{long}={x}"))),
                (toml::Value::Boolean(b), false) => flags.push(OsString::from(format!("--{long}={b}"))),
                _ => return Err(bad("expected a string, a number, a boolean or a list of them")),
            }
        }
    }
    let mut out = Vec::with_capacity(argv.len() + flags.len());
    let mut rest = argv.into_iter();
    out.extend(rest.next());
    out.extend(flags);
    out.extend(rest);
    Ok(out)
}

/// The path after `--config` (or in `--config=<path>`), looked for before any `--`.
fn config_path(argv: &[OsString]) -> Result<Option<PathBuf>, ConfigFileError> {
    let mut it = argv.iter().skip(1);
    while let Some(a) = it.next() {
        let a = a.to_string_lossy();
        if a == "--" {
            break;
        }
        if a == "--config" {
            return it.next().map(|p| Some(PathBuf::from(p))).ok_or(ConfigFileError::MissingPath);
        }
        if let Some(p) = a.strip_prefix("--config=") {
            return Ok(Some(Path::new(p).to_path_buf()));
        }
    }
    Ok(None)
}

/// Whether `--<long>` is given on the command line itself.
fn on_command_line(argv: &[OsString], long: &str) -> bool {
    let flag = format!("--{long}");
    let with_value = format!("--{long}=");
    argv.iter().skip(1).map(|a| a.to_string_lossy()).take_while(|a| a != "--").any(|a| a == flag || a.starts_with(&with_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Parser, Debug)]
    #[command(name = "svc")]
    struct Args {
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        state: PathBuf,
        #[arg(long, default_value_t = 5)]
        intro_limit: usize,
        #[arg(long = "owner")]
        owners: Vec<String>,
        #[arg(long)]
        release_idle: bool,
    }

    fn parse(file: &str, flags: &[&str]) -> Result<Args, ConfigFileError> {
        let dir = std::env::temp_dir().join(format!("dsip-config-file-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("svc.toml");
        std::fs::write(&path, file).unwrap();
        let mut argv: Vec<OsString> = vec!["svc".into(), "--config".into(), path.clone().into()];
        argv.extend(flags.iter().map(OsString::from));
        let out = with_config_file(&Args::command(), argv).map(|a| Args::try_parse_from(a).expect("parses"));
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    #[test]
    fn keys_are_flags_and_flags_win() {
        let a = parse("state = \"/var/lib/svc\"\nintro_limit = 9\nowner = [\"did:a\", \"did:b\"]\nrelease_idle = true\n", &[]).unwrap();
        assert_eq!(a.state, PathBuf::from("/var/lib/svc"));
        assert_eq!(a.intro_limit, 9);
        assert_eq!(a.owners, ["did:a", "did:b"]);
        assert!(a.release_idle);
        let b = parse("state = \"/s\"\nintro_limit = 9\nowner = [\"did:a\", \"did:b\"]\n", &["--intro-limit", "2", "--owner=did:c"]).unwrap();
        assert_eq!(b.intro_limit, 2);
        assert_eq!(b.owners, ["did:c"], "a list on the command line replaces the file's");
        let c = parse("state = \"/s\"\nrelease_idle = false\n", &[]).unwrap();
        assert!(!c.release_idle);
        assert_eq!(c.intro_limit, 5, "an absent key keeps the default");
    }

    #[test]
    fn unknown_keys_and_bad_shapes_are_errors() {
        assert!(matches!(parse("state = \"/s\"\nintro_limt = 3\n", &[]), Err(ConfigFileError::UnknownKey(_, k, _)) if k == "intro_limt"));
        assert!(matches!(parse("config = \"/x\"\n", &[]), Err(ConfigFileError::UnknownKey(..))));
        assert!(matches!(parse("state = [\"/a\", \"/b\"]\n", &[]), Err(ConfigFileError::Value(..))));
        assert!(matches!(parse("state = \"/s\"\nrelease_idle = \"yes\"\n", &[]), Err(ConfigFileError::Value(..))));
        assert!(matches!(parse("state = \"/s\"\n[section]\nx = 1\n", &[]), Err(ConfigFileError::UnknownKey(..))));
        assert!(matches!(parse("not toml", &[]), Err(ConfigFileError::Parse(..))));
    }

    #[test]
    fn without_config_argv_is_unchanged() {
        let argv: Vec<OsString> = vec!["svc".into(), "--state".into(), "/s".into()];
        assert_eq!(with_config_file(&Args::command(), argv.clone()).unwrap(), argv);
    }
}
