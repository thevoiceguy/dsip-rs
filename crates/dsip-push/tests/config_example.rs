//! `config.example.toml` names only real flags, with values they accept: every key uncommented, the binary parses it
//! (`--help` comes after the file's flags, so each value is checked before help is printed). A misspelt key fails.
//!
//! Spec: none (infrastructure).

use std::process::Command;

fn run(config: &str) -> std::process::Output {
    let path = std::env::temp_dir().join(format!("dsip-push-config-{}-{}.toml", std::process::id(), config.len()));
    std::fs::write(&path, config).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_dsip-push")).arg("--config").arg(&path).arg("--help").output().unwrap();
    let _ = std::fs::remove_file(&path);
    out
}

#[test]
fn every_example_key_is_a_flag_with_a_valid_value() {
    let example = include_str!("../config.example.toml");
    let uncommented: String = example
        .lines()
        .map(|l| match l.strip_prefix("# ") {
            Some(rest) if rest.split_once(" = ").is_some_and(|(k, _)| !k.is_empty() && k.chars().all(|c| c.is_ascii_lowercase() || c == '_')) => rest,
            _ => l,
        })
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(uncommented.lines().filter(|l| l.contains(" = ")).count() > 8, "the example's keys were found");
    let out = run(&uncommented);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn a_misspelt_key_is_refused() {
    let out = run("per_handel = 3\n");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown key `per_handel`"));
}
