//! `cargo test` runs the full conformance suite through the `dsip` binary.
//!
//! Spec: none (infrastructure) — the suite itself carries the citations.

use std::process::Command;

#[test]
fn conformance_vectors_all_pass() {
    let out = Command::new(env!("CARGO_BIN_EXE_dsip")).args(["vectors", "run"]).output().expect("run dsip");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "vector suite failed:\n{stdout}");
    assert!(stdout.contains(", 0 failures"), "{stdout}");
}
