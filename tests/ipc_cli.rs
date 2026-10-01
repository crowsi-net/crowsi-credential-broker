use std::{fs, process::Command};

#[test]
fn bare_cargo_run_selects_the_fail_closed_production_cli() {
    let manifest =
        fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).expect("manifest");
    assert!(manifest.contains("default-run = \"crowsi-credential\""));
}

#[test]
fn standalone_cli_never_bypasses_authenticated_ipc() {
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-credential"))
        .args(["put", "/not/used/request.json"])
        .output()
        .expect("run fail-closed CLI");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).expect("UTF-8 error");
    assert!(error.contains("authenticated-ipc-adapter-required"));
    assert!(!error.contains("TEST-ONLY-GITHUB-PRIVATE-KEY-MARKER"));
}

#[test]
fn sample_ready_status_requires_the_explicit_demo_binary() {
    let output = Command::new(env!("CARGO_BIN_EXE_crowsi-credential-demo"))
        .output()
        .expect("run explicit demo");
    assert!(output.status.success());
    let document = String::from_utf8(output.stdout).expect("UTF-8 sample");
    assert!(document.contains("\"status\": \"ready\""));
    assert!(document.contains("\"tenant\": \"sample\""));
    assert!(document.contains("\"contains_secret_values\": false"));
}
