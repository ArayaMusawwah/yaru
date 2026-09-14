use crate::cli::output;
use crate::config;
use crate::core::aur::AurClient;
use crate::core::types::{ScoreBreakdown, TrustZone};
use crate::storage::{Database, DecisionRecord};
use anyhow::{Context, Result, anyhow};
use colored::Colorize;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::cli::Cli;
use crate::cli::Command;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Status => status(),
        Command::Inspect { package } => inspect(&package, false).await.map(|_| ()),
        Command::Audit { package } => inspect(&package, true).await.map(|_| ()),
        Command::Explain { package } => explain(&package),
        Command::History { package } => history(&package),
        Command::Trust { package } => trust(&package).await,
        Command::AllowRule { rule } => allow_rule(&rule),
        Command::InspectLocal { dir } => inspect_local(Path::new(&dir), true).await,
        Command::Sandbox { dir, command } => sandbox_run(&dir, &command).await,
        Command::Gateway { dry_run, args } => gateway(dry_run, &args).await,
    }
}

/// Phase 5 gateway: evaluate `paru -S` targets through Yaru, then forward the
/// original arguments to the REAL paru binary. Opt-in and explicit — Yaru
/// never wraps paru by itself.
async fn gateway(dry_run: bool, args: &[String]) -> Result<()> {
    use crate::core::types::Verdict;
    use crate::interceptor::{GatewayAction, GatewayDecision, find_real_paru, parse_gateway_args};
    use std::process::Command as StdCommand;

    let real =
        find_real_paru().ok_or_else(|| anyhow!("real paru binary not found at /usr/bin/paru"))?;

    match parse_gateway_args(args) {
        GatewayAction::Forward => {
            if dry_run {
                println!(
                    "  [dry-run] non-install operation; would forward to {}",
                    real.display()
                );
                return Ok(());
            }
            let status = StdCommand::new(&real).args(args).status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        GatewayAction::EvaluateInstall { packages, .. } => {
            let cfg = config::load();
            let policy =
                crate::core::policy::PolicyEngine::with_whitelist(cfg.whitelisted_rules.clone());
            let aur = AurClient::new();
            let mut decision = GatewayDecision::new();

            for pkg in &packages {
                let classification = crate::core::classifier::classify(pkg, &aur)
                    .await
                    .map_err(|e| anyhow!("classification failed for {pkg}: {e}"))?;

                // Zone 0 fast path: no AUR pipeline, zero overhead. Every other
                // zone is scored through the policy engine — never auto-allowed.
                if classification.zone != TrustZone::Aur {
                    let report = policy.evaluate(
                        pkg,
                        classification.zone,
                        &ScoreBreakdown::default(),
                        &[],
                        &[],
                    );
                    output::print_report_card(&report);
                    decision.record(
                        pkg,
                        classification.zone,
                        report.verdict,
                        report.reasons.join("; "),
                    );
                    continue;
                }

                let dir = fetch_aur_snapshot(pkg, classification.url_path.as_deref()).await?;
                let rules = crate::core::analyzer::RuleSet::builtin();
                let analysis = crate::core::analyzer::analyze_pkgbuild_dir(&dir, &rules)
                    .map_err(|e| anyhow!("analysis failed for {pkg}: {e}"))?;
                let snapshot = crate::core::types::PackageSnapshot {
                    package_name: analysis.package_name.clone().unwrap_or_else(|| pkg.clone()),
                    version: analysis.version.clone(),
                    maintainer: classification.maintainer.clone(),
                    pkgbuild_hash: analysis.pkgbuild_hash.clone(),
                    source_urls: analysis.source_urls.clone(),
                    depends: analysis.depends.clone(),
                    makedepends: analysis.makedepends.clone(),
                    checkdepends: analysis.checkdepends.clone(),
                    timestamp: chrono::Utc::now().timestamp(),
                };

                let mut maintainer_changes = Vec::new();
                if let Ok(db) = open_db() {
                    if let Ok(Some(prev)) = db.latest_snapshot(&snapshot.package_name) {
                        if let Some(change) =
                            crate::core::maintainer::detect_change(&prev, &snapshot)
                        {
                            maintainer_changes.push(change);
                        }
                    }
                    let _ = db.save_snapshot(&snapshot);
                }

                let report = policy.evaluate(
                    pkg,
                    TrustZone::Aur,
                    &ScoreBreakdown::default(),
                    &analysis.findings,
                    &maintainer_changes,
                );
                output::print_report_card(&report);
                decision.record(
                    pkg,
                    TrustZone::Aur,
                    report.verdict,
                    report.reasons.join("; "),
                );
            }

            println!();
            if !decision.fast_path_packages.is_empty() {
                println!(
                    "  {} fast path (official zone): {}",
                    "[OK]".green(),
                    decision.fast_path_packages.join(", ")
                );
            }
            for (pkg, reason) in &decision.warnings {
                println!("  {} {pkg}: {reason}", "[!]".yellow());
            }

            if !decision.proceed {
                for (pkg, reason) in &decision.blocked_packages {
                    println!("  {} {pkg} BLOCKED: {reason}", "[X]".red());
                }
                anyhow::bail!("yaru gateway refused to forward: blocked package(s) present");
            }

            if dry_run {
                println!(
                    "\n  [dry-run] would forward to {}: {}",
                    real.display(),
                    args.join(" ")
                );
                return Ok(());
            }

            let status = StdCommand::new(&real).args(args).status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }
}

/// Executes a command inside the bubblewrap sandbox using the configured
/// network mode. Reports isolation outcome and exit code to the user.
async fn sandbox_run(dir: &str, command: &[String]) -> Result<()> {
    use crate::sandbox::{Sandbox, SandboxResult};

    if !Path::new(dir).is_dir() {
        anyhow::bail!("directory not found: {dir}");
    }
    if !Sandbox::backend_available() {
        anyhow::bail!("bubblewrap (bwrap) not found on this system");
    }

    let cfg = config::load();
    let sb = Sandbox::new(cfg.sandbox.network_mode, dir);
    let argv: Vec<&str> = command.iter().map(|s| s.as_str()).collect();

    println!("  Sandbox mode : {:?}", cfg.sandbox.network_mode);
    println!("  Workdir      : {dir}");
    println!("  Command      : {}", argv.join(" "));
    println!();

    let r: SandboxResult = sb.run(&argv);
    if !r.stdout.is_empty() {
        println!("{}", r.stdout);
    }
    if !r.stderr.is_empty() {
        eprintln!("{}", r.stderr.red());
    }

    // Phase 4: Behavioral IDS. The sandbox output is the observable evidence of
    // what the build actually attempted (DNS, privilege, filesystem).
    let behavior = crate::monitor::scan_output(&r.stdout, &r.stderr);
    let events_path = events_path();
    if let Err(e) = crate::monitor::append_events(&events_path, &behavior) {
        eprintln!("  warning: cannot write behavior events: {e}");
    }

    if behavior.suspicious {
        println!(
            "\n{}",
            "── Behavior Findings ──────────────────────────────────────────".yellow()
        );
        for f in &behavior.findings {
            println!(
                "  [{}] line {} · {}",
                f.severity.label(),
                f.line,
                f.title.bold()
            );
            println!("             {}", f.excerpt.dimmed());
        }
        println!(
            "\n  Behavior score : {}/100  (evidence logged to {})",
            behavior.score,
            events_path.display()
        );
        println!(
            "  {} dynamic risk raised — build behavior does not match declared sources",
            "[!]".yellow()
        );
    }

    if r.success && !behavior.suspicious {
        println!("\n  {} sandboxed command exited cleanly", "[OK]".green());
        Ok(())
    } else if r.success {
        anyhow::bail!("sandboxed command exited cleanly but behavior was suspicious")
    } else {
        println!(
            "\n  {} sandboxed command FAILED (exit: {:?})",
            "[X]".red(),
            r.exit_code
        );
        anyhow::bail!("sandboxed command failed")
    }
}

fn events_path() -> PathBuf {
    if let Ok(p) = std::env::var("YARU_EVENTS_PATH") {
        return PathBuf::from(p);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("yaru")
        .join("events.jsonl")
}

fn db_path() -> PathBuf {
    if let Ok(p) = std::env::var("YARU_DB_PATH") {
        return PathBuf::from(p);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("yaru")
        .join("yaru.db")
}

fn open_db() -> Result<Database> {
    let path = db_path();
    Database::open(&path).with_context(|| format!("cannot open database at {}", path.display()))
}

fn status() -> Result<()> {
    output::print_banner();
    let cfg = config::load();

    let db_state = match open_db() {
        Ok(db) => {
            let n = db.total_snapshots().unwrap_or(0);
            format!("OK ({} snapshots)", n)
        }
        Err(e) => format!("UNAVAILABLE ({e})"),
    };

    let sandbox = if which::which("bwrap").is_ok() {
        "bubblewrap available"
    } else {
        "bubblewrap NOT FOUND"
    };

    let paru = if which::which("paru").is_ok() {
        "paru detected"
    } else {
        "paru NOT FOUND"
    };

    println!();
    println!("  Version         : {}", env!("CARGO_PKG_VERSION"));
    println!("  Database        : {}", db_state);
    println!("  DB path         : {}", db_path().display());
    println!("  Sandbox backend : {}", sandbox);
    println!("  Paru integration: {}", paru);
    println!(
        "  Policy          : allow<{} warn<{} quarantine<{} fail={:?}",
        cfg.policy.allow_below,
        cfg.policy.warn_below,
        cfg.policy.quarantine_below,
        cfg.policy.on_engine_failure
    );
    println!("  Network mode    : {:?}", cfg.sandbox.network_mode);
    println!(
        "  Rule whitelist  : {}",
        if cfg.whitelisted_rules.is_empty() {
            "(none)".to_string()
        } else {
            cfg.whitelisted_rules.join(", ")
        }
    );
    Ok(())
}

async fn inspect(package: &str, deep: bool) -> Result<()> {
    let cfg = config::load();
    let aur = AurClient::new();
    let classification = crate::core::classifier::classify(package, &aur)
        .await
        .map_err(|e| anyhow!("classification failed: {e}"))?;

    let policy = crate::core::policy::PolicyEngine::with_whitelist(cfg.whitelisted_rules.clone());

    let (report, _) = if classification.zone == TrustZone::Aur {
        let dir = fetch_aur_snapshot(package, classification.url_path.as_deref()).await?;
        analyze_dir(&dir, package, &policy, deep).await?
    } else {
        let report = policy.evaluate(
            package,
            classification.zone,
            &ScoreBreakdown::default(),
            &[],
            &[],
        );
        (report, None)
    };

    output::print_report_card(&report);
    if deep {
        output::print_findings(&report.findings);
    }
    output::print_reasons(&report.reasons);

    if let Ok(db) = open_db() {
        let _ = db.record_decision(&DecisionRecord {
            package: report.package.clone(),
            score: report.score(),
            verdict: report.verdict,
            reasons: report.reasons.clone(),
            timestamp: chrono::Utc::now().timestamp(),
        });
    }
    Ok(())
}

async fn inspect_local(dir: &Path, deep: bool) -> Result<()> {
    let cfg = config::load();
    let policy = crate::core::policy::PolicyEngine::with_whitelist(cfg.whitelisted_rules.clone());
    let name = dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "local".to_string());
    let (report, _) = analyze_dir(dir, &name, &policy, deep).await?;
    output::print_report_card(&report);
    if deep {
        output::print_findings(&report.findings);
    }
    output::print_reasons(&report.reasons);
    Ok(())
}

/// Runs the analyzer over a directory, compares against the stored snapshot,
/// and produces a scored report.
async fn analyze_dir(
    dir: &Path,
    package: &str,
    policy: &crate::core::policy::PolicyEngine,
    _deep: bool,
) -> Result<(crate::core::types::RiskReport, Option<PathBuf>)> {
    let rules = crate::core::analyzer::RuleSet::builtin();
    let analysis = crate::core::analyzer::analyze_pkgbuild_dir(dir, &rules)
        .map_err(|e| anyhow!("analysis failed: {e}"))?;

    let snapshot = crate::core::types::PackageSnapshot {
        package_name: analysis
            .package_name
            .clone()
            .unwrap_or_else(|| package.to_string()),
        version: analysis.version.clone(),
        maintainer: None,
        pkgbuild_hash: analysis.pkgbuild_hash.clone(),
        source_urls: analysis.source_urls.clone(),
        depends: analysis.depends.clone(),
        makedepends: analysis.makedepends.clone(),
        checkdepends: analysis.checkdepends.clone(),
        timestamp: chrono::Utc::now().timestamp(),
    };

    let mut maintainer_changes = Vec::new();
    let mut breakdown = ScoreBreakdown::default();

    if let Ok(db) = open_db() {
        if let Ok(Some(prev)) = db.latest_snapshot(&snapshot.package_name) {
            if let Some(change) = crate::core::maintainer::detect_change(&prev, &snapshot) {
                maintainer_changes.push(change);
            }

            // Phase 2: Analyze dependency changes against previous snapshot
            let dep_graph = crate::core::dependency::analyze_dependencies(
                package,
                &snapshot.depends,
                &snapshot.makedepends,
                Some(&prev.depends),
                |_| false,
            );
            breakdown.dependency_score = dep_graph.risk_score;
        }

        // Phase 2: Check threat intelligence IOCs for sources
        let ioc_engine = crate::core::threatintel::ThreatIntelEngine::new(&db);
        let matches = ioc_engine.match_candidates(&snapshot.source_urls);
        breakdown.threat_score = ioc_engine.calculate_score(&matches);

        let _ = db.save_snapshot(&snapshot);
    }

    let report = policy.evaluate(
        package,
        TrustZone::Aur,
        &breakdown,
        &analysis.findings,
        &maintainer_changes,
    );

    Ok((report, Some(dir.to_path_buf())))
}

/// Downloads the AUR snapshot tarball and extracts PKGBUILD/.install into a
/// temp dir. The caller owns the returned directory.
async fn fetch_aur_snapshot(package: &str, url_path: Option<&str>) -> Result<PathBuf> {
    let base =
        std::env::var("YARU_AUR_BASE").unwrap_or_else(|_| "https://aur.archlinux.org".into());
    let path = url_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("/cgit/aur.git/snapshot/{package}.tar.gz"));
    let url = format!("{base}{path}");

    let bytes = reqwest::get(&url)
        .await
        .with_context(|| format!("cannot download {url}"))?
        .bytes()
        .await?;

    let dir = std::env::temp_dir().join(format!("yaru-snap-{}-{}", package, std::process::id()));
    std::fs::create_dir_all(&dir)?;

    let gz = flate2::read::GzDecoder::new(bytes.as_ref());
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(&dir)
        .with_context(|| format!("cannot extract snapshot for {package}"))?;

    // The tarball nests everything under <package>/
    let nested = dir.join(package);
    Ok(if nested.is_dir() { nested } else { dir })
}

fn explain(package: &str) -> Result<()> {
    let db = open_db()?;
    let decisions = db.list_decisions(package)?;
    match decisions.last() {
        Some(d) => {
            println!(
                "\n  {} — score {}/100 — {}",
                d.package.bold(),
                d.score,
                d.verdict.label()
            );
            output::print_reasons(&d.reasons);
        }
        None => {
            println!("  No recorded decision for '{package}'. Run `yaru inspect {package}` first.")
        }
    }
    Ok(())
}

fn history(package: &str) -> Result<()> {
    let db = open_db()?;
    let snaps = db.list_snapshots(package)?;
    let changes = db.list_maintainer_changes(package)?;
    println!("\n  Snapshot history for {}", package.bold());
    println!("  {}", "─".repeat(60));
    for s in &snaps {
        println!(
            "  {}  {:<16} {}  {}",
            chrono::DateTime::from_timestamp(s.timestamp, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| s.timestamp.to_string()),
            s.version.as_deref().unwrap_or("-"),
            s.maintainer.as_deref().unwrap_or("-"),
            &s.pkgbuild_hash[..12.min(s.pkgbuild_hash.len())]
        );
    }
    if changes.is_empty() {
        println!("  No maintainer changes recorded.");
    } else {
        println!("\n  Maintainer changes:");
        for c in changes {
            println!(
                "    {} — {} → {}",
                c.kind.label(),
                c.previous.as_deref().unwrap_or("n/a"),
                c.current.as_deref().unwrap_or("n/a")
            );
        }
    }
    Ok(())
}

async fn trust(package: &str) -> Result<()> {
    let aur = AurClient::new();
    let c = crate::core::classifier::classify(package, &aur)
        .await
        .map_err(|e| anyhow!("classification failed: {e}"))?;

    println!("\n  Trust view for {}", package.bold());
    println!("  {}", "─".repeat(60));
    println!(
        "  Zone        : {} (base risk {})",
        c.zone.label(),
        c.zone.base_risk()
    );
    println!("  Repository  : {}", c.repository.as_deref().unwrap_or("-"));
    println!("  Version     : {}", c.version.as_deref().unwrap_or("-"));
    println!(
        "  Maintainer  : {}",
        c.maintainer.as_deref().unwrap_or("- (orphaned)")
    );
    println!("  URL         : {}", c.url.as_deref().unwrap_or("-"));

    if let Ok(db) = open_db() {
        let snaps = db.list_snapshots(package).unwrap_or_default();
        println!("  Snapshots   : {}", snaps.len());
    }
    Ok(())
}

fn allow_rule(rule: &str) -> Result<()> {
    let dir = if let Ok(d) = std::env::var("YARU_CONFIG_DIR") {
        PathBuf::from(d)
    } else {
        dirs::config_dir()
            .ok_or_else(|| anyhow!("no config dir"))?
            .join("yaru")
    };
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("config.toml");
    let mut cfg = config::load();
    if !cfg.whitelisted_rules.iter().any(|r| r == rule) {
        cfg.whitelisted_rules.push(rule.to_string());
    }
    std::fs::write(&path, toml::to_string_pretty(&cfg)?)?;
    println!("  Whitelisted rule '{}' in {}", rule, path.display());
    Ok(())
}

/// Read a file as text, returning an empty string when absent.
pub fn read_optional(path: &Path) -> String {
    std::fs::File::open(path)
        .and_then(|mut f| {
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(s)
        })
        .unwrap_or_default()
}
