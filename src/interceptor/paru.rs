use crate::core::types::{TrustZone, Verdict};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// Classified invocation of a paru/pacman command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayAction {
    /// Non-install operation (-Q, -R, -F, --help, etc.): forward directly to real paru.
    Forward,
    /// Install operation with explicit packages (-S pkg1 pkg2).
    EvaluateInstall {
        packages: Vec<String>,
        passthrough_flags: Vec<String>,
    },
    /// System upgrade operation (-Syu, -Syyu, -u, or bare `paru`): requires querying
    /// out-of-date AUR packages and evaluating them before proceeding.
    EvaluateUpgrade { passthrough_flags: Vec<String> },
}

/// Parses command line arguments to separate action, flags, and package targets.
pub fn parse_gateway_args(args: &[String]) -> GatewayAction {
    if args.is_empty() {
        return GatewayAction::EvaluateUpgrade {
            passthrough_flags: Vec::new(),
        };
    }

    let mut is_sync = false;
    let mut is_upgrade = false;
    let mut packages = Vec::new();
    let mut passthrough_flags = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') {
            passthrough_flags.push(arg.clone());
            if arg == "-S"
                || arg == "--sync"
                || (arg.starts_with("-S") && !arg.starts_with("-Ss") && !arg.starts_with("-Si"))
            {
                is_sync = true;
            }
            if arg.contains('u') || arg == "--sysupgrade" {
                is_upgrade = true;
            }
        } else {
            packages.push(arg.clone());
        }
        i += 1;
    }

    if is_sync && !packages.is_empty() {
        GatewayAction::EvaluateInstall {
            packages,
            passthrough_flags,
        }
    } else if is_upgrade || (is_sync && packages.is_empty()) {
        GatewayAction::EvaluateUpgrade { passthrough_flags }
    } else {
        GatewayAction::Forward
    }
}

/// Parses the output of `paru -Qua` (or `paru -Qu --aur`) to extract package names.
/// Expected line format: `<package_name> <old_ver> -> <new_ver>`
pub fn parse_aur_upgrades(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with("::") || line.starts_with("error:") {
                None
            } else {
                line.split_whitespace().next().map(String::from)
            }
        })
        .collect()
}

/// Queries outdated AUR packages using `paru -Qua`.
pub fn query_aur_upgrades(real_paru: &Path) -> std::io::Result<Vec<String>> {
    let output = Command::new(real_paru).args(["-Qua"]).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_aur_upgrades(&stdout))
}

/// Locates the real paru binary, avoiding loops if a wrapper is on PATH.
pub fn find_real_paru() -> Option<PathBuf> {
    for candidate in ["/usr/bin/paru", "/bin/paru"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    which::which("paru").ok()
}

/// Result of evaluating a batch of packages before installation.
#[derive(Debug, Clone)]
pub struct GatewayDecision {
    pub proceed: bool,
    pub fast_path_packages: Vec<String>,
    pub blocked_packages: Vec<(String, String)>,
    pub warnings: Vec<(String, String)>,
}

impl GatewayDecision {
    pub fn new() -> Self {
        Self {
            proceed: true,
            fast_path_packages: Vec::new(),
            blocked_packages: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn record(&mut self, package: &str, zone: TrustZone, verdict: Verdict, reason: String) {
        match verdict {
            Verdict::Allow => {
                if zone == TrustZone::Official {
                    self.fast_path_packages.push(package.to_string());
                }
            }
            Verdict::Warn => {
                self.warnings.push((package.to_string(), reason));
            }
            // Quarantine means not trusted to enter the system yet. The
            // non-interactive gateway refuses rather than forwarding.
            Verdict::Quarantine | Verdict::Block => {
                self.proceed = false;
                self.blocked_packages.push((package.to_string(), reason));
            }
        }
    }
}

impl Default for GatewayDecision {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawns the real paru binary with passthrough arguments.
pub fn execute_real_paru(real_paru: &PathBuf, args: &[String]) -> std::io::Result<ExitStatus> {
    Command::new(real_paru).args(args).status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_install_command_with_packages() {
        let args: Vec<String> = vec![
            "-S".into(),
            "--needed".into(),
            "ripgrep".into(),
            "google-chrome".into(),
        ];
        match parse_gateway_args(&args) {
            GatewayAction::EvaluateInstall {
                packages,
                passthrough_flags,
            } => {
                assert_eq!(packages, vec!["ripgrep", "google-chrome"]);
                assert_eq!(passthrough_flags, vec!["-S", "--needed"]);
            }
            _ => panic!("expected EvaluateInstall"),
        }
    }

    #[test]
    fn parses_upgrade_commands_as_evaluate_upgrade() {
        // paru -Syu
        let args: Vec<String> = vec!["-Syu".into()];
        assert!(matches!(
            parse_gateway_args(&args),
            GatewayAction::EvaluateUpgrade { .. }
        ));

        // paru -Syyu
        let args: Vec<String> = vec!["-Syyu".into()];
        assert!(matches!(
            parse_gateway_args(&args),
            GatewayAction::EvaluateUpgrade { .. }
        ));

        // paru (empty args)
        let empty: Vec<String> = vec![];
        assert!(matches!(
            parse_gateway_args(&empty),
            GatewayAction::EvaluateUpgrade { .. }
        ));
    }

    #[test]
    fn parses_aur_upgrades_output() {
        let sample = "\
android-studio 2026.1.3.7-1 -> 2026.1.4.7-1
ani-cli 4.15-1 -> 5.1-1
google-chrome 153.0.8010.36-1 -> 153.0.8010.47-1
";
        let pkgs = parse_aur_upgrades(sample);
        assert_eq!(pkgs, vec!["android-studio", "ani-cli", "google-chrome"]);
    }

    #[test]
    fn parses_query_command_as_forward() {
        let args: Vec<String> = vec!["-Qs".into(), "ripgrep".into()];
        assert_eq!(parse_gateway_args(&args), GatewayAction::Forward);
    }

    #[test]
    fn blocking_package_stops_install() {
        let mut d = GatewayDecision::new();
        d.record(
            "firefox",
            TrustZone::Official,
            Verdict::Allow,
            "Official repo".into(),
        );
        d.record(
            "malicious-aur",
            TrustZone::Aur,
            Verdict::Block,
            "Remote shell detected".into(),
        );

        assert!(!d.proceed);
        assert_eq!(d.fast_path_packages, vec!["firefox"]);
        assert_eq!(d.blocked_packages.len(), 1);
        assert_eq!(d.blocked_packages[0].0, "malicious-aur");
    }

    #[test]
    fn official_only_install_proceeds_unblocked() {
        let mut d = GatewayDecision::new();
        d.record(
            "firefox",
            TrustZone::Official,
            Verdict::Allow,
            "Official repo".into(),
        );
        d.record(
            "git",
            TrustZone::Official,
            Verdict::Allow,
            "Official repo".into(),
        );

        assert!(d.proceed);
        assert_eq!(d.fast_path_packages.len(), 2);
        assert!(d.blocked_packages.is_empty());
    }
}
