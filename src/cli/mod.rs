pub mod commands;
pub mod output;
pub mod prompt;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "yaru",
    version,
    about = "AUR Supply-Chain Security Layer for Arch Linux",
    after_help = "Yaru never replaces paru or pacman; it evaluates what flows through them."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Show engine, database, and policy status
    Status,
    /// Quick risk evaluation of a package without installing it
    Inspect { package: String },
    /// Deep analysis: full findings list with evidence
    Audit { package: String },
    /// Explain the last or current decision for a package
    Explain {
        package: String,
        /// Request AI triage assistance to explain security findings
        #[arg(long)]
        ai: bool,
        /// Bypass cached AI triage response and query AI server again
        #[arg(long)]
        refresh: bool,
    },
    /// Show snapshot and maintainer history
    History { package: String },
    /// Show reputation/trust view of a package
    Trust { package: String },
    /// Whitelist a rule id for this machine (or remove with 'remove <rule>' or '--remove')
    AllowRule {
        /// Rule ID to whitelist, or 'remove' to remove a rule
        rule: String,
        /// Target rule ID when using 'allow-rule remove <rule>'
        target: Option<String>,
        /// Remove rule from whitelist instead of adding
        #[arg(long)]
        remove: bool,
    },
    /// Inspect a local PKGBUILD directory
    InspectLocal { dir: String },
    /// Check if a package requires sandboxed build based on risk policy
    ShouldSandbox {
        package: String,
        /// Optional directory of PKGBUILD if not in database
        #[arg(long)]
        dir: Option<String>,
    },
    /// Run a command inside an isolated bwrap sandbox for a PKGBUILD directory
    Sandbox {
        dir: String,
        /// Sandbox network mode override (strict, source-allowlist, audit)
        #[arg(long)]
        network: Option<crate::config::NetworkMode>,
        /// Command to execute inside the sandbox (defaults to /usr/bin/true)
        #[arg(default_value = "/usr/bin/true", num_args = 1.., trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Evaluate a PKGBUILD directory, then build it inside the sandbox
    Build {
        dir: String,
        /// Evaluate and report only; never invoke makepkg
        #[arg(long)]
        dry_run: bool,
    },
    /// Manage local threat intelligence indicators
    Ioc {
        #[command(subcommand)]
        command: IocCommand,
    },
    /// Evaluate `paru -S` targets, then forward to the real paru binary
    #[command(disable_help_flag = true)]
    Gateway {
        /// Evaluate and report only; never execute paru
        #[arg(long)]
        dry_run: bool,
        /// Arguments as they would be passed to paru (e.g. -S pkg1 pkg2)
        #[arg(num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Show aggregate security report for recent activity
    Report {
        /// Show only today's activity (default)
        #[arg(long, conflicts_with = "days")]
        today: bool,
        /// Show activity for the last N days
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..=365))]
        days: Option<u64>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum IocCommand {
    /// Import IOC indicators from a JSON or YAML file into the local SQLite database
    Import { file: String },
    /// Download and import IOC indicators from a remote URL (JSON or YAML)
    Sync {
        /// Feed URL; falls back to configured [ioc_feed] when omitted
        url: Option<String>,
    },
}
