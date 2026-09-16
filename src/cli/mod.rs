pub mod commands;
pub mod output;

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
    Explain { package: String },
    /// Show snapshot and maintainer history
    History { package: String },
    /// Show reputation/trust view of a package
    Trust { package: String },
    /// Whitelist a rule id for this machine
    AllowRule { rule: String },
    /// Inspect a local PKGBUILD directory
    InspectLocal { dir: String },
    /// Run a command inside an isolated bwrap sandbox for a PKGBUILD directory
    Sandbox {
        dir: String,
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
    Gateway {
        /// Evaluate and report only; never execute paru
        #[arg(long)]
        dry_run: bool,
        /// Arguments as they would be passed to paru (e.g. -S pkg1 pkg2)
        #[arg(num_args = 1.., trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum IocCommand {
    /// Import IOC indicators from a JSON or YAML file into the local SQLite database
    Import { file: String },
}
