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
}
