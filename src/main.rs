use clap::Parser;
use yaru::cli::{Cli, commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    commands::run(cli).await
}
