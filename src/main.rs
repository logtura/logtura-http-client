//! logtura-http-client: HTTP poller that handles auth refresh.
//!
//! Drop-in stopgap for Vector's `http_client` source until upstream
//! gets `bearer_refresh` / `oauth_refresh` (vectordotdev/vector#17192).
//! Reads a TOML config that mirrors Vector's `http_client` shape, polls
//! the configured endpoint on a schedule, and emits each row of the
//! response body as newline-delimited JSON on stdout — ready for
//! Vector's `exec` source to consume.

use logtura_http_client_lib::{config, poll};

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the TOML config file.
    #[arg(long, short)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Log to stderr so stdout stays event-only. Vector's exec source
    // pulls events from stdout; stderr lands in container logs.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let cfg = config::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;
    tracing::info!(endpoint = %cfg.endpoint, strategy = ?cfg.auth.strategy, "logtura-http-client starting");

    poll::run(cfg).await
}
