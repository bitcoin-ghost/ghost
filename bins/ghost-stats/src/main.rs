//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: bins/ghost-stats/src/main.rs                                                                                   |

//! ghost-stats — public pool-stats aggregator.
//!
//! The public pool page used to be its own aggregator: every browser fanned out to all eight nodes
//! and merged the results itself, at roughly 145 requests per minute per viewer. The cost therefore
//! scaled with the number of people looking at the page, and several of the underlying queries take
//! seconds, so tiles arrived late, blanked on failure, or 504'd at the proxy.
//!
//! This service does that fan-out once, on a schedule, and holds the merged result in memory. The
//! page makes one request. The rules it exists to enforce:
//!
//! 1. **Never serve nothing.** A section is replaced only by a successful refresh; a failed cycle
//!    leaves the previous answer standing, and the snapshot survives a restart via disk.
//! 2. **Pace each query to its own cost.** A 20s monthly scan does not get to delay a 60ms one.
//! 3. **Say how old it is.** Every section reports `age_secs` and how many nodes answered.

mod api;
mod config;
mod merge;
mod refresh;
mod snapshot;

use clap::Parser;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "ghost-stats",
    about = "Public pool-stats aggregator for bitcoinghost.org"
)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "/etc/ghost/stats.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ghost_stats=info".into()),
        )
        .init();

    let args = Args::parse();
    let cfg = Arc::new(config::Config::load(&args.config)?);
    tracing::info!(config = %args.config, nodes = cfg.nodes.len(), listen = %cfg.server.listen,
        "starting ghost-stats");

    let snap = snapshot::SharedSnapshot::load_or_empty(&cfg.snapshot_path);
    let fetcher = Arc::new(refresh::Fetcher::new(cfg.clone())?);
    refresh::spawn_all(cfg.clone(), snap.clone(), fetcher);

    let listener = tokio::net::TcpListener::bind(&cfg.server.listen).await?;
    tracing::info!(addr = %cfg.server.listen, "listening");
    axum::serve(listener, api::router(snap)).await?;
    Ok(())
}
