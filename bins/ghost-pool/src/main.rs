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
//| FILE: main.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Pool - Bitcoin Ghost Mining Pool Node
//!
//! Main entry point for the Ghost Pool node:
//!
//! - BUDS-filtered block templates served to the co-located pool_sv2 over TDP
//! - round statistics and the operator API
//!
//! Miners' balances and every coinbase are the node pool's, in pool_sv2.
//!
//! Run with: ghost-mining --config ghost.toml

#![deny(unreachable_pub)]

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn, Level};

use tracing_subscriber::prelude::*;

use ghost_common::config::{NodeConfig, ReaperSettings};
use ghost_common::identity::NodeIdentity;
use ghost_common::metrics::Metrics;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::signer::SignerConfig;
use ghost_common::zmq::{ZmqConfig, ZmqSubscriber};
use ghost_policy::PolicyProfile;
use ghost_reaper::ReaperConfig;
use ghost_storage::Database;
use ghost_verification::{start_server, start_server_on, VerificationState};

use ghost_pool::capacity;
use ghost_pool::reorg::{ReorgConfig, ReorgHandler};
use ghost_pool::round::{RoundConfig, RoundManager};
use ghost_pool::template::{TemplateConfig, TemplateEvent, TemplateProcessor};
use ghost_pool::template_provider::{TdpConfig, TemplateDistributionServer};

/// Exit code that signals systemd to restart the service
/// Used when config is updated via API and requires restart to apply
const EXIT_CODE_RESTART: i32 = 100;

/// Trailing window for this node's realized hashrate. 10 minutes smooths small-miner share
/// variance while still tracking real changes within a few minutes.
const LOCAL_HASHRATE_WINDOW_SECS: i64 = 600;

/// H-8 SECURITY: Static storage for ZMQ subscriber to prevent memory leak.
/// Previously used std::mem::forget which intentionally leaked memory.
/// Using OnceLock ensures the subscriber lives for the program lifetime
/// without leaking, and can be properly dropped on program exit.
static ZMQ_SUBSCRIBER: OnceLock<ZmqSubscriber> = OnceLock::new();

/// What a node should report as its own hashrate, given a query outcome.
///
/// Pure so the failure path can actually be tested — the failure path is the whole point. The
/// HTTP route used to call `.unwrap_or(0.0)` here, so a node whose database was too slow to answer
/// reported ZERO hashes. That is indistinguishable from having no miners and logged nothing. It hid 94 TH/s on ghost-vm5 (88% of the pool) behind a
/// database stalled by #554, and the public site reported 13.8 TH/s against a real ~107 TH/s.
///
/// `query` is `None` when the database could not answer. A genuine idle node returns `Some(0.0)`
/// and is reported as zero, which is correct — only a FAILED query takes the fallback.
///
/// Returns the value to report and how it was arrived at, so the caller can log accordingly.
fn reported_hashrate(
    query: Option<f64>,
    last_good: Option<(f64, u64)>,
    grace_secs: u64,
) -> (f64, HashrateSource) {
    match query {
        Some(th) => (th, HashrateSource::Measured),
        None => match last_good {
            Some((th, age)) if age <= grace_secs => (th, HashrateSource::Stale { age_secs: age }),
            _ => (0.0, HashrateSource::Unavailable),
        },
    }
}

/// Where a reported hashrate came from. `Unavailable` means the pool-wide total is understated.
#[derive(Debug, Clone, Copy, PartialEq)]
enum HashrateSource {
    Measured,
    Stale { age_secs: u64 },
    Unavailable,
}

/// Ghost Mining - Decentralized Bitcoin Mining Pool
#[derive(Parser, Debug)]
#[command(name = "ghost-mining")]
// #759: the workspace number alone does not identify a build — see `ghost_build_info`.
#[command(author, version, long_version = ghost_build_info::LONG_VERSION, about, long_about = None)]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "ghost.toml")]
    config: PathBuf,

    /// Data directory
    #[arg(short, long, default_value = "~/.ghost")]
    data_dir: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Generate new node identity
    #[arg(long)]
    generate_identity: bool,

    /// Show node identity and exit
    #[arg(long)]
    show_identity: bool,

    /// Report config keys the binary does not understand, then exit.
    ///
    /// Prints key NAMES only, never values — safe to run on a production node
    /// whose config carries secrets. Exits non-zero if any key is unknown, so
    /// it can gate a deploy.
    #[arg(long)]
    check_config: bool,

    /// Show what this node can establish about itself, and exit
    #[arg(long)]
    status: bool,

    /// Watch node status continuously (refresh every N seconds)
    #[arg(long, value_name = "SECS")]
    watch: Option<u64>,

    /// Bitcoin RPC host override
    #[arg(long)]
    rpc_host: Option<String>,

    /// Bitcoin RPC port override
    #[arg(long)]
    rpc_port: Option<u16>,

    /// Stratum listen port override
    #[arg(long)]
    stratum_port: Option<u16>,

    /// Enable Template Distribution Protocol server (for SRI pool)
    #[arg(long)]
    tdp_enabled: bool,

    /// TDP server port (default: 8442)
    #[arg(long, default_value = "8442")]
    tdp_port: u16,

    /// Address the TDP server listens on (default: 127.0.0.1). Only the node's own pool_sv2
    /// connects to it; give 0.0.0.0 only for a pool_sv2 on another machine.
    #[arg(long, default_value = "127.0.0.1")]
    tdp_bind: std::net::IpAddr,

    /// Disable native stratum server (use when running with SRI pool via TDP)
    #[arg(long)]
    no_stratum: bool,
}

/// Handle `--status`: report what THIS node can establish about itself (B4).
///
/// This used to query a central registry for its own status, and printed "Registry not configured" when
/// the `[registry]` block was absent — which it is on every node in the fleet, so the command told an
/// operator nothing. The registry is being deleted; three of its fields could not be repointed at
/// anything because they only meant something relative to a central service:
///
/// - `registered` — there is no authority to be registered with
/// - `rank_in_region`, `total_in_region` — nothing ranks nodes any more
///
/// Reproducing those would be reimplementing the service being removed. What replaces them is what a
/// node can observe for itself: its own `/health`, its own peer count, and — for `in_dns` — resolving
/// the mining name and looking for itself in the answer.
async fn handle_status_command(
    config: &NodeConfig,
    identity: &NodeIdentity,
    watch_interval: Option<u64>,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let node_id = identity.node_id_hex();
    // The node's own API, not a peer's and not a central service's.
    let health_url = format!("http://127.0.0.1:{}/health", config.network.http_port);

    loop {
        if watch_interval.is_some() {
            print!("\x1B[2J\x1B[1;1H");
        }

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║                    Ghost Pool Status                          ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
        println!("Node ID:     {} ({})", identity.node_id_short(), node_id);

        match client.get(&health_url).send().await {
            Ok(response) if response.status().is_success() => {
                let body: serde_json::Value = response.json().await?;
                // /health answers {"signed":…,"response":{…}} on mainnet; accept both shapes rather
                // than depending on which is in force.
                let h = body.get("response").unwrap_or(&body);
                print_local_status(h);
            }
            Ok(response) => {
                println!("Status:      ○ API returned {}", response.status());
                println!();
                println!("The pool service is listening but its health endpoint is unhappy.");
            }
            Err(e) => {
                println!("Status:      ○ NOT RUNNING (or API unreachable)");
                println!("             {e}");
                println!();
                println!("Check: systemctl status ghost-mining");
            }
        }

        // in_dns: resolve the mining name and look for ourselves. A direct observation, and the check
        // that would have caught #596 — four nodes absent from DNS for weeks while reporting healthy.
        println!();
        match config.pool.mining_dns_name.as_deref() {
            None => println!(
                "In mining DNS: ? not checked — set `mining_dns_name` under [pool] to have this node \
                 verify it is actually in the DNS answer miners resolve"
            ),
            Some(name) => match mining_dns_membership(name).await {
                ghost_pool::InDns::Yes => {
                    println!("In mining DNS: ● yes — this node receives miners")
                }
                ghost_pool::InDns::No => println!(
                    "In mining DNS: ○ NO — {name} does not resolve to this node, so it receives no \
                     miners from the pool address"
                ),
                ghost_pool::InDns::Unknown => println!(
                    "In mining DNS: ? could not determine ({name} did not resolve, or local \
                     addresses unavailable) — this is NOT a report that the node is absent"
                ),
            },
        }

        let Some(interval) = watch_interval else {
            break;
        };
        println!();
        println!("Refreshing every {interval}s — Ctrl-C to stop");
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
    }

    Ok(())
}

/// Resolve the mining name and decide whether one of our own addresses is in the answer.
///
/// Both halves can fail independently, and either failure means `Unknown` rather than `No`, because
/// reporting absence on a resolver problem points the operator at the wrong thing.
async fn mining_dns_membership(name: &str) -> ghost_pool::InDns {
    use std::net::IpAddr;

    let resolved: Vec<IpAddr> = match tokio::net::lookup_host(format!("{name}:0")).await {
        Ok(it) => it.map(|s| s.ip()).collect(),
        Err(_) => Vec::new(),
    };
    let local: Vec<IpAddr> = local_ip_addresses().unwrap_or_default();
    ghost_pool::is_in_mining_dns(&resolved, &local)
}

/// This node's own routable addresses, via the OS.
///
/// Uses `hostname -I` rather than a crate: it is already how every deploy script on this fleet reads a
/// node's address, so the two agree by construction.
fn local_ip_addresses() -> Option<Vec<std::net::IpAddr>> {
    let out = std::process::Command::new("hostname")
        .arg("-I")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let v: Vec<std::net::IpAddr> = text
        .split_whitespace()
        .filter_map(|t| t.parse().ok())
        .collect();
    (!v.is_empty()).then_some(v)
}

/// Render the node's own health document.
fn print_local_status(h: &serde_json::Value) {
    let healthy = h.get("healthy").and_then(|v| v.as_bool()).unwrap_or(false);
    let icon = if healthy { "●" } else { "○" };
    println!(
        "Status:      {icon} {}",
        if healthy { "HEALTHY" } else { "UNHEALTHY" }
    );
    println!();

    let g = |k: &str| h.get(k).cloned().unwrap_or(serde_json::Value::Null);
    println!("Version:     {}", g("version"));
    println!("Block height:{}", g("block_height"));
    println!("Round:       {}", g("round_id"));
    println!("Miners:      {}", g("miner_count"));
    println!("Relay peers: {}", g("peer_count"));
    println!("Uptime (s):  {}", g("uptime_secs"));
    println!(
        "Bitcoin RPC: {}",
        if h.get("core_reachable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "reachable"
        } else {
            "UNREACHABLE"
        }
    );
}

/// Heap profiling allocator, compiled in only under `--features heap-profiling`.
///
/// jemalloc with profiling support. Inert until switched on at runtime, so a build with this
/// feature behaves normally until you ask for a profile:
///
/// ```text
/// MALLOC_CONF=prof:true,prof_active:true,lg_prof_sample:19,lg_prof_interval:30,prof_prefix:/tmp/gp-heap \
///     /opt/ghost/bin/ghost-mining ...
/// jeprof --show_bytes --text /opt/ghost/bin/ghost-mining /tmp/gp-heap.*.heap | head -40
/// ```
///
/// `lg_prof_sample:19` samples every ~512KB allocated (cheap), and `lg_prof_interval:30`
/// dumps a profile per ~1GB allocated, which is enough granularity to see what accumulates
/// without babysitting it. Added to chase the ~2.2GB steady-state working set in #418, where
/// reasoning from the outside repeatedly produced wrong answers.
#[cfg(feature = "heap-profiling")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// Eight worker threads, not the default.
//
// `#[tokio::main]` with no argument sets `worker_threads = num_cpus`, and every node in this
// fleet has **2 CPUs**. That number is not a throughput knob here, it is the number of
// concurrent blocking database calls it takes to stall the entire runtime.
//
// `Database::with_connection` takes a `parking_lot::Mutex` around the single SQLite connection
// and holds it for the whole closure (#537). `parking_lot` does not yield: a task waiting on it
// blocks the OS thread it is running on rather than returning it to the runtime. With 2 workers,
// **two** concurrent database callers park both, and at that point nothing else is polled — not
// inbound HTTP, not RPC completions, not timers. That is the shape of the multi-second stalls in
// #535, on nodes where the individual queries measure 0.03-0.2s.
//
// A parked worker consumes no CPU, so extra workers cost stack memory (~2 MB each, so ~12 MB
// here) and nothing else. They do not add parallelism — there are still 2 cores — but they mean
// a handful of blocked database calls no longer takes the whole reactor down with them.
//
// ⚠ This is a MITIGATION, not the fix, and the distinction matters for anyone reading #537 later:
//
//   * it removes the "every worker parked, nothing polled" failure mode;
//   * it does NOT remove the serialisation. One connection behind one mutex is still a
//     throughput ceiling, and 278 `with_connection` call sites still run on async workers.
//
// The structural fix is to move database work off the runtime (`spawn_blocking`, of which there
// are currently 9 uses in routes.rs and 8 here, against those 278 call sites). ⛔ It is NOT a
// read/write connection split: that was built and REVERTED in #571/#579 — see the notes there
// before re-proposing it.
#[tokio::main(worker_threads = 8)]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let log_filter = build_log_filter(&args.log_level, std::env::var("RUST_LOG").ok().as_deref());

    // Console layer (stdout → journald under systemd). ANSI is gated on an
    // interactive terminal so journald stores clean UTF-8, not colour escapes.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false);

    // Ring-buffer layer feeds the dashboard `/logs` endpoint with ghost-mining's
    // own structured log tail (real message + target + level per event).
    let subscriber = tracing_subscriber::registry()
        .with(log_filter)
        .with(fmt_layer)
        .with(ghost_pool::log_ring::LogRingLayer);

    // HIGH-8: Use fallible initialization - if subscriber is already set, that's fine
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        // A subscriber is already registered (e.g., from test harness). Continue with existing one.
        eprintln!("Note: Tracing subscriber already initialized, using existing configuration");
    }

    // Install the rustls process-level CryptoProvider exactly once, before
    // any code path constructs a `rustls::ClientConfig::builder()` or similar.
    // The verification client's identity-pinned TLS path triggers this otherwise.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        // Already installed (test harness / re-init); nothing to do.
    }

    // Expand data directory
    let data_dir = expand_path(&args.data_dir)?;
    std::fs::create_dir_all(&data_dir)?;

    // Default key path in data directory (used for --generate-identity and fallback)
    let default_key_path = data_dir.join("node.key");

    // Handle --generate-identity command (doesn't need config)
    if args.generate_identity {
        info!("Generating new node identity...");
        let identity = NodeIdentity::generate();
        identity.save(&default_key_path)?;
        info!("Node ID: {}", identity.node_id_hex());
        info!("Key saved to: {}", default_key_path.display());
        return Ok(());
    }

    // Load configuration first (needed for signer config)
    let config = load_config(&args.config)?;

    // --check-config: run BEFORE identity, keys, or storage, so a config problem
    // is reported as a config problem rather than as whatever fails next.
    if args.check_config {
        return handle_check_config(&args.config);
    }

    // Policy master/slave reconciliation. `pool.toml [policy] profile` is the single
    // MASTER the operator edits (directly or via the dashboard); ghostd's
    // `-ghostpolicy-allowtiers` is a derived SLAVE. If they have drifted — e.g. the
    // dashboard shows `strict` while ghostd is still accepting T2 — bring ghostd back
    // in line with pool.toml here, before anything else, so the two can never silently
    // disagree. No-op when already in sync; only restarts ghostd when it must.
    ghost_verification::routes::reconcile_ghostd_policy_to_config(config.policy.profile.as_str());

    // Determine the effective signer configuration
    // Priority: config.identity.signer > config.identity.key_path > data_dir/node.key
    let signer_config = resolve_signer_path(
        &config.identity.signer,
        &config.identity.key_path,
        &default_key_path,
    )?;

    // Load or create identity using signer config
    let identity = match &signer_config {
        SignerConfig::Local { key_path } => {
            if key_path.exists() {
                NodeIdentity::load(key_path)?
            } else {
                info!(
                    "No identity found at {}, generating new one...",
                    key_path.display()
                );
                let identity = NodeIdentity::generate();
                identity.save(key_path)?;
                info!("Generated new identity, saved to: {}", key_path.display());
                identity
            }
        }
        SignerConfig::Hsm { .. } | SignerConfig::Kms { .. } => {
            // HSM/KMS signers require the key to already exist
            NodeIdentity::from_config(&signer_config).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to initialize {} signer: {}",
                    match &signer_config {
                        SignerConfig::Hsm { .. } => "HSM",
                        SignerConfig::Kms { .. } => "KMS",
                        _ => "unknown",
                    },
                    e
                )
            })?
        }
    };

    // Handle --show-identity command
    if args.show_identity {
        println!("Node ID: {}", identity.node_id_hex());
        println!("Short ID: {}", identity.node_id_short());
        println!("Signer: {}", identity.signer_type());
        return Ok(());
    }

    // Handle --status command
    if args.status {
        return handle_status_command(&config, &identity, None).await;
    }

    // Handle --watch command
    if let Some(interval) = args.watch {
        return handle_status_command(&config, &identity, Some(interval.max(1))).await;
    }

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!(
        "║              Ghost Pool v{}                           ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("║          Decentralized Bitcoin Mining Pool                   ║");
    info!("╚══════════════════════════════════════════════════════════════╝");
    info!(
        "Node ID: {} ({})",
        identity.node_id_short(),
        identity.signer_type()
    );

    // Validate configuration
    let validation = config.validate();

    // Log warnings
    for warning in &validation.warnings {
        warn!("{}", warning);
    }

    // Check for errors
    if !validation.is_valid() {
        error!("Configuration validation failed:");
        for err in &validation.errors {
            error!("  {}", err);
        }
        return Err(anyhow::anyhow!(
            "Configuration validation failed with {} error(s)",
            validation.errors.len()
        ));
    }

    info!(
        "Configuration validated ({} warning(s))",
        validation.warnings.len()
    );

    // Override config with CLI args
    let rpc_host = args.rpc_host.as_ref().unwrap_or(&config.bitcoin.rpc_host);
    let rpc_port = args.rpc_port.unwrap_or(config.bitcoin.rpc_port);

    // Initialize Bitcoin RPC
    info!("Connecting to Ghost Core at {}:{}", rpc_host, rpc_port);
    let mut rpc = BitcoinRpc::new(
        rpc_host,
        rpc_port,
        &config.bitcoin.rpc_user,
        &config.bitcoin.rpc_password,
    )?;
    rpc.set_network(config.bitcoin.network);
    let rpc = Arc::new(rpc);

    // Test RPC connection
    match rpc.get_blockchain_info().await {
        Ok(info) => {
            info!(
                chain = %info.chain,
                height = info.blocks,
                difficulty = info.difficulty,
                "Connected to Ghost Core"
            );
        }
        Err(e) => {
            error!(error = %e, "Failed to connect to Ghost Core");
            return Err(anyhow::anyhow!("Bitcoin RPC connection failed: {}", e));
        }
    };

    // Query Tor mode status from Ghost Core
    let tor_status = match rpc.get_tor_mode().await {
        Ok(status) => {
            if status.enabled {
                info!(
                    onion_address = status.onion_address.as_deref().unwrap_or("pending"),
                    embedded = status.embedded_tor,
                    "Tor mode active on Ghost Core"
                );
            }
            Some(status)
        }
        Err(e) => {
            // gettormode may not exist on older Ghost Core versions
            debug!(error = %e, "Could not query Tor mode (older ghostd?)");
            None
        }
    };

    // Initialize database
    let db_path = data_dir.join("ghost.db");

    // Apply a pending restore staged by the dashboard Backup & Restore import,
    // if any. This MUST run before the DB is opened so the swap happens while the
    // file is closed (never corrupting a running DB). It first copies the current
    // DB to a timestamped `.pre-restore-*.db` safety backup. A failure here is
    // non-fatal — the existing DB is left intact and we start from it.
    match ghost_storage::database::apply_pending_restore(&db_path) {
        Ok(true) => info!("Applied pending database restore from dashboard import"),
        Ok(false) => {}
        Err(e) => error!(
            error = %e,
            "Pending database restore failed; starting with the existing database"
        ),
    }

    let db = Arc::new(Database::open(&db_path)?);
    info!("Database opened: {}", db_path.display());

    // P-4: Configure database encryption for payout addresses.
    // Derive a deterministic encryption key from the node identity by signing
    // a domain-separated message. This works with any Signer backend (local, HSM, KMS)
    // and produces a node-specific key without exposing the private key directly.
    // Falls back to GHOST_ENCRYPTION_KEY env var if identity-based derivation fails.
    {
        use sha2::{Digest, Sha256};
        let signature = identity.signer().sign(b"ghost/db-encryption/v1");
        let mut hasher = Sha256::new();
        hasher.update(b"ghost/db-encryption-key/v1");
        hasher.update(signature);
        let key_material = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_material);
        db.set_encryption_key(key);
        // Zeroize local copies
        key.fill(0);
    }

    // Setup policy profile
    let policy = match config.policy.profile {
        ghost_common::config::PolicyProfile::BitcoinPure => PolicyProfile::bitcoin_pure(),
        ghost_common::config::PolicyProfile::Permissive => PolicyProfile::permissive(),
        ghost_common::config::PolicyProfile::FullOpen => PolicyProfile::full_open(),
        // Custom: build the enforced profile from the operator's `[policy].custom`
        // fields so the finer knobs (tiers, content toggles, size limits, min fee)
        // actually bite at block-build time. Falls back to the default custom
        // block when none is persisted.
        ghost_common::config::PolicyProfile::Custom => {
            let custom = config.policy.custom.clone().unwrap_or_default();
            policy_profile_from_custom(&custom)
        }
    };
    info!(
        "Policy profile: {} (allows up to T{})",
        policy.name,
        policy.highest_allowed_tier().map(|t| t as u8).unwrap_or(0)
    );

    // Setup reaper config for dead code detection, honouring the operator's
    // per-vector detector selection (not just the master on/off).
    let reaper_config = reaper_config_from_settings(&config.reaper);
    if let Err(e) = reaper_config.validate() {
        warn!("Reaper config invalid ({e}); falling back to all-on defaults");
    }
    info!(
        "Reaper: {} (inscription={} dropstuffing={} fakepubkey={} annex={} unreachable={} excess_witness={} legacy={})",
        if reaper_config.enabled { "enabled" } else { "disabled" },
        reaper_config.reject_inscription_envelope,
        reaper_config.reject_drop_stuffing,
        reaper_config.reject_fake_pubkeys,
        reaper_config.reject_annex,
        reaper_config.reject_unreachable_code,
        reaper_config.reject_excess_witness,
        reaper_config.reject_legacy_data_stuffing,
    );

    // Register this node in the database (its own row: uptime and the swarm page).
    let node_id_hex = identity.node_id_hex();
    if let Err(e) = db.register_node(
        &node_id_hex,
        config.network.public_address.as_deref(),
        config.identity.display_name.as_deref(),
    ) {
        warn!("Failed to register node: {} - continuing anyway", e);
    }

    // Create identity Arc
    let identity = Arc::new(identity);

    // Prometheus metrics
    let metrics = Metrics::default_metrics();

    // Rounds, for statistics: one per template.
    let round_manager = Arc::new(RoundManager::new(RoundConfig::default()));

    // Seed the chain height so `/health` reports a real height before the first template
    // arrives. A failure here is not fatal: the first template still sets it.
    match rpc.get_block_count().await {
        Ok(h) => {
            round_manager.seed_height(h);
            info!(height = h, "Seeded chain height from Core");
        }
        Err(e) => warn!(
            error = %e,
            "Could not seed chain height from Core — it reads 0 until the first template"
        ),
    }

    // Reload the latest round's statistics from the database
    round_manager.reload_from_db(&db);

    // Resolve coinbase tag: coinbase_extra > pool_name formatted > default
    let coinbase_tag = config
        .pool
        .coinbase_extra
        .clone()
        .or_else(|| {
            config
                .pool
                .pool_name
                .as_ref()
                .map(|name| format!("GHOST {}", name))
        })
        .unwrap_or_else(|| ghost_common::config::DEFAULT_COINBASE_TAG.to_string());

    // Write tag file so SRI pool service can pick it up via ExecStartPre
    let tag_path = data_dir.join("coinbase_tag");
    if let Err(e) = std::fs::write(&tag_path, &coinbase_tag) {
        warn!(error = %e, "Failed to write coinbase tag file");
    }
    info!(tag = %coinbase_tag, "Coinbase tag: {}", coinbase_tag);

    // Initialize the template processor
    // Per-field policy enforcement (max outputs / size / OP_RETURN / witness /
    // content) is the "Advanced" Custom profile only. The three "Basic" presets
    // stay tier-gate-only, so their baked-in field limits are NOT enforced at
    // block-build time — preserving the historical preset behaviour.
    let enforce_custom_policy_fields = matches!(
        config.policy.profile,
        ghost_common::config::PolicyProfile::Custom
    );

    // The template's minimum fee-rate floor. Presets keep the historical
    // TemplateConfig default (unchanged behaviour); the Custom profile lets the
    // operator set their own floor via `[policy].custom.min_fee_rate`.
    let template_min_fee_rate = if enforce_custom_policy_fields {
        policy.min_fee_rate
    } else {
        TemplateConfig::default().min_fee_rate
    };

    let template_config = TemplateConfig {
        network: config.bitcoin.network,
        coinbase_extra: coinbase_tag,
        // The identity itself, not a pre-hashed commitment: the scriptSig builder derives the
        // tag per build — `node_commitment_plain` below SHARE_TIER_BIND_HEIGHT (byte-identical
        // to the sha256(node_id)[..20] always stamped), `node_commitment_for_tier` above it for
        // builds that know their tier. See TemplateConfig::node_id.
        node_id: Some(identity.node_id()),
        min_fee_rate: template_min_fee_rate,
        enforce_custom_policy_fields,
        // Block-priority lever (max_fee default | payments_first). Resolved once
        // here at startup from pool.toml; the dashboard POST persists + restarts.
        block_priority: config.pool.block_priority,
        // Template refresh cadence (ms) from pool.toml, clamped to [10s,60s].
        // The dashboard retunes it live via the atomic handle (no restart).
        refresh_interval_ms: config.pool.template_refresh_ms(),
        ..Default::default()
    };
    let template_processor = Arc::new(TemplateProcessor::new(
        template_config,
        Arc::clone(&rpc),
        policy.clone(),
        reaper_config,
    ));

    // Note: Native stratum server removed - using SRI (Stratum Reference Implementation) via TDP
    // SRI pool connects to ghost-mining's TDP server for templates
    // SRI translator handles SV1 miners on port 3333

    // This node's own realized hashrate (10-min trailing window). Scoped by
    // `received_by = hex(node_id[..8])` so only shares this node received count.
    let self_received_by = hex::encode(&identity.node_id()[..8]);

    // A database too slow to answer used to read as ZERO hashes, indistinguishable from having
    // no miners, with no error logged. On 2026-08-09 that hid 94 TH/s on ghost-vm5 behind a
    // database stalled by #554.
    //
    // A genuine zero still passes through untouched — an idle node's query SUCCEEDS with 0.0.
    // Only a FAILED query takes the fallback, and the fallback is the last value this node
    // actually measured rather than a fabricated zero. Bounded, because stale-forever is its own
    // lie: past the grace period it reports zero and says so at WARN.
    let local_hashrate_provider: Arc<dyn Fn() -> f64 + Send + Sync> = {
        const STALE_GRACE_SECS: u64 = 600;
        let db_for_local_hr = Arc::clone(&db);
        let self_rx = self_received_by.clone();
        let last_good: Arc<parking_lot::Mutex<Option<(f64, std::time::Instant)>>> =
            Arc::new(parking_lot::Mutex::new(None));
        Arc::new(move || {
            let outcome = db_for_local_hr.local_hashrate_th(LOCAL_HASHRATE_WINDOW_SECS, &self_rx);
            let err = outcome.as_ref().err().map(|e| e.to_string());
            let cached = last_good
                .lock()
                .map(|(th, at): (f64, std::time::Instant)| (th, at.elapsed().as_secs()));
            let (th, source) = reported_hashrate(outcome.ok(), cached, STALE_GRACE_SECS);
            match source {
                HashrateSource::Measured => {
                    *last_good.lock() = Some((th, std::time::Instant::now()));
                }
                HashrateSource::Stale { age_secs } => tracing::warn!(
                    error = err.unwrap_or_default(),
                    reusing_th = th,
                    age_secs,
                    "local hashrate query FAILED; reusing the last measured value rather than \
                     reporting zero, which would deflate the pool-wide total"
                ),
                HashrateSource::Unavailable => tracing::warn!(
                    error = err.unwrap_or_default(),
                    "local hashrate query FAILED and no recent measurement is available; \
                     reporting 0 TH/s. The pool-wide total is UNDERSTATED by this node's real \
                     hashrate until its database responds again"
                ),
            }
            th
        })
    };

    // Hardware-derived miner capacity. Operator's `network.max_miners` is the
    // ceiling — `measure()` returns `min(calculated, declared)`.
    let cap_breakdown = capacity::measure(Some(config.network.max_miners));
    let effective_max_capacity = cap_breakdown.effective_max;

    // Create shutdown channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Start verification HTTP server
    let rm_for_height = Arc::clone(&round_manager);
    let rm_for_round = Arc::clone(&round_manager);
    let rm_for_miners = Arc::clone(&round_manager);
    let rm_for_elapsed = Arc::clone(&round_manager);

    let mut verification_state = VerificationState::new(
        identity.node_id_hex(),
        env!("CARGO_PKG_VERSION").to_string(),
    );

    // Give the HTTP layer the node's signing key. Without this `can_sign()` is false
    // and every endpoint answers `"signed": false` — which is what the fleet did, for
    // as long as the field has existed. Two things were inert as a result: an
    // identity-bound reachability probe is impossible without a signed reply (H-7),
    // and the H-8 re-derivation defence reaches `ReVerdict::Unverifiable` and records
    // nothing when the target's response carries no signature.
    verification_state = verification_state.with_node_identity(Arc::clone(&identity));

    // Report the node's real configured chain on the status/info endpoints
    // (dashboard + wallets) instead of the historical hardcoded "signet".
    verification_state = verification_state.with_network(config.bitcoin.network);
    // Where pool_sv2 serves the node pool API and where the lister writes its node list, when
    // the config moves them off the installer's defaults (validated loopback above).
    if let Some(api) = config.pool.node_pool_api.clone() {
        verification_state = verification_state.with_node_pool_api(api);
    }
    if let Some(path) = config.pool.node_list_path.clone() {
        verification_state = verification_state.with_node_list_path(path);
    }
    // H-13: the webhook ingest judges every share by its committed tier and requires its 80-byte
    // header; pool_sv2 sends both on every share.
    verification_state = verification_state
        .with_share_tier_bind_height(0)
        .with_share_pow_verify_height(0);
    // The stratum host the API reports to miners.
    if let Some(public_address) = config.network.public_address.clone() {
        verification_state = verification_state.with_stratum_host(public_address);
    }

    // Configure callbacks for health/status endpoints
    // Miner count now comes from share notifications via SRI forwarder
    verification_state = verification_state.with_callbacks(
        move || rm_for_height.current_height(),
        move || rm_for_round.current_round_id(),
        move || {
            rm_for_miners
                .round_stats(rm_for_miners.current_round_id())
                .map(|s| s.miner_count as u32)
                .unwrap_or(0)
        },
    );

    // This node's own realized hashrate, surfaced as `local_hashrate_th`.
    let local_hr_for_route = Arc::clone(&local_hashrate_provider);
    verification_state = verification_state.with_local_hashrate(move || local_hr_for_route());
    // Scope the operator/peer detailed miner list to this node's own miners
    // (shares stored under our `received_by`), so "This Node's Miners" and the
    // /miners/full feed are local.
    verification_state = verification_state.with_local_received_by(self_received_by.clone());
    // Live handle to the template refresh cadence so the dashboard can retune it
    // (10–60s) without restarting the pool.
    verification_state =
        verification_state.with_template_refresh(template_processor.refresh_interval_handle());
    // Current-template snapshot provider for the dashboard visualiser (reads the
    // summary fields under the lock without cloning the full tx set).
    let tp_for_snapshot = Arc::clone(&template_processor);
    verification_state = verification_state
        .with_template_snapshot(move || tp_for_snapshot.current_template_summary());
    // Coinbase breakdown provider: the current template's subsidy split between the treasury
    // base and the miners' pool, and the fees that go to the finder.
    let tp_for_coinbase = Arc::clone(&template_processor);
    verification_state = verification_state
        .with_coinbase_snapshot(move || tp_for_coinbase.current_coinbase_breakdown());

    // Seconds elapsed working the current template, surfaced as
    // `current_round_duration_secs` on the pool-status endpoint so the
    // dashboard's round-progress readout reflects real round timing.
    verification_state = verification_state
        .with_round_elapsed_secs(move || rm_for_elapsed.current_round_elapsed_secs());

    // Advertise this node's hardware-derived capacity via /api/internal/pool-nodes
    // so the colocated translator's load balancer routes by utilisation %.
    verification_state.set_max_capacity(effective_max_capacity);

    // Wire Reaper observability counters through to /api/v1/reaper/status.
    // The processor owns the Arc<ReaperStats>; we hand the dashboard a closure
    // that snapshots it on demand.
    let reaper_stats_for_api = template_processor.reaper_stats();
    verification_state = verification_state.with_reaper_stats(move || {
        serde_json::to_value(reaper_stats_for_api.snapshot()).unwrap_or(serde_json::Value::Null)
    });

    // Pass database and RPC to verification state for API endpoints
    verification_state = verification_state.with_database((*db).clone());
    verification_state = verification_state.with_rpc(Arc::clone(&rpc));

    // Wire node config path for persisting ghost_mode, shroud_enabled, etc.
    verification_state =
        verification_state.with_node_config_path(data_dir.join("node_config.json"));

    // Wire Tor mode status from Ghost Core RPC
    if let Some(ref ts) = tor_status {
        verification_state =
            verification_state.with_tor_status(ts.enabled, ts.onion_address.clone());
    }

    // Wire full node config for config update API
    // This allows the dashboard to modify settings via POST /api/internal/config/update
    verification_state =
        verification_state.with_full_node_config(config.clone(), args.config.clone());
    // #403: the operator-signed config endpoint edits THIS file. Passed explicitly rather than
    // guessed, so a node started with a non-default config cannot have a different one rewritten.
    verification_state = verification_state.with_pool_config_path(args.config.clone());

    // Configure internal API authentication (AUTH4-1 security fix)
    let is_mainnet_auth = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    if let Some(ref secret_hex) = config.network.internal_api_secret {
        match ghost_verification::InternalAuth::from_hex(secret_hex) {
            Ok(auth) => {
                info!("Internal API authentication configured for /api/internal/* and /admin/*");
                verification_state = verification_state.with_internal_auth(auth);
            }
            Err(e) => {
                // H-2: Malformed secret is always fatal — operator intended to configure auth
                return Err(anyhow::anyhow!(
                    "Invalid internal_api_secret: {} — fix or remove the config entry",
                    e
                ));
            }
        }
    } else if is_mainnet_auth {
        // C-1: Mainnet MUST have internal API authentication
        return Err(anyhow::anyhow!(
            "FATAL: network.internal_api_secret is required on mainnet. \
             Generate one with: openssl rand -hex 32"
        ));
    } else {
        warn!(
            "AUTH4-1 WARNING: network.internal_api_secret not configured! \
             Internal endpoints (/api/internal/*, /admin/*) are UNPROTECTED. \
             Generate a secret with: openssl rand -hex 32"
        );
        // Dev/test: on non-mainnet networks, allow the verification server to start
        // without an internal API secret so local rigs can POST to /api/internal/*.
        // Mainnet enforcement is still intact via the normal validator path.
        if !matches!(
            config.bitcoin.network,
            ghost_common::config::BitcoinNetwork::Mainnet
        ) {
            warn!(
                "Dev mode: network != mainnet and no internal_api_secret — allowing insecure internal API for local development only"
            );
            verification_state = verification_state.allow_insecure_internal_api(true);
        }
    }

    // Configure share recorder callback for SRI Pool share notifications
    let rm_for_shares = Arc::clone(&round_manager);
    let identity_for_shares = Arc::clone(&identity);
    let db_for_shares = Arc::clone(&db);
    let network_for_shares = config.bitcoin.network;
    verification_state = verification_state.with_share_recorder(move |share| {
        // Get current round ID for database record
        let round_id = rm_for_shares.current_round_id();

        // Record the share in the current round (in-memory tracking)
        rm_for_shares
            .record_share(&share.miner_id, share.work)
            .map_err(|e| ghost_common::GhostError::Internal(e.to_string()))?;

        // The SV2/SRI layer reports share_hash in big-endian DISPLAY order (PoW leading zeros
        // at the front). CANONICAL STORAGE IS INTERNAL (little-endian) ORDER, zeros at the
        // high-index end, which is what the records and difficulty readers expect.
        let mut share_hash_bytes = [0u8; 32];
        if let Ok(decoded) = hex::decode(&share.share_hash) {
            if decoded.len() == 32 {
                for (i, b) in decoded.iter().rev().enumerate() {
                    share_hash_bytes[i] = *b; // display (big-endian) -> internal (little-endian)
                }
            } else {
                let len = decoded.len().min(32);
                share_hash_bytes[..len].copy_from_slice(&decoded[..len]);
            }
        }
        let canonical_share_hash = hex::encode(share_hash_bytes);

        // Persist share to database for historical tracking and auditing
        let share_record = ghost_storage::models::ShareRecord {
            id: None,
            round_id,
            miner_id: share.miner_id.clone(),
            difficulty: share.work, // SRI reports work as difficulty-adjusted value
            work: share.work,
            share_hash: canonical_share_hash,
            timestamp: share.timestamp as i64,
            received_by: hex::encode(&identity_for_shares.node_id()[..8]),
            // H-13: this used to read "Already validated by SRI Pool", which was a claim about a
            // process on the other side of an HTTP endpoint that anything on the box could call.
            // It is now true of this share specifically: the ingest gate in
            // `VerificationState::record_share` has recomputed sha256d(header) and confirmed it
            // justifies `share.work` before this recorder ever ran.
            valid: true,
        };

        match db_for_shares.insert_share(&share_record) {
            Ok(_) => {
                // Share inserted successfully — update miner cumulative stats
                if let Err(e) = db_for_shares.increment_miner_stats(&share.miner_id, 1, share.work)
                {
                    tracing::warn!(
                        miner_id = %share.miner_id,
                        error = %e,
                        "Failed to increment miner stats"
                    );
                }
            }
            Err(e) => {
                // Log but don't fail - in-memory tracking is primary, DB is for auditing
                // UNIQUE constraint failures are expected (dedup) and don't increment stats
                tracing::warn!(
                    miner_id = %share.miner_id,
                    share_hash = %share.share_hash,
                    error = %e,
                    "Failed to persist share to database"
                );
            }
        }

        // Update miner's payout address in database if provided
        // The payout_address is extracted from user_identity (format: <address>.<worker>)
        if let Some(ref payout_address) = share.payout_address {
            // Node pool: only P2SH, P2WPKH, P2WSH and P2TR are recorded.
            let payee_refused = if payout_address.is_empty() {
                None
            } else {
                ghost_pool::payee_class::accept_payout_address(
                    payout_address,
                    network_for_shares.to_bitcoin_network(),
                )
                .err()
            };
            if let Some(refusal) = payee_refused {
                tracing::warn!(
                    miner_id = %share.miner_id,
                    payout_address = %payout_address,
                    %refusal,
                    "payout address refused for the node pool; not recorded"
                );
            } else if !payout_address.is_empty() {
                if let Err(e) = db_for_shares.update_miner_address(&share.miner_id, payout_address)
                {
                    tracing::warn!(
                        miner_id = %share.miner_id,
                        payout_address = %payout_address,
                        error = %e,
                        "Failed to update miner payout address"
                    );
                } else {
                    tracing::trace!(
                        miner_id = %share.miner_id,
                        payout_address = %payout_address,
                        "Updated miner payout address"
                    );
                }
            }
        }

        tracing::debug!(
            miner_id = %share.miner_id,
            work = share.work,
            round_id = round_id,
            "Share recorded from SRI notification"
        );
        Ok(())
    });

    // Shared slot for the operator-alert dispatcher. The block_found callback is
    // registered here (before `verification_state` is wrapped in an `Arc`, which
    // the dispatcher's live-config closure needs), so it can't capture the
    // dispatcher directly. Instead it captures this slot, which is populated
    // once the dispatcher is built (just after the `Arc::new` below). BlockFound
    // is the one trigger site on a pre-Arc, synchronous callback path.
    let alert_slot: Arc<std::sync::OnceLock<Arc<ghost_verification::alerts::AlertDispatcher>>> =
        Arc::new(std::sync::OnceLock::new());

    // Block-difficulty share: fire the operator alert. The block's coinbase is the job's
    // canonical one (pool_sv2 submits it at once and checks it after, as an alarm); what it paid
    // is settled by the node
    // pool relay when the block enters the best chain.
    {
        let rm_for_bf = Arc::clone(&round_manager);
        let alert_slot_for_bf = Arc::clone(&alert_slot);

        verification_state = verification_state.with_block_found_callback(move |block_info| {
            let round_id = rm_for_bf.current_round_id();
            info!(
                round = round_id,
                share_hash = %block_info.share_hash,
                miner = %block_info.miner_id,
                "Block-difficulty share found"
            );
            // Async, non-blocking. Enable-flag + delivery are handled inside the dispatcher.
            if let Some(dispatcher) = alert_slot_for_bf.get() {
                let dispatcher = Arc::clone(dispatcher);
                let detail = format!(
                    "Block-difficulty share found in round {round_id} (share {}, miner {}).",
                    block_info.share_hash, block_info.miner_id
                );
                tokio::spawn(async move {
                    dispatcher
                        .fire(ghost_verification::alerts::AlertEvent::BlockFound, &detail)
                        .await;
                });
            }
        });
    }

    // Report Ghost Core's liveness on /health, so a node whose Core has died stops claiming to be
    // healthy. `healthy` used to be a literal `true`; on 2026-08-01 vm7 served it for an hour with
    // Core dead underneath and nothing — dashboard, load balancer, operator — could tell.
    //
    // Two template refreshes' worth of silence is the staleness bound: one missed refresh is a
    // hiccup, two in a row means Core is not answering.
    {
        let rpc_for_health = Arc::clone(&rpc);
        let stale_after = (config.pool.template_refresh_ms() / 1000)
            .saturating_mul(2)
            .max(120);
        verification_state =
            verification_state.with_core_health(move || rpc_for_health.core_liveness(stale_after));
    }

    // Wire Prometheus metrics to verification state
    verification_state = verification_state.with_metrics(Arc::clone(&metrics));

    let verification_state = Arc::new(verification_state);

    // Build the operator-alert dispatcher now that the state is an `Arc`. Its
    // config closure reads `full_node_config` on every dispatch, so live edits
    // to `[alerts]` via the config API apply without a restart. All async
    // trigger sites below clone this `Arc`; the block_found callback (registered
    // pre-Arc) reads it via `alert_slot`, populated here.
    let alert_dispatcher = {
        let state_for_alerts = Arc::clone(&verification_state);
        Arc::new(ghost_verification::alerts::AlertDispatcher::new(
            verification_state.node_id.clone(),
            move || {
                state_for_alerts
                    .full_node_config
                    .as_ref()
                    .map(|c| c.read().alerts.clone())
                    .unwrap_or_default()
            },
        ))
    };
    let _ = alert_slot.set(Arc::clone(&alert_dispatcher));

    // ⛔ Say so when nothing will ever be delivered (#985).
    //
    // There are fourteen AlertEvent variants and every one of them is really wired to a trigger —
    // capability drift, low disk, node offline, behind tip, service restart loop, failed login,
    // reorg, block found, and more. But `AlertsConfig.enabled` defaults FALSE and
    // `dispatch_event` returns immediately when it is (alerts.rs:212), so on a node that was never
    // explicitly configured all fourteen detectors fire into nothing and the only trace is a
    // journal line nobody reads.
    //
    // That was invisible to us because our own fleet was configured by hand. It is total for a
    // freshly installed node. An installer cannot invent a delivery endpoint for an operator, so
    // the node itself has to be the thing that says it is deaf — and it has to say it at WARN,
    // every start, because the whole failure mode is silence.
    {
        let alerts_cfg = verification_state
            .full_node_config
            .as_ref()
            .map(|c| c.read().alerts.clone())
            .unwrap_or_default();

        if !alerts_cfg.enabled {
            warn!(
                "ALERTS ARE DISABLED — no node event will reach you. Fourteen detectors \
                 (low disk, node offline, behind tip, capability drift, restart loop, failed \
                 login, …) are wired and will fire into nothing. Set `[alerts] enabled = true` in \
                 pool.toml and configure at least one channel under `[alerts.channels]`."
            );
        } else {
            let ch = &alerts_cfg.channels;
            let push_live = ch.push.enabled && ch.push.webhook_url.is_some();
            let email_live = ch.email.enabled;
            let telegram_live = ch.telegram.enabled;
            if !(push_live || email_live || telegram_live) {
                warn!(
                    "ALERTS ARE ENABLED BUT NO CHANNEL CAN DELIVER — `[alerts] enabled = true` is \
                     set, but no channel under `[alerts.channels]` is both enabled and configured. \
                     Every alert will be computed and then dropped. Configure push                      (`webhook_url`), email, or telegram."
                );
            } else {
                info!(
                    push = push_live,
                    email = email_live,
                    telegram = telegram_live,
                    "Alert delivery active"
                );
            }
        }
    }

    // Register the dispatcher on the verification state so the internal
    // failed-login endpoint (signalled by the dashboard login route) can
    // dispatch the `FailedLogin` alert through the same debouncing dispatcher.
    verification_state.set_alert_dispatcher(Arc::clone(&alert_dispatcher));

    // Get restart signal for monitoring (config update API)
    let restart_signal = verification_state.restart_signal();

    // Start restart signal monitor task
    // When config is updated via API, this triggers graceful shutdown
    let restart_signal_for_monitor = Arc::clone(&restart_signal);
    let shutdown_tx_for_restart = shutdown_tx.clone();
    let alert_dispatcher_for_restart = Arc::clone(&alert_dispatcher);
    let restart_node_id = verification_state.node_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            if restart_signal_for_monitor.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Restart signal received (config update). Initiating graceful shutdown...");
                // Fire the RestartNeeded alert BEFORE broadcasting shutdown so
                // the HTTPS delivery isn't cut short by the graceful-exit path.
                // Fires once (the loop breaks immediately after).
                alert_dispatcher_for_restart
                    .fire(
                        ghost_verification::alerts::AlertEvent::RestartNeeded,
                        &format!(
                            "Node {} is restarting to apply a configuration change.",
                            &restart_node_id[..8.min(restart_node_id.len())]
                        ),
                    )
                    .await;
                let _ = shutdown_tx_for_restart.send(());
                break;
            }
        }
    });
    info!("Restart signal monitor started (for config update API)");

    // Start WebSocket health broadcast task
    let ws_state = Arc::clone(&verification_state.ws_state);
    let rm_for_ws = Arc::clone(&round_manager);
    let state_for_ws = Arc::clone(&verification_state);
    let start_time = std::time::Instant::now();
    let mut ws_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let miner_count = rm_for_ws
                        .round_stats(rm_for_ws.current_round_id())
                        .map(|s| s.miner_count as u32)
                        .unwrap_or(0);
                    let event = ghost_verification::WsEvent::HealthUpdate {
                        block_height: rm_for_ws.current_height(),
                        round_id: rm_for_ws.current_round_id(),
                        miner_count,
                        peer_count: state_for_ws.relay_peers(),
                        uptime_secs: start_time.elapsed().as_secs(),
                    };
                    ws_state.broadcast(event);
                }
                _ = ws_shutdown.recv() => break,
            }
        }
    });

    // The relay-peers monitor (`alert_monitors::spawn_relay_peers_monitor`) is not started: the
    // solo pool has no share-chain relay, so there are no relay peers to count.

    // Start the behind-tip monitor. Edge-triggered `BehindTip` alert when this
    // node's local height lags the best header its Bitcoin node has heard of, or
    // the tip stalls while the headers are ahead. Core's `headers` is the
    // network's view as its Bitcoin peers announce it; sampled every 30 s so the
    // monitor's callback stays synchronous (0 until the first answer → silent).
    {
        let best_headers = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let headers_for_sampler = Arc::clone(&best_headers);
        let rpc_for_headers = Arc::clone(&rpc);
        let mut headers_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Ok(info) = rpc_for_headers.get_blockchain_info().await {
                            headers_for_sampler
                                .store(info.headers, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    _ = headers_shutdown.recv() => break,
                }
            }
        });
        let rm_for_tip = Arc::clone(&round_manager);
        let alerts_for_tip = Arc::clone(&alert_dispatcher);
        ghost_pool::alert_monitors::spawn_behind_tip_monitor(
            alerts_for_tip,
            Arc::clone(&verification_state.chain_health),
            move || rm_for_tip.current_height(),
            move || best_headers.load(std::sync::atomic::Ordering::Relaxed),
            shutdown_tx.subscribe(),
        );
    }

    // Start the update-available monitor. Rate-limited `UpdateAvailable` alert
    // (at most once/day) when the updater's published latest version is newer
    // than the installed one — same version files the dashboard auto-update
    // view reads.
    ghost_pool::alert_monitors::spawn_update_available_monitor(
        Arc::clone(&alert_dispatcher),
        env!("CARGO_PKG_VERSION").to_string(),
        shutdown_tx.subscribe(),
    );

    // Start the mempool-congestion monitor. Edge-triggered `MempoolCongestion`
    // alert (with hysteresis) when ghostd's mempool `usage` nears `maxmempool`,
    // read via the pool's shared RPC client (`getmempoolinfo`).
    ghost_pool::alert_monitors::spawn_mempool_congestion_monitor(
        Arc::clone(&alert_dispatcher),
        Arc::clone(&rpc),
        shutdown_tx.subscribe(),
    );

    // Start the fee-spike monitor. Rate-limited `FeeSpike` alert when the
    // next-block fee rate (`estimatesmartfee`) crosses an absolute threshold or
    // jumps sharply versus a rolling baseline, read via the same RPC client.
    ghost_pool::alert_monitors::spawn_fee_spike_monitor(
        Arc::clone(&alert_dispatcher),
        Arc::clone(&rpc),
        shutdown_tx.subscribe(),
    );

    // Start pool time-series sampler task.
    // Snapshots this node's hashrate + active-miner count (the same
    // accessors the /api/v1/mining/status handler reads) into the bounded
    // in-memory ring on VerificationState every 30s, so /api/v1/pool/series can
    // serve real server-side history instead of a client-side session buffer.
    {
        let state_for_series = Arc::clone(&verification_state);
        let rpc_for_series = Arc::clone(&rpc);
        let tp_for_series = Arc::clone(&template_processor);
        let mut series_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let local_hashrate_th =
                            state_for_series.local_hashrate().unwrap_or(0.0);
                        // Local ghostd mempool tx count via the shared RPC client
                        // (0 if the RPC is briefly unavailable).
                        let mempool_txs = rpc_for_series
                            .get_mempool_info()
                            .await
                            .map(|i| i.size)
                            .unwrap_or(0);
                        // Current block template tx count (incl. coinbase); 0 before
                        // the first template is built.
                        let block_txs = tp_for_series
                            .current_work()
                            .map(|w| w.tx_count as u64)
                            .unwrap_or(0);
                        let sample = ghost_verification::pool_series::PoolSample {
                            t: chrono::Utc::now().timestamp(),
                            mesh_hashrate_th: local_hashrate_th,
                            local_hashrate_th,
                            miners: state_for_series.local_active_miners(),
                            mempool_txs,
                            block_txs,
                        };
                        state_for_series.pool_series.push(sample);
                    }
                    _ = series_shutdown.recv() => break,
                }
            }
        });
        info!("Pool time-series sampler started (30s interval, 24h retention)");
    }

    // Self-uptime recording: the uptime % this node shows on the swarm page.
    let db_for_uptime = Arc::clone(&db);
    let node_id_for_uptime = identity.node_id_hex();
    let mut uptime_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        let mut sample_count: u64 = 0;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = chrono::Utc::now().timestamp();
                    // Also refreshes our own `nodes.last_seen` (#1004).
                    match db_for_uptime.record_self_liveness(&node_id_for_uptime, now) {
                        Ok(_) => {
                            sample_count += 1;
                            // Log every 360 samples (~1 hour) to confirm it's working
                            if sample_count.is_multiple_of(360) {
                                tracing::debug!(
                                    samples = sample_count,
                                    node_id = %&node_id_for_uptime[..8],
                                    "Self-uptime recording checkpoint"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                node_id = %&node_id_for_uptime[..8],
                                "Failed to record self-uptime sample"
                            );
                        }
                    }
                }
                _ = uptime_shutdown.recv() => {
                    tracing::info!(
                        total_samples = sample_count,
                        "Self-uptime recording task shutting down"
                    );
                    break;
                }
            }
        }
    });
    info!(
        node_id = %&node_id_hex[..8],
        interval_secs = 10,
        "Self-uptime recording task started"
    );

    // M-MINE-2: Start rate limit cleanup task for RoundManager
    // Periodically cleans up old rate limit entries to prevent memory growth
    let rm_for_cleanup = Arc::clone(&round_manager);
    let mut rate_limit_cleanup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    rm_for_cleanup.cleanup_rate_limits();
                }
                _ = rate_limit_cleanup_shutdown.recv() => {
                    tracing::info!("Rate limit cleanup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Rate limit cleanup task started (60s interval)");

    // Periodic share pruning — delete shares older than 24 hours, run every hour
    let db_for_pruning = Arc::clone(&db);
    let mut share_prune_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const PRUNE_INTERVAL_SECS: u64 = 3600;
        const SHARE_RETENTION_SECS: i64 = 24 * 3600;

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    match db_for_pruning.delete_old_shares(SHARE_RETENTION_SECS) {
                        Ok(0) => {}
                        Ok(count) => {
                            tracing::info!(deleted = count, "Pruned old shares from database");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to prune old shares");
                        }
                    }
                }
                _ = share_prune_shutdown.recv() => {
                    tracing::info!("Share pruning task shutting down");
                    break;
                }
            }
        }
    });
    info!("Share pruning task started (hourly, 24h retention)");

    // Periodic database maintenance — prune health_pings, uptime_samples, challenges,
    // verifications, votes + WAL checkpoint + VACUUM. Runs every hour.
    let db_for_maintenance = Arc::clone(&db);
    let mut maintenance_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const MAINTENANCE_INTERVAL_SECS: u64 = 3600;

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
        // Skip the first immediate tick — let the node fully start up first
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let config = ghost_storage::database::MaintenanceConfig::default();
                    // Off the runtime (#1034): the pass is a chain of blocking database calls,
                    // and run inline it parked one of a 2-CPU node's two tokio workers for its
                    // whole length.
                    let db = Arc::clone(&db_for_maintenance);
                    match tokio::task::spawn_blocking(move || db.run_maintenance(config)).await {
                        Ok(Ok(result)) => {
                            tracing::info!(
                                rounds = result.rounds_deleted,
                                uptime = result.uptime_deleted,
                                // Without this the two numbers that matter cannot be paired.
                                // MEASURED on vm1, 2026-10-04: two consecutive passes each
                                // deleted ~5,280 rows and `db_size_mb` read 2433 both times —
                                // pruning working perfectly and the file not shrinking by a byte.
                                // `pages_reclaimed` is what tells those two states apart.
                                pages_reclaimed = result.pages_reclaimed,
                                db_size_mb = result.db_size_bytes / (1024 * 1024),
                                "Database maintenance complete"
                            );
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "Database maintenance failed");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Database maintenance task did not complete");
                        }
                    }
                }
                _ = maintenance_shutdown.recv() => {
                    tracing::info!("Database maintenance task shutting down");
                    break;
                }
            }
        }
    });
    info!("Database maintenance task started (hourly)");

    // M5: Daily database backup task
    let db_for_backup = Arc::clone(&db);
    let backup_dir = data_dir.clone();
    let mut backup_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        const BACKUP_INTERVAL_SECS: u64 = 86400; // 24 hours

        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(BACKUP_INTERVAL_SECS));
        // Skip first immediate tick — let node start fully first
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let backup_path = backup_dir.join("ghost_backup.db");
                    match db_for_backup.backup(&backup_path) {
                        Ok(()) => {
                            tracing::info!(path = ?backup_path, "Daily database backup complete");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "Daily database backup failed");
                        }
                    }
                }
                _ = backup_shutdown.recv() => {
                    tracing::info!("Database backup task shutting down");
                    break;
                }
            }
        }
    });
    info!("Database backup task started (daily)");

    // Automatic scheduled encrypted-backup task. Secure-by-default: it idles and
    // writes nothing until an operator enables `[backup]` in pool.toml (or via
    // the dashboard). When enabled it reuses the SAME `Database::backup`
    // (VACUUM INTO) routine the manual backup uses — so the artifact inherits
    // the database's SQLCipher encryption — writing a timestamped file into the
    // configured target dir, pruning to `retention`, and recording last-run
    // status for the dashboard. The live schedule is re-read from the shared
    // full_node_config each tick, so enable/interval/retention/target_dir edits
    // take effect without a node restart.
    {
        let db_for_sched = Arc::clone(&db);
        let state_for_sched = Arc::clone(&verification_state);
        let mut sched_shutdown = shutdown_tx.subscribe();
        tokio::spawn(async move {
            // Coarse poll cadence: the loop wakes on this fixed interval and only
            // runs a backup once the configured period has elapsed. 60s keeps the
            // task off any hot path while still honouring hourly custom periods.
            const CHECK_SECS: u64 = 60;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(CHECK_SECS));
            // Let the node finish starting before the first check/run.
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Snapshot the live schedule (may have changed via the API).
                        let schedule = match state_for_sched.full_node_config.as_ref() {
                            Some(cfg) => cfg.read().backup.clone(),
                            None => continue,
                        };
                        if !schedule.enabled {
                            continue;
                        }
                        let now_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let last_run = state_for_sched.backup_status.read().last_run_unix;
                        if !ghost_common::config::backup_is_due(
                            last_run,
                            now_unix,
                            schedule.interval.period_secs(),
                        ) {
                            continue;
                        }

                        let target_dir = std::path::PathBuf::from(&schedule.target_dir);
                        let filename =
                            ghost_common::config::BackupSchedule::artifact_filename(now_unix);
                        let backup_path = target_dir.join(&filename);
                        let retention = schedule.effective_retention();

                        // Blocking DB + filesystem work off the async worker.
                        let db_run = Arc::clone(&db_for_sched);
                        let dir_run = target_dir.clone();
                        let path_run = backup_path.clone();
                        let result = tokio::task::spawn_blocking(
                            move || -> Result<(), String> {
                                std::fs::create_dir_all(&dir_run)
                                    .map_err(|e| format!("create target dir: {e}"))?;
                                db_run.backup(&path_run).map_err(|e| e.to_string())?;
                                // Prune old artifacts down to the retention window.
                                let mut names: Vec<String> = Vec::new();
                                if let Ok(entries) = std::fs::read_dir(&dir_run) {
                                    for entry in entries.flatten() {
                                        if let Some(name) = entry.file_name().to_str() {
                                            if name.starts_with("ghost-backup-")
                                                && name.ends_with(".db")
                                            {
                                                names.push(name.to_string());
                                            }
                                        }
                                    }
                                }
                                for stale in ghost_common::config::backups_to_prune(
                                    names, retention,
                                ) {
                                    let _ = std::fs::remove_file(dir_run.join(stale));
                                }
                                Ok(())
                            },
                        )
                        .await;

                        let finished_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(now_unix);
                        let mut status = state_for_sched.backup_status.write();
                        status.last_run_unix = Some(finished_unix);
                        match result {
                            Ok(Ok(())) => {
                                status.last_success = Some(true);
                                status.last_path =
                                    Some(backup_path.to_string_lossy().to_string());
                                status.last_error = None;
                                tracing::info!(
                                    path = ?backup_path,
                                    "Scheduled encrypted backup complete"
                                );
                            }
                            Ok(Err(e)) => {
                                status.last_success = Some(false);
                                status.last_error = Some(e.clone());
                                tracing::warn!(error = %e, "Scheduled backup failed");
                            }
                            Err(e) => {
                                let msg = format!("backup task join error: {e}");
                                status.last_success = Some(false);
                                status.last_error = Some(msg.clone());
                                tracing::warn!(error = %msg, "Scheduled backup task failed");
                            }
                        }
                    }
                    _ = sched_shutdown.recv() => {
                        tracing::info!("Scheduled backup task shutting down");
                        break;
                    }
                }
            }
        });
        info!("Scheduled encrypted-backup task started (idle until enabled)");
    }

    // Clone ws_state for event handlers before moving verification_state
    let _verification_state_for_ws = Arc::clone(&verification_state);

    let http_port = config.network.http_port;
    let verification_https_port = config.network.verification_https_port;
    // Build TLS config for the verification HTTPS listener. Resolution order:
    //   1. Operator-managed PEM files (`tls.cert_path` + `tls.key_path`)
    //   2. Identity-derived cert (cert pubkey == node_id; mainnet-allowed)
    //   3. Random self-signed (testnet/dev only)
    //
    // Plain HTTP on `http_port` is ALWAYS bound — it serves SRI's share
    // webhook (loopback), nginx public-API upstream, and the local dashboard.
    // TLS is added on a SEPARATE listener (`verification_https_port`) used
    // only by cross-VM peer challenges, so SRI/nginx/dashboard never see TLS.
    let has_explicit_tls = config.network.tls.cert_path.is_some();
    let is_mainnet_tls = config.bitcoin.network == ghost_common::config::BitcoinNetwork::Mainnet;
    // Identity-derived TLS works only with LocalSigner; HSM/KMS need operator PEMs.
    let identity_secret_for_tls: Option<[u8; 32]> = identity
        .signer()
        .as_any()
        .downcast_ref::<ghost_common::signer::LocalSigner>()
        .map(|s| s.signing_key_bytes());

    let tls_server_config = if has_explicit_tls {
        match ghost_common::tls::build_server_config_for_network(
            &config.network.tls,
            is_mainnet_tls,
        ) {
            Ok(tls) => {
                info!(
                    "TLS configured (operator PEM) for verification server on port {}",
                    http_port
                );
                Some(tls)
            }
            Err(e) => {
                error!(
                    error = %e,
                    "Operator PEM TLS load failed; verification mesh will not start cleanly"
                );
                None
            }
        }
    } else if let Some(secret) = identity_secret_for_tls {
        match ghost_common::tls::build_server_config_with_identity(
            &config.network.tls,
            &secret,
            config.network.public_address.as_deref(),
        ) {
            Ok(tls) => {
                info!(
                    "TLS configured (identity-derived, cert pubkey = node_id) on port {}",
                    http_port
                );
                Some(tls)
            }
            Err(e) => {
                error!(
                    error = %e,
                    "Identity-derived TLS build failed; falling back to plain HTTP"
                );
                None
            }
        }
    } else if is_mainnet_tls {
        // HSM/KMS without operator PEMs is a misconfiguration on mainnet.
        match ghost_common::tls::build_server_config_for_network(
            &config.network.tls,
            is_mainnet_tls,
        ) {
            Ok(tls) => Some(tls),
            Err(e) => {
                error!(
                    error = %e,
                    "Mainnet TLS unavailable: HSM/KMS signers must supply tls.cert_path + tls.key_path"
                );
                None
            }
        }
    } else {
        info!("No TLS configured — verification HTTPS listener will not start");
        None
    };

    // Always bind plain HTTP on `http_port`. Loopback-only consumers (SRI
    // share webhook on 127.0.0.1, nginx public-API upstream, the local
    // dashboard) all expect plain HTTP and have no TLS-skip-verify escape
    // hatch. Cross-VM peer challenges use the HTTPS listener below instead.
    let state_for_http = Arc::clone(&verification_state);
    tokio::spawn(async move {
        if let Err(e) = start_server(state_for_http, http_port, None).await {
            error!(error = %e, "Verification HTTP server error (port {})", http_port);
        }
    });
    info!("HTTP API listening on port {} (plain HTTP)", http_port);

    // Additionally bind HTTPS on `verification_https_port` for the inter-peer
    // verification mesh — only the verification client uses this port. Cert
    // is identity-derived (pubkey == node_id), peers pin against the
    // registered node_id, no CA / DNS / Let's Encrypt required.
    if let Some(tls) = tls_server_config {
        let state_for_https = Arc::clone(&verification_state);
        tokio::spawn(async move {
            // Loopback only: this listener served the old mesh's peer challenges, and nothing off
            // the machine uses it on a node pool node.
            if let Err(e) = start_server_on(
                state_for_https,
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                verification_https_port,
                Some(tls),
            )
            .await
            {
                error!(
                    error = %e,
                    "Verification HTTPS server error (port {})",
                    verification_https_port
                );
            }
        });
        info!(
            "Verification HTTPS listening on 127.0.0.1:{} (identity-pinned TLS)",
            verification_https_port
        );
    }

    // Low-disk monitor on the data partition (edge-triggered LowDisk alerts).
    ghost_pool::alert_monitors::spawn_low_disk_monitor(
        config.storage.db_path.clone(),
        Arc::clone(&alert_dispatcher),
    );

    // Subscribe to template events BEFORE starting the processor to avoid race condition
    // (the processor fires NewWork immediately on first refresh)
    let mut template_events_early = template_processor.subscribe();

    // Start template processor
    let tp = Arc::clone(&template_processor);
    let mut template_shutdown = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            result = tp.start() => {
                if let Err(e) = result {
                    error!(error = %e, "Template processor error");
                }
            }
            _ = template_shutdown.recv() => {}
        }
    });
    info!("Template processor started");

    // Note: Native stratum server removed - SRI handles all miner connections via TDP

    // Start Template Distribution Protocol server (for SRI pool integration)
    if args.tdp_enabled {
        // Load node key bytes for TDP Noise authentication
        // The key file contains 32 bytes of private key (+ optional 12 bytes PoW proof)
        let key_path = data_dir.join("node.key");
        let key_bytes = std::fs::read(&key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read node key for TDP: {}", e))?;

        // HIGH-6: Proper error handling instead of panic on short key file
        if key_bytes.len() < 32 {
            return Err(anyhow::anyhow!(
                "Node key file '{}' is too short: expected at least 32 bytes, got {}. \
                 Generate a new key with: ghost-mining --generate-identity",
                key_path.display(),
                key_bytes.len()
            ));
        }
        let tdp_secret_key: [u8; 32] = key_bytes[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Node key slice conversion failed"))?;

        // L-26: Use proper error handling instead of expect()
        let mut tdp_config = TdpConfig::new(tdp_secret_key).map_err(|e| {
            anyhow::anyhow!(
                "L-26: Invalid TDP secret key from node key file '{}': {}. \
                 The key may be all zeros or outside the valid secp256k1 scalar range. \
                 Regenerate with: ghost-mining --generate-identity",
                key_path.display(),
                e
            )
        })?;
        tdp_config.port = args.tdp_port;
        tdp_config.listen_addr = args.tdp_bind.to_string();
        tdp_config.max_connections = 10;
        tdp_config.timeout_secs = 30;

        info!(
            "TDP authority public key: {} (use this in SRI pool config)",
            tdp_config.authority_pubkey_base58()
        );

        let tdp_server = TemplateDistributionServer::new(
            tdp_config,
            Arc::clone(&template_processor),
            shutdown_tx.subscribe(),
        );

        tokio::spawn(async move {
            if let Err(e) = tdp_server.run().await {
                error!(error = %e, "TDP server error");
            }
        });

        info!(
            "TDP server listening on {}:{} (Template Distribution Protocol for SRI pool)",
            args.tdp_bind, args.tdp_port
        );
    }

    // Start ZMQ block watcher with reorg detection (if configured)
    if let Some(ref zmq_endpoint) = config.bitcoin.zmq_hashblock {
        let rm = Arc::clone(&round_manager);
        let tp = Arc::clone(&template_processor);

        // Use ZmqSubscriber for both block notifications and reorg detection
        // Derive sequence endpoint from hashblock (28332 -> 28334 typically)
        let sequence_endpoint = config.bitcoin.zmq_sequence.clone().or_else(|| {
            // Auto-derive sequence endpoint: tcp://127.0.0.1:28332 -> tcp://127.0.0.1:28334
            zmq_endpoint.replace(":28332", ":28334").into()
        });

        let zmq_config = ZmqConfig {
            hashblock_endpoint: Some(zmq_endpoint.clone()),
            hashtx_endpoint: None,
            rawblock_endpoint: None,
            rawtx_endpoint: None,
            sequence_endpoint: sequence_endpoint.clone(),
        };

        let zmq_subscriber = ZmqSubscriber::new(zmq_config).map_err(|e| {
            anyhow::anyhow!(
                "ZMQ security validation failed: {}. Only localhost endpoints are allowed.",
                e
            )
        })?;
        let mut block_rx = zmq_subscriber.subscribe_blocks();

        // Start block event handler for new blocks
        tokio::spawn(async move {
            // `Lagged` is recoverable; only `Closed` is terminal (#984). Exiting on a lag would
            // stop this node reacting to new blocks at all, silently.
            loop {
                let block_hash = match block_rx.recv().await {
                    Ok(h) => h,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            skipped,
                            "ZMQ block consumer lagged — block notifications dropped; continuing"
                        );
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("ZMQ block channel closed — block consumer stopping");
                        break;
                    }
                };
                info!(hash = %block_hash, "New block detected via ZMQ");

                // End current round
                if let Some(summary) = rm.end_round() {
                    info!(
                        round = summary.round_id,
                        miners = summary.miner_count,
                        work = summary.total_miner_work,
                        "Round ended"
                    );
                }

                // Fast changeover: publish a coinbase-only (empty) template for
                // the new tip immediately so SV1/SV2 miners start hashing the new
                // block with zero transaction-assembly latency, then build and
                // swap in the full template. A block found in the sub-second gap
                // is a valid empty block (subsidy only).
                if let Err(e) = tp.publish_empty_template().await {
                    warn!(error = %e, "Failed to publish empty template on new block");
                }
                // Full template (forced — the empty one already bumped the height).
                if let Err(e) = tp.refresh_template_forced().await {
                    error!(error = %e, "Failed to refresh full template on new block");
                }
            }
        });

        // Start reorg handler (subscribes to block disconnect events). Wire the
        // operator-alert dispatcher so the existing reorg-detection point also
        // fires a `ReorgDetected` alert (gated on the operator's event flag).
        let block_events = zmq_subscriber.subscribe_block_events();
        let rm_for_reorg = Arc::clone(&round_manager);
        let reorg_handler = ReorgHandler::new(Arc::clone(&db), ReorgConfig::default())
            .with_alert_dispatcher(Arc::clone(&alert_dispatcher))
            // Record each detected reorg into the shared chain-health ring so the
            // Sync page's Chain Health view can display it (not just alert).
            .with_chain_health(Arc::clone(&verification_state.chain_health))
            .with_height_getter(move || rm_for_reorg.current_height());
        reorg_handler.start(block_events);
        info!("ZMQ block watcher connected to {}", zmq_endpoint);
        if let Some(seq_ep) = sequence_endpoint {
            info!("ZMQ reorg detection connected to {}", seq_ep);
        }

        // H-8 SECURITY: Store ZMQ subscriber in static OnceLock instead of leaking via mem::forget.
        // This keeps it alive for the program lifetime while allowing proper cleanup on exit.
        if ZMQ_SUBSCRIBER.set(zmq_subscriber).is_err() {
            warn!("ZMQ subscriber already initialized - this should not happen");
        }
    }

    // Handle template events for round management
    // (subscription was created earlier before template processor started)
    // Note: Job notifications to miners now handled by SRI via TDP
    let rm_notify = Arc::clone(&round_manager);
    // Persist each round at start so the `rounds` table carries its block
    // height. The best-hash per-window queries LEFT JOIN rounds to resolve a
    // share's block height; previously rounds were only ever written by the
    // payout path (block-found), which almost never fires, so every per-window
    // best share reported a null block height.
    let db_for_rounds = Arc::clone(&db);
    tokio::spawn(async move {
        // `Lagged` is recoverable; only `Closed` is terminal (#984).
        loop {
            let event = match template_events_early.recv().await {
                Ok(event) => event,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        skipped,
                        "Template-event consumer lagged — template events dropped; continuing"
                    );
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!("Template-event channel closed — consumer stopping");
                    break;
                }
            };
            match event {
                TemplateEvent::NewWork { job_id: _, height } => {
                    // Start new round (SRI gets jobs via TDP automatically)
                    let round_id = rm_notify.start_round(height);

                    // Persist the round (round_id → block_height) so the
                    // best-hash per-window join can resolve a share's block
                    // height. INSERT OR IGNORE: the payout path later upserts
                    // the block-outcome columns onto this row if a block is
                    // found for the round.
                    let round_record = ghost_storage::RoundRecord {
                        round_id,
                        block_height: height,
                        block_hash: None,
                        start_time: chrono::Utc::now().timestamp(),
                        end_time: None,
                        total_shares: 0,
                        total_work: 0.0,
                        winning_miner: None,
                        found_by_node: None,
                        payout_status: ghost_storage::PayoutStatus::Active,
                        subsidy_sats: None,
                        tx_fees_sats: None,
                    };
                    if let Err(e) = db_for_rounds.create_round_if_not_exists(&round_record) {
                        warn!(round_id = round_id, error = %e, "Failed to persist round at start");
                    }
                }
                TemplateEvent::TransactionsFiltered {
                    original_count,
                    filtered_count,
                    removed_fees,
                } => {
                    info!(
                        original = original_count,
                        filtered = filtered_count,
                        removed_fees = removed_fees,
                        "BUDS filtering applied"
                    );
                }
                TemplateEvent::FetchFailed { error } => {
                    warn!(error = %error, "Template fetch failed");
                }
            }
        }
    });

    // Note: Stratum events now come from SRI, not ghost-mining
    // WebSocket broadcast for miner events would need SRI integration

    // Print startup summary
    info!("════════════════════════════════════════════════════════════════");
    info!("Ghost Pool is ready!");
    info!("  Stratum:    via SRI (connect to TDP)");
    if args.tdp_enabled {
        info!("  TDP:        {}:{}", args.tdp_bind, args.tdp_port);
    }
    info!("  HTTP API:   0.0.0.0:{}", http_port);
    info!("  Policy:     {}", policy.name);
    if let Some(ref ts) = tor_status {
        if ts.enabled {
            info!(
                "  Tor:        active ({})",
                ts.onion_address.as_deref().unwrap_or("pending")
            );
        }
    }
    info!("════════════════════════════════════════════════════════════════");

    // Verify template processor has work (for TDP job delivery)
    {
        let tp_check = Arc::clone(&template_processor);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match tp_check.current_work() {
                Some(work) => {
                    info!(
                        height = work.height,
                        job_id = %work.job_id,
                        "STARTUP CHECK: Template processor has work available"
                    );
                }
                None => {
                    error!("STARTUP CHECK: Template processor has NO work - SRI won't receive templates!");
                }
            }
        });
    }

    // Wait for shutdown signal (ctrl+c, SIGTERM, or restart signal from config update)
    let mut shutdown_rx = shutdown_tx.subscribe();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT, shutting down Ghost Pool...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down Ghost Pool...");
        }
        _ = shutdown_rx.recv() => {
            // Shutdown triggered by restart signal monitor
            if restart_signal.load(std::sync::atomic::Ordering::SeqCst) {
                info!("Shutting down for restart (config update)...");
            } else {
                info!("Shutting down Ghost Pool...");
            }
        }
    }

    // Send shutdown signal to all tasks
    let _ = shutdown_tx.send(());

    // H-9 SECURITY: Allow graceful shutdown period for spawned tasks.
    // Tasks subscribe to shutdown_tx and exit when signaled. This gives them
    // time to complete in-flight operations (save state, close connections).
    // 5 seconds is sufficient for orderly cleanup without blocking restart.
    info!("Waiting up to 5 seconds for tasks to complete...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Cleanup
    template_processor.stop();

    // Checkpoint WAL and clean up database files
    if let Err(e) = db.shutdown() {
        warn!("Database shutdown error (non-fatal): {}", e);
    }

    // Check if this was a restart request
    if restart_signal.load(std::sync::atomic::Ordering::SeqCst) {
        info!(
            "Ghost Pool shutdown complete. Exiting with code {} for systemd restart.",
            EXIT_CODE_RESTART
        );
        std::process::exit(EXIT_CODE_RESTART);
    }

    info!("Ghost Pool shutdown complete");
    Ok(())
}

/// Expand ~ in path
fn expand_path(path: &std::path::Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(PathBuf::from(home).join(stripped))
    } else {
        Ok(path.to_path_buf())
    }
}

/// Build the pool template-reaper config from the operator's per-vector
/// settings. When the master switch is off, every detector is disabled.
/// Otherwise each detector and threshold maps straight through to the
/// `ghost_reaper::ReaperConfig` field that enforces it. Node-only vectors
/// (`reject_opreturn`, `reject_runestone`) have no pool-side equivalent and are
/// intentionally not mapped here — the Rust reaper bounds OP_RETURN via the
/// `max_op_return_bytes` threshold and has no Runestone detector.
/// Build the enforced `ghost_policy::PolicyProfile` from an operator's
/// `[policy].custom` config block. This is the source of truth the template
/// builder enforces per-field (tiers, content toggles, size limits) when the
/// operator selects the `Custom` profile.
fn policy_profile_from_custom(custom: &ghost_common::config::CustomPolicyConfig) -> PolicyProfile {
    // Map the config-crate BudsTier enum onto the ghost_buds tier the policy
    // engine/classifier use.
    let allowed_tiers = custom
        .allowed_tiers
        .iter()
        .map(|t| match t {
            ghost_common::config::BudsTier::T0 => ghost_buds::BudsTier::T0,
            ghost_common::config::BudsTier::T1 => ghost_buds::BudsTier::T1,
            ghost_common::config::BudsTier::T2 => ghost_buds::BudsTier::T2,
            ghost_common::config::BudsTier::T3 => ghost_buds::BudsTier::T3,
        })
        .collect();

    PolicyProfile {
        name: "custom".to_string(),
        description: "Operator-defined custom policy".to_string(),
        allowed_tiers,
        max_op_return_size: custom.max_op_return_size,
        max_witness_per_input: custom.max_witness_per_input,
        max_tx_outputs: custom.max_tx_outputs,
        max_tx_size: custom.max_tx_size,
        allow_inscriptions: custom.allow_inscriptions,
        allow_runes: custom.allow_runes,
        allow_brc20: custom.allow_brc20,
        min_fee_rate: custom.min_fee_rate,
        t0_priority_boost: 1.0,
    }
}

fn reaper_config_from_settings(s: &ReaperSettings) -> ReaperConfig {
    if !s.enabled {
        return ReaperConfig::disabled();
    }
    ReaperConfig {
        enabled: true,
        reject_inscription_envelope: s.reject_inscription,
        reject_drop_stuffing: s.reject_dropstuffing,
        reject_fake_pubkeys: s.reject_fakepubkey,
        reject_annex: s.reject_annex,
        reject_unreachable_code: s.reject_unreachable_code,
        max_op_return_bytes: s.max_op_return_bytes,
        min_drop_data_size: s.min_drop_size,
        reject_excess_witness: s.reject_excess_witness,
        min_excess_witness_bytes: s.min_excess_witness_bytes,
        reject_legacy_data_stuffing: s.reject_legacy_data_stuffing,
        legacy_max_push_bytes: s.legacy_max_push_bytes,
        validate_pubkey_curve_point: s.validate_pubkey_curve_point,
    }
}

/// Load configuration from file
/// `--check-config`: report keys this binary does not understand.
///
/// The oracle is `ignored_config_keys`, which round-trips the file through
/// `NodeConfig` and diffs written-vs-understood, so the struct is its own
/// source of truth and this cannot drift from it the way a hand-maintained
/// list of dead key names does.
///
/// ⚠ A missing file is an ERROR here, unlike `load_config`, which falls back to
/// defaults. A check that silently passes on a path that does not exist is a
/// check that cannot fail.
fn handle_check_config(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        anyhow::bail!("no config file at {} — nothing to check", path.display());
    }
    let raw = std::fs::read_to_string(path)?;
    match ghost_common::config::ignored_config_keys(&raw) {
        Err(e) => anyhow::bail!("{}: {e}", path.display()),
        Ok(keys) if keys.is_empty() => {
            println!("{}: ok — every key is understood", path.display());
            Ok(())
        }
        Ok(keys) => {
            println!(
                "{}: {} key(s) NOT understood by this binary:",
                path.display(),
                keys.len()
            );
            for k in &keys {
                println!("  {k}");
            }
            anyhow::bail!("config carries {} unknown key(s)", keys.len())
        }
    }
}

fn load_config(path: &std::path::Path) -> Result<NodeConfig> {
    let mut config = if path.exists() {
        let content = std::fs::read_to_string(path)?;

        let config: NodeConfig = toml::from_str(&content)?;

        // Check config file permissions — fails on mainnet if world-readable
        ghost_common::config::validate_config_permissions(path, Some(&config.bitcoin.network))
            .map_err(|e| anyhow::anyhow!(e))?;

        config
    } else {
        info!("No config file found at {}, using defaults", path.display());
        NodeConfig::default()
    };

    // Ghost Mode builds near-empty blocks and forfeits all transaction-fee income, so a pool
    // node must never run it. If a config file sets it, it is disabled and the change is logged
    // loudly rather than silently allowed.
    if let Some(warning) = config.reconcile_ghost_mode_mining_exclusion() {
        warn!("{}", warning);
    }

    Ok(config)
}

/// Parse a log level string into a tracing Level
/// Build the log filter from the `--log-level` argument and `RUST_LOG`.
///
/// `RUST_LOG` wins when it is set, and it takes full `tracing` directives, so
/// `RUST_LOG=info,ghost_pool::round=debug` turns up one module and leaves the rest at info.
///
/// The flat `LevelFilter` this replaces could not express that. Any per-target string fell through
/// [`parse_log_level`]'s catch-all arm and silently became `INFO`, so the only way to see a
/// `debug!` on a live node was to turn the whole binary to debug — on a node ingesting ~200
/// shares/min, against the 30 GB disks vm5-7 run, that is not a thing you can safely do. #583 went
/// weeks without a diagnosis for exactly this reason: the evidence existed and could not be reached.
fn build_log_filter(arg_level: &str, rust_log: Option<&str>) -> tracing_subscriber::EnvFilter {
    let default = tracing_subscriber::filter::LevelFilter::from_level(parse_log_level(arg_level));
    let directives = rust_log.map(str::trim).filter(|s| !s.is_empty());
    tracing_subscriber::EnvFilter::builder()
        .with_default_directive(default.into())
        // Lossy: a fat-fingered RUST_LOG drops the bad directive instead of refusing to boot.
        .parse_lossy(directives.unwrap_or(""))
}

fn parse_log_level(s: &str) -> Level {
    match s.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

/// Resolve the effective signer configuration from config and defaults
fn resolve_signer_path(
    config_signer: &Option<SignerConfig>,
    config_key_path: &std::path::Path,
    default_key_path: &std::path::Path,
) -> Result<SignerConfig> {
    match config_signer {
        Some(cfg) => Ok(cfg.clone()),
        None => {
            let cfg_key_path = expand_path(config_key_path)?;
            if cfg_key_path.exists() {
                Ok(SignerConfig::Local {
                    key_path: cfg_key_path,
                })
            } else {
                Ok(SignerConfig::Local {
                    key_path: default_key_path.to_path_buf(),
                })
            }
        }
    }
}

#[cfg(test)]
mod hashrate_reporting_tests {
    use super::{reported_hashrate, HashrateSource};

    /// A node that genuinely has no miners reports zero, and that zero is REAL.
    ///
    /// The distinction this whole function exists for: an idle node's query succeeds with 0.0 and
    /// must not be papered over with a stale value.
    #[test]
    fn a_successful_zero_is_reported_as_measured() {
        let (th, src) = reported_hashrate(Some(0.0), Some((94.0, 5)), 600);
        assert_eq!(
            th, 0.0,
            "a real zero must not be replaced by a cached value"
        );
        assert_eq!(src, HashrateSource::Measured);
    }

    /// A FAILED query must not be reported as zero while a recent measurement exists.
    ///
    /// This is the ghost-vm5 case: 94 TH/s behind a stalled database. Reporting 0 deflated the
    /// pool-wide total by 88% and logged nothing at all.
    #[test]
    fn a_failed_query_reuses_the_last_measurement_instead_of_reporting_zero() {
        let (th, src) = reported_hashrate(None, Some((94.13, 42)), 600);
        assert_eq!(th, 94.13, "a database failure must not read as 'no miners'");
        assert_eq!(src, HashrateSource::Stale { age_secs: 42 });
    }

    /// Stale-forever is its own lie. Past the grace period it reports zero and says so.
    #[test]
    fn a_measurement_older_than_the_grace_period_is_not_reused() {
        let (th, src) = reported_hashrate(None, Some((94.13, 601)), 600);
        assert_eq!(th, 0.0);
        assert_eq!(
            src,
            HashrateSource::Unavailable,
            "an ancient reading must be surfaced as unavailable, not presented as current"
        );
    }

    /// A failure with nothing cached is unavailable — reported as zero, but flagged.
    #[test]
    fn a_failure_with_no_history_is_flagged_unavailable() {
        let (th, src) = reported_hashrate(None, None, 600);
        assert_eq!(th, 0.0);
        assert_eq!(src, HashrateSource::Unavailable);
    }

    /// Exactly at the boundary the cached value is still good — an off-by-one here silently
    /// switches a healthy node to reporting zero.
    #[test]
    fn the_grace_boundary_is_inclusive() {
        let (th, src) = reported_hashrate(None, Some((12.0, 600)), 600);
        assert_eq!(th, 12.0);
        assert_eq!(src, HashrateSource::Stale { age_secs: 600 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ── reaper_config_from_settings ──────────────────────────────────

    #[test]
    fn test_reaper_config_master_off_disables_all() {
        let s = ReaperSettings {
            enabled: false,
            ..Default::default()
        };
        let cfg = reaper_config_from_settings(&s);
        assert!(!cfg.enabled);
    }

    #[test]
    fn test_reaper_config_maps_per_vector() {
        let s = ReaperSettings {
            enabled: true,
            reject_inscription: false,
            reject_annex: false,
            reject_legacy_data_stuffing: false,
            max_op_return_bytes: 40,
            min_drop_size: 64,
            ..Default::default()
        };
        let cfg = reaper_config_from_settings(&s);
        assert!(cfg.enabled);
        // disabled vectors map through
        assert!(!cfg.reject_inscription_envelope);
        assert!(!cfg.reject_annex);
        assert!(!cfg.reject_legacy_data_stuffing);
        // untouched vectors stay on
        assert!(cfg.reject_drop_stuffing);
        assert!(cfg.reject_fake_pubkeys);
        assert!(cfg.reject_unreachable_code);
        assert!(cfg.reject_excess_witness);
        // thresholds map (canonical min_drop_size -> min_drop_data_size)
        assert_eq!(cfg.max_op_return_bytes, 40);
        assert_eq!(cfg.min_drop_data_size, 64);
        // valid for the analyzer
        assert!(cfg.validate().is_ok());
    }

    // ── expand_path ──────────────────────────────────────────────────

    #[test]
    fn expand_path_tilde_prefix() {
        let home = std::env::var("HOME").unwrap();
        let result = expand_path(Path::new("~/foo")).unwrap();
        assert_eq!(result, PathBuf::from(home).join("foo"));
    }

    #[test]
    fn expand_path_absolute_unchanged() {
        let result = expand_path(Path::new("/absolute/path")).unwrap();
        assert_eq!(result, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn expand_path_relative_unchanged() {
        let result = expand_path(Path::new("relative/path")).unwrap();
        assert_eq!(result, PathBuf::from("relative/path"));
    }

    #[test]
    fn expand_path_tilde_deeply_nested() {
        let home = std::env::var("HOME").unwrap();
        let result = expand_path(Path::new("~/deeply/nested/path")).unwrap();
        assert_eq!(result, PathBuf::from(home).join("deeply/nested/path"));
    }

    #[test]
    fn expand_path_tilde_alone() {
        // strip_prefix("~/") doesn't match bare "~", so returned unchanged
        let result = expand_path(Path::new("~")).unwrap();
        assert_eq!(result, PathBuf::from("~"));
    }

    // ── load_config ──────────────────────────────────────────────────

    #[test]
    fn load_config_missing_file_returns_defaults() {
        let result = load_config(Path::new("/nonexistent/ghost.toml")).unwrap();
        let default = NodeConfig::default();
        assert_eq!(result.pool.pool_name, default.pool.pool_name);
    }

    #[test]
    fn load_config_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ghost.toml");
        // Serialize the default config, then override a field
        let mut default = NodeConfig::default();
        default.bitcoin.rpc_host = "10.0.0.1".to_string();
        default.bitcoin.rpc_user = "testuser".to_string();
        let toml_str = toml::to_string(&default).unwrap();
        std::fs::write(&path, &toml_str).unwrap();
        let config = load_config(&path).unwrap();
        assert_eq!(config.bitcoin.rpc_host, "10.0.0.1");
        assert_eq!(config.bitcoin.rpc_user, "testuser");
    }

    #[test]
    fn load_config_invalid_toml_returns_err() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is [[[not valid toml").unwrap();
        assert!(load_config(&path).is_err());
    }

    #[test]
    fn load_config_empty_file_is_err() {
        // Empty TOML is missing required fields (identity, bitcoin, etc.)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();
        assert!(load_config(&path).is_err());
    }

    // ── parse_log_level ──────────────────────────────────────────────

    #[test]
    fn parse_log_level_all_valid() {
        assert_eq!(parse_log_level("trace"), Level::TRACE);
        assert_eq!(parse_log_level("debug"), Level::DEBUG);
        assert_eq!(parse_log_level("info"), Level::INFO);
        assert_eq!(parse_log_level("warn"), Level::WARN);
        assert_eq!(parse_log_level("error"), Level::ERROR);
    }

    #[test]
    fn parse_log_level_case_insensitive() {
        assert_eq!(parse_log_level("TRACE"), Level::TRACE);
        assert_eq!(parse_log_level("Trace"), Level::TRACE);
        assert_eq!(parse_log_level("DEBUG"), Level::DEBUG);
    }

    #[test]
    fn parse_log_level_unknown_defaults_to_info() {
        assert_eq!(parse_log_level("verbose"), Level::INFO);
        assert_eq!(parse_log_level("nonsense"), Level::INFO);
    }

    #[test]
    fn parse_log_level_empty_defaults_to_info() {
        assert_eq!(parse_log_level(""), Level::INFO);
    }

    // ── build_log_filter ─────────────────────────────────────────────
    //
    // The point of these is that ONE module can be turned up without turning the whole binary
    // into a firehose. #583 sat undiagnosed for weeks because that was impossible.

    #[test]
    fn log_filter_honours_a_per_target_directive() {
        let f = build_log_filter("info", Some("info,ghost_pool::round=debug")).to_string();
        assert!(
            f.contains("ghost_pool::round=debug"),
            "per-target directive must survive, got {f:?}"
        );
    }

    #[test]
    fn log_filter_falls_back_to_the_cli_level_without_rust_log() {
        assert_eq!(build_log_filter("warn", None).to_string(), "warn");
        assert_eq!(build_log_filter("debug", Some("")).to_string(), "debug");
    }

    #[test]
    fn log_filter_keeps_the_valid_half_of_a_typo() {
        // parse_lossy drops the bad directive rather than dying at startup — a fat-fingered
        // RUST_LOG must never stop a node from booting.
        let f =
            build_log_filter("info", Some("ghost_pool::round=debug,!!!nonsense!!!")).to_string();
        assert!(f.contains("ghost_pool::round=debug"), "got {f:?}");
    }

    // ── resolve_signer_path ──────────────────────────────────────────

    #[test]
    fn resolve_signer_explicit_config() {
        let explicit = SignerConfig::Local {
            key_path: PathBuf::from("/custom/key"),
        };
        let result = resolve_signer_path(
            &Some(explicit.clone()),
            Path::new("/ignored"),
            Path::new("/also_ignored"),
        )
        .unwrap();
        assert_eq!(result, explicit);
    }

    #[test]
    fn resolve_signer_config_key_exists() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("node.key");
        std::fs::write(&key_path, "key_data").unwrap();
        let default_path = dir.path().join("default.key");

        let result = resolve_signer_path(&None, &key_path, &default_path).unwrap();
        assert_eq!(
            result,
            SignerConfig::Local {
                key_path: key_path.clone()
            }
        );
    }

    #[test]
    fn resolve_signer_config_key_missing_uses_default() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.key");
        let default_path = dir.path().join("default.key");

        let result = resolve_signer_path(&None, &missing, &default_path).unwrap();
        assert_eq!(
            result,
            SignerConfig::Local {
                key_path: default_path.clone()
            }
        );
    }

    #[test]
    fn resolve_signer_neither_path_exists() {
        let dir = tempfile::tempdir().unwrap();
        let missing1 = dir.path().join("a.key");
        let missing2 = dir.path().join("b.key");

        let result = resolve_signer_path(&None, &missing1, &missing2).unwrap();
        assert_eq!(
            result,
            SignerConfig::Local {
                key_path: missing2.clone()
            }
        );
    }
}
