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

//! Ghost CLI - Administration tool for Bitcoin Ghost
//!
//! Provides commands for:
//! - Viewing pool status
//! - Managing miners
//! - Monitoring consensus
//! - Querying payouts
//! - Key management

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::PathBuf;
use tabled::{Table, Tabled};

fn confirm(prompt: &str) -> bool {
    print!("{} (y/n): ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().eq_ignore_ascii_case("y")
}

/// Ghost CLI - Bitcoin Ghost Administration Tool
#[derive(Parser)]
#[command(name = "ghost-admin")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Pool API URL (required, or set GHOST_POOL_URL env var)
    ///
    /// Made optional at the clap level to sidestep a quirk where a required
    /// `global = true` String arg ends up being required at both the top level
    /// and every subcommand level. Presence is validated in main().
    #[arg(short, long, env = "GHOST_POOL_URL", global = true)]
    url: Option<String>,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,

    /// Retry HTTP requests on transient failures (network errors, timeouts, 5xx)
    #[arg(long, default_value = "3", global = true)]
    retries: u32,

    /// Dry-run mode: print what mutating commands would do without calling the API
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, Default)]
enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Show pool status
    Status,

    /// Miner management
    #[command(subcommand)]
    Miner(MinerCommands),

    /// Round information
    #[command(subcommand)]
    Round(RoundCommands),

    /// Payout information
    #[command(subcommand)]
    Payout(PayoutCommands),

    /// Consensus operations
    #[command(subcommand)]
    Consensus(ConsensusCommands),

    /// Key management
    #[command(subcommand)]
    Key(KeyCommands),

    /// Node management
    #[command(subcommand)]
    Node(NodeCommands),

    /// Show metrics
    Metrics,
}

#[derive(Subcommand)]
enum MinerCommands {
    /// List connected miners
    List {
        /// Show only active miners
        #[arg(short, long)]
        active: bool,
        /// Limit results
        #[arg(short, long, default_value = "100")]
        limit: usize,
    },
    /// Show miner details
    Info {
        /// Miner ID
        miner_id: String,
    },
    /// Kick a miner
    Kick {
        /// Miner ID
        miner_id: String,
        /// Reason for kick
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Ban a miner
    Ban {
        /// Miner address or ID
        target: String,
        /// Duration in hours (0 = permanent)
        #[arg(short, long, default_value = "24")]
        duration: u64,
        /// Reason for ban
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Unban a miner
    Unban {
        /// Miner address or ID
        target: String,
    },
}

#[derive(Subcommand)]
enum RoundCommands {
    /// Show current round
    Current,
    /// Show round history
    History {
        /// Number of rounds
        #[arg(short, long, default_value = "10")]
        count: usize,
    },
    /// Show specific round
    Info {
        /// Round ID
        round_id: u64,
    },
}

#[derive(Subcommand)]
enum PayoutCommands {
    /// List pending payouts
    Pending {
        /// Limit results
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },
    /// Show payout history
    History {
        /// Number of payouts
        #[arg(short, long, default_value = "20")]
        count: usize,
    },
    /// Show payout details
    Info {
        /// Payout ID or transaction ID
        id: String,
    },
    /// Force payout processing
    Process {
        /// Dry run (don't actually process)
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum ConsensusCommands {
    /// Show consensus status
    Status,
    /// List peers in mesh
    Peers,
    /// Show recent votes
    Votes {
        /// Number of votes
        #[arg(short, long, default_value = "20")]
        count: usize,
    },
    /// Show elder nodes
    Elders,
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new node identity key
    Generate {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Show current node ID
    Show,
    /// Verify a key file
    Verify {
        /// Key file path
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum NodeCommands {
    /// Show node info
    Info,
    /// Check health
    Health,
    /// Drain node (stop accepting new work)
    Drain,
    /// Resume node (accept new work)
    Resume,
    /// Show configuration
    Config,
}

// =============================================================================
// API Response Types
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct StatusResponse {
    status: String,
    version: String,
    node_id: String,
    uptime_secs: u64,
    bitcoin_connected: bool,
    block_height: u64,
    miners_connected: u64,
    miners_active: u64,
    current_round: u64,
    shares_this_round: u64,
    hashrate_estimate: f64,
    blocks_found_total: u64,
}

#[derive(Debug, Serialize, Deserialize, Tabled)]
struct MinerInfo {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Hashrate")]
    hashrate: String,
    #[tabled(rename = "Shares")]
    shares: u64,
    #[tabled(rename = "Last Seen")]
    last_seen: String,
    #[tabled(rename = "Status")]
    status: String,
}

#[derive(Debug, Serialize, Deserialize, Tabled)]
struct RoundInfo {
    #[tabled(rename = "ID")]
    id: u64,
    #[tabled(rename = "Height")]
    height: u64,
    #[tabled(rename = "Shares")]
    shares: u64,
    #[tabled(rename = "Work")]
    work: String,
    #[tabled(rename = "Duration")]
    duration: String,
    #[tabled(rename = "Status")]
    status: String,
}

#[derive(Debug, Serialize, Deserialize, Tabled)]
struct PayoutInfo {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Amount (sats)")]
    amount_sats: u64,
    #[tabled(rename = "Round")]
    round_id: u64,
    #[tabled(rename = "Status")]
    status: String,
}

#[derive(Debug, Serialize, Deserialize, Tabled)]
struct PeerInfo {
    #[tabled(rename = "Node ID")]
    node_id: String,
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Tenure")]
    tenure: String,
    #[tabled(rename = "Elder")]
    is_elder: String,
    #[tabled(rename = "Uptime")]
    uptime: String,
}

// =============================================================================
// Client
// =============================================================================

struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    retries: u32,
}

/// Outcome of a single attempt when running a request through [`ApiClient::with_retries`].
/// Transient errors return Retry; any other error should not be retried.
enum AttemptResult<T> {
    Ok(T),
    Retry(anyhow::Error),
    Fatal(anyhow::Error),
}

impl ApiClient {
    fn new(base_url: &str, retries: u32) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("L-1: Failed to build HTTP client - check TLS/SSL configuration"),
            retries,
        }
    }

    /// Retry transient errors up to `self.retries` times with exponential backoff + jitter.
    /// Network errors, timeouts, and 5xx responses are retried; 4xx and decode errors are not.
    async fn with_retries<T, F, Fut>(&self, mut attempt: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = AttemptResult<T>>,
    {
        let max_attempts = self.retries.saturating_add(1);
        let mut last_err: Option<anyhow::Error> = None;
        for n in 0..max_attempts {
            match attempt().await {
                AttemptResult::Ok(value) => return Ok(value),
                AttemptResult::Fatal(e) => return Err(e),
                AttemptResult::Retry(e) => {
                    last_err = Some(e);
                    if n + 1 >= max_attempts {
                        break;
                    }
                    let base_ms = 250u64 << n.min(6); // 250,500,1000,…,16000 ms
                    let jitter = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.subsec_nanos() as u64 % 100)
                        .unwrap_or(0);
                    tokio::time::sleep(std::time::Duration::from_millis(base_ms + jitter)).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("request failed")))
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}/api/v1{}", self.base_url, path);
        self.with_retries(|| async {
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    return AttemptResult::Retry(
                        anyhow::Error::from(e).context("Failed to connect to pool"),
                    );
                }
            };
            let status = resp.status();
            if status.is_server_error() {
                return AttemptResult::Retry(anyhow::anyhow!("API error: {}", status));
            }
            if !status.is_success() {
                return AttemptResult::Fatal(anyhow::anyhow!("API error: {}", status));
            }
            match resp.json::<T>().await {
                Ok(v) => AttemptResult::Ok(v),
                Err(e) => AttemptResult::Fatal(
                    anyhow::Error::from(e).context("Failed to parse API response"),
                ),
            }
        })
        .await
    }

    async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T> {
        let url = format!("{}/api/v1{}", self.base_url, path);
        let body_json = serde_json::to_value(body).context("Failed to serialize request body")?;
        self.with_retries(|| async {
            let resp = match self.client.post(&url).json(&body_json).send().await {
                Ok(r) => r,
                Err(e) => {
                    return AttemptResult::Retry(
                        anyhow::Error::from(e).context("Failed to connect to pool"),
                    );
                }
            };
            let status = resp.status();
            if status.is_server_error() {
                return AttemptResult::Retry(anyhow::anyhow!("API error: {}", status));
            }
            if !status.is_success() {
                return AttemptResult::Fatal(anyhow::anyhow!("API error: {}", status));
            }
            match resp.json::<T>().await {
                Ok(v) => AttemptResult::Ok(v),
                Err(e) => AttemptResult::Fatal(
                    anyhow::Error::from(e).context("Failed to parse API response"),
                ),
            }
        })
        .await
    }

    async fn get_text(&self, path: &str) -> Result<String> {
        let url = format!("{}/api/v1{}", self.base_url, path);
        self.with_retries(|| async {
            let resp = match self.client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    return AttemptResult::Retry(
                        anyhow::Error::from(e).context("Failed to connect to pool"),
                    );
                }
            };
            let status = resp.status();
            if status.is_server_error() {
                return AttemptResult::Retry(anyhow::anyhow!("API error: {}", status));
            }
            if !status.is_success() {
                return AttemptResult::Fatal(anyhow::anyhow!("API error: {}", status));
            }
            match resp.text().await {
                Ok(v) => AttemptResult::Ok(v),
                Err(e) => AttemptResult::Fatal(
                    anyhow::Error::from(e).context("Failed to read API response"),
                ),
            }
        })
        .await
    }
}

// =============================================================================
// Command Handlers
// =============================================================================

async fn cmd_status(client: &ApiClient, format: OutputFormat) -> Result<()> {
    let status: StatusResponse = client.get("/status").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        OutputFormat::Text => {
            println!("{}", "=== Ghost Pool Status ===".green().bold());
            println!();
            println!("  {} {}", "Version:".cyan(), status.version);
            println!("  {} {}", "Node ID:".cyan(), &status.node_id[..16]);
            println!(
                "  {} {}",
                "Status:".cyan(),
                if status.status == "healthy" {
                    status.status.green()
                } else {
                    status.status.red()
                }
            );
            println!(
                "  {} {}s",
                "Uptime:".cyan(),
                format_duration(status.uptime_secs)
            );
            println!();
            println!("{}", "--- Bitcoin ---".yellow());
            println!(
                "  {} {}",
                "Connected:".cyan(),
                if status.bitcoin_connected {
                    "Yes".green()
                } else {
                    "No".red()
                }
            );
            println!("  {} {}", "Block Height:".cyan(), status.block_height);
            println!();
            println!("{}", "--- Mining ---".yellow());
            println!(
                "  {} {}",
                "Miners Connected:".cyan(),
                status.miners_connected
            );
            println!("  {} {}", "Miners Active:".cyan(), status.miners_active);
            println!("  {} {}", "Current Round:".cyan(), status.current_round);
            println!(
                "  {} {}",
                "Shares (this round):".cyan(),
                status.shares_this_round
            );
            println!(
                "  {} {:.2} TH/s",
                "Hashrate:".cyan(),
                status.hashrate_estimate / 1e12
            );
            println!("  {} {}", "Blocks Found:".cyan(), status.blocks_found_total);
        }
    }
    Ok(())
}

async fn cmd_miner_list(
    client: &ApiClient,
    format: OutputFormat,
    active: bool,
    limit: usize,
) -> Result<()> {
    let path = if active {
        format!("/miners?active=true&limit={}", limit)
    } else {
        format!("/miners?limit={}", limit)
    };

    let miners: Vec<MinerInfo> = client.get(&path).await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&miners)?);
        }
        OutputFormat::Text => {
            if miners.is_empty() {
                println!("{}", "No miners connected".yellow());
            } else {
                println!(
                    "{}",
                    format!("=== {} Miners ===", miners.len()).green().bold()
                );
                let table = Table::new(&miners).to_string();
                println!("{}", table);
            }
        }
    }
    Ok(())
}

async fn cmd_round_current(client: &ApiClient, format: OutputFormat) -> Result<()> {
    let round: RoundInfo = client.get("/rounds/current").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&round)?);
        }
        OutputFormat::Text => {
            println!("{}", "=== Current Round ===".green().bold());
            println!();
            println!("  {} {}", "Round ID:".cyan(), round.id);
            println!("  {} {}", "Block Height:".cyan(), round.height);
            println!("  {} {}", "Shares:".cyan(), round.shares);
            println!("  {} {}", "Total Work:".cyan(), round.work);
            println!("  {} {}", "Duration:".cyan(), round.duration);
            println!("  {} {}", "Status:".cyan(), round.status);
        }
    }
    Ok(())
}

async fn cmd_payout_pending(client: &ApiClient, format: OutputFormat, limit: usize) -> Result<()> {
    let payouts: Vec<PayoutInfo> = client
        .get(&format!("/payouts/pending?limit={}", limit))
        .await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&payouts)?);
        }
        OutputFormat::Text => {
            if payouts.is_empty() {
                println!("{}", "No pending payouts".yellow());
            } else {
                println!(
                    "{}",
                    format!("=== {} Pending Payouts ===", payouts.len())
                        .green()
                        .bold()
                );
                let table = Table::new(&payouts).to_string();
                println!("{}", table);
            }
        }
    }
    Ok(())
}

async fn cmd_consensus_status(client: &ApiClient, format: OutputFormat) -> Result<()> {
    #[derive(Debug, Serialize, Deserialize)]
    struct ConsensusStatus {
        connected_peers: u64,
        elder_count: u64,
        participation_percent: f64,
        last_vote_time: String,
        pending_proposals: u64,
    }

    let status: ConsensusStatus = client.get("/consensus/status").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        OutputFormat::Text => {
            println!("{}", "=== Consensus Status ===".green().bold());
            println!();
            println!("  {} {}", "Connected Peers:".cyan(), status.connected_peers);
            println!("  {} {}", "Elder Nodes:".cyan(), status.elder_count);
            println!(
                "  {} {:.1}%",
                "Participation:".cyan(),
                status.participation_percent
            );
            println!("  {} {}", "Last Vote:".cyan(), status.last_vote_time);
            println!(
                "  {} {}",
                "Pending Proposals:".cyan(),
                status.pending_proposals
            );
        }
    }
    Ok(())
}

async fn cmd_consensus_peers(client: &ApiClient, format: OutputFormat) -> Result<()> {
    let peers: Vec<PeerInfo> = client.get("/consensus/peers").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&peers)?);
        }
        OutputFormat::Text => {
            if peers.is_empty() {
                println!("{}", "No peers connected".yellow());
            } else {
                println!(
                    "{}",
                    format!("=== {} Connected Peers ===", peers.len())
                        .green()
                        .bold()
                );
                let table = Table::new(&peers).to_string();
                println!("{}", table);
            }
        }
    }
    Ok(())
}

async fn cmd_metrics(client: &ApiClient) -> Result<()> {
    let metrics = client.get_text("/metrics").await?;
    println!("{}", metrics);
    Ok(())
}

async fn cmd_key_generate(output: Option<PathBuf>) -> Result<()> {
    use ghost_common::identity::NodeIdentity;

    let identity = NodeIdentity::generate();
    let node_id = identity.node_id_hex();

    let output_path = output.unwrap_or_else(|| PathBuf::from("node.key"));

    identity.save(&output_path)?;

    println!("{}", "=== New Node Identity Generated ===".green().bold());
    println!();
    println!("  {} {}", "Node ID:".cyan(), node_id);
    println!("  {} {}", "Key File:".cyan(), output_path.display());
    println!();
    println!("{}", "Keep your key file secure!".yellow());

    Ok(())
}

async fn cmd_key_show(client: &ApiClient, format: OutputFormat) -> Result<()> {
    #[derive(Debug, Serialize, Deserialize)]
    struct NodeInfo {
        node_id: String,
        display_name: Option<String>,
    }

    let info: NodeInfo = client.get("/node/info").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Text => {
            println!("{}", "=== Node Identity ===".green().bold());
            println!();
            println!("  {} {}", "Node ID:".cyan(), info.node_id);
            if let Some(name) = info.display_name {
                println!("  {} {}", "Display Name:".cyan(), name);
            }
        }
    }
    Ok(())
}

async fn cmd_key_verify(path: PathBuf) -> Result<()> {
    use ghost_common::identity::NodeIdentity;

    let identity = NodeIdentity::load(&path)?;
    let node_id = identity.node_id_hex();

    println!("{}", "=== Key Verification ===".green().bold());
    println!();
    println!("  {} {}", "File:".cyan(), path.display());
    println!("  {} {}", "Status:".cyan(), "Valid".green());
    println!("  {} {}", "Node ID:".cyan(), node_id);

    Ok(())
}

async fn cmd_node_health(client: &ApiClient, format: OutputFormat) -> Result<()> {
    #[derive(Debug, Serialize, Deserialize)]
    struct HealthResponse {
        status: String,
        checks: std::collections::HashMap<String, bool>,
    }

    let health: HealthResponse = client.get("/health").await?;

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&health)?);
        }
        OutputFormat::Text => {
            let status_color = if health.status == "healthy" {
                health.status.green()
            } else {
                health.status.red()
            };

            println!("{}", "=== Health Check ===".green().bold());
            println!();
            println!("  {} {}", "Overall:".cyan(), status_color);
            println!();
            for (check, passed) in &health.checks {
                let status = if *passed { "OK".green() } else { "FAIL".red() };
                println!("  {} {}", format!("{}:", check).cyan(), status);
            }
        }
    }
    Ok(())
}

async fn cmd_node_drain(client: &ApiClient) -> Result<()> {
    #[derive(Debug, Serialize, Deserialize)]
    struct DrainResponse {
        status: String,
        message: String,
    }

    let response: DrainResponse = client.post("/admin/drain", &()).await?;

    println!("{}", "=== Node Drain ===".yellow().bold());
    println!();
    println!("  {} {}", "Status:".cyan(), response.status);
    println!("  {} {}", "Message:".cyan(), response.message);

    Ok(())
}

async fn cmd_node_resume(client: &ApiClient) -> Result<()> {
    #[derive(Debug, Serialize, Deserialize)]
    struct ResumeResponse {
        status: String,
        message: String,
    }

    let response: ResumeResponse = client.post("/admin/resume", &()).await?;

    println!("{}", "=== Node Resume ===".green().bold());
    println!();
    println!("  {} {}", "Status:".cyan(), response.status);
    println!("  {} {}", "Message:".cyan(), response.message);

    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

fn format_duration(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, mins)
    } else if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

// =============================================================================
// Main
// =============================================================================

/// Print a dry-run summary for a mutating request and return true so the caller can skip it.
fn dry_run_notice(method: &str, path: &str, body: Option<&serde_json::Value>) -> bool {
    println!("{}", "[dry-run] would send:".yellow().bold());
    println!("  {} {}", method.cyan(), path);
    if let Some(b) = body {
        if !b.is_null() {
            println!("  body: {}", serde_json::to_string(b).unwrap_or_default());
        }
    }
    println!("{}", "[dry-run] no request sent.".yellow());
    true
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let url = cli.url.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
        anyhow::anyhow!(
            "pool API URL is required — pass --url <URL> or set GHOST_POOL_URL (currently unset or empty)"
        )
    })?;
    let client = ApiClient::new(url, cli.retries);
    let dry_run = cli.dry_run;

    match cli.command {
        Commands::Status => cmd_status(&client, cli.format).await?,

        Commands::Miner(cmd) => match cmd {
            MinerCommands::List { active, limit } => {
                cmd_miner_list(&client, cli.format, active, limit).await?
            }
            MinerCommands::Info { miner_id } => {
                let miner: MinerInfo = client.get(&format!("/miners/{}", miner_id)).await?;
                match cli.format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&miner)?),
                    OutputFormat::Text => {
                        let table = Table::new(&[miner]).to_string();
                        println!("{}", table);
                    }
                }
            }
            MinerCommands::Kick { miner_id, reason } => {
                let path = format!("/admin/miners/{}/kick", miner_id);
                let body = serde_json::json!({ "reason": reason });
                if dry_run {
                    dry_run_notice("POST", &path, Some(&body));
                    return Ok(());
                }
                if !confirm(&format!("Kick miner {}?", miner_id)) {
                    println!("Cancelled.");
                    return Ok(());
                }
                let _: serde_json::Value = client.post(&path, &body).await?;
                println!("{}", format!("Miner {} kicked", miner_id).yellow());
            }
            MinerCommands::Ban {
                target,
                duration,
                reason,
            } => {
                let path = format!("/admin/ban/{}", target);
                let body = serde_json::json!({ "duration_hours": duration, "reason": reason });
                if dry_run {
                    dry_run_notice("POST", &path, Some(&body));
                    return Ok(());
                }
                if !confirm(&format!("Ban {} for {} hours?", target, duration)) {
                    println!("Cancelled.");
                    return Ok(());
                }
                let _: serde_json::Value = client.post(&path, &body).await?;
                println!(
                    "{}",
                    format!("Banned {} for {} hours", target, duration).red()
                );
            }
            MinerCommands::Unban { target } => {
                let path = format!("/admin/unban/{}", target);
                if dry_run {
                    dry_run_notice("POST", &path, None);
                    return Ok(());
                }
                let _: serde_json::Value = client.post(&path, &()).await?;
                println!("{}", format!("Unbanned {}", target).green());
            }
        },

        Commands::Round(cmd) => match cmd {
            RoundCommands::Current => cmd_round_current(&client, cli.format).await?,
            RoundCommands::History { count } => {
                let rounds: Vec<RoundInfo> =
                    client.get(&format!("/rounds?limit={}", count)).await?;
                match cli.format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&rounds)?),
                    OutputFormat::Text => {
                        let table = Table::new(&rounds).to_string();
                        println!("{}", table);
                    }
                }
            }
            RoundCommands::Info { round_id } => {
                let round: RoundInfo = client.get(&format!("/rounds/{}", round_id)).await?;
                match cli.format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&round)?),
                    OutputFormat::Text => {
                        let table = Table::new(&[round]).to_string();
                        println!("{}", table);
                    }
                }
            }
        },

        Commands::Payout(cmd) => match cmd {
            PayoutCommands::Pending { limit } => {
                cmd_payout_pending(&client, cli.format, limit).await?
            }
            PayoutCommands::History { count } => {
                let payouts: Vec<PayoutInfo> =
                    client.get(&format!("/payouts?limit={}", count)).await?;
                match cli.format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&payouts)?),
                    OutputFormat::Text => {
                        let table = Table::new(&payouts).to_string();
                        println!("{}", table);
                    }
                }
            }
            PayoutCommands::Info { id } => {
                let payout: PayoutInfo = client.get(&format!("/payouts/{}", id)).await?;
                match cli.format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&payout)?),
                    OutputFormat::Text => {
                        let table = Table::new(&[payout]).to_string();
                        println!("{}", table);
                    }
                }
            }
            PayoutCommands::Process { dry_run: local_dry } => {
                // Two dry-runs in play: --dry-run skips the call entirely; the local
                // --dry-run on payout process keeps the call but asks the backend to
                // simulate. Global wins when set.
                let body = serde_json::json!({ "dry_run": local_dry || dry_run });
                if dry_run {
                    dry_run_notice("POST", "/admin/payouts/process", Some(&body));
                    return Ok(());
                }
                let result: serde_json::Value =
                    client.post("/admin/payouts/process", &body).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },

        Commands::Consensus(cmd) => match cmd {
            ConsensusCommands::Status => cmd_consensus_status(&client, cli.format).await?,
            ConsensusCommands::Peers => cmd_consensus_peers(&client, cli.format).await?,
            ConsensusCommands::Votes { count } => {
                let votes: serde_json::Value = client
                    .get(&format!("/consensus/votes?limit={}", count))
                    .await?;
                println!("{}", serde_json::to_string_pretty(&votes)?);
            }
            ConsensusCommands::Elders => {
                let elders: Vec<PeerInfo> = client.get("/consensus/elders").await?;
                match cli.format {
                    OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&elders)?),
                    OutputFormat::Text => {
                        let table = Table::new(&elders).to_string();
                        println!("{}", table);
                    }
                }
            }
        },

        Commands::Key(cmd) => match cmd {
            KeyCommands::Generate { output } => cmd_key_generate(output).await?,
            KeyCommands::Show => cmd_key_show(&client, cli.format).await?,
            KeyCommands::Verify { path } => cmd_key_verify(path).await?,
        },

        Commands::Node(cmd) => match cmd {
            NodeCommands::Info => {
                let info: serde_json::Value = client.get("/node/info").await?;
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
            NodeCommands::Health => cmd_node_health(&client, cli.format).await?,
            NodeCommands::Drain => {
                if dry_run {
                    dry_run_notice("POST", "/admin/drain", None);
                } else {
                    cmd_node_drain(&client).await?
                }
            }
            NodeCommands::Resume => {
                if dry_run {
                    dry_run_notice("POST", "/admin/resume", None);
                } else {
                    cmd_node_resume(&client).await?
                }
            }
            NodeCommands::Config => {
                let config: serde_json::Value = client.get("/node/config").await?;
                println!("{}", serde_json::to_string_pretty(&config)?);
            }
        },

        Commands::Metrics => cmd_metrics(&client).await?,
    }

    Ok(())
}
