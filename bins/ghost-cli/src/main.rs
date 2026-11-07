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
//! - The node pool's health (relay tip, peers, settlement, connected miners)
//! - The node's own health and metrics
//! - Key management

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Ghost CLI - Bitcoin Ghost Administration Tool
#[derive(Parser)]
#[command(name = "ghost-admin")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// The node's API URL (or set GHOST_POOL_URL). Default: this machine's ghost-mining API.
    ///
    /// An Option at the clap level to sidestep a quirk where a required `global = true` String
    /// arg ends up being required at both the top level and every subcommand level. An empty
    /// value is refused in main().
    #[arg(
        short,
        long,
        env = "GHOST_POOL_URL",
        global = true,
        default_value = "http://127.0.0.1:8080"
    )]
    url: Option<String>,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,

    /// Retry HTTP requests on transient failures (network errors, timeouts, 5xx)
    #[arg(long, default_value = "3", global = true)]
    retries: u32,

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
    /// Key management
    #[command(subcommand)]
    Key(KeyCommands),

    /// Node management
    #[command(subcommand)]
    Node(NodeCommands),

    /// Show metrics (Prometheus text)
    Metrics,
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
    /// Node pool health: relay tip, peers, settlement, fee address, connected miners' slot classes
    Status,
    /// Show node info
    Info,
    /// Check health (`/health`)
    Health,
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

    /// GET a JSON route under `/api/v1`.
    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        self.get_json_at(&format!("/api/v1{path}")).await
    }

    /// GET a JSON route at `path` from the server root.
    async fn get_json_at<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
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

    /// GET a text route at `path` from the server root.
    async fn get_text_at(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.base_url, path);
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

async fn cmd_metrics(client: &ApiClient) -> Result<()> {
    let metrics = client.get_text_at("/metrics").await?;
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

/// `node status`: the solo pool's status, from `GET /api/v1/pool/status` (served by pool_sv2,
/// forwarded by ghost-mining).
async fn cmd_node_pool_status(client: &ApiClient, format: OutputFormat) -> Result<()> {
    let status: serde_json::Value = client.get("/pool/status").await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&status)?),
        OutputFormat::Text => print!("{}", render_pool_status(&status)),
    }
    Ok(())
}

/// The pool status as plain lines. Missing fields print as `?`, never as a healthy default.
fn render_pool_status(v: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    fn f(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::Null => "?".to_string(),
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }
    let rate = |v: &serde_json::Value| v.as_f64().map_or_else(|| "?".to_string(), fmt_hashrate);
    let sats = |v: &serde_json::Value| {
        v.as_u64()
            .map_or_else(|| "?".to_string(), |n| group_digits(i128::from(n)))
    };
    let mut o = String::new();
    let b = &v["bitcoin"];
    let _ = writeln!(o, "=== Ghost Solo ({}) ===", f(&v["network"]));
    let _ = writeln!(
        o,
        "  bitcoin tip:   {} ({}), difficulty {}",
        f(&b["tip_height"]),
        f(&b["tip_hash"]),
        f(&b["network_difficulty"])
    );
    let _ = writeln!(
        o,
        "  miners:        {} addresses, {} workers",
        f(&v["miners"]["connected"]),
        f(&v["miners"]["workers"])
    );
    let h = &v["pool_hashrate_hs"];
    let _ = writeln!(
        o,
        "  pool hashrate: {} (15m), {} (1h), {} (24h)",
        rate(&h["15m"]),
        rate(&h["1h"]),
        rate(&h["24h"])
    );
    let _ = writeln!(
        o,
        "  best share:    {} (ever), {} (24h)",
        f(&v["best_share"]["ever"]),
        f(&v["best_share"]["24h"])
    );
    let fp = &v["fee_policy"];
    let _ = writeln!(
        o,
        "  next block:    {} sats to the treasury ({}), {} sats + fees to the finder",
        sats(&fp["treasury_sats_next_block"]),
        f(&fp["treasury_address"]),
        sats(&fp["miner_sats_next_block_before_fees"])
    );
    let blocks = v["blocks_found"].as_array().cloned().unwrap_or_default();
    let _ = writeln!(o, "  blocks found:  {}", blocks.len());
    for blk in &blocks {
        let _ = writeln!(
            o,
            "    {} {} to {} ({} sats), check {}",
            f(&blk["height"]),
            f(&blk["hash"]),
            f(&blk["address"]),
            sats(&blk["reward_sats"]),
            f(&blk["check"])
        );
    }
    o
}

fn fmt_hashrate(hs: f64) -> String {
    const UNITS: [(f64, &str); 6] = [
        (1e18, "EH/s"),
        (1e15, "PH/s"),
        (1e12, "TH/s"),
        (1e9, "GH/s"),
        (1e6, "MH/s"),
        (1e3, "kH/s"),
    ];
    for (f, u) in UNITS {
        if hs >= f {
            return format!("{:.2} {u}", hs / f);
        }
    }
    format!("{hs:.0} H/s")
}

/// `1234567` -> `1,234,567`.
fn group_digits(n: i128) -> String {
    let digits = n.unsigned_abs().to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if n < 0 {
        out.push('-');
    }
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `node health`: the node's own `/health` document. `healthy` is false until it can show it
/// reaches its Bitcoin node; unknown fields print as `?`.
async fn cmd_node_health(client: &ApiClient, format: OutputFormat) -> Result<()> {
    let health: serde_json::Value = client.get_json_at("/health").await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&health)?),
        OutputFormat::Text => {
            let f = |k: &str| match &health[k] {
                serde_json::Value::Null => "?".to_string(),
                v => v.to_string(),
            };
            let healthy = health["healthy"].as_bool() == Some(true);
            println!("{}", "=== Health Check ===".green().bold());
            println!();
            println!(
                "  {} {}",
                "Overall:".cyan(),
                if healthy {
                    "healthy".green()
                } else {
                    "UNHEALTHY".red()
                }
            );
            for k in [
                "core_reachable",
                "block_height",
                "miner_count",
                "version",
                "uptime_secs",
            ] {
                println!("  {} {}", format!("{k}:").cyan(), f(k));
            }
        }
    }
    Ok(())
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let url = cli.url.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
        anyhow::anyhow!(
            "the node API URL is empty — pass --url <URL> or unset GHOST_POOL_URL to use http://127.0.0.1:8080"
        )
    })?;
    let client = ApiClient::new(url, cli.retries);

    match cli.command {
        Commands::Key(cmd) => match cmd {
            KeyCommands::Generate { output } => cmd_key_generate(output).await?,
            KeyCommands::Show => cmd_key_show(&client, cli.format).await?,
            KeyCommands::Verify { path } => cmd_key_verify(path).await?,
        },

        Commands::Node(cmd) => match cmd {
            NodeCommands::Status => cmd_node_pool_status(&client, cli.format).await?,
            NodeCommands::Info => {
                let info: serde_json::Value = client.get("/node/info").await?;
                println!("{}", serde_json::to_string_pretty(&info)?);
            }
            NodeCommands::Health => cmd_node_health(&client, cli.format).await?,
        },

        Commands::Metrics => cmd_metrics(&client).await?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_status_renders_every_line() {
        let v = serde_json::json!({
            "network": "regtest",
            "bitcoin": {"tip_height": 999, "tip_hash": "00ab", "job_height": 1000,
                        "network_difficulty": 1.0},
            "miners": {"connected": 2, "workers": 3},
            "pool_hashrate_hs": {"15m": 101808185.67, "1h": null, "24h": 2.0e12},
            "best_share": {"ever": 5000.0, "24h": 70.0},
            "fee_policy": {"treasury_address": "bcrt1qtreasury",
                           "treasury_sats_next_block": 24414,
                           "miner_sats_next_block_before_fees": 4858398},
            "blocks_found": [{"height": 990, "hash": "00cd", "address": "bcrt1qminer",
                              "reward_sats": 4858398, "check": "ok"}]
        });
        let out = render_pool_status(&v);
        for want in [
            "Ghost Solo (regtest)",
            "bitcoin tip:   999 (00ab), difficulty 1.0",
            "miners:        2 addresses, 3 workers",
            "pool hashrate: 101.81 MH/s (15m), ? (1h), 2.00 TH/s (24h)",
            "best share:    5000.0 (ever), 70.0 (24h)",
            "next block:    24,414 sats to the treasury (bcrt1qtreasury), 4,858,398 sats + fees",
            "blocks found:  1",
            "990 00cd to bcrt1qminer (4,858,398 sats), check ok",
        ] {
            assert!(out.contains(want), "{want:?} missing from:\n{out}");
        }
        let empty = render_pool_status(&serde_json::json!({}));
        assert!(
            empty.contains("bitcoin tip:   ? (?)"),
            "unknown is not healthy: {empty}"
        );
        assert!(empty.contains("blocks found:  0"), "{empty}");
    }

    #[test]
    fn digits_are_grouped() {
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(-1_000), "-1,000");
        assert_eq!(group_digits(1_234_567), "1,234,567");
    }
}
