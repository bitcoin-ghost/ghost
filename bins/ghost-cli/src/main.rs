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

/// `node status`: the node pool's health, from `GET /api/v1/node-pool/status` (served by pool_sv2,
/// forwarded by ghost-mining).
async fn cmd_node_pool_status(client: &ApiClient, format: OutputFormat) -> Result<()> {
    let status: serde_json::Value = client.get("/node-pool/status").await?;
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&status)?),
        OutputFormat::Text => print!("{}", render_node_pool_status(&status)),
    }
    Ok(())
}

/// The node pool status as plain lines. Missing fields print as `?`, never as a healthy default.
fn render_node_pool_status(v: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    fn f(v: &serde_json::Value) -> String {
        match v {
            serde_json::Value::Null => "?".to_string(),
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        }
    }
    let short = |v: &serde_json::Value| {
        let s = f(v);
        if s.len() > 16 {
            format!("{}…", &s[..16])
        } else {
            s
        }
    };
    let mut o = String::new();
    let chain = &v["share_chain"];
    let st = &v["settlement"];
    let _ = writeln!(o, "=== Node pool ({}) ===", f(&v["network"]));
    let _ = writeln!(
        o,
        "  relay tip:     {} (anchor height {}, Bitcoin height {}, T_net {})",
        short(&chain["tip"]),
        f(&chain["anchor_height"]),
        f(&chain["btc_height"]),
        f(&chain["t_net"])
    );
    let _ = writeln!(
        o,
        "  genesis:       {} at height {} ({})",
        short(&v["start"]["genesis_anchor"]),
        f(&v["start"]["genesis_btc_height"]),
        f(&v["start"]["source"])
    );
    let _ = writeln!(o, "  peers:         {}", f(&v["peers"]));
    let caught_up = match st["caught_up"].as_bool() {
        Some(true) => "yes".to_string(),
        Some(false) => "NO".to_string(),
        None => "?".to_string(),
    };
    let provisional = st["provisional"].as_array().map_or(0, Vec::len);
    let _ = writeln!(
        o,
        "  settlement:    caught up {caught_up} (synced {} of Bitcoin tip {}), {provisional} provisional",
        f(&st["synced_height"]),
        f(&st["bitcoin_tip"])
    );
    let _ = writeln!(o, "  fee address:   {}", f(&v["fee_address"]));
    let _ = writeln!(o, "  ledger rows:   {}", f(&v["ledger_rows"]));
    let miners = v["miners"].as_array().cloned().unwrap_or_default();
    let _ = writeln!(o, "  miners:        {}", miners.len());
    for m in &miners {
        let _ = writeln!(
            o,
            "    {} {} class {}{}",
            f(&m["address"]),
            f(&m["kind"]),
            f(&m["slot_class"]),
            m["sensing"]["model"]
                .as_str()
                .map(|x| format!(" ({x})"))
                .unwrap_or_default()
        );
        if let Some(w) = m["firmware_warning"].as_str() {
            let _ = writeln!(o, "      warning: {w}");
        }
    }
    o
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
            "pool API URL is required — pass --url <URL> or set GHOST_POOL_URL (currently unset or empty)"
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
    fn node_pool_status_renders_every_health_line() {
        let v = serde_json::json!({
            "network": "regtest",
            "start": {"genesis_anchor": "8d8cd561340ff83e99410e115619d64a", "genesis_btc_height": 0,
                      "source": "default"},
            "share_chain": {"tip": "abababababababababab", "anchor_height": 7, "btc_height": 998,
                            "t_net": 10},
            "peers": 2,
            "settlement": {"caught_up": false, "synced_height": 990, "bitcoin_tip": 999,
                           "provisional": [{"height": 960, "block_hash": "00"}]},
            "fee_address": "bcrt1qfee",
            "ledger_rows": 3,
            "miners": [{"address": "bcrt1qminer", "kind": "extended", "slot_class": 9,
                        "sensing": {"model": "Stock Antminer"},
                        "firmware_warning": "Stock Antminer firmware is limited to slot class 9"}]
        });
        let out = render_node_pool_status(&v);
        for want in [
            "Node pool (regtest)",
            "relay tip:     abababababababab… (anchor height 7, Bitcoin height 998, T_net 10)",
            "peers:         2",
            "caught up NO (synced 990 of Bitcoin tip 999), 1 provisional",
            "fee address:   bcrt1qfee",
            "bcrt1qminer extended class 9 (Stock Antminer)",
            "warning: Stock Antminer firmware is limited to slot class 9",
        ] {
            assert!(out.contains(want), "{want:?} missing from:\n{out}");
        }
        let empty = render_node_pool_status(&serde_json::json!({}));
        assert!(
            empty.contains("caught up ?"),
            "unknown is not healthy: {empty}"
        );
    }
}
