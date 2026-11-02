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

//! `ghost-audit`: check that a node pool node's jobs pay the canonical coinbase and credit you.
//!
//! `ghost-audit audit` connects to a node's stratum port like a miner, with your payout address,
//! and judges every job it is sent. `ghost-audit probe` is the public prober: it checks a node's
//! relay advert and jobs and prints a JSON verdict. Neither submits a share.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use ghost_audit::check::{JobReport, Verdict};
use ghost_audit::probe::{probe, ProbeConfig, ProbeVerdict};
use ghost_audit::source::{start_share_chain, ChainConfig};
use ghost_audit::sv1::Sv1Config;
use ghost_audit::{audit_jobs, AuditTarget, RelayStamps};
use ghost_common::node_pool_constants::T_NET_FLOOR;
use ghost_common::node_pool_u256::U256;
use ghost_common::share_commit::{diff1_target, payee_script_class};

/// The regtest share-chain genesis every regtest node shares: sha256("GhostNodePool/genesis/regtest").
const REGTEST_GENESIS: &str = "8d8cd561340ff83e99410e115619d64ad94516264d3e5cd6a991109c69f1229c";
/// Regtest's tier base: its proof-of-work limit, so CPU-mined shares reach `T_net`.
const REGTEST_TIER_BASE: &str = "7fffff0000000000000000000000000000000000000000000000000000000000";

#[derive(Parser)]
#[command(
    name = "ghost-audit",
    version,
    about = "Check that a Ghost node pool node's jobs pay the canonical coinbase and credit you",
    long_about = "Check that a Ghost node pool node's jobs pay the canonical coinbase and credit \
                  you.\n\nghost-audit connects to the node's stratum port like a miner, with your \
                  payout address, and judges each job it is sent against a share chain it syncs \
                  itself from relay peers, settled from your own Bitcoin node. It never submits a \
                  share: it only reads jobs."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Judge the jobs a node sends you.
    Audit(AuditArgs),
    /// Probe a node's advert and jobs and print a JSON verdict (for open listing).
    Probe(ProbeArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Signet,
    Regtest,
}

impl Network {
    fn bitcoin(self) -> bitcoin::Network {
        match self {
            Network::Mainnet => bitcoin::Network::Bitcoin,
            Network::Signet => bitcoin::Network::Signet,
            Network::Regtest => bitcoin::Network::Regtest,
        }
    }

    fn rpc_port(self) -> u16 {
        match self {
            Network::Mainnet => 8332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        }
    }
}

/// The share chain and the Bitcoin node the auditor judges against.
#[derive(Args)]
struct ChainArgs {
    /// Bitcoin network.
    #[arg(long, value_enum, default_value = "mainnet")]
    network: Network,
    /// Share-chain genesis anchor, 64 hex characters. Regtest has a fixed one; none is published
    /// for mainnet or signet yet.
    #[arg(long)]
    genesis_anchor: Option<String>,
    /// The genesis anchor's Bitcoin height.
    #[arg(long)]
    genesis_height: Option<u32>,
    /// `T_net` at genesis.
    #[arg(long, default_value_t = T_NET_FLOOR)]
    genesis_tier: u8,
    /// Tier 0 target, 64 hex characters, big-endian. Defaults to difficulty 1 (regtest: its
    /// proof-of-work limit).
    #[arg(long)]
    tier_base: Option<String>,
    /// A relay peer to sync the share chain from, `host:port`. Repeat for more. Prefer nodes
    /// other than the one you audit.
    #[arg(long = "relay-peer", required = true)]
    relay_peers: Vec<String>,
    /// Where the auditor keeps its share chain. Default: ~/.ghost-audit/<network>.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Your Bitcoin node's RPC host.
    #[arg(long, default_value = "127.0.0.1")]
    rpc_host: String,
    /// Its RPC port. Default: the network's.
    #[arg(long)]
    rpc_port: Option<u16>,
    /// RPC user.
    #[arg(long, env = "GHOST_AUDIT_RPC_USER")]
    rpc_user: String,
    /// RPC password.
    #[arg(long, env = "GHOST_AUDIT_RPC_PASSWORD", hide_env_values = true)]
    rpc_password: String,
}

/// The node to audit or probe.
#[derive(Args)]
struct NodeArgs {
    /// The node's SV1 stratum port, `host:port`.
    #[arg(long)]
    stratum: String,
    /// The node's relay port, `host:port`: asked only for its job stamps.
    #[arg(long)]
    node_relay: String,
    /// User agent sent in mining.subscribe. The node picks the slot class from it: pass your
    /// miner's own (for example `bmminer/2.0.0`) to audit the class your hardware is served.
    #[arg(long)]
    user_agent: Option<String>,
    /// Seconds to keep retrying a job the auditor cannot judge yet (its share chain is syncing).
    #[arg(long, default_value_t = 300)]
    wait: u64,
    /// Seconds to wait for each job and each connection.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

#[derive(Args)]
struct AuditArgs {
    #[command(flatten)]
    chain: ChainArgs,
    #[command(flatten)]
    node: NodeArgs,
    /// Your payout address (P2SH, P2WPKH, P2WSH or P2TR).
    #[arg(long)]
    address: String,
    /// Stratum username, if not the bare address (for example `address.worker`).
    #[arg(long)]
    username: Option<String>,
    /// Jobs to judge; 0 keeps going until the node disconnects.
    #[arg(long, default_value_t = 3)]
    jobs: usize,
    /// One JSON object per job instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ProbeArgs {
    #[command(flatten)]
    chain: ChainArgs,
    #[command(flatten)]
    node: NodeArgs,
    /// The payout address the probe logs in with; its jobs must credit it.
    #[arg(long)]
    address: String,
    /// Jobs to judge.
    #[arg(long, default_value_t = 2)]
    jobs: usize,
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    hex::decode(s.trim())
        .map_err(|e| format!("{what}: {e}"))?
        .try_into()
        .map_err(|_| format!("{what}: not 32 bytes"))
}

async fn resolve(s: &str) -> Result<SocketAddr, String> {
    tokio::net::lookup_host(s)
        .await
        .map_err(|e| format!("{s}: {e}"))?
        .next()
        .ok_or_else(|| format!("{s}: no address"))
}

fn payee_script(address: &str, network: Network) -> Result<Vec<u8>, String> {
    let a = bitcoin::Address::from_str(address.trim())
        .map_err(|e| format!("{address}: {e}"))?
        .require_network(network.bitcoin())
        .map_err(|e| format!("{address}: {e}"))?;
    let script = a.script_pubkey().to_bytes();
    if payee_script_class(&script).is_none() {
        return Err(format!(
            "{address}: the node pool pays only P2SH, P2WPKH, P2WSH and P2TR addresses"
        ));
    }
    Ok(script)
}

impl ChainArgs {
    async fn config(&self) -> Result<ChainConfig, String> {
        let regtest = matches!(self.network, Network::Regtest);
        let genesis_anchor = match (&self.genesis_anchor, regtest) {
            (Some(g), _) => hex32(g, "--genesis-anchor")?,
            (None, true) => hex32(REGTEST_GENESIS, "regtest genesis")?,
            (None, false) => {
                return Err(format!(
                    "no share-chain genesis is published for {} yet: pass --genesis-anchor and \
                     --genesis-height",
                    self.network.name()
                ))
            }
        };
        let genesis_height = match (self.genesis_height, self.genesis_anchor.is_some(), regtest) {
            (Some(h), _, _) => h,
            (None, false, true) => 0,
            _ => return Err("--genesis-anchor needs --genesis-height".into()),
        };
        let tier_base = match (&self.tier_base, regtest) {
            (Some(t), _) => U256::from_be_bytes(hex32(t, "--tier-base")?),
            (None, true) => U256::from_be_bytes(hex32(REGTEST_TIER_BASE, "regtest tier base")?),
            (None, false) => diff1_target(),
        };
        let mut relay_peers = Vec::new();
        for p in &self.relay_peers {
            relay_peers.push(resolve(p).await?);
        }
        let data_dir = match &self.data_dir {
            Some(d) => d.clone(),
            None => PathBuf::from(std::env::var("HOME").map_err(|_| "set --data-dir")?)
                .join(".ghost-audit")
                .join(self.network.name()),
        };
        Ok(ChainConfig {
            data_dir,
            genesis_anchor,
            genesis_height,
            genesis_tier: self.genesis_tier,
            tier_base,
            relay_peers,
            rpc_host: self.rpc_host.clone(),
            rpc_port: self.rpc_port.unwrap_or(self.network.rpc_port()),
            rpc_user: self.rpc_user.clone(),
            rpc_password: self.rpc_password.clone(),
        })
    }
}

fn agent(n: &NodeArgs) -> String {
    n.user_agent
        .clone()
        .unwrap_or_else(|| format!("ghost-audit/{}", env!("CARGO_PKG_VERSION")))
}

fn print_text(r: &JobReport) {
    let v = match r.verdict {
        Verdict::Pass => "PASS",
        Verdict::Fail => "FAIL",
        Verdict::Unchecked => "UNCHECKED",
    };
    let why = r
        .reason
        .map(|x| format!("{}: ", x.label()))
        .unwrap_or_default();
    let h = r
        .height
        .map(|h| h.to_string())
        .unwrap_or_else(|| "?".into());
    let c = r
        .slot_class
        .map(|c| c.to_string())
        .unwrap_or_else(|| "?".into());
    println!(
        "{v:<9} job {} height {h} class {c} ({} outputs, {} B): {why}{}",
        r.job_id, r.outputs, r.coinbase_bytes, r.detail
    );
}

async fn run_audit(a: AuditArgs) -> Result<ExitCode, String> {
    let payee = payee_script(&a.address, a.chain.network)?;
    let chain_cfg = a.chain.config().await?;
    let node_relay = resolve(&a.node.node_relay).await?;
    if chain_cfg.relay_peers.contains(&node_relay) {
        eprintln!(
            "note: the audited node {node_relay} is also a relay peer. Its share-chain data is \
             checked like any peer's, but add other peers so the audit does not depend on it."
        );
    }
    eprintln!(
        "ghost-audit submits no shares: it only reads the jobs {} sends.",
        a.node.stratum
    );
    let data = start_share_chain(&chain_cfg).await?;
    let target = AuditTarget {
        stratum: Sv1Config {
            addr: a.node.stratum.clone(),
            username: a.username.clone().unwrap_or_else(|| a.address.clone()),
            password: "x".into(),
            user_agent: agent(&a.node),
            timeout: Duration::from_secs(a.node.timeout),
        },
        payee,
        jobs: a.jobs,
        wait: Duration::from_secs(a.node.wait),
        job_timeout: Duration::from_secs(a.node.timeout),
    };
    let stamps = RelayStamps {
        addr: node_relay,
        genesis: chain_cfg.genesis_anchor,
        timeout: Duration::from_secs(a.node.timeout.min(30)),
    };
    let json = a.json;
    let reports = audit_jobs(&target, &stamps, &data, |r| {
        if json {
            println!("{}", serde_json::to_string(r).unwrap_or_default());
        } else {
            print_text(r);
        }
    })
    .await
    .map_err(|e| format!("stratum {}: {e}", a.node.stratum))?;
    let fails = reports
        .iter()
        .filter(|r| r.verdict == Verdict::Fail)
        .count();
    let unchecked = reports
        .iter()
        .filter(|r| r.verdict == Verdict::Unchecked)
        .count();
    if !json {
        println!(
            "{} jobs: {} PASS, {fails} FAIL, {unchecked} UNCHECKED",
            reports.len(),
            reports.len() - fails - unchecked
        );
    }
    Ok(if fails > 0 {
        ExitCode::from(1)
    } else if unchecked > 0 || reports.is_empty() {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}

async fn run_probe(p: ProbeArgs) -> Result<ExitCode, String> {
    let payee = payee_script(&p.address, p.chain.network)?;
    let chain_cfg = p.chain.config().await?;
    let relay = resolve(&p.node.node_relay).await?;
    let data = start_share_chain(&chain_cfg).await?;
    let cfg = ProbeConfig {
        stratum: p.node.stratum.clone(),
        relay,
        genesis: chain_cfg.genesis_anchor,
        address: p.address.clone(),
        payee,
        user_agent: agent(&p.node),
        jobs: p.jobs,
        wait: Duration::from_secs(p.node.wait),
        timeout: Duration::from_secs(p.node.timeout),
    };
    let report = probe(&cfg, &data).await;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(match report.verdict {
        ProbeVerdict::Pass => ExitCode::SUCCESS,
        ProbeVerdict::Fail => ExitCode::from(1),
        ProbeVerdict::Unmeasured => ExitCode::from(2),
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let r = match Cli::parse().cmd {
        Cmd::Audit(a) => run_audit(a).await,
        Cmd::Probe(p) => run_probe(p).await,
    };
    r.unwrap_or_else(|e| {
        eprintln!("ghost-audit: {e}");
        ExitCode::from(3)
    })
}
