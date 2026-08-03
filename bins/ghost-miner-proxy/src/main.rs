//! ghost-miner-proxy — a decentralised mining-discovery shim.
//!
//! Point your ASIC/Bitaxe at this proxy instead of a DNS name. It fetches the BFT-signed Ghost
//! node-list checkpoint, verifies it offline against a baked-in genesis signer set (advancing
//! that set along the signed forward chain), and transparently stratum-proxies your miner to a
//! live pool node — failing over to another node if one is down. After the first fetch it needs
//! neither DNS nor the website: any one node serves the whole verifiable list.
//!
//! DISCOVERY, NOT CONSENSUS: this is a pure client. It never signs or votes; it only verifies.

mod checkpoint;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{info, warn};

use ghost_common::types::NodeId;

use checkpoint::{verify_and_advance, CheckpointBlob, VerifiedNode};

const ENDPOINT_PATH: &str = "/api/v1/pool/mesh-node-list-checkpoint";

#[derive(Parser, Clone)]
#[command(
    name = "ghost-miner-proxy",
    about = "Decentralised mining discovery: verify the signed Ghost node list and proxy your miner to a live pool node"
)]
struct Args {
    /// Address to listen on for the miner — point your ASIC/Bitaxe here.
    #[arg(long, default_value = "127.0.0.1:3333")]
    listen: String,

    /// Checkpoint endpoint seed(s) (repeatable). The endpoint path is appended automatically,
    /// e.g. `--seed https://pool.bitcoinghost.org` or `--seed http://203.0.113.7:8080`.
    /// After the first successful fetch, any verified node also serves as a seed.
    #[arg(long = "seed", required = true)]
    seeds: Vec<String>,

    /// Genesis signer set: comma-separated hex node ids (the MPC elders) — the root of trust.
    #[arg(long)]
    genesis_signers: Option<String>,

    /// File with one hex node id per line (`#` comments allowed): the genesis signer set.
    #[arg(long)]
    genesis_file: Option<std::path::PathBuf>,

    /// Proxy to the Stratum V2 port instead of V1.
    #[arg(long)]
    sv2: bool,

    /// Seconds between checkpoint refreshes (min 15).
    #[arg(long, default_value_t = 300)]
    refresh_secs: u64,
}

/// The shim's live, verified view.
struct PoolState {
    nodes: Vec<VerifiedNode>,
    trusted: Vec<NodeId>,
    rr: AtomicUsize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    // reqwest's rustls-tls backend needs a process-wide crypto provider installed.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();
    let genesis = load_genesis(&args)?;
    info!(
        signers = genesis.len(),
        "loaded genesis signer set (root of trust)"
    );

    let state = Arc::new(RwLock::new(PoolState {
        nodes: Vec::new(),
        trusted: genesis,
        rr: AtomicUsize::new(0),
    }));

    // Best-effort initial fetch so we can route immediately; otherwise the background loop fills
    // it in shortly.
    if let Err(e) = refresh(&args, &state).await {
        warn!(error = %e, "initial checkpoint fetch failed — retrying in the background");
    }

    // Background refresh: node lists change often (nodes join/leave), signer sets rarely.
    {
        let args = args.clone();
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut iv =
                tokio::time::interval(std::time::Duration::from_secs(args.refresh_secs.max(15)));
            iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                iv.tick().await;
                if let Err(e) = refresh(&args, &state).await {
                    warn!(error = %e, "checkpoint refresh failed (keeping last verified list)");
                }
            }
        });
    }

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    info!(listen = %args.listen, sv2 = args.sv2, "listening — point your miner here");
    loop {
        let (inbound, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let state = Arc::clone(&state);
        let sv2 = args.sv2;
        tokio::spawn(async move {
            if let Err(e) = handle_conn(inbound, sv2, &state).await {
                warn!(peer = %peer, error = %e, "miner connection ended");
            }
        });
    }
}

/// Fetch the latest signed checkpoint from a seed, verify it, and update the live view. The
/// seed list is the configured seeds plus every currently-verified node (so DNS/the site are
/// only ever needed for the very first fetch).
async fn refresh(args: &Args, state: &Arc<RwLock<PoolState>>) -> Result<()> {
    // Snapshot trusted set + build the candidate seed list (configured + known nodes).
    let (mut trusted, mut urls) = {
        let s = state.read().await;
        let mut urls: Vec<String> = args.seeds.clone();
        for n in &s.nodes {
            // Verified nodes serve the same endpoint on their HTTP port (8080).
            urls.push(format!("http://{}:8080", n.host));
        }
        (s.trusted.clone(), urls)
    };
    urls.dedup();

    let blob = fetch_blob(&urls).await?;
    let nodes = verify_and_advance(&blob, &mut trusted)?;
    let mut s = state.write().await;
    s.nodes = nodes;
    s.trusted = trusted;
    info!(
        nodes = s.nodes.len(),
        height = blob.height,
        "checkpoint verified and applied"
    );
    Ok(())
}

/// Try each seed URL until one returns a parseable checkpoint blob.
async fn fetch_blob(seeds: &[String]) -> Result<CheckpointBlob> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut last_err = None;
    for seed in seeds {
        let url = format!("{}{}", seed.trim_end_matches('/'), ENDPOINT_PATH);
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json::<CheckpointBlob>().await {
                Ok(b) => return Ok(b),
                Err(e) => last_err = Some(anyhow::anyhow!("parse {url}: {e}")),
            },
            Ok(resp) => last_err = Some(anyhow::anyhow!("{url}: HTTP {}", resp.status())),
            Err(e) => last_err = Some(anyhow::anyhow!("{url}: {e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no seeds configured")))
}

/// Route one miner connection to a verified node, round-robin, failing over to the next node on
/// a connection error. Transparent byte proxy — the miner's Stratum session terminates on the node.
async fn handle_conn(
    mut inbound: TcpStream,
    sv2: bool,
    state: &Arc<RwLock<PoolState>>,
) -> Result<()> {
    let candidates: Vec<VerifiedNode> = {
        let s = state.read().await;
        let n = s.nodes.len();
        if n == 0 {
            bail!("no verified nodes yet — waiting on the first checkpoint");
        }
        let start = s.rr.fetch_add(1, Ordering::Relaxed);
        (0..n).map(|i| s.nodes[(start + i) % n].clone()).collect()
    };

    for node in candidates {
        let port = if sv2 { node.sv2_port } else { node.sv1_port };
        let addr = format!("{}:{}", node.host, port);
        match TcpStream::connect(&addr).await {
            Ok(mut outbound) => {
                info!(upstream = %addr, "routing miner");
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                return Ok(());
            }
            Err(e) => warn!(upstream = %addr, error = %e, "node unreachable — trying next"),
        }
    }
    bail!("all verified nodes unreachable")
}

/// Parse the genesis signer set from `--genesis-signers` and/or `--genesis-file` into a sorted,
/// de-duplicated set of 32-byte node ids.
fn load_genesis(args: &Args) -> Result<Vec<NodeId>> {
    let mut raw: Vec<String> = Vec::new();
    if let Some(s) = &args.genesis_signers {
        raw.extend(
            s.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty()),
        );
    }
    if let Some(path) = &args.genesis_file {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        raw.extend(
            text.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')),
        );
    }
    if raw.is_empty() {
        bail!("provide --genesis-signers or --genesis-file (the MPC elder node ids = the root of trust)");
    }
    let mut set = std::collections::BTreeSet::new();
    for h in raw {
        let b = hex::decode(&h).with_context(|| format!("invalid hex node id: {h}"))?;
        if b.len() != 32 {
            bail!("node id must be 32 bytes: {h}");
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&b);
        set.insert(id);
    }
    Ok(set.into_iter().collect())
}
