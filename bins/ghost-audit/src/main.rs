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
//! and judges every job it is sent, over Stratum V1, Stratum V2 or both. `ghost-audit probe` is the public prober: it checks a node's
//! relay advert and jobs and prints a JSON verdict. `ghost-audit list` is open listing (W2.10):
//! it finds nodes from relay gossip, probes them on a schedule, and writes the website's
//! `node-list.json` and a DNS fragment. `ghost-audit merge` combines several listers' lists by
//! majority and pushes DNS changes through a hook. None of them submits a share.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};

use ghost_audit::check::{JobReport, ShareChainData, Verdict};
use ghost_audit::discover::Limits;
use ghost_audit::lister::{now_secs, run_round, write_atomic, LiveProber, RoundConfig};
use ghost_audit::listing::{render_dns, render_node_list, DnsConfig, ListMeta, ListState, Policy};
use ghost_audit::merge::{
    display_source, fetch, merge, publish_dns, render_merged, render_merged_dns, Fetched, Hook,
    MergeConfig, PushOutcome, SourceReport, SourceStatus,
};
use ghost_audit::probe::{probe, read_advert, ProbeConfig, ProbeVerdict, Sv2Endpoint};
use ghost_audit::source::{start_share_chain, ChainConfig, ExportSource, GenesisSource};
use ghost_audit::sv1::Sv1Config;
use ghost_audit::sv2::{Sv2Config, Sv2Device, DEFAULT_HASH_RATE};
use ghost_audit::{audit_jobs, audit_sv2_jobs, AuditTarget, RelayStamps, Sv2Target};
use ghost_common::node_pool_constants::T_NET_FLOOR;
use ghost_common::node_pool_genesis_export::hex32;
use ghost_common::node_pool_network::{NodePoolNetwork, MAINNET_START};
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
    /// Open listing: find nodes from relay gossip, probe them on a schedule, and write the
    /// website's node-list.json and a DNS fragment.
    List(ListArgs),
    /// Merge several listers' node-list.json into one, listing a node only when a strict
    /// majority of the configured listers list it, and push DNS changes through a hook.
    Merge(MergeArgs),
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

    fn node_pool(self) -> NodePoolNetwork {
        match self {
            Network::Mainnet => NodePoolNetwork::Mainnet,
            Network::Signet => NodePoolNetwork::Signet,
            Network::Regtest => NodePoolNetwork::Regtest,
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
    /// The network's published ledger export: a directory holding ledger-export.bin and
    /// ledger-export.json. Its genesis table (the balances carried over at the cutover) is what
    /// every table folds onto. Checked as pool_sv2's import checks it and kept in the auditor's
    /// store, so later runs need not pass it again.
    #[arg(long, requires = "export_digest", env = "GHOST_AUDIT_GENESIS_EXPORT")]
    genesis_export: Option<PathBuf>,
    /// The published sha256 of ledger-export.bin, 64 hex characters.
    #[arg(long, requires = "genesis_export", env = "GHOST_AUDIT_EXPORT_DIGEST")]
    export_digest: Option<String>,
    /// The network's pinned genesis table digest (the table_root nodes pin), 64 hex characters.
    /// Nothing is audited unless the auditor's genesis table hashes to it. Required except on
    /// regtest; on mainnet it must equal the compiled one once that is set.
    #[arg(long, env = "GHOST_AUDIT_GENESIS_TABLE_DIGEST")]
    genesis_table_digest: Option<String>,
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
    stratum: Option<String>,
    /// The node's SV2 port, `host:port`.
    #[arg(long)]
    sv2: Option<String>,
    /// The SV2 authority public key the node's Noise certificate must be signed by
    /// (base58check). Default: the key the node's relay advertises.
    #[arg(long)]
    sv2_authority_key: Option<String>,
    /// The node's relay port, `host:port`: asked for its job stamps (and its advert).
    #[arg(long)]
    node_relay: String,
    /// User agent sent in mining.subscribe. The node picks the slot class from it: pass your
    /// miner's own (for example `bmminer/2.0.0`) to audit the class your hardware is served.
    #[arg(long)]
    user_agent: Option<String>,
    #[command(flatten)]
    sv2_id: Sv2IdArgs,
    /// Seconds to keep retrying a job the auditor cannot judge yet (its share chain is syncing).
    #[arg(long, default_value_t = 300)]
    wait: u64,
    /// Seconds to wait for each job and each connection.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
}

/// What the SV2 channels say about the miner.
#[derive(Args)]
struct Sv2IdArgs {
    /// `vendor/hardware_version/firmware` sent in the SV2 SetupConnection. The node may pick an
    /// extended channel's slot class from it: pass your miner's own to audit its class.
    #[arg(long)]
    sv2_device: Option<String>,
    /// The hash rate the SV2 channels declare, H/s; the node sets their difficulty from it.
    #[arg(long, default_value_t = DEFAULT_HASH_RATE)]
    sv2_hash_rate: f32,
}

impl Sv2IdArgs {
    fn device(&self) -> Sv2Device {
        match &self.sv2_device {
            Some(d) => Sv2Device::parse(d),
            None => Sv2Device {
                vendor: "ghost-audit".into(),
                hardware_version: String::new(),
                firmware: env!("CARGO_PKG_VERSION").into(),
            },
        }
    }
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
    /// Jobs to judge on each protocol (on SV2, on each channel); 0 keeps going until the node
    /// disconnects.
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
    /// Jobs to judge on each protocol.
    #[arg(long, default_value_t = 2)]
    jobs: usize,
}

#[derive(Args)]
struct ListArgs {
    #[command(flatten)]
    chain: ChainArgs,
    /// A relay to start discovery from, `host:port`, besides the --relay-peer ones. Repeat for
    /// more.
    #[arg(long = "seed")]
    seeds: Vec<String>,
    /// The payout address the probes log in with; every job must credit it.
    #[arg(long)]
    address: String,
    /// User agent sent in mining.subscribe.
    #[arg(long)]
    user_agent: Option<String>,
    #[command(flatten)]
    sv2_id: Sv2IdArgs,
    /// The lister's state (candidates and probe history). Default: <data dir>/list-state.json.
    #[arg(long)]
    state: Option<PathBuf>,
    /// Where to write node-list.json. Not written if absent.
    #[arg(long)]
    out_json: Option<PathBuf>,
    /// Where to write the DNS zone fragment. Not written if absent.
    #[arg(long)]
    out_dns: Option<PathBuf>,
    /// Run one round, write, and exit.
    #[arg(long)]
    once: bool,
    /// Seconds between the starts of rounds.
    #[arg(long, default_value_t = 600)]
    interval: u64,
    /// Passes needed within the window to be listed.
    #[arg(long, default_value_t = 3)]
    list_after: usize,
    /// Probes of history per node that listing looks at.
    #[arg(long, default_value_t = 6)]
    window: usize,
    /// Probes in a row that are not a pass (fail or unmeasured) that delist a listed node.
    #[arg(long, default_value_t = 3)]
    delist_after: usize,
    /// Failed probes in a row that delist a listed node.
    #[arg(long, default_value_t = 1)]
    delist_after_fail: usize,
    /// Most candidates kept.
    #[arg(long, default_value_t = 1_024)]
    max_candidates: usize,
    /// Most candidates on one IP.
    #[arg(long, default_value_t = 2)]
    max_per_ip: usize,
    /// Most relays asked for addresses in one round.
    #[arg(long, default_value_t = 256)]
    max_crawl: usize,
    /// Accept private and loopback addresses from gossip. Always on for regtest.
    #[arg(long)]
    allow_private: bool,
    /// Nodes probed at once.
    #[arg(long, default_value_t = 4)]
    probe_concurrency: usize,
    /// Jobs judged per probe, on each protocol.
    #[arg(long, default_value_t = 2)]
    jobs: usize,
    /// Seconds to keep retrying a job the prober cannot judge yet.
    #[arg(long, default_value_t = 120)]
    wait: u64,
    /// Seconds to wait for each connection and each job.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
    /// Forget an unlisted candidate discovery has not seen for this many seconds.
    #[arg(long, default_value_t = 7 * 24 * 3_600)]
    forget_after: u64,
    /// DNS owner name for the fragment (relative to the zone, or absolute with a final dot).
    #[arg(long, default_value = "pool")]
    dns_name: String,
    /// DNS TTL, seconds.
    #[arg(long, default_value_t = 300)]
    dns_ttl: u32,
    /// Only listed nodes serving SV1 on this port go in the DNS fragment (a DNS name carries no
    /// port, so an SV2-only node is listed in node-list.json but not here).
    #[arg(long, default_value_t = 3333)]
    dns_sv1_port: u16,
    /// Most records in the DNS fragment.
    #[arg(long, default_value_t = 32)]
    dns_max: usize,
}

#[derive(Args)]
struct MergeArgs {
    /// A lister's node-list.json: an http:// or https:// URL (for a node running a lister,
    /// http://<node>:8080/api/v1/node-pool/node-list) or a file. Repeat for each lister. A node
    /// is listed when more than half of the listers given here list it; one that cannot be
    /// read, or whose list is not valid, votes for nothing.
    #[arg(long = "lister", required = true)]
    listers: Vec<String>,
    /// The network every list must be for.
    #[arg(long, value_enum, default_value = "mainnet")]
    network: Network,
    /// The share-chain genesis anchor every list must carry, 64 hex characters. Default: the one
    /// a majority of the listers carry.
    #[arg(long)]
    genesis_anchor: Option<String>,
    /// A list generated longer ago than this many seconds does not vote.
    #[arg(long, default_value_t = 3_600)]
    max_age: u64,
    /// Seconds to wait for each lister.
    #[arg(long, default_value_t = 20)]
    timeout: u64,
    /// Where to write the merged node-list.json.
    #[arg(long)]
    out_json: Option<PathBuf>,
    /// Where to write the merged DNS zone fragment.
    #[arg(long)]
    out_dns: Option<PathBuf>,
    /// DNS owner name for the fragment (relative to the zone, or absolute with a final dot).
    #[arg(long, default_value = "pool")]
    dns_name: String,
    /// DNS TTL, seconds.
    #[arg(long, default_value_t = 300)]
    dns_ttl: u32,
    /// Only merged nodes serving SV1 on this port go in the DNS fragment.
    #[arg(long, default_value_t = 3333)]
    dns_sv1_port: u16,
    /// Most records in the DNS fragment.
    #[arg(long, default_value_t = 32)]
    dns_max: usize,
    /// A program run, without a shell, when the fragment's records differ from the ones last
    /// pushed: `<program> <--dns-hook-arg…> <fragment path>`, with GHOST_DNS_FRAGMENT,
    /// GHOST_DNS_NAME, GHOST_DNS_OLD_RECORDS, GHOST_DNS_NEW_RECORDS and GHOST_DNS_FIRST_PUSH in
    /// its environment. The push is recorded (<fragment>.pushed) only when it exits 0. Needs
    /// --out-dns.
    #[arg(long, requires = "out_dns")]
    dns_hook: Option<PathBuf>,
    /// An argument for the hook, before the fragment's path. Repeat for more.
    #[arg(
        long = "dns-hook-arg",
        requires = "dns_hook",
        allow_hyphen_values = true
    )]
    dns_hook_args: Vec<String>,
    /// Seconds the hook may run before it is killed and the push counted as failed.
    #[arg(long, default_value_t = 120)]
    dns_hook_timeout: u64,
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
        let export = match (&self.genesis_export, &self.export_digest) {
            (Some(dir), Some(d)) => Some(ExportSource {
                dir: dir.clone(),
                digest: hex32(d, "--export-digest")?,
            }),
            _ => None,
        };
        let flag = self
            .genesis_table_digest
            .as_deref()
            .map(|d| hex32(d, "--genesis-table-digest"))
            .transpose()?;
        let compiled = match self.network {
            Network::Mainnet => MAINNET_START.and_then(|s| s.genesis_table_digest),
            _ => None,
        };
        let pinned = match (flag, compiled) {
            (Some(f), Some(c)) if f != c => {
                return Err(format!(
                    "--genesis-table-digest {} is not mainnet's compiled {}",
                    hex::encode(f),
                    hex::encode(c)
                ))
            }
            (f, c) => f.or(c),
        };
        Ok(ChainConfig {
            data_dir,
            genesis_table: GenesisSource {
                network: self.network.node_pool(),
                export,
                pinned,
            },
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

fn tally(reports: &[JobReport]) -> (usize, usize) {
    let fails = reports
        .iter()
        .filter(|r| r.verdict == Verdict::Fail)
        .count();
    let unchecked = reports
        .iter()
        .filter(|r| r.verdict == Verdict::Unchecked)
        .count();
    (fails, unchecked)
}

/// The SV2 authority key: `--sv2-authority-key`, else the one the node's relay advertises.
async fn sv2_key(n: &NodeArgs, relay: SocketAddr, genesis: [u8; 32]) -> Result<String, String> {
    if let Some(k) = &n.sv2_authority_key {
        return Ok(k.clone());
    }
    let t = Duration::from_secs(n.timeout.min(30));
    let a = read_advert(relay, genesis, t)
        .await
        .map_err(|e| format!("no --sv2-authority-key, and the node's advert: {e}"))?;
    if a.sv2_authority_key.is_empty() {
        return Err("no --sv2-authority-key, and the node advertises none".into());
    }
    Ok(a.sv2_authority_key)
}

async fn run_audit(a: AuditArgs) -> Result<ExitCode, String> {
    if a.node.stratum.is_none() && a.node.sv2.is_none() {
        return Err("pass --stratum (SV1), --sv2 (SV2), or both".into());
    }
    let payee = payee_script(&a.address, a.chain.network)?;
    let chain_cfg = a.chain.config().await?;
    let node_relay = resolve(&a.node.node_relay).await?;
    if chain_cfg.relay_peers.contains(&node_relay) {
        eprintln!(
            "note: the audited node {node_relay} is also a relay peer. Its share-chain data is \
             checked like any peer's, but add other peers so the audit does not depend on it."
        );
    }
    let sv2_key = match &a.node.sv2 {
        Some(_) => Some(sv2_key(&a.node, node_relay, chain_cfg.genesis_anchor).await?),
        None => None,
    };
    eprintln!("ghost-audit submits no shares: it only reads the jobs the node sends.");
    let data = start_share_chain(&chain_cfg).await?;
    let username = a.username.clone().unwrap_or_else(|| a.address.clone());
    let timeout = Duration::from_secs(a.node.timeout);
    let stamps = RelayStamps {
        addr: node_relay,
        genesis: chain_cfg.genesis_anchor,
        timeout: Duration::from_secs(a.node.timeout.min(30)),
    };
    let json = a.json;
    let print = |proto: &str, r: &JobReport| {
        if json {
            println!("{}", serde_json::to_string(r).unwrap_or_default());
        } else {
            print!("{proto} ");
            print_text(r);
        }
    };
    let v1 = async {
        let Some(addr) = &a.node.stratum else {
            return None;
        };
        let target = AuditTarget {
            stratum: Sv1Config {
                addr: addr.clone(),
                username: username.clone(),
                password: "x".into(),
                user_agent: agent(&a.node),
                timeout,
            },
            payee: payee.clone(),
            jobs: a.jobs,
            wait: Duration::from_secs(a.node.wait),
            job_timeout: timeout,
        };
        Some(
            audit_jobs(&target, &stamps, &data, |r| print("SV1", r))
                .await
                .map_err(|e| format!("SV1 {addr}: {e}")),
        )
    };
    let v2 = async {
        let (Some(addr), Some(key)) = (&a.node.sv2, &sv2_key) else {
            return None;
        };
        let target = Sv2Target {
            node: Sv2Config {
                addr: addr.clone(),
                authority_key: key.clone(),
                username: username.clone(),
                device: a.node.sv2_id.device(),
                nominal_hash_rate: a.node.sv2_id.sv2_hash_rate,
                timeout,
            },
            payee: payee.clone(),
            jobs: a.jobs,
            wait: Duration::from_secs(a.node.wait),
            job_timeout: timeout,
        };
        Some(
            audit_sv2_jobs(&target, &stamps, &data, |r| print("SV2", r))
                .await
                .map_err(|e| format!("SV2 {addr}: {e}")),
        )
    };
    let (r1, r2) = tokio::join!(v1, v2);
    let mut reports = Vec::new();
    let mut errors = Vec::new();
    for r in [r1, r2].into_iter().flatten() {
        match r {
            Ok(v) => reports.extend(v),
            Err(e) => errors.push(e),
        }
    }
    let (fails, unchecked) = tally(&reports);
    if !json {
        println!(
            "{} jobs: {} PASS, {fails} FAIL, {unchecked} UNCHECKED",
            reports.len(),
            reports.len() - fails - unchecked
        );
    }
    if fails == 0 && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    for e in &errors {
        eprintln!("ghost-audit: {e}");
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
    // Ports not given are the ones the node advertises, on its relay's IP: every protocol it
    // serves is probed.
    let need_advert =
        p.node.stratum.is_none() || p.node.sv2.is_none() || p.node.sv2_authority_key.is_none();
    let advert = if need_advert {
        read_advert(
            relay,
            chain_cfg.genesis_anchor,
            Duration::from_secs(p.node.timeout.min(30)),
        )
        .await
        .ok()
    } else {
        None
    };
    let at = |port: u16| SocketAddr::new(relay.ip(), port).to_string();
    let stratum = p.node.stratum.clone().or_else(|| {
        advert
            .as_ref()
            .filter(|a| a.sv1_port != 0)
            .map(|a| at(a.sv1_port))
    });
    let sv2_addr = p.node.sv2.clone().or_else(|| {
        advert
            .as_ref()
            .filter(|a| a.sv2_port != 0)
            .map(|a| at(a.sv2_port))
    });
    let sv2 = sv2_addr.map(|addr| Sv2Endpoint {
        addr,
        authority_key: p.node.sv2_authority_key.clone().unwrap_or_else(|| {
            advert
                .as_ref()
                .map(|a| a.sv2_authority_key.clone())
                .unwrap_or_default()
        }),
    });
    let data = start_share_chain(&chain_cfg).await?;
    let cfg = ProbeConfig {
        stratum,
        sv2,
        relay,
        genesis: chain_cfg.genesis_anchor,
        address: p.address.clone(),
        payee,
        user_agent: agent(&p.node),
        sv2_device: p.node.sv2_id.device(),
        sv2_hash_rate: p.node.sv2_id.sv2_hash_rate,
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

async fn run_list(a: ListArgs) -> Result<ExitCode, String> {
    let policy = Policy {
        list_after: a.list_after,
        window: a.window,
        delist_after: a.delist_after,
        delist_after_fail: a.delist_after_fail,
        interval_secs: a.interval,
    };
    policy.check()?;
    let payee = payee_script(&a.address, a.chain.network)?;
    let chain_cfg = a.chain.config().await?;
    let mut seeds = chain_cfg.relay_peers.clone();
    for s in &a.seeds {
        seeds.push(resolve(s).await?);
    }
    seeds.sort();
    seeds.dedup();
    let limits = Limits {
        max_candidates: a.max_candidates,
        max_per_ip: a.max_per_ip.max(1),
        max_crawl: a.max_crawl,
        allow_private: a.allow_private || matches!(a.chain.network, Network::Regtest),
        timeout: Duration::from_secs(a.timeout.min(30)),
        ..Limits::default()
    };
    let state_path = a
        .state
        .clone()
        .unwrap_or_else(|| chain_cfg.data_dir.join("list-state.json"));
    let mut state = match std::fs::read_to_string(&state_path) {
        Ok(s) => ListState::from_json(&s)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ListState::default(),
        Err(e) => return Err(format!("{}: {e}", state_path.display())),
    };
    let data: Arc<dyn ShareChainData> = Arc::new(start_share_chain(&chain_cfg).await?);
    let prober = Arc::new(LiveProber {
        genesis: chain_cfg.genesis_anchor,
        address: a.address.clone(),
        payee,
        user_agent: a
            .user_agent
            .clone()
            .unwrap_or_else(|| format!("ghost-audit-list/{}", env!("CARGO_PKG_VERSION"))),
        sv2_device: a.sv2_id.device(),
        sv2_hash_rate: a.sv2_id.sv2_hash_rate,
        jobs: a.jobs.max(1),
        wait: Duration::from_secs(a.wait),
        timeout: Duration::from_secs(a.timeout),
        data,
    });
    let round_cfg = RoundConfig {
        seeds,
        limits: limits.clone(),
        policy,
        probe_concurrency: a.probe_concurrency,
        forget_after_secs: a.forget_after,
    };
    let dns = DnsConfig {
        name: a.dns_name.clone(),
        ttl: a.dns_ttl,
        sv1_port: a.dns_sv1_port,
        max_records: a.dns_max,
    };
    let genesis = chain_cfg.genesis_anchor;
    let timeout = limits.timeout;
    eprintln!(
        "ghost-audit list: probes submit no shares. Listing: {} passes in {} probes, delist \
         after {} non-passes or {} fails.",
        policy.list_after, policy.window, policy.delist_after, policy.delist_after_fail
    );
    loop {
        let started = std::time::Instant::now();
        let r = run_round(
            &mut state,
            &round_cfg,
            move |relay| ghost_audit::discover::ask(relay, genesis, timeout),
            prober.clone(),
            now_secs(),
        )
        .await;
        let now = now_secs();
        let meta = ListMeta {
            generated_at: now,
            network: a.chain.network.name().to_string(),
            genesis_anchor: hex::encode(genesis),
            policy,
        };
        write_atomic(&state_path, &state.to_json())
            .map_err(|e| format!("{}: {e}", state_path.display()))?;
        if let Some(p) = &a.out_json {
            write_atomic(p, &render_node_list(&state, &meta))
                .map_err(|e| format!("{}: {e}", p.display()))?;
        }
        if let Some(p) = &a.out_dns {
            write_atomic(p, &render_dns(&state, &dns, now))
                .map_err(|e| format!("{}: {e}", p.display()))?;
        }
        eprintln!(
            "round: {} relays answered, {} candidates, {} probed ({} pass, {} fail, {} \
             unmeasured), {} listed; listed {:?}, delisted {:?}, forgot {}",
            r.answered,
            r.candidates,
            r.probed,
            r.outcomes.0,
            r.outcomes.1,
            r.outcomes.2,
            state.listed().count(),
            r.listed,
            r.delisted,
            r.forgotten
        );
        if a.once {
            return Ok(ExitCode::SUCCESS);
        }
        let next = Duration::from_secs(a.interval).saturating_sub(started.elapsed());
        tokio::time::sleep(next).await;
    }
}

/// `ghost-audit merge`. Exit 0 when written (and pushed, or nothing to push), 2 on no quorum
/// (nothing written), 4 when written but the DNS hook failed (retried on the next run).
async fn run_merge(a: MergeArgs) -> Result<ExitCode, String> {
    if a.out_json.is_none() && a.out_dns.is_none() {
        return Err("nothing to write: pass --out-json, --out-dns or both".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for l in &a.listers {
        if !seen.insert(display_source(l)) {
            return Err(format!(
                "--lister {} is given twice: each lister votes once",
                display_source(l)
            ));
        }
    }
    let genesis_anchor = a
        .genesis_anchor
        .as_deref()
        .map(|g| hex32(g, "--genesis-anchor").map(hex::encode))
        .transpose()?;
    let timeout = Duration::from_secs(a.timeout.max(1));
    let mut tasks = tokio::task::JoinSet::new();
    for (i, l) in a.listers.iter().enumerate() {
        let l = l.clone();
        tasks.spawn(async move { (i, fetch(&l, timeout).await) });
    }
    let mut fetched: Vec<Option<Fetched>> = vec![None; a.listers.len()];
    while let Some(done) = tasks.join_next().await {
        if let Ok((i, f)) = done {
            fetched[i] = Some(f);
        }
    }
    let inputs: Vec<(String, Fetched)> = a
        .listers
        .iter()
        .zip(fetched)
        .map(|(l, f)| {
            (
                display_source(l),
                f.unwrap_or_else(|| Fetched::Unreachable("the fetch task failed".into())),
            )
        })
        .collect();
    let now = now_secs();
    let cfg = MergeConfig {
        network: a.network.name().to_string(),
        genesis_anchor,
        max_age_secs: a.max_age,
        now,
    };
    let print_sources = |sources: &[SourceReport]| {
        for s in sources {
            match (s.status, &s.detail) {
                (SourceStatus::Ok, _) => {
                    eprintln!("lister {}: ok, {} listed", s.source, s.listed.unwrap_or(0))
                }
                (st, d) => eprintln!(
                    "lister {}: SKIPPED, {}: {}; it votes for nothing",
                    s.source,
                    st.label(),
                    d.as_deref().unwrap_or("")
                ),
            }
        }
    };
    let m = match merge(&inputs, &cfg) {
        Ok(m) => m,
        Err(e) => {
            print_sources(&e.sources);
            eprintln!("ghost-audit merge: {e}");
            return Ok(ExitCode::from(2));
        }
    };
    print_sources(&m.sources);
    if let Some(p) = &a.out_json {
        write_atomic(p, &render_merged(&m, now)).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    eprintln!(
        "merged: {} of {} listers voted, a node needs {}; {} listed of {} candidates",
        m.voting,
        m.configured,
        m.threshold,
        m.nodes.len(),
        m.candidates
    );
    let Some(out) = &a.out_dns else {
        return Ok(ExitCode::SUCCESS);
    };
    let dns = DnsConfig {
        name: a.dns_name.clone(),
        ttl: a.dns_ttl,
        sv1_port: a.dns_sv1_port,
        max_records: a.dns_max,
    };
    let hook = a.dns_hook.as_ref().map(|p| Hook {
        program: p.clone(),
        args: a.dns_hook_args.clone(),
        timeout: Duration::from_secs(a.dns_hook_timeout.max(1)),
        name: a.dns_name.clone(),
    });
    match publish_dns(out, &render_merged_dns(&m, &dns, now), hook.as_ref()).await? {
        PushOutcome::NoHook => eprintln!("dns: written; no --dns-hook"),
        PushOutcome::Unchanged => eprintln!("dns: records unchanged since the last push"),
        PushOutcome::Pushed => eprintln!("dns: records changed; the hook pushed them"),
        PushOutcome::Failed(why) => {
            eprintln!("dns: records changed but the push FAILED ({why}); retried next run");
            return Ok(ExitCode::from(4));
        }
    }
    Ok(ExitCode::SUCCESS)
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
        Cmd::List(l) => run_list(l).await,
        Cmd::Merge(m) => run_merge(m).await,
    };
    r.unwrap_or_else(|e| {
        eprintln!("ghost-audit: {e}");
        ExitCode::from(3)
    })
}
