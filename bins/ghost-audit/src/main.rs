//! `ghost-audit`: check that a Ghost Solo node's jobs pay you and the treasury, and nothing else.
//!
//! `ghost-audit check` connects to a node's stratum port like a miner, with your payout address,
//! and checks every job it is sent, over Stratum V1, Stratum V2 or both. It never submits a
//! share. See the library docs for the rule, the output and the exit status.

use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;

use ghost_audit::check::{JobReport, Verdict};
use ghost_audit::sv1::Sv1Config;
use ghost_audit::sv2::{Sv2Config, Sv2Device, DEFAULT_HASH_RATE};
use ghost_audit::{audit_sv1, audit_sv2};
use ghost_common::solo::{payee_script_class, SoloNetwork};

#[derive(Parser)]
#[command(
    name = "ghost-audit",
    version,
    about = "Check that a Ghost Solo node's jobs pay you and the treasury, and nothing else",
    long_about = "Check that a Ghost Solo node's jobs pay you and the treasury, and nothing \
                  else.\n\nghost-audit connects to the node's stratum port like a miner, with \
                  your payout address, and checks that each job's coinbase pays the treasury \
                  exactly subsidy / 200 and your address everything else (subsidy - subsidy / \
                  200 + fees), followed by nothing but the witness commitment. It never submits \
                  a share: it only reads jobs."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect like a miner and check the jobs the node sends.
    Check(CheckArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Signet,
    Regtest,
}

impl Network {
    fn solo(self) -> SoloNetwork {
        match self {
            Network::Mainnet => SoloNetwork::Mainnet,
            Network::Signet => SoloNetwork::Signet,
            Network::Regtest => SoloNetwork::Regtest,
        }
    }
}

#[derive(Args)]
struct CheckArgs {
    /// The node's SV1 stratum port, `host:port`.
    #[arg(long)]
    sv1: Option<String>,
    /// The node's SV2 port, `host:port`.
    #[arg(long, requires = "authority_key")]
    sv2: Option<String>,
    /// The SV2 authority public key the node's Noise certificate must be signed by (base58check,
    /// as pool_sv2 prints it).
    #[arg(long)]
    authority_key: Option<String>,
    /// Your payout address (P2SH, P2WPKH, P2WSH or P2TR).
    #[arg(long)]
    address: String,
    /// Worker name: the stratum username becomes `address.worker`.
    #[arg(long)]
    worker: Option<String>,
    /// The network the node mines on.
    #[arg(long, value_enum, default_value = "mainnet")]
    network: Network,
    /// Jobs to check on each protocol (on SV2, on each channel); 0 keeps going until the node
    /// disconnects.
    #[arg(long, default_value_t = 3)]
    jobs: usize,
    /// Seconds to wait for each connection and each job.
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
    /// User agent sent in mining.subscribe.
    #[arg(long)]
    user_agent: Option<String>,
    /// The hash rate the SV2 channels declare, H/s; the node sets their difficulty from it.
    #[arg(long, default_value_t = DEFAULT_HASH_RATE)]
    sv2_hash_rate: f32,
    /// One JSON object for the whole check instead of text.
    #[arg(long)]
    json: bool,
}

fn payee_script(address: &str, network: SoloNetwork) -> Result<Vec<u8>, String> {
    let a = bitcoin::Address::from_str(address.trim())
        .map_err(|e| format!("{address}: {e}"))?
        .require_network(network.bitcoin_network())
        .map_err(|e| format!("{address}: {e}"))?;
    let script = a.script_pubkey().to_bytes();
    if payee_script_class(&script).is_none() {
        return Err(format!(
            "{address}: the pool pays only P2SH, P2WPKH, P2WSH and P2TR addresses"
        ));
    }
    Ok(script)
}

fn print_text(r: &JobReport) {
    let v = match r.verdict {
        Verdict::Pass => "PASS",
        Verdict::Fail => "FAIL",
        Verdict::Unchecked => "UNCHECKED",
    };
    let n = |x: Option<u64>| x.map_or_else(|| "?".to_string(), |x| x.to_string());
    let why = r
        .reason
        .as_ref()
        .map(|w| format!(": {w}"))
        .unwrap_or_default();
    println!(
        "{v:<9} {} height {} treasury {} miner {} fees {} ({} B){why}",
        r.job_id,
        n(r.height),
        n(r.treasury_sats),
        n(r.miner_sats),
        n(r.fees_sats),
        r.coinbase_bytes
    );
}

/// Exit status for what was checked: 1 on any fail, 2 if nothing passed or anything is unchecked
/// or errored, else 0.
fn exit_status(reports: &[JobReport], errors: usize) -> u8 {
    if reports.iter().any(|r| r.verdict == Verdict::Fail) {
        1
    } else if errors > 0
        || reports.is_empty()
        || reports.iter().any(|r| r.verdict == Verdict::Unchecked)
    {
        2
    } else {
        0
    }
}

async fn run_check(a: CheckArgs) -> Result<ExitCode, String> {
    if a.sv1.is_none() && a.sv2.is_none() {
        return Err("give --sv1 <host:port>, --sv2 <host:port>, or both".into());
    }
    let network = a.network.solo();
    let payee = payee_script(&a.address, network)?;
    let username = match &a.worker {
        Some(w) => format!("{}.{w}", a.address.trim()),
        None => a.address.trim().to_string(),
    };
    let timeout = Duration::from_secs(a.timeout_secs.max(1));
    let text = !a.json;
    let print = |r: &JobReport| {
        if text {
            print_text(r);
        }
    };
    let mut reports = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    if let Some(addr) = &a.sv1 {
        let cfg = Sv1Config {
            addr: addr.clone(),
            username: username.clone(),
            password: "x".into(),
            user_agent: a
                .user_agent
                .clone()
                .unwrap_or_else(|| format!("ghost-audit/{}", env!("CARGO_PKG_VERSION"))),
            timeout,
        };
        match audit_sv1(&cfg, &payee, network, a.jobs, timeout, print).await {
            Ok(r) => reports.extend(r),
            Err(e) => errors.push(format!("SV1 {addr}: {e}")),
        }
    }
    if let (Some(addr), Some(key)) = (&a.sv2, &a.authority_key) {
        let cfg = Sv2Config {
            addr: addr.clone(),
            authority_key: key.clone(),
            username: username.clone(),
            device: Sv2Device {
                vendor: "ghost-audit".into(),
                hardware_version: String::new(),
                firmware: env!("CARGO_PKG_VERSION").into(),
            },
            nominal_hash_rate: a.sv2_hash_rate,
            timeout,
        };
        match audit_sv2(&cfg, &payee, network, a.jobs, timeout, print).await {
            Ok(r) => reports.extend(r),
            Err(e) => errors.push(format!("SV2 {addr}: {e}")),
        }
    }
    let count = |v: Verdict| reports.iter().filter(|r| r.verdict == v).count();
    let (passed, failed, unchecked) = (
        count(Verdict::Pass),
        count(Verdict::Fail),
        count(Verdict::Unchecked),
    );
    if a.json {
        let out = json!({
            "address": a.address.trim(),
            "network": network.as_str(),
            "jobs": &reports,
            "passed": passed,
            "failed": failed,
            "unchecked": unchecked,
            "errors": errors,
        });
        println!("{out}");
    } else {
        for e in &errors {
            eprintln!("ghost-audit: {e}");
        }
        println!("{passed} passed, {failed} failed, {unchecked} unchecked");
    }
    Ok(ExitCode::from(exit_status(&reports, errors.len())))
}

#[tokio::main]
async fn main() -> ExitCode {
    let r = match Cli::parse().cmd {
        Cmd::Check(a) => run_check(a).await,
    };
    r.unwrap_or_else(|e| {
        eprintln!("ghost-audit: {e}");
        ExitCode::from(2)
    })
}
