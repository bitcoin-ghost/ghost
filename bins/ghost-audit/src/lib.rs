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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! `ghost-audit`: a miner's check that the node it mines on is honest with it (W2.9).
//!
//! Any node checks any other node's shares, so a node cannot credit itself work it did not do or
//! pay the wrong people in a block without the pool refusing it. What no other node can see is the
//! job a node hands its own miner before the miner hashes it. A hostile node can stamp a job with
//! its own payee, or build a coinbase that pays someone the ledger does not owe; the shares would
//! credit the node, and nothing on the share chain would look wrong. Only the miner can catch
//! that, by checking the jobs it is sent. That is this crate.
//!
//! The auditor connects to the node's stratum port like a miner ([`crate::sv1`]), takes jobs,
//! and judges each one ([`crate::check::audit_job`]):
//!
//! - **the coinbase pays the canonical outputs** for the job's height, parent anchor and slot
//!   class, recomputed from a share chain the auditor syncs itself from relay peers
//!   ([`crate::source`]), never from the audited node;
//! - **the share tag credits the miner**: the job's tag opens to the miner's own payout script
//!   with the node's disclosed job stamp ([`ghost_np_relay::client`]);
//! - **the committed tier is one the miner's shares meet.**
//!
//! It submits nothing. It never sends `mining.submit`, so no share it could find is credited to
//! anyone. It only reads jobs.
//!
//! [`crate::probe`] is the public prober: the same checks plus the node's relay advert, with a
//! machine-readable verdict that open listing (W2.10) calls to decide whether to list a node.
//! Open listing itself is [`crate::discover`] (candidates from relay gossip), [`crate::listing`]
//! (the policy and the generated `node-list.json` and DNS fragment) and [`crate::lister`] (one
//! round), run by `ghost-audit list`.

#![warn(missing_docs)]

pub mod check;
pub mod discover;
pub mod job;
pub mod lister;
pub mod listing;
pub mod probe;
pub mod source;
pub mod sv1;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use ghost_np_relay::client::{fetch_stamps, ClientError};
use ghost_np_relay::wire::JobStamps;

use crate::check::{audit_job, FailReason, JobReport, ShareChainData, Verdict};
use crate::job::Job;
use crate::sv1::{Sv1Config, Sv1Error, Sv1Session};

/// What the audited node said when asked for its job stamps.
#[derive(Debug, Clone)]
pub enum StampAnswer {
    /// Its stamps.
    Stamps(JobStamps),
    /// It answered, and refused: it does not disclose what its tags commit to.
    Refused(String),
    /// It could not be asked (unreachable, timed out, another share chain).
    Unreachable(String),
}

/// Where job stamps come from.
#[async_trait]
pub trait StampSource: Send + Sync {
    /// Ask now.
    async fn stamps(&self) -> StampAnswer;
}

/// The audited node's relay port.
#[derive(Debug, Clone)]
pub struct RelayStamps {
    /// Its relay address.
    pub addr: SocketAddr,
    /// The share chain's genesis.
    pub genesis: [u8; 32],
    /// Deadline per request.
    pub timeout: Duration,
}

#[async_trait]
impl StampSource for RelayStamps {
    async fn stamps(&self) -> StampAnswer {
        let agent = format!("ghost-audit/{}", env!("CARGO_PKG_VERSION"));
        match fetch_stamps(self.addr, self.genesis, &agent, self.timeout).await {
            Ok((_, s)) => StampAnswer::Stamps(s),
            Err(e @ ClientError::NoStamps) => StampAnswer::Refused(e.to_string()),
            Err(e @ ClientError::Genesis { .. }) | Err(e @ ClientError::Version { .. }) => {
                StampAnswer::Refused(e.to_string())
            }
            Err(e) => StampAnswer::Unreachable(e.to_string()),
        }
    }
}

/// Judge `job`, asking for fresh stamps first and once more if the tag does not open (the node
/// may have re-stamped between the job and the request), and retrying an UNCHECKED verdict until
/// `wait` has passed (the auditor's share chain may still be syncing).
pub async fn judge_job(
    job: &Job,
    payee: &[u8],
    stamps: &dyn StampSource,
    data: &dyn ShareChainData,
    wait: Duration,
) -> JobReport {
    let deadline = Instant::now() + wait;
    let mut answer = stamps.stamps().await;
    let mut refetched = false;
    loop {
        let r = match &answer {
            StampAnswer::Stamps(s) => audit_job(job, payee, Some(s), data).await,
            StampAnswer::Refused(why) => {
                let mut r = audit_job(job, payee, None, data).await;
                if r.reason == Some(FailReason::TagNotBinding) {
                    r.detail = format!("{} ({why})", r.detail);
                }
                r
            }
            StampAnswer::Unreachable(why) => {
                let mut r = audit_job(job, payee, None, data).await;
                if r.reason == Some(FailReason::TagNotBinding) {
                    r.verdict = Verdict::Unchecked;
                    r.reason = None;
                    r.detail = format!("could not ask the node's relay port for its stamps: {why}");
                }
                r
            }
        };
        let retry_stamps = r.reason == Some(FailReason::TagNotBinding) && !refetched;
        if retry_stamps {
            refetched = true;
            answer = stamps.stamps().await;
            continue;
        }
        if r.verdict == Verdict::Unchecked && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if matches!(answer, StampAnswer::Unreachable(_)) {
                answer = stamps.stamps().await;
            }
            continue;
        }
        return r;
    }
}

/// What to audit.
#[derive(Debug, Clone)]
pub struct AuditTarget {
    /// The node's stratum port and how to log in.
    pub stratum: Sv1Config,
    /// The miner's payout script (from the address in `stratum.username`).
    pub payee: Vec<u8>,
    /// Jobs to judge; 0 runs until the connection ends.
    pub jobs: usize,
    /// How long to keep retrying an UNCHECKED job.
    pub wait: Duration,
    /// How long to wait for the next job.
    pub job_timeout: Duration,
}

/// Connect like a miner and judge `target.jobs` jobs, calling `on_report` after each. Submits
/// nothing.
pub async fn audit_jobs(
    target: &AuditTarget,
    stamps: &dyn StampSource,
    data: &dyn ShareChainData,
    mut on_report: impl FnMut(&JobReport),
) -> Result<Vec<JobReport>, Sv1Error> {
    let mut s = Sv1Session::connect(&target.stratum).await?;
    let mut out = Vec::new();
    while target.jobs == 0 || out.len() < target.jobs {
        let job = match s.next_job(target.job_timeout).await {
            Ok(j) => j,
            Err(e) if !out.is_empty() && target.jobs == 0 => {
                tracing::warn!("stratum session ended: {e}");
                break;
            }
            Err(e) => return Err(e),
        };
        let r = judge_job(&job, &target.payee, stamps, data, target.wait).await;
        on_report(&r);
        out.push(r);
    }
    Ok(out)
}
