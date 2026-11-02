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
//! The auditor connects to the node's stratum port like a miner ([`crate::sv1`] for Stratum V1,
//! [`crate::sv2`] for Stratum V2, where it opens an extended and a standard channel), takes jobs,
//! and judges each one ([`crate::check::audit_job`]):
//!
//! - **the coinbase pays the canonical outputs** for the job's height, parent anchor and slot
//!   class, recomputed from a share chain the auditor syncs itself from relay peers
//!   ([`crate::source`]), never from the audited node;
//! - **the share tag credits the miner**: the job's tag opens to the miner's own payout script
//!   with the node's disclosed job stamp ([`ghost_np_relay::client`]);
//! - **the committed tier is one the miner's shares meet.**
//!
//! It submits nothing. It never sends `mining.submit` or `SubmitShares*`, so no share it could
//! find is credited to anyone. It only reads jobs.
//!
//! An SV2 standard channel's job is only a merkle root. The auditor checks it by rebuilding the
//! coinbase from the node's own extended job on the same template ([`crate::audit_sv2_jobs`],
//! [`crate::sv2::rebuild_standard`]).
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
pub mod sv2;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use ghost_common::coinbase_tags::extract_payout_tag;
use ghost_np_relay::client::{fetch_stamps, ClientError};
use ghost_np_relay::wire::JobStamps;

use crate::check::{audit_job, FailReason, JobReport, ShareChainData, Verdict};
use crate::job::{display_hex, Job};
use crate::sv1::{Sv1Config, Sv1Error, Sv1Session};
use crate::sv2::{
    rebuild_standard, ChannelKind, ExtendedJob, StandardJob, Sv2Config, Sv2Error, Sv2Job,
    Sv2Session,
};

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

/// What to audit over Stratum V2.
#[derive(Debug, Clone)]
pub struct Sv2Target {
    /// The node's SV2 port, its authority key, and how to log in.
    pub node: Sv2Config,
    /// The miner's payout script (from the address in `node.username`).
    pub payee: Vec<u8>,
    /// Jobs to judge on each channel (extended and standard); 0 runs until a connection ends.
    pub jobs: usize,
    /// How long to keep retrying an UNCHECKED job.
    pub wait: Duration,
    /// How long to wait for the next job.
    pub job_timeout: Duration,
}

/// A standard job waiting for the extended job it is rebuilt from.
struct PendingStandard {
    job: StandardJob,
    /// Extended jobs received before it.
    after: u64,
    arrived: Instant,
}

/// What rebuilding a standard job came to.
enum Rebuilt {
    /// The coinbase behind it.
    Job(Job),
    /// Nothing canonical hashes to it.
    NoMatch(String),
    /// The node will not disclose its stamps.
    Refused(String),
    /// Not judgeable yet.
    Unknown(String, Option<u32>),
}

/// Extended jobs on the same `prev_hash` that a standard job is rebuilt from, newest first, at
/// most this many.
const REBUILD_FROM: usize = 4;
/// Extended jobs kept.
const EXT_KEPT: usize = 32;
/// A standard job whose rebuild finds nothing is failed once an extended job has arrived after
/// it and this long has passed: pool_sv2 sends every channel its job for a template in the same
/// pass, so the matching extended job is in by then.
const SETTLE: Duration = Duration::from_secs(2);
/// How often waiting standard jobs are retried (each retry asks the node for its stamps once).
const RETRY: Duration = Duration::from_secs(2);

async fn rebuild(
    std: &StandardJob,
    exts: &[(u64, ExtendedJob)],
    payee: &[u8],
    answer: &StampAnswer,
    data: &dyn ShareChainData,
) -> Rebuilt {
    let Some(prev_height) = data.block_height(&std.prev_hash).await else {
        return Rebuilt::Unknown(
            "the job's prev_hash is not a Bitcoin block this auditor knows yet".into(),
            None,
        );
    };
    let h = prev_height + 1;
    let stamps = match answer {
        StampAnswer::Stamps(s) => s,
        StampAnswer::Refused(why) => return Rebuilt::Refused(why.clone()),
        StampAnswer::Unreachable(why) => {
            return Rebuilt::Unknown(
                format!("could not ask the node's relay port for its stamps: {why}"),
                Some(h),
            )
        }
    };
    let on_prev: Vec<ExtendedJob> = exts
        .iter()
        .rev()
        .filter(|(_, e)| e.job.prev_hash == std.prev_hash)
        .take(REBUILD_FROM)
        .map(|(_, e)| e.clone())
        .collect();
    if on_prev.is_empty() {
        return Rebuilt::Unknown(
            "no extended job on this prev_hash to rebuild the standard job from".into(),
            Some(h),
        );
    }
    // The anchors the extended jobs build on: a standard job of the same pass builds on the same
    // one. Their tables are tried first, and must be held before a miss can be a FAIL.
    let wanted: Vec<[u8; 16]> = on_prev
        .iter()
        .filter_map(|e| {
            e.job
                .coinbase
                .input
                .first()
                .and_then(|i| extract_payout_tag(i.script_sig.as_bytes()))
        })
        .collect();
    let (mut tables, mut others) = (Vec::new(), Vec::new());
    for a in &stamps.recent {
        let ours = wanted.iter().any(|p| a.parent_anchor.starts_with(p));
        match data.table(&a.parent_anchor, h, &std.prev_hash).await {
            Some(t) if ours => tables.push((*a, t)),
            Some(t) => others.push((*a, t)),
            None if ours => {
                return Rebuilt::Unknown(
                    format!(
                        "the anchor {} the node's jobs build on is not held yet",
                        hex::encode(a.parent_anchor)
                    ),
                    Some(h),
                )
            }
            None => {}
        }
    }
    tables.extend(others);
    if tables.is_empty() {
        return Rebuilt::Unknown(
            "none of the anchors the node stamps its jobs with is held yet".into(),
            Some(h),
        );
    }
    let (job, payee_v, node_id, n_stamps) = (
        std.clone(),
        payee.to_vec(),
        stamps.node_id,
        stamps.recent.len(),
    );
    let tables = Arc::new(tables);
    let halving = data.halving();
    let n_ext = on_prev.len();
    let found = tokio::task::spawn_blocking(move || {
        on_prev
            .iter()
            .find_map(|e| rebuild_standard(&job, e, &payee_v, &node_id, &tables, h, halving))
    })
    .await
    .ok()
    .flatten();
    match found {
        Some(j) => Rebuilt::Job(j),
        None => Rebuilt::NoMatch(format!(
            "no canonical coinbase crediting your payout script {}, under any of the node's {} \
             stamps, any slot class or any tier, hashes to the merkle root {} (rebuilt from the \
             node's {} newest extended jobs on this prev_hash): the job pays someone else, pays \
             other outputs, or credits someone else",
            hex::encode(payee),
            n_stamps,
            display_hex(&std.merkle_root),
            n_ext
        )),
    }
}

fn standard_report(
    job: &StandardJob,
    verdict: Verdict,
    reason: Option<FailReason>,
    detail: String,
    height: Option<u32>,
) -> JobReport {
    JobReport {
        job_id: job.job_id.clone(),
        verdict,
        reason,
        detail,
        height,
        prev_hash: display_hex(&job.prev_hash),
        parent_anchor: None,
        slot_class: None,
        tier: None,
        outputs: 0,
        coinbase_bytes: 0,
    }
}

/// Aborts the session readers when the audit returns.
struct Readers(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Readers {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

type Event = Result<Sv2Job, Sv2Error>;

fn spawn_reader(
    mut s: Sv2Session,
    tx: tokio::sync::mpsc::UnboundedSender<Event>,
    timeout: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let r = s.next_job(timeout).await;
            let end = r.is_err();
            if tx.send(r).is_err() || end {
                return;
            }
        }
    })
}

/// Connect over Stratum V2 like a miner and judge `target.jobs` jobs on each of an extended and
/// a standard channel, calling `on_report` after each. Submits nothing.
///
/// The extended channel opens first, on a connection of its own, and its jobs are judged as SV1
/// jobs are. The standard channel then opens on a second connection, as a header-only miner's
/// would (`REQUIRES_STANDARD_JOBS`), so nothing on it tells the node that the same auditor also
/// holds an extended channel. Each standard job is rebuilt from the extended jobs on its
/// `prev_hash` ([`crate::sv2::rebuild_standard`]) and the coinbase found is judged like any
/// other; if none is found once a later extended job is in, the job FAILs
/// ([`crate::check::FailReason::StandardJobNotCanonical`]). A standard job that cannot be rebuilt
/// yet (no extended job on its `prev_hash`, the auditor's share chain still syncing) is retried
/// until `target.wait` has passed and is then UNCHECKED.
pub async fn audit_sv2_jobs(
    target: &Sv2Target,
    stamps: &dyn StampSource,
    data: &dyn ShareChainData,
    mut on_report: impl FnMut(&JobReport),
) -> Result<Vec<JobReport>, Sv2Error> {
    let want = |n: usize| target.jobs == 0 || n < target.jobs;
    let mut ext = Sv2Session::connect(&target.node, ChannelKind::Extended).await?;
    let first = ext.next_job(target.job_timeout).await?;
    let std = Sv2Session::connect(&target.node, ChannelKind::Standard).await?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(Ok(first)).ok();
    let _readers = Readers(vec![
        spawn_reader(ext, tx.clone(), target.job_timeout),
        spawn_reader(std, tx, target.job_timeout),
    ]);

    let mut out = Vec::new();
    let (mut ext_done, mut std_done) = (0usize, 0usize);
    let mut exts: Vec<(u64, ExtendedJob)> = Vec::new();
    let mut ext_seq = 0u64;
    let mut pending: Vec<PendingStandard> = Vec::new();
    let mut last_try = Instant::now() - RETRY;
    loop {
        if target.jobs > 0 && ext_done >= target.jobs && std_done >= target.jobs {
            break;
        }
        let mut fresh = false;
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(Ok(Sv2Job::Extended(e)))) => {
                ext_seq += 1;
                fresh = true;
                if want(ext_done) {
                    let r = judge_job(&e.job, &target.payee, stamps, data, target.wait).await;
                    on_report(&r);
                    out.push(r);
                    ext_done += 1;
                }
                exts.push((ext_seq, e));
                if exts.len() > EXT_KEPT {
                    exts.remove(0);
                }
            }
            Ok(Some(Ok(Sv2Job::Standard(s)))) => {
                if want(std_done + pending.len()) {
                    pending.push(PendingStandard {
                        job: s,
                        after: ext_seq,
                        arrived: Instant::now(),
                    });
                    fresh = true;
                }
            }
            Ok(Some(Err(e))) => {
                if target.jobs == 0 && !out.is_empty() {
                    tracing::warn!("SV2 session ended: {e}");
                    break;
                }
                return Err(e);
            }
            Ok(None) => break,
            Err(_) => {}
        }
        if pending.is_empty() || !(fresh || last_try.elapsed() >= RETRY) {
            continue;
        }
        last_try = Instant::now();
        let answer = stamps.stamps().await;
        let mut keep = Vec::new();
        for p in pending.drain(..) {
            let settled = ext_seq > p.after && p.arrived.elapsed() >= SETTLE;
            let expired = p.arrived.elapsed() >= target.wait;
            let r = match rebuild(&p.job, &exts, &target.payee, &answer, data).await {
                Rebuilt::Job(j) => {
                    Some(judge_job(&j, &target.payee, stamps, data, target.wait).await)
                }
                Rebuilt::Refused(why) => Some(standard_report(
                    &p.job,
                    Verdict::Fail,
                    Some(FailReason::TagNotBinding),
                    format!(
                        "the node does not disclose its job stamps, so nothing shows the job \
                         credits you ({why})"
                    ),
                    None,
                )),
                Rebuilt::NoMatch(why) if settled || expired => Some(standard_report(
                    &p.job,
                    Verdict::Fail,
                    Some(FailReason::StandardJobNotCanonical),
                    why,
                    None,
                )),
                Rebuilt::Unknown(why, h) if expired => {
                    Some(standard_report(&p.job, Verdict::Unchecked, None, why, h))
                }
                _ => None,
            };
            match r {
                Some(r) => {
                    on_report(&r);
                    out.push(r);
                    std_done += 1;
                }
                None => keep.push(p),
            }
        }
        pending = keep;
    }
    Ok(out)
}
