//! `ghost-audit`: a miner's check that a Ghost Solo node's jobs pay the miner.
//!
//! On a solo pool the node builds every coinbase the miner hashes. A hostile or broken node could
//! hand the miner a job that pays someone else, and the miner would only find out when a block
//! went elsewhere. The auditor connects to the node's stratum port like a miner, with the miner's
//! payout address as its username, takes jobs, and checks each one ([`crate::check::audit_job`])
//! against the solo rule:
//!
//! - output 0 pays the treasury (`bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k`) exactly
//!   `subsidy / 200`;
//! - output 1 pays the miner's own address everything else, `subsidy - subsidy / 200 + fees`;
//! - nothing follows but a zero-value witness commitment.
//!
//! The height, and with it the subsidy, comes from the coinbase's BIP34 push; the subsidy halves
//! every 210,000 blocks (150 on regtest). The fees are not known to a miner, so they are reported
//! as what the miner's output implies.
//!
//! It submits nothing: no `mining.submit` and no `SubmitShares*`. It only reads jobs.
//!
//! ## Stratum V1 and V2
//!
//! - [`crate::sv1`]: subscribe and authorize, then read `mining.notify` ([`audit_sv1`]).
//! - [`crate::sv2`]: the Noise handshake checked against the node's authority key, then an
//!   extended channel (its jobs carry the coinbase) and a standard channel on a second
//!   connection, whose header-only jobs are checked by rebuilding their coinbase from the
//!   extended jobs ([`crate::sv2::rebuild_standard`], [`audit_sv2`]).
//!
//! ## CLI
//!
//! ```text
//! ghost-audit check --sv1 <host:port> --address <addr> [--worker <name>]
//!                   [--network mainnet|signet|regtest] [--jobs N] [--timeout-secs S] [--json]
//! ghost-audit check --sv2 <host:port> --authority-key <base58> --address <addr> [...]
//! ```
//!
//! Both `--sv1` and `--sv2` may be given; each is checked. Text output is one line per job
//! (`PASS ext-3 height 960000 treasury 1562500 miner 310942500 fees 5000`); `--json` prints one
//! object `{"address", "network", "jobs": [JobReport...], "passed", "failed", "unchecked",
//! "errors": [...]}`. Exit status: `0` every job checked passed, `1` a job failed, `2` nothing
//! could be judged (no job in time, a connection refused, bad arguments).

#![warn(missing_docs)]

pub mod check;
pub mod job;
pub mod sv1;
pub mod sv2;

use std::time::{Duration, Instant};

use ghost_common::solo::SoloNetwork;

use crate::check::{audit_job, JobReport};
use crate::sv1::{Sv1Config, Sv1Error, Sv1Session};
use crate::sv2::{
    rebuild_standard, ChannelKind, ExtendedJob, StandardJob, Sv2Config, Sv2Error, Sv2Job,
    Sv2Session,
};

/// Connect over Stratum V1 like a miner and check `jobs` jobs (0: until the session ends),
/// calling `on_report` after each. Submits nothing.
pub async fn audit_sv1(
    cfg: &Sv1Config,
    payee: &[u8],
    network: SoloNetwork,
    jobs: usize,
    job_timeout: Duration,
    mut on_report: impl FnMut(&JobReport),
) -> Result<Vec<JobReport>, Sv1Error> {
    let mut s = Sv1Session::connect(cfg).await?;
    let mut out = Vec::new();
    while jobs == 0 || out.len() < jobs {
        let job = match s.next_job(job_timeout).await {
            Ok(j) => j,
            Err(_) if !out.is_empty() && jobs == 0 => break,
            Err(e) => return Err(e),
        };
        let r = audit_job(&job, payee, network);
        on_report(&r);
        out.push(r);
    }
    Ok(out)
}

/// Extended jobs kept to rebuild standard jobs from.
const EXT_KEPT: usize = 32;
/// A standard job no kept extended job rebuilds is failed once an extended job has arrived
/// after it and this long has passed: pool_sv2 sends every channel its job for a template in
/// the same pass, so the matching extended job is in by then.
const SETTLE: Duration = Duration::from_secs(2);

/// A standard job waiting for the extended job it is rebuilt from.
struct PendingStandard {
    job: StandardJob,
    /// Extended jobs received before it.
    after: u64,
    arrived: Instant,
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

fn rebuild(std: &StandardJob, exts: &[(u64, ExtendedJob)]) -> Option<crate::job::Job> {
    exts.iter()
        .rev()
        .filter(|(_, e)| e.job.prev_hash == std.prev_hash)
        .find_map(|(_, e)| rebuild_standard(std, e))
}

/// Connect over Stratum V2 like a miner and check `jobs` jobs on each of an extended and a
/// standard channel (0: until a connection ends), calling `on_report` after each. Submits
/// nothing.
///
/// The extended channel opens first; its jobs are checked as SV1 jobs are. The standard channel
/// opens on a second connection, as a header-only miner's would. Each standard job is rebuilt
/// from the extended jobs on its `prev_hash` ([`crate::sv2::rebuild_standard`]); one that none
/// rebuilds once a later extended job is in fails, since its coinbase is not this miner's solo
/// coinbase. Standard jobs still waiting when the audit ends are reported unchecked.
pub async fn audit_sv2(
    cfg: &Sv2Config,
    payee: &[u8],
    network: SoloNetwork,
    jobs: usize,
    job_timeout: Duration,
    mut on_report: impl FnMut(&JobReport),
) -> Result<Vec<JobReport>, Sv2Error> {
    let want = |n: usize| jobs == 0 || n < jobs;
    let mut ext = Sv2Session::connect(cfg, ChannelKind::Extended).await?;
    let first = ext.next_job(job_timeout).await?;
    let std = Sv2Session::connect(cfg, ChannelKind::Standard).await?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tx.send(Ok(first)).ok();
    let _readers = Readers(vec![
        spawn_reader(ext, tx.clone(), job_timeout),
        spawn_reader(std, tx, job_timeout),
    ]);

    let mut out = Vec::new();
    let (mut ext_done, mut std_done) = (0usize, 0usize);
    let mut exts: Vec<(u64, ExtendedJob)> = Vec::new();
    let mut ext_seq = 0u64;
    let mut pending: Vec<PendingStandard> = Vec::new();
    let deadline = Instant::now() + job_timeout.saturating_mul(4);
    loop {
        if jobs > 0 && ext_done >= jobs && std_done >= jobs {
            break;
        }
        if jobs > 0 && Instant::now() >= deadline && ext_done >= jobs {
            break;
        }
        match tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
            Ok(Some(Ok(Sv2Job::Extended(e)))) => {
                ext_seq += 1;
                if want(ext_done) {
                    let r = audit_job(&e.job, payee, network);
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
                }
            }
            Ok(Some(Err(e))) => {
                if out.is_empty() {
                    return Err(e);
                }
                break;
            }
            Ok(None) => break,
            Err(_) => {}
        }
        let mut keep = Vec::new();
        for p in pending.drain(..) {
            let r = match rebuild(&p.job, &exts) {
                Some(j) => Some(audit_job(&j, payee, network)),
                None if ext_seq > p.after && p.arrived.elapsed() >= SETTLE => {
                    Some(JobReport::fail(
                        &p.job.job_id,
                        0,
                        None,
                        format!(
                            "no coinbase paying the treasury and your payout script {}, rebuilt \
                             from the node's extended jobs on this prev_hash, hashes to the \
                             standard job's merkle root {}: the job pays other outputs",
                            hex::encode(payee),
                            crate::job::display_hex(&p.job.merkle_root)
                        ),
                    ))
                }
                None => None,
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
    for p in pending {
        let r = JobReport::unchecked(
            &p.job.job_id,
            "no extended job on this prev_hash arrived to rebuild the standard job from".into(),
        );
        on_report(&r);
        out.push(r);
    }
    Ok(out)
}
