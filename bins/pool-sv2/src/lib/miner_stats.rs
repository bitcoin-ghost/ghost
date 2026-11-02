//! Per-worker share statistics for the miner pages (W2.17).
//!
//! Every share a miner submits to this node is judged by the channel layer; the judgement and the
//! difficulty of the job it was mined on land here, keyed by payee script and worker name (the
//! part of the user identity after the first `.`). From them the miner API
//! ([`crate::node_pool_miner_api`]) derives hashrate over time, accepted, stale and rejected
//! counts with their reasons, and when each worker last sent a share.
//!
//! ## Where it is kept, and why not in the store
//!
//! In memory, in two bounded rings per worker: [`FINE`] (5-minute buckets for 24 hours) and
//! [`COARSE`] (1-hour buckets for 30 days). Only buckets that saw a share are held, so an idle
//! worker costs nothing and a busy one at most 1,008 buckets. The whole set is written to a small
//! JSON file next to the relay's store (`miner-stats.json`, mode 0600) every
//! [`SAVE_INTERVAL`] and read back on start, so a restart keeps the history.
//!
//! This is local, unverifiable telemetry about one node's connections, not ledger state: no
//! peer can check it and nothing is paid from it. Putting it in the node pool store would need a
//! migration (v66) for data with none of the store's guarantees, and would add a write on every
//! share to the database the relay and settlement depend on. A crash loses at most the last
//! [`SAVE_INTERVAL`] of statistics, never a sat.
//!
//! What a restart does to the numbers is explicit rather than hidden: [`Snapshot::collecting_since`]
//! is when this node's history begins (the oldest file it has kept going, or the process start),
//! and a window or bucket before it is reported as unknown, never as zero. Time while pool_sv2
//! was down shows as zero hashrate, which is what this node saw.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use stratum_apps::stratum_core::channels_sv2::server::share_accounting::{
    ShareValidationError, ShareValidationResult,
};
use tracing::warn;

/// A bucket width and how many buckets a ring keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution {
    /// Bucket width, seconds.
    pub width: u64,
    /// Buckets kept.
    pub kept: u64,
}

impl Resolution {
    /// Seconds a ring of this resolution covers.
    pub const fn span(&self) -> u64 {
        self.width * self.kept
    }

    /// The start of the bucket `t` falls in.
    pub const fn floor(&self, t: u64) -> u64 {
        t - t % self.width
    }
}

/// 5-minute buckets for 24 hours.
pub const FINE: Resolution = Resolution {
    width: 300,
    kept: 288,
};
/// 1-hour buckets for 30 days.
pub const COARSE: Resolution = Resolution {
    width: 3_600,
    kept: 720,
};

/// How often the statistics are written to their file.
pub const SAVE_INTERVAL: Duration = Duration::from_secs(300);
/// Workers tracked at most; beyond it the one silent longest is dropped.
pub const MAX_WORKERS: usize = 10_000;
/// Longest worker name kept, in characters.
pub const MAX_WORKER_NAME: usize = 32;
/// A worker that sent a share this recently is online.
pub const ONLINE_SECS: u64 = 600;
/// The shortest span a hashrate is computed over; shorter is unknown.
pub const MIN_RATE_SECS: u64 = 60;
/// The file's format version.
const FILE_VERSION: u32 = 1;

/// Why a share was refused, as the SV2 error code the miner was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RejectReason {
    /// `invalid-share`.
    InvalidShare,
    /// `invalid-job-id`: a job this channel no longer holds.
    InvalidJobId,
    /// `difficulty-too-low`: the hash does not meet the job's target.
    DifficultyTooLow,
    /// `duplicate-share`.
    DuplicateShare,
    /// `bad-extranonce-size`.
    BadExtranonceSize,
    /// Anything else (the channel is disconnected for it).
    Other,
}

/// Number of [`RejectReason`]s.
pub const REASONS: usize = 6;

impl RejectReason {
    /// Every reason, in bucket order.
    pub const ALL: [RejectReason; REASONS] = [
        RejectReason::InvalidShare,
        RejectReason::InvalidJobId,
        RejectReason::DifficultyTooLow,
        RejectReason::DuplicateShare,
        RejectReason::BadExtranonceSize,
        RejectReason::Other,
    ];

    fn index(self) -> usize {
        self as usize
    }

    /// The error code, as sent to the miner.
    pub fn code(self) -> &'static str {
        match self {
            RejectReason::InvalidShare => "invalid-share",
            RejectReason::InvalidJobId => "invalid-job-id",
            RejectReason::DifficultyTooLow => "difficulty-too-low",
            RejectReason::DuplicateShare => "duplicate-share",
            RejectReason::BadExtranonceSize => "bad-extranonce-size",
            RejectReason::Other => "other",
        }
    }
}

/// What became of one submitted share.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    /// Accepted, on a job of this difficulty.
    Accepted {
        /// The job's difficulty (difficulty-1 multiples).
        difficulty: f64,
    },
    /// `stale-share`: mined on a tip that moved.
    Stale,
    /// Refused.
    Rejected(RejectReason),
}

impl Outcome {
    /// The outcome of a channel's validation of a share mined on a job of `difficulty`.
    pub fn of(
        res: &Result<ShareValidationResult, ShareValidationError>,
        difficulty: f64,
    ) -> Outcome {
        match res {
            Ok(_) => Outcome::Accepted { difficulty },
            Err(ShareValidationError::Stale) => Outcome::Stale,
            Err(ShareValidationError::Invalid) => Outcome::Rejected(RejectReason::InvalidShare),
            Err(ShareValidationError::InvalidJobId) => {
                Outcome::Rejected(RejectReason::InvalidJobId)
            }
            Err(ShareValidationError::DoesNotMeetTarget) => {
                Outcome::Rejected(RejectReason::DifficultyTooLow)
            }
            Err(ShareValidationError::DuplicateShare) => {
                Outcome::Rejected(RejectReason::DuplicateShare)
            }
            Err(ShareValidationError::BadExtranonceSize) => {
                Outcome::Rejected(RejectReason::BadExtranonceSize)
            }
            Err(_) => Outcome::Rejected(RejectReason::Other),
        }
    }
}

/// One bucket's counts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Bucket {
    /// Its start, unix seconds, a multiple of the ring's width.
    pub start: u64,
    /// Accepted shares.
    pub accepted: u64,
    /// Sum of the accepted shares' job difficulties: expected hashes are `work * 2^32`.
    pub work: f64,
    /// Stale shares.
    pub stale: u64,
    /// Refused shares, by [`RejectReason`] index.
    pub rejected: [u64; REASONS],
}

impl Bucket {
    fn add(&mut self, o: Outcome) {
        match o {
            Outcome::Accepted { difficulty } => {
                self.accepted += 1;
                if difficulty.is_finite() && difficulty > 0.0 {
                    self.work += difficulty;
                }
            }
            Outcome::Stale => self.stale += 1,
            Outcome::Rejected(r) => self.rejected[r.index()] += 1,
        }
    }

    /// Refused shares of every reason.
    pub fn rejected_total(&self) -> u64 {
        self.rejected.iter().sum()
    }
}

/// A ring of buckets at one resolution. Sparse: only buckets that saw a share are held,
/// ascending by start.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Ring {
    buckets: VecDeque<Bucket>,
}

impl Ring {
    /// The oldest bucket start a ring holds at `now`.
    fn oldest_kept(res: Resolution, now: u64) -> u64 {
        res.floor(now).saturating_sub((res.kept - 1) * res.width)
    }

    fn add(&mut self, res: Resolution, t: u64, o: Outcome) {
        let start = res.floor(t);
        match self.buckets.back_mut() {
            Some(b) if b.start == start => b.add(o),
            Some(b) if b.start > start => {
                // A clock that stepped back: count it where it belongs if still kept.
                match self.buckets.binary_search_by_key(&start, |b| b.start) {
                    Ok(i) => self.buckets[i].add(o),
                    Err(i) => {
                        let mut b = Bucket {
                            start,
                            ..Default::default()
                        };
                        b.add(o);
                        self.buckets.insert(i, b);
                    }
                }
            }
            _ => {
                let mut b = Bucket {
                    start,
                    ..Default::default()
                };
                b.add(o);
                self.buckets.push_back(b);
            }
        }
    }

    /// Drop buckets that have left the ring at `now`.
    fn prune(&mut self, res: Resolution, now: u64) {
        let oldest = Self::oldest_kept(res, now);
        while self.buckets.front().is_some_and(|b| b.start < oldest) {
            self.buckets.pop_front();
        }
    }

    /// The held buckets, oldest first.
    pub fn buckets(&self) -> impl Iterator<Item = &Bucket> {
        self.buckets.iter()
    }

    /// The bucket starting at `start`, if it saw a share.
    pub fn get(&self, start: u64) -> Option<&Bucket> {
        self.buckets
            .binary_search_by_key(&start, |b| b.start)
            .ok()
            .map(|i| &self.buckets[i])
    }
}

/// One worker's history on this node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkerStats {
    /// 5-minute buckets.
    pub fine: Ring,
    /// 1-hour buckets.
    pub coarse: Ring,
    /// Its last accepted share, unix seconds.
    pub last_share_at: Option<u64>,
    /// Its last submission of any outcome, unix seconds.
    pub last_submit_at: u64,
}

impl WorkerStats {
    fn new(now: u64) -> WorkerStats {
        WorkerStats {
            fine: Ring::default(),
            coarse: Ring::default(),
            last_share_at: None,
            last_submit_at: now,
        }
    }

    fn add(&mut self, o: Outcome, now: u64) {
        self.fine.add(FINE, now, o);
        self.coarse.add(COARSE, now, o);
        self.fine.prune(FINE, now);
        self.coarse.prune(COARSE, now);
        self.last_submit_at = self.last_submit_at.max(now);
        if matches!(o, Outcome::Accepted { .. }) {
            self.last_share_at = Some(self.last_share_at.map_or(now, |t| t.max(now)));
        }
    }

    /// The ring of a resolution.
    pub fn ring(&self, res: Resolution) -> &Ring {
        if res == FINE {
            &self.fine
        } else {
            &self.coarse
        }
    }
}

/// A worker name from a user identity: what follows the first `.`, trimmed, at most
/// [`MAX_WORKER_NAME`] characters, anything outside `[A-Za-z0-9_.:-]` replaced by `_`. Empty when
/// the identity has no worker part.
pub fn worker_name(identity: &str) -> String {
    let Some((_, w)) = identity.split_once('.') else {
        return String::new();
    };
    w.trim()
        .chars()
        .take(MAX_WORKER_NAME)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// A user identity as kept for display: at most 128 characters.
pub fn clamp_identity(identity: &str) -> String {
    identity.chars().take(128).collect()
}

/// Now, unix seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Default)]
struct Inner {
    collecting_since: u64,
    workers: HashMap<Vec<u8>, BTreeMap<String, WorkerStats>>,
    count: usize,
}

impl Inner {
    fn evict_one(&mut self) {
        let oldest = self
            .workers
            .iter()
            .flat_map(|(s, ws)| ws.iter().map(move |(w, st)| (st.last_submit_at, s, w)))
            .min()
            .map(|(_, s, w)| (s.clone(), w.clone()));
        if let Some((s, w)) = oldest {
            self.remove(&s, &w);
        }
    }

    fn remove(&mut self, script: &[u8], worker: &str) {
        if let Some(ws) = self.workers.get_mut(script) {
            if ws.remove(worker).is_some() {
                self.count -= 1;
            }
            if ws.is_empty() {
                self.workers.remove(script);
            }
        }
    }
}

/// What the API reads for one address.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    /// When this node's history begins: buckets before it are unknown, not zero.
    pub collecting_since: u64,
    /// The address's workers by name.
    pub workers: BTreeMap<String, WorkerStats>,
}

/// The file's shape.
#[derive(Serialize, Deserialize)]
struct SavedFile {
    version: u32,
    collecting_since: u64,
    saved_at: u64,
    workers: Vec<SavedWorker>,
}

#[derive(Serialize, Deserialize)]
struct SavedWorker {
    script: String,
    worker: String,
    stats: WorkerStats,
}

/// Every worker's statistics on this node.
pub struct MinerStats {
    inner: Mutex<Inner>,
    path: Option<PathBuf>,
}

impl MinerStats {
    /// Statistics kept in memory only, starting at `now`.
    pub fn in_memory(now: u64) -> MinerStats {
        MinerStats {
            inner: Mutex::new(Inner {
                collecting_since: now,
                ..Default::default()
            }),
            path: None,
        }
    }

    /// Statistics saved to `path`, read back from it if it holds any. A file that does not
    /// parse is set aside (renamed `.bad`) and collection starts afresh at `now`.
    pub fn open(path: PathBuf, now: u64) -> MinerStats {
        let mut inner = Inner {
            collecting_since: now,
            ..Default::default()
        };
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<SavedFile>(&bytes) {
                Ok(f) if f.version == FILE_VERSION => {
                    inner.collecting_since = f.collecting_since.min(now);
                    for w in f.workers {
                        let Ok(script) = hex::decode(&w.script) else {
                            continue;
                        };
                        let mut st = w.stats;
                        st.fine.prune(FINE, now);
                        st.coarse.prune(COARSE, now);
                        if now.saturating_sub(st.last_submit_at) > COARSE.span() {
                            continue;
                        }
                        if inner
                            .workers
                            .entry(script)
                            .or_default()
                            .insert(w.worker, st)
                            .is_none()
                        {
                            inner.count += 1;
                        }
                    }
                }
                Ok(f) => warn!(
                    path = %path.display(),
                    version = f.version,
                    "NODE_POOL: miner statistics file has an unknown version; starting afresh"
                ),
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        "NODE_POOL: miner statistics file does not parse ({e}); set aside, \
                         starting afresh"
                    );
                    let _ = std::fs::rename(&path, path.with_extension("json.bad"));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                path = %path.display(),
                "NODE_POOL: cannot read the miner statistics file ({e}); starting afresh"
            ),
        }
        MinerStats {
            inner: Mutex::new(inner),
            path: Some(path),
        }
    }

    /// Where the statistics of a relay whose store is `db_path` are saved: beside it.
    pub fn path_beside(db_path: &Path) -> PathBuf {
        db_path.with_file_name("miner-stats.json")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // Every mutation is a single insert or counter bump; a poisoned lock is still consistent.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Record a share from `worker` paying `script` at `now`.
    pub fn record(&self, script: &[u8], worker: &str, outcome: Outcome, now: u64) {
        if script.is_empty() {
            return;
        }
        let mut st = self.lock();
        let known = st
            .workers
            .get(script)
            .is_some_and(|w| w.contains_key(worker));
        if !known {
            while st.count >= MAX_WORKERS {
                st.evict_one();
            }
            st.count += 1;
        }
        st.workers
            .entry(script.to_vec())
            .or_default()
            .entry(worker.to_string())
            .or_insert_with(|| WorkerStats::new(now))
            .add(outcome, now);
    }

    /// The statistics of every worker paying `script`, pruned to `now`.
    pub fn snapshot(&self, script: &[u8], now: u64) -> Snapshot {
        let st = self.lock();
        let mut workers = st.workers.get(script).cloned().unwrap_or_default();
        for w in workers.values_mut() {
            w.fine.prune(FINE, now);
            w.coarse.prune(COARSE, now);
        }
        Snapshot {
            collecting_since: st.collecting_since,
            workers,
        }
    }

    /// When this node's history begins.
    pub fn collecting_since(&self) -> u64 {
        self.lock().collecting_since
    }

    /// Workers tracked.
    pub fn worker_count(&self) -> usize {
        self.lock().count
    }

    /// Drop buckets past their ring and workers silent for longer than [`COARSE`] covers.
    pub fn prune(&self, now: u64) {
        let mut st = self.lock();
        let mut gone = vec![];
        for (s, ws) in st.workers.iter_mut() {
            for (w, stats) in ws.iter_mut() {
                stats.fine.prune(FINE, now);
                stats.coarse.prune(COARSE, now);
                if now.saturating_sub(stats.last_submit_at) > COARSE.span() {
                    gone.push((s.clone(), w.clone()));
                }
            }
        }
        for (s, w) in gone {
            st.remove(&s, &w);
        }
    }

    /// Write the statistics to their file (a temporary file renamed over it, mode 0600). A
    /// no-op for in-memory statistics.
    pub fn save(&self, now: u64) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        self.prune(now);
        let file = {
            let st = self.lock();
            SavedFile {
                version: FILE_VERSION,
                collecting_since: st.collecting_since,
                saved_at: now,
                workers: st
                    .workers
                    .iter()
                    .flat_map(|(s, ws)| {
                        ws.iter().map(move |(w, stats)| SavedWorker {
                            script: hex::encode(s),
                            worker: w.clone(),
                            stats: stats.clone(),
                        })
                    })
                    .collect(),
            }
        };
        let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Save every [`SAVE_INTERVAL`] for as long as the runtime runs.
    pub fn spawn_saver(self: &std::sync::Arc<Self>) {
        if self.path.is_none() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(SAVE_INTERVAL);
            every.tick().await;
            loop {
                every.tick().await;
                let m = me.clone();
                match tokio::task::spawn_blocking(move || m.save(now_secs())).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!("NODE_POOL: could not save miner statistics: {e}"),
                    Err(e) => warn!("NODE_POOL: miner statistics save task failed: {e}"),
                }
            }
        });
    }
}

/// A history window the API serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Its name in the query: `24h`, `7d` or `30d`.
    pub name: &'static str,
    /// The ring it reads.
    pub res: Resolution,
    /// Seconds it covers.
    pub span: u64,
}

/// The windows, by name.
pub const WINDOWS: [Window; 3] = [
    Window {
        name: "24h",
        res: FINE,
        span: 86_400,
    },
    Window {
        name: "7d",
        res: COARSE,
        span: 7 * 86_400,
    },
    Window {
        name: "30d",
        res: COARSE,
        span: 30 * 86_400,
    },
];

/// The window named `name`.
pub fn window(name: &str) -> Option<Window> {
    WINDOWS.iter().copied().find(|w| w.name == name)
}

/// The bucket starts of `w` ending with the bucket `now` is in, oldest first.
pub fn bucket_starts(w: Window, now: u64) -> Vec<u64> {
    let last = w.res.floor(now);
    let n = w.span / w.res.width;
    (0..n)
        .rev()
        .filter_map(|i| last.checked_sub(i * w.res.width))
        .collect()
}

/// The seconds of bucket `start` that this node observed by `now`: its overlap with
/// `[since, now]`. Zero when it lies wholly before `since` or after `now`.
pub fn observed_secs(res: Resolution, start: u64, since: u64, now: u64) -> u64 {
    let from = start.max(since);
    let to = (start + res.width).min(now);
    to.saturating_sub(from)
}

/// Hashes per second from `work` (difficulty-1 multiples) over `secs`.
pub fn hashrate_hs(work: f64, secs: u64) -> f64 {
    if secs == 0 {
        return 0.0;
    }
    work * 4_294_967_296.0 / secs as f64
}

/// The counts and hashrate of `ring` over the last `span` seconds before `now`, observed since
/// `since`. A bucket only partly inside the span counts in proportion, as if its shares were
/// spread evenly across what was observed of it. `None` when less than [`MIN_RATE_SECS`] of the
/// span was observed.
pub fn over_span(
    ring: &Ring,
    res: Resolution,
    span: u64,
    since: u64,
    now: u64,
) -> Option<SpanTotals> {
    let from = now.saturating_sub(span).max(since);
    let observed = now.saturating_sub(from);
    if observed < MIN_RATE_SECS {
        return None;
    }
    let mut t = SpanTotals {
        observed_secs: observed,
        ..Default::default()
    };
    for b in ring.buckets() {
        let seen = observed_secs(res, b.start, since, now);
        if seen == 0 {
            continue;
        }
        let inside = observed_secs(res, b.start, from, now);
        if inside == 0 {
            continue;
        }
        let f = inside as f64 / seen as f64;
        t.work += b.work * f;
        t.accepted += b.accepted as f64 * f;
        t.stale += b.stale as f64 * f;
        for (i, r) in b.rejected.iter().enumerate() {
            t.rejected[i] += *r as f64 * f;
        }
    }
    Some(t)
}

/// Totals over a span, possibly fractional where a bucket straddles its start.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SpanTotals {
    /// Seconds observed.
    pub observed_secs: u64,
    /// Accepted work.
    pub work: f64,
    /// Accepted shares.
    pub accepted: f64,
    /// Stale shares.
    pub stale: f64,
    /// Refused shares by reason.
    pub rejected: [f64; REASONS],
}

impl SpanTotals {
    /// Hashes per second.
    pub fn hashrate_hs(&self) -> f64 {
        hashrate_hs(self.work, self.observed_secs)
    }

    /// Refused shares of every reason.
    pub fn rejected_total(&self) -> f64 {
        self.rejected.iter().sum()
    }
}

#[cfg(test)]
#[path = "miner_stats_tests.rs"]
mod tests;
