//! The pool's miner and status API, on the monitoring listener (loopback,
//! `monitoring_address`). ghost-mining forwards the same paths on its public API, with the same
//! address checks, so the website and `ghost-cli` read them where they read everything else.
//!
//! Every number here is this pool's own view of its connections: hashrate is estimated from
//! accepted shares at their job difficulty, so it is noisy at low share counts. A hashrate is
//! `null` when the pool has observed less than a minute of the window. A worker is `online` when
//! it is connected and sent a share in the last 10 minutes, `idle` when it is connected but has
//! not, `offline` when it is not connected. Difficulties are in difficulty-1 units; a best share
//! of `0` means none yet.
//!
//! ## `GET /api/v1/miner/{address}`
//!
//! ```json
//! {
//!   "address": "bc1q…", "network": "mainnet", "script_hex": "0014…",
//!   "generated_at": 1800000000, "collecting_since": 1799990000,
//!   "summary": {
//!     "workers": 2, "online": 1, "idle": 0, "offline": 1,
//!     "hashrate_hs": { "15m": 1.2e14, "1h": 1.1e14, "24h": 9.8e13 },
//!     "shares_24h": { "accepted": 812, "stale": 3, "rejected": 1,
//!                     "reject_reasons": { "duplicate-share": 1 } },
//!     "last_share_at": 1799999990,
//!     "best_share": { "ever": 4.1e9, "24h": 2.2e8 }
//!   },
//!   "workers": [{
//!     "name": "rig1", "status": "online", "last_share_at": 1799999990,
//!     "last_submit_at": 1799999990, "hashrate_hs": { … }, "shares_24h": { … },
//!     "best_share": { "ever": 4.1e9, "24h": 2.2e8 },
//!     "connections": [{ "downstream_id": 4, "channel_id": 1, "kind": "extended" }]
//!   }],
//!   "blocks_found": [{ "height": 974900, "hash": "0000…", "worker": "rig1",
//!                      "reward_sats": 311000000, "treasury_sats": 1562500,
//!                      "fees_sats": 62500, "found_at": 1799999000, "check": "ok",
//!                      "submitted": [{ "node": "http://10.0.0.2:8332", "result": "accepted" }] }],
//!   "expected_time_to_block": {
//!     "known": true, "seconds": 4.3e9, "hashrate_hs": 1.1e14, "hashrate_window": "1h",
//!     "network_difficulty": 1.1e14, "reason": null
//!   }
//! }
//! ```
//!
//! `blocks_found` lists this address's blocks, oldest first; `reward_sats` is what the coinbase
//! paid it (`subsidy - subsidy / 200 + fees`). `expected_time_to_block` is
//! `network_difficulty * 2^32 / hashrate`, the mean wait at the address's hashrate over the last
//! hour (the last 24 hours when the hour is unknown); unknown, with a `reason`, when there is no
//! tip or no hashrate. Block finding is random: the real wait is often far shorter or longer.
//!
//! ## `GET /api/v1/miner/{address}/history?window=24h|7d|30d`
//!
//! `24h` is 288 five-minute buckets, `7d` 168 and `30d` 720 one-hour buckets, oldest first,
//! ending with the bucket now is in. Every series is aligned with `buckets`. A value is `null`
//! for a bucket the pool was not yet collecting in (before `collecting_since`): unknown, not zero.
//!
//! ```json
//! {
//!   "address": "bc1q…", "network": "mainnet", "window": "24h", "bucket_seconds": 300,
//!   "generated_at": 1800000000, "collecting_since": 1799990000, "buckets": [1799913900, …],
//!   "total": { "hashrate_hs": [null, …, 1.1e14], "accepted": [null, …, 31], "stale": [...],
//!              "rejected": [...], "best_share": [...] },
//!   "workers": [{ "name": "rig1", "series": { … } }], "workers_omitted": 0,
//!   "reject_reasons": { "duplicate-share": 1 }
//! }
//! ```
//!
//! ## `GET /api/v1/pool/status`
//!
//! ```json
//! {
//!   "network": "mainnet", "generated_at": 1800000000, "collecting_since": 1799990000,
//!   "bitcoin": { "tip_height": 974899, "tip_hash": "0000…", "job_height": 974900,
//!                "network_difficulty": 1.1e14 },
//!   "miners": { "connected": 3, "workers": 5 },
//!   "pool_hashrate_hs": { "15m": 3.0e14, "1h": 2.9e14, "24h": 2.5e14 },
//!   "best_share": { "ever": 9.9e10, "24h": 1.2e9 },
//!   "blocks_found": [ … as above, plus "address" … ],
//!   "fee_policy": { "treasury_address": "bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k",
//!                   "treasury_share_of_subsidy": 0.005, "treasury_sats_next_block": 1562500,
//!                   "miner_sats_next_block_before_fees": 310937500, "fees_to": "miner" },
//!   "ports": { "sv1": [3333, 4444], "sv2": 34255,
//!              "sv2_authority_public_key": "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72" },
//!   "submit_nodes": [{ "node": "http://10.0.0.2:8332", "reachable": true,
//!                      "last_checked_at": 1799999990, "last_ok_at": 1799999990,
//!                      "height": 974899, "error": null }]
//! }
//! ```
//!
//! `miners.connected` counts distinct payout addresses with an open channel, `miners.workers`
//! open channels. `pool_hashrate_hs` is the sum of every worker's hashrate. `tip_height` is the
//! job height less one; both are `null` before the first template.
//! `ports.sv2_authority_public_key` is the key SV2 miners pin (base58check, as
//! `authority_public_key` in the pool's config). `submit_nodes` are the other nodes found blocks
//! are sent to, each with what the last reachability check (`getblockchaininfo`, every 60 s, 10 s
//! timeout) found: `reachable` is `null` until the first check, `height` and `last_ok_at` are from
//! the last answer, `error` is why the last check failed. Credentials never appear.
//!
//! ## `GET /api/v1/pool/miners` (operator only)
//!
//! Every payout address with an open channel or a share in the last 24 hours, the most hashrate
//! (last hour) first. It names miners' addresses, so it is served on the loopback monitoring
//! listener only, and ghost-mining forwards it only to HMAC-signed requests (the dashboard); the
//! website proxy never forwards it.
//!
//! ```json
//! {
//!   "network": "mainnet", "generated_at": 1800000000, "collecting_since": 1799990000,
//!   "miners": [{
//!     "address": "bc1q…", "connected": true,
//!     "workers": 2, "online": 1, "idle": 1, "offline": 0,
//!     "hashrate_hs": { "15m": 1.2e14, "1h": 1.1e14, "24h": 9.8e13 },
//!     "shares_24h": { "accepted": 812, "stale": 3, "rejected": 1, "reject_reasons": { … } },
//!     "last_share_at": 1799999990, "best_share": { "ever": 4.1e9, "24h": 2.2e8 },
//!     "blocks_found": 1
//!   }]
//! }
//! ```

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use ghost_common::solo::{payee_script_class, split, TREASURY_SCRIPT};
use serde::Serialize;
use stratum_apps::stratum_core::bitcoin::{address::NetworkUnchecked, Address};

use crate::{
    blocks_found::FoundBlock,
    miner_stats::{
        bucket_starts, hashrate_hs, now_secs, observed_secs, over_span, window, Bucket, Ring,
        Snapshot, SpanTotals, WorkerStats, FINE, ONLINE_SECS, REASONS,
    },
    solo::{ChannelStatus, Solo},
};

/// Workers listed in a history; the rest are in the total only.
pub const MAX_HISTORY_WORKERS: usize = 64;

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The address is not one this network's pool can pay (400).
    BadAddress(String),
}

impl ApiError {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        400
    }

    /// The message.
    pub fn message(&self) -> &str {
        match self {
            ApiError::BadAddress(m) => m,
        }
    }
}

/// Hashrate over three spans, hashes per second.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Rates {
    /// Last 15 minutes.
    #[serde(rename = "15m")]
    pub m15: Option<f64>,
    /// Last hour.
    #[serde(rename = "1h")]
    pub h1: Option<f64>,
    /// Last 24 hours.
    #[serde(rename = "24h")]
    pub h24: Option<f64>,
}

/// Best share difficulties.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct BestShare {
    /// The best ever seen here.
    pub ever: f64,
    /// The best in the last 24 hours.
    #[serde(rename = "24h")]
    pub h24: f64,
}

impl BestShare {
    fn max(self, o: BestShare) -> BestShare {
        BestShare {
            ever: self.ever.max(o.ever),
            h24: self.h24.max(o.h24),
        }
    }

    fn of(w: &WorkerStats, now: u64) -> BestShare {
        BestShare {
            ever: w.best_ever,
            h24: w.best_24h(now),
        }
    }
}

/// Share counts over the last 24 hours.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// Accepted.
    pub accepted: u64,
    /// Stale (`stale-share`).
    pub stale: u64,
    /// Refused for any other reason.
    pub rejected: u64,
    /// Refused, by SV2 error code; only reasons seen.
    pub reject_reasons: BTreeMap<&'static str, u64>,
}

impl Counts {
    fn add_bucket(&mut self, b: &Bucket) {
        self.accepted += b.accepted;
        self.stale += b.stale;
        for (i, n) in b.rejected.iter().enumerate() {
            if *n > 0 {
                self.rejected += n;
                *self
                    .reject_reasons
                    .entry(crate::miner_stats::RejectReason::ALL[i].code())
                    .or_default() += n;
            }
        }
    }

    fn add(&mut self, o: &Counts) {
        self.accepted += o.accepted;
        self.stale += o.stale;
        self.rejected += o.rejected;
        for (k, v) in &o.reject_reasons {
            *self.reject_reasons.entry(k).or_default() += v;
        }
    }
}

/// One open channel of a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionView {
    /// Downstream connection id.
    pub downstream_id: usize,
    /// Channel id.
    pub channel_id: u32,
    /// `standard` or `extended`.
    pub kind: &'static str,
}

/// One worker.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WorkerView {
    /// What follows the first `.` of its user identity; empty when there is none.
    pub name: String,
    /// `online`, `idle` or `offline`.
    pub status: &'static str,
    /// Its last accepted share, unix seconds.
    pub last_share_at: Option<u64>,
    /// Its last submission of any outcome, unix seconds.
    pub last_submit_at: Option<u64>,
    /// Hashrate from accepted shares.
    pub hashrate_hs: Rates,
    /// Shares in the last 24 hours.
    pub shares_24h: Counts,
    /// Its best shares.
    pub best_share: BestShare,
    /// Its open channels.
    pub connections: Vec<ConnectionView>,
}

/// The address, summed over its workers.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MinerSummary {
    /// Workers known.
    pub workers: usize,
    /// Of which online.
    pub online: usize,
    /// Connected but quiet.
    pub idle: usize,
    /// Not connected.
    pub offline: usize,
    /// Hashrate of all workers.
    pub hashrate_hs: Rates,
    /// Shares in the last 24 hours.
    pub shares_24h: Counts,
    /// The latest accepted share of any worker.
    pub last_share_at: Option<u64>,
    /// The best shares of any worker.
    pub best_share: BestShare,
}

/// The mean time to a block at a hashrate.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ExpectedTime {
    /// An estimate was possible.
    pub known: bool,
    /// Mean seconds to a block: `network_difficulty * 2^32 / hashrate_hs`.
    pub seconds: Option<f64>,
    /// The hashrate it assumes.
    pub hashrate_hs: Option<f64>,
    /// `1h` or `24h`: the window that hashrate is from.
    pub hashrate_window: Option<&'static str>,
    /// The difficulty of the next block.
    pub network_difficulty: Option<f64>,
    /// Why not, when `known` is false.
    pub reason: Option<String>,
}

/// `GET /api/v1/miner/{address}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MinerResponse {
    /// The address asked about.
    pub address: String,
    /// The pool's network.
    pub network: &'static str,
    /// Its output script, hex.
    pub script_hex: String,
    /// When this answer was built, unix seconds.
    pub generated_at: u64,
    /// When the share statistics begin.
    pub collecting_since: u64,
    /// Summed over the workers.
    pub summary: MinerSummary,
    /// The workers, online first.
    pub workers: Vec<WorkerView>,
    /// The blocks this address found here, oldest first.
    pub blocks_found: Vec<FoundBlock>,
    /// The mean time to a block at this address's hashrate.
    pub expected_time_to_block: ExpectedTime,
}

/// Series aligned with a history's buckets.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Series {
    /// Hashes per second over what was observed of each bucket.
    pub hashrate_hs: Vec<Option<f64>>,
    /// Accepted shares.
    pub accepted: Vec<Option<u64>>,
    /// Stale shares.
    pub stale: Vec<Option<u64>>,
    /// Refused shares.
    pub rejected: Vec<Option<u64>>,
    /// The best share's difficulty in each bucket.
    pub best_share: Vec<Option<f64>>,
}

/// One worker's series.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WorkerSeries {
    /// Its name.
    pub name: String,
    /// Its series.
    pub series: Series,
}

/// `GET /api/v1/miner/{address}/history`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryResponse {
    /// The address asked about.
    pub address: String,
    /// The pool's network.
    pub network: &'static str,
    /// `24h`, `7d` or `30d`.
    pub window: &'static str,
    /// Bucket width.
    pub bucket_seconds: u64,
    /// When this answer was built.
    pub generated_at: u64,
    /// When the share statistics begin.
    pub collecting_since: u64,
    /// Bucket starts, unix seconds, oldest first.
    pub buckets: Vec<u64>,
    /// All workers together.
    pub total: Series,
    /// The workers with the most work in the window, at most [`MAX_HISTORY_WORKERS`].
    pub workers: Vec<WorkerSeries>,
    /// Workers left out of `workers` (still in `total`).
    pub workers_omitted: usize,
    /// Refused shares in the window, by reason.
    pub reject_reasons: BTreeMap<&'static str, u64>,
}

/// The Bitcoin side of the status.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct BitcoinView {
    /// The tip's height.
    pub tip_height: Option<u32>,
    /// The tip's hash, as explorers show it.
    pub tip_hash: Option<String>,
    /// The height jobs are built at.
    pub job_height: Option<u32>,
    /// The difficulty of the next block.
    pub network_difficulty: Option<f64>,
}

/// Who is connected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MinersView {
    /// Distinct payout addresses with an open channel.
    pub connected: usize,
    /// Open channels.
    pub workers: usize,
}

/// How a block's coinbase is split.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeePolicy {
    /// The treasury's address.
    pub treasury_address: String,
    /// Its share of the subsidy, never of the fees: 0.005.
    pub treasury_share_of_subsidy: f64,
    /// What the next block pays the treasury, sats.
    pub treasury_sats_next_block: Option<u64>,
    /// What it pays its finder before fees, sats; the finder also takes every fee.
    pub miner_sats_next_block_before_fees: Option<u64>,
    /// Who takes the transaction fees: `miner`.
    pub fees_to: &'static str,
}

/// The ports miners connect to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Ports {
    /// The translator's SV1 ports (configured, not probed).
    pub sv1: Vec<u16>,
    /// This pool's SV2 port.
    pub sv2: u16,
    /// The SV2 authority public key miners pin (base58check).
    pub sv2_authority_public_key: Option<String>,
}

/// `GET /api/v1/pool/status`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StatusResponse {
    /// The pool's network.
    pub network: &'static str,
    /// When this answer was built.
    pub generated_at: u64,
    /// When the share statistics begin.
    pub collecting_since: u64,
    /// The Bitcoin tip.
    pub bitcoin: BitcoinView,
    /// Who is connected.
    pub miners: MinersView,
    /// The sum of every worker's hashrate.
    pub pool_hashrate_hs: Rates,
    /// The best shares of any worker.
    pub best_share: BestShare,
    /// Every block this pool found, oldest first.
    pub blocks_found: Vec<FoundBlock>,
    /// How a block's coinbase is split.
    pub fee_policy: FeePolicy,
    /// The ports miners connect to.
    pub ports: Ports,
    /// The other nodes found blocks are sent to, and whether each answers now.
    pub submit_nodes: Vec<crate::submit_rpc::NodeHealth>,
}

/// One payout address in the operator's list.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MinerListEntry {
    /// The payout address.
    pub address: String,
    /// It has an open channel.
    pub connected: bool,
    /// Its workers, online, idle and offline, hashrate, shares, last share and best share.
    #[serde(flatten)]
    pub summary: MinerSummary,
    /// Blocks it found here.
    pub blocks_found: usize,
}

/// `GET /api/v1/pool/miners`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MinersResponse {
    /// The pool's network.
    pub network: &'static str,
    /// When this answer was built.
    pub generated_at: u64,
    /// When the share statistics begin.
    pub collecting_since: u64,
    /// The addresses, most hashrate first.
    pub miners: Vec<MinerListEntry>,
}

fn worker_rates(ring: &Ring, since: u64, now: u64) -> (Rates, [Option<SpanTotals>; 3]) {
    let spans = [
        over_span(ring, FINE, 900, since, now),
        over_span(ring, FINE, 3_600, since, now),
        over_span(ring, FINE, 86_400, since, now),
    ];
    (
        Rates {
            m15: spans[0].as_ref().map(SpanTotals::hashrate_hs),
            h1: spans[1].as_ref().map(SpanTotals::hashrate_hs),
            h24: spans[2].as_ref().map(SpanTotals::hashrate_hs),
        },
        spans,
    )
}

fn counts_24h(w: &WorkerStats, now: u64) -> Counts {
    let first = bucket_starts(window("24h").expect("24h is a window"), now)[0];
    let mut c = Counts::default();
    for b in w.fine.buckets().filter(|b| b.start >= first) {
        c.add_bucket(b);
    }
    c
}

/// The summed rates of `workers`, observed since `since`: unknown per span when the pool has not
/// observed enough of it.
pub fn sum_rates<'a>(
    workers: impl Iterator<Item = &'a WorkerStats>,
    since: u64,
    now: u64,
) -> Rates {
    let mut work = [0.0f64; 3];
    for st in workers {
        let (_, spans) = worker_rates(&st.fine, since, now);
        for (i, sp) in spans.iter().enumerate() {
            if let Some(sp) = sp {
                work[i] += sp.work;
            }
        }
    }
    let empty = worker_rates(&Ring::default(), since, now).1;
    let rate = |i: usize| {
        empty[i]
            .as_ref()
            .map(|e| hashrate_hs(work[i], e.observed_secs))
    };
    Rates {
        m15: rate(0),
        h1: rate(1),
        h24: rate(2),
    }
}

/// The workers of one address, from its statistics and its open channels.
pub fn worker_views(snap: &Snapshot, channels: &[ChannelStatus], now: u64) -> Vec<WorkerView> {
    let mut by_name: BTreeMap<String, Vec<&ChannelStatus>> = BTreeMap::new();
    for c in channels {
        by_name
            .entry(crate::miner_stats::worker_name(&c.user_identity))
            .or_default()
            .push(c);
    }
    let mut names: Vec<&String> = snap.workers.keys().chain(by_name.keys()).collect();
    names.sort();
    names.dedup();
    let mut out: Vec<WorkerView> = names
        .into_iter()
        .map(|name| {
            let stats = snap.workers.get(name);
            let conns: Vec<ConnectionView> = by_name
                .get(name)
                .map(|cs| {
                    cs.iter()
                        .map(|c| ConnectionView {
                            downstream_id: c.key.0,
                            channel_id: c.key.1,
                            kind: c.kind.as_str(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let last_submit_at = stats.map(|s| s.last_submit_at);
            let status = if conns.is_empty() {
                "offline"
            } else if last_submit_at.is_some_and(|t| now.saturating_sub(t) <= ONLINE_SECS)
                && stats.is_some_and(|s| s.last_share_at.is_some())
            {
                "online"
            } else {
                "idle"
            };
            let empty = Ring::default();
            let ring = stats.map_or(&empty, |s| &s.fine);
            WorkerView {
                name: name.clone(),
                status,
                last_share_at: stats.and_then(|s| s.last_share_at),
                last_submit_at,
                hashrate_hs: worker_rates(ring, snap.collecting_since, now).0,
                shares_24h: stats.map(|s| counts_24h(s, now)).unwrap_or_default(),
                best_share: stats.map(|s| BestShare::of(s, now)).unwrap_or_default(),
                connections: conns,
            }
        })
        .collect();
    let rank = |s: &str| match s {
        "online" => 0,
        "idle" => 1,
        _ => 2,
    };
    out.sort_by(|a, b| {
        rank(a.status)
            .cmp(&rank(b.status))
            .then_with(|| a.name.cmp(&b.name))
    });
    out
}

/// The summary of `workers`.
pub fn summarize(workers: &[WorkerView], snap: &Snapshot, now: u64) -> MinerSummary {
    let mut s = MinerSummary {
        workers: workers.len(),
        ..Default::default()
    };
    for w in workers {
        match w.status {
            "online" => s.online += 1,
            "idle" => s.idle += 1,
            _ => s.offline += 1,
        }
        s.shares_24h.add(&w.shares_24h);
        s.last_share_at = s.last_share_at.max(w.last_share_at);
        s.best_share = s.best_share.max(w.best_share);
    }
    s.hashrate_hs = sum_rates(snap.workers.values(), snap.collecting_since, now);
    s
}

/// `network_difficulty * 2^32 / hashrate`, from the last hour's hashrate, else the last day's.
pub fn expected_time(rates: &Rates, network_difficulty: Option<f64>) -> ExpectedTime {
    let mut e = ExpectedTime {
        network_difficulty,
        ..Default::default()
    };
    let Some(d) = network_difficulty.filter(|d| d.is_finite() && *d > 0.0) else {
        e.reason = Some("the pool has no Bitcoin tip yet, so the difficulty is not known".into());
        return e;
    };
    let (rate, win) = match (rates.h1, rates.h24) {
        (Some(r), _) if r > 0.0 => (r, "1h"),
        (_, Some(r)) if r > 0.0 => (r, "24h"),
        _ => {
            e.reason = Some("no accepted shares in the last 24 hours, so no hashrate".into());
            return e;
        }
    };
    e.known = true;
    e.hashrate_hs = Some(rate);
    e.hashrate_window = Some(win);
    e.seconds = Some(d * 4_294_967_296.0 / rate);
    e
}

/// Fill a history's share series from `ring` at `res`, `null` where nothing was observed.
fn series_of(
    ring: &Ring,
    res: crate::miner_stats::Resolution,
    starts: &[u64],
    since: u64,
    now: u64,
) -> Series {
    let mut s = Series::default();
    for &t in starts {
        let seen = observed_secs(res, t, since, now);
        if seen == 0 {
            s.hashrate_hs.push(None);
            s.accepted.push(None);
            s.stale.push(None);
            s.rejected.push(None);
            s.best_share.push(None);
            continue;
        }
        let b = ring.get(t);
        s.hashrate_hs
            .push(Some(hashrate_hs(b.map_or(0.0, |b| b.work), seen)));
        s.accepted.push(Some(b.map_or(0, |b| b.accepted)));
        s.stale.push(Some(b.map_or(0, |b| b.stale)));
        s.rejected.push(Some(b.map_or(0, Bucket::rejected_total)));
        s.best_share.push(Some(b.map_or(0.0, |b| b.best)));
    }
    s
}

fn sum_series(a: &mut Series, b: &Series) {
    fn add<T: Copy + std::ops::Add<Output = T>>(x: &mut [Option<T>], y: &[Option<T>]) {
        for (x, y) in x.iter_mut().zip(y) {
            *x = match (*x, *y) {
                (Some(p), Some(q)) => Some(p + q),
                (p, q) => p.or(q),
            };
        }
    }
    if a.hashrate_hs.is_empty() {
        *a = b.clone();
        return;
    }
    add(&mut a.hashrate_hs, &b.hashrate_hs);
    add(&mut a.accepted, &b.accepted);
    add(&mut a.stale, &b.stale);
    add(&mut a.rejected, &b.rejected);
    for (x, y) in a.best_share.iter_mut().zip(&b.best_share) {
        *x = match (*x, *y) {
            (Some(p), Some(q)) => Some(p.max(q)),
            (p, q) => p.or(q),
        };
    }
}

/// The API's state: the solo layer, and what the config says about ports.
pub struct SoloApi {
    pub(crate) solo: Arc<Solo>,
    sv1_ports: Vec<u16>,
    sv2_port: u16,
    authority_public_key: Option<String>,
    /// Unix seconds now; a fixed clock in tests.
    pub(crate) clock: fn() -> u64,
}

impl SoloApi {
    /// The API over `solo`.
    pub fn new(
        solo: Arc<Solo>,
        sv1_ports: Vec<u16>,
        sv2_port: u16,
        authority_public_key: Option<String>,
    ) -> SoloApi {
        SoloApi {
            solo,
            sv1_ports,
            sv2_port,
            authority_public_key,
            clock: now_secs,
        }
    }

    /// The payee script of `address`, refused unless it is this network's and a payee class.
    pub fn payee_script(&self, address: &str) -> Result<Vec<u8>, ApiError> {
        let net = self.solo.network();
        let a = address.trim();
        let parsed = Address::<NetworkUnchecked>::from_str(a)
            .map_err(|e| ApiError::BadAddress(format!("{a:?} is not a Bitcoin address: {e}")))?;
        let checked = parsed.require_network(net.bitcoin_network()).map_err(|_| {
            ApiError::BadAddress(format!(
                "{a:?} is not a {net} address; this pool runs on {net}"
            ))
        })?;
        let script = checked.script_pubkey().to_bytes();
        if payee_script_class(&script).is_none() {
            return Err(ApiError::BadAddress(format!(
                "{a:?} cannot be mined to: only P2SH, P2WPKH, P2WSH and P2TR addresses can be"
            )));
        }
        Ok(script)
    }

    fn network_difficulty(&self) -> Option<f64> {
        self.solo.tip().map(|t| t.difficulty)
    }

    /// One address's workers, blocks and expected time to a block.
    pub fn miner(&self, address: &str) -> Result<MinerResponse, ApiError> {
        let script = self.payee_script(address)?;
        let now = (self.clock)();
        let snap = self.solo.miner_stats().snapshot(&script, now);
        let channels: Vec<ChannelStatus> = self
            .solo
            .channel_status()
            .into_iter()
            .filter(|c| c.payee_script == script)
            .collect();
        let workers = worker_views(&snap, &channels, now);
        let summary = summarize(&workers, &snap, now);
        let address = address.trim().to_string();
        let blocks_found = self
            .solo
            .blocks_found()
            .all()
            .into_iter()
            .filter(|b| b.address == address || b.address == self.solo.address_of(&script))
            .collect();
        let expected_time_to_block = expected_time(&summary.hashrate_hs, self.network_difficulty());
        Ok(MinerResponse {
            address,
            network: self.solo.network().as_str(),
            script_hex: hex::encode(&script),
            generated_at: now,
            collecting_since: snap.collecting_since,
            summary,
            workers,
            blocks_found,
            expected_time_to_block,
        })
    }

    /// One address's history over `window_name` (`24h`, `7d` or `30d`).
    pub fn miner_history(
        &self,
        address: &str,
        window_name: &str,
    ) -> Result<HistoryResponse, ApiError> {
        let script = self.payee_script(address)?;
        let w = window(window_name.trim()).ok_or_else(|| {
            ApiError::BadAddress(format!(
                "window {window_name:?} is not one of 24h, 7d or 30d"
            ))
        })?;
        let now = (self.clock)();
        let snap = self.solo.miner_stats().snapshot(&script, now);
        let starts = bucket_starts(w, now);
        let since = snap.collecting_since;
        let first = starts[0];
        let work_in = |st: &WorkerStats| -> f64 {
            st.ring(w.res)
                .buckets()
                .filter(|b| b.start >= first)
                .map(|b| b.work)
                .sum()
        };
        let mut ranked: Vec<(&String, &WorkerStats)> = snap.workers.iter().collect();
        ranked.sort_by(|a, b| {
            work_in(b.1)
                .partial_cmp(&work_in(a.1))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(b.0))
        });
        let mut total = series_of(&Ring::default(), w.res, &starts, since, now);
        let mut workers = Vec::new();
        let mut reasons: HashMap<&'static str, u64> = HashMap::new();
        for (i, (name, st)) in ranked.iter().enumerate() {
            let ring = st.ring(w.res);
            let s = series_of(ring, w.res, &starts, since, now);
            sum_series(&mut total, &s);
            for b in ring.buckets().filter(|b| b.start >= first) {
                for (k, n) in b.rejected.iter().enumerate().take(REASONS) {
                    if *n > 0 {
                        *reasons
                            .entry(crate::miner_stats::RejectReason::ALL[k].code())
                            .or_default() += n;
                    }
                }
            }
            if i < MAX_HISTORY_WORKERS {
                workers.push(WorkerSeries {
                    name: (*name).clone(),
                    series: s,
                });
            }
        }
        Ok(HistoryResponse {
            address: address.trim().to_string(),
            network: self.solo.network().as_str(),
            window: w.name,
            bucket_seconds: w.res.width,
            generated_at: now,
            collecting_since: since,
            buckets: starts,
            total,
            workers_omitted: ranked.len().saturating_sub(MAX_HISTORY_WORKERS),
            workers,
            reject_reasons: reasons.into_iter().collect(),
        })
    }

    /// The pool-wide view.
    pub fn status(&self) -> StatusResponse {
        let now = (self.clock)();
        let stats = self.solo.miner_stats();
        let all = stats.all(now);
        let since = stats.collecting_since();
        let pool_hashrate_hs = sum_rates(all.iter().map(|(_, _, w)| w), since, now);
        let best_share = all
            .iter()
            .map(|(_, _, w)| BestShare::of(w, now))
            .fold(BestShare::default(), BestShare::max);
        let channels = self.solo.channel_status();
        let connected: HashSet<&[u8]> =
            channels.iter().map(|c| c.payee_script.as_slice()).collect();
        let job_height = self.solo.job_height();
        let tip = self.solo.tip();
        let next = job_height.map(|h| split(h, self.solo.halving(), 0));
        StatusResponse {
            network: self.solo.network().as_str(),
            generated_at: now,
            collecting_since: since,
            bitcoin: BitcoinView {
                tip_height: job_height.and_then(|h| h.checked_sub(1)),
                tip_hash: tip.map(|t| {
                    let mut b = t.prev_hash;
                    b.reverse();
                    hex::encode(b)
                }),
                job_height,
                network_difficulty: tip.map(|t| t.difficulty),
            },
            miners: MinersView {
                connected: connected.len(),
                workers: channels.len(),
            },
            pool_hashrate_hs,
            best_share,
            blocks_found: self.solo.blocks_found().all(),
            fee_policy: FeePolicy {
                treasury_address: self.solo.address_of(&TREASURY_SCRIPT),
                treasury_share_of_subsidy: 0.005,
                treasury_sats_next_block: next.map(|n| n.0),
                miner_sats_next_block_before_fees: next.map(|n| n.1),
                fees_to: "miner",
            },
            ports: Ports {
                sv1: self.sv1_ports.clone(),
                sv2: self.sv2_port,
                sv2_authority_public_key: self.authority_public_key.clone(),
            },
            submit_nodes: self
                .solo
                .submit_targets()
                .map(|t| t.health())
                .unwrap_or_default(),
        }
    }

    /// Every payout address with an open channel or a share in the last 24 hours.
    pub fn miners(&self) -> MinersResponse {
        let now = (self.clock)();
        let stats = self.solo.miner_stats();
        let since = stats.collecting_since();
        let mut by_script: BTreeMap<Vec<u8>, Snapshot> = BTreeMap::new();
        for (script, name, w) in stats.all(now) {
            by_script
                .entry(script)
                .or_insert_with(|| Snapshot {
                    collecting_since: since,
                    workers: BTreeMap::new(),
                })
                .workers
                .insert(name, w);
        }
        let mut channels: HashMap<Vec<u8>, Vec<ChannelStatus>> = HashMap::new();
        for c in self.solo.channel_status() {
            channels.entry(c.payee_script.clone()).or_default().push(c);
        }
        for script in channels.keys() {
            by_script.entry(script.clone()).or_insert_with(|| Snapshot {
                collecting_since: since,
                workers: BTreeMap::new(),
            });
        }
        let blocks = self.solo.blocks_found().all();
        let mut miners: Vec<MinerListEntry> = by_script
            .into_iter()
            .filter_map(|(script, snap)| {
                let open = channels.get(&script).map_or(&[][..], Vec::as_slice);
                let recent = snap
                    .workers
                    .values()
                    .any(|w| now.saturating_sub(w.last_submit_at) <= 86_400);
                if open.is_empty() && !recent {
                    return None;
                }
                let workers = worker_views(&snap, open, now);
                let summary = summarize(&workers, &snap, now);
                let address = self.solo.address_of(&script);
                let found = blocks.iter().filter(|b| b.address == address).count();
                Some(MinerListEntry {
                    address,
                    connected: !open.is_empty(),
                    summary,
                    blocks_found: found,
                })
            })
            .collect();
        let key = |m: &MinerListEntry| m.summary.hashrate_hs.h1.unwrap_or(0.0);
        miners.sort_by(|a, b| {
            key(b)
                .partial_cmp(&key(a))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.address.cmp(&b.address))
        });
        MinersResponse {
            network: self.solo.network().as_str(),
            generated_at: now,
            collecting_since: since,
            miners,
        }
    }
}

/// The routes, for the monitoring listener.
#[cfg(feature = "monitoring")]
pub fn router(api: Arc<SoloApi>) -> stratum_apps::monitoring::axum::Router {
    use stratum_apps::monitoring::axum::{
        extract::{Path, Query, State},
        http::StatusCode,
        response::{IntoResponse, Json, Response},
        routing::get,
        Router,
    };

    fn refuse(e: ApiError) -> Response {
        let code = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_REQUEST);
        (code, Json(serde_json::json!({ "error": e.message() }))).into_response()
    }

    async fn miner(State(api): State<Arc<SoloApi>>, Path(address): Path<String>) -> Response {
        match api.miner(&address) {
            Ok(r) => Json(r).into_response(),
            Err(e) => refuse(e),
        }
    }

    async fn history(
        State(api): State<Arc<SoloApi>>,
        Path(address): Path<String>,
        Query(q): Query<HashMap<String, String>>,
    ) -> Response {
        let w = q.get("window").map_or("24h", String::as_str);
        match api.miner_history(&address, w) {
            Ok(r) => Json(r).into_response(),
            Err(e) => refuse(e),
        }
    }

    async fn status(State(api): State<Arc<SoloApi>>) -> Response {
        Json(api.status()).into_response()
    }

    async fn miners(State(api): State<Arc<SoloApi>>) -> Response {
        Json(api.miners()).into_response()
    }

    Router::new()
        .route("/api/v1/miner/{address}", get(miner))
        .route("/api/v1/miner/{address}/history", get(history))
        .route("/api/v1/pool/status", get(status))
        .route("/api/v1/pool/miners", get(miners))
        .with_state(api)
}

#[cfg(test)]
#[path = "solo_api_tests.rs"]
mod tests;
