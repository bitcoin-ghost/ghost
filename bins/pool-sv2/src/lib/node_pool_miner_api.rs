//! The miner pages' API (W2.17): one address's workers on this node, their history, its balance
//! history, and an honest expected wait.
//!
//! Served beside the ledger and status ([`crate::node_pool_api`]) on the monitoring listener, and
//! forwarded by ghost-mining as `GET /api/v1/miner/{address}` and
//! `GET /api/v1/miner/{address}/history?window=24h|7d|30d`, with the same address checks.
//!
//! Two kinds of data, and the answer says which is which:
//! - **This node's**: hashrate, share counts and reject reasons, last share times, connections
//!   with their slot class and firmware warning. Only the node a miner is connected to sees its
//!   shares, so these come from [`crate::miner_stats`] and a page shows them per node. They are
//!   telemetry, not ledger: nothing is paid from them.
//! - **The share chain's**: the balance history (from the ledger journals, the same on every
//!   node) and the expected wait (from the next block's table and the pool's recent blocks).
//!
//! ## `GET /api/v1/node-pool/miner/{address}`
//!
//! ```json
//! {
//!   "address": "bc1q…", "network": "mainnet", "script_hex": "0014…",
//!   "node_id": "7a7a…", "generated_at": 1800000000, "collecting_since": 1799990000,
//!   "summary": {
//!     "workers": 2, "online": 1, "idle": 0, "offline": 1,
//!     "hashrate_hs": { "15m": 1.2e14, "1h": 1.1e14, "24h": 9.8e13 },
//!     "shares_24h": { "accepted": 812, "stale": 3, "rejected": 1,
//!                     "reject_reasons": { "duplicate-share": 1 } },
//!     "last_share_at": 1799999990
//!   },
//!   "workers": [{
//!     "name": "rig1", "status": "online", "last_share_at": 1799999990,
//!     "last_submit_at": 1799999990, "hashrate_hs": { … }, "shares_24h": { … },
//!     "slot_class": 9, "firmware_warning": "Stock Antminer firmware …",
//!     "connections": [{ "downstream_id": 4, "channel_id": 1, "kind": "extended",
//!                       "slot_class": 9, "model": "Stock Antminer", "firmware": "2.0.0",
//!                       "ceiling_class": 9, "settled": true, "firmware_warning": "…" }]
//!   }],
//!   "expected_wait": { "known": true, "seconds": 52000, "blocks_needed": 2, … }
//! }
//! ```
//!
//! A hashrate is `null` when this node has observed less than a minute of the window. A worker
//! is `online` when it is connected and sent a share in the last 10 minutes, `idle` when it is
//! connected but has not, `offline` when it is not connected here.
//!
//! ## `GET /api/v1/node-pool/miner/{address}/history?window=24h|7d|30d`
//!
//! `24h` is 288 five-minute buckets, `7d` 168 and `30d` 720 one-hour buckets, oldest first,
//! ending with the bucket now is in. Every series is aligned with `buckets`. A share series value
//! is `null` for a bucket this node was not yet collecting in (before `collecting_since`):
//! unknown, not zero. The balance series is the share chain's and is never `null`.
//!
//! ```json
//! {
//!   "address": "bc1q…", "network": "mainnet", "node_id": "7a7a…", "window": "24h",
//!   "bucket_seconds": 300, "generated_at": 1800000000, "collecting_since": 1799990000,
//!   "buckets": [1799913900, …],
//!   "total": { "hashrate_hs": [null, …, 1.1e14], "accepted": [null, …, 31],
//!              "stale": [...], "rejected": [...] },
//!   "workers": [{ "name": "rig1", "series": { … } }], "workers_omitted": 0,
//!   "reject_reasons": { "duplicate-share": 1 },
//!   "balance": { "start_sats": 0, "end_sats": [...], "credited_sats": [...],
//!                "paid_sats": [...], "payouts": [{ "time": …, "height": …, "sats": …,
//!                "block_hash": "…" }], "time_basis": "…" }
//! }
//! ```

use std::collections::{BTreeMap, HashMap};

use ghost_common::{
    canonical_payout::{paid_to, queue_position, split_slots},
    node_pool_constants::{MIN_PAYOUT_SATS, SLOT_CLASSES, SNAPSHOT_CUT_LAG},
};
use ghost_storage::node_pool_store::NpLedgerEventKind;
use serde::Serialize;

use crate::{
    miner_stats::{
        bucket_starts, hashrate_hs, observed_secs, over_span, window, Bucket, Ring, Snapshot,
        SpanTotals, WorkerStats, FINE, ONLINE_SECS, REASONS,
    },
    node_pool::{ChannelKind, ChannelStatus},
    node_pool_api::{display_hash, internal, ApiError, NodePoolApi},
};

/// Workers listed in a history; the rest are in the total only.
pub const MAX_HISTORY_WORKERS: usize = 64;
/// Ledger events read for a balance history.
const MAX_LEDGER_EVENTS: usize = 200_000;
/// Pool blocks read for the block rate.
const RATE_BLOCKS: usize = 20;
/// Fewest pool blocks in [`RATE_WINDOW_SECS`] the block rate is estimated from.
pub const MIN_RATE_BLOCKS: usize = 3;
/// How far back pool blocks count toward the rate.
pub const RATE_WINDOW_SECS: u64 = 30 * 86_400;
/// An event applied this long after its Bitcoin time was applied late (a node syncing): it is
/// placed at its Bitcoin time instead.
const LATE_APPLY_SECS: i64 = 2 * 3_600;
/// Bitcoin's target block interval, for the snapshot lag.
const BITCOIN_BLOCK_SECS: u64 = 600;

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

/// One connection of a worker to this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionView {
    /// Downstream connection id.
    pub downstream_id: usize,
    /// Channel id.
    pub channel_id: u32,
    /// `standard` or `extended`.
    pub kind: &'static str,
    /// Miner outputs its jobs carry.
    pub slot_class: u16,
    /// The ceiling table's model, as sensed.
    pub model: Option<&'static str>,
    /// Its firmware token, if the agent carried one.
    pub firmware: Option<String>,
    /// The largest class it may be stepped to.
    pub ceiling_class: Option<u16>,
    /// The sensing loop has settled.
    pub settled: Option<bool>,
    /// The low-limit firmware warning, if its model is one.
    pub firmware_warning: Option<String>,
}

/// One worker on this node.
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
    /// The smallest slot class among its connections.
    pub slot_class: Option<u16>,
    /// A firmware warning from any of its connections.
    pub firmware_warning: Option<String>,
    /// Its open channels on this node.
    pub connections: Vec<ConnectionView>,
}

/// The address on this node, summed over its workers.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MinerSummary {
    /// Workers known to this node.
    pub workers: usize,
    /// Of which online.
    pub online: usize,
    /// Connected but quiet.
    pub idle: usize,
    /// Not connected here.
    pub offline: usize,
    /// Hashrate of all workers.
    pub hashrate_hs: Rates,
    /// Shares in the last 24 hours.
    pub shares_24h: Counts,
    /// The latest accepted share of any worker.
    pub last_share_at: Option<u64>,
}

/// An estimate of how long until this address is next paid, or why there is none.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ExpectedWait {
    /// An estimate was possible.
    pub known: bool,
    /// Why not, in plain words, when `known` is false.
    pub reason: Option<String>,
    /// Estimated seconds until the payment.
    pub seconds: Option<u64>,
    /// Pool blocks until the payment, as estimated.
    pub blocks_needed: Option<u32>,
    /// Pool blocks counted for the rate.
    pub pool_blocks_counted: usize,
    /// Mean seconds between pool blocks, from them.
    pub pool_block_interval_secs: Option<u64>,
    /// Miner outputs the recent pool blocks paid (the median).
    pub typical_outputs_per_block: Option<u32>,
    /// Sats still needed to reach the 1,000-sat floor.
    pub sats_to_floor: Option<u64>,
    /// Sats credited in the last 24 hours.
    pub credited_sats_24h: Option<i64>,
    /// What the estimate assumes.
    pub assumptions: Vec<String>,
}

/// `GET /api/v1/node-pool/miner/{address}`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MinerResponse {
    /// The address asked about.
    pub address: String,
    /// This node's network.
    pub network: &'static str,
    /// Its output script, hex.
    pub script_hex: String,
    /// This node's identity, hex.
    pub node_id: Option<String>,
    /// When this answer was built, unix seconds.
    pub generated_at: u64,
    /// When this node's share statistics begin.
    pub collecting_since: u64,
    /// Summed over the workers.
    pub summary: MinerSummary,
    /// The workers this node knows, online first.
    pub workers: Vec<WorkerView>,
    /// How long until it is next paid.
    pub expected_wait: ExpectedWait,
    /// Whether work served now earns (it does not before the first earning height).
    pub earning: crate::node_pool_api::EarningView,
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
}

/// One worker's series.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WorkerSeries {
    /// Its name.
    pub name: String,
    /// Its series.
    pub series: Series,
}

/// A payout, placed in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayoutPoint {
    /// Unix seconds (see `time_basis`).
    pub time: i64,
    /// The block's height.
    pub height: u32,
    /// Sats paid.
    pub sats: i64,
    /// The block's hash, as explorers show it.
    pub block_hash: String,
}

/// The balance over a window, from the ledger journals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct BalanceHistory {
    /// The balance when the window starts, sats (floor).
    pub start_sats: i64,
    /// The balance at the end of each bucket (or now, for the last), sats.
    pub end_sats: Vec<i64>,
    /// Credited in each bucket, sats.
    pub credited_sats: Vec<i64>,
    /// Paid in each bucket, sats.
    pub paid_sats: Vec<i64>,
    /// Payouts in the window.
    pub payouts: Vec<PayoutPoint>,
    /// The balance carried over from the old pool at the cutover (the imported genesis table),
    /// when the window reaches back to it: the opening balance, in place from its time on.
    /// Not counted in `credited_sats`.
    pub carried_over: Option<CarriedOverPoint>,
    /// How events are placed in time.
    pub time_basis: &'static str,
}

/// The opening balance carried over at the cutover, placed in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CarriedOverPoint {
    /// Unix seconds (see `time_basis`): the export height's block time, else when it was
    /// imported.
    pub time: i64,
    /// The export's height (the freeze height).
    pub height: u64,
    /// Sats carried over.
    pub sats: i64,
}

/// A payee's genesis row as the history opens with it: its balance from `time` on, before any
/// share-chain event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opening {
    /// Unix seconds.
    pub time: i64,
    /// The export's height.
    pub height: u64,
    /// Face units carried over.
    pub owed: i128,
}

/// `GET /api/v1/node-pool/miner/{address}/history`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistoryResponse {
    /// The address asked about.
    pub address: String,
    /// This node's network.
    pub network: &'static str,
    /// This node's identity, hex.
    pub node_id: Option<String>,
    /// `24h`, `7d` or `30d`.
    pub window: &'static str,
    /// Bucket width.
    pub bucket_seconds: u64,
    /// When this answer was built.
    pub generated_at: u64,
    /// When this node's share statistics begin.
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
    /// The balance over the window.
    pub balance: BalanceHistory,
}

const TIME_BASIS: &str = "when this node applied the event, or the Bitcoin time of its block \
                          when it was applied more than two hours later (a node catching up)";

/// Where a ledger event sits in time: when it was applied, unless that was well after its
/// Bitcoin time (a syncing node applies months at once), then its Bitcoin time.
pub fn event_time(applied_at: i64, chain_time: Option<u32>) -> i64 {
    match chain_time {
        Some(c) if applied_at > i64::from(c) + LATE_APPLY_SECS => i64::from(c),
        _ => applied_at,
    }
}

fn sats(units: i128) -> i64 {
    crate::node_pool_api::Amount::of(units).sats
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

fn connection_view(c: &ChannelStatus) -> ConnectionView {
    ConnectionView {
        downstream_id: c.key.0,
        channel_id: c.key.1,
        kind: match c.kind {
            ChannelKind::Standard => "standard",
            ChannelKind::Extended => "extended",
        },
        slot_class: c.slot_class,
        model: c.sensing.as_ref().map(|s| s.model),
        firmware: c.sensing.as_ref().and_then(|s| s.firmware.clone()),
        ceiling_class: c.sensing.as_ref().map(|s| s.ceiling_class),
        settled: c.sensing.as_ref().map(|s| s.settled),
        firmware_warning: c
            .sensing
            .as_ref()
            .and_then(|s| s.warning.as_ref())
            .map(ToString::to_string),
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
                .map(|cs| cs.iter().map(|c| connection_view(c)).collect())
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
            let (hashrate_hs, shares_24h) = match stats {
                Some(s) => (
                    worker_rates(&s.fine, snap.collecting_since, now).0,
                    counts_24h(s, now),
                ),
                None => (
                    worker_rates(&Ring::default(), snap.collecting_since, now).0,
                    Counts::default(),
                ),
            };
            WorkerView {
                name: name.clone(),
                status,
                last_share_at: stats.and_then(|s| s.last_share_at),
                last_submit_at,
                hashrate_hs,
                shares_24h,
                slot_class: conns.iter().map(|c| c.slot_class).min(),
                firmware_warning: conns.iter().find_map(|c| c.firmware_warning.clone()),
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
    }
    // Rates sum per span; unknown when the node has not observed enough of it.
    let mut work = [0.0f64; 3];
    let mut observed: [Option<u64>; 3] = [None; 3];
    for st in snap.workers.values() {
        let (_, spans) = worker_rates(&st.fine, snap.collecting_since, now);
        for (i, sp) in spans.iter().enumerate() {
            if let Some(sp) = sp {
                work[i] += sp.work;
                observed[i] = Some(sp.observed_secs);
            }
        }
    }
    let empty = worker_rates(&Ring::default(), snap.collecting_since, now).1;
    let rate = |i: usize| {
        observed[i]
            .or(empty[i].as_ref().map(|e| e.observed_secs))
            .map(|o| hashrate_hs(work[i], o))
    };
    s.hashrate_hs = Rates {
        m15: rate(0),
        h1: rate(1),
        h24: rate(2),
    };
    s
}

/// What [`estimate_wait`] works from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WaitInput {
    /// The next block's table was available.
    pub have_table: bool,
    /// Eligible on that table.
    pub eligible: bool,
    /// The largest eligible balance.
    pub is_top: bool,
    /// Rank in the oldest queue.
    pub age_rank: Option<usize>,
    /// Eligible balances on the table.
    pub eligible_count: usize,
    /// What the next block would pay this address with the typical number of outputs, from
    /// `canonical_payout::paid_to`; `None` when there is no typical number.
    pub paid_next_at_typical: Option<u64>,
    /// The balance now, sats.
    pub balance_sats: i64,
    /// Times of recent pool blocks, unix seconds, any order.
    pub block_times: Vec<i64>,
    /// Miner outputs each of those blocks paid.
    pub block_outputs: Vec<usize>,
    /// Sats credited in the last 24 hours, if known.
    pub credited_sats_24h: Option<i64>,
    /// Now.
    pub now: u64,
}

/// The median of the outputs recent pool blocks paid, at least the smallest slot class (a block
/// that paid fewer had fewer balances to pay, not fewer outputs to pay them with).
pub fn typical_outputs(outputs: &[usize]) -> Option<usize> {
    if outputs.is_empty() {
        return None;
    }
    let mut v = outputs.to_vec();
    v.sort_unstable();
    Some(v[v.len() / 2].max(usize::from(SLOT_CLASSES[0])))
}

/// Estimate the wait for the next payment. Unknown, with the reason, whenever the data is thin:
/// no table, fewer than [`MIN_RATE_BLOCKS`] pool blocks in [`RATE_WINDOW_SECS`], or (below the
/// floor) no credits in the last day. Never a guess.
pub fn estimate_wait(i: &WaitInput) -> ExpectedWait {
    let unknown = |reason: String, mut w: ExpectedWait| {
        w.known = false;
        w.reason = Some(reason);
        w
    };
    let mut w = ExpectedWait {
        credited_sats_24h: i.credited_sats_24h,
        ..Default::default()
    };
    if !i.have_table {
        return unknown(
            "this node has no table for the next block yet, so where you stand is not known".into(),
            w,
        );
    }
    let now = i.now as i64;
    let window_start = now - RATE_WINDOW_SECS as i64;
    let mut recent: Vec<i64> = i
        .block_times
        .iter()
        .copied()
        .filter(|t| *t >= window_start && *t <= now)
        .collect();
    recent.sort_unstable();
    w.pool_blocks_counted = recent.len();
    if recent.len() < MIN_RATE_BLOCKS {
        return unknown(
            format!(
                "the pool has found {} block{} in the last 30 days; at least {MIN_RATE_BLOCKS} \
                 are needed to estimate how often it finds one",
                recent.len(),
                if recent.len() == 1 { "" } else { "s" }
            ),
            w,
        );
    }
    // Blocks after the first, over the time from the first to now: a long dry spell since the
    // last block lengthens the interval rather than being ignored.
    let interval = ((now - recent[0]).max(1) as u64) / (recent.len() as u64 - 1);
    let interval = interval.max(1);
    w.pool_block_interval_secs = Some(interval);
    let typical = typical_outputs(&i.block_outputs).unwrap_or(usize::from(SLOT_CLASSES[0]));
    w.typical_outputs_per_block = Some(typical as u32);
    let (oldest_slots, _) = split_slots(typical);
    w.assumptions = vec![
        format!(
            "the pool keeps finding blocks at its recent rate: {} blocks in the last 30 days, one \
             every {} on average",
            recent.len(),
            human_secs(interval)
        ),
        format!(
            "each block pays about as many balances as recent blocks did ({typical}, the \
             median), half of them the oldest"
        ),
        "block finding is random: the real wait can easily be half or double this".into(),
    ];

    let blocks = if i.eligible {
        if i.paid_next_at_typical.is_some_and(|p| p > 0) || i.is_top {
            1
        } else if let Some(r) = i.age_rank {
            r.div_ceil(oldest_slots.max(1))
        } else {
            return unknown(
                "you are eligible but in neither queue's reach on this table".into(),
                w,
            );
        }
    } else {
        // Below the floor: first reach 1,000 sats, then wait out the snapshot lag, then join
        // the back of the oldest queue.
        let to_floor = (MIN_PAYOUT_SATS as i64 - i.balance_sats).max(0) as u64;
        w.sats_to_floor = Some(to_floor);
        let per_day = match i.credited_sats_24h {
            Some(c) if c > 0 => c as u64,
            _ => {
                return unknown(
                    format!(
                        "your balance is under the 1,000-sat floor ({to_floor} sats to go) and \
                         nothing was credited in the last 24 hours, so there is no rate to \
                         reach it at"
                    ),
                    w,
                )
            }
        };
        let to_floor_secs = if to_floor == 0 {
            0
        } else {
            (to_floor * 86_400).div_ceil(per_day)
        };
        let lag = u64::from(SNAPSHOT_CUT_LAG) * BITCOIN_BLOCK_SECS;
        let blocks = (i.eligible_count + 1).div_ceil(oldest_slots.max(1));
        w.assumptions.push(format!(
            "you keep earning about {per_day} sats a day, reach 1,000 sats, and then wait out \
             the {SNAPSHOT_CUT_LAG}-block snapshot lag (about {}) before joining the back of \
             the oldest queue",
            human_secs(lag)
        ));
        let blocks = u32::try_from(blocks).unwrap_or(u32::MAX);
        w.blocks_needed = Some(blocks);
        w.seconds = Some(to_floor_secs + lag + u64::from(blocks) * interval);
        w.known = true;
        return w;
    };
    let blocks = u32::try_from(blocks).unwrap_or(u32::MAX);
    w.blocks_needed = Some(blocks);
    w.seconds = Some(u64::from(blocks).saturating_mul(interval));
    w.known = true;
    w
}

fn human_secs(s: u64) -> String {
    if s < 3_600 {
        format!("{} minutes", s.div_ceil(60))
    } else if s < 2 * 86_400 {
        format!("{:.1} hours", s as f64 / 3_600.0)
    } else {
        format!("{:.1} days", s as f64 / 86_400.0)
    }
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
            continue;
        }
        let b = ring.get(t);
        s.hashrate_hs
            .push(Some(hashrate_hs(b.map_or(0.0, |b| b.work), seen)));
        s.accepted.push(Some(b.map_or(0, |b| b.accepted)));
        s.stale.push(Some(b.map_or(0, |b| b.stale)));
        s.rejected.push(Some(b.map_or(0, Bucket::rejected_total)));
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
}

/// One balance change placed in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceEvent {
    /// Unix seconds.
    pub time: i64,
    /// Applied order.
    pub seq: i64,
    /// A credit or a payout.
    pub kind: NpLedgerEventKind,
    /// Face units credited or paid.
    pub amount: i128,
    /// The balance before it.
    pub prior_owed: i128,
    /// The block's height, for a payout.
    pub height: u32,
    /// The block, for a payout.
    pub block_hash: Option<[u8; 32]>,
}

/// One step of a balance's history: the opening balance, or a ledger event.
#[derive(Clone, Copy)]
enum Step<'a> {
    Open(&'a Opening),
    Event(&'a BalanceEvent),
}

impl Step<'_> {
    fn key(&self) -> (i64, i64) {
        match self {
            // Before any event at the same second: the share chain starts on it.
            Step::Open(o) => (o.time, i64::MIN),
            Step::Event(e) => (e.time, e.seq),
        }
    }

    fn before(&self) -> i128 {
        match self {
            Step::Open(_) => 0,
            Step::Event(e) => e.prior_owed,
        }
    }

    fn after(&self) -> i128 {
        match self {
            Step::Open(o) => o.owed,
            Step::Event(e) => match e.kind {
                NpLedgerEventKind::Credit => e.prior_owed + e.amount,
                NpLedgerEventKind::Block => e.prior_owed - e.amount,
            },
        }
    }
}

/// The balance over `starts` (each `width` long), from `events`, the genesis `opening` when the
/// events reach back to it (every event after it is in `events`), and the balance now.
pub fn balance_history(
    events: &[BalanceEvent],
    opening: Option<&Opening>,
    starts: &[u64],
    width: u64,
    balance_now: i128,
) -> BalanceHistory {
    let mut ev: Vec<Step> = events.iter().map(Step::Event).collect();
    ev.extend(opening.map(Step::Open));
    ev.sort_by_key(Step::key);
    let Some(&first) = starts.first() else {
        return BalanceHistory {
            time_basis: TIME_BASIS,
            ..Default::default()
        };
    };
    let first = first as i64;
    // The balance at the window's start: after the last step before it, else before the first
    // step in it, else (no steps at all) the balance now.
    let start = ev
        .iter()
        .rev()
        .find(|e| e.key().0 < first)
        .map(Step::after)
        .or_else(|| ev.iter().find(|e| e.key().0 >= first).map(Step::before))
        .unwrap_or(balance_now);
    let mut h = BalanceHistory {
        start_sats: sats(start),
        time_basis: TIME_BASIS,
        carried_over: opening.map(|o| CarriedOverPoint {
            time: o.time,
            height: o.height,
            sats: sats(o.owed),
        }),
        ..Default::default()
    };
    let mut bal = start;
    let mut idx = ev.partition_point(|e| e.key().0 < first);
    for &t in starts {
        let end = (t + width) as i64;
        let (mut credited, mut paid) = (0i128, 0i128);
        while idx < ev.len() && ev[idx].key().0 < end {
            let step = ev[idx];
            bal = step.after();
            if let Step::Event(e) = step {
                match e.kind {
                    NpLedgerEventKind::Credit => credited += e.amount,
                    NpLedgerEventKind::Block => {
                        paid += e.amount;
                        h.payouts.push(PayoutPoint {
                            time: e.time,
                            height: e.height,
                            sats: sats(e.amount),
                            block_hash: e.block_hash.as_ref().map(display_hash).unwrap_or_default(),
                        });
                    }
                }
            }
            idx += 1;
        }
        h.end_sats.push(sats(bal));
        h.credited_sats.push(sats(credited));
        h.paid_sats.push(sats(paid));
    }
    h
}

impl NodePoolApi {
    fn node_hex(&self) -> Option<String> {
        self.live.node_id().map(hex::encode)
    }

    /// The ledger events of `script` reaching back at least `span` seconds, placed in time, and
    /// its genesis row as the opening balance when they reach back to the export height (and
    /// none was cut by the event limit).
    fn balance_events(
        &self,
        script: &[u8],
        span: u64,
    ) -> Result<(Vec<BalanceEvent>, Option<Opening>), ApiError> {
        // Heights are chain time, so a syncing node's late application cannot hide events: read
        // from 1.5x the window's blocks below the tip (and the snapshot lag), then place each
        // event in time and let the caller cut the window.
        let tip = self
            .settlement_brief()
            .bitcoin_tip
            .unwrap_or(self.parts.status.borrow().btc_height);
        let blocks = (span / BITCOIN_BLOCK_SECS) * 3 / 2 + u64::from(SNAPSHOT_CUT_LAG);
        let min_height = tip.saturating_sub(u32::try_from(blocks).unwrap_or(u32::MAX));
        let all = self
            .parts
            .db
            .np_payee_ledger_events(script, min_height, MAX_LEDGER_EVENTS)
            .map_err(internal)?;
        let opening = if all.len() < MAX_LEDGER_EVENTS {
            self.parts
                .db
                .np_genesis_balance(script)
                .map_err(internal)?
                .filter(|g| g.export_height >= u64::from(min_height))
                .map(|g| Opening {
                    time: event_time(g.imported_at, g.chain_time),
                    height: g.export_height,
                    owed: g.balance.owed,
                })
        } else {
            None
        };
        let events = all
            .into_iter()
            .map(|e| BalanceEvent {
                time: event_time(e.applied_at, e.chain_time),
                seq: e.seq,
                kind: e.kind,
                amount: e.amount,
                prior_owed: e.prior_owed,
                height: e.height,
                block_hash: e.block_hash,
            })
            .collect();
        Ok((events, opening))
    }

    fn credited_24h(events: &[BalanceEvent], now: u64) -> i64 {
        let from = now as i64 - 86_400;
        sats(
            events
                .iter()
                .filter(|e| e.kind == NpLedgerEventKind::Credit && e.time >= from)
                .map(|e| e.amount)
                .sum(),
        )
    }

    async fn wait_for(
        &self,
        script: &[u8],
        balance_sats: i64,
        credited_sats_24h: Option<i64>,
        now: u64,
    ) -> Result<ExpectedWait, ApiError> {
        let blocks = self
            .parts
            .db
            .np_recent_blocks(RATE_BLOCKS)
            .map_err(internal)?;
        let mut block_times = Vec::with_capacity(blocks.len());
        let mut block_outputs = Vec::with_capacity(blocks.len());
        for b in &blocks {
            let chain = self
                .parts
                .db
                .np_get_btc_block(&b.block_hash)
                .map_err(internal)?
                .and_then(|x| x.header.get(68..72).map(|t| t.to_vec()))
                .and_then(|t| <[u8; 4]>::try_from(t.as_slice()).ok())
                .map(u32::from_le_bytes);
            block_times.push(event_time(b.applied_at, chain));
            block_outputs.push(b.retirements.len());
        }
        let mut input = WaitInput {
            balance_sats,
            block_times,
            credited_sats_24h,
            now,
            ..Default::default()
        };
        // A table the payout arithmetic refuses leaves the wait unknown; it never fails the page.
        if let Some(next) = self.live.next_table().await {
            let t = next.table.as_ref();
            if let (Ok(pos), Ok(count)) = (
                queue_position(t, script),
                ghost_common::canonical_payout::eligible_count(t),
            ) {
                input.have_table = true;
                input.eligible = pos.is_some_and(|p| p.eligible);
                input.is_top = pos.is_some_and(|p| p.is_top);
                input.age_rank = pos.and_then(|p| p.age_rank);
                input.eligible_count = count;
                input.paid_next_at_typical = typical_outputs(&block_outputs)
                    .and_then(|n| paid_to(next.height, self.halving(), t, n, script).ok());
            }
        }
        input.block_outputs = block_outputs;
        Ok(estimate_wait(&input))
    }

    /// One address's workers on this node, with the expected wait.
    pub async fn miner(&self, address: &str) -> Result<MinerResponse, ApiError> {
        let script = self.payee_script(address)?;
        let now = (self.clock)();
        let snap = self.stats.snapshot(&script, now);
        let channels: Vec<ChannelStatus> = self
            .live
            .miners()
            .into_iter()
            .filter(|c| c.payee_script == script)
            .collect();
        let workers = worker_views(&snap, &channels, now);
        let summary = summarize(&workers, &snap, now);

        let balance = self
            .parts
            .db
            .np_payee_balance(&script)
            .map_err(internal)?
            .map_or(0, |b| b.owed);
        let (events, _) = self.balance_events(&script, 86_400)?;
        let credited = Self::credited_24h(&events, now);
        let expected_wait = self
            .wait_for(&script, sats(balance), Some(credited), now)
            .await?;
        Ok(MinerResponse {
            address: address.trim().to_string(),
            network: self.network().as_str(),
            script_hex: hex::encode(&script),
            node_id: self.node_hex(),
            generated_at: now,
            collecting_since: snap.collecting_since,
            summary,
            workers,
            expected_wait,
            earning: crate::node_pool_api::EarningView::new(
                self.parts.start.genesis_btc_height,
                self.live.job_height(),
            ),
        })
    }

    /// One address's history over `window_name` (`24h`, `7d` or `30d`).
    pub async fn miner_history(
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
        let snap = self.stats.snapshot(&script, now);
        let starts = bucket_starts(w, now);
        let since = snap.collecting_since;

        // Workers ranked by work in the window.
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

        let balance_now = self
            .parts
            .db
            .np_payee_balance(&script)
            .map_err(internal)?
            .map_or(0, |b| b.owed);
        let (events, opening) = self.balance_events(&script, w.span)?;
        let balance = balance_history(&events, opening.as_ref(), &starts, w.res.width, balance_now);

        Ok(HistoryResponse {
            address: address.trim().to_string(),
            network: self.network().as_str(),
            node_id: self.node_hex(),
            window: w.name,
            bucket_seconds: w.res.width,
            generated_at: now,
            collecting_since: since,
            buckets: starts,
            total,
            workers_omitted: ranked.len().saturating_sub(MAX_HISTORY_WORKERS),
            workers,
            reject_reasons: reasons.into_iter().collect(),
            balance,
        })
    }
}

/// The routes, for the monitoring listener.
#[cfg(feature = "monitoring")]
pub fn router(api: std::sync::Arc<NodePoolApi>) -> stratum_apps::monitoring::axum::Router {
    use std::sync::Arc;
    use stratum_apps::monitoring::axum::{
        extract::{Path, Query, State},
        http::StatusCode,
        response::{IntoResponse, Json, Response},
        routing::get,
        Router,
    };

    fn refuse(e: ApiError) -> Response {
        let code = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (code, Json(serde_json::json!({ "error": e.message() }))).into_response()
    }

    async fn miner(State(api): State<Arc<NodePoolApi>>, Path(address): Path<String>) -> Response {
        match api.miner(&address).await {
            Ok(r) => Json(r).into_response(),
            Err(e) => refuse(e),
        }
    }

    async fn history(
        State(api): State<Arc<NodePoolApi>>,
        Path(address): Path<String>,
        Query(q): Query<HashMap<String, String>>,
    ) -> Response {
        let w = q.get("window").map_or("24h", String::as_str);
        match api.miner_history(&address, w).await {
            Ok(r) => Json(r).into_response(),
            Err(e) => refuse(e),
        }
    }

    Router::new()
        .route("/api/v1/node-pool/miner/{address}", get(miner))
        .route("/api/v1/node-pool/miner/{address}/history", get(history))
        .with_state(api)
}

#[cfg(test)]
#[path = "node_pool_miner_api_tests.rs"]
mod tests;
