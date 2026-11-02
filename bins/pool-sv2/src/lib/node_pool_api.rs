//! The node pool's ledger and status API (W2.11).
//!
//! pool_sv2 owns everything these answers come from: the relay's store (`/var/lib/ghost/
//! node-pool.db`, root-owned, mode 0600), the share-chain tip and peers, settlement's progress
//! and its provisional blocks, and the connected miners with their sensed slot classes. So the
//! answers are built here and served on the monitoring listener (loopback, `monitoring_address`);
//! ghost-mining's public API forwards `GET /api/v1/ledger/{address}` and
//! `GET /api/v1/node-pool/status` to them, so the website and `ghost-cli node status` read them
//! where they read everything else.
//!
//! - `GET /api/v1/node-pool/ledger/{address}`: one miner's balance (sats and the exact `2^-32`
//!   units), where it stands in the payout queues of the table the next block pays (ranked by
//!   [`canonical_payout::queue_position`], paid per slot class by
//!   [`canonical_payout::paid_to`]: the rule is never re-implemented here), recent credited
//!   shares, and recent payouts with their heights, settled or provisional. An address with no
//!   row, share or payout is a 200 with `known: false`; an address that is not one of this
//!   network's, or not a payee class, is a 400.
//! - `GET /api/v1/node-pool/status`: share-chain tip and anchor height, peers, settlement
//!   caught up or not, recent pool blocks with their payouts and the treasury change, and the
//!   connected miners with their slot class and any firmware warning.

use std::{collections::HashSet, future::Future, pin::Pin, str::FromStr, sync::Arc};

use ghost_common::{
    canonical_payout::{
        eligible_count, paid_to, queue_position, split, split_slots, subsidy, Table,
    },
    node_pool_constants::{FACE_PER_SAT, MIN_PAYOUT_SATS, SLOT_CLASSES, SNAPSHOT_CUT_LAG},
    node_pool_network::NodePoolNetwork,
    share_commit::payee_script_class,
};
use ghost_np_relay::relay::credit_event_key;
use ghost_storage::node_pool_store::NpLedgerEventKind;
use serde::Serialize;
use stratum_apps::stratum_core::bitcoin::{address::NetworkUnchecked, Address, Script};

use crate::{
    miner_stats::{now_secs, MinerStats},
    node_pool::{ChannelKind, ChannelStatus, NodePool},
    node_pool_relay::RelayParts,
};

/// Credited shares listed per miner.
const SHARES_LISTED: usize = 50;
/// Batch memberships read to find them (a share can sit in a losing anchor's batch too).
const SHARES_SCANNED: usize = 200;
/// Payouts listed per miner.
const PAYOUTS_LISTED: usize = 50;
/// Pool blocks listed in the status.
const BLOCKS_LISTED: usize = 20;
/// Confirmations before a coinbase output can be spent.
const COINBASE_MATURITY: u32 = 100;

/// The table the next block pays: the relay's `block_table` for the job's parent anchor and
/// height, the same table every job on the active template is built on.
#[derive(Debug, Clone)]
pub struct NextTable {
    /// The next block's height.
    pub height: u32,
    /// The anchor its jobs build on.
    pub parent_anchor: [u8; 32],
    /// The table.
    pub table: Arc<Table>,
}

/// Boxed future for [`LiveView::next_table`].
pub type NextTableFuture<'a> = Pin<Box<dyn Future<Output = Option<NextTable>> + Send + 'a>>;

/// The live, in-memory side of the API: the job layer's channels and its next table.
pub trait LiveView: Send + Sync {
    /// Every open channel.
    fn miners(&self) -> Vec<ChannelStatus>;
    /// The table the next block pays, if the relay can give one now.
    fn next_table(&self) -> NextTableFuture<'_>;
    /// This node's identity, if it has one.
    fn node_id(&self) -> Option<[u8; 32]> {
        None
    }
}

impl LiveView for NodePool {
    fn miners(&self) -> Vec<ChannelStatus> {
        self.channel_status()
    }

    fn node_id(&self) -> Option<[u8; 32]> {
        Some(*NodePool::node_id(self))
    }

    fn next_table(&self) -> NextTableFuture<'_> {
        Box::pin(async move {
            let height = self
                .active_template()
                .as_ref()
                .and_then(|t| NodePool::template_height(t))?;
            let parent_anchor = self.anchor_driver().current()?.parent_anchor;
            let table = self.fetch_table(parent_anchor, height).await?;
            Some(NextTable {
                height,
                parent_anchor,
                table,
            })
        })
    }
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// The address is not one this network's ledger can hold (400).
    BadAddress(String),
    /// The store failed (500).
    Internal(String),
}

impl ApiError {
    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        match self {
            ApiError::BadAddress(_) => 400,
            ApiError::Internal(_) => 500,
        }
    }

    /// The message.
    pub fn message(&self) -> &str {
        match self {
            ApiError::BadAddress(m) | ApiError::Internal(m) => m,
        }
    }
}

pub(crate) fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(format!("node pool store: {e}"))
}

/// An amount in face units: exact, and in whole sats (floor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Amount {
    /// Face units of `2^-32` sat, exact, as a decimal string (it can exceed 2^53).
    pub units: String,
    /// Whole sats, rounded down.
    pub sats: i64,
}

impl Amount {
    pub(crate) fn of(units: i128) -> Amount {
        let sats = units.div_euclid(FACE_PER_SAT);
        Amount {
            units: units.to_string(),
            sats: i64::try_from(sats).unwrap_or(if sats < 0 { i64::MIN } else { i64::MAX }),
        }
    }
}

/// What one block at one slot class would pay this miner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassPayout {
    /// Miner outputs the block carries.
    pub slot_class: u16,
    /// Of which the oldest half, `ceil(N/2)`.
    pub oldest_slots: usize,
    /// This miner is in the oldest half at this class.
    pub in_oldest: bool,
    /// Sats the block would pay it (0 if none), from `canonical_payout::build_outputs`.
    pub sats: u64,
}

/// Where a miner stands for the next block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueView {
    /// The next block's height.
    pub next_block_height: u32,
    /// The snapshot height its table counts credits to, `H - 20`.
    pub snapshot_height: Option<u32>,
    /// The anchor the next jobs build on, internal byte order.
    pub parent_anchor: String,
    /// Owed on that table (credits after the snapshot are not in it yet).
    pub owed: Amount,
    /// At or above the 1,000-sat floor on that table.
    pub eligible: bool,
    /// Eligible balances on that table.
    pub eligible_count: usize,
    /// The largest eligible balance: paid last in a block, with whatever is left.
    pub is_top: bool,
    /// Rank in the oldest queue (1 = oldest), excluding top.
    pub age_rank: Option<usize>,
    /// Rank by size (1 = top).
    pub size_rank: Option<usize>,
    /// What the next block would pay at each slot class.
    pub next_block: Vec<ClassPayout>,
}

/// A credited share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShareView {
    /// Its header hash, internal byte order.
    pub share_id: String,
    /// The anchor whose batch credited it, internal byte order.
    pub anchor: String,
    /// That anchor's Bitcoin height.
    pub anchor_btc_height: u32,
    /// The share's job height.
    pub job_height: u32,
    /// The tier it was credited at.
    pub credited_tier: u8,
    /// What it earned.
    pub credit: Amount,
    /// When this node received its batch, unix seconds.
    pub received_at: i64,
}

/// A payout: a pool block's output to this miner, as settlement retired it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayoutView {
    /// The block's height.
    pub height: u32,
    /// The block's hash, as explorers show it.
    pub block_hash: String,
    /// Sats paid.
    pub sats: i64,
    /// Face units retired (sats times 2^32).
    pub units: String,
    /// `settled`: checked against its anchor's table. `provisional`: retired from its coinbase
    /// because this node does not hold its anchor yet; checked when the anchor arrives.
    pub status: &'static str,
    /// Confirmations at the last Bitcoin tip settlement saw.
    pub confirmations: Option<u32>,
    /// Spendable: 100 confirmations or more.
    pub mature: Option<bool>,
    /// When settlement applied it, unix seconds.
    pub applied_at: i64,
}

/// Settlement, briefly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettlementBrief {
    /// Settlement has looked at every block to the Bitcoin tip it last saw.
    pub caught_up: bool,
    /// The highest height it has looked at.
    pub synced_height: Option<u32>,
    /// The Bitcoin tip it last saw.
    pub bitcoin_tip: Option<u32>,
    /// Blocks retired provisionally.
    pub provisional_blocks: usize,
}

/// `GET /api/v1/node-pool/ledger/{address}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LedgerResponse {
    /// The address asked about.
    pub address: String,
    /// This node's network.
    pub network: &'static str,
    /// Its output script, hex: what the ledger keys on.
    pub script_hex: String,
    /// The ledger has a row, a credited share or a payout for it.
    pub known: bool,
    /// Plain words when `known` is false.
    pub message: Option<String>,
    /// Owed now: every credit through the tip, minus every payout.
    pub balance: Amount,
    /// The height its balance last crossed 1,000 sats; it orders the oldest queue.
    pub queue_since: Option<u32>,
    /// Balances below this are not paid.
    pub min_payout_sats: u64,
    /// Face units per sat.
    pub units_per_sat: u64,
    /// Where it stands for the next block, when the relay can give that block's table.
    pub queue: Option<QueueView>,
    /// Why `queue` is absent.
    pub queue_unavailable: Option<String>,
    /// Credited shares, newest first.
    pub recent_shares: Vec<ShareView>,
    /// Payouts, highest block first.
    pub payouts: Vec<PayoutView>,
    /// Settlement's progress, which `payouts` depends on.
    pub settlement: SettlementBrief,
}

/// A coinbase output to a miner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PaidOutput {
    /// The payee's address (the script as hex if it has none).
    pub address: String,
    /// Sats.
    pub sats: i64,
}

/// A pool block as settlement retired it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockView {
    /// Height.
    pub height: u32,
    /// Hash, as explorers show it.
    pub block_hash: String,
    /// `settled` or `provisional`.
    pub status: &'static str,
    /// The subsidy.
    pub subsidy_sats: u64,
    /// The treasury's fixed share, `S/200`.
    pub treasury_base_sats: u64,
    /// Paid to miners' balances.
    pub miners_paid_sats: i64,
    /// What the miners' half could not pay (`Rm` minus what it paid), sent to the treasury.
    pub treasury_change_sats: i64,
    /// The treasury output: base plus change.
    pub treasury_sats: i64,
    /// The miner outputs in pay order.
    pub payouts: Vec<PaidOutput>,
    /// When settlement applied it, unix seconds.
    pub applied_at: i64,
}

/// Sensing, as the status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SensingView {
    /// The ceiling table's model for this miner.
    pub model: &'static str,
    /// Its firmware token, if the agent carried one.
    pub firmware: Option<String>,
    /// The agent it reported.
    pub agent: Option<String>,
    /// The largest class it may be stepped to.
    pub ceiling_class: u16,
    /// The sensing loop has settled.
    pub settled: bool,
    /// The largest class that passed.
    pub highest_passed: Option<u16>,
}

/// One connected channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MinerView {
    /// Downstream connection id.
    pub downstream_id: usize,
    /// Channel id.
    pub channel_id: u32,
    /// `standard` (header-only, always the full class) or `extended` (sensed).
    pub kind: &'static str,
    /// The payee its shares credit.
    pub address: String,
    /// The worker name: what follows the first `.` of its user identity.
    pub worker: String,
    /// Miner outputs its jobs carry.
    pub slot_class: u16,
    /// Sensing state, for extended channels.
    pub sensing: Option<SensingView>,
    /// The low-limit firmware warning, if its model is one.
    pub firmware_warning: Option<String>,
}

/// Where the share chain starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StartView {
    /// Genesis anchor, internal byte order.
    pub genesis_anchor: String,
    /// Its Bitcoin height.
    pub genesis_btc_height: u32,
    /// `config`, `compiled` or `default`.
    pub source: &'static str,
    /// `T_net` at genesis.
    pub genesis_tier: u8,
    /// The digest of the genesis table this node runs on.
    pub genesis_table_digest: String,
    /// The pinned digest, if any.
    pub pinned_genesis_table_digest: Option<String>,
}

/// The share chain's tip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChainView {
    /// Best anchor, internal byte order.
    pub tip: String,
    /// Its anchor height (genesis is 0).
    pub anchor_height: u32,
    /// The Bitcoin tip its job saw.
    pub btc_height: u32,
    /// `T_net` for a job on it now.
    pub t_net: u8,
    /// Cumulative anchor work, hex.
    pub work: String,
    /// Network shares waiting for a batch.
    pub loose_shares: usize,
    /// Anchors held without their batch.
    pub unseen_anchors: usize,
}

/// A provisional block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvisionalBlock {
    /// Height.
    pub height: u32,
    /// Hash, as explorers show it.
    pub block_hash: String,
}

/// Settlement, in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettlementView {
    /// Settlement has looked at every block to the Bitcoin tip it last saw.
    pub caught_up: bool,
    /// The highest height it has looked at.
    pub synced_height: Option<u32>,
    /// The Bitcoin tip it last saw.
    pub bitcoin_tip: Option<u32>,
    /// Blocks retired provisionally, waiting for their anchor.
    pub provisional: Vec<ProvisionalBlock>,
    /// Blocks matched since start.
    pub matched: u64,
    /// Provisional blocks later confirmed.
    pub confirmed: u64,
    /// Blocks refused: anchor held, outputs not canonical.
    pub mismatched: u64,
    /// Blocks undone by a Bitcoin reorg.
    pub disconnected: u64,
}

/// `GET /api/v1/node-pool/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusResponse {
    /// This node's network.
    pub network: &'static str,
    /// Where the share chain starts.
    pub start: StartView,
    /// The share chain's tip.
    pub share_chain: ChainView,
    /// Connected relay peers.
    pub peers: usize,
    /// Settlement.
    pub settlement: SettlementView,
    /// The finder output: every fee of a block this node's miners find.
    pub fee_address: String,
    /// Rows in the balance table.
    pub ledger_rows: u64,
    /// Recent pool blocks, highest first.
    pub recent_blocks: Vec<BlockView>,
    /// Connected miners.
    pub miners: Vec<MinerView>,
}

/// The API over a running relay and job layer.
pub struct NodePoolApi {
    pub(crate) parts: RelayParts,
    fee_address: String,
    pub(crate) live: Arc<dyn LiveView>,
    /// Per-worker share statistics (W2.17), for the miner pages.
    pub(crate) stats: Arc<MinerStats>,
    /// Unix seconds now; a fixed clock in tests.
    pub(crate) clock: fn() -> u64,
}

pub(crate) fn display_hash(h: &[u8; 32]) -> String {
    let mut b = *h;
    b.reverse();
    hex::encode(b)
}

fn sats_of(units: i128) -> i64 {
    Amount::of(units).sats
}

impl NodePoolApi {
    /// An API over `parts`, with the job layer `live`.
    pub fn new(parts: RelayParts, fee_address: String, live: Arc<dyn LiveView>) -> NodePoolApi {
        NodePoolApi {
            parts,
            fee_address,
            live,
            stats: Arc::new(MinerStats::in_memory(now_secs())),
            clock: now_secs,
        }
    }

    /// The same API reading `stats` for the miner pages.
    pub fn with_miner_stats(mut self, stats: Arc<MinerStats>) -> NodePoolApi {
        self.stats = stats;
        self
    }

    /// The same API on a fixed clock (tests).
    pub fn with_clock(mut self, clock: fn() -> u64) -> NodePoolApi {
        self.clock = clock;
        self
    }

    pub(crate) fn network(&self) -> NodePoolNetwork {
        self.parts.start.network
    }

    pub(crate) fn address_of(&self, script: &[u8]) -> String {
        Address::from_script(Script::from_bytes(script), self.network().bitcoin_network())
            .map(|a| a.to_string())
            .unwrap_or_else(|_| hex::encode(script))
    }

    /// The payee script of `address`, refused unless it is this network's and a payee class.
    pub fn payee_script(&self, address: &str) -> Result<Vec<u8>, ApiError> {
        let net = self.network();
        let a = address.trim();
        let parsed = Address::<NetworkUnchecked>::from_str(a)
            .map_err(|e| ApiError::BadAddress(format!("{a:?} is not a Bitcoin address: {e}")))?;
        let checked = parsed.require_network(net.bitcoin_network()).map_err(|_| {
            ApiError::BadAddress(format!(
                "{a:?} is not a {net} address; this node runs on {net}"
            ))
        })?;
        let script = checked.script_pubkey().to_bytes();
        if payee_script_class(&script).is_none() {
            return Err(ApiError::BadAddress(format!(
                "{a:?} cannot be paid by the node pool: only P2SH, P2WPKH, P2WSH and P2TR \
                 addresses can be"
            )));
        }
        Ok(script)
    }

    pub(crate) fn settlement_brief(&self) -> SettlementBrief {
        let s = self.parts.settlement.borrow();
        SettlementBrief {
            caught_up: s.caught_up(),
            synced_height: s.synced_height,
            bitcoin_tip: s.bitcoin_tip,
            provisional_blocks: s.provisional.len(),
        }
    }

    fn provisional_set(&self) -> HashSet<[u8; 32]> {
        self.parts
            .settlement
            .borrow()
            .provisional
            .iter()
            .map(|(_, h)| *h)
            .collect()
    }

    /// The ledger for `address`.
    pub async fn ledger(&self, address: &str) -> Result<LedgerResponse, ApiError> {
        let script = self.payee_script(address)?;
        let db = &self.parts.db;
        let row = db.np_balance(&script).map_err(internal)?;

        let mut recent_shares = Vec::new();
        for s in db
            .np_payee_shares(&script, SHARES_SCANNED)
            .map_err(internal)?
        {
            if recent_shares.len() == SHARES_LISTED {
                break;
            }
            let key = credit_event_key(&s.anchor_hash, s.job_height);
            if !db
                .np_ledger_event_applied(NpLedgerEventKind::Credit, &key)
                .map_err(internal)?
            {
                continue;
            }
            recent_shares.push(ShareView {
                share_id: hex::encode(s.share_id),
                anchor: hex::encode(s.anchor_hash),
                anchor_btc_height: s.anchor_btc_height,
                job_height: s.job_height,
                credited_tier: s.credited_tier,
                credit: Amount::of(s.face),
                received_at: s.received_at,
            });
        }

        let settlement = self.settlement_brief();
        let provisional = self.provisional_set();
        let tip = settlement.bitcoin_tip;
        let payouts: Vec<PayoutView> = db
            .np_payee_retirements(&script, PAYOUTS_LISTED)
            .map_err(internal)?
            .into_iter()
            .map(|r| {
                let confirmations = tip.and_then(|t| t.checked_sub(r.height)).map(|d| d + 1);
                PayoutView {
                    height: r.height,
                    block_hash: display_hash(&r.block_hash),
                    sats: sats_of(r.amount),
                    units: r.amount.to_string(),
                    status: if provisional.contains(&r.block_hash) {
                        "provisional"
                    } else {
                        "settled"
                    },
                    confirmations,
                    mature: confirmations.map(|c| c >= COINBASE_MATURITY),
                    applied_at: r.applied_at,
                }
            })
            .collect();

        let (queue, queue_unavailable) = match self.live.next_table().await {
            None => (
                None,
                Some(
                    "the relay has no table for the next block yet (no template, no anchor, or \
                     settlement still catching up)"
                        .to_string(),
                ),
            ),
            Some(next) => match self.queue_view(&next, &script) {
                Ok(q) => (Some(q), None),
                Err(e) => (None, Some(e)),
            },
        };

        let known = row.is_some() || !recent_shares.is_empty() || !payouts.is_empty();
        let balance = row.map_or(0, |b| b.owed);
        Ok(LedgerResponse {
            address: address.trim().to_string(),
            network: self.network().as_str(),
            script_hex: hex::encode(&script),
            known,
            message: (!known).then(|| {
                "This address has no balance, credited shares or payouts on this node's share \
                 chain. Shares appear once an anchor's batch credits them (about a minute), and \
                 only shares at or above the network tier are credited."
                    .to_string()
            }),
            balance: Amount::of(balance),
            queue_since: row.and_then(|b| b.queue_since),
            min_payout_sats: MIN_PAYOUT_SATS,
            units_per_sat: FACE_PER_SAT as u64,
            queue,
            queue_unavailable,
            recent_shares,
            payouts,
            settlement,
        })
    }

    fn queue_view(&self, next: &NextTable, script: &[u8]) -> Result<QueueView, String> {
        let t = next.table.as_ref();
        let pos = queue_position(t, script).map_err(|e| format!("payout arithmetic: {e}"))?;
        let mut next_block = Vec::new();
        for &class in &SLOT_CLASSES {
            let slots = class as usize;
            let (oldest_slots, _) = split_slots(slots);
            next_block.push(ClassPayout {
                slot_class: class,
                oldest_slots,
                in_oldest: pos
                    .and_then(|p| p.age_rank)
                    .is_some_and(|r| r <= oldest_slots),
                sats: paid_to(next.height, t, slots, script)
                    .map_err(|e| format!("payout arithmetic: {e}"))?,
            });
        }
        Ok(QueueView {
            next_block_height: next.height,
            snapshot_height: next.height.checked_sub(SNAPSHOT_CUT_LAG),
            parent_anchor: hex::encode(next.parent_anchor),
            owed: Amount::of(pos.map_or(0, |p| p.owed)),
            eligible: pos.is_some_and(|p| p.eligible),
            eligible_count: eligible_count(t).map_err(|e| format!("payout arithmetic: {e}"))?,
            is_top: pos.is_some_and(|p| p.is_top),
            age_rank: pos.and_then(|p| p.age_rank),
            size_rank: pos.and_then(|p| p.size_rank),
            next_block,
        })
    }

    /// The pool-wide status.
    pub async fn status(&self) -> Result<StatusResponse, ApiError> {
        let db = &self.parts.db;
        let relay = *self.parts.status.borrow();
        let st = self.parts.settlement.borrow().clone();
        let provisional: HashSet<[u8; 32]> = st.provisional.iter().map(|(_, h)| *h).collect();
        let recent_blocks = db
            .np_recent_blocks(BLOCKS_LISTED)
            .map_err(internal)?
            .into_iter()
            .map(|b| {
                let (base, rm) = split(b.height);
                let paid: i64 = b.retirements.iter().map(|(_, a)| sats_of(*a)).sum();
                let change = i64::try_from(rm).unwrap_or(i64::MAX) - paid;
                BlockView {
                    height: b.height,
                    block_hash: display_hash(&b.block_hash),
                    status: if provisional.contains(&b.block_hash) {
                        "provisional"
                    } else {
                        "settled"
                    },
                    subsidy_sats: subsidy(b.height),
                    treasury_base_sats: base,
                    miners_paid_sats: paid,
                    treasury_change_sats: change,
                    treasury_sats: i64::try_from(base).unwrap_or(i64::MAX) + change,
                    payouts: b
                        .retirements
                        .iter()
                        .map(|(s, a)| PaidOutput {
                            address: self.address_of(s),
                            sats: sats_of(*a),
                        })
                        .collect(),
                    applied_at: b.applied_at,
                }
            })
            .collect();
        let miners = self
            .live
            .miners()
            .into_iter()
            .map(|c| MinerView {
                downstream_id: c.key.0,
                channel_id: c.key.1,
                kind: match c.kind {
                    ChannelKind::Standard => "standard",
                    ChannelKind::Extended => "extended",
                },
                address: self.address_of(&c.payee_script),
                worker: crate::miner_stats::worker_name(&c.user_identity),
                slot_class: c.slot_class,
                firmware_warning: c
                    .sensing
                    .as_ref()
                    .and_then(|s| s.warning.as_ref())
                    .map(ToString::to_string),
                sensing: c.sensing.map(|s| SensingView {
                    model: s.model,
                    firmware: s.firmware,
                    agent: s.agent,
                    ceiling_class: s.ceiling_class,
                    settled: s.settled,
                    highest_passed: s.highest_passed,
                }),
            })
            .collect();
        let start = &self.parts.start;
        Ok(StatusResponse {
            network: start.network.as_str(),
            start: StartView {
                genesis_anchor: hex::encode(start.genesis_anchor),
                genesis_btc_height: start.genesis_btc_height,
                source: start.source.as_str(),
                genesis_tier: self.parts.genesis_tier,
                genesis_table_digest: hex::encode(self.parts.genesis_table_digest),
                pinned_genesis_table_digest: start.pinned_table_digest.map(hex::encode),
            },
            share_chain: ChainView {
                tip: hex::encode(relay.best),
                anchor_height: relay.height,
                btc_height: relay.btc_height,
                t_net: relay.t_net,
                work: hex::encode(relay.work.to_be_bytes()),
                loose_shares: relay.loose,
                unseen_anchors: relay.unseen,
            },
            peers: relay.peers,
            settlement: SettlementView {
                caught_up: st.caught_up(),
                synced_height: st.synced_height,
                bitcoin_tip: st.bitcoin_tip,
                provisional: st
                    .provisional
                    .iter()
                    .map(|(h, b)| ProvisionalBlock {
                        height: *h,
                        block_hash: display_hash(b),
                    })
                    .collect(),
                matched: st.stats.matched,
                confirmed: st.stats.confirmed,
                mismatched: st.stats.mismatched,
                disconnected: st.stats.disconnected,
            },
            fee_address: self.fee_address.clone(),
            ledger_rows: db.np_ledger_rows().map_err(internal)?,
            recent_blocks,
            miners,
        })
    }
}

/// The routes, for the monitoring listener.
#[cfg(feature = "monitoring")]
pub fn router(api: Arc<NodePoolApi>) -> stratum_apps::monitoring::axum::Router {
    use stratum_apps::monitoring::axum::{
        extract::{Path, State},
        http::StatusCode,
        response::{IntoResponse, Json, Response},
        routing::get,
        Router,
    };

    fn refuse(e: ApiError) -> Response {
        let code = StatusCode::from_u16(e.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (code, Json(serde_json::json!({ "error": e.message() }))).into_response()
    }

    async fn ledger(State(api): State<Arc<NodePoolApi>>, Path(address): Path<String>) -> Response {
        match api.ledger(&address).await {
            Ok(r) => Json(r).into_response(),
            Err(e) => refuse(e),
        }
    }

    async fn status(State(api): State<Arc<NodePoolApi>>) -> Response {
        match api.status().await {
            Ok(r) => Json(r).into_response(),
            Err(e) => refuse(e),
        }
    }

    Router::new()
        .route("/api/v1/node-pool/status", get(status))
        .route("/api/v1/node-pool/ledger/{address}", get(ledger))
        .with_state(api)
}

#[cfg(test)]
#[path = "node_pool_api_tests.rs"]
pub(crate) mod tests;
