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
//| FILE: relay.rs                                                                                                       |
//|======================================================================================================================|

//! The relay core: what a node does with network shares, anchors and batches (spec 2.1, 2.2).
//!
//! Synchronous and transport-free. The network layer ([`crate::net`]) or a test harness feeds it
//! messages with a [`PeerId`] and collects [`Out`] actions: messages to send, penalties, and new
//! job anchors for pool_sv2's `AnchorDriver`.
//!
//! ## Receive path
//!
//! - **Network share (NS).** Checked as the next anchor on this node's best tip would include it
//!   (rules 1-6, the snapshot from the best tip's ancestry), kept in the loose pool and relayed.
//!   A share that is merely stale or already included is dropped without penalty.
//! - **Anchor.** Self-contained checks first (the coinbase folds to the header, the tag
//!   recomputes, the parent tag and BIP34 height agree with the claimed `btc_height`). Then the
//!   [`AnchorChain`] insert checks `btc_height` against the parent and the hash against
//!   `T_net + 8`. An anchor with an unknown parent waits as an orphan while the parent is fetched.
//! - **Batch.** The ids must hash to the anchor's committed `batch_root`. Missing share bodies are
//!   fetched. When the parent is seen and every body is held, every share (and the anchor's own
//!   share) is checked against the INCLUDING anchor's ancestry; one failure makes the anchor
//!   invalid. A valid batch is stored, attached, and relayed with its anchor. Until then the anchor
//!   is unseen (correction 6): it neither wins fork choice nor credits anyone.
//!
//! ## Send path
//!
//! Local shares from pool_sv2 at tier `>= T_net` go out as NS. A local share meeting `T_net + 8`
//! on a job whose `(parent_anchor, batch_root)` this node published becomes an anchor with the
//! batch published under that root. Every change of best tip publishes a new [`JobAnchor`] at
//! once, and the loose pool is re-batched every [`RelayParams::backstop_secs`].
//!
//! ## Credits
//!
//! When an anchor joins the best chain its batch's credits are applied to the stored ledger,
//! one event per job height in ascending order; on a reorg the disconnected anchors are undone
//! newest first, then the new branch applied. Block retirements applied by settlement (W2.7) that
//! sit above them are undone and re-applied around the move.
//!
//! ## Retirements (deterministic settlement, W2.13)
//!
//! A snapshot table subtracts the retirements of the node pool blocks on the Bitcoin ancestry of
//! the share's own `prev_hash`, read from the [`crate::archive::BtcArchive`], never this node's
//! best chain. A pool block retires what it paid unless an anchor with its `GHPP` prefix sits on
//! the includer's ancestry and none of them matches it (`block_table` root and canonical outputs),
//! in which case it retires nothing. Every input is committed by the share, its includer, or an
//! archived block, so two nodes with the same archive reach the same table whatever their Bitcoin
//! tips.
//!
//! ## Sync, checkpoints and pruning (W2.13)
//!
//! See [`crate::relay::sync`].

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use ghost_common::anchor_chain::{
    AncestryError, AnchorChain, AnchorError, AnchorHash, AnchorHeader, ShareId,
};
use ghost_common::canonical_payout::{
    cut, first_earning_height, provisional_retirements, table_for_from, table_root, Halving,
    Retirement, Script, Table,
};
use ghost_common::coinbase_tags::{extract_node_tag, extract_payout_tag};
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::node_pool_constants::{
    ANCHOR_TIER_OFFSET, PARENT_ANCHOR_TAG_LEN, SHARE_HEIGHT_WINDOW,
};
use ghost_common::node_pool_u256::U256;
use ghost_common::share_commit::{
    batch_root, fold_coinbase_branch, hash_meets_tier, settle_outputs, verify_share, ShareContext,
    ShareError, ShareSubmission,
};
use ghost_storage::node_pool_store::{NpAnchorRecord, NpBatchShare, NpLedgerEventKind};
use ghost_storage::Database;

use crate::archive::{ArchivedBlock, BtcArchive};
use crate::checkpoint::{Checkpoint, CreditMap};
use crate::headers::{HeaderFacts, HeaderLookup};
use crate::peers::penalty;
use crate::wire::{
    AnchorMsg, Message, NetShare, NotFoundKind, MAX_BATCH_SHARES, MAX_SHARES_PER_MESSAGE,
};

pub mod sync;

/// A connected peer, as the network layer numbers it.
pub type PeerId = u64;

/// What new jobs build on: pool_sv2's `AnchorUpdate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobAnchor {
    /// The anchor jobs are built on.
    pub parent_anchor: AnchorHash,
    /// Root of the batch a job would lock in if it became an anchor.
    pub batch_root: [u8; 32],
}

/// An action for the network layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// Send to one peer.
    Send(PeerId, Message),
    /// Send to every peer except one.
    Broadcast {
        /// The message.
        msg: Message,
        /// Who not to send it to (where it came from).
        except: Option<PeerId>,
    },
    /// Add to a peer's ban score.
    Penalize {
        /// The peer.
        peer: PeerId,
        /// Score to add.
        score: u32,
        /// Why, for the log.
        reason: String,
    },
    /// New jobs: push to pool_sv2's `AnchorDriver`.
    Publish(JobAnchor),
}

/// The trusted start of the share chain.
#[derive(Debug, Clone)]
pub struct Genesis {
    /// The genesis anchor's hash.
    pub hash: AnchorHash,
    /// Its `btc_height`.
    pub btc_height: u32,
    /// `T_net` at genesis.
    pub tier: u8,
    /// The imported genesis balance table (plan, Phase 4). Every snapshot table folds onto it.
    pub table: Table,
}

/// Relay settings.
#[derive(Debug, Clone)]
pub struct RelayParams {
    /// The share chain's genesis.
    pub genesis: Genesis,
    /// Tier 0 target: `share_commit::diff1_target()` on mainnet and signet.
    pub tier_base: U256,
    /// Re-batch the loose pool and re-publish (if changed) this often, seconds. Spec: 30.
    pub backstop_secs: u64,
    /// Ask another peer for a missing batch or share bodies after this long, seconds.
    pub request_timeout_secs: u64,
    /// Most loose shares kept.
    pub max_loose: usize,
    /// Most anchors waiting for an unknown parent.
    pub max_orphans: usize,
    /// Relay policy (correction 3): an anchor more than this many Bitcoin blocks behind the local
    /// tip on receipt is accepted but not relayed.
    pub recency_blocks: u32,
    /// Relay policy: a loose share stamped more than this far in the future is dropped.
    pub future_time_secs: u64,
    /// Announce the best tip to every peer this often, seconds.
    pub tip_announce_secs: u64,
    /// Fold a checkpoint at the last best-chain anchor this many Bitcoin blocks below the best
    /// anchor's `btc_height`. 0: never (every batch stays in memory and is replayed on start).
    /// At least [`sync::MIN_CHECKPOINT_DEPTH`] otherwise.
    pub checkpoint_depth: u32,
    /// Fold a new checkpoint once the target anchor is this many Bitcoin blocks past the last.
    pub checkpoint_interval: u32,
    /// Delete stored batches below the older of the two kept checkpoints. Off: an archive node,
    /// which can serve a fresh node's sync from genesis.
    pub prune: bool,
    /// Batches requested at once while syncing.
    pub sync_inflight: usize,
    /// The Bitcoin network's subsidy schedule (`NodePoolNetwork::halving`): what shares are priced
    /// at, what coinbases pay, and where the era guard splits. Mainnet's by default; a regtest
    /// relay must set regtest's.
    pub halving: Halving,
}

impl RelayParams {
    /// Defaults around a genesis.
    pub fn new(genesis: Genesis, tier_base: U256) -> Self {
        RelayParams {
            genesis,
            tier_base,
            backstop_secs: 30,
            request_timeout_secs: 5,
            max_loose: 65_536,
            max_orphans: 1_024,
            recency_blocks: 6,
            future_time_secs: 7_200,
            tip_announce_secs: 30,
            checkpoint_depth: sync::DEFAULT_CHECKPOINT_DEPTH,
            checkpoint_interval: sync::DEFAULT_CHECKPOINT_INTERVAL,
            prune: false,
            sync_inflight: 32,
            halving: Halving::MAINNET,
        }
    }
}

/// One share's credit under its including anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credit {
    /// Job height `H`.
    pub job_height: u32,
    /// Payee.
    pub script: Script,
    /// Face units.
    pub face: i128,
    /// `max(T_net, committed tier)`.
    pub credited_tier: u8,
}

/// What a local share became.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalOutcome {
    /// A network share, relayed.
    Share,
    /// An anchor, valid and attached.
    Anchor,
}

/// Counters for logs and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    /// Network shares accepted into the loose pool.
    pub shares_accepted: u64,
    /// Network shares dropped as stale or not includable.
    pub shares_stale: u64,
    /// Network shares refused as invalid.
    pub shares_invalid: u64,
    /// Anchors whose batch completed.
    pub anchors_valid: u64,
    /// Anchors found invalid.
    pub anchors_invalid: u64,
    /// Best-tip changes that disconnected at least one anchor.
    pub reorgs: u64,
}

/// Status for logs and the network layer's handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayStatus {
    /// Best seen tip.
    pub best: AnchorHash,
    /// Its anchor height.
    pub height: u32,
    /// Its cumulative work.
    pub work: U256,
    /// Its `btc_height`.
    pub btc_height: u32,
    /// `T_net` for a job on the best tip at the local Bitcoin tip.
    pub t_net: u8,
    /// Shares in the loose pool.
    pub loose: usize,
    /// Anchors held but not yet seen: waiting for their batch, its bodies, or what its checks
    /// need.
    pub unseen: usize,
    /// Connected peers.
    pub peers: usize,
    /// Counters.
    pub stats: RelayStats,
}

/// Why a share was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reject {
    /// Something it refers to is not held yet: a Bitcoin header or an anchor.
    Wait(WaitOn),
    /// Not includable here (stale, duplicate, a view-dependent mismatch). No penalty for a loose
    /// share; still a rule break inside a batch.
    Stale(String),
    /// Invalid whoever checks it.
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitOn {
    Header([u8; 32]),
    Anchor(AnchorHash),
    /// Not judgeable here: it reaches below this node's checkpoint.
    Checkpoint,
}

/// Who would include a share.
#[derive(Debug, Clone, Copy)]
enum Includer {
    /// A held anchor (batch checks).
    Anchor(AnchorHash),
    /// The next anchor on `parent`, at `btc_height` (loose shares).
    Next { parent: AnchorHash, btc_height: u32 },
}

struct AnchorEntry {
    share: Arc<NetShare>,
    btc_height: u32,
    source: Option<PeerId>,
    received_at: i64,
}

struct Awaiting {
    since: u64,
    asked: Vec<PeerId>,
}

struct Loose {
    job_height: u32,
    /// The snapshot anchor and the includer (the best tip then) it was last fully checked
    /// against. Tables are pure functions of those, the job height and the share's own prev.
    checked: Option<(AnchorHash, AnchorHash)>,
}

struct Published {
    parent: AnchorHash,
    root: [u8; 32],
    ids: Arc<Vec<ShareId>>,
}

/// Retirements by Bitcoin height, and a digest of them for cache keys.
type RetireView = Arc<(BTreeMap<u32, Vec<Retirement>>, [u8; 32])>;

/// Why a table could not be had.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TableErr {
    /// A Bitcoin block on the way is not archived: fetch it.
    Wait([u8; 32]),
    /// It reaches below this node's checkpoint.
    Unavailable,
    /// The arithmetic refused.
    Arith(String),
}

/// One ledger credit event: `(key, job height, deltas per payee)`.
pub type CreditEvent = ([u8; 32], u32, BTreeMap<Script, i128>);

/// Batches kept retrievable by root for local anchor production.
const PUBLISHED_KEPT: usize = 32;
/// Cached cumulative credit maps.
const CUM_CACHE: usize = 64;
/// Cached snapshot tables.
const TABLE_CACHE: usize = 32;
/// Batches buffered for anchors not held yet.
const EARLY_BATCHES: usize = 256;
/// Cached retirement views.
const RETIRE_CACHE: usize = 256;
/// Most share bodies served for one `GetShares`.
const MAX_SERVED_SHARES: usize = 4 * MAX_SHARES_PER_MESSAGE;
/// Re-batched shares must still be includable this many Bitcoin blocks ahead.
const BATCH_MARGIN: u32 = 2;

/// The ledger event key for the credits of `anchor`'s batch at job height `h`:
/// `sha256("GhostNP/credit/v1" || anchor || h as u32 LE)`.
pub fn credit_event_key(anchor: &AnchorHash, h: u32) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(b"GhostNP/credit/v1");
    s.update(anchor);
    s.update(h.to_le_bytes());
    s.finalize().into()
}

/// A batch's credits as ledger events: per job height ascending, deltas summed per payee.
pub fn credit_events(anchor: &AnchorHash, credits: &[Credit]) -> GhostResult<Vec<CreditEvent>> {
    let mut by: CreditMap = BTreeMap::new();
    for c in credits {
        let slot = by
            .entry(c.job_height)
            .or_default()
            .entry(c.script.clone())
            .or_insert(0);
        *slot = slot
            .checked_add(c.face)
            .ok_or_else(|| GhostError::PayoutCalculation("credit sum overflow".into()))?;
    }
    Ok(by
        .into_iter()
        .map(|(h, d)| (credit_event_key(anchor, h), h, d))
        .collect())
}

/// The parts of a share its id does not commit are bound to it: the coinbase is a coinbase and
/// folds to the header's merkle root, and its scriptSig carries the preimage's tag and parent
/// anchor prefix. A body that fails this was substituted in transit and says nothing about the
/// share or any anchor that includes it.
pub fn share_integrity(s: &NetShare) -> Result<(), String> {
    let tx = s.coinbase_tx().map_err(|e| e.to_string())?;
    if !tx.is_coinbase() || tx.input.len() != 1 {
        return Err("not a coinbase".into());
    }
    let txid = bitcoin::hashes::Hash::to_byte_array(tx.compute_txid());
    if fold_coinbase_branch(txid, &s.merkle_branch)
        != bitcoin::hashes::Hash::to_byte_array(s.header.merkle_root)
    {
        return Err("coinbase does not fold to the header".into());
    }
    let sig = tx.input[0].script_sig.as_bytes();
    if extract_node_tag(sig) != Some(s.tag.tag()) {
        return Err("tag does not match its preimage".into());
    }
    if extract_payout_tag(sig) != Some(s.tag.parent_anchor_tag()) {
        return Err("payout-tag slot does not carry the parent anchor".into());
    }
    Ok(())
}

/// The relay core.
pub struct Relay {
    p: RelayParams,
    db: Arc<Database>,
    chain: AnchorChain,
    anchors: HashMap<AnchorHash, AnchorEntry>,
    kids: HashMap<AnchorHash, Vec<AnchorHash>>,
    invalid: HashSet<AnchorHash>,
    orphans: HashMap<AnchorHash, Vec<(Option<PeerId>, AnchorMsg, u64)>>,
    orphan_count: usize,
    asked_anchor: HashMap<AnchorHash, u64>,
    early_batches: HashMap<AnchorHash, (Option<PeerId>, Vec<ShareId>)>,
    batch_ids: HashMap<AnchorHash, Arc<Vec<ShareId>>>,
    batch_source: HashMap<AnchorHash, Option<PeerId>>,
    awaiting: HashMap<AnchorHash, Awaiting>,
    wanted: HashMap<ShareId, HashSet<AnchorHash>>,
    waiting_on_anchor: HashMap<AnchorHash, HashSet<AnchorHash>>,
    credits: HashMap<AnchorHash, Arc<Vec<Credit>>>,
    shares: HashMap<ShareId, Arc<NetShare>>,
    loose: HashMap<ShareId, Loose>,
    published: VecDeque<Published>,
    last_publish: Option<JobAnchor>,
    last_snapshot_at: u64,
    /// The local Bitcoin tip moved since the last re-batch: re-batch at the next tick.
    rebatch_due: bool,
    last_tip_announce: u64,
    /// The best chain whose credits the stored ledger holds: `path[i]` is the anchor at height
    /// `i + 1`.
    path: Vec<AnchorHash>,
    applied_tip: AnchorHash,
    btc_tip: u32,
    peers: Vec<PeerId>,
    tip_peers: HashMap<PeerId, (AnchorHash, U256)>,
    cum_cache: HashMap<AnchorHash, Arc<CreditMap>>,
    cum_order: VecDeque<AnchorHash>,
    table_cache: HashMap<(AnchorHash, u32, [u8; 32]), Arc<Table>>,
    table_order: VecDeque<(AnchorHash, u32, [u8; 32])>,
    archive: Arc<BtcArchive>,
    base: Arc<Checkpoint>,
    retire_cache: HashMap<(AnchorHash, [u8; 32], u32), RetireView>,
    retire_order: VecDeque<(AnchorHash, [u8; 32], u32)>,
    block_checks: HashMap<([u8; 32], AnchorHash), Option<Vec<Retirement>>>,
    prefix_index: HashMap<[u8; PARENT_ANCHOR_TAG_LEN], Vec<AnchorHash>>,
    sync: sync::SyncState,
    needed_headers: HashSet<[u8; 32]>,
    out: Vec<Out>,
    now: u64,
    stats: RelayStats,
}

fn db_ctx(what: &str) -> impl Fn(GhostError) -> GhostError + '_ {
    move |e| GhostError::Database(format!("{what}: {e}"))
}

impl Relay {
    /// Open the relay over `db`: store the genesis anchor if new, load the newest checkpoint that
    /// verifies, replay every stored anchor and the batches above the checkpoint into the chain,
    /// and bring the stored ledger to the best tip's credits. Share checks read Bitcoin blocks
    /// from `archive`.
    pub fn open(
        params: RelayParams,
        db: Arc<Database>,
        archive: Arc<BtcArchive>,
    ) -> GhostResult<Relay> {
        let g = params.genesis.clone();
        let chain = AnchorChain::new(g.hash, g.btc_height, g.tier, params.tier_base);
        let gi = chain.get(&g.hash).expect("genesis").clone();
        db.np_insert_anchor(&NpAnchorRecord {
            hash: g.hash,
            parent: None,
            height: 0,
            t_net: gi.t_net,
            btc_height: g.btc_height,
            cum_work: gi.work,
            batch_root: batch_root(&[]),
            received_at: 0,
        })
        .map_err(db_ctx("genesis anchor"))?;
        let base = Arc::new(Checkpoint::genesis(
            g.hash,
            g.btc_height,
            gi.work,
            g.table.clone(),
        ));
        let mut r = Relay {
            p: params,
            db,
            chain,
            anchors: HashMap::new(),
            kids: HashMap::new(),
            invalid: HashSet::new(),
            orphans: HashMap::new(),
            orphan_count: 0,
            asked_anchor: HashMap::new(),
            early_batches: HashMap::new(),
            batch_ids: HashMap::new(),
            batch_source: HashMap::new(),
            awaiting: HashMap::new(),
            wanted: HashMap::new(),
            waiting_on_anchor: HashMap::new(),
            credits: HashMap::new(),
            shares: HashMap::new(),
            loose: HashMap::new(),
            published: VecDeque::new(),
            last_publish: None,
            last_snapshot_at: 0,
            rebatch_due: false,
            last_tip_announce: 0,
            path: Vec::new(),
            applied_tip: g.hash,
            btc_tip: g.btc_height,
            peers: Vec::new(),
            tip_peers: HashMap::new(),
            cum_cache: HashMap::new(),
            cum_order: VecDeque::new(),
            table_cache: HashMap::new(),
            table_order: VecDeque::new(),
            archive,
            base,
            retire_cache: HashMap::new(),
            retire_order: VecDeque::new(),
            block_checks: HashMap::new(),
            prefix_index: HashMap::new(),
            sync: sync::SyncState::default(),
            needed_headers: HashSet::new(),
            out: Vec::new(),
            now: 0,
            stats: RelayStats::default(),
        };
        r.index_prefix(g.hash);
        let (base, stale) = r.load_checkpoints()?;
        if let Some(cp) = base {
            r.adopt_base(cp);
        }
        r.replay()?;
        r.reconcile_ledger()?;
        r.verify_newer_checkpoints(stale)?;
        r.publish_snapshot(&HashMap::<[u8; 32], HeaderFacts>::new(), true);
        Ok(r)
    }

    fn replay(&mut self) -> GhostResult<()> {
        let records = self.db.np_load_anchors()?;
        // The checkpoint anchor's ancestry: held without its batch (folded into the base).
        let parents: HashMap<AnchorHash, AnchorHash> = records
            .iter()
            .filter_map(|r| r.parent.map(|p| (r.hash, p)))
            .collect();
        let mut folded = HashSet::new();
        let mut cur = self.base.anchor;
        while let Some(p) = parents.get(&cur) {
            folded.insert(cur);
            cur = *p;
        }
        if cur != self.p.genesis.hash {
            return Err(GhostError::Database(format!(
                "the checkpoint anchor {} does not descend from the stored genesis",
                hex::encode(self.base.anchor)
            )));
        }
        for rec in records {
            let Some(parent) = rec.parent else {
                if rec.hash != self.p.genesis.hash {
                    return Err(GhostError::Database(format!(
                        "the store holds genesis {}, not the configured {}",
                        hex::encode(rec.hash),
                        hex::encode(self.p.genesis.hash)
                    )));
                }
                continue;
            };
            let Some(own) = self.db.np_get_share(&rec.hash)? else {
                warn!(anchor = %hex::encode(rec.hash), "NP_RELAY: stored anchor has no share; skipped");
                continue;
            };
            let share = NetShare::from_record(&own)
                .map_err(|e| GhostError::Database(format!("stored share: {e}")))?;
            if let Err(e) = self.chain.insert(AnchorHeader {
                hash: rec.hash,
                parent,
                btc_height: rec.btc_height,
            }) {
                warn!(anchor = %hex::encode(rec.hash), "NP_RELAY: stored anchor refused on replay: {e}");
                continue;
            }
            self.kids.entry(parent).or_default().push(rec.hash);
            let share = Arc::new(share);
            self.shares.insert(rec.hash, share.clone());
            self.anchors.insert(
                rec.hash,
                AnchorEntry {
                    share,
                    btc_height: rec.btc_height,
                    source: None,
                    received_at: rec.received_at,
                },
            );
            if folded.contains(&rec.hash) {
                // Folded into the checkpoint: seen, its credits in the base.
                self.chain
                    .attach_batch(&rec.hash, &[])
                    .map_err(|e| GhostError::Database(format!("checkpoint ancestry: {e}")))?;
                self.index_prefix(rec.hash);
                self.stats.anchors_valid += 1;
                continue;
            }
            if !self.chain.is_ancestor(&self.base.anchor, &rec.hash) {
                // A fork below the checkpoint: kept as a header, never judged again.
                continue;
            }
            let Some(batch) = self.db.np_get_batch(&rec.hash)? else {
                // Pruned under a checkpoint that no longer verifies, or stored without it: fetch
                // it from peers like any unseen anchor's.
                self.awaiting.insert(
                    rec.hash,
                    Awaiting {
                        since: 0,
                        asked: Vec::new(),
                    },
                );
                continue;
            };
            let mut ids = Vec::with_capacity(batch.shares.len());
            let mut cs = Vec::with_capacity(batch.shares.len());
            let mut bodies = Vec::with_capacity(batch.shares.len());
            for m in &batch.shares {
                let s = NetShare::from_record(&m.share)
                    .map_err(|e| GhostError::Database(format!("stored share: {e}")))?;
                ids.push(m.share.share_id);
                cs.push(Credit {
                    job_height: m.share.job_height,
                    script: m.share.tag.payee_script.clone(),
                    face: i128::try_from(m.face)
                        .map_err(|_| GhostError::Database("stored face above i128".into()))?,
                    credited_tier: m.credited_tier,
                });
                bodies.push((m.share.share_id, s));
            }
            if let Err(e) = self.chain.attach_batch(&rec.hash, &ids) {
                warn!(anchor = %hex::encode(rec.hash), "NP_RELAY: stored batch refused on replay: {e}");
                continue;
            }
            for (id, s) in bodies {
                self.shares.entry(id).or_insert_with(|| Arc::new(s));
            }
            self.batch_ids.insert(rec.hash, Arc::new(ids));
            self.credits.insert(rec.hash, Arc::new(cs));
            self.index_prefix(rec.hash);
            self.stats.anchors_valid += 1;
        }
        Ok(())
    }

    /// Bring the stored ledger to the best tip after a restart: undo credit events of anchors
    /// that are no longer on the best chain (they sit on top, since events are applied in chain
    /// order and undone last-in first-out), then apply what is missing. Events of anchors folded
    /// into the checkpoint are below every event this can need to undo.
    fn reconcile_ledger(&mut self) -> GhostResult<()> {
        let path = self.path_from_base(self.chain.best());
        let on_path: HashSet<AnchorHash> = path.iter().copied().collect();
        let mut expected = HashSet::new();
        let mut other = HashSet::new();
        for (a, cs) in &self.credits {
            for (k, _, _) in credit_events(a, cs)? {
                if on_path.contains(a) {
                    expected.insert(k);
                } else {
                    other.insert(k);
                }
            }
        }
        let mut parked = Vec::new();
        while let Some(ev) = self.db.np_last_ledger_event()? {
            match ev.kind {
                NpLedgerEventKind::Credit if other.contains(&ev.key) => {
                    self.db.np_undo_credits(&ev.key)?
                }
                NpLedgerEventKind::Credit => break,
                NpLedgerEventKind::Block => self.park_block(&ev.key, ev.height, &mut parked)?,
            }
        }
        for a in &path {
            self.apply_credits_of(a)?;
        }
        self.unpark(parked)?;
        self.path = self.path_from_genesis(self.chain.best());
        self.applied_tip = self.chain.best();
        Ok(())
    }

    /// The best-chain anchors from genesis (excluded) to `tip`.
    fn path_from_genesis(&self, tip: AnchorHash) -> Vec<AnchorHash> {
        self.path_down_to(tip, self.p.genesis.hash)
    }

    /// The anchors from the checkpoint anchor (excluded) to `tip`, which descends from it.
    fn path_from_base(&self, tip: AnchorHash) -> Vec<AnchorHash> {
        self.path_down_to(tip, self.base.anchor)
    }

    fn path_down_to(&self, tip: AnchorHash, stop: AnchorHash) -> Vec<AnchorHash> {
        let mut v = Vec::new();
        let mut cur = tip;
        while cur != stop && cur != self.p.genesis.hash {
            v.push(cur);
            cur = self
                .chain
                .get(&cur)
                .and_then(|i| i.parent)
                .expect("seen ancestry");
        }
        v.reverse();
        v
    }

    fn index_prefix(&mut self, a: AnchorHash) {
        let mut k = [0u8; PARENT_ANCHOR_TAG_LEN];
        k.copy_from_slice(&a[..PARENT_ANCHOR_TAG_LEN]);
        let v = self.prefix_index.entry(k).or_default();
        if !v.contains(&a) {
            v.push(a);
            v.sort_unstable();
        }
    }

    // ---------------------------------------------------------------------------------------
    // Queries
    // ---------------------------------------------------------------------------------------

    /// The best seen tip.
    pub fn best(&self) -> AnchorHash {
        self.chain.best()
    }

    /// The anchor chain, read-only.
    pub fn chain(&self) -> &AnchorChain {
        &self.chain
    }

    /// The store.
    pub fn db(&self) -> &Arc<Database> {
        &self.db
    }

    /// The last published job anchor.
    pub fn job_anchor(&self) -> Option<JobAnchor> {
        self.last_publish
    }

    /// Whether `a` is held with its batch checked and attached.
    pub fn has_batch(&self, a: &AnchorHash) -> bool {
        self.credits.contains_key(a)
    }

    /// The credits of a held batch.
    pub fn batch_credits(&self, a: &AnchorHash) -> Option<Arc<Vec<Credit>>> {
        self.credits.get(a).cloned()
    }

    /// Status.
    pub fn status(&self) -> RelayStatus {
        let best = self.chain.best();
        let info = self.chain.get(&best).expect("best is held");
        RelayStatus {
            best,
            height: info.height,
            work: info.work,
            btc_height: info.btc_height,
            t_net: self
                .chain
                .required_tier(&best, self.btc_tip.max(info.btc_height))
                .unwrap_or(info.t_net),
            loose: self.loose.len(),
            unseen: self.awaiting.len(),
            peers: self.peers.len(),
            stats: self.stats,
        }
    }

    /// `T_net` for a job on `parent` while the Bitcoin tip is `btc_height`.
    pub fn required_tier(&self, parent: &AnchorHash, btc_height: u32) -> Option<u8> {
        let pi = self.chain.get(parent)?;
        self.chain
            .required_tier(parent, btc_height.max(pi.btc_height))
            .ok()
    }

    /// The subsidy schedule shares and coinbases are judged on.
    pub fn halving(&self) -> Halving {
        self.p.halving
    }

    /// The archive share checks read Bitcoin blocks from.
    pub fn archive(&self) -> &Arc<BtcArchive> {
        &self.archive
    }

    /// The checkpoint the in-memory state is folded at (genesis when none).
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.base
    }

    /// The table a job on `parent` at job height `h` must pay (rule 4), on this node's best
    /// Bitcoin chain (the job's `prev_hash` is the local tip). For the coinbase builder (W2.6).
    pub fn job_table(&mut self, parent: &AnchorHash, h: u32) -> Option<Arc<Table>> {
        self.block_table(parent, h)
    }

    /// The table a block (or a job) at height `h` built on `parent` must pay, with `prev_hash`
    /// this node's best-chain block at `h - 1`. See [`Relay::block_table_on`].
    pub fn block_table(&mut self, parent: &AnchorHash, h: u32) -> Option<Arc<Table>> {
        let prev = self.archive.main_at(h.checked_sub(1)?)?;
        self.block_table_on(parent, h, &prev)
    }

    /// The table a block (or a job) at height `h` on Bitcoin block `prev`, built on `parent`, must
    /// pay: the snapshot `S(h)` from `parent`'s ancestry with the retirements of `prev`'s Bitcoin
    /// ancestry folded; in the first 20 Bitcoin blocks after genesis, where no anchor sits below
    /// the cut, the genesis table with those retirements. `None` if `parent` is not a held anchor
    /// with its batch, a Bitcoin block on the way is not archived (it is wanted), it reaches
    /// below the checkpoint, or the arithmetic refuses.
    pub fn block_table_on(
        &mut self,
        parent: &AnchorHash,
        h: u32,
        prev: &[u8; 32],
    ) -> Option<Arc<Table>> {
        match self.table_for_job(parent, h, prev) {
            Ok(t) => Some(t),
            Err(TableErr::Wait(x)) => {
                self.needed_headers.insert(x);
                None
            }
            Err(_) => None,
        }
    }

    fn table_for_job(
        &mut self,
        parent: &AnchorHash,
        h: u32,
        prev: &[u8; 32],
    ) -> Result<Arc<Table>, TableErr> {
        if !self.is_complete(parent) {
            return Err(TableErr::Unavailable);
        }
        if let Some(s) = cut(h).and_then(|c| self.chain.last_below(parent, c)) {
            return self.table_at(s, h, parent, prev);
        }
        if self.base.anchor != self.p.genesis.hash {
            return Err(TableErr::Unavailable);
        }
        let view = self.retirements_for(parent, prev, h)?;
        table_for_from(self.p.genesis.table.clone(), h, &BTreeMap::new(), &view.0)
            .map(Arc::new)
            .map_err(|e| TableErr::Arith(e.to_string()))
    }

    /// Whether `a` is genesis, or held with its batch checked (folded into the checkpoint counts).
    fn is_complete(&self, a: &AnchorHash) -> bool {
        *a == self.p.genesis.hash
            || self.credits.contains_key(a)
            || (self.chain.get(a).is_some_and(|i| i.seen)
                && self.chain.is_ancestor(a, &self.base.anchor))
    }

    /// Held anchors (batch attached, or genesis) whose hash starts with `prefix`: the anchors a
    /// block's `GHPP` slot can name.
    pub fn anchors_with_prefix(&self, prefix: &[u8; PARENT_ANCHOR_TAG_LEN]) -> Vec<AnchorHash> {
        self.prefix_index.get(prefix).cloned().unwrap_or_default()
    }

    /// Bitcoin headers the core needed and did not have since the last call.
    pub fn take_needed_headers(&mut self) -> Vec<[u8; 32]> {
        self.needed_headers.drain().collect()
    }

    /// Whether a peer announced a heavier tip this node cannot place yet: it is syncing.
    pub fn behind_peers(&self) -> bool {
        let work = self.chain.get(&self.chain.best()).expect("best").work;
        self.tip_peers
            .values()
            .any(|(h, w)| *w > work && !self.credits.contains_key(h))
    }

    /// Actions produced since the last call.
    pub fn take_out(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }

    // ---------------------------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------------------------

    /// The local Bitcoin tip moved. The next tick re-batches: a batch keeps only shares
    /// includable a couple of blocks past the tip it was built at, and jobs carry it until the
    /// next re-batch, so waiting for the 30 s backstop let a job commit shares that the tip had
    /// already moved out of the window, which makes its anchor invalid (seen on regtest, where
    /// blocks come seconds apart).
    pub fn set_btc_tip(&mut self, h: u32) {
        if h != self.btc_tip {
            self.rebatch_due = true;
        }
        self.btc_tip = h;
    }

    /// A peer finished its handshake.
    pub fn peer_connected(&mut self, peer: PeerId) -> Vec<Out> {
        if !self.peers.contains(&peer) {
            self.peers.push(peer);
        }
        let m = self.tip_message();
        self.out.push(Out::Send(peer, m));
        self.take_out()
    }

    /// A peer went away.
    pub fn peer_disconnected(&mut self, peer: PeerId) {
        self.peers.retain(|p| *p != peer);
        self.tip_peers.remove(&peer);
        self.sync.headers_asked.remove(&peer);
        self.sync.forget(peer);
    }

    fn tip_message(&self) -> Message {
        let best = self.chain.best();
        let info = self.chain.get(&best).expect("best");
        Message::Tip {
            hash: best,
            work: info.work,
            height: info.height,
        }
    }

    /// One message from `peer`. Header facts for any share it carries should be in `hdr`.
    pub fn on_message(
        &mut self,
        peer: PeerId,
        msg: Message,
        hdr: &dyn HeaderLookup,
        now: u64,
    ) -> Vec<Out> {
        self.now = now;
        match msg {
            Message::Hello(_) | Message::GetAddr | Message::Addr(_) => {}
            Message::GetHeaders(loc) => self.serve_headers(peer, &loc),
            Message::Headers(v) => self.on_headers(peer, v, hdr),
            Message::GetBtcBlocks(v) => self.serve_btc_blocks(peer, &v),
            Message::BtcBlocks(v) => self.on_btc_blocks(peer, v, hdr),
            Message::Share(s) => self.on_net_share(Some(peer), s, hdr),
            Message::Anchor(a) => self.on_anchor(Some(peer), a, hdr),
            Message::Batch { anchor, ids } => self.on_batch(Some(peer), anchor, ids, hdr),
            Message::GetBatch(a) => self.serve_batch(peer, &a),
            Message::GetShares(ids) => self.serve_shares(peer, &ids),
            Message::Shares(v) => {
                for s in v {
                    if self.wanted.contains_key(&s.id()) {
                        self.store_body(Some(peer), s, hdr);
                    }
                }
            }
            Message::GetAnchor(h) => self.serve_anchor(peer, &h),
            Message::NotFound(kind, h) => match kind {
                NotFoundKind::Anchor => {
                    self.asked_anchor.remove(&h);
                }
                NotFoundKind::Batch | NotFoundKind::Share => {
                    if let Some(a) = self.awaiting.get_mut(&h) {
                        a.since = 0;
                    }
                }
                NotFoundKind::BtcBlock => self.btc_not_found(peer, h),
                NotFoundKind::Stamps | NotFoundKind::Advert => {}
            },
            // Job stamps and the mining advert are the network layer's: it holds what was
            // published to pool_sv2 and what this node serves miners on.
            Message::GetStamps | Message::Stamps(_) | Message::GetAdvert | Message::Advert(_) => {}
            Message::Tip { hash, work, .. } => self.on_tip(peer, hash, work),
        }
        self.take_out()
    }

    /// A share accepted by this node's pool_sv2. Shares below `T_net` are refused.
    pub fn on_local_share(
        &mut self,
        share: NetShare,
        hdr: &dyn HeaderLookup,
        now: u64,
    ) -> Result<LocalOutcome, String> {
        self.now = now;
        let id = share.id();
        if self.shares.contains_key(&id) || self.anchors.contains_key(&id) {
            return Err("already held".into());
        }
        let prev = share.prev_hash();
        let f = self.facts(hdr, &prev).ok_or_else(|| {
            self.needed_headers.insert(prev);
            "unknown Bitcoin header".to_string()
        })?;
        // Void work (rule 6: no snapshot anchor below the cut) is neither relayed nor made an
        // anchor: every node would refuse it.
        let first = first_earning_height(self.p.genesis.btc_height);
        if f.height.saturating_add(1) < first {
            return Err(format!(
                "void: job height {} is below the first earning height {first} (genesis + 21)",
                f.height.saturating_add(1)
            ));
        }
        let parent = share.tag.parent_anchor;
        let t_net = self
            .required_tier(&parent, f.height)
            .ok_or("job built on an unknown anchor")?;
        if hash_meets_tier(&id, self.p.tier_base, t_net + ANCHOR_TIER_OFFSET) {
            let found = self
                .published
                .iter()
                .rev()
                .find(|p| p.parent == parent && p.root == share.tag.batch_root)
                .map(|p| p.ids.clone());
            match found {
                Some(ids) => {
                    let msg = AnchorMsg {
                        btc_height: f.height,
                        share,
                    };
                    self.on_anchor(None, msg, hdr);
                    self.on_batch(None, id, ids.to_vec(), hdr);
                    return if self.credits.contains_key(&id) {
                        info!(anchor = %hex::encode(id), "NP_RELAY: produced an anchor");
                        Ok(LocalOutcome::Anchor)
                    } else if self.invalid.contains(&id) {
                        Err("produced an invalid anchor".into())
                    } else {
                        Err("anchor waiting for data".into())
                    };
                }
                None => warn!(
                    share = %hex::encode(id),
                    "NP_RELAY: a share meets the anchor tier but its batch root was not published \
                     here; relayed as a network share"
                ),
            }
        }
        if !hash_meets_tier(&id, self.p.tier_base, t_net) {
            return Err("below T_net".into());
        }
        let inc = self.next_includer();
        match self.check_share(&share, inc, hdr) {
            Ok((c, s)) => {
                self.accept_loose(share, c.job_height, Some(s), None);
                Ok(LocalOutcome::Share)
            }
            Err(Reject::Wait(w)) => {
                self.wait_on(w, None, None);
                Err(format!("waiting on {w:?}"))
            }
            Err(Reject::Stale(e)) | Err(Reject::Invalid(e)) => Err(e),
        }
    }

    /// Timers: retries, eviction, the 30 s backstop and the periodic tip announcement.
    pub fn tick(&mut self, hdr: &dyn HeaderLookup, now: u64) -> Vec<Out> {
        self.now = now;
        let timeout = self.p.request_timeout_secs;
        // Missing batches and bodies: ask the next peer.
        let due: Vec<AnchorHash> = self
            .awaiting
            .iter()
            .filter(|(_, a)| now.saturating_sub(a.since) >= timeout)
            .map(|(h, _)| *h)
            .collect();
        for a in due {
            self.retry_request(a);
        }
        // Headers or parents may have arrived: retry completions.
        let ready: Vec<AnchorHash> = self
            .awaiting
            .keys()
            .filter(|a| self.batch_ids.contains_key(*a))
            .copied()
            .collect();
        for a in ready {
            self.complete_from(a, hdr);
        }
        self.asked_anchor
            .retain(|_, t| now.saturating_sub(*t) < timeout);
        let mut dropped = 0;
        for v in self.orphans.values_mut() {
            let before = v.len();
            v.retain(|(_, _, t)| now.saturating_sub(*t) < 600);
            dropped += before - v.len();
        }
        self.orphans.retain(|_, v| !v.is_empty());
        self.orphan_count -= dropped;
        // Parents of orphans not on request any more: ask again, from whoever sent the orphan.
        let lost: Vec<(AnchorHash, Option<PeerId>)> = self
            .orphans
            .iter()
            .filter(|(p, _)| !self.asked_anchor.contains_key(*p))
            .map(|(p, v)| (*p, v.first().and_then(|(s, _, _)| *s)))
            .collect();
        for (p, from) in lost {
            self.ask_anchor(p, from);
        }
        self.evict_loose();
        self.drive_sync();
        self.retry_btc_requests();
        if let Err(e) = self.maybe_checkpoint(hdr) {
            error!("NP_RELAY: checkpoint failed: {e}");
        }
        if self.rebatch_due || now.saturating_sub(self.last_snapshot_at) >= self.p.backstop_secs {
            self.publish_snapshot(hdr, false);
        }
        if now.saturating_sub(self.last_tip_announce) >= self.p.tip_announce_secs {
            self.last_tip_announce = now;
            let m = self.tip_message();
            self.out.push(Out::Broadcast {
                msg: m,
                except: None,
            });
        }
        self.take_out()
    }

    // ---------------------------------------------------------------------------------------
    // Network shares
    // ---------------------------------------------------------------------------------------

    fn next_includer(&self) -> Includer {
        let best = self.chain.best();
        let b = self.chain.get(&best).expect("best").btc_height;
        Includer::Next {
            parent: best,
            btc_height: b.max(self.btc_tip),
        }
    }

    fn on_net_share(&mut self, src: Option<PeerId>, s: NetShare, hdr: &dyn HeaderLookup) {
        let id = s.id();
        let known = self.shares.contains_key(&id);
        if self.wanted.contains_key(&id) {
            self.store_body(src, s.clone(), hdr);
        }
        if known || self.loose.contains_key(&id) {
            return;
        }
        if s.header.time as u64 > self.now + self.p.future_time_secs {
            self.stats.shares_stale += 1;
            return;
        }
        let inc = self.next_includer();
        match self.check_share(&s, inc, hdr) {
            Ok((c, sa)) => self.accept_loose(s, c.job_height, Some(sa), src),
            Err(Reject::Wait(w)) => {
                // Not held here yet; it reaches this node again inside a batch if it matters.
                if let WaitOn::Header(h) = w {
                    self.needed_headers.insert(h);
                }
                self.stats.shares_stale += 1;
            }
            Err(Reject::Stale(e)) => {
                debug!(share = %hex::encode(id), "NP_RELAY: network share not includable: {e}");
                self.stats.shares_stale += 1;
            }
            Err(Reject::Invalid(e)) => {
                self.stats.shares_invalid += 1;
                self.penalize(src, penalty::INVALID_SHARE, format!("invalid share: {e}"));
            }
        }
    }

    fn accept_loose(
        &mut self,
        s: NetShare,
        job_height: u32,
        checked: Option<AnchorHash>,
        src: Option<PeerId>,
    ) {
        let id = s.id();
        let best = self.chain.best();
        self.shares.entry(id).or_insert_with(|| Arc::new(s.clone()));
        self.loose.insert(
            id,
            Loose {
                job_height,
                checked: checked.map(|a| (a, best)),
            },
        );
        self.stats.shares_accepted += 1;
        self.out.push(Out::Broadcast {
            msg: Message::Share(s),
            except: src,
        });
    }

    fn evict_loose(&mut self) {
        let b = self.btc_tip;
        self.loose
            .retain(|_, l| l.job_height.saturating_add(SHARE_HEIGHT_WINDOW) >= b);
        if self.loose.len() > self.p.max_loose {
            let mut v: Vec<(u32, ShareId)> =
                self.loose.iter().map(|(i, l)| (l.job_height, *i)).collect();
            v.sort();
            for (_, id) in v.iter().take(self.loose.len() - self.p.max_loose) {
                self.loose.remove(id);
            }
        }
    }

    /// Rules 1 to 6 for `s` as `inc` would include it. Returns the credit and the snapshot anchor.
    ///
    /// `T_net` is the tier the share's own job required: its `parent_anchor`'s retarget state at
    /// the job's Bitcoin height. It does not depend on who includes the share, so a share earns
    /// the same credit on every fork that can include it.
    fn check_share(
        &mut self,
        s: &NetShare,
        inc: Includer,
        hdr: &dyn HeaderLookup,
    ) -> Result<(Credit, AnchorHash), Reject> {
        let id = s.id();
        let prev = s.prev_hash();
        let f = self
            .facts(hdr, &prev)
            .ok_or(Reject::Wait(WaitOn::Header(prev)))?;
        let h = f
            .height
            .checked_add(1)
            .ok_or_else(|| Reject::Invalid("height".into()))?;
        let parent = s.tag.parent_anchor;
        if self.chain.get(&parent).is_none() {
            return Err(Reject::Wait(WaitOn::Anchor(parent)));
        }
        let t_net = self
            .required_tier(&parent, f.height)
            .ok_or_else(|| Reject::Invalid("tier".into()))?;
        let (inc_btc, sa, view) = match inc {
            Includer::Anchor(a) => {
                let ai = self
                    .chain
                    .get(&a)
                    .ok_or_else(|| Reject::Stale("unknown includer".into()))?;
                let btc = ai.btc_height;
                let sa = self
                    .chain
                    .check_share_ancestry(&a, &parent, h, &id)
                    .map_err(|e| match e {
                        AncestryError::UnknownParent => Reject::Wait(WaitOn::Anchor(parent)),
                        e => Reject::Invalid(format!("rule 6: {e}")),
                    })?;
                (btc, sa, a)
            }
            Includer::Next {
                parent: p,
                btc_height: b,
            } => {
                let c = cut(h).ok_or_else(|| Reject::Stale("no snapshot below the cut".into()))?;
                if b < c {
                    return Err(Reject::Stale("job height ahead of the next anchor".into()));
                }
                let sa = self
                    .chain
                    .last_below(&p, c)
                    .ok_or_else(|| Reject::Stale("no snapshot below the cut".into()))?;
                if !self.chain.is_ancestor(&sa, &parent)
                    || self.chain.snapshot_anchor(&parent, h) != Some(sa)
                {
                    return Err(Reject::Stale("parent does not share the snapshot".into()));
                }
                if self.chain.included_on_ancestry(&p, &id) {
                    return Err(Reject::Stale("already included".into()));
                }
                (b, sa, p)
            }
        };
        if !self.chain.is_ancestor(&self.base.anchor, &sa) {
            return Err(Reject::Wait(WaitOn::Checkpoint));
        }
        let table = self.table_at(sa, h, &view, &prev).map_err(|e| match e {
            TableErr::Wait(x) => Reject::Wait(WaitOn::Header(x)),
            TableErr::Unavailable => Reject::Wait(WaitOn::Checkpoint),
            TableErr::Arith(e) => Reject::Invalid(format!("table: {e}")),
        })?;
        let tx = s
            .coinbase_tx()
            .map_err(|e| Reject::Invalid(format!("coinbase: {e}")))?;
        let ctx = ShareContext {
            t_net,
            tier_base: self.p.tier_base,
            anchor_btc_height: inc_btc,
            prev_block_height: f.height,
            expected_bits: f.next_bits,
            median_time_past: f.median_time_past,
            // Validity cannot depend on a local clock; the future bound is relay policy.
            max_time: u32::MAX,
            table: &table,
            halving: self.p.halving,
        };
        let sub = ShareSubmission {
            header: &s.header,
            coinbase: &tx,
            merkle_branch: &s.merkle_branch,
            tag: &s.tag,
        };
        let v = verify_share(&sub, &ctx).map_err(|e| match (&inc, e) {
            // For a loose share these depend on this node's view; never a penalty.
            (
                Includer::Next { .. },
                e @ (ShareError::TooOld { .. }
                | ShareError::Era
                | ShareError::OutputsMismatch
                | ShareError::Payout(_)),
            ) => Reject::Stale(e.to_string()),
            (_, e) => Reject::Invalid(e.to_string()),
        })?;
        let face = i128::try_from(v.face).map_err(|_| Reject::Invalid("face".into()))?;
        Ok((
            Credit {
                job_height: v.job_height,
                script: s.tag.payee_script.clone(),
                face,
                credited_tier: v.credited_tier,
            },
            sa,
        ))
    }

    /// Header facts: the caller's lookup (the local Bitcoin node), then the archive.
    fn facts(&self, hdr: &dyn HeaderLookup, h: &[u8; 32]) -> Option<HeaderFacts> {
        hdr.facts(h).or_else(|| self.archive.facts(h))
    }

    /// The snapshot table at `sa` for job height `h`: the checkpoint's base table (the genesis
    /// table when none), the credits of every batch on `sa`'s ancestry above it folded by job
    /// height (`canonical_payout::table_for_from`), and the retirements of the pool blocks on
    /// `prev`'s Bitcoin ancestry below `h` as `inc` judges them. `sa` descends from the
    /// checkpoint anchor.
    fn table_at(
        &mut self,
        sa: AnchorHash,
        h: u32,
        inc: &AnchorHash,
        prev: &[u8; 32],
    ) -> Result<Arc<Table>, TableErr> {
        if h < self.base.fold_height || !self.chain.is_ancestor(&self.base.anchor, &sa) {
            return Err(TableErr::Unavailable);
        }
        let view = self.retirements_for(inc, prev, h)?;
        let key = (sa, h, view.1);
        if let Some(t) = self.table_cache.get(&key) {
            return Ok(t.clone());
        }
        let cum = self.cum_credits(sa);
        let t = Arc::new(
            table_for_from(self.base.base.clone(), h, &cum, &view.0)
                .map_err(|e| TableErr::Arith(e.to_string()))?,
        );
        if self.table_order.len() >= TABLE_CACHE {
            if let Some(old) = self.table_order.pop_front() {
                self.table_cache.remove(&old);
            }
        }
        self.table_order.push_back(key);
        self.table_cache.insert(key, t.clone());
        Ok(t)
    }

    /// The retirements a table at job height `h` subtracts for a share on Bitcoin block `prev`
    /// included by `inc` (or, for a job, the next anchor on `inc`): every node pool block on
    /// `prev`'s Bitcoin ancestry at or above the checkpoint's fold height and below `h`, each
    /// judged by [`Relay::block_retirement`].
    fn retirements_for(
        &mut self,
        inc: &AnchorHash,
        prev: &[u8; 32],
        h: u32,
    ) -> Result<RetireView, TableErr> {
        let key = (*inc, *prev, h);
        if let Some(v) = self.retire_cache.get(&key) {
            return Ok(v.clone());
        }
        let from = self.base.fold_height.max(self.p.genesis.btc_height + 1);
        let blocks = if h <= from {
            Vec::new()
        } else {
            self.archive
                .pool_blocks_on(prev, from, h)
                .map_err(TableErr::Wait)?
        };
        let mut map = BTreeMap::new();
        let mut tag = Sha256::new();
        tag.update(b"GhostNP/retire/v2");
        for b in blocks {
            let r = self.block_retirement(&b, inc)?;
            tag.update(b.height.to_le_bytes());
            tag.update(b.hash());
            match &r {
                Some(r) => {
                    tag.update([1]);
                    tag.update((r.len() as u32).to_le_bytes());
                    for (sc, v) in r {
                        tag.update((sc.len() as u16).to_le_bytes());
                        tag.update(sc);
                        tag.update(v.to_le_bytes());
                    }
                    map.insert(b.height, r.clone());
                }
                None => tag.update([0]),
            }
        }
        let v: RetireView = Arc::new((map, tag.finalize().into()));
        if self.retire_order.len() >= RETIRE_CACHE {
            if let Some(old) = self.retire_order.pop_front() {
                self.retire_cache.remove(&old);
            }
        }
        self.retire_order.push_back(key);
        self.retire_cache.insert(key, v.clone());
        Ok(v)
    }

    /// What pool block `b` retires as seen from includer `inc`, a pure function of the two:
    ///
    /// - no anchor with its `GHPP` prefix on `inc`'s ancestry: what it paid (its miner outputs,
    ///   `canonical_payout::provisional_retirements`);
    /// - one that it matches (the `block_table` root it commits, outputs canonical for some slot
    ///   class): what it paid, which is the same;
    /// - such anchors, none matching: nothing.
    ///
    /// `None` is nothing.
    fn block_retirement(
        &mut self,
        b: &ArchivedBlock,
        inc: &AnchorHash,
    ) -> Result<Option<Vec<Retirement>>, TableErr> {
        let Some((prefix, _)) = b.pool_tag() else {
            return Ok(None);
        };
        let cands: Vec<AnchorHash> = self
            .anchors_with_prefix(&prefix)
            .into_iter()
            .filter(|a| self.chain.is_ancestor(a, inc))
            .collect();
        let halving = self.p.halving;
        let paid = || {
            let (cb, _) = b.coinbase.as_ref().expect("a pool block has its coinbase");
            let outs: Vec<(u64, Script)> = cb
                .output
                .iter()
                .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
                .collect();
            provisional_retirements(b.height, halving, &outs)
        };
        if cands.is_empty() {
            return Ok(paid());
        }
        for a in cands {
            match self.check_block(b, &a) {
                Ok(Some(r)) => return Ok(Some(r)),
                Ok(None) => {}
                Err(TableErr::Unavailable) => {
                    // Decided before a checkpoint folded what it needs, and not carried: it
                    // arrived too late to judge here. Count what it paid.
                    warn!(
                        block = %hex::encode(b.hash()),
                        "NP_RELAY: a pool block below the checkpoint cannot be matched; \
                         counting what it paid"
                    );
                    return Ok(paid());
                }
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// Whether pool block `b` pays `a`'s table: `Some(retirements)` on a match. Cached: it is a
    /// pure function of the block and the anchor.
    fn check_block(
        &mut self,
        b: &ArchivedBlock,
        a: &AnchorHash,
    ) -> Result<Option<Vec<Retirement>>, TableErr> {
        let key = (b.hash(), *a);
        if let Some(r) = self.block_checks.get(&key) {
            return Ok(r.clone());
        }
        let (Some((_, root)), Some((cb, _))) = (b.pool_tag(), b.coinbase.as_ref()) else {
            return Ok(None);
        };
        let r = match self.table_for_job(a, b.height, &b.prev()) {
            Ok(t) if table_root(&t) == root => {
                settle_outputs(cb, &t, b.height, self.p.halving).map(|(_, r)| r)
            }
            Ok(_) | Err(TableErr::Arith(_)) => None,
            Err(e) => return Err(e),
        };
        self.block_checks.insert(key, r.clone());
        Ok(r)
    }

    /// Credits of every batch from the checkpoint anchor (exclusive; its ancestry's credits above
    /// the fold are the checkpoint's residual) to `a` inclusive, by job height and payee.
    fn cum_credits(&mut self, a: AnchorHash) -> Arc<CreditMap> {
        let mut stack = Vec::new();
        let mut cur = a;
        let mut base = Arc::new(self.base.residual.clone());
        loop {
            if let Some(m) = self.cum_cache.get(&cur) {
                base = m.clone();
                break;
            }
            if cur == self.base.anchor || cur == self.p.genesis.hash {
                break;
            }
            stack.push(cur);
            match self.chain.get(&cur).and_then(|i| i.parent) {
                Some(p) => cur = p,
                None => break,
            }
        }
        while let Some(x) = stack.pop() {
            let mut m = (*base).clone();
            if let Some(cs) = self.credits.get(&x) {
                for c in cs.iter() {
                    let e = m
                        .entry(c.job_height)
                        .or_default()
                        .entry(c.script.clone())
                        .or_insert(0);
                    *e = e.saturating_add(c.face);
                }
            } else {
                error!(anchor = %hex::encode(x), "NP_RELAY: snapshot ancestry has no credits");
            }
            base = Arc::new(m);
            if self.cum_order.len() >= CUM_CACHE {
                if let Some(old) = self.cum_order.pop_front() {
                    self.cum_cache.remove(&old);
                }
            }
            self.cum_order.push_back(x);
            self.cum_cache.insert(x, base.clone());
        }
        base
    }

    // ---------------------------------------------------------------------------------------
    // Anchors
    // ---------------------------------------------------------------------------------------

    /// Checks that need only the anchor message: the coinbase is bound to the header, the tag to
    /// the coinbase, and the parent tag and BIP34 height agree with what the message claims. A
    /// failure here may be a substituted body, so it penalizes the sender without condemning the
    /// anchor's hash.
    fn anchor_self_checks(&self, m: &AnchorMsg) -> Result<(), String> {
        let s = &m.share;
        share_integrity(s)?;
        let tx = s.coinbase_tx().map_err(|e| e.to_string())?;
        let sig = tx.input[0].script_sig.as_bytes();
        let bip34 = bitcoin::script::Builder::new()
            .push_int(m.btc_height as i64 + 1)
            .into_bytes();
        if !sig.starts_with(&bip34) {
            return Err("BIP34 height is not btc_height + 1".into());
        }
        Ok(())
    }

    fn on_anchor(&mut self, src: Option<PeerId>, msg: AnchorMsg, hdr: &dyn HeaderLookup) {
        let mut queue = vec![(src, msg)];
        while let Some((src, msg)) = queue.pop() {
            let h = msg.share.id();
            if h == self.p.genesis.hash
                || self.anchors.contains_key(&h)
                || self.invalid.contains(&h)
            {
                continue;
            }
            if let Err(e) = self.anchor_self_checks(&msg) {
                self.penalize(src, penalty::INVALID_ANCHOR, format!("anchor: {e}"));
                continue;
            }
            let parent = msg.share.tag.parent_anchor;
            if self.invalid.contains(&parent) {
                self.invalid.insert(h);
                self.penalize(
                    src,
                    penalty::INVALID_DESCENDANT,
                    "anchor on an invalid anchor".into(),
                );
                continue;
            }
            if self.chain.get(&parent).is_none() {
                self.add_orphan(src, msg, parent);
                continue;
            }
            match self.chain.insert(AnchorHeader {
                hash: h,
                parent,
                btc_height: msg.btc_height,
            }) {
                Ok(()) => {}
                Err(AnchorError::Duplicate) => continue,
                Err(e) => {
                    // The hash commits the header, the header the coinbase, the coinbase the
                    // tag: these are properties of the anchor itself.
                    self.invalid.insert(h);
                    self.stats.anchors_invalid += 1;
                    self.penalize(src, penalty::INVALID_ANCHOR, format!("anchor: {e}"));
                    continue;
                }
            }
            self.kids.entry(parent).or_default().push(h);
            self.anchors.insert(
                h,
                AnchorEntry {
                    share: Arc::new(msg.share),
                    btc_height: msg.btc_height,
                    source: src,
                    received_at: self.now as i64,
                },
            );
            self.asked_anchor.remove(&h);
            self.awaiting.insert(
                h,
                Awaiting {
                    since: self.now,
                    asked: src.into_iter().collect(),
                },
            );
            if let Some((bsrc, ids)) = self.early_batches.remove(&h) {
                self.on_batch(bsrc, h, ids, hdr);
            }
            if let Some(waiters) = self.waiting_on_anchor.remove(&h) {
                for w in waiters {
                    self.complete_from(w, hdr);
                }
            }
            if let Some(kids) = self.orphans.remove(&h) {
                self.orphan_count -= kids.len();
                queue.extend(kids.into_iter().map(|(s, m, _)| (s, m)));
            }
        }
    }

    fn add_orphan(&mut self, src: Option<PeerId>, msg: AnchorMsg, parent: AnchorHash) {
        let h = msg.share.id();
        let list = self.orphans.entry(parent).or_default();
        if list.iter().any(|(_, m, _)| m.share.id() == h) {
            return;
        }
        if self.orphan_count >= self.p.max_orphans {
            // Deeper than this is initial sync (W2.13), not relay.
            debug!(
                "NP_RELAY: orphan pool full; anchor {} dropped",
                hex::encode(h)
            );
            return;
        }
        list.push((src, msg, self.now));
        self.orphan_count += 1;
        self.ask_anchor(parent, src);
    }

    fn ask_anchor(&mut self, a: AnchorHash, from: Option<PeerId>) {
        if self.asked_anchor.contains_key(&a) || self.invalid.contains(&a) {
            return;
        }
        let peer = from.or_else(|| self.peers.first().copied());
        if let Some(p) = peer {
            self.asked_anchor.insert(a, self.now);
            self.out.push(Out::Send(p, Message::GetAnchor(a)));
        }
    }

    fn on_tip(&mut self, peer: PeerId, hash: AnchorHash, work: U256) {
        self.tip_peers.insert(peer, (hash, work));
        if self.invalid.contains(&hash) || hash == self.p.genesis.hash {
            return;
        }
        if self.anchors.contains_key(&hash) {
            if !self.batch_ids.contains_key(&hash) {
                self.out.push(Out::Send(peer, Message::GetBatch(hash)));
            }
            return;
        }
        let ours = self.chain.get(&self.chain.best()).expect("best").work;
        if work > ours {
            self.request_headers(peer);
        } else if work == ours {
            self.ask_anchor(hash, Some(peer));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Batches
    // ---------------------------------------------------------------------------------------

    fn on_batch(
        &mut self,
        src: Option<PeerId>,
        a: AnchorHash,
        ids: Vec<ShareId>,
        hdr: &dyn HeaderLookup,
    ) {
        if self.credits.contains_key(&a)
            || self.invalid.contains(&a)
            || self.batch_ids.contains_key(&a)
        {
            return;
        }
        let Some(entry) = self.anchors.get(&a) else {
            if self.early_batches.len() < EARLY_BATCHES {
                self.early_batches.insert(a, (src, ids));
            }
            return;
        };
        if batch_root(&ids) != entry.share.tag.batch_root {
            self.penalize(
                src,
                penalty::BAD_BATCH_ROOT,
                "batch does not match its root".into(),
            );
            return;
        }
        let mut uniq = HashSet::with_capacity(ids.len());
        if !ids.iter().all(|i| uniq.insert(*i)) {
            // The list is bound to the anchor by its root: the anchor itself is invalid.
            self.mark_invalid(a, "a share listed twice in its batch");
            return;
        }
        let missing: Vec<ShareId> = ids
            .iter()
            .filter(|i| !self.shares.contains_key(*i))
            .copied()
            .collect();
        for m in &missing {
            self.wanted.entry(*m).or_default().insert(a);
        }
        self.batch_ids.insert(a, Arc::new(ids));
        self.batch_source.insert(a, src);
        if !missing.is_empty() {
            if let Some(p) = src {
                for chunk in missing.chunks(MAX_SERVED_SHARES) {
                    self.out
                        .push(Out::Send(p, Message::GetShares(chunk.to_vec())));
                }
            }
            if let Some(aw) = self.awaiting.get_mut(&a) {
                aw.since = self.now;
            }
            return;
        }
        self.complete_from(a, hdr);
    }

    fn store_body(&mut self, src: Option<PeerId>, s: NetShare, hdr: &dyn HeaderLookup) {
        let id = s.id();
        if !self.wanted.contains_key(&id) {
            return;
        }
        // The id commits only the header: a body whose coinbase or tag was substituted would
        // condemn an honest anchor. Refuse it here, from its sender, and keep waiting.
        if let Err(e) = share_integrity(&s) {
            self.penalize(src, penalty::BAD_BODY, format!("share body: {e}"));
            return;
        }
        let Some(waiters) = self.wanted.remove(&id) else {
            return;
        };
        self.shares.entry(id).or_insert_with(|| Arc::new(s));
        for a in waiters {
            self.complete_from(a, hdr);
        }
    }

    /// Try to complete `a`, then any descendants it unblocks, then move the best tip.
    fn complete_from(&mut self, a: AnchorHash, hdr: &dyn HeaderLookup) {
        let mut work = vec![a];
        while let Some(x) = work.pop() {
            if self.try_complete(x, hdr) {
                if let Some(k) = self.kids.get(&x) {
                    work.extend(k.iter().copied());
                }
            }
        }
        self.update_best(hdr);
    }

    /// Check and attach `a`'s batch if everything it needs is held. Returns whether it completed.
    fn try_complete(&mut self, a: AnchorHash, hdr: &dyn HeaderLookup) -> bool {
        if self.credits.contains_key(&a) || self.invalid.contains(&a) {
            return false;
        }
        let Some(ids) = self.batch_ids.get(&a).cloned() else {
            return false;
        };
        let info = self.chain.get(&a).expect("held").clone();
        let parent = info.parent.expect("not genesis");
        if !self.chain.get(&parent).is_some_and(|p| p.seen) {
            return false;
        }
        if !self.chain.is_ancestor(&self.base.anchor, &parent) {
            // A fork from below the checkpoint: its shares reach state folded away here.
            debug!(anchor = %hex::encode(a), "NP_RELAY: anchor forks below the checkpoint; not judged");
            return false;
        }
        if ids.iter().any(|i| !self.shares.contains_key(i)) {
            return false;
        }
        let entry = &self.anchors[&a];
        let (own, btc, src) = (entry.share.clone(), entry.btc_height, entry.source);
        // The anchor's own share is a share like any other, included by the anchor itself.
        let own_credit = match self.check_share(&own, Includer::Anchor(a), hdr) {
            Ok((c, _)) => c,
            Err(Reject::Wait(w)) => {
                self.wait_on(w, Some(a), src);
                return false;
            }
            Err(Reject::Stale(e)) | Err(Reject::Invalid(e)) => {
                self.mark_invalid(a, &format!("its own share: {e}"));
                return false;
            }
        };
        if own_credit.job_height != btc + 1 {
            self.mark_invalid(a, "btc_height is not its header's height");
            return false;
        }
        let mut cs = Vec::with_capacity(ids.len());
        for id in ids.iter() {
            let s = self.shares[id].clone();
            match self.check_share(&s, Includer::Anchor(a), hdr) {
                Ok((c, _)) => cs.push(c),
                Err(Reject::Wait(w)) => {
                    let from = self.batch_source.get(&a).copied().flatten().or(src);
                    self.wait_on(w, Some(a), from);
                    return false;
                }
                Err(Reject::Stale(e)) | Err(Reject::Invalid(e)) => {
                    self.mark_invalid(a, &format!("share {}: {e}", hex::encode(id)));
                    return false;
                }
            }
        }
        if let Err(e) = self.persist(a, &info, &own, own_credit.job_height, &ids, &cs) {
            error!(anchor = %hex::encode(a), "NP_RELAY: storing a valid anchor failed: {e}");
            return false;
        }
        if let Err(e) = self.chain.attach_batch(&a, &ids) {
            self.mark_invalid(a, &format!("batch: {e}"));
            return false;
        }
        let job_height = own_credit.job_height;
        self.credits.insert(a, Arc::new(cs));
        self.awaiting.remove(&a);
        self.sync.inflight.remove(&a);
        self.index_prefix(a);
        self.shares.entry(a).or_insert_with(|| own.clone());
        self.loose.insert(
            a,
            Loose {
                job_height,
                checked: None,
            },
        );
        self.stats.anchors_valid += 1;
        debug!(anchor = %hex::encode(a), shares = ids.len(), "NP_RELAY: anchor complete");
        if btc + self.p.recency_blocks >= self.btc_tip {
            let bsrc = self.batch_source.get(&a).copied().flatten();
            self.out.push(Out::Broadcast {
                msg: Message::Anchor(AnchorMsg {
                    btc_height: btc,
                    share: (*own).clone(),
                }),
                except: src,
            });
            self.out.push(Out::Broadcast {
                msg: Message::Batch {
                    anchor: a,
                    ids: ids.to_vec(),
                },
                except: bsrc.or(src),
            });
        }
        true
    }

    fn persist(
        &self,
        a: AnchorHash,
        info: &ghost_common::anchor_chain::AnchorInfo,
        own: &NetShare,
        own_height: u32,
        ids: &[ShareId],
        cs: &[Credit],
    ) -> GhostResult<()> {
        let now = self.now as i64;
        let anchor = NpAnchorRecord {
            hash: a,
            parent: info.parent,
            height: info.height,
            t_net: info.t_net,
            btc_height: info.btc_height,
            cum_work: info.work,
            batch_root: own.tag.batch_root,
            received_at: self.anchors[&a].received_at,
        };
        let members: Vec<NpBatchShare> = ids
            .iter()
            .zip(cs)
            .map(|(id, c)| NpBatchShare {
                share: self.shares[id].to_record(c.job_height),
                credited_tier: c.credited_tier,
                face: c.face as u128,
            })
            .collect();
        // One transaction, one commit: the share, the header and the batch (see
        // `np_insert_anchor_with_batch`).
        self.db
            .np_insert_anchor_with_batch(&own.to_record(own_height), &anchor, &members, now)?;
        Ok(())
    }

    fn wait_on(&mut self, w: WaitOn, a: Option<AnchorHash>, from: Option<PeerId>) {
        match w {
            WaitOn::Header(h) => {
                self.needed_headers.insert(h);
            }
            WaitOn::Anchor(p) => {
                if let Some(a) = a {
                    self.waiting_on_anchor.entry(p).or_default().insert(a);
                }
                self.ask_anchor(p, from);
            }
            WaitOn::Checkpoint => {}
        }
    }

    /// `a` broke a rule: never seen, never relayed; its descendants with it. Whoever sent the
    /// anchor and its batch is penalized.
    fn mark_invalid(&mut self, a: AnchorHash, why: &str) {
        warn!(anchor = %hex::encode(a), "NP_RELAY: invalid anchor: {why}");
        let mut stack = vec![a];
        while let Some(x) = stack.pop() {
            if !self.invalid.insert(x) {
                continue;
            }
            self.stats.anchors_invalid += 1;
            self.awaiting.remove(&x);
            self.sync.inflight.remove(&x);
            if let Some(ids) = self.batch_ids.remove(&x) {
                for i in ids.iter() {
                    if let Some(w) = self.wanted.get_mut(i) {
                        w.remove(&x);
                        if w.is_empty() {
                            self.wanted.remove(i);
                        }
                    }
                }
            }
            let srcs = [
                self.anchors.get(&x).and_then(|e| e.source),
                self.batch_source.get(&x).copied().flatten(),
            ];
            let mut seen = HashSet::new();
            for p in srcs.into_iter().flatten() {
                if seen.insert(p) {
                    let score = if x == a {
                        penalty::INVALID_ANCHOR
                    } else {
                        penalty::INVALID_DESCENDANT
                    };
                    self.penalize(Some(p), score, format!("invalid anchor: {why}"));
                }
            }
            if let Some(k) = self.kids.get(&x) {
                stack.extend(k.iter().copied());
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // Best tip, ledger and jobs
    // ---------------------------------------------------------------------------------------

    fn update_best(&mut self, hdr: &dyn HeaderLookup) {
        let best = self.chain.best();
        if best == self.applied_tip {
            return;
        }
        match self.move_ledger(best) {
            Ok((undone, applied)) => {
                if !undone.is_empty() {
                    self.stats.reorgs += 1;
                    info!(
                        undone = undone.len(),
                        applied = applied.len(),
                        tip = %hex::encode(best),
                        "NP_RELAY: share chain reorg"
                    );
                }
                // The losing side's shares become loose again, to be re-included.
                for x in &undone {
                    let cs = self.credits.get(x).cloned();
                    if let (Some(ids), Some(cs)) = (self.batch_ids.get(x).cloned(), cs) {
                        for (id, c) in ids.iter().zip(cs.iter()) {
                            self.loose.entry(*id).or_insert(Loose {
                                job_height: c.job_height,
                                checked: None,
                            });
                        }
                    }
                }
                for x in &applied {
                    if let Some(ids) = self.batch_ids.get(x).cloned() {
                        for id in ids.iter() {
                            self.loose.remove(id);
                        }
                    }
                }
            }
            Err(e) => error!("NP_RELAY: ledger move to {} failed: {e}", hex::encode(best)),
        }
        self.applied_tip = best;
        self.publish_snapshot(hdr, true);
        let m = self.tip_message();
        self.out.push(Out::Broadcast {
            msg: m,
            except: None,
        });
    }

    /// Move the stored ledger from the applied chain to `tip`'s. Returns the anchors undone
    /// (newest first) and applied (oldest first). The fork point is at or above the checkpoint
    /// anchor: anchors forking below it never complete.
    fn move_ledger(&mut self, tip: AnchorHash) -> GhostResult<(Vec<AnchorHash>, Vec<AnchorHash>)> {
        let mut fresh = Vec::new();
        let mut cur = tip;
        while cur != self.p.genesis.hash && !self.on_path(&cur) {
            fresh.push(cur);
            cur = self
                .chain
                .get(&cur)
                .and_then(|i| i.parent)
                .expect("seen ancestry");
        }
        let keep = self.chain.get(&cur).expect("held").height as usize;
        if keep < self.base.height as usize {
            return Err(GhostError::Database(format!(
                "a reorg to {} forks below the checkpoint at height {}",
                hex::encode(tip),
                self.base.height
            )));
        }
        let mut parked = Vec::new();
        let mut undone = Vec::new();
        while self.path.len() > keep {
            let a = self.path.pop().expect("len > keep");
            for (key, _, _) in credit_events(&a, &self.credits[&a])?.into_iter().rev() {
                self.undo_credit_event(&key, &mut parked)?;
            }
            undone.push(a);
        }
        fresh.reverse();
        for a in &fresh {
            self.apply_credits_of(a)?;
            self.path.push(*a);
        }
        self.unpark(parked)?;
        Ok((undone, fresh))
    }

    /// Whether `a` is on the applied best chain.
    fn on_path(&self, a: &AnchorHash) -> bool {
        self.chain
            .get(a)
            .and_then(|i| i.height.checked_sub(1))
            .and_then(|i| self.path.get(i as usize))
            == Some(a)
    }

    fn apply_credits_of(&self, a: &AnchorHash) -> GhostResult<()> {
        for (key, h, deltas) in credit_events(a, &self.credits[a])? {
            self.db
                .np_apply_credits(&key, h, &deltas, self.now as i64)?;
        }
        Ok(())
    }

    /// Undo credit event `key`, which must be the newest credit event. Block events above it are
    /// undone first and parked for re-application.
    fn undo_credit_event(
        &self,
        key: &[u8; 32],
        parked: &mut Vec<([u8; 32], u32, Vec<Retirement>)>,
    ) -> GhostResult<()> {
        loop {
            match self.db.np_last_ledger_event()? {
                Some(ev) if ev.kind == NpLedgerEventKind::Credit && ev.key == *key => {
                    return self.db.np_undo_credits(key);
                }
                Some(ev) if ev.kind == NpLedgerEventKind::Block => {
                    self.park_block(&ev.key, ev.height, parked)?;
                }
                other => {
                    return Err(GhostError::Database(format!(
                        "np ledger: expected credit event {} on top, found {other:?}",
                        hex::encode(key)
                    )))
                }
            }
        }
    }

    fn park_block(
        &self,
        hash: &[u8; 32],
        height: u32,
        parked: &mut Vec<([u8; 32], u32, Vec<Retirement>)>,
    ) -> GhostResult<()> {
        let r = self.db.np_block_retirements(hash)?.unwrap_or_default();
        self.db.np_undo_block(hash)?;
        parked.push((*hash, height, r));
        Ok(())
    }

    fn unpark(&self, parked: Vec<([u8; 32], u32, Vec<Retirement>)>) -> GhostResult<()> {
        for (hash, height, r) in parked.into_iter().rev() {
            self.db.np_apply_block(&hash, height, &r, self.now as i64)?;
        }
        Ok(())
    }

    /// The batch the next local anchor would lock in: loose shares still includable by an anchor
    /// on the best tip a couple of Bitcoin blocks from now, oldest job height first.
    fn snapshot_batch(&mut self, hdr: &dyn HeaderLookup) -> Vec<ShareId> {
        let best = self.chain.best();
        let b = self
            .chain
            .get(&best)
            .expect("best")
            .btc_height
            .max(self.btc_tip);
        let halving = self.p.halving;
        let era = halving.era(b + 1);
        let mut cands: Vec<(u32, ShareId)> = self
            .loose
            .iter()
            .filter(|(_, l)| l.job_height + SHARE_HEIGHT_WINDOW >= b + BATCH_MARGIN)
            .filter(|(_, l)| halving.era(l.job_height) == era)
            .map(|(i, l)| (l.job_height, *i))
            .collect();
        cands.sort_unstable();
        let mut out = Vec::new();
        let mut drop = Vec::new();
        for (h, id) in cands {
            if out.len() >= MAX_BATCH_SHARES {
                break;
            }
            let sa = cut(h).and_then(|c| self.chain.last_below(&best, c));
            let quick = sa.is_some()
                && self.loose[&id].checked == sa.map(|a| (a, best))
                && !self.chain.included_on_ancestry(&best, &id);
            if quick {
                out.push(id);
                continue;
            }
            let Some(s) = self.shares.get(&id).cloned() else {
                drop.push(id);
                continue;
            };
            let inc = Includer::Next {
                parent: best,
                btc_height: b,
            };
            match self.check_share(&s, inc, hdr) {
                Ok((_, sa)) => {
                    if let Some(l) = self.loose.get_mut(&id) {
                        l.checked = Some((sa, best));
                    }
                    out.push(id);
                }
                Err(Reject::Wait(_)) => {}
                Err(_) => drop.push(id),
            }
        }
        for d in drop {
            self.loose.remove(&d);
        }
        out
    }

    /// Re-batch and publish if `(best, batch_root)` changed (always on `force`).
    fn publish_snapshot(&mut self, hdr: &dyn HeaderLookup, force: bool) {
        self.last_snapshot_at = self.now;
        self.rebatch_due = false;
        let ids = self.snapshot_batch(hdr);
        let job = JobAnchor {
            parent_anchor: self.chain.best(),
            batch_root: batch_root(&ids),
        };
        if self.last_publish == Some(job) && !force {
            return;
        }
        if self.last_publish != Some(job) {
            if self.published.len() >= PUBLISHED_KEPT {
                self.published.pop_front();
            }
            self.published.push_back(Published {
                parent: job.parent_anchor,
                root: job.batch_root,
                ids: Arc::new(ids),
            });
        }
        self.last_publish = Some(job);
        self.out.push(Out::Publish(job));
    }

    // ---------------------------------------------------------------------------------------
    // Serving and retries
    // ---------------------------------------------------------------------------------------

    fn serve_anchor(&mut self, peer: PeerId, h: &AnchorHash) {
        let ids = match self.batch_ids.get(h) {
            Some(ids) if self.credits.contains_key(h) => Some(ids.to_vec()),
            _ if *h != self.p.genesis.hash && self.is_complete(h) => self.stored_batch_ids(h),
            _ => None,
        };
        match (self.anchors.get(h), ids) {
            (Some(e), Some(ids)) => {
                let m = Message::Anchor(AnchorMsg {
                    btc_height: e.btc_height,
                    share: (*e.share).clone(),
                });
                let b = Message::Batch { anchor: *h, ids };
                self.out.push(Out::Send(peer, m));
                self.out.push(Out::Send(peer, b));
            }
            _ => self
                .out
                .push(Out::Send(peer, Message::NotFound(NotFoundKind::Anchor, *h))),
        }
    }

    fn serve_batch(&mut self, peer: PeerId, a: &AnchorHash) {
        let ids = match self.batch_ids.get(a) {
            Some(ids) if self.credits.contains_key(a) => Some(ids.to_vec()),
            // Folded into the checkpoint, or below it: served from the store while it holds it.
            _ if self.is_complete(a) => self.stored_batch_ids(a),
            _ => None,
        };
        match ids {
            Some(ids) => self
                .out
                .push(Out::Send(peer, Message::Batch { anchor: *a, ids })),
            None => self
                .out
                .push(Out::Send(peer, Message::NotFound(NotFoundKind::Batch, *a))),
        }
    }

    fn stored_batch_ids(&self, a: &AnchorHash) -> Option<Vec<ShareId>> {
        match self.db.np_get_batch(a) {
            Ok(b) => b.map(|b| b.shares.iter().map(|m| m.share.share_id).collect()),
            Err(e) => {
                error!(anchor = %hex::encode(a), "NP_RELAY: reading a stored batch failed: {e}");
                None
            }
        }
    }

    fn serve_shares(&mut self, peer: PeerId, ids: &[ShareId]) {
        // Bounded per request: a peer that needs more asks again (`retry_request` does).
        let held: Vec<NetShare> = ids
            .iter()
            .filter_map(|i| match self.shares.get(i) {
                Some(s) => Some((**s).clone()),
                None => self
                    .db
                    .np_get_share(i)
                    .ok()
                    .flatten()
                    .and_then(|r| NetShare::from_record(&r).ok()),
            })
            .take(MAX_SERVED_SHARES)
            .collect();
        for chunk in held.chunks(MAX_SHARES_PER_MESSAGE) {
            self.out
                .push(Out::Send(peer, Message::Shares(chunk.to_vec())));
        }
    }

    fn retry_request(&mut self, a: AnchorHash) {
        let Some(aw) = self.awaiting.get(&a) else {
            return;
        };
        let asked = aw.asked.clone();
        let mut peer = self.peers.iter().find(|p| !asked.contains(p)).copied();
        if peer.is_none() {
            // Everyone was asked once: start the round again.
            peer = self.peers.first().copied();
            if let Some(aw) = self.awaiting.get_mut(&a) {
                aw.asked.clear();
            }
        }
        let Some(p) = peer else {
            return;
        };
        let msgs = match self.batch_ids.get(&a) {
            None => vec![Message::GetBatch(a)],
            Some(ids) => {
                let missing: Vec<ShareId> = ids
                    .iter()
                    .filter(|i| !self.shares.contains_key(*i))
                    .copied()
                    .collect();
                if missing.is_empty() {
                    return;
                }
                missing
                    .chunks(MAX_SERVED_SHARES)
                    .map(|c| Message::GetShares(c.to_vec()))
                    .collect()
            }
        };
        if let Some(aw) = self.awaiting.get_mut(&a) {
            aw.asked.push(p);
            aw.since = self.now;
        }
        self.out.extend(msgs.into_iter().map(|m| Out::Send(p, m)));
    }

    fn penalize(&mut self, peer: Option<PeerId>, score: u32, reason: String) {
        match peer {
            Some(p) => {
                warn!(peer = p, score, "NP_RELAY: {reason}");
                self.out.push(Out::Penalize {
                    peer: p,
                    score,
                    reason,
                });
            }
            None => warn!("NP_RELAY: local {reason}"),
        }
    }
}
