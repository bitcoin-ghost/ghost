//! The network shard's runtime on this node (`SHARE_SHARD.md` §4.3/§4.4, build Stage 3).
//!
//! This owns the impure edges of the shard the way `sbc_shadow.rs` does for the batch chain: the
//! deterministic core lives in `ghost_common::share_shard` and is already pinned by golden
//! vectors; persistence and its one-transaction fold live in `ghost_storage::shard_store`. What
//! remains here is the epoch lifecycle — which epoch to fold, when it has closed, when its
//! evidence expires — and the in-memory table those decisions read.
//!
//! ## What a node folds
//!
//! Only shares **it** received (`received_by`), only valid ones, only network tier. A gossiped
//! share was received by a peer and belongs in *that* peer's column — folding it here would
//! double-credit the work the moment both columns merged. The fold's input is read from the
//! persisted `shares` table by the round's recorded height, NEVER from an in-memory accumulator:
//! the prior design lost 6,499 pending shares on a restart to exactly that, silently.
//!
//! ## Lifecycle
//!
//! Nothing here spawns. The caller owns the schedule and calls four entry points:
//!
//! - `ShardRuntime::note_height` on the template-refresh path — an integer compare that
//!   reports an epoch boundary, and nothing else;
//! - `ShardRuntime::tick` from the epoch task — folds closed epochs, bounded per call;
//! - `ShardRuntime::settle_matured` from the same epoch task — settles pool blocks that have
//!   reached coinbase maturity, bounded per call;
//! - `ShardRuntime::fold_epoch` if a single epoch needs folding by hand.
//!
//! Storage is a single `Mutex<Connection>` shared with share ingest, so every call does bounded
//! work: a tick folds at most `MAX_FOLDS_PER_TICK` epochs, an epoch's input is bounded by the
//! epoch length, evidence deletes are chunked inside the storage layer's one transaction, and a
//! settlement call settles at most `MAX_SETTLES_PER_CALL` blocks.
//!
//! ## Why settlement lives here and not on the block-connected path
//!
//! `settlement.rs` settles at the TIP and has to carry reorg reversal, because it acts on a
//! block that may still be undone. The shard settles at **coinbase maturity** (§4.6): a block
//! 100 deep is past any reorg this code contemplates, so there is no reversal to handle, and
//! nothing hooks `on_block_connected` at all — the epoch task that already ticks looks back to
//! `tip − 100` and settles what it has not settled yet. Idempotence comes from recording which
//! block hashes have been settled, not from transaction gymnastics on a hot path.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{debug, error, info, warn};

use ghost_common::coinbase_tags::extract_payout_tag;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::share_batch::creditable_difficulty;
use ghost_common::share_shard::{
    discharged_micro_work, epoch_for_height, EpochSummary, ShardTable, EPOCH_BLOCKS,
    NETWORK_TIER_LOG2, RETENTION_EPOCHS,
};
use ghost_common::types::ShareProof;
use ghost_common::zmq::block_hash_to_display_order;
use ghost_reconciliation::batch::compute_merkle_root;
use ghost_storage::database::Database;

use crate::coinbase_verifier::{address_to_script_pubkey, CoinbaseOutput};

/// Epochs one tick may fold. Bounds the work done against the shared connection between two
/// share-ingest writes: a node that is many epochs behind catches up across ticks — resume, not
/// a stall — rather than holding the storage mutex for the whole backlog at once.
const MAX_FOLDS_PER_TICK: usize = 4;

/// Coinbase maturity: the depth at which a coinbase output becomes spendable, and therefore the
/// depth the shard settles at (§4.6). A block this deep is past any reorg this code contemplates
/// (`RETENTION_FLOOR_BLOCKS` is also 100), which is exactly what removes the need for reversal.
/// Never settle shallower — a shallower block's payment can still be undone, and the shard
/// carries no undo.
const COINBASE_MATURITY: u64 = 100;

/// Pool blocks one settlement call may settle. Same rationale as [`MAX_FOLDS_PER_TICK`]: each
/// settlement is one bounded transaction against the connection share ingest also uses, so a
/// node returning from downtime discharges its backlog across calls — resume, not a stall.
const MAX_SETTLES_PER_CALL: usize = 4;

/// Heights one settlement call may examine. Bounds the RPC work of a long catch-up (each height
/// costs a `getblockhash` and a coinbase fetch); anything further behind carries to the next
/// call, exactly as the legacy forward scan batches its own catch-up.
/// Heights one call will examine.
///
/// This is an RPC-burst bound, not a correctness one. The per-call *settle* bound rarely stops the
/// walk early, because pool blocks are rare and almost everything examined is somebody else's — so
/// in practice a call fetches this many full blocks whatever the settle bound says, inline in a
/// 30 s tick whose `MissedTickBehavior::Skip` would then drop fold ticks behind it.
///
/// Twenty per tick still catches up roughly forty times faster than blocks arrive (~8 min each),
/// so a backlog closes quickly while no single tick spends long in RPC. Chunking the fetch so the
/// settle bound could halt it early was considered and rejected: it would need a second copy of
/// the decision walk to interleave with, and duplicated decision paths are what finding 5 was.
const MAX_SETTLE_SCAN_BLOCKS: u64 = 20;

/// How many consecutive calls may fail to read the same height before it is abandoned.
///
/// A transient RPC hiccup must not skip a block — a skipped POOL block is work never discharged,
/// paid twice later. But a DURABLY unreadable height must not wedge the walk for ever either: the
/// cursor would never advance past it and every later block would go unsettled, which is the same
/// loss multiplied by every block after it. So: retry a few times, then step over it loudly.
const MAX_BLOCK_READ_ATTEMPTS: u32 = 3;

/// kv key holding the height the maturity lookback has reached.
///
/// The cursor is an ECONOMY, never the idempotence: it only spares re-fetching coinbases already
/// examined. Correctness — a block settling exactly once — rests on the recorded block hashes in
/// `shard_settled_blocks`, so a lost or rewound cursor re-reads blocks and changes nothing.
const SETTLE_CURSOR_KEY: &str = "shard.settle_height";

/// What one epoch's fold did, for logs and for the caller's soak checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldReport {
    /// The epoch that folded.
    pub epoch: u64,
    /// Network-tier shares credited and committed under the summary's Merkle root.
    pub shares_folded: usize,
    /// Distinct payout addresses the epoch credited.
    pub addresses: usize,
    /// Shares left local: sub-tier or pre-tier-gate. Expected, tallied for visibility.
    pub below_tier: usize,
    /// Proof blobs that would not deserialise. Damaged data — never silently dropped.
    pub undecodable: usize,
    /// Shares screened out as unfoldable (no payout address, or a difficulty no proof of work
    /// stands behind). Attributable to nobody, so excluding them loses nothing — but say so.
    pub screened_out: usize,
    /// The epoch whose evidence fell out of retention with this fold, if any.
    pub expired_epoch: Option<u64>,
    /// Evidence rows deleted for `expired_epoch`, inside the fold's own transaction.
    pub evidence_dropped: usize,
}

/// One epoch's fold outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldOutcome {
    /// This node already holds its signed summary for the epoch. Nothing moved — a re-fold is a
    /// no-op, never a double credit.
    AlreadyFolded,
    /// The epoch folded: column credited, summary signed and stored, expired evidence dropped,
    /// all in one storage transaction.
    Folded(FoldReport),
}

/// What arming did — the ceremony's receipt, for the operator's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmReport {
    /// The anchor height the opening balances were converted from.
    pub anchor_height: u64,
    /// The pre-genesis epoch floor. Summaries below it are refused.
    pub epoch_floor: u64,
    /// How many accrued columns the ceremony replaced — the soak's state, discarded.
    pub replaced_columns: usize,
    /// Addresses in the opening genesis column.
    pub opening_addresses: usize,
    /// The table root after arming. Must match on all 8; this is what Stage 5 step 5 compares.
    pub table_root: [u8; 32],
}

/// What one tick did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    /// Epochs folded this tick, in order.
    pub folded: Vec<FoldReport>,
    /// Epochs the walk found already folded (a watermark behind reality — harmless).
    pub already_folded: usize,
    /// Closed epochs still unfolded when the per-tick bound stopped the walk. Non-zero means
    /// the next tick continues the catch-up.
    pub remaining: u64,
}

/// One block's fetched coinbase, ready for the settlement decision path.
///
/// Fetch and decision are split the way `settlement.rs` splits them: everything that can be
/// wrong — the tag, the maturity guard, matching outputs to owed addresses, the discharge
/// arithmetic — is testable without a live Core, while the fetch is a thin wrapper.
#[derive(Debug, Clone)]
struct FetchedCoinbase {
    block_hash: String,
    height: u64,
    scriptsig: Vec<u8>,
    outputs: Vec<CoinbaseOutput>,
}

/// What settling one matured block came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSettlement {
    /// The block, display-order hex — the same spelling its idempotence record carries.
    pub block_hash: String,
    /// Its height.
    pub height: u64,
    /// Addresses credited with a positive discharge.
    pub addresses: usize,
    /// Total micro-work discharged.
    pub discharged_micro: i64,
}

/// One matured block's settlement outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SettleBlockOutcome {
    /// No payout tag in the coinbase — someone else's block, the overwhelmingly common case.
    NotOurs,
    /// Not yet [`COINBASE_MATURITY`] deep. Refused, never recorded: an immature block's payment
    /// can still be undone by a reorg, and the shard carries no undo.
    Immature,
    /// Already recorded in `shard_settled_blocks`. Nothing moved — a re-run is a no-op, never a
    /// second discharge.
    AlreadySettled,
    /// Settled: block recorded and `settled` credited, one storage transaction.
    Settled(BlockSettlement),
}

/// What one [`ShardRuntime::settle_matured`] call did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettleReport {
    /// Blocks settled this call, in height order.
    pub settled: Vec<BlockSettlement>,
    /// Blocks examined that carry no payout tag.
    pub not_ours: usize,
    /// The height the walk could not read, if it stopped early. **A stall must be visible**: a
    /// settlement that has silently stopped looks exactly like one with nothing to do, and the
    /// difference is unpaid work accruing behind a cursor that never moves.
    pub stalled_at: Option<u64>,
    /// Heights abandoned as durably unreadable after `MAX_BLOCK_READ_ATTEMPTS`. Skipping is the
    /// lesser evil — one block's payments undischarged beats every later block never settling —
    /// but it is never silent.
    pub skipped_unreadable: Vec<u64>,
    /// Pool blocks found already settled (a rewound cursor — harmless).
    pub already_settled: usize,
    /// Blocks handed to this call but left for the next one by the per-call bound. Non-zero
    /// means the next call continues the catch-up.
    pub deferred: usize,
}

/// How far the shard's balances have drifted from the legacy ledger's.
///
/// This is the soak signal the cutover is judged on: if the two agree, a coinbase built from the
/// shard pays what the coinbase built from the ledger would have paid, and the switch is safe. If
/// they disagree, the disagreement is visible here BEFORE any money moves rather than afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriftReport {
    /// Addresses both sides know, whose micro-work totals differ, with `shard − ledger`.
    pub differing: Vec<(String, i64)>,
    /// Addresses the shard credits that the legacy ledger does not.
    pub only_shard: Vec<String>,
    /// Addresses the legacy ledger credits that the shard does not.
    pub only_ledger: Vec<String>,
    /// Addresses agreeing exactly. The number that should be ~everything.
    pub agreeing: usize,
    /// Net `shard − ledger` across every address, in micro-work.
    pub net_micro: i64,
}

impl DriftReport {
    /// Whether the two ledgers agree completely.
    pub fn is_clean(&self) -> bool {
        self.differing.is_empty() && self.only_shard.is_empty() && self.only_ledger.is_empty()
    }
}

/// The shard's view on this node: the merged table, plus the fold watermark.
pub struct ShardRuntime {
    identity: Arc<NodeIdentity>,
    db: Arc<Database>,
    /// How local ingest stamps this node on a share row: `hex(node_id[..8])`. Derived once —
    /// the fold input query is scoped by it on every call.
    received_by: String,
    /// A solo node's work is its own (§10). Latched at load: nothing this runtime does may put
    /// solo work into the shared shard, so the gate sits here rather than in the caller, where
    /// one missed call site would leak silently.
    solo: bool,
    /// Whether this node's shard OWNS the `shares` table — i.e. whether retention may delete from
    /// it. **False until cutover, and that is a money-safety gate, not a tidiness one.**
    ///
    /// Retention deletes evidence from `shares`, which is the same table the legacy payout path
    /// still computes unpaid balances from. While both ledgers are live, a delete here removes
    /// work the old machinery would have paid for — so enabling the shard would silently reduce
    /// what miners are owed, roughly `RETENTION_EPOCHS` after the flag was set.
    ///
    /// That breaks the property the whole dark-ship approach rests on: **dark must mean changes
    /// nothing.** A feature that quietly deletes production rows is not dark, however carefully
    /// the rest of it is gated.
    ///
    /// Stage 5 renames `shares` to `shares_archive` and the shard becomes authoritative; this
    /// flips there, in the same change, and not before. Until then retention still *computes* its
    /// expiry and logs it, so the behaviour is observable without being destructive.
    owns_evidence: bool,
    /// The merged shard table. Guarded by one mutex and held across a fold — fold, persist and
    /// the in-memory credit must be a single observable step, and nothing else takes this lock
    /// while holding another.
    table: Mutex<ShardTable>,
    /// The next epoch [`ShardRuntime::tick`] will fold, or `None` before the first tick derives
    /// it. In-memory only: the durable truth is the summary rows the fold writes, from which a
    /// restart re-derives this — state that can be derived is state that cannot drift.
    next_fold: Mutex<Option<u64>>,
    /// The height the walk last failed to read, and how many consecutive calls have failed on it.
    /// In memory only: a restart is itself a reason to retry, and persisting a give-up decision
    /// would outlive the condition that caused it.
    read_failures: Mutex<Option<(u64, u32)>>,
    /// The last epoch [`ShardRuntime::note_height`] saw, stored as `epoch + 1` so zero can mean
    /// "never" (an epoch is `height / EPOCH_BLOCKS`, so `+ 1` cannot wrap). Atomic because it is
    /// read on the template-refresh path, which must never wait on a fold in progress.
    last_epoch_seen: AtomicU64,
}

impl ShardRuntime {
    /// Load the persisted table and resume. A restart resumes the shard, not restarts it: the
    /// fleet compares table roots, and a node that reset on every deploy could never agree with
    /// anyone.
    ///
    /// `solo` latches solo mode for the life of the runtime: a solo node's work must never enter
    /// the shared shard, so [`ShardRuntime::tick`] and [`ShardRuntime::fold_epoch`] refuse
    /// outright rather than trusting every caller to remember.
    ///
    /// Call-site contract (the `sbc_chain` precedent, `main.rs`): a load failure must NOT take
    /// the pool down. The shard is an observation, and killing the node because an observation
    /// could not start would make the safer configuration the riskier one to deploy — log it,
    /// carry `None`, keep mining.
    pub fn load(
        identity: Arc<NodeIdentity>,
        db: Arc<Database>,
        solo: bool,
        owns_evidence: bool,
    ) -> GhostResult<Self> {
        let table = db.shard_load_table()?;

        // Re-assert the opening balances against the ceremony pin, every start.
        //
        // `merge_accrued` skips the reserved genesis column, so once a node is armed those rows
        // can never be re-learned from a peer — they are the one part of the table with no
        // redundancy anywhere in the design. Truncation, a partial delete, or a backup restored
        // from before the ceremony would leave the node opening under-owing every miner, staying
        // internally consistent, with nothing to contradict it.
        //
        // An ABSENT column is not a failure: that is every pre-ceremony start, which is all of
        // them today. Present-and-wrong is the only thing refused, and refusing means the shard
        // does not load while the pool keeps mining (see the call-site contract above) — the
        // safe direction, because a shard that is not observing costs nothing and a shard
        // observing from the wrong balances is what the ceremony exists to prevent.
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        if let Err(e) = ghost_accounting::shard_genesis::verify_loaded_genesis(&table, &anchor) {
            error!(
                anchor_height = anchor.height,
                error = %e,
                "share shard: persisted genesis column does not match the pin — REFUSING to load"
            );
            return Err(GhostError::Database(e.to_string()));
        }

        let received_by = hex::encode(&identity.node_id()[..8]);
        info!(
            columns = table.accrued().len(),
            genesis_installed = table
                .accrued()
                .contains_key(&ghost_accounting::shard_genesis::GENESIS_NODE_ID),
            solo,
            owns_evidence,
            "share shard: runtime loaded"
        );
        Ok(Self {
            identity,
            db,
            received_by,
            solo,
            owns_evidence,
            read_failures: Mutex::new(None),
            table: Mutex::new(table),
            next_fold: Mutex::new(None),
            last_epoch_seen: AtomicU64::new(0),
        })
    }

    /// Arm the shard from the pinned genesis checkpoint — Stage 5 step 4, the one-time ceremony.
    ///
    /// Converts this node's own copy of the byte-identical checkpoint, asserts the result against
    /// the compile-time pin, and replaces the table with the opening balances. A loud LOCAL
    /// self-check: no node asks another node anything, so there is no negotiation to partition and
    /// no quorum to stall, and a node holding the wrong bytes finds out on its own.
    ///
    /// **The gap-fold is not a separate mechanism.** The plan describes folding "shares with
    /// `timestamp ∈ (cutoff_ts, now]`", but a timestamp-range fold would overlap the ordinary epoch
    /// folds that run from the floor onward, double-crediting every share in the intersection. What
    /// is actually needed is for the epoch watermark to restart at the floor, after which
    /// [`ShardRuntime::tick`] catches up epoch by epoch using machinery that is already bounded,
    /// already idempotent (`shard_epochs` is the durable marker), and already retries a failed
    /// epoch instead of skipping it. So arming sets the watermark and returns; the catch-up is the
    /// existing loop, and the 6,499-share lesson is honoured because the fold's input still comes
    /// from the persisted shares table rather than from anything held in memory.
    ///
    /// ⚠ **The floor is the anchor's epoch PLUS ONE, and that under-credits slightly.** Genesis
    /// credits work up to `cutoff_ts`, which falls partway through the epoch containing the anchor
    /// height. Folding that epoch would re-credit the part of it genesis already covered, so it is
    /// skipped entirely — which loses this node's own work in the remainder of that one epoch, at
    /// most `EPOCH_BLOCKS - 1` heights. Deliberate, and in the same direction as the conversion's
    /// truncation: under-crediting by a sliver is immaterial, crediting work twice is not.
    pub fn arm_from_genesis(
        &self,
        anchor: &ghost_accounting::shard_genesis::GenesisAnchor,
        canonical_payout: &[u8],
    ) -> GhostResult<ArmReport> {
        let (genesis, rounding) =
            ghost_accounting::shard_genesis::open_shard_from_checkpoint(canonical_payout, anchor)
                .map_err(|e| GhostError::Database(e.to_string()))?;

        let floor = epoch_for_height(anchor.height, EPOCH_BLOCKS) + 1;

        let mut table = self.table.lock();

        // Refuse rather than clear if anything has been settled. The pool has won zero blocks, so
        // this cannot fire today — but if it ever does, the genesis checkpoint (an UNPAID ledger)
        // and a non-empty `settled` disagree about history, and silently discarding the settled
        // side would be the one destructive thing in an otherwise additive ceremony.
        if !table.settled().is_empty() {
            return Err(GhostError::Database(format!(
                "shard: refusing to arm — {} settled balances exist, which the genesis checkpoint \
                 does not account for; investigate before arming",
                table.settled().len()
            )));
        }

        let replaced_columns = table.accrued().len();
        *table = genesis;
        table.set_epoch_floor(floor);

        // Replace semantics: rows absent from the new table are deleted, so the soak's columns do
        // not survive as stale contributors to the next load's root.
        self.db.shard_save_table(&table, floor, anchor.height)?;

        let root = table.compute_table_root();
        drop(table);

        *self.next_fold.lock() = Some(floor);

        info!(
            anchor_height = anchor.height,
            floor,
            replaced_columns,
            addresses_rounded = rounding.addresses_rounded,
            addresses_dropped = rounding.addresses_dropped,
            units_discarded = rounding.units_discarded,
            root = %hex::encode(&root[..8]),
            "share shard: ARMED from genesis"
        );

        Ok(ArmReport {
            anchor_height: anchor.height,
            epoch_floor: floor,
            replaced_columns,
            opening_addresses: self
                .table
                .lock()
                .accrued()
                .get(&ghost_accounting::shard_genesis::GENESIS_NODE_ID)
                .map(|c| c.len())
                .unwrap_or(0),
            table_root: root,
        })
    }

    /// Compare the shard's balances against the legacy unpaid ledger.
    ///
    /// ⚠ **Call this once per EPOCH, never per tick.** It runs `get_top_unpaid_addresses`, which is
    /// the 2.76M-row, ~1.6 s scan already running at roughly 40% duty on the propose and vote
    /// paths — the very load this design exists to delete. Hourly it is lost in the noise; every
    /// thirty seconds it would be a meaningful share of the node, and we would have rebuilt the
    /// problem while measuring the cure for it.
    ///
    /// Compares in integer micro-work, converted the same way [`micro_work`] converts, so a
    /// difference here is a real difference and not a rounding artefact of the comparison.
    ///
    /// [`micro_work`]: ghost_common::share_batch::micro_work
    pub fn drift_against_legacy_ledger(&self, cutoff_ts: i64) -> GhostResult<DriftReport> {
        let ledger = self.db.get_top_unpaid_addresses(cutoff_ts, u32::MAX)?;
        let ledger: BTreeMap<String, i64> = ledger
            .into_iter()
            .map(|(addr, work, _)| (addr, ghost_common::share_batch::micro_work(work)))
            .collect();

        let owed = self.table.lock().owed();
        let mut report = DriftReport::default();

        for (addr, &shard_micro) in &owed {
            match ledger.get(addr) {
                Some(&ledger_micro) if ledger_micro == shard_micro => report.agreeing += 1,
                Some(&ledger_micro) => {
                    let delta = shard_micro.saturating_sub(ledger_micro);
                    report.net_micro = report.net_micro.saturating_add(delta);
                    report.differing.push((addr.clone(), delta));
                }
                None => {
                    report.net_micro = report.net_micro.saturating_add(shard_micro);
                    report.only_shard.push(addr.clone());
                }
            }
        }
        for (addr, &ledger_micro) in &ledger {
            if !owed.contains_key(addr) {
                report.net_micro = report.net_micro.saturating_sub(ledger_micro);
                report.only_ledger.push(addr.clone());
            }
        }
        Ok(report)
    }

    /// Record the height seen on a template refresh. Returns true iff this height crossed into
    /// a new epoch.
    ///
    /// Cheap and non-blocking by construction — one division and one atomic max, no lock the
    /// fold could be holding, no database — because it runs on the template-refresh path, which
    /// must stay responsive. It reports the boundary; it never folds (`main.rs`'s `NewWork`
    /// handler logs the crossing and signals the epoch task, which is where the fold lives).
    ///
    /// Idempotent within an epoch: only the FIRST call that lands in a new epoch returns true.
    /// The max means a height that steps backwards (a reorg) neither reports nor rewinds — the
    /// boundary was already reported once, and once is what the caller is promised.
    pub fn note_height(&self, height: u64) -> bool {
        let tagged = epoch_for_height(height, EPOCH_BLOCKS) + 1;
        let prev = self.last_epoch_seen.fetch_max(tagged, Ordering::AcqRel);
        // `prev == 0` is the first observation ever: there is no previous epoch to have crossed
        // FROM, so it initialises silently rather than reporting a boundary that did not happen.
        prev != 0 && tagged > prev
    }

    /// The merged table's root — what the fleet compares (§12.6), for logs and the soak gate.
    pub fn table_root(&self) -> [u8; 32] {
        self.table.lock().compute_table_root()
    }

    /// What each address is owed under the current merged view. A copy: callers must not be able
    /// to mutate the table, and the map is a few hundred rows by design.
    pub fn owed(&self) -> BTreeMap<String, i64> {
        self.table.lock().owed()
    }

    /// Fold every epoch that has CLOSED and has not been folded, bounded per call, and drop
    /// evidence that has left the retention window (each fold carries its own expiry — see
    /// [`ShardRuntime::fold_epoch`]).
    ///
    /// The epoch in progress is never folded: its round set is still growing, and a summary is
    /// this node's one signed statement per epoch — signing it early and signing it again later
    /// is equivocation by construction.
    ///
    /// The walk resumes rather than restarts: the watermark is derived from the summary rows the
    /// folds themselves wrote, so a restart continues exactly where the last successful fold
    /// stopped. A node that has never folded starts at the CURRENT epoch — epochs that closed
    /// before this node ever ran the shard belong to the old ledger, and the cutover's gap-fold
    /// (build plan Stage 5) owns that seam explicitly; folding arbitrary history here would race
    /// it.
    pub fn tick(&self, current_height: u64) -> GhostResult<TickReport> {
        let mut report = TickReport::default();
        if self.solo {
            debug!("share shard: solo mode — nothing folds into the shared shard");
            return Ok(report);
        }

        let current = epoch_for_height(current_height, EPOCH_BLOCKS);
        let mut next_guard = self.next_fold.lock();
        let mut next = match *next_guard {
            Some(n) => n,
            None => {
                let n = match self.db.shard_latest_epoch(&self.identity.node_id())? {
                    Some(latest) => latest + 1,
                    None => current,
                };
                *next_guard = Some(n);
                n
            }
        };

        for _ in 0..MAX_FOLDS_PER_TICK {
            if next >= current {
                break;
            }
            match self.fold_epoch(next)? {
                FoldOutcome::Folded(r) => report.folded.push(r),
                FoldOutcome::AlreadyFolded => report.already_folded += 1,
            }
            // Advanced only past a SUCCESSFUL fold: an error above propagates with the
            // watermark still pointing at the failed epoch, so the next tick retries it.
            next += 1;
            *next_guard = Some(next);
        }
        report.remaining = current.saturating_sub(next);
        Ok(report)
    }

    /// Fold one epoch: query its shares from the persisted table, fold them into this node's OWN
    /// column, sign the [`EpochSummary`], and persist through the storage layer's single
    /// fold-then-delete transaction. Idempotent — an epoch this node has already summarised is a
    /// no-op, never a double credit.
    ///
    /// The same transaction drops the evidence of the epoch that left the retention window with
    /// this fold: `expired = epoch − RETENTION_EPOCHS` (§4.3 — evidence is kept a sampling
    /// window past its summary so peers can audit it, then dropped). Expiry is therefore a pure
    /// function of height, which matters because an honest node dropping expired evidence must
    /// be distinguishable from one refusing to be audited — both sides compute the same
    /// boundary from the chain. Epochs this node never summarised are never dropped: their rows
    /// are the OLD ledger's history, not shard evidence, and the old ledger still pays from it.
    ///
    /// Callers other than [`ShardRuntime::tick`] must not pass the epoch in progress — this
    /// method cannot see the tip, so closedness is the caller's contract.
    ///
    /// On ANY failure the in-memory table and the database are both untouched: the storage call
    /// is one transaction, and the in-memory credit happens only after it commits.
    pub fn fold_epoch(&self, epoch: u64) -> GhostResult<FoldOutcome> {
        if self.solo {
            return Err(GhostError::Internal(
                "share shard: refusing to fold in solo mode — solo work never enters the \
                 shared shard"
                    .into(),
            ));
        }
        let node = self.identity.node_id();
        let mut table = self.table.lock();

        // The idempotence gate. The summary row is written inside the fold's own transaction,
        // so "a summary exists" and "the epoch is folded" cannot disagree; re-folding would
        // rebuild the summary from an already-credited column and double the credit.
        if self.db.shard_get_epoch(epoch, &node)?.is_some() {
            debug!(epoch, "share shard: epoch already folded — no-op");
            return Ok(FoldOutcome::AlreadyFolded);
        }

        let input = self.db.shard_epoch_shares(
            epoch,
            EPOCH_BLOCKS,
            &self.received_by,
            NETWORK_TIER_LOG2,
        )?;
        if input.undecodable > 0 {
            warn!(
                epoch,
                undecodable = input.undecodable,
                "share shard: proof blobs would not deserialise — damaged rows excluded from \
                 the fold"
            );
        }
        let (evidence, screened_out) = screen(input.shares);
        if screened_out > 0 {
            warn!(
                epoch,
                screened_out,
                "share shard: unfoldable shares excluded (no payout address, or a \
                 non-creditable difficulty)"
            );
        }

        // Each node writes only its own column (§4.4): the summary's totals continue this
        // node's column and nothing else.
        let prior: BTreeMap<String, i64> = table.accrued().get(&node).cloned().unwrap_or_default();
        let summary = EpochSummary::build(
            epoch,
            &self.identity,
            &prior,
            &evidence,
            compute_merkle_root,
        )
        .map_err(|e| {
            GhostError::Internal(format!(
                "share shard: epoch {epoch} evidence failed its own screen: {e}"
            ))
        })?;

        // The full post-fold column — the storage layer replaces, so it needs the whole truth.
        let mut column = prior;
        for (addr, row) in &summary.deltas {
            column.insert(addr.clone(), row.total_micro);
        }

        let (expired_epoch, expired_hashes) = self.expired_evidence(epoch)?;

        // Retention is COMPUTED always and ACTED ON only when this shard owns the table. While
        // the legacy payout path still reads `shares`, deleting from it would reduce what miners
        // are owed by the machinery that is still paying them — see `owns_evidence`. Logging the
        // count keeps the behaviour observable during the dark soak without being destructive.
        let to_delete: &[[u8; 32]] = if self.owns_evidence {
            &expired_hashes
        } else {
            if !expired_hashes.is_empty() {
                info!(
                    epoch,
                    expired_epoch = ?expired_epoch,
                    would_drop = expired_hashes.len(),
                    "share shard: retention withheld — the legacy ledger still owns `shares`"
                );
            }
            &[]
        };

        let evidence_dropped = self
            .db
            .shard_fold_epoch(&node, &column, &summary, to_delete)?;

        // Only after the transaction has committed does the in-memory table move — a failed
        // fold must leave the counters untouched, or memory and disk drift apart and the next
        // save persists the drift.
        for (addr, row) in &summary.deltas {
            table.accrue(node, addr, row.delta_micro);
        }

        let report = FoldReport {
            epoch,
            shares_folded: evidence.len(),
            addresses: summary.deltas.len(),
            below_tier: input.below_tier,
            undecodable: input.undecodable,
            screened_out,
            expired_epoch,
            evidence_dropped,
        };
        info!(
            epoch,
            shares = report.shares_folded,
            addresses = report.addresses,
            evidence_dropped,
            "share shard: epoch folded"
        );
        Ok(FoldOutcome::Folded(report))
    }

    /// The evidence that leaves the retention window when `epoch` folds: the share hashes of
    /// `epoch − RETENTION_EPOCHS`, IF this node summarised that epoch.
    ///
    /// The set is re-derived by the same eligibility query and screen that built the expired
    /// epoch's summary — one spelling of "what was evidence" — so the delete matches what the
    /// summary's root committed to. An epoch with no summary contributes nothing: those rows
    /// were never shard evidence and are not the shard's to delete.
    fn expired_evidence(&self, epoch: u64) -> GhostResult<(Option<u64>, Vec<[u8; 32]>)> {
        let Some(expired) = epoch.checked_sub(RETENTION_EPOCHS) else {
            return Ok((None, Vec::new()));
        };
        let node = self.identity.node_id();
        if self.db.shard_get_epoch(expired, &node)?.is_none() {
            return Ok((None, Vec::new()));
        }
        let input = self.db.shard_epoch_shares(
            expired,
            EPOCH_BLOCKS,
            &self.received_by,
            NETWORK_TIER_LOG2,
        )?;
        let (evidence, _) = screen(input.shares);
        Ok((
            Some(expired),
            evidence.iter().map(|s| s.share_hash).collect(),
        ))
    }

    /// Settle pool blocks that have reached coinbase maturity (§4.6), bounded per call.
    ///
    /// Called from the epoch task — NEVER the block-connected or template-refresh paths. At
    /// maturity there is no reversal to handle (the block is past reorg range), so the whole
    /// mechanism is a lookback: walk the chain from where the last call stopped up to
    /// `tip − 100`, and for each block carrying our payout tag, credit `settled` with what its
    /// coinbase actually paid. The chain is already replicated to every node, so this needs
    /// zero messages and zero coordination.
    ///
    /// This changes what nobody is paid: the coinbase is still built from the legacy proposal,
    /// and the shard is observing what it paid.
    ///
    /// The fetch stops at the first RPC gap rather than skipping it — the cursor only ever
    /// advances over blocks actually examined, so a gap is retried next call rather than lost.
    pub async fn settle_matured(
        &self,
        rpc: &BitcoinRpc,
        tip_height: u64,
    ) -> GhostResult<SettleReport> {
        if self.solo {
            // A solo node's blocks pay by the solo path and its work never entered the shared
            // shard, so there is nothing here its payments could legitimately discharge.
            debug!("share shard: solo mode — no maturity settlement");
            return Ok(SettleReport::default());
        }
        let Some((from, to)) = self.settle_window(tip_height)? else {
            return Ok(SettleReport::default());
        };

        // Three outcomes, not one. A read failure used to `break` unconditionally, which meant a
        // DURABLY unreadable height wedged the walk for ever: the cursor never advanced past it and
        // every later block went unsettled — one block's loss multiplied by every block after it.
        // Retrying for ever is not the alternative either, because a transient hiccup must not skip
        // a pool block. So: retry a bounded number of times, then step over it loudly.
        let mut blocks = Vec::new();
        let mut stalled_at = None;
        let mut skipped_unreadable = Vec::new();
        for height in from..=to {
            let read = match rpc.get_block_hash(height).await {
                Ok(hash) => crate::settlement::fetch_coinbase_parts(rpc, &hash)
                    .await
                    .map(|(scriptsig, outputs)| FetchedCoinbase {
                        block_hash: hash,
                        height,
                        scriptsig,
                        outputs,
                    }),
                Err(e) => Err(e),
            };
            match read {
                Ok(fetched) => {
                    *self.read_failures.lock() = None;
                    blocks.push(fetched);
                }
                Err(e) => {
                    let attempts = {
                        let mut f = self.read_failures.lock();
                        let n = match *f {
                            Some((h, n)) if h == height => n + 1,
                            _ => 1,
                        };
                        *f = Some((height, n));
                        n
                    };
                    if attempts >= MAX_BLOCK_READ_ATTEMPTS {
                        error!(
                            height,
                            attempts,
                            error = %e,
                            "share shard: block is durably unreadable — SKIPPING it so settlement \
                             can continue. Its payments discharge nothing and that work stays owed"
                        );
                        skipped_unreadable.push(height);
                        *self.read_failures.lock() = None;
                        continue;
                    }
                    warn!(
                        height,
                        attempts,
                        error = %e,
                        "share shard: settlement stalled on an unreadable block — retrying next call"
                    );
                    stalled_at = Some(height);
                    break;
                }
            }
        }

        let mut report = self.settle_fetched(tip_height, &blocks)?;
        report.stalled_at = stalled_at;

        // Guarantee forward progress past a skipped height. `settle_fetched` advances the cursor
        // only past blocks it processed, so a skip at the END of a batch would otherwise be
        // retried for ever and the walk would never move.
        if let Some(&highest) = skipped_unreadable.iter().max() {
            let cursor: u64 = self
                .db
                .kv_get(SETTLE_CURSOR_KEY)?
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if highest > cursor {
                self.db.kv_set(SETTLE_CURSOR_KEY, &highest.to_string())?;
            }
        }
        report.skipped_unreadable = skipped_unreadable;
        Ok(report)
    }

    /// The height range the next settlement call should examine, or `None` if there is nothing
    /// to do. Initialises the cursor on the first call ever: history that matured before the
    /// shard ran belongs to the legacy ledger — the shard accrued nothing for it, so its
    /// payments have nothing here to discharge — which mirrors the fold watermark starting at
    /// the current epoch.
    fn settle_window(&self, tip_height: u64) -> GhostResult<Option<(u64, u64)>> {
        let mature = tip_height.saturating_sub(COINBASE_MATURITY);
        if mature == 0 {
            return Ok(None);
        }
        // ABSENT and UNPARSEABLE are different facts and must not share a branch. Absent is a
        // first run, and fast-forwarding to today's boundary is right: history that matured before
        // the shard existed belongs to the legacy ledger. Unparseable is CORRUPTION of a cursor
        // that once had a value — fast-forwarding there silently skips every pool block between
        // the real position and now, and unpaid work is exactly what nobody notices.
        let raw = self.db.kv_get(SETTLE_CURSOR_KEY)?;
        let cursor: Option<u64> = match raw.as_deref() {
            None => None,
            Some(v) => match v.parse() {
                Ok(h) => Some(h),
                Err(_) => {
                    error!(
                        value = %v,
                        "share shard: settle cursor is unreadable — refusing to fast-forward past \
                         blocks that may be unsettled. Settlement is HALTED until it is repaired"
                    );
                    return Ok(None);
                }
            },
        };
        let Some(cursor) = cursor else {
            self.db.kv_set(SETTLE_CURSOR_KEY, &mature.to_string())?;
            return Ok(None);
        };
        if cursor >= mature {
            return Ok(None);
        }
        // Catch-up is bounded per call, exactly as the legacy forward scan bounds its own.
        Ok(Some((
            cursor + 1,
            mature.min(cursor + MAX_SETTLE_SCAN_BLOCKS),
        )))
    }

    /// Walk fetched blocks in height order, settling at most [`MAX_SETTLES_PER_CALL`] of them.
    ///
    /// The cursor advances only past blocks actually processed, so blocks the bound defers are
    /// re-examined next call rather than silently skipped — and a deferred POOL block is the
    /// case that matters, because skipping one is unpaid work never discharged.
    fn settle_fetched(
        &self,
        tip_height: u64,
        blocks: &[FetchedCoinbase],
    ) -> GhostResult<SettleReport> {
        let mut report = SettleReport::default();
        let mut processed_to: Option<u64> = None;
        for (i, block) in blocks.iter().enumerate() {
            if report.settled.len() >= MAX_SETTLES_PER_CALL {
                report.deferred = blocks.len() - i;
                break;
            }
            let outcome = self.settle_block_from_coinbase(
                tip_height,
                &block.block_hash,
                block.height,
                &block.scriptsig,
                &block.outputs,
            )?;
            match outcome {
                SettleBlockOutcome::Immature => {
                    // The window never hands this path an immature block; a caller that does
                    // gets it deferred, cursor untouched, so it is revisited once it matures.
                    report.deferred = blocks.len() - i;
                    break;
                }
                SettleBlockOutcome::NotOurs => report.not_ours += 1,
                SettleBlockOutcome::AlreadySettled => report.already_settled += 1,
                SettleBlockOutcome::Settled(s) => report.settled.push(s),
            }
            processed_to = Some(block.height);
        }

        // ONE cursor write, not one per examined block. The old per-block write meant up to
        // MAX_SETTLE_SCAN_BLOCKS autocommit fsyncs per call on the connection share ingest is
        // waiting for — and it bought nothing: the cursor is an economy, never the idempotence
        // (that is the recorded block hashes), so writing the last processed height once at the
        // end is exactly equivalent. Blocks the bound deferred are not passed, so they are
        // re-examined next call rather than skipped.
        if let Some(height) = processed_to {
            self.db.kv_set(SETTLE_CURSOR_KEY, &height.to_string())?;
        }
        Ok(report)
    }

    /// Decide and apply one block's settlement, given its coinbase already in hand.
    ///
    /// Credits from the MINED outputs — what the chain actually paid, never a stored proposal —
    /// which is #601's correction carried over: the mined coinbase absorbs the winner's fee
    /// drift, so any stored amount records money the chain never moved.
    ///
    /// The satoshi→micro-work conversion is [`discharged_micro_work`] at the rate the payment
    /// was computed under: `pool_sats` is what the coinbase paid the matched addresses and
    /// `top_work` is THIS NODE'S owed total across those same addresses (§4.6). That is
    /// deterministic given a table, not identical across nodes, and it is safe because `owed`
    /// is signed and never clamped: over-discharge leaves a negative residual that accrues back
    /// up, under-discharge leaves work the next block pays.
    ///
    /// `settled` only ever increases. Nothing here touches `accrued` — subtracting from it is
    /// the single-counter model, and it double-pays the moment a node that slept through the
    /// settlement re-advertises its pre-settlement column (§4.4).
    fn settle_block_from_coinbase(
        &self,
        tip_height: u64,
        block_hash: &str,
        height: u64,
        scriptsig: &[u8],
        outputs: &[CoinbaseOutput],
    ) -> GhostResult<SettleBlockOutcome> {
        // The maturity guard, first: settling shallower than the coinbase's own spendability is
        // settling a payment a reorg can still undo, and the shard carries no undo.
        if height.saturating_add(COINBASE_MATURITY) > tip_height {
            return Ok(SettleBlockOutcome::Immature);
        }
        // Ownership: the tag's PRESENCE is not enough. `GHPP` says "some Ghost deployment mined
        // this", not "this pool did" — and the whole design is permissionless, so other Ghost
        // deployments carrying the same tag is the expected state, not a corner case. A sibling's
        // block (or a forged tag) that happens to pay an address we also credit would discharge
        // our miners' owed work against money this pool never received: marked paid, not paid.
        //
        // So resolve the 16-byte payout id to a proposal WE hold, exactly as the legacy settlement
        // path does. That works today because the coinbase is still built from the proposal; when
        // the coinbase moves to declaring shard state (Stage 5), this ownership test moves with it
        // and must not be loosened in the meantime.
        let Some(payout_id) = extract_payout_tag(scriptsig) else {
            return Ok(SettleBlockOutcome::NotOurs);
        };
        match self.db.get_proposal_by_hash_prefix(&payout_id) {
            Ok(Some(_)) => {}
            Ok(None) => return Ok(SettleBlockOutcome::NotOurs),
            Err(e) => {
                // Cannot prove ownership => do not settle. Failing closed here costs a deferral;
                // failing open would discharge real balances on an unproven block.
                warn!(error = %e, "shard: payout id lookup failed — deferring, not settling");
                return Ok(SettleBlockOutcome::NotOurs);
            }
        }
        // One spelling of the hash everywhere: the idempotence record only works if every
        // caller writes display order, and the normaliser leaves a display-order hash alone.
        let block_hash = block_hash_to_display_order(block_hash);

        // What the coinbase paid, per script — summed first, because a coinbase may carry more
        // than one output to the same script and each satoshi discharges work exactly once.
        let mut paid_by_script: BTreeMap<&[u8], u64> = BTreeMap::new();
        for out in outputs {
            let paid = paid_by_script
                .entry(out.script_pubkey.as_slice())
                .or_insert(0);
            *paid = paid.saturating_add(out.value);
        }

        // Held across the storage call, like the fold: the discharge is computed against this
        // table, and crediting a table that moved in between would discharge at a rate nobody
        // computed.
        let mut table = self.table.lock();
        let owed = table.owed();

        // ⚠ This lock is held across the storage transaction ON PURPOSE, and it is a trade, not an
        // oversight. Releasing it to shorten the window would mean computing the discharge from one
        // table state and applying it to another: the rate would be one nobody computed, against
        // balances that had moved. Since the whole point of `settled` is that it discharges exactly
        // what the rate was derived from, that is the wrong thing to give up.
        //
        // What it costs: root, owed, drift and fold readers wait for the duration of a short
        // transaction, and a `SQLITE_BUSY` aborts the call (which retries next tick, harmlessly).
        // Reviewed and accepted rather than fixed — lock ORDER was verified, so there is no
        // deadlock, only latency. If this ever shows up as contention, the fix is to make the
        // storage call cheaper, not to widen the gap between computing a rate and applying it.
        //
        // The matched set: positively-owed addresses this coinbase actually paid. Outputs to
        // anything else — the treasury, node rewards, an address already at or below zero —
        // discharge nothing, because there is no owed work to attribute them to.
        let mut matched: Vec<(&String, i64, u64)> = Vec::new();
        for (addr, &owed_micro) in &owed {
            if owed_micro <= 0 {
                continue;
            }
            let Some(spk) = address_to_script_pubkey(addr.as_bytes()) else {
                debug!(address = %addr, "share shard: owed address does not convert to a \
                       script — cannot match coinbase outputs to it");
                continue;
            };
            if let Some(&paid) = paid_by_script.get(spk.as_slice()) {
                if paid > 0 {
                    matched.push((addr, owed_micro, paid));
                }
            }
        }

        // ⚠ The rate must be ABSOLUTE, never self-normalising. Summing both sides over the same
        // matched set makes the ratio cancel:
        //
        //     Σ discharged = (Σ paid) × top_work / pool_sats = pool_sats × top_work / pool_sats
        //
        // so the total discharged equals the total owed no matter what the block actually paid — a
        // one-satoshi block would clear every matched balance in full. That inversion is only valid
        // when the coinbase was BUILT from this node's shard view, and it is not: it is still built
        // from the legacy proposal, so the equation being inverted does not hold.
        //
        // Both terms therefore come from outside the matched set. `pool_sats` is the block's whole
        // coinbase — an absolute number of satoshis this block paid out — and `top_work` is this
        // node's entire positively-owed ledger.
        //
        // Including the treasury and node-reward outputs in `pool_sats` deliberately UNDER-states
        // the rate, so payments discharge slightly less work than they bought. That is the safe
        // direction: under-discharging leaves work owed and the next block pays it, while
        // over-discharging marks a miner paid for money they never received. When the coinbase
        // moves to declaring shard state (Stage 5) the two converge and the residual disappears.
        //
        // ⚠ `owed` is reused rather than re-locking `self.table`: the guard above is still alive
        // here and `parking_lot::Mutex` is not reentrant, so a second `lock()` would deadlock the
        // epoch task outright.
        let pool_sats: u64 = outputs.iter().map(|o| o.value).sum();
        let top_work: i64 = owed
            .values()
            .filter(|micro| **micro > 0)
            .fold(0i64, |acc, micro| acc.saturating_add(*micro));

        let amounts: Vec<(String, i64)> = matched
            .iter()
            .map(|(addr, _, paid)| {
                (
                    (*addr).clone(),
                    discharged_micro_work(*paid, pool_sats, top_work),
                )
            })
            .collect();

        // One transaction: the block's idempotence record and its credits land together, and
        // `false` means the block was already settled — in which case the in-memory table must
        // not move either.
        if !self.db.shard_settle_block(&block_hash, height, &amounts)? {
            debug!(block_hash = %block_hash, height, "share shard: block already settled — no-op");
            return Ok(SettleBlockOutcome::AlreadySettled);
        }

        // Only after the transaction has committed does the in-memory table move — the fold's
        // rule, for the fold's reason.
        let mut discharged_total = 0i64;
        for (addr, micro) in &amounts {
            table.record_settled(addr, *micro);
            discharged_total = discharged_total.saturating_add((*micro).max(0));
        }
        let settlement = BlockSettlement {
            block_hash,
            height,
            addresses: amounts.iter().filter(|(_, micro)| *micro > 0).count(),
            discharged_micro: discharged_total,
        };
        info!(
            block_hash = %settlement.block_hash,
            height,
            addresses = settlement.addresses,
            discharged_micro = settlement.discharged_micro,
            "share shard: settled a matured pool block"
        );
        Ok(SettleBlockOutcome::Settled(settlement))
    }
}

/// Screen tier-eligible shares down to what [`EpochSummary::build`] will accept: attributed, and
/// carrying a difficulty some proof of work stands behind.
///
/// Screened here rather than left for `build` to refuse because `build` refuses the WHOLE epoch:
/// one damaged share would wedge the fold forever, retried every tick — a check that cannot fail
/// paired with a log that cannot speak. Excluding the share loses nothing (work with no payout
/// address is attributable to nobody), and the count is reported so it cannot happen silently.
fn screen(shares: Vec<ShareProof>) -> (Vec<ShareProof>, usize) {
    let before = shares.len();
    let evidence: Vec<ShareProof> = shares
        .into_iter()
        .filter(|s| s.payout_address.is_some() && creditable_difficulty(s.difficulty))
        .collect();
    let screened_out = before - evidence.len();
    (evidence, screened_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::share_batch::micro_work;
    use ghost_storage::models::{PayoutStatus, RoundRecord, ShareRecord};

    /// One runtime over a fresh in-memory database, non-solo.
    fn runtime() -> (Arc<NodeIdentity>, Arc<Database>, ShardRuntime) {
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        let rt =
            ShardRuntime::load(Arc::clone(&identity), Arc::clone(&db), false, true).expect("load");
        // Fixtures that stamp the payout tag are only OURS if its id resolves to a proposal we
        // hold — tag presence alone is a sibling deployment's block. Seeded here so the tagged
        // fixtures mean what they read as; the foreign-block test stamps no tag and is unaffected.
        seed_owning_proposal(&db);
        (identity, db, rt)
    }

    fn our_received_by(identity: &NodeIdentity) -> String {
        hex::encode(&identity.node_id()[..8])
    }

    /// The adopted blob for the pinned anchor, reconstructed exactly as production stores it.
    /// Kept here rather than exported from the accounting crate's tests so this suite exercises
    /// the same public entry point an operator's ceremony will.
    fn pinned_canonical_blob() -> Vec<u8> {
        let miner_payouts: Vec<(String, u128)> = vec![
            ("bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".into(), 57_371_941_344_568_806_473_728),
            ("bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".into(), 2_609_462_108_645_369_053_184),
            ("bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".into(), 2_503_874_639_417_892_143_104),
            ("148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN".into(), 528_968_877_836_852_002_816),
            ("bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h".into(), 9_741_908_758_669_000_704),
        ];
        let hx = |s: &str| -> [u8; 32] {
            let mut o = [0u8; 32];
            o.copy_from_slice(&hex::decode(s).unwrap());
            o
        };
        let node_shares: Vec<([u8; 32], i32)> = vec![
            (hx("46141044f80c99ac01476b3c2d6cd2149f31b5f1b06ffd2dfa3d15d588c7a39b"), 6),
            (hx("fb71fee87bb0516920fdb673f3068be3c0b9b29fc62e309b99594a0008c25622"), 10),
            (hx("849bceceb22cc7ebbeec252d824940ebb73ee08c7855c5a90b5661dd21aeb18c"), 10),
            (hx("e557c97a32335457ed6eceb6f8a9c7ee13f8731ee99dc9f4b7831dcf606d6927"), 10),
            (hx("9fe860bda96ff81820a2e166f48cb3ae59010fc9e42550a3aeafb5bfef4d1b38"), 10),
            (hx("5867b555602257bdffa5d4c3577c464416087f2aa04ac478f3986a17e51d3393"), 6),
            (hx("f0215f1ffd9a711ffc8e476f37bf3e19a2afc18803d146ecedb5d53d4fe9bd4f"), 6),
            (hx("4c8c2272ae67d76c6c4108f0e4e6dfde7ff864689d3e9b99a35ab1bd46051132"), 6),
        ];
        serde_json::to_vec(&(&miner_payouts, &node_shares)).expect("encodable")
    }

    /// Arming replaces the soak's state, opens on the pinned balances, and restarts the epoch
    /// watermark at the floor — the whole ceremony, on the public entry point.
    #[test]
    fn arming_replaces_soak_state_and_restarts_the_watermark_at_the_floor() {
        let (identity, _db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();

        // Stand in for the Stage 4 soak: this node has accrued its own work already.
        {
            let mut t = rt.table.lock();
            t.accrue(identity.node_id(), "bc1qsoak", 12_345);
        }
        assert_eq!(rt.table.lock().accrued().len(), 1);

        let report = rt
            .arm_from_genesis(&anchor, &pinned_canonical_blob())
            .expect("arming must succeed on the pinned bytes");

        assert_eq!(report.anchor_height, anchor.height);
        assert_eq!(report.opening_addresses, 5);
        assert_eq!(report.replaced_columns, 1, "the soak's column is discarded");
        assert_eq!(report.table_root, anchor.table_root);

        let t = rt.table.lock();
        // The soak's work is gone: it is already inside the genesis balances, and leaving it as a
        // second column is exactly the double count the floor exists to prevent.
        assert!(!t.accrued().contains_key(&identity.node_id()));
        assert!(!t.owed().contains_key("bc1qsoak"));
        assert_eq!(
            t.owed().get("bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492"),
            Some(&57_371_941_344_568_806)
        );

        // Floor is the anchor's epoch PLUS ONE — folding the anchor's own epoch would re-credit
        // the part of it genesis already covers.
        let expected_floor = epoch_for_height(anchor.height, EPOCH_BLOCKS) + 1;
        assert_eq!(report.epoch_floor, expected_floor);
        assert_eq!(t.epoch_floor(), expected_floor);
        drop(t);
        assert_eq!(*rt.next_fold.lock(), Some(expected_floor));
    }

    /// Arming must survive a restart: the ceremony writes through to storage, and the load-time
    /// self-check must accept what it wrote.
    #[test]
    fn an_armed_table_reloads_intact_and_passes_its_own_self_check() {
        let (identity, db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        let report = rt
            .arm_from_genesis(&anchor, &pinned_canonical_blob())
            .expect("arm");

        let reloaded = ShardRuntime::load(identity, Arc::clone(&db), false, true)
            .expect("an armed table must pass the load-time genesis check");
        assert_eq!(
            reloaded.table.lock().compute_table_root(),
            report.table_root,
            "the opening root must survive a restart"
        );
    }

    /// Bytes the ceremony did not verify must not arm the node, and must leave it untouched.
    #[test]
    fn arming_refuses_bytes_that_are_not_the_pinned_anchor() {
        let (_identity, _db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        let mut wrong = pinned_canonical_blob();
        wrong.push(b' ');

        let before = rt.table.lock().compute_table_root();
        assert!(rt.arm_from_genesis(&anchor, &wrong).is_err());
        assert_eq!(
            rt.table.lock().compute_table_root(),
            before,
            "a refused arming must leave the table byte-identical"
        );
        assert_eq!(rt.table.lock().epoch_floor(), 0, "and must not arm the floor");
    }

    fn seed_round(db: &Database, round_id: u64, block_height: u64) {
        db.create_round(&RoundRecord {
            round_id,
            block_height,
            block_hash: None,
            start_time: 1_000,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        })
        .expect("round");
    }

    /// Insert a share the way ingest does: row + canonical proof JSON, hex hash, internal order.
    /// Each argument is one eligibility axis the tests vary independently — that is the point of
    /// the width, so a fixture struct would only rename the problem.
    #[allow(clippy::too_many_arguments)]
    fn seed_share(
        db: &Database,
        round_id: u64,
        hash_byte: u8,
        addr: &str,
        difficulty: f64,
        tier: Option<u32>,
        received_by: &str,
        valid: bool,
    ) {
        let proof = ShareProof {
            round_id,
            miner_id: [7u8; 32],
            difficulty,
            work: difficulty,
            share_hash: [hash_byte; 32],
            timestamp: 1_000,
            received_by: [0u8; 32],
            template_id: None,
            payout_address: Some(addr.to_string()),
            header: None,
            tier_log2: tier,
            signature: None,
        };
        let record = ShareRecord {
            id: None,
            round_id,
            miner_id: "shardminer".to_string(),
            difficulty,
            work: difficulty,
            share_hash: hex::encode([hash_byte; 32]),
            timestamp: 1_000,
            received_by: received_by.to_string(),
            valid,
        };
        db.insert_share_with_proof(&record, &serde_json::to_vec(&proof).expect("json"))
            .expect("share");
    }

    /// How many eligible shares an epoch still holds — presence-of-evidence, through the same
    /// query the fold uses.
    fn evidence_count(db: &Database, epoch: u64, rx: &str) -> usize {
        db.shard_epoch_shares(epoch, EPOCH_BLOCKS, rx, NETWORK_TIER_LOG2)
            .expect("query")
            .shares
            .len()
    }

    /// An epoch folds exactly once. The re-fold — same process or after a restart — is a no-op:
    /// same owed, same persisted column, never a second credit. This is THE money property; a
    /// re-fold that credits again pays the same work twice.
    #[test]
    fn an_epoch_folds_exactly_once_and_a_refold_is_a_noop() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        // Epoch 100 spans heights 600..=605 at EPOCH_BLOCKS = 6.
        seed_round(&db, 1, 602);
        seed_share(&db, 1, 0xA1, "bc1qalice", 2.0, Some(12), &rx, true);
        seed_share(&db, 1, 0xA2, "bc1qalice", 3.0, Some(12), &rx, true);

        let outcome = rt.fold_epoch(100).expect("fold");
        let FoldOutcome::Folded(report) = outcome else {
            panic!("first fold must fold");
        };
        assert_eq!(report.shares_folded, 2);
        assert_eq!(
            rt.owed().get("bc1qalice"),
            Some(&micro_work(5.0)),
            "the fold credits the epoch's work once"
        );
        let root_after = rt.table_root();
        let persisted_after = db.shard_load_table().expect("load").compute_table_root();

        assert_eq!(
            rt.fold_epoch(100).expect("refold"),
            FoldOutcome::AlreadyFolded,
            "a re-fold is a no-op"
        );
        assert_eq!(rt.owed().get("bc1qalice"), Some(&micro_work(5.0)));
        assert_eq!(rt.table_root(), root_after);
        assert_eq!(
            db.shard_load_table().expect("load").compute_table_root(),
            persisted_after,
            "the persisted column must be untouched by a re-fold"
        );

        // And across a restart: the summary row is the durable marker, so a fresh runtime
        // reaches the same verdict.
        let rt2 = ShardRuntime::load(identity, db, false, true).expect("reload");
        assert_eq!(
            rt2.fold_epoch(100).expect("refold"),
            FoldOutcome::AlreadyFolded
        );
        assert_eq!(rt2.owed().get("bc1qalice"), Some(&micro_work(5.0)));
    }

    /// Eligibility end to end: a peer's share, an invalid share and a sub-tier share all sit in
    /// the epoch's height range, and none of them may fold — each is a distinct money bug (a
    /// peer's share double-credits once its receiver's summary merges; sub-tier work is local by
    /// design, §4.2).
    #[test]
    fn only_own_received_valid_network_tier_shares_are_folded() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        seed_round(&db, 1, 602);
        seed_share(
            &db,
            1,
            0xA1,
            "bc1qalice",
            2.0,
            Some(NETWORK_TIER_LOG2),
            &rx,
            true,
        );
        seed_share(
            &db,
            1,
            0xB1,
            "bc1qalice",
            2.0,
            Some(12),
            "eeff001122334455",
            true,
        );
        seed_share(&db, 1, 0xB2, "bc1qalice", 2.0, Some(12), &rx, false);
        seed_share(
            &db,
            1,
            0xB3,
            "bc1qalice",
            2.0,
            Some(NETWORK_TIER_LOG2 - 1),
            &rx,
            true,
        );

        let FoldOutcome::Folded(report) = rt.fold_epoch(100).expect("fold") else {
            panic!("must fold");
        };
        assert_eq!(
            report.shares_folded, 1,
            "only the own, valid, network-tier share"
        );
        assert_eq!(report.below_tier, 1);
        assert_eq!(
            rt.owed().get("bc1qalice"),
            Some(&micro_work(2.0)),
            "credit must come from the one eligible share alone"
        );
    }

    /// The share→epoch binding across a boundary, through the real constants: adjacent rounds
    /// one height apart fold into different epochs, and each epoch takes exactly its own.
    #[test]
    fn the_height_range_binding_splits_adjacent_epochs_correctly() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        seed_round(&db, 1, 605); // last height of epoch 100
        seed_round(&db, 2, 606); // first height of epoch 101
        seed_share(&db, 1, 0xA1, "bc1qedge", 2.0, Some(12), &rx, true);
        seed_share(&db, 2, 0xA2, "bc1qedge", 5.0, Some(12), &rx, true);

        let FoldOutcome::Folded(r100) = rt.fold_epoch(100).expect("fold 100") else {
            panic!("must fold");
        };
        assert_eq!(r100.shares_folded, 1);
        assert_eq!(rt.owed().get("bc1qedge"), Some(&micro_work(2.0)));

        let FoldOutcome::Folded(r101) = rt.fold_epoch(101).expect("fold 101") else {
            panic!("must fold");
        };
        assert_eq!(r101.shares_folded, 1);
        assert_eq!(
            rt.owed().get("bc1qedge"),
            Some(&micro_work(7.0)),
            "each epoch folded exactly its own side of the boundary"
        );
    }

    /// A fold that fails must leave EVERYTHING untouched: the in-memory counters, the persisted
    /// column, and the evidence. The failure is real, not injected — the epoch record's table is
    /// gone, so the storage transaction fails at its last step, after the column replace and any
    /// deletes have already run inside it. All of it must roll back, and the runtime's memory
    /// must never have moved.
    #[test]
    fn a_fold_failure_leaves_counters_and_evidence_untouched() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        seed_round(&db, 1, 602);
        seed_share(&db, 1, 0xA1, "bc1qalice", 2.0, Some(12), &rx, true);
        let root_before = rt.table_root();

        db.with_connection(|conn| {
            conn.execute_batch("DROP TABLE shard_epochs")
                .map_err(|e| GhostError::Database(e.to_string()))
        })
        .expect("drop");

        rt.fold_epoch(100)
            .expect_err("the fold must fail when its marker cannot be written");

        assert_eq!(
            rt.table_root(),
            root_before,
            "a failed fold must leave the in-memory counters untouched"
        );
        assert_eq!(
            db.shard_load_table().expect("load"),
            ShardTable::new(),
            "a failed fold must leave the persisted table untouched"
        );
        assert_eq!(
            evidence_count(&db, 100, &rx),
            1,
            "a failed fold must leave the evidence untouched"
        );
    }

    /// Retention (§4.3): folding epoch E drops the evidence of E − RETENTION_EPOCHS — and ONLY
    /// that. Evidence inside the window stays so peers can still sample it, and an epoch this
    /// node never summarised is never dropped: those rows are the old ledger's history, and the
    /// old ledger still pays from them.
    #[test]
    fn evidence_past_retention_is_dropped_and_evidence_inside_it_is_kept() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);

        // Epoch 99: seeded but NEVER folded — pre-shard history.
        seed_round(&db, 99, 99 * 6);
        seed_share(&db, 99, 99, "bc1qold", 2.0, Some(12), &rx, true);
        // Epochs 100..=106, one share each.
        for epoch in 100u64..=106 {
            seed_round(&db, epoch, epoch * 6);
            seed_share(
                &db,
                epoch,
                epoch as u8,
                "bc1qminer",
                2.0,
                Some(12),
                &rx,
                true,
            );
        }

        for epoch in 100u64..=105 {
            let FoldOutcome::Folded(r) = rt.fold_epoch(epoch).expect("fold") else {
                panic!("must fold");
            };
            assert_eq!(
                r.expired_epoch, None,
                "nothing expires while every folded epoch is inside the window"
            );
        }
        assert_eq!(evidence_count(&db, 100, &rx), 1, "still inside retention");

        // Folding 106 puts epoch 100 exactly RETENTION_EPOCHS behind: out it goes.
        let FoldOutcome::Folded(r) = rt.fold_epoch(106).expect("fold") else {
            panic!("must fold");
        };
        assert_eq!(r.expired_epoch, Some(106 - RETENTION_EPOCHS));
        assert_eq!(r.evidence_dropped, 1);

        assert_eq!(evidence_count(&db, 100, &rx), 0, "past retention: dropped");
        for epoch in 101u64..=106 {
            assert_eq!(
                evidence_count(&db, epoch, &rx),
                1,
                "epoch {epoch} is inside retention and its evidence must be kept"
            );
        }
        assert_eq!(
            evidence_count(&db, 99, &rx),
            1,
            "an epoch this node never summarised is not shard evidence and is never dropped"
        );

        // The credit itself outlives its evidence — dropping evidence is not un-crediting.
        assert_eq!(rt.owed().get("bc1qminer"), Some(&micro_work(14.0)));
    }

    /// Solo mode must not leak (§10): a solo node's work is its own, so nothing it does may
    /// reach the shared shard — no fold, no summary row, no counter.
    #[test]
    fn solo_mode_never_reaches_the_shared_shard() {
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        let rt =
            ShardRuntime::load(Arc::clone(&identity), Arc::clone(&db), true, true).expect("load");
        let rx = our_received_by(&identity);
        seed_round(&db, 1, 602);
        seed_share(&db, 1, 0xA1, "bc1qsolo", 2.0, Some(12), &rx, true);

        assert_eq!(
            rt.tick(613).expect("tick"),
            TickReport::default(),
            "a solo tick folds nothing"
        );
        // A later tick, with an epoch now closed behind it. This is the call that would reach a
        // fold if tick's own solo gate were missing — the first tick cannot, because a first run
        // starts its watermark at the current epoch and has nothing closed to walk.
        assert_eq!(
            rt.tick(619).expect("tick"),
            TickReport::default(),
            "a solo tick folds nothing even once epochs have closed behind it"
        );
        rt.fold_epoch(100)
            .expect_err("a direct solo fold must refuse");
        assert_eq!(db.shard_load_table().expect("load"), ShardTable::new());
        assert_eq!(
            db.shard_latest_epoch(&identity.node_id()).expect("query"),
            None,
            "no summary row may exist — a solo node signs no statement into the shard"
        );
    }

    /// The tick lifecycle: never the epoch in progress, bounded work per call, and resume — not
    /// restart — across a process restart.
    #[test]
    fn tick_folds_only_closed_epochs_bounded_and_resumes() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        for epoch in 100u64..=101 {
            seed_round(&db, epoch, epoch * 6);
            seed_share(
                &db,
                epoch,
                epoch as u8,
                "bc1qminer",
                2.0,
                Some(12),
                &rx,
                true,
            );
        }

        // First tick, inside epoch 100: the watermark initialises to the CURRENT epoch and
        // nothing folds — 100 has not closed.
        let t = rt.tick(605).expect("tick");
        assert!(t.folded.is_empty(), "the epoch in progress must not fold");
        assert_eq!(t.remaining, 0);

        // Height crosses into epoch 101: 100 has closed and folds; 101 is now in progress.
        let t = rt.tick(607).expect("tick");
        assert_eq!(
            t.folded.iter().map(|r| r.epoch).collect::<Vec<_>>(),
            vec![100]
        );

        // Into epoch 102: 101 folds. A repeat tick at the same height does nothing.
        let t = rt.tick(613).expect("tick");
        assert_eq!(
            t.folded.iter().map(|r| r.epoch).collect::<Vec<_>>(),
            vec![101]
        );
        assert_eq!(rt.tick(613).expect("tick"), TickReport::default());

        // Restart, several epochs later: the watermark re-derives from the stored summaries and
        // the walk continues from 102 — including empty epochs, which fold to an empty summary
        // so the walk can advance past them. Bounded: 102..=107 are closed (current is 108),
        // but one tick folds at most MAX_FOLDS_PER_TICK of them.
        let rt2 = ShardRuntime::load(identity, db, false, true).expect("reload");
        let t = rt2.tick(108 * 6 + 2).expect("tick");
        assert_eq!(
            t.folded.iter().map(|r| r.epoch).collect::<Vec<_>>(),
            vec![102, 103, 104, 105],
            "resume from the durable watermark, oldest first, bounded per tick"
        );
        assert_eq!(t.remaining, 2, "106 and 107 wait for the next tick");
        let t = rt2.tick(108 * 6 + 2).expect("tick");
        assert_eq!(
            t.folded.iter().map(|r| r.epoch).collect::<Vec<_>>(),
            vec![106, 107]
        );
        assert_eq!(t.remaining, 0);
        assert_eq!(
            rt2.owed().get("bc1qminer"),
            Some(&micro_work(4.0)),
            "the two seeded epochs credited once each; empty epochs credited nothing"
        );
    }

    /// `note_height` reports each boundary crossing exactly once. The first observation ever
    /// initialises silently (there is no epoch to have crossed FROM), repeats inside an epoch
    /// are false, and a height that steps backwards neither reports nor rewinds the latch.
    #[test]
    fn retention_is_withheld_while_the_legacy_ledger_owns_shares() {
        // The failure this pins is a money bug wearing a tidiness costume. Retention deletes from
        // `shares`, the same table the legacy payout path computes unpaid balances from. Delete
        // there while both ledgers are live and miners are silently owed less — roughly
        // RETENTION_EPOCHS after somebody set a flag they were told was dark. "Dark" has to mean
        // changes nothing, so the fold must compute its expiry and act on none of it.
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        // owns_evidence = false: the pre-cutover setting, and the only one that ships until
        // `shares` has been renamed out from under the legacy path.
        let rt =
            ShardRuntime::load(Arc::clone(&identity), Arc::clone(&db), false, false).expect("load");
        let rx = our_received_by(&identity);

        for epoch in 100u64..=106 {
            seed_round(&db, epoch, epoch * 6);
            seed_share(
                &db,
                epoch,
                epoch as u8,
                "bc1qminer",
                2.0,
                Some(12),
                &rx,
                true,
            );
        }
        for epoch in 100u64..=105 {
            rt.fold_epoch(epoch).expect("fold");
        }

        // Same boundary the sibling test uses: folding 106 expires 100. There, one row goes; here,
        // the expiry is still COMPUTED — so the behaviour stays observable — and acted on not at all.
        let FoldOutcome::Folded(r) = rt.fold_epoch(106).expect("fold") else {
            panic!("must fold");
        };
        assert_eq!(
            r.expired_epoch,
            Some(106 - RETENTION_EPOCHS),
            "expiry must still be computed, or the withholding is indistinguishable from a bug"
        );
        assert_eq!(
            r.evidence_dropped, 0,
            "retention must delete nothing while the legacy ledger still owns `shares`"
        );
        assert_eq!(
            evidence_count(&db, 100, &rx),
            1,
            "not one row may leave `shares` before cutover"
        );
    }

    // ---- maturity settlement ----------------------------------------------------------------
    //
    // Real bech32 addresses, because settlement matches owed addresses to coinbase outputs by
    // script — the fold tests' "bc1qalice" has no script to match.
    const ADDR_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const ADDR_B: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

    /// A coinbase scriptSig carrying our payout tag: BIP34 height push, tag, pool text.
    /// Seed a payout proposal this node holds, whose hash prefix matches [`tagged_scriptsig`].
    ///
    /// Ownership is not "the block carries a GHPP tag" — that only says *some* Ghost deployment
    /// mined it. It is "the tag's payout id resolves to a proposal WE hold". A fixture that stamps
    /// a tag without seeding the proposal is a foreign block, and settling it would discharge our
    /// miners against money this pool never received.
    fn seed_owning_proposal(db: &Database) {
        let mut hash = [0u8; 32];
        hash[..16].copy_from_slice(&[0xAB; 16]);
        db.store_payout_proposal(&hash, 1, 600, "{}")
            .expect("seed the proposal that makes the tagged fixtures ours");
    }

    fn tagged_scriptsig() -> Vec<u8> {
        let mut s = vec![0x03, 0x40, 0x1f, 0x0e];
        s.extend_from_slice(&ghost_common::coinbase_tags::encode_payout_tag(&[0xAB; 16]));
        s.extend_from_slice(b"GHOST PublicPool");
        s
    }

    /// Coinbase outputs paying the given addresses.
    /// The block subsidy a real coinbase carries. Fixtures must include it, because the discharge
    /// rate is `coinbase_total / total_owed` — an absolute number of satoshis against an absolute
    /// amount of work. A fixture whose only output is the payment makes that ratio cancel, which
    /// is precisely the self-normalising bug the rate was changed to avoid, reintroduced in the
    /// test rig instead of the code.
    const SUBSIDY_SATS: u64 = 312_500_000;

    /// A coinbase shaped like a real one: the named payments, plus the remaining subsidy paid
    /// somewhere the shard does not credit (treasury, node rewards, whatever is left).
    fn coinbase(pairs: &[(&str, u64)]) -> Vec<CoinbaseOutput> {
        let mut outs = pay(pairs);
        let paid: u64 = pairs.iter().map(|(_, s)| *s).sum();
        outs.push(CoinbaseOutput {
            value: SUBSIDY_SATS.saturating_sub(paid),
            script_pubkey: vec![0x6a],
        });
        outs
    }

    fn pay(pairs: &[(&str, u64)]) -> Vec<CoinbaseOutput> {
        pairs
            .iter()
            .map(|(addr, sats)| CoinbaseOutput {
                value: *sats,
                script_pubkey: address_to_script_pubkey(addr.as_bytes())
                    .expect("test address must convert to a script pubkey"),
            })
            .collect()
    }

    /// Accrue owed work for settlement tests: one epoch-100 round, one share per (address,
    /// work) pair, folded — so `owed` holds real folded balances, not hand-planted ones.
    fn accrue(db: &Database, rt: &ShardRuntime, rx: &str, work_by_addr: &[(&str, f64)]) {
        seed_round(db, 1, 602);
        for (i, (addr, work)) in work_by_addr.iter().enumerate() {
            seed_share(db, 1, 0xC0 + i as u8, addr, *work, Some(12), rx, true);
        }
        let FoldOutcome::Folded(_) = rt.fold_epoch(100).expect("fold") else {
            panic!("the accrual fold must fold");
        };
    }

    /// How many settled-block records exist — the idempotence ledger, directly.
    fn settled_block_count(db: &Database) -> i64 {
        db.with_connection(|conn| {
            conn.query_row("SELECT COUNT(*) FROM shard_settled_blocks", [], |r| {
                r.get(0)
            })
            .map_err(|e| GhostError::Database(e.to_string()))
        })
        .expect("count")
    }

    /// THE money property of settlement: a matured pool block settles exactly once. The re-run —
    /// same process or after a restart — is a no-op: same owed, same root, never a second
    /// discharge. A second discharge is the same payment shrinking the same debt twice.
    #[test]
    fn a_matured_pool_block_settles_exactly_once_and_a_rerun_is_a_noop() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        accrue(&db, &rt, &rx, &[(ADDR_A, 5.0)]);
        assert_eq!(rt.owed().get(ADDR_A), Some(&micro_work(5.0)));

        let sig = tagged_scriptsig();
        let outs = pay(&[(ADDR_A, 250_000)]);
        // Block at 602, tip at 702: exactly COINBASE_MATURITY deep.
        let outcome = rt
            .settle_block_from_coinbase(702, "00aa", 602, &sig, &outs)
            .expect("settle");
        let SettleBlockOutcome::Settled(s) = outcome else {
            panic!("a matured pool block must settle, got {outcome:?}");
        };
        assert_eq!(
            s.discharged_micro,
            micro_work(5.0),
            "the sole paid address's full owed work discharges"
        );
        assert_eq!(
            rt.owed().get(ADDR_A),
            Some(&0),
            "paid work is no longer owed"
        );

        let root_after = rt.table_root();
        assert_eq!(
            rt.settle_block_from_coinbase(702, "00aa", 602, &sig, &outs)
                .expect("re-run"),
            SettleBlockOutcome::AlreadySettled,
            "a re-run must be a no-op"
        );
        assert_eq!(rt.owed().get(ADDR_A), Some(&0));
        assert_eq!(rt.table_root(), root_after);
        assert_eq!(settled_block_count(&db), 1);

        // Across a restart: the recorded block hash is the durable marker, so a fresh runtime
        // reaches the same verdict from the same chain.
        let rt2 = ShardRuntime::load(identity, db, false, true).expect("reload");
        assert_eq!(rt2.owed().get(ADDR_A), Some(&0));
        assert_eq!(rt2.table_root(), root_after);
        assert_eq!(
            rt2.settle_block_from_coinbase(702, "00aa", 602, &sig, &outs)
                .expect("re-run after restart"),
            SettleBlockOutcome::AlreadySettled
        );
    }

    /// A block below maturity depth is NOT settled — its payment can still be undone by a reorg
    /// and the shard carries no undo, so settling it would need the reversal machinery this
    /// design exists to not need. Nothing is recorded either: once the block matures it settles
    /// in full through the same path.
    #[test]
    fn a_block_below_maturity_depth_is_not_settled() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        accrue(&db, &rt, &rx, &[(ADDR_A, 5.0)]);

        let sig = tagged_scriptsig();
        let outs = pay(&[(ADDR_A, 250_000)]);
        // Block at 602, tip at 701: 99 deep — one short.
        assert_eq!(
            rt.settle_block_from_coinbase(701, "00bb", 602, &sig, &outs)
                .expect("attempt"),
            SettleBlockOutcome::Immature
        );
        assert_eq!(
            rt.owed().get(ADDR_A),
            Some(&micro_work(5.0)),
            "an immature block must discharge nothing"
        );
        assert_eq!(
            settled_block_count(&db),
            0,
            "an immature block must not be recorded — it is not settled, not settled-with-zero"
        );

        // One block later it is exactly at maturity, and settles in full.
        let SettleBlockOutcome::Settled(s) = rt
            .settle_block_from_coinbase(702, "00bb", 602, &sig, &outs)
            .expect("settle at maturity")
        else {
            panic!("the block must settle once mature");
        };
        assert_eq!(s.discharged_micro, micro_work(5.0));
        assert_eq!(rt.owed().get(ADDR_A), Some(&0));
    }

    /// The discharge arithmetic (§4.6): `settled` increases by the payment converted at
    /// `top_work / pool_sats`, and `owed` falls by exactly that — signed, never clamped. Equal
    /// payments against unequal balances leave one address still owed and the other negative,
    /// which IS the correction that makes independent payout views converge.
    #[test]
    fn settled_increases_and_owed_falls_by_the_discharged_amount() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        accrue(&db, &rt, &rx, &[(ADDR_A, 5.0), (ADDR_B, 3.0)]);

        // Equal payments: pool_sats = 800_000 over top_work = 8_000_000, so each 400_000-sat
        // payment discharges 4_000_000 micro-work regardless of who was owed what.
        let outs = pay(&[(ADDR_A, 400_000), (ADDR_B, 400_000)]);
        let SettleBlockOutcome::Settled(s) = rt
            .settle_block_from_coinbase(702, "00cc", 602, &tagged_scriptsig(), &outs)
            .expect("settle")
        else {
            panic!("must settle");
        };
        assert_eq!(s.addresses, 2);
        assert_eq!(s.discharged_micro, 8_000_000);

        let owed = rt.owed();
        assert_eq!(
            owed.get(ADDR_A),
            Some(&1_000_000),
            "A was owed 5.0 and discharged 4.0 — the remainder stays owed"
        );
        assert_eq!(
            owed.get(ADDR_B),
            Some(&-1_000_000),
            "B was owed 3.0 and discharged 4.0 — the overpayment goes NEGATIVE, never clamped"
        );

        // The persisted table agrees cell for cell: settled grew by exactly the discharge, and
        // a restart resumes from the same truth this runtime holds.
        let loaded = db.shard_load_table().expect("load");
        assert_eq!(loaded.settled().get(ADDR_A), Some(&4_000_000));
        assert_eq!(loaded.settled().get(ADDR_B), Some(&4_000_000));
        assert_eq!(loaded.compute_table_root(), rt.table_root());
    }

    /// A full payout discharges the full work; a partial payout — the coinbase paid only some
    /// of the owed addresses — leaves the rest owed, untouched, for the next block to pay. The
    /// unpaid address must play no part in the paid one's rate.
    #[test]
    fn a_full_payout_discharges_all_and_a_partial_leaves_the_remainder_owed() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        accrue(&db, &rt, &rx, &[(ADDR_A, 5.0), (ADDR_B, 3.0)]);

        // The rate is ABSOLUTE: `coinbase_total / total_owed`. This block's coinbase carries a
        // full subsidy and pays A a slice of it, so A discharges that slice's worth of work — not
        // A's whole balance. B, unpaid, is untouched.
        //
        // discharged_A = 250_000 × 8_000_000 / 312_500_000 = 6_400 micro-work.
        let SettleBlockOutcome::Settled(s) = rt
            .settle_block_from_coinbase(
                702,
                "00dd",
                602,
                &tagged_scriptsig(),
                &coinbase(&[(ADDR_A, 250_000)]),
            )
            .expect("partial")
        else {
            panic!("must settle");
        };
        assert_eq!(s.addresses, 1);
        assert_eq!(
            s.discharged_micro, 6_400,
            "a slice of the subsidy buys a slice of the work"
        );
        assert_eq!(
            rt.owed().get(ADDR_A),
            Some(&(micro_work(5.0) - 6_400)),
            "A keeps the work the payment did not buy"
        );
        assert_eq!(
            rt.owed().get(ADDR_B),
            Some(&micro_work(3.0)),
            "the unpaid address keeps its full remainder owed"
        );

        // A block that pays its WHOLE coinbase to the owed set discharges the whole ledger — and
        // does so however the split falls, because `Σpaid == coinbase_total` makes the rate exact.
        // That is the identity the target design relies on once the coinbase is built from the
        // shard; here it is reached only because this fixture hands out every satoshi.
        let owed_now = rt.owed();
        let remaining: i64 = owed_now.values().filter(|m| **m > 0).sum();
        let a_share = 200_000_000u64;
        let SettleBlockOutcome::Settled(s) = rt
            .settle_block_from_coinbase(
                703,
                "00ee",
                603,
                &tagged_scriptsig(),
                &pay(&[(ADDR_A, a_share), (ADDR_B, SUBSIDY_SATS - a_share)]),
            )
            .expect("remainder")
        else {
            panic!("must settle");
        };
        assert_eq!(
            s.discharged_micro, remaining,
            "paying out the entire coinbase discharges the entire ledger"
        );

        // The TOTAL is exact; the individual residuals are not, because this split does not match
        // the owed proportions — A was handed more than its share and B less. That is the design
        // working rather than failing: `owed` is signed and never clamped (§4.4), so the
        // over-discharged address carries a negative balance and accrues back up while the
        // under-discharged one stays owed. What must hold is that the two cancel.
        let after = rt.owed();
        let a = *after.get(ADDR_A).unwrap_or(&0);
        let b = *after.get(ADDR_B).unwrap_or(&0);
        assert!(
            a < 0,
            "the over-paid address carries a negative residual, not a clamped zero"
        );
        assert!(b > 0, "the under-paid address is still owed");
        assert_eq!(
            a + b,
            0,
            "and the residuals cancel exactly — no work invented or lost"
        );
    }

    /// A block without our tag discharges nothing and is not recorded — every block anyone
    /// mines passes through this path, and the common case must leave no trace at all.
    #[test]
    fn a_corrupt_cursor_halts_rather_than_fast_forwarding_past_unsettled_blocks() {
        // ABSENT and UNPARSEABLE shared a branch, and the difference is unpaid work. Absent is a
        // first run: fast-forwarding to today's boundary is correct, because history that matured
        // before the shard existed belongs to the legacy ledger. Unparseable is corruption of a
        // cursor that HAD a position — fast-forwarding there skips every pool block between the
        // real position and now, discharges nothing for them, and says nothing.
        let (_identity, db, rt) = runtime();
        let tip = 10_000u64;

        // Absent: initialise, settle nothing this call, and leave a usable cursor behind.
        assert_eq!(rt.settle_window(tip).expect("absent"), None);
        let initialised = db.kv_get(SETTLE_CURSOR_KEY).expect("get").expect("set");
        assert_eq!(initialised, (tip - COINBASE_MATURITY).to_string());

        // Corrupt: refuse to run at all. Halting is loud and recoverable; fast-forwarding is
        // silent and is not.
        db.kv_set(SETTLE_CURSOR_KEY, "not-a-height")
            .expect("corrupt");
        assert_eq!(
            rt.settle_window(tip).expect("corrupt"),
            None,
            "a corrupt cursor must halt settlement"
        );
        assert_eq!(
            db.kv_get(SETTLE_CURSOR_KEY).expect("get").as_deref(),
            Some("not-a-height"),
            "and must NOT be overwritten with a fast-forward that hides what was skipped"
        );
    }

    #[test]
    fn a_tiny_payment_cannot_clear_a_large_balance() {
        // The bug this pins was self-normalisation: with `pool_sats` and `top_work` both summed
        // over the MATCHED set, the ratio cancels and Σdischarged always equals Σowed — so a
        // one-satoshi block cleared every matched balance in full, and every miner it touched was
        // marked paid for money they never received.
        //
        // The inversion is only valid when the coinbase was built from this node's shard view. It
        // is not; it is still built from the legacy proposal. So the rate must be absolute.
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);

        seed_round(&db, 900, 900 * 6);
        seed_share(&db, 900, 90, ADDR_A, 1_000.0, Some(12), &rx, true);
        rt.fold_epoch(900).ok();

        let owed_before = *rt.owed().get(ADDR_A).unwrap_or(&0);
        assert!(owed_before > 0, "fixture must leave ADDR_A genuinely owed");

        // A block whose entire coinbase is one satoshi to that address.
        rt.settle_block_from_coinbase(
            5_502,
            "00ff",
            5_402,
            &tagged_scriptsig(),
            &coinbase(&[(ADDR_A, 1)]),
        )
        .expect("settle");

        let owed_after = *rt.owed().get(ADDR_A).unwrap_or(&0);
        assert!(
            owed_after > 0,
            "one satoshi must not clear a balance of {owed_before} micro-work; owed is now \
             {owed_after}"
        );
        assert!(
            owed_after < owed_before || owed_before == 0,
            "a real payment should still discharge something"
        );
    }

    #[test]
    fn a_foreign_block_neither_discharges_nor_is_recorded() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        accrue(&db, &rt, &rx, &[(ADDR_A, 5.0)]);

        // A plausible foreign coinbase — height push, someone else's text — that even pays an
        // address we hold owed work for. Without the tag it is not the pool paying a debt.
        let mut foreign = vec![0x03, 0x40, 0x1f, 0x0e];
        foreign.extend_from_slice(b"/SomeOtherPool/");
        assert_eq!(
            rt.settle_block_from_coinbase(702, "00ff", 602, &foreign, &pay(&[(ADDR_A, 250_000)]))
                .expect("attempt"),
            SettleBlockOutcome::NotOurs
        );
        assert_eq!(rt.owed().get(ADDR_A), Some(&micro_work(5.0)));
        assert_eq!(settled_block_count(&db), 0);
    }

    /// The per-call bound: one call settles at most MAX_SETTLES_PER_CALL blocks and defers the
    /// rest to the next call — storage is one `Mutex<Connection>` shared with share ingest, and
    /// a node catching up must resume, not stall the pool. Deferred blocks are NOT lost: the
    /// next call settles them.
    #[test]
    fn the_per_call_settle_bound_holds_and_deferred_blocks_carry_over() {
        let (identity, db, rt) = runtime();
        let rx = our_received_by(&identity);
        accrue(&db, &rt, &rx, &[(ADDR_A, 5.0)]);

        // Six matured pool blocks. The first fully discharges A; the rest are pool blocks that
        // pay an address no longer positively owed, which still settle (recorded, zero credit).
        let blocks: Vec<FetchedCoinbase> = (0..6u64)
            .map(|i| FetchedCoinbase {
                block_hash: format!("b{i}"),
                height: 602 + i,
                scriptsig: tagged_scriptsig(),
                outputs: pay(&[(ADDR_A, 100_000)]),
            })
            .collect();

        let report = rt.settle_fetched(800, &blocks).expect("first call");
        assert_eq!(
            report.settled.len(),
            MAX_SETTLES_PER_CALL,
            "one call settles at most the bound"
        );
        assert_eq!(report.deferred, 2, "the rest is deferred, not dropped");
        assert_eq!(settled_block_count(&db), MAX_SETTLES_PER_CALL as i64);

        // The next call finds the settled four already recorded and settles the deferred two.
        let report = rt.settle_fetched(800, &blocks).expect("second call");
        assert_eq!(report.already_settled, 4);
        assert_eq!(report.settled.len(), 2);
        assert_eq!(report.deferred, 0);
        assert_eq!(settled_block_count(&db), 6);

        // A third call has nothing left to do.
        let report = rt.settle_fetched(800, &blocks).expect("third call");
        assert_eq!(report.already_settled, 6);
        assert!(report.settled.is_empty());

        // And across all of it, A's work discharged exactly once.
        assert_eq!(rt.owed().get(ADDR_A), Some(&0));
    }

    #[test]
    fn note_height_reports_each_boundary_exactly_once() {
        let (_identity, _db, rt) = runtime();
        let seen: Vec<bool> = [600u64, 601, 605, 606, 607, 611, 612, 600, 612]
            .iter()
            .map(|&h| rt.note_height(h))
            .collect();
        assert_eq!(
            seen,
            vec![false, false, false, true, false, false, true, false, false],
            "true exactly at the first height inside each NEW epoch: 606 (epoch 101) and \
             612 (epoch 102); never at initialisation, repeats, or a reorg's step back"
        );
    }
}
