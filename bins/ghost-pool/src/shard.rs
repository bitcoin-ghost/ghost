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
use ghost_common::share_batch::{canonical_sort, creditable_difficulty};
use ghost_common::share_shard::{
    discharged_micro_work, epoch_for_height, EpochSummary, ShardTable, EPOCH_BLOCKS,
    NETWORK_TIER_LOG2, RETENTION_EPOCHS,
};
use ghost_common::types::ShareProof;
use ghost_common::zmq::block_hash_to_display_order;
use ghost_reconciliation::batch::{compute_merkle_proof, compute_merkle_root};
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

/// What a gossiped summary did to the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMergeOutcome {
    /// Merged into the peer's column; the table root is the §12.6 comparison value.
    ///
    /// `summary_retained` carries the reason the peer's signed summary could NOT be stored, when
    /// that happens — the counter moved but the evidence next epoch's chain check needs did not.
    Merged {
        addresses: usize,
        table_root: [u8; 32],
        summary_retained: Option<String>,
    },
    /// Solo mode: the shared shard is not this node's business (§10).
    SoloRefused,
    /// The sender is not in the fleet's ratified node set. Until §6 sampling exists, an
    /// unrecognised node's counters are an unverified assertion that a max would make permanent.
    NotAdmitted,
    /// Our own summary came back to us. Not an error, and not a contribution.
    OwnEcho,
    /// Verification refused it. Expected traffic during a rolling cutover (a pre-genesis epoch,
    /// or a peer running a different genesis), so it is reported rather than treated as a fault.
    Rejected(String),
}

/// What a whole-table sync did (§12.6 receiving side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TableSyncMerge {
    /// Applied. `columns_gained` counts peer columns this node held NOTHING for before — the
    /// number that matters, because that is the gap epoch summaries cannot close.
    Applied {
        columns_gained: usize,
        columns_raised: usize,
        roots_match: bool,
        table_root: [u8; 32],
    },
    /// Solo mode: the shared shard is not this node's business (§10).
    SoloRefused,
    /// Our own table came back to us.
    OwnEcho,
    /// The responder is not in the fleet's ratified node set. A whole table from a stranger is a
    /// far larger unverified assertion than a single summary, and a max would make it permanent.
    NotAdmitted,
    /// Verification refused it — non-canonical, bad signature, or a different genesis.
    Rejected(String),
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
    /// Epoch summary rows cleared so the catch-up can genuinely re-fold them.
    pub cleared_epochs: usize,
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
    /// §6 audits this node has sent and not yet resolved, keyed by `(target, epoch)`.
    ///
    /// The request and the summary it was drawn against MUST both survive until the response
    /// arrives: `verify_sample_response` binds all three together, and re-deriving the request
    /// later would change the leaf indices (the selection is a function of the private entropy).
    ///
    /// ⚠ In memory only, and deliberately. The entropy's whole job is to be unpredictable to the
    /// node being audited, so persisting it widens who can learn it for no benefit — an audit lost
    /// to a restart costs one sample, which is exactly what a retry is for.
    pending_samples: Mutex<BTreeMap<(ghost_common::types::NodeId, u64), PendingSample>>,
    /// Nodes proven, by §12.4 evidence, to have committed a share they cannot back.
    ///
    /// ⚠ This does NOT un-credit them. The counters are grow-only and there is no arm for
    /// "remove a liar's work" — a max cannot be undone, which is the same property that makes the
    /// merge safe. What quarantine buys is that we stop accepting anything FURTHER from them: no
    /// new summary, no whole-table sync. Their existing column stands, and correcting it is a
    /// fleet decision, not something one node does quietly on its own.
    ///
    /// In memory only. A restart clears it, and that is the honest behaviour: the evidence is on
    /// the wire and re-arrives, whereas a persisted accusation would outlive the ability to
    /// re-derive it and become an unfalsifiable mark on a node's record.
    quarantined: Mutex<std::collections::BTreeSet<ghost_common::types::NodeId>>,
}

/// An audit in flight: what we asked, and the commitment we asked it against.
#[derive(Debug, Clone)]
struct PendingSample {
    request: ghost_consensus::message::ShardSampleRequestMessage,
    summary: EpochSummary,
    /// When it was sent, so a response that never comes can be expired rather than held for ever.
    sent_at: std::time::Instant,
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

        // Re-derive the pre-genesis floor rather than persisting it.
        //
        // ⚠ It is NOT enough to set the floor at arming. `shard_save_table` stamps `updated_epoch`
        // on rows but that is diagnosis only, and `shard_load_table` rebuilds from an empty table —
        // so without this the floor would last exactly one process lifetime, and the first restart
        // of an armed node would re-open both merge paths to pre-genesis summaries from unarmed
        // peers. Merging is a max, so that inflation is permanent, and `compute_table_root` does
        // not cover the floor, so the fleet root comparison could not see it either.
        //
        // Derived from the pin, not stored: the pin is in the binary, the genesis column says
        // whether we are armed, and state that can be derived is state that cannot drift.
        let mut table = table;
        let armed = table
            .accrued()
            .contains_key(&ghost_accounting::shard_genesis::GENESIS_NODE_ID);
        if armed {
            table.set_epoch_floor(epoch_for_height(anchor.height, EPOCH_BLOCKS) + 1);
        }

        let received_by = hex::encode(&identity.node_id()[..8]);
        info!(
            columns = table.accrued().len(),
            genesis_installed = armed,
            epoch_floor = table.epoch_floor(),
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
            pending_samples: Mutex::new(BTreeMap::new()),
            quarantined: Mutex::new(std::collections::BTreeSet::new()),
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
        // The load-time self-check compares against the PINNED anchor, so arming with any other
        // would install a genesis column this node refuses to load on its next restart — an armed
        // node whose shard never comes back. Re-pinning at ceremony time is a source change and a
        // new binary, not a runtime argument.
        if *anchor != ghost_accounting::shard_genesis::pinned_anchor() {
            return Err(GhostError::Database(
                "shard: refusing to arm from an anchor that is not the compile-time pin — the \
                 load-time self-check would reject the result on the next restart"
                    .to_string(),
            ));
        }

        let (genesis, rounding) =
            ghost_accounting::shard_genesis::open_shard_from_checkpoint(canonical_payout, anchor)
                .map_err(|e| GhostError::Database(e.to_string()))?;

        let floor = epoch_for_height(anchor.height, EPOCH_BLOCKS) + 1;

        // Held across the whole ceremony, INCLUDING the watermark write. Dropping it early would
        // let a `tick` blocked on this lock fold an epoch into the just-replaced table and then
        // have its watermark overwritten underneath it.
        let mut table = self.table.lock();
        let mut next_fold = self.next_fold.lock();

        // Arming is once. A re-run — a retried rollout, a script invoked twice — would discard
        // every column accrued since the first arming, and (because the epoch markers below are
        // already cleared and re-folded) that work would not come back.
        if table
            .accrued()
            .contains_key(&ghost_accounting::shard_genesis::GENESIS_NODE_ID)
        {
            return Err(GhostError::Database(
                "shard: already armed — the genesis column is installed; refusing to re-run the \
                 ceremony"
                    .to_string(),
            ));
        }

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

        // Persist BEFORE mutating memory, like every other money path in this file. If the write
        // fails, the operator is told arming failed and the live runtime is still holding the
        // pre-ceremony table — rather than being told it failed while running wiped and armed
        // against an unchanged database.
        //
        // Two writes, and the order between them matters more than their atomicity: clearing the
        // epoch markers is what lets the catch-up re-credit, so it must not be left undone if the
        // table write succeeds. Doing it first means the worst interleaving re-folds epochs into a
        // table that still holds the soak's columns — visible, and corrected by re-running arming
        // (which is refused only once the genesis column is actually installed).
        // Clear EVERY node's summaries at/above the floor, not just our own.
        //
        // Arming re-folds ~dozens of epochs with different totals. Peers hold our PRE-arming
        // summaries for those epochs, and a same-epoch lookup with different signing bytes is
        // `SummaryEquivocation` — an honest node accused of signing two conflicting statements,
        // by the ceremony itself. `store_epoch_tx` then refuses to overwrite the held row, so the
        // accusation sticks and every re-fold is rejected again. Those rows describe a
        // pre-genesis ledger; genesis is a reset, so they go with it.
        let cleared_epochs = self.db.shard_clear_all_epochs_from(floor)?;
        self.db.shard_save_table(&genesis, floor, anchor.height)?;

        *table = genesis;
        table.set_epoch_floor(floor);
        let root = table.compute_table_root();
        *next_fold = Some(floor);

        let opening_addresses = table
            .accrued()
            .get(&ghost_accounting::shard_genesis::GENESIS_NODE_ID)
            .map(|c| c.len())
            .unwrap_or(0);

        info!(
            anchor_height = anchor.height,
            floor,
            replaced_columns,
            cleared_epochs,
            opening_addresses,
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
            cleared_epochs,
            opening_addresses,
            table_root: root,
        })
    }

    /// This node's own summaries still waiting to go on the wire, oldest first.
    ///
    /// ⚠ **Solo mode publishes nothing.** A solo node's work is its own (§10); putting its
    /// summaries on the mesh would fold that work into the shared shard and pay it twice — once
    /// by the solo node's own coinbase and once by whoever wins from the shared table. The gate
    /// sits here rather than in the caller for the same reason `tick` and `fold_epoch` carry it:
    /// one missed call site leaks silently and there is no signal that it happened.
    pub fn pending_broadcasts(&self, limit: u32) -> GhostResult<Vec<EpochSummary>> {
        if self.solo {
            return Ok(Vec::new());
        }
        self.db
            .shard_unpublished_epochs(&self.identity.node_id(), limit)
    }

    /// Record that a summary reached the mesh, so it is not re-broadcast for ever.
    ///
    /// Called only AFTER the broadcast returns Ok. Marking first would lose a summary whose send
    /// failed, and the flag is the only record that it still needs sending.
    pub fn mark_broadcast(&self, epoch: u64) -> GhostResult<bool> {
        self.db
            .shard_mark_epoch_published(epoch, &self.identity.node_id())
    }

    /// Merge a peer's verified epoch summary into its own column — the receive half of gossip.
    ///
    /// Verification strictly precedes mutation (§12.3): a max cannot be undone, so an unverified
    /// counter that reaches the table has already won. The chain check needs the peer's PREVIOUS
    /// summary, which is read from storage; absent, the summary is still admissible — a node
    /// joining mid-stream cannot have it, and refusing would make "behind" mean "wrong".
    ///
    /// On success the peer's column is persisted so the merge survives a restart, and the caller
    /// gets the table root back for the §12.6 comparison.
    ///
    /// The table lock is taken and released here, never held across an await — the handler runs on
    /// the mesh's task and must not block ingest behind a network round trip.
    /// Whether a peer's counters may enter this node's table at all.
    ///
    /// ⚠ **Temporary, and a deliberate narrowing of the permissionless design.** `SHARE_SHARD.md`
    /// §10 makes the λ-sampling verifier and evidence broadcast a hard precondition for admitting
    /// a node you do not own, because without them a foreign node's counter is an unverified
    /// assertion. Sampling is not built yet, and the mesh runs `allow_unknown_peers = true` by
    /// intent — so anyone completing a Noise handshake could otherwise gossip under N generated
    /// keypairs, each creating a column. `owed()` sums across columns and merging is a max, so a
    /// single accepted inflation is permanent and nothing in the runtime can remove it.
    ///
    /// Until sampling lands, admission is restricted to the fleet's own BFT-ratified membership:
    /// the `node_shares` set on the latest payout checkpoint, which is the same set the genesis
    /// anchor pins. Operator decision, 2026-08-14, for the single-operator window.
    ///
    /// **Fails CLOSED.** No checkpoint, or one carrying no node set, admits nobody. A shard that
    /// cannot converge is a visible, recoverable problem; one that merged a stranger's counters is
    /// neither.
    ///
    /// ⛔ Remove this ONLY together with building §6 sampling — not because it is inconvenient.
    fn peer_is_admissible(&self, node: &ghost_common::types::NodeId) -> GhostResult<bool> {
        // A node proven to have committed work it cannot back is refused everything further: its
        // summaries, its table syncs, and its sampling requests. Checked FIRST so a quarantined
        // node cannot be re-admitted by a later ratified set.
        if self.quarantined.lock().contains(node) {
            return Ok(false);
        }
        match self.db.get_latest_payout_ledger_checkpoint()? {
            Some(cp) if !cp.node_shares.is_empty() => {
                Ok(cp.node_shares.iter().any(|(id, _)| id == node))
            }
            _ => Ok(false),
        }
    }

    pub fn apply_peer_summary(
        &self,
        msg: &ghost_consensus::message::ShardEpochSummaryMessage,
    ) -> GhostResult<PeerMergeOutcome> {
        // Solo work is its own (§10). `tick`, `fold_epoch` and `pending_broadcasts` all refuse in
        // solo mode; the RECEIVE half must too, or a solo node merges the whole fleet's columns
        // into its table and — once Stage 5 makes the shard authoritative — a solo block pays the
        // shared shard's miners. Merging is a max, so that cannot be undone afterwards.
        if self.solo {
            return Ok(PeerMergeOutcome::SoloRefused);
        }

        let node = msg.summary.node_id;
        if node == self.identity.node_id() {
            return Ok(PeerMergeOutcome::OwnEcho);
        }

        // Admission BEFORE verification, deliberately: a summary from a node we do not recognise
        // should not even earn the signature check's compute, and refusing early keeps a stranger
        // from probing which of its keys are known.
        if !self.peer_is_admissible(&node)? {
            return Ok(PeerMergeOutcome::NotAdmitted);
        }

        // The prior summary the chain check needs is NOT always epoch-1.
        //
        // `verify_summary_stateless` uses it two ways: a SAME-epoch prior detects equivocation
        // (two different signed statements for one epoch), and an epoch-1 prior chains the totals.
        // Looking up only epoch-1 leaves equivocation permanently undetectable. Same-epoch takes
        // precedence because a node contradicting itself matters more than one whose totals fail
        // to chain.
        let prior = match self.db.shard_get_epoch(msg.summary.epoch, &node)? {
            Some(same_epoch) => Some(same_epoch),
            None => match msg.summary.epoch.checked_sub(1) {
                Some(prev) => self.db.shard_get_epoch(prev, &node)?,
                None => None,
            },
        };

        // ⚠ The lock is held ACROSS the persist, deliberately.
        //
        // `shard_upsert_column` is REPLACE semantics (delete the node's rows, re-insert). Each
        // inbound Noise connection dispatches on its own task, so two summaries from one peer can
        // interleave: merge N, merge N+1, then write N over N+1 — deleting the fresher rows. In
        // memory the max still holds, so nothing looks wrong until a restart loads the stale
        // column and this node's table root silently stops matching the fleet. Holding the lock
        // serialises merge-and-persist into one step and closes that window. It also keeps a merge
        // from landing between `arm_from_genesis`'s wipe and its save, which would re-insert a
        // pre-genesis column that the epoch floor cannot remove because it loads straight off disk.
        //
        // This is a synchronous storage call, never an await, so it cannot park the mesh task.
        let mut table = self.table.lock();
        match ghost_consensus::shard_handler::apply_shard_epoch_summary(
            &mut table,
            msg,
            prior.as_ref(),
            None, // gossip path: peers send summaries, not shares
            compute_merkle_root,
        ) {
            Ok(()) => {
                let column = table.accrued().get(&node).cloned().unwrap_or_default();
                let addresses = column.len();

                // Persist the merged column, then the peer's signed summary.
                //
                // If either write fails the in-memory table is ahead of disk, and a restart loses
                // this merge. That is "behind, never wrong": the counter is grow-only and the peer
                // re-gossips a total that already contains this epoch, so the max restores it. The
                // opposite ordering — disk ahead of memory — has no such recovery.
                self.db
                    .shard_upsert_column(&node, &column, msg.summary.epoch)?;

                // Retaining the peer's summary is what makes the chain and equivocation checks
                // work AT ALL for the next epoch, and it is the evidence an accusation is made of
                // (§6: a rejection must rest on publishable evidence, never private sampling
                // luck). `published = true` because it is not ours to broadcast.
                //
                // A conflicting summary at the same (epoch, node) is REFUSED by the storage layer
                // rather than overwritten — the held row is the evidence — so that error is
                // surfaced as a rejection rather than swallowed.
                if let Err(e) = self.db.shard_store_epoch(&msg.summary, true) {
                    let root = table.compute_table_root();
                    drop(table);
                    return Ok(PeerMergeOutcome::Merged {
                        addresses,
                        table_root: root,
                        summary_retained: Some(format!("{e}")),
                    });
                }

                let root = table.compute_table_root();
                drop(table);
                Ok(PeerMergeOutcome::Merged {
                    addresses,
                    table_root: root,
                    summary_retained: None,
                })
            }
            Err(e) => Ok(PeerMergeOutcome::Rejected(format!("{e}"))),
        }
    }

    /// Whether the genesis column is installed — i.e. whether this node has been through the
    /// Stage 5 ceremony.
    ///
    /// The coinbase source checks this before paying from the shard: without genesis the table
    /// holds only post-arming accrual and would pay a fraction of what is owed.
    pub fn genesis_installed(&self) -> bool {
        self.table
            .lock()
            .accrued()
            .contains_key(&ghost_accounting::shard_genesis::GENESIS_NODE_ID)
    }

    /// A snapshot of `owed()` for the coinbase builder.
    ///
    /// Taken under the lock and returned by value so the proposal builder stays a pure function
    /// of its input and never holds the table lock while building a block.
    pub fn owed_snapshot(&self) -> BTreeMap<String, i64> {
        self.table.lock().owed()
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
    /// Build this node's §12.6 whole-table sync REQUEST.
    ///
    /// Carries our own root so the responder can see the drift too — either side can log it.
    ///
    /// `None` in solo mode. A solo node's work is its own (§10), and its `apply_table_sync` would
    /// discard any answer as `SoloRefused` — so asking would make every peer build, sign and
    /// unicast a whole table for a reply that is thrown away. Every other transmit path
    /// (`pending_broadcasts`, `fold_epoch`, `tick`) already refuses in solo mode; this one was the
    /// exception, which is exactly how a "dark" flag stops meaning dark.
    pub fn table_sync_request(&self) -> Option<ghost_consensus::message::ShardTableSyncMessage> {
        if self.solo {
            return None;
        }
        Some(ghost_consensus::message::ShardTableSyncMessage::Request {
            requesting_node: self.identity.node_id(),
            table_root: self.table.lock().compute_table_root(),
        })
    }

    /// Draw a §6 audit against a peer's retained summary, or `None` if there is nothing to audit.
    ///
    /// ⚠ **`entropy` must be fresh, private, and never derived from anything the target can
    /// compute.** The audit's ~10⁻⁶ detection bound rests entirely on the sampled node not knowing
    /// which leaves will be pulled before it signs: a node that can predict its samples fabricates
    /// work in the never-sampled leaves, keeps the predicted ones honest, and the bound collapses
    /// to exactly zero. Deriving it from the summary, chain data, a schedule or a fixed per-node
    /// seed all break it. The caller passes it in rather than this deriving one, so the source
    /// stays visible at the call site instead of buried here.
    ///
    /// The request is retained under `(target, epoch)` because `verify_sample_response` binds the
    /// summary, the request and the response together — and the leaf choice cannot be re-derived
    /// later without the same entropy.
    pub fn sample_request_for(
        &self,
        target: &ghost_common::types::NodeId,
        entropy: &[u8; 32],
        lambda: u32,
    ) -> GhostResult<Option<ghost_consensus::message::ShardSampleRequestMessage>> {
        if self.solo {
            return Ok(None);
        }
        // Auditing ourselves proves nothing — we would be marking our own homework.
        if target == &self.identity.node_id() {
            return Ok(None);
        }
        if !self.peer_is_admissible(target)? {
            return Ok(None);
        }
        // Choose among ALL RETAINED epochs that have leaves, not just the latest.
        //
        // Auditing only the newest epoch has two failures, and the first makes the sampler inert:
        // an idle epoch has `share_count = 0`, so on a quiet pool every tick would find nothing to
        // ask and no audit would ever run. The second is worse — work fabricated in any earlier
        // retained epoch could never be sampled, because the window had already moved past it. The
        // evidence is retained for `RETENTION_EPOCHS` precisely so it stays auditable for that long.
        //
        // `entropy` is reused as the epoch chooser: it is already fresh, private, and unknown to
        // the target until the request is sent, which is exactly the property the choice needs. A
        // predictable epoch choice would let a node fabricate in the epochs it knows will not be
        // picked — the same collapse as a predictable leaf choice, one level up.
        let Some(latest) = self.db.shard_latest_epoch(target)? else {
            return Ok(None);
        };
        // RETENTION_EPOCHS - 1: folding `latest` deletes the evidence for
        // `latest - RETENTION_EPOCHS`, so including it picks an epoch whose leaves are already
        // gone — the responder rebuilds a short tree, the root check fails, and the audit burns a
        // pending slot for an hour learning nothing.
        let oldest = latest.saturating_sub(RETENTION_EPOCHS.saturating_sub(1));
        let mut candidates = Vec::new();
        for epoch in oldest..=latest {
            if let Some(summary) = self.db.shard_get_epoch(epoch, target)? {
                if summary.share_count > 0 {
                    candidates.push(summary);
                }
            }
        }
        if candidates.is_empty() {
            return Ok(None);
        }
        let pick = u64::from_be_bytes(entropy[..8].try_into().unwrap_or([0u8; 8]))
            % candidates.len() as u64;
        let summary = candidates.swap_remove(pick as usize);
        let epoch = summary.epoch;

        let request = ghost_consensus::shard_handler::build_sample_request(
            self.identity.node_id(),
            &summary,
            lambda,
            entropy,
        );
        self.pending_samples.lock().insert(
            (*target, epoch),
            PendingSample {
                request: request.clone(),
                summary,
                sent_at: std::time::Instant::now(),
            },
        );
        Ok(Some(request))
    }

    /// Verify a §6 sampling response against the audit we sent.
    ///
    /// `share_is_valid` must judge a share by ITS OWN era — pass a closure over the era-aware
    /// `NodeBatchChecks`, never a height-derived predicate. A predicate judged by the current
    /// height condemns every pre-gate share the moment the fleet crosses a gate, and here that
    /// does not merely reject a share: it publishes an accusation against an honest node.
    ///
    /// Returns `None` when the response answers no audit we are holding — an unsolicited response,
    /// or one that arrived after its audit expired. That is dropped rather than verified: without
    /// the original request there is no record of which leaves WE chose, and verifying against a
    /// request the responder supplied would let it set its own exam.
    pub fn apply_sample_response(
        &self,
        response: &ghost_consensus::message::ShardSampleResponseMessage,
        share_is_valid: ghost_consensus::shard_handler::ShareValidityFn<'_>,
        now_ms: u64,
    ) -> GhostResult<Option<ghost_consensus::shard_handler::ShardSampleOutcome>> {
        let key = (response.responding_node, response.epoch);
        // ⚠ Look up WITHOUT removing. Removing first meant a refused response still consumed the
        // audit, so a peer could enumerate `(target, epoch)` — both public — and spam garbage
        // responses, evicting every pending audit before the genuine answer arrived. One node
        // could disable §6 sampling fleet-wide, and the only trace was a `debug!`. The entry is
        // now dropped only once the response has actually been verified.
        let Some(pending) = self.pending_samples.lock().get(&key).cloned() else {
            debug!(
                epoch = response.epoch,
                "shard: sampling response answers no audit we are holding — dropped"
            );
            return Ok(None);
        };

        match ghost_consensus::shard_handler::verify_sample_response(
            &pending.summary,
            &pending.request,
            response,
            &self.identity,
            now_ms,
            ghost_reconciliation::batch::verify_merkle_proof,
            share_is_valid,
        ) {
            Ok(outcome) => {
                // Verified: the audit is answered and may be retired.
                self.pending_samples.lock().remove(&key);
                Ok(Some(outcome))
            }
            Err(e) => {
                // A refused response is not evidence of bad WORK — it is a malformed or
                // unattributable answer — so it is reported, not published as an accusation.
                info!(
                    epoch = response.epoch,
                    peer = %hex::encode(&response.responding_node[..4]),
                    reason = %e,
                    "shard: sampling response refused"
                );
                Ok(None)
            }
        }
    }

    /// Drop audits that were never answered, so the map cannot grow without bound.
    ///
    /// An expired audit is NOT a verdict. §6 deliberately does not say what refusal-to-serve means,
    /// and the response cap makes an honest partial answer legal, so silence is surfaced by the
    /// caller's policy rather than turned into an accusation here.
    pub fn expire_pending_samples(&self, older_than: std::time::Duration) -> usize {
        let mut pending = self.pending_samples.lock();
        let before = pending.len();
        pending.retain(|_, p| p.sent_at.elapsed() < older_than);
        before - pending.len()
    }

    /// Quarantine a node proven by §12.4 evidence to have committed an unbackable share.
    ///
    /// Returns whether this was new. Idempotent: the same evidence relayed by several peers must
    /// not read as several offences.
    pub fn quarantine(&self, node: ghost_common::types::NodeId) -> bool {
        self.quarantined.lock().insert(node)
    }

    /// Is this node quarantined?
    pub fn is_quarantined(&self, node: &ghost_common::types::NodeId) -> bool {
        self.quarantined.lock().contains(node)
    }

    /// This node's id — the sampler needs it to exclude itself from audit targets.
    pub fn node_id(&self) -> ghost_common::types::NodeId {
        self.identity.node_id()
    }

    /// Serve a §6 sampling request against OUR OWN summary for `req.epoch`.
    ///
    /// The audit only means anything because the sampled node cannot predict which leaves will be
    /// pulled: the requester draws private entropy and keeps it until the request is sent, by which
    /// time our root is signed and immutable. So this reconstructs the exact tree that root commits
    /// to and answers the indices asked for — it never chooses which leaves to serve.
    ///
    /// ⚠ **Canonical order is the whole contract.** `check_evidence` sorts the evidence with
    /// [`canonical_sort`] before hashing, so leaf `i` is the `i`-th share in THAT order. Rebuilding
    /// the tree in storage order would produce paths that do not bind, and the requester would read
    /// an honest node as serving garbage — an accusation manufactured by our own bug.
    ///
    /// Returns `None` when we will not serve: solo mode, a request aimed at another node's summary,
    /// a requester outside the ratified set, or an epoch we hold no summary for. A subset answer is
    /// legal (§6) — the response cap means a worst-case λ of shares need not fit one envelope — and
    /// deciding what persistent silence means is the sampler's policy, not ours.
    pub fn sample_response_for(
        &self,
        req: &ghost_consensus::message::ShardSampleRequestMessage,
    ) -> GhostResult<Option<ghost_consensus::message::ShardSampleResponseMessage>> {
        use ghost_consensus::message::ShardSampleLeaf;

        if self.solo {
            return Ok(None);
        }
        // We can only answer for our own commitment: nobody else holds the evidence, and a
        // response signed by anyone but the summarising node is refused by `verify_sample_response`.
        if req.target_node != self.identity.node_id() {
            return Ok(None);
        }
        if !self.peer_is_admissible(&req.requesting_node)? {
            debug!(
                epoch = req.epoch,
                "shard: sampling request from outside the ratified set — not served"
            );
            return Ok(None);
        }

        let Some(summary) = self
            .db
            .shard_get_epoch(req.epoch, &self.identity.node_id())?
        else {
            return Ok(None);
        };
        // Answering a root we did not sign would be answering from a different tree — exactly what
        // the root check in `verify_sample_response` exists to catch. Refuse rather than serve it.
        if req.share_root != summary.share_root {
            warn!(
                epoch = req.epoch,
                "shard: sampling request names a root we did not sign — not served"
            );
            return Ok(None);
        }

        // Rebuild the committed tree from the retained evidence, in canonical order.
        let input = self.db.shard_epoch_shares(
            req.epoch,
            EPOCH_BLOCKS,
            &self.received_by,
            NETWORK_TIER_LOG2,
        )?;
        let (mut evidence, _screened) = screen(input.shares);
        canonical_sort(&mut evidence);
        let hashes: Vec<[u8; 32]> = evidence.iter().map(|s| s.share_hash).collect();

        // If the rebuilt tree does not reproduce the signed root, our evidence no longer matches
        // what we committed — retention may have expired it. Serving paths from a different tree
        // would look like fabrication to the sampler, so say nothing and let the request go
        // unanswered, which §6 already treats as the sampler's call.
        if compute_merkle_root(&hashes) != summary.share_root {
            debug!(
                epoch = req.epoch,
                leaves = hashes.len(),
                "shard: retained evidence no longer reproduces the signed root — sampling request \
                 left unanswered rather than served from a tree we did not commit"
            );
            return Ok(None);
        }

        // ⚠ Bound the work a single request can demand, and de-duplicate it.
        //
        // `compute_merkle_proof` rebuilds the whole level stack per leaf, so serving is
        // O(indices x N) SHA-256 on top of a full evidence read — and it runs synchronously on the
        // mesh dispatch task, which processes handlers in turn. Nothing enforced
        // `MAX_SAMPLE_REQUEST_INDICES` (it was referenced only by a sizing test), and the payload
        // cap allows far more small indices than its arithmetic assumed, duplicates included. One
        // ratified peer could therefore wedge this node's inbound votes and checkpoints behind a
        // single request. The table-sync path guards exactly this with a cooldown; this is the
        // same guard expressed as a work bound.
        let mut wanted: Vec<u32> = req.leaf_indices.clone();
        wanted.sort_unstable();
        wanted.dedup();
        if wanted.len() > ghost_consensus::message_validator::MAX_SAMPLE_REQUEST_INDICES {
            warn!(
                epoch = req.epoch,
                asked = req.leaf_indices.len(),
                cap = ghost_consensus::message_validator::MAX_SAMPLE_REQUEST_INDICES,
                "shard: sampling request asks for more leaves than the cap — not served"
            );
            return Ok(None);
        }

        let mut leaves = Vec::new();
        for &idx in &wanted {
            let Some(share) = evidence.get(idx as usize) else {
                continue; // out of range for this tree — serve what we can, per §6
            };
            leaves.push(ShardSampleLeaf {
                leaf_index: idx,
                share: share.clone(),
                merkle_proof: compute_merkle_proof(&hashes, idx as usize),
            });
        }

        Ok(Some(ghost_consensus::shard_handler::build_sample_response(
            &self.identity,
            &summary,
            leaves,
        )))
    }

    /// Build the RESPONSE for a specific requester, or `None` if we will not serve them.
    ///
    /// Signing makes the served table attributable — a peer that serves an inflated cell has
    /// signed the inflation, which is what makes it publishable evidence rather than hearsay.
    ///
    /// ⚠ **Admission is checked on the SERVE side too, not only on apply.** The response carries
    /// the whole accrued table, whose cells are keyed by PAYOUT ADDRESS in the clear inside the
    /// envelope. The mesh authenticates the sender's signature, but authentication is not
    /// authorisation: without this check any node whose envelopes we accept could ask once an hour
    /// and harvest every payout address the fleet knows. Serving only the ratified set makes the
    /// disclosure the same set that already holds this data.
    ///
    /// Solo nodes never serve: their work is their own (§10), and the table they would hand over
    /// is not the shared shard's.
    pub fn table_sync_response_for(
        &self,
        requester: &ghost_common::types::NodeId,
    ) -> GhostResult<Option<ghost_consensus::message::ShardTableSyncMessage>> {
        if self.solo {
            return Ok(None);
        }
        if !self.peer_is_admissible(requester)? {
            return Ok(None);
        }
        Ok(Some(
            ghost_consensus::shard_handler::build_table_sync_response(
                &self.identity,
                &self.table.lock(),
            ),
        ))
    }

    /// Apply a peer's whole-table sync response — the repair path for a column this node missed.
    ///
    /// ## Why this exists at all
    ///
    /// Epoch summaries cannot close a gap. [`EpochSummary::build`] emits only the addresses that
    /// had shares IN THAT EPOCH, so a node which has gone quiet broadcasts a summary with no cells
    /// — carrying none of its cumulative totals. A peer that missed the epochs where that node was
    /// working can therefore never learn those totals from gossip, no matter how long it listens.
    /// The design's "a missing message makes you behind, never wrong" holds only while the address
    /// keeps producing shares; once it stops, the gap is frozen.
    ///
    /// Measured on the fleet 2026-08-15: vm1–4 held 5 columns and vm5–8 held 6, byte-identical
    /// within each group, with ZERO refusals logged. The missing node folds `share_count=0` every
    /// epoch, so nothing in the gossip path could ever have repaired it. This is the path that
    /// can, and until it was wired the two halves would have computed different payouts for ever.
    ///
    /// Merging is per-cell max, so a stale table loses, a duplicate is a no-op and delivery order
    /// cannot matter. `settled` is never touched: it does not ride in the message and must not.
    pub fn apply_table_sync(
        &self,
        msg: &ghost_consensus::message::ShardTableSyncMessage,
    ) -> GhostResult<TableSyncMerge> {
        // Solo work is its own (§10) — the same reasoning as `apply_peer_summary`, and more
        // pressing here: a whole table is every column at once.
        if self.solo {
            return Ok(TableSyncMerge::SoloRefused);
        }

        let responder = match msg {
            ghost_consensus::message::ShardTableSyncMessage::Response {
                responding_node, ..
            } => *responding_node,
            // A Request is not something to apply. The caller routes it to `table_sync_response`.
            ghost_consensus::message::ShardTableSyncMessage::Request { .. } => {
                return Ok(TableSyncMerge::Rejected("not a response".into()))
            }
        };

        if responder == self.identity.node_id() {
            return Ok(TableSyncMerge::OwnEcho);
        }

        // Admission before verification, as on the summary path.
        if !self.peer_is_admissible(&responder)? {
            return Ok(TableSyncMerge::NotAdmitted);
        }

        // Lock held across the persist, for the reason `apply_peer_summary` documents at length:
        // `shard_upsert_column` is REPLACE semantics, and a concurrent merge landing between this
        // merge and its write would leave disk holding a column the memory table has moved past.
        let mut table = self.table.lock();

        // Snapshot BEFORE, so the persist can write exactly the columns that changed. Writing all
        // of them would rewrite every peer's rows on every sync — needless churn on a table the
        // payout path reads, and it would bump `updated_epoch` on columns nothing touched.
        let before: BTreeMap<_, _> = table
            .accrued()
            .iter()
            .map(|(node, col)| (*node, col.clone()))
            .collect();

        // ⚠ Verify on a CLONE, then merge back every column EXCEPT our own.
        //
        // This node is authoritative for its own column, and `merge_accrued` maxes every column in
        // the payload (skipping only `GENESIS_NODE_ID`). A peer serving a table whose cell for our
        // node id exceeds ours would otherwise raise our own counter permanently — a max cannot be
        // undone — and it would not stop there: the next `fold_epoch` reads `prior` straight out of
        // that column and hands it to `EpochSummary::build`, so this node would SIGN
        // `inflated_prior + delta` and gossip it fleet-wide as its own attributable statement. We
        // would become the source of the forgery, with our signature on it.
        //
        // The summary path structurally cannot do this — `apply_shard_epoch_summary` only ever
        // touches the sender's own column — which is why the whole-table path needs it said here
        // rather than assumed. Verification still happens in the library, on the clone, so the
        // signature is checked over the bytes the peer actually sent.
        let self_id = self.identity.node_id();
        let mut probe = table.clone();
        match ghost_consensus::shard_handler::apply_table_sync_response(&mut probe, msg) {
            Ok(outcome) => {
                let mut safe = ghost_common::share_shard::AccruedColumns::new();
                for (node, column) in probe.accrued() {
                    if *node == self_id {
                        continue;
                    }
                    safe.insert(*node, column.clone());
                }

                // A peer that tried to move our own column is misbehaving, not merely stale. It is
                // refused silently by the filter above, but it must not be invisible.
                if probe.accrued().get(&self_id) != table.accrued().get(&self_id) {
                    warn!(
                        peer = %hex::encode(&responder[..4]),
                        "shard: peer's table would have CHANGED this node's own column — refused \
                         (we are authoritative for it); merging the rest"
                    );
                }

                table.merge_accrued(&safe);

                let after: BTreeMap<_, _> = table
                    .accrued()
                    .iter()
                    .map(|(node, col)| (*node, col.clone()))
                    .collect();

                // `updated_epoch` is bookkeeping only; a sync carries no epoch of its own, so
                // stamp it with the epoch this node last saw rather than inventing one.
                let stamp = self
                    .last_epoch_seen
                    .load(Ordering::Relaxed)
                    .saturating_sub(1);

                let mut gained = 0usize;
                let mut raised = 0usize;
                let mut unpersisted = 0usize;
                for (node, column) in &after {
                    match before.get(node) {
                        Some(prev) if prev == column => continue,
                        Some(_) => raised += 1,
                        None => gained += 1,
                    }
                    // ⚠ CONTINUE past a write failure, never return.
                    //
                    // The in-memory merge has already happened, so the next hourly sync will see
                    // `prev == column` for every column skipped here and never try to write them
                    // again for the life of the process. A restart before then loses the recovered
                    // columns with nothing in the log to say so — the same silent-loss shape as the
                    // SBC pending pool. Writing every column we can, and counting the ones we
                    // could not, keeps the failure both bounded and visible.
                    if let Err(e) = self.db.shard_upsert_column(node, column, stamp) {
                        unpersisted += 1;
                        warn!(
                            peer = %hex::encode(&node[..4]),
                            error = %e,
                            "shard: table sync merged but a column could NOT be persisted"
                        );
                    }
                }
                if unpersisted > 0 {
                    warn!(
                        unpersisted,
                        "shard: table sync left columns in memory only — a restart before the next \
                         sync will lose them"
                    );
                }

                let root = table.compute_table_root();
                drop(table);
                // Compare against OUR table after the filtered merge, not the probe's: the probe
                // may hold a column we deliberately refused, so its root is not ours to report.
                let roots_match = root == outcome.remote_root;
                Ok(TableSyncMerge::Applied {
                    columns_gained: gained,
                    columns_raised: raised,
                    roots_match,
                    table_root: root,
                })
            }
            Err(e) => {
                drop(table);
                Ok(TableSyncMerge::Rejected(format!("{:?}", e)))
            }
        }
    }

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

        // Clamp the watermark to the arming floor.
        //
        // `next_fold` is in-memory, so a restart re-derives it as `shard_latest_epoch + 1` — which
        // sits BELOW the floor for any node whose watermark lagged the anchor when it armed
        // (downtime, `share_shard` enabled late, a backlog longer than MAX_FOLDS_PER_TICK). It
        // would then fold pre-genesis epochs into its own column on top of the genesis column:
        // exactly the double count the floor exists to stop, arriving by the one path the floor
        // did not cover, because `fold_epoch` credits locally rather than merging a summary.
        let floor = self.table.lock().epoch_floor();
        if next < floor {
            debug!(
                next,
                floor, "share shard: watermark below the arming floor — clamping"
            );
            next = floor;
            *next_guard = Some(next);
        }

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
        // Stamped with which genesis this node is running, so a peer can tell an armed summary
        // from an unarmed one. Taken from the table rather than the pin: the pin is what we SHOULD
        // be running, the table is what we ARE, and a peer needs the latter.
        let summary = EpochSummary::build(
            epoch,
            &self.identity,
            &prior,
            &evidence,
            compute_merkle_root,
            table.genesis_marker(),
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

    /// The adopted blob the genesis pin was taken over — from ghost-accounting's single
    /// definition, not a copy. A copy here went stale the first time the anchor was re-pinned.
    fn pinned_canonical_blob() -> Vec<u8> {
        ghost_accounting::shard_genesis::pinned_canonical_payout_blob()
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
            Some(&62_143_408_528_125_167)
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

    /// The floor must survive a restart, or arming's protection lasts one process lifetime.
    ///
    /// `shard_save_table` stamps `updated_epoch` for diagnosis only and `shard_load_table` rebuilds
    /// from an empty table, so a floor that is merely set in memory is gone on the next start —
    /// re-opening both merge paths to pre-genesis summaries from unarmed peers. Merging is a max,
    /// so that inflation is permanent, and the table root does not cover the floor, so the fleet
    /// comparison could not detect it either.
    #[test]
    fn the_arming_floor_survives_a_restart() {
        let (identity, db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        let report = rt
            .arm_from_genesis(&anchor, &pinned_canonical_blob())
            .expect("arm");
        assert!(report.epoch_floor > 0);

        let reloaded = ShardRuntime::load(identity, Arc::clone(&db), false, true).expect("load");
        assert_eq!(
            reloaded.table.lock().epoch_floor(),
            report.epoch_floor,
            "an armed node must come back armed"
        );
    }

    /// An UNARMED node must not acquire a floor from the pin — it has no genesis column, so every
    /// epoch is legitimately foldable and mergeable.
    #[test]
    fn an_unarmed_node_has_no_floor() {
        let (_identity, _db, rt) = runtime();
        assert_eq!(rt.table.lock().epoch_floor(), 0);
    }

    /// Arming must clear its own epoch markers, or the catch-up credits nothing.
    ///
    /// The soak folds epochs and writes `shard_epochs` rows. Arming replaces the columns but those
    /// rows would survive, and `fold_epoch`'s idempotence gate reads exactly them — so every epoch
    /// between the anchor and the moment of arming would return `AlreadyFolded`, and every miner's
    /// work across that window would vanish with no error anywhere.
    #[test]
    fn arming_lets_the_catch_up_re_fold_the_soaks_epochs() {
        let (identity, db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        let floor = epoch_for_height(anchor.height, EPOCH_BLOCKS) + 1;

        // The soak folds an epoch at/above the floor and marks it.
        let height = floor * EPOCH_BLOCKS.get();
        seed_round(&db, 9_001, height);
        seed_share(
            &db,
            9_001,
            77,
            "bc1qgap",
            4.0,
            Some(NETWORK_TIER_LOG2),
            &our_received_by(&identity),
            true,
        );
        rt.fold_epoch(floor).expect("soak fold");
        assert!(
            rt.table.lock().owed().contains_key("bc1qgap"),
            "precondition: the soak credited this work"
        );
        assert!(db
            .shard_get_epoch(floor, &identity.node_id())
            .unwrap()
            .is_some());

        let report = rt
            .arm_from_genesis(&anchor, &pinned_canonical_blob())
            .expect("arm");
        assert_eq!(
            report.cleared_epochs, 1,
            "the soak's marker must be cleared"
        );

        // Now the catch-up must genuinely re-credit it.
        rt.tick(height + EPOCH_BLOCKS.get() * 2).expect("tick");
        assert_eq!(
            rt.table.lock().owed().get("bc1qgap"),
            Some(&(micro_work(4.0) as i64)),
            "work between the anchor and arming must be re-credited, not silently lost"
        );
    }

    /// A watermark left below the floor by a restart must be clamped, not folded from.
    ///
    /// `fold_epoch` credits this node's column directly, so the floor's merge-path checks do not
    /// cover it — a node whose watermark lagged the anchor would fold pre-genesis epochs on top of
    /// the genesis column, which is the double count the floor exists to stop.
    #[test]
    fn a_watermark_below_the_floor_is_clamped_before_folding() {
        let (_identity, _db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        let report = rt
            .arm_from_genesis(&anchor, &pinned_canonical_blob())
            .expect("arm");

        // Simulate a restart that re-derived a stale watermark from an old summary.
        *rt.next_fold.lock() = Some(report.epoch_floor - 50);
        rt.tick(anchor.height + EPOCH_BLOCKS.get() * 4)
            .expect("tick");
        assert!(
            rt.next_fold.lock().unwrap() >= report.epoch_floor,
            "the watermark must never sit below the arming floor"
        );
    }

    /// Arming is once. A re-run would discard everything accrued since the first one.
    #[test]
    fn arming_twice_is_refused() {
        let (_identity, _db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        rt.arm_from_genesis(&anchor, &pinned_canonical_blob())
            .expect("first arming");
        assert!(
            rt.arm_from_genesis(&anchor, &pinned_canonical_blob())
                .is_err(),
            "a second arming must be refused"
        );
    }

    /// Arming from anything but the compile-time pin would install a genesis column this node
    /// refuses to load on its next restart.
    #[test]
    fn arming_from_an_unpinned_anchor_is_refused() {
        let (_identity, _db, rt) = runtime();
        let rogue = ghost_accounting::shard_genesis::GenesisAnchor {
            height: 900_000,
            ..ghost_accounting::shard_genesis::pinned_anchor()
        };
        assert!(rt
            .arm_from_genesis(&rogue, &pinned_canonical_blob())
            .is_err());
        assert_eq!(rt.table.lock().epoch_floor(), 0);
    }

    /// Arming must clear PEERS' retained summaries, not only its own.
    ///
    /// The failure this pins is a false accusation of misbehaviour, generated by the ceremony
    /// against an honest node. Arming re-folds every epoch since the anchor with different totals;
    /// a peer holding the pre-arming summary for one of those epochs sees the same epoch with
    /// different signing bytes and returns `SummaryEquivocation` — "this node signed two
    /// conflicting statements", which §6 treats as publishable evidence. `store_epoch_tx` then
    /// refuses to overwrite the held row, so the accusation sticks and every re-fold is refused
    /// again.
    ///
    /// Invisible until gossip was wired, because nothing compared summaries across nodes, and
    /// created by retaining peers' summaries — which is itself correct and required for the chain
    /// check.
    #[test]
    fn arming_clears_pre_genesis_summaries_from_every_node_not_just_our_own() {
        let (identity, db, rt) = runtime();
        let anchor = ghost_accounting::shard_genesis::pinned_anchor();
        let floor = epoch_for_height(anchor.height, EPOCH_BLOCKS) + 1;

        // A peer's summary at/above the floor, retained exactly as the gossip path retains it.
        let peer = NodeIdentity::generate();
        let peer_summary = ghost_common::share_shard::EpochSummary::build(
            floor + 3,
            &peer,
            &BTreeMap::new(),
            &[],
            compute_merkle_root,
            None,
        )
        .expect("legal");
        db.shard_store_epoch(&peer_summary, true).expect("retain");

        // And one of our own, as a pre-arming fold would have left it.
        let own_summary = ghost_common::share_shard::EpochSummary::build(
            floor + 3,
            &identity,
            &BTreeMap::new(),
            &[],
            compute_merkle_root,
            None,
        )
        .expect("legal");
        db.shard_store_epoch(&own_summary, true).expect("retain");

        assert!(db
            .shard_get_epoch(floor + 3, &peer.node_id())
            .unwrap()
            .is_some());
        assert!(db
            .shard_get_epoch(floor + 3, &identity.node_id())
            .unwrap()
            .is_some());

        rt.arm_from_genesis(&anchor, &pinned_canonical_blob())
            .expect("arm");

        assert!(
            db.shard_get_epoch(floor + 3, &peer.node_id())
                .unwrap()
                .is_none(),
            "a PEER's pre-genesis summary must be cleared, or re-folding that epoch is refused \
             as equivocation and an honest node stands accused"
        );
        assert!(
            db.shard_get_epoch(floor + 3, &identity.node_id())
                .unwrap()
                .is_none(),
            "our own pre-genesis summary must be cleared too"
        );
    }

    /// A stranger's summary must not enter the table, and must not do so by DEFAULT.
    ///
    /// Fails closed: the fixture DB carries no payout checkpoint, so nobody is admissible. That is
    /// the state a fresh node is in, and it is the one where a permissive default would be most
    /// tempting and most wrong — `owed()` sums across columns and a max cannot be undone, so an
    /// accepted stranger is permanent.
    #[test]
    fn an_unratified_peer_is_refused_before_anything_is_merged() {
        let (_identity, _db, rt) = runtime();
        let stranger = NodeIdentity::generate();
        let (summary, _ev) = {
            let evidence = vec![];
            let s = ghost_common::share_shard::EpochSummary::build(
                7,
                &stranger,
                &BTreeMap::new(),
                &evidence,
                compute_merkle_root,
                None,
            )
            .expect("empty evidence is legal");
            (s, evidence)
        };
        let before = rt.table.lock().compute_table_root();

        let out = rt
            .apply_peer_summary(&ghost_consensus::message::ShardEpochSummaryMessage { summary })
            .expect("admission is a verdict, not an error");

        assert_eq!(out, PeerMergeOutcome::NotAdmitted);
        assert_eq!(
            rt.table.lock().compute_table_root(),
            before,
            "a refused summary must leave the table byte-identical"
        );
        assert!(
            rt.table.lock().accrued().is_empty(),
            "no column may be created for an unratified sender"
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
        assert_eq!(
            rt.table.lock().epoch_floor(),
            0,
            "and must not arm the floor"
        );
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
