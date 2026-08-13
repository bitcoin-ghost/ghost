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
//! Nothing here spawns. The caller owns the schedule and calls three entry points:
//!
//! - [`ShardRuntime::note_height`] on the template-refresh path — an integer compare that
//!   reports an epoch boundary, and nothing else;
//! - [`ShardRuntime::tick`] from the epoch task — folds closed epochs, bounded per call;
//! - [`ShardRuntime::fold_epoch`] if a single epoch needs folding by hand.
//!
//! Storage is a single `Mutex<Connection>` shared with share ingest, so every call does bounded
//! work: a tick folds at most [`MAX_FOLDS_PER_TICK`] epochs, an epoch's input is bounded by the
//! epoch length, and evidence deletes are chunked inside the storage layer's one transaction.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use ghost_common::coinbase_tags::MIN_DIFFICULTY_TIER_LOG2;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::share_batch::creditable_difficulty;
use ghost_common::share_shard::{
    epoch_for_height, EpochSummary, ShardTable, EPOCH_BLOCKS, RETENTION_EPOCHS,
};
use ghost_common::types::ShareProof;
use ghost_reconciliation::batch::compute_merkle_root;
use ghost_storage::database::Database;

/// The tier floor a share must have committed to before its work enters the shared shard.
///
/// Stage 2 ships R = 1: this equals the vardiff floor, so behaviour is byte-for-byte today's, and
/// raising R later is a coordinated roll of this one constant. Baked into the binary, NEVER read
/// from local config — a node-local value in an eligibility test is exactly how M-6 split the
/// fleet (§12.1: validity must be a pure function of the share).
pub const NETWORK_TIER_LOG2: u32 = MIN_DIFFICULTY_TIER_LOG2;

/// Epochs one tick may fold. Bounds the work done against the shared connection between two
/// share-ingest writes: a node that is many epochs behind catches up across ticks — resume, not
/// a stall — rather than holding the storage mutex for the whole backlog at once.
const MAX_FOLDS_PER_TICK: usize = 4;

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
        let received_by = hex::encode(&identity.node_id()[..8]);
        info!(
            columns = table.accrued().len(),
            solo, owns_evidence, "share shard: runtime loaded"
        );
        Ok(Self {
            identity,
            db,
            received_by,
            solo,
            owns_evidence,
            table: Mutex::new(table),
            next_fold: Mutex::new(None),
            last_epoch_seen: AtomicU64::new(0),
        })
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

        let input =
            self.db
                .shard_epoch_shares(epoch, EPOCH_BLOCKS, &self.received_by, NETWORK_TIER_LOG2)?;
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
        let summary =
            EpochSummary::build(epoch, &self.identity, &prior, &evidence, compute_merkle_root)
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
        Ok((Some(expired), evidence.iter().map(|s| s.share_hash).collect()))
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
        (identity, db, rt)
    }

    fn our_received_by(identity: &NodeIdentity) -> String {
        hex::encode(&identity.node_id()[..8])
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
        assert_eq!(rt2.fold_epoch(100).expect("refold"), FoldOutcome::AlreadyFolded);
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
        seed_share(&db, 1, 0xA1, "bc1qalice", 2.0, Some(NETWORK_TIER_LOG2), &rx, true);
        seed_share(&db, 1, 0xB1, "bc1qalice", 2.0, Some(12), "eeff001122334455", true);
        seed_share(&db, 1, 0xB2, "bc1qalice", 2.0, Some(12), &rx, false);
        seed_share(&db, 1, 0xB3, "bc1qalice", 2.0, Some(NETWORK_TIER_LOG2 - 1), &rx, true);

        let FoldOutcome::Folded(report) = rt.fold_epoch(100).expect("fold") else {
            panic!("must fold");
        };
        assert_eq!(report.shares_folded, 1, "only the own, valid, network-tier share");
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
            seed_share(&db, epoch, epoch as u8, "bc1qminer", 2.0, Some(12), &rx, true);
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
        let rt = ShardRuntime::load(Arc::clone(&identity), Arc::clone(&db), true, true).expect("load");
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
            seed_share(&db, epoch, epoch as u8, "bc1qminer", 2.0, Some(12), &rx, true);
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
        let rt = ShardRuntime::load(Arc::clone(&identity), Arc::clone(&db), false, false)
            .expect("load");
        let rx = our_received_by(&identity);

        for epoch in 100u64..=106 {
            seed_round(&db, epoch, epoch * 6);
            seed_share(&db, epoch, epoch as u8, "bc1qminer", 2.0, Some(12), &rx, true);
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
