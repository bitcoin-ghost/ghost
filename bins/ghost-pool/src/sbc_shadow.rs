//! The share-batch chain running in shadow (WP-5).
//!
//! Both systems live; **only checkpoints feed the coinbase**. This computes the chain, folds
//! balances and persists them, and hands out the `(seq, state_root)` the trust gate compares across
//! the fleet. It pays nobody. Nothing here reaches the coinbase until WP-6.
//!
//! ## What a node batches
//!
//! Only shares **it** received — `received_by == our node id`. A gossiped share was received by a
//! peer and belongs in *that* peer's batch, which is the whole reason a node never needs a peer's
//! shares to compute the payout. Batching a share someone else received would double-count it the
//! moment both batches were adopted.
//!
//! ## Where the impure edges are
//!
//! The consensus decisions are pure and already tested in `ghost-common`: `pack_batch`,
//! `fold_shares`, `compute_state_root`, `verify_batch`, `on_batch`, `on_vote`. This type owns only
//! the parts that cannot be pure — the pending pool, the database, and the clock, which is supplied
//! by the caller rather than read here so the tests can drive it.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use tracing::{info, warn};

use ghost_common::batch_consensus::{ProposerSchedule, SeqTally, SeqVoteLock};
use ghost_common::batch_driver::{on_batch, on_vote, Action, BatchContext, VoteAction};
use ghost_common::batch_quarantine::Quarantine;
use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::share_batch::{compute_state_root, fold_shares, pack_batch, ShareBatch};
use ghost_common::types::ShareProof;
use ghost_storage::database::Database;
use ghost_storage::sbc_store::ChainHead;

/// The chain's view on this node.
pub struct ShadowChain {
    identity: Arc<NodeIdentity>,
    db: Arc<Database>,
    /// Shares this node received and has not yet packed into a batch, KEYED BY SHARE HASH.
    ///
    /// A map, not a Vec, because the pending pool must not hold the same share twice. The share
    /// recorder can fire more than once for a share, and a duplicate inside a proposed batch is a
    /// TERMINAL fault: `verify_batch` returns `DuplicateShare`, every peer quarantines the
    /// proposer, and quarantine is operator-release-only. On the 2026-08-09 four-node run that
    /// excluded ghost-vm5 — the one canary carrying a real miner — from consensus permanently.
    ///
    /// Bounded by the pack budget on the way out, not on the way in: dropping a share here is work
    /// a miner never gets paid for, whereas a large pool merely produces a truncated batch and the
    /// remainder is carried to the next one.
    pending: Mutex<BTreeMap<[u8; 32], ShareProof>>,
    /// The adopted head, or `None` before genesis.
    head: RwLock<Option<ChainHead>>,
    /// Running balances after the head. Plaintext address -> integer micro-work, exactly the
    /// form `fold_shares` and `compute_state_root` take.
    balances: RwLock<BTreeMap<String, i64>>,
    /// Peers quarantined this process, with the outcome the driver decided.
    quarantine: Mutex<Quarantine>,
    /// Peers quarantined in an EARLIER process, restored from the database.
    ///
    /// Held separately from [`Quarantine`] rather than replayed into it: that type takes the
    /// `FaultReason` and the voter set the decision was made against, and neither is available at
    /// load time — the reason is persisted as text and the fleet is not yet known. Reconstructing
    /// an approximation would put a fabricated reason on a real exclusion.
    ///
    /// Checked before the driver is consulted, so release stays operator-only across restarts. An
    /// automatic timer would let a Byzantine node misbehave, wait it out, and repeat forever.
    restored_quarantine: RwLock<std::collections::HashSet<[u8; 32]>>,
    /// One vote per sequence, ever. Two individually-valid batches must not both reach quorum, and
    /// the voter is the only place that can be prevented.
    vote_lock: Mutex<SeqVoteLock>,
    /// Votes seen per sequence. Counted per SEQUENCE rather than per batch, because equivocation
    /// is only visible when the candidates are tallied together.
    tallies: Mutex<BTreeMap<u64, SeqTally>>,
    /// When the current sequence opened, for escalation. A stalled proposer must pass the turn on,
    /// or a hash chain that cannot skip a sequence deadlocks forever.
    seq_opened_ts: RwLock<i64>,
}

/// What a finalisation produced, for the trust gate and for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalised {
    pub seq: u64,
    pub state_root: [u8; 32],
    pub batch_hash: [u8; 32],
    pub credited: usize,
    pub unattributed: usize,
}

impl ShadowChain {
    /// Load persisted state. A restart must resume the chain, not restart it: the trust gate wants
    /// a byte-identical `(seq, state_root)` across the fleet for a SUSTAINED window, and a node
    /// that reset its chain on every deploy could never contribute to one.
    pub fn load(identity: Arc<NodeIdentity>, db: Arc<Database>) -> GhostResult<Self> {
        let head = db.sbc_head()?;
        let balances = db.sbc_load_balances()?;
        info!(
            seq = head.as_ref().map(|h| h.seq),
            addresses = balances.len(),
            "SBC shadow: resumed"
        );
        // Quarantine survives the process by design, so restore it before judging anything.
        let restored: std::collections::HashSet<[u8; 32]> = db
            .sbc_quarantined()?
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        if !restored.is_empty() {
            info!(count = restored.len(), "SBC shadow: restored quarantine");
        }

        // The next sequence opened when the head was ADOPTED, not when its proposer closed it.
        // Using close_ts started escalation from the genesis checkpoint's cutoff, which on
        // ghost-vm8 was 32,473 s (9 h) before adoption — so the rota sat permanently escalated.
        let opened = head.as_ref().map(|h| h.finalised_at).unwrap_or(0);
        Ok(Self {
            identity,
            db,
            pending: Mutex::new(BTreeMap::new()),
            head: RwLock::new(head),
            balances: RwLock::new(balances),
            quarantine: Mutex::new(Quarantine::new()),
            restored_quarantine: RwLock::new(restored),
            vote_lock: Mutex::new(SeqVoteLock::new()),
            tallies: Mutex::new(BTreeMap::new()),
            seq_opened_ts: RwLock::new(opened),
        })
    }

    /// The head, for judging an incoming batch's parent.
    pub fn head(&self) -> Option<ChainHead> {
        self.head.read().clone()
    }

    /// The running balances — a copy, because a validator folds a candidate batch onto them and
    /// must not mutate the adopted state while doing it.
    pub fn balances(&self) -> BTreeMap<String, i64> {
        self.balances.read().clone()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// How many addresses carry a balance. Cheap — does not clone the map.
    pub fn balance_count(&self) -> usize {
        self.balances.read().len()
    }

    /// When the current sequence opened — the instant stall escalation is measured from.
    ///
    /// Exposed because it is the input to whose-turn-it-is, and a wrong value here is invisible
    /// from the outside: the rota still functions, it simply never lets a proposer hold a turn.
    pub fn seq_opened(&self) -> i64 {
        *self.seq_opened_ts.read()
    }

    /// Record a share THIS node received.
    ///
    /// Returns false — and keeps nothing — for a share received by a peer. That share belongs in
    /// the peer's batch; taking it here would credit the same work twice once both batches were
    /// adopted, and the two batches would each be individually valid.
    ///
    /// Idempotent on `share_hash`. Recording the same share twice must be harmless: a duplicate
    /// reaching a proposed batch is terminal, and the node that receives the most shares is the
    /// most likely to trip it — precisely the node the fleet can least afford to exclude.
    pub fn record_received(&self, share: ShareProof) -> bool {
        if share.received_by != self.identity.node_id() {
            return false;
        }
        self.pending.lock().insert(share.share_hash, share);
        true
    }

    /// Build the next batch from the pending pool, without proposing it.
    ///
    /// Returns `None` when there is nothing to batch. An empty batch is a legitimate claim ("I
    /// received nothing"), but proposing one on every tick would fill the chain with noise; the
    /// caller decides whether a heartbeat batch is wanted.
    ///
    /// The pool is NOT drained here. Draining before adoption would lose the shares if the batch
    /// failed to reach quorum — see [`ShadowChain::finalise`], which drains what was actually
    /// adopted.
    pub fn build_batch(&self, close_ts: i64, budget_bytes: usize) -> Option<ShareBatch> {
        let pending: Vec<ShareProof> = self.pending.lock().values().cloned().collect();
        if pending.is_empty() {
            return None;
        }

        let packed = pack_batch(&pending, budget_bytes);
        if packed.included.is_empty() {
            return None;
        }

        // Before genesis there is nothing to build on. The caller must run the genesis ceremony
        // first; proposing seq 0 from here would be starting a chain from nothing, which is a
        // chain anybody could start.
        let head = self.head()?;
        let (seq, prev_batch_hash) = (head.seq + 1, head.batch_hash);

        let mut balances = self.balances();
        fold_shares(&mut balances, &packed.included);
        let state_root = compute_state_root(&balances, seq, close_ts);

        let mut batch = ShareBatch {
            seq,
            prev_batch_hash,
            close_ts,
            proposer: self.identity.node_id(),
            shares: packed.included,
            settled_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root,
            truncated: packed.truncated,
            pending_count: packed.deferred.len() as u32,
            proposer_signature: Vec::new(),
        };
        let hash = batch.batch_hash();
        batch.proposer_signature = self.identity.sign(&hash).to_vec();
        Some(batch)
    }

    /// Propose, if it is this node's turn and there is something to say.
    ///
    /// Whose turn it is comes from [`ProposerSchedule`], including stall escalation — a hash chain
    /// cannot skip a sequence, so an absent proposer would deadlock it forever without the turn
    /// passing on. Exactly one node is authorised to propose at a time; acceptance is wider by a
    /// step to absorb clock skew, but proposing is not, or two nodes split the vote on one
    /// sequence.
    pub fn try_propose(
        &self,
        schedule: &ProposerSchedule,
        now: i64,
        budget_bytes: usize,
    ) -> Option<ShareBatch> {
        let head = self.head()?;
        let seq = head.seq + 1;
        let opened = *self.seq_opened_ts.read();
        if !schedule.is_my_turn(seq, &self.identity.node_id(), opened, now) {
            return None;
        }
        self.build_batch(now, budget_bytes)
    }

    /// Judge an incoming batch and record what follows.
    ///
    /// The decision is entirely `batch_driver::on_batch`'s — this supplies the context and applies
    /// the consequences. Position is judged before contents there, so a batch this node is not
    /// entitled to judge is never branded for a defect; the response to a fault cannot be taken
    /// back.
    pub fn on_proposal<C: ghost_common::batch_consensus::BatchChecks>(
        &self,
        batch: &ShareBatch,
        schedule: &ProposerSchedule,
        checks: &C,
        now: i64,
    ) -> Action {
        // A peer excluded in an earlier process stays excluded. Checked here rather than inside
        // the driver because the restored set is deliberately not replayed into `Quarantine`.
        if self.restored_quarantine.read().contains(&batch.proposer) {
            return Action::ProposerQuarantined;
        }

        let Some(parent_head) = self.head() else {
            // No genesis yet: we cannot judge anything and must catch up first.
            return Action::Hold {
                reason: ghost_common::batch_consensus::DeferReason::AheadOfUs {
                    batch_seq: batch.seq,
                    our_seq: 0,
                },
            };
        };

        // The driver judges against the parent BATCH, so a head we hold only as a summary is not
        // enough — fetch what we adopted. If it is outside the retention window we are too far
        // behind to judge and must sync, which is a defer, not a fault.
        let Ok(Some(parent_json)) = self.db.sbc_get_batch(parent_head.seq) else {
            return Action::Hold {
                reason: ghost_common::batch_consensus::DeferReason::AheadOfUs {
                    batch_seq: batch.seq,
                    our_seq: parent_head.seq,
                },
            };
        };
        let Ok(parent) = serde_json::from_str::<ShareBatch>(&parent_json) else {
            warn!(
                seq = parent_head.seq,
                "SBC shadow: stored parent will not deserialise — holding rather than judging"
            );
            return Action::Hold {
                reason: ghost_common::batch_consensus::DeferReason::AheadOfUs {
                    batch_seq: batch.seq,
                    our_seq: parent_head.seq,
                },
            };
        };

        let balances = self.balances();
        let ctx = BatchContext {
            parent: &parent,
            parent_balances: &balances,
            schedule,
            checks,
            now,
        };

        let action = {
            let mut quarantine = self.quarantine.lock();
            let mut lock = self.vote_lock.lock();
            on_batch(batch, &ctx, &mut quarantine, &mut lock)
        };

        // A terminal fault must outlive the process, or a restart silently forgives it.
        if let Action::Quarantine { reason, .. } = &action {
            let reason = format!("{reason:?}");
            if let Err(e) = self
                .db
                .sbc_quarantine(batch.proposer, &reason, Some(batch.seq), now)
            {
                warn!(error = %e, "SBC shadow: could not persist quarantine");
            }
            self.restored_quarantine.write().insert(batch.proposer);
        }

        action
    }

    /// Record a vote and report whether it carried the sequence.
    pub fn on_batch_vote(
        &self,
        voter: [u8; 32],
        batch_hash: [u8; 32],
        seq: u64,
        schedule: &ProposerSchedule,
        now: i64,
    ) -> VoteAction {
        let mut tallies = self.tallies.lock();
        let tally = tallies
            .entry(seq)
            .or_insert_with(|| SeqTally::new(seq, schedule.quorum()));
        let mut quarantine = self.quarantine.lock();
        on_vote(voter, batch_hash, tally, &mut quarantine, schedule, now)
    }

    /// The adopted batch at `seq`, verbatim, for answering a sync request.
    pub fn batch_at(&self, seq: u64) -> GhostResult<Option<String>> {
        self.db.sbc_get_batch(seq)
    }

    /// Note that a sequence has opened, so escalation is measured from the right moment.
    ///
    /// Without this the stall clock would run from the parent's `close_ts`, which is when the
    /// PREVIOUS batch closed — a sequence that opened late would look stalled the instant it began
    /// and escalate past a proposer who never had a chance.
    pub fn note_seq_opened(&self, now: i64) {
        *self.seq_opened_ts.write() = now;
    }

    /// Adopt a finalised batch: fold it, persist it, and advance the head.
    ///
    /// Persisted in an order chosen so a crash cannot leave the node claiming a head it has not
    /// folded: balances first, then the batch. Replaying a batch already folded is harmless —
    /// `sbc_store_batch` is idempotent on the same batch — whereas a head ahead of its balances
    /// would compute every later state root from the wrong state, silently and forever.
    pub fn finalise(&self, batch: &ShareBatch, now: i64) -> GhostResult<Finalised> {
        let mut balances = self.balances();
        let outcome = fold_shares(&mut balances, &batch.shares);
        let recomputed = compute_state_root(&balances, batch.seq, batch.close_ts);

        // The batch states its own root; recomputing must agree. A mismatch here means this node
        // folded different inputs from the proposer, and adopting it anyway would put a wrong
        // balance behind a root the fleet believes in.
        if recomputed != batch.state_root {
            warn!(
                seq = batch.seq,
                stated = %hex::encode(&batch.state_root[..8]),
                recomputed = %hex::encode(&recomputed[..8]),
                "SBC shadow: refusing to adopt — recomputed state root disagrees"
            );
            return Err(ghost_common::error::GhostError::Internal(format!(
                "state root mismatch at seq {}: stated {} recomputed {}",
                batch.seq,
                hex::encode(&batch.state_root[..8]),
                hex::encode(&recomputed[..8])
            )));
        }

        let batch_hash = batch.batch_hash();
        let batch_json = serde_json::to_string(batch).map_err(|e| {
            ghost_common::error::GhostError::Serialization(format!("batch {}: {e}", batch.seq))
        })?;

        self.db.sbc_save_balances(&balances, batch.seq)?;
        self.db.sbc_store_batch(
            batch.seq,
            batch_hash,
            batch.prev_batch_hash,
            batch.proposer,
            batch.close_ts,
            batch.state_root,
            batch.shares.len() as u32,
            &batch_json,
            now,
        )?;

        *self.balances.write() = balances;
        *self.head.write() = Some(ChainHead {
            seq: batch.seq,
            batch_hash,
            state_root: batch.state_root,
            close_ts: batch.close_ts,
            finalised_at: now,
        });

        // Drain exactly what was adopted. Anything not in this batch stays pending and lands in a
        // later one — which is why a share that misses its batch is deferred, never lost.
        {
            let mut pending = self.pending.lock();
            for s in &batch.shares {
                pending.remove(&s.share_hash);
            }
        }

        info!(
            seq = batch.seq,
            state_root = %hex::encode(&batch.state_root[..8]),
            credited = outcome.credited,
            unattributed = outcome.unattributed,
            pending = self.pending_count(),
            "SBC shadow: finalised"
        );

        Ok(Finalised {
            seq: batch.seq,
            state_root: batch.state_root,
            batch_hash,
            credited: outcome.credited,
            unattributed: outcome.unattributed,
        })
    }

    /// Bootstrap `seq 0` from a ratified payout checkpoint, if the chain has not started.
    ///
    /// Every node performs this conversion INDEPENDENTLY and must arrive at the same bytes. That is
    /// only true because the checkpoint is adopted verbatim by the fleet rather than recomputed —
    /// the raw share ledgers differ, the adopted `canonical_payout` does not. Recomputing genesis
    /// from local shares would reintroduce exactly the divergence the checkpoint exists to have
    /// settled.
    ///
    /// ## The proposer is ZERO, and that is load-bearing
    ///
    /// `batch_hash` commits to `proposer` (`share_batch.rs`). If each node used its own node id,
    /// all eight would derive an identical `state_root` and EIGHT DIFFERENT `batch_hash`es — and
    /// since `seq 1` names its parent by hash, the chain would fork at its very first link while
    /// every node believed it was correct. A zero proposer is also honest: genesis was converted,
    /// not proposed by anyone.
    ///
    /// `prev_batch_hash` is the checkpoint's `ledger_root`, so the first link points at the object
    /// that authorises it. A zero parent would be a chain anyone could start.
    ///
    /// Returns `Ok(None)` if the chain has already started (idempotent — a restart must not
    /// re-run genesis) or if no ratified checkpoint exists at or below `anchor_height`.
    pub fn bootstrap_genesis(&self, anchor_height: u64, now: i64) -> GhostResult<Option<u64>> {
        if self.head().is_some() {
            return Ok(None);
        }

        let Some(cp) = self
            .db
            .get_payout_ledger_checkpoint_at_or_before(anchor_height)?
        else {
            warn!(
                anchor_height,
                "SBC genesis: no ratified checkpoint at or below the anchor — cannot start"
            );
            return Ok(None);
        };

        if cp.miner_payouts.is_empty() {
            // A pre-option-(c) row carries no canonical payout. Starting from it would open every
            // balance at zero and silently write off every miner's accrued work.
            warn!(
                height = cp.height,
                "SBC genesis: checkpoint carries no canonical payout — refusing to open empty"
            );
            return Ok(None);
        }

        let (batch, balances, rounding) = ghost_accounting::batch_genesis::genesis_batch(
            cp.ledger_root,
            cp.cutoff_ts,
            [0u8; 32],
            &cp.miner_payouts,
            cp.node_shares.clone(),
        );

        info!(
            height = cp.height,
            cutoff_ts = cp.cutoff_ts,
            payees = balances.len(),
            state_root = %hex::encode(&batch.state_root[..8]),
            ledger_root = %hex::encode(&cp.ledger_root[..8]),
            addresses_rounded = rounding.addresses_rounded,
            addresses_dropped = rounding.addresses_dropped,
            units_discarded = rounding.units_discarded,
            "SBC genesis: converting a ratified checkpoint"
        );

        // Reported, never swallowed: a conversion that quietly loses balance is how an unexplained
        // drift begins, and at genesis there is nothing to reconcile against afterwards.
        if rounding.addresses_dropped > 0 {
            warn!(
                dropped = rounding.addresses_dropped,
                "SBC genesis: addresses rounded out of existence — their work is below one \
                 micro-work and cannot be represented"
            );
        }

        self.install_genesis(&batch, balances, now)?;
        Ok(Some(cp.height))
    }

    /// Install the genesis batch and its opening balances.
    ///
    /// Separate from [`ShadowChain::finalise`] because genesis is adopted by conversion of a
    /// finalised checkpoint rather than by vote, and it carries no shares — the work is already in
    /// the balances.
    pub fn install_genesis(
        &self,
        batch: &ShareBatch,
        balances: BTreeMap<String, i64>,
        now: i64,
    ) -> GhostResult<()> {
        let batch_hash = batch.batch_hash();
        let batch_json = serde_json::to_string(batch)
            .map_err(|e| ghost_common::error::GhostError::Serialization(format!("genesis: {e}")))?;

        self.db.sbc_save_balances(&balances, batch.seq)?;
        self.db.sbc_store_batch(
            batch.seq,
            batch_hash,
            batch.prev_batch_hash,
            batch.proposer,
            batch.close_ts,
            batch.state_root,
            0,
            &batch_json,
            now,
        )?;

        *self.balances.write() = balances;
        *self.head.write() = Some(ChainHead {
            seq: batch.seq,
            batch_hash,
            state_root: batch.state_root,
            close_ts: batch.close_ts,
            finalised_at: now,
        });
        // The first real sequence opens NOW, not at the checkpoint's cutoff.
        *self.seq_opened_ts.write() = now;

        info!(
            seq = batch.seq,
            state_root = %hex::encode(&batch.state_root[..8]),
            addresses = self.balances.read().len(),
            "SBC shadow: genesis installed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::share_batch::micro_work;

    const REACHABLE_DIFFICULTY: f64 = 1e-9;

    fn chain(identity: &Arc<NodeIdentity>) -> ShadowChain {
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        ShadowChain::load(Arc::clone(identity), db).expect("load")
    }

    fn share(identity: &NodeIdentity, addr: &str, work: f64, salt: u8) -> ShareProof {
        let mut header = vec![0u8; 80];
        header[0] = salt;
        let real_hash = {
            use bitcoin::hashes::{sha256d, Hash};
            sha256d::Hash::hash(&header).to_byte_array()
        };
        let mut s = ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: REACHABLE_DIFFICULTY,
            work,
            share_hash: real_hash,
            timestamp: 1_000 + salt as u64,
            received_by: identity.node_id(),
            template_id: Some([3u8; 32]),
            payout_address: Some(addr.to_string()),
            header: Some(header),
            signature: None,
        };
        s.sign(identity);
        s
    }

    fn genesis(chain: &ShadowChain, balances: BTreeMap<String, i64>) {
        let state_root = compute_state_root(&balances, 0, 500);
        let batch = ShareBatch {
            seq: 0,
            prev_batch_hash: [0xC0; 32],
            close_ts: 500,
            proposer: [0u8; 32],
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root,
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        chain.install_genesis(&batch, balances, 0).expect("genesis");
    }

    /// A node batches only what IT received. Taking a peer's share would credit the same work
    /// twice once both batches were adopted — and both batches would be individually valid, so
    /// nothing downstream would catch it.
    #[test]
    fn only_shares_this_node_received_are_batched() {
        let id = Arc::new(NodeIdentity::generate());
        let other = NodeIdentity::generate();
        let chain = chain(&id);

        assert!(chain.record_received(share(&id, "bc1qa", 1.0, 1)));
        assert!(
            !chain.record_received(share(&other, "bc1qa", 1.0, 2)),
            "a share received by a peer belongs in the peer's batch"
        );
        assert_eq!(chain.pending_count(), 1);
    }

    /// The state root must be a function of the balances after folding, and adopting must advance
    /// the head and persist both.
    #[test]
    fn finalising_folds_persists_and_advances_the_head() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        chain.record_received(share(&id, "bc1qa", 2.0, 1));
        chain.record_received(share(&id, "bc1qb", 3.0, 2));
        let batch = chain.build_batch(600, 1_000_000).expect("batch");

        let out = chain.finalise(&batch, 0).expect("finalise");
        assert_eq!(out.seq, 1);
        assert_eq!(out.credited, 2);

        let balances = chain.balances();
        assert_eq!(balances.get("bc1qa"), Some(&micro_work(2.0)));
        assert_eq!(balances.get("bc1qb"), Some(&micro_work(3.0)));

        let head = chain.head().expect("head");
        assert_eq!(head.seq, 1);
        assert_eq!(head.state_root, batch.state_root);
    }

    /// Persisted state must survive a restart, or the trust gate's sustained window resets on
    /// every deploy and can never be met.
    #[test]
    fn a_restart_resumes_the_chain_rather_than_restarting_it() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        let (seq, root) = {
            let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
            genesis(&chain, BTreeMap::new());
            chain.record_received(share(&id, "bc1qa", 7.0, 1));
            let batch = chain.build_batch(600, 1_000_000).expect("batch");
            let out = chain.finalise(&batch, 0).expect("finalise");
            (out.seq, out.state_root)
        };

        // A fresh instance over the same database — as a restart would be.
        let resumed = ShadowChain::load(id, db).expect("reload");
        let head = resumed.head().expect("head survives");
        assert_eq!(head.seq, seq);
        assert_eq!(head.state_root, root, "the resumed root must be identical");
        assert_eq!(resumed.balances().get("bc1qa"), Some(&micro_work(7.0)));
    }

    /// A batch whose stated root does not match a local recompute must be refused. Adopting it
    /// would place a wrong balance behind a root the fleet believes in — undetectable afterwards,
    /// because the node would then be internally consistent.
    #[test]
    fn a_batch_whose_stated_root_is_wrong_is_refused() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        let mut batch = chain.build_batch(600, 1_000_000).expect("batch");
        batch.state_root = [0xEE; 32];

        let err = chain.finalise(&batch, 0).expect_err("must refuse");
        assert!(format!("{err}").contains("state root mismatch"), "{err}");

        assert_eq!(
            chain.head().expect("head").seq,
            0,
            "the head must not advance"
        );
        assert!(chain.balances().is_empty(), "balances must be untouched");
    }

    /// Shares are drained only when adopted. A share left out of a batch stays pending and lands
    /// in a later one — deferred, never lost.
    #[test]
    fn unadopted_shares_stay_pending() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        for salt in 1..=3 {
            chain.record_received(share(&id, "bc1qa", 1.0, salt));
        }
        let batch = chain.build_batch(600, 1_000_000).expect("batch");
        let adopted = batch.shares.len();
        assert_eq!(adopted, 3);

        // Build does not drain — a batch that never reaches quorum must not cost the shares.
        assert_eq!(chain.pending_count(), 3, "building must not drain the pool");

        chain.finalise(&batch, 0).expect("finalise");
        assert_eq!(
            chain.pending_count(),
            0,
            "adoption drains exactly what was adopted"
        );
    }

    /// Before genesis there is nothing to build on, and a chain started from nothing is one
    /// anybody could start.
    #[test]
    fn no_batch_is_built_before_genesis() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        assert!(chain.build_batch(600, 1_000_000).is_none());
    }

    /// Genesis opens with converted balances and no shares — the work is already in the balances,
    /// and re-listing shares would invite a validator to re-derive numbers agreed by vote.
    #[test]
    fn genesis_opens_with_balances_and_no_shares() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        let opening: BTreeMap<String, i64> = [
            ("bc1qa".to_string(), 1_000i64),
            ("bc1qb".to_string(), 2_000i64),
        ]
        .into_iter()
        .collect();
        genesis(&chain, opening.clone());

        assert_eq!(chain.head().expect("head").seq, 0);
        assert_eq!(chain.balances(), opening);
    }

    /// Exactly one node proposes per sequence. Being generous here would put two nodes on one
    /// sequence and split the vote — acceptance is the thing that tolerates skew, not proposing.
    #[test]
    fn only_the_node_whose_turn_it_is_proposes() {
        let id = Arc::new(NodeIdentity::generate());
        let other = NodeIdentity::generate();
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());
        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        chain.note_seq_opened(500);

        // A schedule where the turn for seq 1 belongs to whoever sorts into that slot.
        let schedule = ProposerSchedule::new([id.node_id(), other.node_id()]);
        let mine = schedule.is_my_turn(1, &id.node_id(), 500, 500);

        let proposed = chain.try_propose(&schedule, 500, 1_000_000);
        assert_eq!(
            proposed.is_some(),
            mine,
            "a node must propose exactly when the rota says it is its turn"
        );
    }

    /// A stalled sequence must pass to the next node, or a hash chain that cannot skip a sequence
    /// deadlocks forever on an absent proposer.
    #[test]
    fn a_stalled_sequence_escalates_to_another_node() {
        let id = Arc::new(NodeIdentity::generate());
        let other = NodeIdentity::generate();
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());
        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        chain.note_seq_opened(500);

        let schedule = ProposerSchedule::new([id.node_id(), other.node_id()]);
        let at_open = schedule.is_my_turn(1, &id.node_id(), 500, 500);
        // Two escalation steps later the turn must have moved.
        let later = 500 + 2 * ghost_common::batch_consensus::STALL_ESCALATION_SECS;
        let after = schedule.is_my_turn(1, &id.node_id(), 500, later);
        assert_eq!(
            at_open, after,
            "with two voters, two steps returns the turn to its starting node"
        );

        let one_step = 500 + ghost_common::batch_consensus::STALL_ESCALATION_SECS;
        assert_ne!(
            at_open,
            schedule.is_my_turn(1, &id.node_id(), 500, one_step),
            "one step must hand the turn to the other node"
        );
    }

    /// A peer quarantined in an earlier process stays quarantined. Release is operator-only, and a
    /// restart is not an operator.
    #[test]
    fn quarantine_survives_a_restart() {
        let id = Arc::new(NodeIdentity::generate());
        let bad = NodeIdentity::generate();
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        db.sbc_quarantine(bad.node_id(), "wrong state root", Some(3), 0)
            .expect("quarantine");

        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        genesis(&chain, BTreeMap::new());

        let batch = ShareBatch {
            seq: 1,
            prev_batch_hash: [0u8; 32],
            close_ts: 600,
            proposer: bad.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id(), bad.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true);

        assert_eq!(
            chain.on_proposal(&batch, &schedule, &checks, 600),
            Action::ProposerQuarantined,
            "a peer excluded before the restart must not be judged again"
        );
    }

    /// An operator release readmits a peer to judgement on the next start.
    ///
    /// This is the other half of `quarantine_survives_a_restart`, and it is the half that had no
    /// caller: `sbc_release` existed but nothing outside its own unit test ever invoked it, so a
    /// quarantined node could never come back. The pair pins both directions — a restart alone
    /// must NOT readmit, a release must.
    #[test]
    fn an_operator_release_readmits_a_peer_on_the_next_start() {
        let id = Arc::new(NodeIdentity::generate());
        let bad = NodeIdentity::generate();
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        db.sbc_quarantine(bad.node_id(), "wrong state root", Some(3), 0)
            .expect("quarantine");

        // The operator releases it, then the node restarts.
        assert!(
            db.sbc_release(bad.node_id()).expect("release"),
            "release must report a change"
        );

        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        genesis(&chain, BTreeMap::new());

        let batch = ShareBatch {
            seq: 1,
            prev_batch_hash: [0u8; 32],
            close_ts: 600,
            proposer: bad.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id(), bad.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true);

        assert_ne!(
            chain.on_proposal(&batch, &schedule, &checks, 600),
            Action::ProposerQuarantined,
            "a released peer must be judged on merit again, not rejected on sight"
        );
    }

    /// Judging must never happen against a parent we do not hold — that is a sync condition, not a
    /// disagreement, and faulting it would have honest nodes quarantining each other.
    #[test]
    fn a_batch_is_held_not_faulted_when_we_lack_the_parent() {
        let id = Arc::new(NodeIdentity::generate());
        let peer = NodeIdentity::generate();
        let chain = chain(&id);
        // No genesis: we hold nothing.

        let batch = ShareBatch {
            seq: 9,
            prev_batch_hash: [0xAB; 32],
            close_ts: 600,
            proposer: peer.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id(), peer.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true);

        assert!(
            matches!(
                chain.on_proposal(&batch, &schedule, &checks, 600),
                Action::Hold { .. }
            ),
            "no parent means hold and sync, never accuse"
        );
    }

    /// The property the WP-5 trust gate is defined by: separate nodes, separate databases, and a
    /// byte-identical `(seq, state_root)` after adopting the same chain.
    ///
    /// `share_batch.rs` already proves the pure fold agrees across simulated nodes. This proves it
    /// survives the parts that are NOT pure — three independent stores, three encryption keys, and
    /// a round trip through SQLite in between. A divergence introduced by persistence would be
    /// invisible to the fold's own tests and fatal to the gate.
    ///
    /// ⚠ A convergence assertion alone CANNOT catch a uniform arithmetic error: every node runs the
    /// same fold, so a fold that is wrong the same way everywhere still agrees. Verified by
    /// mutation — adding 1 to every credit leaves the roots identical and this test green. So the
    /// expected balances are pinned by value below, and correctness of the quantisation itself is
    /// `share_batch.rs`'s job. Agreement and correctness are different claims and need different
    /// assertions.
    #[test]
    fn separate_nodes_with_separate_stores_converge_on_one_state_root() {
        let ids: Vec<Arc<NodeIdentity>> =
            (0..3).map(|_| Arc::new(NodeIdentity::generate())).collect();

        // Distinct encryption keys per node, as the fleet has: the ciphertext differs everywhere,
        // and only the plaintext balances may agree.
        let chains: Vec<ShadowChain> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let db = Arc::new(Database::in_memory().expect("db"));
                db.set_encryption_key([(0x40 + i) as u8; 32]);
                ShadowChain::load(Arc::clone(id), db).expect("load")
            })
            .collect();

        let opening: BTreeMap<String, i64> =
            [("bc1qopen".to_string(), 5_000i64)].into_iter().collect();
        for c in &chains {
            genesis(c, opening.clone());
        }

        // Node 0 receives work and proposes; the others adopt what it produced.
        chains[0].record_received(share(&ids[0], "bc1qa", 2.0, 1));
        chains[0].record_received(share(&ids[0], "bc1qb", 3.0, 2));
        let batch = chains[0].build_batch(600, 1_000_000).expect("batch");

        for c in &chains {
            c.finalise(&batch, 0)
                .expect("every node must adopt the same batch");
        }

        let heads: Vec<_> = chains.iter().map(|c| c.head().expect("head")).collect();
        for h in &heads[1..] {
            assert_eq!(h.seq, heads[0].seq, "sequences must match");
            assert_eq!(
                h.state_root, heads[0].state_root,
                "state roots must be byte-identical — this is the trust gate's criterion"
            );
        }
        for c in &chains[1..] {
            assert_eq!(
                c.balances(),
                chains[0].balances(),
                "balances must agree despite different encryption keys"
            );
        }

        // Pinned by VALUE, not merely by agreement — see the mutation note above.
        let expected: BTreeMap<String, i64> = [
            ("bc1qopen".to_string(), 5_000i64),
            ("bc1qa".to_string(), micro_work(2.0)),
            ("bc1qb".to_string(), micro_work(3.0)),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            chains[0].balances(),
            expected,
            "opening balance carried forward plus each share credited exactly once"
        );

        // And it must survive the round trip through storage, which is where a divergence the
        // fold's own tests cannot see would appear.
        for (i, c) in chains.iter().enumerate() {
            let reloaded = c.db.sbc_load_balances().expect("reload");
            assert_eq!(
                reloaded,
                chains[0].balances(),
                "node {i} disagrees after a store round trip"
            );
        }
    }

    /// A second batch must chain onto the first on every node, so convergence is a property of the
    /// chain rather than of one lucky adoption.
    #[test]
    fn convergence_holds_across_successive_batches() {
        let ids: Vec<Arc<NodeIdentity>> =
            (0..3).map(|_| Arc::new(NodeIdentity::generate())).collect();
        let chains: Vec<ShadowChain> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let db = Arc::new(Database::in_memory().expect("db"));
                db.set_encryption_key([(0x40 + i) as u8; 32]);
                ShadowChain::load(Arc::clone(id), db).expect("load")
            })
            .collect();
        for c in &chains {
            genesis(c, BTreeMap::new());
        }

        // Each node takes a turn proposing, so the chain is not built by one node alone.
        for (round, proposer) in [0usize, 1, 2].into_iter().enumerate() {
            let salt = (round + 1) as u8;
            chains[proposer].record_received(share(&ids[proposer], "bc1qa", 1.0, salt));
            let batch = chains[proposer]
                .build_batch(600 + round as i64, 1_000_000)
                .expect("batch");
            for c in &chains {
                c.finalise(&batch, 0).expect("adopt");
            }
        }

        let heads: Vec<_> = chains.iter().map(|c| c.head().expect("head")).collect();
        assert_eq!(heads[0].seq, 3, "three batches on top of genesis");
        for h in &heads[1..] {
            assert_eq!(
                h.state_root, heads[0].state_root,
                "roots must still agree at seq 3"
            );
        }
        // Work from three different proposers, all credited once.
        assert_eq!(
            chains[0].balances().get("bc1qa"),
            Some(&(3 * micro_work(1.0))),
            "each proposer's share must be credited exactly once"
        );
    }

    fn seed_checkpoint(db: &Database, height: u64, cutoff_ts: i64) {
        // Built through the real accessor rather than raw SQL: a fixture that writes the row its
        // own way proves the reader agrees with the fixture, not that it agrees with the writer.
        // Uses the actual adopted figures from 961,642 — the chosen genesis anchor.
        let record = ghost_storage::queries::PayoutLedgerCheckpointRecord {
            height,
            cutoff_ts,
            ledger_root: [0xABu8; 32],
            proposer_id: "deadbeef".to_string(),
            active_node_count: 8,
            miner_payouts: vec![
                (
                    "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                    52_157_533_139_126_865_362_944u128,
                ),
                (
                    "bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".to_string(),
                    2_503_874_639_417_892_143_104u128,
                ),
            ],
            node_shares: vec![([1u8; 32], 10), ([2u8; 32], 6)],
        };
        db.upsert_payout_ledger_checkpoint(&record)
            .expect("seed checkpoint");
    }

    /// THE genesis correctness property: every node converts the same checkpoint into the same
    /// bytes, independently.
    ///
    /// `batch_hash` commits to `proposer`. If genesis used each node's own id, all eight would
    /// derive an identical state_root and EIGHT DIFFERENT batch hashes — and since seq 1 names its
    /// parent by hash, the chain would fork at its first link with every node believing it was
    /// correct. This asserts the HASH, not just the root.
    #[test]
    fn genesis_is_byte_identical_across_independently_converting_nodes() {
        let mut hashes = Vec::new();
        let mut roots = Vec::new();

        for i in 0..3u8 {
            let id = Arc::new(NodeIdentity::generate());
            let db = Arc::new(Database::in_memory().expect("db"));
            db.set_encryption_key([0x40 + i; 32]);
            seed_checkpoint(&db, 961_642, 1_786_228_093);

            let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
            let height = chain
                .bootstrap_genesis(961_642, 0)
                .expect("bootstrap")
                .expect("a checkpoint was available");
            assert_eq!(height, 961_642);

            let head = chain.head().expect("head");
            hashes.push(head.batch_hash);
            roots.push(head.state_root);
        }

        for h in &hashes[1..] {
            assert_eq!(
                *h, hashes[0],
                "genesis BATCH HASH must be identical — differing hashes fork the chain at seq 1 \
                 even when every state_root agrees"
            );
        }
        for r in &roots[1..] {
            assert_eq!(*r, roots[0], "genesis state root must be identical");
        }
    }

    /// A restart must not re-run genesis, or the chain restarts from the anchor and every batch
    /// adopted since is silently discarded.
    #[test]
    fn genesis_is_idempotent() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);

        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        assert!(chain
            .bootstrap_genesis(961_642, 0)
            .expect("first")
            .is_some());
        assert!(
            chain
                .bootstrap_genesis(961_642, 0)
                .expect("second")
                .is_none(),
            "a chain that has already started must not be re-genesised"
        );
        assert_eq!(chain.head().expect("head").seq, 0);
    }

    /// Without a ratified checkpoint there is nothing to convert, and opening every balance at zero
    /// would write off every miner's accrued work.
    #[test]
    fn genesis_refuses_when_there_is_nothing_ratified_to_convert() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        let chain = ShadowChain::load(id, db).expect("load");
        assert!(
            chain
                .bootstrap_genesis(961_642, 0)
                .expect("bootstrap")
                .is_none(),
            "no checkpoint means no chain, not an empty one"
        );
        assert!(chain.head().is_none());
    }

    /// Convert the REAL adopted checkpoint at 961,642 — the pinned genesis anchor — through the
    /// real storage accessor and the real bootstrap, and check it lands on the golden vector.
    ///
    /// The other genesis tests use a fixture. This one uses the exact bytes all 8 nodes ratified,
    /// read back the way a node will read them, so it tests the PATH and not just the arithmetic.
    /// If this ever disagrees with `batch_genesis.rs`'s pinned root, either the conversion or the
    /// state-root encoding has moved and the ceremony would open eight different chains.
    #[test]
    fn the_real_961642_checkpoint_converts_to_the_pinned_genesis_root() {
        fn hexid(h: &str) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("hex");
            }
            out
        }

        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        // Exactly what the fleet adopted, read from ghost-vm8 2026-08-09: 5 payees, 8 node
        // entries, cutoff_ts 1786228093.
        let record = ghost_storage::queries::PayoutLedgerCheckpointRecord {
            height: 961_642,
            cutoff_ts: 1_786_228_093,
            ledger_root: hexid("0fe9bac3023f624b99b087a9c7e6c4c8b5cd557225f0ea9ef9828608fec0caa9"),
            proposer_id: "unused-by-genesis".to_string(),
            active_node_count: 8,
            miner_payouts: vec![
                (
                    "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                    52_157_533_139_126_865_362_944u128,
                ),
                (
                    "bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".to_string(),
                    2_503_874_639_417_892_143_104u128,
                ),
                (
                    "bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".to_string(),
                    2_341_458_453_435_845_967_872u128,
                ),
                (
                    "148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN".to_string(),
                    478_353_203_210_592_976_896u128,
                ),
                (
                    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h".to_string(),
                    9_741_908_758_669_000_704u128,
                ),
            ],
            node_shares: vec![
                (
                    hexid("5867b555602257bdffa5d4c3577c464416087f2aa04ac478f3986a17e51d3393"),
                    6,
                ),
                (
                    hexid("e557c97a32335457ed6eceb6f8a9c7ee13f8731ee99dc9f4b7831dcf606d6927"),
                    10,
                ),
                (
                    hexid("fb71fee87bb0516920fdb673f3068be3c0b9b29fc62e309b99594a0008c25622"),
                    10,
                ),
                (
                    hexid("849bceceb22cc7ebbeec252d824940ebb73ee08c7855c5a90b5661dd21aeb18c"),
                    10,
                ),
                (
                    hexid("9fe860bda96ff81820a2e166f48cb3ae59010fc9e42550a3aeafb5bfef4d1b38"),
                    10,
                ),
                (
                    hexid("46141044f80c99ac01476b3c2d6cd2149f31b5f1b06ffd2dfa3d15d588c7a39b"),
                    6,
                ),
                (
                    hexid("f0215f1ffd9a711ffc8e476f37bf3e19a2afc18803d146ecedb5d53d4fe9bd4f"),
                    6,
                ),
                (
                    hexid("4c8c2272ae67d76c6c4108f0e4e6dfde7ff864689d3e9b99a35ab1bd46051132"),
                    6,
                ),
            ],
        };
        db.upsert_payout_ledger_checkpoint(&record).expect("seed");

        let chain = ShadowChain::load(id, Arc::clone(&db)).expect("load");
        let h = chain
            .bootstrap_genesis(crate::SBC_GENESIS_ANCHOR_HEIGHT, 0)
            .expect("bootstrap")
            .expect("the anchor checkpoint is present");
        assert_eq!(h, 961_642);

        let head = chain.head().expect("head");
        let root: String = head.state_root.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            root, "cb5ac8470686192246bfc1330791e85023f2044b58f0b076b167ff89923ddc7f",
            "the real checkpoint must convert to the golden vector pinned in batch_genesis.rs"
        );

        // The first link must point at the object that authorises it.
        assert!(
            chain.batch_at(0).expect("stored").is_some(),
            "genesis must be retrievable for a peer syncing from seq 0"
        );

        // Five payees survive; the dominant one holds ~90% of the ledger and is where a
        // conversion bug would actually cost someone money.
        let balances = chain.balances();
        assert_eq!(
            balances.len(),
            5,
            "every ratified payee must open with a balance"
        );
        assert_eq!(
            balances.get("bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492"),
            Some(&52_157_533_139_126_865i64)
        );
    }

    /// The escalation clock must read ADOPTION time, not the proposer's close time.
    ///
    /// A genesis head carries the converted checkpoint's `cutoff_ts`. Measured on ghost-vm8:
    /// cutoff 1786228093, adopted 1786260566 — a 32,473 s (9 h) gap, so escalation read 416 steps
    /// where it should have read ~34. The rota sat permanently escalated, rotating the turn every
    /// 90 s rather than giving a proposer a stable one.
    ///
    /// Invisible from outside: the rota still works, nobody diverges, and every node agrees. It is
    /// simply always wrong in the same way, which is why it needs an explicit assertion.
    #[test]
    fn the_escalation_clock_reads_adoption_time_not_close_time() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        let stale_close = 1_786_228_093; // a checkpoint cutoff, days in the past
        let adopted_at = 1_786_470_000; // when this node took it
        db.sbc_store_batch(
            0,
            [1u8; 32],
            [0u8; 32],
            [0u8; 32],
            stale_close,
            [2u8; 32],
            0,
            "{}",
            adopted_at,
        )
        .expect("adopt");

        let chain = ShadowChain::load(id, db).expect("load");
        assert_eq!(
            chain.seq_opened(),
            adopted_at,
            "escalation must run from adoption; reading close_ts starts it days in the past"
        );
        assert_ne!(chain.seq_opened(), stale_close);
    }

    /// Genesis opens the first real sequence NOW, not at the checkpoint's cutoff.
    #[test]
    fn genesis_opens_the_next_sequence_at_bootstrap_time() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);

        let chain = ShadowChain::load(id, Arc::clone(&db)).expect("load");
        let bootstrap_at = 1_786_470_000;
        chain
            .bootstrap_genesis(961_642, bootstrap_at)
            .expect("bootstrap")
            .expect("converted");

        assert_eq!(
            chain.seq_opened(),
            bootstrap_at,
            "the first sequence opens when the chain starts, not when the checkpoint closed"
        );
    }

    /// Recording the same share twice must NOT put it in a batch twice.
    ///
    /// Found on the live four-node run, 2026-08-09. `record_received` pushed onto a Vec with no
    /// dedup, the share recorder fired more than once for a share, and ghost-vm5 proposed a batch
    /// containing a duplicate. `verify_batch` correctly ruled it `DuplicateShare` — a TERMINAL
    /// fault — so vm6, vm7 and vm8 all quarantined vm5, and quarantine is operator-release-only.
    ///
    /// The node receiving the most shares is the most likely to trip this, which is exactly the
    /// node a pool can least afford to exclude from its own consensus. No unit test caught it
    /// because nothing in-process delivered the same share twice.
    #[test]
    fn recording_a_share_twice_does_not_duplicate_it_in_a_batch() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        let a = share(&id, "bc1qa", 2.0, 1);
        let b = share(&id, "bc1qb", 3.0, 2);
        assert_ne!(
            a.share_hash, b.share_hash,
            "fixture must produce distinct shares"
        );

        assert!(chain.record_received(a.clone()));
        assert!(
            chain.record_received(a.clone()),
            "a repeat must be accepted, not rejected"
        );
        assert!(chain.record_received(a), "and again");
        assert!(chain.record_received(b));

        // TWO distinct shares must survive. Asserting only that a repeat collapses would pass even
        // if the pool keyed every share under one constant — verified by mutation.
        assert_eq!(
            chain.pending_count(),
            2,
            "distinct shares must not collapse together"
        );

        let batch = chain.build_batch(600, 1_000_000).expect("batch");
        assert_eq!(
            batch.shares.len(),
            2,
            "a duplicate in a batch is a terminal fault"
        );

        // And the credit must be for one share, not three.
        chain.finalise(&batch, 0).expect("finalise");
        assert_eq!(
            chain.balances().get("bc1qa"),
            Some(&micro_work(2.0)),
            "a share recorded three times must be credited once"
        );
        assert_eq!(
            chain.balances().get("bc1qb"),
            Some(&micro_work(3.0)),
            "the other share must still be credited"
        );
    }
}
