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
    /// Shares this node received and has not yet packed into a batch.
    ///
    /// Bounded by the pack budget on the way out, not on the way in: dropping a share here is work
    /// a miner never gets paid for, whereas a large pool merely produces a truncated batch and the
    /// remainder is carried to the next one.
    pending: Mutex<Vec<ShareProof>>,
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

        let opened = head.as_ref().map(|h| h.close_ts).unwrap_or(0);
        Ok(Self {
            identity,
            db,
            pending: Mutex::new(Vec::new()),
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

    /// Record a share THIS node received.
    ///
    /// Returns false — and keeps nothing — for a share received by a peer. That share belongs in
    /// the peer's batch; taking it here would credit the same work twice once both batches were
    /// adopted, and the two batches would each be individually valid.
    pub fn record_received(&self, share: ShareProof) -> bool {
        if share.received_by != self.identity.node_id() {
            return false;
        }
        self.pending.lock().push(share);
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
        let pending = self.pending.lock().clone();
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
        });

        // Drain exactly what was adopted. Anything not in this batch stays pending and lands in a
        // later one — which is why a share that misses its batch is deferred, never lost.
        {
            let adopted: std::collections::HashSet<&[u8; 32]> =
                batch.shares.iter().map(|s| &s.share_hash).collect();
            self.pending
                .lock()
                .retain(|s| !adopted.contains(&s.share_hash));
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
        });

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
}
