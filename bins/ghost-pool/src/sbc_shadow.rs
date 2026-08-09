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
        Ok(Self {
            identity,
            db,
            pending: Mutex::new(Vec::new()),
            head: RwLock::new(head),
            balances: RwLock::new(balances),
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
}
