//! Payout-ledger checkpoint finalisation (payout-finalisation P1, task 3).
//!
//! The coherent fix for the payout-agreement problem: instead of every node
//! independently recomputing the coinbase from its own live ledger at `now()`
//! (which is never converged — the v1.10.32 failure), the fleet BFT-**finalises**
//! a `PayoutLedgerCheckpoint {height, cutoff_ts, ledger_root}` at a lagging,
//! chain-committed height. The coinbase then becomes a pure function of the
//! agreed checkpoint (see `tasks/design_payout_finalization.md`).
//!
//! Flow (mirrors the L2 nullifier checkpoint, but decoupled and payout-scoped):
//! - **Propose**: the deterministic proposer for `height` (`elders[height % n]`,
//!   over the MPC elder set) computes `ledger_root` from ITS converged view at
//!   `cutoff_ts = block(height).time` and broadcasts the checkpoint.
//! - **Vote**: every elder independently recomputes the root; it votes approve
//!   iff its root equals the proposal's. A node that cannot yet compute the root
//!   (data not converged) **abstains** rather than approving — the C-7 rule.
//! - **Finalise**: at ≥67% approvals for a checkpoint hash, the checkpoint is
//!   persisted (`payout_ledger_checkpoints`), identical fleet-wide.
//!
//! Authentication rides the mesh's Noise channel: `envelope.sender` is
//! cryptographically authenticated, so proposer/voter identity is taken from it
//! (and cross-checked against the message's declared field). Messages also carry
//! a signature over their content hash for defence in depth.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;
use ghost_consensus::{
    MeshNetwork, MessageEnvelope, MessageHandler, MessageType, PayoutLedgerCheckpointMessage,
    PayoutLedgerCheckpointVoteMessage,
};
use ghost_storage::{Database, PayoutLedgerCheckpointRecord};

/// BFT approval threshold (percent of the active/elder set).
const BFT_THRESHOLD_PERCENT: u64 = 67;

/// `(cutoff_ts, height) -> Some(ledger_root)` if this node can compute the
/// canonical root from its converged view, or `None` if it lacks the data
/// (triggers the C-7 abstain-and-wait-for-convergence path). Injected by
/// `main.rs`, which holds the DB + qualification engine.
pub type ComputeRootFn = Arc<dyn Fn(i64, u64) -> Option<[u8; 32]> + Send + Sync>;

/// `height -> Some(block timestamp)`: the deterministic, chain-committed cutoff
/// anchor. `None` if the anchor block isn't known locally yet.
pub type BlockTimeFn = Arc<dyn Fn(u64) -> Option<i64> + Send + Sync>;

struct PendingEntry {
    /// The proposal content (needed to persist on finalise). `None` if a vote
    /// arrived before the proposal (race) — we still tally the approver.
    proposal: Option<PayoutLedgerCheckpointMessage>,
    approvers: HashSet<NodeId>,
}

struct Pending {
    by_hash: HashMap<[u8; 32], PendingEntry>,
    finalized: bool,
}

impl Pending {
    fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
            finalized: false,
        }
    }
    fn entry(&mut self, hash: [u8; 32]) -> &mut PendingEntry {
        self.by_hash.entry(hash).or_insert_with(|| PendingEntry {
            proposal: None,
            approvers: HashSet::new(),
        })
    }
}

/// Drives payout-ledger checkpoint proposal/voting/finalisation and also acts as
/// the mesh `MessageHandler` for the two payout-checkpoint message types.
pub struct PayoutCheckpointManager {
    identity: Arc<NodeIdentity>,
    db: Arc<Database>,
    mesh: Arc<MeshNetwork>,
    compute_root: ComputeRootFn,
    block_time_at: BlockTimeFn,
    /// height -> in-flight vote tallies.
    pending: RwLock<HashMap<u64, Pending>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl PayoutCheckpointManager {
    pub fn new(
        identity: Arc<NodeIdentity>,
        db: Arc<Database>,
        mesh: Arc<MeshNetwork>,
        compute_root: ComputeRootFn,
        block_time_at: BlockTimeFn,
    ) -> Self {
        Self {
            identity,
            db,
            mesh,
            compute_root,
            block_time_at,
            pending: RwLock::new(HashMap::new()),
        }
    }

    /// Deterministic, fleet-agreed elder set, sorted so every node indexes it
    /// identically.
    fn elders_sorted(&self) -> Vec<NodeId> {
        let mut e: Vec<NodeId> = self
            .db
            .get_mpc_elder_node_ids()
            .unwrap_or_default()
            .into_iter()
            .collect();
        e.sort_unstable();
        e
    }

    /// Deterministic proposer for `height` (round-robin over the elder set).
    fn proposer_for(&self, height: u64) -> Option<NodeId> {
        let e = self.elders_sorted();
        if e.is_empty() {
            None
        } else {
            Some(e[(height as usize) % e.len()])
        }
    }

    /// Approvals required for finalisation (ceil of 67% of the elder set).
    fn quorum_needed(&self) -> usize {
        let n = self.elders_sorted().len() as u64;
        (n * BFT_THRESHOLD_PERCENT).div_ceil(100) as usize
    }

    fn already_finalized(&self, height: u64) -> bool {
        if self
            .pending
            .read()
            .get(&height)
            .map(|p| p.finalized)
            .unwrap_or(false)
        {
            return true;
        }
        // Durably persisted at this exact height?
        matches!(
            self.db.get_payout_ledger_checkpoint_at_or_before(height),
            Ok(Some(r)) if r.height == height
        )
    }

    /// Called on a cadence from `main.rs` with the target lagging checkpoint
    /// height. No-op unless this node is the deterministic proposer for it.
    pub async fn maybe_propose(&self, height: u64) {
        let me = self.identity.node_id();
        if self.proposer_for(height) != Some(me) || self.already_finalized(height) {
            return;
        }
        let Some(cutoff_ts) = (self.block_time_at)(height) else {
            debug!(height, "payout checkpoint: anchor block time unknown yet");
            return;
        };
        let Some(ledger_root) = (self.compute_root)(cutoff_ts, height) else {
            // C-7: cannot compute from our own view — do not propose an
            // unreproducible root; wait for convergence.
            warn!(
                height,
                "payout checkpoint: ledger_root not computable (data not converged) — not proposing"
            );
            return;
        };

        let active_node_count = self.elders_sorted().len() as u32;
        let mut msg = PayoutLedgerCheckpointMessage {
            height,
            cutoff_ts,
            ledger_root,
            active_node_count,
            proposer: me,
            proposer_signature: [0u8; 64],
            timestamp: now_ms(),
        };
        let hash = msg.checkpoint_hash();
        msg.proposer_signature = self.identity.sign(&hash);

        // Record our own proposal + approval, then broadcast both.
        {
            let mut pending = self.pending.write();
            let p = pending.entry(height).or_insert_with(Pending::new);
            let e = p.entry(hash);
            e.proposal = Some(msg.clone());
            e.approvers.insert(me);
        }
        info!(
            height,
            root = %hex::encode(&ledger_root[..8]),
            "payout checkpoint: proposing"
        );
        if let Err(e) = self
            .mesh
            .broadcast_message(MessageType::PayoutLedgerCheckpoint, &msg)
            .await
        {
            warn!(height, error = %e, "payout checkpoint: proposal broadcast failed");
        }
        self.cast_vote(height, hash, true).await;
        self.maybe_finalize(height, hash);
    }

    async fn on_proposal(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let msg: PayoutLedgerCheckpointMessage = match serde_json::from_slice(&env.payload) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        // Authorisation: the Noise-authenticated sender must be the declared
        // proposer AND the deterministic proposer for this height.
        if env.sender != msg.proposer || self.proposer_for(msg.height) != Some(msg.proposer) {
            debug!(height = msg.height, "payout checkpoint: proposal from non-proposer — ignored");
            return Ok(());
        }
        if self.already_finalized(msg.height) {
            return Ok(());
        }
        let hash = msg.checkpoint_hash();

        // Recompute the root from our own converged view.
        let Some(local_root) = (self.compute_root)(msg.cutoff_ts, msg.height) else {
            // C-7: we lack the data to reproduce it — abstain (do NOT approve).
            warn!(
                height = msg.height,
                "payout checkpoint: cannot recompute ledger_root — abstaining (needs convergence)"
            );
            // Still record the proposal so a later recompute/vote can finalise.
            let height = msg.height;
            let mut pending = self.pending.write();
            let slot = pending
                .entry(height)
                .or_insert_with(Pending::new)
                .entry(hash);
            slot.proposal = Some(msg);
            return Ok(());
        };
        let approve = local_root == msg.ledger_root;
        {
            let mut pending = self.pending.write();
            let p = pending.entry(msg.height).or_insert_with(Pending::new);
            let e = p.entry(hash);
            e.proposal = Some(msg.clone());
            if approve {
                e.approvers.insert(self.identity.node_id());
            }
        }
        if !approve {
            warn!(
                height = msg.height,
                "payout checkpoint: local root mismatch — voting reject"
            );
        }
        self.cast_vote(msg.height, hash, approve).await;
        if approve {
            self.maybe_finalize(msg.height, hash);
        }
        Ok(())
    }

    async fn on_vote(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let vote: PayoutLedgerCheckpointVoteMessage = match serde_json::from_slice(&env.payload) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        // Authenticated sender must be the voter, and the voter must be an elder.
        if env.sender != vote.voter {
            return Ok(());
        }
        if !self.elders_sorted().contains(&vote.voter) {
            debug!("payout checkpoint: vote from non-elder — ignored");
            return Ok(());
        }
        if !vote.approve {
            return Ok(());
        }
        {
            let mut pending = self.pending.write();
            pending
                .entry(vote.height)
                .or_insert_with(Pending::new)
                .entry(vote.checkpoint_hash)
                .approvers
                .insert(vote.voter);
        }
        self.maybe_finalize(vote.height, vote.checkpoint_hash);
        Ok(())
    }

    async fn cast_vote(&self, height: u64, checkpoint_hash: [u8; 32], approve: bool) {
        let mut vote = PayoutLedgerCheckpointVoteMessage {
            height,
            checkpoint_hash,
            voter: self.identity.node_id(),
            approve,
            signature: [0u8; 64],
            timestamp: now_ms(),
        };
        vote.signature = self.identity.sign(&vote.signing_message());
        if let Err(e) = self
            .mesh
            .broadcast_message(MessageType::PayoutLedgerCheckpointVote, &vote)
            .await
        {
            warn!(height, error = %e, "payout checkpoint: vote broadcast failed");
        }
    }

    /// Persist the checkpoint once ≥67% of elders have approved a hash for which
    /// we hold the proposal content. Idempotent.
    fn maybe_finalize(&self, height: u64, hash: [u8; 32]) {
        let needed = self.quorum_needed();
        if needed == 0 {
            return;
        }
        let mut pending = self.pending.write();
        let Some(p) = pending.get_mut(&height) else {
            return;
        };
        if p.finalized {
            return;
        }
        let Some(entry) = p.by_hash.get(&hash) else {
            return;
        };
        if entry.approvers.len() < needed {
            return;
        }
        let Some(msg) = entry.proposal.clone() else {
            // Quorum reached but we don't hold the proposal content — cannot
            // persist yet; the proposal message will arrive and re-trigger this.
            return;
        };
        let record = PayoutLedgerCheckpointRecord {
            height,
            cutoff_ts: msg.cutoff_ts,
            ledger_root: msg.ledger_root,
            proposer_id: hex::encode(msg.proposer),
            active_node_count: msg.active_node_count,
        };
        match self.db.upsert_payout_ledger_checkpoint(&record) {
            Ok(()) => {
                p.finalized = true;
                info!(
                    height,
                    root = %hex::encode(&msg.ledger_root[..8]),
                    approvals = entry.approvers.len(),
                    needed,
                    "payout ledger checkpoint FINALISED"
                );
            }
            Err(e) => error!(height, error = %e, "payout checkpoint: persist failed"),
        }
    }
}

#[async_trait]
impl MessageHandler for PayoutCheckpointManager {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        match envelope.msg_type {
            MessageType::PayoutLedgerCheckpoint => self.on_proposal(&envelope).await,
            MessageType::PayoutLedgerCheckpointVote => self.on_vote(&envelope).await,
            _ => Ok(()),
        }
    }
}
