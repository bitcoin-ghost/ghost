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
    MessageEnvelope, MessageHandler, MessageType, PayoutLedgerCheckpointMessage,
    PayoutLedgerCheckpointVoteMessage,
};
use ghost_storage::{Database, PayoutLedgerCheckpointRecord};

/// BFT approval threshold (percent of the active/elder set).
const BFT_THRESHOLD_PERCENT: u64 = 67;

/// Enqueues an outbound broadcast `(msg_type, json_payload)`. Injected so the
/// manager doesn't depend on the mesh directly: `main.rs` wires a closure that
/// pushes to the broadcast task (as `ConvergenceHandler` does), and tests wire a
/// closure that captures messages for in-process routing under induced lag.
pub type BroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// The canonical payout a node computes at a cutoff: the miner set (payout address →
/// WORK_SCALE-quantised work) and the qualified-node set (node_id → 5-4-3-2-1 shares),
/// plus their root `H(miners ‖ nodes)`. Option (c): the fleet BFT-ratifies the
/// proposer's `CanonicalPayout` (tolerance-checked, not byte-identical) and ADOPTS it,
/// so agreement no longer needs every node's local ledger to be identical.
#[derive(Clone, Debug)]
pub struct CanonicalPayout {
    pub miner_payouts: Vec<(String, u128)>,
    pub node_shares: Vec<(NodeId, i32)>,
    pub root: [u8; 32],
}

pub type ComputeRootFn = Arc<dyn Fn(i64, u64) -> Option<CanonicalPayout> + Send + Sync>;

/// Miner-work tolerance for option (c). The share SET converges (proven by the union)
/// but attribution (same share → different miner_id representation) and float-sum-order
/// leave a per-address work difference; a voter approves the proposer's canonical payout
/// if every address's work is within `REL_TOL` (relative) or `ABS_TOL` (absolute floor)
/// of its own. This is sound because the fleet is SINGLE-OPERATOR — an honest quorum
/// still bounds any per-block drift to the tolerance, strictly stronger than no split.
const REL_TOL_NUM: u128 = 2; // 2%
const REL_TOL_DEN: u128 = 100;
const ABS_TOL: u128 = 1_000_000_000_000; // ~one share of WORK_SCALE-quantised work

/// Does the proposer's canonical payout agree with our own within tolerance?
/// Node set: exact (it converges via payout-address gossip). Miner set: identical
/// address keys, each address's work within tolerance.
fn payouts_agree(
    local: &CanonicalPayout,
    proposed_miners: &[(String, u128)],
    proposed_nodes: &[(NodeId, i32)],
) -> bool {
    let mut ln = local.node_shares.clone();
    ln.sort();
    let mut pn = proposed_nodes.to_vec();
    pn.sort();
    if ln != pn {
        return false;
    }

    let lm: HashMap<&str, u128> = local
        .miner_payouts
        .iter()
        .map(|(a, w)| (a.as_str(), *w))
        .collect();
    if lm.len() != proposed_miners.len() {
        return false;
    }
    for (addr, pw) in proposed_miners {
        let pw = *pw;
        let Some(&lw) = lm.get(addr.as_str()) else {
            return false; // address only in the proposal
        };
        let diff = lw.max(pw) - lw.min(pw);
        let tol = (lw / REL_TOL_DEN * REL_TOL_NUM).max(ABS_TOL);
        if diff > tol {
            return false;
        }
    }
    true
}

/// Optional diagnostic: `(cutoff_ts, height) -> human breakdown` of the root inputs
/// (miner-set + node-set hashed separately, with counts + node list). Injected by
/// `main.rs` to isolate live root divergence; `None` in tests and once diagnosed.
pub type ComputeRootDiagFn = Arc<dyn Fn(i64, u64) -> String + Send + Sync>;

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
    send: BroadcastFn,
    compute_root: ComputeRootFn,
    /// Optional root-input breakdown for live divergence diagnosis.
    diag: Option<ComputeRootDiagFn>,
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
        send: BroadcastFn,
        compute_root: ComputeRootFn,
    ) -> Self {
        Self {
            identity,
            db,
            send,
            compute_root,
            diag: None,
            pending: RwLock::new(HashMap::new()),
        }
    }

    /// Attach a diagnostic breakdown closure (see [`ComputeRootDiagFn`]).
    pub fn with_diag(mut self, diag: ComputeRootDiagFn) -> Self {
        self.diag = Some(diag);
        self
    }

    /// Emit the root-input breakdown at INFO under a shared `tag`, if diag is wired.
    fn log_diag(&self, tag: &str, height: u64, cutoff_ts: i64) {
        if let Some(d) = &self.diag {
            info!(height, tag, "payout checkpoint DIAG: {}", d(cutoff_ts, height));
        }
    }

    /// Serialise + enqueue an outbound broadcast (fire-and-forget).
    fn broadcast<T: serde::Serialize>(&self, ty: MessageType, msg: &T) {
        match serde_json::to_vec(msg) {
            Ok(bytes) => {
                if let Err(e) = (self.send)(ty, bytes) {
                    warn!(error = %e, "payout checkpoint: enqueue broadcast failed");
                }
            }
            Err(e) => error!(error = %e, "payout checkpoint: serialise failed"),
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
    pub async fn maybe_propose(&self, height: u64, cutoff_ts: i64) {
        let me = self.identity.node_id();
        if self.proposer_for(height) != Some(me) || self.already_finalized(height) {
            return;
        }
        let Some(canonical) = (self.compute_root)(cutoff_ts, height) else {
            // C-7: cannot compute from our own view — do not propose an
            // unreproducible payout; wait for convergence.
            warn!(
                height,
                "payout checkpoint: canonical payout not computable (data not converged) — not proposing"
            );
            return;
        };

        let active_node_count = self.elders_sorted().len() as u32;
        let mut msg = PayoutLedgerCheckpointMessage {
            height,
            cutoff_ts,
            ledger_root: canonical.root,
            miner_payouts: canonical.miner_payouts,
            node_shares: canonical.node_shares,
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
            root = %hex::encode(&msg.ledger_root[..8]),
            miners = msg.miner_payouts.len(),
            nodes = msg.node_shares.len(),
            "payout checkpoint: proposing"
        );
        self.log_diag("propose", height, cutoff_ts);
        self.broadcast(MessageType::PayoutLedgerCheckpoint, &msg);
        self.cast_vote(height, hash, true);
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

        // INTEGRITY: the proposer's `ledger_root` must actually be the hash of the lists
        // it sent — otherwise the signed `checkpoint_hash` (which commits to `ledger_root`)
        // wouldn't bind the payload, and a proposer could ship one root but different lists.
        let claimed_root = crate::payout::compute_ledger_root(
            &msg.miner_payouts,
            &msg.node_shares,
            msg.cutoff_ts,
            msg.height,
        );
        if claimed_root != msg.ledger_root {
            warn!(
                height = msg.height,
                proposer = %hex::encode(&msg.proposer[..4]),
                "payout checkpoint: proposal root does not match its lists — voting reject"
            );
            self.cast_vote(msg.height, hash, false);
            return Ok(());
        }

        // Option (c): recompute our OWN canonical payout and tolerance-check the proposer's.
        let Some(local) = (self.compute_root)(msg.cutoff_ts, msg.height) else {
            // C-7: we lack the data to judge it — abstain (do NOT approve).
            warn!(
                height = msg.height,
                "payout checkpoint: cannot recompute canonical payout — abstaining (needs convergence)"
            );
            self.log_diag("abstain", msg.height, msg.cutoff_ts);
            let height = msg.height;
            let mut pending = self.pending.write();
            let slot = pending
                .entry(height)
                .or_insert_with(Pending::new)
                .entry(hash);
            slot.proposal = Some(msg);
            return Ok(());
        };
        // Approve if the proposer's payout is within tolerance of ours (attribution +
        // float-order noise is same-operator cosmetic); a real misallocation exceeds it.
        let approve = payouts_agree(&local, &msg.miner_payouts, &msg.node_shares);
        // DIAG (tolerance-zero readiness): does our OWN root match the proposer's EXACTLY?
        // If `exact=true` holds fleet-wide, the determinism fixes are sufficient and the
        // tolerance can be dropped to zero (multi-operator-safe). `exact=false, approve=true`
        // means we're still relying on tolerance.
        info!(
            height = msg.height,
            exact = (local.root == msg.ledger_root),
            approve,
            local_root = %hex::encode(&local.root[..8]),
            proposed_root = %hex::encode(&msg.ledger_root[..8]),
            "payout checkpoint: vote"
        );
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
                local_root = %hex::encode(&local.root[..8]),
                proposed_root = %hex::encode(&msg.ledger_root[..8]),
                proposer = %hex::encode(&msg.proposer[..4]),
                "payout checkpoint: payout outside tolerance — voting reject"
            );
            self.log_diag("reject", msg.height, msg.cutoff_ts);
        }
        self.cast_vote(msg.height, hash, approve);
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

    fn cast_vote(&self, height: u64, checkpoint_hash: [u8; 32], approve: bool) {
        let mut vote = PayoutLedgerCheckpointVoteMessage {
            height,
            checkpoint_hash,
            voter: self.identity.node_id(),
            approve,
            signature: [0u8; 64],
            timestamp: now_ms(),
        };
        vote.signature = self.identity.sign(&vote.signing_message());
        self.broadcast(MessageType::PayoutLedgerCheckpointVote, &vote);
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
            // Adopt-on-finalise: persist the proposer's canonical lists verbatim so the
            // coinbase builds from THEM, not from this node's (divergent) local ledger.
            miner_payouts: msg.miner_payouts.clone(),
            node_shares: msg.node_shares.clone(),
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

#[cfg(test)]
mod tests {
    //! In-process N-node cluster tests with INDUCED per-node ledger divergence —
    //! the property that only a converged input finalises, and a divergent/lagged
    //! or malicious view can never force a bad checkpoint. This is exactly the
    //! gap that shipped v1.10.32 broken (regtest had no gossip lag → false green).
    use super::*;
    use ghost_storage::MpcContributionRecord;
    use std::sync::Mutex;

    type Outbox = Arc<Mutex<Vec<(MessageType, Vec<u8>)>>>;

    struct Node {
        id: NodeId,
        db: Arc<Database>,
        mgr: PayoutCheckpointManager,
        outbox: Outbox,
    }

    fn register_elders(db: &Database, elders: &[NodeId]) {
        for (i, e) in elders.iter().enumerate() {
            db.save_mpc_contribution(&MpcContributionRecord {
                elder_position: (i as u32) + 1,
                contributor_node_id: hex::encode(e),
                prev_params_hash: [0u8; 32],
                new_params_hash: [0u8; 32],
                contribution_proof: Vec::new(),
                epoch: 0,
                created_at: 0,
            })
            .expect("save elder");
        }
    }

    /// Build `n` nodes whose elder set is all `n` ids (sorted by node_id). The
    /// node at SORTED position `i` computes `roots[i]` from its own view
    /// (`None` = "can't compute yet" → C-7 abstain). Building in sorted order
    /// means `nodes[i].id == elders_sorted[i]`, so the proposer for height `H` is
    /// `nodes[H % n]` — deterministic and controllable.
    /// A shared 3-node qualified set every test uses (node set must match EXACTLY for
    /// approval — it converges via payout-address gossip in production).
    fn node_set() -> Vec<(NodeId, i32)> {
        vec![([1u8; 32], 10), ([2u8; 32], 6), ([3u8; 32], 6)]
    }

    /// Build a `CanonicalPayout` from a miner list (address, work), reusing `node_set()`.
    fn cp(miners: &[(&str, u128)]) -> CanonicalPayout {
        let miner_payouts: Vec<(String, u128)> =
            miners.iter().map(|(a, w)| (a.to_string(), *w)).collect();
        let node_shares = node_set();
        let root = crate::payout::compute_ledger_root(&miner_payouts, &node_shares, CUTOFF, H);
        CanonicalPayout {
            miner_payouts,
            node_shares,
            root,
        }
    }

    /// Build `n` nodes; node at SORTED elder position `i` computes `payouts[i]` from its
    /// own view (`None` = C-7 abstain). Sorted order means `nodes[i].id == elders_sorted[i]`,
    /// so the proposer for height `H` is `nodes[H % n]`.
    fn build(n: usize, payouts: &[Option<CanonicalPayout>]) -> Vec<Node> {
        assert_eq!(n, payouts.len());
        let ids: Vec<Arc<NodeIdentity>> =
            (0..n).map(|_| Arc::new(NodeIdentity::generate())).collect();
        let mut elders: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        elders.sort_unstable();

        let mut nodes = Vec::new();
        for (pos, &want) in elders.iter().enumerate() {
            let identity = ids.iter().find(|i| i.node_id() == want).unwrap().clone();
            let db = Arc::new(Database::in_memory().expect("db"));
            register_elders(&db, &elders);
            let outbox: Outbox = Arc::new(Mutex::new(Vec::new()));
            let ob = Arc::clone(&outbox);
            let send: BroadcastFn = Arc::new(move |ty, bytes| {
                ob.lock().unwrap().push((ty, bytes));
                Ok(())
            });
            let payout = payouts[pos].clone();
            let compute_root: ComputeRootFn = Arc::new(move |_c, _h| payout.clone());
            let mgr = PayoutCheckpointManager::new(
                identity.clone(),
                Arc::clone(&db),
                send,
                compute_root,
            );
            nodes.push(Node {
                id: identity.node_id(),
                db,
                mgr,
                outbox,
            });
        }
        nodes
    }

    fn drain(n: &Node) -> Vec<(MessageType, Vec<u8>)> {
        std::mem::take(&mut *n.outbox.lock().unwrap())
    }

    /// Deliver every queued broadcast to every other node until the fleet is
    /// quiet (bounded — the flow settles in a couple of rounds).
    async fn gossip_until_quiet(nodes: &[Node]) {
        for _ in 0..20 {
            let mut msgs = Vec::new();
            for n in nodes {
                for (ty, payload) in drain(n) {
                    msgs.push((n.id, ty, payload));
                }
            }
            if msgs.is_empty() {
                break;
            }
            for (from, ty, payload) in msgs {
                for n in nodes {
                    if n.id != from {
                        let env =
                            Arc::new(MessageEnvelope::new(ty, from, payload.clone(), 0, [0u8; 64]));
                        n.mgr.handle_message(env).await.expect("handle");
                    }
                }
            }
        }
    }

    const H: u64 = 100; // 100 % 4 == 0 → proposer is sorted-elder[0] = nodes[0]
    const CUTOFF: i64 = 1_784_000_000;

    #[tokio::test]
    async fn convergent_fleet_finalises_and_adopts_lists() {
        let payout = cp(&[("bc1qaaa", 1_000_000_000_000_000), ("bc1qbbb", 500_000_000_000_000)]);
        let nodes = build(4, &vec![Some(payout.clone()); 4]);
        assert_eq!(nodes[0].mgr.proposer_for(H), Some(nodes[0].id));
        assert_eq!(nodes[0].mgr.quorum_needed(), 3, "67% of 4 = 3");
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            let rec = n
                .db
                .get_latest_payout_ledger_checkpoint()
                .unwrap()
                .expect("every node finalises");
            assert_eq!(rec.ledger_root, payout.root);
            assert_eq!(rec.height, H);
            // Adopt-on-finalise: the canonical lists are persisted verbatim.
            assert_eq!(rec.miner_payouts, payout.miner_payouts, "adopted miner list");
            assert_eq!(rec.node_shares.len(), 3, "adopted node list");
        }
    }

    #[tokio::test]
    async fn within_tolerance_divergence_still_finalises() {
        // THE option-(c) property: nodes DON'T have byte-identical ledgers. The proposer
        // says a miner has 1_000_000..., peers each computed a slightly different value
        // (attribution/float noise) — all within 2% — so they ADOPT the proposer's list.
        let proposer = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let near1 = cp(&[("bc1qaaa", 1_005_000_000_000_000)]); // +0.5%
        let near2 = cp(&[("bc1qaaa", 995_000_000_000_000)]); //  -0.5%
        let near3 = cp(&[("bc1qaaa", 1_010_000_000_000_000)]); // +1.0%
        let nodes = build(
            4,
            &[Some(proposer.clone()), Some(near1), Some(near2), Some(near3)],
        );
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            let rec = n
                .db
                .get_latest_payout_ledger_checkpoint()
                .unwrap()
                .expect("finalises within tolerance");
            // Every node adopted the PROPOSER's exact value — convergence by adoption.
            assert_eq!(rec.miner_payouts, proposer.miner_payouts);
        }
    }

    #[tokio::test]
    async fn gross_misallocation_outside_tolerance_rejected() {
        // Proposer + one peer agree; two peers computed a value 2x off (WAY beyond 2%).
        // Those two reject → only 2 approvals < 3 → nothing finalises (safe).
        let a = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let gross = cp(&[("bc1qaaa", 2_000_000_000_000_000)]);
        let nodes = build(4, &[Some(a.clone()), Some(a), Some(gross.clone()), Some(gross)]);
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            assert!(n.db.get_latest_payout_ledger_checkpoint().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn c7_abstainer_does_not_block_liveness() {
        let a = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let nodes = build(4, &[Some(a.clone()), Some(a.clone()), Some(a), None]);
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            n.db.get_latest_payout_ledger_checkpoint()
                .unwrap()
                .expect("finalises despite one abstainer");
        }
    }

    #[tokio::test]
    async fn proposal_root_not_matching_its_lists_rejected() {
        // Integrity: a proposal whose ledger_root does NOT hash its own lists is rejected
        // even from the real proposer — otherwise the signed hash wouldn't bind the payload.
        let a = cp(&[("bc1qaaa", 1_000_000_000_000_000)]);
        let nodes = build(4, &vec![Some(a.clone()); 4]);
        let proposer = nodes[0].id;
        let msg = PayoutLedgerCheckpointMessage {
            height: H,
            cutoff_ts: CUTOFF,
            ledger_root: [9u8; 32], // does NOT match the lists below
            miner_payouts: a.miner_payouts.clone(),
            node_shares: a.node_shares.clone(),
            active_node_count: 4,
            proposer,
            proposer_signature: [0u8; 64],
            timestamp: 0,
        };
        let payload = serde_json::to_vec(&msg).unwrap();
        for n in &nodes[1..] {
            let env = Arc::new(MessageEnvelope::new(
                MessageType::PayoutLedgerCheckpoint,
                proposer,
                payload.clone(),
                0,
                [0u8; 64],
            ));
            n.mgr.handle_message(env).await.unwrap();
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            assert!(n.db.get_latest_payout_ledger_checkpoint().unwrap().is_none());
        }
    }
}
