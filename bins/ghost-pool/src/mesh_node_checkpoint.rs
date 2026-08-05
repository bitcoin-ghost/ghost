//! Mesh node-list checkpoint finalisation (decentralised mining discovery).
//!
//! A BFT-finalised, signed snapshot of the public-mining node set that an UNTRUSTED
//! miner-side shim can verify offline, so mining discovery no longer depends on trusting
//! DNS or a website. Mirrors [`crate::payout_checkpoint`]'s BFT lifecycle, with three
//! differences specific to this checkpoint:
//!
//! - **Agreement is exact-set, not tolerance.** A voter approves iff its own connected
//!   public-mining set hashes to the same `list_root` as the proposer's.
//! - **The signer set rides a forward chain.** Each checkpoint carries `signer_set_root`
//!   (the root of the deterministic voter set, committed in `checkpoint_hash`) and a
//!   `signer_set_delta` vs the previous checkpoint. A shim baked with the genesis signer set
//!   (the MPC elders) advances it by applying deltas, verifying each resulting set against
//!   the signed root (decision C — see `tasks/design_mesh_node_list_checkpoint.md`).
//! - **The finalised record keeps signatures.** Unlike the payout checkpoint (whose consumer
//!   is the local coinbase builder), this checkpoint is served to external shims, so the
//!   proposer signature and the ≥67% approver signatures are persisted, and sync adoption
//!   verifies the whole signed blob rather than recomputing from a (possibly unconverged)
//!   local mesh view.
//!
//! DORMANT until `MESH_NODE_LIST_CHECKPOINT_HEIGHT` — below the gate nothing is proposed.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, error, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::{verify_signature, NodeIdentity};
use ghost_common::types::NodeId;
use ghost_consensus::{
    mesh_node_list_root, mesh_signer_set_root, MeshNodeEntry, MeshNodeListCheckpointMessage,
    MeshNodeListCheckpointSyncEntry, MeshNodeListCheckpointSyncRequest,
    MeshNodeListCheckpointSyncResponse, MeshNodeListCheckpointVoteMessage, MessageEnvelope,
    MessageHandler, MessageType, SignerSetDelta,
};
use ghost_storage::{Database, MeshNodeListCheckpointRecord};

use crate::payout_checkpoint::{widen_voter_set, BroadcastFn};

/// BFT approval threshold (percent of the voter/signer set).
const BFT_THRESHOLD_PERCENT: u64 = 67;

/// Backfill cooldown (client re-request and per-peer serve). Mirrors the payout sync window.
const SYNC_COOLDOWN_MS: u64 = 60_000;

/// Max checkpoints served per sync response; the requester paginates if capped.
const MAX_SYNC_CHECKPOINTS: u64 = 8;

/// Computes THIS node's canonical public-mining node set at a cutoff:
/// `(cutoff_ts, height) -> sorted node entries`. `None` = cannot compute yet (mesh view not
/// ready) → the C-7 abstain rule. `main.rs` wires this to the live mesh peer state.
pub type ComputeNodeListFn = Arc<dyn Fn(i64, u64) -> Option<Vec<MeshNodeEntry>> + Send + Sync>;

/// Resolves the ACTIVE qualified voter set at a cutoff (see the payout manager's analog).
/// `None` in tests → the elder floor is always used.
pub type ActiveVoterSetFn = Arc<dyn Fn(i64, u64) -> Vec<NodeId> + Send + Sync>;

struct PendingEntry {
    /// The proposal content (needed to persist on finalise). `None` if a vote arrived first.
    proposal: Option<MeshNodeListCheckpointMessage>,
    /// voter -> their approve-vote signature over the vote signing message. Kept (not just a
    /// `HashSet<NodeId>`) so the finalised record can carry the verifiable approver signatures.
    approvals: HashMap<NodeId, [u8; 64]>,
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
            approvals: HashMap::new(),
        })
    }
}

/// Drives mesh node-list checkpoint proposal/voting/finalisation and acts as the mesh
/// `MessageHandler` for the three mesh-node-list-checkpoint message types.
pub struct MeshNodeListCheckpointManager {
    identity: Arc<NodeIdentity>,
    db: Arc<Database>,
    send: BroadcastFn,
    compute_nodes: ComputeNodeListFn,
    active_voter_set: Option<ActiveVoterSetFn>,
    /// Activation-height override for tests. `None` (production) = read the live gate
    /// `crate::mesh_node_list_checkpoint_height()` (u64::MAX = dormant on mainnet).
    gate_height: Option<u64>,
    pending: RwLock<HashMap<u64, Pending>>,
    last_sync_request: RwLock<u64>,
    sync_serves: RwLock<HashMap<NodeId, u64>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Approvals required to finalise: ceil of 67% of `n` voters.
fn quorum_for(n: usize) -> usize {
    (n as u64 * BFT_THRESHOLD_PERCENT).div_ceil(100) as usize
}

/// Decode a hex node-id string back to a `NodeId`.
fn decode_node_id(s: &str) -> Option<NodeId> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// A 64-byte signature from a `Vec<u8>` (storage/wire hold them as `Vec` since serde arrays
/// stop at 32); `None` on a wrong length.
fn vec_to_sig(v: &[u8]) -> Option<[u8; 64]> {
    if v.len() != 64 {
        return None;
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(v);
    Some(a)
}

fn entries_to_storage(nodes: &[MeshNodeEntry]) -> Vec<([u8; 32], String, u16, u16)> {
    nodes
        .iter()
        .map(|e| (e.node_id, e.host.clone(), e.sv1_port, e.sv2_port))
        .collect()
}

fn storage_to_entries(nodes: &[([u8; 32], String, u16, u16)]) -> Vec<MeshNodeEntry> {
    nodes
        .iter()
        .map(|(id, host, s1, s2)| MeshNodeEntry {
            node_id: *id,
            host: host.clone(),
            sv1_port: *s1,
            sv2_port: *s2,
        })
        .collect()
}

impl MeshNodeListCheckpointManager {
    pub fn new(
        identity: Arc<NodeIdentity>,
        db: Arc<Database>,
        send: BroadcastFn,
        compute_nodes: ComputeNodeListFn,
    ) -> Self {
        Self {
            identity,
            db,
            send,
            compute_nodes,
            active_voter_set: None,
            gate_height: None,
            pending: RwLock::new(HashMap::new()),
            last_sync_request: RwLock::new(0),
            sync_serves: RwLock::new(HashMap::new()),
        }
    }

    /// Attach the active-voter-set resolver (see the payout manager's analog). Once the
    /// `ACTIVE_VOTER_SET` gate is active, the signer/voter set widens from the MPC elders to
    /// the converged active qualified set.
    pub fn with_active_voter_set_fn(mut self, f: ActiveVoterSetFn) -> Self {
        self.active_voter_set = Some(f);
        self
    }

    /// Override the activation height (tests only); production reads the live gate.
    #[cfg(test)]
    fn with_gate_height(mut self, h: u64) -> Self {
        self.gate_height = Some(h);
        self
    }

    /// The activation height at/above which this checkpoint is live. Below it the whole
    /// subsystem is dormant: nothing is proposed, and no backfill is requested.
    fn gate(&self) -> u64 {
        self.gate_height
            .unwrap_or_else(crate::mesh_node_list_checkpoint_height)
    }

    fn broadcast<T: serde::Serialize>(&self, ty: MessageType, msg: &T) {
        match serde_json::to_vec(msg) {
            Ok(bytes) => {
                if let Err(e) = (self.send)(ty, bytes) {
                    warn!(error = %e, "mesh node checkpoint: enqueue broadcast failed");
                }
            }
            Err(e) => error!(error = %e, "mesh node checkpoint: serialise failed"),
        }
    }

    /// Deterministic, fleet-agreed elder set, sorted. This is also the shim's genesis anchor.
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

    /// The consensus voter/signer set for `height` at `cutoff_ts`: the MPC elder set below the
    /// `ACTIVE_VOTER_SET` gate (or with no resolver), the widened active qualified set at/above
    /// it. Identical logic and floor to the payout manager, so both consensuses draw the same set.
    fn voter_set_for(&self, height: u64, cutoff_ts: i64) -> Vec<NodeId> {
        let elders = self.elders_sorted();
        if height >= crate::active_voter_set_height() {
            if let Some(resolve) = &self.active_voter_set {
                return widen_voter_set(elders, resolve(cutoff_ts, height));
            }
        }
        elders
    }

    /// Deterministic proposer for `height` (round-robin over the voter set at `cutoff_ts`).
    fn proposer_for(&self, height: u64, cutoff_ts: i64) -> Option<NodeId> {
        let v = self.voter_set_for(height, cutoff_ts);
        if v.is_empty() {
            None
        } else {
            Some(v[(height as usize) % v.len()])
        }
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
        matches!(
            self.db.get_mesh_node_list_checkpoint_at_or_before(height),
            Ok(Some(r)) if r.height == height
        )
    }

    /// The signer-set forward-chain delta from the previous checkpoint's set to `current`,
    /// plus the root of `current`. The previous set is recomputed deterministically from the
    /// latest finalised checkpoint's `(height, cutoff)`; with none yet, the genesis anchor is
    /// the elder set (what the shim is baked with). The delta is not itself in `checkpoint_hash`
    /// — it is verified by a shim against the committed `signer_set_root`.
    fn signer_delta(&self, current: &[NodeId]) -> (SignerSetDelta, [u8; 32]) {
        let prev_set = match self.db.get_latest_mesh_node_list_checkpoint() {
            Ok(Some(prev)) => self.voter_set_for(prev.height, prev.cutoff_ts),
            _ => self.elders_sorted(),
        };
        let prev: HashSet<NodeId> = prev_set.into_iter().collect();
        let cur: HashSet<NodeId> = current.iter().copied().collect();
        let mut added: Vec<NodeId> = cur.difference(&prev).copied().collect();
        let mut removed: Vec<NodeId> = prev.difference(&cur).copied().collect();
        added.sort_unstable();
        removed.sort_unstable();
        (
            SignerSetDelta { added, removed },
            mesh_signer_set_root(current),
        )
    }

    /// Called on a cadence from `main.rs` with the target lagging checkpoint height. No-op
    /// unless this node is the deterministic proposer AND the node set actually changed since
    /// the latest finalised checkpoint (the cadence decision: re-affirm, don't re-checkpoint).
    pub async fn maybe_propose(&self, height: u64, cutoff_ts: i64) {
        if height < self.gate() {
            return; // dormant below the activation gate — behaviour-neutral
        }
        let me = self.identity.node_id();
        let voters = self.voter_set_for(height, cutoff_ts);
        let proposer = (!voters.is_empty()).then(|| voters[(height as usize) % voters.len()]);
        if proposer != Some(me) || self.already_finalized(height) {
            return;
        }
        let Some(mut nodes) = (self.compute_nodes)(cutoff_ts, height) else {
            warn!(
                height,
                "mesh node checkpoint: node set not computable yet — not proposing"
            );
            return;
        };
        nodes.sort_by_key(|n| n.node_id);
        let list_root = mesh_node_list_root(&nodes);

        // Cadence: only checkpoint when the set changed. If the latest finalised checkpoint
        // already commits this exact list, re-affirm silently rather than mint a duplicate.
        if let Ok(Some(latest)) = self.db.get_latest_mesh_node_list_checkpoint() {
            if latest.list_root == list_root {
                debug!(
                    height,
                    "mesh node checkpoint: node set unchanged — not re-proposing"
                );
                return;
            }
        }

        let (signer_set_delta, signer_set_root) = self.signer_delta(&voters);
        let mut msg = MeshNodeListCheckpointMessage {
            height,
            cutoff_ts,
            nodes,
            list_root,
            signer_set_delta,
            signer_set_root,
            active_node_count: voters.len() as u32,
            proposer: me,
            proposer_signature: [0u8; 64],
            timestamp: now_ms(),
        };
        let hash = msg.checkpoint_hash();
        msg.proposer_signature = self.identity.sign(&hash);

        {
            let mut pending = self.pending.write();
            let p = pending.entry(height).or_insert_with(Pending::new);
            p.entry(hash).proposal = Some(msg.clone());
        }
        info!(
            height,
            list_root = %hex::encode(&list_root[..8]),
            nodes = msg.nodes.len(),
            "mesh node checkpoint: proposing"
        );
        self.broadcast(MessageType::MeshNodeListCheckpoint, &msg);
        self.cast_vote(height, hash, true);
        self.maybe_finalize(height, hash);
    }

    async fn on_proposal(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let msg: MeshNodeListCheckpointMessage = match serde_json::from_slice(&env.payload) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };
        if env.sender != msg.proposer
            || self.proposer_for(msg.height, msg.cutoff_ts) != Some(msg.proposer)
        {
            debug!(
                height = msg.height,
                "mesh node checkpoint: proposal from non-proposer — ignored"
            );
            return Ok(());
        }
        if self.already_finalized(msg.height) {
            return Ok(());
        }
        let hash = msg.checkpoint_hash();

        // INTEGRITY: the declared roots must actually describe the payload / deterministic set,
        // else the signed hash wouldn't bind them.
        let voters = self.voter_set_for(msg.height, msg.cutoff_ts);
        if mesh_node_list_root(&msg.nodes) != msg.list_root
            || mesh_signer_set_root(&voters) != msg.signer_set_root
        {
            warn!(
                height = msg.height,
                "mesh node checkpoint: proposal roots do not match — voting reject"
            );
            self.cast_vote(msg.height, hash, false);
            return Ok(());
        }

        // EXACT-SET AGREEMENT: recompute our own connected public-mining set; approve iff it
        // hashes to the same list_root. Cannot compute yet → abstain (C-7).
        let Some(local) = (self.compute_nodes)(msg.cutoff_ts, msg.height) else {
            warn!(
                height = msg.height,
                "mesh node checkpoint: cannot recompute node set — abstaining"
            );
            let height = msg.height;
            let mut pending = self.pending.write();
            pending
                .entry(height)
                .or_insert_with(Pending::new)
                .entry(hash)
                .proposal = Some(msg);
            return Ok(());
        };
        let approve = mesh_node_list_root(&local) == msg.list_root;
        info!(height = msg.height, approve, "mesh node checkpoint: vote");
        {
            let mut pending = self.pending.write();
            pending
                .entry(msg.height)
                .or_insert_with(Pending::new)
                .entry(hash)
                .proposal = Some(msg.clone());
        }
        self.cast_vote(msg.height, hash, approve);
        if approve {
            self.maybe_finalize(msg.height, hash);
        }
        Ok(())
    }

    async fn on_vote(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let vote: MeshNodeListCheckpointVoteMessage = match serde_json::from_slice(&env.payload) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        if env.sender != vote.voter || !vote.approve {
            return Ok(());
        }
        // Defence in depth: only record a signature that actually verifies for the voter.
        if !verify_signature(&vote.voter, &vote.signing_message(), &vote.signature).unwrap_or(false)
        {
            return Ok(());
        }
        {
            let mut pending = self.pending.write();
            pending
                .entry(vote.height)
                .or_insert_with(Pending::new)
                .entry(vote.checkpoint_hash)
                .approvals
                .insert(vote.voter, vote.signature);
        }
        self.maybe_finalize(vote.height, vote.checkpoint_hash);
        Ok(())
    }

    fn cast_vote(&self, height: u64, checkpoint_hash: [u8; 32], approve: bool) {
        let mut vote = MeshNodeListCheckpointVoteMessage {
            height,
            checkpoint_hash,
            voter: self.identity.node_id(),
            approve,
            signature: [0u8; 64],
            timestamp: now_ms(),
        };
        vote.signature = self.identity.sign(&vote.signing_message());
        if approve {
            // Record our own approval signature locally so a checkpoint we finalise carries it.
            let mut pending = self.pending.write();
            pending
                .entry(height)
                .or_insert_with(Pending::new)
                .entry(checkpoint_hash)
                .approvals
                .insert(vote.voter, vote.signature);
        }
        self.broadcast(MessageType::MeshNodeListCheckpointVote, &vote);
    }

    /// Persist once ≥67% of the voter set have approved a hash for which we hold the proposal.
    /// The record keeps the proposer + approver signatures so it can be served to shims.
    fn maybe_finalize(&self, height: u64, hash: [u8; 32]) {
        let mut pending = self.pending.write();
        let Some(p) = pending.get_mut(&height) else {
            return;
        };
        if p.finalized {
            return;
        }
        let (approvals, msg) = {
            let Some(entry) = p.by_hash.get(&hash) else {
                return;
            };
            let Some(msg) = entry.proposal.clone() else {
                return;
            };
            (entry.approvals.clone(), msg)
        };
        let voters = self.voter_set_for(height, msg.cutoff_ts);
        let needed = quorum_for(voters.len());
        if needed == 0 {
            return;
        }
        let approved: Vec<(NodeId, [u8; 64])> = voters
            .iter()
            .filter_map(|v| approvals.get(v).map(|s| (*v, *s)))
            .collect();
        if approved.len() < needed {
            return;
        }
        let record = MeshNodeListCheckpointRecord {
            height,
            cutoff_ts: msg.cutoff_ts,
            list_root: msg.list_root,
            signer_set_root: msg.signer_set_root,
            proposer_id: hex::encode(msg.proposer),
            active_node_count: msg.active_node_count,
            proposer_signature: msg.proposer_signature.to_vec(),
            nodes: entries_to_storage(&msg.nodes),
            signer_set_delta: (
                msg.signer_set_delta.added.clone(),
                msg.signer_set_delta.removed.clone(),
            ),
            approvals: approved.iter().map(|(v, s)| (*v, s.to_vec())).collect(),
        };
        match self.db.upsert_mesh_node_list_checkpoint(&record) {
            Ok(()) => {
                p.finalized = true;
                info!(
                    height,
                    list_root = %hex::encode(&msg.list_root[..8]),
                    approvals = approved.len(),
                    needed,
                    "mesh node-list checkpoint FINALISED"
                );
            }
            Err(e) => error!(height, error = %e, "mesh node checkpoint: persist failed"),
        }
    }

    /// Backfill trigger (propose cadence): if our latest finalised checkpoint lags the anchor,
    /// broadcast a bounded, rate-limited sync request to recover a missed proposal.
    pub fn maybe_request_backfill(&self, target_height: u64) {
        if target_height < self.gate() {
            return; // dormant below the activation gate
        }
        let latest = self
            .db
            .get_latest_mesh_node_list_checkpoint()
            .ok()
            .flatten()
            .map(|r| r.height)
            .unwrap_or(0);
        if latest >= target_height {
            return;
        }
        let now = now_ms();
        {
            let mut last = self.last_sync_request.write();
            if now.saturating_sub(*last) < SYNC_COOLDOWN_MS {
                return;
            }
            *last = now;
        }
        let from_height = (latest + 1).max(target_height.saturating_sub(MAX_SYNC_CHECKPOINTS - 1));
        let req = MeshNodeListCheckpointSyncRequest {
            requesting_node: self.identity.node_id(),
            from_height,
            timestamp: now,
        };
        info!(
            from_height,
            latest,
            target = target_height,
            "mesh node checkpoint: requesting backfill"
        );
        self.broadcast(MessageType::MeshNodeListCheckpointSync, &req);
    }

    async fn on_sync_request(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let req: MeshNodeListCheckpointSyncRequest = match serde_json::from_slice(&env.payload) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if env.sender != req.requesting_node {
            return Ok(());
        }
        let now = now_ms();
        {
            let mut serves = self.sync_serves.write();
            if let Some(&last) = serves.get(&req.requesting_node) {
                if now.saturating_sub(last) < SYNC_COOLDOWN_MS {
                    return Ok(());
                }
            }
            serves.insert(req.requesting_node, now);
        }
        let records = match self
            .db
            .get_mesh_node_list_checkpoints_from_height(req.from_height, MAX_SYNC_CHECKPOINTS)
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "mesh node checkpoint: sync query failed");
                return Ok(());
            }
        };
        if records.is_empty() {
            return Ok(());
        }
        let has_more = records.len() as u64 >= MAX_SYNC_CHECKPOINTS;
        let mut checkpoints = Vec::with_capacity(records.len());
        for r in records {
            let (Some(proposer), Some(proposer_signature)) = (
                decode_node_id(&r.proposer_id),
                vec_to_sig(&r.proposer_signature),
            ) else {
                continue;
            };
            checkpoints.push(MeshNodeListCheckpointSyncEntry {
                height: r.height,
                cutoff_ts: r.cutoff_ts,
                nodes: storage_to_entries(&r.nodes),
                list_root: r.list_root,
                signer_set_delta: SignerSetDelta {
                    added: r.signer_set_delta.0,
                    removed: r.signer_set_delta.1,
                },
                signer_set_root: r.signer_set_root,
                active_node_count: r.active_node_count,
                proposer,
                proposer_signature,
                approvals: r.approvals,
            });
        }
        if checkpoints.is_empty() {
            return Ok(());
        }
        let resp = MeshNodeListCheckpointSyncResponse {
            responding_node: self.identity.node_id(),
            checkpoints,
            has_more,
            timestamp: now,
        };
        debug!(
            count = resp.checkpoints.len(),
            to = %hex::encode(&req.requesting_node[..4]),
            "mesh node checkpoint: serving backfill"
        );
        self.broadcast(MessageType::MeshNodeListCheckpointSync, &resp);
        Ok(())
    }

    async fn on_sync_response(&self, env: &MessageEnvelope) -> GhostResult<()> {
        let resp: MeshNodeListCheckpointSyncResponse = match serde_json::from_slice(&env.payload) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        if env.sender != resp.responding_node {
            return Ok(());
        }
        let mut applied = 0usize;
        for entry in &resp.checkpoints {
            if self.apply_synced_checkpoint(entry) {
                applied += 1;
            }
        }
        if applied > 0 {
            info!(applied, "mesh node checkpoint: backfilled");
        }
        Ok(())
    }

    /// Trustlessly adopt one synced checkpoint by verifying the WHOLE signed blob — authorship,
    /// root integrity, the proposer signature, and a ≥67% quorum of valid approver signatures
    /// from the deterministic voter set. This is exactly the check an external shim performs,
    /// so it never depends on the local mesh view being converged at the historical cutoff.
    /// Returns true iff newly persisted.
    fn apply_synced_checkpoint(&self, entry: &MeshNodeListCheckpointSyncEntry) -> bool {
        if self.already_finalized(entry.height) {
            return false;
        }
        if self.proposer_for(entry.height, entry.cutoff_ts) != Some(entry.proposer) {
            return false;
        }
        let voters = self.voter_set_for(entry.height, entry.cutoff_ts);
        if mesh_node_list_root(&entry.nodes) != entry.list_root
            || mesh_signer_set_root(&voters) != entry.signer_set_root
        {
            return false;
        }
        // Reconstruct the checkpoint hash and verify the proposer's signature over it.
        let msg = MeshNodeListCheckpointMessage {
            height: entry.height,
            cutoff_ts: entry.cutoff_ts,
            nodes: entry.nodes.clone(),
            list_root: entry.list_root,
            signer_set_delta: entry.signer_set_delta.clone(),
            signer_set_root: entry.signer_set_root,
            active_node_count: entry.active_node_count,
            proposer: entry.proposer,
            proposer_signature: entry.proposer_signature,
            timestamp: 0,
        };
        let hash = msg.checkpoint_hash();
        if !verify_signature(&entry.proposer, &hash, &entry.proposer_signature).unwrap_or(false) {
            return false;
        }
        // Count valid, distinct approver signatures from the voter set.
        let voter_set: HashSet<NodeId> = voters.iter().copied().collect();
        let needed = quorum_for(voters.len());
        if needed == 0 {
            return false;
        }
        let mut seen = HashSet::new();
        let mut valid = 0usize;
        for (voter, sig) in &entry.approvals {
            if !voter_set.contains(voter) || !seen.insert(*voter) {
                continue;
            }
            let Some(sig) = vec_to_sig(sig) else { continue };
            let vote = MeshNodeListCheckpointVoteMessage {
                height: entry.height,
                checkpoint_hash: hash,
                voter: *voter,
                approve: true,
                signature: sig,
                timestamp: 0,
            };
            if verify_signature(voter, &vote.signing_message(), &sig).unwrap_or(false) {
                valid += 1;
            }
        }
        if valid < needed {
            warn!(
                height = entry.height,
                valid, needed, "mesh node checkpoint: synced checkpoint lacks quorum — rejected"
            );
            return false;
        }
        let record = MeshNodeListCheckpointRecord {
            height: entry.height,
            cutoff_ts: entry.cutoff_ts,
            list_root: entry.list_root,
            signer_set_root: entry.signer_set_root,
            proposer_id: hex::encode(entry.proposer),
            active_node_count: entry.active_node_count,
            proposer_signature: entry.proposer_signature.to_vec(),
            nodes: entries_to_storage(&entry.nodes),
            signer_set_delta: (
                entry.signer_set_delta.added.clone(),
                entry.signer_set_delta.removed.clone(),
            ),
            approvals: entry.approvals.clone(),
        };
        match self.db.upsert_mesh_node_list_checkpoint(&record) {
            Ok(()) => {
                self.pending
                    .write()
                    .entry(entry.height)
                    .or_insert_with(Pending::new)
                    .finalized = true;
                true
            }
            Err(e) => {
                error!(height = entry.height, error = %e, "mesh node checkpoint: sync persist failed");
                false
            }
        }
    }
}

#[async_trait]
impl MessageHandler for MeshNodeListCheckpointManager {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        match envelope.msg_type {
            MessageType::MeshNodeListCheckpoint => self.on_proposal(&envelope).await,
            MessageType::MeshNodeListCheckpointVote => self.on_vote(&envelope).await,
            MessageType::MeshNodeListCheckpointSync => {
                // Multiplex request/response by trial-deserialise (only the request carries
                // `from_height`), matching the payout-checkpoint sync handler.
                if serde_json::from_slice::<MeshNodeListCheckpointSyncRequest>(&envelope.payload)
                    .is_ok()
                {
                    self.on_sync_request(&envelope).await
                } else {
                    self.on_sync_response(&envelope).await
                }
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    //! In-process N-node cluster tests with real identities/signatures and induced per-node
    //! node-set divergence — the property that only a converged set finalises, that an
    //! unchanged set is not re-checkpointed, and that a signed checkpoint backfills trustlessly.
    use super::*;
    use ghost_storage::MpcContributionRecord;
    use std::sync::Mutex;

    type Outbox = Arc<Mutex<Vec<(MessageType, Vec<u8>)>>>;

    struct Node {
        id: NodeId,
        db: Arc<Database>,
        mgr: MeshNodeListCheckpointManager,
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

    fn entry(id: u8, host: &str) -> MeshNodeEntry {
        MeshNodeEntry {
            node_id: [id; 32],
            host: host.to_string(),
            sv1_port: 3333,
            sv2_port: 34255,
        }
    }

    /// The shared "converged" public-mining set every node computes.
    fn std_nodes() -> Vec<MeshNodeEntry> {
        vec![entry(200, "203.0.113.1"), entry(201, "203.0.113.2")]
    }

    /// Build `n` nodes; node at SORTED elder position `i` computes `lists[i]` as its own view
    /// (`None` = C-7 abstain). Sorted order means `nodes[i].id == elders_sorted[i]`, so the
    /// proposer for height `H` is `nodes[H % n]`.
    fn build(n: usize, lists: &[Option<Vec<MeshNodeEntry>>]) -> (Vec<Node>, Vec<NodeId>) {
        assert_eq!(n, lists.len());
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
            let list = lists[pos].clone();
            let compute: ComputeNodeListFn = Arc::new(move |_c, _h| list.clone());
            let mgr = MeshNodeListCheckpointManager::new(
                identity.clone(),
                Arc::clone(&db),
                send,
                compute,
            )
            .with_gate_height(0); // armed for the cluster tests
            nodes.push(Node {
                id: identity.node_id(),
                db,
                mgr,
                outbox,
            });
        }
        (nodes, elders)
    }

    fn drain(n: &Node) -> Vec<(MessageType, Vec<u8>)> {
        std::mem::take(&mut *n.outbox.lock().unwrap())
    }

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
                        let env = Arc::new(MessageEnvelope::new(
                            ty,
                            from,
                            payload.clone(),
                            0,
                            [0u8; 64],
                        ));
                        n.mgr.handle_message(env).await.expect("handle");
                    }
                }
            }
        }
    }

    const H: u64 = 100; // 100 % 4 == 0 → proposer is sorted-elder[0] = nodes[0]
    const CUTOFF: i64 = 1_784_000_000;

    #[tokio::test]
    async fn dormant_below_the_gate_proposes_nothing() {
        // A manager with the DEFAULT (production) gate — u64::MAX in tests, since the activation
        // OnceLock is never armed here — must be fully inert even when it is the sole proposer
        // (quorum_for(1) == 1, so without the gate it WOULD finalise). This proves the gate is
        // actually enforced, not merely declared.
        let ident = Arc::new(NodeIdentity::generate());
        let elders = vec![ident.node_id()];
        let db = Arc::new(Database::in_memory().expect("db"));
        register_elders(&db, &elders);
        let outbox: Outbox = Arc::new(Mutex::new(Vec::new()));
        let ob = Arc::clone(&outbox);
        let send: BroadcastFn = Arc::new(move |ty, bytes| {
            ob.lock().unwrap().push((ty, bytes));
            Ok(())
        });
        let compute: ComputeNodeListFn = Arc::new(|_, _| Some(std_nodes()));
        // No .with_gate_height → uses the live gate (dormant u64::MAX).
        let mgr = MeshNodeListCheckpointManager::new(ident, Arc::clone(&db), send, compute);
        mgr.maybe_propose(100, CUTOFF).await;
        mgr.maybe_request_backfill(100);
        assert!(
            outbox.lock().unwrap().is_empty(),
            "dormant manager broadcasts nothing"
        );
        assert!(
            db.get_latest_mesh_node_list_checkpoint().unwrap().is_none(),
            "dormant manager finalises nothing"
        );
    }

    #[tokio::test]
    async fn convergent_fleet_finalises_signed_list() {
        let (nodes, _) = build(4, &vec![Some(std_nodes()); 4]);
        assert_eq!(nodes[0].mgr.proposer_for(H, CUTOFF), Some(nodes[0].id));
        assert_eq!(quorum_for(4), 3, "67% of 4 = 3");
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        let want_root = mesh_node_list_root(&std_nodes());
        for n in &nodes {
            let rec =
                n.db.get_latest_mesh_node_list_checkpoint()
                    .unwrap()
                    .expect("every node finalises");
            assert_eq!(rec.height, H);
            assert_eq!(rec.list_root, want_root);
            assert_eq!(rec.nodes.len(), 2, "adopted node list");
            assert_eq!(
                rec.proposer_signature.len(),
                64,
                "proposer signature persisted"
            );
            assert!(
                rec.approvals.len() >= 3,
                "≥quorum approver signatures persisted, got {}",
                rec.approvals.len()
            );
        }
    }

    #[tokio::test]
    async fn divergent_node_set_does_not_finalise() {
        // Proposer + one peer see std; two peers see a DIFFERENT set → they reject → only 2
        // approvals < 3 → nothing finalises (safe).
        let other = vec![entry(210, "198.51.100.9")];
        let (nodes, _) = build(
            4,
            &[
                Some(std_nodes()),
                Some(std_nodes()),
                Some(other.clone()),
                Some(other),
            ],
        );
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        for n in &nodes {
            assert!(n
                .db
                .get_latest_mesh_node_list_checkpoint()
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn unchanged_node_set_is_not_re_proposed() {
        let (nodes, _) = build(4, &vec![Some(std_nodes()); 4]);
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        // All finalised H. Now the proposer for a later height with the SAME set must not
        // propose again (cadence: re-affirm, don't re-checkpoint).
        let h2 = 104; // 104 % 4 == 0 → proposer is nodes[0]
        nodes[0].mgr.maybe_propose(h2, CUTOFF).await;
        assert!(
            !drain(&nodes[0])
                .iter()
                .any(|(ty, _)| *ty == MessageType::MeshNodeListCheckpoint),
            "unchanged set → no new proposal"
        );
    }

    #[tokio::test]
    async fn changed_node_set_is_re_proposed() {
        // Pre-seed a stale finalised checkpoint whose list_root differs from the current set, so
        // the proposer sees a change and DOES propose (the other direction of the cadence gate).
        let (nodes, _) = build(4, &vec![Some(std_nodes()); 4]);
        let stale = MeshNodeListCheckpointRecord {
            height: 96,
            cutoff_ts: CUTOFF,
            list_root: [1u8; 32], // != mesh_node_list_root(std_nodes())
            signer_set_root: [2u8; 32],
            proposer_id: hex::encode(nodes[0].id),
            active_node_count: 4,
            proposer_signature: vec![0u8; 64],
            nodes: vec![],
            signer_set_delta: (vec![], vec![]),
            approvals: vec![],
        };
        nodes[0]
            .db
            .upsert_mesh_node_list_checkpoint(&stale)
            .unwrap();
        nodes[0].mgr.maybe_propose(H, CUTOFF).await; // H=100 → proposer is nodes[0]
        assert!(
            drain(&nodes[0])
                .iter()
                .any(|(ty, _)| *ty == MessageType::MeshNodeListCheckpoint),
            "changed set → proposes"
        );
    }

    #[tokio::test]
    async fn missed_checkpoint_backfills_via_signed_sync() {
        // Build a fleet, finalise H with real signatures, then hand the finalised checkpoint to a
        // BYSTANDER that missed it. It adopts only after verifying the full signed blob.
        let (nodes, elders) = build(4, &vec![Some(std_nodes()); 4]);
        for n in &nodes {
            n.mgr.maybe_propose(H, CUTOFF).await;
        }
        gossip_until_quiet(&nodes).await;
        let rec = nodes[0]
            .db
            .get_latest_mesh_node_list_checkpoint()
            .unwrap()
            .expect("finalised");

        // Reconstruct the sync entry a peer would serve from that record.
        let synced = MeshNodeListCheckpointSyncEntry {
            height: rec.height,
            cutoff_ts: rec.cutoff_ts,
            nodes: storage_to_entries(&rec.nodes),
            list_root: rec.list_root,
            signer_set_delta: SignerSetDelta {
                added: rec.signer_set_delta.0.clone(),
                removed: rec.signer_set_delta.1.clone(),
            },
            signer_set_root: rec.signer_set_root,
            active_node_count: rec.active_node_count,
            proposer: decode_node_id(&rec.proposer_id).unwrap(),
            proposer_signature: vec_to_sig(&rec.proposer_signature).unwrap(),
            approvals: rec.approvals.clone(),
        };

        // A bystander with the same elder registration but no checkpoint.
        let db = Arc::new(Database::in_memory().expect("db"));
        register_elders(&db, &elders);
        let send: BroadcastFn = Arc::new(|_, _| Ok(()));
        let compute: ComputeNodeListFn = Arc::new(|_, _| None); // apply verifies sigs, not view
        let bystander = MeshNodeListCheckpointManager::new(
            Arc::new(NodeIdentity::generate()),
            Arc::clone(&db),
            send,
            compute,
        );

        assert!(
            bystander.apply_synced_checkpoint(&synced),
            "valid signed checkpoint adopted"
        );
        assert_eq!(
            db.get_latest_mesh_node_list_checkpoint()
                .unwrap()
                .unwrap()
                .height,
            H
        );

        // Tamper: flip one approver signature byte → quorum fails → rejected.
        let mut bad = synced.clone();
        let db2 = Arc::new(Database::in_memory().expect("db2"));
        register_elders(&db2, &elders);
        let send2: BroadcastFn = Arc::new(|_, _| Ok(()));
        let compute2: ComputeNodeListFn = Arc::new(|_, _| None);
        let bystander2 = MeshNodeListCheckpointManager::new(
            Arc::new(NodeIdentity::generate()),
            Arc::clone(&db2),
            send2,
            compute2,
        );
        if let Some(first) = bad.approvals.first_mut() {
            if let Some(b) = first.1.first_mut() {
                *b ^= 0xff;
            }
        }
        // Drop the tampered approver below quorum by also truncating to force <3 valid.
        bad.approvals.truncate(2);
        assert!(
            !bystander2.apply_synced_checkpoint(&bad),
            "sub-quorum / tampered signatures rejected"
        );
        assert!(db2
            .get_latest_mesh_node_list_checkpoint()
            .unwrap()
            .is_none());
    }
}
