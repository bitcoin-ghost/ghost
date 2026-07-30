//! NullifierRouteHandler — L2 transaction validation + checkpoint BFT
//!
//! All nodes validate transactions; all active nodes participate in BFT
//! checkpoint consensus.
//!
//! Flow:
//! 1. Sender submits tx with ZK proof → deterministically routed to validator
//! 2. Validator verifies proof (~5ms), confirms to sender, broadcasts
//! 3. Every 10s: proposer assembles checkpoint from confirmed pool
//! 4. All active nodes vote on checkpoint (67% BFT threshold)
//! 5. On finalization: persist, update tree, manage epochs

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use parking_lot::RwLock;
use tracing::{debug, info, trace, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity;
use ghost_common::metrics::Metrics;
use ghost_common::types::NodeId;
use ghost_storage::Database;
use ghost_zkp::{
    GhostConsolidateVerifier, GhostNoteSpendPublicInputs, GhostNoteVerifier, GhostUnshieldVerifier,
};

use crate::epoch_manager::{EpochManager, PROPOSER_GRACE_SECS};
use crate::mesh::MessageHandler;
use crate::message::{
    L2CheckpointBlockMessage, L2CheckpointVoteMessage, L2ConfidentialTransferMessage, L2EpochSync,
    L2NoteGapRequest, L2NoteGapResponse, L2Transaction, L2TransferBroadcastMessage,
    L2TransferConfirmationMessage, L2TreeSyncRequest, L2TreeSyncResponse, MessageEnvelope,
    MessageType, ShieldCommitment,
};
use crate::vote_handler::BroadcastFn;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// BFT threshold for checkpoint approval (67%)
pub const BFT_THRESHOLD_PERCENT: u64 = 67;

/// Maximum transactions per checkpoint block
pub const MAX_TXS_PER_CHECKPOINT: usize = 10_000;

/// Max L2 messages per second per peer
const MAX_L2_MSG_PER_PEER_PER_SEC: u32 = 100;

/// Max L2 messages per second globally
const MAX_L2_MSG_GLOBAL_PER_SEC: u32 = 10_000;

/// Max checkpoints per tree sync response
const MAX_SYNC_CHECKPOINTS: usize = 100;

/// Min interval between sync requests from same peer (seconds)
const SYNC_REQUEST_COOLDOWN_SECS: u64 = 60;

/// Signing function type (matches NodeIdentity.sign() signature)
pub type SignFn = Arc<dyn Fn(&[u8]) -> [u8; 64] + Send + Sync>;

/// Checkpoint finalization callback type.
/// Called after a checkpoint is finalized with (height, state_root, nullifiers).
/// Nullifiers identify which transactions were included; callers derive tx_count from `.len()`.
/// Used to notify ghost-pay of finalized L2 blocks.
pub type FinalizeFn = Arc<dyn Fn(u64, [u8; 32], Vec<[u8; 32]>) + Send + Sync>;

/// Configuration for the nullifier route handler
#[derive(Debug, Clone)]
pub struct NullifierRouteConfig {
    pub bft_threshold_percent: u64,
    pub max_txs_per_checkpoint: usize,
}

impl Default for NullifierRouteConfig {
    fn default() -> Self {
        Self {
            bft_threshold_percent: BFT_THRESHOLD_PERCENT,
            max_txs_per_checkpoint: MAX_TXS_PER_CHECKPOINT,
        }
    }
}

// =============================================================================
// VERIFIED VOTE NEWTYPE (S-6)
// =============================================================================

/// S-6: Newtype ensuring votes are only constructed after signature verification.
/// Can only be created via `VerifiedVote::new()` in `handle_message()` after
/// Ed25519 signature verification completes successfully.
pub(crate) struct VerifiedVote {
    voter: NodeId,
    approve: bool,
}

impl VerifiedVote {
    /// Create a verified vote. Only call after signature verification.
    pub(crate) fn new(voter: NodeId, approve: bool) -> Self {
        Self { voter, approve }
    }
}

// =============================================================================
// CHECKPOINT VOTE STATE
// =============================================================================

/// Tracks votes for a specific checkpoint height
#[derive(Debug)]
struct CheckpointVoteState {
    /// Hash of the proposed checkpoint
    checkpoint_hash: [u8; 32],
    /// Votes received (voter -> approve)
    votes: HashMap<NodeId, bool>,
    /// Whether this checkpoint has been finalized
    finalized: bool,
    /// The proposed checkpoint block (if we received it)
    proposal: Option<L2CheckpointBlockMessage>,
}

impl CheckpointVoteState {
    fn new(checkpoint_hash: [u8; 32]) -> Self {
        Self {
            checkpoint_hash,
            votes: HashMap::new(),
            finalized: false,
            proposal: None,
        }
    }

    /// Add a vote from a verified source. S-6: accepts VerifiedVote newtype
    /// to ensure only signature-verified votes can be added.
    fn add_vote(&mut self, vote: VerifiedVote) -> bool {
        self.votes.insert(vote.voter, vote.approve).is_none() // true if new vote
    }

    fn approval_count(&self) -> usize {
        self.votes.values().filter(|&&v| v).count()
    }

    fn has_quorum(&self, active_count: usize, threshold_percent: u64) -> bool {
        if active_count == 0 {
            return false;
        }
        let needed = (active_count as u64 * threshold_percent).div_ceil(100);
        self.approval_count() as u64 >= needed
    }
}

// =============================================================================
// NULLIFIER ROUTE HANDLER
// =============================================================================

/// Handles L2 transaction validation and checkpoint BFT consensus
pub struct NullifierRouteHandler {
    /// Our node ID
    our_id: NodeId,
    /// Epoch manager (tree, nullifiers, roots, proposer rotation)
    epoch_manager: Arc<EpochManager>,
    /// Note verifier (Groth16 proof verification)
    verifier: RwLock<Option<Arc<GhostNoteVerifier>>>,
    /// Consolidation verifier (Groth16 consolidation proof verification)
    consolidation_verifier: RwLock<Option<Arc<GhostConsolidateVerifier>>>,
    /// Unshield verifier (Groth16 unshield/withdrawal proof verification)
    unshield_verifier: RwLock<Option<Arc<GhostUnshieldVerifier>>>,
    /// Confirmed transactions waiting for next checkpoint
    confirmed_pool: RwLock<Vec<L2Transaction>>,
    /// S-4: O(1) nullifier dedup index for confirmed_pool (parallel HashSet)
    confirmed_nullifiers: RwLock<HashSet<[u8; 32]>>,
    /// Shield commitments pending inclusion in next checkpoint.
    /// Drained by propose_checkpoint() and piggybacked on transfer broadcasts.
    pending_shields: RwLock<Vec<ShieldCommitment>>,
    /// Vote state per checkpoint height
    votes: RwLock<HashMap<u64, CheckpointVoteState>>,
    /// Database
    db: Arc<Database>,
    /// Configuration
    config: NullifierRouteConfig,
    /// Broadcast function (set after construction)
    broadcast_fn: RwLock<Option<BroadcastFn>>,
    /// Signing function for Ed25519 signatures (set after construction)
    sign_fn: RwLock<Option<SignFn>>,
    /// Time of last finalized checkpoint (for proposer timeout detection)
    last_checkpoint_time: RwLock<Instant>,
    /// Per-peer L2 message rate tracking: peer -> (window_start, count)
    peer_msg_rates: RwLock<HashMap<NodeId, (Instant, u32)>>,
    /// Global L2 message rate tracking: (window_start, count)
    global_msg_rate: RwLock<(Instant, u32)>,
    /// Last tree sync request per peer (for rate limiting)
    sync_requests: RwLock<HashMap<NodeId, Instant>>,
    /// Client-side cooldown: last time we sent a tree sync request.
    /// Prevents spamming peers (who rate-limit at 60s) with redundant requests.
    last_sync_request_sent: RwLock<Option<Instant>>,
    /// Cached proposal for the current height. Reused on repeated proposal cycles to ensure
    /// hash stability — without this, any tree mutation between cycles would change the hash
    /// and reset peer vote state, preventing BFT quorum.
    cached_proposal: RwLock<Option<L2CheckpointBlockMessage>>,
    /// Callback for checkpoint finalization (notifies ghost-pay)
    finalize_fn: RwLock<Option<FinalizeFn>>,
    /// Prometheus metrics (optional, set after construction)
    metrics: RwLock<Option<Arc<Metrics>>>,
    /// Root at last finalized checkpoint — stable reference for checkpoint proposals.
    /// Unlike current_root() which changes when shields are synced locally,
    /// this only advances on checkpoint finalization.
    checkpoint_base_root: RwLock<[u8; 32]>,
}

impl NullifierRouteHandler {
    /// Create a new handler
    pub fn new(
        our_id: NodeId,
        epoch_manager: Arc<EpochManager>,
        db: Arc<Database>,
        config: NullifierRouteConfig,
    ) -> Self {
        let base_root = epoch_manager.current_root().unwrap_or([0u8; 32]);
        Self {
            our_id,
            epoch_manager,
            verifier: RwLock::new(None),
            consolidation_verifier: RwLock::new(None),
            unshield_verifier: RwLock::new(None),
            confirmed_pool: RwLock::new(Vec::new()),
            confirmed_nullifiers: RwLock::new(HashSet::new()),
            pending_shields: RwLock::new(Vec::new()),
            votes: RwLock::new(HashMap::new()),
            db,
            config,
            broadcast_fn: RwLock::new(None),
            sign_fn: RwLock::new(None),
            last_checkpoint_time: RwLock::new(Instant::now()),
            peer_msg_rates: RwLock::new(HashMap::new()),
            global_msg_rate: RwLock::new((Instant::now(), 0)),
            sync_requests: RwLock::new(HashMap::new()),
            last_sync_request_sent: RwLock::new(None),
            cached_proposal: RwLock::new(None),
            finalize_fn: RwLock::new(None),
            metrics: RwLock::new(None),
            checkpoint_base_root: RwLock::new(base_root),
        }
    }

    /// Create with default config
    pub fn with_defaults(
        our_id: NodeId,
        epoch_manager: Arc<EpochManager>,
        db: Arc<Database>,
    ) -> Self {
        Self::new(our_id, epoch_manager, db, NullifierRouteConfig::default())
    }

    /// Restore pending shields from DB after restart.
    /// Must be called after construction to recover shields that were synced
    /// but not yet included in a finalized checkpoint.
    pub fn restore_pending_shields(&self) -> GhostResult<()> {
        let shields = self.db.load_pending_shields()?;
        if shields.is_empty() {
            return Ok(());
        }
        let mut pending = self.pending_shields.write();
        for (note_index, commitment, block_height) in &shields {
            pending.push(ShieldCommitment {
                commitment: *commitment,
                note_index: *note_index,
                block_height: *block_height,
            });
        }
        info!(
            count = shields.len(),
            "Restored pending shields from DB after restart"
        );
        Ok(())
    }

    /// Restore confirmed pool from the staging table after a restart.
    /// Transactions that were ZK-verified and added to confirmed_pool before
    /// the crash are recovered, preventing fund-freeze.
    /// Skips transactions whose nullifiers are already spent (they were finalized
    /// in a checkpoint before the crash but the staging table wasn't cleaned up).
    pub fn restore_confirmed_pool(&self) -> GhostResult<()> {
        let rows = self.db.load_confirmed_pool_staging()?;
        if rows.is_empty() {
            return Ok(());
        }
        let mut pool = self.confirmed_pool.write();
        let mut nullifiers = self.confirmed_nullifiers.write();
        let mut restored = 0u64;
        let mut skipped_spent = 0u64;
        for (nullifier_vec, tx_data) in &rows {
            if let Ok(tx) = serde_json::from_slice::<L2Transaction>(tx_data) {
                let nullifier: [u8; 32] = match nullifier_vec.as_slice().try_into() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                // Skip if this nullifier was already finalized in a prior checkpoint.
                // This happens when we crash after checkpoint persist but before
                // staging table cleanup.
                if self.epoch_manager.is_nullifier_spent(&nullifier) {
                    skipped_spent += 1;
                    continue;
                }
                if nullifiers.insert(nullifier) {
                    pool.push(tx);
                    restored += 1;
                }
            } else {
                warn!("Skipping undeserializable confirmed_pool_staging row");
            }
        }
        // Clean up stale entries from staging
        if skipped_spent > 0 {
            if let Err(e) = self.db.clear_confirmed_pool_staging() {
                warn!(error = %e, "Failed to clear stale confirmed_pool_staging entries");
            } else {
                // Re-persist only the live ones
                for tx in pool.iter() {
                    if let Ok(tx_bytes) = serde_json::to_vec(tx) {
                        let _ = self.db.insert_confirmed_pool_tx(&tx.nullifier, &tx_bytes);
                    }
                }
            }
        }
        info!(
            restored,
            skipped_already_spent = skipped_spent,
            "Restored confirmed pool from DB after restart"
        );
        Ok(())
    }

    /// Set the verifier (after MPC params are loaded)
    pub fn set_verifier(&self, verifier: Arc<GhostNoteVerifier>) {
        *self.verifier.write() = Some(verifier);
    }

    /// Set the consolidation verifier (after MPC params are loaded)
    pub fn set_consolidation_verifier(&self, verifier: Arc<GhostConsolidateVerifier>) {
        *self.consolidation_verifier.write() = Some(verifier);
    }

    /// Set the unshield verifier (after MPC params are loaded)
    pub fn set_unshield_verifier(&self, verifier: Arc<GhostUnshieldVerifier>) {
        *self.unshield_verifier.write() = Some(verifier);
    }

    /// Set the broadcast function
    pub fn set_broadcast_fn(&self, f: BroadcastFn) {
        *self.broadcast_fn.write() = Some(f);
    }

    /// Set the signing function (from NodeIdentity)
    pub fn set_sign_fn(&self, f: SignFn) {
        *self.sign_fn.write() = Some(f);
    }

    /// Set the finalization callback (notifies ghost-pay when checkpoints are finalized)
    pub fn set_finalize_fn(&self, f: FinalizeFn) {
        *self.finalize_fn.write() = Some(f);
    }

    /// Set Prometheus metrics for consensus tracking
    pub fn set_metrics(&self, m: Arc<Metrics>) {
        *self.metrics.write() = Some(m);
    }

    /// Set checkpoint base root (called during startup after loading from DB)
    pub fn set_checkpoint_base_root(&self, root: [u8; 32]) {
        *self.checkpoint_base_root.write() = root;
    }

    /// Sign a message using our signing function
    fn sign(&self, message: &[u8]) -> [u8; 64] {
        if let Some(ref f) = *self.sign_fn.read() {
            f(message)
        } else {
            [0u8; 64]
        }
    }

    /// Get our node ID
    pub fn our_id(&self) -> &NodeId {
        &self.our_id
    }

    /// Get the confirmed pool size
    pub fn confirmed_pool_size(&self) -> usize {
        self.confirmed_pool.read().len()
    }

    /// Submit an externally-verified L2 transaction for consensus processing.
    ///
    /// Called by ghost-pool's HTTP API when ghost-pay forwards a verified NoteSpend
    /// transaction. Always validates locally (bypasses deterministic routing) since
    /// ghost-pay already verified the proof. Broadcasts signed confirmation + transfer
    /// to the network. Other nodes verify the proof via handle_transfer_broadcast().
    pub fn submit_external_transfer(&self, msg: &L2ConfidentialTransferMessage) -> GhostResult<()> {
        let tx = &msg.transaction;

        // Validate root and nullifier locally (no deterministic routing needed —
        // this node acts as validator for HTTP submissions from colocated ghost-pay)
        if !self.epoch_manager.is_root_valid(&tx.commitment_root) {
            let our_root = self.epoch_manager.current_root().unwrap_or([0u8; 32]);
            warn!(
                requested_root = %hex::encode(&tx.commitment_root[..8]),
                our_current_root = %hex::encode(&our_root[..8]),
                "submit_external_transfer: commitment root not in valid roots window"
            );
            return Err(GhostError::InvalidInput("Invalid commitment root".into()));
        }
        if self.epoch_manager.is_nullifier_spent(&tx.nullifier) {
            return Err(GhostError::InvalidInput("Nullifier already spent".into()));
        }

        // Verify Groth16 proof
        let verifier = self.verifier.read();
        if let Some(ref v) = *verifier {
            let public_inputs = GhostNoteSpendPublicInputs {
                commitment_root: tx.commitment_root,
                nullifier: tx.nullifier,
                change_commitment: tx.change_commitment,
                recipient_commitment: tx.recipient_commitment,
            };
            let valid = v
                .verify_raw(&tx.proof, &public_inputs)
                .map_err(|e| GhostError::Internal(format!("Proof verification error: {}", e)))?;
            if !valid {
                return Err(GhostError::InvalidInput("Proof verification failed".into()));
            }
        } else {
            return Err(GhostError::Internal(
                "No verifier available — MPC params not loaded".into(),
            ));
        }
        drop(verifier);

        // Atomically record nullifier as spent
        let height = self.epoch_manager.current_height();
        if !self.epoch_manager.spend_nullifier(tx.nullifier, height)? {
            return Err(GhostError::InvalidInput("Nullifier race".into()));
        }

        // Add to confirmed pool + persist to staging table for crash recovery
        {
            let mut pool = self.confirmed_pool.write();
            pool.push(tx.clone());
            self.confirmed_nullifiers.write().insert(tx.nullifier);
        }
        if let Ok(tx_bytes) = serde_json::to_vec(tx) {
            if let Err(e) = self.db.insert_confirmed_pool_tx(&tx.nullifier, &tx_bytes) {
                warn!(error = %e, "Failed to persist confirmed tx to staging (non-fatal)");
            }
        }

        // Signed confirmation
        let mut confirmation = L2TransferConfirmationMessage {
            nullifier: tx.nullifier,
            validator: self.our_id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            signature: [0u8; 64],
        };
        let sign_msg = confirmation.signing_message();
        confirmation.signature = self.sign(&sign_msg);

        // Snapshot pending shields as prerequisites for instant network confirmation
        let prerequisites: Vec<ShieldCommitment> = self.pending_shields.read().clone();

        // Broadcast confirmation + signed transfer with prerequisites
        if let Some(ref broadcast) = *self.broadcast_fn.read() {
            let payload = serde_json::to_vec(&confirmation)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            broadcast(MessageType::L2TransferConfirmation, payload)?;

            let mut bcast = L2TransferBroadcastMessage {
                transaction: tx.clone(),
                validator: self.our_id,
                signature: [0u8; 64],
                prerequisites,
            };
            let sign_msg = bcast.signing_message();
            bcast.signature = self.sign(&sign_msg);
            let payload =
                serde_json::to_vec(&bcast).map_err(|e| GhostError::Serialization(e.to_string()))?;
            broadcast(MessageType::L2TransferBroadcast, payload)?;
        }

        debug!(
            nullifier = %hex::encode(&tx.nullifier[..8]),
            pool_size = self.confirmed_pool_size(),
            "External transfer validated and broadcast"
        );

        Ok(())
    }

    /// Sync a commitment from ghost-pay to the local L2 tree.
    ///
    /// Called when ghost-pay shields a note. Broadcasts to all peers via P2P
    /// so every node applies the shield immediately, preventing tree divergence.
    /// Shields are also batched in the next L2CheckpointBlockMessage for BFT finality.
    pub fn sync_commitment(
        &self,
        commitment: [u8; 32],
        note_index: u64,
        block_height: u64,
    ) -> GhostResult<()> {
        self.apply_shield_commitment(commitment, note_index, block_height)?;

        // Broadcast to all peers so they apply immediately
        let shield = ShieldCommitment {
            commitment,
            note_index,
            block_height,
        };
        if let Some(ref broadcast) = *self.broadcast_fn.read() {
            let payload = serde_json::to_vec(&shield)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            if let Err(e) = broadcast(MessageType::L2ShieldBroadcast, payload) {
                warn!(error = %e, "Failed to broadcast shield commitment to peers");
            }
        }

        debug!(
            index = note_index,
            height = block_height,
            "Synced commitment to local tree and broadcast to peers"
        );
        Ok(())
    }

    /// Apply a shield commitment to the local tree (used by both local sync and P2P receive).
    fn apply_shield_commitment(
        &self,
        commitment: [u8; 32],
        note_index: u64,
        block_height: u64,
    ) -> GhostResult<()> {
        self.epoch_manager
            .insert_commitment_at(note_index, commitment, block_height)?;
        let root = self.epoch_manager.current_root()?;
        self.epoch_manager.add_valid_root(root, block_height)?;

        // Use L2 checkpoint height for pending shield tracking, NOT the Bitcoin
        // block height passed from ghost-pay. The stale shield expiry in
        // propose_checkpoint() compares against L2 checkpoint heights — using
        // Bitcoin heights (31xxx) against L2 heights (139xxx) caused all shields
        // to expire immediately, preventing checkpoint inclusion.
        let checkpoint_height = self.epoch_manager.current_height();

        // Persist to staging table so pending shields survive restarts.
        self.db
            .insert_pending_shield(note_index, &commitment, checkpoint_height)?;

        // Queue for checkpoint inclusion and transfer prerequisites
        self.pending_shields.write().push(ShieldCommitment {
            commitment,
            note_index,
            block_height: checkpoint_height,
        });

        Ok(())
    }

    // =========================================================================
    // RATE LIMITING
    // =========================================================================

    /// Check per-peer and global rate limits for L2 messages.
    /// Returns Err if rate limit exceeded.
    fn check_rate_limit(&self, peer: &NodeId) -> GhostResult<()> {
        let now = Instant::now();

        // Per-peer rate limit
        {
            let mut rates = self.peer_msg_rates.write();
            let entry = rates.entry(*peer).or_insert((now, 0));
            if now.duration_since(entry.0).as_secs() >= 1 {
                // Reset window
                *entry = (now, 1);
            } else {
                entry.1 += 1;
                if entry.1 > MAX_L2_MSG_PER_PEER_PER_SEC {
                    return Err(GhostError::InvalidInput(format!(
                        "L2 rate limit exceeded: {} msgs/sec from peer {}",
                        entry.1,
                        hex::encode(&peer[..8])
                    )));
                }
            }
        }

        // Global rate limit
        {
            let mut global = self.global_msg_rate.write();
            if now.duration_since(global.0).as_secs() >= 1 {
                *global = (now, 1);
            } else {
                global.1 += 1;
                if global.1 > MAX_L2_MSG_GLOBAL_PER_SEC {
                    return Err(GhostError::InvalidInput(
                        "L2 global rate limit exceeded".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    // =========================================================================
    // SIGNATURE VERIFICATION
    // =========================================================================

    /// Verify an Ed25519 signature from a peer
    fn verify_peer_signature(
        &self,
        peer_id: &NodeId,
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        match identity::verify_signature(peer_id, message, signature) {
            Ok(valid) => {
                if !valid {
                    warn!(
                        peer = %hex::encode(&peer_id[..8]),
                        "Invalid Ed25519 signature on L2 message"
                    );
                }
                valid
            }
            Err(e) => {
                warn!(
                    peer = %hex::encode(&peer_id[..8]),
                    error = %e,
                    "Signature verification error (invalid public key)"
                );
                false
            }
        }
    }

    // =========================================================================
    // TRANSACTION VALIDATION (per-tx, ~5ms target)
    // =========================================================================

    /// Handle an incoming confidential transfer submission
    ///
    /// Called when this node is the assigned validator for the transaction's nullifier.
    pub fn handle_transfer(
        &self,
        msg: &L2ConfidentialTransferMessage,
    ) -> GhostResult<Option<L2TransferConfirmationMessage>> {
        let tx = &msg.transaction;

        // 1. Check this node is the assigned validator
        if let Some(assigned) = self.epoch_manager.validator_for_nullifier(&tx.nullifier) {
            if assigned != self.our_id {
                debug!("Not assigned validator for this nullifier, ignoring");
                return Ok(None);
            }
        } else {
            return Err(GhostError::Internal("No active nodes for routing".into()));
        }

        // 2. Check commitment_root is valid
        if !self.epoch_manager.is_root_valid(&tx.commitment_root) {
            return Err(GhostError::InvalidInput(
                "Invalid commitment root — not in valid roots window".into(),
            ));
        }

        // 3. Check nullifier not already spent (fast-path read check)
        if self.epoch_manager.is_nullifier_spent(&tx.nullifier) {
            return Err(GhostError::InvalidInput(
                "Nullifier already spent — double-spend attempt".into(),
            ));
        }

        // 4. Verify Groth16 proof
        let verifier = self.verifier.read();
        if let Some(ref v) = *verifier {
            let public_inputs = GhostNoteSpendPublicInputs {
                commitment_root: tx.commitment_root,
                nullifier: tx.nullifier,
                change_commitment: tx.change_commitment,
                recipient_commitment: tx.recipient_commitment,
            };
            let valid = v
                .verify_raw(&tx.proof, &public_inputs)
                .map_err(|e| GhostError::Internal(format!("Proof verification error: {}", e)))?;
            if !valid {
                return Err(GhostError::InvalidInput(
                    "Proof verification failed — invalid ZK proof".into(),
                ));
            }
        } else {
            return Err(GhostError::Internal(
                "No verifier available — MPC params not loaded".into(),
            ));
        }

        // 5. Record nullifier as spent (atomic check+insert)
        let height = self.epoch_manager.current_height();
        let spent = self.epoch_manager.spend_nullifier(tx.nullifier, height)?;
        if !spent {
            return Err(GhostError::InvalidInput(
                "Nullifier race: already spent by another thread".into(),
            ));
        }

        // 6. Add to confirmed pool
        {
            let mut pool = self.confirmed_pool.write();
            if pool.len() >= self.config.max_txs_per_checkpoint {
                warn!("Confirmed pool full, rejecting transaction");
                return Err(GhostError::Internal("Confirmed pool full".into()));
            }
            pool.push(tx.clone());
            self.confirmed_nullifiers.write().insert(tx.nullifier);
        }

        // 7. Create signed confirmation receipt
        let mut confirmation = L2TransferConfirmationMessage {
            nullifier: tx.nullifier,
            validator: self.our_id,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            signature: [0u8; 64],
        };
        let sign_msg = confirmation.signing_message();
        confirmation.signature = self.sign(&sign_msg);

        debug!(
            nullifier = %hex::encode(&tx.nullifier[..8]),
            pool_size = self.confirmed_pool_size(),
            "Transaction confirmed"
        );

        Ok(Some(confirmation))
    }

    /// Handle a broadcast of a confirmed transaction from another validator
    ///
    /// Other nodes add the transaction to their local view for checkpoint verification.
    pub fn handle_transfer_broadcast(&self, msg: &L2TransferBroadcastMessage) -> GhostResult<()> {
        let tx = &msg.transaction;

        // Apply piggybacked shield prerequisites before root check.
        // Ensures our tree includes shield commitments that the transfer's proof
        // was built against. insert_commitment_at is idempotent (INSERT OR IGNORE).
        for p in &msg.prerequisites {
            let _ =
                self.epoch_manager
                    .insert_commitment_at(p.note_index, p.commitment, p.block_height);
            if let Ok(root) = self.epoch_manager.current_root() {
                let _ = self.epoch_manager.add_valid_root(root, p.block_height);
            }
        }

        // Validate root is known
        if !self.epoch_manager.is_root_valid(&tx.commitment_root) {
            warn!("Broadcast tx has unknown commitment root, ignoring");
            return Ok(());
        }

        // H-3: Verify ZK proof before accepting broadcast transactions.
        // Without this, a malicious validator could broadcast fabricated transactions
        // that bypass proof verification, corrupting the confirmed pool.
        let verifier = self.verifier.read();
        if let Some(ref v) = *verifier {
            let public_inputs = GhostNoteSpendPublicInputs {
                commitment_root: tx.commitment_root,
                nullifier: tx.nullifier,
                change_commitment: tx.change_commitment,
                recipient_commitment: tx.recipient_commitment,
            };
            match v.verify_raw(&tx.proof, &public_inputs) {
                Ok(true) => {} // Valid proof, continue
                Ok(false) => {
                    warn!(
                        validator = %hex::encode(&msg.validator[..8]),
                        "H-3: Rejecting broadcast with invalid ZK proof"
                    );
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        validator = %hex::encode(&msg.validator[..8]),
                        error = %e,
                        "H-3: Proof verification error on broadcast, rejecting"
                    );
                    return Ok(());
                }
            }
        } else {
            // S-1: Fail-closed — reject broadcast if verifier is not loaded.
            // This matches handle_transfer() at line 360 which correctly rejects.
            warn!("Rejecting L2 broadcast — verifier not loaded");
            return Ok(());
        }

        // Record nullifier (if not already known)
        let height = self.epoch_manager.current_height();
        let _ = self.epoch_manager.spend_nullifier(tx.nullifier, height);

        // Add to confirmed pool (S-4: O(1) dedup via HashSet instead of linear scan)
        {
            let mut nullifiers = self.confirmed_nullifiers.write();
            if nullifiers.insert(tx.nullifier) {
                self.confirmed_pool.write().push(tx.clone());
                // Persist to staging table for crash recovery
                if let Ok(tx_bytes) = serde_json::to_vec(tx) {
                    if let Err(e) = self.db.insert_confirmed_pool_tx(&tx.nullifier, &tx_bytes) {
                        warn!(error = %e, "Failed to persist confirmed tx to staging (non-fatal)");
                    }
                }
            }
        }

        Ok(())
    }

    // =========================================================================
    // CHECKPOINT PROPOSAL (every 10s, with fallback timeout)
    // =========================================================================

    /// Create a checkpoint block if we are the designated proposer or fallback.
    ///
    /// Called periodically (every 10s). Returns the proposal if we should propose.
    /// Implements proposer timeout: if the primary proposer hasn't produced within
    /// PROPOSER_GRACE_SECS, the fallback proposer takes over.
    pub fn propose_checkpoint(&self) -> GhostResult<Option<L2CheckpointBlockMessage>> {
        // Return cached proposal if we already proposed for the current height.
        // This guarantees hash stability across repeated 10s cycles — any tree mutations
        // (shield syncs, etc.) between cycles won't change the proposal hash.
        let base_height = self.epoch_manager.current_height() + 1;
        if let Some(ref cached) = *self.cached_proposal.read() {
            if cached.height == base_height {
                return Ok(Some(cached.clone()));
            }
        }

        let elapsed = self.last_checkpoint_time.read().elapsed();
        let stuck = elapsed.as_secs() > PROPOSER_GRACE_SECS * 2;

        // Determine which height to propose for
        let (height, is_fallback) = if stuck {
            // Scan a range of heights to find one we can propose for.
            // By pigeonhole, within N consecutive heights every node is primary at least once.
            let node_count = self.epoch_manager.active_node_count().max(1);
            let mut found = None;
            for offset in 0..node_count {
                let h = base_height + offset as u64;
                if self.epoch_manager.is_proposer(&self.our_id, h) {
                    found = Some((h, false));
                    break;
                }
                if self
                    .epoch_manager
                    .get_fallback_proposer(h)
                    .map(|fb| fb == self.our_id)
                    .unwrap_or(false)
                {
                    found = Some((h, true));
                    break;
                }
            }
            match found {
                Some(f) => f,
                None => return Ok(None),
            }
        } else {
            // Normal path: only try current_height + 1
            let is_primary = self.epoch_manager.is_proposer(&self.our_id, base_height);
            let is_fb = if !is_primary {
                if elapsed.as_secs() > PROPOSER_GRACE_SECS {
                    self.epoch_manager
                        .get_fallback_proposer(base_height)
                        .map(|fb| fb == self.our_id)
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            };
            if !is_primary && !is_fb {
                return Ok(None);
            }
            (base_height, is_fb)
        };

        if is_fallback {
            info!(
                height,
                grace_secs = PROPOSER_GRACE_SECS,
                "Primary proposer timed out, acting as fallback"
            );
        }

        // Clone confirmed pool for checkpoint inclusion. We do NOT drain here —
        // transactions are only removed from confirmed_pool when they are finalized in
        // finalize_checkpoint(). If this proposal loses to a competing proposal (e.g.,
        // primary/fallback race, network partition), the transactions remain available
        // for re-proposal. The confirmed_nullifiers set stays intact for dedup.
        let transactions: Vec<L2Transaction> = {
            let pool = self.confirmed_pool.read();
            pool.iter()
                .take(self.config.max_txs_per_checkpoint)
                .cloned()
                .collect()
        };

        // Expire phantom shields that have been pending too long (>15 checkpoint heights).
        // Without this, shields from stalled periods accumulate and poison the tree root,
        // preventing checkpoint convergence when nodes have accumulated different phantoms.
        {
            let current_height = self.epoch_manager.current_height();
            let mut pending = self.pending_shields.write();
            let before = pending.len();
            pending.retain(|sc| current_height.saturating_sub(sc.block_height) < 15);
            let expired = before - pending.len();
            if expired > 0 {
                info!(
                    expired,
                    remaining = pending.len(),
                    "Expired stale pending shields (>15 checkpoints old)"
                );
                // Also clean expired shields from the staging table
                if let Err(e) = self.db.delete_stale_pending_shields() {
                    warn!(error = %e, "Failed to clean expired shields from staging table");
                }
            }
        }

        // Clone pending shields for checkpoint inclusion. Same clone-not-drain pattern —
        // shields are only removed from pending_shields when they are finalized in
        // finalize_checkpoint(). If this proposal loses to a competing proposal,
        // the shields remain queued for the next checkpoint attempt.
        let shield_commitments: Vec<ShieldCommitment> = self.pending_shields.read().clone();

        // Use checkpoint base root (stable across shield insertions) instead of current_root()
        let prev_root = *self.checkpoint_base_root.read();

        // Compute hypothetical new root on a scratch tree WITHOUT mutating the real tree.
        // This prevents tree divergence if the proposal loses BFT consensus — the real
        // tree only gets mutated in finalize_checkpoint() after consensus is reached.
        let new_root = {
            let mut scratch = self.epoch_manager.clone_tree();
            for sc in &shield_commitments {
                scratch.insert(sc.note_index, sc.commitment);
            }
            for tx in &transactions {
                let idx = scratch.next_index();
                scratch.insert(idx, tx.change_commitment);
                let idx2 = scratch.next_index();
                scratch.insert(idx2, tx.recipient_commitment);
            }
            scratch
                .root()
                .map_err(|e| GhostError::Internal(format!("scratch root: {}", e)))?
        };

        let mut proposal = L2CheckpointBlockMessage {
            height,
            epoch: self.epoch_manager.current_epoch(),
            prev_commitment_root: prev_root,
            new_commitment_root: new_root,
            transactions,
            shield_commitments,
            active_node_count: self.epoch_manager.active_node_count() as u32,
            proposer: self.our_id,
            proposer_signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            epoch_transition: None,
        };

        // Sign the proposal
        let signable = proposal.to_signable_bytes();
        proposal.proposer_signature = self.sign(&signable);

        info!(
            height,
            tx_count = proposal.transactions.len(),
            fallback = is_fallback,
            "Proposed checkpoint block"
        );

        // Cache proposal so repeated cycles reuse it with identical hash
        *self.cached_proposal.write() = Some(proposal.clone());

        Ok(Some(proposal))
    }

    // =========================================================================
    // CHECKPOINT VOTING (all-node BFT)
    // =========================================================================

    /// Handle a checkpoint block proposal
    ///
    /// Validates the proposal and casts a vote.
    /// Handle a checkpoint proposal after signature verification.
    ///
    /// # Prerequisite: Signature Already Verified
    ///
    /// The caller (handle_message) MUST verify the proposer's Ed25519 signature
    /// before calling this method. This ensures we do not waste CPU on root
    /// verification or voting for unsigned/invalid messages. The ordering is:
    ///
    /// 1. Verify proposer signature (in handle_message)
    /// 2. Validate proposer identity and root (this method)
    /// 3. Cast vote
    pub fn handle_checkpoint_proposal(
        &self,
        msg: &L2CheckpointBlockMessage,
    ) -> GhostResult<Option<L2CheckpointVoteMessage>> {
        let height = msg.height;
        let checkpoint_hash = msg.checkpoint_hash();

        // Detect height gap — if we're behind, trigger tree sync
        let our_height = self.epoch_manager.current_height();
        if msg.height > our_height + 1 {
            info!(
                our_height,
                proposal_height = msg.height,
                gap = msg.height - our_height,
                "Behind on checkpoint height, requesting tree sync"
            );
            let _ = self.request_tree_sync();
            return Ok(None); // Don't vote on proposals we can't validate yet
        }

        // Validate proposer is correct for this height (primary or fallback)
        if let Some(expected) = self.epoch_manager.get_proposer(height) {
            if expected != msg.proposer {
                // Check fallback proposer
                let is_valid_fallback = self
                    .epoch_manager
                    .get_fallback_proposer(height)
                    .map(|fb| fb == msg.proposer)
                    .unwrap_or(false);

                if !is_valid_fallback {
                    warn!(
                        height,
                        expected = %hex::encode(&expected[..8]),
                        got = %hex::encode(&msg.proposer[..8]),
                        "Wrong proposer for checkpoint"
                    );
                    return Ok(None);
                }
            }
        }

        // Determine if this proposal is from the primary proposer for this height.
        let is_primary_proposal = self
            .epoch_manager
            .get_proposer(height)
            .map(|p| p == msg.proposer)
            .unwrap_or(false);

        // Store the proposal and manage competing proposals at the same height.
        //
        // Key invariant: primary proposer proposals ALWAYS supersede fallback proposals.
        // When a fallback proposal created the vote state first (due to timing/network
        // delays), and the primary's proposal arrives later with shield commitments,
        // we must reset the vote state to use the primary's hash. Without this, shield
        // commitments from the primary are permanently ignored because votes for its
        // hash get rejected against the fallback's hash.
        {
            let mut votes = self.votes.write();
            let state = votes
                .entry(height)
                .or_insert_with(|| CheckpointVoteState::new(checkpoint_hash));

            if state.checkpoint_hash != checkpoint_hash {
                if is_primary_proposal && !state.finalized {
                    // Primary proposal arrived after a fallback (or early vote) set the hash.
                    // Reset vote state to adopt the primary's hash. Existing votes for the
                    // old hash are stale and must be discarded — they voted on different content.
                    info!(
                        height,
                        old_hash = %hex::encode(&state.checkpoint_hash[..8]),
                        new_hash = %hex::encode(&checkpoint_hash[..8]),
                        stale_votes = state.votes.len(),
                        "Primary proposal supersedes fallback — resetting vote state"
                    );
                    *state = CheckpointVoteState::new(checkpoint_hash);
                    state.proposal = Some(msg.clone());
                } else {
                    // Fallback proposal arrived but a different hash (from primary or earlier
                    // vote) already owns this slot. Do NOT overwrite the proposal — the stored
                    // hash's proposal must win to preserve shield commitments. Return without
                    // voting since this proposal is superseded.
                    debug!(
                        height,
                        "Fallback proposal arrived but different hash already stored, skipping"
                    );
                    return Ok(None);
                }
            } else {
                // Hashes match — store or update the proposal.
                state.proposal = Some(msg.clone());
            }
        }

        // Apply shield commitments from the proposal BEFORE root validation.
        // Shields are synced to the proposer's tree via ghost-pay but may not have
        // reached other nodes yet. Applying them here (idempotent via INSERT OR IGNORE)
        // ensures all validators have the same tree state.
        // Note: we do NOT update checkpoint_base_root here — that only advances on
        // finalization. The proposer's prev_commitment_root was set from its own
        // checkpoint_base_root (pre-shield), so our comparison must use ours unchanged.
        if !msg.shield_commitments.is_empty() {
            for sc in &msg.shield_commitments {
                let _ = self.epoch_manager.insert_commitment_at(
                    sc.note_index,
                    sc.commitment,
                    sc.block_height,
                );
            }
            debug!(
                height,
                shields = msg.shield_commitments.len(),
                "Applied shield commitments from proposal before vote"
            );
        }

        // Validate prev_commitment_root matches our checkpoint base root.
        let our_base_root = *self.checkpoint_base_root.read();
        if msg.prev_commitment_root != our_base_root {
            warn!(
                height,
                our_root = %hex::encode(&our_base_root[..8]),
                proposal_root = %hex::encode(&msg.prev_commitment_root[..8]),
                "Checkpoint prev_root doesn't match our checkpoint base root — attempting recovery"
            );

            // Attempt recovery: flush all pending shields (they're likely phantoms causing
            // the divergence) and request tree sync to converge with the proposer.
            {
                let mut pending = self.pending_shields.write();
                if !pending.is_empty() {
                    let flushed = pending.len();
                    pending.clear();
                    info!(
                        flushed,
                        "Flushed all pending shields to resolve root divergence"
                    );
                    if let Err(e) = self.db.delete_stale_pending_shields() {
                        warn!(error = %e, "Failed to clean pending shields from staging table");
                    }
                }
            }

            // Request tree sync to converge with peers
            let _ = self.request_tree_sync();

            // Still vote but reject (recovery happens asynchronously via tree sync)
            let mut vote = L2CheckpointVoteMessage {
                height,
                checkpoint_hash,
                voter: self.our_id,
                approve: false,
                signature: [0u8; 64],
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
            };
            let sign_msg = vote.signing_message();
            vote.signature = self.sign(&sign_msg);
            return Ok(Some(vote));
        }

        // Cast our signed vote (approve)
        let mut vote = L2CheckpointVoteMessage {
            height,
            checkpoint_hash,
            voter: self.our_id,
            approve: true,
            signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        let sign_msg = vote.signing_message();
        vote.signature = self.sign(&sign_msg);

        if let Some(ref m) = *self.metrics.read() {
            m.consensus_votes_total.inc();
        }
        debug!(height, "Cast checkpoint vote (approve)");
        Ok(Some(vote))
    }

    /// Broadcast a checkpoint proposal to the network and handle it locally.
    ///
    /// This is the proposer's entry point — it:
    /// 1. Broadcasts the proposal to all peers (L2CheckpointBlock)
    /// 2. Validates and votes on our own proposal (handle_checkpoint_proposal)
    /// 3. Records our own vote locally (handle_checkpoint_vote)
    /// 4. Broadcasts our vote to all peers (L2CheckpointVote)
    pub fn propose_and_broadcast(&self, proposal: &L2CheckpointBlockMessage) -> GhostResult<()> {
        // 1. Broadcast proposal to network
        if let Some(ref broadcast) = *self.broadcast_fn.read() {
            let payload = serde_json::to_vec(proposal)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            broadcast(MessageType::L2CheckpointBlock, payload)?;
        }

        // 2. Handle locally — validate and create our vote
        if let Some(vote) = self.handle_checkpoint_proposal(proposal)? {
            // 3. Record our own vote locally (enables single-node quorum)
            self.handle_checkpoint_vote(&vote)?;

            // 4. Broadcast our vote to peers
            if let Some(ref broadcast) = *self.broadcast_fn.read() {
                let payload = serde_json::to_vec(&vote)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                broadcast(MessageType::L2CheckpointVote, payload)?;
            }
        }

        Ok(())
    }

    /// Handle a checkpoint vote
    ///
    /// Returns true if the checkpoint reached quorum and was finalized.
    pub fn handle_checkpoint_vote(&self, msg: &L2CheckpointVoteMessage) -> GhostResult<bool> {
        let height = msg.height;
        let active_count = self.epoch_manager.active_node_count();

        // C-10: Only accept votes from nodes in the active set.
        // Prevents removed nodes from influencing quorum with stale keys.
        if self.epoch_manager.our_index(&msg.voter).is_none() {
            debug!(
                height,
                voter = %hex::encode(&msg.voter[..8]),
                "Ignoring vote from non-active node"
            );
            return Ok(false);
        }

        let (finalized, proposal) = {
            let mut votes = self.votes.write();
            let state = votes
                .entry(height)
                .or_insert_with(|| CheckpointVoteState::new(msg.checkpoint_hash));

            if state.finalized {
                return Ok(false); // Already finalized
            }

            // Verify vote is for the same checkpoint.
            // If hashes differ: when no proposal is stored yet, the hash was set by
            // whichever vote arrived first (arbitrary). In that case, we cannot know
            // which hash is correct, so we accept the vote and let proposal arrival
            // (which resets state for primary proposals) sort it out. When a proposal
            // IS stored, the hash is authoritative and mismatched votes are rejected.
            if state.checkpoint_hash != msg.checkpoint_hash {
                if state.proposal.is_some() {
                    debug!(
                        height,
                        "Vote for different checkpoint hash (proposal stored), ignoring"
                    );
                    return Ok(false);
                }
                // No proposal stored — hash was set by an earlier vote. Don't reject;
                // this vote will be re-evaluated when the proposal arrives and resets state.
                // For now, skip counting it (it may be for the correct primary proposal).
                debug!(
                    height,
                    "Vote for different checkpoint hash (no proposal yet), deferring"
                );
                return Ok(false);
            }

            state.add_vote(VerifiedVote::new(msg.voter, msg.approve));

            if state.has_quorum(active_count, self.config.bft_threshold_percent) {
                state.finalized = true;
                (true, state.proposal.clone())
            } else {
                (false, None)
            }
        };

        if finalized {
            // C-7: Only finalize if we have the proposal data. Without it, we can't
            // apply commitments or compute the canonical root, which would cause this
            // node's tree to diverge from nodes that do have the proposal.
            if proposal.is_none() {
                warn!(
                    height,
                    "Checkpoint reached quorum but proposal data missing — requesting tree sync"
                );
                // Unmark as finalized so tree sync can replay this height
                let mut votes = self.votes.write();
                if let Some(state) = votes.get_mut(&height) {
                    state.finalized = false;
                }
                // Self-heal: the proposer that finalized has the checkpoint data.
                // Request tree sync so we can replay it locally.
                if let Err(e) = self.request_tree_sync() {
                    warn!(error = %e, "Failed to request tree sync after quorum-without-proposal");
                }
                return Ok(false);
            }
            info!(
                height,
                votes = active_count,
                "Checkpoint reached BFT quorum"
            );
            self.finalize_checkpoint(height, proposal.as_ref())?;
        }

        Ok(finalized)
    }

    /// Finalize a checkpoint after BFT approval
    fn finalize_checkpoint(
        &self,
        height: u64,
        proposal: Option<&L2CheckpointBlockMessage>,
    ) -> GhostResult<()> {
        // ALL nodes (including the proposer) apply commitments from the winning proposal.
        // The proposer no longer mutates the real tree during propose_checkpoint() — it
        // uses a scratch tree for root computation. This eliminates tree divergence when
        // a proposal loses consensus.
        if let Some(block) = proposal {
            // Apply shield commitments (idempotent via INSERT OR IGNORE at specific index)
            for sc in &block.shield_commitments {
                let _ = self.epoch_manager.insert_commitment_at(
                    sc.note_index,
                    sc.commitment,
                    sc.block_height,
                );
            }

            // Apply transaction commitments (sequential append)
            for tx in &block.transactions {
                self.epoch_manager
                    .append_commitment(tx.change_commitment, height)?;
                self.epoch_manager
                    .append_commitment(tx.recipient_commitment, height)?;
            }
        }

        // --- PHASE 1: Compute canonical root and persist checkpoint to DB ---
        // DB persist happens BEFORE in-memory cleanup. If we crash after persist,
        // state is consistent (tree rebuilt from l2_notes, checkpoint recorded).
        // If we crash before persist, confirmed_pool is restored from staging (C-3).

        // Register new valid root from local tree state
        let local_root = self.epoch_manager.current_root()?;
        self.epoch_manager.add_valid_root(local_root, height)?;

        // Update checkpoint base root to the PROPOSAL's new_commitment_root.
        // This ensures all nodes converge on the same base root regardless of
        // local tree state (e.g., pending shields that haven't been checkpointed yet).
        // Fall back to local root only if no proposal is available.
        let canonical_root = proposal
            .map(|p| p.new_commitment_root)
            .unwrap_or(local_root);
        *self.checkpoint_base_root.write() = canonical_root;

        // Also register the canonical root as valid (may differ from local if shields pending)
        if canonical_root != local_root {
            self.epoch_manager.add_valid_root(canonical_root, height)?;
        }

        // Persist checkpoint + nullifiers atomically in a single SQLite transaction.
        // If the process crashes mid-write, the entire checkpoint is rolled back.
        // Count both transactions and shield commitments as finalized activity.
        // Shields are BFT-finalized tree modifications and should count as finalizations.
        let tx_count = proposal
            .map(|p| p.transactions.len() + p.shield_commitments.len())
            .unwrap_or(0);
        let pending_nullifiers = self.epoch_manager.drain_pending_nullifiers();
        let record = ghost_storage::L2CheckpointRecord {
            height,
            epoch: self.epoch_manager.current_epoch(),
            commitment_root: canonical_root,
            tx_count: tx_count as u32,
            proposer_id: proposal
                .map(|p| hex::encode(p.proposer))
                .unwrap_or_default(),
            active_node_count: self.epoch_manager.active_node_count() as u32,
            block_data: proposal
                .and_then(|p| serde_json::to_vec(p).ok())
                .unwrap_or_default(),
        };
        // Use upsert fallback for idempotent persistence (checkpoint may already exist from tree sync)
        let atomic_ok = self
            .db
            .persist_l2_checkpoint_atomic(&record, &pending_nullifiers)
            .is_ok();
        if !atomic_ok {
            warn!(height, "Checkpoint atomic persist failed, upserting checkpoint record (nullifier WAL preserved)");
            self.db.upsert_l2_checkpoint(&record)?;
        }

        // C-9: Only clear the nullifier write-ahead log if the atomic persist succeeded.
        // The atomic persist moves nullifiers from pending_nullifiers → l2_nullifiers in
        // one transaction. If it failed, the nullifiers are still ONLY in pending_nullifiers.
        // Clearing the WAL here would lose them permanently.
        if atomic_ok {
            if let Err(e) = self.db.confirm_pending_nullifiers() {
                warn!(height, error = %e, "Failed to clear pending_nullifiers write-ahead log (non-fatal, will be cleared on next checkpoint)");
            }
        }

        // --- PHASE 2: Clean up in-memory pools (safe to lose on crash — pools restored from staging) ---

        // Clear cached proposal — height has advanced, next cycle builds a fresh proposal
        *self.cached_proposal.write() = None;

        // Remove finalized data from in-memory pools.
        // Since we clone (not drain) in propose_checkpoint(), data remains in the pools
        // until finalized here. This ensures nothing is lost if a proposal fails quorum.
        if let Some(block) = proposal {
            // Remove finalized shield commitments from pending_shields and staging table
            if !block.shield_commitments.is_empty() {
                let finalized_indices: Vec<u64> = block
                    .shield_commitments
                    .iter()
                    .map(|sc| sc.note_index)
                    .collect();
                let finalized_set: HashSet<u64> = finalized_indices.iter().copied().collect();
                self.pending_shields
                    .write()
                    .retain(|sc| !finalized_set.contains(&sc.note_index));
                if let Err(e) = self.db.delete_pending_shields(&finalized_indices) {
                    warn!(
                        height,
                        error = %e,
                        "Failed to delete finalized shields from staging table (non-fatal)"
                    );
                }
            }

            // Remove finalized transactions from confirmed_pool + staging table
            if !block.transactions.is_empty() {
                let finalized_nullifiers: HashSet<[u8; 32]> =
                    block.transactions.iter().map(|tx| tx.nullifier).collect();
                {
                    let mut pool = self.confirmed_pool.write();
                    pool.retain(|tx| !finalized_nullifiers.contains(&tx.nullifier));
                }
                {
                    let mut nullifiers = self.confirmed_nullifiers.write();
                    for n in &finalized_nullifiers {
                        nullifiers.remove(n);
                    }
                }
                // Remove from DB staging table
                let nullifier_vec: Vec<[u8; 32]> = finalized_nullifiers.into_iter().collect();
                if let Err(e) = self.db.delete_confirmed_pool_txs(&nullifier_vec) {
                    warn!(
                        height,
                        error = %e,
                        "Failed to delete finalized txs from staging table (non-fatal)"
                    );
                }
            }
        }

        // Track L2 transfer fees: each NoteSpend transaction pays a flat protocol fee
        // (shields don't pay fees, only NoteSpend transfers do)
        let transfer_count = proposal.map(|p| p.transactions.len()).unwrap_or(0);
        if transfer_count > 0 {
            if let Err(e) = self
                .db
                .increment_epoch_fee(self.epoch_manager.current_epoch(), transfer_count as u64)
            {
                warn!(epoch = self.epoch_manager.current_epoch(), error = %e,
                    "Failed to increment epoch fee counter — fees will be under-counted");
            }
        }

        // Update last checkpoint time (for proposer timeout detection)
        *self.last_checkpoint_time.write() = Instant::now();

        // Check for epoch transition
        let compaction = self.epoch_manager.on_checkpoint_finalized(height)?;
        if let Some(result) = compaction {
            info!(
                new_epoch = result.new_epoch,
                notes_migrated = result.notes_migrated,
                "Epoch transition during checkpoint finalization"
            );
        }

        // Clean up old vote states
        self.prune_vote_states(height);

        // Notify ghost-pay of finalized checkpoint (MEDIUM-2: pass nullifiers for tx identification)
        if let Some(ref finalize_fn) = *self.finalize_fn.read() {
            let nullifiers: Vec<[u8; 32]> = proposal
                .map(|p| p.transactions.iter().map(|tx| tx.nullifier).collect())
                .unwrap_or_default();
            finalize_fn(height, canonical_root, nullifiers);
        }

        if let Some(ref m) = *self.metrics.read() {
            m.consensus_rounds_total.inc();
            let votes = m.consensus_votes_total.get();
            let rounds = m.consensus_rounds_total.get();
            // Participation = votes / rounds * 100 (each round we should cast 1 vote).
            // `checked_div` rather than a `rounds > 0` guard: same result, and it cannot be
            // reintroduced as a divide-by-zero if the guard is ever moved.
            if let Some(pct) = (votes * 100).checked_div(rounds) {
                m.consensus_participation_percent.set(pct.min(100) as i64);
            }
        }
        debug!(height, tx_count, "Checkpoint finalized");
        Ok(())
    }

    /// Prune vote states older than the current height
    fn prune_vote_states(&self, current_height: u64) {
        let cutoff = current_height.saturating_sub(100);
        let mut votes = self.votes.write();
        votes.retain(|h, _| *h > cutoff);
    }

    // =========================================================================
    // TREE SYNC (for new nodes joining the network)
    // =========================================================================

    /// Handle a tree sync request from a new node
    fn handle_tree_sync_request(
        &self,
        request: &L2TreeSyncRequest,
    ) -> GhostResult<Option<L2TreeSyncResponse>> {
        // Rate limit: max 1 request per peer per 60 seconds
        {
            let mut sync_reqs = self.sync_requests.write();
            if let Some(last) = sync_reqs.get(&request.requesting_node) {
                if last.elapsed().as_secs() < SYNC_REQUEST_COOLDOWN_SECS {
                    debug!(
                        peer = %hex::encode(&request.requesting_node[..8]),
                        "Tree sync request rate limited"
                    );
                    return Ok(None);
                }
            }
            sync_reqs.insert(request.requesting_node, Instant::now());
        }

        // Load checkpoints from requested height
        let checkpoints = self
            .db
            .get_l2_checkpoints_from_height(request.from_height, MAX_SYNC_CHECKPOINTS as u64)?;

        // Deserialize checkpoint blocks from stored data
        let mut checkpoint_blocks = Vec::new();
        let mut has_more = false;
        for record in &checkpoints {
            if checkpoint_blocks.len() >= MAX_SYNC_CHECKPOINTS {
                has_more = true;
                break;
            }
            if !record.block_data.is_empty() {
                if let Ok(block) =
                    serde_json::from_slice::<L2CheckpointBlockMessage>(&record.block_data)
                {
                    checkpoint_blocks.push(block);
                }
            }
        }

        // Attach the parent epoch record for every epoch referenced by the
        // checkpoints being sent. The requesting node upserts these BEFORE
        // persisting the checkpoints so the l2_checkpoints.epoch -> l2_epochs
        // FK is satisfied even when this batch starts past an epoch boundary
        // (the requester may never have replayed the boundary transition that
        // would otherwise create the epoch row locally).
        let mut epochs: Vec<L2EpochSync> = Vec::new();
        let mut seen_epochs = std::collections::HashSet::new();
        for block in &checkpoint_blocks {
            if !seen_epochs.insert(block.epoch) {
                continue;
            }
            match self.db.get_l2_epoch(block.epoch) {
                Ok(Some(rec)) => epochs.push(L2EpochSync {
                    epoch: rec.epoch,
                    start_height: rec.start_height,
                    end_height: rec.end_height,
                    initial_root: rec.initial_root,
                    final_root: rec.final_root,
                    notes_migrated: rec.notes_migrated,
                    status: rec.status,
                }),
                Ok(None) => {
                    // Our own checkpoint references an epoch we don't have —
                    // should not happen, but don't fail the whole sync.
                    warn!(
                        epoch = block.epoch,
                        "Tree sync: local epoch record missing for checkpoint being sent"
                    );
                }
                Err(e) => {
                    warn!(epoch = block.epoch, error = %e, "Tree sync: failed to load epoch record");
                }
            }
        }

        // Use checkpoint_base_root (last finalized canonical root) instead of current_root()
        // which includes pending shields. This gives the requesting node a stable target
        // to verify against after replaying the checkpoints.
        let canonical_root = *self.checkpoint_base_root.read();

        let response = L2TreeSyncResponse {
            responding_node: self.our_id,
            // Address it. Responses go out over the broadcast transport, so without this every
            // node in the mesh processes every response (#517).
            requesting_node: Some(request.requesting_node),
            checkpoints: checkpoint_blocks,
            current_epoch: self.epoch_manager.current_epoch(),
            commitment_root: canonical_root,
            epochs,
            has_more,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        info!(
            peer = %hex::encode(&request.requesting_node[..8]),
            from_height = request.from_height,
            checkpoints_sent = response.checkpoints.len(),
            "Responded to tree sync request"
        );

        Ok(Some(response))
    }

    /// Handle a tree sync response (replay checkpoints to catch up)
    fn handle_tree_sync_response(&self, response: &L2TreeSyncResponse) -> GhostResult<()> {
        // Answers to somebody else's question are not ours to process.
        //
        // Responses are broadcast, so before this every node ran the full handler on every
        // response in the mesh: with N nodes, N(N-1) runs for (N-1) real answers, each
        // recomputing a Merkle root. On the 8-node fleet that was ~175 responses processed per
        // node per 10 minutes against ~25 actually sent — and the surplus is what starved the
        // runtime until the HTTP listener stopped being scheduled at all (#517).
        //
        // Worse than the wasted CPU: the pagination path below calls `request_tree_sync()` and
        // mutates `sync_requests` keyed on `responding_node`, so a foreign response could drive
        // this node into re-requesting and corrupt its own tracking state.
        //
        // `None` means the peer predates the field — process it, as before. The amplification
        // only clears once both ends are upgraded, which is the honest ordering here.
        if let Some(addressee) = response.requesting_node {
            if addressee != self.our_id {
                trace!(
                    responder = %hex::encode(&response.responding_node[..8]),
                    addressee = %hex::encode(&addressee[..8]),
                    "Ignoring tree sync response addressed to another node"
                );
                return Ok(());
            }
        }

        if response.checkpoints.is_empty() {
            debug!("Empty tree sync response, nothing to replay");
            // Even with no checkpoints to replay, check root convergence.
            // This catches the case where notes were lost (e.g., SIGKILL) but
            // checkpoint records survived — the node is at the right height
            // but its Merkle root diverges from peers.
            let our_root = self.epoch_manager.current_root()?;
            if our_root != response.commitment_root && response.commitment_root != [0u8; 32] {
                warn!(
                    our_root = %hex::encode(&our_root[..8]),
                    peer_root = %hex::encode(&response.commitment_root[..8]),
                    "Root mismatch on empty tree sync — initiating note gap recovery"
                );
                let epoch = self.epoch_manager.current_epoch();
                if let Ok(our_notes) = self.db.load_all_l2_notes_for_epoch(epoch) {
                    let our_indices: Vec<u64> = our_notes.iter().map(|(idx, _)| *idx).collect();
                    let gap_request = L2NoteGapRequest {
                        requesting_node: self.our_id,
                        our_note_count: our_indices.len() as u64,
                        our_note_indices: our_indices,
                        from_index: 0,
                        timestamp: chrono::Utc::now().timestamp_millis() as u64,
                    };
                    if let Some(ref broadcast) = *self.broadcast_fn.read() {
                        let payload = serde_json::to_vec(&gap_request)
                            .map_err(|e| GhostError::Serialization(e.to_string()))?;
                        broadcast(MessageType::L2TreeSync, payload)?;
                        info!("Sent note gap request to peers (empty sync path)");
                    }
                }
            }
            return Ok(());
        }

        info!(
            from = %hex::encode(&response.responding_node[..8]),
            checkpoints = response.checkpoints.len(),
            epoch = response.current_epoch,
            "Replaying tree sync response"
        );

        // Verify all checkpoint signatures before applying any (atomic)
        if self.sign_fn.read().is_none() {
            warn!("M-5: Rejecting tree sync — sign_fn not initialized");
            return Ok(());
        }
        for (i, block) in response.checkpoints.iter().enumerate() {
            let signable = block.to_signable_bytes();
            if !self.verify_peer_signature(&block.proposer, &signable, &block.proposer_signature) {
                warn!(
                    height = block.height,
                    proposer = %hex::encode(&block.proposer[..8]),
                    checkpoint_idx = i,
                    "Rejecting tree sync — invalid proposer signature"
                );
                return Err(GhostError::SignatureVerification(
                    "Tree sync checkpoint has invalid signature".into(),
                ));
            }
        }

        // Materialise the parent epoch rows BEFORE replaying any checkpoint.
        // Checkpoints foreign-key l2_checkpoints.epoch -> l2_epochs.epoch; a
        // fresh node that starts syncing past an epoch boundary (pruned early
        // checkpoints, or a dropped boundary batch) never replayed the local
        // transition that would create those epoch rows. Upserting the peer's
        // authoritative epoch records here satisfies the FK legitimately
        // instead of tripping the trigger on every sync round.
        for epoch in &response.epochs {
            let record = ghost_storage::L2EpochRecord {
                epoch: epoch.epoch,
                start_height: epoch.start_height,
                end_height: epoch.end_height,
                initial_root: epoch.initial_root,
                final_root: epoch.final_root,
                notes_migrated: epoch.notes_migrated,
                status: epoch.status.clone(),
            };
            self.db.upsert_l2_epoch(&record)?;
        }

        // Replay checkpoint blocks in order
        let mut last_applied_root: Option<[u8; 32]> = None;
        for block in &response.checkpoints {
            let height = block.height;

            // Defence in depth: if a checkpoint's parent epoch is still absent
            // (e.g. a peer predating the `epochs` field, or a malformed batch),
            // DEFER rather than force the insert and trip the FK trigger every
            // round. Stop at the first unsatisfiable checkpoint — later ones in
            // the batch would cascade — and return cleanly so the mesh does not
            // log a handler error. The next sync round (from an upgraded peer)
            // supplies the epoch and replay resumes from here.
            match self.db.get_l2_epoch(block.epoch) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    warn!(
                        height,
                        epoch = block.epoch,
                        "Tree sync: deferring checkpoint — parent epoch not yet available"
                    );
                    break;
                }
                Err(e) => return Err(e),
            }

            // Apply shield commitments first (they may be needed for tx roots)
            for sc in &block.shield_commitments {
                let _ = self.epoch_manager.insert_commitment_at(
                    sc.note_index,
                    sc.commitment,
                    sc.block_height,
                );
            }

            // Append commitments from each transaction
            for tx in &block.transactions {
                self.epoch_manager
                    .append_commitment(tx.change_commitment, height)?;
                self.epoch_manager
                    .append_commitment(tx.recipient_commitment, height)?;
            }

            // Record nullifiers
            for tx in &block.transactions {
                let _ = self.epoch_manager.spend_nullifier(tx.nullifier, height);
            }

            // Add valid roots (both local and canonical)
            let local_root = self.epoch_manager.current_root()?;
            self.epoch_manager.add_valid_root(local_root, height)?;

            // Use the proposal's new_commitment_root as canonical root, matching
            // finalize_checkpoint() behavior. The local root may differ if this node
            // has pending shields that aren't in the checkpoint, but the canonical
            // root must match what all other nodes agreed on via BFT.
            let canonical_root = block.new_commitment_root;
            if canonical_root != local_root {
                self.epoch_manager.add_valid_root(canonical_root, height)?;
            }

            // Process epoch transitions
            self.epoch_manager.on_checkpoint_finalized(height)?;

            // Persist synced checkpoint with canonical root (not local root)
            let tx_count = block.transactions.len() + block.shield_commitments.len();
            let record = ghost_storage::L2CheckpointRecord {
                height,
                epoch: block.epoch,
                commitment_root: canonical_root,
                tx_count: tx_count as u32,
                proposer_id: hex::encode(block.proposer),
                active_node_count: block.active_node_count,
                block_data: serde_json::to_vec(block).unwrap_or_default(),
            };
            self.db.upsert_l2_checkpoint(&record)?;

            // Mark this height as finalized in vote state so late-arriving proposals
            // cannot supersede it. Without this, a primary proposal arriving after
            // tree sync can reset the vote state (primary-supersedes-fallback), and
            // if no new blocks arrive to trigger re-voting, the checkpoint is left
            // in limbo — causing permanent root divergence.
            {
                let mut votes = self.votes.write();
                let state = votes
                    .entry(height)
                    .or_insert_with(|| CheckpointVoteState::new(canonical_root));
                state.finalized = true;
                state.checkpoint_hash = canonical_root;
            }

            last_applied_root = Some(canonical_root);
        }

        // Update checkpoint base root to the last checkpoint we actually applied
        // (not response.checkpoints.last(), which may have been deferred above).
        if let Some(root) = last_applied_root {
            *self.checkpoint_base_root.write() = root;
        }

        // Pagination follow-up: if peer has more checkpoints, request next batch
        if response.has_more {
            let new_height = self.epoch_manager.current_height();
            info!(
                from_height = new_height,
                "Tree sync has more checkpoints — requesting next batch"
            );
            // Clear rate limit for responding peer so follow-up isn't throttled
            self.sync_requests.write().remove(&response.responding_node);
            let _ = self.request_tree_sync();
            // Update last checkpoint time and return — don't gap-check mid-pagination
            *self.last_checkpoint_time.write() = Instant::now();
            return Ok(());
        }

        // Verify our root matches the peer's reported root
        let final_root = self.epoch_manager.current_root()?;
        if final_root != response.commitment_root {
            warn!(
                our_root = %hex::encode(&final_root[..8]),
                peer_root = %hex::encode(&response.commitment_root[..8]),
                "Root mismatch after tree sync — initiating note gap recovery"
            );

            // Load our note indices and ask peer for any we're missing
            let epoch = self.epoch_manager.current_epoch();
            if let Ok(our_notes) = self.db.load_all_l2_notes_for_epoch(epoch) {
                let our_indices: Vec<u64> = our_notes.iter().map(|(idx, _)| *idx).collect();
                let gap_request = L2NoteGapRequest {
                    requesting_node: self.our_id,
                    our_note_count: our_indices.len() as u64,
                    our_note_indices: our_indices,
                    from_index: 0,
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                };
                if let Some(ref broadcast) = *self.broadcast_fn.read() {
                    let payload = serde_json::to_vec(&gap_request)
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;
                    broadcast(MessageType::L2TreeSync, payload)?;
                    info!("Sent note gap request to peers");
                }
            }
        } else {
            info!("Tree sync complete — root matches peer");
        }

        // Update last checkpoint time
        *self.last_checkpoint_time.write() = Instant::now();

        Ok(())
    }

    /// Request tree sync from peers (called on startup or when behind).
    /// Client-side cooldown prevents spamming peers who rate-limit at 60s.
    pub fn request_tree_sync(&self) -> GhostResult<()> {
        // Client-side dedup: don't re-request within the cooldown window.
        // Peers rate-limit at SYNC_REQUEST_COOLDOWN_SECS, so sending more
        // often just wastes bandwidth and delays the first accepted response.
        {
            let last = self.last_sync_request_sent.read();
            if let Some(last_time) = *last {
                if last_time.elapsed().as_secs() < SYNC_REQUEST_COOLDOWN_SECS {
                    info!(
                        remaining_secs = SYNC_REQUEST_COOLDOWN_SECS - last_time.elapsed().as_secs(),
                        "Tree sync request suppressed (client-side cooldown)"
                    );
                    return Ok(());
                }
            }
        }

        // Ask for the lowest INTERIOR hole if we have one, otherwise for the tip.
        //
        // This only ever requested `current_height`, so it chased the few blocks it was behind
        // at the FRONT and never asked for holes inside its own range. The canaries sat on
        // frozen interior gaps — vm5 1,216 checkpoints in 64 contiguous runs, vm7 446, vm6 244 —
        // that no amount of syncing could close, because nothing looked for them. Sync kept
        // reporting "Tree sync complete — root matches peer" the whole time, which is true of
        // the tip and says nothing about the holes (#535).
        //
        // Serving `from_height` walks forward from there, so requesting the gap start pulls the
        // missing run. Taking the LOWEST gap each time makes repeated calls walk the range
        // forward deterministically instead of re-requesting the same window.
        let tip_height = self.epoch_manager.current_height();
        let from_height = match self.db.lowest_l2_checkpoint_gap() {
            Ok(Some((gap_start, gap_end))) => {
                info!(
                    gap_start,
                    gap_end, tip_height, "L2 tree sync targeting an interior checkpoint gap"
                );
                gap_start
            }
            Ok(None) => tip_height,
            Err(e) => {
                // Never let a gap-query failure stop the tip from syncing.
                warn!(error = %e, "could not check for interior checkpoint gaps — syncing tip");
                tip_height
            }
        };

        let request = L2TreeSyncRequest {
            requesting_node: self.our_id,
            from_height,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };

        if let Some(ref broadcast) = *self.broadcast_fn.read() {
            let payload = serde_json::to_vec(&request)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            broadcast(MessageType::L2TreeSync, payload)?;
            *self.last_sync_request_sent.write() = Some(Instant::now());
            info!(from_height, tip_height, "Requested L2 tree sync from peers");
        }

        Ok(())
    }

    /// Handle note gap request — peer is missing notes after tree sync, respond with
    /// the notes they don't have.
    fn handle_note_gap_request(
        &self,
        request: &L2NoteGapRequest,
    ) -> GhostResult<Option<L2NoteGapResponse>> {
        // Don't respond to our own requests
        if request.requesting_node == self.our_id {
            return Ok(None);
        }

        let epoch = self.epoch_manager.current_epoch();
        let our_notes = self.db.load_all_l2_notes_for_epoch(epoch)?;

        // Build set of requester's indices for O(1) lookup
        let their_indices: HashSet<u64> = request.our_note_indices.iter().copied().collect();

        // Find notes we have that they don't, starting from the pagination cursor
        let mut missing: Vec<ShieldCommitment> = our_notes
            .iter()
            .filter(|(idx, _)| *idx >= request.from_index && !their_indices.contains(idx))
            .map(|(idx, commitment)| ShieldCommitment {
                note_index: *idx,
                commitment: *commitment,
                block_height: 0,
            })
            .collect();

        if missing.is_empty() {
            return Ok(None);
        }

        // Cap at MAX_SYNC_CHECKPOINTS (100) per batch
        let has_more = missing.len() > MAX_SYNC_CHECKPOINTS;
        missing.truncate(MAX_SYNC_CHECKPOINTS);

        info!(
            peer = %hex::encode(&request.requesting_node[..8]),
            batch_size = missing.len(),
            has_more,
            from_index = request.from_index,
            our_count = our_notes.len(),
            their_count = request.our_note_count,
            "Responding to note gap request"
        );

        Ok(Some(L2NoteGapResponse {
            responding_node: self.our_id,
            missing_notes: missing,
            their_note_count: our_notes.len() as u64,
            commitment_root: self.epoch_manager.current_root()?,
            has_more,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }))
    }

    /// Handle note gap response — insert missing notes from peer to recover from SIGKILL gaps
    fn handle_note_gap_response(&self, response: &L2NoteGapResponse) -> GhostResult<()> {
        if response.missing_notes.is_empty() {
            return Ok(());
        }

        info!(
            from = %hex::encode(&response.responding_node[..8]),
            count = response.missing_notes.len(),
            has_more = response.has_more,
            "Applying note gap recovery batch"
        );

        for note in &response.missing_notes {
            // insert_commitment_at uses INSERT OR IGNORE — safe to replay
            let _ = self.epoch_manager.insert_commitment_at(
                note.note_index,
                note.commitment,
                note.block_height,
            );
        }

        // If peer has more missing notes, request the next batch
        if response.has_more {
            // Pagination cursor: continue from after the last note we received
            let next_index = response
                .missing_notes
                .iter()
                .map(|n| n.note_index)
                .max()
                .unwrap_or(0)
                + 1;

            let epoch = self.epoch_manager.current_epoch();
            if let Ok(our_notes) = self.db.load_all_l2_notes_for_epoch(epoch) {
                let our_indices: Vec<u64> = our_notes.iter().map(|(idx, _)| *idx).collect();
                let follow_up = L2NoteGapRequest {
                    requesting_node: self.our_id,
                    our_note_count: our_indices.len() as u64,
                    our_note_indices: our_indices,
                    from_index: next_index,
                    timestamp: chrono::Utc::now().timestamp_millis() as u64,
                };
                if let Some(ref broadcast) = *self.broadcast_fn.read() {
                    let payload = serde_json::to_vec(&follow_up)
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;
                    broadcast(MessageType::L2TreeSync, payload)?;
                    info!(from_index = next_index, "Requesting next note gap batch");
                }
            }
            return Ok(());
        }

        // Final batch — check if roots match
        let our_root = self.epoch_manager.current_root()?;
        if our_root == response.commitment_root {
            info!(
                recovered_notes = response.missing_notes.len(),
                "Note gap recovery complete — roots match"
            );
        } else {
            warn!(
                our_root = %hex::encode(&our_root[..8]),
                peer_root = %hex::encode(&response.commitment_root[..8]),
                "Root still mismatched after note gap recovery"
            );
        }

        Ok(())
    }

    /// Get current epoch manager (for external use)
    pub fn epoch_manager(&self) -> &Arc<EpochManager> {
        &self.epoch_manager
    }

    /// Check if verifier is ready
    pub fn has_verifier(&self) -> bool {
        self.verifier.read().is_some()
    }

    /// Check if checkpoint pipeline is stuck and attempt self-healing.
    ///
    /// Called from the proposal loop. If no finalization has occurred in
    /// STALE_CHECKPOINT_SECS, proactively request tree sync from peers.
    /// This handles the case where votes arrived without proposal data
    /// and the initial tree sync request (from handle_checkpoint_vote)
    /// was rate-limited or lost.
    pub fn check_and_heal_stale_pipeline(&self) -> bool {
        const STALE_CHECKPOINT_SECS: u64 = 120;

        let elapsed = self.last_checkpoint_time.read().elapsed();
        if elapsed.as_secs() > STALE_CHECKPOINT_SECS {
            warn!(
                stale_secs = elapsed.as_secs(),
                "Checkpoint pipeline stale — requesting tree sync for self-healing"
            );
            if let Err(e) = self.request_tree_sync() {
                warn!(error = %e, "Stale pipeline tree sync request failed");
            }
            // Also clear cached proposal so we don't keep re-proposing stale data
            *self.cached_proposal.write() = None;
            true
        } else {
            false
        }
    }
}

// =============================================================================
// MESSAGE HANDLER (mesh integration)
// =============================================================================

#[async_trait]
impl MessageHandler for NullifierRouteHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        // Rate limit all L2 messages
        if matches!(
            envelope.msg_type,
            MessageType::L2ConfidentialTransfer
                | MessageType::L2TransferBroadcast
                | MessageType::L2CheckpointBlock
                | MessageType::L2CheckpointVote
                | MessageType::L2ShieldBroadcast
        ) {
            if let Err(e) = self.check_rate_limit(&envelope.sender) {
                warn!(error = %e, "L2 message rate limited");
                return Err(e);
            }
        }

        match envelope.msg_type {
            MessageType::L2ConfidentialTransfer => {
                let msg: L2ConfidentialTransferMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                match self.handle_transfer(&msg)? {
                    Some(confirmation) => {
                        // Send confirmation back via broadcast
                        if let Some(ref broadcast) = *self.broadcast_fn.read() {
                            let payload = serde_json::to_vec(&confirmation)
                                .map_err(|e| GhostError::Serialization(e.to_string()))?;
                            broadcast(MessageType::L2TransferConfirmation, payload)?;
                        }

                        // Broadcast the confirmed tx to all nodes (signed)
                        // Include pending shields as prerequisites for instant confirmation
                        let prerequisites: Vec<ShieldCommitment> =
                            self.pending_shields.read().clone();
                        let mut broadcast_msg = L2TransferBroadcastMessage {
                            transaction: msg.transaction,
                            validator: self.our_id,
                            signature: [0u8; 64],
                            prerequisites,
                        };
                        let sign_msg = broadcast_msg.signing_message();
                        broadcast_msg.signature = self.sign(&sign_msg);

                        if let Some(ref broadcast) = *self.broadcast_fn.read() {
                            let payload = serde_json::to_vec(&broadcast_msg)
                                .map_err(|e| GhostError::Serialization(e.to_string()))?;
                            broadcast(MessageType::L2TransferBroadcast, payload)?;
                        }
                    }
                    None => {
                        // Not our responsibility or validation failed silently
                    }
                }
            }

            MessageType::L2TransferConfirmation => {
                // Confirmations are sent to the original sender — just log
                debug!("Received L2 transfer confirmation");
            }

            MessageType::L2TransferBroadcast => {
                let msg: L2TransferBroadcastMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                // M-5: Verify broadcast signature — reject if signing not available
                if self.sign_fn.read().is_none() {
                    warn!("M-5: Rejecting L2 broadcast — sign_fn not initialized (cannot verify signatures)");
                    return Ok(());
                }
                let sign_msg = msg.signing_message();
                if !self.verify_peer_signature(&msg.validator, &sign_msg, &msg.signature) {
                    warn!(
                        validator = %hex::encode(&msg.validator[..8]),
                        "Rejecting broadcast with invalid signature"
                    );
                    return Ok(());
                }

                self.handle_transfer_broadcast(&msg)?;
            }

            MessageType::L2CheckpointBlock => {
                let msg: L2CheckpointBlockMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                // M-5: Verify proposer signature — reject if signing not available
                if self.sign_fn.read().is_none() {
                    warn!("M-5: Rejecting L2 checkpoint — sign_fn not initialized (cannot verify signatures)");
                    return Ok(());
                }
                let signable = msg.to_signable_bytes();
                if !self.verify_peer_signature(&msg.proposer, &signable, &msg.proposer_signature) {
                    warn!(
                        proposer = %hex::encode(&msg.proposer[..8]),
                        height = msg.height,
                        "Rejecting checkpoint with invalid proposer signature"
                    );
                    return Ok(());
                }

                // Update last checkpoint time on receiving any valid proposal
                *self.last_checkpoint_time.write() = Instant::now();

                if let Some(vote) = self.handle_checkpoint_proposal(&msg)? {
                    // Record our own vote locally (same as propose_and_broadcast does)
                    self.handle_checkpoint_vote(&vote)?;

                    // Broadcast our vote to peers
                    if let Some(ref broadcast) = *self.broadcast_fn.read() {
                        let payload = serde_json::to_vec(&vote)
                            .map_err(|e| GhostError::Serialization(e.to_string()))?;
                        broadcast(MessageType::L2CheckpointVote, payload)?;
                    }
                }
            }

            MessageType::L2CheckpointVote => {
                let msg: L2CheckpointVoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                // M-5: Verify voter signature — reject if signing not available
                if self.sign_fn.read().is_none() {
                    warn!("M-5: Rejecting L2 vote — sign_fn not initialized (cannot verify signatures)");
                    return Ok(());
                }
                let sign_msg = msg.signing_message();
                if !self.verify_peer_signature(&msg.voter, &sign_msg, &msg.signature) {
                    warn!(
                        voter = %hex::encode(&msg.voter[..8]),
                        height = msg.height,
                        "Rejecting vote with invalid signature"
                    );
                    return Ok(());
                }

                self.handle_checkpoint_vote(&msg)?;
            }

            MessageType::L2TreeSync => {
                // Tree sync request/response + note gap recovery
                if let Ok(request) = serde_json::from_slice::<L2TreeSyncRequest>(&envelope.payload)
                {
                    if let Some(response) = self.handle_tree_sync_request(&request)? {
                        if let Some(ref broadcast) = *self.broadcast_fn.read() {
                            let payload = serde_json::to_vec(&response)
                                .map_err(|e| GhostError::Serialization(e.to_string()))?;
                            broadcast(MessageType::L2TreeSync, payload)?;
                        }
                    }
                } else if let Ok(response) =
                    serde_json::from_slice::<L2TreeSyncResponse>(&envelope.payload)
                {
                    self.handle_tree_sync_response(&response)?;
                } else if let Ok(gap_req) =
                    serde_json::from_slice::<L2NoteGapRequest>(&envelope.payload)
                {
                    if let Ok(Some(gap_resp)) = self.handle_note_gap_request(&gap_req) {
                        if let Some(ref broadcast) = *self.broadcast_fn.read() {
                            let payload = serde_json::to_vec(&gap_resp)
                                .map_err(|e| GhostError::Serialization(e.to_string()))?;
                            broadcast(MessageType::L2TreeSync, payload)?;
                        }
                    }
                } else if let Ok(gap_resp) =
                    serde_json::from_slice::<L2NoteGapResponse>(&envelope.payload)
                {
                    self.handle_note_gap_response(&gap_resp)?;
                } else {
                    debug!("Unrecognized L2TreeSync message format");
                }
            }

            MessageType::L2ShieldBroadcast => {
                let shield: ShieldCommitment = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;

                // Idempotent: insert_commitment_at uses INSERT OR IGNORE
                if let Err(e) = self.apply_shield_commitment(
                    shield.commitment,
                    shield.note_index,
                    shield.block_height,
                ) {
                    debug!(
                        index = shield.note_index,
                        error = %e,
                        "Shield broadcast apply failed (likely duplicate)"
                    );
                }
            }

            _ => {
                // Not an L2 message — ignore
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_manager::EpochManagerConfig;

    fn setup() -> (Arc<Database>, Arc<EpochManager>, NullifierRouteHandler) {
        let db = Arc::new(Database::in_memory().expect("Failed to create in-memory DB"));
        let config = EpochManagerConfig {
            epoch_length: 100,
            transition_window: 10,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
        epoch_mgr.initialize_genesis().unwrap();

        let our_id = [0x01; 32];
        let handler = NullifierRouteHandler::with_defaults(our_id, epoch_mgr.clone(), db.clone());

        (db, epoch_mgr, handler)
    }

    #[test]
    fn test_handler_creation() {
        let (_db, _epoch_mgr, handler) = setup();
        assert_eq!(*handler.our_id(), [0x01; 32]);
        assert_eq!(handler.confirmed_pool_size(), 0);
    }

    #[test]
    fn test_transfer_rejected_without_verifier() {
        let (_db, epoch_mgr, handler) = setup();

        // Set ourselves as the only active node (so we're the validator)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Add a valid root
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        // Should fail because no verifier is set
        let result = handler.handle_transfer(&msg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No verifier available"));
    }

    #[test]
    fn test_transfer_rejected_invalid_root() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: [0xFF; 32], // Invalid root
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid commitment root"));
    }

    #[test]
    fn test_transfer_rejected_wrong_validator() {
        let (_db, epoch_mgr, handler) = setup();

        // Add another node as the only active node (we're NOT the validator)
        epoch_mgr.update_active_nodes(vec![[0x99; 32]]);

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // Not our responsibility
    }

    #[test]
    fn test_checkpoint_proposal_not_proposer() {
        let (_db, epoch_mgr, handler) = setup();

        // Another node is the proposer
        epoch_mgr.update_active_nodes(vec![[0x99; 32]]);

        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_checkpoint_proposal_as_proposer() {
        let (_db, epoch_mgr, handler) = setup();

        // We're the only active node (and thus the proposer)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_some());

        let block = result.unwrap();
        assert_eq!(block.height, 1); // current_height(0) + 1
        assert_eq!(block.proposer, [0x01; 32]);
        assert_eq!(block.transactions.len(), 0); // No confirmed txs
    }

    #[test]
    fn test_checkpoint_vote_quorum() {
        let (_db, epoch_mgr, handler) = setup();

        // 4 active nodes — 67% of 4 = ceil(2.68) = 3 votes needed
        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let node_c = [0x03; 32];
        let node_d = [0x04; 32];
        epoch_mgr.update_active_nodes(vec![node_a, node_b, node_c, node_d]);

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();
        let hash = [0xAA; 32];

        // C-7: Must store a proposal — finalization requires proposal data
        let proposal = L2CheckpointBlockMessage {
            height: 1,
            epoch: 0,
            prev_commitment_root: root,
            new_commitment_root: root,
            transactions: vec![],
            shield_commitments: vec![],
            active_node_count: 4,
            proposer: node_a,
            proposer_signature: [0u8; 64],
            timestamp: 0,
            epoch_transition: None,
        };
        {
            let mut votes = handler.votes.write();
            let state = votes
                .entry(1)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal);
        }

        // First vote (25% — not enough)
        let vote1 = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_a,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote1).unwrap();
        assert!(!finalized);

        // Second vote (50% — still not enough for 67%)
        let vote2 = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_b,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote2).unwrap();
        assert!(!finalized);

        // Third vote (75% — meets 67% threshold)
        let vote3 = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_c,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote3).unwrap();
        assert!(finalized);
    }

    #[test]
    fn test_checkpoint_vote_dedup() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32], [0x02; 32]]);

        let hash = [0xAA; 32];
        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: [0x01; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };

        // First vote
        handler.handle_checkpoint_vote(&vote).unwrap();

        // Duplicate vote — should be ignored (not double-counted)
        handler.handle_checkpoint_vote(&vote).unwrap();

        // Check internal state
        let votes = handler.votes.read();
        let state = votes.get(&1).unwrap();
        assert_eq!(state.approval_count(), 1); // Only counted once
    }

    #[test]
    fn test_transfer_broadcast_dedup() {
        let (_db, epoch_mgr, handler) = setup();

        // S-1: Verifier must be set or broadcasts are rejected
        handler.set_verifier(test_verifier());

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let broadcast = L2TransferBroadcastMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            validator: [0x99; 32],
            signature: [0u8; 64],
            prerequisites: vec![],
        };

        handler.handle_transfer_broadcast(&broadcast).unwrap();
        handler.handle_transfer_broadcast(&broadcast).unwrap(); // Duplicate

        assert_eq!(handler.confirmed_pool_size(), 1); // Only one copy
    }

    #[test]
    fn test_bft_threshold_calculation() {
        // div_ceil(3 * 67, 100) = div_ceil(201, 100) = 3 → all 3 must vote
        let mut state = CheckpointVoteState::new([0; 32]);
        state.add_vote(VerifiedVote::new([1; 32], true));
        state.add_vote(VerifiedVote::new([2; 32], true));
        assert!(!state.has_quorum(3, 67)); // 2/3 = 66.6% < 67%

        state.add_vote(VerifiedVote::new([3; 32], true));
        assert!(state.has_quorum(3, 67)); // 3/3 = 100% >= 67%

        // div_ceil(4 * 67, 100) = div_ceil(268, 100) = 3 → need 3 of 4
        let mut state2 = CheckpointVoteState::new([0; 32]);
        state2.add_vote(VerifiedVote::new([1; 32], true));
        state2.add_vote(VerifiedVote::new([2; 32], true));
        assert!(!state2.has_quorum(4, 67)); // 2/4 = 50% < 67%

        state2.add_vote(VerifiedVote::new([3; 32], true));
        assert!(state2.has_quorum(4, 67)); // 3/4 = 75% >= 67%

        // div_ceil(10 * 67, 100) = div_ceil(670, 100) = 7 → need 7 of 10
        let mut state3 = CheckpointVoteState::new([0; 32]);
        for i in 0..6 {
            state3.add_vote(VerifiedVote::new([i as u8; 32], true));
        }
        assert!(!state3.has_quorum(10, 67)); // 6/10 = 60% < 67%

        state3.add_vote(VerifiedVote::new([6; 32], true));
        assert!(state3.has_quorum(10, 67)); // 7/10 = 70% >= 67%

        // Edge: 0 active nodes
        assert!(!state3.has_quorum(0, 67));
    }

    #[test]
    fn test_rate_limiting() {
        let (_db, _epoch_mgr, handler) = setup();

        let peer = [0x42; 32];

        // Should allow up to MAX_L2_MSG_PER_PEER_PER_SEC messages
        for _ in 0..MAX_L2_MSG_PER_PEER_PER_SEC {
            assert!(handler.check_rate_limit(&peer).is_ok());
        }

        // Next message should be rate limited
        assert!(handler.check_rate_limit(&peer).is_err());

        // Different peer should still work
        let other_peer = [0x43; 32];
        assert!(handler.check_rate_limit(&other_peer).is_ok());
    }

    #[test]
    fn test_proposer_fallback() {
        let (_db, epoch_mgr, handler) = setup();

        let node_a = [0x01; 32]; // us
        let node_b = [0x02; 32];
        epoch_mgr.update_active_nodes(vec![node_a, node_b]);

        // With 2 sorted nodes [node_a, node_b]:
        //   height % 2 == 0 → node_a is proposer
        //   height % 2 == 1 → node_b is proposer
        // Fallback = (height + 1) % 2
        //   height 3: primary = node_b (3%2=1), fallback = node_a ((3+1)%2=0)

        // Advance current_height to 2 so next proposal targets height 3
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 1).unwrap();
        epoch_mgr.on_checkpoint_finalized(1).unwrap();
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 2).unwrap();
        epoch_mgr.on_checkpoint_finalized(2).unwrap();

        // Now current_height = 2, next = 3
        // Height 3: primary = node_b, fallback = node_a (us)
        assert!(!epoch_mgr.is_proposer(&node_a, 3));
        assert_eq!(epoch_mgr.get_fallback_proposer(3), Some(node_a));

        // With recent checkpoint, we should NOT propose
        *handler.last_checkpoint_time.write() = Instant::now();
        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_none());

        // With old checkpoint (proposer timeout), we SHOULD propose as fallback
        *handler.last_checkpoint_time.write() =
            Instant::now() - std::time::Duration::from_secs(PROPOSER_GRACE_SECS + 5);
        let result = handler.propose_checkpoint().unwrap();
        assert!(result.is_some());
    }

    /// Helper to create a verifier for tests (accepts all proofs unconditionally)
    fn test_verifier() -> Arc<ghost_zkp::GhostNoteVerifier> {
        Arc::new(ghost_zkp::GhostNoteVerifier::test_accept_all())
    }

    /// Test full checkpoint cycle: add txs → propose → vote → finalize
    #[test]
    fn test_checkpoint_full_cycle() {
        let (db, epoch_mgr, handler) = setup();

        // We're the only active node (proposer + validator)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Set a sign function
        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            let len = msg.len().min(64);
            sig[..len].copy_from_slice(&msg[..len]);
            sig
        }));

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Inject 3 transactions directly into confirmed pool
        // (bypasses Groth16 verification which requires real MPC params)
        {
            let mut pool = handler.confirmed_pool.write();
            for i in 1u8..=3 {
                let mut change = [0u8; 32];
                change[0] = i * 10;
                let mut recipient = [0u8; 32];
                recipient[0] = i * 20;

                pool.push(L2Transaction {
                    epoch: 0,
                    nullifier: [i; 32],
                    change_commitment: change,
                    recipient_commitment: recipient,
                    commitment_root: root,
                    proof: vec![0u8; 192],
                    encrypted_change: vec![],
                    encrypted_recipient: vec![],
                    timestamp: 0,
                });
            }
        }

        assert_eq!(handler.confirmed_pool_size(), 3);

        // Propose checkpoint
        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        assert_eq!(proposal.height, 1);
        assert_eq!(proposal.transactions.len(), 3);
        assert_eq!(proposal.proposer, [0x01; 32]);

        // Vote on the checkpoint (we're the only node, so 1 vote = quorum)
        let hash = proposal.checkpoint_hash();
        {
            let mut votes = handler.votes.write();
            let state = votes
                .entry(proposal.height)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal.clone());
        }

        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: [0x01; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let finalized = handler.handle_checkpoint_vote(&vote).unwrap();
        assert!(finalized, "Single node vote should finalize checkpoint");

        // Verify: tree root updated, confirmed pool empty
        let new_root = epoch_mgr.current_root().unwrap();
        assert_ne!(new_root, root, "Root should change after checkpoint");
        assert_eq!(
            handler.confirmed_pool_size(),
            0,
            "Confirmed pool should be drained after finalization"
        );
        assert_eq!(epoch_mgr.note_count(), 6); // 3 txs * 2 commitments each

        // Verify DB persisted the checkpoint
        let checkpoints = db.get_l2_checkpoints_from_height(0, 10).unwrap();
        assert!(
            !checkpoints.is_empty(),
            "Checkpoint should be persisted to DB"
        );
    }

    /// Test tree sync request rate limiting
    #[test]
    fn test_tree_sync_request_rate_limiting() {
        let (_db, _epoch_mgr, handler) = setup();

        let peer = [0x42; 32];
        let request = L2TreeSyncRequest {
            requesting_node: peer,
            from_height: 0,
            timestamp: 0,
        };

        // First request should succeed
        let result1 = handler.handle_tree_sync_request(&request).unwrap();
        assert!(result1.is_some(), "First sync request should succeed");

        // Second request within 60s should be rate limited (returns None)
        let result2 = handler.handle_tree_sync_request(&request).unwrap();
        assert!(
            result2.is_none(),
            "Second request within cooldown should be rate limited"
        );

        // Different peer should still work
        let other_request = L2TreeSyncRequest {
            requesting_node: [0x43; 32],
            from_height: 0,
            timestamp: 0,
        };
        let result3 = handler.handle_tree_sync_request(&other_request).unwrap();
        assert!(
            result3.is_some(),
            "Different peer should not be rate limited"
        );
    }

    /// Test that tree sync replays checkpoints so a new peer's root matches the source
    #[test]
    fn test_tree_sync_replays_checkpoints() {
        use ghost_common::identity::NodeIdentity;

        // === Peer A: build a checkpoint with real Ed25519 signatures ===
        let identity_a = NodeIdentity::generate();
        let node_id_a = identity_a.node_id();

        let db_a = Arc::new(Database::in_memory().expect("in-memory db"));
        let config_a = EpochManagerConfig {
            epoch_length: 100,
            transition_window: 10,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let epoch_mgr_a = Arc::new(EpochManager::new(db_a.clone(), config_a));
        epoch_mgr_a.initialize_genesis().unwrap();
        let handler_a =
            NullifierRouteHandler::with_defaults(node_id_a, epoch_mgr_a.clone(), db_a.clone());
        epoch_mgr_a.update_active_nodes(vec![node_id_a]);

        handler_a.set_sign_fn(Arc::new(move |msg: &[u8]| identity_a.sign(msg)));

        let root_a = epoch_mgr_a.current_root().unwrap();
        epoch_mgr_a.add_valid_root(root_a, 0).unwrap();

        // Inject 2 txs into A's confirmed pool
        {
            let mut pool = handler_a.confirmed_pool.write();
            for i in 1u8..=2 {
                let mut change = [0u8; 32];
                change[0] = i * 10;
                let mut recipient = [0u8; 32];
                recipient[0] = i * 20;
                pool.push(L2Transaction {
                    epoch: 0,
                    nullifier: [i; 32],
                    change_commitment: change,
                    recipient_commitment: recipient,
                    commitment_root: root_a,
                    proof: vec![],
                    encrypted_change: vec![],
                    encrypted_recipient: vec![],
                    timestamp: 0,
                });
            }
        }

        // Propose + vote to finalize checkpoint on A
        let proposal = handler_a.propose_checkpoint().unwrap().unwrap();
        let hash = proposal.checkpoint_hash();
        {
            let mut votes = handler_a.votes.write();
            let state = votes
                .entry(proposal.height)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal.clone());
        }
        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_id_a,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        handler_a.handle_checkpoint_vote(&vote).unwrap();

        let root_after_a = epoch_mgr_a.current_root().unwrap();
        assert_ne!(
            root_after_a, root_a,
            "A's root should change after checkpoint"
        );

        // === Peer B: sync from A ===
        let identity_b = NodeIdentity::generate();
        let db_b = Arc::new(Database::in_memory().expect("in-memory db"));
        let config_b = EpochManagerConfig {
            epoch_length: 100,
            transition_window: 10,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let epoch_mgr_b = Arc::new(EpochManager::new(db_b.clone(), config_b));
        epoch_mgr_b.initialize_genesis().unwrap();
        let handler_b = NullifierRouteHandler::with_defaults(
            identity_b.node_id(),
            epoch_mgr_b.clone(),
            db_b.clone(),
        );
        // B needs sign_fn to verify incoming checkpoint signatures
        handler_b.set_sign_fn(Arc::new(move |msg: &[u8]| identity_b.sign(msg)));

        // Build a sync response from A's persisted checkpoint data.
        //
        // The request must carry B's real id: responses are addressed to their requester (#517)
        // and B replays this one below. The fixture previously used a placeholder that matched
        // no node, which only worked because every node processed every response regardless.
        let request = L2TreeSyncRequest {
            requesting_node: handler_b.our_id,
            from_height: 0,
            timestamp: 0,
        };
        let response = handler_a
            .handle_tree_sync_request(&request)
            .unwrap()
            .expect("Should produce sync response");

        assert!(
            !response.checkpoints.is_empty(),
            "Response should contain checkpoints"
        );
        assert_eq!(response.commitment_root, root_after_a);

        // B replays the checkpoints
        handler_b.handle_tree_sync_response(&response).unwrap();

        // Verify B's root matches A's
        let root_b = epoch_mgr_b.current_root().unwrap();
        assert_eq!(
            root_b, root_after_a,
            "Synced peer's root should match source peer"
        );
    }

    /// Regression: tree sync marks heights finalized so primary-supersedes-fallback
    /// cannot reset vote state for already-synced checkpoints. Without this guard,
    /// a late primary proposal wipes votes, and if no new blocks arrive, the
    /// checkpoint is left in limbo causing permanent root divergence.
    #[test]
    fn test_tree_sync_blocks_supersede() {
        use ghost_common::identity::NodeIdentity;

        // === Peer A: build and finalize a checkpoint ===
        let identity_a = NodeIdentity::generate();
        let node_id_a = identity_a.node_id();

        let db_a = Arc::new(Database::in_memory().expect("in-memory db"));
        let config_a = EpochManagerConfig {
            epoch_length: 100,
            transition_window: 10,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let epoch_mgr_a = Arc::new(EpochManager::new(db_a.clone(), config_a));
        epoch_mgr_a.initialize_genesis().unwrap();
        let handler_a =
            NullifierRouteHandler::with_defaults(node_id_a, epoch_mgr_a.clone(), db_a.clone());
        epoch_mgr_a.update_active_nodes(vec![node_id_a]);
        handler_a.set_sign_fn(Arc::new(move |msg: &[u8]| identity_a.sign(msg)));

        let root_a = epoch_mgr_a.current_root().unwrap();
        epoch_mgr_a.add_valid_root(root_a, 0).unwrap();

        // Inject a tx so the checkpoint has content
        {
            let mut pool = handler_a.confirmed_pool.write();
            pool.push(L2Transaction {
                epoch: 0,
                nullifier: [0x01; 32],
                change_commitment: [0x10; 32],
                recipient_commitment: [0x20; 32],
                commitment_root: root_a,
                proof: vec![],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            });
        }

        // Finalize on A
        let proposal = handler_a.propose_checkpoint().unwrap().unwrap();
        let hash = proposal.checkpoint_hash();
        {
            let mut votes = handler_a.votes.write();
            let state = votes
                .entry(proposal.height)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal.clone());
        }
        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: node_id_a,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        handler_a.handle_checkpoint_vote(&vote).unwrap();

        // === Peer B: sync from A, then receive a late primary proposal ===
        let identity_b = NodeIdentity::generate();
        let node_id_b = identity_b.node_id();
        let db_b = Arc::new(Database::in_memory().expect("in-memory db"));
        let config_b = EpochManagerConfig {
            epoch_length: 100,
            transition_window: 10,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let epoch_mgr_b = Arc::new(EpochManager::new(db_b.clone(), config_b));
        epoch_mgr_b.initialize_genesis().unwrap();
        let handler_b =
            NullifierRouteHandler::with_defaults(node_id_b, epoch_mgr_b.clone(), db_b.clone());
        handler_b.set_sign_fn(Arc::new(move |msg: &[u8]| identity_b.sign(msg)));
        // B knows about A so it can verify signatures
        epoch_mgr_b.update_active_nodes(vec![node_id_a, node_id_b]);

        // B syncs from A
        let request = L2TreeSyncRequest {
            requesting_node: node_id_b,
            from_height: 0,
            timestamp: 0,
        };
        let response = handler_a
            .handle_tree_sync_request(&request)
            .unwrap()
            .expect("Should produce sync response");
        handler_b.handle_tree_sync_response(&response).unwrap();

        // Verify B's root matches A
        let root_b = epoch_mgr_b.current_root().unwrap();
        let root_after_a = epoch_mgr_a.current_root().unwrap();
        assert_eq!(root_b, root_after_a, "B should match A after sync");

        // Verify height 1 is marked finalized in B's vote state
        {
            let votes = handler_b.votes.read();
            let state = votes.get(&1).expect("Vote state should exist for height 1");
            assert!(
                state.finalized,
                "Tree sync should mark replayed heights as finalized"
            );
        }

        // Now simulate a late primary proposal arriving at height 1 with a different hash.
        // Before the fix, this would reset vote state and cause divergence.
        let late_proposal = L2CheckpointBlockMessage {
            height: 1,
            epoch: 0,
            prev_commitment_root: root_a,
            new_commitment_root: [0xFF; 32], // Different root
            transactions: vec![],
            shield_commitments: vec![],
            active_node_count: 2,
            proposer: node_id_b, // B is primary for this height
            proposer_signature: [0u8; 64],
            timestamp: 0,
            epoch_transition: None,
        };

        // This should NOT reset the vote state because height 1 is already finalized
        let vote_result = handler_b
            .handle_checkpoint_proposal(&late_proposal)
            .unwrap();

        // Verify vote state is still finalized with the synced hash (not reset)
        {
            let votes = handler_b.votes.read();
            let state = votes.get(&1).unwrap();
            assert!(
                state.finalized,
                "Vote state should remain finalized after late proposal"
            );
        }

        // B's root should still match A's
        let root_b_after = epoch_mgr_b.current_root().unwrap();
        assert_eq!(
            root_b_after, root_after_a,
            "B's root must not change after late supersede attempt"
        );

        // The late proposal should not produce a vote (already finalized returns early)
        // or if it does, the finalized flag should block supersede
        let _ = vote_result; // Result doesn't matter as long as state is preserved
    }

    /// Regression (l2-checkpoint-epoch-fk): a freshly-joined node whose
    /// `l2_epochs` only contains genesis (epoch 0) receives a tree-sync batch
    /// whose checkpoints reference a higher epoch it never replayed the
    /// boundary for. The parent epoch rows now travel in the response, so the
    /// checkpoint persists and the `l2_checkpoints.epoch -> l2_epochs.epoch` FK
    /// is satisfied — no FK-violation error, no infinite re-attempt loop. When
    /// the epoch is absent from the payload (a peer predating the field), the
    /// checkpoint is DEFERRED rather than force-inserted, and the FK trigger is
    /// still enforced against a genuinely orphan checkpoint.
    #[test]
    fn test_tree_sync_materialises_missing_epoch() {
        use ghost_common::identity::NodeIdentity;

        // Proposer identity — signs the checkpoint so the joining node accepts it.
        let proposer = NodeIdentity::generate();
        let proposer_id = proposer.node_id();

        // Checkpoint for epoch 5 at a non-boundary height (epoch_length = 100).
        let mut block = L2CheckpointBlockMessage {
            height: 550,
            epoch: 5,
            prev_commitment_root: [0u8; 32],
            new_commitment_root: [0xAB; 32],
            transactions: vec![],
            shield_commitments: vec![],
            active_node_count: 1,
            proposer: proposer_id,
            proposer_signature: [0u8; 64],
            timestamp: 0,
            epoch_transition: None,
        };
        block.proposer_signature = proposer.sign(&block.to_signable_bytes());

        let epoch5 = L2EpochSync {
            epoch: 5,
            start_height: 500,
            end_height: None,
            initial_root: [0x11; 32],
            final_root: None,
            notes_migrated: 0,
            status: "active".to_string(),
        };

        // Fresh joining node: only genesis epoch 0 present.
        let make_node = || {
            let identity = NodeIdentity::generate();
            let db = Arc::new(Database::in_memory().expect("in-memory db"));
            let config = EpochManagerConfig {
                epoch_length: 100,
                transition_window: 10,
                tree_depth: 4,
                max_valid_roots: 16,
            };
            let epoch_mgr = Arc::new(EpochManager::new(db.clone(), config));
            epoch_mgr.initialize_genesis().unwrap();
            let handler = NullifierRouteHandler::with_defaults(
                identity.node_id(),
                epoch_mgr.clone(),
                db.clone(),
            );
            handler.set_sign_fn(Arc::new(move |msg: &[u8]| identity.sign(msg)));
            (db, handler)
        };

        // --- Case 1: epoch supplied in payload -> checkpoint persists, no error ---
        let (db_ok, handler_ok) = make_node();
        assert!(
            db_ok.get_l2_epoch(5).unwrap().is_none(),
            "epoch 5 should be absent before sync"
        );
        let response = L2TreeSyncResponse {
            responding_node: proposer_id,
            requesting_node: Some(handler_ok.our_id),
            checkpoints: vec![block.clone()],
            current_epoch: 5,
            commitment_root: block.new_commitment_root,
            epochs: vec![epoch5.clone()],
            has_more: false,
            timestamp: 0,
        };
        // Must NOT return a FK-violation error (that is the bug being fixed).
        handler_ok
            .handle_tree_sync_response(&response)
            .expect("sync carrying the parent epoch must succeed");
        assert!(
            db_ok.get_l2_epoch(5).unwrap().is_some(),
            "epoch 5 must be materialised from the payload"
        );
        let cps = db_ok.get_l2_checkpoints_from_height(550, 10).unwrap();
        assert_eq!(cps.len(), 1, "checkpoint must be persisted");
        assert_eq!(cps[0].epoch, 5);

        // Replaying the SAME response again must remain error-free and idempotent
        // (no FK violation, no PK conflict on the epoch upsert) — proves there is
        // no re-attempt error loop across sync rounds.
        handler_ok
            .handle_tree_sync_response(&response)
            .expect("re-replay must stay error-free");
        assert_eq!(
            db_ok.get_l2_checkpoints_from_height(550, 10).unwrap().len(),
            1,
            "re-replay must not duplicate the checkpoint"
        );

        // --- A response addressed to ANOTHER node must be ignored entirely (#517) ---
        //
        // Responses are broadcast, so before the addressee field every node ran this handler on
        // every response in the mesh: with N nodes, N(N-1) runs for (N-1) real answers, each
        // recomputing a Merkle root. On the 8-node fleet that was ~175 responses processed per
        // node per 10 minutes against ~25 actually sent, and the surplus starved the runtime
        // until the HTTP listener stopped being scheduled at all.
        let (db_other, handler_other) = make_node();
        let someone_else = [0xABu8; 32];
        assert_ne!(someone_else, handler_other.our_id);
        let foreign = L2TreeSyncResponse {
            responding_node: proposer_id,
            requesting_node: Some(someone_else),
            checkpoints: vec![block.clone()],
            current_epoch: 5,
            commitment_root: block.new_commitment_root,
            epochs: vec![epoch5.clone()],
            has_more: false,
            timestamp: 0,
        };
        handler_other
            .handle_tree_sync_response(&foreign)
            .expect("ignoring a foreign response is not an error");
        assert!(
            db_other.get_l2_epoch(5).unwrap().is_none(),
            "a response addressed to another node must not be replayed at all"
        );
        assert_eq!(
            db_other
                .get_l2_checkpoints_from_height(550, 10)
                .unwrap()
                .len(),
            0,
            "no checkpoint may be persisted from somebody else's answer"
        );

        // ...and the SAME payload addressed to us IS processed, so the filter is a filter and
        // not a blanket refusal.
        let (db_mine, handler_mine) = make_node();
        let mine = L2TreeSyncResponse {
            requesting_node: Some(handler_mine.our_id),
            ..foreign.clone()
        };
        handler_mine
            .handle_tree_sync_response(&mine)
            .expect("our own answer must still be processed");
        assert!(
            db_mine.get_l2_epoch(5).unwrap().is_some(),
            "a response addressed to us must be replayed"
        );

        // A peer that predates the field sends None. That must still be processed, or upgrading
        // one node would cut it out of sync with every older peer in the fleet.
        let (db_legacy, handler_legacy) = make_node();
        let _ = handler_legacy;
        let legacy = L2TreeSyncResponse {
            requesting_node: None,
            ..foreign.clone()
        };
        handler_legacy
            .handle_tree_sync_response(&legacy)
            .expect("a legacy response must still be processed");
        assert!(
            db_legacy.get_l2_epoch(5).unwrap().is_some(),
            "an unaddressed response from an older peer must not be dropped"
        );

        // --- Case 2: epoch missing from payload -> deferred, not force-inserted ---
        let (db_defer, handler_defer) = make_node();
        let response_no_epoch = L2TreeSyncResponse {
            responding_node: proposer_id,
            requesting_node: Some(handler_defer.our_id),
            checkpoints: vec![block.clone()],
            current_epoch: 5,
            commitment_root: block.new_commitment_root,
            epochs: vec![], // peer predating the `epochs` field
            has_more: false,
            timestamp: 0,
        };
        // No FK-violation error surfaces (returns Ok), so the mesh logs no
        // "Handler error" and the round does not spam — it defers instead.
        handler_defer
            .handle_tree_sync_response(&response_no_epoch)
            .expect("must defer cleanly rather than error");
        assert!(
            db_defer.get_l2_epoch(5).unwrap().is_none(),
            "epoch must not be fabricated when the peer did not supply it"
        );
        assert!(
            db_defer
                .get_l2_checkpoints_from_height(550, 10)
                .unwrap()
                .is_empty(),
            "orphan checkpoint must be deferred, not persisted"
        );

        // --- FK still enforced: a genuinely orphan checkpoint is rejected ---
        let orphan = ghost_storage::L2CheckpointRecord {
            height: 550,
            epoch: 5,
            commitment_root: [0xAB; 32],
            tx_count: 0,
            proposer_id: hex::encode(proposer_id),
            active_node_count: 1,
            block_data: vec![],
        };
        assert!(
            db_defer.upsert_l2_checkpoint(&orphan).is_err(),
            "FK trigger must still reject a checkpoint with no parent epoch"
        );
    }

    /// Test that a transfer with an invalid (wrong) commitment root is rejected
    #[test]
    fn test_transfer_with_wrong_root_rejected() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);
        handler.set_verifier(test_verifier());

        // Add a valid root
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Submit transfer with a WRONG commitment root
        let wrong_root = [0xFF; 32];
        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: wrong_root, // Not in valid roots
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid commitment root"),
            "Should reject wrong root"
        );
    }

    /// Test that a transfer with a corrupted proof is rejected when verifier has real VK
    /// This test requires Groth16 setup (~10-30s), so it's marked #[ignore]
    #[test]
    #[ignore]
    fn test_groth16_invalid_proof_rejected() {
        let (_db, epoch_mgr, handler) = setup();
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Create a real verifier with Groth16 VK
        let prover = ghost_zkp::note_prover::GhostNoteProver::new_with_setup(4)
            .expect("Groth16 setup should succeed");
        let verifier = Arc::new(ghost_zkp::GhostNoteVerifier::for_prover(&prover));
        handler.set_verifier(verifier);

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Submit with a corrupted proof (valid size but garbage bytes)
        let msg = L2ConfidentialTransferMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0xFF; 192], // Garbage proof
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            sender: [0x99; 32],
        };

        let result = handler.handle_transfer(&msg);
        assert!(result.is_err(), "Corrupted proof should be rejected");
    }

    #[test]
    fn test_signing_with_sign_fn() {
        let (_db, epoch_mgr, handler) = setup();

        // Set a dummy sign function
        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            // Use first 32 bytes of message as part of signature for testing
            let copy_len = msg.len().min(32);
            sig[..copy_len].copy_from_slice(&msg[..copy_len]);
            sig
        }));

        // We're the only active node (proposer)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        // Signature should NOT be all zeros (sign_fn was called)
        assert_ne!(proposal.proposer_signature, [0u8; 64]);
    }

    #[test]
    fn test_rate_limiting_per_peer() {
        let (_db, _epoch_mgr, handler) = setup();

        let peer = [0x42; 32];

        // Should allow exactly MAX_L2_MSG_PER_PEER_PER_SEC messages
        for i in 0..MAX_L2_MSG_PER_PEER_PER_SEC {
            assert!(
                handler.check_rate_limit(&peer).is_ok(),
                "Message {} should be accepted (within limit)",
                i
            );
        }

        // The 101st message (index 100) should be rate limited
        let result = handler.check_rate_limit(&peer);
        assert!(
            result.is_err(),
            "Message beyond per-peer limit should be rejected"
        );
        assert!(
            result.unwrap_err().to_string().contains("rate limit"),
            "Error should mention rate limit"
        );

        // A different peer should still be allowed (per-peer, not global at this count)
        let other_peer = [0x43; 32];
        assert!(
            handler.check_rate_limit(&other_peer).is_ok(),
            "Different peer should not be affected by first peer's rate limit"
        );
    }

    #[test]
    fn test_propose_uses_scratch_tree_no_mutation() {
        let (_db, epoch_mgr, handler) = setup();

        // We're the only active node (proposer)
        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        // Add a transaction to the confirmed pool so the checkpoint has content
        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let mut change_commit = [0u8; 32];
        change_commit[0] = 0x10;
        let mut recipient_commit = [0u8; 32];
        recipient_commit[0] = 0x20;

        {
            let mut pool = handler.confirmed_pool.write();
            pool.push(L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: change_commit,
                recipient_commitment: recipient_commit,
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            });
        }

        let note_count_before = epoch_mgr.note_count();
        assert_eq!(note_count_before, 0);

        // Propose checkpoint — scratch tree computes root, real tree is NOT mutated
        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        let note_count_after_propose = epoch_mgr.note_count();
        assert_eq!(
            note_count_after_propose, 0,
            "Scratch tree: propose_checkpoint must NOT mutate the real tree"
        );

        // The proposal should have a non-zero new_commitment_root (computed on scratch tree)
        assert_ne!(
            proposal.new_commitment_root, [0u8; 32],
            "Scratch tree should compute a valid root"
        );

        // Now finalize — ALL nodes (including proposer) apply commitments here
        {
            let mut votes = handler.votes.write();
            let state = votes
                .entry(proposal.height)
                .or_insert_with(|| CheckpointVoteState::new(proposal.checkpoint_hash()));
            state.proposal = Some(proposal.clone());
        }

        handler
            .finalize_checkpoint(proposal.height, Some(&proposal))
            .unwrap();

        // Tree should have exactly 2 notes after finalization
        let note_count_after_finalize = epoch_mgr.note_count();
        assert_eq!(
            note_count_after_finalize, 2,
            "Finalize must apply commitments to the real tree"
        );
    }

    /// S-1: Broadcast without verifier is rejected (fail-closed)
    #[test]
    fn test_broadcast_rejected_without_verifier() {
        let (_db, epoch_mgr, handler) = setup();

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Verifier is NOT set — should reject
        assert!(!handler.has_verifier());

        let broadcast = L2TransferBroadcastMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            validator: [0x99; 32],
            signature: [0u8; 64],
            prerequisites: vec![],
        };

        handler.handle_transfer_broadcast(&broadcast).unwrap();
        // S-1: confirmed_pool should remain empty since verifier is not loaded
        assert_eq!(
            handler.confirmed_pool_size(),
            0,
            "S-1: Broadcast without verifier should be rejected"
        );
    }

    /// S-1: Broadcast WITH verifier set is accepted
    #[test]
    fn test_broadcast_accepted_with_verifier() {
        let (_db, epoch_mgr, handler) = setup();

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Set a test verifier that accepts all proofs
        handler.set_verifier(test_verifier());

        let broadcast = L2TransferBroadcastMessage {
            transaction: L2Transaction {
                epoch: 0,
                nullifier: [0x42; 32],
                change_commitment: [0u8; 32],
                recipient_commitment: [0u8; 32],
                commitment_root: root,
                proof: vec![0u8; 192],
                encrypted_change: vec![],
                encrypted_recipient: vec![],
                timestamp: 0,
            },
            validator: [0x99; 32],
            signature: [0u8; 64],
            prerequisites: vec![],
        };

        handler.handle_transfer_broadcast(&broadcast).unwrap();
        assert_eq!(
            handler.confirmed_pool_size(),
            1,
            "S-1: Broadcast with verifier should be accepted"
        );
    }

    /// S-5: vote states are pruned (proposed_heights removed — scratch tree design)
    #[test]
    fn test_vote_states_pruned() {
        let (_db, _epoch_mgr, handler) = setup();

        // Add 200 vote states
        {
            let mut votes = handler.votes.write();
            for h in 1..=200u64 {
                votes.insert(h, CheckpointVoteState::new([0; 32]));
            }
        }
        assert_eq!(handler.votes.read().len(), 200);

        // Prune at current_height=200, cutoff=100
        handler.prune_vote_states(200);

        // Only heights > 100 should remain
        let votes = handler.votes.read();
        assert_eq!(
            votes.len(),
            100,
            "S-5: Should have pruned vote states <= 100"
        );
        assert!(
            !votes.contains_key(&100),
            "S-5: Height 100 should be pruned"
        );
        assert!(votes.contains_key(&101), "S-5: Height 101 should remain");
        assert!(votes.contains_key(&200), "S-5: Height 200 should remain");
    }

    /// S-6: VerifiedVote newtype ensures type-safe vote construction
    #[test]
    fn test_verified_vote_newtype() {
        let mut state = CheckpointVoteState::new([0; 32]);

        // Create verified votes (simulating post-signature-verification)
        let vote1 = VerifiedVote::new([1; 32], true);
        let vote2 = VerifiedVote::new([2; 32], false);

        assert!(state.add_vote(vote1)); // New vote → true
        assert!(state.add_vote(vote2)); // New vote → true

        // Duplicate voter
        let vote_dup = VerifiedVote::new([1; 32], true);
        assert!(!state.add_vote(vote_dup)); // Duplicate → false

        assert_eq!(state.approval_count(), 1); // Only [1;32] approved
    }

    /// Test: primary proposal supersedes fallback when fallback arrived first.
    ///
    /// Simulates the race condition where VM2 (fallback) proposes an empty checkpoint,
    /// then VM1 (primary) proposes with shield commitments. The primary must win and
    /// shields must be applied on the validator.
    #[test]
    fn test_primary_supersedes_fallback_with_shields() {
        let (_db, epoch_mgr, handler) = setup();

        let node_a = [0x01; 32]; // us (validator)
        let node_b = [0x02; 32]; // primary proposer
        let node_c = [0x03; 32]; // fallback proposer
        epoch_mgr.update_active_nodes(vec![node_a, node_b, node_c]);

        // Set sign function
        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            let len = msg.len().min(64);
            sig[..len].copy_from_slice(&msg[..len]);
            sig
        }));

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Height 1: primary = node_b (1 % 3 = 1), fallback = node_c ((1+1) % 3 = 2)
        assert_eq!(epoch_mgr.get_proposer(1), Some(node_b));
        assert_eq!(epoch_mgr.get_fallback_proposer(1), Some(node_c));

        // Fallback proposal (empty, no shields)
        let fallback_proposal = L2CheckpointBlockMessage {
            height: 1,
            epoch: 0,
            prev_commitment_root: root,
            new_commitment_root: root, // No changes
            transactions: vec![],
            shield_commitments: vec![],
            active_node_count: 3,
            proposer: node_c,
            proposer_signature: [0u8; 64],
            timestamp: 0,
            epoch_transition: None,
        };
        let fallback_hash = fallback_proposal.checkpoint_hash();

        // Primary proposal (with a shield commitment)
        let shield = ShieldCommitment {
            commitment: [0xAA; 32],
            note_index: 100,
            block_height: 12345,
        };
        let primary_proposal = L2CheckpointBlockMessage {
            height: 1,
            epoch: 0,
            prev_commitment_root: root,
            new_commitment_root: [0xBB; 32], // Different root due to shield
            transactions: vec![],
            shield_commitments: vec![shield.clone()],
            active_node_count: 3,
            proposer: node_b,
            proposer_signature: [0u8; 64],
            timestamp: 0,
            epoch_transition: None,
        };
        let primary_hash = primary_proposal.checkpoint_hash();

        // Hashes must be different (primary has shields, fallback doesn't)
        assert_ne!(fallback_hash, primary_hash);

        // Step 1: Fallback proposal arrives first
        let vote1 = handler
            .handle_checkpoint_proposal(&fallback_proposal)
            .unwrap();
        // We should get a vote (approve, since roots match)
        assert!(vote1.is_some());
        let vote1 = vote1.unwrap();
        assert_eq!(vote1.checkpoint_hash, fallback_hash);

        // Verify vote state has fallback hash
        {
            let votes = handler.votes.read();
            let state = votes.get(&1).unwrap();
            assert_eq!(state.checkpoint_hash, fallback_hash);
        }

        // Step 2: Primary proposal arrives (should supersede fallback)
        let vote2 = handler
            .handle_checkpoint_proposal(&primary_proposal)
            .unwrap();
        // We should get a vote for the PRIMARY hash
        assert!(vote2.is_some());
        let vote2 = vote2.unwrap();
        assert_eq!(
            vote2.checkpoint_hash, primary_hash,
            "Vote should be for primary proposal, not fallback"
        );

        // Verify vote state now has primary hash
        {
            let votes = handler.votes.read();
            let state = votes.get(&1).unwrap();
            assert_eq!(
                state.checkpoint_hash, primary_hash,
                "Vote state should have been reset to primary hash"
            );
            assert!(
                state.proposal.is_some(),
                "Primary proposal should be stored"
            );
            assert_eq!(
                state.proposal.as_ref().unwrap().shield_commitments.len(),
                1,
                "Primary proposal's shields should be preserved"
            );
        }

        // Step 3: Votes for fallback hash should be rejected
        let stale_vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: fallback_hash,
            voter: node_c,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        let result = handler.handle_checkpoint_vote(&stale_vote).unwrap();
        assert!(!result, "Stale fallback vote should not finalize");
    }

    /// Test: fallback proposal does NOT overwrite primary when primary hash is stored.
    ///
    /// If a vote for the primary hash arrives first (setting the hash), then a fallback
    /// proposal arrives with a different hash, the fallback must NOT overwrite the stored
    /// proposal or change the hash.
    #[test]
    fn test_fallback_does_not_overwrite_primary_vote() {
        let (_db, epoch_mgr, handler) = setup();

        let node_a = [0x01; 32]; // us
        let node_b = [0x02; 32]; // primary proposer
        let node_c = [0x03; 32]; // fallback proposer
        epoch_mgr.update_active_nodes(vec![node_a, node_b, node_c]);

        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            let len = msg.len().min(64);
            sig[..len].copy_from_slice(&msg[..len]);
            sig
        }));

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        let primary_hash = [0xAA; 32];
        let _fallback_hash = [0xBB; 32];

        // Step 1: Vote for primary hash arrives first (from relay)
        let primary_vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: primary_hash,
            voter: node_b,
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        handler.handle_checkpoint_vote(&primary_vote).unwrap();

        // Step 2: Fallback proposal arrives with different hash
        let fallback_proposal = L2CheckpointBlockMessage {
            height: 1,
            epoch: 0,
            prev_commitment_root: root,
            new_commitment_root: root,
            transactions: vec![],
            shield_commitments: vec![],
            active_node_count: 3,
            proposer: node_c,
            proposer_signature: [0u8; 64],
            timestamp: 0,
            epoch_transition: None,
        };

        // Fallback is NOT the primary, so it should NOT supersede
        let vote_result = handler
            .handle_checkpoint_proposal(&fallback_proposal)
            .unwrap();
        assert!(
            vote_result.is_none(),
            "Fallback proposal with different hash should return no vote"
        );

        // Vote state should still have primary hash
        {
            let votes = handler.votes.read();
            let state = votes.get(&1).unwrap();
            assert_eq!(
                state.checkpoint_hash, primary_hash,
                "Primary hash should NOT be overwritten by fallback"
            );
            assert!(
                state.proposal.is_none(),
                "Fallback proposal should NOT have been stored"
            );
        }
    }

    /// Test: pending_shields are retained until finalization (not drained on propose).
    #[test]
    fn test_pending_shields_retained_until_finalize() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            let len = msg.len().min(64);
            sig[..len].copy_from_slice(&msg[..len]);
            sig
        }));

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Add a pending shield
        handler.sync_commitment([0xCC; 32], 100, 12345).unwrap();
        assert_eq!(handler.pending_shields.read().len(), 1);

        // Propose checkpoint (should include the shield)
        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        assert_eq!(proposal.shield_commitments.len(), 1);

        // Pending shields should NOT be drained (they're cloned, not drained)
        assert_eq!(
            handler.pending_shields.read().len(),
            1,
            "Pending shields should be retained until finalization"
        );

        // Finalize the checkpoint
        let hash = proposal.checkpoint_hash();
        {
            let mut votes = handler.votes.write();
            let state = votes
                .entry(1)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal.clone());
        }

        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: [0x01; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        handler.handle_checkpoint_vote(&vote).unwrap();

        // NOW pending shields should be drained
        assert_eq!(
            handler.pending_shields.read().len(),
            0,
            "Pending shields should be drained after finalization"
        );
    }

    /// Test: confirmed_pool transactions are retained until finalization.
    #[test]
    fn test_confirmed_pool_retained_until_finalize() {
        let (_db, epoch_mgr, handler) = setup();

        epoch_mgr.update_active_nodes(vec![[0x01; 32]]);

        handler.set_sign_fn(Arc::new(|msg: &[u8]| {
            let mut sig = [0u8; 64];
            let len = msg.len().min(64);
            sig[..len].copy_from_slice(&msg[..len]);
            sig
        }));

        let root = epoch_mgr.current_root().unwrap();
        epoch_mgr.add_valid_root(root, 0).unwrap();

        // Add transactions to the confirmed pool
        {
            let mut pool = handler.confirmed_pool.write();
            for i in 1u8..=2 {
                pool.push(L2Transaction {
                    epoch: 0,
                    nullifier: [i; 32],
                    change_commitment: [i * 10; 32],
                    recipient_commitment: [i * 20; 32],
                    commitment_root: root,
                    proof: vec![0u8; 192],
                    encrypted_change: vec![],
                    encrypted_recipient: vec![],
                    timestamp: 0,
                });
            }
            handler.confirmed_nullifiers.write().insert([1; 32]);
            handler.confirmed_nullifiers.write().insert([2; 32]);
        }
        assert_eq!(handler.confirmed_pool_size(), 2);

        // Propose checkpoint (should include both transactions)
        let proposal = handler.propose_checkpoint().unwrap().unwrap();
        assert_eq!(proposal.transactions.len(), 2);

        // Confirmed pool should NOT be drained (transactions cloned, not drained)
        assert_eq!(
            handler.confirmed_pool_size(),
            2,
            "Confirmed pool should be retained until finalization"
        );

        // Finalize the checkpoint
        let hash = proposal.checkpoint_hash();
        {
            let mut votes = handler.votes.write();
            let state = votes
                .entry(1)
                .or_insert_with(|| CheckpointVoteState::new(hash));
            state.proposal = Some(proposal.clone());
        }

        let vote = L2CheckpointVoteMessage {
            height: 1,
            checkpoint_hash: hash,
            voter: [0x01; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 0,
        };
        handler.handle_checkpoint_vote(&vote).unwrap();

        // NOW confirmed pool should be drained
        assert_eq!(
            handler.confirmed_pool_size(),
            0,
            "Confirmed pool should be drained after finalization"
        );

        // Nullifiers dedup set should also be cleared for finalized transactions
        assert!(
            handler.confirmed_nullifiers.read().is_empty(),
            "Confirmed nullifiers should be cleared after finalization"
        );
    }

    /// Test: C-7 — quorum without proposal does NOT finalize.
    #[test]
    fn test_quorum_without_proposal_skips_finalization() {
        let (_db, epoch_mgr, handler) = setup();

        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let node_c = [0x03; 32];
        epoch_mgr.update_active_nodes(vec![node_a, node_b, node_c]);

        let hash = [0xAA; 32];

        // Submit 3 votes (quorum for 3 nodes at 67%) WITHOUT storing a proposal
        for voter in &[node_a, node_b, node_c] {
            let vote = L2CheckpointVoteMessage {
                height: 1,
                checkpoint_hash: hash,
                voter: *voter,
                approve: true,
                signature: [0u8; 64],
                timestamp: 0,
            };
            let result = handler.handle_checkpoint_vote(&vote).unwrap();
            // Should NOT finalize because no proposal is stored
            assert!(!result, "Should not finalize without proposal data");
        }

        // Vote state should have been un-finalized
        {
            let votes = handler.votes.read();
            let state = votes.get(&1).unwrap();
            assert!(
                !state.finalized,
                "State should be un-finalized when proposal is missing"
            );
        }
    }
}
