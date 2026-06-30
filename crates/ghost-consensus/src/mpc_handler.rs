//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: mpc_handler.rs                                                                                                 |
//|======================================================================================================================|

//! MPC Ceremony Handler - MPC-C1/C2/C3/C4
//!
//! Handles the MPC ceremony protocol for ZK parameter generation:
//!
//! - **MPC-C1**: MpcContribution - new elder's contribution to ceremony
//! - **MPC-C2**: MpcVerificationVote - elder votes on contributions
//! - **MPC-C3**: MpcParametersRequest - request params from peers
//! - **MPC-C4**: MpcParametersResponse - chunked parameter transfer
//!
//! ## Ceremony Flow
//!
//! 1. New elder generates MPC contribution after registration approval
//! 2. Contribution is broadcast to network
//! 3. Current elders verify and vote on contribution
//! 4. Bootstrap (positions 1-3): genesis node approves alone
//!    Normal (position 4+): 67% supermajority of elders must approve
//! 5. At elder 101, ceremony ossifies permanently
//!
//! ## Security Properties
//!
//! - 1-of-N security: Only ONE honest contributor needed
//! - BFT threshold (67%) prevents invalid contributions
//! - Cryptographic proof verifies valid transformation
//! - Toxic waste is zeroized immediately after contribution

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;
use ghost_storage::queries::{MpcContributionRecord, MpcVerificationVote as DbMpcVote};
use ghost_storage::Database;

use crate::mesh::MessageHandler;
use crate::message::{
    MessageEnvelope, MessageType, MpcContributionMessage, MpcParametersRequestMessage,
    MpcParametersResponseMessage, MpcVerificationVoteMessage,
};

/// BFT threshold + bootstrap count for MPC contribution approval.
///
/// SINGLE SOURCE OF TRUTH: these come from `ghost_common::constants` (and are
/// re-exported by `ghost-mpc`) so the quorum computed here matches every other
/// node and every other MPC code path exactly. A divergence would split
/// consensus — one node applying a contribution that another rejects.
use ghost_common::constants::{MPC_BFT_BOOTSTRAP_COUNT, MPC_BFT_THRESHOLD_PERCENT};

/// Compute BFT threshold for MPC contribution approval.
///
/// During bootstrap (fewer than `MPC_BFT_BOOTSTRAP_COUNT` contributors) the
/// genesis node can approve alone (threshold = 1).  Once the contributor count
/// reaches `MPC_BFT_BOOTSTRAP_COUNT` (4), the threshold becomes a
/// `MPC_BFT_THRESHOLD_PERCENT` (67%) supermajority:
/// `ceil(contributor_count * 67 / 100)`.
pub(crate) fn bft_threshold(contributor_count: u32) -> u32 {
    if contributor_count < MPC_BFT_BOOTSTRAP_COUNT {
        1
    } else {
        (contributor_count * MPC_BFT_THRESHOLD_PERCENT).div_ceil(100)
    }
}

/// Rate limiting for MPC messages
const RATE_LIMIT_MAX_TOKENS: u32 = 10;
const RATE_LIMIT_REFILL_RATE: u32 = 2; // 2 per second

/// Callback for broadcasting MPC messages to the network
pub type MpcBroadcastFn = Arc<dyn Fn(MessageType, Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback invoked when parameters are updated.
/// Arguments: (new_params_hash, contributor_node_id)
pub type ParamsUpdateCallback = Arc<dyn Fn(&[u8; 32], &[u8; 32]) + Send + Sync>;

/// S-4: One token in millis (1000 millis = 1 token)
const MPC_MILLIS_PER_TOKEN: u64 = 1000;

/// S-4: Token bucket for rate limiting using integer millis (matches H-14 pattern from vote_handler.rs)
#[derive(Clone)]
struct TokenBucket {
    /// Tokens × 1000 for sub-token precision without floating point
    tokens_millis: u64,
    last_update: Instant,
}

/// Rate limiter for MPC messages
struct RateLimiter {
    buckets: RwLock<HashMap<NodeId, TokenBucket>>,
    max_tokens: u32,
    refill_rate: u32,
}

impl RateLimiter {
    fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens,
            refill_rate,
        }
    }

    fn check_and_consume(&self, node_id: &NodeId) -> bool {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        let max_millis = (self.max_tokens as u64).saturating_mul(MPC_MILLIS_PER_TOKEN);

        let bucket = buckets.entry(*node_id).or_insert_with(|| TokenBucket {
            tokens_millis: max_millis,
            last_update: now,
        });

        // S-4: Refill tokens using integer millisecond arithmetic (no f64)
        let elapsed_ms = now
            .duration_since(bucket.last_update)
            .as_millis()
            .min(3_600_000) as u64;
        // refill_millis = elapsed_ms * refill_rate (tokens/sec) * 1000 (millis/token) / 1000 (ms→sec)
        // Simplifies to: elapsed_ms * refill_rate
        let refill_millis = elapsed_ms.saturating_mul(self.refill_rate as u64);
        bucket.tokens_millis = bucket
            .tokens_millis
            .saturating_add(refill_millis)
            .min(max_millis);
        bucket.last_update = now;

        if bucket.tokens_millis >= MPC_MILLIS_PER_TOKEN {
            bucket.tokens_millis -= MPC_MILLIS_PER_TOKEN;
            true
        } else {
            false
        }
    }
}

/// Maximum age for pending contributions before cleanup (30 minutes)
const PENDING_CONTRIBUTION_TIMEOUT_SECS: u64 = 30 * 60;

/// Pending contribution awaiting verification
#[derive(Clone)]
struct PendingContribution {
    message: MpcContributionMessage,
    received_at: Instant,
    approval_count: u32,
    rejection_count: u32,
    /// Track which voters have already voted (prevents duplicate vote inflation)
    voters: std::collections::HashSet<NodeId>,
}

/// MPC ceremony handler
///
/// Manages the MPC ceremony protocol, including:
/// - Receiving and validating contributions
/// - Collecting and counting verification votes
/// - Triggering contribution application on BFT approval
/// - Handling parameter sync requests
pub struct MpcHandler {
    /// Our node's identity
    identity: Arc<NodeIdentity>,
    /// Database for storing contributions and votes
    db: Arc<Database>,
    /// Broadcast function for sending messages
    broadcaster: Option<MpcBroadcastFn>,
    /// Callback when parameters are updated
    params_callback: Option<ParamsUpdateCallback>,
    /// Rate limiter
    rate_limiter: RateLimiter,
    /// Pending contributions awaiting BFT approval
    pending_contributions: RwLock<HashMap<[u8; 32], PendingContribution>>,
    /// Whether the ceremony has ossified
    is_ossified: RwLock<bool>,
    /// Current contribution count
    contribution_count: RwLock<u32>,
}

impl MpcHandler {
    /// Create a new MPC handler
    pub fn new(identity: Arc<NodeIdentity>, db: Arc<Database>) -> Self {
        Self {
            identity,
            db,
            broadcaster: None,
            params_callback: None,
            rate_limiter: RateLimiter::new(RATE_LIMIT_MAX_TOKENS, RATE_LIMIT_REFILL_RATE),
            pending_contributions: RwLock::new(HashMap::new()),
            is_ossified: RwLock::new(false),
            contribution_count: RwLock::new(0),
        }
    }

    /// Set the message broadcaster
    pub fn with_broadcaster(mut self, broadcaster: MpcBroadcastFn) -> Self {
        self.broadcaster = Some(broadcaster);
        self
    }

    /// Set the parameters update callback
    pub fn with_params_callback(mut self, callback: ParamsUpdateCallback) -> Self {
        self.params_callback = Some(callback);
        self
    }

    /// Initialize with ceremony state
    pub fn with_state(self, contribution_count: u32, is_ossified: bool) -> Self {
        *self.contribution_count.write() = contribution_count;
        *self.is_ossified.write() = is_ossified;
        self
    }

    /// Check if ceremony is ossified
    pub fn is_ossified(&self) -> bool {
        *self.is_ossified.read()
    }

    /// Get current contribution count from database
    ///
    /// This queries the database directly to ensure we have the latest count,
    /// since contributions can be applied outside this handler (e.g., during startup).
    ///
    /// Progression count = the `mpc_ceremony` singleton (authoritative), falling
    /// back to `COUNT(mpc_contributions)` when the singleton is absent. The
    /// helper also logs loudly if the two disagree. This is intentionally
    /// DISTINCT from `mpc_contributor_count()` (raw COUNT), which sizes the
    /// BFT voter set for `bft_threshold`.
    pub fn contribution_count(&self) -> u32 {
        self.db
            .mpc_contribution_count_authoritative()
            .unwrap_or_else(|_| self.mpc_contributor_count())
    }

    /// Handle an incoming MPC contribution
    fn handle_contribution(&self, msg: MpcContributionMessage, sender: NodeId) -> GhostResult<()> {
        debug!(
            position = msg.elder_position,
            sender = %hex::encode(&sender[..8]),
            candidate = %hex::encode(&msg.candidate[..8]),
            "handle_contribution() entry"
        );

        // Rate limit
        if !self.rate_limiter.check_and_consume(&sender) {
            debug!(sender = %hex::encode(&sender[..8]), "MPC contribution rate limited");
            return Ok(());
        }

        // Check if ossified
        if self.is_ossified() {
            debug!("MPC ceremony ossified, ignoring contribution");
            return Ok(());
        }

        // Verify signature
        if !msg.verify_signature() {
            warn!(
                candidate = %hex::encode(&msg.candidate[..8]),
                "Invalid MPC contribution signature"
            );
            return Ok(());
        }

        // Verify position is next expected
        let expected_position = self.contribution_count() + 1;
        if msg.elder_position != expected_position {
            warn!(
                position = msg.elder_position,
                expected = expected_position,
                "MPC contribution position mismatch"
            );
            return Ok(());
        }

        // Reject contributions for burned (revoked) positions
        if let Ok(true) = self.db.is_position_burned(msg.elder_position) {
            warn!(
                position = msg.elder_position,
                "Rejecting MPC contribution for burned elder position"
            );
            return Ok(());
        }

        // Store as pending
        let contribution_hash = msg.contribution_hash();
        {
            let mut pending = self.pending_contributions.write();
            if pending.contains_key(&contribution_hash) {
                debug!("Duplicate MPC contribution, ignoring");
                return Ok(());
            }
            // Clean up stale pending contributions before inserting
            pending.retain(|_, c| {
                c.received_at.elapsed().as_secs() < PENDING_CONTRIBUTION_TIMEOUT_SECS
            });

            pending.insert(
                contribution_hash,
                PendingContribution {
                    message: msg.clone(),
                    received_at: Instant::now(),
                    approval_count: 0,
                    rejection_count: 0,
                    voters: std::collections::HashSet::new(),
                },
            );
        }

        info!(
            position = msg.elder_position,
            candidate = %hex::encode(&msg.candidate[..8]),
            "Received MPC contribution"
        );

        // Check for genesis case: first contribution is auto-approved
        let contributor_count = self.mpc_contributor_count();

        // Genesis protection layer 3: Ceremony ID matching
        // If we already have contributors, reject incoming genesis (position 1) contributions.
        // This catches conflicting genesis from a node that mistakenly ran --genesis on an
        // existing network — their position-1 contribution targets different genesis params.
        if msg.elder_position == 1 && contributor_count > 0 {
            warn!(
                sender = %hex::encode(&msg.candidate[..8]),
                our_count = contributor_count,
                "Rejecting conflicting genesis contribution — network already has MPC contributors"
            );
            return Ok(());
        }

        if contributor_count == 0 && msg.elder_position == 1 {
            info!(
                "MPC genesis: Auto-approving first contribution (no existing contributors to vote)"
            );
            self.apply_contribution(&contribution_hash)?;
            return Ok(());
        }

        // If we're an MPC contributor, verify and vote on new contributions
        if self.is_mpc_contributor() {
            self.verify_and_vote(&msg)?;
        }

        Ok(())
    }

    /// Check if we are an MPC contributor (elder)
    ///
    /// Elder status is determined by MPC contribution, not the old canonical elder list.
    /// If you contributed to the MPC ceremony, you're an elder.
    fn is_mpc_contributor(&self) -> bool {
        let node_id_hex = hex::encode(self.identity.node_id());
        self.db.is_mpc_elder(&node_id_hex).unwrap_or(false)
    }

    /// Check if a node is an MPC contributor
    fn is_node_mpc_contributor(&self, node_id: &NodeId) -> bool {
        let node_id_hex = hex::encode(node_id);
        self.db.is_mpc_elder(&node_id_hex).unwrap_or(false)
    }

    /// Get the current MPC contributor count
    fn mpc_contributor_count(&self) -> u32 {
        self.db.get_mpc_elder_count().unwrap_or(0)
    }

    /// Verify a contribution and cast our vote
    fn verify_and_vote(&self, msg: &MpcContributionMessage) -> GhostResult<()> {
        // Structural validation: proof exists, hashes are non-zero and different
        let structurally_valid = !msg.contribution_proof.is_empty()
            && msg.prev_params_hash != [0u8; 32]
            && msg.new_params_hash != [0u8; 32]
            && msg.prev_params_hash != msg.new_params_hash;

        // Hash chain validation: verify prev_params_hash matches the latest contribution
        // This prevents contributions that don't chain from the current ceremony state
        let chain_valid = if msg.elder_position == 1 {
            // Genesis contribution has no predecessor to validate against
            true
        } else {
            // Check that prev_params_hash matches new_params_hash of the previous contribution
            match self.db.get_mpc_contribution(msg.elder_position - 1) {
                Ok(Some(prev)) => {
                    if prev.new_params_hash != msg.prev_params_hash {
                        warn!(
                            position = msg.elder_position,
                            expected = %hex::encode(&prev.new_params_hash[..8]),
                            got = %hex::encode(&msg.prev_params_hash[..8]),
                            "MPC contribution prev_params_hash does not chain from previous contribution"
                        );
                        false
                    } else {
                        true
                    }
                }
                Ok(None) => {
                    warn!(
                        position = msg.elder_position,
                        prev_position = msg.elder_position - 1,
                        "Cannot verify hash chain: previous contribution not found"
                    );
                    false
                }
                Err(e) => {
                    warn!(error = %e, "Failed to look up previous MPC contribution for chain verification");
                    false
                }
            }
        };

        let valid = structurally_valid && chain_valid;

        // Sign and broadcast vote
        let signing_msg = {
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(b"MpcVerificationVote/v1");
            hasher.update(msg.contribution_hash());
            hasher.update([valid as u8]);
            let result: [u8; 32] = hasher.finalize().into();
            result
        };

        let signature = self.identity.sign(&signing_msg);

        let vote_msg = MpcVerificationVoteMessage {
            contribution_hash: msg.contribution_hash(),
            voter: self.identity.node_id(),
            approve: valid,
            rejection_reason: if valid {
                None
            } else {
                Some("Invalid proof".to_string())
            },
            signature,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };

        // Save vote to database
        let db_vote = DbMpcVote {
            contribution_position: msg.elder_position,
            voter_node_id: hex::encode(self.identity.node_id()),
            approve: valid,
            signature: signature.to_vec(),
            voted_at: vote_msg.timestamp,
        };
        self.db.save_mpc_vote(&db_vote)?;

        // Broadcast vote
        if let Some(broadcaster) = &self.broadcaster {
            let payload = serde_json::to_vec(&vote_msg)
                .map_err(|e| GhostError::Serialization(e.to_string()))?;
            broadcaster(MessageType::MpcVerificationVote, payload)?;
        }

        info!(
            position = msg.elder_position,
            approve = valid,
            "Cast MPC verification vote"
        );

        // CRITICAL: Also count our own vote locally and check threshold
        // Without this, our vote only goes to peers but doesn't trigger
        // the approval threshold on this node
        let contribution_hash = msg.contribution_hash();
        let should_apply = {
            let mut pending = self.pending_contributions.write();
            if let Some(contribution) = pending.get_mut(&contribution_hash) {
                // H-4: Insert our node ID into voters set before incrementing count.
                // This prevents double-counting if our own vote arrives back via P2P.
                let our_id = self.identity.node_id();
                if !contribution.voters.insert(our_id) {
                    // Already voted (shouldn't happen in normal flow, but guard against it)
                    return Ok(());
                }
                if valid {
                    contribution.approval_count += 1;
                } else {
                    contribution.rejection_count += 1;
                }

                // Check if we have BFT threshold
                let contributor_count = self.mpc_contributor_count();
                let threshold = bft_threshold(contributor_count);

                info!(
                    approvals = contribution.approval_count,
                    rejections = contribution.rejection_count,
                    mpc_contributors = contributor_count,
                    threshold = threshold,
                    "Self-vote counted for MPC contribution"
                );

                contribution.approval_count >= threshold
            } else {
                false
            }
        };

        // Apply if threshold reached
        if should_apply {
            info!(
                position = msg.elder_position,
                "MPC contribution threshold met, applying"
            );
            self.apply_contribution(&contribution_hash)?;
        }

        Ok(())
    }

    /// Handle an incoming verification vote
    fn handle_verification_vote(
        &self,
        msg: MpcVerificationVoteMessage,
        sender: NodeId,
    ) -> GhostResult<()> {
        // Rate limit
        if !self.rate_limiter.check_and_consume(&sender) {
            return Ok(());
        }

        // Verify signature
        if !msg.verify_signature() {
            warn!(
                voter = %hex::encode(&msg.voter[..8]),
                "Invalid MPC vote signature"
            );
            return Ok(());
        }

        // Verify voter is an MPC contributor (elder)
        if !self.is_node_mpc_contributor(&msg.voter) {
            warn!(
                voter = %hex::encode(&msg.voter[..8]),
                "MPC vote from non-contributor (not an elder)"
            );
            return Ok(());
        }

        // Update pending contribution (with duplicate vote prevention)
        let should_apply = {
            let mut pending = self.pending_contributions.write();
            if let Some(contribution) = pending.get_mut(&msg.contribution_hash) {
                // Reject duplicate votes from the same voter
                if !contribution.voters.insert(msg.voter) {
                    debug!(
                        voter = %hex::encode(&msg.voter[..8]),
                        "Duplicate MPC vote from same voter, ignoring"
                    );
                    return Ok(());
                }

                if msg.approve {
                    contribution.approval_count += 1;
                } else {
                    contribution.rejection_count += 1;
                }

                // Check if we have BFT threshold
                let contributor_count = self.mpc_contributor_count();
                let threshold = bft_threshold(contributor_count);

                debug!(
                    approvals = contribution.approval_count,
                    rejections = contribution.rejection_count,
                    mpc_contributors = contributor_count,
                    threshold = threshold,
                    "MPC vote counted"
                );

                contribution.approval_count >= threshold
            } else {
                false
            }
        };

        // Save vote to database
        if let Some(pending) = self
            .pending_contributions
            .read()
            .get(&msg.contribution_hash)
        {
            let db_vote = DbMpcVote {
                contribution_position: pending.message.elder_position,
                voter_node_id: hex::encode(msg.voter),
                approve: msg.approve,
                signature: msg.signature.to_vec(),
                voted_at: msg.timestamp,
            };
            let _ = self.db.save_mpc_vote(&db_vote);
        }

        // Apply if threshold reached
        if should_apply {
            self.apply_contribution(&msg.contribution_hash)?;
        }

        Ok(())
    }

    /// Apply a contribution after BFT approval
    fn apply_contribution(&self, contribution_hash: &[u8; 32]) -> GhostResult<()> {
        let contribution = {
            let mut pending = self.pending_contributions.write();
            pending.remove(contribution_hash)
        };

        if let Some(contribution) = contribution {
            let msg = &contribution.message;

            // Save contribution to database
            let record = MpcContributionRecord {
                elder_position: msg.elder_position,
                contributor_node_id: hex::encode(msg.candidate),
                prev_params_hash: msg.prev_params_hash,
                new_params_hash: msg.new_params_hash,
                contribution_proof: msg.contribution_proof.clone(),
                epoch: 0, // Will be set properly in integration
                created_at: msg.timestamp,
            };
            self.db.save_mpc_contribution(&record)?;

            // Update state
            *self.contribution_count.write() = msg.elder_position;

            // Check for ossification
            if msg.elder_position >= 101 {
                *self.is_ossified.write() = true;
                info!("MPC ceremony OSSIFIED at 101 contributions");
            }

            // Notify callback with contributor's node_id so caller can fetch params
            if let Some(callback) = &self.params_callback {
                callback(&msg.new_params_hash, &msg.candidate);
            }

            info!(
                position = msg.elder_position,
                params_hash = %hex::encode(&msg.new_params_hash[..8]),
                "Applied MPC contribution"
            );
        }

        Ok(())
    }

    /// Handle parameter request
    fn handle_params_request(
        &self,
        msg: MpcParametersRequestMessage,
        sender: NodeId,
    ) -> GhostResult<()> {
        // Rate limit
        if !self.rate_limiter.check_and_consume(&sender) {
            return Ok(());
        }

        debug!(
            requester = %hex::encode(&msg.requester[..8]),
            params_hash = %hex::encode(&msg.params_hash[..8]),
            chunks = ?msg.chunk_indices,
            "Received MPC params request"
        );

        // Parameter serving would be handled by the sync module in ghost-mpc
        // This handler just logs the request

        Ok(())
    }

    /// Handle parameter response
    fn handle_params_response(
        &self,
        msg: MpcParametersResponseMessage,
        sender: NodeId,
    ) -> GhostResult<()> {
        debug!(
            sender = %hex::encode(&sender[..8]),
            params_hash = %hex::encode(&msg.params_hash[..8]),
            chunk = msg.chunk_index,
            total = msg.total_chunks,
            "Received MPC params chunk"
        );

        // Chunk handling would be done by ghost-mpc sync module

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for MpcHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        // Log entry for MPC message types only
        if matches!(
            envelope.msg_type,
            MessageType::MpcContribution
                | MessageType::MpcVerificationVote
                | MessageType::MpcParametersRequest
                | MessageType::MpcParametersResponse
        ) {
            debug!(
                msg_type = ?envelope.msg_type,
                sender = %hex::encode(&envelope.sender[..8]),
                payload_len = envelope.payload.len(),
                "MpcHandler received MPC message"
            );
        }

        match envelope.msg_type {
            MessageType::MpcContribution => {
                let msg: MpcContributionMessage = match serde_json::from_slice(&envelope.payload) {
                    Ok(m) => m,
                    Err(e) => {
                        error!(
                            error = %e,
                            payload_preview = %String::from_utf8_lossy(&envelope.payload[..envelope.payload.len().min(200)]),
                            "MpcContribution deserialization failed"
                        );
                        return Err(GhostError::Serialization(e.to_string()));
                    }
                };
                debug!(
                    position = msg.elder_position,
                    candidate = %hex::encode(&msg.candidate[..8]),
                    "MpcContribution deserialized"
                );
                self.handle_contribution(msg, envelope.sender)?;
            }
            MessageType::MpcVerificationVote => {
                let msg: MpcVerificationVoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_verification_vote(msg, envelope.sender)?;
            }
            MessageType::MpcParametersRequest => {
                let msg: MpcParametersRequestMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_params_request(msg, envelope.sender)?;
            }
            MessageType::MpcParametersResponse => {
                let msg: MpcParametersResponseMessage =
                    serde_json::from_slice(&envelope.payload)
                        .map_err(|e| GhostError::Serialization(e.to_string()))?;
                self.handle_params_response(msg, envelope.sender)?;
            }
            _ => {
                // Handlers receive all message types - silently ignore non-MPC messages
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 1);
        let node_id = [1u8; 32];

        // First 5 should succeed
        for _ in 0..5 {
            assert!(limiter.check_and_consume(&node_id));
        }

        // 6th should fail
        assert!(!limiter.check_and_consume(&node_id));
    }

    // --- BFT threshold tests ---

    #[test]
    fn test_bft_threshold_bootstrap_1() {
        // 1 contributor is below bootstrap count (4), threshold = 1
        assert_eq!(bft_threshold(1), 1);
    }

    #[test]
    fn test_bft_threshold_bootstrap_3() {
        // 3 contributors still in bootstrap range (< 4), threshold = 1
        assert_eq!(bft_threshold(3), 1);
    }

    #[test]
    fn test_bft_threshold_4_contributors() {
        // 4 contributors: ceil(4 * 67 / 100) = ceil(268/100) = 3
        assert_eq!(bft_threshold(4), 3);
    }

    #[test]
    fn test_bft_threshold_10_contributors() {
        // 10 contributors: ceil(10 * 67 / 100) = ceil(670/100) = 7
        assert_eq!(bft_threshold(10), 7);
    }

    #[test]
    fn test_bft_threshold_100_contributors() {
        // 100 contributors: ceil(100 * 67 / 100) = ceil(6700/100) = 67
        assert_eq!(bft_threshold(100), 67);
    }

    #[test]
    fn test_bft_threshold_101_max() {
        // 101 contributors (max): ceil(101 * 67 / 100) = ceil(6767/100) = 68
        assert_eq!(bft_threshold(101), 68);
    }

    /// Stage A task 1: the handler's quorum constant is the single shared
    /// `ghost-common` value (== the `ghost-mpc` re-export), == documented 67%.
    #[test]
    fn test_bft_threshold_uses_shared_constant() {
        assert_eq!(MPC_BFT_THRESHOLD_PERCENT, 67);
        assert_eq!(MPC_BFT_BOOTSTRAP_COUNT, 4);
        assert_eq!(
            MPC_BFT_THRESHOLD_PERCENT,
            ghost_common::constants::MPC_BFT_THRESHOLD_PERCENT
        );
        // The handler and the ghost-mpc library re-export must be identical.
        assert_eq!(
            MPC_BFT_THRESHOLD_PERCENT,
            ghost_mpc::MPC_BFT_THRESHOLD_PERCENT
        );
        assert_eq!(MPC_BFT_BOOTSTRAP_COUNT, ghost_mpc::MPC_BFT_BOOTSTRAP_COUNT);
    }

    // --- Rate limiter tests ---

    #[test]
    fn test_rate_limiter_independent_buckets() {
        // Two different node_ids should have independent token pools
        let limiter = RateLimiter::new(2, 0);
        let node_a = [0xAAu8; 32];
        let node_b = [0xBBu8; 32];

        // Drain all tokens for node_a
        assert!(limiter.check_and_consume(&node_a));
        assert!(limiter.check_and_consume(&node_a));
        assert!(!limiter.check_and_consume(&node_a)); // exhausted

        // node_b should still have its full allowance
        assert!(limiter.check_and_consume(&node_b));
        assert!(limiter.check_and_consume(&node_b));
        assert!(!limiter.check_and_consume(&node_b)); // exhausted
    }

    #[test]
    fn test_rate_limiter_max_tokens_cap() {
        // Even after a long delay the token count must not exceed max_tokens.
        // We simulate by creating a bucket, waiting (artificially), then checking
        // that we get at most max_tokens successful calls.
        let max = 3u32;
        let refill = 1000; // extremely fast refill rate
        let limiter = RateLimiter::new(max, refill);
        let node = [0xCCu8; 32];

        // First call initialises the bucket at max_tokens.
        assert!(limiter.check_and_consume(&node)); // leaves 2

        // Manipulate last_update to simulate a long elapsed time (1 hour).
        {
            let mut buckets = limiter.buckets.write();
            let bucket = buckets.get_mut(&node).unwrap();
            bucket.last_update = Instant::now() - std::time::Duration::from_secs(3600);
        }

        // After that long delay an uncapped refill would add far more than
        // max_tokens — it must CAP at max_tokens. This call refills (capped) then
        // consumes one, leaving exactly max-1 tokens. We assert the bucket level
        // DIRECTLY rather than consuming in a real-time loop: with this fast
        // refill (~1 token/ms) a wall-clock loop tops the bucket back up between
        // iterations on a loaded runner and overshoots the success count — the
        // historical flake. Inspecting the level is deterministic and still
        // proves the cap held (a broken cap would leave the level higher).
        assert!(limiter.check_and_consume(&node));
        let remaining_millis = limiter.buckets.read().get(&node).unwrap().tokens_millis;
        assert_eq!(
            remaining_millis,
            (max as u64 - 1) * MPC_MILLIS_PER_TOKEN,
            "refill must cap at max_tokens (then -1 for the consume just made)"
        );
    }
}
