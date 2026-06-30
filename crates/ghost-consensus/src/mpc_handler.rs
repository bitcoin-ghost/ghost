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
use std::sync::{Arc, Weak};
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

#[cfg(feature = "mpc-ceremony")]
use ghost_mpc::{CeremonyManager, ContributionProof, Groth16Params, MpcContribution, MpcError};
#[cfg(feature = "mpc-ceremony")]
use ghost_storage::queries::MpcCeremonyState;
#[cfg(feature = "mpc-ceremony")]
use std::future::Future;
#[cfg(feature = "mpc-ceremony")]
use std::pin::Pin;

/// A fetched, hash-matched bundle of ceremony parameters for ONE contribution.
///
/// Returned by the injected [`MpcParamsFetchFn`]. The fetcher guarantees that
/// `hash_parameters(note_spend)` equals the requested lineage hash before
/// handing the bundle back — so the voter never feeds mismatched parameters
/// into the cryptographic check. `payout`/`unshield` ride along for the apply
/// step (they share the same toxic waste as `note_spend`).
#[cfg(feature = "mpc-ceremony")]
#[derive(Clone)]
pub struct FetchedCeremonyParams {
    /// Primary (note-spend) parameters — the lineage chain.
    pub note_spend: Arc<Groth16Params>,
    /// Payout circuit parameters (same toxic waste), if the peer served them.
    pub payout: Option<Arc<Groth16Params>>,
    /// Unshield circuit parameters (same toxic waste), if the peer served them.
    pub unshield: Option<Arc<Groth16Params>>,
}

/// Async callback that fetches a candidate's parameter bundle from the network.
///
/// Input: the expected note-spend lineage hash (`hash_parameters`) of the new
/// parameters. Output: `Some(bundle)` only when a peer supplied parameters whose
/// `hash_parameters()` matches the request; `None` on any fetch/parse/mismatch.
///
/// A `None` result means the voter could not obtain the parameters and MUST
/// abstain — it must never weaken verification or vote approve blind.
#[cfg(feature = "mpc-ceremony")]
pub type MpcParamsFetchFn = Arc<
    dyn Fn([u8; 32]) -> Pin<Box<dyn Future<Output = Option<FetchedCeremonyParams>> + Send>>
        + Send
        + Sync,
>;

/// A cryptographically-verified parameter bundle held between the approve vote
/// and the apply step, keyed by `new_params_hash`. Bounded by
/// `PENDING_CONTRIBUTION_TIMEOUT_SECS` so a never-applied entry is reclaimed.
#[cfg(feature = "mpc-ceremony")]
struct CachedParams {
    inserted_at: Instant,
    bundle: FetchedCeremonyParams,
}

/// The outcome of evaluating a contribution: the only way to reach `Approve` is
/// a successful real cryptographic verification. `Abstain` casts NO vote
/// (fail-closed for transient/local failures so the 67% threshold is not
/// dragged toward rejection); `Reject` casts a signed reject vote.
///
/// Without the `mpc-ceremony` feature there is no cryptographic backend, so
/// `Approve` is never constructed (the voter always abstains) — allow that.
#[cfg_attr(not(feature = "mpc-ceremony"), allow(dead_code))]
enum VoteDecision {
    Approve,
    Reject(String),
    Abstain,
}

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
    /// Weak self-handle so message processing can offload the heavy
    /// fetch/verify/apply work to a background task. The mesh message loop is
    /// single-threaded — running a multi-hundred-megabyte pairing verification
    /// inline would stall ALL inbound messages (health pings, shares, votes).
    /// Set once via [`MpcHandler::init_self_ref`] after the handler is `Arc`-wrapped.
    weak_self: RwLock<Option<Weak<MpcHandler>>>,
    /// Ceremony manager: the authoritative cryptographic backend. Required to
    /// run `verify_contribution` (Schnorr + pairing checks) before approving.
    #[cfg(feature = "mpc-ceremony")]
    ceremony_manager: Option<Arc<CeremonyManager>>,
    /// Network fetcher for candidate parameters (see [`MpcParamsFetchFn`]).
    #[cfg(feature = "mpc-ceremony")]
    params_fetcher: Option<MpcParamsFetchFn>,
    /// Verified parameter bundles, keyed by `new_params_hash`, cached between the
    /// approve vote and the apply step so the (large) params are fetched once.
    #[cfg(feature = "mpc-ceremony")]
    verified_params: RwLock<HashMap<[u8; 32], CachedParams>>,
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
            weak_self: RwLock::new(None),
            #[cfg(feature = "mpc-ceremony")]
            ceremony_manager: None,
            #[cfg(feature = "mpc-ceremony")]
            params_fetcher: None,
            #[cfg(feature = "mpc-ceremony")]
            verified_params: RwLock::new(HashMap::new()),
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

    /// Wire the authoritative cryptographic backend (the ceremony manager).
    ///
    /// Without it the handler cannot verify contributions and will ABSTAIN on
    /// every non-genesis contribution rather than approve unverified.
    #[cfg(feature = "mpc-ceremony")]
    pub fn with_ceremony_manager(mut self, manager: Arc<CeremonyManager>) -> Self {
        self.ceremony_manager = Some(manager);
        self
    }

    /// Wire the network parameter fetcher used to obtain candidate parameters
    /// before cryptographic verification.
    #[cfg(feature = "mpc-ceremony")]
    pub fn with_params_fetcher(mut self, fetcher: MpcParamsFetchFn) -> Self {
        self.params_fetcher = Some(fetcher);
        self
    }

    /// Record a weak self-reference so MPC message handling can be offloaded to
    /// a background task. Call this exactly once after `Arc`-wrapping the handler.
    pub fn init_self_ref(self: &Arc<Self>) {
        *self.weak_self.write() = Some(Arc::downgrade(self));
    }

    /// Upgrade the weak self-reference, if it was installed.
    fn upgrade_self(&self) -> Option<Arc<MpcHandler>> {
        self.weak_self.read().as_ref().and_then(Weak::upgrade)
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
    async fn handle_contribution(
        &self,
        msg: MpcContributionMessage,
        sender: NodeId,
    ) -> GhostResult<()> {
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

            // Reclaim any cached verified parameters that aged out without being
            // applied (rejected / no-quorum). Same lifetime bound as the pending.
            #[cfg(feature = "mpc-ceremony")]
            self.verified_params.write().retain(|_, c| {
                c.inserted_at.elapsed().as_secs() < PENDING_CONTRIBUTION_TIMEOUT_SECS
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
            self.apply_contribution(&contribution_hash).await?;
            return Ok(());
        }

        // If we're an MPC contributor, verify and vote on new contributions
        if self.is_mpc_contributor() {
            self.verify_and_vote(&msg).await?;
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

    /// Cheap structural + hash-chain pre-check (the FAST REJECT).
    ///
    /// Returns `true` only when the proof is present, the hashes are well-formed
    /// and distinct, AND `prev_params_hash` chains from the recorded previous
    /// contribution. This is necessary but NOT sufficient — it does NOT prove
    /// the contribution is a valid cryptographic transformation. Approval
    /// additionally requires [`MpcHandler::crypto_decide`].
    fn structural_precheck(&self, msg: &MpcContributionMessage) -> bool {
        // Structural validation: proof exists, hashes are non-zero and different
        let structurally_valid = !msg.contribution_proof.is_empty()
            && msg.prev_params_hash != [0u8; 32]
            && msg.new_params_hash != [0u8; 32]
            && msg.prev_params_hash != msg.new_params_hash;
        if !structurally_valid {
            return false;
        }

        // Hash chain validation: verify prev_params_hash matches the latest contribution.
        if msg.elder_position == 1 {
            // Genesis contribution has no predecessor to validate against.
            return true;
        }
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
    }

    /// Decide how to vote on a contribution.
    ///
    /// SECURITY (Stage 1a): the ONLY path to [`VoteDecision::Approve`] is a
    /// successful cryptographic `verify_contribution` (Schnorr proof + h/l
    /// pairing checks) against the candidate's fetched parameters. The cheap
    /// structural/chain check is merely a fast reject. A transient inability to
    /// fetch/verify yields [`VoteDecision::Abstain`] (fail-closed: cast no vote)
    /// so a flaky node never approves blind and never drags the 67% threshold
    /// toward rejection.
    async fn decide_vote(&self, msg: &MpcContributionMessage) -> VoteDecision {
        if !self.structural_precheck(msg) {
            return VoteDecision::Reject("Invalid structure or hash chain".to_string());
        }

        #[cfg(feature = "mpc-ceremony")]
        {
            self.crypto_decide(msg).await
        }
        #[cfg(not(feature = "mpc-ceremony"))]
        {
            // No cryptographic backend compiled in — cannot authoritatively
            // verify, so we must NOT approve. Abstain (fail-closed).
            let _ = msg;
            VoteDecision::Abstain
        }
    }

    /// Authoritative cryptographic decision (Stage 1a). Fetches the candidate's
    /// new parameters, confirms they hash to the claimed `new_params_hash`, then
    /// runs the full Schnorr + pairing `verify_contribution` bound to the stable
    /// `ceremony_id`. Heavy work (param hash + pairing checks) runs on a blocking
    /// thread so the mesh loop is never stalled.
    #[cfg(feature = "mpc-ceremony")]
    async fn crypto_decide(&self, msg: &MpcContributionMessage) -> VoteDecision {
        let manager = match &self.ceremony_manager {
            Some(m) => Arc::clone(m),
            None => {
                warn!("MPC: no ceremony manager wired — abstaining (cannot verify)");
                return VoteDecision::Abstain;
            }
        };
        let fetcher = match &self.params_fetcher {
            Some(f) => Arc::clone(f),
            None => {
                warn!("MPC: no params fetcher wired — abstaining (cannot verify)");
                return VoteDecision::Abstain;
            }
        };

        // 1. Fetch the candidate's parameters. None => cannot verify => ABSTAIN.
        let claimed = msg.new_params_hash;
        let bundle = match fetcher(claimed).await {
            Some(b) => b,
            None => {
                info!(
                    position = msg.elder_position,
                    expected = %hex::encode(&claimed[..8]),
                    "MPC: could not fetch candidate parameters — abstaining (fail-closed)"
                );
                return VoteDecision::Abstain;
            }
        };

        // 1b. Defence in depth: confirm the fetched bytes hash to the claim.
        // A mismatch means we hold the wrong params (e.g. fetched from a stale
        // peer) and cannot judge the contribution — ABSTAIN, do not reject.
        {
            let ns = Arc::clone(&bundle.note_spend);
            let h =
                tokio::task::spawn_blocking(move || ghost_mpc::contribution::hash_parameters(&ns))
                    .await;
            match h {
                Ok(Ok(hash)) if hash == claimed => {}
                Ok(Ok(hash)) => {
                    warn!(
                        expected = %hex::encode(&claimed[..8]),
                        got = %hex::encode(&hash[..8]),
                        "MPC: fetched params hash != claimed new_params_hash — abstaining"
                    );
                    return VoteDecision::Abstain;
                }
                _ => {
                    warn!("MPC: failed to hash fetched params — abstaining");
                    return VoteDecision::Abstain;
                }
            }
        }

        // 2. Reconstruct the contribution. A malformed proof is part of the
        // signed payload every node sees identically — REJECT (deterministic).
        let contribution = match reconstruct_contribution(msg) {
            Some(c) => c,
            None => {
                return VoteDecision::Reject("Malformed contribution proof".to_string());
            }
        };

        // 3. Run the authoritative verification on a blocking thread.
        let note_spend = Arc::clone(&bundle.note_spend);
        let contribution_for_verify = contribution.clone();
        let manager_for_verify = Arc::clone(&manager);
        let result = tokio::task::spawn_blocking(move || {
            manager_for_verify.verify_contribution(&note_spend, &contribution_for_verify)
        })
        .await;

        match result {
            Ok(Ok(true)) => {
                // 4. Cache the verified bundle for the apply step (fetch once).
                self.verified_params.write().insert(
                    claimed,
                    CachedParams {
                        inserted_at: Instant::now(),
                        bundle,
                    },
                );
                VoteDecision::Approve
            }
            Ok(Ok(false)) => {
                VoteDecision::Reject("Contribution failed cryptographic verification".to_string())
            }
            Ok(Err(e)) => classify_verify_error(e),
            Err(join_err) => {
                warn!(error = %join_err, "MPC: verification task panicked — abstaining");
                VoteDecision::Abstain
            }
        }
    }

    /// Verify a contribution and cast our vote.
    async fn verify_and_vote(&self, msg: &MpcContributionMessage) -> GhostResult<()> {
        match self.decide_vote(msg).await {
            VoteDecision::Abstain => {
                info!(
                    position = msg.elder_position,
                    "MPC: abstaining on contribution (could not authoritatively verify)"
                );
                Ok(())
            }
            VoteDecision::Approve => self.cast_vote(msg, true, None).await,
            VoteDecision::Reject(reason) => self.cast_vote(msg, false, Some(reason)).await,
        }
    }

    /// Sign, persist, broadcast our vote, count it locally, and apply on threshold.
    async fn cast_vote(
        &self,
        msg: &MpcContributionMessage,
        approve: bool,
        reason: Option<String>,
    ) -> GhostResult<()> {
        let signing_msg = {
            let mut hasher = sha2::Sha256::new();
            use sha2::Digest;
            hasher.update(b"MpcVerificationVote/v1");
            hasher.update(msg.contribution_hash());
            hasher.update([approve as u8]);
            let result: [u8; 32] = hasher.finalize().into();
            result
        };

        let signature = self.identity.sign(&signing_msg);

        let vote_msg = MpcVerificationVoteMessage {
            contribution_hash: msg.contribution_hash(),
            voter: self.identity.node_id(),
            approve,
            rejection_reason: reason,
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
            approve,
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
            approve = approve,
            "Cast MPC verification vote"
        );

        // CRITICAL: Also count our own vote locally and check threshold.
        let contribution_hash = msg.contribution_hash();
        let should_apply = {
            let mut pending = self.pending_contributions.write();
            if let Some(contribution) = pending.get_mut(&contribution_hash) {
                // H-4: Insert our node ID into voters set before incrementing count.
                let our_id = self.identity.node_id();
                if !contribution.voters.insert(our_id) {
                    return Ok(());
                }
                if approve {
                    contribution.approval_count += 1;
                } else {
                    contribution.rejection_count += 1;
                }

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

        if should_apply {
            info!(
                position = msg.elder_position,
                "MPC contribution threshold met, applying"
            );
            self.apply_contribution(&contribution_hash).await?;
        }

        Ok(())
    }

    /// Handle an incoming verification vote
    async fn handle_verification_vote(
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
            self.apply_contribution(&msg.contribution_hash).await?;
        }

        Ok(())
    }

    /// Apply a contribution after BFT approval.
    ///
    /// Records the contribution row, then (Stage 1b) drives the canonical
    /// parameter swap through the ceremony manager and persists the
    /// `mpc_ceremony` singleton so the on-disk params, in-memory hot-swap, and
    /// the authoritative count/hash all advance atomically with the recorded
    /// lineage. `save_mpc_contribution` stays strictly inside this
    /// post-threshold path — no elder position is ever recorded without BFT
    /// approval.
    async fn apply_contribution(&self, contribution_hash: &[u8; 32]) -> GhostResult<()> {
        let contribution = {
            let mut pending = self.pending_contributions.write();
            pending.remove(contribution_hash)
        };

        if let Some(contribution) = contribution {
            let msg = contribution.message.clone();

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

            // Update handler-tracked progression state.
            *self.contribution_count.write() = msg.elder_position;

            // Check for ossification
            if msg.elder_position >= 101 {
                *self.is_ossified.write() = true;
                info!("MPC ceremony OSSIFIED at 101 contributions");
            }

            // Stage 1b: apply through the ceremony manager (disk write + symlink
            // + in-memory hot-swap + count/current_params_hash + ossify) using the
            // parameters we verified during our approve vote, then persist the
            // singleton. Applies IMMEDIATELY on threshold (rolling design), not at
            // an epoch boundary.
            #[cfg(feature = "mpc-ceremony")]
            self.apply_through_manager(&msg).await;

            // Notify callback so nodes that did not vote (no locally-cached
            // params) fetch + verify + adopt the new parameters.
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

    /// Stage 1b: drive the parameter swap through the ceremony manager using the
    /// cached, already-verified parameters, then persist the `mpc_ceremony`
    /// singleton from the manager's authoritative post-apply state.
    #[cfg(feature = "mpc-ceremony")]
    async fn apply_through_manager(&self, msg: &MpcContributionMessage) {
        let manager = match &self.ceremony_manager {
            Some(m) => Arc::clone(m),
            None => return,
        };

        // The verified bundle must have been cached during our approve vote.
        // If it is absent (we abstained, or we are a non-voter that reached
        // threshold via peer votes) we do NOT fabricate state here — the
        // params_callback path fetches + verifies + adopts asynchronously.
        let bundle = match self.verified_params.write().remove(&msg.new_params_hash) {
            Some(c) => c.bundle,
            None => {
                debug!(
                    position = msg.elder_position,
                    "MPC apply: no locally-cached verified params — deferring adoption to params_callback"
                );
                return;
            }
        };

        let contribution = match reconstruct_contribution(msg) {
            Some(c) => c,
            None => {
                warn!("MPC apply: could not reconstruct contribution from message");
                return;
            }
        };

        // Clone owned params out of the cached Arcs for the manager (owned API).
        let note_spend = (*bundle.note_spend).clone();
        let payout = bundle.payout.as_ref().map(|p| (**p).clone());
        let unshield = bundle.unshield.as_ref().map(|p| (**p).clone());

        let manager_for_apply = Arc::clone(&manager);
        let apply_res = tokio::task::spawn_blocking(move || {
            manager_for_apply.apply_contribution_multi(note_spend, payout, unshield, &contribution)
        })
        .await;

        match apply_res {
            Ok(Ok(())) => {
                // Persist the singleton from the manager's authoritative state.
                // On position 101 the manager ossifies internally, so the saved
                // state carries is_ossified=1 (do NOT rely on a separate
                // set_ceremony_ossified UPDATE, which no-ops on an absent row).
                if let Err(e) = persist_singleton(&self.db, &manager) {
                    warn!(error = %e, "MPC: failed to persist ceremony singleton after apply");
                } else {
                    info!(
                        position = msg.elder_position,
                        "MPC: applied contribution through ceremony manager and persisted singleton"
                    );
                }
            }
            Ok(Err(e)) => {
                warn!(error = %e, position = msg.elder_position, "MPC: ceremony manager apply failed");
            }
            Err(e) => {
                warn!(error = %e, "MPC: ceremony manager apply task panicked");
            }
        }
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

/// Reconstruct the `ghost-mpc` contribution record from a wire message.
///
/// `contribution_proof` is the `serde_json` encoding of [`ContributionProof`]
/// (see the send path in `ghost-pool`); `timestamp` is seconds (matching what
/// `verify_contribution`'s skew window expects); `contributor` is the hex of the
/// candidate node id (informational — not used by the crypto checks).
#[cfg(feature = "mpc-ceremony")]
fn reconstruct_contribution(msg: &MpcContributionMessage) -> Option<MpcContribution> {
    let proof: ContributionProof = serde_json::from_slice(&msg.contribution_proof).ok()?;
    Some(MpcContribution {
        position: msg.elder_position,
        prev_params_hash: msg.prev_params_hash,
        new_params_hash: msg.new_params_hash,
        proof,
        contributor: hex::encode(msg.candidate),
        timestamp: msg.timestamp,
        commitment_hash: None,
    })
}

/// Map a `verify_contribution` error to a vote decision.
///
/// Cryptographic failures (bad proof / hash / chain) are deterministic across
/// honest nodes — REJECT. Infrastructure / transient errors (no local params,
/// position desync, ossified) are not proof of forgery and could be local-only,
/// so they ABSTAIN (fail-closed: never approve, never drag the threshold).
#[cfg(feature = "mpc-ceremony")]
fn classify_verify_error(e: MpcError) -> VoteDecision {
    match e {
        MpcError::InvalidProof(_)
        | MpcError::HashMismatch { .. }
        | MpcError::InvalidChain { .. } => {
            VoteDecision::Reject(format!("Cryptographic verification failed: {e}"))
        }
        _ => {
            warn!(error = %e, "MPC: non-cryptographic verification error — abstaining");
            VoteDecision::Abstain
        }
    }
}

/// Persist the `mpc_ceremony` singleton from the manager's authoritative state.
///
/// Maps `ghost_mpc::CeremonyState` → `MpcCeremonyState` (note
/// `note_spend_vk_hash` → `block_vk_hash`). This is the single writer that keeps
/// the singleton in lock-step with the in-memory hot-swap and on-disk params.
#[cfg(feature = "mpc-ceremony")]
fn persist_singleton(db: &Database, manager: &CeremonyManager) -> GhostResult<()> {
    let s = manager.state();
    let db_state = MpcCeremonyState {
        contribution_count: s.contribution_count,
        current_params_hash: s.current_params_hash,
        is_ossified: s.is_ossified,
        ossified_at: s.ossified_at,
        block_vk_hash: s.note_spend_vk_hash,
        payout_vk_hash: s.payout_vk_hash,
        updated_at: s.updated_at,
        ceremony_id: s.ceremony_id,
    };
    db.save_mpc_ceremony_state(&db_state)
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
                // Offload to a background task: handling may fetch + run heavy
                // pairing verification, which must NOT stall the single-threaded
                // mesh message loop. Falls back to inline when no self-ref is set
                // (e.g. unit tests that drive methods directly).
                let sender = envelope.sender;
                match self.upgrade_self() {
                    Some(me) => {
                        tokio::spawn(async move {
                            if let Err(e) = me.handle_contribution(msg, sender).await {
                                warn!(error = %e, "MPC contribution handling failed");
                            }
                        });
                    }
                    None => self.handle_contribution(msg, sender).await?,
                }
            }
            MessageType::MpcVerificationVote => {
                let msg: MpcVerificationVoteMessage = serde_json::from_slice(&envelope.payload)
                    .map_err(|e| GhostError::Serialization(e.to_string()))?;
                let sender = envelope.sender;
                match self.upgrade_self() {
                    Some(me) => {
                        tokio::spawn(async move {
                            if let Err(e) = me.handle_verification_vote(msg, sender).await {
                                warn!(error = %e, "MPC vote handling failed");
                            }
                        });
                    }
                    None => self.handle_verification_vote(msg, sender).await?,
                }
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

/// Stage 1a/1b tests: the BFT voter now runs REAL cryptographic verification
/// before approving, applies through the ceremony manager, and persists the
/// `mpc_ceremony` singleton. These exercise the closed vulnerability end-to-end.
#[cfg(all(test, feature = "mpc-ceremony"))]
mod ceremony_vote_tests {
    use super::*;
    use ghost_mpc::CeremonyManager;
    use ghost_storage::Database;
    use tempfile::TempDir;

    /// A genesis-initialised manager (real Groth16 params for all three circuits).
    fn genesis_manager() -> (Arc<CeremonyManager>, TempDir) {
        let dir = TempDir::new().unwrap();
        let mgr = CeremonyManager::new(dir.path().to_path_buf());
        mgr.ensure_genesis_initialized().unwrap();
        (Arc::new(mgr), dir)
    }

    /// Build a signed wire message for a generated contribution. `contribution_proof`
    /// is the `serde_json` encoding of the proof (matching the production send path);
    /// `timestamp` is seconds (matching `verify_contribution`'s skew window).
    fn message_for(
        contribution: &ghost_mpc::MpcContribution,
        identity: &NodeIdentity,
    ) -> MpcContributionMessage {
        let proof_bytes = serde_json::to_vec(&contribution.proof).unwrap();
        let mut msg = MpcContributionMessage {
            candidate: identity.node_id(),
            elder_position: contribution.position,
            prev_params_hash: contribution.prev_params_hash,
            new_params_hash: contribution.new_params_hash,
            contribution_proof: proof_bytes,
            signature: [0u8; 64],
            timestamp: contribution.timestamp,
        };
        let sm = msg.signing_message();
        msg.signature = identity.sign(&sm);
        msg
    }

    fn fetcher_returning(params: Arc<Groth16Params>) -> MpcParamsFetchFn {
        Arc::new(move |_expected| {
            let p = Arc::clone(&params);
            Box::pin(async move {
                Some(FetchedCeremonyParams {
                    note_spend: p,
                    payout: None,
                    unshield: None,
                })
            })
        })
    }

    fn fetcher_failing() -> MpcParamsFetchFn {
        Arc::new(move |_expected| Box::pin(async move { Option::<FetchedCeremonyParams>::None }))
    }

    fn insert_pending(handler: &MpcHandler, msg: &MpcContributionMessage) {
        handler.pending_contributions.write().insert(
            msg.contribution_hash(),
            PendingContribution {
                message: msg.clone(),
                received_at: Instant::now(),
                approval_count: 0,
                rejection_count: 0,
                voters: std::collections::HashSet::new(),
            },
        );
    }

    /// (1) A valid contribution is cryptographically verified → approved → at the
    /// (bootstrap) threshold it applies: a `mpc_contributions` row is written, the
    /// `mpc_ceremony` singleton is populated with the incremented count + matching
    /// `current_params_hash`, and the manager hot-swaps the parameters.
    #[tokio::test]
    async fn test_valid_contribution_approved_applied_and_persisted() {
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().unwrap());
        let (manager, _dir) = genesis_manager();

        let (new_params, contribution) = manager.generate_contribution("node1").unwrap();
        let new_params = Arc::new(new_params);
        let msg = message_for(&contribution, &identity);

        let handler = MpcHandler::new(Arc::clone(&identity), Arc::clone(&db))
            .with_ceremony_manager(Arc::clone(&manager))
            .with_params_fetcher(fetcher_returning(Arc::clone(&new_params)))
            .with_state(0, false);
        insert_pending(&handler, &msg);

        handler.verify_and_vote(&msg).await.unwrap();

        // mpc_contributions row recorded at position 1.
        let row = db.get_mpc_contribution(1).unwrap();
        assert!(
            row.is_some(),
            "contribution row must be saved at position 1"
        );
        assert_eq!(row.unwrap().new_params_hash, contribution.new_params_hash);

        // Singleton populated, count incremented, hash matches.
        let singleton = db
            .get_mpc_ceremony_state()
            .unwrap()
            .expect("singleton must be persisted");
        assert_eq!(singleton.contribution_count, 1);
        assert_eq!(singleton.current_params_hash, contribution.new_params_hash);

        // Manager hot-swapped in memory.
        assert_eq!(manager.contribution_count(), 1);
        assert_eq!(manager.current_params_hash(), contribution.new_params_hash);

        // We cast exactly one approve vote (no reject).
        let (approvals, rejections) = db.count_mpc_approvals(1).unwrap();
        assert_eq!(approvals, 1);
        assert_eq!(rejections, 0);
    }

    /// (2) A forged contribution — valid structure + valid hash-chain link but a
    /// TAMPERED Schnorr proof — is REJECTED and never applied. CRITICAL: the same
    /// input WOULD have passed the old structural-only pre-check, proving Stage 1a
    /// closed the hole.
    #[tokio::test]
    async fn test_forged_contribution_rejected_not_applied() {
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().unwrap());
        let (manager, _dir) = genesis_manager();
        let genesis_hash = manager.current_params_hash();

        let (new_params, mut contribution) = manager.generate_contribution("node1").unwrap();
        let new_params = Arc::new(new_params);

        // Tamper ONLY the Schnorr response (low byte → stays a valid scalar). The
        // parameters and all hashes are untouched, so the structural pre-check and
        // the fetched-params hash match both still pass — only the cryptographic
        // proof check can catch this.
        contribution.proof.tau_pok.response[0] ^= 0x01;
        let msg = message_for(&contribution, &identity);

        let handler = MpcHandler::new(Arc::clone(&identity), Arc::clone(&db))
            .with_ceremony_manager(Arc::clone(&manager))
            .with_params_fetcher(fetcher_returning(Arc::clone(&new_params)))
            .with_state(0, false);

        // PROOF the hole is closed: the OLD structural-only check approves this.
        assert!(
            handler.structural_precheck(&msg),
            "the old structural-only check WOULD have passed the forged contribution"
        );

        insert_pending(&handler, &msg);
        handler.verify_and_vote(&msg).await.unwrap();

        // Never applied: no row, no state change.
        assert!(
            db.get_mpc_contribution(1).unwrap().is_none(),
            "forged contribution must NOT be recorded"
        );
        assert_eq!(manager.contribution_count(), 0);
        assert_eq!(
            manager.current_params_hash(),
            genesis_hash,
            "current params must be unchanged"
        );
        if let Some(s) = db.get_mpc_ceremony_state().unwrap() {
            assert_eq!(s.contribution_count, 0, "singleton must not advance");
        }
        // A reject vote was cast (not an approve).
        let (approvals, rejections) = db.count_mpc_approvals(1).unwrap();
        assert_eq!(approvals, 0);
        assert!(rejections >= 1, "forged contribution must be rejected");
    }

    /// (3) A transient fetch failure makes the voter ABSTAIN: it casts NO vote (so
    /// the 67% threshold is not dragged toward rejection), does not apply, and the
    /// pending contribution survives — the ceremony is not stalled.
    #[tokio::test]
    async fn test_fetch_failure_abstains_no_stall() {
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().unwrap());
        let (manager, _dir) = genesis_manager();
        let genesis_hash = manager.current_params_hash();

        let (_new_params, contribution) = manager.generate_contribution("node1").unwrap();
        let msg = message_for(&contribution, &identity);

        let handler = MpcHandler::new(Arc::clone(&identity), Arc::clone(&db))
            .with_ceremony_manager(Arc::clone(&manager))
            .with_params_fetcher(fetcher_failing())
            .with_state(0, false);
        insert_pending(&handler, &msg);

        handler.verify_and_vote(&msg).await.unwrap();

        // No vote cast (abstained), nothing applied, params unchanged.
        let (approvals, rejections) = db.count_mpc_approvals(1).unwrap();
        assert_eq!(approvals, 0, "abstention casts no approve vote");
        assert_eq!(rejections, 0, "abstention casts no reject vote");
        assert!(db.get_mpc_contribution(1).unwrap().is_none());
        assert_eq!(manager.contribution_count(), 0);
        assert_eq!(manager.current_params_hash(), genesis_hash);
        // Pending survives → ceremony not stalled (a later retry can still vote).
        assert!(
            handler
                .pending_contributions
                .read()
                .contains_key(&msg.contribution_hash()),
            "pending must survive an abstention"
        );
    }

    /// (4) The crypto gate that BOTH the voter and `params_callback` enforce:
    /// parameters whose NEW-params hash matches the contribution's claim are STILL
    /// rejected when they do not verify against THIS node's own current params
    /// (its prev). Hash-match alone is never sufficient. Here a contribution from a
    /// foreign lineage A is offered to node B: the new hash matches, the structural
    /// check passes, but verification against B's prev fails → reject, no adoption.
    #[tokio::test]
    async fn test_verify_gate_rejects_hash_matching_foreign_lineage() {
        let identity = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().unwrap());
        let (manager_a, _da) = genesis_manager();
        let (manager_b, _db_dir) = genesis_manager();

        // Contribution generated on lineage A.
        let (new_a, contribution_a) = manager_a.generate_contribution("nodeA").unwrap();
        let new_a = Arc::new(new_a);

        // The NEW-params hash genuinely matches the contribution's claim …
        assert_eq!(
            ghost_mpc::contribution::hash_parameters(&new_a).unwrap(),
            contribution_a.new_params_hash,
            "fetched params hash matches the claimed new_params_hash"
        );

        let msg = message_for(&contribution_a, &identity);

        // … but node B (a different genesis lineage) must NOT adopt it.
        let handler = MpcHandler::new(Arc::clone(&identity), Arc::clone(&db))
            .with_ceremony_manager(Arc::clone(&manager_b))
            .with_params_fetcher(fetcher_returning(Arc::clone(&new_a)))
            .with_state(0, false);

        // Structural + hash checks pass — proving hash match alone is insufficient.
        assert!(handler.structural_precheck(&msg));
        insert_pending(&handler, &msg);

        handler.verify_and_vote(&msg).await.unwrap();

        // Gate held: B refused the foreign-lineage params.
        assert_eq!(manager_b.contribution_count(), 0);
        assert!(db.get_mpc_contribution(1).unwrap().is_none());
        let (approvals, rejections) = db.count_mpc_approvals(1).unwrap();
        assert_eq!(approvals, 0, "must not approve on hash match alone");
        assert!(
            rejections >= 1,
            "the verify gate must reject foreign-lineage params"
        );
    }
}
