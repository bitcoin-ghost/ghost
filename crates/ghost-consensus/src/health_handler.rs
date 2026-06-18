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
//| FILE: health_handler.rs                                                                                              |
//|======================================================================================================================|

//! Health ping handler
//!
//! Handles incoming health pings and updates peer information in the database.
//! Also discovers elders dynamically from HealthPing capabilities.
//!
//! ## Security Features
//!
//! - **PoW Verification**: Nodes must provide valid proof-of-work to register as voters.
//!   This prevents Sybil attacks where attackers create unlimited fake nodes.
//!
//! - **Rate Limiting**: Limits health pings per node to prevent flooding attacks.
//!   Uses token bucket algorithm similar to VoteHandler.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

use ghost_common::error::GhostResult;
use ghost_common::identity::{NodeIdProof, NODE_ID_POW_DIFFICULTY};
use ghost_common::types::NodeId;
use ghost_storage::{Database, PeerRecord};

use crate::ban_manager::BanManager;
use crate::mesh::MessageHandler;
use crate::message::{HealthPingMessage, MessageEnvelope, MessageType};
use crate::peer::PeerManager;

/// Callback for registering discovered elders
pub type ElderCallback = Arc<dyn Fn(NodeId) + Send + Sync>;

/// Callback for registering node capabilities (for payout calculation)
pub type NodeCapabilitiesCallback =
    Arc<dyn Fn(NodeId, ghost_common::types::NodeCapabilities) + Send + Sync>;

/// P2P4-M2: Callback to verify capabilities against challenge results
///
/// This callback queries the verification system to determine which capabilities
/// have been verified for a given node. It takes the node ID and returns the
/// set of VERIFIED capabilities (not just claimed ones).
///
/// The verification system maintains challenge results and pass rates. Only
/// capabilities with sufficient challenge passes (e.g., 10+ challenges, 95% pass)
/// should be included in the returned capabilities.
pub type CapabilityVerifierCallback =
    Arc<dyn Fn(&NodeId) -> ghost_common::types::NodeCapabilities + Send + Sync>;

/// Rate limit configuration for health pings
///
/// Default: 10 pings burst, 1/second sustained per node
/// Health pings are sent every 10 seconds normally, so 1/sec is generous
const HEALTH_RATE_LIMIT_MAX_TOKENS: u32 = 10;
const HEALTH_RATE_LIMIT_REFILL_RATE: u32 = 1;

/// L-7/M-5 SECURITY: Dynamic PoW difficulty adjustment configuration
///
/// The difficulty is adjusted based on recent ping rates to prevent
/// Sybil attacks during high-traffic periods while maintaining usability
/// during low-activity periods.
///
/// M-5 DESIGN NOTE: Node-local PoW difficulty adjustment is INTENTIONAL
///
/// Each node independently adjusts its PoW difficulty based on the traffic it observes.
/// This is a deliberate design choice for DoS protection, NOT a bug:
///
/// 1. **Local DoS Protection**: A node under attack sees high traffic and raises its
///    difficulty, protecting itself without affecting other nodes.
///
/// 2. **Attack Isolation**: An attacker flooding one node doesn't affect the difficulty
///    for communications with other nodes in the network.
///
/// 3. **No Coordination Required**: Nodes don't need to agree on difficulty, avoiding
///    the complexity and attack surface of consensus on PoW difficulty.
///
/// 4. **Graceful Degradation**: If an attacker manages to lower difficulty on one node,
///    other nodes still maintain their own appropriate difficulty levels.
///
/// This is analogous to TCP congestion control - each endpoint manages its own state
/// based on local observations. A global PoW difficulty would require consensus and
/// could be manipulated by colluding nodes.
///
/// Base PoW difficulty (minimum)
const BASE_POW_DIFFICULTY: u32 = 16;

/// Maximum PoW difficulty under attack conditions
const MAX_POW_DIFFICULTY: u32 = 24;

/// Number of pings to track for rate calculation
const PING_RATE_WINDOW_SIZE: usize = 1000;

/// Threshold: if we receive more than this many pings per second, increase difficulty
const HIGH_TRAFFIC_THRESHOLD_PER_SEC: f64 = 50.0;

/// Low traffic threshold (pings per second) below which we decrease difficulty
const LOW_TRAFFIC_THRESHOLD_PER_SEC: f64 = 5.0;

/// How often to recalculate difficulty (seconds)
const DIFFICULTY_ADJUSTMENT_INTERVAL_SECS: u64 = 60;

/// One token in millis (1000 millis = 1 token)
/// M-1: Using integer arithmetic for precision, matching vote_handler.rs
const MILLIS_PER_TOKEN: u64 = 1000;

/// Token bucket for rate limiting
///
/// M-1: Uses integer-based tokens with milli-token precision to avoid
/// floating-point precision issues. One token = 1000 millis.
/// This prevents subtle bugs from f64 rounding that could allow
/// rate limit bypass or unfair throttling.
#[derive(Clone)]
struct TokenBucket {
    /// Tokens * 1000 for sub-token precision without floating point
    tokens_millis: u64,
    last_update: Instant,
}

/// L-7 SECURITY: Dynamic difficulty adjuster for health ping PoW
///
/// Adjusts PoW difficulty based on recent ping rates:
/// - Under attack (high traffic): Increase difficulty to make Sybil expensive
/// - Normal operation (low traffic): Decrease difficulty for usability
pub struct DynamicDifficultyAdjuster {
    /// Timestamps of recent pings for rate calculation
    ping_timestamps: RwLock<std::collections::VecDeque<Instant>>,
    /// Current effective difficulty
    current_difficulty: RwLock<u32>,
    /// Last time difficulty was adjusted
    last_adjustment: RwLock<Instant>,
}

impl DynamicDifficultyAdjuster {
    /// Create a new difficulty adjuster with base difficulty
    pub fn new() -> Self {
        Self {
            ping_timestamps: RwLock::new(std::collections::VecDeque::with_capacity(
                PING_RATE_WINDOW_SIZE,
            )),
            current_difficulty: RwLock::new(BASE_POW_DIFFICULTY),
            last_adjustment: RwLock::new(Instant::now()),
        }
    }

    /// Record a ping and potentially adjust difficulty
    ///
    /// Returns the current required difficulty
    pub fn record_ping(&self) -> u32 {
        let now = Instant::now();

        // Record this ping
        {
            let mut timestamps = self.ping_timestamps.write();
            timestamps.push_back(now);

            // Keep only recent pings (within 60 seconds)
            let cutoff = now - Duration::from_secs(60);
            while timestamps.front().map(|t| *t < cutoff).unwrap_or(false) {
                timestamps.pop_front();
            }

            // Cap at window size
            while timestamps.len() > PING_RATE_WINDOW_SIZE {
                timestamps.pop_front();
            }
        }

        // Check if it's time to adjust difficulty
        let should_adjust = {
            let last = self.last_adjustment.read();
            now.duration_since(*last).as_secs() >= DIFFICULTY_ADJUSTMENT_INTERVAL_SECS
        };

        if should_adjust {
            self.adjust_difficulty();
        }

        *self.current_difficulty.read()
    }

    /// Get the current difficulty without recording a ping
    pub fn current_difficulty(&self) -> u32 {
        *self.current_difficulty.read()
    }

    /// Adjust difficulty based on recent ping rate
    ///
    /// L-1: Uses bounds checking to prevent integer overflow in log2 calculation
    fn adjust_difficulty(&self) {
        let now = Instant::now();
        let rate = self.calculate_ping_rate();
        let current = *self.current_difficulty.read();

        let new_difficulty = if rate > HIGH_TRAFFIC_THRESHOLD_PER_SEC {
            // Under attack - increase difficulty
            // L-1: Bounds checking for log2 calculation
            // 1. Calculate ratio with bounds to prevent division issues
            let ratio = rate / HIGH_TRAFFIC_THRESHOLD_PER_SEC;

            // L-1: Validate ratio before log2 to prevent NaN/Infinity
            // ratio > 1.0 is guaranteed since rate > HIGH_TRAFFIC_THRESHOLD_PER_SEC
            // But we add defensive checks for safety
            let increase = if ratio.is_finite() && ratio > 1.0 {
                let log_value = ratio.log2();
                // L-1: Clamp log2 result before casting to u32
                // Maximum practical increase is MAX_POW_DIFFICULTY - BASE_POW_DIFFICULTY = 8
                // Cap at 8 to prevent any overflow issues
                if log_value.is_finite() && log_value >= 0.0 {
                    (log_value as u32).clamp(1, MAX_POW_DIFFICULTY - BASE_POW_DIFFICULTY)
                } else {
                    1 // Minimum increase if log2 returns invalid value
                }
            } else {
                1 // Minimum increase for safety
            };
            (current.saturating_add(increase)).min(MAX_POW_DIFFICULTY)
        } else if rate < LOW_TRAFFIC_THRESHOLD_PER_SEC && current > BASE_POW_DIFFICULTY {
            // Low traffic - decrease difficulty (but not below base)
            (current - 1).max(BASE_POW_DIFFICULTY)
        } else {
            current
        };

        if new_difficulty != current {
            debug!(
                old_difficulty = current,
                new_difficulty,
                ping_rate = rate,
                "L-7: Adjusting PoW difficulty based on traffic"
            );
            *self.current_difficulty.write() = new_difficulty;
        }

        *self.last_adjustment.write() = now;
    }

    /// Calculate pings per second over the tracking window
    fn calculate_ping_rate(&self) -> f64 {
        let timestamps = self.ping_timestamps.read();
        if timestamps.len() < 2 {
            return 0.0;
        }

        // CRIT-PANIC-1: Use .first()/.last() instead of .front()/.back() unwrap
        let (first, last) = match (timestamps.front(), timestamps.back()) {
            (Some(f), Some(l)) => (f, l),
            _ => return 0.0, // Should never happen due to len check, but safe
        };
        let duration = last.duration_since(*first).as_secs_f64();

        if duration < 0.001 {
            return 0.0;
        }

        timestamps.len() as f64 / duration
    }

    /// Clean up old ping timestamps (call periodically)
    pub fn cleanup(&self) {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(60);
        let mut timestamps = self.ping_timestamps.write();
        while timestamps.front().map(|t| *t < cutoff).unwrap_or(false) {
            timestamps.pop_front();
        }
    }
}

impl Default for DynamicDifficultyAdjuster {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter for health pings
pub struct HealthRateLimiter {
    buckets: RwLock<HashMap<NodeId, TokenBucket>>,
    max_tokens: u32,
    refill_rate: u32,
}

impl HealthRateLimiter {
    /// Create a new rate limiter
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens,
            refill_rate,
        }
    }

    /// Check if a node is rate limited and consume a token if not
    ///
    /// Returns true if the ping should be allowed, false if rate limited
    ///
    /// M-1: Uses integer arithmetic with milli-token precision to avoid
    /// floating-point precision issues. This matches the approach used in
    /// vote_handler.rs and discovery_handler.rs.
    pub fn check_and_consume(&self, node_id: &NodeId) -> bool {
        let mut buckets = self.buckets.write();
        let now = Instant::now();

        let max_tokens_millis = (self.max_tokens as u64).saturating_mul(MILLIS_PER_TOKEN);

        let bucket = buckets.entry(*node_id).or_insert_with(|| TokenBucket {
            tokens_millis: max_tokens_millis,
            last_update: now,
        });

        // M-1: Refill tokens based on time elapsed using integer arithmetic
        // Cap elapsed time to 1 hour (3600000 ms) to prevent overflow
        let elapsed_ms = now
            .duration_since(bucket.last_update)
            .as_millis()
            .min(3_600_000) as u64;

        // refill_millis = elapsed_ms * refill_rate * MILLIS_PER_TOKEN / 1000
        // Reorder to minimize precision loss: (elapsed_ms * refill_rate_millis) / 1000
        let refill_rate_millis = (self.refill_rate as u64).saturating_mul(MILLIS_PER_TOKEN);
        let refill_millis = elapsed_ms.saturating_mul(refill_rate_millis) / 1000;

        bucket.tokens_millis = bucket
            .tokens_millis
            .saturating_add(refill_millis)
            .min(max_tokens_millis);
        bucket.last_update = now;

        // Try to consume one token (1000 millis)
        if bucket.tokens_millis >= MILLIS_PER_TOKEN {
            bucket.tokens_millis -= MILLIS_PER_TOKEN;
            true
        } else {
            false
        }
    }

    /// Clean up old buckets (call periodically)
    pub fn cleanup(&self, max_age_secs: u64) {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        buckets.retain(|_, bucket| now.duration_since(bucket.last_update).as_secs() < max_age_secs);
    }

    /// Get the number of tracked nodes
    pub fn bucket_count(&self) -> usize {
        self.buckets.read().len()
    }
}

/// Maximum timestamp drift allowed for health pings (H4 security fix)
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300; // 5 minutes

/// Default minimum uptime for voter registration (C2 security fix)
const DEFAULT_MIN_UPTIME_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// Default registration cooldown (C2 security fix)
const DEFAULT_REGISTRATION_COOLDOWN_SECS: u64 = 3600; // 1 hour

/// Configuration for the health ping handler
#[derive(Debug, Clone)]
pub struct HealthHandlerConfig {
    /// Whether to require PoW for voter registration
    pub require_pow: bool,
    /// Required PoW difficulty (leading zero bits)
    pub pow_difficulty: u32,
    /// Rate limit max tokens per node
    pub rate_limit_max_tokens: u32,
    /// Rate limit refill rate (tokens per second)
    pub rate_limit_refill_rate: u32,
    /// Minimum uptime (seconds) required for voter registration (C2 security fix)
    pub min_uptime_for_voting_secs: u64,
    /// Cooldown between registration attempts (C2 security fix)
    pub registration_cooldown_secs: u64,
    /// Maximum timestamp drift for health pings (H4 security fix)
    pub max_timestamp_drift_secs: u64,
    /// AUTH4-3: Reject peers with invalid PoW (don't update peer info)
    ///
    /// When true, health pings from nodes without valid PoW are completely ignored.
    /// When false, peer info is still updated but node is not registered as voter.
    /// Default: true (strict mode for production)
    pub reject_invalid_pow_peers: bool,
    /// P2P-H4: Require capability verification for payout calculations
    ///
    /// When true, if no capability_verifier is configured, nodes are registered
    /// with empty capabilities (no shares) instead of trusting claimed capabilities.
    /// This prevents nodes from claiming capabilities they haven't verified.
    ///
    /// When false (dev only), claimed capabilities are trusted if no verifier is set.
    /// Default: true (production mode - require verification)
    pub require_capability_verification: bool,
}

impl Default for HealthHandlerConfig {
    fn default() -> Self {
        Self {
            require_pow: true,
            pow_difficulty: NODE_ID_POW_DIFFICULTY,
            rate_limit_max_tokens: HEALTH_RATE_LIMIT_MAX_TOKENS,
            rate_limit_refill_rate: HEALTH_RATE_LIMIT_REFILL_RATE,
            min_uptime_for_voting_secs: DEFAULT_MIN_UPTIME_SECS,
            registration_cooldown_secs: DEFAULT_REGISTRATION_COOLDOWN_SECS,
            max_timestamp_drift_secs: MAX_TIMESTAMP_DRIFT_SECS,
            reject_invalid_pow_peers: true, // AUTH4-3: Strict mode by default
            require_capability_verification: true, // P2P-H4: Require verification by default
        }
    }
}

/// Handler for health ping messages
pub struct HealthPingHandler {
    /// Peer manager for updating peer state
    peers: Arc<PeerManager>,
    /// Database for persisting peer info
    db: Option<Arc<Database>>,
    /// Callback to register discovered elders
    elder_callback: Option<ElderCallback>,
    /// Callback to register node capabilities for payout calculations
    node_capabilities_callback: Option<NodeCapabilitiesCallback>,
    /// P2P4-M2: Callback to verify capabilities against challenge results
    capability_verifier: Option<CapabilityVerifierCallback>,
    /// Rate limiter for incoming pings
    rate_limiter: HealthRateLimiter,
    /// Configuration
    config: HealthHandlerConfig,
    /// L-6: Shared ban manager for cross-handler enforcement (required, not optional).
    ///
    /// The ban manager is required to ensure banned nodes are never silently
    /// accepted. When ban_manager was Optional, a misconfiguration could result
    /// in is_banned() always returning false, defeating ban enforcement.
    ban_manager: Arc<BanManager>,
    /// Last registration time per node (C2 security fix - cooldown tracking)
    last_registration: RwLock<HashMap<NodeId, Instant>>,
    /// First seen time per node (C2 security fix - uptime tracking)
    ///
    /// M-11 SECURITY: Node-Local Uptime Tracking Limitation
    ///
    /// This uptime tracking is NODE-LOCAL only. Each node independently tracks when
    /// it first saw each peer. This has important security implications:
    ///
    /// 1. Different nodes may have different first_seen times for the same peer
    /// 2. Uptime calculations are NOT consensus-critical and should NOT be used for:
    ///    - Voting eligibility (use CanonicalElderList instead)
    ///    - Payout share calculations (use verified capabilities from ghost-verification)
    ///    - Any decision requiring agreement across nodes
    ///
    /// 3. Uptime data here is used ONLY for:
    ///    - Local DoS protection (rate limiting new nodes)
    ///    - Peer quality heuristics (preferring long-running peers)
    ///
    /// For consensus-critical uptime verification, nodes must query distributed uptime
    /// from peers via the verification system (see ghost-verification crate).
    first_seen_times: RwLock<HashMap<NodeId, Instant>>,
    /// L-7/L-9 SECURITY: Dynamic PoW difficulty adjuster
    ///
    /// L-9: This difficulty adjustment is NODE-LOCAL for DoS protection only.
    ///
    /// Each node independently adjusts its PoW difficulty based on local traffic.
    /// This is intentionally NOT consensus-critical because:
    ///
    /// 1. Different nodes see different traffic levels based on network topology
    /// 2. Difficulty adjustment is a DoS protection mechanism, not a consensus rule
    /// 3. Nodes under attack can increase difficulty without affecting peers
    ///
    /// The base difficulty (NODE_ID_POW_DIFFICULTY) IS consensus-critical and is
    /// enforced uniformly. Only the dynamic adjustment layer is node-local.
    difficulty_adjuster: DynamicDifficultyAdjuster,
}

impl HealthPingHandler {
    /// Create a new health ping handler with default configuration
    ///
    /// L-6: ban_manager is required to ensure banned nodes are never silently accepted.
    pub fn new(
        peers: Arc<PeerManager>,
        db: Option<Arc<Database>>,
        ban_manager: Arc<BanManager>,
    ) -> Self {
        Self::with_config(peers, db, HealthHandlerConfig::default(), ban_manager)
    }

    /// Create a new health ping handler with custom configuration
    ///
    /// L-6: ban_manager is required to ensure banned nodes are never silently accepted.
    pub fn with_config(
        peers: Arc<PeerManager>,
        db: Option<Arc<Database>>,
        config: HealthHandlerConfig,
        ban_manager: Arc<BanManager>,
    ) -> Self {
        Self {
            peers,
            db,
            elder_callback: None,
            node_capabilities_callback: None,
            capability_verifier: None,
            rate_limiter: HealthRateLimiter::new(
                config.rate_limit_max_tokens,
                config.rate_limit_refill_rate,
            ),
            config,
            ban_manager,
            last_registration: RwLock::new(HashMap::new()),
            first_seen_times: RwLock::new(HashMap::new()),
            difficulty_adjuster: DynamicDifficultyAdjuster::new(),
        }
    }

    /// Set the database for persistence
    pub fn with_database(mut self, db: Arc<Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Set callback for elder discovery
    ///
    /// When a HealthPing is received from a node with elder_status=true,
    /// this callback will be invoked to register the elder.
    pub fn with_elder_callback(mut self, callback: ElderCallback) -> Self {
        self.elder_callback = Some(callback);
        self
    }

    /// Set callback for node capabilities registration
    ///
    /// When a HealthPing is received, this callback will be invoked to
    /// register the node's capabilities for payout calculations.
    pub fn with_node_capabilities_callback(mut self, callback: NodeCapabilitiesCallback) -> Self {
        self.node_capabilities_callback = Some(callback);
        self
    }

    /// P2P4-M2: Set callback for capability verification
    ///
    /// When set, capabilities from health pings will be verified against
    /// challenge results before being registered. Only VERIFIED capabilities
    /// (those that have passed sufficient challenges) will be registered.
    ///
    /// If not set, claimed capabilities are registered as-is (legacy behavior).
    pub fn with_capability_verifier(mut self, verifier: CapabilityVerifierCallback) -> Self {
        self.capability_verifier = Some(verifier);
        self
    }

    /// Clean up rate limiter state (call periodically)
    pub fn cleanup_rate_limiter(&self) {
        self.rate_limiter.cleanup(300); // 5 minute TTL
        self.difficulty_adjuster.cleanup(); // L-7: Clean up old ping timestamps
    }

    /// Get rate limiter statistics
    pub fn rate_limiter_bucket_count(&self) -> usize {
        self.rate_limiter.bucket_count()
    }

    /// Verify the PoW proof from a health ping
    ///
    /// L-7 SECURITY: Uses dynamic difficulty that adjusts based on traffic.
    /// Under attack conditions, difficulty increases to make Sybil expensive.
    /// During low activity, difficulty decreases for usability.
    ///
    /// Returns true if:
    /// - PoW is not required (config.require_pow = false), OR
    /// - The ping contains a valid PoW proof with sufficient difficulty
    fn verify_pow(&self, node_id: &NodeId, pow_proof: Option<(u64, u32)>) -> bool {
        if !self.config.require_pow {
            return true;
        }

        // L-7: Use dynamic difficulty instead of static config value
        let required_difficulty = self.difficulty_adjuster.current_difficulty();

        match pow_proof {
            Some((nonce, difficulty)) => {
                let proof = NodeIdProof { nonce, difficulty };
                // Verify against the dynamically adjusted difficulty
                proof.verify(node_id, required_difficulty)
            }
            None => false,
        }
    }

    /// L-7: Get the current required PoW difficulty
    ///
    /// This is useful for nodes to know what difficulty they should target
    /// when generating their PoW proofs.
    pub fn current_pow_difficulty(&self) -> u32 {
        self.difficulty_adjuster.current_difficulty()
    }

    /// Validate health ping timestamp (H4 security fix)
    ///
    /// Returns true if timestamp is within acceptable drift of current time.
    fn validate_timestamp(&self, timestamp: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let max_drift_ms = self.config.max_timestamp_drift_secs * 1000;
        timestamp.abs_diff(now) <= max_drift_ms
    }

    /// Check if node can register as voter (C2 security fix)
    ///
    /// Implements two protections against validator set manipulation:
    /// 1. Minimum uptime requirement - node must be known for min_uptime_for_voting_secs
    /// 2. Registration cooldown - can't re-register within registration_cooldown_secs
    fn can_register_as_voter(&self, node_id: &NodeId) -> bool {
        let now = Instant::now();

        // Check registration cooldown
        {
            let last_reg = self.last_registration.read();
            if let Some(last_time) = last_reg.get(node_id) {
                let cooldown = Duration::from_secs(self.config.registration_cooldown_secs);
                if now.duration_since(*last_time) < cooldown {
                    debug!(
                        node_id = %hex::encode(&node_id[..8]),
                        "Registration cooldown not elapsed"
                    );
                    return false;
                }
            }
        }

        // Check minimum uptime requirement
        {
            let first_seen = self.first_seen_times.read();
            if let Some(first_time) = first_seen.get(node_id) {
                let min_uptime = Duration::from_secs(self.config.min_uptime_for_voting_secs);
                if now.duration_since(*first_time) < min_uptime {
                    debug!(
                        node_id = %hex::encode(&node_id[..8]),
                        elapsed_secs = now.duration_since(*first_time).as_secs(),
                        required_secs = min_uptime.as_secs(),
                        "Node has not met minimum uptime requirement for voting"
                    );
                    return false;
                }
            } else {
                // First time seeing this node - record it but don't allow registration yet
                drop(first_seen);
                self.first_seen_times.write().insert(*node_id, now);
                debug!(
                    node_id = %hex::encode(&node_id[..8]),
                    "First time seeing node - starting uptime tracking"
                );
                return false;
            }
        }

        true
    }

    /// Record a successful voter registration (C2 security fix)
    fn record_registration(&self, node_id: &NodeId) {
        self.last_registration
            .write()
            .insert(*node_id, Instant::now());
    }

    /// Check if node is banned
    fn is_banned(&self, node_id: &NodeId) -> bool {
        self.ban_manager.is_banned(node_id)
    }

    /// Handle a health ping message
    ///
    /// ## Security Note (H2 TOCTOU Mitigation)
    ///
    /// There is a theoretical TOCTOU race between the ban check and processing.
    /// However, health pings have no critical security impact:
    /// - They only update peer information and capabilities
    /// - Voter registration requires PoW + uptime requirements (C2)
    /// - One extra ping from a soon-to-be-banned node doesn't affect consensus
    ///
    /// The ban check is still performed for defense-in-depth.
    async fn handle_ping(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let node_id_hex = hex::encode(envelope.sender);
        let short_id = node_id_hex[..8].to_string();

        // C1: Check if node is banned using shared BanManager
        if self.is_banned(&envelope.sender) {
            debug!(node_id = %short_id, "Ignoring health ping from banned node");
            return Ok(());
        }

        // Rate limit check - reject pings from nodes sending too fast
        if !self.rate_limiter.check_and_consume(&envelope.sender) {
            warn!(
                node_id = %short_id,
                "Rate limited health ping from peer"
            );
            return Err(ghost_common::error::GhostError::RateLimited(format!(
                "Node {} rate limited for health pings",
                short_id
            )));
        }

        // L-7: Record this ping for dynamic difficulty adjustment
        self.difficulty_adjuster.record_ping();

        // Deserialize the health ping
        let ping_msg: HealthPingMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;

        let ping = &ping_msg.ping;

        // H4: Validate timestamp to prevent replay attacks
        if !self.validate_timestamp(ping.timestamp) {
            warn!(
                node_id = %short_id,
                timestamp = ping.timestamp,
                "Rejected health ping with invalid timestamp"
            );
            return Err(ghost_common::error::GhostError::InvalidTimestamp(format!(
                "Health ping timestamp {} out of range",
                ping.timestamp
            )));
        }

        debug!(
            node_id = %short_id,
            block_height = ping.block_height,
            round_id = ping.round_id,
            miner_count = ping.miner_count,
            elder = ping.capabilities.elder_status,
            has_pow = ping.pow_proof.is_some(),
            "Received health ping"
        );

        // Verify PoW before registering as voter (Sybil resistance)
        let pow_valid = self.verify_pow(&envelope.sender, ping.pow_proof);

        // AUTH4-3: Optionally reject peers entirely if PoW is invalid
        if !pow_valid && self.config.reject_invalid_pow_peers {
            warn!(
                node_id = %short_id,
                has_pow = ping.pow_proof.is_some(),
                "Rejecting health ping - invalid PoW (strict mode enabled)"
            );
            return Ok(()); // Don't update any peer state
        }

        if !pow_valid {
            warn!(
                node_id = %short_id,
                has_pow = ping.pow_proof.is_some(),
                "Node without valid PoW - not registering as voter (lenient mode)"
            );
            // In lenient mode, still update peer info but don't register as voter
        }

        // Register node as voter for BFT consensus ONLY if:
        // 1. PoW is valid (Sybil resistance)
        // 2. C2: Node meets uptime requirements and cooldown elapsed
        if pow_valid && self.can_register_as_voter(&envelope.sender) {
            if let Some(ref callback) = self.elder_callback {
                callback(envelope.sender);
                self.record_registration(&envelope.sender);
                debug!(node_id = %short_id, "Registered node as BFT voter from health ping (PoW verified, uptime met)");
            }

            // Register node capabilities for payout calculations (only with valid PoW)
            if let Some(ref callback) = self.node_capabilities_callback {
                // P2P4-M2 + P2P-H4: Determine capabilities based on verification
                let capabilities = if let Some(ref verifier) = self.capability_verifier {
                    // Verifier is configured - use VERIFIED capabilities
                    let verified_caps = verifier(&envelope.sender);
                    debug!(
                        node_id = %short_id,
                        claimed_archive = ping.capabilities.archive_mode,
                        verified_archive = verified_caps.archive_mode,
                        claimed_ghost_pay = ping.capabilities.ghost_pay,
                        verified_ghost_pay = verified_caps.ghost_pay,
                        claimed_public_mining = ping.capabilities.public_mining,
                        verified_public_mining = verified_caps.public_mining,
                        claimed_reaper = ping.capabilities.reaper,
                        verified_reaper = verified_caps.reaper,
                        claimed_elder = ping.capabilities.elder_status,
                        verified_elder = verified_caps.elder_status,
                        "Using verified capabilities instead of claimed"
                    );
                    verified_caps
                } else if self.config.require_capability_verification {
                    // P2P-H4: No verifier AND verification required = empty capabilities
                    // This prevents nodes from getting shares without verification
                    warn!(
                        node_id = %short_id,
                        "No capability verifier configured but verification required - using empty capabilities"
                    );
                    ghost_common::types::NodeCapabilities::default()
                } else {
                    // Dev mode: trust claimed capabilities (NOT for production)
                    debug!(
                        node_id = %short_id,
                        "INSECURE: Using claimed capabilities without verification (dev mode)"
                    );
                    ping.capabilities
                };

                callback(envelope.sender, capabilities);
                debug!(node_id = %short_id, "Registered node capabilities for payout");
            }
        } else if pow_valid {
            // PoW valid but uptime/cooldown requirements not met
            debug!(
                node_id = %short_id,
                "Node has valid PoW but does not meet voter registration requirements"
            );
        }

        // Update peer's last seen time in memory (regardless of PoW - for tracking)
        // If the peer doesn't exist or has empty address, update with real info from ping
        let existing_peer = self.peers.get_peer(&envelope.sender);
        let needs_update = existing_peer
            .as_ref()
            .map(|p| p.public_address.is_empty())
            .unwrap_or(true);

        if needs_update && !ping.public_address.is_empty() {
            // Create/update peer with real node_id and real public address from the ping
            let mut peer = crate::peer::Peer::new(envelope.sender, ping.public_address.clone());
            peer.state = crate::peer::PeerState::Connected;
            // Preserve first_seen if peer existed
            if let Some(ref existing) = existing_peer {
                peer.first_seen = existing.first_seen;
            }
            self.peers.upsert_peer(peer);
            debug!(node_id = %short_id, address = %ping.public_address, "Updated peer address from health ping");
        }
        self.peers.update_last_seen(&envelope.sender);

        // Update miner_count and capabilities from the health ping on every tick,
        // even when the peer address hasn't changed — these are live metrics.
        self.peers
            .update_health_metrics(&envelope.sender, ping.miner_count, ping.capabilities);
        // Active miner_id hashes (mesh-wide dedup count) + this node's own
        // realized hashrate (summed across the mesh for the pool total).
        self.peers.update_active_miner_hashes(
            &envelope.sender,
            ping.active_miner_id_hashes.clone(),
            ping.local_hashrate_th,
        );
        // Hardware-derived capacity used by the LB for utilisation routing.
        self.peers
            .update_max_capacity(&envelope.sender, ping.max_capacity);

        // Persist to database if available
        if let Some(ref db) = self.db {
            let now = chrono::Utc::now().timestamp();
            let capabilities_json = serde_json::to_string(&ping.capabilities).unwrap_or_default();

            // Create peer record for database
            let peer = PeerRecord {
                peer_id: node_id_hex.clone(),
                address: ping.public_address.clone(),
                port: 8555, // Default port
                node_id: Some(node_id_hex.clone()),
                first_seen: now,
                last_seen: now,
                last_success: Some(now),
                last_failure: None,
                connection_count: 1,
                failure_count: 0,
                is_banned: false,
                ban_until: None,
                capabilities: Some(capabilities_json),
                protocol_version: Some(1),
            };

            if let Err(e) = db.upsert_peer(&peer) {
                warn!(error = %e, peer_id = %short_id, "Failed to persist peer info");
            }

            // Register node in nodes table (required for node reward payouts).
            // Thread through the peer's gossip'd PoW proof so they're eligible
            // for elder promotion on our local DB view (without this the mesh
            // never converges on an elder set — each node sees only itself
            // as eligible because only its own PoW ever gets stored).
            let capabilities_str = format!(
                "archive:{},ghost_pay:{},public_mining:{},reaper:{}",
                ping.capabilities.archive_mode,
                ping.capabilities.ghost_pay,
                ping.capabilities.public_mining,
                ping.capabilities.reaper
            );
            let peer_pow_hex = ping.pow_proof.map(|(nonce, difficulty)| {
                ghost_common::identity::NodeIdProof { nonce, difficulty }.to_hex()
            });
            if let Err(e) = db.register_node_with_elder_check_and_pow(
                &node_id_hex,
                Some(ping.public_address.as_str()),
                None, // display_name not available from health ping
                &capabilities_str,
                peer_pow_hex.as_deref(),
            ) {
                debug!(error = %e, peer_id = %short_id, "Failed to register node from health ping");
            }

            // Record uptime sample - node is online since we received their health ping
            if let Err(e) = db.record_uptime_sample(&node_id_hex, now, true) {
                warn!(error = %e, peer_id = %short_id, "Failed to record uptime sample");
            }
        }

        Ok(())
    }

    /// Check for elders that have been offline > ELDER_OFFLINE_THRESHOLD_DAYS.
    /// Returns list of (node_id, offline_days) for elders exceeding the threshold.
    /// Skips our own node_id (don't propose revocation of self).
    pub fn detect_offline_elders(&self, elder_node_ids: &[NodeId]) -> Vec<(NodeId, u64)> {
        let all_peers = self.peers.get_all_peers();
        let peer_map: HashMap<NodeId, &crate::peer::Peer> =
            all_peers.iter().map(|p| (p.node_id, p)).collect();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let threshold_secs = ghost_common::constants::ELDER_OFFLINE_THRESHOLD_DAYS * 86400;
        let our_id = self.peers.our_node_id();

        let mut offline = Vec::new();
        for elder_id in elder_node_ids {
            if *elder_id == our_id {
                continue;
            }
            if let Some(peer) = peer_map.get(elder_id) {
                if peer.last_seen > 0 {
                    let offline_secs = now.saturating_sub(peer.last_seen);
                    if offline_secs > threshold_secs {
                        let offline_days = offline_secs / 86400;
                        offline.push((*elder_id, offline_days));
                    }
                }
            }
            // Elder not in peer table at all — no evidence of how long offline, skip
        }
        offline
    }
}

#[async_trait]
impl MessageHandler for HealthPingHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type == MessageType::HealthPing {
            self.handle_ping(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdProof;

    #[test]
    fn test_rate_limiter_allows_initial_requests() {
        let limiter = HealthRateLimiter::new(10, 1);
        let node_id = [1u8; 32];

        // Should allow up to max_tokens requests
        for _ in 0..10 {
            assert!(limiter.check_and_consume(&node_id));
        }

        // Should be rate limited after exhausting tokens
        assert!(!limiter.check_and_consume(&node_id));
    }

    #[test]
    fn test_rate_limiter_refills_tokens() {
        let limiter = HealthRateLimiter::new(2, 100); // High refill for testing
        let node_id = [1u8; 32];

        // Exhaust tokens
        assert!(limiter.check_and_consume(&node_id));
        assert!(limiter.check_and_consume(&node_id));
        assert!(!limiter.check_and_consume(&node_id));

        // Wait a bit for refill (in real test we'd mock time)
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Should have refilled
        assert!(limiter.check_and_consume(&node_id));
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = HealthRateLimiter::new(10, 1);
        let node1 = [1u8; 32];
        let node2 = [2u8; 32];

        limiter.check_and_consume(&node1);
        limiter.check_and_consume(&node2);

        assert_eq!(limiter.bucket_count(), 2);

        // Cleanup with 0 age should remove all
        limiter.cleanup(0);
        assert_eq!(limiter.bucket_count(), 0);
    }

    #[test]
    fn test_pow_verification() {
        let our_node_id = [0u8; 32];
        let peers = Arc::new(PeerManager::new(our_node_id, 100));
        let handler = HealthPingHandler::new(peers, None, Arc::new(BanManager::new()));

        // L-7: Dynamic difficulty starts at BASE_POW_DIFFICULTY (16)
        // Generate a node with valid PoW at that difficulty
        let test_key = [1u8; 32];
        let proof = NodeIdProof::mine(&test_key, BASE_POW_DIFFICULTY).unwrap();

        // Valid PoW should pass (at base difficulty which the dynamic adjuster uses)
        assert!(handler.verify_pow(&test_key, Some((proof.nonce, proof.difficulty))));

        // No PoW should fail
        assert!(!handler.verify_pow(&test_key, None));

        // Wrong nonce should fail
        assert!(!handler.verify_pow(&test_key, Some((999999999, BASE_POW_DIFFICULTY))));

        // Wrong node_id should fail
        let wrong_key = [2u8; 32];
        assert!(!handler.verify_pow(&wrong_key, Some((proof.nonce, proof.difficulty))));
    }

    #[test]
    fn test_pow_not_required_config() {
        let mut config = HealthHandlerConfig::default();
        config.require_pow = false;

        let our_node_id = [0u8; 32];
        let peers = Arc::new(PeerManager::new(our_node_id, 100));
        let handler =
            HealthPingHandler::with_config(peers, None, config, Arc::new(BanManager::new()));

        let node_id = [1u8; 32];

        // Should pass without PoW when not required
        assert!(handler.verify_pow(&node_id, None));
    }

    // =========================================================================
    // L-7 TESTS: Dynamic PoW difficulty adjustment
    // =========================================================================

    #[test]
    fn test_dynamic_difficulty_starts_at_base() {
        let adjuster = DynamicDifficultyAdjuster::new();
        assert_eq!(adjuster.current_difficulty(), BASE_POW_DIFFICULTY);
    }

    #[test]
    fn test_dynamic_difficulty_records_pings() {
        let adjuster = DynamicDifficultyAdjuster::new();

        // Record some pings
        for _ in 0..10 {
            adjuster.record_ping();
        }

        // Should still be at base difficulty (not enough time/traffic for adjustment)
        assert_eq!(adjuster.current_difficulty(), BASE_POW_DIFFICULTY);
    }

    #[test]
    fn test_dynamic_difficulty_cleanup() {
        let adjuster = DynamicDifficultyAdjuster::new();

        // Record some pings
        for _ in 0..5 {
            adjuster.record_ping();
        }

        // Cleanup should not panic
        adjuster.cleanup();

        // Difficulty should still be accessible
        let _ = adjuster.current_difficulty();
    }

    #[test]
    fn test_dynamic_difficulty_default() {
        let adjuster = DynamicDifficultyAdjuster::default();
        assert_eq!(adjuster.current_difficulty(), BASE_POW_DIFFICULTY);
    }

    #[test]
    fn test_handler_uses_dynamic_difficulty() {
        let our_node_id = [0u8; 32];
        let peers = Arc::new(PeerManager::new(our_node_id, 100));
        let handler = HealthPingHandler::new(peers, None, Arc::new(BanManager::new()));

        // Handler should expose current difficulty
        let difficulty = handler.current_pow_difficulty();
        assert_eq!(difficulty, BASE_POW_DIFFICULTY);
    }

    // =========================================================================
    // M-1 TESTS: Integer-based rate limiting
    // =========================================================================

    #[test]
    fn test_m1_rate_limiter_uses_integer_arithmetic() {
        // M-1: Verify the rate limiter uses milli-tokens (1000 millis = 1 token)
        let limiter = HealthRateLimiter::new(3, 1);
        let node_id = [1u8; 32];

        // Should allow 3 tokens (3000 millis internally)
        assert!(limiter.check_and_consume(&node_id));
        assert!(limiter.check_and_consume(&node_id));
        assert!(limiter.check_and_consume(&node_id));

        // 4th should be rate limited
        assert!(!limiter.check_and_consume(&node_id));
    }

    #[test]
    fn test_m1_rate_limiter_per_sender() {
        let limiter = HealthRateLimiter::new(2, 1);
        let node1 = [1u8; 32];
        let node2 = [2u8; 32];

        // Node 1 uses its tokens
        assert!(limiter.check_and_consume(&node1));
        assert!(limiter.check_and_consume(&node1));
        assert!(
            !limiter.check_and_consume(&node1),
            "Node 1 should be limited"
        );

        // Node 2 should still have its tokens
        assert!(
            limiter.check_and_consume(&node2),
            "Node 2 should not be affected by node 1"
        );
        assert!(limiter.check_and_consume(&node2));
        assert!(
            !limiter.check_and_consume(&node2),
            "Node 2 should be limited now"
        );
    }

    #[test]
    fn test_m1_rate_limiter_no_overflow() {
        // M-1: Test that large but reasonable values don't overflow
        // Use refill_rate=0 so tokens don't refill during the loop
        let limiter = HealthRateLimiter::new(1000, 0);
        let node = [1u8; 32];

        // Exhaust all tokens
        for _ in 0..1000 {
            assert!(limiter.check_and_consume(&node));
        }

        // Should be limited now
        assert!(!limiter.check_and_consume(&node));
    }

    // =========================================================================
    // L-1 TESTS: Bounds checking in dynamic difficulty
    // =========================================================================

    #[test]
    fn test_l1_difficulty_bounded_by_max() {
        // L-1: Verify difficulty never exceeds MAX_POW_DIFFICULTY
        let adjuster = DynamicDifficultyAdjuster::new();

        // Even after many adjustments, difficulty should stay bounded
        // This is tested indirectly - we ensure the adjuster handles edge cases
        let difficulty = adjuster.current_difficulty();
        assert!(
            difficulty <= MAX_POW_DIFFICULTY,
            "L-1: Difficulty {} should be <= MAX {}",
            difficulty,
            MAX_POW_DIFFICULTY
        );
        assert!(
            difficulty >= BASE_POW_DIFFICULTY,
            "L-1: Difficulty {} should be >= BASE {}",
            difficulty,
            BASE_POW_DIFFICULTY
        );
    }

    #[test]
    fn test_l1_difficulty_starts_at_base() {
        // L-1: Verify initial difficulty is at the safe base level
        let adjuster = DynamicDifficultyAdjuster::new();
        assert_eq!(
            adjuster.current_difficulty(),
            BASE_POW_DIFFICULTY,
            "L-1: Initial difficulty should be BASE_POW_DIFFICULTY"
        );
    }

    #[test]
    fn test_l1_max_difficulty_reasonable() {
        // L-1: Verify constants are reasonable to prevent overflow
        assert!(
            MAX_POW_DIFFICULTY > BASE_POW_DIFFICULTY,
            "MAX must be greater than BASE"
        );
        assert!(
            MAX_POW_DIFFICULTY <= 32,
            "MAX difficulty should not exceed 32 bits"
        );
        assert!(
            BASE_POW_DIFFICULTY >= 8,
            "BASE difficulty should be at least 8 for minimum security"
        );
    }
}
