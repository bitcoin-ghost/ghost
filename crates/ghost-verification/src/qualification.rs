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
//| FILE: qualification.rs                                                                                               |
//|======================================================================================================================|

//! Qualified capability provider
//!
//! Provides VERIFIED capabilities for payout calculations based on:
//! 1. Uptime gatekeeper: 95% uptime over trailing 7 days
//! 2. Per-capability verification: 10+ challenges with 95% pass rate

use std::sync::Arc;
use tracing::{info, warn};

use ghost_common::types::{NodeCapabilities, NodeId};
use ghost_storage::Database;

/// Seconds in a day
const SECONDS_PER_DAY: i64 = 86_400;

/// M-15: Base minimum unique challengers required for capability qualification
/// This prevents Sybil attacks where colluding nodes verify each other.
/// Increased from 5 to 10 to require more diverse verification sources.
/// MED-VER-6: This is the base value; actual requirement scales with network size
const BASE_MIN_UNIQUE_CHALLENGERS: u32 = 10;

/// MED-VER-6: Maximum unique challengers required (cap for very large networks)
const MAX_MIN_UNIQUE_CHALLENGERS: u32 = 50;

/// Decode a 32-byte `NodeId` from a hex string, or `None` if malformed/short.
fn decode_node_id(hex_id: &str) -> Option<NodeId> {
    let bytes = hex::decode(hex_id).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[..32]);
    Some(id)
}

/// Configuration for capability qualification
///
/// AUTH4-L3: Per-capability pass rates allow different thresholds based on
/// the difficulty/importance of each capability verification.
#[derive(Debug, Clone)]
pub struct QualificationConfig {
    /// Minimum number of challenges required per capability
    pub min_challenges: u32,
    /// C-2: Minimum number of unique challengers required per capability
    pub min_unique_challengers: u32,
    /// Minimum pass rate for Archive capability (0.0 to 1.0)
    pub archive_pass_rate: f64,
    /// Minimum pass rate for GhostPay capability (0.0 to 1.0)
    pub ghostpay_pass_rate: f64,
    /// Minimum pass rate for Stratum/Public Mining capability (0.0 to 1.0)
    pub stratum_pass_rate: f64,
    /// Minimum pass rate for Bitcoin Pure/Policy capability (0.0 to 1.0)
    pub policy_pass_rate: f64,
    /// Lookback period in days for uptime and challenges
    pub lookback_days: u32,
    /// Minimum uptime percentage required (gatekeeper)
    pub min_uptime: f64,
}

impl QualificationConfig {
    /// Get the pass rate for a specific capability type
    pub fn pass_rate_for(&self, capability: &str) -> f64 {
        match capability {
            "archive" => self.archive_pass_rate,
            "ghostpay" => self.ghostpay_pass_rate,
            "stratum" => self.stratum_pass_rate,
            "policy" => self.policy_pass_rate,
            _ => self.archive_pass_rate, // Default to archive rate
        }
    }
}

impl Default for QualificationConfig {
    fn default() -> Self {
        use ghost_common::constants::{
            ARCHIVE_PASS_RATE, GHOSTPAY_PASS_RATE, MIN_CHALLENGES_FOR_QUALIFICATION,
            POLICY_PASS_RATE, STRATUM_PASS_RATE, UPTIME_GATEKEEPER_THRESHOLD, UPTIME_WINDOW_DAYS,
        };
        Self {
            min_challenges: MIN_CHALLENGES_FOR_QUALIFICATION as u32,
            min_unique_challengers: BASE_MIN_UNIQUE_CHALLENGERS, // MED-VER-6: Base value, scaled at runtime
            archive_pass_rate: ARCHIVE_PASS_RATE,
            ghostpay_pass_rate: GHOSTPAY_PASS_RATE,
            stratum_pass_rate: STRATUM_PASS_RATE,
            policy_pass_rate: POLICY_PASS_RATE,
            lookback_days: UPTIME_WINDOW_DAYS as u32,
            min_uptime: UPTIME_GATEKEEPER_THRESHOLD / 100.0, // 95% -> 0.95
        }
    }
}

/// Provides qualified (verified) capabilities for nodes
///
/// H-14: Maximum age for cached network size (1 hour in seconds)
const NETWORK_SIZE_CACHE_MAX_AGE_SECS: u64 = 3600;

/// H-14: Cached network size with timestamp for expiration
struct CachedNetworkSize {
    size: usize,
    /// Timestamp when cached (seconds since epoch)
    timestamp: u64,
}

/// This replaces CLAIMED capabilities with VERIFIED capabilities
/// based on challenge results and uptime tracking.
///
/// M-7 FIX: Includes cached network size for fallback on DB failures
/// H-14 FIX: Cache now includes timestamp for expiration (max 1 hour)
pub struct QualifiedCapabilityProvider {
    /// Database for looking up challenge results and uptime
    db: Arc<Database>,
    /// Qualification configuration
    config: QualificationConfig,
    /// M-7/H-14 FIX: Cached network size with timestamp for expiration
    /// Uses RwLock for thread-safe access with timestamp
    cached_network_size: parking_lot::RwLock<Option<CachedNetworkSize>>,
}

impl QualifiedCapabilityProvider {
    /// Create a new qualified capability provider
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            config: QualificationConfig::default(),
            // M-7/H-14 FIX: Initialize with empty cache
            cached_network_size: parking_lot::RwLock::new(None),
        }
    }

    /// Create with custom configuration
    pub fn with_config(db: Arc<Database>, config: QualificationConfig) -> Self {
        Self {
            db,
            config,
            cached_network_size: parking_lot::RwLock::new(None),
        }
    }

    /// Get current Unix timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// M-7/H-14 FIX: Get network size with fallback to cached value
    ///
    /// On DB success, updates the cache and returns the fresh value.
    /// On DB failure, returns the cached value with a warning if not expired.
    /// H-14: Cached values older than 1 hour are rejected (treated as empty).
    /// If cache is empty or expired, uses a conservative default (100 nodes).
    fn get_network_size_with_fallback(&self) -> usize {
        let now = Self::current_timestamp();

        match self.db.get_all_node_ids_with_payout() {
            Ok(ids) => {
                let size = ids.len();
                // Update cache on successful query with current timestamp
                let mut cache = self.cached_network_size.write();
                *cache = Some(CachedNetworkSize {
                    size,
                    timestamp: now,
                });
                size
            }
            Err(e) => {
                let cache = self.cached_network_size.read();
                if let Some(ref cached) = *cache {
                    // H-14 FIX: Check if cache is expired (older than 1 hour)
                    let age_secs = now.saturating_sub(cached.timestamp);
                    if age_secs <= NETWORK_SIZE_CACHE_MAX_AGE_SECS {
                        warn!(
                            cached_size = cached.size,
                            cache_age_secs = age_secs,
                            error = %e,
                            "M-7: DB failure for network size, using cached value"
                        );
                        return cached.size;
                    } else {
                        warn!(
                            cached_size = cached.size,
                            cache_age_secs = age_secs,
                            max_age = NETWORK_SIZE_CACHE_MAX_AGE_SECS,
                            error = %e,
                            "H-14: DB failure and cache expired, using conservative default"
                        );
                    }
                } else {
                    warn!(
                        error = %e,
                        "M-7: DB failure for network size with empty cache, using default (100)"
                    );
                }
                // No valid cache - use conservative default
                // 100 nodes gives min_unique = 13, which is reasonable
                100
            }
        }
    }

    /// MED-VER-5/MED-VER-6: Maximum network size for scaling calculation
    /// Cap at 1M nodes to prevent overflow and unreasonable scaling
    const MAX_NETWORK_SIZE: usize = 1_000_000;

    /// VER-8/MED-VER-6: Calculate scaled unique challenger requirement based on network size
    ///
    /// Scales with total node count to balance Sybil resistance with practical achievability:
    ///
    /// **VER-8 FIX**: For small networks, the minimum is now: max(3, min(10, network_size / 3))
    /// This ensures verification is possible even in small bootstrap networks while still
    /// providing meaningful Sybil resistance.
    ///
    /// Scaling behavior:
    /// - 3-9 nodes: 3 unique challengers (minimum viable Sybil resistance)
    /// - 10-29 nodes: 3-9 unique challengers (scales with network_size / 3)
    /// - 30-50 nodes: 10 unique challengers (base threshold)
    /// - 100 nodes: 13 unique challengers
    /// - 500 nodes: 19 unique challengers
    /// - 1000 nodes: 23 unique challengers
    /// - 5000+ nodes: 50 unique challengers (cap)
    ///
    /// Formula for large networks: min(MAX, BASE + sqrt(network_size / 10))
    /// Formula for small networks: max(3, min(10, network_size / 3))
    ///
    /// MED-VER-5 FIX: Added bounds check to prevent integer overflow.
    /// Network size is capped at 1M nodes.
    fn scaled_min_unique_challengers(&self, network_size: usize) -> u32 {
        // VER-8 FIX: For very small networks, scale down the requirement
        // to make verification achievable during network bootstrap.
        // Minimum is 3 to provide some Sybil resistance.
        const ABSOLUTE_MINIMUM: u32 = 3;

        if network_size < ABSOLUTE_MINIMUM as usize {
            // Network too small for meaningful verification
            return ABSOLUTE_MINIMUM;
        }

        // VER-8 FIX: For small networks (< 30 nodes), use network_size / 3
        // This allows a 9-node network to require 3 challengers,
        // and a 27-node network to require 9 challengers.
        if network_size < 30 {
            let small_net_min = (network_size / 3).max(ABSOLUTE_MINIMUM as usize);
            return (small_net_min as u32).min(BASE_MIN_UNIQUE_CHALLENGERS);
        }

        if network_size <= 50 {
            return BASE_MIN_UNIQUE_CHALLENGERS;
        }

        // MED-VER-5 FIX: Cap network size to prevent overflow
        let capped_size = network_size.min(Self::MAX_NETWORK_SIZE);

        let scaled =
            BASE_MIN_UNIQUE_CHALLENGERS as f64 + ((capped_size as f64) / 10.0).sqrt().floor();

        (scaled as u32).min(MAX_MIN_UNIQUE_CHALLENGERS)
    }

    /// Scale minimum challenge count based on network size.
    ///
    /// With daily unique constraints (one challenge per challenger per target per day),
    /// each node can receive at most (network_size - 1) challenges per day.
    /// For small networks, requiring 10 challenges is impossible within a single day.
    ///
    /// Scaling:
    /// - < 4 nodes: 3 (absolute minimum)
    /// - 4-10 nodes: network_size - 1 (max achievable per day)
    /// - 11+ nodes: min_challenges config value (protocol constant, easily achievable)
    fn scaled_min_challenges(&self, network_size: usize) -> u32 {
        const ABSOLUTE_MINIMUM: u32 = 3;
        if network_size <= ABSOLUTE_MINIMUM as usize {
            return ABSOLUTE_MINIMUM;
        }
        let max_per_day = (network_size - 1) as u32;
        max_per_day.min(self.config.min_challenges)
    }

    /// Get the lookback timestamp
    fn lookback_timestamp(&self) -> i64 {
        chrono::Utc::now().timestamp() - (self.config.lookback_days as i64 * SECONDS_PER_DAY)
    }

    /// Check if a node passes the uptime gatekeeper
    ///
    /// A node must have 95% uptime over the trailing 7 days before
    /// ANY capabilities count for payout shares.
    pub fn check_uptime_gatekeeper(&self, node_id: &NodeId) -> bool {
        let node_id_hex = hex::encode(node_id);
        let since = self.lookback_timestamp();

        match self.db.get_uptime_percent(&node_id_hex, since) {
            Ok(uptime) => {
                if uptime >= self.config.min_uptime {
                    info!(
                        node = %&node_id_hex[..8],
                        uptime = format!("{:.1}%", uptime * 100.0),
                        "DIAG: Node passes uptime gatekeeper"
                    );
                    true
                } else {
                    info!(
                        node = %&node_id_hex[..8],
                        uptime = format!("{:.1}%", uptime * 100.0),
                        required = format!("{:.1}%", self.config.min_uptime * 100.0),
                        "DIAG: Node fails uptime gatekeeper"
                    );
                    false
                }
            }
            Err(e) => {
                info!(
                    node = %&node_id_hex[..8],
                    error = %e,
                    "DIAG: Failed to get uptime - treating as 0"
                );
                false
            }
        }
    }

    /// Get qualified capabilities for a node
    ///
    /// Returns only capabilities that:
    /// 1. Pass the uptime gatekeeper (95% over 7 days)
    /// 2. Have 10+ challenges with 95% pass rate
    /// 3. C-2: Have 5+ unique challengers (Sybil prevention)
    ///
    /// Returns default (all false) capabilities if the node doesn't
    /// meet the requirements.
    pub fn get_qualified(&self, node_id: &NodeId) -> NodeCapabilities {
        let node_id_hex = hex::encode(node_id);
        let since = self.lookback_timestamp();

        // Log challenge stats for debugging (before gatekeeper check)
        let archive_stats = self
            .db
            .get_archive_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let policy_stats = self
            .db
            .get_policy_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let stratum_stats = self
            .db
            .get_stratum_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let ghostpay_stats = self
            .db
            .get_ghostpay_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));

        // C-2: Get unique challenger counts for Sybil prevention
        let archive_unique = self
            .db
            .get_archive_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);
        let policy_unique = self
            .db
            .get_policy_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);
        let stratum_unique = self
            .db
            .get_stratum_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);
        let ghostpay_unique = self
            .db
            .get_ghostpay_unique_challengers(&node_id_hex, since)
            .unwrap_or(0);

        // MED-VER-6 + M-7 FIX: Get network size with fallback to cached value
        // M-7: On DB failure, use cached network size instead of returning empty capabilities
        // This prevents transient DB issues from stalling all payouts
        let network_size = self.get_network_size_with_fallback();
        let min_unique_scaled = self.scaled_min_unique_challengers(network_size);

        let scaled_min_challenges = self.scaled_min_challenges(network_size);

        // AUTH4-L3 + MED-VER-6: Log per-capability pass rate requirements
        info!(
            node = %&node_id_hex[..8],
            archive = format!("{}/{}", archive_stats.0, archive_stats.1),
            policy = format!("{}/{}", policy_stats.0, policy_stats.1),
            stratum = format!("{}/{}", stratum_stats.0, stratum_stats.1),
            ghostpay = format!("{}/{}", ghostpay_stats.0, ghostpay_stats.1),
            archive_unique = archive_unique,
            policy_unique = policy_unique,
            stratum_unique = stratum_unique,
            ghostpay_unique = ghostpay_unique,
            min_challenges = self.config.min_challenges,
            scaled_min_challenges = scaled_min_challenges,
            min_unique = min_unique_scaled,
            network_size = network_size,
            archive_rate = format!("{:.0}%", self.config.archive_pass_rate * 100.0),
            ghostpay_rate = format!("{:.0}%", self.config.ghostpay_pass_rate * 100.0),
            "DIAG: Node challenge stats (scaled min_challenges and unique requirement)"
        );

        // GATEKEEPER: Check uptime first
        if !self.check_uptime_gatekeeper(node_id) {
            return NodeCapabilities::default(); // 0 shares if uptime < 95%
        }

        // VER-5 FIX: Reuse network_size from earlier query instead of calling again
        // The network_size variable was already set before the diagnostic log above.
        // Previously this queried get_network_size_with_fallback() twice unnecessarily.
        let min_unique = self.scaled_min_unique_challengers(network_size);

        // M-16 FIX: Get qualified capabilities with per-capability pass rates
        // Each capability type has its own threshold (e.g., GhostPay is 90%, Archive is 95%)
        // Use scaled min_challenges so small networks can qualify within a single day
        match self.db.get_qualified_capabilities_with_rates(
            &node_id_hex,
            since,
            scaled_min_challenges,
            self.config.archive_pass_rate,
            self.config.ghostpay_pass_rate,
            self.config.stratum_pass_rate,
            self.config.policy_pass_rate,
        ) {
            Ok(mut caps) => {
                // C-2 + MED-VER-6: Apply unique challengers requirement (Sybil prevention)
                // A capability is only qualified if challenges came from multiple independent nodes
                // The requirement now scales with network size for better Sybil resistance
                if archive_unique < min_unique {
                    if caps.archive_mode {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = archive_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: Archive capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.archive_mode = false;
                }
                if policy_unique < min_unique {
                    if caps.reaper {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = policy_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: Policy capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.reaper = false;
                }
                if stratum_unique < min_unique {
                    if caps.public_mining {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = stratum_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: Stratum capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.public_mining = false;
                }
                if ghostpay_unique < min_unique {
                    if caps.ghost_pay {
                        info!(
                            node = %&node_id_hex[..8],
                            unique = ghostpay_unique,
                            required = min_unique,
                            network_size = network_size,
                            "C-2/MED-VER-6: GhostPay capability disqualified - insufficient unique challengers"
                        );
                    }
                    caps.ghost_pay = false;
                }

                info!(
                    node = %&node_id_hex[..8],
                    archive = caps.archive_mode,
                    ghost_pay = caps.ghost_pay,
                    public_mining = caps.public_mining,
                    reaper = caps.reaper,
                    total_shares = caps.total_shares(),
                    "DIAG: Qualified capabilities result (after C-2 filter)"
                );
                caps
            }
            Err(e) => {
                // MED-VER-10: Log at warn level - this node won't receive capability-based payouts
                warn!(
                    node = %&node_id_hex[..8],
                    error = %e,
                    "MED-VER-10: Failed to get qualified capabilities - node receives 0 shares. \
                     If this persists, check database connectivity."
                );
                NodeCapabilities::default()
            }
        }
    }

    /// Get qualified capabilities for a node by hex string
    ///
    /// M-4 FIX: Now uses scaled_min_unique_challengers like get_qualified()
    /// M-10 FIX: Uses get_network_size_with_fallback() for cached fallback on DB failure
    pub fn get_qualified_by_hex(&self, node_id_hex: &str) -> NodeCapabilities {
        let since = self.lookback_timestamp();

        // GATEKEEPER: Check uptime first
        match self.db.get_uptime_percent(node_id_hex, since) {
            Ok(uptime) => {
                if uptime < self.config.min_uptime {
                    return NodeCapabilities::default();
                }
            }
            Err(_) => return NodeCapabilities::default(),
        }

        // M-4 + M-10 FIX: Get network size for scaled unique challenger requirement
        // M-10: Use get_network_size_with_fallback() for cached fallback on DB failure,
        // matching the behavior of get_qualified(). This prevents transient DB issues
        // from causing all nodes to return default capabilities.
        let network_size = self.get_network_size_with_fallback();
        let min_unique = self.scaled_min_unique_challengers(network_size);

        // C-2: Get unique challenger counts for Sybil prevention
        let archive_unique = self
            .db
            .get_archive_unique_challengers(node_id_hex, since)
            .unwrap_or(0);
        let policy_unique = self
            .db
            .get_policy_unique_challengers(node_id_hex, since)
            .unwrap_or(0);
        let stratum_unique = self
            .db
            .get_stratum_unique_challengers(node_id_hex, since)
            .unwrap_or(0);
        let ghostpay_unique = self
            .db
            .get_ghostpay_unique_challengers(node_id_hex, since)
            .unwrap_or(0);

        // VER-1 FIX: Get qualified capabilities with per-capability pass rates
        // Each capability type has its own threshold (e.g., GhostPay is 90%, Archive is 95%)
        // Use scaled min_challenges so small networks can qualify within a single day
        let scaled_min_challenges = self.scaled_min_challenges(network_size);
        let mut caps = self
            .db
            .get_qualified_capabilities_with_rates(
                node_id_hex,
                since,
                scaled_min_challenges,
                self.config.archive_pass_rate,
                self.config.ghostpay_pass_rate,
                self.config.stratum_pass_rate,
                self.config.policy_pass_rate,
            )
            .unwrap_or_default();

        // C-2 + M-4 FIX: Apply SCALED unique challengers requirement (Sybil prevention)
        if archive_unique < min_unique {
            caps.archive_mode = false;
        }
        if policy_unique < min_unique {
            caps.reaper = false;
        }
        if stratum_unique < min_unique {
            caps.public_mining = false;
        }
        if ghostpay_unique < min_unique {
            caps.ghost_pay = false;
        }

        caps
    }

    /// Get all nodes with qualified (verified) capabilities
    ///
    /// Returns Vec<(NodeId, shares)> for all known nodes that have
    /// verified capabilities. Used for payout calculations.
    ///
    /// Queries the `nodes` table (not `peers`) to include the local node.
    ///
    /// M-5 FIX: Now uses scaled_min_unique_challengers based on network size
    /// M-11 FIX: Updates network size cache for other methods to use as fallback
    /// H-14 FIX: Cache now includes timestamp for expiration
    pub fn get_all_qualified_nodes(&self) -> Vec<(NodeId, i32)> {
        let since = self.lookback_timestamp();
        let mut qualified_nodes = Vec::new();

        // Get all nodes with payout addresses from database (includes local node)
        // MED-VER-10: If this DB query fails, the returned empty list will cause
        // the payout handler to skip node reward distribution. This is fail-safe
        // (no incorrect payments) but may delay payouts until DB recovers.
        let node_ids = match self.db.get_all_node_ids_with_payout() {
            Ok(ids) => ids,
            Err(e) => {
                // MED-VER-10: Log at ERROR level since this affects payouts
                tracing::error!(
                    error = %e,
                    "MED-VER-10: PAYOUT IMPACT - Failed to get nodes for qualification. \
                     Node reward distribution will be empty until DB recovers. \
                     This is fail-safe but delays payouts."
                );
                return qualified_nodes;
            }
        };

        // M-5 + M-11 + H-14 FIX: Calculate scaled unique challenger requirement based on network size
        // M-11: Also update the cached network size so other methods (like get_qualified_by_hex)
        // can use it as a fallback if their DB queries fail
        // H-14: Include timestamp so cache can expire
        let network_size = node_ids.len();
        {
            let mut cache = self.cached_network_size.write();
            *cache = Some(CachedNetworkSize {
                size: network_size,
                timestamp: Self::current_timestamp(),
            });
        }
        let min_unique = self.scaled_min_unique_challengers(network_size);
        let scaled_min_challenges = self.scaled_min_challenges(network_size);

        info!(
            total_nodes = node_ids.len(),
            min_unique_challengers = min_unique,
            scaled_min_challenges = scaled_min_challenges,
            "DIAG: Checking qualification for all nodes with payout addresses (scaled requirements)"
        );

        // MED-VER-10: Track DB failures for logging
        let mut db_failures = 0u32;

        for node_id_hex in &node_ids {
            // GATEKEEPER: Check uptime first
            let uptime = match self.db.get_uptime_percent(node_id_hex, since) {
                Ok(u) => u,
                Err(e) => {
                    // MED-VER-10: Log individual failures at debug level, aggregate at end
                    tracing::debug!(
                        node = %&node_id_hex[..8.min(node_id_hex.len())],
                        error = %e,
                        "MED-VER-10: Failed to get uptime for node - skipping"
                    );
                    db_failures += 1;
                    continue;
                }
            };

            if uptime < self.config.min_uptime {
                info!(
                    node = %&node_id_hex[..8.min(node_id_hex.len())],
                    uptime = format!("{:.1}%", uptime * 100.0),
                    "DIAG: Node fails uptime gatekeeper"
                );
                continue; // Doesn't pass uptime gatekeeper
            }

            // C-2: Get unique challenger counts for Sybil prevention
            let archive_unique = self
                .db
                .get_archive_unique_challengers(node_id_hex, since)
                .unwrap_or(0);
            let policy_unique = self
                .db
                .get_policy_unique_challengers(node_id_hex, since)
                .unwrap_or(0);
            let stratum_unique = self
                .db
                .get_stratum_unique_challengers(node_id_hex, since)
                .unwrap_or(0);
            let ghostpay_unique = self
                .db
                .get_ghostpay_unique_challengers(node_id_hex, since)
                .unwrap_or(0);

            // Get qualified capabilities with per-capability pass rates
            // Each capability type has its own threshold (e.g., GhostPay is 90%, Archive is 95%)
            // Use scaled min_challenges so small networks can qualify within a single day
            let mut caps = self
                .db
                .get_qualified_capabilities_with_rates(
                    node_id_hex,
                    since,
                    scaled_min_challenges,
                    self.config.archive_pass_rate,
                    self.config.ghostpay_pass_rate,
                    self.config.stratum_pass_rate,
                    self.config.policy_pass_rate,
                )
                .unwrap_or_default();

            // C-2 + M-5 FIX: Apply SCALED unique challengers requirement (Sybil prevention)
            if archive_unique < min_unique {
                caps.archive_mode = false;
            }
            if policy_unique < min_unique {
                caps.reaper = false;
            }
            if stratum_unique < min_unique {
                caps.public_mining = false;
            }
            if ghostpay_unique < min_unique {
                caps.ghost_pay = false;
            }

            let shares = caps.total_shares();
            if shares > 0 {
                // Convert hex string to NodeId
                if let Ok(bytes) = hex::decode(node_id_hex) {
                    if bytes.len() >= 32 {
                        let mut node_id = [0u8; 32];
                        node_id.copy_from_slice(&bytes[..32]);

                        info!(
                            node = %&node_id_hex[..8],
                            shares = shares,
                            archive = caps.archive_mode,
                            reaper = caps.reaper,
                            "DIAG: Qualified node for payout"
                        );

                        qualified_nodes.push((node_id, shares));
                    }
                }
            }
        }

        // MED-VER-10: Log summary with DB failure count if any occurred
        if db_failures > 0 {
            warn!(
                total_nodes = node_ids.len(),
                qualified_nodes = qualified_nodes.len(),
                db_failures = db_failures,
                "MED-VER-10: Qualification complete with DB failures. \
                 Some nodes may not receive payouts due to failed uptime queries."
            );
        } else {
            info!(
                total_nodes = node_ids.len(),
                qualified_nodes = qualified_nodes.len(),
                "DIAG: Qualification complete"
            );
        }

        qualified_nodes
    }

    /// Deterministic, cutoff-anchored qualification over the converged ledger.
    ///
    /// The reward-path replacement for [`Self::get_all_qualified_nodes`]
    /// (Components B/C/F of node-reward determinism). It differs on every axis
    /// that made the live path unreproducible:
    /// - takes a fixed `cutoff_ts` (the proposal's agreed tip-change timestamp)
    ///   instead of reading `now()`, so the window is identical on every node;
    /// - reads the converged `verification_ledger` instead of the private,
    ///   eventually-consistent `*_challenges` tables;
    /// - drops the uptime gatekeeper entirely — a node that cannot answer
    ///   challenges simply fails the count/pass floor, so liveness is proven by
    ///   signed peer evidence rather than a private, non-convergent ping counter;
    /// - derives network size and the scaled thresholds from the passed node set
    ///   with no cache.
    ///
    /// Given a converged ledger, every node computes an identical result — which
    /// is exactly what lets the node split be independently recomputed and
    /// rejected on mismatch (Component E / GHOST-02). Window is
    /// `[cutoff − lookback, cutoff]`; `node_ids` is the deterministic node set
    /// (hex) that all nodes must agree on.
    ///
    /// NOTE: not yet on the live payout path — the proposer and the validator
    /// recompute switch to this behind a height gate only after convergence (A)
    /// has soaked, per the rollout order in the design doc.
    pub fn get_all_qualified_nodes_at_cutoff(
        &self,
        node_ids: &[String],
        cutoff_ts: i64,
    ) -> Vec<(NodeId, i32)> {
        let since = cutoff_ts - (self.config.lookback_days as i64 * SECONDS_PER_DAY);
        let network_size = node_ids.len();
        let min_unique = self.scaled_min_unique_challengers(network_size);
        let min_challenges = self.scaled_min_challenges(network_size);

        let mut qualified = Vec::new();
        for hex_id in node_ids {
            let caps =
                self.qualified_caps_at_cutoff(hex_id, since, cutoff_ts, min_challenges, min_unique);
            let shares = caps.total_shares();
            if shares > 0 {
                if let Some(node_id) = decode_node_id(hex_id) {
                    qualified.push((node_id, shares));
                }
            }
        }
        qualified
    }

    /// Deterministic per-node capability set from the converged ledger over
    /// `[since, until]`. Mirrors `get_qualified_capabilities_with_rates` plus the
    /// C-2 unique-challenger filter, but ledger-based and cutoff-anchored.
    fn qualified_caps_at_cutoff(
        &self,
        node_id_hex: &str,
        since: i64,
        until: i64,
        min_challenges: u32,
        min_unique: u32,
    ) -> NodeCapabilities {
        // Archive / Policy: per-row rate (verdicts are re-derived at ingest) + C-2.
        let archive_mode = self.rate_capability_qualified(
            node_id_hex,
            "archive",
            since,
            until,
            min_challenges,
            min_unique,
            self.config.archive_pass_rate,
        );
        let reaper = self.rate_capability_qualified(
            node_id_hex,
            "policy",
            since,
            until,
            min_challenges,
            min_unique,
            self.config.policy_pass_rate,
        );
        // Stratum / GhostPay: strict per-distinct-challenger majority + C-2.
        let public_mining = self
            .majority_capability_qualified(node_id_hex, "stratum", since, until, min_challenges, min_unique);
        let ghost_pay = self
            .majority_capability_qualified(node_id_hex, "ghostpay", since, until, min_challenges, min_unique);

        // Elder is registration order in the (converged) nodes table, unchanged.
        let elder_status = self.db.is_node_elder(node_id_hex).unwrap_or(false);

        NodeCapabilities {
            archive_mode,
            ghost_pay,
            public_mining,
            reaper,
            elder_status,
            coordinator: false,
        }
    }

    /// Archive/Policy gate over the ledger: `total ≥ X AND passed/total ≥ rate
    /// AND distinct challengers ≥ min_unique`.
    fn rate_capability_qualified(
        &self,
        node_id_hex: &str,
        capability: &str,
        since: i64,
        until: i64,
        min_challenges: u32,
        min_unique: u32,
        pass_rate: f64,
    ) -> bool {
        let (passed, total) = self
            .db
            .ledger_pass_rate(node_id_hex, capability, since, until)
            .unwrap_or((0, 0));
        if total == 0 || total < min_challenges {
            return false;
        }
        if (passed as f64 / total as f64) < pass_rate {
            return false;
        }
        let unique = self
            .db
            .ledger_unique_challengers(node_id_hex, capability, since, until)
            .unwrap_or(0);
        unique >= min_unique
    }

    /// Stratum/GhostPay gate over the ledger: `distinct challengers ≥ X AND a
    /// strict majority of distinct challengers passed AND distinct challengers ≥
    /// min_unique`. `challengers_total` from the majority query IS the distinct-
    /// challenger count, so it serves the count floor and the C-2 Sybil floor.
    fn majority_capability_qualified(
        &self,
        node_id_hex: &str,
        capability: &str,
        since: i64,
        until: i64,
        min_challenges: u32,
        min_unique: u32,
    ) -> bool {
        let (chal_pass, chal_total) = self
            .db
            .ledger_challenger_majority(node_id_hex, capability, since, until)
            .unwrap_or((0, 0));
        chal_total >= min_challenges && chal_total >= min_unique && chal_pass * 2 > chal_total
    }

    /// Get statistics for a node's qualification status
    pub fn get_qualification_stats(&self, node_id: &NodeId) -> QualificationStats {
        let node_id_hex = hex::encode(node_id);
        let since = self.lookback_timestamp();

        let uptime = self
            .db
            .get_uptime_percent(&node_id_hex, since)
            .unwrap_or(0.0);
        let passes_uptime = uptime >= self.config.min_uptime;

        let archive = self
            .db
            .get_archive_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let policy = self
            .db
            .get_policy_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let stratum = self
            .db
            .get_stratum_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));
        let ghostpay = self
            .db
            .get_ghostpay_pass_rate(&node_id_hex, since)
            .unwrap_or((0, 0));

        QualificationStats {
            node_id: node_id_hex,
            uptime_percent: uptime,
            passes_uptime_gate: passes_uptime,
            archive_challenges: archive.1,
            archive_passed: archive.0,
            policy_challenges: policy.1,
            policy_passed: policy.0,
            stratum_challenges: stratum.1,
            stratum_passed: stratum.0,
            ghostpay_challenges: ghostpay.1,
            ghostpay_passed: ghostpay.0,
            qualified_capabilities: if passes_uptime {
                // AUTH4-L3: Use archive_pass_rate as the baseline
                self.db
                    .get_qualified_capabilities(
                        &hex::encode(node_id),
                        since,
                        self.config.min_challenges,
                        self.config.archive_pass_rate,
                    )
                    .unwrap_or_default()
            } else {
                NodeCapabilities::default()
            },
        }
    }
}

/// Statistics about a node's qualification status
#[derive(Debug, Clone)]
pub struct QualificationStats {
    /// Node ID (hex)
    pub node_id: String,
    /// Uptime percentage over lookback period
    pub uptime_percent: f64,
    /// Whether node passes uptime gatekeeper
    pub passes_uptime_gate: bool,
    /// Total archive challenges
    pub archive_challenges: u32,
    /// Passed archive challenges
    pub archive_passed: u32,
    /// Total policy challenges
    pub policy_challenges: u32,
    /// Passed policy challenges
    pub policy_passed: u32,
    /// Total stratum challenges
    pub stratum_challenges: u32,
    /// Passed stratum challenges
    pub stratum_passed: u32,
    /// Total ghostpay challenges
    pub ghostpay_challenges: u32,
    /// Passed ghostpay challenges
    pub ghostpay_passed: u32,
    /// Final qualified capabilities
    pub qualified_capabilities: NodeCapabilities,
}

impl QualificationStats {
    /// Get pass rate for a capability (0.0 if no challenges)
    pub fn archive_pass_rate(&self) -> f64 {
        if self.archive_challenges == 0 {
            0.0
        } else {
            self.archive_passed as f64 / self.archive_challenges as f64
        }
    }

    pub fn policy_pass_rate(&self) -> f64 {
        if self.policy_challenges == 0 {
            0.0
        } else {
            self.policy_passed as f64 / self.policy_challenges as f64
        }
    }

    pub fn stratum_pass_rate(&self) -> f64 {
        if self.stratum_challenges == 0 {
            0.0
        } else {
            self.stratum_passed as f64 / self.stratum_challenges as f64
        }
    }

    pub fn ghostpay_pass_rate(&self) -> f64 {
        if self.ghostpay_challenges == 0 {
            0.0
        } else {
            self.ghostpay_passed as f64 / self.ghostpay_challenges as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = QualificationConfig::default();
        assert_eq!(
            config.min_challenges,
            ghost_common::constants::MIN_CHALLENGES_FOR_QUALIFICATION as u32
        );
        // C-2: Test minimum unique challengers requirement
        assert_eq!(config.min_unique_challengers, BASE_MIN_UNIQUE_CHALLENGERS);
        // AUTH4-L3: Test per-capability pass rates
        assert!((config.archive_pass_rate - 0.95).abs() < 0.001);
        assert!((config.ghostpay_pass_rate - 0.90).abs() < 0.001);
        assert!((config.stratum_pass_rate - 0.95).abs() < 0.001);
        assert!((config.policy_pass_rate - 0.95).abs() < 0.001);
        assert_eq!(config.lookback_days, 7);
        assert!((config.min_uptime - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_qualification_stats_pass_rates() {
        let stats = QualificationStats {
            node_id: "test".to_string(),
            uptime_percent: 0.98,
            passes_uptime_gate: true,
            archive_challenges: 20,
            archive_passed: 19,
            policy_challenges: 15,
            policy_passed: 15,
            stratum_challenges: 0,
            stratum_passed: 0,
            ghostpay_challenges: 10,
            ghostpay_passed: 8,
            qualified_capabilities: NodeCapabilities::default(),
        };

        assert!((stats.archive_pass_rate() - 0.95).abs() < 0.001);
        assert!((stats.policy_pass_rate() - 1.0).abs() < 0.001);
        assert!((stats.stratum_pass_rate() - 0.0).abs() < 0.001);
        assert!((stats.ghostpay_pass_rate() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_scaled_min_unique_challengers() {
        // MEDIUM-1/MEDIUM-2/VER-8 verification: Test that scaled_min_unique_challengers
        // returns appropriate values based on network size
        let db = Arc::new(Database::in_memory().unwrap());
        let provider = QualifiedCapabilityProvider::new(db);

        // VER-8 FIX: Very small networks (< 3) use absolute minimum (3)
        assert_eq!(
            provider.scaled_min_unique_challengers(0),
            3, // Absolute minimum for Sybil resistance
            "Network size 0 should give absolute minimum (3)"
        );
        assert_eq!(
            provider.scaled_min_unique_challengers(2),
            3, // Absolute minimum
            "Network size 2 should give absolute minimum (3)"
        );

        // VER-8 FIX: Small networks (3-29) use network_size / 3
        assert_eq!(
            provider.scaled_min_unique_challengers(5),
            3, // 5/3 = 1, clamped to min 3
            "Network size 5 should give 3"
        );
        assert_eq!(
            provider.scaled_min_unique_challengers(9),
            3, // 9/3 = 3
            "Network size 9 should give 3"
        );
        assert_eq!(
            provider.scaled_min_unique_challengers(15),
            5, // 15/3 = 5
            "Network size 15 should give 5"
        );
        assert_eq!(
            provider.scaled_min_unique_challengers(27),
            9, // 27/3 = 9
            "Network size 27 should give 9"
        );

        // Medium networks (30-50) use base requirement (10)
        assert_eq!(
            provider.scaled_min_unique_challengers(30),
            BASE_MIN_UNIQUE_CHALLENGERS,
            "Network size 30 should give base (10)"
        );
        assert_eq!(
            provider.scaled_min_unique_challengers(50),
            BASE_MIN_UNIQUE_CHALLENGERS,
            "Network size 50 should give base (10)"
        );

        // Larger networks: scaled requirement
        // Formula: min(MAX, BASE + sqrt(network_size / 10))
        // 100 nodes: 10 + sqrt(10) = 10 + 3.16 = 13
        let result_100 = provider.scaled_min_unique_challengers(100);
        assert!(
            (13..=14).contains(&result_100),
            "100 nodes should give ~13, got {}",
            result_100
        );

        // 500 nodes: 10 + sqrt(50) = 10 + 7.07 = 17
        let result_500 = provider.scaled_min_unique_challengers(500);
        assert!(
            (17..=18).contains(&result_500),
            "500 nodes should give ~17, got {}",
            result_500
        );

        // 1000 nodes: 10 + sqrt(100) = 10 + 10 = 20
        let result_1000 = provider.scaled_min_unique_challengers(1000);
        assert_eq!(result_1000, 20, "1000 nodes should give 20");

        // Very large networks: capped at MAX_MIN_UNIQUE_CHALLENGERS (50)
        let result_max = provider.scaled_min_unique_challengers(100_000);
        assert_eq!(
            result_max, MAX_MIN_UNIQUE_CHALLENGERS,
            "Large networks should cap at {}",
            MAX_MIN_UNIQUE_CHALLENGERS
        );

        // Overflow protection: very large values should not overflow
        let result_huge = provider.scaled_min_unique_challengers(usize::MAX);
        assert_eq!(
            result_huge, MAX_MIN_UNIQUE_CHALLENGERS,
            "Huge networks should cap at {}",
            MAX_MIN_UNIQUE_CHALLENGERS
        );
    }

    #[test]
    fn test_network_size_fallback_cache() {
        // M-7/H-14 verification: Test cached network size behavior
        let db = Arc::new(Database::in_memory().unwrap());
        let provider = QualifiedCapabilityProvider::new(db);

        // Initial call should populate cache and return result
        let size1 = provider.get_network_size_with_fallback();
        // With empty DB, should return 0 or cached default
        assert!(
            size1 <= 100,
            "Empty DB should return small value or default"
        );

        // Cache should be populated after first call
        let cache = provider.cached_network_size.read();
        assert!(
            cache.is_some(),
            "Cache should be populated after first call"
        );
    }

    #[test]
    fn test_scaled_min_challenges() {
        let db = Arc::new(Database::in_memory().unwrap());
        let provider = QualifiedCapabilityProvider::new(db);

        // Very small networks: absolute minimum of 3
        assert_eq!(provider.scaled_min_challenges(0), 3);
        assert_eq!(provider.scaled_min_challenges(2), 3);
        assert_eq!(provider.scaled_min_challenges(3), 3);

        // 4 nodes: max 3 challenges/day (4-1), capped by min_challenges=10 → 3
        assert_eq!(provider.scaled_min_challenges(4), 3);

        // 5 nodes: max 4 challenges/day (5-1)
        assert_eq!(provider.scaled_min_challenges(5), 4);

        // 10 nodes: max 9 challenges/day (10-1)
        assert_eq!(provider.scaled_min_challenges(10), 9);

        // 11 nodes: max 10 challenges/day (11-1), capped at min_challenges=10
        assert_eq!(provider.scaled_min_challenges(11), 10);

        // Large networks: always capped at protocol constant (10)
        assert_eq!(provider.scaled_min_challenges(100), 10);
        assert_eq!(provider.scaled_min_challenges(1_000_000), 10);
    }

    #[test]
    fn test_pass_rate_for_archive() {
        let config = QualificationConfig::default();
        let rate = config.pass_rate_for("archive");
        assert!(
            (rate - 0.95).abs() < f64::EPSILON,
            "archive pass rate should be 0.95, got {}",
            rate
        );
    }

    #[test]
    fn test_pass_rate_for_ghostpay() {
        let config = QualificationConfig::default();
        let rate = config.pass_rate_for("ghostpay");
        assert!(
            (rate - 0.90).abs() < f64::EPSILON,
            "ghostpay pass rate should be 0.90 (lower threshold), got {}",
            rate
        );
    }

    #[test]
    fn test_pass_rate_for_stratum() {
        let config = QualificationConfig::default();
        let rate = config.pass_rate_for("stratum");
        assert!(
            (rate - 0.95).abs() < f64::EPSILON,
            "stratum pass rate should be 0.95, got {}",
            rate
        );
    }

    #[test]
    fn test_pass_rate_for_policy() {
        let config = QualificationConfig::default();
        let rate = config.pass_rate_for("policy");
        assert!(
            (rate - 0.95).abs() < f64::EPSILON,
            "policy pass rate should be 0.95, got {}",
            rate
        );
    }

    #[test]
    fn test_pass_rate_for_unknown() {
        let config = QualificationConfig::default();
        let rate = config.pass_rate_for("nonexistent_capability");
        let archive_rate = config.archive_pass_rate;
        assert!(
            (rate - archive_rate).abs() < f64::EPSILON,
            "unknown capability should default to archive_pass_rate ({}), got {}",
            archive_rate,
            rate
        );
    }

    #[test]
    fn test_stats_zero_challenges() {
        let stats = QualificationStats {
            node_id: "deadbeef".to_string(),
            uptime_percent: 0.0,
            passes_uptime_gate: false,
            archive_challenges: 0,
            archive_passed: 0,
            policy_challenges: 0,
            policy_passed: 0,
            stratum_challenges: 0,
            stratum_passed: 0,
            ghostpay_challenges: 0,
            ghostpay_passed: 0,
            qualified_capabilities: NodeCapabilities::default(),
        };

        assert!(
            (stats.archive_pass_rate() - 0.0).abs() < f64::EPSILON,
            "archive_pass_rate should be 0.0 with 0 challenges"
        );
        assert!(
            (stats.policy_pass_rate() - 0.0).abs() < f64::EPSILON,
            "policy_pass_rate should be 0.0 with 0 challenges"
        );
        assert!(
            (stats.stratum_pass_rate() - 0.0).abs() < f64::EPSILON,
            "stratum_pass_rate should be 0.0 with 0 challenges"
        );
        assert!(
            (stats.ghostpay_pass_rate() - 0.0).abs() < f64::EPSILON,
            "ghostpay_pass_rate should be 0.0 with 0 challenges"
        );
    }

    #[test]
    fn test_stats_perfect_pass_rate() {
        let stats = QualificationStats {
            node_id: "cafebabe".to_string(),
            uptime_percent: 1.0,
            passes_uptime_gate: true,
            archive_challenges: 50,
            archive_passed: 50,
            policy_challenges: 30,
            policy_passed: 30,
            stratum_challenges: 25,
            stratum_passed: 25,
            ghostpay_challenges: 10,
            ghostpay_passed: 10,
            qualified_capabilities: NodeCapabilities::default(),
        };

        assert!(
            (stats.archive_pass_rate() - 1.0).abs() < f64::EPSILON,
            "archive_pass_rate should be 1.0 when all pass"
        );
        assert!(
            (stats.policy_pass_rate() - 1.0).abs() < f64::EPSILON,
            "policy_pass_rate should be 1.0 when all pass"
        );
        assert!(
            (stats.stratum_pass_rate() - 1.0).abs() < f64::EPSILON,
            "stratum_pass_rate should be 1.0 when all pass"
        );
        assert!(
            (stats.ghostpay_pass_rate() - 1.0).abs() < f64::EPSILON,
            "ghostpay_pass_rate should be 1.0 when all pass"
        );
    }

    #[test]
    fn test_lookback_timestamp_is_7_days_ago() {
        let db = Arc::new(Database::in_memory().unwrap());
        let provider = QualifiedCapabilityProvider::new(db);

        let lookback = provider.lookback_timestamp();
        let now = chrono::Utc::now().timestamp();
        let expected = now - (7 * SECONDS_PER_DAY);

        // Allow 2 seconds of epsilon for timing between calls
        let diff = (lookback - expected).abs();
        assert!(
            diff <= 2,
            "lookback_timestamp should be ~604800s (7 days) before now, \
             but diff from expected was {} seconds",
            diff
        );
    }

    // =================================================================
    // Deterministic, cutoff-anchored qualification (Components B/C/F)
    // =================================================================

    /// 32-byte hex node id from a single fill byte.
    fn hex_id(fill: u8) -> String {
        hex::encode([fill; 32])
    }

    /// Seed `n` distinct challengers each recording one `passed` archive proof
    /// for `target` at `ts` into the converged ledger.
    fn seed_archive(db: &Database, target: &str, first_challenger: u8, n: u8, passed: bool, ts: i64) {
        for i in 0..n {
            let challenger = hex_id(first_challenger + i);
            db.insert_verification_proof(&challenger, target, "archive", passed, ts, b"p")
                .unwrap();
        }
    }

    /// Two nodes with identical converged ledgers must produce byte-identical
    /// qualified sets for the same (node set, cutoff) — the property the whole
    /// determinism effort exists to deliver.
    #[test]
    fn cutoff_qualification_is_deterministic_across_nodes() {
        let target = hex_id(0xAA);
        let node_ids = vec![target.clone(), hex_id(1), hex_id(2), hex_id(3), hex_id(4)];
        let cutoff = 2_000_000i64;

        let db_a = Arc::new(Database::in_memory().unwrap());
        let db_b = Arc::new(Database::in_memory().unwrap());
        // network_size = 5 → min_challenges = 4, min_unique = 3.
        // Seed 4 distinct challengers all passing, within the window.
        seed_archive(&db_a, &target, 0x10, 4, true, cutoff - 100);
        seed_archive(&db_b, &target, 0x10, 4, true, cutoff - 100);

        let a = QualifiedCapabilityProvider::new(db_a).get_all_qualified_nodes_at_cutoff(&node_ids, cutoff);
        let b = QualifiedCapabilityProvider::new(db_b).get_all_qualified_nodes_at_cutoff(&node_ids, cutoff);

        assert_eq!(a, b, "identical ledgers must yield identical qualified sets");
        assert_eq!(
            a,
            vec![(decode_node_id(&target).unwrap(), 5)],
            "archive-only target should qualify for exactly +5 shares"
        );
    }

    /// Challenges after the cutoff are excluded, and no uptime rows are required
    /// (the uptime gatekeeper is retired). A node just under the count floor
    /// stays unqualified until an in-window challenge lifts it over.
    #[test]
    fn cutoff_qualification_excludes_post_cutoff_and_retires_uptime() {
        let target = hex_id(0xBB);
        let node_ids = vec![target.clone(), hex_id(1), hex_id(2), hex_id(3), hex_id(4)];
        let cutoff = 2_000_000i64; // min_challenges = 4 at network_size 5
        let db = Arc::new(Database::in_memory().unwrap());

        // 3 in-window (below the floor of 4) + 2 AFTER the cutoff (must be ignored).
        seed_archive(&db, &target, 0x10, 3, true, cutoff - 100);
        seed_archive(&db, &target, 0x20, 2, true, cutoff + 100);

        let provider = QualifiedCapabilityProvider::new(Arc::clone(&db));
        assert!(
            provider
                .get_all_qualified_nodes_at_cutoff(&node_ids, cutoff)
                .is_empty(),
            "post-cutoff challenges must not count; node is under the floor with no uptime rows"
        );

        // A 4th in-window distinct challenger lifts it over the floor — still no
        // uptime data anywhere, proving liveness comes from challenge-accrual.
        seed_archive(&db, &target, 0x13, 1, true, cutoff - 50);
        assert_eq!(
            provider.get_all_qualified_nodes_at_cutoff(&node_ids, cutoff),
            vec![(decode_node_id(&target).unwrap(), 5)],
            "an in-window challenge over the floor qualifies the node"
        );
    }

    /// A single lazy/malicious challenger signing `passed=false` cannot drag a
    /// stratum-qualified node under: the gate is a strict majority of DISTINCT
    /// challengers, so 4 passing vs 1 failing still qualifies (+3 shares).
    #[test]
    fn cutoff_stratum_majority_survives_one_griefer() {
        let target = hex_id(0xCC);
        let node_ids = vec![target.clone(), hex_id(1), hex_id(2), hex_id(3), hex_id(4)];
        let cutoff = 2_000_000i64; // min_challenges = 4, min_unique = 3
        let db = Arc::new(Database::in_memory().unwrap());

        // 4 distinct challengers pass, 1 distinct challenger fails.
        for i in 0..4u8 {
            db.insert_verification_proof(&hex_id(0x30 + i), &target, "stratum", true, cutoff - 100, b"p")
                .unwrap();
        }
        db.insert_verification_proof(&hex_id(0x40), &target, "stratum", false, cutoff - 100, b"p")
            .unwrap();

        let provider = QualifiedCapabilityProvider::new(db);
        assert_eq!(
            provider.get_all_qualified_nodes_at_cutoff(&node_ids, cutoff),
            vec![(decode_node_id(&target).unwrap(), 3)],
            "4-of-5 distinct challengers passing is a strict majority → +3 shares"
        );
    }
}
