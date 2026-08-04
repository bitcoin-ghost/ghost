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
//| FILE: challenge.rs                                                                                                   |
//|======================================================================================================================|

//! Verification challenge types

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Challenge type for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    /// Archive mode: Request historical block
    ArchiveBlock,
    /// Archive mode: Request historical transaction
    ArchiveTx,
    /// Policy: Submit test transaction for classification
    PolicyCheck,
    /// Stratum: Check port accessibility
    StratumPing,
    /// Ghost Pay: L2 balance query
    GhostPayBalance,
    /// Ghost Pay: L2 transfer capability
    GhostPayTransfer,
}

/// Archive challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveChallenge {
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Block hash to retrieve (hex)
    pub block_hash: Option<String>,
    /// Transaction ID to retrieve (hex)
    pub txid: Option<String>,
    /// Minimum block height to prove
    pub min_height: Option<u64>,
}

/// Archive challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveResponse {
    /// Success
    pub success: bool,
    /// Block data (if requested)
    pub block_data: Option<BlockData>,
    /// Transaction data (if requested)
    pub tx_data: Option<TxData>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Block data for archive verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockData {
    /// Block hash
    pub hash: String,
    /// Block height
    pub height: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Number of transactions
    pub tx_count: usize,
    /// Merkle root
    pub merkle_root: String,
}

/// Transaction data for archive verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxData {
    /// Transaction ID
    pub txid: String,
    /// Block hash containing the transaction
    pub block_hash: String,
    /// Transaction index in block
    pub tx_index: usize,
    /// Transaction size (bytes)
    pub size: usize,
    /// Number of inputs
    pub input_count: usize,
    /// Number of outputs
    pub output_count: usize,
    /// Bitcoin merkle proof that this transaction is in `block_hash`, hex-serialised `MerkleBlock`
    /// (#605). Produced by Core's `gettxoutproof`, so it follows Bitcoin's rules — double SHA-256 and
    /// the last hash of an odd level duplicated.
    ///
    /// `#[serde(default)]` so a responder that predates this field still deserialises. Verification is
    /// gated, and the gate cannot arm until the whole fleet ships this.
    #[serde(default)]
    pub txout_proof: Option<String>,
}

/// C-2 FIX: Validate an archive response against expected ground-truth values.
///
/// Returns `(passed, validation_details)`.
///
/// This is the single source of truth for archive verdict comparison. It is
/// called both by the CHALLENGER (`task.rs`, against its own RPC at challenge
/// time) and by RECIPIENTS of a broadcast result (`ghost-pool`'s
/// `ChainReVerifier`, against their own RPC when re-deriving the verdict). Both
/// paths run identical logic so there is zero divergence between the verdict a
/// challenger records and the verdict a recipient re-derives.
///
/// SECURITY: `expected_hash`, `expected_height` and `expected_merkle_root` MUST
/// come from the caller's own trusted source (its Bitcoin Core), never from the
/// untrusted party whose response is being judged.
pub fn validate_archive_response(
    resp: &ArchiveResponse,
    expected_hash: &str,
    expected_height: u64,
    expected_merkle_root: Option<&str>,
) -> (bool, String) {
    // Basic check: response must indicate success
    if !resp.success {
        return (false, "Response indicates failure".to_string());
    }

    // C-2 FIX: Block data must be present
    let block_data = match &resp.block_data {
        Some(data) => data,
        None => {
            return (false, "C-2: No block data in response".to_string());
        }
    };

    // C-2 FIX: Block hash must match what we requested
    if block_data.hash.to_lowercase() != expected_hash.to_lowercase() {
        return (
            false,
            format!(
                "C-2: Block hash mismatch: got {}, expected {}",
                block_data.hash, expected_hash
            ),
        );
    }

    // C-2 FIX: Height must match
    if block_data.height != expected_height {
        return (
            false,
            format!(
                "C-2: Block height mismatch: got {}, expected {}",
                block_data.height, expected_height
            ),
        );
    }

    // C-2 FIX: Validate merkle root format (64 hex chars)
    if block_data.merkle_root.len() != 64
        || !block_data
            .merkle_root
            .chars()
            .all(|c| c.is_ascii_hexdigit())
    {
        return (
            false,
            format!(
                "C-2: Invalid merkle root format: {}",
                block_data.merkle_root
            ),
        );
    }

    // C-2 FIX: If we have expected merkle root from our RPC, cross-check it
    if let Some(expected_mr) = expected_merkle_root {
        if block_data.merkle_root.to_lowercase() != expected_mr.to_lowercase() {
            return (
                false,
                format!(
                    "C-2: Merkle root mismatch: got {}, expected {}",
                    block_data.merkle_root, expected_mr
                ),
            );
        }
    }

    // C-2 FIX: Validate tx_count is reasonable (at least 1 for coinbase)
    if block_data.tx_count == 0 {
        return (false, "C-2: Block has zero transactions".to_string());
    }

    // C-2 FIX + LOW-VER-4 FIX: Validate timestamp for historical blocks
    // Archive verification is for HISTORICAL blocks, so timestamps must be in the past.
    // The 2-hour future tolerance was for new blocks being mined, but archive challenges
    // request blocks that already exist in the chain - they cannot have future timestamps.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // LOW-VER-4 FIX: Historical blocks must have timestamp <= now
    // Only allow minimal clock skew (60 seconds) to account for verification timing
    if block_data.timestamp > now + 60 {
        return (
            false,
            format!(
                "LOW-VER-4: Historical block timestamp {} is in the future (now: {})",
                block_data.timestamp, now
            ),
        );
    }

    (true, "Validation passed".to_string())
}

/// Policy challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyChallenge {
    /// Raw transaction hex
    pub tx_hex: String,
    /// Expected tier (for verification)
    pub expected_tier: Option<String>,
}

/// Policy challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Success
    pub success: bool,
    /// Active policy profile
    pub profile: String,
    /// Transaction classification
    pub classification: Option<PolicyClassification>,
    /// Would transaction be accepted
    pub accepted: bool,
    /// Rejection reason (if not accepted)
    pub rejection_reason: Option<String>,
    /// CONSENSUS SECURITY: Bitcoin txid (`tx.compute_txid()`) of the transaction
    /// the target actually classified. Set by the server INSIDE the signed
    /// payload so a recipient can BIND this classification to the exact tx the
    /// challenger broadcast: the recipient recomputes the txid of the challenger-
    /// supplied `tx_hex` and requires it to equal `tx_txid` before trusting the
    /// verdict. Without this, a colluder could pair a valid target-signed
    /// classification with a DIFFERENT `tx_hex` to force a spurious mismatch and
    /// grief the target. `#[serde(default)]` for backward-compatible deserialization
    /// of responses from peers that predate this field.
    #[serde(default)]
    pub tx_txid: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// CONSENSUS SECURITY: Compare a TARGET-signed [`PolicyResponse`] against the
/// caller's own ground-truth classification of the SAME transaction.
///
/// Returns `(passed, validation_details)`.
///
/// This is the single source of truth for policy verdict comparison, mirroring
/// [`validate_archive_response`]. It is called both by the CHALLENGER (`task.rs`,
/// against its own [`ghost_policy::PolicyEngine`] at challenge time) and by
/// RECIPIENTS of a broadcast result (`ghost-pool`'s `ChainReVerifier`, against
/// their own engine when re-deriving the verdict). Both paths run identical
/// logic, so there is zero divergence between the verdict a challenger records
/// and the verdict a recipient re-derives.
///
/// The target classified correctly (`passed = true`) iff:
///   1. it reported `success = true`,
///   2. its classification tier equals the caller's `recipient_tier`, and
///   3. its `accepted` flag equals the caller's `recipient_accepted`.
///
/// SECURITY: `recipient_tier` and `recipient_accepted` MUST be the caller's OWN
/// classification of the same transaction (from its own policy engine), never a
/// value taken from the untrusted party whose response is being judged.
pub fn validate_policy_response(
    target_resp: &PolicyResponse,
    recipient_tier: &str,
    recipient_accepted: bool,
) -> (bool, String) {
    // The target must claim success — a failed evaluation tells us nothing.
    if !target_resp.success {
        return (false, "Response indicates failure".to_string());
    }

    // The target must have produced a classification.
    let target_tier = match target_resp.classification.as_ref() {
        Some(c) => c.tier.as_str(),
        None => return (false, "No classification in response".to_string()),
    };

    // Tier must match the caller's own classification of the same tx.
    if !target_tier.eq_ignore_ascii_case(recipient_tier) {
        return (
            false,
            format!(
                "Tier mismatch: target classified {}, our engine classified {}",
                target_tier, recipient_tier
            ),
        );
    }

    // Accept/reject decision must match the caller's own decision.
    if target_resp.accepted != recipient_accepted {
        return (
            false,
            format!(
                "Accept decision mismatch: target accepted={}, our engine accepted={}",
                target_resp.accepted, recipient_accepted
            ),
        );
    }

    (true, "Validation passed".to_string())
}

/// Policy classification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyClassification {
    /// BUDS tier (T0-T3)
    pub tier: String,
    /// Classification reason
    pub reason: String,
    /// Detected features
    pub features: Vec<String>,
}

/// M-11: Minimum allowed stratum port (well-known ports reserved)
pub const MIN_STRATUM_PORT: u16 = 1024;

/// Stratum challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumChallenge {
    /// Port to check (default: 34255 for SV2, 3333 for SV1)
    /// M-11: Must be in range MIN_STRATUM_PORT..=MAX_STRATUM_PORT
    pub port: Option<u16>,
    /// Protocol version
    pub protocol: StratumProtocol,
}

impl StratumChallenge {
    /// M-11: Validate port number is in acceptable range
    ///
    /// Returns true if port is valid (None is valid - uses default)
    /// Returns false if port is set but outside valid range
    pub fn is_port_valid(&self) -> bool {
        match self.port {
            None => true,                           // Default port will be used
            Some(port) => port >= MIN_STRATUM_PORT, // MAX_STRATUM_PORT is u16::MAX, no need to check upper bound
        }
    }

    /// M-11: Get validated port or default based on protocol
    ///
    /// Returns None if port is set but invalid, Some(port) otherwise
    pub fn validated_port(&self) -> Option<u16> {
        match self.port {
            None => {
                // Default ports for each protocol
                Some(match self.protocol {
                    StratumProtocol::Sv1 => 3333,
                    StratumProtocol::Sv2 => 34255,
                })
            }
            Some(port) if port >= MIN_STRATUM_PORT => Some(port), // MAX is u16::MAX
            Some(_) => None, // Invalid port (below MIN_STRATUM_PORT)
        }
    }
}

/// Stratum protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StratumProtocol {
    Sv1,
    Sv2,
}

/// Stratum challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumResponse {
    /// Success
    pub success: bool,
    /// Port checked
    pub port: u16,
    /// Protocol
    pub protocol: StratumProtocol,
    /// Connection established
    pub connected: bool,
    /// Latency (milliseconds)
    pub latency_ms: Option<u32>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Ghost Pay challenge request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPayChallenge {
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Address to query (for balance)
    pub address: Option<String>,
    /// H-5: Random epoch to verify L2 state for
    /// When set, requires the node to prove it has state for this epoch
    #[serde(default)]
    pub challenge_epoch: Option<u64>,
    /// VER-2: Random challenge nonce that must be incorporated into the response
    /// This prevents precomputation attacks where an attacker pre-builds a lookup table
    /// of epoch_state_hash values. The response must include hash(epoch_state_hash || nonce).
    #[serde(default)]
    pub challenge_nonce: Option<String>,
}

/// M-13: Maximum reasonable virtual block number
/// Prevents overflow in downstream calculations
pub const MAX_VIRTUAL_BLOCK: u64 = u64::MAX / 2;

/// M-13: Maximum reasonable epoch number
pub const MAX_EPOCH: u64 = u64::MAX / 2;

/// Ghost Pay challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPayResponse {
    /// Success
    pub success: bool,
    /// L2 enabled
    pub l2_enabled: bool,
    /// Current virtual block
    pub virtual_block: Option<u64>,
    /// Current epoch
    pub epoch: Option<u64>,
    /// Balance (if queried)
    pub balance_sats: Option<u64>,
    /// Wraith enabled
    pub wraith_enabled: bool,
    /// H-5: Epoch state proof (hash of L2 state at challenged epoch)
    /// This proves the node actually has L2 state data, not just self-reporting
    #[serde(default)]
    pub epoch_state_hash: Option<String>,
    /// H-5: Transaction count at challenged epoch (for verification)
    #[serde(default)]
    pub epoch_tx_count: Option<u64>,
    /// VER-2/VER-3: Nonce-bound state proof: SHA256(epoch_state_hash || challenge_nonce)
    /// This prevents precomputation attacks. The verifier computes this hash locally
    /// using the epoch_state_hash and the nonce they sent, and compares.
    /// If a challenge_nonce was provided, this field MUST be present and valid.
    #[serde(default)]
    pub nonce_bound_proof: Option<String>,
    /// VER-3: Merkle proof or signature from GhostPay consensus layer
    /// This provides verifiable evidence that the epoch_state_hash is legitimate.
    /// Format: JSON object with "type" ("merkle" or "signature") and proof data.
    #[serde(default)]
    pub epoch_proof: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

impl GhostPayResponse {
    /// M-13: Validate the response fields are within acceptable ranges
    ///
    /// Returns true if all fields are valid, false if any field has an invalid value
    /// that could indicate a malicious or malformed response.
    pub fn is_valid(&self) -> bool {
        // Check virtual_block is within reasonable range
        if let Some(vb) = self.virtual_block {
            if vb > MAX_VIRTUAL_BLOCK {
                return false;
            }
        }

        // Check epoch is within reasonable range
        if let Some(ep) = self.epoch {
            if ep > MAX_EPOCH {
                return false;
            }
        }

        // If success is claimed but l2 is not enabled, that's suspicious
        // (not strictly invalid but worth noting)

        true
    }

    /// M-13: Get validated virtual block or None if invalid
    pub fn validated_virtual_block(&self) -> Option<u64> {
        self.virtual_block.filter(|&vb| vb <= MAX_VIRTUAL_BLOCK)
    }

    /// M-13: Get validated epoch or None if invalid
    pub fn validated_epoch(&self) -> Option<u64> {
        self.epoch.filter(|&ep| ep <= MAX_EPOCH)
    }
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Whether the node can actually do its job.
    ///
    /// This was the literal `true` for as long as the HTTP server could answer — a check that
    /// cannot fail. On 2026-08-01 ghost-vm7 served `healthy: true` for an hour with its Ghost Core
    /// dead underneath it, and nothing noticed: not the dashboard, not the load balancer, not an
    /// operator. It now reflects the one dependency without which the node does nothing useful.
    pub healthy: bool,
    /// Whether Ghost Core answered recently.
    ///
    /// `None` means no probe was wired, which is reported as such rather than assumed good — so a
    /// monitor can tell "never checked" from "checked and failing".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_reachable: Option<bool>,
    /// Seconds since Ghost Core last answered, so a monitor sees how stale the answer is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_last_ok_secs: Option<u64>,
    /// Node ID (hex)
    pub node_id: String,
    /// Software version
    pub version: String,
    /// Current block height
    pub block_height: u64,
    /// Current round ID
    pub round_id: u64,
    /// Connected miners
    pub miner_count: u32,
    /// Connected peers
    pub peer_count: u32,
    /// Capabilities
    pub capabilities: CapabilityStatus,
    /// Uptime (seconds)
    pub uptime_secs: u64,
    /// Mesh message-validation counters, or `null` if not wired.
    ///
    /// #591: these were incremented on every rejected message and read by nobody, so an oversized
    /// or malformed-message storm was invisible — the same blindness that let #558 and #583 run
    /// for weeks. A counter with no reader is not instrumentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_validation: Option<MeshValidationStats>,
}

/// Mesh message-validation counters surfaced on `/health`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct MeshValidationStats {
    pub total: u64,
    pub valid: u64,
    pub too_small: u64,
    pub too_large: u64,
    pub bad_version: u64,
    pub bad_type: u64,
    pub bad_signature: u64,
    pub bad_timestamp: u64,
    pub other_errors: u64,
    pub memory_limit_exceeded: u64,
}

/// Capability status
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityStatus {
    /// Archive mode enabled
    pub archive_mode: bool,
    /// Ghost Pay enabled
    pub ghost_pay: bool,
    /// Public mining enabled
    pub public_mining: bool,
    /// Reaper policy enabled
    pub reaper: bool,
    /// Elder status
    pub elder_status: bool,
    /// GSP (Ghost Service Protocol) light wallet server enabled
    pub gsp_enabled: bool,
    /// Total shares
    pub total_shares: i32,
}

impl From<ghost_common::types::NodeCapabilities> for CapabilityStatus {
    fn from(caps: ghost_common::types::NodeCapabilities) -> Self {
        Self {
            archive_mode: caps.archive_mode,
            ghost_pay: caps.ghost_pay,
            public_mining: caps.public_mining,
            reaper: caps.reaper,
            elder_status: caps.elder_status,
            gsp_enabled: false, // Set via VerificationState.gsp_enabled()
            total_shares: caps.total_shares(),
        }
    }
}

/// Maximum age of a signed response before it's considered stale (5 minutes)
pub const MAX_RESPONSE_AGE_SECS: u64 = 300;

/// Maximum time in the future a response timestamp can be (2 minutes)
pub const MAX_FUTURE_TIME_SECS: u64 = 120;

/// Default nonce TTL for verification challenges (5 minutes)
pub const DEFAULT_NONCE_TTL_SECS: u64 = 300;

/// Maximum number of nonces to track (prevent memory exhaustion)
pub const MAX_NONCE_CACHE_SIZE: usize = 10_000;

// ============================================================================
// AUTH4-M2: Nonce Expiry Cache
// ============================================================================

/// Error types for nonce validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonceError {
    /// Nonce was not issued by this server
    Unknown,
    /// Nonce has already been used (replay attack)
    AlreadyUsed,
    /// Nonce has expired
    Expired,
    /// Cache is full (rate limiting)
    CacheFull,
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceError::Unknown => write!(f, "unknown nonce"),
            NonceError::AlreadyUsed => write!(f, "nonce already used"),
            NonceError::Expired => write!(f, "nonce expired"),
            NonceError::CacheFull => write!(f, "nonce cache full"),
        }
    }
}

impl std::error::Error for NonceError {}

/// AUTH4-M2: Nonce cache for tracking issued and used nonces
///
/// This cache ensures:
/// 1. Nonces are only valid if issued by this server
/// 2. Each nonce can only be used once (prevents replay attacks)
/// 3. Nonces expire after a configurable TTL
/// 4. Memory usage is bounded by MAX_NONCE_CACHE_SIZE
pub struct NonceCache {
    /// Nonces that have been issued but not yet used.
    ///
    /// Maps nonce string -> the MONOTONIC instant it was issued. Deliberately `Instant`, not epoch
    /// seconds: `Instant` cannot be adjusted, so no clock change can widen a nonce's validity
    /// window (#615). It was `u64` epoch seconds, and a backwards adjustment of `d` seconds extended
    /// every live nonce by `d` — the replay window this cache exists to close, held open from
    /// outside. Nothing here is persisted or transmitted, so `Instant` costs no compatibility.
    issued: parking_lot::RwLock<std::collections::HashMap<String, std::time::Instant>>,
    /// Nonces that have been used (for preventing replay)
    ///
    /// Maps nonce string -> the monotonic instant it was used. Used nonces are kept for the TTL
    /// after use to prevent replay.
    used: parking_lot::RwLock<std::collections::HashMap<String, std::time::Instant>>,
    /// TTL for nonces. Held as a `Duration` so expiry is a duration comparison rather than
    /// second-granularity integer arithmetic, which let a nonce issued late in a second live up to
    /// `TTL + 1` seconds.
    ttl: std::time::Duration,
    /// Maximum cache size
    max_size: usize,
}

impl NonceCache {
    /// Create a new nonce cache with default TTL
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_NONCE_TTL_SECS)
    }

    /// Create a nonce cache with custom TTL
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            issued: parking_lot::RwLock::new(std::collections::HashMap::new()),
            used: parking_lot::RwLock::new(std::collections::HashMap::new()),
            ttl: std::time::Duration::from_secs(ttl_secs),
            max_size: MAX_NONCE_CACHE_SIZE,
        }
    }

    /// Generate and track a new nonce
    pub fn generate_nonce(&self) -> Result<String, NonceError> {
        let mut issued = self.issued.write();

        // Check cache size limit
        if issued.len() >= self.max_size {
            // Try cleanup first
            drop(issued);
            self.cleanup();
            issued = self.issued.write();

            if issued.len() >= self.max_size {
                return Err(NonceError::CacheFull);
            }
        }

        // C-4 FIX: Use OsRng for cryptographically secure nonce generation
        let mut nonce_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        issued.insert(nonce.clone(), std::time::Instant::now());
        Ok(nonce)
    }

    /// Validate and consume a nonce
    ///
    /// Returns Ok(()) if the nonce is valid and has not been used before.
    /// The nonce is marked as used and cannot be reused.
    pub fn validate_and_consume(&self, nonce: &str) -> Result<(), NonceError> {
        let now = std::time::Instant::now();

        // Check if already used
        {
            let used = self.used.read();
            if used.contains_key(nonce) {
                return Err(NonceError::AlreadyUsed);
            }
        }

        // Check if issued and not expired
        let issued_at = {
            let issued = self.issued.read();
            match issued.get(nonce) {
                Some(&ts) => ts,
                None => return Err(NonceError::Unknown),
            }
        };

        // Check expiry against MONOTONIC elapsed time (#615).
        if now.saturating_duration_since(issued_at) > self.ttl {
            return Err(NonceError::Expired);
        }

        // Mark as used and remove from issued
        // Track the usage timestamp for selective cleanup
        {
            let mut issued = self.issued.write();
            let mut used = self.used.write();

            issued.remove(nonce);
            used.insert(nonce.to_string(), now);
        }

        Ok(())
    }

    /// Check if a nonce is valid without consuming it
    pub fn is_valid(&self, nonce: &str) -> bool {
        let now = std::time::Instant::now();

        // Check if used
        {
            let used = self.used.read();
            if used.contains_key(nonce) {
                return false;
            }
        }

        // Check if issued and not expired
        let issued = self.issued.read();
        match issued.get(nonce) {
            Some(&ts) => now.saturating_duration_since(ts) <= self.ttl,
            None => false,
        }
    }

    /// Test-only: age a nonce by rewriting its issue instant, so expiry can be tested without
    /// sleeping. Saturates at the process start instant rather than panicking on underflow.
    #[cfg(test)]
    fn age_nonce_for_test(&self, nonce: &str, age: std::time::Duration) {
        let aged = std::time::Instant::now()
            .checked_sub(age)
            .unwrap_or_else(std::time::Instant::now);
        self.issued.write().insert(nonce.to_string(), aged);
    }

    /// Clean up expired nonces
    ///
    /// Returns the number of entries removed
    ///
    /// LOW-VER-7 SAFETY: Removing expired nonces is safe because:
    /// 1. Expired issued nonces cannot be used - validation checks timestamp freshness
    /// 2. Expired used nonces need not be tracked - any attempt to reuse them would
    ///    fail the timestamp freshness check before reaching the replay check
    /// 3. The TTL window (default 5 minutes) provides sufficient time for legitimate
    ///    challenge-response cycles while preventing memory exhaustion
    ///
    /// The nonce validation flow is:
    /// 1. Check timestamp freshness (rejects if > TTL seconds old)
    /// 2. Check if nonce was issued by us (reject if not)
    /// 3. Check if nonce was already used (reject if replay)
    ///
    /// Since step 1 happens before step 3, expired nonces are rejected before
    /// we even check the used set, making their removal from the used set safe.
    pub fn cleanup(&self) -> usize {
        let now = std::time::Instant::now();
        let mut removed = 0;

        // Clean up expired issued nonces
        {
            let mut issued = self.issued.write();
            let before = issued.len();
            issued.retain(|_, &mut ts| now.saturating_duration_since(ts) <= self.ttl);
            removed += before - issued.len();
        }

        // Clean up expired used nonces (kept for TTL duration after use)
        // Now that we track usage timestamps, we can selectively remove only expired entries
        {
            let mut used = self.used.write();
            let before = used.len();
            used.retain(|_, &mut used_at| now.saturating_duration_since(used_at) <= self.ttl);
            removed += before - used.len();
        }

        removed
    }

    /// Get statistics about the cache
    pub fn stats(&self) -> (usize, usize) {
        let issued = self.issued.read().len();
        let used = self.used.read().len();
        (issued, used)
    }
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Signed verification response wrapper
///
/// Wraps any verification response with a cryptographic signature to:
/// - Prove the response came from the claimed node
/// - Prevent proxying attacks (where an attacker relays another node's responses)
/// - Ensure freshness via timestamp and nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedResponse<T: Serialize> {
    /// The actual response payload
    pub payload: T,
    /// Node ID that signed this response (hex-encoded Ed25519 public key)
    pub signer: String,
    /// Unix timestamp when the response was generated
    pub timestamp: u64,
    /// Random nonce for uniqueness (hex-encoded 16 bytes)
    pub nonce: String,
    /// Challenge nonce from request (if provided) - ensures response matches request
    pub challenge_nonce: Option<String>,
    /// Ed25519 signature over (payload_hash || signer || timestamp || nonce || challenge_nonce)
    /// Hex-encoded 64-byte signature
    pub signature: String,
}

impl<T: Serialize> SignedResponse<T> {
    /// Create a new signed response
    ///
    /// # Arguments
    /// * `payload` - The response data to sign
    /// * `signer` - Node ID (hex-encoded public key)
    /// * `sign_fn` - Closure that takes a message hash and returns a signature
    /// * `challenge_nonce` - Optional nonce from the request
    pub fn new<F>(payload: T, signer: String, sign_fn: F, challenge_nonce: Option<String>) -> Self
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // C-4 FIX: Use OsRng for cryptographically secure nonce generation
        let mut nonce_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Compute message hash for signing
        let message_hash = Self::compute_message_hash(
            &payload,
            &signer,
            timestamp,
            &nonce,
            challenge_nonce.as_deref(),
        );

        // Sign the message hash
        let signature_bytes = sign_fn(&message_hash);
        let signature = hex::encode(signature_bytes);

        Self {
            payload,
            signer,
            timestamp,
            nonce,
            challenge_nonce,
            signature,
        }
    }

    /// Compute the message hash for signing/verification
    fn compute_message_hash(
        payload: &T,
        signer: &str,
        timestamp: u64,
        nonce: &str,
        challenge_nonce: Option<&str>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash the payload JSON
        if let Ok(payload_json) = serde_json::to_vec(payload) {
            hasher.update(&payload_json);
        }

        // Hash metadata
        hasher.update(signer.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce.as_bytes());

        // Include challenge nonce if present
        if let Some(cn) = challenge_nonce {
            hasher.update(cn.as_bytes());
        }

        hasher.finalize().into()
    }

    /// Verify the signature is valid
    ///
    /// # Arguments
    /// * `verify_fn` - Closure that takes (public_key_hex, message_hash, signature_bytes)
    ///   and returns true if the signature is valid
    ///
    /// # Returns
    /// * `Ok(())` if signature is valid
    /// * `Err(reason)` if verification fails
    pub fn verify<F>(&self, verify_fn: F) -> Result<(), String>
    where
        F: FnOnce(&str, &[u8], &[u8]) -> bool,
    {
        // Check timestamp bounds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Not too far in the future
        if self.timestamp > now + MAX_FUTURE_TIME_SECS {
            return Err(format!(
                "Response timestamp {} is too far in the future (current: {})",
                self.timestamp, now
            ));
        }

        // Not too old
        if self.timestamp + MAX_RESPONSE_AGE_SECS < now {
            return Err(format!(
                "Response timestamp {} is too old (max age: {}s, current: {})",
                self.timestamp, MAX_RESPONSE_AGE_SECS, now
            ));
        }

        // Decode signature
        let signature_bytes =
            hex::decode(&self.signature).map_err(|e| format!("Invalid signature hex: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: {} (expected 64)",
                signature_bytes.len()
            ));
        }

        // Recompute message hash
        let message_hash = Self::compute_message_hash(
            &self.payload,
            &self.signer,
            self.timestamp,
            &self.nonce,
            self.challenge_nonce.as_deref(),
        );

        // Verify signature
        if verify_fn(&self.signer, &message_hash, &signature_bytes) {
            Ok(())
        } else {
            Err("Signature verification failed".to_string())
        }
    }
}

/// Verification request with nonce
///
/// Clients should include a nonce in requests so that the response
/// can be bound to that specific request (prevents replay of old responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest<T> {
    /// The actual request payload
    pub request: T,
    /// Random nonce for this request (hex-encoded 16 bytes)
    pub nonce: String,
}

impl<T> VerificationRequest<T> {
    /// Create a new verification request with random nonce
    pub fn new(request: T) -> Self {
        // C-4 FIX: Use OsRng for cryptographically secure nonce generation
        let mut nonce_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        Self {
            request,
            nonce: hex::encode(nonce_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_nonce_cache_basic() {
        let cache = NonceCache::new();

        // Generate a nonce
        let nonce = cache.generate_nonce().unwrap();
        assert_eq!(nonce.len(), 32); // 16 bytes = 32 hex chars

        // Should be valid
        assert!(cache.is_valid(&nonce));

        // Consume it
        assert!(cache.validate_and_consume(&nonce).is_ok());

        // Should no longer be valid (already used)
        assert!(!cache.is_valid(&nonce));
        assert_eq!(
            cache.validate_and_consume(&nonce),
            Err(NonceError::AlreadyUsed)
        );
    }

    #[test]
    fn test_nonce_cache_unknown() {
        let cache = NonceCache::new();

        // Unknown nonce should fail
        let result = cache.validate_and_consume("unknown_nonce_12345678");
        assert_eq!(result, Err(NonceError::Unknown));
    }

    /// #615: a nonce must not outlive its TTL, and the TTL must be measured in monotonic time.
    ///
    /// The bug this replaced was demonstrated with a test that recorded an issue time in the FUTURE —
    /// standing in for "issued while the host clock was ahead, then stepped back by NTP or a resume".
    /// Against the old epoch-seconds implementation a 2-second nonce stayed valid for a full hour,
    /// because `now <= ts + ttl` held until the clock caught up. That is the replay window this cache
    /// exists to close, held open from outside it.
    ///
    /// That test cannot be written against the fix: `Instant` is monotonic, so an issue instant in the
    /// future is not constructible from `Instant::now()`, and no clock adjustment moves it. The
    /// property is now structural rather than asserted, which is the stronger of the two. What is left
    /// to test is the boundary itself.
    #[test]
    #[serial]
    fn nonce_expires_exactly_at_its_ttl() {
        let cache = NonceCache::with_ttl(2);

        let fresh = cache.generate_nonce().unwrap();
        assert!(
            cache.is_valid(&fresh),
            "a freshly issued nonce must be valid"
        );

        // Just inside the window must still be valid — else the fix would expire live nonces, which
        // breaks every honest challenge-response cycle.
        let inside = cache.generate_nonce().unwrap();
        cache.age_nonce_for_test(&inside, std::time::Duration::from_millis(1_900));
        assert!(
            cache.is_valid(&inside),
            "1.9s into a 2s TTL must still be valid"
        );

        // Just outside must not be. Sub-second granularity matters here: the old integer-seconds
        // arithmetic let a nonce issued late in a second live up to TTL + 1 seconds.
        let outside = cache.generate_nonce().unwrap();
        cache.age_nonce_for_test(&outside, std::time::Duration::from_millis(2_100));
        assert!(
            !cache.is_valid(&outside),
            "2.1s into a 2s TTL must be expired"
        );
        assert_eq!(
            cache.validate_and_consume(&outside),
            Err(NonceError::Expired),
            "and consuming it must be refused as expired, not accepted"
        );
    }

    #[test]
    #[serial]
    fn test_nonce_cache_cleanup() {
        // Age the nonce by rewriting its issue timestamp instead of sleeping. The old version slept
        // 5s against a 2s TTL and still failed roughly one run in seven, because expiry compares
        // wall-clock `SystemTime`: any backwards clock adjustment during the sleep (WSL2 does this
        // on resume and after NTP correction) leaves the nonce inside its window. Injecting the
        // timestamp tests the expiry rule itself, and runs 5 seconds faster.
        let cache = NonceCache::with_ttl(2);

        let nonce = cache.generate_nonce().unwrap();
        assert!(cache.is_valid(&nonce), "a fresh nonce must be valid");

        // One second past the TTL, via the monotonic clock (#615).
        cache.age_nonce_for_test(&nonce, cache.ttl + std::time::Duration::from_secs(1));

        assert!(
            !cache.is_valid(&nonce),
            "a nonce past its TTL must not be valid"
        );
        assert_eq!(cache.validate_and_consume(&nonce), Err(NonceError::Expired));
    }

    #[test]
    fn test_nonce_cache_stats() {
        let cache = NonceCache::new();

        let (issued, used) = cache.stats();
        assert_eq!(issued, 0);
        assert_eq!(used, 0);

        // Generate and consume
        let nonce = cache.generate_nonce().unwrap();
        let (issued, used) = cache.stats();
        assert_eq!(issued, 1);
        assert_eq!(used, 0);

        cache.validate_and_consume(&nonce).unwrap();
        let (issued, used) = cache.stats();
        assert_eq!(issued, 0);
        assert_eq!(used, 1);
    }

    #[test]
    fn test_challenge_serialization() {
        let challenge = ArchiveChallenge {
            challenge_type: ChallengeType::ArchiveBlock,
            block_hash: Some("abc123".to_string()),
            txid: None,
            min_height: Some(100),
        };

        let json = serde_json::to_string(&challenge).unwrap();
        let decoded: ArchiveChallenge = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.challenge_type, ChallengeType::ArchiveBlock);
    }

    #[test]
    fn test_signed_response_creation() {
        let health = HealthResponse {
            mesh_validation: None,
            healthy: true,
            core_reachable: Some(true),
            core_last_ok_secs: Some(0),
            node_id: "test_node".to_string(),
            version: "1.0.0".to_string(),
            block_height: 100,
            round_id: 1,
            miner_count: 10,
            peer_count: 5,
            capabilities: CapabilityStatus::default(),
            uptime_secs: 3600,
        };

        // Mock signing function that returns a fake signature
        let sign_fn = |_message: &[u8]| -> [u8; 64] { [0xABu8; 64] };

        let signed = SignedResponse::new(
            health,
            "0123456789abcdef".to_string(),
            sign_fn,
            Some("challenge_nonce".to_string()),
        );

        assert_eq!(signed.signer, "0123456789abcdef");
        assert!(signed.timestamp > 0);
        assert!(!signed.nonce.is_empty());
        assert_eq!(signed.challenge_nonce, Some("challenge_nonce".to_string()));
        assert_eq!(signed.signature, hex::encode([0xABu8; 64]));
    }

    #[test]
    fn test_signed_response_timestamp_validation() {
        let health = HealthResponse {
            mesh_validation: None,
            healthy: true,
            core_reachable: Some(true),
            core_last_ok_secs: Some(0),
            node_id: "test".to_string(),
            version: "1.0".to_string(),
            block_height: 0,
            round_id: 0,
            miner_count: 0,
            peer_count: 0,
            capabilities: CapabilityStatus::default(),
            uptime_secs: 0,
        };

        // Create a signed response with timestamp far in the past
        let mut signed = SignedResponse {
            payload: health,
            signer: "test".to_string(),
            timestamp: 1000, // Very old timestamp
            nonce: "abc123".to_string(),
            challenge_nonce: None,
            signature: hex::encode([0u8; 64]),
        };

        // Verification should fail due to old timestamp
        let result = signed.verify(|_, _, _| true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));

        // Test timestamp too far in future
        signed.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + MAX_FUTURE_TIME_SECS
            + 100;

        let result = signed.verify(|_, _, _| true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("future"));
    }

    #[test]
    fn test_verification_request_nonce() {
        let request = VerificationRequest::new(ArchiveChallenge {
            challenge_type: ChallengeType::ArchiveBlock,
            block_hash: Some("abc".to_string()),
            txid: None,
            min_height: None,
        });

        // Nonce should be 32 hex chars (16 bytes)
        assert_eq!(request.nonce.len(), 32);

        // Each request should have a different nonce
        let request2 = VerificationRequest::new(ArchiveChallenge {
            challenge_type: ChallengeType::ArchiveBlock,
            block_hash: Some("abc".to_string()),
            txid: None,
            min_height: None,
        });

        assert_ne!(request.nonce, request2.nonce);
    }

    #[test]
    fn test_stratum_port_validation() {
        // M-11: Test stratum port validation

        // No port (uses default) should be valid
        let challenge = StratumChallenge {
            port: None,
            protocol: StratumProtocol::Sv2,
        };
        assert!(challenge.is_port_valid());
        assert_eq!(challenge.validated_port(), Some(34255)); // SV2 default

        // Valid port should be valid
        let challenge = StratumChallenge {
            port: Some(8333),
            protocol: StratumProtocol::Sv1,
        };
        assert!(challenge.is_port_valid());
        assert_eq!(challenge.validated_port(), Some(8333));

        // Port below MIN_STRATUM_PORT should be invalid
        let challenge = StratumChallenge {
            port: Some(80), // Well-known port
            protocol: StratumProtocol::Sv1,
        };
        assert!(!challenge.is_port_valid());
        assert_eq!(challenge.validated_port(), None);

        // Port at boundary should be valid
        let challenge = StratumChallenge {
            port: Some(MIN_STRATUM_PORT),
            protocol: StratumProtocol::Sv1,
        };
        assert!(challenge.is_port_valid());
        assert_eq!(challenge.validated_port(), Some(MIN_STRATUM_PORT));
    }

    #[test]
    fn test_ghostpay_response_validation() {
        // M-13: Test GhostPay response validation

        // Normal response should be valid
        let response = GhostPayResponse {
            success: true,
            l2_enabled: true,
            virtual_block: Some(1000),
            epoch: Some(5),
            balance_sats: Some(100_000),
            wraith_enabled: false,
            epoch_state_hash: None,
            epoch_tx_count: None,
            nonce_bound_proof: None,
            epoch_proof: None,
            error: None,
        };
        assert!(response.is_valid());
        assert_eq!(response.validated_virtual_block(), Some(1000));
        assert_eq!(response.validated_epoch(), Some(5));

        // Extremely large virtual_block should be invalid
        let response = GhostPayResponse {
            success: true,
            l2_enabled: true,
            virtual_block: Some(u64::MAX),
            epoch: Some(5),
            balance_sats: None,
            wraith_enabled: false,
            epoch_state_hash: None,
            epoch_tx_count: None,
            nonce_bound_proof: None,
            epoch_proof: None,
            error: None,
        };
        assert!(!response.is_valid());
        assert_eq!(response.validated_virtual_block(), None);

        // Extremely large epoch should be invalid
        let response = GhostPayResponse {
            success: true,
            l2_enabled: true,
            virtual_block: Some(1000),
            epoch: Some(u64::MAX),
            balance_sats: None,
            wraith_enabled: false,
            epoch_state_hash: None,
            epoch_tx_count: None,
            nonce_bound_proof: None,
            epoch_proof: None,
            error: None,
        };
        assert!(!response.is_valid());
        assert_eq!(response.validated_epoch(), None);
    }
}
