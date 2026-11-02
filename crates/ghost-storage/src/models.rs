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
//| FILE: models.rs                                                                                                      |
//|======================================================================================================================|

//! Database models for Ghost storage

use serde::{Deserialize, Serialize};

/// Share record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareRecord {
    /// Auto-increment ID
    pub id: Option<i64>,
    /// Round ID
    pub round_id: u64,
    /// Miner pubkey hash (hex)
    pub miner_id: String,
    /// Share difficulty
    pub difficulty: f64,
    /// Work value
    pub work: f64,
    /// Share hash (hex)
    pub share_hash: String,
    /// Timestamp (Unix seconds)
    pub timestamp: i64,
    /// Node that received the share (hex)
    pub received_by: String,
    /// Whether this share is valid
    pub valid: bool,
}

/// Best (lowest-value, most-leading-zeros) share in a time window.
/// Used to power the records strip on the public pool page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BestShare {
    /// Raw share hash (hex, 64 chars)
    pub share_hash: String,
    /// Miner ID in `address.worker` form (caller is responsible for any
    /// redaction before returning to public HTTP clients).
    pub miner_id: String,
    /// Unix millisecond timestamp the share was received.
    pub timestamp: i64,
    /// Claimed share difficulty at submission time.
    pub difficulty: f64,
    /// Block height of the round the share belongs to, resolved via the
    /// share's `round_id` against the `rounds` table. `None` when the round
    /// row is absent (e.g. a share recorded before its round was persisted).
    pub block_height: Option<u64>,
}

/// Round record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundRecord {
    /// Round ID
    pub round_id: u64,
    /// Block height
    pub block_height: u64,
    /// Block hash (hex, None if not found)
    pub block_hash: Option<String>,
    /// Round start timestamp
    pub start_time: i64,
    /// Round end timestamp (None if active)
    pub end_time: Option<i64>,
    /// Total shares in round
    pub total_shares: u64,
    /// Total work in round
    pub total_work: f64,
    /// Winning miner (hex, None if not found)
    pub winning_miner: Option<String>,
    /// Node that found the block (hex)
    pub found_by_node: Option<String>,
    /// Payout status
    pub payout_status: PayoutStatus,
    /// Subsidy amount (satoshis)
    pub subsidy_sats: Option<u64>,
    /// TX fees amount (satoshis)
    pub tx_fees_sats: Option<u64>,
}

/// Payout status for a round
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    /// Round active, no payout yet
    Active,
    /// Payout proposal pending consensus
    Pending,
    /// Payout approved by consensus
    Approved,
    /// Payout transaction broadcast
    Broadcast,
    /// Payout confirmed on chain
    Confirmed,
    /// Payout failed
    Failed,
    /// Block was orphaned due to reorg - payout cancelled
    Orphaned,
}

impl PayoutStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Broadcast => "broadcast",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
            Self::Orphaned => "orphaned",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "broadcast" => Some(Self::Broadcast),
            "confirmed" => Some(Self::Confirmed),
            "failed" => Some(Self::Failed),
            "orphaned" => Some(Self::Orphaned),
            _ => None,
        }
    }
}

/// Node record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    /// Node ID (hex)
    pub node_id: String,
    /// Public address (IP:port or hostname)
    pub public_address: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last seen timestamp
    pub last_seen: i64,
    /// Is elder
    pub is_elder: bool,
    /// Elder registration order (for top 101)
    pub elder_order: Option<u32>,
    /// Capabilities JSON
    pub capabilities: String,
    /// Total uptime (seconds)
    pub total_uptime_secs: u64,
    /// 7-day uptime percentage
    pub uptime_7d_percent: f64,
    /// Verification pass rate
    pub verification_pass_rate: f64,
    /// Total shares received
    pub total_shares_received: u64,
    /// Total blocks found
    pub total_blocks_found: u64,
    /// Payout address for node rewards (script hex)
    pub payout_address: Option<String>,
}

/// Miner record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerRecord {
    /// Miner pubkey hash (hex)
    pub miner_id: String,
    /// Payout address (script hex)
    pub payout_address: String,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last seen timestamp
    pub last_seen: i64,
    /// Connected to node (hex)
    pub connected_node: Option<String>,
    /// Total shares submitted
    pub total_shares: u64,
    /// Total work contributed
    pub total_work: f64,
    /// Total blocks won
    pub blocks_won: u64,
    /// Total payouts received (satoshis)
    pub total_payouts_sats: u64,
    /// Average hashrate (TH/s)
    pub avg_hashrate_ths: f64,
}

/// Payout record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutRecord {
    /// Auto-increment ID
    pub id: Option<i64>,
    /// Round ID
    pub round_id: u64,
    /// Recipient (miner_id or node_id hex)
    pub recipient_id: String,
    /// Recipient type
    pub recipient_type: RecipientType,
    /// Payout address (script hex)
    pub address: String,
    /// Amount (satoshis)
    pub amount_sats: u64,
    /// Transaction ID (hex, None if not broadcast)
    pub txid: Option<String>,
    /// Output index in transaction
    pub vout: Option<u32>,
    /// Status
    pub status: PayoutStatus,
    /// Created timestamp
    pub created_at: i64,
    /// Confirmed timestamp
    pub confirmed_at: Option<i64>,
}

/// Recipient type for payouts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientType {
    Miner,
    Node,
    Treasury,
    TxFees,
}

impl RecipientType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Miner => "miner",
            Self::Node => "node",
            Self::Treasury => "treasury",
            Self::TxFees => "tx_fees",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "miner" => Some(Self::Miner),
            "node" => Some(Self::Node),
            "treasury" => Some(Self::Treasury),
            "tx_fees" => Some(Self::TxFees),
            _ => None,
        }
    }
}

/// Node reward ledger entry
///
/// Tracks accumulated rewards for nodes outside the top 100
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRewardEntry {
    /// Node ID (hex)
    pub node_id: String,
    /// Accumulated balance (satoshis)
    pub balance_sats: u64,
    /// Last credited round
    pub last_credited_round: u64,
    /// Total credits received
    pub total_credits_sats: u64,
    /// Total withdrawals
    pub total_withdrawals_sats: u64,
    /// Created timestamp
    pub created_at: i64,
    /// Updated timestamp
    pub updated_at: i64,
}

/// Verification result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    Pending,
    Pass,
    Fail,
    Timeout,
    Error,
}

impl VerificationResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "pass" => Some(Self::Pass),
            "fail" => Some(Self::Fail),
            "timeout" => Some(Self::Timeout),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

// =============================================================================
// PEER MODELS
// =============================================================================

/// Peer record for P2P network tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    /// Peer ID (derived from address)
    pub peer_id: String,
    /// IP address or hostname
    pub address: String,
    /// Port number
    pub port: u16,
    /// Associated node ID (if known)
    pub node_id: Option<String>,
    /// First seen timestamp
    pub first_seen: i64,
    /// Last seen timestamp
    pub last_seen: i64,
    /// Last successful connection
    pub last_success: Option<i64>,
    /// Last failed connection
    pub last_failure: Option<i64>,
    /// Total connection attempts
    pub connection_count: u32,
    /// Failed connection attempts
    pub failure_count: u32,
    /// Whether peer is banned
    pub is_banned: bool,
    /// Ban expiration timestamp
    pub ban_until: Option<i64>,
    /// Peer capabilities (JSON)
    pub capabilities: Option<String>,
    /// Protocol version
    pub protocol_version: Option<u32>,
}

// =============================================================================
// MINER SEARCH MODELS
// =============================================================================

/// Miner search result (summary)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerSearchResult {
    /// Miner ID (worker name)
    pub miner_id: String,
    /// Total shares submitted (all time)
    pub total_shares: u64,
    /// Total work contributed
    pub total_work: f64,
    /// Valid shares count
    pub valid_shares: u64,
    /// First share timestamp
    pub first_seen: i64,
    /// Last share timestamp
    pub last_seen: i64,
    /// Average difficulty
    pub avg_difficulty: f64,
}

/// Detailed miner statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinerDetailedStats {
    /// Miner ID (worker name)
    pub miner_id: String,
    /// Total shares submitted (all time)
    pub total_shares: u64,
    /// Total work contributed
    pub total_work: f64,
    /// Valid shares count
    pub valid_shares: u64,
    /// Invalid shares count
    pub invalid_shares: u64,
    /// First share timestamp
    pub first_seen: i64,
    /// Last share timestamp
    pub last_seen: i64,
    /// Average difficulty
    pub avg_difficulty: f64,
    /// Number of rounds participated
    pub rounds_participated: u64,
    /// Recent shares (last 10)
    pub recent_shares: Vec<RecentShare>,
}

/// Recent share info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentShare {
    /// Round ID
    pub round_id: u64,
    /// Share difficulty
    pub difficulty: f64,
    /// Work value
    pub work: f64,
    /// Timestamp
    pub timestamp: i64,
    /// Whether share was valid
    pub valid: bool,
}

// =============================================================================
// PAYOUT HISTORY MODELS
// =============================================================================

/// Query parameters for paginated payout history
#[derive(Debug, Clone)]
pub struct PayoutHistoryQuery {
    /// Maximum number of results to return (default: 100)
    pub limit: u32,
    /// Number of results to skip (for pagination)
    pub offset: u32,
    /// Only include payouts at or above this block height
    pub min_height: Option<u64>,
    /// Only include payouts at or below this block height
    pub max_height: Option<u64>,
}

impl Default for PayoutHistoryQuery {
    fn default() -> Self {
        Self {
            limit: 100,
            offset: 0,
            min_height: None,
            max_height: None,
        }
    }
}

impl PayoutHistoryQuery {
    /// Create a new query with just a limit
    pub fn with_limit(limit: u32) -> Self {
        Self {
            limit,
            ..Default::default()
        }
    }

    /// Set the offset for pagination
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Filter by minimum block height
    pub fn with_min_height(mut self, height: u64) -> Self {
        self.min_height = Some(height);
        self
    }

    /// Filter by maximum block height
    pub fn with_max_height(mut self, height: u64) -> Self {
        self.max_height = Some(height);
        self
    }
}

/// Summary of payouts for a single round (for history display)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundPayoutSummary {
    /// Round ID
    pub round_id: u64,
    /// Block height
    pub block_height: u64,
    /// Block hash (hex)
    pub block_hash: Option<String>,
    /// Total miners paid
    pub miner_count: u32,
    /// Total nodes paid
    pub node_count: u32,
    /// Total miner payouts (satoshis)
    pub total_miner_sats: u64,
    /// Total node payouts (satoshis)
    pub total_node_sats: u64,
    /// Treasury amount (satoshis)
    pub treasury_sats: u64,
    /// TX fees (satoshis)
    pub tx_fees_sats: u64,
    /// Payout status
    pub status: String,
    /// Created timestamp
    pub created_at: i64,
}

// =============================================================================
// EQUIVOCATION PROOF RECORDS (P2P4-L7)
// =============================================================================

/// Equivocation proof record for Byzantine behavior evidence
///
/// P2P4-L7: Stores cryptographic proof when a node is caught signing
/// conflicting votes, providing evidence for slashing and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProofRecord {
    /// Auto-increment ID
    pub id: i64,
    /// Node ID that committed equivocation (32-byte blob)
    pub node_id: Vec<u8>,
    /// Serialized equivocation proof (both conflicting votes)
    pub proof_data: Vec<u8>,
    /// Unix timestamp when equivocation was detected
    pub detected_at: i64,
    /// Optional round number where equivocation occurred
    pub round_number: Option<i64>,
    /// Optional vote type description (e.g., "payout", "block")
    pub vote_type: Option<String>,
    /// Database creation timestamp
    pub created_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payout_status() {
        assert_eq!(PayoutStatus::parse("active"), Some(PayoutStatus::Active));
        assert_eq!(PayoutStatus::Confirmed.as_str(), "confirmed");
    }

    #[test]
    fn test_recipient_type() {
        assert_eq!(RecipientType::parse("miner"), Some(RecipientType::Miner));
        assert_eq!(RecipientType::Treasury.as_str(), "treasury");
    }

    // =========================================================================
    // 1. PayoutStatus roundtrip for every variant
    // =========================================================================
    #[test]
    fn test_payout_status_roundtrip_all() {
        let variants = [
            PayoutStatus::Active,
            PayoutStatus::Pending,
            PayoutStatus::Approved,
            PayoutStatus::Broadcast,
            PayoutStatus::Confirmed,
            PayoutStatus::Failed,
            PayoutStatus::Orphaned,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = PayoutStatus::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse PayoutStatus from '{}'", s));
            assert_eq!(*v, parsed, "Roundtrip failed for PayoutStatus::{:?}", v);
        }
    }

    // =========================================================================
    // 2. PayoutStatus parse unknown returns None
    // =========================================================================
    #[test]
    fn test_payout_status_parse_unknown() {
        assert_eq!(PayoutStatus::parse("bogus"), None);
        assert_eq!(PayoutStatus::parse(""), None);
        assert_eq!(PayoutStatus::parse("ACTIVE"), None);
    }

    // =========================================================================
    // 3. RecipientType roundtrip for every variant
    // =========================================================================
    #[test]
    fn test_recipient_type_roundtrip_all() {
        let variants = [
            RecipientType::Miner,
            RecipientType::Node,
            RecipientType::Treasury,
            RecipientType::TxFees,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = RecipientType::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse RecipientType from '{}'", s));
            assert_eq!(*v, parsed, "Roundtrip failed for RecipientType::{:?}", v);
        }
    }

    // =========================================================================
    // 4. RecipientType parse unknown returns None
    // =========================================================================
    #[test]
    fn test_recipient_type_parse_unknown() {
        assert_eq!(RecipientType::parse("bogus"), None);
        assert_eq!(RecipientType::parse(""), None);
        assert_eq!(RecipientType::parse("MINER"), None);
    }

    // =========================================================================
    // 5. VerificationResult roundtrip for all 5 variants
    // =========================================================================
    #[test]
    fn test_verification_result_roundtrip_all() {
        let variants = [
            VerificationResult::Pending,
            VerificationResult::Pass,
            VerificationResult::Fail,
            VerificationResult::Timeout,
            VerificationResult::Error,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = VerificationResult::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse VerificationResult from '{}'", s));
            assert_eq!(
                *v, parsed,
                "Roundtrip failed for VerificationResult::{:?}",
                v
            );
        }
    }

    // =========================================================================
    // 6. VerificationResult parse unknown returns None
    // =========================================================================
    #[test]
    fn test_verification_result_parse_unknown() {
        assert_eq!(VerificationResult::parse("bogus"), None);
        assert_eq!(VerificationResult::parse(""), None);
        assert_eq!(VerificationResult::parse("PASS"), None);
    }

    // =========================================================================
    // 20. WithdrawalStatus is_terminal
    // =========================================================================
}
