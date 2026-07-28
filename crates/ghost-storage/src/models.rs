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
// GHOST LOCK MODELS
// =============================================================================

/// Ghost Lock record for database persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostLockRecord {
    /// Unique lock ID (hex)
    pub lock_id: String,
    /// Owner's Ghost ID
    pub owner_ghost_id: String,
    /// Lock public key (hex)
    pub lock_pubkey: String,
    /// Recovery public key (hex)
    pub recovery_pubkey: String,
    /// Denomination (Micro, Small, Medium, Large, XLarge, Whale)
    pub denomination: String,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Timelock tier (Short, Standard, Long)
    pub timelock_tier: String,
    /// Block height when created
    pub creation_height: u32,
    /// Block height when recovery becomes available
    pub recovery_height: u32,
    /// Current state
    pub state: GhostLockState,
    /// Funding transaction ID (hex, None if not funded)
    pub funding_txid: Option<String>,
    /// Funding output index
    pub funding_vout: Option<u32>,
    /// Spend transaction ID (hex, None if not spent)
    pub spend_txid: Option<String>,
    /// Output script (hex)
    pub output_script: String,
    /// Jump risk tier (Low, Medium, High)
    pub jump_risk_tier: String,
    /// Next required jump height
    pub next_jump_height: Option<u32>,
    /// Created timestamp
    pub created_at: i64,
    /// Updated timestamp
    pub updated_at: i64,
    /// Lock source: "manual", "wraith_mix", "wraith_jump"
    pub source: String,
    /// Wraith service fee deducted at L2 (0 for non-wraith locks)
    pub wraith_fee_sats: u64,
    /// Key derivation index (stored at creation time for stable signing)
    pub key_index: Option<u32>,
}

/// Ghost Lock state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GhostLockState {
    /// Lock created but not funded
    Pending,
    /// Lock funded and active
    Active,
    /// Lock being jumped to new address
    Jumping,
    /// Lock is being settled, awaiting broadcast confirmation (H-PAY-1 fix)
    /// Safe to revert to Active if broadcast fails
    PendingSettlement,
    /// Lock spent normally (key path)
    Spent,
    /// Lock recovered (script path after timelock)
    Recovered,
    /// Lock expired (recovery window passed)
    Expired,
}

impl GhostLockState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Jumping => "jumping",
            Self::PendingSettlement => "pending_settlement",
            Self::Spent => "spent",
            Self::Recovered => "recovered",
            Self::Expired => "expired",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "jumping" => Some(Self::Jumping),
            "pending_settlement" => Some(Self::PendingSettlement),
            "spent" => Some(Self::Spent),
            "recovered" => Some(Self::Recovered),
            "expired" => Some(Self::Expired),
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
// WRAITH MODELS
// =============================================================================

/// Aggregate Pay-page stats returned by `Database::get_pay_stats`.
/// All fields are pool-wide counts or a single sum — no per-payment,
/// per-participant, or per-note detail is exposed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PayStats {
    pub payments_24h: u64,
    pub payments_total: u64,
    pub wraith_rounds_24h: u64,
    pub wraith_rounds_total: u64,
    pub wraith_rounds_active: u64,
    pub settlements_24h: u64,
    pub settlements_total: u64,
    pub epoch_fee_pool_sats: u64,
    pub unspent_notes: u64,
}

/// Wraith mixing round record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithRoundRecord {
    /// Round ID
    pub round_id: String,
    /// Coordinator node ID
    pub coordinator_id: String,
    /// Denomination for this round
    pub denomination: String,
    /// Amount per participant in satoshis
    pub amount_sats: u64,
    /// Current phase
    pub phase: WraithPhase,
    /// Number of participants
    pub participant_count: u32,
    /// Minimum participants required
    pub min_participants: u32,
    /// Maximum participants allowed
    pub max_participants: u32,
    /// Registration deadline timestamp
    pub registration_deadline: i64,
    /// Execution deadline timestamp
    pub execution_deadline: Option<i64>,
    /// Split phase transaction ID
    pub split_txid: Option<String>,
    /// Merge phase transaction ID
    pub merge_txid: Option<String>,
    /// Round status
    pub status: WraithStatus,
    /// Created timestamp
    pub created_at: i64,
    /// Updated timestamp
    pub updated_at: i64,
}

/// Wraith mixing phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WraithPhase {
    Registration,
    Signing,
    Split,
    Shuffle,
    Merge,
    Complete,
}

impl WraithPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Signing => "signing",
            Self::Split => "split",
            Self::Shuffle => "shuffle",
            Self::Merge => "merge",
            Self::Complete => "complete",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "registration" => Some(Self::Registration),
            "signing" => Some(Self::Signing),
            "split" => Some(Self::Split),
            "shuffle" => Some(Self::Shuffle),
            "merge" => Some(Self::Merge),
            "complete" => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Wraith round status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WraithStatus {
    Active,
    Completed,
    Failed,
    Refunded,
}

impl WraithStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Refunded => "refunded",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "refunded" => Some(Self::Refunded),
            _ => None,
        }
    }
}

// =============================================================================
// RECONCILIATION MODELS
// =============================================================================

/// L2 reconciliation batch record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationRecord {
    /// Batch ID
    pub batch_id: String,
    /// Settlement class (Express, Standard, Economy)
    pub settlement_class: String,
    /// Number of participants in batch
    pub participant_count: u32,
    /// Total amount in satoshis
    pub total_amount_sats: u64,
    /// Merkle root of batch entries
    pub merkle_root: String,
    /// L1 settlement transaction ID
    pub l1_txid: Option<String>,
    /// L1 block height of settlement
    pub l1_block_height: Option<u64>,
    /// Dispute deadline block height
    pub dispute_deadline: Option<u64>,
    /// Batch status
    pub status: ReconciliationStatus,
    /// Created timestamp
    pub created_at: i64,
    /// Finalized timestamp
    pub finalized_at: Option<i64>,
    /// Portion of this batch's fee pool that went to the node reward pool.
    /// Captured at batch creation so finalization can bump a running
    /// cumulative counter once the L1 tx reaches required confirmations.
    #[serde(default)]
    pub l2_node_rewards_sats: u64,
}

/// Reconciliation batch status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    Pending,
    Submitted,
    Disputed,
    Finalized,
    Failed,
}

impl ReconciliationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Disputed => "disputed",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "submitted" => Some(Self::Submitted),
            "disputed" => Some(Self::Disputed),
            "finalized" => Some(Self::Finalized),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

// =============================================================================
// WITHDRAWAL REQUEST MODELS
// =============================================================================

/// Withdrawal request record for L1 settlement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// Auto-increment ID
    pub id: Option<i64>,
    /// Owner's Ghost ID
    pub ghost_id: String,
    /// Source lock ID (hex)
    pub lock_id: String,
    /// Destination Bitcoin address
    pub destination_address: String,
    /// Amount to withdraw in satoshis
    pub amount_sats: u64,
    /// Fee to deduct in satoshis
    pub fee_sats: u64,
    /// Current status
    pub status: WithdrawalStatus,
    /// Settlement batch ID (if batched)
    pub batch_id: Option<String>,
    /// L1 transaction ID (if broadcast)
    pub l1_txid: Option<String>,
    /// Settlement class (express, standard, economy)
    pub settlement_class: String,
    /// Created timestamp
    pub created_at: i64,
    /// Updated timestamp
    pub updated_at: i64,
}

/// Withdrawal request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalStatus {
    /// Request submitted, waiting for batching
    Pending,
    /// Included in a batch
    Batched,
    /// Batch submitted to L1
    Submitted,
    /// L1 transaction confirmed
    Confirmed,
    /// Withdrawal failed
    Failed,
    /// Withdrawal cancelled by user
    Cancelled,
}

impl WithdrawalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Batched => "batched",
            Self::Submitted => "submitted",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "batched" => Some(Self::Batched),
            "submitted" => Some(Self::Submitted),
            "confirmed" => Some(Self::Confirmed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// Check if a status transition is valid
    ///
    /// Valid transitions:
    /// - pending -> batched, cancelled, failed
    /// - batched -> submitted, failed
    /// - submitted -> confirmed, failed
    /// - confirmed -> (terminal state)
    /// - failed -> (terminal state)
    /// - cancelled -> (terminal state)
    pub fn can_transition_to(&self, new_status: Self) -> bool {
        match self {
            Self::Pending => matches!(new_status, Self::Batched | Self::Cancelled | Self::Failed),
            Self::Batched => matches!(new_status, Self::Submitted | Self::Failed),
            Self::Submitted => matches!(new_status, Self::Confirmed | Self::Failed),
            // Terminal states cannot transition
            Self::Confirmed | Self::Failed | Self::Cancelled => false,
        }
    }

    /// Check if this is a terminal state (no further transitions allowed)
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Confirmed | Self::Failed | Self::Cancelled)
    }
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
    // 7. GhostLockState roundtrip for all 7 variants
    // =========================================================================
    #[test]
    fn test_ghost_lock_state_roundtrip_all() {
        let variants = [
            GhostLockState::Pending,
            GhostLockState::Active,
            GhostLockState::Jumping,
            GhostLockState::PendingSettlement,
            GhostLockState::Spent,
            GhostLockState::Recovered,
            GhostLockState::Expired,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = GhostLockState::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse GhostLockState from '{}'", s));
            assert_eq!(*v, parsed, "Roundtrip failed for GhostLockState::{:?}", v);
        }
    }

    // =========================================================================
    // 8. GhostLockState parse unknown returns None
    // =========================================================================
    #[test]
    fn test_ghost_lock_state_parse_unknown() {
        assert_eq!(GhostLockState::parse("bogus"), None);
        assert_eq!(GhostLockState::parse(""), None);
        assert_eq!(GhostLockState::parse("PENDING"), None);
    }

    // =========================================================================
    // 9. WraithPhase roundtrip for all 6 variants
    // =========================================================================
    #[test]
    fn test_wraith_phase_roundtrip_all() {
        let variants = [
            WraithPhase::Registration,
            WraithPhase::Signing,
            WraithPhase::Split,
            WraithPhase::Shuffle,
            WraithPhase::Merge,
            WraithPhase::Complete,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = WraithPhase::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse WraithPhase from '{}'", s));
            assert_eq!(*v, parsed, "Roundtrip failed for WraithPhase::{:?}", v);
        }
    }

    // =========================================================================
    // 10. WraithPhase parse unknown returns None
    // =========================================================================
    #[test]
    fn test_wraith_phase_parse_unknown() {
        assert_eq!(WraithPhase::parse("bogus"), None);
        assert_eq!(WraithPhase::parse(""), None);
        assert_eq!(WraithPhase::parse("REGISTRATION"), None);
    }

    // =========================================================================
    // 11. WraithStatus roundtrip for all 4 variants
    // =========================================================================
    #[test]
    fn test_wraith_status_roundtrip_all() {
        let variants = [
            WraithStatus::Active,
            WraithStatus::Completed,
            WraithStatus::Failed,
            WraithStatus::Refunded,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = WraithStatus::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse WraithStatus from '{}'", s));
            assert_eq!(*v, parsed, "Roundtrip failed for WraithStatus::{:?}", v);
        }
    }

    // =========================================================================
    // 12. WraithStatus parse unknown returns None
    // =========================================================================
    #[test]
    fn test_wraith_status_parse_unknown() {
        assert_eq!(WraithStatus::parse("bogus"), None);
        assert_eq!(WraithStatus::parse(""), None);
        assert_eq!(WraithStatus::parse("ACTIVE"), None);
    }

    // =========================================================================
    // 13. ReconciliationStatus roundtrip for all 5 variants
    // =========================================================================
    #[test]
    fn test_reconciliation_status_roundtrip_all() {
        let variants = [
            ReconciliationStatus::Pending,
            ReconciliationStatus::Submitted,
            ReconciliationStatus::Disputed,
            ReconciliationStatus::Finalized,
            ReconciliationStatus::Failed,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = ReconciliationStatus::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse ReconciliationStatus from '{}'", s));
            assert_eq!(
                *v, parsed,
                "Roundtrip failed for ReconciliationStatus::{:?}",
                v
            );
        }
    }

    // =========================================================================
    // 14. ReconciliationStatus parse unknown returns None
    // =========================================================================
    #[test]
    fn test_reconciliation_status_parse_unknown() {
        assert_eq!(ReconciliationStatus::parse("bogus"), None);
        assert_eq!(ReconciliationStatus::parse(""), None);
        assert_eq!(ReconciliationStatus::parse("PENDING"), None);
    }

    // =========================================================================
    // 15. WithdrawalStatus roundtrip for all 6 variants
    // =========================================================================
    #[test]
    fn test_withdrawal_status_roundtrip_all() {
        let variants = [
            WithdrawalStatus::Pending,
            WithdrawalStatus::Batched,
            WithdrawalStatus::Submitted,
            WithdrawalStatus::Confirmed,
            WithdrawalStatus::Failed,
            WithdrawalStatus::Cancelled,
        ];
        for v in &variants {
            let s = v.as_str();
            let parsed = WithdrawalStatus::parse(s)
                .unwrap_or_else(|| panic!("Failed to parse WithdrawalStatus from '{}'", s));
            assert_eq!(*v, parsed, "Roundtrip failed for WithdrawalStatus::{:?}", v);
        }
    }

    // =========================================================================
    // 16. WithdrawalStatus parse unknown returns None
    // =========================================================================
    #[test]
    fn test_withdrawal_status_parse_unknown() {
        assert_eq!(WithdrawalStatus::parse("bogus"), None);
        assert_eq!(WithdrawalStatus::parse(""), None);
        assert_eq!(WithdrawalStatus::parse("PENDING"), None);
    }

    // =========================================================================
    // 17. WithdrawalStatus can_transition_to valid paths
    // =========================================================================
    #[test]
    fn test_withdrawal_can_transition_valid() {
        // Pending -> Batched, Cancelled, Failed
        assert!(WithdrawalStatus::Pending.can_transition_to(WithdrawalStatus::Batched));
        assert!(WithdrawalStatus::Pending.can_transition_to(WithdrawalStatus::Cancelled));
        assert!(WithdrawalStatus::Pending.can_transition_to(WithdrawalStatus::Failed));

        // Batched -> Submitted, Failed
        assert!(WithdrawalStatus::Batched.can_transition_to(WithdrawalStatus::Submitted));
        assert!(WithdrawalStatus::Batched.can_transition_to(WithdrawalStatus::Failed));

        // Submitted -> Confirmed, Failed
        assert!(WithdrawalStatus::Submitted.can_transition_to(WithdrawalStatus::Confirmed));
        assert!(WithdrawalStatus::Submitted.can_transition_to(WithdrawalStatus::Failed));
    }

    // =========================================================================
    // 18. Terminal states cannot transition to anything
    // =========================================================================
    #[test]
    fn test_withdrawal_can_transition_from_terminal() {
        let terminal_states = [
            WithdrawalStatus::Confirmed,
            WithdrawalStatus::Failed,
            WithdrawalStatus::Cancelled,
        ];
        let all_states = [
            WithdrawalStatus::Pending,
            WithdrawalStatus::Batched,
            WithdrawalStatus::Submitted,
            WithdrawalStatus::Confirmed,
            WithdrawalStatus::Failed,
            WithdrawalStatus::Cancelled,
        ];
        for terminal in &terminal_states {
            for target in &all_states {
                assert!(
                    !terminal.can_transition_to(*target),
                    "{:?} should not be able to transition to {:?}",
                    terminal,
                    target,
                );
            }
        }
    }

    // =========================================================================
    // 19. Invalid skip transitions are rejected
    // =========================================================================
    #[test]
    fn test_withdrawal_can_transition_skip_invalid() {
        // Pending cannot skip to Confirmed or Submitted
        assert!(!WithdrawalStatus::Pending.can_transition_to(WithdrawalStatus::Confirmed));
        assert!(!WithdrawalStatus::Pending.can_transition_to(WithdrawalStatus::Submitted));

        // Batched cannot skip to Confirmed
        assert!(!WithdrawalStatus::Batched.can_transition_to(WithdrawalStatus::Confirmed));
    }

    // =========================================================================
    // 20. WithdrawalStatus is_terminal
    // =========================================================================
    #[test]
    fn test_withdrawal_is_terminal() {
        // Terminal states
        assert!(WithdrawalStatus::Confirmed.is_terminal());
        assert!(WithdrawalStatus::Failed.is_terminal());
        assert!(WithdrawalStatus::Cancelled.is_terminal());

        // Non-terminal states
        assert!(!WithdrawalStatus::Pending.is_terminal());
        assert!(!WithdrawalStatus::Batched.is_terminal());
        assert!(!WithdrawalStatus::Submitted.is_terminal());
    }
}
