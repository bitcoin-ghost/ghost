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
//| FILE: lock.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Lock types for GSP Protocol
//!
//! Defines lock information and management types for the light wallet.

use serde::{Deserialize, Serialize};

use crate::auth::WalletProof;

/// Ghost lock status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GhostLockStatus {
    /// Lock is pending funding
    Pending,
    /// Lock is funded and active
    Active,
    /// Lock is being used in a transaction
    InUse,
    /// Lock is undergoing jump
    Jumping,
    /// Lock has been spent
    Spent,
    /// Lock is in recovery (timelock expired)
    Recovering,
    /// Lock recovery complete
    Recovered,
    /// Lock was invalidated
    Invalid,
    /// MED-ENUM-1 FIX: Unknown status for future compatibility
    /// Used when an unrecognized status string is received.
    /// This prevents silent data loss and allows graceful handling
    /// of new status values from updated backends.
    Unknown,
}

impl GhostLockStatus {
    /// Check if lock can be spent
    pub fn can_spend(&self) -> bool {
        matches!(self, GhostLockStatus::Active)
    }

    /// Check if lock can be jumped
    pub fn can_jump(&self) -> bool {
        matches!(self, GhostLockStatus::Active | GhostLockStatus::InUse)
    }

    /// Check if lock is in terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            GhostLockStatus::Spent | GhostLockStatus::Recovered | GhostLockStatus::Invalid
        )
    }
}

impl std::fmt::Display for GhostLockStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            GhostLockStatus::Pending => "pending",
            GhostLockStatus::Active => "active",
            GhostLockStatus::InUse => "in_use",
            GhostLockStatus::Jumping => "jumping",
            GhostLockStatus::Spent => "spent",
            GhostLockStatus::Recovering => "recovering",
            GhostLockStatus::Recovered => "recovered",
            GhostLockStatus::Invalid => "invalid",
            GhostLockStatus::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

/// Ghost lock information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostLockInfo {
    /// Unique lock ID (hex)
    pub lock_id: String,

    /// Current status
    pub status: GhostLockStatus,

    /// Lock capacity in satoshis
    pub capacity_sats: u64,

    /// Current balance in satoshis (may be less than capacity)
    pub balance_sats: u64,

    /// Denomination name (Micro, Small, Medium, etc.)
    pub denomination: String,

    /// Timelock tier (Short, Standard, Long)
    pub timelock_tier: String,

    /// Jump risk tier (Low, Medium, High, Critical)
    pub jump_risk_tier: String,

    /// Funding address (P2TR)
    pub funding_address: String,

    /// Funding transaction ID (if funded)
    pub funding_txid: Option<String>,

    /// Funding output index
    pub funding_vout: Option<u32>,

    /// Creation block height
    pub creation_height: u32,

    /// Recovery height (when timelock expires)
    pub recovery_height: u32,

    /// Next jump deadline height
    pub next_jump_height: Option<u32>,

    /// Whether jump is needed soon
    pub needs_jump: bool,

    /// Blocks until jump deadline (0 if not applicable)
    pub blocks_until_jump: u32,

    /// Creation timestamp (Unix seconds)
    pub created_at: i64,

    /// Last update timestamp
    pub updated_at: i64,
    /// Operator-derived lock public key (cooperative-path key).
    /// 33-byte SEC1 compressed, hex-encoded.
    #[serde(default)]
    pub lock_pubkey: String,
    /// Echo of the wallet-supplied recovery_pubkey.
    /// 33-byte SEC1 compressed, hex-encoded.
    #[serde(default)]
    pub recovery_pubkey: String,
    /// Echo of the wallet-supplied derivation index.
    #[serde(default)]
    pub recovery_index: u32,
    /// CSV blocks the recovery branch waits before becoming spendable.
    #[serde(default)]
    pub recovery_blocks: u32,
}

impl GhostLockInfo {
    /// Check if lock is funded
    pub fn is_funded(&self) -> bool {
        self.funding_txid.is_some()
    }

    /// Check if recovery is available (timelock expired)
    pub fn is_recovery_available(&self, current_height: u32) -> bool {
        current_height >= self.recovery_height
    }

    /// Get remaining blocks until recovery
    pub fn blocks_until_recovery(&self, current_height: u32) -> u32 {
        self.recovery_height.saturating_sub(current_height)
    }
}

/// Request to create a new ghost lock
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts the owner_pubkey and proof fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct LockRequest {
    /// Owner's public key (32 bytes hex)
    pub owner_pubkey: String,

    /// Lock capacity in satoshis
    pub capacity_sats: u64,

    /// Preferred denomination (optional, will be auto-selected)
    pub denomination: Option<String>,

    /// Preferred timelock tier (optional)
    pub timelock_tier: Option<String>,

    /// Authentication proof
    pub proof: WalletProof,
}

impl std::fmt::Debug for LockRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockRequest")
            .field("owner_pubkey", &"[REDACTED]")
            .field("capacity_sats", &self.capacity_sats)
            .field("denomination", &self.denomination)
            .field("timelock_tier", &self.timelock_tier)
            .field("proof", &self.proof)
            .finish()
    }
}

/// Response for lock creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockResponse {
    /// Whether creation succeeded
    pub success: bool,

    /// Created lock info
    pub lock: Option<GhostLockInfo>,

    /// Error message if failed
    pub error: Option<String>,
}

/// Jump request priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum JumpPriority {
    /// Normal priority (queued)
    #[default]
    Normal,
    /// High priority (expedited)
    High,
    /// Urgent (immediate, higher fee)
    Urgent,
}

impl std::fmt::Display for JumpPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JumpPriority::Normal => write!(f, "normal"),
            JumpPriority::High => write!(f, "high"),
            JumpPriority::Urgent => write!(f, "urgent"),
        }
    }
}

/// Request to jump a lock
///
/// # Security: Redacted Debug
///
/// The Debug implementation redacts the target_address and proof fields.
#[derive(Clone, Serialize, Deserialize)]
pub struct JumpRequest {
    /// Lock ID to jump
    pub lock_id: String,

    /// Priority level
    #[serde(default)]
    pub priority: JumpPriority,

    /// Target address for the jump (new lock)
    pub target_address: String,

    /// Authentication proof
    pub proof: WalletProof,
}

impl std::fmt::Debug for JumpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JumpRequest")
            .field("lock_id", &self.lock_id)
            .field("priority", &self.priority)
            .field("target_address", &"[REDACTED]")
            .field("proof", &self.proof)
            .finish()
    }
}

/// Response for jump request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpResponse {
    /// Whether jump was initiated
    pub success: bool,

    /// Lock ID
    pub lock_id: String,

    /// Jump transaction ID (if broadcast)
    pub jump_txid: Option<String>,

    /// New lock ID (after jump completes)
    pub new_lock_id: Option<String>,

    /// Estimated fee
    pub fee_sats: Option<u64>,

    /// Error message if failed
    pub error: Option<String>,
}

/// Lock funding confirmation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockFundingConfirmation {
    /// Lock ID
    pub lock_id: String,

    /// Funding transaction ID
    pub funding_txid: String,

    /// Funding output index
    pub funding_vout: u32,

    /// Confirmation block height
    pub block_height: u32,

    /// Number of confirmations
    pub confirmations: u32,
}

/// Lock state transition event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockStateTransition {
    /// Lock ID
    pub lock_id: String,

    /// Previous status
    pub from_status: GhostLockStatus,

    /// New status
    pub to_status: GhostLockStatus,

    /// Transition reason
    pub reason: String,

    /// Related transaction ID (if applicable)
    pub txid: Option<String>,

    /// Timestamp
    pub timestamp: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_status_serialize() {
        let status = GhostLockStatus::Active;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"active\"");

        let parsed: GhostLockStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, GhostLockStatus::Active);
    }

    #[test]
    fn test_lock_status_can_spend() {
        assert!(GhostLockStatus::Active.can_spend());
        assert!(!GhostLockStatus::Pending.can_spend());
        assert!(!GhostLockStatus::Spent.can_spend());
    }

    #[test]
    fn test_lock_status_can_jump() {
        assert!(GhostLockStatus::Active.can_jump());
        assert!(GhostLockStatus::InUse.can_jump());
        assert!(!GhostLockStatus::Pending.can_jump());
        assert!(!GhostLockStatus::Spent.can_jump());
    }

    #[test]
    fn test_lock_status_terminal() {
        assert!(GhostLockStatus::Spent.is_terminal());
        assert!(GhostLockStatus::Recovered.is_terminal());
        assert!(!GhostLockStatus::Active.is_terminal());
    }

    #[test]
    fn test_jump_priority_default() {
        let priority: JumpPriority = Default::default();
        assert_eq!(priority, JumpPriority::Normal);
    }

    #[test]
    fn test_lock_info_recovery() {
        let lock = GhostLockInfo {
            lock_id: "test".to_string(),
            status: GhostLockStatus::Active,
            capacity_sats: 100000,
            balance_sats: 100000,
            denomination: "Small".to_string(),
            timelock_tier: "Standard".to_string(),
            jump_risk_tier: "Low".to_string(),
            funding_address: "bc1q...".to_string(),
            funding_txid: Some("abc123".to_string()),
            funding_vout: Some(0),
            creation_height: 800000,
            recovery_height: 826000, // ~6 months
            next_jump_height: Some(810000),
            needs_jump: false,
            blocks_until_jump: 10000,
            created_at: 0,
            updated_at: 0,
            lock_pubkey: String::new(),
            recovery_pubkey: String::new(),
            recovery_index: 0,
            recovery_blocks: 26000,
        };

        assert!(lock.is_funded());
        assert!(!lock.is_recovery_available(800000));
        assert!(lock.is_recovery_available(826000));
        assert_eq!(lock.blocks_until_recovery(800000), 26000);
    }
}
