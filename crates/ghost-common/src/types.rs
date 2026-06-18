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
//| FILE: types.rs                                                                                                       |
//|======================================================================================================================|

//! Common types used across Bitcoin Ghost

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 32-byte Node ID (Ed25519 public key)
pub type NodeId = [u8; 32];

/// 32-byte block hash
pub type BlockHash = [u8; 32];

/// 32-byte transaction ID
pub type Txid = [u8; 32];

/// 64-byte Ed25519 signature
pub type Signature = [u8; 64];

/// Round identifier
pub type RoundId = u64;

/// Block height
pub type BlockHeight = u64;

/// Amount in satoshis
pub type Satoshis = u64;

/// Node capabilities flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NodeCapabilities {
    /// Archive mode enabled (+5 shares)
    pub archive_mode: bool,
    /// Ghost Pay L2 enabled (+4 shares)
    pub ghost_pay: bool,
    /// Public mining enabled (+3 shares)
    pub public_mining: bool,
    /// Reaper strict mode enabled (+2 shares)
    pub reaper: bool,
    /// Elder status (+1 share)
    pub elder_status: bool,
}

impl NodeCapabilities {
    /// Create new capabilities with all disabled
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate total shares (0-15)
    ///
    /// MEDIUM-STOR-1: Uses checked arithmetic to prevent overflow.
    /// The compile-time assertion below ensures max possible shares < i32::MAX.
    pub fn total_shares(&self) -> i32 {
        let mut shares = 0i32;
        if self.archive_mode {
            shares = shares
                .checked_add(crate::constants::ARCHIVE_MODE_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        if self.ghost_pay {
            shares = shares
                .checked_add(crate::constants::GHOST_PAY_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        if self.public_mining {
            shares = shares
                .checked_add(crate::constants::PUBLIC_MINING_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        if self.reaper {
            shares = shares.checked_add(crate::constants::REAPER_SHARES).expect(
                "BUG: share calculation overflow - max possible shares verified < i32::MAX",
            );
        }
        if self.elder_status {
            shares = shares
                .checked_add(crate::constants::ELDER_STATUS_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        shares
    }

    /// Check if node has any capabilities
    pub fn has_any(&self) -> bool {
        self.archive_mode
            || self.ghost_pay
            || self.public_mining
            || self.reaper
            || self.elder_status
    }
}

/// Capacity state for load balancing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityState {
    /// Below 50% capacity
    Healthy,
    /// 50-75% capacity
    Normal,
    /// 75-90% capacity
    SoftLimit,
    /// Above 90% capacity
    HardLimit,
}

impl CapacityState {
    /// Calculate from current/max miners
    ///
    /// M-25: Uses integer arithmetic to avoid floating-point imprecision.
    /// `(current * 100) / max` gives the integer percentage (truncated).
    pub fn from_load(current: u32, max: u32) -> Self {
        if max == 0 {
            return Self::HardLimit;
        }
        // M-25: Integer percentage — u64 intermediate prevents u32 overflow
        let percent = (current as u64 * 100) / max as u64;
        if percent < 50 {
            Self::Healthy
        } else if percent < 75 {
            Self::Normal
        } else if percent < 90 {
            Self::SoftLimit
        } else {
            Self::HardLimit
        }
    }

    /// Get load penalty for scoring
    pub fn load_penalty(&self) -> f64 {
        match self {
            Self::Healthy => 0.0,
            Self::Normal => 0.1,
            Self::SoftLimit => 0.3,
            Self::HardLimit => 1.0,
        }
    }
}

/// Consensus result types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusResult {
    /// Proposal approved by 67%+
    Approved {
        proposal_hash: [u8; 32],
        approval_count: u32,
        total_nodes: u32,
    },
    /// Proposal rejected by 67%+
    Rejected {
        proposal_hash: [u8; 32],
        rejection_count: u32,
        total_nodes: u32,
        reason: Option<String>,
    },
    /// Voting timed out
    Timeout {
        proposal_hash: [u8; 32],
        approvals: u32,
        rejections: u32,
        total_nodes: u32,
    },
    /// Error during consensus
    Error(String),
}

/// Vote type for consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Vote on payout proposal
    PayoutApproval,
    /// Vote on elder revocation
    ElderRevocation,
    /// Vote on share allocation
    ShareAllocation,
}

/// Revocation reason for elders
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Offline for 7+ days
    ExtendedOffline { offline_days: u64 },
    /// Malicious behavior detected
    MaliciousBehavior { description: String },
    /// Voluntary resignation
    Voluntary,
}

/// Block found event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFoundEvent {
    /// Block hash
    pub block_hash: BlockHash,
    /// Block height
    pub block_height: BlockHeight,
    /// Round ID
    pub round_id: RoundId,
    /// Winning miner pubkey hash
    pub winning_miner: [u8; 32],
    /// Node that found the block
    pub found_by_node: NodeId,
    /// Transaction fees in satoshis
    pub tx_fees_satoshis: Satoshis,
    /// Block subsidy in satoshis
    pub subsidy_satoshis: Satoshis,
    /// Timestamp
    pub timestamp: u64,
}

/// Share proof for P2P propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProof {
    /// Round ID
    pub round_id: RoundId,
    /// Miner pubkey hash
    pub miner_id: [u8; 32],
    /// Share difficulty met
    pub difficulty: f64,
    /// Work value
    pub work: f64,
    /// Share hash
    pub share_hash: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Node that received the share
    pub received_by: NodeId,
    /// M-MINE-1: Template ID (prev_block_hash) this share is for
    /// Used to validate share is for current or recent template
    #[serde(default)]
    pub template_id: Option<[u8; 32]>,
    /// Payout address for the miner (needed by remote nodes that haven't seen this miner)
    #[serde(default)]
    pub payout_address: Option<String>,
}

/// Payout proposal for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutProposal {
    /// Proposal hash (for voting)
    pub proposal_hash: [u8; 32],
    /// Round ID
    pub round_id: RoundId,
    /// Block hash
    pub block_hash: BlockHash,
    /// Block height
    pub block_height: BlockHeight,
    /// Proposing node
    pub proposer: NodeId,
    /// Miner payouts
    pub miner_payouts: Vec<PayoutEntry>,
    /// Node reward payouts
    pub node_payouts: Vec<PayoutEntry>,
    /// Treasury amount
    pub treasury_amount: Satoshis,
    /// H-MINE-3: Treasury address snapshot taken at round/proposal creation
    /// This prevents TOCTOU issues where the config might change between
    /// proposal creation and coinbase building. Used instead of live config.
    #[serde(default)]
    pub treasury_address: Vec<u8>,
    /// TX fees (to node operator)
    pub tx_fees: Satoshis,
    /// Total subsidy
    pub subsidy: Satoshis,
    /// Timestamp
    pub timestamp: u64,
    /// TX fees that could not be allocated (e.g., block finder has no address)
    /// This field tracks satoshis that would otherwise be lost (PO-H4)
    #[serde(default)]
    pub tx_fees_unallocated: Satoshis,
}

/// Single payout entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutEntry {
    /// Recipient address (script pubkey)
    pub address: Vec<u8>,
    /// Amount in satoshis
    pub amount: Satoshis,
    /// Recipient identifier (miner_id or node_id)
    pub recipient_id: [u8; 32],
    /// Payout type
    pub payout_type: PayoutType,
}

/// Type of payout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayoutType {
    /// Mining reward
    Mining,
    /// Node capability reward
    NodeReward,
    /// Treasury allocation
    Treasury,
    /// TX fees to node operator
    TxFees,
}

/// Health ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPing {
    /// Sender node ID
    pub node_id: NodeId,
    /// Public address for P2P connections
    pub public_address: String,
    /// Current block height
    pub block_height: BlockHeight,
    /// Current round ID
    pub round_id: RoundId,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Connected miners count
    pub miner_count: u32,
    /// Timestamp
    pub timestamp: u64,
    /// PoW proof for Sybil resistance (nonce, difficulty)
    /// Proves computational work was done to create this identity
    #[serde(default)]
    pub pow_proof: Option<(u64, u32)>,
    /// Truncated SHA-256 hashes of miner_ids active in the last N seconds on
    /// the sender. Used by peers to compute a deduplicated mesh-wide active
    /// miner count without leaking miner_ids in cleartext.
    /// Field is `#[serde(default)]` for backward compatibility — older nodes
    /// that don't include it deserialize to an empty Vec.
    #[serde(default, with = "ghost_common_active_hashes")]
    pub active_miner_id_hashes: Vec<[u8; 16]>,
    /// This node's own realized hashrate (TH/s) over a trailing window,
    /// computed from shares THIS node received directly (scoped by
    /// `received_by`, so replicated peer share-proofs aren't counted). Peers
    /// SUM these across the mesh for a pool-wide total: shares are partitioned
    /// by node, so the sum can't double-count and is identical on every node,
    /// and a miner migrating between nodes shifts work from one term to another
    /// without changing the total. `#[serde(default)]` for backward
    /// compatibility — older nodes that don't send it contribute 0.
    #[serde(default)]
    pub local_hashrate_th: f64,
    /// Hardware-derived effective miner capacity. Translator's load balancer
    /// uses `miner_count / max_capacity` to compute utilisation and route
    /// new arrivals to the under-utilised peer. 0 = pre-update node (treated
    /// as unknown / excluded from utilisation routing).
    #[serde(default)]
    pub max_capacity: u32,
}

/// Hex-encoded serialization for the active miner-id hash list.
/// Keeps health-ping JSON human-readable and matches the `serde_hex` style
/// used elsewhere for fixed-size byte arrays in this module.
mod ghost_common_active_hashes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[[u8; 16]], s: S) -> Result<S::Ok, S::Error> {
        let hex_strs: Vec<String> = v.iter().map(hex::encode).collect();
        serde::Serialize::serialize(&hex_strs, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 16]>, D::Error> {
        let hex_strs: Vec<String> = Vec::deserialize(d)?;
        let mut out = Vec::with_capacity(hex_strs.len());
        for s in hex_strs {
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 16 {
                return Err(serde::de::Error::custom(format!(
                    "expected 16 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            out.push(arr);
        }
        Ok(out)
    }
}

/// Errors for treasury address validation
#[derive(Debug, Error)]
pub enum TreasuryAddressError {
    /// Invalid M-of-N parameters
    #[error("Invalid M-of-N: M={m} must be <= N={n} and both must be between 1 and 15")]
    InvalidMofN { m: u8, n: u8 },

    /// Empty address
    #[error("Treasury address cannot be empty")]
    EmptyAddress,

    /// Invalid witness script
    #[error("Invalid witness script: {0}")]
    InvalidWitnessScript(String),

    /// Public key count mismatch
    #[error("Expected {expected} public keys, got {actual}")]
    PubkeyCountMismatch { expected: u8, actual: usize },

    /// P2TR address (quantum-unsafe)
    #[error("P2TR addresses (bc1p...) are quantum-vulnerable. Use P2WPKH (bc1q...) instead.")]
    QuantumUnsafe,
}

/// Treasury address configuration
///
/// Supports both single-sig and multi-sig (P2WSH) addresses for treasury payouts.
/// Multi-sig provides enhanced security for mainnet deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TreasuryAddress {
    /// Single-sig address (bech32 format)
    ///
    /// Example: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    Single(String),

    /// Multi-sig P2WSH address
    ///
    /// Requires M-of-N signatures to spend.
    MultiSig {
        /// P2WSH bech32 address
        address: String,

        /// Witness script (redeem script) in hex
        ///
        /// This is the actual multi-sig script that gets hashed to create
        /// the P2WSH address. Required for spending.
        witness_script: String,

        /// Required signatures (M in M-of-N)
        required: u8,

        /// Total signers (N in M-of-N)
        total: u8,

        /// Public keys of all signers (optional, for verification)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pubkeys: Vec<String>,
    },
}

impl TreasuryAddress {
    /// Create a single-sig treasury address
    pub fn single(address: impl Into<String>) -> Self {
        Self::Single(address.into())
    }

    /// Create a multi-sig treasury address
    ///
    /// # Arguments
    /// * `address` - P2WSH bech32 address
    /// * `witness_script` - Witness script (redeem script) in hex
    /// * `required` - Required signatures (M)
    /// * `total` - Total signers (N)
    pub fn multisig(
        address: impl Into<String>,
        witness_script: impl Into<String>,
        required: u8,
        total: u8,
    ) -> Result<Self, TreasuryAddressError> {
        // Validate M-of-N parameters
        if required == 0 || total == 0 || required > total || total > 15 {
            return Err(TreasuryAddressError::InvalidMofN {
                m: required,
                n: total,
            });
        }

        Ok(Self::MultiSig {
            address: address.into(),
            witness_script: witness_script.into(),
            required,
            total,
            pubkeys: Vec::new(),
        })
    }

    /// Create a multi-sig treasury address with public keys
    pub fn multisig_with_pubkeys(
        address: impl Into<String>,
        witness_script: impl Into<String>,
        required: u8,
        total: u8,
        pubkeys: Vec<String>,
    ) -> Result<Self, TreasuryAddressError> {
        // Validate M-of-N parameters
        if required == 0 || total == 0 || required > total || total > 15 {
            return Err(TreasuryAddressError::InvalidMofN {
                m: required,
                n: total,
            });
        }

        // Validate pubkey count if provided
        if !pubkeys.is_empty() && pubkeys.len() != total as usize {
            return Err(TreasuryAddressError::PubkeyCountMismatch {
                expected: total,
                actual: pubkeys.len(),
            });
        }

        Ok(Self::MultiSig {
            address: address.into(),
            witness_script: witness_script.into(),
            required,
            total,
            pubkeys,
        })
    }

    /// Get the address string (works for both single and multi-sig)
    pub fn address(&self) -> &str {
        match self {
            Self::Single(addr) => addr,
            Self::MultiSig { address, .. } => address,
        }
    }

    /// Check if this is a multi-sig address
    pub fn is_multisig(&self) -> bool {
        matches!(self, Self::MultiSig { .. })
    }

    /// Get M-of-N parameters for multi-sig
    pub fn multisig_params(&self) -> Option<(u8, u8)> {
        match self {
            Self::Single(_) => None,
            Self::MultiSig {
                required, total, ..
            } => Some((*required, *total)),
        }
    }

    /// Get the witness script for multi-sig
    pub fn witness_script(&self) -> Option<&str> {
        match self {
            Self::Single(_) => None,
            Self::MultiSig { witness_script, .. } => Some(witness_script),
        }
    }

    /// Validate the treasury address configuration
    ///
    /// # Quantum Safety
    ///
    /// Rejects P2TR addresses (bc1p...) for quantum safety. P2TR exposes
    /// public keys on-chain, making them vulnerable to quantum computer
    /// attacks while funds are locked.
    pub fn validate(&self) -> Result<(), TreasuryAddressError> {
        // Helper to check if address is P2TR (quantum-unsafe)
        fn is_p2tr_address(addr: &str) -> bool {
            addr.starts_with("bc1p") || addr.starts_with("tb1p") || addr.starts_with("bcrt1p")
        }

        match self {
            Self::Single(addr) => {
                if addr.is_empty() {
                    return Err(TreasuryAddressError::EmptyAddress);
                }
                // QUANTUM SAFETY: Reject P2TR addresses
                if is_p2tr_address(addr) {
                    return Err(TreasuryAddressError::QuantumUnsafe);
                }
                Ok(())
            }
            Self::MultiSig {
                address,
                witness_script,
                required,
                total,
                pubkeys,
            } => {
                if address.is_empty() {
                    return Err(TreasuryAddressError::EmptyAddress);
                }

                // QUANTUM SAFETY: Reject P2TR addresses
                if is_p2tr_address(address) {
                    return Err(TreasuryAddressError::QuantumUnsafe);
                }

                if *required == 0 || *total == 0 || *required > *total || *total > 15 {
                    return Err(TreasuryAddressError::InvalidMofN {
                        m: *required,
                        n: *total,
                    });
                }

                if witness_script.is_empty() {
                    return Err(TreasuryAddressError::InvalidWitnessScript(
                        "witness script cannot be empty".into(),
                    ));
                }

                // Validate hex encoding
                if hex::decode(witness_script).is_err() {
                    return Err(TreasuryAddressError::InvalidWitnessScript(
                        "witness script must be valid hex".into(),
                    ));
                }

                // Validate pubkey count if provided
                if !pubkeys.is_empty() && pubkeys.len() != *total as usize {
                    return Err(TreasuryAddressError::PubkeyCountMismatch {
                        expected: *total,
                        actual: pubkeys.len(),
                    });
                }

                Ok(())
            }
        }
    }

    /// Check if the address is empty
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(addr) => addr.is_empty(),
            Self::MultiSig { address, .. } => address.is_empty(),
        }
    }
}

impl Default for TreasuryAddress {
    fn default() -> Self {
        Self::Single(String::new())
    }
}

impl From<String> for TreasuryAddress {
    fn from(address: String) -> Self {
        Self::Single(address)
    }
}

impl From<&str> for TreasuryAddress {
    fn from(address: &str) -> Self {
        Self::Single(address.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_capabilities_shares() {
        let mut caps = NodeCapabilities::new();
        assert_eq!(caps.total_shares(), 0);

        caps.archive_mode = true;
        assert_eq!(caps.total_shares(), 5);

        caps.public_mining = true;
        assert_eq!(caps.total_shares(), 8); // 5 + 3

        caps.reaper = true;
        assert_eq!(caps.total_shares(), 10); // 5 + 3 + 2

        caps.ghost_pay = true;
        caps.elder_status = true;
        assert_eq!(caps.total_shares(), 15); // 5 + 3 + 2 + 4 + 1
    }

    #[test]
    fn test_reaper_works_independently() {
        // Reaper works with private mining (no public_mining flag)
        let mut caps = NodeCapabilities::new();
        caps.reaper = true;
        assert_eq!(caps.total_shares(), 2); // Reaper alone counts

        // Also works with public mining
        caps.public_mining = true;
        assert_eq!(caps.total_shares(), 5); // 2 + 3
    }

    #[test]
    fn test_capacity_state() {
        assert_eq!(CapacityState::from_load(10, 100), CapacityState::Healthy);
        assert_eq!(CapacityState::from_load(60, 100), CapacityState::Normal);
        assert_eq!(CapacityState::from_load(80, 100), CapacityState::SoftLimit);
        assert_eq!(CapacityState::from_load(95, 100), CapacityState::HardLimit);
    }

    #[test]
    fn test_treasury_address_single() {
        let addr = TreasuryAddress::single("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(!addr.is_multisig());
        assert_eq!(addr.address(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(addr.validate().is_ok());
    }

    #[test]
    fn test_treasury_address_single_empty() {
        let addr = TreasuryAddress::single("");
        assert!(addr.is_empty());
        assert!(matches!(
            addr.validate(),
            Err(TreasuryAddressError::EmptyAddress)
        ));
    }

    #[test]
    fn test_treasury_address_rejects_p2tr() {
        // P2TR addresses should be rejected for quantum safety

        // Mainnet P2TR
        let p2tr_mainnet = TreasuryAddress::single(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        );
        assert!(matches!(
            p2tr_mainnet.validate(),
            Err(TreasuryAddressError::QuantumUnsafe)
        ));

        // Testnet P2TR
        let p2tr_testnet = TreasuryAddress::single(
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        );
        assert!(matches!(
            p2tr_testnet.validate(),
            Err(TreasuryAddressError::QuantumUnsafe)
        ));

        // Regtest P2TR
        let p2tr_regtest = TreasuryAddress::single(
            "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6",
        );
        assert!(matches!(
            p2tr_regtest.validate(),
            Err(TreasuryAddressError::QuantumUnsafe)
        ));

        // P2WPKH should be accepted (quantum-safe)
        let p2wpkh = TreasuryAddress::single("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(p2wpkh.validate().is_ok());
    }

    #[test]
    fn test_treasury_address_multisig() {
        let addr =
            TreasuryAddress::multisig("bc1qmultisigaddress...", "522102abc...02def...52ae", 2, 3)
                .unwrap();

        assert!(addr.is_multisig());
        assert_eq!(addr.multisig_params(), Some((2, 3)));
        assert_eq!(addr.witness_script(), Some("522102abc...02def...52ae"));
    }

    #[test]
    fn test_treasury_address_multisig_invalid_m_of_n() {
        // M > N
        assert!(TreasuryAddress::multisig("addr", "script", 3, 2).is_err());

        // M = 0
        assert!(TreasuryAddress::multisig("addr", "script", 0, 2).is_err());

        // N = 0
        assert!(TreasuryAddress::multisig("addr", "script", 1, 0).is_err());

        // N > 15
        assert!(TreasuryAddress::multisig("addr", "script", 1, 16).is_err());
    }

    #[test]
    fn test_treasury_address_multisig_with_pubkeys() {
        let pubkeys = vec![
            "02abc...".to_string(),
            "02def...".to_string(),
            "02ghi...".to_string(),
        ];

        let addr = TreasuryAddress::multisig_with_pubkeys(
            "bc1qmultisigaddress...",
            "522102abc...52ae",
            2,
            3,
            pubkeys,
        )
        .unwrap();

        assert!(addr.is_multisig());
    }

    #[test]
    fn test_treasury_address_multisig_pubkey_mismatch() {
        let pubkeys = vec!["02abc...".to_string(), "02def...".to_string()];

        // 2 pubkeys but total is 3
        let result = TreasuryAddress::multisig_with_pubkeys(
            "bc1qmultisigaddress...",
            "522102abc...52ae",
            2,
            3,
            pubkeys,
        );

        assert!(matches!(
            result,
            Err(TreasuryAddressError::PubkeyCountMismatch { .. })
        ));
    }

    #[test]
    fn test_treasury_address_from_string() {
        let addr: TreasuryAddress = "bc1qtest...".into();
        assert!(!addr.is_multisig());
        assert_eq!(addr.address(), "bc1qtest...");
    }

    #[test]
    fn test_treasury_address_serde_single() {
        let addr = TreasuryAddress::single("bc1qtest...");
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, "\"bc1qtest...\"");

        let parsed: TreasuryAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_treasury_address_serde_multisig() {
        let addr = TreasuryAddress::multisig("bc1qmultisig", "abcd1234", 2, 3).unwrap();

        let json = serde_json::to_string(&addr).unwrap();
        let parsed: TreasuryAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, parsed);
    }

    fn sample_health_ping() -> HealthPing {
        HealthPing {
            node_id: [7u8; 32],
            public_address: String::new(),
            block_height: 0,
            round_id: 0,
            capabilities: NodeCapabilities::new(),
            miner_count: 2,
            timestamp: 1,
            pow_proof: None,
            active_miner_id_hashes: vec![[1u8; 16], [2u8; 16]],
            local_hashrate_th: 4.0,
            max_capacity: 0,
        }
    }

    #[test]
    fn health_ping_hashrate_roundtrip() {
        let ping = sample_health_ping();
        let json = serde_json::to_string(&ping).unwrap();
        let back: HealthPing = serde_json::from_str(&json).unwrap();
        assert_eq!(back.local_hashrate_th, 4.0);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
    }

    #[test]
    fn health_ping_deserializes_without_hashrate_field() {
        // Emulate an OLDER node's ping that predates `local_hashrate_th`:
        // serialize, strip the field, and confirm it defaults to 0.0 (and the
        // rest of the ping is unaffected). Proves the wire change is additive.
        let ping = sample_health_ping();
        let mut v = serde_json::to_value(&ping).unwrap();
        assert!(v
            .as_object_mut()
            .unwrap()
            .remove("local_hashrate_th")
            .is_some());
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert_eq!(back.local_hashrate_th, 0.0);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
        assert_eq!(back.miner_count, 2);
    }
}
