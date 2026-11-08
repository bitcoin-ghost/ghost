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
//| FILE: error.rs                                                                                                       |
//|======================================================================================================================|

//! Error types for Bitcoin Ghost v1.4

use thiserror::Error;

/// Main error type for Ghost operations
#[derive(Error, Debug)]
pub enum GhostError {
    // =========================================================================
    // Identity Errors
    // =========================================================================
    #[error("Invalid Ed25519 key: {0}")]
    InvalidKey(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("Key file not found: {0}")]
    KeyFileNotFound(String),

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    // =========================================================================
    // Configuration Errors
    // =========================================================================
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid configuration value: {field} = {value}")]
    InvalidConfigValue { field: String, value: String },

    #[error("Missing required configuration: {0}")]
    MissingConfig(String),

    // =========================================================================
    // Bitcoin RPC Errors
    // =========================================================================
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpc(String),

    #[error("Bitcoin RPC connection failed: {0}")]
    BitcoinRpcConnection(String),

    #[error("Bitcoin RPC authentication failed")]
    BitcoinRpcAuth,

    #[error("Invalid block template: {0}")]
    InvalidBlockTemplate(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    // =========================================================================
    // Policy Errors
    // =========================================================================
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Transaction rejected by policy: tier={tier}, reason={reason}")]
    TransactionRejected { tier: String, reason: String },

    #[error("Invalid policy configuration: {0}")]
    InvalidPolicy(String),

    // =========================================================================
    // BUDS Classification Errors
    // =========================================================================
    #[error("BUDS classification error: {0}")]
    BudsClassification(String),

    #[error("Unknown transaction type: {0}")]
    UnknownTransactionType(String),

    // =========================================================================
    // Consensus Errors
    // =========================================================================
    #[error("Consensus timeout: round={round_id}")]
    ConsensusTimeout { round_id: u64 },

    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),

    #[error("Invalid vote: {0}")]
    InvalidVote(String),

    #[error("Duplicate vote from node: {node_id}")]
    DuplicateVote { node_id: String },

    #[error("Insufficient votes: got={got}, needed={needed}")]
    InsufficientVotes { got: u32, needed: u32 },

    #[error("Insufficient voters for BFT: have={available}, need={required}")]
    InsufficientVoters { required: usize, available: usize },

    #[error("Round not found: {0}")]
    RoundNotFound(u64),

    // =========================================================================
    // P2P Network Errors
    // =========================================================================
    #[error("P2P connection error: {0}")]
    P2PConnection(String),

    #[error("P2P message error: {0}")]
    P2PMessage(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Discovery failed: {0}")]
    Discovery(String),

    #[error("Rate limited: {0}")]
    RateLimited(String),

    #[error("Node banned: {0}")]
    NodeBanned(String),

    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),

    // =========================================================================
    // State Transition Errors
    // =========================================================================
    #[error("Invalid state transition: {0}")]
    InvalidState(String),

    // =========================================================================
    // Share Errors
    // =========================================================================
    #[error("Invalid share: {0}")]
    InvalidShare(String),

    #[error("Share difficulty too low: got={got}, needed={needed}")]
    ShareDifficultyTooLow { got: f64, needed: f64 },

    #[error("Duplicate share: {0}")]
    DuplicateShare(String),

    #[error("Share from unknown miner: {0}")]
    UnknownMiner(String),

    // =========================================================================
    // Payout Errors
    // =========================================================================
    #[error("Payout calculation error: {0}")]
    PayoutCalculation(String),

    #[error("Invalid payout proposal: {0}")]
    InvalidPayoutProposal(String),

    #[error(
        "No verification provider configured - cannot distribute node rewards without verification"
    )]
    NoVerificationProvider,

    #[error("Block finder address not found - cannot distribute TX fees")]
    BlockFinderAddressNotFound { node_id: String, tx_fees: u64 },

    #[error("TX fee allocation failed: block builder {node_id} not found, {tx_fees} sats unallocated - block production MUST be halted")]
    TxFeeAllocationFailed { node_id: String, tx_fees: u64 },

    #[error("Coinbase construction failed: {0}")]
    CoinbaseConstruction(String),

    #[error("Too many outputs: {count} exceeds limit {limit}")]
    TooManyOutputs { count: usize, limit: usize },

    #[error("Amount below dust threshold: {amount} < {threshold}")]
    DustAmount { amount: u64, threshold: u64 },

    #[error(
        "Treasury balance overflow: adding {amount} to {current_balance} would exceed u64::MAX"
    )]
    TreasuryOverflow { current_balance: u64, amount: u64 },

    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    // =========================================================================
    // Configuration Errors (startup validation)
    // =========================================================================
    #[error("Configuration error: {0}")]
    ConfigError(String),

    // =========================================================================
    // Cryptographic Errors (H-6)
    // =========================================================================
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    // =========================================================================
    // Storage Errors
    // =========================================================================
    #[error("Database error: {0}")]
    Database(String),

    #[error("Database migration failed: {0}")]
    Migration(String),

    #[error("Record not found: {table}.{key}")]
    RecordNotFound { table: String, key: String },

    // =========================================================================
    // Verification Errors
    // =========================================================================
    #[error("Verification challenge failed: {capability} - {reason}")]
    VerificationFailed { capability: String, reason: String },

    #[error("Verification timeout: {0}")]
    VerificationTimeout(String),

    #[error("Invalid verification response: {0}")]
    InvalidVerificationResponse(String),

    // =========================================================================
    // Address Errors
    // =========================================================================
    #[error("Invalid Bitcoin address: {0}")]
    InvalidAddress(String),

    // =========================================================================
    // Quantum Safety Errors
    // =========================================================================
    #[error("Quantum-unsafe address: {0}")]
    QuantumUnsafe(String),

    // =========================================================================
    // Elder Errors
    // =========================================================================
    #[error("Elder operation failed: {0}")]
    ElderOperation(String),

    #[error("Not an elder: {0}")]
    NotAnElder(String),

    #[error("Elder limit reached: {0}")]
    ElderLimitReached(u32),

    // =========================================================================
    // Coordinator Errors
    // =========================================================================
    #[error("Coordinator error: {0}")]
    Coordinator(String),

    #[error("Fire Ping timeout")]
    FirePingTimeout,

    #[error("Convergence failed: {0}")]
    ConvergenceFailed(String),

    // =========================================================================
    // Service State Errors
    // =========================================================================
    #[error("Service not running: {0}")]
    NotRunning(String),

    #[error("Service already running: {0}")]
    AlreadyRunning(String),

    // =========================================================================
    // Input Validation Errors
    // =========================================================================
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    // =========================================================================
    // General Errors
    // =========================================================================
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

/// Result type alias for Ghost operations
pub type GhostResult<T> = Result<T, GhostError>;

impl From<serde_json::Error> for GhostError {
    fn from(err: serde_json::Error) -> Self {
        GhostError::Serialization(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = GhostError::ConsensusTimeout { round_id: 42 };
        assert_eq!(err.to_string(), "Consensus timeout: round=42");

        let err = GhostError::InsufficientVotes { got: 5, needed: 10 };
        assert_eq!(err.to_string(), "Insufficient votes: got=5, needed=10");
    }

    #[test]
    fn test_error_conversion() {
        let json_err = serde_json::from_str::<i32>("invalid").unwrap_err();
        let ghost_err: GhostError = json_err.into();
        assert!(matches!(ghost_err, GhostError::Serialization(_)));
    }
}
