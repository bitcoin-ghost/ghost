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

//! Error types for reconciliation

use thiserror::Error;

/// Reconciliation errors
#[derive(Error, Debug)]
pub enum ReconciliationError {
    #[error("Settlement below minimum: {amount} < {minimum}")]
    BelowMinimum { amount: u64, minimum: u64 },

    #[error("Batch too small: {size} < {minimum}")]
    BatchTooSmall { size: usize, minimum: usize },

    #[error("Batch too large: {size} > {maximum}")]
    BatchTooLarge { size: usize, maximum: usize },

    #[error("Settlement not found: {id}")]
    SettlementNotFound { id: String },

    #[error("Batch not found: {id}")]
    BatchNotFound { id: String },

    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("Dispute active: {batch_id}")]
    DisputeActive { batch_id: String },

    #[error("Already finalized: {id}")]
    AlreadyFinalized { id: String },

    #[error("Invalid state transition: {from} -> {to}")]
    InvalidStateTransition { from: String, to: String },

    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    #[error("L1 transaction error: {0}")]
    L1TransactionError(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid batch: {0}")]
    InvalidBatch(String),

    #[error("Insufficient settlements: have {have}, need {need}")]
    InsufficientSettlements { have: usize, need: usize },

    #[error("Insufficient funds for {ghost_id}: required {required}, available {available}")]
    InsufficientFunds {
        ghost_id: String,
        required: u64,
        available: u64,
    },

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Dispute window active: ends at block {ends_at}, current {current}")]
    DisputeWindowActive { ends_at: u64, current: u64 },

    #[error("Invalid settlement: {0}")]
    InvalidSettlement(String),

    /// H-8: UTXO not found on L1 - lock may have been spent or reorged
    #[error("UTXO not found for lock: {lock_id}")]
    UtxoNotFound { lock_id: String },

    /// H-CRYPTO-3: UTXO has insufficient confirmations for finality
    #[error("Insufficient confirmations for UTXO {txid}:{vout}: {confirmations} < {required}")]
    InsufficientConfirmations {
        txid: String,
        vout: u32,
        confirmations: u32,
        required: u32,
    },

    /// H-8: Bitcoin RPC error during UTXO verification
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpcError(String),

    /// C-1: Settlement ownership verification failed
    #[error("Settlement ownership verification failed: {0}")]
    OwnershipVerificationFailed(String),

    /// C-2: Double-spend attempt within same batch
    #[error("Double-spend in batch: input {outpoint} already consumed")]
    DoubleSpendInBatch { outpoint: String },

    /// H-FUND-3: Cross-batch double-spend attempt
    #[error("Cross-batch double-spend: input {outpoint} already reserved for batch {existing_batch}, cannot use for {new_batch}")]
    CrossBatchDoubleSpend {
        outpoint: String,
        existing_batch: String,
        new_batch: String,
    },

    /// QUANTUM SAFETY: P2TR addresses are rejected
    #[error("Quantum-unsafe: P2TR addresses (bc1p...) are quantum-vulnerable. Use P2WPKH (bc1q...) instead.")]
    QuantumUnsafe,

    /// H-8: Arithmetic overflow in transaction building
    #[error("Arithmetic overflow: {0}")]
    Overflow(&'static str),

    /// M-VAL-1: Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// HIGH-5: RNG failure during cryptographic operations
    #[error("RNG failure: system entropy source unavailable")]
    RngFailure,

    /// M-14: Verification timeout - too many concurrent proof verifications
    #[error("Verification timeout: {reason}")]
    VerificationTimeout { reason: String },

    /// M-14: Semaphore was closed (should not happen in normal operation)
    #[error("Internal error: proof verification semaphore closed")]
    SemaphoreClosed,

    /// M-8: Too many pending verifications - rate limiting
    #[error("Too many pending verifications: {pending} >= {max}")]
    TooManyPendingVerifications { pending: usize, max: usize },

    /// M-14: Too many pending settlements - rate limiting
    #[error("Too many pending settlements: {count} >= {max}. Try again after current batch is processed.")]
    TooManyPendingSettlements { count: usize, max: usize },

    /// H-5: Merkle proof size too large
    #[error("Merkle proof too large: {size} > {max}")]
    ProofTooLarge { size: usize, max: usize },

    /// L1 broadcast failed
    #[error("L1 broadcast failed: {0}")]
    BroadcastFailed(String),

    /// Internal error for unexpected conditions
    #[error("Internal error: {details}")]
    InternalError { details: String },
}

pub type ReconciliationResult<T> = Result<T, ReconciliationError>;
