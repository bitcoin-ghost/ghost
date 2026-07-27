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
//| FILE: messages.rs                                                                                                    |
//|======================================================================================================================|

//! WebSocket message types for GSP Protocol
//!
//! Defines the bidirectional message format for client-server communication.

use serde::{Deserialize, Serialize};

use crate::auth::WalletProof;
use crate::lock::GhostLockInfo;
use crate::payment::{PaymentMode, PaymentStatus, PreparedPayment};

// Re-export instant types for convenience
pub use ghost_common::instant::{
    InstantCapability, InstantCondition, LockSnapshot, SignedInstantPayment,
};

/// Messages sent from Light Wallet client to GSP server
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    // =========================================================================
    // Session Management
    // =========================================================================
    /// Authenticate with session token
    Authenticate {
        /// JWT session token
        token: String,
    },

    /// Ping to keep connection alive
    Ping {
        /// Optional timestamp for latency measurement
        timestamp: Option<i64>,
    },

    // =========================================================================
    // Balance & Queries
    // =========================================================================
    /// Request current balance
    GetBalance {
        /// Max derivation index for Silent Payment scanning (default: 10)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_k: Option<u32>,
    },

    /// Request UTXOs with minimum confirmations
    GetUtxos {
        /// Minimum confirmations required
        min_confirmations: u32,
    },

    /// Request all ghost locks for this wallet
    GetGhostLocks,

    /// Request transaction history
    GetTransactions {
        /// Maximum number of transactions to return
        limit: u32,
        /// Offset for pagination
        offset: u32,
        /// Optional bech32 ghost-id of the requesting wallet, used so
        /// ghost-pay can match L2 ledger rows where this wallet is the
        /// recipient (`merchant_wallet_id` is stored as bech32 — the
        /// only stable identifier the sender has at INSERT time). The
        /// session-static wallet_id (which the GSP server forwards
        /// separately) matches sender-side rows. Without this field,
        /// recipients see only sent payments, never received ones.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wallet_bech32: Option<String>,
    },

    // =========================================================================
    // Payments
    // =========================================================================
    /// Prepare a payment (requires WalletProof)
    PreparePayment {
        /// Recipient Ghost ID or Bitcoin address
        recipient: String,
        /// Amount in satoshis
        amount_sats: u64,
        /// Payment mode (ghostpay or wraith)
        mode: PaymentMode,
        /// Authentication proof
        proof: WalletProof,
        /// Optional memo/note
        #[serde(skip_serializing_if = "Option::is_none")]
        memo: Option<String>,
        /// Encrypted label metadata (80 bytes, base64 encoded)
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_metadata: Option<String>,
    },

    /// Submit a signed payment
    SubmitSignedPayment {
        /// Payment ID from prepare_payment response
        payment_id: String,
        /// Schnorr signature (64 bytes hex)
        signature: String,
        /// Public key used for signing (32 bytes hex)
        public_key: String,
    },

    /// One-shot L2 payment. Replaces the misshapen
    /// `PreparePayment` → wallet-signs-sighash → `SubmitSignedPayment`
    /// dance. L2 transfers don't produce a Bitcoin tx — they're
    /// authenticated debits/credits against the operator's ledger.
    /// The session auth proof is the right primitive; per-payment
    /// sighash signing was a wire-format mismatch.
    SendL2Payment {
        /// Recipient Ghost ID or payment address.
        recipient: String,
        /// Amount in satoshis.
        amount_sats: u64,
        /// Authentication proof (per-call, prevents replay).
        proof: WalletProof,
        /// Optional memo (max 59 chars — OP_RETURN-compatible
        /// length even though L2 transfers don't actually emit
        /// OP_RETURN).
        #[serde(skip_serializing_if = "Option::is_none")]
        memo: Option<String>,
    },

    /// Get payment status
    ///
    /// H-1: Requires wallet proof for authorization to prevent information leakage
    GetPaymentStatus {
        /// Payment ID to query
        payment_id: String,
        /// H-1: Authentication proof to verify wallet ownership
        proof: WalletProof,
    },

    /// Cancel a pending payment
    CancelPayment {
        /// Payment ID to cancel
        payment_id: String,
        /// Authentication proof
        proof: WalletProof,
    },

    // =========================================================================
    // Ghost Locks
    // =========================================================================
    /// Prepare a new ghost lock.
    ///
    /// The wallet supplies its own `recovery_pubkey` so the lock script's
    /// recovery branch is spendable by the user — not by the operator.
    /// This is what makes the timelock recovery path a real unilateral exit:
    /// after the timelock expires, the user can spend their lock with just
    /// their seed phrase, no operator cooperation needed.
    ///
    /// The operator still derives the `lock_pubkey` (cooperative-path key)
    /// from its own keys, because fast L2 spends require operator-side
    /// signing. The split is: lock_pubkey = operator (fast cooperative
    /// path), recovery_pubkey = user (slow unilateral fallback).
    PrepareGhostLock {
        /// Owner's public key (32 bytes x-only, hex). Wallet's GSP auth
        /// identity — not used in the lock script, kept for accounting.
        owner_pubkey: String,
        /// Lock capacity in satoshis.
        capacity_sats: u64,
        /// User-derived recovery public key. 33-byte SEC1-compressed,
        /// hex-encoded (66 chars). Goes into the lock script's recovery
        /// branch. Wallet derives it from its own GhostKeys at
        /// `recovery_index` and keeps the matching secret locally.
        recovery_pubkey: String,
        /// Wallet-side derivation index used to produce `recovery_pubkey`.
        /// Recorded by the operator alongside the lock for diagnostics
        /// and for the wallet to look up which secret to sign with at
        /// recovery time. Independent of any operator-side index.
        recovery_index: u32,
    },

    /// Confirm ghost lock funding
    ConfirmGhostLockFunding {
        /// Lock ID
        lock_id: String,
        /// Funding transaction ID
        funding_txid: String,
        /// Authentication proof
        proof: WalletProof,
    },

    /// Register the wallet's BIP-352 scan public key with the GSP so the
    /// server can detect incoming silent payments on the wallet's behalf.
    /// The scan key is public (only used for detection, never for spending);
    /// the wallet keeps the matching scan_secret.
    RegisterScanKey {
        /// 33-byte SEC1 compressed scan public key, hex-encoded.
        scan_pubkey: String,
        /// Authentication proof (action: "register_scan_key").
        proof: WalletProof,
    },

    /// Request emergency jump for a lock
    RequestJump {
        /// Lock ID to jump
        lock_id: String,
        /// Priority level (normal, high, urgent)
        priority: String,
        /// Target address for the jump
        target_address: String,
        /// Authentication proof
        proof: WalletProof,
    },

    // =========================================================================
    // Subscriptions
    // =========================================================================
    /// Subscribe to balance updates
    SubscribeBalance,

    /// Subscribe to payment notifications
    SubscribePayments,

    /// Subscribe to lock notifications
    SubscribeLocks,

    /// Unsubscribe from a subscription
    Unsubscribe {
        /// Subscription type to cancel
        subscription: String,
    },

    /// Subscribe to chain reorganization notifications
    SubscribeReorgs,

    /// Unsubscribe from chain reorganization notifications
    UnsubscribeReorgs,

    /// Subscribe to BIP-352 silent-payment candidate transaction pushes.
    /// Server pushes every taproot-output-bearing transaction with its
    /// computed ephemeral pubkey; wallet runs scanner locally with its
    /// scan secret. Server never learns the wallet's scan secret.
    SubscribeSilentPayments,

    /// Unsubscribe from silent-payment pushes.
    UnsubscribeSilentPayments,

    // =========================================================================
    // Instant Payments
    // =========================================================================
    /// Check if a lock is instant-capable for a payment amount
    CheckInstantCapability {
        /// Lock ID to check
        lock_id: String,
        /// Amount to pay (sats)
        amount_sats: u64,
    },

    /// Subscribe to real-time lock state updates
    SubscribeLockState {
        /// Lock ID to monitor
        lock_id: String,
    },

    /// Unsubscribe from lock state updates
    UnsubscribeLockState {
        /// Lock ID to stop monitoring
        lock_id: String,
    },

    /// Accept an instant payment as merchant
    ///
    /// M-9 SECURITY: This message now REQUIRES a SignedInstantPayment from the sender.
    /// The GSP verifies the sender's BIP-340 Schnorr signature before accepting.
    /// Without this verification, anyone could claim payments from any lock.
    AcceptInstantPayment {
        /// Sender's lock ID
        sender_lock_id: String,
        /// Payment amount (sats)
        amount_sats: u64,
        /// Merchant's authentication proof
        proof: WalletProof,
        /// M-9 FIX: Signed instant payment from sender (required)
        /// Contains sender's BIP-340 Schnorr signature over the payment details.
        /// The payment_id, sender_lock_id, recipient, and amount are bound by this signature.
        signed_payment: SignedInstantPayment,
    },

    // =========================================================================
    // Confidential Transfers
    // =========================================================================
    /// Submit a confidential transfer with Groth16 proof
    SubmitConfidentialTransfer {
        /// Groth16 proof (192 bytes hex)
        proof_hex: String,
        /// Current tree root before transfer
        old_commitment_root: String,
        /// Expected tree root after transfer
        new_commitment_root: String,
        /// Nullifier proving note ownership (prevents double-spend)
        nullifier: String,
        /// Sender's new change commitment
        sender_new_commitment: String,
        /// Recipient's new balance commitment
        recipient_new_commitment: String,
        /// Sender's note position in tree
        sender_index: u64,
        /// Recipient's note position in tree
        recipient_index: u64,
        /// Recipient's owner pubkey (for notification routing)
        recipient_owner_pubkey: String,
    },

    /// Shield plaintext balance into a confidential commitment
    ShieldBalance {
        /// Amount to shield (satoshis)
        amount_sats: u64,
        /// Random blinding factor (32 bytes hex)
        blinding_hex: String,
        /// Owner's public key (32 bytes hex)
        owner_pubkey: String,
        /// Authentication proof
        proof: WalletProof,
    },

    /// Get current commitment tree state
    GetCommitmentTreeState,

    /// Get confidential notes for a specific owner
    GetConfidentialNotes {
        /// Owner public key (32 bytes hex)
        owner_pubkey: String,
    },

    /// Subscribe to confidential transfer notifications
    SubscribeConfidential,

    /// Get recent L2 transactions with encrypted fields for wallet scanning
    GetRecentL2Transactions {
        /// Only return transactions from checkpoints above this height
        since_height: u64,
    },
}

/// Messages sent from GSP server to Light Wallet client
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    // =========================================================================
    // Session Management
    // =========================================================================
    /// Authentication result
    AuthResult {
        /// Whether authentication succeeded
        success: bool,
        /// Wallet ID if successful
        wallet_id: Option<String>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Pong response to ping
    Pong {
        /// Echoed timestamp
        timestamp: Option<i64>,
        /// Server timestamp
        server_time: i64,
    },

    /// Generic error response
    Error {
        /// Error code
        code: String,
        /// Human-readable error message
        message: String,
        /// Related request ID if applicable
        request_id: Option<String>,
    },

    // =========================================================================
    // Balance & Query Responses
    // =========================================================================
    /// Balance update (response or push notification)
    BalanceUpdate {
        /// Confirmed balance in satoshis
        confirmed: u64,
        /// Unconfirmed balance in satoshis
        unconfirmed: u64,
        /// Amount locked in Ghost Locks
        locked: u64,
    },

    /// UTXO list response
    Utxos {
        /// List of UTXOs
        utxos: Vec<UtxoInfo>,
        /// Total value in satoshis
        total_sats: u64,
    },

    /// Ghost locks list response
    GhostLocks {
        /// List of ghost locks
        locks: Vec<GhostLockInfo>,
        /// Total locked value
        total_locked_sats: u64,
    },

    /// Transaction history response
    Transactions {
        /// List of transactions
        transactions: Vec<TransactionInfo>,
        /// Total count (for pagination)
        total_count: u32,
    },

    // =========================================================================
    // Payment Responses & Notifications
    // =========================================================================
    /// Payment preparation result
    PaymentPrepared {
        /// Whether preparation succeeded
        success: bool,
        /// Prepared payment details
        payment: Option<PreparedPayment>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Payment submission result
    PaymentSubmitted {
        /// Whether submission succeeded
        success: bool,
        /// Payment ID
        payment_id: String,
        /// Transaction ID if broadcast
        txid: Option<String>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Reply to [`ClientMessage::SendL2Payment`]. Carries the
    /// operator-assigned `payment_id` on success so the wallet can
    /// reference the L2 ledger entry later (e.g. for status polls
    /// or settlement reconciliation).
    PaymentSent {
        success: bool,
        /// Operator-assigned payment_id. None on failure.
        payment_id: Option<String>,
        /// Echoed amount and recipient for confirmation.
        amount_sats: u64,
        recipient: String,
        /// Operator-side status string (e.g. "pending",
        /// "settled"). Pending means the L2 entry was recorded
        /// but the ZK proof / settlement step is still required.
        status: Option<String>,
        /// Error message if failed.
        error: Option<String>,
    },

    /// M-14 FIX: Payment cancellation result (distinct from PaymentSubmitted)
    PaymentCancelled {
        /// Whether cancellation succeeded
        success: bool,
        /// Payment ID that was cancelled
        payment_id: String,
        /// Error message if cancellation failed
        error: Option<String>,
    },

    /// Payment status response
    ///
    /// PAY-3 FIX: Added version field for optimistic locking. Clients should include
    /// this version when making state changes to detect concurrent modifications.
    PaymentStatus {
        /// Payment ID
        payment_id: String,
        /// Current status
        status: PaymentStatus,
        /// Confirmations if confirmed
        confirmations: Option<u32>,
        /// PAY-3 FIX: Version for optimistic locking (detects concurrent modifications)
        /// Clients should echo this value in subsequent state change requests
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<u64>,
    },

    /// Payment received notification (push)
    PaymentReceived {
        /// Payment ID
        payment_id: String,
        /// Amount in satoshis
        amount_sats: u64,
        /// Sender Ghost ID if known
        sender: Option<String>,
        /// Transaction ID
        txid: String,
        /// Encrypted label metadata (80 bytes, base64 encoded)
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_metadata: Option<String>,
        /// Ephemeral public key for metadata decryption (33 bytes hex)
        #[serde(skip_serializing_if = "Option::is_none")]
        ephemeral_pubkey: Option<String>,
    },

    /// Payment confirmed notification (push)
    PaymentConfirmed {
        /// Payment ID
        payment_id: String,
        /// Number of confirmations
        confirmations: u32,
    },

    // =========================================================================
    // Ghost Lock Responses & Notifications
    // =========================================================================
    /// Lock preparation result.
    ///
    /// On success the operator echoes back the full lock-script details
    /// so the wallet can (1) verify the operator built the lock with
    /// the wallet's supplied `recovery_pubkey`, and (2) reconstruct the
    /// witness script later for the recovery spend. The wallet pins
    /// these locally keyed by `lock_id`; without them recovery is
    /// impossible (P2WSH spends require revealing the script).
    LockPrepared {
        success: bool,
        lock_id: Option<String>,
        /// P2WSH funding address (`bc1q...` / `tb1q...`).
        funding_address: Option<String>,
        required_sats: Option<u64>,
        /// Operator-derived lock public key (cooperative path).
        /// 33-byte SEC1 compressed, hex.
        lock_pubkey: Option<String>,
        /// Echo of the wallet-supplied recovery public key. The wallet
        /// MUST verify this matches the value it sent before
        /// considering the lock prepared — otherwise an operator could
        /// silently substitute its own key and steal the recovery path.
        recovery_pubkey: Option<String>,
        /// Echo of the wallet's `recovery_index`. Same diligence —
        /// the wallet checks this matches what it sent.
        recovery_index: Option<u32>,
        /// CSV blocks the recovery branch waits before becoming
        /// spendable.
        recovery_blocks: Option<u32>,
        /// Block height the lock was created at. Combined with
        /// `recovery_blocks` gives the absolute height after which the
        /// recovery path is spendable.
        creation_height: Option<u32>,
        error: Option<String>,
    },

    /// Lock funding confirmed
    LockConfirmed {
        /// Lock ID
        lock_id: String,
        /// Funding transaction ID
        txid: String,
        /// Block height of confirmation
        block_height: u32,
    },

    /// Jump request result
    JumpRequested {
        /// Whether jump was initiated
        success: bool,
        /// Lock ID
        lock_id: String,
        /// Jump transaction ID if broadcast
        jump_txid: Option<String>,
        /// Error message if failed
        error: Option<String>,
    },

    /// Push: a candidate transaction the wallet should scan locally for
    /// silent-payment matches. Sent when the wallet has subscribed via
    /// `SubscribeSilentPayments` and the server has chain-extracted the
    /// transaction's ephemeral pubkey + taproot outputs.
    CandidateTransaction {
        /// 33-byte SEC1 compressed ephemeral input-set pubkey, hex.
        ephemeral_pubkey: String,
        /// All taproot outputs from the transaction.
        outputs: Vec<CandidateOutput>,
        /// Transaction id (32 bytes hex).
        txid: String,
        /// Block height the tx was confirmed at, or `None` for mempool.
        block_height: Option<u32>,
    },

    /// BIP-352 scan-key registration result
    ScanKeyRegistered {
        /// Whether registration succeeded
        success: bool,
        /// Error message if failed
        error: Option<String>,
    },

    /// Lock state changed notification (push)
    LockStateChanged {
        /// Lock ID
        lock_id: String,
        /// Previous state
        old_state: String,
        /// New state
        new_state: String,
    },

    // =========================================================================
    // Subscription Confirmations
    // =========================================================================
    /// Subscription confirmed
    Subscribed {
        /// Subscription type
        subscription: String,
    },

    /// Unsubscription confirmed
    Unsubscribed {
        /// Subscription type
        subscription: String,
    },

    // =========================================================================
    // Instant Payment Responses & Notifications
    // =========================================================================
    /// Instant capability check result
    InstantCapabilityResult {
        /// Lock ID that was checked
        lock_id: String,
        /// Whether instant payment is possible
        capable: bool,
        /// Maximum instant payment amount (sats)
        max_instant_sats: u64,
        /// Confidence score (0.0 - 1.0)
        confidence: f32,
        /// Block height until this capability is valid
        valid_until_height: u64,
        /// Conditions that passed (as bitmap)
        conditions_met: u8,
        /// Conditions that failed (as bitmap)
        conditions_failed: u8,
        /// Error message if check failed
        error: Option<String>,
    },

    /// Lock state subscription confirmed
    LockStateSubscribed {
        /// Lock ID being monitored
        lock_id: String,
        /// Initial snapshot of lock state
        snapshot: LockStateSnapshot,
    },

    /// Lock state subscription cancelled
    LockStateUnsubscribed {
        /// Lock ID no longer monitored
        lock_id: String,
    },

    /// Real-time lock state update (push notification)
    LockStateUpdate {
        /// Lock ID
        lock_id: String,
        /// Updated snapshot
        snapshot: LockStateSnapshot,
        /// What changed
        change_type: LockStateChangeType,
        /// Timestamp
        timestamp: i64,
    },

    /// Instant payment accepted (merchant side)
    InstantPaymentAccepted {
        /// Payment ID (32 bytes hex)
        payment_id: String,
        /// Sender's lock ID
        sender_lock_id: String,
        /// Amount (sats)
        amount_sats: u64,
        /// Expected settlement block
        settlement_block: u64,
        /// Confidence at acceptance
        confidence: f32,
        /// Timestamp
        timestamp: i64,
    },

    /// Instant payment settled notification
    InstantPaymentSettled {
        /// Payment ID
        payment_id: String,
        /// Settlement block height
        settled_at_height: u64,
        /// Final status (confirmed/failed)
        success: bool,
    },

    // =========================================================================
    // Chain Reorganization Notifications
    // =========================================================================
    /// Reorg subscription confirmed
    ReorgsSubscribed,

    /// Reorg subscription cancelled
    ReorgsUnsubscribed,

    /// L1 (Bitcoin) chain reorganization detected (push notification)
    L1ReorgDetected {
        /// Block height where reorg started
        reorg_height: u64,
        /// Number of blocks reorganized
        depth: u32,
        /// Previous chain tip hash
        old_tip: String,
        /// New chain tip hash
        new_tip: String,
        /// Payments affected by this reorg (payment IDs that lost confirmations)
        affected_payments: Vec<String>,
        /// Locks affected by this reorg (lock IDs that lost confirmations)
        affected_locks: Vec<String>,
        /// Timestamp when reorg was detected
        detected_at: i64,
    },

    /// L2 (Ghost Pay) chain reorganization detected (push notification)
    L2ReorgDetected {
        /// Virtual block height where reorg started
        reorg_height: u64,
        /// Number of virtual blocks reorganized
        depth: u32,
        /// Previous state root
        old_state_root: String,
        /// New state root
        new_state_root: String,
        /// Reason for reorg (fork_resolution, equivocation, network_partition)
        reason: L2ReorgReason,
        /// Payments affected (payment IDs with changed status)
        affected_payments: Vec<String>,
        /// Whether any pending L2 transfers were rolled back
        transfers_rolled_back: u32,
        /// Timestamp when reorg was detected
        detected_at: i64,
    },

    /// A specific payment was affected by a chain reorg
    PaymentReorged {
        /// Payment ID
        payment_id: String,
        /// Layer where reorg occurred (l1 or l2)
        layer: ReorgLayer,
        /// Previous confirmation count
        old_confirmations: u32,
        /// New confirmation count (may be 0 if unconfirmed)
        new_confirmations: u32,
        /// New payment status
        new_status: PaymentStatus,
        /// Human-readable explanation
        reason: String,
    },

    /// A specific lock was affected by a chain reorg
    LockReorged {
        /// Lock ID
        lock_id: String,
        /// Layer where reorg occurred (l1 or l2)
        layer: ReorgLayer,
        /// Previous state
        old_state: String,
        /// New state after reorg
        new_state: String,
        /// Previous confirmation count
        old_confirmations: u32,
        /// New confirmation count
        new_confirmations: u32,
        /// Human-readable explanation
        reason: String,
    },

    /// Chain reorganization resolved (chain stabilized)
    ReorgResolved {
        /// Layer that stabilized
        layer: ReorgLayer,
        /// Current chain height
        height: u64,
        /// Current tip hash (L1) or state root (L2)
        tip: String,
        /// Number of confirmations since reorg
        confirmations_since_reorg: u32,
    },

    // =========================================================================
    // Confidential Transfers
    // =========================================================================
    /// Result of a confidential transfer submission
    ConfidentialTransferResult {
        success: bool,
        transfer_id: Option<String>,
        new_commitment_root: Option<String>,
        error: Option<String>,
    },

    /// Result of a shield balance operation
    ShieldResult {
        success: bool,
        note_index: Option<u64>,
        commitment: Option<String>,
        new_root: Option<String>,
        error: Option<String>,
    },

    /// Current commitment tree state
    CommitmentTreeState {
        root: String,
        note_count: u64,
        next_index: u64,
        tree_depth: usize,
        nullifier_count: u64,
        /// Current epoch (increments after compaction, ~11.5 days)
        #[serde(default)]
        current_epoch: u64,
    },

    /// Notes owned by a specific pubkey
    ConfidentialNotes { notes: Vec<ConfidentialNoteInfo> },

    /// Push notification: a confidential transfer was received
    ConfidentialTransferReceived {
        transfer_id: String,
        recipient_new_commitment: String,
        note_index: u64,
        block_height: u64,
        /// Encrypted change note data (hex, for wallet scanning)
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_change: Option<String>,
        /// Encrypted recipient note data (hex, for wallet scanning)
        #[serde(skip_serializing_if = "Option::is_none")]
        encrypted_recipient: Option<String>,
        /// Change commitment (hex)
        #[serde(skip_serializing_if = "Option::is_none")]
        change_commitment: Option<String>,
    },

    /// Recent L2 transactions with encrypted fields for wallet scanning
    RecentL2Transactions {
        transactions: Vec<L2TransactionInfo>,
        latest_height: u64,
    },
}

/// One taproot output from a `CandidateTransaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateOutput {
    /// 32-byte x-only output pubkey, hex.
    pub output_pubkey: String,
    /// Output value in satoshis, if known.
    pub amount_sats: Option<u64>,
    /// Output index in the transaction.
    pub vout: u32,
}

/// UTXO information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Number of confirmations
    pub confirmations: u32,
    /// Script type (p2tr, p2wpkh, etc.)
    pub script_type: String,
    /// Whether this UTXO is spendable
    pub spendable: bool,
}

/// L2 transaction info with encrypted fields for wallet scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TransactionInfo {
    /// Checkpoint height where this transaction was included
    pub checkpoint_height: u64,
    /// Epoch when this transaction was processed
    pub epoch: u64,
    /// Nullifier (hex, 32 bytes)
    pub nullifier: String,
    /// Sender's change commitment (hex, 32 bytes)
    pub change_commitment: String,
    /// Recipient's commitment (hex, 32 bytes)
    pub recipient_commitment: String,
    /// Encrypted change note data (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_change: Option<String>,
    /// Encrypted recipient note data (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_recipient: Option<String>,
}

/// Confidential note information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidentialNoteInfo {
    /// Note position in commitment tree
    pub index: u64,
    /// MiMC commitment (32 bytes hex)
    pub commitment: String,
    /// Block height when created
    pub created_height: u64,
    /// Whether this note has been spent
    pub spent: bool,
}

/// Transaction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInfo {
    /// Transaction ID
    pub txid: String,
    /// Block height (None if unconfirmed)
    pub block_height: Option<u32>,
    /// Timestamp (Unix seconds)
    pub timestamp: i64,
    /// Net amount change (positive for received, negative for sent)
    pub amount_sats: i64,
    /// Fee paid (if known)
    pub fee_sats: Option<u64>,
    /// Transaction type (send, receive, lock, jump, etc.)
    pub tx_type: String,
    /// Number of confirmations
    pub confirmations: u32,
    /// Optional memo/note
    pub memo: Option<String>,
}

/// Lock state snapshot for real-time updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockStateSnapshot {
    /// Current state (Active, Frozen, etc.)
    pub state: String,
    /// L2 balance in sats
    pub balance_sats: u64,
    /// Current confirmations
    pub confirmations: u32,
    /// Jump urgency (0.0 = fresh, 1.0 = needs rotation)
    pub jump_urgency: f32,
    /// Whether lock UTXO is in mempool
    pub in_mempool: bool,
    /// Pending L2 payment amount
    pub pending_l2_sats: u64,
    /// Maximum instant payment amount
    pub max_instant_sats: u64,
    /// Current block height
    pub current_height: u64,
}

/// Type of lock state change
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStateChangeType {
    /// Balance changed (L2 payment)
    BalanceChange,
    /// Lock state transition (Active -> Frozen)
    StateTransition,
    /// Confirmation count increased
    Confirmation,
    /// Jump urgency changed
    JumpUrgency,
    /// Mempool status changed (L1 tx appeared/confirmed)
    MempoolChange,
    /// Pending L2 payment added/removed
    PendingL2Change,
}

/// Layer where a chain reorganization occurred
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgLayer {
    /// Bitcoin L1 chain reorg
    L1,
    /// Ghost Pay L2 virtual chain reorg
    L2,
}

/// Reason for L2 chain reorganization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L2ReorgReason {
    /// Normal fork resolution (competing blocks at same height)
    ForkResolution,
    /// Proposer equivocation detected (same proposer, two different blocks)
    Equivocation,
    /// Network partition recovery (nodes rejoining after split)
    NetworkPartition,
    /// State snapshot restoration
    SnapshotRestore,
    /// Manual intervention required
    ManualRollback,
}

impl ClientMessage {
    /// Check if this message requires authentication
    pub fn requires_auth(&self) -> bool {
        matches!(
            self,
            ClientMessage::GetBalance { .. }
                | ClientMessage::GetUtxos { .. }
                | ClientMessage::GetGhostLocks
                | ClientMessage::GetTransactions { .. }
                | ClientMessage::PreparePayment { .. }
                | ClientMessage::SubmitSignedPayment { .. }
                | ClientMessage::SendL2Payment { .. }
                | ClientMessage::GetPaymentStatus { .. }
                | ClientMessage::CancelPayment { .. }
                | ClientMessage::PrepareGhostLock { .. }
                | ClientMessage::ConfirmGhostLockFunding { .. }
                | ClientMessage::RegisterScanKey { .. }
                | ClientMessage::RequestJump { .. }
                | ClientMessage::SubscribeBalance
                | ClientMessage::SubscribePayments
                | ClientMessage::SubscribeLocks
                | ClientMessage::SubscribeReorgs
                | ClientMessage::UnsubscribeReorgs
                | ClientMessage::SubscribeSilentPayments
                | ClientMessage::UnsubscribeSilentPayments
                | ClientMessage::CheckInstantCapability { .. }
                | ClientMessage::SubscribeLockState { .. }
                | ClientMessage::UnsubscribeLockState { .. }
                | ClientMessage::AcceptInstantPayment { .. }
                | ClientMessage::SubmitConfidentialTransfer { .. }
                | ClientMessage::ShieldBalance { .. }
                | ClientMessage::GetConfidentialNotes { .. }
                | ClientMessage::SubscribeConfidential
                | ClientMessage::GetRecentL2Transactions { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_serialize() {
        let msg = ClientMessage::GetBalance { max_k: None };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"get_balance\""));

        let msg2 = ClientMessage::GetUtxos {
            min_confirmations: 6,
        };
        let json2 = serde_json::to_string(&msg2).unwrap();
        assert!(json2.contains("\"min_confirmations\":6"));
    }

    #[test]
    fn test_server_message_serialize() {
        let msg = ServerMessage::BalanceUpdate {
            confirmed: 100000,
            unconfirmed: 50000,
            locked: 25000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"balance_update\""));
        assert!(json.contains("\"confirmed\":100000"));
    }

    #[test]
    fn test_requires_auth() {
        assert!(ClientMessage::GetBalance { max_k: None }.requires_auth());
        assert!(!ClientMessage::Ping { timestamp: None }.requires_auth());
    }

    #[test]
    fn test_utxo_info_serialize() {
        let utxo = UtxoInfo {
            txid: "abc123".to_string(),
            vout: 0,
            amount_sats: 100000,
            confirmations: 6,
            script_type: "p2tr".to_string(),
            spendable: true,
        };
        let json = serde_json::to_string(&utxo).unwrap();
        assert!(json.contains("\"txid\":\"abc123\""));
        assert!(json.contains("\"spendable\":true"));
    }

    #[test]
    fn test_instant_capability_request_serialize() {
        let msg = ClientMessage::CheckInstantCapability {
            lock_id: "lock123".to_string(),
            amount_sats: 50000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"check_instant_capability\""));
        assert!(json.contains("\"lock_id\":\"lock123\""));
        assert!(json.contains("\"amount_sats\":50000"));
    }

    #[test]
    fn test_instant_capability_result_serialize() {
        let msg = ServerMessage::InstantCapabilityResult {
            lock_id: "lock123".to_string(),
            capable: true,
            max_instant_sats: 100000,
            confidence: 0.95,
            valid_until_height: 800100,
            conditions_met: 0xFF,
            conditions_failed: 0x00,
            error: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"instant_capability_result\""));
        assert!(json.contains("\"capable\":true"));
        assert!(json.contains("\"confidence\":0.95"));
    }

    #[test]
    fn test_lock_state_update_serialize() {
        let snapshot = LockStateSnapshot {
            state: "Active".to_string(),
            balance_sats: 500000,
            confirmations: 10,
            jump_urgency: 0.05,
            in_mempool: false,
            pending_l2_sats: 0,
            max_instant_sats: 100000,
            current_height: 800100,
        };
        let msg = ServerMessage::LockStateUpdate {
            lock_id: "lock123".to_string(),
            snapshot,
            change_type: LockStateChangeType::BalanceChange,
            timestamp: 1700000000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"lock_state_update\""));
        assert!(json.contains("\"change_type\":\"balance_change\""));
    }

    #[test]
    fn test_l2_transaction_info_roundtrip() {
        let info = L2TransactionInfo {
            checkpoint_height: 42,
            epoch: 1,
            nullifier: "aa".repeat(32),
            change_commitment: "bb".repeat(32),
            recipient_commitment: "cc".repeat(32),
            encrypted_change: Some("deadbeef".to_string()),
            encrypted_recipient: Some("cafebabe".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        let restored: L2TransactionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.checkpoint_height, 42);
        assert_eq!(restored.epoch, 1);
        assert!(restored.encrypted_change.is_some());
        assert!(restored.encrypted_recipient.is_some());
    }

    #[test]
    fn test_recent_l2_transactions_message() {
        let msg = ServerMessage::RecentL2Transactions {
            transactions: vec![],
            latest_height: 100,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"recent_l2_transactions\""));
        assert!(json.contains("\"latest_height\":100"));
    }

    #[test]
    fn test_get_recent_l2_transactions_requires_auth() {
        assert!(ClientMessage::GetRecentL2Transactions { since_height: 0 }.requires_auth());
    }

    #[test]
    fn test_confidential_transfer_received_with_encrypted_fields() {
        let msg = ServerMessage::ConfidentialTransferReceived {
            transfer_id: "tx123".to_string(),
            recipient_new_commitment: "aa".repeat(32),
            note_index: 5,
            block_height: 200,
            encrypted_change: Some("deadbeef".to_string()),
            encrypted_recipient: Some("cafebabe".to_string()),
            change_commitment: Some("bb".repeat(32)),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"encrypted_change\""));
        assert!(json.contains("\"encrypted_recipient\""));

        // Also test backward compat - missing fields deserialize as None
        let old_json = r#"{"type":"confidential_transfer_received","transfer_id":"tx123","recipient_new_commitment":"aa","note_index":5,"block_height":200}"#;
        let parsed: ServerMessage = serde_json::from_str(old_json).unwrap();
        if let ServerMessage::ConfidentialTransferReceived {
            encrypted_change,
            encrypted_recipient,
            change_commitment,
            ..
        } = parsed
        {
            assert!(encrypted_change.is_none());
            assert!(encrypted_recipient.is_none());
            assert!(change_commitment.is_none());
        } else {
            panic!("Wrong variant");
        }
    }

    #[test]
    fn test_instant_messages_require_auth() {
        assert!(ClientMessage::CheckInstantCapability {
            lock_id: "test".to_string(),
            amount_sats: 1000,
        }
        .requires_auth());

        assert!(ClientMessage::SubscribeLockState {
            lock_id: "test".to_string(),
        }
        .requires_auth());
    }
}
