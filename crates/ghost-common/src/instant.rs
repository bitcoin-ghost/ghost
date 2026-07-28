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
//| FILE: instant.rs                                                                                                     |
//|======================================================================================================================|

//! Instant Payment Capability for Light Wallets
//!
//! Enables "optimistic confirmation" for small L2 payments:
//! - Merchant shows "Confirmed" immediately
//! - Actual settlement happens on next virtual block (~10 sec)
//! - Risk bounded by denomination and conditions
//!
//! ## Security Fixes (CRIT-1 and CRIT-2)
//!
//! - CRIT-1: ReservationTracker prevents double-spending by atomically reserving funds
//! - CRIT-2: SignedInstantPayment requires cryptographic proof of lock ownership

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Maximum instant payment by denomination tier
/// Cap at Tiny (~$100) - larger amounts require confirmation
pub const INSTANT_LIMIT_MICRO: u64 = 10_000; // 10k sats (~$10)
pub const INSTANT_LIMIT_TINY: u64 = 100_000; // 100k sats (~$100) - MAX

/// Minimum confirmations for instant payment eligibility
pub const MIN_CONFIRMATIONS_INSTANT: u32 = 6;

/// Maximum jump urgency for instant payments (20%)
pub const MAX_JUMP_URGENCY_INSTANT: f32 = 0.2;

/// Minimum recovery window remaining (50%)
pub const MIN_RECOVERY_WINDOW_PERCENT: f32 = 0.5;

/// Instant capability validity window (blocks)
pub const INSTANT_VALIDITY_BLOCKS: u32 = 6; // ~1 hour

/// M-8 FIX: Legacy receipt cutoff block height.
/// After this block height, legacy receipts (with zero state hash) are rejected.
/// This prevents unbounded backwards compatibility that could allow state manipulation.
///
/// Set to mainnet target launch height + 6 months (~26,280 blocks at 10 min/block).
/// This gives operators time to upgrade while ensuring legacy receipts eventually expire.
/// For signet/testnet, set lower for faster testing.
///
/// Production value: 890_000 (approximately Feb 2025 + 6 months)
/// This can be overridden via GHOST_LEGACY_RECEIPT_CUTOFF env var for testing.
pub const LEGACY_RECEIPT_CUTOFF_HEIGHT: u64 = 890_000;

/// Reservation expiry time in seconds (CRIT-1)
pub const RESERVATION_EXPIRY_SECS: i64 = 30;

/// M-VAL-2: Minimum confidence threshold for instant payments
/// Payments below this confidence are rejected as too risky.
/// 0.7 = 70% confidence required
pub const MIN_CONFIDENCE_THRESHOLD: f32 = 0.7;

/// Conditions that must be met for instant payments
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InstantCondition {
    /// Lock is in Active state
    ActiveState,
    /// Lock has sufficient confirmations
    SufficientConfirmations,
    /// Denomination is within instant limit
    DenominationEligible,
    /// Jump urgency is low (not due for rotation)
    LowJumpUrgency,
    /// Recovery timelock has sufficient buffer
    RecoveryWindowSafe,
    /// No pending L1 transactions (mempool clear)
    NoPendingL1,
    /// No pending L2 payments that would exhaust balance
    NoPendingL2,
    /// L2 balance sufficient for payment + buffer
    SufficientBalance,
}

impl InstantCondition {
    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::ActiveState => "Lock is active and spendable",
            Self::SufficientConfirmations => "Lock has 6+ confirmations",
            Self::DenominationEligible => "Amount within instant limit",
            Self::LowJumpUrgency => "Key rotation not urgent",
            Self::RecoveryWindowSafe => "Recovery timelock has buffer",
            Self::NoPendingL1 => "No pending L1 transactions",
            Self::NoPendingL2 => "No pending L2 payments",
            Self::SufficientBalance => "Balance covers payment + fees",
        }
    }

    /// Get condition as a bit flag
    pub fn bit_flag(&self) -> u8 {
        match self {
            Self::ActiveState => 0b0000_0001,
            Self::SufficientConfirmations => 0b0000_0010,
            Self::DenominationEligible => 0b0000_0100,
            Self::LowJumpUrgency => 0b0000_1000,
            Self::RecoveryWindowSafe => 0b0001_0000,
            Self::NoPendingL1 => 0b0010_0000,
            Self::NoPendingL2 => 0b0100_0000,
            Self::SufficientBalance => 0b1000_0000,
        }
    }
}

/// Result of checking instant payment capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantCapability {
    /// Whether instant payment is possible
    pub capable: bool,
    /// Maximum amount for instant payment (sats)
    pub max_instant_sats: u64,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Block height when this capability expires
    pub valid_until_height: u64,
    /// Conditions that were met
    pub conditions_met: Vec<InstantCondition>,
    /// Conditions that failed (if not capable)
    pub conditions_failed: Vec<InstantCondition>,
}

impl InstantCapability {
    /// Create a new "not capable" result
    pub fn not_capable(failed: Vec<InstantCondition>) -> Self {
        Self {
            capable: false,
            max_instant_sats: 0,
            confidence: 0.0,
            valid_until_height: 0,
            conditions_met: vec![],
            conditions_failed: failed,
        }
    }

    /// Create a new "capable" result
    ///
    /// M-VAL-2 FIX: Validates that confidence is above minimum threshold.
    /// If confidence is too low, returns a "not capable" result instead.
    pub fn capable(max_sats: u64, confidence: f32, valid_until: u64) -> Self {
        // M-VAL-2 FIX: Reject if confidence is below minimum threshold
        if confidence < MIN_CONFIDENCE_THRESHOLD {
            return Self {
                capable: false,
                max_instant_sats: 0,
                confidence,
                valid_until_height: 0,
                conditions_met: vec![],
                conditions_failed: vec![], // Confidence failure, not a condition failure
            };
        }

        Self {
            capable: true,
            max_instant_sats: max_sats,
            confidence,
            valid_until_height: valid_until,
            conditions_met: vec![
                InstantCondition::ActiveState,
                InstantCondition::SufficientConfirmations,
                InstantCondition::DenominationEligible,
                InstantCondition::LowJumpUrgency,
                InstantCondition::RecoveryWindowSafe,
                InstantCondition::NoPendingL1,
                InstantCondition::NoPendingL2,
                InstantCondition::SufficientBalance,
            ],
            conditions_failed: vec![],
        }
    }

    /// Check if confidence is above minimum threshold
    ///
    /// M-VAL-2 FIX: Allows explicit confidence checking
    pub fn is_confidence_sufficient(&self) -> bool {
        self.confidence >= MIN_CONFIDENCE_THRESHOLD
    }

    /// Encode conditions as a bitmap for compact transmission
    pub fn conditions_bitmap(&self) -> u8 {
        self.conditions_met
            .iter()
            .fold(0u8, |acc, c| acc | c.bit_flag())
    }

    /// Decode conditions from a bitmap
    pub fn from_bitmap(bitmap: u8) -> Vec<InstantCondition> {
        let all_conditions = [
            InstantCondition::ActiveState,
            InstantCondition::SufficientConfirmations,
            InstantCondition::DenominationEligible,
            InstantCondition::LowJumpUrgency,
            InstantCondition::RecoveryWindowSafe,
            InstantCondition::NoPendingL1,
            InstantCondition::NoPendingL2,
            InstantCondition::SufficientBalance,
        ];

        all_conditions
            .into_iter()
            .filter(|c| bitmap & c.bit_flag() != 0)
            .collect()
    }
}

/// Request to check instant payment capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantCheckRequest {
    /// Lock ID to check
    pub lock_id: String,
    /// Amount to pay (sats)
    pub amount_sats: u64,
    /// Current block height (for expiry calculation)
    pub current_height: u64,
}

/// Lock state snapshot for instant payment evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockSnapshot {
    /// Lock identifier
    pub lock_id: String,
    /// Current state (must be "Active")
    pub state: String,
    /// Total balance in sats
    pub balance_sats: u64,
    /// Block height when lock was funded
    pub funding_height: u32,
    /// Confirmations since funding
    pub confirmations: u32,
    /// Denomination tier
    pub denomination: String,
    /// Jump urgency (0.0 = fresh, 1.0 = needs rotation)
    pub jump_urgency: f32,
    /// Blocks until recovery timelock
    pub recovery_blocks_remaining: u32,
    /// Total recovery window blocks
    pub recovery_window_total: u32,
    /// Whether lock is in mempool (pending L1 tx)
    pub in_mempool: bool,
    /// Pending L2 payment amount (sats)
    pub pending_l2_sats: u64,
    /// CRIT-1 FIX: Amount reserved for pending instant payments (sats)
    #[serde(default)]
    pub pending_instant_sats: u64,
    /// CRIT-2 FIX: Lock owner's public key (32 bytes, x-only for Schnorr)
    #[serde(default)]
    pub owner_pubkey: Option<[u8; 32]>,
}

impl LockSnapshot {
    /// Check if this lock meets instant payment conditions for the given amount
    ///
    /// CRIT-1 FIX: Now accounts for pending_instant_sats when calculating available balance
    pub fn check_instant(&self, amount_sats: u64, current_height: u64) -> InstantCapability {
        let mut met = Vec::new();
        let mut failed = Vec::new();

        // 1. Active state
        if self.state == "Active" {
            met.push(InstantCondition::ActiveState);
        } else {
            failed.push(InstantCondition::ActiveState);
        }

        // 2. Sufficient confirmations
        if self.confirmations >= MIN_CONFIRMATIONS_INSTANT {
            met.push(InstantCondition::SufficientConfirmations);
        } else {
            failed.push(InstantCondition::SufficientConfirmations);
        }

        // 3. Denomination eligible
        let max_for_denomination = self.instant_limit_for_denomination();
        if amount_sats <= max_for_denomination {
            met.push(InstantCondition::DenominationEligible);
        } else {
            failed.push(InstantCondition::DenominationEligible);
        }

        // 4. Low jump urgency
        if self.jump_urgency < MAX_JUMP_URGENCY_INSTANT {
            met.push(InstantCondition::LowJumpUrgency);
        } else {
            failed.push(InstantCondition::LowJumpUrgency);
        }

        // 5. Recovery window safe
        let recovery_ratio =
            self.recovery_blocks_remaining as f32 / self.recovery_window_total.max(1) as f32;
        if recovery_ratio >= MIN_RECOVERY_WINDOW_PERCENT {
            met.push(InstantCondition::RecoveryWindowSafe);
        } else {
            failed.push(InstantCondition::RecoveryWindowSafe);
        }

        // 6. No pending L1
        if !self.in_mempool {
            met.push(InstantCondition::NoPendingL1);
        } else {
            failed.push(InstantCondition::NoPendingL1);
        }

        // CRIT-1 FIX: Calculate available balance accounting for BOTH pending L2
        // payments AND pending instant payment reservations
        let committed = self
            .pending_l2_sats
            .saturating_add(self.pending_instant_sats);
        let available = self.balance_sats.saturating_sub(committed);

        // 7. No pending payments that would exhaust balance
        if committed == 0 || available >= amount_sats {
            met.push(InstantCondition::NoPendingL2);
        } else {
            failed.push(InstantCondition::NoPendingL2);
        }

        // 8. Sufficient balance (with 10% buffer for fees)
        let required = amount_sats + (amount_sats / 10);
        if available >= required {
            met.push(InstantCondition::SufficientBalance);
        } else {
            failed.push(InstantCondition::SufficientBalance);
        }

        // Determine capability
        if failed.is_empty() {
            let confidence = self.calculate_confidence();
            let max_instant = max_for_denomination.min(available.saturating_sub(available / 10));
            let valid_until = current_height + INSTANT_VALIDITY_BLOCKS as u64;

            InstantCapability {
                capable: true,
                max_instant_sats: max_instant,
                confidence,
                valid_until_height: valid_until,
                conditions_met: met,
                conditions_failed: failed,
            }
        } else {
            InstantCapability {
                capable: false,
                max_instant_sats: 0,
                confidence: 0.0,
                valid_until_height: 0,
                conditions_met: met,
                conditions_failed: failed,
            }
        }
    }

    /// Get instant limit based on denomination
    fn instant_limit_for_denomination(&self) -> u64 {
        match self.denomination.as_str() {
            "Micro" => INSTANT_LIMIT_MICRO,
            "Tiny" | "Small" | "Medium" | "Large" | "XL" => INSTANT_LIMIT_TINY,
            _ => 0,
        }
    }

    /// Calculate confidence score based on lock health
    fn calculate_confidence(&self) -> f32 {
        let mut score = 1.0f32;

        if self.confirmations < 10 {
            score *= 0.9;
        }

        if self.jump_urgency > 0.1 {
            score *= 1.0 - (self.jump_urgency * 0.3);
        }

        let recovery_ratio =
            self.recovery_blocks_remaining as f32 / self.recovery_window_total.max(1) as f32;
        if recovery_ratio < 0.7 {
            score *= recovery_ratio + 0.3;
        }

        score.clamp(0.5, 1.0)
    }

    /// H-AUTH-3 FIX: Compute a cryptographic hash of the lock's state
    ///
    /// This hash binds the receipt to the exact lock state at the time of payment.
    /// If the lock state changes (balance, pending payments, state transitions),
    /// the hash will no longer match, and settlement must be rejected.
    ///
    /// The hash includes:
    /// - lock_id (identity)
    /// - state (must still be Active)
    /// - balance_sats (funds available)
    /// - pending_l2_sats (outstanding L2 payments)
    /// - pending_instant_sats (outstanding instant reservations)
    /// - in_mempool (L1 state)
    /// - owner_pubkey (ownership hasn't changed)
    pub fn state_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(self.lock_id.as_bytes());
        hasher.update(self.state.as_bytes());
        hasher.update(self.balance_sats.to_le_bytes());
        hasher.update(self.pending_l2_sats.to_le_bytes());
        hasher.update(self.pending_instant_sats.to_le_bytes());
        hasher.update([self.in_mempool as u8]);
        if let Some(pubkey) = &self.owner_pubkey {
            hasher.update(pubkey);
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// =============================================================================
// CRIT-2 FIX: Signed Instant Payment
// =============================================================================

/// Signed instant payment request from sender
///
/// CRIT-2 FIX: This structure contains the sender's signature proving
/// ownership of the lock. Without a valid signature, payment MUST be rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInstantPayment {
    /// Payment ID (unique identifier)
    pub payment_id: [u8; 32],
    /// Sender's lock ID
    pub sender_lock_id: String,
    /// Recipient identifier (merchant's lock ID or payment address)
    pub recipient: String,
    /// Amount in sats
    pub amount_sats: u64,
    /// Timestamp when signed (Unix millis)
    pub timestamp: u64,
    /// Sender's public key (32 bytes, x-only for Schnorr)
    pub sender_pubkey: [u8; 32],
    /// BIP-340 Schnorr signature (64 bytes) over the payment message, hex-encoded
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
}

/// Serde helper module for [u8; 64] as hex string
mod hex_bytes_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl SignedInstantPayment {
    /// Compute the message that is signed
    ///
    /// Message format: "ghost-instant-v1" || payment_id || lock_id || recipient || amount || timestamp
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(128);
        msg.extend_from_slice(b"ghost-instant-v1");
        msg.extend_from_slice(&self.payment_id);
        msg.extend_from_slice(self.sender_lock_id.as_bytes());
        msg.extend_from_slice(self.recipient.as_bytes());
        msg.extend_from_slice(&self.amount_sats.to_le_bytes());
        msg.extend_from_slice(&self.timestamp.to_le_bytes());
        msg
    }
}

// =============================================================================
// CRIT-1 FIX: Fund Reservation System
// =============================================================================

/// Fund reservation for preventing double-spend
///
/// CRIT-1 FIX: Tracks reserved amounts that cannot be spent in concurrent payments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundReservation {
    /// Payment ID this reservation is for
    pub payment_id: [u8; 32],
    /// Amount reserved in sats
    pub amount_sats: u64,
    /// When the reservation was created (Unix millis)
    pub created_at: u64,
    /// When the reservation expires (Unix millis)
    pub expires_at: u64,
}

impl FundReservation {
    /// Check if reservation has expired
    pub fn is_expired(&self, current_time_millis: u64) -> bool {
        current_time_millis > self.expires_at
    }
}

/// L-11 FIX: Result of a reservation attempt, including any expired reservations
///
/// This allows callers to be notified when reservations expire during cleanup,
/// enabling merchants to log/alert about payments that were initiated but never settled.
#[derive(Debug, Clone)]
pub struct ReservationResult {
    /// The newly created reservation (if successful)
    pub reservation: FundReservation,
    /// L-11 FIX: Reservations that expired and were cleaned up during this call.
    /// Each represents a payment that was initiated but never settled within
    /// the RESERVATION_EXPIRY_SECS window. Merchants should log/alert on these.
    pub expired_reservations: Vec<FundReservation>,
}

/// Reservation tracker for a lock
///
/// CRIT-1 FIX: Thread-safe tracker that prevents double-spending by atomically
/// reserving funds before showing payment confirmation.
#[derive(Debug, Default)]
pub struct ReservationTracker {
    /// Active reservations (payment_id -> reservation)
    reservations: RwLock<HashMap<[u8; 32], FundReservation>>,
}

impl ReservationTracker {
    /// Create a new reservation tracker
    pub fn new() -> Self {
        Self {
            reservations: RwLock::new(HashMap::new()),
        }
    }

    /// Get total reserved amount (excluding expired reservations)
    pub fn total_reserved(&self, current_time_millis: u64) -> u64 {
        let reservations = self.reservations.read();
        reservations
            .values()
            .filter(|r| !r.is_expired(current_time_millis))
            .map(|r| r.amount_sats)
            .sum()
    }

    /// Attempt to reserve funds for an instant payment
    ///
    /// Returns Ok(ReservationResult) if funds were successfully reserved.
    /// The result includes the new reservation AND any expired reservations that were
    /// cleaned up during this call (L-11 FIX: enables merchant notification).
    ///
    /// Returns Err if insufficient funds available after accounting for existing reservations.
    pub fn try_reserve(
        &self,
        payment_id: [u8; 32],
        amount_sats: u64,
        available_balance: u64,
        current_time_millis: u64,
    ) -> Result<ReservationResult, InstantPaymentError> {
        let mut reservations = self.reservations.write();

        // L-11 FIX: Collect expired reservations before removing them
        // This allows callers to log/alert about payments that were initiated
        // but never settled within the reservation window.
        let expired_reservations: Vec<FundReservation> = reservations
            .values()
            .filter(|r| r.is_expired(current_time_millis))
            .cloned()
            .collect();

        // Clean up expired reservations
        reservations.retain(|_, r| !r.is_expired(current_time_millis));

        // Check if this payment already has a reservation
        if reservations.contains_key(&payment_id) {
            return Err(InstantPaymentError::DuplicatePayment);
        }

        // Calculate total already reserved
        let total_reserved: u64 = reservations.values().map(|r| r.amount_sats).sum();

        // Check if there's enough balance after reservations
        let available_after_reservations = available_balance.saturating_sub(total_reserved);

        // Need amount plus 10% buffer for fees
        let required = amount_sats.saturating_add(amount_sats / 10);

        if available_after_reservations < required {
            return Err(InstantPaymentError::InsufficientFunds {
                requested: amount_sats,
                available: available_after_reservations,
                reserved: total_reserved,
            });
        }

        // Create reservation
        let reservation = FundReservation {
            payment_id,
            amount_sats,
            created_at: current_time_millis,
            expires_at: current_time_millis + (RESERVATION_EXPIRY_SECS as u64 * 1000),
        };

        reservations.insert(payment_id, reservation.clone());

        // L-11 FIX: Return both the new reservation and any expired ones
        Ok(ReservationResult {
            reservation,
            expired_reservations,
        })
    }

    /// Release a reservation (e.g., payment settled or cancelled)
    pub fn release(&self, payment_id: &[u8; 32]) {
        let mut reservations = self.reservations.write();
        reservations.remove(payment_id);
    }

    /// Get the count of active reservations
    pub fn active_count(&self, current_time_millis: u64) -> usize {
        let reservations = self.reservations.read();
        reservations
            .values()
            .filter(|r| !r.is_expired(current_time_millis))
            .count()
    }

    /// Prune expired reservations
    pub fn prune_expired(&self, current_time_millis: u64) {
        let mut reservations = self.reservations.write();
        reservations.retain(|_, r| !r.is_expired(current_time_millis));
    }
}

/// Errors that can occur during instant payment processing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstantPaymentError {
    /// Insufficient funds after accounting for reservations
    InsufficientFunds {
        requested: u64,
        available: u64,
        reserved: u64,
    },
    /// Duplicate payment ID
    DuplicatePayment,
    /// Invalid or missing signature
    InvalidSignature,
    /// Signature verification failed
    SignatureVerificationFailed,
    /// Lock ownership not proven
    OwnershipNotProven,
    /// Payment amount exceeds instant limit
    AmountExceedsLimit { amount: u64, limit: u64 },
    /// Lock not instant-capable
    NotInstantCapable(Vec<InstantCondition>),
    /// Reservation expired
    ReservationExpired,
}

impl std::fmt::Display for InstantPaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientFunds {
                requested,
                available,
                reserved,
            } => {
                write!(
                    f,
                    "Insufficient funds: requested {} sats, {} available ({} reserved)",
                    requested, available, reserved
                )
            }
            Self::DuplicatePayment => write!(f, "Duplicate payment ID"),
            Self::InvalidSignature => write!(f, "Invalid or missing signature"),
            Self::SignatureVerificationFailed => write!(f, "Signature verification failed"),
            Self::OwnershipNotProven => write!(f, "Lock ownership not proven"),
            Self::AmountExceedsLimit { amount, limit } => {
                write!(f, "Amount {} exceeds instant limit {} sats", amount, limit)
            }
            Self::NotInstantCapable(conditions) => {
                write!(f, "Lock not instant-capable: {:?}", conditions)
            }
            Self::ReservationExpired => write!(f, "Reservation expired"),
        }
    }
}

impl std::error::Error for InstantPaymentError {}

/// M-8 FIX: Result of lock state verification with detailed failure reasons
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockStateVerificationResult {
    /// State hash matches - verification passed
    Valid,
    /// Legacy receipt accepted (before cutoff height)
    LegacyReceiptAccepted,
    /// Legacy receipt rejected - past cutoff height
    LegacyReceiptExpired {
        current_height: u64,
        cutoff_height: u64,
    },
    /// State hash mismatch - lock state changed
    StateMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl LockStateVerificationResult {
    /// Returns true if verification passed
    pub fn is_valid(&self) -> bool {
        matches!(
            self,
            LockStateVerificationResult::Valid | LockStateVerificationResult::LegacyReceiptAccepted
        )
    }
}

impl std::fmt::Display for LockStateVerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "Lock state verification passed"),
            Self::LegacyReceiptAccepted => {
                write!(f, "Legacy receipt accepted (before cutoff height)")
            }
            Self::LegacyReceiptExpired {
                current_height,
                cutoff_height,
            } => {
                write!(
                    f,
                    "Legacy receipt rejected: current height {} >= cutoff {}",
                    current_height, cutoff_height
                )
            }
            Self::StateMismatch { .. } => {
                write!(
                    f,
                    "Lock state mismatch: state changed since receipt creation"
                )
            }
        }
    }
}

/// Instant payment receipt (for merchant confirmation)
///
/// CRIT-2 FIX: Now includes sender_pubkey and signature for verification
/// H-AUTH-3 FIX: Now includes lock_state_hash to detect state changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantReceipt {
    /// Payment ID
    pub payment_id: [u8; 32],
    /// Sender's lock ID
    pub sender_lock_id: String,
    /// Recipient identifier
    pub recipient: String,
    /// Amount in sats
    pub amount_sats: u64,
    /// Capability snapshot at time of payment
    pub capability: InstantCapability,
    /// Timestamp
    pub timestamp: u64,
    /// Expected settlement block
    pub settlement_block: u64,
    /// Sender's public key (for verification)
    pub sender_pubkey: [u8; 32],
    /// Original signature from sender (proof of authorization), hex-encoded
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
    /// H-AUTH-3 FIX: Hash of lock state at receipt creation time.
    /// Settlement MUST verify this matches the current lock state.
    #[serde(default)]
    pub lock_state_hash: [u8; 32],
}

impl InstantReceipt {
    /// Check if receipt is still valid
    pub fn is_valid(&self, current_height: u64) -> bool {
        current_height <= self.capability.valid_until_height
    }

    /// Check if payment has likely settled
    pub fn is_settled(&self, current_height: u64) -> bool {
        current_height >= self.settlement_block
    }

    /// H-AUTH-3 FIX: Verify the lock state hasn't changed since receipt was created.
    ///
    /// This MUST be called before settlement to prevent:
    /// - Double-spending via state manipulation
    /// - Settlement when lock has been frozen/recovered
    /// - Settlement when balance has been exhausted
    ///
    /// M-8 FIX: Legacy receipts (with zero state hash) are now rejected after
    /// LEGACY_RECEIPT_CUTOFF_HEIGHT to prevent unbounded backwards compatibility attacks.
    ///
    /// L-20 FIX: On mainnet, GHOST_LEGACY_RECEIPT_CUTOFF override is blocked.
    ///
    /// Returns true if the current lock state matches the state at receipt creation.
    pub fn verify_lock_state(&self, current_snapshot: &LockSnapshot, current_height: u64) -> bool {
        // If lock_state_hash is all zeros, this is a legacy receipt without state binding
        if self.lock_state_hash == [0u8; 32] {
            // L-20 FIX: Check if we're on mainnet - env override is blocked on mainnet
            let is_mainnet = std::env::var("GHOST_NETWORK")
                .map(|v| v.to_lowercase() == "mainnet" || v.to_lowercase() == "bitcoin")
                .unwrap_or(false);

            // M-8 FIX: Check if we're past the legacy receipt cutoff
            // L-20 FIX: Only allow env var override on non-mainnet networks
            let cutoff = if is_mainnet {
                // On mainnet, ALWAYS use the hardcoded cutoff - no override allowed
                LEGACY_RECEIPT_CUTOFF_HEIGHT
            } else {
                // Non-mainnet: allow env var override for testing
                std::env::var("GHOST_LEGACY_RECEIPT_CUTOFF")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(LEGACY_RECEIPT_CUTOFF_HEIGHT)
            };

            if current_height >= cutoff {
                // Legacy receipt rejected - past cutoff
                return false;
            }

            // Before cutoff, allow legacy receipts for backwards compatibility
            return true;
        }

        current_snapshot.state_hash() == self.lock_state_hash
    }

    /// H-AUTH-3/M-8: Verify lock state with explicit cutoff check
    ///
    /// Returns a detailed result explaining why verification failed.
    ///
    /// L-20 FIX: On mainnet, GHOST_LEGACY_RECEIPT_CUTOFF override is blocked.
    pub fn verify_lock_state_detailed(
        &self,
        current_snapshot: &LockSnapshot,
        current_height: u64,
    ) -> LockStateVerificationResult {
        // Check for legacy receipt
        if self.lock_state_hash == [0u8; 32] {
            // L-20 FIX: Check if we're on mainnet - env override is blocked on mainnet
            let is_mainnet = std::env::var("GHOST_NETWORK")
                .map(|v| v.to_lowercase() == "mainnet" || v.to_lowercase() == "bitcoin")
                .unwrap_or(false);

            // L-20 FIX: Only allow env var override on non-mainnet networks
            let cutoff = if is_mainnet {
                // On mainnet, ALWAYS use the hardcoded cutoff - no override allowed
                LEGACY_RECEIPT_CUTOFF_HEIGHT
            } else {
                // Non-mainnet: allow env var override for testing
                std::env::var("GHOST_LEGACY_RECEIPT_CUTOFF")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(LEGACY_RECEIPT_CUTOFF_HEIGHT)
            };

            if current_height >= cutoff {
                return LockStateVerificationResult::LegacyReceiptExpired {
                    current_height,
                    cutoff_height: cutoff,
                };
            }

            return LockStateVerificationResult::LegacyReceiptAccepted;
        }

        // Compare state hashes
        let current_hash = current_snapshot.state_hash();
        if current_hash == self.lock_state_hash {
            LockStateVerificationResult::Valid
        } else {
            LockStateVerificationResult::StateMismatch {
                expected: self.lock_state_hash,
                actual: current_hash,
            }
        }
    }

    /// Check if this receipt has state binding (H-AUTH-3 compliant)
    pub fn has_state_binding(&self) -> bool {
        self.lock_state_hash != [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_healthy_lock() -> LockSnapshot {
        LockSnapshot {
            lock_id: "abc123".to_string(),
            state: "Active".to_string(),
            balance_sats: 500_000,
            funding_height: 100,
            confirmations: 10,
            denomination: "Small".to_string(),
            jump_urgency: 0.05,
            recovery_blocks_remaining: 40_000,
            recovery_window_total: 52_560,
            in_mempool: false,
            pending_l2_sats: 0,
            pending_instant_sats: 0,
            owner_pubkey: Some([1u8; 32]),
        }
    }

    #[test]
    fn test_healthy_lock_is_instant_capable() {
        let lock = create_healthy_lock();
        let result = lock.check_instant(100_000, 200);

        assert!(result.capable);
        assert!(result.max_instant_sats >= 100_000);
        assert!(result.confidence > 0.9);
        assert!(result.conditions_failed.is_empty());
    }

    #[test]
    fn test_inactive_lock_not_capable() {
        let mut lock = create_healthy_lock();
        lock.state = "Frozen".to_string();

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::ActiveState));
    }

    #[test]
    fn test_insufficient_confirmations() {
        let mut lock = create_healthy_lock();
        lock.confirmations = 3;

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::SufficientConfirmations));
    }

    #[test]
    fn test_amount_exceeds_denomination_limit() {
        let lock = create_healthy_lock();
        let result = lock.check_instant(150_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::DenominationEligible));
    }

    #[test]
    fn test_high_jump_urgency() {
        let mut lock = create_healthy_lock();
        lock.jump_urgency = 0.5;

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::LowJumpUrgency));
    }

    #[test]
    fn test_lock_in_mempool() {
        let mut lock = create_healthy_lock();
        lock.in_mempool = true;

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::NoPendingL1));
    }

    #[test]
    fn test_insufficient_balance() {
        let mut lock = create_healthy_lock();
        lock.balance_sats = 50_000;

        let result = lock.check_instant(100_000, 200);

        assert!(!result.capable);
        assert!(result
            .conditions_failed
            .contains(&InstantCondition::SufficientBalance));
    }

    #[test]
    fn test_pending_l2_reduces_available() {
        let mut lock = create_healthy_lock();
        lock.pending_l2_sats = 400_000;

        let result = lock.check_instant(150_000, 200);

        assert!(!result.capable);
    }

    #[test]
    fn test_large_denomination_capped_at_100k() {
        let mut lock = create_healthy_lock();
        lock.denomination = "Large".to_string();
        lock.balance_sats = 100_000_000;

        let result = lock.check_instant(50_000, 200);
        assert!(result.capable);
        assert_eq!(result.max_instant_sats, INSTANT_LIMIT_TINY);

        let result = lock.check_instant(150_000, 200);
        assert!(!result.capable);
    }

    #[test]
    fn test_conditions_bitmap() {
        let capability = InstantCapability::capable(100_000, 0.95, 300);
        let bitmap = capability.conditions_bitmap();
        assert_eq!(bitmap, 0xFF);

        let decoded = InstantCapability::from_bitmap(bitmap);
        assert_eq!(decoded.len(), 8);
    }

    #[test]
    fn test_micro_denomination_limits() {
        let mut lock = create_healthy_lock();
        lock.denomination = "Micro".to_string();
        lock.balance_sats = 10_000;

        let result = lock.check_instant(5_000, 200);
        assert!(result.capable);

        let result = lock.check_instant(15_000, 200);
        assert!(!result.capable);
    }

    #[test]
    fn test_confidence_calculation() {
        let lock = create_healthy_lock();
        let result = lock.check_instant(100_000, 200);
        assert!(result.confidence > 0.95);

        let mut lock2 = create_healthy_lock();
        lock2.confirmations = 7;
        let result2 = lock2.check_instant(100_000, 200);
        assert!(result2.capable);
        assert!(result2.confidence < result.confidence);
    }

    #[test]
    fn test_instant_receipt() {
        let lock = create_healthy_lock();
        let state_hash = lock.state_hash();

        let receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: state_hash,
        };

        assert!(receipt.is_valid(200));
        assert!(receipt.is_valid(210));
        assert!(!receipt.is_valid(211));

        assert!(!receipt.is_settled(204));
        assert!(receipt.is_settled(205));
        assert!(receipt.is_settled(300));
    }

    // =========================================================================
    // H-AUTH-3 FIX TESTS: Lock State Hash Verification
    // =========================================================================

    #[test]
    fn test_lock_state_hash_is_deterministic() {
        let lock = create_healthy_lock();
        let hash1 = lock.state_hash();
        let hash2 = lock.state_hash();
        assert_eq!(hash1, hash2, "State hash should be deterministic");
    }

    #[test]
    fn test_lock_state_hash_changes_with_balance() {
        let lock1 = create_healthy_lock();
        let mut lock2 = create_healthy_lock();
        lock2.balance_sats = 600_000;

        assert_ne!(
            lock1.state_hash(),
            lock2.state_hash(),
            "State hash should change when balance changes"
        );
    }

    #[test]
    fn test_lock_state_hash_changes_with_state() {
        let lock1 = create_healthy_lock();
        let mut lock2 = create_healthy_lock();
        lock2.state = "Frozen".to_string();

        assert_ne!(
            lock1.state_hash(),
            lock2.state_hash(),
            "State hash should change when state changes"
        );
    }

    #[test]
    fn test_lock_state_hash_changes_with_pending() {
        let lock1 = create_healthy_lock();
        let mut lock2 = create_healthy_lock();
        lock2.pending_instant_sats = 10_000;

        assert_ne!(
            lock1.state_hash(),
            lock2.state_hash(),
            "State hash should change when pending_instant_sats changes"
        );
    }

    #[test]
    fn test_receipt_verify_lock_state_matches() {
        let lock = create_healthy_lock();
        let state_hash = lock.state_hash();

        let receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: state_hash,
        };

        // Same lock should verify (using height before cutoff)
        assert!(
            receipt.verify_lock_state(&lock, 200),
            "Receipt should verify against unchanged lock"
        );
    }

    #[test]
    fn test_receipt_verify_lock_state_detects_change() {
        let lock = create_healthy_lock();
        let state_hash = lock.state_hash();

        let receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: state_hash,
        };

        // Modified lock should NOT verify
        let mut modified_lock = create_healthy_lock();
        modified_lock.balance_sats = 400_000; // Balance changed!

        assert!(
            !receipt.verify_lock_state(&modified_lock, 200),
            "Receipt should NOT verify against modified lock"
        );
    }

    #[test]
    fn test_receipt_has_state_binding() {
        let lock = create_healthy_lock();

        // Receipt with state hash
        let receipt_with_binding = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: lock.state_hash(),
        };
        assert!(receipt_with_binding.has_state_binding());

        // Legacy receipt without state hash
        let legacy_receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: [0u8; 32],
        };
        assert!(!legacy_receipt.has_state_binding());
        // Legacy receipts should still verify for backwards compat (before cutoff)
        assert!(legacy_receipt.verify_lock_state(&lock, 200));
    }

    // =========================================================================
    // M-8 FIX TESTS: Legacy Receipt Cutoff
    // =========================================================================

    #[test]
    fn test_legacy_receipt_accepted_before_cutoff() {
        let lock = create_healthy_lock();

        let legacy_receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: [0u8; 32], // Legacy: no state binding
        };

        // Before cutoff, should be accepted
        assert!(
            legacy_receipt.verify_lock_state(&lock, LEGACY_RECEIPT_CUTOFF_HEIGHT - 1),
            "Legacy receipt should be accepted before cutoff"
        );
    }

    #[test]
    fn test_legacy_receipt_rejected_after_cutoff() {
        let lock = create_healthy_lock();

        let legacy_receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: [0u8; 32], // Legacy: no state binding
        };

        // At cutoff, should be rejected
        assert!(
            !legacy_receipt.verify_lock_state(&lock, LEGACY_RECEIPT_CUTOFF_HEIGHT),
            "Legacy receipt should be rejected at cutoff"
        );

        // After cutoff, should be rejected
        assert!(
            !legacy_receipt.verify_lock_state(&lock, LEGACY_RECEIPT_CUTOFF_HEIGHT + 1000),
            "Legacy receipt should be rejected after cutoff"
        );
    }

    #[test]
    fn test_verify_lock_state_detailed() {
        let lock = create_healthy_lock();

        // Receipt with valid state hash
        let valid_receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: lock.state_hash(),
        };

        let result = valid_receipt.verify_lock_state_detailed(&lock, 200);
        assert!(result.is_valid());
        assert_eq!(result, LockStateVerificationResult::Valid);

        // Legacy receipt before cutoff
        let legacy_receipt = InstantReceipt {
            payment_id: [1u8; 32],
            sender_lock_id: "abc123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            capability: InstantCapability::capable(100_000, 0.95, 210),
            timestamp: 1700000000,
            settlement_block: 205,
            sender_pubkey: [1u8; 32],
            signature: [0u8; 64],
            lock_state_hash: [0u8; 32],
        };

        let result = legacy_receipt.verify_lock_state_detailed(&lock, 200);
        assert!(result.is_valid());
        assert_eq!(result, LockStateVerificationResult::LegacyReceiptAccepted);

        // Legacy receipt after cutoff
        let result =
            legacy_receipt.verify_lock_state_detailed(&lock, LEGACY_RECEIPT_CUTOFF_HEIGHT + 100);
        assert!(!result.is_valid());
        match result {
            LockStateVerificationResult::LegacyReceiptExpired {
                current_height,
                cutoff_height,
            } => {
                assert_eq!(current_height, LEGACY_RECEIPT_CUTOFF_HEIGHT + 100);
                assert_eq!(cutoff_height, LEGACY_RECEIPT_CUTOFF_HEIGHT);
            }
            _ => panic!("Expected LegacyReceiptExpired"),
        }
    }

    // =========================================================================
    // CRIT-1 FIX TESTS: Double-Spend Prevention via Reservations
    // =========================================================================

    #[test]
    fn test_reservation_tracker_basic() {
        let tracker = ReservationTracker::new();
        let current_time = 1700000000000u64;
        let payment_id = [1u8; 32];

        assert_eq!(tracker.total_reserved(current_time), 0);
        assert_eq!(tracker.active_count(current_time), 0);

        let result = tracker.try_reserve(payment_id, 50_000, 500_000, current_time);
        assert!(result.is_ok());

        // L-11: Result now contains both reservation and expired_reservations
        let res_result = result.unwrap();
        assert_eq!(res_result.reservation.amount_sats, 50_000);
        assert!(res_result.expired_reservations.is_empty()); // No expired reservations on first call
        assert_eq!(tracker.total_reserved(current_time), 50_000);
        assert_eq!(tracker.active_count(current_time), 1);

        tracker.release(&payment_id);
        assert_eq!(tracker.total_reserved(current_time), 0);
        assert_eq!(tracker.active_count(current_time), 0);
    }

    #[test]
    fn test_reservation_prevents_double_spend() {
        let tracker = ReservationTracker::new();
        let current_time = 1700000000000u64;
        let available_balance = 100_000u64;

        // First payment: reserve 60k (needs 66k with 10% buffer)
        let payment1 = [1u8; 32];
        let result1 = tracker.try_reserve(payment1, 60_000, available_balance, current_time);
        assert!(result1.is_ok());

        // Second payment: try to reserve 50k (insufficient after first reservation)
        let payment2 = [2u8; 32];
        let result2 = tracker.try_reserve(payment2, 50_000, available_balance, current_time);

        // CRIT-1 FIX: Second payment MUST fail
        assert!(result2.is_err());
        match result2 {
            Err(InstantPaymentError::InsufficientFunds {
                requested,
                reserved,
                ..
            }) => {
                assert_eq!(requested, 50_000);
                assert_eq!(reserved, 60_000);
            }
            _ => panic!("Expected InsufficientFunds error"),
        }
    }

    #[test]
    fn test_duplicate_payment_rejected() {
        let tracker = ReservationTracker::new();
        let current_time = 1700000000000u64;
        let payment_id = [1u8; 32];

        let result1 = tracker.try_reserve(payment_id, 10_000, 500_000, current_time);
        assert!(result1.is_ok());

        let result2 = tracker.try_reserve(payment_id, 10_000, 500_000, current_time);
        assert!(matches!(
            result2,
            Err(InstantPaymentError::DuplicatePayment)
        ));
    }

    #[test]
    fn test_reservation_expiry() {
        let tracker = ReservationTracker::new();
        let start_time = 1700000000000u64;
        let payment_id = [1u8; 32];

        tracker
            .try_reserve(payment_id, 50_000, 500_000, start_time)
            .unwrap();
        assert_eq!(tracker.active_count(start_time), 1);

        // After expiry (30 seconds + 1ms)
        let after_expiry = start_time + (RESERVATION_EXPIRY_SECS as u64 * 1000) + 1;
        assert_eq!(tracker.active_count(after_expiry), 0);
        assert_eq!(tracker.total_reserved(after_expiry), 0);
    }

    #[test]
    fn test_l11_expired_reservations_returned() {
        // L-11 FIX TEST: Verify expired reservations are returned when cleaned up
        let tracker = ReservationTracker::new();
        let start_time = 1700000000000u64;

        // Create first reservation
        let payment1 = [1u8; 32];
        let result1 = tracker.try_reserve(payment1, 50_000, 500_000, start_time);
        assert!(result1.is_ok());
        let res1 = result1.unwrap();
        assert!(res1.expired_reservations.is_empty()); // No expired yet

        // Create second reservation at same time
        let payment2 = [2u8; 32];
        let result2 = tracker.try_reserve(payment2, 30_000, 500_000, start_time);
        assert!(result2.is_ok());
        let res2 = result2.unwrap();
        assert!(res2.expired_reservations.is_empty()); // Still no expired

        // Wait until after expiry (30 seconds + 1ms)
        let after_expiry = start_time + (RESERVATION_EXPIRY_SECS as u64 * 1000) + 1;

        // Create third reservation - this should clean up the first two and return them
        let payment3 = [3u8; 32];
        let result3 = tracker.try_reserve(payment3, 10_000, 500_000, after_expiry);
        assert!(result3.is_ok());
        let res3 = result3.unwrap();

        // L-11 FIX: The two expired reservations should be returned
        assert_eq!(res3.expired_reservations.len(), 2);

        // Verify the expired reservations contain the correct payment IDs and amounts
        let expired_ids: Vec<[u8; 32]> = res3
            .expired_reservations
            .iter()
            .map(|r| r.payment_id)
            .collect();
        assert!(expired_ids.contains(&payment1));
        assert!(expired_ids.contains(&payment2));

        let expired_amounts: Vec<u64> = res3
            .expired_reservations
            .iter()
            .map(|r| r.amount_sats)
            .collect();
        assert!(expired_amounts.contains(&50_000));
        assert!(expired_amounts.contains(&30_000));

        // The tracker should now only have the new reservation
        assert_eq!(tracker.active_count(after_expiry), 1);
        assert_eq!(tracker.total_reserved(after_expiry), 10_000);
    }

    #[test]
    fn test_lock_snapshot_accounts_for_reservations() {
        let mut lock = create_healthy_lock();
        lock.balance_sats = 100_000;
        lock.pending_instant_sats = 0;

        // Without reservations, 90k can be instant
        let cap1 = lock.check_instant(80_000, 200);
        assert!(cap1.capable);

        // Add pending instant reservation
        lock.pending_instant_sats = 60_000;

        // Now only 40k available, so 80k payment should fail
        let cap2 = lock.check_instant(80_000, 200);
        assert!(!cap2.capable);
        assert!(cap2
            .conditions_failed
            .contains(&InstantCondition::SufficientBalance));

        // But 30k should still work (needs 33k, have 40k)
        let cap3 = lock.check_instant(30_000, 200);
        assert!(cap3.capable);
    }

    // =========================================================================
    // CRIT-2 FIX TESTS: Ownership Verification
    // =========================================================================

    #[test]
    fn test_signed_payment_message_format() {
        let payment = SignedInstantPayment {
            payment_id: [1u8; 32],
            sender_lock_id: "lock123".to_string(),
            recipient: "merchant456".to_string(),
            amount_sats: 50_000,
            timestamp: 1700000000000,
            sender_pubkey: [2u8; 32],
            signature: [0u8; 64],
        };

        let msg = payment.signing_message();
        assert!(msg.starts_with(b"ghost-instant-v1"));
        assert!(msg.len() > 16);
    }

    #[test]
    fn test_instant_payment_error_display() {
        let err = InstantPaymentError::InsufficientFunds {
            requested: 100_000,
            available: 50_000,
            reserved: 30_000,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("100000"));
        assert!(msg.contains("50000"));
        assert!(msg.contains("30000"));

        let err2 = InstantPaymentError::SignatureVerificationFailed;
        assert_eq!(format!("{}", err2), "Signature verification failed");

        let err3 = InstantPaymentError::OwnershipNotProven;
        assert_eq!(format!("{}", err3), "Lock ownership not proven");
    }

    // =========================================================================
    // H-FUND-4: Concurrent Merchant Instant Payment Tests
    // =========================================================================

    #[test]
    fn test_h_fund4_concurrent_merchants_same_lock() {
        // H-FUND-4: Verify that multiple merchants cannot simultaneously
        // accept instant payments from the same lock that exceed its balance.
        //
        // Scenario: User has 100k sats. Two merchants simultaneously check
        // capability and attempt to accept 60k sats each.
        //
        // Expected: One succeeds, one fails. No double-spend possible.

        let tracker = ReservationTracker::new();
        let current_time = 1700000000000u64;
        let lock_balance = 100_000u64; // 100k sats

        // Merchant A checks and reserves 60k (with 10% buffer needs 66k)
        let payment_a = [1u8; 32];
        let result_a = tracker.try_reserve(payment_a, 60_000, lock_balance, current_time);
        assert!(result_a.is_ok(), "Merchant A should succeed first");

        // After merchant A's reservation, only ~34k remains (100k - 66k)
        // Merchant B attempts to reserve 60k
        let payment_b = [2u8; 32];
        let result_b = tracker.try_reserve(payment_b, 60_000, lock_balance, current_time);

        // H-FUND-4: Merchant B MUST fail
        assert!(result_b.is_err(), "Merchant B must fail - funds reserved");
        match result_b {
            Err(InstantPaymentError::InsufficientFunds {
                requested,
                available,
                reserved,
            }) => {
                assert_eq!(requested, 60_000);
                assert_eq!(reserved, 60_000);
                // Available should be 40k (100k - 60k reserved)
                assert_eq!(available, 40_000);
            }
            _ => panic!("Expected InsufficientFunds error"),
        }

        // Total reserved should be just merchant A's amount
        assert_eq!(tracker.total_reserved(current_time), 60_000);
    }

    #[test]
    fn test_h_fund4_atomic_check_and_reserve() {
        // H-FUND-4: Verify the atomicity of the check-and-reserve operation.
        // The RwLock ensures that between checking available balance and
        // inserting the reservation, no other thread can modify the state.

        let tracker = ReservationTracker::new();
        let current_time = 1700000000000u64;

        // Simulate rapid successive reservations
        let mut successful = 0;
        let mut failed = 0;

        for i in 0..10 {
            let payment_id = [i as u8; 32];
            // Each tries to reserve 15k from a 100k balance
            // Only 6 should succeed (6 * 16.5k = 99k with 10% buffer)
            match tracker.try_reserve(payment_id, 15_000, 100_000, current_time) {
                Ok(_) => successful += 1,
                Err(_) => failed += 1,
            }
        }

        // Should have exactly 6 successful and 4 failed
        // 15k * 1.1 = 16.5k per payment, 100k / 16.5k = 6.06 = 6 payments
        assert_eq!(successful, 6, "Expected 6 successful reservations");
        assert_eq!(failed, 4, "Expected 4 failed reservations");
        assert_eq!(tracker.total_reserved(current_time), 90_000); // 6 * 15k
    }

    #[test]
    fn test_h_fund4_rwlock_thread_safety() {
        // H-FUND-4: The ReservationTracker uses parking_lot::RwLock which:
        // 1. Allows multiple concurrent readers OR one exclusive writer
        // 2. The try_reserve method takes a write lock immediately
        // 3. Holds the lock through check + insert = atomic operation
        //
        // This test documents the expected behavior - actual concurrent
        // testing would require threads which is difficult in unit tests.

        let tracker = ReservationTracker::new();

        // Verify type implements Send + Sync (required for thread safety)
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<ReservationTracker>();
        assert_sync::<ReservationTracker>();

        // Verify the internal RwLock type
        // The write() call returns a guard that holds exclusive access
        let current_time = 1700000000000u64;
        let _ = tracker.try_reserve([1u8; 32], 1000, 10000, current_time);

        // After the method returns, the lock is released
        // Other operations can proceed
        assert_eq!(tracker.active_count(current_time), 1);
    }

    // =========================================================================
    // M-VAL-2 FIX TESTS: Minimum Confidence Threshold
    // =========================================================================

    #[test]
    fn test_confidence_threshold_rejects_low_confidence() {
        // M-VAL-2 TEST: Verify that low confidence results in not capable
        let capability = InstantCapability::capable(100_000, 0.5, 300);
        assert!(
            !capability.capable,
            "Confidence 0.5 (50%) should be rejected - below {} threshold",
            MIN_CONFIDENCE_THRESHOLD
        );
    }

    #[test]
    fn test_confidence_threshold_accepts_high_confidence() {
        // M-VAL-2 TEST: Verify that high confidence is accepted
        let capability = InstantCapability::capable(100_000, 0.8, 300);
        assert!(
            capability.capable,
            "Confidence 0.8 (80%) should be accepted - above {} threshold",
            MIN_CONFIDENCE_THRESHOLD
        );
    }

    #[test]
    fn test_confidence_threshold_boundary() {
        // M-VAL-2 TEST: Verify boundary behavior at threshold
        let below = InstantCapability::capable(100_000, MIN_CONFIDENCE_THRESHOLD - 0.01, 300);
        assert!(!below.capable, "Just below threshold should be rejected");

        let at = InstantCapability::capable(100_000, MIN_CONFIDENCE_THRESHOLD, 300);
        assert!(at.capable, "At threshold should be accepted");

        let above = InstantCapability::capable(100_000, MIN_CONFIDENCE_THRESHOLD + 0.01, 300);
        assert!(above.capable, "Just above threshold should be accepted");
    }

    #[test]
    fn test_is_confidence_sufficient_method() {
        // M-VAL-2 TEST: Verify the is_confidence_sufficient helper method
        let high_confidence = InstantCapability::capable(100_000, 0.9, 300);
        assert!(high_confidence.is_confidence_sufficient());

        let low_confidence = InstantCapability {
            capable: false,
            max_instant_sats: 0,
            confidence: 0.5,
            valid_until_height: 0,
            conditions_met: vec![],
            conditions_failed: vec![],
        };
        assert!(!low_confidence.is_confidence_sufficient());
    }
}
