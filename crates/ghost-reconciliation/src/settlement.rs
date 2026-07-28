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
//| FILE: settlement.rs                                                                                                  |
//|======================================================================================================================|

//! Settlement types and management

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ReconciliationError, ReconciliationResult};
use crate::MIN_SETTLEMENT_SATS;

// ============================================================================
// C-1: Settlement Ownership Verification
// ============================================================================
//
// This module implements cryptographic verification that settlement requesters
// own the locks they are attempting to spend. Without this verification, an
// attacker could request settlements from locks they don't own, potentially
// stealing funds.
//
// The ownership proof consists of:
// 1. A signature over the settlement details (settlement_id || destination || amount)
// 2. The public key corresponding to the lock's private key
//
// Verification ensures the requester controls the lock's private key.
// ============================================================================

/// C-7 FIX: Domain separator for settlement ownership signatures (version 2)
/// This prevents signature reuse across different protocols AND across epochs/batches.
/// The "v2" domain indicates signatures include epoch and batch_id.
const SETTLEMENT_OWNERSHIP_DOMAIN: &[u8] = b"GhostSettlement/Ownership/v2";

/// The kind of settlement determines fee treatment and output construction.
///
/// All Ghost Lock L1 spends go through settlement batches — no direct spends allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SettlementKind {
    /// User exiting Ghost Pay to an external Bitcoin address.
    /// Only pays mining fee share (protocol fee removed).
    Exit,

    /// Key rotation to new Ghost Lock address(es).
    /// Fee-exempt: only pays mining fee share, not the 0.1% protocol fee.
    /// Can optionally re-split into different denominations.
    Jump,

    /// Key rotation routed through a Wraith mix cycle for maximum privacy.
    /// Fee-exempt: Wraith service fee is collected inside the CoinJoin tx.
    /// Only pays mining fee share (handled at batch level).
    /// Gets full 140-500 anonymity set through split/merge mixing.
    WraithJump,
}

impl SettlementKind {
    /// Display name
    pub fn name(&self) -> &'static str {
        match self {
            SettlementKind::Exit => "Exit",
            SettlementKind::Jump => "Jump",
            SettlementKind::WraithJump => "WraithJump",
        }
    }
}

impl std::fmt::Display for SettlementKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Ownership proof for a settlement request (C-1, C-7)
///
/// Proves that the requester owns the lock being spent by providing a
/// Schnorr signature over the settlement details.
///
/// C-7 FIX: The signed message now includes epoch and batch_id to prevent signature
/// replay attacks across different epochs or batches. An attacker cannot reuse a
/// signature from a previous epoch/batch to claim funds in a new context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipProof {
    /// The signature over: DOMAIN || epoch || batch_id || settlement_id || destination_address || amount_sats
    /// Stored as hex string because serde doesn't support [u8; 64] natively
    signature_hex: String,
    /// The x-only public key (32 bytes) corresponding to the lock's private key
    source_pubkey: [u8; 32],
    /// C-7: Epoch number when this proof was created (prevents cross-epoch replay)
    epoch: u64,
    /// C-7: Batch ID this proof is for (prevents cross-batch replay, 32 bytes as hex)
    /// If not yet assigned to a batch, this should be all zeros.
    batch_id_hex: String,
}

impl OwnershipProof {
    /// Create a new ownership proof from raw components
    ///
    /// C-7 FIX: Now requires epoch and batch_id to prevent replay attacks.
    pub fn new(
        signature: [u8; 64],
        source_pubkey: [u8; 32],
        epoch: u64,
        batch_id: [u8; 32],
    ) -> Self {
        Self {
            signature_hex: hex::encode(signature),
            source_pubkey,
            epoch,
            batch_id_hex: hex::encode(batch_id),
        }
    }

    /// Create an ownership proof for a pending settlement (batch_id = zeros)
    ///
    /// Use this when creating a proof before the settlement is assigned to a batch.
    /// The batch_id is set to all zeros, which will be verified during batching.
    pub fn new_pending(signature: [u8; 64], source_pubkey: [u8; 32], epoch: u64) -> Self {
        Self::new(signature, source_pubkey, epoch, [0u8; 32])
    }

    /// Get the epoch this proof is for
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the batch_id this proof is for
    pub fn batch_id(&self) -> Result<[u8; 32], ReconciliationError> {
        let bytes = hex::decode(&self.batch_id_hex).map_err(|e| {
            ReconciliationError::InvalidSettlement(format!("Invalid batch_id hex: {}", e))
        })?;
        if bytes.len() != 32 {
            return Err(ReconciliationError::InvalidSettlement(format!(
                "Invalid batch_id length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Get the signature bytes
    pub fn signature(&self) -> Result<[u8; 64], ReconciliationError> {
        let bytes = hex::decode(&self.signature_hex).map_err(|e| {
            ReconciliationError::InvalidSettlement(format!("Invalid signature hex: {}", e))
        })?;
        if bytes.len() != 64 {
            return Err(ReconciliationError::InvalidSettlement(format!(
                "Invalid signature length: expected 64, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Get the source public key
    pub fn source_pubkey(&self) -> &[u8; 32] {
        &self.source_pubkey
    }

    /// Build the message that should be signed for ownership verification
    ///
    /// C-7 FIX: Format now includes epoch and batch_id to prevent replay:
    /// DOMAIN || epoch (LE) || batch_id || settlement_id || destination_address || amount_sats (LE)
    ///
    /// This ensures signatures cannot be replayed across:
    /// - Different epochs (epoch changes prevent old signatures from being valid)
    /// - Different batches (batch_id uniqueness prevents cross-batch replay)
    pub fn build_message(
        epoch: u64,
        batch_id: &[u8; 32],
        settlement_id: &[u8; 32],
        destination: &str,
        amount_sats: u64,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(SETTLEMENT_OWNERSHIP_DOMAIN);
        // C-7: Include epoch first to prevent cross-epoch replay
        hasher.update(epoch.to_le_bytes());
        // C-7: Include batch_id to prevent cross-batch replay
        hasher.update(batch_id);
        hasher.update(settlement_id);
        hasher.update(destination.as_bytes());
        hasher.update(amount_sats.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify that this proof is valid for the given settlement details
    ///
    /// C-7 FIX: Now validates epoch and batch_id are included in the signed message.
    ///
    /// Returns Ok(()) if verification succeeds, or an error describing why it failed.
    pub fn verify(
        &self,
        settlement_id: &[u8; 32],
        destination: &str,
        amount_sats: u64,
        expected_lock_pubkey: &[u8; 32],
    ) -> ReconciliationResult<()> {
        use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};

        // C-1: First verify the pubkey matches the expected lock pubkey
        if self.source_pubkey != *expected_lock_pubkey {
            return Err(ReconciliationError::InvalidSettlement(format!(
                "C-1 SECURITY: Ownership proof pubkey {} does not match lock pubkey {}",
                hex::encode(self.source_pubkey),
                hex::encode(expected_lock_pubkey)
            )));
        }

        let secp = Secp256k1::verification_only();

        // Parse the x-only public key
        let pubkey = XOnlyPublicKey::from_slice(&self.source_pubkey).map_err(|e| {
            ReconciliationError::InvalidSettlement(format!(
                "C-1: Invalid source pubkey in ownership proof: {}",
                e
            ))
        })?;

        // Parse the signature
        let sig_bytes = self.signature()?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|e| {
            ReconciliationError::InvalidSettlement(format!(
                "C-1: Invalid signature in ownership proof: {}",
                e
            ))
        })?;

        // C-7: Get batch_id from proof for replay prevention
        let batch_id = self.batch_id()?;

        // Build the message (C-7: now includes epoch and batch_id)
        let message_hash = Self::build_message(
            self.epoch,
            &batch_id,
            settlement_id,
            destination,
            amount_sats,
        );
        let message = Message::from_digest(message_hash);

        // Verify the signature
        secp.verify_schnorr(&sig, &message, &pubkey).map_err(|e| {
            ReconciliationError::InvalidSettlement(format!(
                "C-1/C-7 SECURITY: Settlement ownership verification failed - signature invalid: {}. \
                 Requester does NOT own the lock they are trying to spend OR signature was created \
                 for a different epoch/batch (replay attack prevented)!",
                e
            ))
        })?;

        Ok(())
    }

    /// Verify that this proof matches the expected epoch (C-7)
    ///
    /// Call this during batch formation to ensure the proof is for the current epoch.
    pub fn verify_epoch(&self, expected_epoch: u64) -> ReconciliationResult<()> {
        if self.epoch != expected_epoch {
            return Err(ReconciliationError::InvalidSettlement(format!(
                "C-7 SECURITY: Ownership proof epoch {} does not match current epoch {}. \
                 This prevents replay of old proofs.",
                self.epoch, expected_epoch
            )));
        }
        Ok(())
    }
}

/// A settlement request with ownership proof (C-1)
///
/// Wraps a Settlement with cryptographic proof that the requester owns
/// the source lock. This MUST be verified before the settlement is
/// included in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRequest {
    /// The settlement to execute
    pub settlement: Settlement,
    /// Cryptographic proof of lock ownership
    pub ownership_proof: OwnershipProof,
}

impl SettlementRequest {
    /// Create a new settlement request with ownership proof
    pub fn new(settlement: Settlement, ownership_proof: OwnershipProof) -> Self {
        Self {
            settlement,
            ownership_proof,
        }
    }

    /// Verify the ownership proof is valid for this settlement
    ///
    /// This MUST be called before including the settlement in a batch.
    /// Returns Ok(()) if the proof is valid.
    ///
    /// Note: This method verifies the signature but does not validate the epoch.
    /// For full H-6 compliance, use `verify_ownership_with_epoch()` which also
    /// validates that the proof was created for the current epoch.
    pub fn verify_ownership(&self) -> ReconciliationResult<()> {
        // The expected lock pubkey is derived from the lock_id
        // In Ghost Locks, the lock_id IS the x-only pubkey of the lock output
        self.ownership_proof.verify(
            self.settlement.id(),
            self.settlement.destination_address(),
            self.settlement.amount_sats(),
            self.settlement.source_lock_id(),
        )
    }

    /// H-6 FIX: Verify the ownership proof is valid for this settlement AND the current epoch
    ///
    /// This is the PREFERRED method for verifying settlement requests. It verifies both:
    /// 1. The signature is valid (C-1)
    /// 2. The epoch in the proof matches the current epoch (H-6)
    ///
    /// The epoch check prevents replay attacks where old proofs from previous epochs
    /// are reused in the current epoch.
    ///
    /// # Arguments
    ///
    /// * `current_epoch` - The current epoch number. Must match the epoch in the proof.
    ///
    /// # Returns
    ///
    /// Ok(()) if both signature and epoch are valid.
    pub fn verify_ownership_with_epoch(&self, current_epoch: u64) -> ReconciliationResult<()> {
        // H-6: Verify epoch FIRST before signature verification
        // This prevents processing of stale proofs from old epochs
        self.ownership_proof.verify_epoch(current_epoch)?;

        // C-1: Now verify the signature
        self.ownership_proof.verify(
            self.settlement.id(),
            self.settlement.destination_address(),
            self.settlement.amount_sats(),
            self.settlement.source_lock_id(),
        )
    }

    /// Get the inner settlement (only after ownership is verified)
    pub fn into_settlement(self) -> Settlement {
        self.settlement
    }

    /// Get a reference to the settlement
    pub fn settlement(&self) -> &Settlement {
        &self.settlement
    }
}

/// Settlement state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SettlementState {
    /// Pending inclusion in batch
    Pending,
    /// Included in batch, awaiting L1 confirmation
    Batched,
    /// L1 transaction confirmed, in dispute window
    Confirming,
    /// Dispute window passed, fully settled
    Finalized,
    /// Settlement was disputed and rejected
    Rejected,
    /// Settlement was cancelled by user
    Cancelled,
}

impl SettlementState {
    /// Check if settlement is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SettlementState::Finalized | SettlementState::Rejected | SettlementState::Cancelled
        )
    }

    /// Check if settlement can be cancelled
    pub fn can_cancel(&self) -> bool {
        matches!(self, SettlementState::Pending)
    }

    /// Get state name
    pub fn name(&self) -> &'static str {
        match self {
            SettlementState::Pending => "Pending",
            SettlementState::Batched => "Batched",
            SettlementState::Confirming => "Confirming",
            SettlementState::Finalized => "Finalized",
            SettlementState::Rejected => "Rejected",
            SettlementState::Cancelled => "Cancelled",
        }
    }
}

impl std::fmt::Display for SettlementState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A settlement request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settlement {
    /// Unique settlement ID
    id: [u8; 32],
    /// Settlement kind (Exit, Jump, or WraithJump)
    kind: SettlementKind,
    /// Source Ghost ID (L2 account)
    source_ghost_id: String,
    /// Source lock ID (the Ghost Lock being spent)
    source_lock_id: [u8; 32],
    /// Destination Bitcoin address (or new Ghost Lock address for Jump/WraithJump)
    destination_address: String,
    /// Amount in satoshis
    amount_sats: u64,
    /// Fee in satoshis (always 0 — protocol fee removed, kept for hash stability)
    fee_sats: u64,
    /// Current state
    state: SettlementState,
    /// Created timestamp
    created_at: u64,
    /// Updated timestamp
    updated_at: u64,
    /// Batch ID (if batched)
    batch_id: Option<[u8; 32]>,
    /// Merkle proof (if batched)
    merkle_proof: Option<Vec<[u8; 32]>>,
    /// L1 transaction ID (if confirmed)
    l1_txid: Option<String>,
}

impl Settlement {
    /// Create a new Exit settlement (leaving Ghost Pay to external Bitcoin address)
    pub fn new(
        source_ghost_id: String,
        source_lock_id: [u8; 32],
        destination_address: String,
        amount_sats: u64,
    ) -> ReconciliationResult<Self> {
        Self::new_with_kind(
            SettlementKind::Exit,
            source_ghost_id,
            source_lock_id,
            destination_address,
            amount_sats,
        )
    }

    /// Create a new Jump settlement (key rotation to new Ghost Lock address)
    pub fn new_jump(
        source_ghost_id: String,
        source_lock_id: [u8; 32],
        destination_address: String,
        amount_sats: u64,
    ) -> ReconciliationResult<Self> {
        Self::new_with_kind(
            SettlementKind::Jump,
            source_ghost_id,
            source_lock_id,
            destination_address,
            amount_sats,
        )
    }

    /// Create a new WraithJump settlement (key rotation through Wraith mix cycle)
    pub fn new_wraith_jump(
        source_ghost_id: String,
        source_lock_id: [u8; 32],
        destination_address: String,
        amount_sats: u64,
    ) -> ReconciliationResult<Self> {
        Self::new_with_kind(
            SettlementKind::WraithJump,
            source_ghost_id,
            source_lock_id,
            destination_address,
            amount_sats,
        )
    }

    /// Internal constructor with settlement kind
    ///
    /// # Amount Validation Rules
    ///
    /// The following validation checks are applied to every settlement:
    ///
    /// 1. **Minimum amount**: `amount_sats >= MIN_SETTLEMENT_SATS` (10,000 sats).
    ///    Settlements below this threshold are rejected because the L1 transaction
    ///    fees would consume a disproportionate share of the settlement value,
    ///    making it uneconomical. This also prevents dust-output DoS attacks where
    ///    an attacker creates many tiny settlements to bloat batch sizes.
    ///
    /// 2. **Overflow protection**: The batch-level `total_amount_sats` accumulation
    ///    uses checked arithmetic in `Batch::add_settlement` to prevent overflow
    ///    when summing many settlements.
    fn new_with_kind(
        kind: SettlementKind,
        source_ghost_id: String,
        source_lock_id: [u8; 32],
        destination_address: String,
        amount_sats: u64,
    ) -> ReconciliationResult<Self> {
        // Validate minimum amount
        if amount_sats < MIN_SETTLEMENT_SATS {
            return Err(ReconciliationError::BelowMinimum {
                amount: amount_sats,
                minimum: MIN_SETTLEMENT_SATS,
            });
        }

        // All settlement types are fee-free (protocol fee removed)
        let fee_sats = 0u64;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Generate unique ID with cryptographic nonce for collision resistance
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| ReconciliationError::RngFailure)?;

        let mut hasher = Sha256::new();
        hasher.update(b"GhostSettlement/v2");
        hasher.update(nonce);
        hasher.update(&source_ghost_id);
        hasher.update(source_lock_id);
        hasher.update(&destination_address);
        hasher.update(amount_sats.to_le_bytes());
        hasher.update(now.to_le_bytes());
        let id: [u8; 32] = hasher.finalize().into();

        Ok(Self {
            id,
            kind,
            source_ghost_id,
            source_lock_id,
            destination_address,
            amount_sats,
            fee_sats,
            state: SettlementState::Pending,
            created_at: now,
            updated_at: now,
            batch_id: None,
            merkle_proof: None,
            l1_txid: None,
        })
    }

    /// Get settlement kind
    pub fn kind(&self) -> SettlementKind {
        self.kind
    }

    /// Get settlement ID
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get settlement ID as hex
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    /// Get source ghost ID
    pub fn source_ghost_id(&self) -> &str {
        &self.source_ghost_id
    }

    /// Get source lock ID
    pub fn source_lock_id(&self) -> &[u8; 32] {
        &self.source_lock_id
    }

    /// Get destination address
    pub fn destination_address(&self) -> &str {
        &self.destination_address
    }

    /// Get amount in satoshis
    pub fn amount_sats(&self) -> u64 {
        self.amount_sats
    }

    /// Get fee in satoshis
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// Get net amount after fee.
    ///
    /// Protocol fee has been removed, so this always returns `amount_sats`.
    /// Kept for API compatibility.
    pub fn net_amount_sats(&self) -> u64 {
        self.amount_sats
    }

    /// Get current state
    pub fn state(&self) -> SettlementState {
        self.state
    }

    /// Get batch ID
    pub fn batch_id(&self) -> Option<&[u8; 32]> {
        self.batch_id.as_ref()
    }

    /// Get merkle proof
    pub fn merkle_proof(&self) -> Option<&Vec<[u8; 32]>> {
        self.merkle_proof.as_ref()
    }

    /// Get L1 transaction ID
    pub fn l1_txid(&self) -> Option<&str> {
        self.l1_txid.as_deref()
    }

    /// Compute the settlement hash (leaf in merkle tree)
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.id);
        hasher.update(&self.source_ghost_id);
        hasher.update(self.source_lock_id);
        hasher.update(&self.destination_address);
        hasher.update(self.amount_sats.to_le_bytes());
        hasher.update(self.fee_sats.to_le_bytes());
        hasher.finalize().into()
    }

    /// Mark as batched
    pub fn mark_batched(
        &mut self,
        batch_id: [u8; 32],
        merkle_proof: Vec<[u8; 32]>,
    ) -> ReconciliationResult<()> {
        if self.state != SettlementState::Pending {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Batched".to_string(),
            });
        }

        self.state = SettlementState::Batched;
        self.batch_id = Some(batch_id);
        self.merkle_proof = Some(merkle_proof);
        self.updated_at = Self::now();
        Ok(())
    }

    /// Mark as confirming (L1 tx confirmed)
    pub fn mark_confirming(&mut self, l1_txid: String) -> ReconciliationResult<()> {
        if self.state != SettlementState::Batched {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Confirming".to_string(),
            });
        }

        self.state = SettlementState::Confirming;
        self.l1_txid = Some(l1_txid);
        self.updated_at = Self::now();
        Ok(())
    }

    /// Mark as finalized
    pub fn mark_finalized(&mut self) -> ReconciliationResult<()> {
        if self.state != SettlementState::Confirming {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Finalized".to_string(),
            });
        }

        self.state = SettlementState::Finalized;
        self.updated_at = Self::now();
        Ok(())
    }

    /// Mark as rejected
    pub fn mark_rejected(&mut self) -> ReconciliationResult<()> {
        if self.state == SettlementState::Finalized {
            return Err(ReconciliationError::AlreadyFinalized { id: self.id_hex() });
        }

        self.state = SettlementState::Rejected;
        self.updated_at = Self::now();
        Ok(())
    }

    /// Cancel the settlement
    pub fn cancel(&mut self) -> ReconciliationResult<()> {
        if !self.state.can_cancel() {
            return Err(ReconciliationError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Cancelled".to_string(),
            });
        }

        self.state = SettlementState::Cancelled;
        self.updated_at = Self::now();
        Ok(())
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lock_id() -> [u8; 32] {
        [1u8; 32]
    }

    #[test]
    fn test_settlement_creation() {
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        assert_eq!(settlement.state(), SettlementState::Pending);
        assert_eq!(settlement.amount_sats(), 100_000);
        assert_eq!(settlement.fee_sats(), 0);
        assert_eq!(settlement.net_amount_sats(), 100_000);
        assert_eq!(settlement.source_lock_id(), &test_lock_id());
    }

    #[test]
    fn test_minimum_amount() {
        let result = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            1_000, // Below minimum
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_state_transitions() {
        let mut settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        // Pending -> Batched
        settlement.mark_batched([0u8; 32], vec![]).unwrap();
        assert_eq!(settlement.state(), SettlementState::Batched);

        // Batched -> Confirming
        settlement.mark_confirming("txid123".to_string()).unwrap();
        assert_eq!(settlement.state(), SettlementState::Confirming);

        // Confirming -> Finalized
        settlement.mark_finalized().unwrap();
        assert_eq!(settlement.state(), SettlementState::Finalized);
    }

    #[test]
    fn test_cancel() {
        let mut settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        settlement.cancel().unwrap();
        assert_eq!(settlement.state(), SettlementState::Cancelled);
    }

    #[test]
    fn test_settlement_id_collision_prevention() {
        // C-5: Verify that settlements with identical params created in the same second
        // still have different IDs due to cryptographic nonce
        use std::collections::HashSet;

        let source_ghost_id = "ghost1abc".to_string();
        let lock_id = test_lock_id();
        let destination = "bc1qtest".to_string();
        let amount = 100_000u64;

        // Create multiple settlements with identical parameters rapidly
        let mut ids = HashSet::new();
        for _ in 0..100 {
            let settlement = Settlement::new(
                source_ghost_id.clone(),
                lock_id,
                destination.clone(),
                amount,
            )
            .unwrap();
            let id = *settlement.id();
            assert!(
                ids.insert(id),
                "CRITICAL: Settlement ID collision detected - same-second settlements must have unique IDs"
            );
        }
        assert_eq!(ids.len(), 100, "All 100 settlement IDs must be unique");
    }

    // ========================================================================
    // C-1: Ownership Proof Tests
    // ========================================================================

    #[test]
    fn test_c1_ownership_proof_creation() {
        let sig = [1u8; 64];
        let pubkey = [2u8; 32];
        let epoch = 42u64;
        let batch_id = [3u8; 32];

        let proof = OwnershipProof::new(sig, pubkey, epoch, batch_id);

        assert_eq!(proof.signature().unwrap(), sig);
        assert_eq!(proof.source_pubkey(), &pubkey);
        assert_eq!(proof.epoch(), epoch);
        assert_eq!(proof.batch_id().unwrap(), batch_id);
    }

    #[test]
    fn test_c7_ownership_proof_pending() {
        // C-7 TEST: Test pending proof (batch_id = zeros)
        let sig = [1u8; 64];
        let pubkey = [2u8; 32];
        let epoch = 42u64;

        let proof = OwnershipProof::new_pending(sig, pubkey, epoch);

        assert_eq!(proof.batch_id().unwrap(), [0u8; 32]);
        assert_eq!(proof.epoch(), epoch);
    }

    #[test]
    fn test_c1_ownership_proof_message_deterministic() {
        let epoch = 10u64;
        let batch_id = [5u8; 32];
        let settlement_id = [1u8; 32];
        let destination = "bc1qtest";
        let amount = 50_000u64;

        let msg1 =
            OwnershipProof::build_message(epoch, &batch_id, &settlement_id, destination, amount);
        let msg2 =
            OwnershipProof::build_message(epoch, &batch_id, &settlement_id, destination, amount);

        assert_eq!(msg1, msg2, "Same inputs must produce same message hash");
    }

    #[test]
    fn test_c1_ownership_proof_message_varies_with_inputs() {
        let epoch = 10u64;
        let batch_id = [5u8; 32];
        let settlement_id = [1u8; 32];
        let destination = "bc1qtest";
        let amount = 50_000u64;

        let msg1 =
            OwnershipProof::build_message(epoch, &batch_id, &settlement_id, destination, amount);

        // Different settlement ID
        let different_id = [2u8; 32];
        let msg2 =
            OwnershipProof::build_message(epoch, &batch_id, &different_id, destination, amount);
        assert_ne!(
            msg1, msg2,
            "Different settlement_id must produce different hash"
        );

        // Different destination
        let msg3 =
            OwnershipProof::build_message(epoch, &batch_id, &settlement_id, "bc1qother", amount);
        assert_ne!(
            msg1, msg3,
            "Different destination must produce different hash"
        );

        // Different amount
        let msg4 = OwnershipProof::build_message(
            epoch,
            &batch_id,
            &settlement_id,
            destination,
            amount + 1,
        );
        assert_ne!(msg1, msg4, "Different amount must produce different hash");
    }

    #[test]
    fn test_c7_ownership_proof_message_varies_with_epoch() {
        // C-7 TEST: Different epoch must produce different hash
        let batch_id = [5u8; 32];
        let settlement_id = [1u8; 32];
        let destination = "bc1qtest";
        let amount = 50_000u64;

        let msg1 =
            OwnershipProof::build_message(10, &batch_id, &settlement_id, destination, amount);
        let msg2 =
            OwnershipProof::build_message(11, &batch_id, &settlement_id, destination, amount);

        assert_ne!(
            msg1, msg2,
            "C-7: Different epoch must produce different hash"
        );
    }

    #[test]
    fn test_c7_ownership_proof_message_varies_with_batch_id() {
        // C-7 TEST: Different batch_id must produce different hash
        let epoch = 10u64;
        let settlement_id = [1u8; 32];
        let destination = "bc1qtest";
        let amount = 50_000u64;

        let batch_id1 = [5u8; 32];
        let batch_id2 = [6u8; 32];

        let msg1 =
            OwnershipProof::build_message(epoch, &batch_id1, &settlement_id, destination, amount);
        let msg2 =
            OwnershipProof::build_message(epoch, &batch_id2, &settlement_id, destination, amount);

        assert_ne!(
            msg1, msg2,
            "C-7: Different batch_id must produce different hash"
        );
    }

    #[test]
    fn test_c1_ownership_verification_fails_with_wrong_pubkey() {
        let settlement_id = [1u8; 32];
        let destination = "bc1qtest";
        let amount = 50_000u64;
        let expected_lock_pubkey = [3u8; 32]; // Expected pubkey

        // Create proof with DIFFERENT pubkey (C-7: with epoch and batch)
        let fake_sig = [0u8; 64];
        let wrong_pubkey = [4u8; 32]; // Doesn't match expected
        let epoch = 10u64;
        let batch_id = [5u8; 32];
        let proof = OwnershipProof::new(fake_sig, wrong_pubkey, epoch, batch_id);

        let result = proof.verify(&settlement_id, destination, amount, &expected_lock_pubkey);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not match lock pubkey"),
            "Error should mention pubkey mismatch, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_c1_settlement_request_creation() {
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        let epoch = 10u64;
        let batch_id = [5u8; 32];
        let proof = OwnershipProof::new([0u8; 64], test_lock_id(), epoch, batch_id);
        let request = SettlementRequest::new(settlement.clone(), proof);

        assert_eq!(request.settlement().id(), settlement.id());
        assert_eq!(request.settlement().amount_sats(), settlement.amount_sats());
    }

    #[test]
    fn test_c1_settlement_request_verify_ownership_fails_invalid_sig() {
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        // Create proof with matching pubkey but invalid signature (C-7: with epoch and batch)
        let invalid_sig = [0u8; 64]; // All zeros is not a valid signature
        let epoch = 10u64;
        let batch_id = [5u8; 32];
        let proof = OwnershipProof::new(invalid_sig, test_lock_id(), epoch, batch_id);
        let request = SettlementRequest::new(settlement, proof);

        // Verification should fail due to invalid signature
        let result = request.verify_ownership();
        assert!(result.is_err(), "Should fail with invalid signature");
    }

    #[test]
    fn test_c7_epoch_verification() {
        // C-7 TEST: Epoch verification should pass for matching epoch
        let sig = [1u8; 64];
        let pubkey = [2u8; 32];
        let epoch = 42u64;
        let batch_id = [3u8; 32];

        let proof = OwnershipProof::new(sig, pubkey, epoch, batch_id);

        assert!(
            proof.verify_epoch(42).is_ok(),
            "Should pass for matching epoch"
        );
        assert!(
            proof.verify_epoch(43).is_err(),
            "Should fail for different epoch"
        );
    }

    #[test]
    fn test_h6_verify_ownership_with_epoch() {
        // H-6 TEST: verify_ownership_with_epoch should check epoch FIRST
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(),
            "bc1qtest".to_string(),
            100_000,
        )
        .unwrap();

        // Create proof with epoch 10
        let proof_epoch = 10u64;
        let batch_id = [5u8; 32];
        let proof = OwnershipProof::new([0u8; 64], test_lock_id(), proof_epoch, batch_id);
        let request = SettlementRequest::new(settlement, proof);

        // Verification with wrong epoch should fail immediately (epoch mismatch)
        let result = request.verify_ownership_with_epoch(11);
        assert!(result.is_err(), "Should fail with wrong epoch");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("epoch") && err_msg.contains("does not match"),
            "Error should indicate epoch mismatch, got: {}",
            err_msg
        );

        // Verification with correct epoch should proceed to signature check
        // (will fail because signature is invalid, but that's after epoch check)
        let result = request.verify_ownership_with_epoch(10);
        assert!(result.is_err(), "Should fail with invalid signature");
        // This error should be about signature, not epoch
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("signature") || err_msg.contains("verification failed"),
            "Error should be about signature after epoch passes, got: {}",
            err_msg
        );
    }
}
