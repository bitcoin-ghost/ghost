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
//| FILE: executor.rs                                                                                                    |
//|======================================================================================================================|

//! Batch Executor - Orchestrates L1 Settlement
//!
//! Manages the complete lifecycle of settlement batches from collection
//! through L1 commitment and finalization.
//!
//! # Security Features
//!
//! ## C-1: Settlement Ownership Verification
//! All settlements must include cryptographic proof that the requester owns
//! the lock being spent. Use `add_settlement_request()` which verifies the
//! ownership proof before accepting the settlement.
//!
//! ## C-2: Double-Spend Prevention (Within-Batch)
//! The batch executor tracks consumed inputs within a batch to prevent the
//! same UTXO from being spent multiple times in the same transaction.
//!
//! ## H-FUND-3: Cross-Batch Double-Spend Prevention
//! Additionally, the executor maintains a global reservation system that tracks
//! inputs reserved for pending (unconfirmed) batches. This prevents overlapping
//! settlements from referencing the same inputs across different batches.

use std::collections::{HashMap, HashSet};

use bitcoin::{Network, OutPoint, Txid};
use parking_lot::RwLock;

use crate::batch::{Batch, BatchState};
use crate::commitment::L1Commitment;
use crate::error::ReconciliationError;
use crate::rules::BatchRules;
use crate::settlement::{Settlement, SettlementRequest};
use crate::transaction::{ReconciliationTx, TxOutput};
use crate::{DISPUTE_WINDOW_BLOCKS, MAX_BATCH_SIZE, MIN_BATCH_SIZE};

/// H-15: Minimum confirmations required before a UTXO can be used as input
pub const MIN_INPUT_CONFIRMATIONS: u32 = 6;

/// Input UTXO for reconciliation
#[derive(Debug, Clone)]
pub struct ReconciliationInput {
    /// Transaction ID
    pub txid: Txid,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount: u64,
    /// Owner's ghost ID
    pub ghost_id: String,
    /// Lock ID (if from Ghost Lock)
    pub lock_id: Option<[u8; 32]>,
    /// H-15: Number of confirmations this UTXO has
    pub confirmations: u32,
}

/// H-FUND-3: Reservation for a pending batch's input
///
/// Tracks inputs that are reserved for batches that have been submitted
/// but not yet finalized. This prevents cross-batch double-spend attacks.
#[derive(Debug, Clone)]
pub struct InputReservation {
    /// The batch ID that reserved this input
    pub batch_id: String,
    /// When the reservation was created
    pub reserved_at: u64,
    /// Block height when batch was submitted (None if not submitted yet)
    pub submitted_height: Option<u32>,
}

/// H-FUND-3: Global input reservation tracker
///
/// Thread-safe tracker for inputs reserved across all pending batches.
/// Inputs are reserved when a batch transaction is built, and released
/// when the batch is finalized or fails.
#[derive(Debug, Default)]
pub struct GlobalInputReservations {
    /// Mapping from outpoint to reservation info
    reservations: RwLock<HashMap<OutPoint, InputReservation>>,
}

impl GlobalInputReservations {
    /// Create a new empty reservation tracker
    pub fn new() -> Self {
        Self {
            reservations: RwLock::new(HashMap::new()),
        }
    }

    /// Check if an outpoint is reserved
    pub fn is_reserved(&self, outpoint: &OutPoint) -> bool {
        self.reservations.read().contains_key(outpoint)
    }

    /// Get reservation info for an outpoint
    pub fn get_reservation(&self, outpoint: &OutPoint) -> Option<InputReservation> {
        self.reservations.read().get(outpoint).cloned()
    }

    /// Reserve inputs for a batch (called when transaction is built)
    ///
    /// Returns error if any input is already reserved for another batch.
    pub fn reserve_batch(
        &self,
        batch_id: &str,
        outpoints: &[OutPoint],
        current_time: u64,
    ) -> Result<(), ReconciliationError> {
        let mut reservations = self.reservations.write();

        // First, check for conflicts
        for outpoint in outpoints {
            if let Some(existing) = reservations.get(outpoint) {
                return Err(ReconciliationError::CrossBatchDoubleSpend {
                    outpoint: format!("{}:{}", outpoint.txid, outpoint.vout),
                    existing_batch: existing.batch_id.clone(),
                    new_batch: batch_id.to_string(),
                });
            }
        }

        // All clear, reserve all inputs
        for outpoint in outpoints {
            reservations.insert(
                *outpoint,
                InputReservation {
                    batch_id: batch_id.to_string(),
                    reserved_at: current_time,
                    submitted_height: None,
                },
            );
        }

        tracing::debug!(
            batch_id = batch_id,
            input_count = outpoints.len(),
            "H-FUND-3: Reserved {} inputs for batch",
            outpoints.len()
        );

        Ok(())
    }

    /// Update reservation to mark batch as submitted
    pub fn mark_submitted(&self, batch_id: &str, block_height: u32) {
        let mut reservations = self.reservations.write();
        for reservation in reservations.values_mut() {
            if reservation.batch_id == batch_id {
                reservation.submitted_height = Some(block_height);
            }
        }
    }

    /// Release all reservations for a batch (on finalization or failure)
    pub fn release_batch(&self, batch_id: &str) -> usize {
        let mut reservations = self.reservations.write();
        let before_count = reservations.len();
        reservations.retain(|_, r| r.batch_id != batch_id);
        let released = before_count - reservations.len();

        if released > 0 {
            tracing::debug!(
                batch_id = batch_id,
                released_count = released,
                "H-FUND-3: Released {} input reservations for batch",
                released
            );
        }

        released
    }

    /// Clean up stale reservations (older than max_age_secs)
    ///
    /// This is a safety mechanism - normally reservations should be released
    /// when batches complete. Stale reservations indicate a bug or crash.
    pub fn cleanup_stale(&self, max_age_secs: u64, current_time: u64) -> usize {
        let mut reservations = self.reservations.write();
        let before_count = reservations.len();
        reservations.retain(|outpoint, r| {
            let age = current_time.saturating_sub(r.reserved_at);
            if age > max_age_secs {
                tracing::warn!(
                    outpoint = %format!("{}:{}", outpoint.txid, outpoint.vout),
                    batch_id = r.batch_id,
                    age_secs = age,
                    "H-FUND-3: Cleaning up stale reservation (possible leak)"
                );
                false
            } else {
                true
            }
        });
        before_count - reservations.len()
    }

    /// Get total count of active reservations
    pub fn count(&self) -> usize {
        self.reservations.read().len()
    }
}

/// Batch executor state
#[derive(Debug)]
pub struct BatchExecutor {
    /// Pending settlements waiting for batching
    pending_settlements: Vec<Settlement>,
    /// Current batch being formed
    current_batch: Option<Batch>,
    /// Settlements in current batch (needed for transaction building)
    current_batch_settlements: Vec<Settlement>,
    /// Available input UTXOs
    available_inputs: HashMap<String, Vec<ReconciliationInput>>, // ghost_id -> inputs
    /// Batch rules
    rules: BatchRules,
    /// Network
    network: Network,
    /// Treasury address for fees
    treasury_address: String,
    /// Current block height
    current_height: u32,
    /// Oldest pending settlement timestamp
    oldest_pending_timestamp: Option<u64>,
    /// Total pending sats
    pending_total_sats: u64,
    /// Next batch ID
    next_batch_id: u32,
    /// H-FUND-3: Global input reservations for cross-batch double-spend prevention
    global_reservations: GlobalInputReservations,
}

impl BatchExecutor {
    /// Create a new batch executor
    pub fn new(network: Network, treasury_address: String) -> Self {
        Self {
            pending_settlements: Vec::new(),
            current_batch: None,
            current_batch_settlements: Vec::new(),
            available_inputs: HashMap::new(),
            rules: BatchRules::default(),
            network,
            treasury_address,
            current_height: 0,
            oldest_pending_timestamp: None,
            pending_total_sats: 0,
            next_batch_id: 1,
            global_reservations: GlobalInputReservations::new(),
        }
    }

    /// H-FUND-3: Get reference to global reservations for external monitoring
    pub fn global_reservations(&self) -> &GlobalInputReservations {
        &self.global_reservations
    }

    /// Set batch rules
    pub fn with_rules(mut self, rules: BatchRules) -> Self {
        self.rules = rules;
        self
    }

    /// Update current block height
    pub fn set_block_height(&mut self, height: u32) {
        self.current_height = height;
    }

    /// Add available input UTXO
    pub fn add_input(&mut self, input: ReconciliationInput) {
        self.available_inputs
            .entry(input.ghost_id.clone())
            .or_default()
            .push(input);
    }

    /// Add a settlement request with ownership verification (C-1)
    ///
    /// This is the RECOMMENDED method for adding settlements. It verifies
    /// that the requester owns the lock they are trying to spend before
    /// accepting the settlement.
    ///
    /// # Security
    ///
    /// This method enforces C-1: Settlement Ownership Verification.
    /// Without valid ownership proof, the settlement is rejected.
    pub fn add_settlement_request(
        &mut self,
        request: SettlementRequest,
    ) -> Result<(), ReconciliationError> {
        // C-1: Verify ownership proof BEFORE any other processing
        request.verify_ownership().map_err(|e| {
            tracing::error!(
                settlement_id = %hex::encode(request.settlement().id()),
                source_ghost_id = %request.settlement().source_ghost_id(),
                destination = %request.settlement().destination_address(),
                amount = request.settlement().amount_sats(),
                "C-1 SECURITY: Settlement ownership verification failed: {}",
                e
            );
            ReconciliationError::OwnershipVerificationFailed(e.to_string())
        })?;

        tracing::debug!(
            settlement_id = %hex::encode(request.settlement().id()),
            "C-1: Settlement ownership verified successfully"
        );

        // Now add the verified settlement
        self.add_settlement_internal(request.into_settlement())
    }

    /// M-12: Add a pre-verified settlement (INTERNAL USE ONLY)
    ///
    /// # Security Warning
    ///
    /// This method does NOT verify ownership. It MUST only be used when:
    /// 1. The caller has already verified ownership through another mechanism
    /// 2. The settlement originates from a trusted internal source
    ///
    /// For external/untrusted settlement requests, ALWAYS use
    /// `add_settlement_request()` which includes C-1 ownership verification.
    ///
    /// # Deprecation
    ///
    /// This method is deprecated for external callers. Internal callers that
    /// have pre-verified ownership (e.g., Ghost Pay withdrawal processing)
    /// may continue to use it with `#[allow(deprecated)]` and a comment
    /// explaining why ownership verification was performed elsewhere.
    #[deprecated(
        since = "1.6.0",
        note = "M-12: Use add_settlement_request() for C-1 ownership verification. \
                Only use this method if ownership was verified through another mechanism \
                and document why in a code comment."
    )]
    pub fn add_settlement(&mut self, settlement: Settlement) -> Result<(), ReconciliationError> {
        // M-12: Log at debug level since legitimate internal use exists
        // The deprecation warning at compile time is sufficient for catching misuse
        tracing::debug!(
            settlement_id = %hex::encode(settlement.id()),
            "add_settlement() called - caller must ensure ownership was verified elsewhere"
        );
        self.add_settlement_internal(settlement)
    }

    /// M-14: Maximum number of pending settlements before rate limiting
    /// This prevents memory exhaustion from excessive settlement requests.
    pub const MAX_PENDING_SETTLEMENTS: usize = 10_000;

    /// Internal method to add a settlement after verification
    fn add_settlement_internal(
        &mut self,
        settlement: Settlement,
    ) -> Result<(), ReconciliationError> {
        // M-14: Rate limit - check pending settlement count before adding
        if self.pending_settlements.len() >= Self::MAX_PENDING_SETTLEMENTS {
            tracing::warn!(
                current = self.pending_settlements.len(),
                max = Self::MAX_PENDING_SETTLEMENTS,
                "M-14: Rate limit reached - too many pending settlements"
            );
            return Err(ReconciliationError::TooManyPendingSettlements {
                count: self.pending_settlements.len(),
                max: Self::MAX_PENDING_SETTLEMENTS,
            });
        }

        // Validate settlement
        crate::rules::validate_settlement(
            settlement.source_ghost_id(),
            settlement.destination_address(),
            settlement.amount_sats(),
        )?;

        // Track oldest timestamp for timeout
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.oldest_pending_timestamp.is_none() {
            self.oldest_pending_timestamp = Some(now);
        }

        self.pending_total_sats += settlement.amount_sats();
        self.pending_settlements.push(settlement);
        Ok(())
    }

    /// Get pending settlement count
    pub fn pending_count(&self) -> usize {
        self.pending_settlements.len()
    }

    /// Check if we should form a batch now
    pub fn should_form_batch(&self) -> bool {
        let oldest_age = self
            .oldest_pending_timestamp
            .map(|ts| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now.saturating_sub(ts)
            })
            .unwrap_or(0);

        self.rules.should_form_batch(
            self.pending_settlements.len(),
            self.pending_total_sats,
            oldest_age,
        )
    }

    /// Form a new batch from pending settlements
    ///
    /// # Security (H-6: Atomic Settlement State Transitions)
    ///
    /// This method clones settlements for batch formation instead of draining them.
    /// Settlements are only removed from the pending queue after successful batch
    /// sealing. If sealing fails, no settlements are lost.
    pub fn form_batch(&mut self) -> Result<Batch, ReconciliationError> {
        // M-20: Clean up stale reservations before forming a new batch
        // Prevents leaked reservations from crashed/stuck batches from blocking new ones
        let stale_cleaned = self.cleanup_stale_reservations(3600); // 1 hour max age
        if stale_cleaned > 0 {
            tracing::warn!(
                cleaned = stale_cleaned,
                "M-20: Cleaned up stale input reservations before batch formation"
            );
        }

        if self.pending_settlements.len() < MIN_BATCH_SIZE {
            return Err(ReconciliationError::InsufficientSettlements {
                have: self.pending_settlements.len(),
                need: MIN_BATCH_SIZE,
            });
        }

        // H-6: CLONE settlements instead of draining them
        // This ensures we don't lose settlements if batch sealing fails
        let batch_size = self.pending_settlements.len().min(MAX_BATCH_SIZE);
        let candidate_settlements: Vec<Settlement> = self
            .pending_settlements
            .iter()
            .take(batch_size)
            .cloned()
            .collect();

        // Create batch from cloned settlements
        let mut batch = Batch::new()?;
        for settlement in &candidate_settlements {
            batch.add_settlement(settlement)?;
        }

        // H-6: Try to seal the batch BEFORE removing from pending
        // If this fails, pending_settlements remain unchanged
        batch.seal()?;

        // H-6: Only now that sealing succeeded, remove from pending
        // Use drain to efficiently remove the first batch_size elements
        let mut settlements: Vec<Settlement> =
            self.pending_settlements.drain(..batch_size).collect();

        // C-11: Update each settlement's batch_id now that they are assigned to a batch
        let batch_id = *batch.id();
        for (i, settlement) in settlements.iter_mut().enumerate() {
            let merkle_proof = crate::batch::compute_merkle_proof(batch.settlement_hashes(), i);
            if let Err(e) = settlement.mark_batched(batch_id, merkle_proof) {
                tracing::warn!(
                    settlement_id = %hex::encode(settlement.id()),
                    error = %e,
                    "C-11: Failed to update settlement batch_id (already batched?)"
                );
            }
        }

        // Update pending tracking
        self.pending_total_sats = self
            .pending_settlements
            .iter()
            .map(|s| s.amount_sats())
            .sum();
        if self.pending_settlements.is_empty() {
            self.oldest_pending_timestamp = None;
        }

        // Store settlements for transaction building
        self.current_batch_settlements = settlements;
        self.current_batch = Some(batch.clone());
        Ok(batch)
    }

    /// Build the L1 reconciliation transaction for a batch
    ///
    /// # Security (C-2 and H-FUND-3)
    ///
    /// This function tracks inputs consumed within the batch (C-2) AND checks
    /// against global reservations from pending batches (H-FUND-3) to prevent
    /// double-spending the same UTXO.
    pub fn build_transaction(
        &mut self,
        batch: &Batch,
        fee_rate: u64,
    ) -> Result<BatchTransaction, ReconciliationError> {
        self.build_transaction_with_l2_fees(batch, fee_rate, 0, &[])
    }

    /// Build batch transaction with L2 fee distribution.
    ///
    /// - `l2_fee_pool`: Accumulated L2 transfer fees (from `get_undistributed_fees()`)
    /// - `l2_fee_split`: Pre-computed per-node payouts: `(node_id, address, amount)`
    ///   plus treasury amount (baked into the regular treasury output).
    pub fn build_transaction_with_l2_fees(
        &mut self,
        batch: &Batch,
        fee_rate: u64,
        l2_treasury_fees: u64,
        l2_node_payouts: &[(String, String, u64)],
    ) -> Result<BatchTransaction, ReconciliationError> {
        if batch.state() != BatchState::Ready {
            return Err(ReconciliationError::InvalidState(format!(
                "Batch must be Ready, got {:?}",
                batch.state()
            )));
        }

        let batch_id = batch.id_hex();
        let mut input_outpoints = Vec::new();
        let mut total_input_sats: u64 = 0;
        let mut total_output_sats: u64 = 0;
        let mut input_lock_ids: Vec<[u8; 32]> = Vec::new();
        let mut input_amounts: Vec<u64> = Vec::new();

        // C-2: Track inputs consumed within THIS batch to prevent double-spend
        // This HashSet tracks outpoints (txid:vout) that have already been
        // selected for spending in this batch.
        let mut consumed_in_batch: HashSet<OutPoint> = HashSet::new();

        // Collect inputs for each settlement
        for settlement in &self.current_batch_settlements {
            // Find available inputs for this ghost_id
            let inputs = match self.available_inputs.get_mut(settlement.source_ghost_id()) {
                Some(inputs) if !inputs.is_empty() => inputs,
                _ => {
                    return Err(ReconciliationError::InsufficientFunds {
                        ghost_id: settlement.source_ghost_id().to_string(),
                        required: settlement.amount_sats(),
                        available: 0,
                    });
                }
            };

            // Find input(s) that cover the settlement amount
            let mut collected = 0u64;
            let mut used_indices = Vec::new();

            for (i, input) in inputs.iter().enumerate() {
                if collected >= settlement.amount_sats() {
                    break;
                }

                let outpoint = OutPoint {
                    txid: input.txid,
                    vout: input.vout,
                };

                // H-15: Check minimum confirmations before using as input
                if input.confirmations < MIN_INPUT_CONFIRMATIONS {
                    tracing::debug!(
                        txid = %input.txid,
                        vout = input.vout,
                        confirmations = input.confirmations,
                        required = MIN_INPUT_CONFIRMATIONS,
                        "H-15: Skipping input with insufficient confirmations"
                    );
                    continue;
                }

                // C-2: Check if this input was already consumed in this batch
                if consumed_in_batch.contains(&outpoint) {
                    tracing::error!(
                        txid = %input.txid,
                        vout = input.vout,
                        settlement_id = %hex::encode(settlement.id()),
                        "C-2 SECURITY: Attempted double-spend of input in same batch"
                    );
                    return Err(ReconciliationError::DoubleSpendInBatch {
                        outpoint: format!("{}:{}", input.txid, input.vout),
                    });
                }

                // H-FUND-3: Check if this input is reserved by another pending batch
                if let Some(reservation) = self.global_reservations.get_reservation(&outpoint) {
                    if reservation.batch_id != batch_id {
                        tracing::error!(
                            txid = %input.txid,
                            vout = input.vout,
                            settlement_id = %hex::encode(settlement.id()),
                            existing_batch = %reservation.batch_id,
                            new_batch = %batch_id,
                            "H-FUND-3 SECURITY: Cross-batch double-spend attempt"
                        );
                        return Err(ReconciliationError::CrossBatchDoubleSpend {
                            outpoint: format!("{}:{}", input.txid, input.vout),
                            existing_batch: reservation.batch_id,
                            new_batch: batch_id.clone(),
                        });
                    }
                }

                // C-2: Mark input as consumed BEFORE adding to the batch
                consumed_in_batch.insert(outpoint);

                collected += input.amount;
                used_indices.push(i);

                input_outpoints.push(outpoint);

                // Use lock_id if available, otherwise generate from txid:vout
                let lock_id = input.lock_id.unwrap_or_else(|| {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(<bitcoin::Txid as AsRef<[u8]>>::as_ref(&input.txid));
                    hasher.update(input.vout.to_le_bytes());
                    hasher.finalize().into()
                });
                input_lock_ids.push(lock_id);
                input_amounts.push(input.amount);
                total_input_sats += input.amount;
            }

            if collected < settlement.amount_sats() {
                return Err(ReconciliationError::InsufficientFunds {
                    ghost_id: settlement.source_ghost_id().to_string(),
                    required: settlement.amount_sats(),
                    available: collected,
                });
            }

            // Remove used inputs (in reverse order to maintain indices)
            for i in used_indices.into_iter().rev() {
                inputs.remove(i);
            }

            total_output_sats += settlement.net_amount_sats();
        }

        tracing::debug!(
            input_count = consumed_in_batch.len(),
            "C-2: Batch transaction built with {} unique inputs",
            consumed_in_batch.len()
        );

        // Calculate fees
        let total_settlement_fees = self
            .current_batch_settlements
            .iter()
            .map(|s| s.fee_sats())
            .sum::<u64>();

        // Settlement fees go 100% as mining fee (they cover the L1 tx cost)
        // L2 protocol fees are distributed separately via l2_treasury_fees / l2_node_payouts
        let treasury_amount = l2_treasury_fees;

        // Estimate mining fee
        let l2_node_output_count = l2_node_payouts.len();
        let estimated_vsize = estimate_transaction_vsize(
            input_outpoints.len(),
            self.current_batch_settlements.len() + 2 + l2_node_output_count, // settlements + treasury + op_return + node fees
        );
        let mining_fee = estimated_vsize * fee_rate;

        // L2 node rewards
        let l2_node_total: u64 = l2_node_payouts.iter().map(|(_, _, amt)| *amt).sum();

        // H-7: Verify total outputs do not exceed total inputs (prevents overflow/theft)
        let total_committed_outputs = total_output_sats
            .checked_add(treasury_amount)
            .and_then(|v| v.checked_add(mining_fee))
            .and_then(|v| v.checked_add(l2_node_total));
        match total_committed_outputs {
            Some(total_out) if total_out > total_input_sats => {
                return Err(ReconciliationError::InvalidSettlement(format!(
                    "H-7: Total outputs ({} sats) exceed total inputs ({} sats)",
                    total_out, total_input_sats
                )));
            }
            None => {
                return Err(ReconciliationError::InvalidSettlement(
                    "H-7: Output sum overflow detected".to_string(),
                ));
            }
            _ => {} // total_out <= total_input_sats, OK
        }

        // Build ReconciliationTx
        let batch_id = self.next_batch_id;
        self.next_batch_id += 1;

        let state_root = batch.merkle_root().copied().ok_or_else(|| {
            ReconciliationError::InvalidState(
                "Batch in Ready state but missing merkle root".to_string(),
            )
        })?;

        let mut recon_tx = ReconciliationTx::new(batch_id, state_root, mining_fee);

        // Add inputs (H-8: handle overflow)
        for (lock_id, amount) in input_lock_ids.iter().zip(input_amounts.iter()) {
            recon_tx.add_input(*lock_id, *amount)?;
        }

        // Add settlement outputs (H-8: handle overflow)
        // All settlement types use Payment output type — the destination address
        // determines whether it's an external address (Exit) or a new Ghost Lock
        // address (Jump/WraithJump). This is intentional: jump outputs are
        // indistinguishable from exit outputs at the L1 transaction level.
        for settlement in &self.current_batch_settlements {
            let output_type = match settlement.kind() {
                crate::settlement::SettlementKind::Exit => TxOutput::Exit {
                    address: settlement.destination_address().to_string(),
                    amount: settlement.net_amount_sats(),
                    from_lock: *settlement.source_lock_id(),
                },
                crate::settlement::SettlementKind::Jump
                | crate::settlement::SettlementKind::WraithJump => TxOutput::Payment {
                    address: settlement.destination_address().to_string(),
                    amount: settlement.net_amount_sats(),
                    from_lock: *settlement.source_lock_id(),
                },
            };
            recon_tx.add_output(output_type)?;
        }

        // Add treasury fee output (H-8: handle overflow)
        if treasury_amount > 0 {
            recon_tx.add_output(TxOutput::TreasuryFee {
                address: self.treasury_address.clone(),
                amount: treasury_amount,
            })?;
        }

        // Add L2 node fee outputs
        for (node_id, address, amount) in l2_node_payouts {
            if *amount > 0 {
                recon_tx.add_output(TxOutput::NodeFee {
                    address: address.clone(),
                    amount: *amount,
                    node_id: node_id.clone(),
                })?;
            }
        }

        // Add OP_RETURN
        recon_tx.add_op_return();

        // CSPRNG-based shuffling of outputs to prevent position-based correlation
        // Inputs are not shuffled (Bitcoin transaction inputs don't reveal order semantics)
        // but outputs are shuffled so an observer cannot tell which output corresponds
        // to which settlement by position alone.
        shuffle_outputs(&mut recon_tx, batch.id())?;

        // Build actual Bitcoin transaction
        let bitcoin_tx = recon_tx.to_bitcoin_transaction(&input_outpoints, self.network)?;

        // Create commitment
        let commitment = L1Commitment::new(
            *batch.id(),
            state_root,
            batch.settlement_count() as u32,
            batch.total_amount_sats(),
        );

        // H-FUND-3: Reserve all inputs in the global tracker to prevent cross-batch double-spend
        // This must happen AFTER successful transaction building to avoid reserving on failure
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let batch_id_hex = batch.id_hex();
        self.global_reservations
            .reserve_batch(&batch_id_hex, &input_outpoints, current_time)?;

        tracing::info!(
            batch_id = %batch_id_hex,
            input_count = input_outpoints.len(),
            total_reserved = self.global_reservations.count(),
            "H-FUND-3: Batch inputs reserved for cross-batch double-spend prevention"
        );

        Ok(BatchTransaction {
            batch_id: batch_id_hex,
            transaction: bitcoin_tx,
            commitment,
            total_input_sats,
            total_output_sats,
            settlement_fees: total_settlement_fees,
            treasury_amount,
            node_rewards: l2_node_total,
            mining_fee,
            input_outpoints,
        })
    }

    /// Mark batch as submitted to L1
    ///
    /// H-FUND-3: Also updates global reservations to track submission height
    pub fn mark_submitted(
        &mut self,
        batch_id: &str,
        txid: Txid,
    ) -> Result<(), ReconciliationError> {
        if let Some(ref mut batch) = self.current_batch {
            if batch.id_hex() == batch_id {
                batch.mark_submitted(txid.to_string())?;
                // H-FUND-3: Update reservation with submission height
                self.global_reservations
                    .mark_submitted(batch_id, self.current_height);
                return Ok(());
            }
        }
        Err(ReconciliationError::BatchNotFound {
            id: batch_id.to_string(),
        })
    }

    /// Mark batch as confirmed
    pub fn mark_confirmed(
        &mut self,
        batch_id: &str,
        block_height: u32,
    ) -> Result<(), ReconciliationError> {
        if let Some(ref mut batch) = self.current_batch {
            if batch.id_hex() == batch_id {
                batch.mark_confirmed(block_height)?;
                return Ok(());
            }
        }
        Err(ReconciliationError::BatchNotFound {
            id: batch_id.to_string(),
        })
    }

    /// Finalize batch after dispute window
    ///
    /// H-FUND-3: Releases all input reservations for this batch
    pub fn finalize_batch(&mut self, batch_id: &str) -> Result<(), ReconciliationError> {
        if let Some(ref mut batch) = self.current_batch {
            if batch.id_hex() == batch_id {
                // Check dispute window has passed
                if let Some(confirm_height) = batch.l1_height() {
                    let dispute_end = confirm_height + DISPUTE_WINDOW_BLOCKS;
                    if self.current_height < dispute_end {
                        return Err(ReconciliationError::DisputeWindowActive {
                            ends_at: dispute_end as u64,
                            current: self.current_height as u64,
                        });
                    }
                }

                batch.mark_finalized()?;

                // H-FUND-3: Release all input reservations for this batch
                let released = self.global_reservations.release_batch(batch_id);
                tracing::info!(
                    batch_id = batch_id,
                    released_count = released,
                    remaining = self.global_reservations.count(),
                    "H-FUND-3: Batch finalized, input reservations released"
                );

                // Clear current batch
                self.current_batch = None;
                self.current_batch_settlements.clear();
                return Ok(());
            }
        }
        Err(ReconciliationError::BatchNotFound {
            id: batch_id.to_string(),
        })
    }

    /// Cancel a batch (e.g., on failure or rejection)
    ///
    /// H-FUND-3: Releases all input reservations for this batch
    pub fn cancel_batch(&mut self, batch_id: &str) -> Result<(), ReconciliationError> {
        if let Some(ref batch) = self.current_batch {
            if batch.id_hex() == batch_id {
                // H-FUND-3: Release all input reservations for this batch
                let released = self.global_reservations.release_batch(batch_id);
                tracing::warn!(
                    batch_id = batch_id,
                    released_count = released,
                    remaining = self.global_reservations.count(),
                    "H-FUND-3: Batch cancelled, input reservations released"
                );

                // Clear current batch
                self.current_batch = None;
                self.current_batch_settlements.clear();
                return Ok(());
            }
        }
        Err(ReconciliationError::BatchNotFound {
            id: batch_id.to_string(),
        })
    }

    /// Cleanup stale reservations
    ///
    /// H-FUND-3: Should be called periodically to clean up reservations from
    /// crashed or stuck batches. Default max age is 1 hour (3600 seconds).
    pub fn cleanup_stale_reservations(&self, max_age_secs: u64) -> usize {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.global_reservations
            .cleanup_stale(max_age_secs, current_time)
    }

    /// Get current batch
    pub fn current_batch(&self) -> Option<&Batch> {
        self.current_batch.as_ref()
    }
}

/// Result of building a batch transaction
#[derive(Debug)]
pub struct BatchTransaction {
    /// Batch ID
    pub batch_id: String,
    /// The Bitcoin transaction
    pub transaction: bitcoin::Transaction,
    /// L1 commitment data
    pub commitment: L1Commitment,
    /// Total input satoshis
    pub total_input_sats: u64,
    /// Total output satoshis
    pub total_output_sats: u64,
    /// Total settlement fees collected
    pub settlement_fees: u64,
    /// Amount going to treasury
    pub treasury_amount: u64,
    /// Amount going to nodes
    pub node_rewards: u64,
    /// Mining fee
    pub mining_fee: u64,
    /// Input outpoints (for signing)
    pub input_outpoints: Vec<OutPoint>,
}

impl BatchTransaction {
    /// Get transaction ID (will change after signing)
    pub fn txid(&self) -> Txid {
        self.transaction.compute_txid()
    }

    /// Get settlement count from commitment
    pub fn settlement_count(&self) -> u64 {
        self.commitment.settlement_count as u64
    }
}

/// Estimate transaction vsize
fn estimate_transaction_vsize(input_count: usize, output_count: usize) -> u64 {
    // P2TR input: ~58 vbytes
    // P2TR output: ~43 vbytes
    // OP_RETURN: ~12 vbytes
    // Overhead: ~10 vbytes
    let input_vsize = input_count as u64 * 58;
    let output_vsize = output_count as u64 * 43;
    let overhead = 10;
    input_vsize + output_vsize + overhead
}

/// CSPRNG-based Fisher-Yates shuffle of transaction outputs.
///
/// Seeded from `SHA256(batch_id || entropy)` where entropy is from the OS CSPRNG.
/// This prevents output position from leaking which settlement produced which output.
/// OP_RETURN outputs are kept at the end (standard Bitcoin convention).
fn shuffle_outputs(
    recon_tx: &mut ReconciliationTx,
    batch_id: &[u8; 32],
) -> Result<(), ReconciliationError> {
    use sha2::{Digest, Sha256};

    let outputs = recon_tx.outputs_mut();
    let len = outputs.len();
    if len <= 1 {
        return Ok(());
    }

    // Separate OP_RETURN outputs (keep at end, Bitcoin convention)
    // Partition: [non-OP_RETURN outputs..., OP_RETURN outputs...]
    let op_return_start = outputs
        .iter()
        .position(|o| matches!(o, TxOutput::OpReturn { .. }))
        .unwrap_or(len);

    if op_return_start <= 1 {
        return Ok(()); // 0 or 1 shuffleable outputs
    }

    // Generate seed: SHA256(batch_id || OS entropy)
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).map_err(|_| ReconciliationError::RngFailure)?;

    let mut hasher = Sha256::new();
    hasher.update(b"ghost/batch-shuffle/v1");
    hasher.update(batch_id);
    hasher.update(entropy);
    let seed: [u8; 32] = hasher.finalize().into();

    // Fisher-Yates shuffle using the seed as a stream of random bytes
    // We re-hash when we exhaust the current block of randomness
    let mut random_state = seed;
    let mut byte_idx = 0;

    for i in (1..op_return_start).rev() {
        // Get random index in [0, i]
        let bound = (i + 1) as u32;
        let j = bounded_rand_from_state(&mut random_state, &mut byte_idx, bound) as usize;
        outputs.swap(i, j);
    }

    Ok(())
}

/// Extract a bounded random u32 from a hash state, re-hashing when exhausted
fn bounded_rand_from_state(state: &mut [u8; 32], byte_idx: &mut usize, bound: u32) -> u32 {
    use sha2::{Digest, Sha256};

    if bound <= 1 {
        return 0;
    }

    let max_valid = u32::MAX - (u32::MAX % bound);

    loop {
        if *byte_idx + 4 > 32 {
            // Re-hash to get more randomness
            let mut hasher = Sha256::new();
            hasher.update(b"ghost/batch-shuffle/chain");
            hasher.update(*state);
            *state = hasher.finalize().into();
            *byte_idx = 0;
        }

        let value = u32::from_le_bytes([
            state[*byte_idx],
            state[*byte_idx + 1],
            state[*byte_idx + 2],
            state[*byte_idx + 3],
        ]);
        *byte_idx += 4;

        if value < max_valid {
            return value % bound;
        }
        // Rejection sampling: re-hash and try again
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::OwnershipProof;
    use std::str::FromStr;

    fn test_txid() -> Txid {
        Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap()
    }

    #[test]
    fn test_executor_creation() {
        let executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());
        assert_eq!(executor.pending_count(), 0);
    }

    fn test_lock_id(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    #[allow(deprecated)] // Testing deprecated method explicitly
    fn test_add_settlement() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(1),
            "bcrt1qoutput".to_string(),
            100_000,
        )
        .unwrap();

        executor.add_settlement(settlement).unwrap();
        assert_eq!(executor.pending_count(), 1);
    }

    #[test]
    fn test_add_input() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        let input = ReconciliationInput {
            txid: test_txid(),
            vout: 0,
            amount: 1_000_000,
            ghost_id: "ghost1abc".to_string(),
            lock_id: None,
            confirmations: 100,
        };

        executor.add_input(input);
        assert!(executor.available_inputs.contains_key("ghost1abc"));
    }

    #[test]
    #[allow(deprecated)] // Testing deprecated method explicitly
    fn test_should_form_batch_min_size() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // No settlements → should NOT form batch
        assert!(!executor.should_form_batch());

        // GHOST-12: a single low-value settlement is BELOW MIN_BATCH_SIZE (10)
        // and must NOT form a batch on its own (anonymity floor).
        let settlement = Settlement::new(
            "ghost10".to_string(),
            test_lock_id(0),
            "bcrt1qoutput0".to_string(),
            100_000,
        )
        .unwrap();
        executor.add_settlement(settlement).unwrap();
        assert!(!executor.should_form_batch());

        // Multiple settlements also form batch
        for i in 1..10 {
            let settlement = Settlement::new(
                format!("ghost1{}", i),
                test_lock_id(i as u8),
                format!("bcrt1qoutput{}", i),
                100_000,
            )
            .unwrap();
            executor.add_settlement(settlement).unwrap();
        }
        assert!(executor.should_form_batch());
    }

    // ========================================================================
    // C-1: Settlement Ownership Verification Tests
    // ========================================================================

    #[test]
    fn test_c1_settlement_rejected_without_ownership_proof() {
        use crate::settlement::{OwnershipProof, SettlementRequest};

        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // Create a settlement
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(1),
            "bcrt1qoutput".to_string(),
            100_000,
        )
        .unwrap();

        // Create a fake/invalid ownership proof (wrong signature)
        // C-7: Must include epoch and batch_id now
        let fake_sig = [0u8; 64];
        let fake_pubkey = test_lock_id(1); // This won't match the actual lock pubkey
        let epoch = 0u64;
        let batch_id = [0u8; 32]; // Pending settlement
        let ownership_proof = OwnershipProof::new(fake_sig, fake_pubkey, epoch, batch_id);

        let request = SettlementRequest::new(settlement, ownership_proof);

        // Verification should fail
        let result = executor.add_settlement_request(request);
        assert!(result.is_err());

        // Error should indicate ownership verification failure
        let err = result.unwrap_err();
        assert!(
            matches!(err, ReconciliationError::OwnershipVerificationFailed(_)),
            "Expected OwnershipVerificationFailed, got {:?}",
            err
        );
    }

    #[test]
    fn test_c1_settlement_rejected_with_wrong_pubkey() {
        use crate::settlement::{OwnershipProof, SettlementRequest};

        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // Create a settlement with lock_id = [1u8; 32]
        let settlement = Settlement::new(
            "ghost1abc".to_string(),
            test_lock_id(1),
            "bcrt1qoutput".to_string(),
            100_000,
        )
        .unwrap();

        // Create proof with DIFFERENT pubkey than the lock
        // C-7: Must include epoch and batch_id now
        let fake_sig = [0u8; 64];
        let wrong_pubkey = test_lock_id(2); // Different from settlement's lock_id
        let epoch = 0u64;
        let batch_id = [0u8; 32]; // Pending settlement
        let ownership_proof = OwnershipProof::new(fake_sig, wrong_pubkey, epoch, batch_id);

        let request = SettlementRequest::new(settlement, ownership_proof);

        // Verification should fail because pubkey doesn't match lock
        let result = executor.add_settlement_request(request);
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not match lock pubkey"),
            "Expected pubkey mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_c1_ownership_proof_message_format() {
        // Verify the message format is deterministic
        // C-7: Now includes epoch and batch_id
        let epoch = 1u64;
        let batch_id = [0u8; 32];
        let settlement_id = [1u8; 32];
        let destination = "bcrt1qtest";
        let amount = 100_000u64;

        let msg1 =
            OwnershipProof::build_message(epoch, &batch_id, &settlement_id, destination, amount);
        let msg2 =
            OwnershipProof::build_message(epoch, &batch_id, &settlement_id, destination, amount);

        assert_eq!(msg1, msg2, "Message hash should be deterministic");

        // Different inputs should produce different messages
        let msg3 = OwnershipProof::build_message(
            epoch,
            &batch_id,
            &settlement_id,
            destination,
            amount + 1,
        );
        assert_ne!(msg1, msg3, "Different amount should produce different hash");

        let msg4 =
            OwnershipProof::build_message(epoch, &batch_id, &settlement_id, "bcrt1qother", amount);
        assert_ne!(
            msg1, msg4,
            "Different destination should produce different hash"
        );

        // C-7: Different epochs should produce different messages
        let msg5 = OwnershipProof::build_message(
            epoch + 1,
            &batch_id,
            &settlement_id,
            destination,
            amount,
        );
        assert_ne!(msg1, msg5, "Different epoch should produce different hash");

        // C-7: Different batch_ids should produce different messages
        let other_batch = [1u8; 32];
        let msg6 =
            OwnershipProof::build_message(epoch, &other_batch, &settlement_id, destination, amount);
        assert_ne!(
            msg1, msg6,
            "Different batch_id should produce different hash"
        );
    }

    // ========================================================================
    // C-2: Double-Spend Prevention Tests
    // ========================================================================

    #[test]
    fn test_c2_double_spend_in_batch_rejected() {
        let mut executor = BatchExecutor::new(Network::Regtest, "bcrt1qtest".to_string());

        // Add 10 settlements to form a batch (minimum batch size)
        for i in 0..10 {
            let settlement = Settlement::new(
                "ghost1same".to_string(), // All from same ghost_id (must start with "ghost1")
                test_lock_id(i as u8),
                format!("bcrt1qoutput{}", i),
                10_000, // Small amounts
            )
            .unwrap();
            #[allow(deprecated)]
            executor.add_settlement(settlement).unwrap();
        }

        // Add only ONE input that's smaller than total required
        // This simulates the scenario where the same input would need
        // to be used for multiple settlements
        let single_input = ReconciliationInput {
            txid: test_txid(),
            vout: 0,
            amount: 50_000,                     // Only enough for ~5 settlements
            ghost_id: "ghost1same".to_string(), // Must match settlement
            lock_id: None,
            confirmations: 100,
        };
        executor.add_input(single_input);

        // Form the batch
        let batch = executor.form_batch().unwrap();

        // Building transaction should fail due to insufficient funds
        // (not double-spend in this case, but demonstrates input tracking)
        let result = executor.build_transaction(&batch, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_c2_unique_inputs_for_settlements() {
        // Use a valid regtest bech32 address
        let treasury_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string();
        let mut executor = BatchExecutor::new(Network::Regtest, treasury_addr);

        // Add 10 settlements from different ghost_ids
        // Using a valid regtest P2WPKH address format
        let output_addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

        for i in 0..10 {
            let settlement = Settlement::new(
                format!("ghost1user{}", i), // Must start with "ghost1"
                test_lock_id(i as u8),
                output_addr.to_string(), // Use valid address for all
                10_000,
            )
            .unwrap();
            #[allow(deprecated)]
            executor.add_settlement(settlement).unwrap();

            // Add corresponding input for each ghost_id
            let input = ReconciliationInput {
                txid: Txid::from_str(&format!(
                    "000000000000000000000000000000000000000000000000000000000000000{}",
                    i
                ))
                .unwrap_or(test_txid()),
                vout: 0,
                amount: 20_000,
                ghost_id: format!("ghost1user{}", i), // Must match settlement
                lock_id: Some(test_lock_id(i as u8)),
                confirmations: 100,
            };
            executor.add_input(input);
        }

        // Form the batch
        let batch = executor.form_batch().unwrap();

        // Building transaction should succeed with unique inputs
        let result = executor.build_transaction(&batch, 1);
        assert!(
            result.is_ok(),
            "Should succeed with unique inputs: {:?}",
            result.err()
        );

        let tx = result.unwrap();
        assert_eq!(tx.input_outpoints.len(), 10, "Should have 10 unique inputs");

        // Verify all outpoints are unique
        let unique_outpoints: HashSet<_> = tx.input_outpoints.iter().collect();
        assert_eq!(
            unique_outpoints.len(),
            tx.input_outpoints.len(),
            "All outpoints should be unique"
        );
    }

    // ========================================================================
    // H-FUND-3: Cross-Batch Double-Spend Prevention Tests
    // ========================================================================

    #[test]
    fn test_h_fund3_global_reservation_basic() {
        let reservations = GlobalInputReservations::new();
        let current_time = 1700000000u64;

        let outpoint = OutPoint {
            txid: test_txid(),
            vout: 0,
        };

        assert!(!reservations.is_reserved(&outpoint));
        assert_eq!(reservations.count(), 0);

        // Reserve one input
        reservations
            .reserve_batch("batch1", &[outpoint], current_time)
            .unwrap();

        assert!(reservations.is_reserved(&outpoint));
        assert_eq!(reservations.count(), 1);

        // Release it
        let released = reservations.release_batch("batch1");
        assert_eq!(released, 1);
        assert!(!reservations.is_reserved(&outpoint));
        assert_eq!(reservations.count(), 0);
    }

    #[test]
    fn test_h_fund3_cross_batch_double_spend_rejected() {
        let reservations = GlobalInputReservations::new();
        let current_time = 1700000000u64;

        let outpoint = OutPoint {
            txid: test_txid(),
            vout: 0,
        };

        // Reserve for batch1
        reservations
            .reserve_batch("batch1", &[outpoint], current_time)
            .unwrap();

        // Attempt to reserve same input for batch2 should FAIL
        let result = reservations.reserve_batch("batch2", &[outpoint], current_time);
        assert!(result.is_err());

        match result {
            Err(ReconciliationError::CrossBatchDoubleSpend {
                existing_batch,
                new_batch,
                ..
            }) => {
                assert_eq!(existing_batch, "batch1");
                assert_eq!(new_batch, "batch2");
            }
            _ => panic!("Expected CrossBatchDoubleSpend error"),
        }
    }

    #[test]
    fn test_h_fund3_different_outpoints_allowed() {
        let reservations = GlobalInputReservations::new();
        let current_time = 1700000000u64;

        let outpoint1 = OutPoint {
            txid: test_txid(),
            vout: 0,
        };
        let outpoint2 = OutPoint {
            txid: test_txid(),
            vout: 1,
        };

        // Reserve different outpoints for different batches should succeed
        reservations
            .reserve_batch("batch1", &[outpoint1], current_time)
            .unwrap();
        reservations
            .reserve_batch("batch2", &[outpoint2], current_time)
            .unwrap();

        assert_eq!(reservations.count(), 2);
        assert!(reservations.is_reserved(&outpoint1));
        assert!(reservations.is_reserved(&outpoint2));
    }

    #[test]
    fn test_h_fund3_stale_cleanup() {
        let reservations = GlobalInputReservations::new();
        let start_time = 1700000000u64;
        let max_age = 3600u64; // 1 hour

        let outpoint = OutPoint {
            txid: test_txid(),
            vout: 0,
        };

        reservations
            .reserve_batch("batch1", &[outpoint], start_time)
            .unwrap();
        assert_eq!(reservations.count(), 1);

        // Cleanup with time still within window should not remove
        let cleaned = reservations.cleanup_stale(max_age, start_time + 1800); // 30 minutes later
        assert_eq!(cleaned, 0);
        assert_eq!(reservations.count(), 1);

        // Cleanup with time past window should remove
        let cleaned = reservations.cleanup_stale(max_age, start_time + 7200); // 2 hours later
        assert_eq!(cleaned, 1);
        assert_eq!(reservations.count(), 0);
    }

    #[test]
    fn test_h_fund3_release_wrong_batch() {
        let reservations = GlobalInputReservations::new();
        let current_time = 1700000000u64;

        let outpoint = OutPoint {
            txid: test_txid(),
            vout: 0,
        };

        reservations
            .reserve_batch("batch1", &[outpoint], current_time)
            .unwrap();

        // Releasing wrong batch should not affect reservation
        let released = reservations.release_batch("batch2");
        assert_eq!(released, 0);
        assert!(reservations.is_reserved(&outpoint));
        assert_eq!(reservations.count(), 1);

        // Releasing correct batch should work
        let released = reservations.release_batch("batch1");
        assert_eq!(released, 1);
        assert!(!reservations.is_reserved(&outpoint));
    }

    #[test]
    fn test_h_fund3_mark_submitted() {
        let reservations = GlobalInputReservations::new();
        let current_time = 1700000000u64;

        let outpoint = OutPoint {
            txid: test_txid(),
            vout: 0,
        };

        reservations
            .reserve_batch("batch1", &[outpoint], current_time)
            .unwrap();

        // Initially no submission height
        let info = reservations.get_reservation(&outpoint).unwrap();
        assert!(info.submitted_height.is_none());

        // Mark submitted
        reservations.mark_submitted("batch1", 100);

        let info = reservations.get_reservation(&outpoint).unwrap();
        assert_eq!(info.submitted_height, Some(100));
    }

    #[test]
    fn test_h_fund3_error_message_format() {
        // Verify the error message contains all needed information for debugging
        let err = ReconciliationError::CrossBatchDoubleSpend {
            outpoint: "abc123:0".to_string(),
            existing_batch: "batch1".to_string(),
            new_batch: "batch2".to_string(),
        };

        let msg = format!("{}", err);
        assert!(msg.contains("abc123:0"), "Must contain outpoint");
        assert!(msg.contains("batch1"), "Must contain existing batch");
        assert!(msg.contains("batch2"), "Must contain new batch");
        assert!(
            msg.to_lowercase().contains("double-spend"),
            "Must mention double-spend"
        );
    }
}
