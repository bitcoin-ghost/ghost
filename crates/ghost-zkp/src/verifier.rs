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
//| FILE: verifier.rs                                                                                                    |
//|======================================================================================================================|

//! Block proof verification
//!
//! The BlockVerifier validates ZK proofs in ~10ms, allowing validators
//! to quickly confirm block validity without re-executing transactions.
//!
//! # Security Model
//!
//! This verifier supports two modes:
//! 1. Full Groth16 mode: Cryptographically verifies proofs using bellperson
//! 2. Simulated mode (TEST ONLY): For development when no setup is available
//!
//! SECURITY WARNING: In production, ALWAYS use full Groth16 mode with
//! a verification key generated from a proper MPC ceremony.

use bellperson::groth16::{verify_proof as groth16_verify_proof, PreparedVerifyingKey, Proof};
use blstrs::{Bls12, G1Affine, G2Affine};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, instrument, warn};

use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::{BlockProof, VerificationKey, GROTH16_PROOF_SIZE};

/// Verifies block validity proofs
///
/// The verifier is initialized once with a verification key and reused
/// for all blocks. Verification takes ~10ms.
///
/// # Security
///
/// For production use, always initialize with `new_with_groth16_vk` to ensure
/// cryptographic verification. The `new` constructor is provided for backwards
/// compatibility but will FAIL CLOSED if no VK is available.
pub struct BlockVerifier {
    /// Prover ID from verification key
    prover_id: [u8; 32],
    /// Maximum transactions per block
    max_txs: usize,
    /// Merkle tree depth
    tree_depth: usize,
    /// Prepared Groth16 verifying key for cryptographic verification
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
}

impl BlockVerifier {
    /// Create a verifier from a verification key
    ///
    /// HIGH-5 SECURITY: This constructor REQUIRES a Groth16 verification key for production use.
    /// Without a Groth16 VK, this method returns an error. Use `new_development()` only for
    /// development/testing environments where cryptographic verification is not required.
    ///
    /// # Errors
    ///
    /// Returns `ZkError::MissingVerificationKey` if no Groth16 VK is provided. In production,
    /// you MUST use `new_with_groth16_vk` instead to provide the prepared verifying key.
    pub fn new(_vk: &VerificationKey) -> ZkResult<Self> {
        // HIGH-5: Fail with error instead of warning when Groth16 VK is not provided.
        // Production deployments MUST use new_with_groth16_vk() with a proper VK from MPC ceremony.
        error!(
            "HIGH-5 SECURITY: BlockVerifier::new() called without Groth16 VK. \
             This is not allowed in production. Use new_with_groth16_vk() with a proper \
             verification key from an MPC ceremony, or new_development() for testing only."
        );
        Err(ZkError::MissingVerificationKey(
            "Groth16 verification key is required. Use new_with_groth16_vk() for production \
             or new_development() for testing only."
                .to_string(),
        ))
    }

    /// Create a verifier for development/testing without Groth16 verification
    ///
    /// SECURITY WARNING: This constructor does NOT enable cryptographic Groth16 verification.
    /// It should ONLY be used in development/testing environments. In production, the verifier
    /// will FAIL CLOSED (reject all proofs) because no Groth16 VK is available.
    ///
    /// # Safety
    ///
    /// Proofs verified by a development verifier are NOT cryptographically secure.
    /// An attacker could forge proofs that pass the simulated verification.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Only use in tests or development:
    /// let verifier = BlockVerifier::new_development(&vk)?;
    /// ```
    pub fn new_development(vk: &VerificationKey) -> ZkResult<Self> {
        if vk.data.len() < 48 {
            return Err(ZkError::ParameterError(
                "Verification key too short".to_string(),
            ));
        }

        let mut prover_id = [0u8; 32];
        prover_id.copy_from_slice(&vk.data[0..32]);

        let max_txs = usize::from_le_bytes(vk.data[32..40].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid max_txs in verification key".to_string())
        })?);

        let tree_depth = usize::from_le_bytes(vk.data[40..48].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid tree_depth in verification key".to_string())
        })?);

        warn!(
            "HIGH-5: BlockVerifier created in DEVELOPMENT MODE without Groth16 VK. \
             Cryptographic verification is NOT available. This verifier will FAIL CLOSED \
             (reject all proofs) in production mode. Use new_with_groth16_vk() for production."
        );

        Ok(Self {
            prover_id,
            max_txs,
            tree_depth,
            prepared_vk: None,
        })
    }

    /// Create a verifier with a Groth16 prepared verifying key
    ///
    /// This is the recommended constructor for production use. It enables
    /// full cryptographic verification of proofs.
    pub fn new_with_groth16_vk(
        vk: &VerificationKey,
        prepared_vk: Arc<PreparedVerifyingKey<Bls12>>,
    ) -> ZkResult<Self> {
        if vk.data.len() < 48 {
            return Err(ZkError::ParameterError(
                "Verification key too short".to_string(),
            ));
        }

        let mut prover_id = [0u8; 32];
        prover_id.copy_from_slice(&vk.data[0..32]);

        let max_txs = usize::from_le_bytes(vk.data[32..40].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid max_txs in verification key".to_string())
        })?);

        let tree_depth = usize::from_le_bytes(vk.data[40..48].try_into().map_err(|_| {
            ZkError::ParameterError("Invalid tree_depth in verification key".to_string())
        })?);

        debug!(
            "BlockVerifier created with Groth16 VK for {} txs, depth {}",
            max_txs, tree_depth
        );

        Ok(Self {
            prover_id,
            max_txs,
            tree_depth,
            prepared_vk: Some(prepared_vk),
        })
    }

    /// Check if Groth16 verification is available
    pub fn has_groth16_vk(&self) -> bool {
        self.prepared_vk.is_some()
    }

    /// Verify a block proof
    ///
    /// This verifies that the proof is valid for the given state transition.
    /// Verification should take ~10ms.
    ///
    /// # Security
    ///
    /// If a Groth16 VK is available, performs cryptographic verification.
    /// Otherwise, FAILS CLOSED (rejects all proofs) in production mode.
    /// Test mode allows simulated verification for development.
    ///
    /// # Arguments
    /// * `proof` - The block proof to verify
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid
    #[instrument(skip_all, fields(height = proof.height, tx_count = proof.tx_count))]
    pub fn verify(&self, proof: &BlockProof) -> ZkResult<bool> {
        // M-7 FIX: Runtime check to block simulated proofs in production
        // Previously used compile-time #[cfg] which could be bypassed by enabling test-utils feature.
        // Now uses runtime environment variable check that CANNOT be bypassed at compile time.
        if proof.is_simulated() {
            // In test builds, allow simulated proofs for testing
            #[cfg(test)]
            {
                // Allow in tests
            }
            #[cfg(not(test))]
            {
                // L-18 FIX: Check if we're on mainnet - simulated proofs NEVER allowed on mainnet
                // GHOST_NETWORK env var is set by ghost-mining and other binaries
                let is_mainnet = std::env::var("GHOST_NETWORK")
                    .map(|v| v.to_lowercase() == "mainnet" || v.to_lowercase() == "bitcoin")
                    .unwrap_or(false);

                // L-9 FIX: Additional safety - if GHOST_ALLOW_SIMULATED_PROOFS is not explicitly set,
                // treat it as if we're in production mode. This means simulated proofs are blocked
                // by default unless explicitly enabled AND we're not on mainnet.
                let simulated_explicitly_allowed = std::env::var("GHOST_ALLOW_SIMULATED_PROOFS")
                    .map(|v| v == "1")
                    .unwrap_or(false);

                // L-9 FIX: Fail safe - if the env var is not set, assume production-like behavior
                // This prevents the case where someone forgets to set GHOST_NETWORK but we're on mainnet
                let simulated_blocked = !simulated_explicitly_allowed;

                if is_mainnet || simulated_blocked {
                    if is_mainnet {
                        // L-18 SECURITY: On mainnet, simulated proofs are ALWAYS rejected
                        // No environment variable can bypass this check
                        error!(
                            "L-18 SECURITY: Simulated proof REJECTED on mainnet. \
                             Simulated proofs are NEVER allowed on mainnet, regardless of GHOST_ALLOW_SIMULATED_PROOFS setting. \
                             A valid Groth16 proof with proper trusted setup is required."
                        );
                    } else {
                        // L-9: Not mainnet, but simulated proofs not explicitly allowed
                        error!(
                            "SECURITY: Simulated proof rejected. \
                             Set GHOST_ALLOW_SIMULATED_PROOFS=1 to allow (development only, NEVER in production)."
                        );
                    }
                    return Err(ZkError::SimulatedProofRejected);
                }

                // Log warning even when allowed - this should never happen in production
                warn!(
                    "SECURITY WARNING: Accepting simulated proof because GHOST_ALLOW_SIMULATED_PROOFS=1. \
                     This MUST NOT be used in production!"
                );
            }
        }

        // Verify transaction count is within limits
        if proof.tx_count as usize > self.max_txs {
            debug!(
                "Transaction count {} exceeds max {}",
                proof.tx_count, self.max_txs
            );
            return Ok(false);
        }

        // If we have a Groth16 VK, perform cryptographic verification
        if let Some(ref prepared_vk) = self.prepared_vk {
            return self.verify_groth16(proof, prepared_vk);
        }

        // No Groth16 VK available - check for simulated proof format
        // SECURITY: In production, we FAIL CLOSED
        if proof.proof.len() < 72 {
            debug!("Proof too short: {} bytes", proof.proof.len());
            return Ok(false);
        }

        // Verify prover ID matches
        let proof_prover_id = &proof.proof[0..32];
        if proof_prover_id != self.prover_id {
            debug!("Prover ID mismatch");
            return Ok(false);
        }

        // SECURITY: No Groth16 VK - FAIL CLOSED in production
        error!(
            "SECURITY: No Groth16 verification key available. \
             Cannot verify block proof cryptographically. Rejecting proof. \
             Ensure trusted setup has been completed and VK is loaded."
        );

        // In test mode, allow simulated verification
        #[cfg(test)]
        {
            self.verify_simulated(proof)
        }

        #[cfg(not(test))]
        Ok(false)
    }

    /// Verify a Groth16 proof cryptographically
    fn verify_groth16(
        &self,
        proof: &BlockProof,
        prepared_vk: &PreparedVerifyingKey<Bls12>,
    ) -> ZkResult<bool> {
        let verify_start = Instant::now();

        // Check proof is correct size for Groth16
        if proof.proof.len() != GROTH16_PROOF_SIZE {
            debug!(
                "Proof size mismatch: {} != {}",
                proof.proof.len(),
                GROTH16_PROOF_SIZE
            );
            return Ok(false);
        }

        // Deserialize the proof with subgroup checks
        let groth16_proof = self.deserialize_proof(&proof.proof)?;

        // Build public inputs from the proof
        // For block proofs, we expose: prev_state_root, new_state_root
        let prev_root = bytes_to_field(&proof.prev_state_root)?;
        let new_root = bytes_to_field(&proof.new_state_root)?;
        let public_inputs = vec![prev_root, new_root];

        debug!(
            "Verifying Groth16 block proof: height={}, txs={}",
            proof.height, proof.tx_count
        );

        // Verify the Groth16 proof
        let result = groth16_verify_proof(prepared_vk, &groth16_proof, &public_inputs);

        debug!(
            "Groth16 verification completed in {:?}",
            verify_start.elapsed()
        );

        match result {
            Ok(valid) => {
                if valid {
                    debug!("Block proof verified successfully");
                } else {
                    warn!("Block proof verification returned false");
                }
                Ok(valid)
            }
            Err(e) => {
                warn!("Block proof verification error: {:?}", e);
                Ok(false)
            }
        }
    }

    /// Deserialize a Groth16 proof with subgroup checks
    fn deserialize_proof(&self, bytes: &[u8]) -> ZkResult<Proof<Bls12>> {
        if bytes.len() != GROTH16_PROOF_SIZE {
            return Err(ZkError::InvalidProof(format!(
                "Invalid proof size: {} != {}",
                bytes.len(),
                GROTH16_PROOF_SIZE
            )));
        }

        // Parse A (G1 point, 48 bytes compressed)
        let a_bytes: [u8; 48] = bytes[0..48]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read A point".to_string()))?;
        let a: G1Affine = G1Affine::from_compressed(&a_bytes)
            .into_option()
            .ok_or_else(|| ZkError::InvalidProof("Invalid A point".to_string()))?;

        // SECURITY: Subgroup check
        if !bool::from(a.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "A point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse B (G2 point, 96 bytes compressed)
        let b_bytes: [u8; 96] = bytes[48..144]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read B point".to_string()))?;
        let b: G2Affine = G2Affine::from_compressed(&b_bytes)
            .into_option()
            .ok_or_else(|| ZkError::InvalidProof("Invalid B point".to_string()))?;

        // SECURITY: Subgroup check
        if !bool::from(b.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "B point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse C (G1 point, 48 bytes compressed)
        let c_bytes: [u8; 48] = bytes[144..192]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read C point".to_string()))?;
        let c: G1Affine = G1Affine::from_compressed(&c_bytes)
            .into_option()
            .ok_or_else(|| ZkError::InvalidProof("Invalid C point".to_string()))?;

        // SECURITY: Subgroup check
        if !bool::from(c.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "C point not in prime-order subgroup".to_string(),
            ));
        }

        Ok(Proof { a, b, c })
    }

    /// Simulated verification for test mode only
    #[cfg(test)]
    fn verify_simulated(&self, proof: &BlockProof) -> ZkResult<bool> {
        // Extract proof components
        let _proof_hash = &proof.proof[32..64];
        let constraint_count = u64::from_le_bytes(
            proof.proof[64..72]
                .try_into()
                .map_err(|_| ZkError::VerificationError("Invalid proof format".to_string()))?,
        );

        // Verify constraint count is reasonable
        let min_expected_constraints = proof.tx_count as u64 * 64;
        if constraint_count < min_expected_constraints && proof.tx_count > 0 {
            debug!(
                "Constraint count {} too low for {} transactions",
                constraint_count, proof.tx_count
            );
            return Ok(false);
        }

        debug!(
            "Simulated proof verified: height={}, txs={}, constraints={}",
            proof.height, proof.tx_count, constraint_count
        );

        Ok(true)
    }

    /// Verify a proof and return detailed result
    ///
    /// Unlike `verify`, this returns a structured result with timing info.
    pub fn verify_detailed(&self, proof: &BlockProof) -> ZkResult<VerificationResult> {
        let start = Instant::now();
        let is_valid = self.verify(proof)?;
        let verification_time = start.elapsed();

        Ok(VerificationResult {
            is_valid,
            verification_time_ms: verification_time.as_millis() as u64,
            height: proof.height,
            tx_count: proof.tx_count,
            proof_size: proof.size(),
        })
    }

    /// Batch verify multiple proofs
    ///
    /// This can be more efficient than verifying proofs one at a time,
    /// though the current implementation just loops.
    pub fn verify_batch(&self, proofs: &[BlockProof]) -> ZkResult<Vec<bool>> {
        proofs.iter().map(|p| self.verify(p)).collect()
    }

    /// Get the maximum transactions this verifier supports
    pub fn max_txs(&self) -> usize {
        self.max_txs
    }

    /// Get the merkle tree depth this verifier supports
    pub fn tree_depth(&self) -> usize {
        self.tree_depth
    }
}

/// Detailed verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the proof is valid
    pub is_valid: bool,
    /// Time taken to verify (milliseconds)
    pub verification_time_ms: u64,
    /// Block height
    pub height: u64,
    /// Number of transactions
    pub tx_count: u32,
    /// Proof size in bytes
    pub proof_size: usize,
}

impl std::fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {} ({} txs): {} in {}ms (proof: {} bytes)",
            self.height,
            self.tx_count,
            if self.is_valid { "VALID" } else { "INVALID" },
            self.verification_time_ms,
            self.proof_size
        )
    }
}

/// Verify a proof without creating a verifier instance
///
/// Convenience function for one-off verification.
pub fn verify_proof(vk: &VerificationKey, proof: &BlockProof) -> ZkResult<bool> {
    let verifier = BlockVerifier::new(vk)?;
    verifier.verify(proof)
}

// M-1: bytes_to_field is now in field_utils.rs for unified prover/verifier use

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::BlockProver;
    use crate::state_tree::BalanceTree;
    use crate::types::BlockWitnessV2;
    use std::collections::HashMap;

    /// Create a test witness with valid merkle proofs using BalanceTree
    fn create_test_witness(tx_count: usize, tree_depth: usize) -> BlockWitnessV2 {
        // Set up initial balances: sender accounts have 1000, recipients have 500
        let mut initial_balances = HashMap::new();
        for i in 0..tx_count {
            let sender_index = (i * 2) as u64; // sender at even indices
            let recipient_index = (i * 2 + 1) as u64; // recipient at odd indices
            initial_balances.insert(sender_index, 1000u64);
            initial_balances.insert(recipient_index, 500u64);
        }

        let mut tree = BalanceTree::from_balances(tree_depth, initial_balances);
        let prev_root = tree.root().expect("Root should compute");

        // Apply each payment and collect witnesses + intermediate roots
        let mut transitions = Vec::with_capacity(tx_count);
        let mut intermediate_roots = Vec::with_capacity(tx_count);

        for i in 0..tx_count {
            let sender_index = (i * 2) as u64;
            let recipient_index = (i * 2 + 1) as u64;
            let witness = tree
                .apply_payment(sender_index, recipient_index, 100)
                .expect("Payment should succeed");
            transitions.push(witness);
            // Record the root AFTER this payment is applied
            intermediate_roots.push(tree.root().expect("Root should compute"));
        }

        let new_root = tree.root().expect("Root should compute");

        BlockWitnessV2::new_with_roots(
            1,
            prev_root,
            new_root,
            transitions,
            intermediate_roots,
            tree_depth,
        )
    }

    #[test]
    fn test_verifier_creation_production_requires_groth16_vk() {
        // HIGH-5: new() should fail in production mode without Groth16 VK
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();

        let verifier = BlockVerifier::new(&vk);
        assert!(verifier.is_err(), "new() should fail without Groth16 VK");
        match verifier {
            Err(ZkError::MissingVerificationKey(_)) => {} // Expected
            _ => panic!("Expected MissingVerificationKey error"),
        }
    }

    #[test]
    fn test_verifier_creation_development() {
        // HIGH-5: new_development() should work for testing
        let prover = BlockProver::new(5, 10).unwrap();
        let vk = prover.verification_key();

        let verifier = BlockVerifier::new_development(&vk);
        assert!(verifier.is_ok(), "new_development() should succeed");

        let verifier = verifier.unwrap();
        assert_eq!(verifier.max_txs(), 5);
        assert_eq!(verifier.tree_depth(), 10);
        assert!(
            !verifier.has_groth16_vk(),
            "Development verifier should not have Groth16 VK"
        );
    }

    #[test]
    fn test_valid_proof_verification() {
        // 2.3 HIGH: max_txs must match witness tx count to avoid padding issues
        let prover = BlockProver::new(2, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new_development(&vk).unwrap();

        let witness = create_test_witness(2, 10);
        let proof = prover.prove(&witness).unwrap();

        let result = verifier.verify(&proof);
        assert!(result.is_ok(), "Verification should not error");
        assert!(result.unwrap(), "Valid proof should verify");
    }

    #[test]
    fn test_detailed_verification() {
        // 2.3 HIGH: max_txs must match witness tx count
        let prover = BlockProver::new(1, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new_development(&vk).unwrap();

        let witness = create_test_witness(1, 10);
        let proof = prover.prove(&witness).unwrap();

        let result = verifier.verify_detailed(&proof).unwrap();
        assert!(result.is_valid, "Proof should be valid");
        assert_eq!(result.height, 1);
        assert_eq!(result.tx_count, 1);
        assert!(result.proof_size > 0);

        println!("Verification result: {}", result);
    }

    #[test]
    fn test_tampered_proof_fails() {
        // 2.3 HIGH: max_txs must match witness tx count
        let prover = BlockProver::new(1, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new_development(&vk).unwrap();

        let witness = create_test_witness(1, 10);
        let mut proof = prover.prove(&witness).unwrap();

        // Tamper with the prover ID in the proof
        if !proof.proof.is_empty() {
            proof.proof[0] ^= 0xFF;
        }

        // Tampered proof should fail verification
        let result = verifier.verify(&proof).unwrap();
        assert!(!result, "Tampered proof should not verify");
    }

    #[test]
    fn test_batch_verification() {
        // 2.3 HIGH: max_txs must match witness tx count
        let prover = BlockProver::new(1, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new_development(&vk).unwrap();

        let proofs: Vec<BlockProof> = (0..3)
            .map(|i| {
                let mut witness = create_test_witness(1, 10);
                witness.height = i as u64;
                prover.prove(&witness).unwrap()
            })
            .collect();

        let results = verifier.verify_batch(&proofs).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&v| v), "All proofs should be valid");
    }

    #[test]
    fn test_convenience_verify_function_requires_groth16() {
        // HIGH-5: verify_proof uses new() internally, which now requires Groth16 VK
        let prover = BlockProver::new(1, 10).unwrap();
        let vk = prover.verification_key();

        let witness = create_test_witness(1, 10);
        let proof = prover.prove(&witness).unwrap();

        let result = verify_proof(&vk, &proof);
        assert!(
            result.is_err(),
            "Convenience function should fail without Groth16 VK"
        );
        assert!(matches!(
            result.unwrap_err(),
            ZkError::MissingVerificationKey(_)
        ));
    }

    #[test]
    fn test_single_tx_verification() {
        // 2.3 HIGH: Renamed from test_empty_block_verification
        // Since ZK state transition mode requires valid merkle proofs,
        // empty blocks (0 transactions) are handled by using 1 transaction
        let prover = BlockProver::new(1, 10).unwrap();
        let vk = prover.verification_key();
        let verifier = BlockVerifier::new_development(&vk).unwrap();

        let witness = create_test_witness(1, 10);
        let proof = prover.prove(&witness).unwrap();

        let result = verifier.verify(&proof).unwrap();
        assert!(result, "Single tx block proof should verify");
    }
}
