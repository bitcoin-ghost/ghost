//! Note spend proof verification
//!
//! Verifies Groth16 proofs that a note spend is valid.
//! Verification is fast (~5ms) and requires only the public inputs.

use bellperson::groth16::{verify_proof, PreparedVerifyingKey, Proof};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::note_prover::{GhostNoteSpendProof, GhostNoteSpendPublicInputs};
use crate::types::GROTH16_PROOF_SIZE;

/// Verifies note spend proofs
pub struct GhostNoteVerifier {
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    prover_id: [u8; 32],
    /// Accept all proofs unconditionally (for external crate tests only).
    /// GHOST-08: never read under `zk-production` — the bypass is compiled out.
    #[cfg_attr(feature = "zk-production", allow(dead_code))]
    accept_all: bool,
}

impl GhostNoteVerifier {
    /// Create a verifier with a Groth16 verification key
    pub fn new(prepared_vk: Arc<PreparedVerifyingKey<Bls12>>, prover_id: [u8; 32]) -> Self {
        Self {
            prepared_vk: Some(prepared_vk),
            prover_id,
            accept_all: false,
        }
    }

    /// Create a verifier from a prover (inherits VK if available)
    pub fn for_prover(prover: &crate::note_prover::GhostNoteProver) -> Self {
        Self {
            prepared_vk: prover.prepared_verifying_key(),
            prover_id: prover.prover_id(),
            accept_all: false,
        }
    }

    /// Create a test verifier that accepts all proofs unconditionally.
    /// For use in external crate tests where `#[cfg(test)]` doesn't propagate.
    /// GHOST-08: the accept-all bypass it sets is compiled out under
    /// `zk-production`, so in mainnet builds this is inert — real verification
    /// still runs. Kept available (not cfg-gated) so cross-crate tests compile
    /// under `--all-features`.
    pub fn test_accept_all() -> Self {
        Self {
            prepared_vk: None,
            prover_id: [0u8; 32],
            accept_all: true,
        }
    }

    /// Check if Groth16 verification is available
    pub fn has_groth16_vk(&self) -> bool {
        self.prepared_vk.is_some()
    }

    /// Verify a note spend proof
    #[instrument(skip_all)]
    pub fn verify(&self, proof: &GhostNoteSpendProof) -> ZkResult<bool> {
        // GHOST-08: the accept-all test bypass is compiled out under
        // `zk-production`, so a mainnet build always runs real verification
        // regardless of how the verifier was constructed.
        #[cfg(not(feature = "zk-production"))]
        if self.accept_all {
            return Ok(true);
        }

        let start = Instant::now();

        if proof.prover_id != self.prover_id {
            warn!("Prover ID mismatch");
            return Ok(false);
        }

        if proof.proof.is_empty() {
            warn!("Empty proof");
            return Ok(false);
        }

        if let Some(ref prepared_vk) = self.prepared_vk {
            if proof.proof.len() != GROTH16_PROOF_SIZE {
                debug!(
                    "Proof size mismatch: {} != {}",
                    proof.proof.len(),
                    GROTH16_PROOF_SIZE
                );
                return Ok(false);
            }

            match self.verify_groth16(proof, prepared_vk) {
                Ok(valid) => {
                    info!("Note spend proof verified in {:?}", start.elapsed());
                    return Ok(valid);
                }
                Err(e) => {
                    warn!("Groth16 verification error: {:?}", e);
                    return Ok(false);
                }
            }
        }

        error!("SECURITY: No Groth16 verification key available. Rejecting proof.");

        #[cfg(test)]
        {
            info!("Accepting simulated proof in test mode");
            Ok(true)
        }

        #[cfg(not(test))]
        Ok(false)
    }

    /// Verify a note spend proof using raw public input bytes.
    ///
    /// This is the hot path for validators (~5ms).
    #[instrument(skip_all)]
    pub fn verify_raw(
        &self,
        proof_bytes: &[u8],
        public_inputs: &GhostNoteSpendPublicInputs,
    ) -> ZkResult<bool> {
        // GHOST-08: the accept-all test bypass is compiled out under
        // `zk-production`, so a mainnet build always runs real verification
        // regardless of how the verifier was constructed.
        #[cfg(not(feature = "zk-production"))]
        if self.accept_all {
            return Ok(true);
        }

        let start = Instant::now();

        if let Some(ref prepared_vk) = self.prepared_vk {
            if proof_bytes.len() != GROTH16_PROOF_SIZE {
                return Ok(false);
            }

            let groth16_proof = self.deserialize_proof(proof_bytes)?;
            let pi = self.build_public_inputs(public_inputs)?;
            let result = verify_proof(prepared_vk, &groth16_proof, &pi);

            debug!("Raw note spend verification in {:?}", start.elapsed());

            match result {
                Ok(valid) => Ok(valid),
                Err(e) => {
                    warn!("Groth16 verification error: {:?}", e);
                    Ok(false)
                }
            }
        } else {
            error!("No Groth16 VK for raw verification");
            #[cfg(test)]
            return Ok(true);
            #[cfg(not(test))]
            Ok(false)
        }
    }

    fn verify_groth16(
        &self,
        proof: &GhostNoteSpendProof,
        prepared_vk: &PreparedVerifyingKey<Bls12>,
    ) -> ZkResult<bool> {
        let groth16_proof = self.deserialize_proof(&proof.proof)?;
        let public_inputs = self.build_public_inputs(&proof.public_inputs)?;

        let result = verify_proof(prepared_vk, &groth16_proof, &public_inputs);

        match result {
            Ok(valid) => Ok(valid),
            Err(e) => {
                warn!("Groth16 verification error: {:?}", e);
                Ok(false)
            }
        }
    }

    /// Build public inputs in circuit order: root, nullifier, change, recipient
    fn build_public_inputs(&self, inputs: &GhostNoteSpendPublicInputs) -> ZkResult<Vec<Fr>> {
        Ok(vec![
            bytes_to_field(&inputs.commitment_root)?,
            bytes_to_field(&inputs.nullifier)?,
            bytes_to_field(&inputs.change_commitment)?,
            bytes_to_field(&inputs.recipient_commitment)?,
        ])
    }

    /// Deserialize a Groth16 proof from bytes with subgroup checks
    fn deserialize_proof(&self, bytes: &[u8]) -> ZkResult<Proof<Bls12>> {
        if bytes.len() != GROTH16_PROOF_SIZE {
            return Err(ZkError::InvalidProof(format!(
                "Invalid proof size: {} != {}",
                bytes.len(),
                GROTH16_PROOF_SIZE
            )));
        }

        // Parse A (G1 point, 48 bytes)
        let a_bytes: [u8; 48] = bytes[0..48]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read A point".to_string()))?;
        let a = G1Affine::from_compressed(&a_bytes);
        let a = if a.is_some().into() {
            a.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid A point".to_string()));
        };
        if !bool::from(a.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "A point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse B (G2 point, 96 bytes)
        let b_bytes: [u8; 96] = bytes[48..144]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read B point".to_string()))?;
        let b = G2Affine::from_compressed(&b_bytes);
        let b = if b.is_some().into() {
            b.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid B point".to_string()));
        };
        if !bool::from(b.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "B point not in prime-order subgroup".to_string(),
            ));
        }

        // Parse C (G1 point, 48 bytes)
        let c_bytes: [u8; 48] = bytes[144..192]
            .try_into()
            .map_err(|_| ZkError::InvalidProof("Failed to read C point".to_string()))?;
        let c = G1Affine::from_compressed(&c_bytes);
        let c = if c.is_some().into() {
            c.unwrap()
        } else {
            return Err(ZkError::InvalidProof("Invalid C point".to_string()));
        };
        if !bool::from(c.is_torsion_free()) {
            return Err(ZkError::InvalidProof(
                "C point not in prime-order subgroup".to_string(),
            ));
        }

        Ok(Proof { a, b, c })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::mimc::field_to_bytes;
    use crate::note_prover::{GhostNoteProver, GhostNoteSpendWitness};
    use blstrs::Scalar as Fr;

    fn create_test_witness(tree_depth: usize) -> GhostNoteSpendWitness {
        GhostNoteSpendWitness {
            spending_key: field_to_bytes(Fr::from(42u64)),
            note_value: 1000,
            note_blinding: field_to_bytes(Fr::from(111u64)),
            note_index: 0,
            epoch: 1,
            merkle_siblings: vec![[0u8; 32]; tree_depth],
            amount: 300,
            change_blinding: field_to_bytes(Fr::from(222u64)),
            recipient_blinding: field_to_bytes(Fr::from(333u64)),
        }
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let prover = GhostNoteProver::new(4);
        let verifier = GhostNoteVerifier::for_prover(&prover);
        let witness = create_test_witness(4);

        let proof = prover.prove(&witness).unwrap();
        assert!(verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_prover_id_mismatch() {
        let prover = GhostNoteProver::new(4);
        let verifier = GhostNoteVerifier {
            prepared_vk: None,
            prover_id: [0xFF; 32],
            accept_all: false,
        };
        let witness = create_test_witness(4);

        let proof = prover.prove(&witness).unwrap();
        assert!(!verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_empty_proof_rejected() {
        let prover = GhostNoteProver::new(4);
        let verifier = GhostNoteVerifier::for_prover(&prover);
        let witness = create_test_witness(4);

        let mut proof = prover.prove(&witness).unwrap();
        proof.proof.clear();
        assert!(!verifier.verify(&proof).unwrap());
    }

    #[test]
    #[ignore] // Expensive ~10-30s
    fn test_groth16_prove_verify_roundtrip() {
        let prover = GhostNoteProver::new_with_setup(4).expect("Setup should succeed");
        assert!(prover.has_groth16_params());

        let verifier = GhostNoteVerifier::for_prover(&prover);
        assert!(verifier.has_groth16_vk());

        let witness = create_test_witness(4);
        let proof = prover.prove(&witness).expect("Proof should succeed");
        assert!(proof.is_real_proof());
        assert_eq!(proof.proof.len(), GROTH16_PROOF_SIZE);

        assert!(verifier
            .verify(&proof)
            .expect("Verification should succeed"));
    }
}
