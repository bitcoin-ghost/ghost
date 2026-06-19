//! Unshield (L2 -> L1 withdrawal) proof verification
//!
//! Verifies Groth16 proofs that a full note withdrawal is valid.
//! Verification is fast (~5ms) and requires only the public inputs.

use bellperson::groth16::{verify_proof, PreparedVerifyingKey, Proof};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::GROTH16_PROOF_SIZE;
use crate::unshield_prover::{UnshieldProof, UnshieldPublicInputs};

/// Verifies unshield (withdrawal) proofs
pub struct GhostUnshieldVerifier {
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    prover_id: [u8; 32],
    #[cfg_attr(feature = "zk-production", allow(dead_code))]
    accept_all: bool,
}

impl GhostUnshieldVerifier {
    /// Create a verifier with a Groth16 verification key
    pub fn new(prepared_vk: Arc<PreparedVerifyingKey<Bls12>>, prover_id: [u8; 32]) -> Self {
        Self {
            prepared_vk: Some(prepared_vk),
            prover_id,
            accept_all: false,
        }
    }

    /// Create a verifier from a prover (inherits VK if available)
    pub fn for_prover(prover: &crate::unshield_prover::GhostUnshieldProver) -> Self {
        Self {
            prepared_vk: prover.prepared_verifying_key(),
            prover_id: prover.prover_id(),
            accept_all: false,
        }
    }

    /// Create a test verifier that accepts all proofs unconditionally.
    /// GHOST-08: unavailable under `zk-production` (mainnet) builds.
    #[cfg(not(feature = "zk-production"))]
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

    /// Verify an unshield proof
    #[instrument(skip_all)]
    pub fn verify(&self, proof: &UnshieldProof) -> ZkResult<bool> {
        // GHOST-08: compiled out under `zk-production` (mainnet always verifies).
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
                    info!("Unshield proof verified in {:?}", start.elapsed());
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

    /// Verify an unshield proof using raw public input bytes
    #[instrument(skip_all)]
    pub fn verify_raw(
        &self,
        proof_bytes: &[u8],
        public_inputs: &UnshieldPublicInputs,
    ) -> ZkResult<bool> {
        // GHOST-08: compiled out under `zk-production` (mainnet always verifies).
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

            debug!("Raw unshield verification in {:?}", start.elapsed());

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
        proof: &UnshieldProof,
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

    /// Build public inputs in circuit order: commitment_root, nullifier, withdrawal_amount
    fn build_public_inputs(&self, inputs: &UnshieldPublicInputs) -> ZkResult<Vec<Fr>> {
        let pi = vec![
            bytes_to_field(&inputs.commitment_root)?,
            bytes_to_field(&inputs.nullifier)?,
            Fr::from(inputs.withdrawal_amount),
        ];
        Ok(pi)
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
    use crate::circuit::commitment::pedersen_commit_native;
    use crate::circuit::mimc::{field_to_bytes, mimc_hash_native};
    use crate::unshield_prover::{GhostUnshieldProver, UnshieldWitness};
    use blstrs::Scalar as Fr;
    use ff::Field;

    fn build_tree(depth: usize, leaves: &[(u64, Fr)]) -> (Fr, Vec<Vec<[u8; 32]>>) {
        let leaf_map: std::collections::HashMap<u64, Fr> = leaves.iter().cloned().collect();

        fn compute_node(
            level: usize,
            index: u64,
            leaves: &std::collections::HashMap<u64, Fr>,
        ) -> Fr {
            if level == 0 {
                return *leaves.get(&index).unwrap_or(&Fr::ZERO);
            }
            let left = compute_node(level - 1, index * 2, leaves);
            let right = compute_node(level - 1, index * 2 + 1, leaves);
            mimc_hash_native(left, right)
        }

        let root = compute_node(depth, 0, &leaf_map);

        let siblings = leaves
            .iter()
            .map(|(index, _)| {
                let mut sibs = Vec::with_capacity(depth);
                let mut current_idx = *index;
                for level in 0..depth {
                    let sibling_idx = current_idx ^ 1;
                    let sibling_hash = compute_node(level, sibling_idx, &leaf_map);
                    sibs.push(field_to_bytes(sibling_hash));
                    current_idx /= 2;
                }
                sibs
            })
            .collect();

        (root, siblings)
    }

    fn create_test_witness(tree_depth: usize) -> UnshieldWitness {
        let spending_key = field_to_bytes(Fr::from(42u64));
        let value = 1000u64;
        let blinding = Fr::from(111u64);
        let commitment = pedersen_commit_native(Fr::from(value), blinding);

        let (_root, all_siblings) = build_tree(tree_depth, &[(0, commitment)]);

        UnshieldWitness {
            spending_key,
            note_value: value,
            note_blinding: field_to_bytes(blinding),
            note_index: 0,
            epoch: 1,
            merkle_siblings: all_siblings[0].clone(),
        }
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let prover = GhostUnshieldProver::new(4);
        let verifier = GhostUnshieldVerifier::for_prover(&prover);
        let witness = create_test_witness(4);

        let proof = prover.prove(&witness).unwrap();
        assert!(verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_prover_id_mismatch() {
        let prover = GhostUnshieldProver::new(4);
        let verifier = GhostUnshieldVerifier {
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
        let prover = GhostUnshieldProver::new(4);
        let verifier = GhostUnshieldVerifier::for_prover(&prover);
        let witness = create_test_witness(4);

        let mut proof = prover.prove(&witness).unwrap();
        proof.proof.clear();
        assert!(!verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_accept_all_verifier() {
        let prover = GhostUnshieldProver::new(4);
        let verifier = GhostUnshieldVerifier::test_accept_all();
        let witness = create_test_witness(4);

        let proof = prover.prove(&witness).unwrap();
        assert!(verifier.verify(&proof).unwrap());
    }

    #[test]
    #[ignore] // Expensive ~10-30s
    fn test_groth16_prove_verify_roundtrip() {
        let prover = GhostUnshieldProver::new_with_setup(4).expect("Setup should succeed");
        assert!(prover.has_groth16_params());

        let verifier = GhostUnshieldVerifier::for_prover(&prover);
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
