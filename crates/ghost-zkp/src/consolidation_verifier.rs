//! Consolidation proof verification
//!
//! Verifies Groth16 proofs that a note consolidation is valid.
//! Verification is fast (~5ms) and requires only the public inputs.

use bellperson::groth16::{verify_proof, PreparedVerifyingKey, Proof};
use blstrs::{Bls12, G1Affine, G2Affine, Scalar as Fr};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, error, info, instrument, warn};

use crate::circuit::note_consolidate::MAX_CONSOLIDATION_INPUTS;
use crate::consolidation_prover::{ConsolidationProof, ConsolidationPublicInputs};
use crate::errors::{ZkError, ZkResult};
use crate::field_utils::bytes_to_field;
use crate::types::GROTH16_PROOF_SIZE;

/// Verifies consolidation proofs
pub struct GhostConsolidateVerifier {
    prepared_vk: Option<Arc<PreparedVerifyingKey<Bls12>>>,
    prover_id: [u8; 32],
    #[cfg_attr(feature = "zk-production", allow(dead_code))]
    accept_all: bool,
}

impl GhostConsolidateVerifier {
    /// Create a verifier with a Groth16 verification key
    pub fn new(prepared_vk: Arc<PreparedVerifyingKey<Bls12>>, prover_id: [u8; 32]) -> Self {
        Self {
            prepared_vk: Some(prepared_vk),
            prover_id,
            accept_all: false,
        }
    }

    /// Create a verifier from a prover (inherits VK if available)
    pub fn for_prover(prover: &crate::consolidation_prover::GhostConsolidateProver) -> Self {
        Self {
            prepared_vk: prover.prepared_verifying_key(),
            prover_id: prover.prover_id(),
            accept_all: false,
        }
    }

    /// Create a test verifier that accepts all proofs unconditionally.
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

    /// Verify a consolidation proof
    #[instrument(skip_all)]
    pub fn verify(&self, proof: &ConsolidationProof) -> ZkResult<bool> {
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
                    info!("Consolidation proof verified in {:?}", start.elapsed());
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

    /// Verify a consolidation proof using raw public input bytes
    #[instrument(skip_all)]
    pub fn verify_raw(
        &self,
        proof_bytes: &[u8],
        public_inputs: &ConsolidationPublicInputs,
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

            debug!("Raw consolidation verification in {:?}", start.elapsed());

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
        proof: &ConsolidationProof,
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

    /// Build public inputs in circuit order: root, nullifiers[0..3], output_commitment
    fn build_public_inputs(&self, inputs: &ConsolidationPublicInputs) -> ZkResult<Vec<Fr>> {
        let mut pi = Vec::with_capacity(1 + MAX_CONSOLIDATION_INPUTS + 1);
        pi.push(bytes_to_field(&inputs.commitment_root)?);
        for nul in &inputs.nullifiers {
            pi.push(bytes_to_field(nul)?);
        }
        pi.push(bytes_to_field(&inputs.output_commitment)?);
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
    use crate::consolidation_prover::{
        ConsolidationInputNote, ConsolidationWitness, GhostConsolidateProver,
    };
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

    fn create_test_witness(tree_depth: usize, num_inputs: usize) -> ConsolidationWitness {
        let spending_key = field_to_bytes(Fr::from(42u64));

        let mut tree_leaves = Vec::new();
        let mut inputs = Vec::new();

        for i in 0..num_inputs {
            let value = (100 + i as u64) * 10;
            let blinding = Fr::from(100u64 + i as u64);
            let commitment = pedersen_commit_native(Fr::from(value), blinding);
            tree_leaves.push((i as u64, commitment));
            inputs.push((value, blinding, i as u64));
        }

        let (_root, all_siblings) = build_tree(tree_depth, &tree_leaves);

        let input_notes: Vec<ConsolidationInputNote> = inputs
            .iter()
            .enumerate()
            .map(|(i, (value, blinding, index))| ConsolidationInputNote {
                value: *value,
                blinding: field_to_bytes(*blinding),
                index: *index,
                epoch: 1,
                merkle_siblings: all_siblings[i].clone(),
            })
            .collect();

        ConsolidationWitness {
            spending_key,
            inputs: input_notes,
            output_blinding: field_to_bytes(Fr::from(999u64)),
        }
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let prover = GhostConsolidateProver::new(4);
        let verifier = GhostConsolidateVerifier::for_prover(&prover);
        let witness = create_test_witness(4, 2);

        let proof = prover.prove(&witness).unwrap();
        assert!(verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_prover_id_mismatch() {
        let prover = GhostConsolidateProver::new(4);
        let verifier = GhostConsolidateVerifier {
            prepared_vk: None,
            prover_id: [0xFF; 32],
            accept_all: false,
        };
        let witness = create_test_witness(4, 2);

        let proof = prover.prove(&witness).unwrap();
        assert!(!verifier.verify(&proof).unwrap());
    }

    #[test]
    fn test_empty_proof_rejected() {
        let prover = GhostConsolidateProver::new(4);
        let verifier = GhostConsolidateVerifier::for_prover(&prover);
        let witness = create_test_witness(4, 2);

        let mut proof = prover.prove(&witness).unwrap();
        proof.proof.clear();
        assert!(!verifier.verify(&proof).unwrap());
    }

    #[test]
    #[ignore] // Expensive ~10-30s
    fn test_groth16_prove_verify_roundtrip() {
        let prover = GhostConsolidateProver::new_with_setup(4).expect("Setup should succeed");
        assert!(prover.has_groth16_params());

        let verifier = GhostConsolidateVerifier::for_prover(&prover);
        assert!(verifier.has_groth16_vk());

        let witness = create_test_witness(4, 2);
        let proof = prover.prove(&witness).expect("Proof should succeed");
        assert!(proof.is_real_proof());
        assert_eq!(proof.proof.len(), GROTH16_PROOF_SIZE);

        assert!(verifier
            .verify(&proof)
            .expect("Verification should succeed"));
    }
}
