//! Phase 2 (dynamic) — accumulator **ADD** step: the UTXO-set root *evolves* in
//! the fold state.
//!
//! `z = [root_hi, root_lo, count]`. Each step appends one UTXO leaf:
//!
//! ```text
//! root' = SHA256d(root || leaf)
//! ```
//!
//! so the accumulator commitment is carried in `z` and mutated across the
//! recursion — the state-carrying counterpart to the (fixed-snapshot) spend-side
//! [`crate::accumulator`] inclusion step. An append/hash-chain accumulator
//! commits to the ordered set of added UTXOs; it is the simplest *sound* evolving
//! commitment. (Full Utreexo forest add/delete — perfect-tree merges, parent
//! recomputation on delete — is the follow-on increment.)
//!
//! The carried root is *bound* to `z` by packing the prover-supplied `prev_root`
//! bits and enforcing they equal the limbs in `z` (packing concrete bits is safe);
//! the new root comes from a **single** `sha256d`, whose output packs cleanly —
//! exactly the shape [`crate::hashed_step::HashedPowStep`] folds. This sidesteps
//! the nova setup quirk that field-packing *chained* SHA output triggers.

use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, sha256d_bits};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

/// Native oracle: append `leaf` to `root` (`SHA256d(root || leaf)`).
pub fn add_native(root: crate::U256, leaf: crate::U256) -> crate::U256 {
    let mut buf = [0u8; 64];
    buf[0..32].copy_from_slice(&root);
    buf[32..64].copy_from_slice(&leaf);
    crate::cumulative_pow::double_sha256(&buf)
}

#[derive(Clone, Debug)]
pub struct AccumulatorAddStep<F: PrimeField> {
    /// The current accumulator root — must equal the root carried in `z`.
    pub prev_root: crate::U256,
    /// The UTXO leaf being appended.
    pub leaf: crate::U256,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> AccumulatorAddStep<F> {
    pub fn new(prev_root: crate::U256, leaf: crate::U256) -> Self {
        Self { prev_root, leaf, _marker: std::marker::PhantomData }
    }
}

impl<F: PrimeField> StepCircuit<F> for AccumulatorAddStep<F> {
    fn arity(&self) -> usize {
        3 // [root_hi, root_lo, count]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Bind the carried root: pack prev_root's (concrete) bits and enforce the
        // limbs equal z. Packing witnessed bits is safe (no chained-SHA output).
        let prev_bits = bytes_to_bits(cs.namespace(|| "prev"), &self.prev_root)?;
        let (prev_hi, prev_lo) = hash_bits_to_limbs(cs.namespace(|| "prev_limbs"), &prev_bits)?;
        cs.enforce(
            || "prev_hi == z[0]",
            |lc| lc + prev_hi.get_variable() - z[0].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );
        cs.enforce(
            || "prev_lo == z[1]",
            |lc| lc + prev_lo.get_variable() - z[1].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // root' = SHA256d(prev_root || leaf) — a single sha256d.
        let leaf_bits = bytes_to_bits(cs.namespace(|| "leaf"), &self.leaf)?;
        let mut concat = prev_bits;
        concat.extend_from_slice(&leaf_bits);
        let new_bits = sha256d_bits(cs.namespace(|| "hash"), &concat)?;
        let (new_hi, new_lo) = hash_bits_to_limbs(cs.namespace(|| "new_limbs"), &new_bits)?;

        // count' = count + 1.
        let count = AllocatedNum::alloc(cs.namespace(|| "count'"), || {
            Ok(z[2].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "count' = count + 1",
            |lc| lc + z[2].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + count.get_variable(),
        );

        Ok(vec![new_hi, new_lo, count])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cumulative_pow::double_sha256;
    use crate::pow_step_circuit::hash_to_limbs;
    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
        PublicParams, RecursiveSNARK,
    };

    type E1 = PallasEngine;
    type E2 = VestaEngine;
    type S1 = <E1 as Engine>::Scalar;
    type S2 = <E2 as Engine>::Scalar;
    type C1 = AccumulatorAddStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn run(steps: &[C1], z0: [S1; 3]) -> Result<Vec<S1>, nova_snark::errors::NovaError> {
        let c2 = C2::default();
        let pp = PublicParams::<E1, E2, C1, C2>::setup(&steps[0], &c2, &*default_ck_hint(), &*default_ck_hint())?;
        let z0_p = z0.to_vec();
        let z0_s = vec![S2::from(0u64)];
        let mut rs = RecursiveSNARK::<E1, E2, C1, C2>::new(&pp, &steps[0], &c2, &z0_p, &z0_s)?;
        for s in steps {
            rs.prove_step(&pp, s, &c2)?;
        }
        rs.verify(&pp, steps.len(), &z0_p, &z0_s).map(|(zn, _)| zn)
    }

    #[test]
    fn adds_evolve_the_root_in_the_fold() {
        let empty: crate::U256 = [0u8; 32];
        let leaf1 = double_sha256(b"utxo-1");
        let leaf2 = double_sha256(b"utxo-2");

        // Native evolution of the accumulator root.
        let root1 = add_native(empty, leaf1);
        let root2 = add_native(root1, leaf2);

        let steps = vec![
            AccumulatorAddStep::new(empty, leaf1),
            AccumulatorAddStep::new(root1, leaf2),
        ];
        let (h0, l0) = hash_to_limbs::<S1>(&empty);
        let zn = run(&steps, [h0, l0, S1::from(0u64)]).expect("verify");

        let (h2, l2) = hash_to_limbs::<S1>(&root2);
        assert_eq!(zn[0], h2, "evolved root_hi must equal native root2");
        assert_eq!(zn[1], l2, "evolved root_lo must equal native root2");
        assert_eq!(zn[2], S1::from(2u64), "two UTXOs added");
    }

    #[test]
    fn wrong_prev_root_fails_to_verify() {
        let empty: crate::U256 = [0u8; 32];
        let leaf1 = double_sha256(b"utxo-1");
        // Step claims a prev_root that does not match the carried z (empty).
        let steps = vec![AccumulatorAddStep::new(double_sha256(b"not-empty"), leaf1)];
        let (h0, l0) = hash_to_limbs::<S1>(&empty);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&steps, [h0, l0, S1::from(0u64)])));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "a mismatched prev_root must not verify");
    }
}
