//! Phase 2 — UTXO accumulator fold step (spend-side).
//!
//! `AccumulatorInclusionStep` proves, per fold step, that a UTXO's leaf is
//! **included** under a committed Merkle root (a spend against a committed /
//! assumeUTXO-style set), counting the spends. It computes the root with
//! [`crate::merkle::merkle_root`] and enforces it **bit-for-bit** against the
//! committed root.
//!
//! `z = [spent_count]`.
//!
//! SPIKE scope: the committed root is supplied as circuit data (the same fixed
//! value every step — a snapshot). Carrying the root in the folding state and
//! *evolving* it (real Utreexo add/delete) is the next increment; this proves
//! inclusion verification runs inside the recursion. (Binding the root into `z`
//! via field limbs currently trips a nova setup check when field-packing the
//! output of chained SHA256 gadgets — tracked as a follow-up.)

use crate::merkle::{merkle_root, PathElem};
use crate::sha256d_gadget::bytes_to_bits;
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{AllocatedBit, Boolean, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct AccumulatorInclusionStep<F: PrimeField> {
    pub leaf: crate::U256,
    pub path: Vec<PathElem>,
    pub committed_root: crate::U256,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> AccumulatorInclusionStep<F> {
    pub fn new(leaf: crate::U256, path: Vec<PathElem>, committed_root: crate::U256) -> Self {
        Self { leaf, path, committed_root, _marker: std::marker::PhantomData }
    }
}

impl<F: PrimeField> StepCircuit<F> for AccumulatorInclusionStep<F> {
    fn arity(&self) -> usize {
        1 // [spent_count]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Compute the root from leaf + authentication path.
        let leaf_bits = bytes_to_bits(cs.namespace(|| "leaf"), &self.leaf)?;
        let mut circuit_path = Vec::with_capacity(self.path.len());
        for (i, e) in self.path.iter().enumerate() {
            let sib = bytes_to_bits(cs.namespace(|| format!("sib_{i}")), &e.sibling)?;
            let dir = Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("dir_{i}")), Some(e.is_right))?);
            circuit_path.push((sib, dir));
        }
        let root_bits = merkle_root(cs.namespace(|| "root"), &leaf_bits, &circuit_path)?;

        // Enforce the computed root equals the committed root, bit-for-bit.
        let committed_bits = bytes_to_bits(cs.namespace(|| "committed"), &self.committed_root)?;
        for (i, (r, c)) in root_bits.iter().zip(committed_bits.iter()).enumerate() {
            Boolean::enforce_equal(cs.namespace(|| format!("root_bit_{i}")), r, c)?;
        }

        // spent_count' = spent_count + 1.
        let count = AllocatedNum::alloc(cs.namespace(|| "count'"), || {
            Ok(z[0].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "count' = count + 1",
            |lc| lc + z[0].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + count.get_variable(),
        );
        Ok(vec![count])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cumulative_pow::double_sha256;
    use crate::merkle::merkle_root_native;
    use crate::U256;
    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
        PublicParams, RecursiveSNARK,
    };

    type E1 = PallasEngine;
    type E2 = VestaEngine;
    type S1 = <E1 as Engine>::Scalar;
    type S2 = <E2 as Engine>::Scalar;
    type C1 = AccumulatorInclusionStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn build_tree(leaves: [U256; 4]) -> (U256, Vec<Vec<PathElem>>) {
        let h2 = |a: &U256, b: &U256| {
            let mut buf = [0u8; 64];
            buf[0..32].copy_from_slice(a);
            buf[32..64].copy_from_slice(b);
            double_sha256(&buf)
        };
        let n01 = h2(&leaves[0], &leaves[1]);
        let n23 = h2(&leaves[2], &leaves[3]);
        let root = h2(&n01, &n23);
        let paths = vec![
            vec![PathElem { sibling: leaves[1], is_right: false }, PathElem { sibling: n23, is_right: false }],
            vec![PathElem { sibling: leaves[0], is_right: true }, PathElem { sibling: n23, is_right: false }],
            vec![PathElem { sibling: leaves[3], is_right: false }, PathElem { sibling: n01, is_right: true }],
            vec![PathElem { sibling: leaves[2], is_right: true }, PathElem { sibling: n01, is_right: true }],
        ];
        (root, paths)
    }

    fn run(steps: &[C1], z0: [S1; 1]) -> Result<Vec<S1>, nova_snark::errors::NovaError> {
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
    fn spends_verify_against_committed_root() {
        let leaves = [double_sha256(b"utxo0"), double_sha256(b"utxo1"), double_sha256(b"utxo2"), double_sha256(b"utxo3")];
        let (root, paths) = build_tree(leaves);
        assert_eq!(merkle_root_native(leaves[1], &paths[1]), root);

        let steps = vec![
            AccumulatorInclusionStep::new(leaves[1], paths[1].clone(), root),
            AccumulatorInclusionStep::new(leaves[2], paths[2].clone(), root),
        ];
        let zn = run(&steps, [S1::from(0u64)]).expect("verify");
        assert_eq!(zn[0], S1::from(2u64), "two spends counted");
    }

    #[test]
    fn non_member_fails_to_verify() {
        let leaves = [double_sha256(b"utxo0"), double_sha256(b"utxo1"), double_sha256(b"utxo2"), double_sha256(b"utxo3")];
        let (root, paths) = build_tree(leaves);
        // leaf 1 with leaf 2's path → computed root != committed root.
        let steps = vec![AccumulatorInclusionStep::new(leaves[1], paths[2].clone(), root)];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&steps, [S1::from(0u64)])));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "a non-member must not prove inclusion");
    }
}
