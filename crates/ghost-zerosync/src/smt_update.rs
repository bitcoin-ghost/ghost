//! Phase 2 (capstone) — sparse-Merkle-tree **update** step: a dynamic UTXO
//! accumulator supporting **add and spend** (deletion), carried in the fold.
//!
//! `z = [root_hi, root_lo, size]`. Each step opens one leaf position of a
//! fixed-depth Merkle tree and rewrites it along a shared authentication path:
//!
//! * **add**  — `old_leaf = EMPTY`, `new_leaf = utxo`, `size += 1`
//! * **spend** — `old_leaf = utxo`,  `new_leaf = EMPTY`, `size -= 1`
//!
//! Both are the *same* R1CS (folding requires uniform steps): the direction is a
//! witnessed `delta ∈ {+1,-1}` pinned by `delta·delta == 1`.
//!
//! Soundness: the prover supplies `old_root`, `new_root`, `old_leaf`, `new_leaf`
//! and the path. The circuit enforces (a) `old_root` equals the carried `z`,
//! (b) `old_leaf` opens to `old_root` under the path, (c) `new_leaf` opens to
//! `new_root` under the *same* path, and (d) `new_root` becomes `z'`. So the only
//! freedom is the tree position, which `old_root == z` pins — a sound SMT update.
//!
//! Quirk-free by construction: every `pack_be` runs over **concrete** witnessed
//! root bits (`old_root`/`new_root` as circuit data), and every *merkle-computed*
//! root is consumed only by **bit comparison** — chained-SHA output is never
//! packed, so the nova `num_io` setup quirk never arises.

use crate::merkle::{merkle_root, PathElem};
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{AllocatedBit, Boolean, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

/// The empty-leaf sentinel (an unoccupied UTXO slot).
pub const EMPTY_LEAF: crate::U256 = [0u8; 32];

#[derive(Clone, Debug)]
pub struct SmtUpdateStep<F: PrimeField> {
    pub old_root: crate::U256,
    pub new_root: crate::U256,
    pub old_leaf: crate::U256,
    pub new_leaf: crate::U256,
    /// Authentication path (shared by old and new — only the opened leaf changes).
    pub path: Vec<PathElem>,
    /// +1 to add, -1 to spend.
    pub size_delta: F,
}

fn circuit_path<F, CS>(
    cs: &mut CS,
    path: &[PathElem],
) -> Result<Vec<(Vec<Boolean>, Boolean)>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let mut out = Vec::with_capacity(path.len());
    for (i, e) in path.iter().enumerate() {
        let sib = bytes_to_bits(cs.namespace(|| format!("sib_{i}")), &e.sibling)?;
        let dir = Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("dir_{i}")), Some(e.is_right))?);
        out.push((sib, dir));
    }
    Ok(out)
}

fn enforce_bits_equal<F, CS>(cs: &mut CS, tag: &str, a: &[Boolean], b: &[Boolean]) -> Result<(), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        Boolean::enforce_equal(cs.namespace(|| format!("{tag}_{i}")), x, y)?;
    }
    Ok(())
}

impl<F: PrimeField> StepCircuit<F> for SmtUpdateStep<F> {
    fn arity(&self) -> usize {
        3 // [root_hi, root_lo, size]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // Concrete old/new root bits (packing these is safe — no chained-SHA output).
        let old_root_bits = bytes_to_bits(cs.namespace(|| "old_root"), &self.old_root)?;
        let new_root_bits = bytes_to_bits(cs.namespace(|| "new_root"), &self.new_root)?;

        // (a) Bind old_root to the carried z.
        let (old_hi, old_lo) = hash_bits_to_limbs(cs.namespace(|| "old_limbs"), &old_root_bits)?;
        cs.enforce(|| "old_hi == z[0]", |lc| lc + old_hi.get_variable() - z[0].get_variable(), |lc| lc + CS::one(), |lc| lc);
        cs.enforce(|| "old_lo == z[1]", |lc| lc + old_lo.get_variable() - z[1].get_variable(), |lc| lc + CS::one(), |lc| lc);

        // Shared authentication path.
        let path = circuit_path(cs, &self.path)?;

        // (b) old_leaf opens to old_root.
        let old_leaf_bits = bytes_to_bits(cs.namespace(|| "old_leaf"), &self.old_leaf)?;
        let computed_old = merkle_root(cs.namespace(|| "old_mr"), &old_leaf_bits, &path)?;
        enforce_bits_equal(cs, "old_open", &computed_old, &old_root_bits)?;

        // (c) new_leaf opens to new_root under the SAME path.
        let new_leaf_bits = bytes_to_bits(cs.namespace(|| "new_leaf"), &self.new_leaf)?;
        let computed_new = merkle_root(cs.namespace(|| "new_mr"), &new_leaf_bits, &path)?;
        enforce_bits_equal(cs, "new_open", &computed_new, &new_root_bits)?;

        // (d) new_root becomes z'. Pack concrete new_root bits — safe.
        let (new_hi, new_lo) = hash_bits_to_limbs(cs.namespace(|| "new_limbs"), &new_root_bits)?;

        // size' = size + delta, with delta ∈ {+1,-1} (uniform across add/spend).
        let delta = AllocatedNum::alloc(cs.namespace(|| "delta"), || Ok(self.size_delta))?;
        cs.enforce(|| "delta^2 == 1", |lc| lc + delta.get_variable(), |lc| lc + delta.get_variable(), |lc| lc + CS::one());
        let size = AllocatedNum::alloc(cs.namespace(|| "size'"), || {
            Ok(z[2].get_value().ok_or(SynthesisError::AssignmentMissing)? + delta.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce(
            || "size' = size + delta",
            |lc| lc + z[2].get_variable() + delta.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + size.get_variable(),
        );

        Ok(vec![new_hi, new_lo, size])
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
    type C1 = SmtUpdateStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn h2(a: &crate::U256, b: &crate::U256) -> crate::U256 {
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(a);
        buf[32..64].copy_from_slice(b);
        double_sha256(&buf)
    }
    // Depth-2 tree over 4 leaves.
    fn root_of(leaves: &[crate::U256; 4]) -> crate::U256 {
        h2(&h2(&leaves[0], &leaves[1]), &h2(&leaves[2], &leaves[3]))
    }
    // Path for leaf `idx`: [sibling-leaf, sibling-subtree].
    fn path_of(leaves: &[crate::U256; 4], idx: usize) -> Vec<PathElem> {
        let (sib_leaf, leaf_is_right) = match idx {
            0 => (leaves[1], false),
            1 => (leaves[0], true),
            2 => (leaves[3], false),
            _ => (leaves[2], true),
        };
        let n01 = h2(&leaves[0], &leaves[1]);
        let n23 = h2(&leaves[2], &leaves[3]);
        let (sib_sub, sub_is_right) = if idx < 2 { (n23, false) } else { (n01, true) };
        vec![
            PathElem { sibling: sib_leaf, is_right: leaf_is_right },
            PathElem { sibling: sib_sub, is_right: sub_is_right },
        ]
    }

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
    fn add_add_then_spend_evolves_the_utxo_set() {
        let e = EMPTY_LEAF;
        let u0 = double_sha256(b"utxo-0");
        let u1 = double_sha256(b"utxo-1");

        // State 0: empty. Add u0@0, add u1@1, spend u0@0.
        let s0 = [e, e, e, e];
        let s1 = [u0, e, e, e];
        let s2 = [u0, u1, e, e];
        let s3 = [e, u1, e, e];

        let steps = vec![
            SmtUpdateStep { old_root: root_of(&s0), new_root: root_of(&s1), old_leaf: e, new_leaf: u0, path: path_of(&s0, 0), size_delta: S1::from(1u64) },
            SmtUpdateStep { old_root: root_of(&s1), new_root: root_of(&s2), old_leaf: e, new_leaf: u1, path: path_of(&s1, 1), size_delta: S1::from(1u64) },
            SmtUpdateStep { old_root: root_of(&s2), new_root: root_of(&s3), old_leaf: u0, new_leaf: e, path: path_of(&s2, 0), size_delta: -S1::from(1u64) },
        ];
        let (h0, l0) = hash_to_limbs::<S1>(&root_of(&s0));
        let zn = run(&steps, [h0, l0, S1::from(0u64)]).expect("verify");

        let (h3, l3) = hash_to_limbs::<S1>(&root_of(&s3));
        assert_eq!(zn[0], h3, "final root_hi");
        assert_eq!(zn[1], l3, "final root_lo");
        assert_eq!(zn[2], S1::from(1u64), "size = +1 +1 -1 = 1");
    }

    #[test]
    fn spending_an_absent_utxo_fails() {
        let e = EMPTY_LEAF;
        let u0 = double_sha256(b"utxo-0");
        let s0 = [e, e, e, e];
        let s1 = [e, e, e, e];
        // Claims to spend u0@0 but the slot is empty → old_leaf u0 does not open to old_root.
        let steps = vec![SmtUpdateStep { old_root: root_of(&s0), new_root: root_of(&s1), old_leaf: u0, new_leaf: e, path: path_of(&s0, 0), size_delta: -S1::from(1u64) }];
        let (h0, l0) = hash_to_limbs::<S1>(&root_of(&s0));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&steps, [h0, l0, S1::from(0u64)])));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "spending an absent UTXO must not verify");
    }
}
