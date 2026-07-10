//! Phase 2 (foundation) — Merkle inclusion in-circuit.
//!
//! `merkle_root(leaf, path)` folds a leaf up an authentication path to a root by
//! hashing sibling pairs with `sha256d` — the core primitive for the UTXO
//! accumulator: a *spend* proves the UTXO's leaf is included (path → committed
//! root), an *add* extends the accumulator. Each path element carries the
//! sibling hash and a direction bit (`is_right` = this node is the right child).
//!
//! Internal node = `SHA256d(left || right)` (Bitcoin convention), matching the
//! native [`merkle_root_native`] oracle byte-for-byte.

use crate::sha256d_gadget::sha256d_bits;
use crate::U256;
use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};

use crate::cumulative_pow::double_sha256;

/// One authentication-path element: the sibling hash and whether the current
/// node sits on the **right** (so the parent hashes `sibling || node`).
#[derive(Clone, Debug)]
pub struct PathElem {
    pub sibling: U256,
    pub is_right: bool,
}

/// Native oracle: fold `leaf` up `path` to the Merkle root.
pub fn merkle_root_native(leaf: U256, path: &[PathElem]) -> U256 {
    let mut node = leaf;
    for e in path {
        let mut buf = [0u8; 64];
        if e.is_right {
            buf[0..32].copy_from_slice(&e.sibling);
            buf[32..64].copy_from_slice(&node);
        } else {
            buf[0..32].copy_from_slice(&node);
            buf[32..64].copy_from_slice(&e.sibling);
        }
        node = double_sha256(&buf);
    }
    node
}

/// `cond ? t : f` for a single `Boolean` (mutually-exclusive OR of the arms).
fn bool_select<F, CS>(
    mut cs: CS,
    cond: &Boolean,
    t: &Boolean,
    f: &Boolean,
) -> Result<Boolean, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let a = Boolean::and(cs.namespace(|| "cond&t"), cond, t)?;
    let not_cond = cond.not();
    let b = Boolean::and(cs.namespace(|| "!cond&f"), &not_cond, f)?;
    Boolean::or(cs.namespace(|| "or"), &a, &b)
}

/// If `cond`, return `(y, x)`, else `(x, y)` — per-bit.
fn cond_swap<F, CS>(
    mut cs: CS,
    cond: &Boolean,
    x: &[Boolean],
    y: &[Boolean],
) -> Result<(Vec<Boolean>, Vec<Boolean>), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let mut left = Vec::with_capacity(x.len());
    let mut right = Vec::with_capacity(x.len());
    for (i, (xi, yi)) in x.iter().zip(y.iter()).enumerate() {
        left.push(bool_select(cs.namespace(|| format!("l{i}")), cond, yi, xi)?);
        right.push(bool_select(cs.namespace(|| format!("r{i}")), cond, xi, yi)?);
    }
    Ok((left, right))
}

/// Fold `leaf_bits` up the authentication path to the root bits, in-circuit.
/// `path[i] = (sibling_bits, is_right)`.
pub fn merkle_root<F, CS>(
    mut cs: CS,
    leaf_bits: &[Boolean],
    path: &[(Vec<Boolean>, Boolean)],
) -> Result<Vec<Boolean>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let mut node: Vec<Boolean> = leaf_bits.to_vec();
    for (i, (sibling, is_right)) in path.iter().enumerate() {
        // is_right → node is the right child → (left,right) = (sibling,node).
        let (left, right) = cond_swap(cs.namespace(|| format!("swap_{i}")), is_right, &node, sibling)?;
        let mut concat = left;
        concat.extend_from_slice(&right);
        node = sha256d_bits(cs.namespace(|| format!("hash_{i}")), &concat)?;
    }
    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256d_gadget::{bits_to_bytes, bytes_to_bits};
    use nova_snark::frontend::solver::SatisfyingAssignment;
    use nova_snark::frontend::{AllocatedBit, Boolean, ConstraintSystem as _};
    use nova_snark::provider::PallasEngine;

    fn alloc_bit<CS: ConstraintSystem<<PallasEngine as nova_snark::traits::Engine>::Scalar>>(
        mut cs: CS,
        b: bool,
    ) -> Boolean {
        Boolean::from(AllocatedBit::alloc(cs.namespace(|| "b"), Some(b)).unwrap())
    }

    #[test]
    fn in_circuit_merkle_root_matches_native() {
        let leaf: U256 = double_sha256(b"a-utxo-leaf");
        let path = vec![
            PathElem { sibling: double_sha256(b"sib0"), is_right: false },
            PathElem { sibling: double_sha256(b"sib1"), is_right: true },
            PathElem { sibling: double_sha256(b"sib2"), is_right: false },
        ];
        let native_root = merkle_root_native(leaf, &path);

        let mut cs = SatisfyingAssignment::<PallasEngine>::new();
        let leaf_bits = bytes_to_bits(cs.namespace(|| "leaf"), &leaf).unwrap();
        let circuit_path: Vec<(Vec<Boolean>, Boolean)> = path
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let sib = bytes_to_bits(cs.namespace(|| format!("sib{i}")), &e.sibling).unwrap();
                let dir = alloc_bit(cs.namespace(|| format!("dir{i}")), e.is_right);
                (sib, dir)
            })
            .collect();
        let root_bits = merkle_root(cs.namespace(|| "root"), &leaf_bits, &circuit_path).unwrap();
        assert_eq!(
            bits_to_bytes(&root_bits),
            native_root,
            "in-circuit Merkle root must equal native"
        );
    }
}
