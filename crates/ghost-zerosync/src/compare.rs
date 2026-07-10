//! Big-endian `<=` comparator over bit arrays — the core of the PoW check
//! (`hash_be <= target`). Bit-serial, MSB→LSB, O(n) boolean gates.

use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};

/// Return `a <= b` as a `Boolean`, where `a` and `b` are equal-length
/// **big-endian** bit slices (most-significant bit first).
///
/// Method: walk MSB→LSB tracking `eq_prefix` (all higher bits equal so far) and
/// `a_gt` (a already decided greater). `a > b` fires at the first differing bit
/// where `a=1, b=0` while still equal above; `a <= b := ¬a_gt`.
pub fn leq_be<F, CS>(mut cs: CS, a: &[Boolean], b: &[Boolean]) -> Result<Boolean, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    assert_eq!(a.len(), b.len(), "leq_be operands must be equal length");
    let mut eq_prefix = Boolean::constant(true);
    let mut a_gt = Boolean::constant(false);
    for i in 0..a.len() {
        // a[i] ∧ ¬b[i]
        let not_b = b[i].not();
        let a_and_notb = Boolean::and(cs.namespace(|| format!("a_notb_{i}")), &a[i], &not_b)?;
        // decided-greater at this position (only counts while still equal above)
        let gt_here = Boolean::and(cs.namespace(|| format!("gt_here_{i}")), &a_and_notb, &eq_prefix)?;
        a_gt = Boolean::or(cs.namespace(|| format!("a_gt_{i}")), &a_gt, &gt_here)?;
        // eq_bit = ¬(a[i] ⊕ b[i]); eq_prefix &= eq_bit
        let xor = Boolean::xor(cs.namespace(|| format!("xor_{i}")), &a[i], &b[i])?;
        let eq_bit = xor.not();
        eq_prefix = Boolean::and(cs.namespace(|| format!("eq_prefix_{i}")), &eq_prefix, &eq_bit)?;
    }
    Ok(a_gt.not())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_snark::frontend::{AllocatedBit, ConstraintSystem as _};
    use nova_snark::frontend::solver::SatisfyingAssignment;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;

    type Scalar = <PallasEngine as Engine>::Scalar;

    fn bits_of<CS: ConstraintSystem<Scalar>>(mut cs: CS, v: u16, n: usize) -> Vec<Boolean> {
        (0..n)
            .map(|i| {
                let b = (v >> (n - 1 - i)) & 1 == 1; // MSB first
                Boolean::from(AllocatedBit::alloc(cs.namespace(|| format!("b{i}")), Some(b)).unwrap())
            })
            .collect()
    }

    #[test]
    fn leq_be_truth_table() {
        for (a, b, expected) in [
            (5u16, 7u16, true),
            (7, 7, true),
            (9, 7, false),
            (0, 255, true),
            (255, 0, false),
            (128, 129, true),
            (200, 199, false),
        ] {
            let mut cs = SatisfyingAssignment::<PallasEngine>::new();
            let ab = bits_of(cs.namespace(|| "a"), a, 8);
            let bb = bits_of(cs.namespace(|| "b"), b, 8);
            let r = leq_be(cs.namespace(|| "leq"), &ab, &bb).unwrap();
            assert_eq!(r.get_value().unwrap(), expected, "leq({a} <= {b})");
        }
    }
}
