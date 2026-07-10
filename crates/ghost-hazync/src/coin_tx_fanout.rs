//! Phase 3 (fan-out) — coin-level transaction with **variable input/output
//! fan-out**, folded uniformly.
//!
//! Folding needs a *uniform* circuit, so the step has a fixed maximum of
//! [`MAX_IN`] inputs and [`MAX_OUT`] outputs; a real tx uses as many slots as it
//! needs and **pads** the rest. Padding is not special-cased in the accumulator:
//! a no-op is simply a transition whose leaf is unchanged, so the root threads
//! through untouched. Each slot carries an `active` bit that MUXes the leaf
//! (`active ? coin : EMPTY`) and zeroes the slot's amount contribution.
//!
//! `z = [acc_hi, acc_lo, txcount]`. Per step: spend up to `MAX_IN` real coins,
//! create up to `MAX_OUT` real coins, chained through `roots[0..=MAX_IN+MAX_OUT]`,
//! and enforce value conservation `Σ amount_in == Σ amount_out + fee`,
//! `fee ∈ [0, 2^64)` — over only the *active* amounts.
//!
//! SPIKE: `MAX_IN = MAX_OUT = 2` and a depth-2 accumulator tree; header PoW
//! composes on top as in [`crate::block_tx_step`].

use crate::coin::{coin_commit, Coin};
use crate::merkle::{select_bits, PathElem};
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, pow2};
use crate::smt_update::{enforce_transition_bits, EMPTY_LEAF};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{AllocatedBit, Boolean, ConstraintSystem, LinearCombination, SynthesisError, Variable};
use nova_snark::traits::circuit::StepCircuit;

pub const MAX_IN: usize = 2;
pub const MAX_OUT: usize = 2;

/// One input slot: the coin being spent, whether the slot is used, and its path.
#[derive(Clone, Debug)]
pub struct InputSlot {
    pub coin: Coin,
    pub active: bool,
    pub path: Vec<PathElem>,
}

/// One output slot: the coin being created, whether the slot is used, and its path.
#[derive(Clone, Debug)]
pub struct OutputSlot {
    pub coin: Coin,
    pub active: bool,
    pub path: Vec<PathElem>,
}

#[derive(Clone, Debug)]
pub struct CoinTxFanoutStep<F: PrimeField> {
    /// Accumulator roots threaded through the slots: `len == MAX_IN + MAX_OUT + 1`.
    /// `roots[0]` is bound to `z`; `roots[MAX_IN+MAX_OUT]` becomes `z'`.
    pub roots: Vec<crate::U256>,
    pub inputs: Vec<InputSlot>,   // len == MAX_IN (pad with inactive slots)
    pub outputs: Vec<OutputSlot>, // len == MAX_OUT
    pub fee: u64,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CoinTxFanoutStep<F> {
    pub fn new(roots: Vec<crate::U256>, inputs: Vec<InputSlot>, outputs: Vec<OutputSlot>, fee: u64) -> Self {
        assert_eq!(roots.len(), MAX_IN + MAX_OUT + 1, "roots length");
        assert_eq!(inputs.len(), MAX_IN, "inputs length");
        assert_eq!(outputs.len(), MAX_OUT, "outputs length");
        Self { roots, inputs, outputs, fee, _marker: std::marker::PhantomData }
    }
}

impl<F: PrimeField> StepCircuit<F> for CoinTxFanoutStep<F> {
    fn arity(&self) -> usize {
        3 // [acc_hi, acc_lo, txcount]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let empty_bits = bytes_to_bits(cs.namespace(|| "empty"), &EMPTY_LEAF)?;
        let roots_bits: Vec<Vec<Boolean>> = self
            .roots
            .iter()
            .enumerate()
            .map(|(i, r)| bytes_to_bits(cs.namespace(|| format!("root_{i}")), r))
            .collect::<Result<_, _>>()?;

        // Bind roots[0] to the carried z.
        let (old_hi, old_lo) = hash_bits_to_limbs(cs.namespace(|| "old_limbs"), &roots_bits[0])?;
        cs.enforce(|| "old_hi == z[0]", |lc| lc + old_hi.get_variable() - z[0].get_variable(), |lc| lc + CS::one(), |lc| lc);
        cs.enforce(|| "old_lo == z[1]", |lc| lc + old_lo.get_variable() - z[1].get_variable(), |lc| lc + CS::one(), |lc| lc);

        // `contrib = active · amount`, collected for the value equation.
        let contrib = |cs: &mut CS, tag: &str, active_bit: &AllocatedBit, active: bool, amount: &AllocatedNum<F>|
            -> Result<Variable, SynthesisError> {
            let c = AllocatedNum::alloc(cs.namespace(|| format!("{tag}_contrib")), || {
                let a = if active { F::ONE } else { F::ZERO };
                Ok(a * amount.get_value().ok_or(SynthesisError::AssignmentMissing)?)
            })?;
            cs.enforce(
                || format!("{tag}_contrib = active·amount"),
                |lc| lc + active_bit.get_variable(),
                |lc| lc + amount.get_variable(),
                |lc| lc + c.get_variable(),
            );
            Ok(c.get_variable())
        };

        let mut in_contribs: Vec<Variable> = Vec::with_capacity(MAX_IN);
        for (i, slot) in self.inputs.iter().enumerate() {
            let (leaf, amount) = coin_commit(cs, &format!("in{i}"), &slot.coin)?;
            let active_bit = AllocatedBit::alloc(cs.namespace(|| format!("in{i}_active")), Some(slot.active))?;
            let active = Boolean::from(active_bit.clone());
            // Spend: old_leaf = active ? coin : EMPTY;  new_leaf = EMPTY.
            let old_leaf = select_bits(cs.namespace(|| format!("in{i}_sel")), &active, &leaf, &empty_bits)?;
            enforce_transition_bits(cs, &format!("in{i}_tr"), &roots_bits[i], &roots_bits[i + 1], &old_leaf, &empty_bits, &slot.path)?;
            in_contribs.push(contrib(cs, &format!("in{i}"), &active_bit, slot.active, &amount)?);
        }

        let mut out_contribs: Vec<Variable> = Vec::with_capacity(MAX_OUT);
        for (j, slot) in self.outputs.iter().enumerate() {
            let k = MAX_IN + j;
            let (leaf, amount) = coin_commit(cs, &format!("out{j}"), &slot.coin)?;
            let active_bit = AllocatedBit::alloc(cs.namespace(|| format!("out{j}_active")), Some(slot.active))?;
            let active = Boolean::from(active_bit.clone());
            // Create: old_leaf = EMPTY;  new_leaf = active ? coin : EMPTY.
            let new_leaf = select_bits(cs.namespace(|| format!("out{j}_sel")), &active, &leaf, &empty_bits)?;
            enforce_transition_bits(cs, &format!("out{j}_tr"), &roots_bits[k], &roots_bits[k + 1], &empty_bits, &new_leaf, &slot.path)?;
            out_contribs.push(contrib(cs, &format!("out{j}"), &active_bit, slot.active, &amount)?);
        }

        // Value conservation: Σ in == Σ out + fee, fee ∈ [0, 2^64).
        let fee = AllocatedNum::alloc(cs.namespace(|| "fee"), || Ok(F::from(self.fee)))?;
        let mut fee_bits = LinearCombination::<F>::zero();
        for i in 0..64 {
            let b = AllocatedBit::alloc(cs.namespace(|| format!("fee_bit_{i}")), Some((self.fee >> i) & 1 == 1))?;
            fee_bits = fee_bits + (pow2::<F>(i), b.get_variable());
        }
        cs.enforce(|| "fee is 64-bit", |_| fee_bits, |lc| lc + CS::one(), |lc| lc + fee.get_variable());

        let sum_lc = |vars: &[Variable]| -> LinearCombination<F> {
            let mut lc = LinearCombination::<F>::zero();
            for v in vars {
                lc = lc + (F::ONE, *v);
            }
            lc
        };
        cs.enforce(
            || "Σ in == Σ out + fee",
            |_| sum_lc(&out_contribs) + fee.get_variable(),
            |lc| lc + CS::one(),
            |_| sum_lc(&in_contribs),
        );

        // Final accumulator root -> z'.
        let last = &roots_bits[MAX_IN + MAX_OUT];
        let (new_hi, new_lo) = hash_bits_to_limbs(cs.namespace(|| "new_limbs"), last)?;
        let txcount = AllocatedNum::alloc(cs.namespace(|| "txcount'"), || {
            Ok(z[2].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "txcount' = txcount + 1",
            |lc| lc + z[2].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + txcount.get_variable(),
        );

        Ok(vec![new_hi, new_lo, txcount])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cumulative_pow::double_sha256;
    use crate::pow_step_circuit::hash_to_limbs;
    use crate::smt_update::tests_util::{path_of, root_of};
    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
        PublicParams, RecursiveSNARK,
    };

    type E1 = PallasEngine;
    type E2 = VestaEngine;
    type S1 = <E1 as Engine>::Scalar;
    type S2 = <E2 as Engine>::Scalar;
    type C1 = CoinTxFanoutStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn coin(tag: &[u8], amount: u64) -> Coin {
        Coin { txid: double_sha256(tag), vout: 0, amount, spk_hash: double_sha256(b"spk") }
    }

    /// Apply `(slot, new_leaf)` ops to a 4-leaf tree, recording the root before
    /// each op (plus the final root) and the path used for each op.
    fn apply(mut leaves: [crate::U256; 4], ops: &[(usize, crate::U256)]) -> (Vec<crate::U256>, Vec<Vec<PathElem>>) {
        let mut roots = vec![root_of(&leaves)];
        let mut paths = Vec::new();
        for (idx, leaf) in ops {
            paths.push(path_of(&leaves, *idx));
            leaves[*idx] = *leaf;
            roots.push(root_of(&leaves));
        }
        (roots, paths)
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

    // 2 real inputs, 1 real output, 1 padded output — exercises fan-out + padding.
    #[test]
    fn two_in_one_out_with_padding_conserves() {
        let e = EMPTY_LEAF;
        let in_a = coin(b"in-a", 40_000_000);
        let in_b = coin(b"in-b", 30_000_000);
        let out_c = coin(b"out-c", 50_000_000); // fee = 70M - 50M = 20M
        let pad = coin(b"unused", 999);

        let seed = [in_a.leaf(), in_b.leaf(), e, e];
        // spend a@0, spend b@1, add c@2, pad: EMPTY@3 -> EMPTY (no-op).
        let (roots, paths) = apply(seed, &[(0, e), (1, e), (2, out_c.leaf()), (3, e)]);

        let inputs = vec![
            InputSlot { coin: in_a, active: true, path: paths[0].clone() },
            InputSlot { coin: in_b, active: true, path: paths[1].clone() },
        ];
        let outputs = vec![
            OutputSlot { coin: out_c, active: true, path: paths[2].clone() },
            OutputSlot { coin: pad, active: false, path: paths[3].clone() },
        ];
        let step = CoinTxFanoutStep::new(roots.clone(), inputs, outputs, 20_000_000);

        let (a_hi, a_lo) = hash_to_limbs::<S1>(&roots[0]);
        let zn = run(&[step], [a_hi, a_lo, S1::from(0u64)]).expect("verify");

        let (n_hi, n_lo) = hash_to_limbs::<S1>(&roots[MAX_IN + MAX_OUT]);
        assert_eq!(zn[0], n_hi, "acc_hi");
        assert_eq!(zn[1], n_lo, "acc_lo");
        assert_eq!(zn[2], S1::from(1u64), "one tx");
    }

    // Same shape, but outputs exceed inputs → must be rejected.
    #[test]
    fn fanout_inflation_is_rejected() {
        let e = EMPTY_LEAF;
        let in_a = coin(b"in-a", 40_000_000);
        let in_b = coin(b"in-b", 30_000_000);
        let out_c = coin(b"out-c", 200_000_000); // 200M > 70M in
        let pad = coin(b"unused", 999);

        let seed = [in_a.leaf(), in_b.leaf(), e, e];
        let (roots, paths) = apply(seed, &[(0, e), (1, e), (2, out_c.leaf()), (3, e)]);

        let inputs = vec![
            InputSlot { coin: in_a, active: true, path: paths[0].clone() },
            InputSlot { coin: in_b, active: true, path: paths[1].clone() },
        ];
        let outputs = vec![
            OutputSlot { coin: out_c, active: true, path: paths[2].clone() },
            OutputSlot { coin: pad, active: false, path: paths[3].clone() },
        ];
        let step = CoinTxFanoutStep::new(roots.clone(), inputs, outputs, 0);

        let (a_hi, a_lo) = hash_to_limbs::<S1>(&roots[0]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&[step], [a_hi, a_lo, S1::from(0u64)])));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "outputs exceeding inputs must not verify");
    }
}
