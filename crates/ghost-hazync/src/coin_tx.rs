//! Phase 3 (consensus) — coin-level transaction step with **value conservation**
//! (the no-inflation rule).
//!
//! `z = [acc_hi, acc_lo, txcount]`. Each step applies a transaction that spends a
//! real coin and creates a real coin against the SMT accumulator, and enforces:
//!
//! ```text
//! amount_in == amount_out + fee,   fee ∈ [0, 2^64)
//! ```
//!
//! where `amount_in`/`amount_out` are the amounts **committed inside** the spent
//! and created coins ([`crate::coin::coin_commit`] binds them to the leaf
//! preimage). A non-negative `fee` means `amount_out ≤ amount_in`: no value is
//! created from nothing. The UTXO transition (spend `input → EMPTY`, then add
//! `EMPTY → output`) is two chained SMT updates, as in
//! [`crate::block_tx_step`].
//!
//! SPIKE: exactly one input + one output; header PoW composes on top as in
//! `block_tx_step`. Variable input/output fan-out and multi-coin fee summation
//! are the follow-on.

use crate::coin::{coin_commit, Coin};
use crate::merkle::PathElem;
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, pow2};
use crate::smt_update::{enforce_transition_bits, EMPTY_LEAF};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{AllocatedBit, ConstraintSystem, LinearCombination, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct CoinTxStep<F: PrimeField> {
    pub old_root: crate::U256,
    pub mid_root: crate::U256,
    pub new_root: crate::U256,
    pub input_coin: Coin,
    pub spend_path: Vec<PathElem>,
    pub output_coin: Coin,
    pub add_path: Vec<PathElem>,
    /// `amount_in − amount_out` (the miner fee); must be ≥ 0 and fit u64.
    pub fee: u64,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CoinTxStep<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        old_root: crate::U256,
        mid_root: crate::U256,
        new_root: crate::U256,
        input_coin: Coin,
        spend_path: Vec<PathElem>,
        output_coin: Coin,
        add_path: Vec<PathElem>,
        fee: u64,
    ) -> Self {
        Self { old_root, mid_root, new_root, input_coin, spend_path, output_coin, add_path, fee, _marker: std::marker::PhantomData }
    }
}

impl<F: PrimeField> StepCircuit<F> for CoinTxStep<F> {
    fn arity(&self) -> usize {
        3 // [acc_hi, acc_lo, txcount]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let old_bits = bytes_to_bits(cs.namespace(|| "old_root"), &self.old_root)?;
        let mid_bits = bytes_to_bits(cs.namespace(|| "mid_root"), &self.mid_root)?;
        let new_bits = bytes_to_bits(cs.namespace(|| "new_root"), &self.new_root)?;
        let empty_bits = bytes_to_bits(cs.namespace(|| "empty"), &EMPTY_LEAF)?;

        // Bind old accumulator root to the carried z.
        let (old_hi, old_lo) = hash_bits_to_limbs(cs.namespace(|| "old_limbs"), &old_bits)?;
        cs.enforce(|| "old_hi == z[0]", |lc| lc + old_hi.get_variable() - z[0].get_variable(), |lc| lc + CS::one(), |lc| lc);
        cs.enforce(|| "old_lo == z[1]", |lc| lc + old_lo.get_variable() - z[1].get_variable(), |lc| lc + CS::one(), |lc| lc);

        // Spend the input coin: input_leaf -> EMPTY (old -> mid).
        let (in_leaf, in_amount) = coin_commit(cs, "in", &self.input_coin)?;
        enforce_transition_bits(cs, "spend", &old_bits, &mid_bits, &in_leaf, &empty_bits, &self.spend_path)?;

        // Create the output coin: EMPTY -> output_leaf (mid -> new).
        let (out_leaf, out_amount) = coin_commit(cs, "out", &self.output_coin)?;
        enforce_transition_bits(cs, "add", &mid_bits, &new_bits, &empty_bits, &out_leaf, &self.add_path)?;

        // Value conservation: amount_in == amount_out + fee, fee ∈ [0, 2^64).
        let fee = AllocatedNum::alloc(cs.namespace(|| "fee"), || Ok(F::from(self.fee)))?;
        let mut fee_bits = LinearCombination::<F>::zero();
        for i in 0..64 {
            let b = AllocatedBit::alloc(cs.namespace(|| format!("fee_bit_{i}")), Some((self.fee >> i) & 1 == 1))?;
            fee_bits = fee_bits + (pow2::<F>(i), b.get_variable());
        }
        // fee == Σ fee_bit·2^i  (range-checks fee to 64 bits, so fee ≥ 0)
        cs.enforce(|| "fee is 64-bit", |_| fee_bits, |lc| lc + CS::one(), |lc| lc + fee.get_variable());
        // amount_in == amount_out + fee  (no inflation; amount_out ≤ amount_in)
        cs.enforce(
            || "amount_in == amount_out + fee",
            |lc| lc + out_amount.get_variable() + fee.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + in_amount.get_variable(),
        );

        // new accumulator root -> z'.
        let (new_acc_hi, new_acc_lo) = hash_bits_to_limbs(cs.namespace(|| "new_limbs"), &new_bits)?;
        let txcount = AllocatedNum::alloc(cs.namespace(|| "txcount'"), || {
            Ok(z[2].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "txcount' = txcount + 1",
            |lc| lc + z[2].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + txcount.get_variable(),
        );

        Ok(vec![new_acc_hi, new_acc_lo, txcount])
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
    type C1 = CoinTxStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn coin(tag: &[u8], amount: u64) -> Coin {
        Coin { txid: double_sha256(tag), vout: 0, amount, spk_hash: double_sha256(b"spk") }
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
    fn conserving_tx_verifies() {
        let e = EMPTY_LEAF;
        let cin = coin(b"in", 50_000_000);
        let cout = coin(b"out", 30_000_000); // fee = 20_000_000

        let seed = [cin.leaf(), e, e, e];
        let mid = [e, e, e, e];
        let new = [e, cout.leaf(), e, e];

        let steps = vec![CoinTxStep::new(
            root_of(&seed), root_of(&mid), root_of(&new),
            cin, path_of(&seed, 0),
            cout, path_of(&mid, 1),
            20_000_000,
        )];
        let (a_hi, a_lo) = hash_to_limbs::<S1>(&root_of(&seed));
        let zn = run(&steps, [a_hi, a_lo, S1::from(0u64)]).expect("verify");

        let (n_hi, n_lo) = hash_to_limbs::<S1>(&root_of(&new));
        assert_eq!(zn[0], n_hi, "acc_hi = root(new)");
        assert_eq!(zn[1], n_lo, "acc_lo");
        assert_eq!(zn[2], S1::from(1u64), "one tx");
    }

    #[test]
    fn inflating_tx_is_rejected() {
        let e = EMPTY_LEAF;
        let cin = coin(b"in", 50_000_000);
        let cout = coin(b"out", 100_000_000); // output > input: minting coins

        let seed = [cin.leaf(), e, e, e];
        let mid = [e, e, e, e];
        let new = [e, cout.leaf(), e, e];

        // No non-negative fee can satisfy 50M == 100M + fee. Prover tries fee = 0.
        let steps = vec![CoinTxStep::new(
            root_of(&seed), root_of(&mid), root_of(&new),
            cin, path_of(&seed, 0),
            cout, path_of(&mid, 1),
            0,
        )];
        let (a_hi, a_lo) = hash_to_limbs::<S1>(&root_of(&seed));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&steps, [a_hi, a_lo, S1::from(0u64)])));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "a tx creating more value than it spends must not verify");
    }
}
