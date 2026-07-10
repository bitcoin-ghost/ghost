//! Phase 3 (real) — block step with a genuine UTXO **transition**: each folded
//! block verifies PoW *and* applies a transaction that **spends one input** and
//! **creates one output** against the SMT accumulator.
//!
//! `z = [tip_hi, tip_lo, cumwork, acc_hi, acc_lo, txcount]`. Per block:
//!  1. **chain** — header PoW + linkage + derived tip + work (as
//!     [`crate::hashed_step`]); and
//!  2. **UTXO transition** — two chained SMT updates ([`crate::smt_update`]):
//!     spend `input_utxo → EMPTY` (root: `acc → mid`), then add
//!     `EMPTY → output_utxo` (root: `mid → acc'`). Net set size is conserved
//!     (one spent, one created), so the step counts *transactions* in `txcount`.
//!
//! A valid fold now attests the full statement: *a sufficient-PoW chain whose
//! UTXO accumulator is the exact result of spending each block's input and
//! creating its output.* SPIKE: exactly one input + one output per block; real
//! variable tx fan-out (fixed-max + padding for uniform R1CS) is the follow-on.

use crate::hashed_step::enforce_pow_fixed_exp32;
use crate::merkle::PathElem;
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, pack_be, sha256d_bits};
use crate::smt_update::{enforce_transition, EMPTY_LEAF};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct BlockTxStep<F: PrimeField> {
    pub header: [u8; 80],
    pub work: F,
    /// Accumulator root before the block — bound to the carried `z`.
    pub prev_acc_root: crate::U256,
    /// Root after spending the input, before adding the output.
    pub mid_acc_root: crate::U256,
    /// Root after adding the output — becomes `z'`.
    pub new_acc_root: crate::U256,
    /// The UTXO the block's tx spends, and its authentication path.
    pub input_utxo: crate::U256,
    pub spend_path: Vec<PathElem>,
    /// The UTXO the block's tx creates, and its authentication path.
    pub output_utxo: crate::U256,
    pub add_path: Vec<PathElem>,
}

impl<F: PrimeField> StepCircuit<F> for BlockTxStep<F> {
    fn arity(&self) -> usize {
        6 // [tip_hi, tip_lo, cumwork, acc_hi, acc_lo, txcount]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // --- 1. chain / PoW ---
        let bits = bytes_to_bits(cs.namespace(|| "hdr"), &self.header)?;
        let prev_hi = pack_be(cs.namespace(|| "prev_hi"), &bits[32..160])?;
        let prev_lo = pack_be(cs.namespace(|| "prev_lo"), &bits[160..288])?;
        cs.enforce(|| "link_hi", |lc| lc + prev_hi.get_variable() - z[0].get_variable(), |lc| lc + CS::one(), |lc| lc);
        cs.enforce(|| "link_lo", |lc| lc + prev_lo.get_variable() - z[1].get_variable(), |lc| lc + CS::one(), |lc| lc);

        let hash_bits = sha256d_bits(cs.namespace(|| "hdr_hash"), &bits)?;
        let (new_tip_hi, new_tip_lo) = hash_bits_to_limbs(cs.namespace(|| "tip"), &hash_bits)?;
        enforce_pow_fixed_exp32(cs.namespace(|| "pow"), &bits, &hash_bits)?;

        let work = AllocatedNum::alloc(cs.namespace(|| "work"), || Ok(self.work))?;
        let cumwork = AllocatedNum::alloc(cs.namespace(|| "cumwork'"), || {
            let prev = z[2].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(prev + work.get_value().ok_or(SynthesisError::AssignmentMissing)?)
        })?;
        cs.enforce(
            || "cumwork' = cumwork + work",
            |lc| lc + z[2].get_variable() + work.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + cumwork.get_variable(),
        );

        // --- 2. UTXO transition (spend input, then add output) ---
        let prev_bits = bytes_to_bits(cs.namespace(|| "acc"), &self.prev_acc_root)?;
        let mid_bits = bytes_to_bits(cs.namespace(|| "mid"), &self.mid_acc_root)?;
        let new_bits = bytes_to_bits(cs.namespace(|| "newacc"), &self.new_acc_root)?;

        // Bind prev accumulator root to the carried z.
        let (acc_hi, acc_lo) = hash_bits_to_limbs(cs.namespace(|| "acc_limbs"), &prev_bits)?;
        cs.enforce(|| "acc_hi == z[3]", |lc| lc + acc_hi.get_variable() - z[3].get_variable(), |lc| lc + CS::one(), |lc| lc);
        cs.enforce(|| "acc_lo == z[4]", |lc| lc + acc_lo.get_variable() - z[4].get_variable(), |lc| lc + CS::one(), |lc| lc);

        // Spend: input_utxo -> EMPTY (acc -> mid).
        enforce_transition(cs, "spend", &prev_bits, &mid_bits, &self.input_utxo, &EMPTY_LEAF, &self.spend_path)?;
        // Add: EMPTY -> output_utxo (mid -> new).
        enforce_transition(cs, "add", &mid_bits, &new_bits, &EMPTY_LEAF, &self.output_utxo, &self.add_path)?;

        // new accumulator root -> z'. Pack concrete bits — safe.
        let (new_acc_hi, new_acc_lo) = hash_bits_to_limbs(cs.namespace(|| "acc'"), &new_bits)?;

        // txcount' = txcount + 1.
        let txcount = AllocatedNum::alloc(cs.namespace(|| "txcount'"), || {
            Ok(z[5].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "txcount' = txcount + 1",
            |lc| lc + z[5].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + txcount.get_variable(),
        );

        Ok(vec![new_tip_hi, new_tip_lo, cumwork, new_acc_hi, new_acc_lo, txcount])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cumulative_pow::{double_sha256, BlockHeader};
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
    type C1 = BlockTxStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn hdr(prev: crate::U256, nonce: u32) -> BlockHeader {
        BlockHeader { version: 1, prev_hash: prev, merkle_root: [7u8; 32], time: 1_700_000_000, bits: 0x207f_ffff, nonce }
    }
    fn mine(prev: crate::U256) -> BlockHeader {
        for nonce in 0..1_000_000u32 {
            let h = hdr(prev, nonce);
            if crate::cumulative_pow::fold_header(prev, 0, &h).is_ok() {
                return h;
            }
        }
        panic!("no valid-PoW nonce");
    }

    fn run(steps: &[C1], z0: [S1; 6]) -> Result<Vec<S1>, nova_snark::errors::NovaError> {
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
    fn blocks_spend_and_create_utxos_with_valid_pow() {
        let e = EMPTY_LEAF;
        let ua = double_sha256(b"utxo-a");
        let ub = double_sha256(b"utxo-b");
        let uc = double_sha256(b"utxo-c");

        // Seed set: slot0 = ua.
        let seed = [ua, e, e, e];
        // Block 1: spend ua@0 -> EMPTY (mid1), add ub@1 (new1).
        let mid1 = [e, e, e, e];
        let new1 = [e, ub, e, e];
        // Block 2: spend ub@1 -> EMPTY (mid2), add uc@2 (new2).
        let mid2 = [e, e, e, e];
        let new2 = [e, e, uc, e];

        let genesis = [0u8; 32];
        let h1 = mine(genesis);
        let tip1 = h1.hash();
        let h2b = mine(tip1);
        let tip2 = h2b.hash();

        let steps = vec![
            BlockTxStep {
                header: h1.serialize(), work: S1::from(3u64),
                prev_acc_root: root_of(&seed), mid_acc_root: root_of(&mid1), new_acc_root: root_of(&new1),
                input_utxo: ua, spend_path: path_of(&seed, 0),
                output_utxo: ub, add_path: path_of(&mid1, 1),
            },
            BlockTxStep {
                header: h2b.serialize(), work: S1::from(5u64),
                prev_acc_root: root_of(&new1), mid_acc_root: root_of(&mid2), new_acc_root: root_of(&new2),
                input_utxo: ub, spend_path: path_of(&new1, 1),
                output_utxo: uc, add_path: path_of(&mid2, 2),
            },
        ];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let (a_hi, a_lo) = hash_to_limbs::<S1>(&root_of(&seed));
        let zn = run(&steps, [g_hi, g_lo, S1::from(0u64), a_hi, a_lo, S1::from(0u64)]).expect("verify");

        let (t_hi, t_lo) = hash_to_limbs::<S1>(&tip2);
        let (ac_hi, ac_lo) = hash_to_limbs::<S1>(&root_of(&new2));
        assert_eq!(zn[0], t_hi, "tip_hi");
        assert_eq!(zn[1], t_lo, "tip_lo");
        assert_eq!(zn[2], S1::from(8u64), "cumwork");
        assert_eq!(zn[3], ac_hi, "acc_hi = root(new2)");
        assert_eq!(zn[4], ac_lo, "acc_lo");
        assert_eq!(zn[5], S1::from(2u64), "two txs");
    }

    #[test]
    fn spending_a_utxo_not_in_the_set_fails() {
        let e = EMPTY_LEAF;
        let phantom = double_sha256(b"never-created");
        let ub = double_sha256(b"utxo-b");
        let seed = [e, e, e, e]; // empty set
        let mid1 = [e, e, e, e];
        let new1 = [e, ub, e, e];
        let genesis = [0u8; 32];
        let h1 = mine(genesis);
        let steps = vec![BlockTxStep {
            header: h1.serialize(), work: S1::from(3u64),
            prev_acc_root: root_of(&seed), mid_acc_root: root_of(&mid1), new_acc_root: root_of(&new1),
            input_utxo: phantom, spend_path: path_of(&seed, 0),
            output_utxo: ub, add_path: path_of(&mid1, 1),
        }];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let (a_hi, a_lo) = hash_to_limbs::<S1>(&root_of(&seed));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&steps, [g_hi, g_lo, S1::from(0u64), a_hi, a_lo, S1::from(0u64)])
        }));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "spending a phantom UTXO must not verify");
    }
}
