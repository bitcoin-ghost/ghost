//! Phase 3 (integration) — the **block step**: one fold step advances the chain
//! *and* the UTXO set together, which is the actual shape of the zero-sync
//! recursion.
//!
//! `z = [tip_hi, tip_lo, cumwork, acc_hi, acc_lo, count]`. Per folded block:
//!  1. **PoW / chain** (as [`crate::hashed_step::HashedPowStep`]): witness the
//!     80-byte header, enforce `header.prev_hash == z.tip` (linkage), derive the
//!     new tip `= SHA256d(header)`, enforce `hash_be <= target(nBits)`, accumulate
//!     work; and
//!  2. **UTXO / accumulator** (as [`crate::accumulator_add::AccumulatorAddStep`]):
//!     bind the carried accumulator root, append the block's new UTXO
//!     (`acc' = SHA256d(acc || utxo)`), bump the count.
//!
//! So a valid fold attests: *a correctly-hashed, correctly-linked, sufficient-PoW
//! chain whose UTXO accumulator is the result of applying each block.* SPIKE: one
//! representative UTXO per block (the coinbase output) — a real block adds every
//! tx output and spends its inputs (variable fan-out), the next increment.

use crate::hashed_step::enforce_pow_fixed_exp32;
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, pack_be, sha256d_bits};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct BlockStep<F: PrimeField> {
    /// The block header (80 bytes).
    pub header: [u8; 80],
    /// PoW/chain work contributed by this block.
    pub work: F,
    /// The accumulator root before this block — bound to the carried `z`.
    pub prev_acc_root: crate::U256,
    /// The UTXO leaf this block appends (spike: the coinbase output).
    pub new_utxo: crate::U256,
}

impl<F: PrimeField> StepCircuit<F> for BlockStep<F> {
    fn arity(&self) -> usize {
        6 // [tip_hi, tip_lo, cumwork, acc_hi, acc_lo, count]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // --- 1. PoW / chain ---
        let bits = bytes_to_bits(cs.namespace(|| "hdr"), &self.header)?;
        // Linkage: header.prev_hash (bits 32..288) == carried tip.
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

        // --- 2. UTXO / accumulator ---
        // Bind the carried accumulator root (pack concrete bits, enforce == z).
        let acc_bits = bytes_to_bits(cs.namespace(|| "acc"), &self.prev_acc_root)?;
        let (acc_hi, acc_lo) = hash_bits_to_limbs(cs.namespace(|| "acc_limbs"), &acc_bits)?;
        cs.enforce(|| "acc_hi == z[3]", |lc| lc + acc_hi.get_variable() - z[3].get_variable(), |lc| lc + CS::one(), |lc| lc);
        cs.enforce(|| "acc_lo == z[4]", |lc| lc + acc_lo.get_variable() - z[4].get_variable(), |lc| lc + CS::one(), |lc| lc);

        // acc' = SHA256d(acc || utxo).
        let utxo_bits = bytes_to_bits(cs.namespace(|| "utxo"), &self.new_utxo)?;
        let mut concat = acc_bits;
        concat.extend_from_slice(&utxo_bits);
        let new_acc_bits = sha256d_bits(cs.namespace(|| "acc_hash"), &concat)?;
        let (new_acc_hi, new_acc_lo) = hash_bits_to_limbs(cs.namespace(|| "acc'"), &new_acc_bits)?;

        let count = AllocatedNum::alloc(cs.namespace(|| "count'"), || {
            Ok(z[5].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "count' = count + 1",
            |lc| lc + z[5].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + count.get_variable(),
        );

        Ok(vec![new_tip_hi, new_tip_lo, cumwork, new_acc_hi, new_acc_lo, count])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulator_add::add_native;
    use crate::cumulative_pow::{double_sha256, BlockHeader};
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
    type C1 = BlockStep<S1>;
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
    fn mine_invalid(prev: crate::U256) -> BlockHeader {
        for nonce in 0..1_000_000u32 {
            let h = hdr(prev, nonce);
            if crate::cumulative_pow::fold_header(prev, 0, &h) == Err(crate::cumulative_pow::PowError::InsufficientWork) {
                return h;
            }
        }
        panic!("no invalid-PoW nonce");
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
    fn two_valid_blocks_advance_chain_and_utxo_set() {
        let genesis = [0u8; 32];
        let empty_acc = [0u8; 32];

        let h1 = mine(genesis);
        let tip1 = h1.hash();
        let utxo1 = double_sha256(b"coinbase-1");
        let acc1 = add_native(empty_acc, utxo1);

        let h2 = mine(tip1);
        let tip2 = h2.hash();
        let utxo2 = double_sha256(b"coinbase-2");
        let acc2 = add_native(acc1, utxo2);

        let steps = vec![
            BlockStep { header: h1.serialize(), work: S1::from(3u64), prev_acc_root: empty_acc, new_utxo: utxo1 },
            BlockStep { header: h2.serialize(), work: S1::from(5u64), prev_acc_root: acc1, new_utxo: utxo2 },
        ];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let (a_hi, a_lo) = hash_to_limbs::<S1>(&empty_acc);
        let zn = run(&steps, [g_hi, g_lo, S1::from(0u64), a_hi, a_lo, S1::from(0u64)]).expect("verify");

        let (t_hi, t_lo) = hash_to_limbs::<S1>(&tip2);
        let (ac_hi, ac_lo) = hash_to_limbs::<S1>(&acc2);
        assert_eq!(zn[0], t_hi, "tip_hi");
        assert_eq!(zn[1], t_lo, "tip_lo");
        assert_eq!(zn[2], S1::from(8u64), "cumwork = 3 + 5");
        assert_eq!(zn[3], ac_hi, "acc_hi");
        assert_eq!(zn[4], ac_lo, "acc_lo");
        assert_eq!(zn[5], S1::from(2u64), "two UTXOs");
    }

    #[test]
    fn invalid_pow_block_fails_to_verify() {
        let genesis = [0u8; 32];
        let empty_acc = [0u8; 32];
        let bad = mine_invalid(genesis);
        let utxo = double_sha256(b"coinbase");
        let steps = vec![BlockStep { header: bad.serialize(), work: S1::from(3u64), prev_acc_root: empty_acc, new_utxo: utxo }];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let (a_hi, a_lo) = hash_to_limbs::<S1>(&empty_acc);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&steps, [g_hi, g_lo, S1::from(0u64), a_hi, a_lo, S1::from(0u64)])
        }));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "insufficient-PoW block must not verify");
    }
}
