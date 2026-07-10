//! Phase 1c (integration) — folding step that **derives** the tip in-circuit.
//!
//! `HashedPowStep` takes the raw 80-byte header, witnesses it as bits, and:
//! 1. extracts the header's `prev_hash` field (bytes 4..36) and enforces it
//!    equals the running tip `z` (chain linkage), and
//! 2. runs `sha256d` over the header bits and packs the result into the new tip
//!    limbs — so the tip is *computed*, not witnessed.
//!
//! What's still missing for a full PoW proof: the target comparison
//! (`hash_be <= target(nBits)`), which is the final 1c gadget. Until then this
//! proves *a correctly-hashed, correctly-linked chain* — everything but the
//! difficulty check.
//!
//! `z = [tip_hi, tip_lo, cumwork]`.

use crate::compare::leq_be;
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, pack_be, sha256d_bits};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

/// Enforce real PoW: `hash_be <= target(nBits)`.
///
/// SPIKE simplification: assumes the compact exponent is `0x20` (regtest / the
/// 3-mantissa-bytes-at-the-front case), which it *enforces*, so the target is
/// just `mantissa_bytes ++ zeros`. Variable-exponent nBits expansion (a byte-
/// position mux keyed on the exponent) is the documented hardening — until then
/// this proves PoW for a fixed difficulty. `header_bits` = 640 header bits;
/// `hash_bits` = 256 sha256d output bits (internal order).
pub(crate) fn enforce_pow_fixed_exp32<F, CS>(
    mut cs: CS,
    header_bits: &[Boolean],
    hash_bits: &[Boolean],
) -> Result<(), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    // nBits is header bytes 72..76 (LE u32): exponent = byte 75, mantissa =
    // bytes 72..75. Enforce exponent bits (600..608) == 0x20 = 0b0010_0000.
    let exp_expected = [false, false, true, false, false, false, false, false];
    for (i, &e) in exp_expected.iter().enumerate() {
        Boolean::enforce_equal(
            cs.namespace(|| format!("exp_bit_{i}")),
            &header_bits[600 + i],
            &Boolean::constant(e),
        )?;
    }

    // target_be = mantissa big-endian bytes (byte74,73,72) then 232 zero bits.
    let mut target = Vec::with_capacity(256);
    target.extend_from_slice(&header_bits[592..600]); // byte 74 (mantissa MSB)
    target.extend_from_slice(&header_bits[584..592]); // byte 73
    target.extend_from_slice(&header_bits[576..584]); // byte 72 (mantissa LSB)
    target.resize(256, Boolean::constant(false));

    // hash_be = reverse the 32 output bytes (internal LE -> big-endian number).
    let mut hash_be = Vec::with_capacity(256);
    for byte in (0..32).rev() {
        hash_be.extend_from_slice(&hash_bits[byte * 8..byte * 8 + 8]);
    }

    // Enforce hash_be <= target.
    let leq = leq_be(cs.namespace(|| "pow_leq"), &hash_be, &target)?;
    Boolean::enforce_equal(cs.namespace(|| "pow_holds"), &leq, &Boolean::constant(true))
}

#[derive(Clone, Debug)]
pub struct HashedPowStep<F: PrimeField> {
    pub header: [u8; 80],
    pub work: F,
}

impl<F: PrimeField> StepCircuit<F> for HashedPowStep<F> {
    fn arity(&self) -> usize {
        3
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        // 80 header bytes → 640 bits (MSB-first per byte).
        let bits = bytes_to_bits(cs.namespace(|| "hdr"), &self.header)?;

        // Chain linkage: header.prev_hash = bytes 4..36 = bits 32..288, split
        // into the same two 128-bit limbs as hash_to_limbs, must equal z.tip.
        let prev_hi = pack_be(cs.namespace(|| "prev_hi"), &bits[32..160])?;
        let prev_lo = pack_be(cs.namespace(|| "prev_lo"), &bits[160..288])?;
        cs.enforce(
            || "link_hi",
            |lc| lc + prev_hi.get_variable() - z[0].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );
        cs.enforce(
            || "link_lo",
            |lc| lc + prev_lo.get_variable() - z[1].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );

        // Derive the new tip in-circuit.
        let hash_bits = sha256d_bits(cs.namespace(|| "hash"), &bits)?;
        let (new_hi, new_lo) = hash_bits_to_limbs(cs.namespace(|| "tip"), &hash_bits)?;

        // Enforce real PoW: hash_be <= target(nBits).
        enforce_pow_fixed_exp32(cs.namespace(|| "pow"), &bits, &hash_bits)?;

        // Work accumulation.
        let work = AllocatedNum::alloc(cs.namespace(|| "work"), || Ok(self.work))?;
        let cumwork = AllocatedNum::alloc(cs.namespace(|| "cumwork'"), || {
            let prev = z[2].get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let w = work.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(prev + w)
        })?;
        cs.enforce(
            || "cumwork' = cumwork + work",
            |lc| lc + z[2].get_variable() + work.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + cumwork.get_variable(),
        );

        Ok(vec![new_hi, new_lo, cumwork])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cumulative_pow::BlockHeader;
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
    type C1 = HashedPowStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn hdr(prev: crate::U256, nonce: u32) -> BlockHeader {
        BlockHeader { version: 1, prev_hash: prev, merkle_root: [7u8; 32], time: 1_700_000_000, bits: 0x207f_ffff, nonce }
    }

    /// Find a nonce whose header has valid PoW under the regtest target.
    fn mine(prev: crate::U256) -> BlockHeader {
        for nonce in 0..1_000_000u32 {
            let h = hdr(prev, nonce);
            if crate::cumulative_pow::fold_header(prev, 0, &h).is_ok() {
                return h;
            }
        }
        panic!("no valid-PoW nonce found");
    }

    /// Find a nonce whose header FAILS PoW (hash > target).
    fn mine_invalid(prev: crate::U256) -> BlockHeader {
        for nonce in 0..1_000_000u32 {
            let h = hdr(prev, nonce);
            if crate::cumulative_pow::fold_header(prev, 0, &h)
                == Err(crate::cumulative_pow::PowError::InsufficientWork)
            {
                return h;
            }
        }
        panic!("no invalid-PoW nonce found");
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
    fn valid_pow_chain_folds_derives_tip_and_links() {
        let genesis = [0u8; 32];
        let h1 = mine(genesis);
        let hash1 = h1.hash();
        let h2 = mine(hash1);
        let hash2 = h2.hash();

        let steps = vec![
            HashedPowStep { header: h1.serialize(), work: S1::from(3u64) },
            HashedPowStep { header: h2.serialize(), work: S1::from(5u64) },
        ];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let zn = run(&steps, [g_hi, g_lo, S1::from(0u64)]).expect("verify");

        let (t_hi, t_lo) = hash_to_limbs::<S1>(&hash2);
        assert_eq!(zn[0], t_hi, "derived tip_hi must equal native hash2");
        assert_eq!(zn[1], t_lo, "derived tip_lo must equal native hash2");
        assert_eq!(zn[2], S1::from(8u64), "cumwork = 3 + 5");
    }

    #[test]
    fn invalid_pow_fails_to_verify() {
        let genesis = [0u8; 32];
        let bad = mine_invalid(genesis);
        let steps = vec![HashedPowStep { header: bad.serialize(), work: S1::from(3u64) }];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run(&steps, [g_hi, g_lo, S1::from(0u64)])
        }));
        let rejected = matches!(result, Err(_) | Ok(Err(_)));
        assert!(rejected, "a header with insufficient PoW must not produce a valid proof");
    }
}
