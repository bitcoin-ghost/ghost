//! Phase 1c (integration) — folding step that **derives** the tip in-circuit.
//!
//! `HashedPowStep` takes the raw 80-byte header, witnesses it as bits, and:
//! 1. extracts the header's `prev_hash` field (bytes 4..36) and enforces it
//!    equals the running tip `z` (chain linkage), and
//! 2. runs `sha256d` over the header bits and packs the result into the new tip
//!    limbs — so the tip is *computed*, not witnessed.
//!
//! 3. enforces real PoW `hash_be <= target(nBits)` for the actual, **variable**
//!    nBits ([`expand_target_be`] reconstructs the 256-bit target from the
//!    compact bits at any exponent), and accumulates work.
//!
//! So a valid fold proves *a correctly-hashed, correctly-linked chain with
//! sufficient proof-of-work at its real difficulty*.
//!
//! `z = [tip_hi, tip_lo, cumwork]`.

use crate::compare::leq_be;
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, pack_be, sha256d_bits};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{AllocatedBit, Boolean, ConstraintSystem, SynthesisError, Variable};
use nova_snark::traits::circuit::StepCircuit;

/// Expand the compact nBits into the full 256-bit big-endian target, in-circuit,
/// for exponent ∈ [4, 32] (every real block). `target = mantissa · 256^(exp−3)`;
/// the mantissa's most-significant byte lands at big-endian index `32 − exp`,
/// matching [`crate::cumulative_pow::target_from_bits`]. A one-hot over the
/// exponent selects the byte placement; exponents outside [4, 32] make the
/// one-hot unsatisfiable (rejected — sub-3 exponents never occur on real chains).
///
/// nBits is header bytes 72..76 (LE u32): byte 72 = mantissa LSB, byte 74 =
/// mantissa MSB, byte 75 = exponent. `header_bits` is MSB-first per byte.
pub(crate) fn expand_target_be<F, CS>(
    mut cs: CS,
    header_bits: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let m_msb = &header_bits[592..600]; // byte 74 (mantissa MSB)
    let m_mid = &header_bits[584..592]; // byte 73
    let m_lsb = &header_bits[576..584]; // byte 72 (mantissa LSB)
    let exp_num = pack_be(cs.namespace(|| "exp_val"), &header_bits[600..608])?;

    // Concrete exponent (when a witness is present) to allocate the one-hot.
    let exp_concrete: Option<u64> = {
        let mut acc = 0u64;
        let mut known = true;
        for (i, b) in header_bits[600..608].iter().enumerate() {
            match b.get_value() {
                Some(v) => {
                    if v {
                        acc |= 1 << (7 - i);
                    }
                }
                None => known = false,
            }
        }
        known.then_some(acc)
    };

    // One-hot indicator over exponent e ∈ [4, 32].
    let mut onehot: Vec<AllocatedBit> = Vec::with_capacity(29);
    for e in 4u64..=32 {
        let is = exp_concrete.map(|x| x == e);
        onehot.push(AllocatedBit::alloc(cs.namespace(|| format!("oh_{e}")), is)?);
    }
    // Exactly one indicator is set.
    let oh_vars: Vec<Variable> = onehot.iter().map(|b| b.get_variable()).collect();
    {
        let vs = oh_vars.clone();
        cs.enforce(
            || "onehot sum == 1",
            |lc| vs.iter().fold(lc, |acc, v| acc + *v),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );
    }
    // The selected index equals the header's exponent.
    {
        let ws: Vec<(F, Variable)> = (4u64..=32).map(|e| (F::from(e), onehot[(e - 4) as usize].get_variable())).collect();
        cs.enforce(
            || "onehot matches exponent",
            |lc| ws.iter().fold(lc, |acc, (c, v)| acc + (*c, *v)),
            |lc| lc + CS::one(),
            |lc| lc + exp_num.get_variable(),
        );
    }

    // target byte k (BE) = mantissa MSB if k == 32−e, mid if 33−e, LSB if 34−e.
    let mut target = Vec::with_capacity(256);
    for k in 0..32i64 {
        for b in 0..8usize {
            let mut acc = Boolean::constant(false);
            for (e, mant) in [(32 - k, m_msb), (33 - k, m_mid), (34 - k, m_lsb)] {
                if !(4..=32).contains(&e) {
                    continue;
                }
                let sel = Boolean::from(onehot[(e - 4) as usize].clone());
                let term = Boolean::and(cs.namespace(|| format!("and_{k}_{b}_{e}")), &sel, &mant[b])?;
                acc = Boolean::or(cs.namespace(|| format!("or_{k}_{b}_{e}")), &acc, &term)?;
            }
            target.push(acc);
        }
    }
    Ok(target)
}

/// Enforce real PoW: `hash_be <= target(nBits)` for the actual, variable nBits.
/// `header_bits` = 640 header bits; `hash_bits` = 256 sha256d output bits
/// (internal little-endian byte order, reversed here to a big-endian number).
pub(crate) fn enforce_pow<F, CS>(
    mut cs: CS,
    header_bits: &[Boolean],
    hash_bits: &[Boolean],
) -> Result<(), SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let target = expand_target_be(cs.namespace(|| "target"), header_bits)?;

    let mut hash_be = Vec::with_capacity(256);
    for byte in (0..32).rev() {
        hash_be.extend_from_slice(&hash_bits[byte * 8..byte * 8 + 8]);
    }

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
        enforce_pow(cs.namespace(|| "pow"), &bits, &hash_bits)?;

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

    /// The in-circuit target expansion must equal the native oracle across a
    /// range of exponents (fast — no folding, just the gadget).
    #[test]
    fn target_expansion_matches_native() {
        use crate::cumulative_pow::target_from_bits;
        use crate::sha256d_gadget::{bits_to_bytes, bytes_to_bits};
        use nova_snark::frontend::solver::SatisfyingAssignment;
        use nova_snark::frontend::ConstraintSystem as _;

        for bits in [0x207f_ffffu32, 0x1f7f_ffff, 0x1d00_ffff, 0x1b04_04cb, 0x1a44_b9f2, 0x1803_4567, 0x1707_a429] {
            let h = BlockHeader { version: 1, prev_hash: [0u8; 32], merkle_root: [7u8; 32], time: 1, bits, nonce: 0 };
            let bytes = h.serialize();
            let mut cs = SatisfyingAssignment::<PallasEngine>::new();
            let hbits = bytes_to_bits(cs.namespace(|| "h"), &bytes).unwrap();
            let target = expand_target_be(cs.namespace(|| "t"), &hbits).unwrap();
            assert_eq!(bits_to_bytes(&target), target_from_bits(bits), "nBits {bits:#010x}");
        }
    }

    /// Fold a header mined against a **non-`0x20`** exponent (0x1f7fffff, exp 31)
    /// — proves the variable-nBits PoW gadget accepts real difficulty, end to end.
    #[test]
    fn valid_pow_nonstandard_exponent_folds() {
        let bits = 0x1f7f_ffffu32; // target ~2^247: harder than regtest, still mineable
        let genesis = [0u8; 32];
        let mut header = None;
        for nonce in 0..2_000_000u32 {
            let h = BlockHeader { version: 1, prev_hash: genesis, merkle_root: [7u8; 32], time: 1_700_000_000, bits, nonce };
            if crate::cumulative_pow::fold_header(genesis, 0, &h).is_ok() {
                header = Some(h);
                break;
            }
        }
        let h = header.expect("mine a valid nonce at exp 31");

        let steps = vec![HashedPowStep { header: h.serialize(), work: S1::from(1u64) }];
        let (g_hi, g_lo) = hash_to_limbs::<S1>(&genesis);
        let zn = run(&steps, [g_hi, g_lo, S1::from(0u64)]).expect("verify");
        let (t_hi, t_lo) = hash_to_limbs::<S1>(&h.hash());
        assert_eq!(zn[0], t_hi, "tip_hi");
        assert_eq!(zn[1], t_lo, "tip_lo");
    }
}
