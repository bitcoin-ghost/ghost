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

use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, pack_be, sha256d_bits};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

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
    fn hashed_step_derives_tip_and_links_chain() {
        let genesis = [0u8; 32];
        let h1 = hdr(genesis, 1);
        let hash1 = h1.hash();
        let h2 = hdr(hash1, 2);
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
}
