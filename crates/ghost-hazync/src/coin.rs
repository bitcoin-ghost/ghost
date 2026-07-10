//! Phase 3 (realism) — **coin-committed** UTXO leaves.
//!
//! Until now accumulator leaves were opaque 32-byte values. A real UTXO commits
//! to the coin it represents, so the leaf is a hash of the coin's fields:
//!
//! ```text
//! leaf = SHA256d( txid[32] || vout_le[4] || amount_le[8] || spk_hash[32] )
//! ```
//!
//! (`spk_hash` = SHA256 of the `scriptPubKey`, keeping the leaf a fixed 76-byte
//! preimage.) [`coin_leaf_bits`] computes this **in-circuit**, so the accumulator
//! provably holds a commitment to real coin data and a spend must present the
//! true `(txid, vout, amount, script)` — not an arbitrary 32 bytes.
//!
//! [`CoinSmtAddStep`] folds a coin into the SMT accumulator ([`crate::smt_update`]):
//! it derives the leaf from the coin fields and adds it at an empty slot,
//! evolving the carried root. Binding a *spend* to the coin being consumed reuses
//! the same commitment on the `old_leaf` side — the next increment.

use crate::merkle::PathElem;
use crate::sha256d_gadget::{bytes_to_bits, hash_bits_to_limbs, sha256d_bits};
use crate::smt_update::{enforce_transition_bits, EMPTY_LEAF};
use ff::PrimeField;
use nova_snark::frontend::num::AllocatedNum;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

/// A UTXO's committed fields.
#[derive(Clone, Copy, Debug)]
pub struct Coin {
    pub txid: crate::U256,
    pub vout: u32,
    pub amount: u64,
    /// `SHA256(scriptPubKey)`.
    pub spk_hash: crate::U256,
}

impl Coin {
    /// The 76-byte commitment preimage: `txid || vout_le || amount_le || spk_hash`.
    pub fn serialize(&self) -> [u8; 76] {
        let mut out = [0u8; 76];
        out[0..32].copy_from_slice(&self.txid);
        out[32..36].copy_from_slice(&self.vout.to_le_bytes());
        out[36..44].copy_from_slice(&self.amount.to_le_bytes());
        out[44..76].copy_from_slice(&self.spk_hash);
        out
    }

    /// Native oracle: the accumulator leaf for this coin.
    pub fn leaf(&self) -> crate::U256 {
        crate::cumulative_pow::double_sha256(&self.serialize())
    }
}

/// Derive the coin's leaf bits in-circuit: witness the 76-byte serialization and
/// return `SHA256d(...)` (256 `Boolean`s), matching [`Coin::leaf`].
pub fn coin_leaf_bits<F, CS>(cs: &mut CS, tag: &str, coin: &Coin) -> Result<Vec<Boolean>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let bytes = coin.serialize();
    let bits = bytes_to_bits(cs.namespace(|| format!("{tag}_ser")), &bytes)?;
    sha256d_bits(cs.namespace(|| format!("{tag}_leaf")), &bits)
}

#[derive(Clone, Debug)]
pub struct CoinSmtAddStep<F: PrimeField> {
    pub old_root: crate::U256,
    pub new_root: crate::U256,
    pub coin: Coin,
    pub path: Vec<PathElem>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: PrimeField> CoinSmtAddStep<F> {
    pub fn new(old_root: crate::U256, new_root: crate::U256, coin: Coin, path: Vec<PathElem>) -> Self {
        Self { old_root, new_root, coin, path, _marker: std::marker::PhantomData }
    }
}

impl<F: PrimeField> StepCircuit<F> for CoinSmtAddStep<F> {
    fn arity(&self) -> usize {
        3 // [root_hi, root_lo, size]
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        let old_root_bits = bytes_to_bits(cs.namespace(|| "old_root"), &self.old_root)?;
        let new_root_bits = bytes_to_bits(cs.namespace(|| "new_root"), &self.new_root)?;

        // Bind old_root to the carried z.
        let (old_hi, old_lo) = hash_bits_to_limbs(cs.namespace(|| "old_limbs"), &old_root_bits)?;
        cs.enforce(|| "old_hi == z[0]", |lc| lc + old_hi.get_variable() - z[0].get_variable(), |lc| lc + CS::one(), |lc| lc);
        cs.enforce(|| "old_lo == z[1]", |lc| lc + old_lo.get_variable() - z[1].get_variable(), |lc| lc + CS::one(), |lc| lc);

        // Derive the coin's leaf in-circuit and add it at an empty slot.
        let empty_bits = bytes_to_bits(cs.namespace(|| "empty"), &EMPTY_LEAF)?;
        let coin_bits = coin_leaf_bits(cs, "coin", &self.coin)?;
        enforce_transition_bits(cs, "add", &old_root_bits, &new_root_bits, &empty_bits, &coin_bits, &self.path)?;

        // new_root -> z'. Pack concrete bits — safe.
        let (new_hi, new_lo) = hash_bits_to_limbs(cs.namespace(|| "new_limbs"), &new_root_bits)?;

        let size = AllocatedNum::alloc(cs.namespace(|| "size'"), || {
            Ok(z[2].get_value().ok_or(SynthesisError::AssignmentMissing)? + F::ONE)
        })?;
        cs.enforce(
            || "size' = size + 1",
            |lc| lc + z[2].get_variable() + CS::one(),
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
    use crate::sha256d_gadget::bits_to_bytes;
    use crate::smt_update::tests_util::{path_of, root_of};
    use nova_snark::frontend::solver::SatisfyingAssignment;
    use nova_snark::{
        provider::{PallasEngine, VestaEngine},
        traits::{circuit::TrivialCircuit, snark::default_ck_hint, Engine},
        PublicParams, RecursiveSNARK,
    };

    type E1 = PallasEngine;
    type E2 = VestaEngine;
    type S1 = <E1 as Engine>::Scalar;
    type S2 = <E2 as Engine>::Scalar;
    type C1 = CoinSmtAddStep<S1>;
    type C2 = TrivialCircuit<S2>;

    fn sample_coin(tag: &[u8]) -> Coin {
        Coin {
            txid: double_sha256(tag),
            vout: 1,
            amount: 50_000_000,
            spk_hash: double_sha256(b"scriptpubkey"),
        }
    }

    #[test]
    fn in_circuit_coin_leaf_matches_native() {
        let coin = sample_coin(b"tx-a");
        let mut cs = SatisfyingAssignment::<PallasEngine>::new();
        let bits = coin_leaf_bits(&mut cs, "coin", &coin).unwrap();
        assert_eq!(bits_to_bytes(&bits), coin.leaf(), "in-circuit coin leaf must equal native");
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
    fn adds_real_coins_to_the_accumulator() {
        let e = EMPTY_LEAF;
        let c0 = sample_coin(b"coin-0");
        let c1 = sample_coin(b"coin-1");

        // Tree slots hold coin leaves.
        let s0 = [e, e, e, e];
        let s1 = [c0.leaf(), e, e, e];
        let s2 = [c0.leaf(), c1.leaf(), e, e];

        let steps = vec![
            CoinSmtAddStep::new(root_of(&s0), root_of(&s1), c0, path_of(&s0, 0)),
            CoinSmtAddStep::new(root_of(&s1), root_of(&s2), c1, path_of(&s1, 1)),
        ];
        let (h0, l0) = hash_to_limbs::<S1>(&root_of(&s0));
        let zn = run(&steps, [h0, l0, S1::from(0u64)]).expect("verify");

        let (h2, l2) = hash_to_limbs::<S1>(&root_of(&s2));
        assert_eq!(zn[0], h2, "root_hi after two coins");
        assert_eq!(zn[1], l2, "root_lo");
        assert_eq!(zn[2], S1::from(2u64), "two coins");
    }

    #[test]
    fn tampered_amount_breaks_the_commitment() {
        let e = EMPTY_LEAF;
        let c0 = sample_coin(b"coin-0");
        let s0 = [e, e, e, e];
        let s1 = [c0.leaf(), e, e, e]; // new_root committed to the honest coin
        // Prover presents a coin with a different amount → its leaf != committed.
        let mut liar = c0;
        liar.amount = 99_999_999;
        let steps = vec![CoinSmtAddStep::new(root_of(&s0), root_of(&s1), liar, path_of(&s0, 0))];
        let (h0, l0) = hash_to_limbs::<S1>(&root_of(&s0));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&steps, [h0, l0, S1::from(0u64)])));
        assert!(matches!(result, Err(_) | Ok(Err(_))), "a coin with tampered fields must not open to the committed root");
    }
}
