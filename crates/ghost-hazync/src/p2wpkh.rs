//! Phase 3 M4 (capstone) — P2WPKH spend verification, composing the primitives.
//!
//! A P2WPKH output commits to `HASH160(pubkey)` (the 20-byte witness program).
//! A valid spend must show: (1) the revealed compressed pubkey hashes to that
//! program, and (2) the signature `(r, s)` is a valid ECDSA signature for the
//! transaction's sighash under that key.
//!
//! [`verify_key`] does the key-binding half (hash160 + decompression) and is
//! directly tested. [`verify_spend`] adds the ECDSA check ([`crate::ecdsa::verify`])
//! for the full proof; its two 256-bit scalar multiplications make it prover-
//! scale (see the ecdsa module note), so it is validated via its tested pieces
//! and exercised end-to-end when folded into a tx step under the Nova prover.

use crate::ecdsa::{derive_u1_u2, verify as ecdsa_verify};
use crate::nonnative::bignat::BigNat;
use crate::pubkey::decompress;
use crate::ripemd160::hash160_bits;
use crate::secp256k1_ec::Point;
use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};

/// Bind the revealed pubkey to the committed program and recover the curve point:
/// enforce `HASH160(pubkey_bits) == committed_program` (160 bits) and decompress
/// `(x, y_is_odd)` to `(x, y)`. Returns the public-key point `Q`.
pub fn verify_key<Scalar, CS>(
    mut cs: CS,
    pubkey_bits: &[Boolean],
    committed_program: &[Boolean],
    x: &BigNat<Scalar>,
    y_is_odd: &Boolean,
) -> Result<Point<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let h = hash160_bits(cs.namespace(|| "hash160"), pubkey_bits)?;
    for (i, (a, b)) in h.iter().zip(committed_program.iter()).enumerate() {
        Boolean::enforce_equal(cs.namespace(|| format!("prog_bit_{i}")), a, b)?;
    }
    decompress(cs.namespace(|| "decompress"), x, y_is_odd)
}

/// Full P2WPKH spend verification: key binding + ECDSA over the sighash `z`.
#[allow(clippy::too_many_arguments)]
pub fn verify_spend<Scalar, CS>(
    mut cs: CS,
    pubkey_bits: &[Boolean],
    committed_program: &[Boolean],
    x: &BigNat<Scalar>,
    y_is_odd: &Boolean,
    g: &Point<Scalar>,
    z: &BigNat<Scalar>,
    r: &BigNat<Scalar>,
    s: &BigNat<Scalar>,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let q = verify_key(cs.namespace(|| "key"), pubkey_bits, committed_program, x, y_is_odd)?;
    let (u1, u2) = derive_u1_u2(cs.namespace(|| "u1u2"), z, r, s)?;
    ecdsa_verify(cs.namespace(|| "ecdsa"), g, &q, r, &u1, &u2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp256k1_field::alloc_fp;
    use crate::sha256d_gadget::bytes_to_bits;
    use crate::test_cs::TestConstraintSystem;
    use nova_snark::frontend::AllocatedBit;
    use nova_snark::provider::PallasEngine;
    use nova_snark::traits::Engine;
    use num_bigint::BigInt;
    use ripemd::{Digest, Ripemd160};
    use sha2::Sha256;

    type Scalar = <PallasEngine as Engine>::Scalar;

    fn native_hash160(x: &[u8]) -> [u8; 20] {
        Ripemd160::digest(Sha256::digest(x)).into()
    }

    // verify_key binds the compressed generator pubkey to its hash160 program and
    // recovers G — the tested half of a P2WPKH spend.
    #[test]
    fn verify_key_binds_generator_pubkey() {
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let program = native_hash160(&pk);
        let gx = BigInt::parse_bytes(b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16).unwrap();
        let gy = BigInt::parse_bytes(b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16).unwrap();

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let pk_bits = bytes_to_bits(cs.namespace(|| "pk"), &pk).unwrap();
        let prog_bits = bytes_to_bits(cs.namespace(|| "prog"), &program).unwrap();
        let x = alloc_fp(cs.namespace(|| "x"), gx).unwrap();
        let parity = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "parity"), Some(false)).unwrap());
        let q = verify_key(cs.namespace(|| "vk"), &pk_bits, &prog_bits, &x, &parity).unwrap();
        assert_eq!(q.y.value, Some(gy), "recovered Q == G");
        assert!(cs.is_satisfied(), "unsat: {:?}", cs.which_is_unsatisfied());
    }

    // A pubkey that does NOT hash to the committed program must be rejected.
    #[test]
    fn verify_key_rejects_wrong_program() {
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let mut wrong = native_hash160(&pk);
        wrong[0] ^= 0xff;
        let gx = BigInt::parse_bytes(b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16).unwrap();

        let mut cs = TestConstraintSystem::<Scalar>::new();
        let pk_bits = bytes_to_bits(cs.namespace(|| "pk"), &pk).unwrap();
        let prog_bits = bytes_to_bits(cs.namespace(|| "prog"), &wrong).unwrap();
        let x = alloc_fp(cs.namespace(|| "x"), gx).unwrap();
        let parity = Boolean::from(AllocatedBit::alloc(cs.namespace(|| "parity"), Some(false)).unwrap());
        let _ = verify_key(cs.namespace(|| "vk"), &pk_bits, &prog_bits, &x, &parity).unwrap();
        assert!(!cs.is_satisfied(), "wrong hash160 program must not verify");
    }
}
