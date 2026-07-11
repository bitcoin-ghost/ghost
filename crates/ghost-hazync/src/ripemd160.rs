//! Phase 3 M4 (foundation) — RIPEMD160 + hash160 in-circuit, for the P2WPKH
//! pubkey-hash check (`HASH160(pubkey) == committed`).
//!
//! `HASH160(x) = RIPEMD160(SHA256(x))`. SHA256 comes from nova's gadget; this
//! module implements RIPEMD160 on the vendored [`crate::u32`] `UInt32` (nova's
//! private word gadget, extended with and/or/not). RIPEMD160 is little-endian
//! (MD-style padding with an LE bit-length; LE message words; LE digest).
//! Validated in tests against the `ripemd` crate.

use crate::u32::word::UInt32;
use ff::PrimeField;
use nova_snark::frontend::{sha256, Boolean, ConstraintSystem, SynthesisError};

// Initial values h0..h4.
const IV: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
// Round constants (left / right lines).
const KL: [u32; 5] = [0x0000_0000, 0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xA953_FD4E];
const KR: [u32; 5] = [0x50A2_8BE6, 0x5C4D_D124, 0x6D70_3EF3, 0x7A6D_76E9, 0x0000_0000];
// Message word index per step (left / right).
#[rustfmt::skip]
const RL: [usize; 80] = [
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
    3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
    1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
    4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
#[rustfmt::skip]
const RR: [usize; 80] = [
    5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
    6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
    15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
    8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
    12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
// Rotation amounts per step (left / right).
#[rustfmt::skip]
const SL: [usize; 80] = [
    11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
    7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
    11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
    11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
    9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
#[rustfmt::skip]
const SR: [usize; 80] = [
    8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
    9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
    9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
    15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
    8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];

fn rotl(x: &UInt32, n: usize) -> UInt32 {
    x.rotr((32 - n) % 32)
}

/// The five RIPEMD160 round functions (`round` = 0..4).
fn f<Scalar, CS>(mut cs: CS, round: usize, x: &UInt32, y: &UInt32, z: &UInt32) -> Result<UInt32, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    Ok(match round {
        0 => x.xor(cs.namespace(|| "xy"), y)?.xor(cs.namespace(|| "xyz"), z)?,
        1 => {
            let a = x.and(cs.namespace(|| "x&y"), y)?;
            let b = x.not().and(cs.namespace(|| "!x&z"), z)?;
            a.or(cs.namespace(|| "or"), &b)?
        }
        2 => {
            let a = x.or(cs.namespace(|| "x|!y"), &y.not())?;
            a.xor(cs.namespace(|| "^z"), z)?
        }
        3 => {
            let a = x.and(cs.namespace(|| "x&z"), z)?;
            let b = y.and(cs.namespace(|| "y&!z"), &z.not())?;
            a.or(cs.namespace(|| "or"), &b)?
        }
        _ => {
            let a = y.or(cs.namespace(|| "y|!z"), &z.not())?;
            x.xor(cs.namespace(|| "x^"), &a)?
        }
    })
}

fn byte_bits_be(b: u8) -> Vec<Boolean> {
    (0..8).map(|i| Boolean::constant((b >> (7 - i)) & 1 == 1)).collect()
}

/// MD-style pad (`0x80`, zeros to 56 mod 64, then LE bit-length) — the padding is
/// constant given the message length.
fn pad(msg_bits: &[Boolean]) -> Vec<Boolean> {
    let l = msg_bits.len() / 8;
    let mut bits = msg_bits.to_vec();
    bits.extend(byte_bits_be(0x80));
    let mut total = l + 1;
    while total % 64 != 56 {
        bits.extend(byte_bits_be(0));
        total += 1;
    }
    for b in ((l as u64) * 8).to_le_bytes() {
        bits.extend(byte_bits_be(b));
    }
    bits
}

/// Load message word `j` of a 512-bit block: little-endian (byte order 4j..4j+3),
/// each byte MSB-first, so the big-endian word is bytes 4j+3,4j+2,4j+1,4j.
fn load_word(block: &[Boolean], j: usize) -> UInt32 {
    let mut be = Vec::with_capacity(32);
    for byte in [4 * j + 3, 4 * j + 2, 4 * j + 1, 4 * j] {
        be.extend_from_slice(&block[byte * 8..byte * 8 + 8]);
    }
    UInt32::from_bits_be(&be)
}

/// RIPEMD160 of `msg_bits` (message bytes as MSB-first-per-byte bits). Returns the
/// 160-bit digest (20 bytes, MSB-first per byte, in the standard LE-word order).
pub fn ripemd160_bits<Scalar, CS>(mut cs: CS, msg_bits: &[Boolean]) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    use crate::u32::multieq::MultiEq;
    let padded = pad(msg_bits);
    let mut h: [UInt32; 5] = [
        UInt32::constant(IV[0]),
        UInt32::constant(IV[1]),
        UInt32::constant(IV[2]),
        UInt32::constant(IV[3]),
        UInt32::constant(IV[4]),
    ];

    for (blk, chunk) in padded.chunks(512).enumerate() {
        let x: Vec<UInt32> = (0..16).map(|j| load_word(chunk, j)).collect();
        let mut mm = MultiEq::new(cs.namespace(|| format!("block_{blk}")));

        let (mut al, mut bl, mut cl, mut dl, mut el) =
            (h[0].clone(), h[1].clone(), h[2].clone(), h[3].clone(), h[4].clone());
        let (mut ar, mut br, mut cr, mut dr, mut er) =
            (h[0].clone(), h[1].clone(), h[2].clone(), h[3].clone(), h[4].clone());

        for j in 0..80 {
            let round = j / 16;
            // left line
            let fl = f(mm.namespace(|| format!("fl_{j}")), round, &bl, &cl, &dl)?;
            let t = UInt32::addmany(
                mm.namespace(|| format!("tl_add_{j}")),
                &[al.clone(), fl, x[RL[j]].clone(), UInt32::constant(KL[round])],
            )?;
            let t = UInt32::addmany(mm.namespace(|| format!("tl_e_{j}")), &[rotl(&t, SL[j]), el.clone()])?;
            al = el;
            el = dl;
            dl = rotl(&cl, 10);
            cl = bl;
            bl = t;
            // right line
            let fr = f(mm.namespace(|| format!("fr_{j}")), 4 - round, &br, &cr, &dr)?;
            let tr = UInt32::addmany(
                mm.namespace(|| format!("tr_add_{j}")),
                &[ar.clone(), fr, x[RR[j]].clone(), UInt32::constant(KR[round])],
            )?;
            let tr = UInt32::addmany(mm.namespace(|| format!("tr_e_{j}")), &[rotl(&tr, SR[j]), er.clone()])?;
            ar = er;
            er = dr;
            dr = rotl(&cr, 10);
            cr = br;
            br = tr;
        }

        // Combine (uses the OLD h values).
        let t = UInt32::addmany(mm.namespace(|| "c0"), &[h[1].clone(), cl, dr])?;
        let n1 = UInt32::addmany(mm.namespace(|| "c1"), &[h[2].clone(), dl, er])?;
        let n2 = UInt32::addmany(mm.namespace(|| "c2"), &[h[3].clone(), el, ar])?;
        let n3 = UInt32::addmany(mm.namespace(|| "c3"), &[h[4].clone(), al, br])?;
        let n4 = UInt32::addmany(mm.namespace(|| "c4"), &[h[0].clone(), bl, cr])?;
        h = [t, n1, n2, n3, n4];
    }

    // Digest: each word as 4 LE bytes (MSB-first per byte) = reverse the 4 byte
    // chunks of its big-endian bit form.
    let mut out = Vec::with_capacity(160);
    for word in &h {
        let be = word.clone().into_bits_be();
        for chunk in [3usize, 2, 1, 0] {
            out.extend_from_slice(&be[chunk * 8..chunk * 8 + 8]);
        }
    }
    Ok(out)
}

/// `HASH160(x) = RIPEMD160(SHA256(x))`. `input_bits` are the input bytes as
/// MSB-first-per-byte bits; returns the 160-bit hash.
pub fn hash160_bits<Scalar, CS>(mut cs: CS, input_bits: &[Boolean]) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let sha = sha256(cs.namespace(|| "sha256"), input_bits)?;
    ripemd160_bits(cs.namespace(|| "ripemd160"), &sha)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256d_gadget::{bits_to_bytes, bytes_to_bits};
    use nova_snark::frontend::solver::SatisfyingAssignment;
    use nova_snark::provider::PallasEngine;
    use ripemd::{Digest, Ripemd160};
    use sha2::Sha256;

    fn native_ripemd160(x: &[u8]) -> [u8; 20] {
        let mut h = Ripemd160::new();
        h.update(x);
        h.finalize().into()
    }
    fn native_hash160(x: &[u8]) -> [u8; 20] {
        native_ripemd160(&Sha256::digest(x))
    }

    fn in_circuit_ripemd160(x: &[u8]) -> [u8; 32] {
        let mut cs = SatisfyingAssignment::<PallasEngine>::new();
        let bits = bytes_to_bits(cs.namespace(|| "m"), x).unwrap();
        let d = ripemd160_bits(cs.namespace(|| "r"), &bits).unwrap();
        bits_to_bytes(&d)
    }

    #[test]
    fn ripemd160_empty_matches_native() {
        let got = in_circuit_ripemd160(b"");
        assert_eq!(&got[..20], &native_ripemd160(b"")[..], "RIPEMD160(\"\")");
    }

    #[test]
    fn ripemd160_abc_matches_native() {
        let got = in_circuit_ripemd160(b"abc");
        assert_eq!(&got[..20], &native_ripemd160(b"abc")[..], "RIPEMD160(abc)");
    }

    #[test]
    fn ripemd160_multiblock_matches_native() {
        // 100 bytes -> padding spills into a second 512-bit block.
        let msg = vec![0x61u8; 100];
        let got = in_circuit_ripemd160(&msg);
        assert_eq!(&got[..20], &native_ripemd160(&msg)[..], "RIPEMD160(100 bytes)");
    }

    #[test]
    fn hash160_pubkey_matches_native() {
        // A real 33-byte compressed secp256k1 pubkey (the generator G).
        let pk = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        let mut cs = SatisfyingAssignment::<PallasEngine>::new();
        let bits = bytes_to_bits(cs.namespace(|| "pk"), &pk).unwrap();
        let d = hash160_bits(cs.namespace(|| "h160"), &bits).unwrap();
        assert_eq!(&bits_to_bytes(&d)[..20], &native_hash160(&pk)[..], "HASH160(pubkey)");
    }
}
