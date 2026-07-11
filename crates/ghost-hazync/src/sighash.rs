//! Phase 3 M1 — BIP143 (segwit v0) signature-hash gadget.
//!
//! Every ECDSA/Schnorr check verifies a signature over the transaction's
//! **sighash** — the message. This module computes the BIP143 `SIGHASH_ALL`
//! sighash **in-circuit** so a spend proof can bind a signature to the actual
//! transaction. It reuses [`crate::sha256d_gadget`] for every hash; there is no
//! new cryptography here, which is why M1 is the small foundation before the
//! secp256k1 work (M2).
//!
//! The BIP143 preimage (`SIGHASH_ALL`) is:
//!
//! ```text
//! version(4) ‖ dSHA256(prevouts) ‖ dSHA256(sequences) ‖ outpoint(36) ‖
//! scriptCode(varint‖script) ‖ amount(8) ‖ nSequence(4) ‖ dSHA256(outputs) ‖
//! locktime(4) ‖ hashtype(4)
//! ```
//!
//! and `sighash = dSHA256(preimage)`. The three mid-hashes are computed
//! in-circuit from the serialised prevouts/sequences/outputs; the fixed segments
//! are witnessed and concatenated, then the whole preimage is double-hashed.
//! The native [`Bip143Tx::sighash_all`] oracle is validated against the
//! canonical BIP143 P2WPKH test vector in the tests.

use crate::cumulative_pow::double_sha256;
use crate::sha256d_gadget::{bytes_to_bits, sha256d, sha256d_bits};
use crate::U256;
use ff::PrimeField;
use nova_snark::frontend::{Boolean, ConstraintSystem, SynthesisError};

/// A transaction input, as far as BIP143 needs it.
#[derive(Clone, Debug)]
pub struct Bip143Input {
    /// txid in internal (serialised) byte order.
    pub txid: [u8; 32],
    pub vout: u32,
    /// Value of the output being spent (satoshis).
    pub amount: u64,
    pub sequence: u32,
}

/// A transaction output.
#[derive(Clone, Debug)]
pub struct Bip143Output {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Bip143Tx {
    pub version: u32,
    pub inputs: Vec<Bip143Input>,
    pub outputs: Vec<Bip143Output>,
    pub locktime: u32,
}

/// Append a Bitcoin compactSize varint.
fn write_varint(out: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&n.to_le_bytes());
    }
}

fn ser_prevouts(inputs: &[Bip143Input]) -> Vec<u8> {
    let mut v = Vec::with_capacity(inputs.len() * 36);
    for i in inputs {
        v.extend_from_slice(&i.txid);
        v.extend_from_slice(&i.vout.to_le_bytes());
    }
    v
}

fn ser_sequences(inputs: &[Bip143Input]) -> Vec<u8> {
    let mut v = Vec::with_capacity(inputs.len() * 4);
    for i in inputs {
        v.extend_from_slice(&i.sequence.to_le_bytes());
    }
    v
}

fn ser_outputs(outputs: &[Bip143Output]) -> Vec<u8> {
    let mut v = Vec::new();
    for o in outputs {
        v.extend_from_slice(&o.value.to_le_bytes());
        write_varint(&mut v, o.script_pubkey.len() as u64);
        v.extend_from_slice(&o.script_pubkey);
    }
    v
}

impl Bip143Tx {
    /// The middle segment of the preimage for input `i` with `script_code`:
    /// `outpoint(36) ‖ varint(len)‖scriptCode ‖ amount(8) ‖ nSequence(4)`.
    fn preimage_middle(&self, i: usize, script_code: &[u8]) -> Vec<u8> {
        let inp = &self.inputs[i];
        let mut m = Vec::new();
        m.extend_from_slice(&inp.txid);
        m.extend_from_slice(&inp.vout.to_le_bytes());
        write_varint(&mut m, script_code.len() as u64);
        m.extend_from_slice(script_code);
        m.extend_from_slice(&inp.amount.to_le_bytes());
        m.extend_from_slice(&inp.sequence.to_le_bytes());
        m
    }

    /// The `locktime(4) ‖ hashtype(4)` tail (`SIGHASH_ALL` = 1).
    fn preimage_tail(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(8);
        t.extend_from_slice(&self.locktime.to_le_bytes());
        t.extend_from_slice(&1u32.to_le_bytes());
        t
    }

    /// Native BIP143 `SIGHASH_ALL` sighash for input `i`, spending a script whose
    /// `script_code` is given (the raw script; the varint length is added here).
    pub fn sighash_all(&self, i: usize, script_code: &[u8]) -> U256 {
        let mut p = Vec::new();
        p.extend_from_slice(&self.version.to_le_bytes());
        p.extend_from_slice(&double_sha256(&ser_prevouts(&self.inputs)));
        p.extend_from_slice(&double_sha256(&ser_sequences(&self.inputs)));
        p.extend_from_slice(&self.preimage_middle(i, script_code));
        p.extend_from_slice(&double_sha256(&ser_outputs(&self.outputs)));
        p.extend_from_slice(&self.preimage_tail());
        double_sha256(&p)
    }
}

/// In-circuit BIP143 `SIGHASH_ALL` sighash for input `i` — returns the 256
/// sighash bits, matching [`Bip143Tx::sighash_all`]. The three mid-hashes are
/// computed in-circuit; the fixed preimage segments are witnessed.
pub fn sighash_all_bits<F, CS>(
    cs: &mut CS,
    tx: &Bip143Tx,
    i: usize,
    script_code: &[u8],
) -> Result<Vec<Boolean>, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
{
    let hash_prevouts = sha256d(cs.namespace(|| "prevouts"), &ser_prevouts(&tx.inputs))?;
    let hash_sequence = sha256d(cs.namespace(|| "sequences"), &ser_sequences(&tx.inputs))?;
    let hash_outputs = sha256d(cs.namespace(|| "outputs"), &ser_outputs(&tx.outputs))?;

    let mut pre: Vec<Boolean> = Vec::new();
    pre.extend(bytes_to_bits(cs.namespace(|| "version"), &tx.version.to_le_bytes())?);
    pre.extend(hash_prevouts);
    pre.extend(hash_sequence);
    pre.extend(bytes_to_bits(cs.namespace(|| "middle"), &tx.preimage_middle(i, script_code))?);
    pre.extend(hash_outputs);
    pre.extend(bytes_to_bits(cs.namespace(|| "tail"), &tx.preimage_tail())?);

    sha256d_bits(cs.namespace(|| "sighash"), &pre)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256d_gadget::bits_to_bytes;
    use nova_snark::frontend::solver::SatisfyingAssignment;
    use nova_snark::provider::PallasEngine;

    fn arr32(hex_str: &str) -> [u8; 32] {
        let v = hex::decode(hex_str).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    // The canonical BIP143 P2WPKH example (BIP143 "Native P2WPKH").
    fn bip143_vector_tx() -> Bip143Tx {
        Bip143Tx {
            version: 1,
            inputs: vec![
                Bip143Input {
                    txid: arr32("fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"),
                    vout: 0,
                    amount: 625_000_000, // 6.25 BTC (P2PK input)
                    sequence: 0xffff_ffee,
                },
                Bip143Input {
                    txid: arr32("ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a"),
                    vout: 1,
                    amount: 600_000_000, // 6 BTC (P2WPKH input — the one we sign)
                    sequence: 0xffff_ffff,
                },
            ],
            outputs: vec![
                Bip143Output {
                    value: 112_340_000,
                    script_pubkey: hex::decode("76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac").unwrap(),
                },
                Bip143Output {
                    value: 223_450_000,
                    script_pubkey: hex::decode("76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac").unwrap(),
                },
            ],
            locktime: 0x11,
        }
    }

    // scriptCode for the P2WPKH input = the implied P2PKH script of the key hash.
    fn bip143_vector_script_code() -> Vec<u8> {
        hex::decode("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac").unwrap()
    }

    #[test]
    fn native_sighash_matches_bip143_vector() {
        let tx = bip143_vector_tx();
        let got = tx.sighash_all(1, &bip143_vector_script_code());
        let expected = arr32("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        assert_eq!(got, expected, "native BIP143 SIGHASH_ALL must match the spec test vector");
    }

    #[test]
    fn in_circuit_sighash_matches_native() {
        let tx = bip143_vector_tx();
        let sc = bip143_vector_script_code();
        let native = tx.sighash_all(1, &sc);

        let mut cs = SatisfyingAssignment::<PallasEngine>::new();
        let bits = sighash_all_bits(&mut cs, &tx, 1, &sc).unwrap();
        assert_eq!(bits_to_bytes(&bits), native, "in-circuit sighash must equal native");
    }
}
