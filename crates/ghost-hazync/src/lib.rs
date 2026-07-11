//! # ghost-hazync — Hazync: recursive validity proof for Ghost
//!
//! Hazync (Haze + sync) is the trustless fast-sync backbone of the Haze family
//! ([`ghost-web/docs/hazedproof.md`]): a recursive **Nova/folding** proof
//! attesting that the UTXO-set commitment `C_H` is the correct result of
//! validating every block from genesis to height `H` — replacing the
//! single-signer checkpoint signature (`haze/checkpoint_signing`) with math, and
//! unlocking the proof-backed hazed wallet. Full plan: `ghost-web/docs/hazync.md`.
//!
//! ## Proving system
//! **Nova folding** (IVC): step `n`'s proof folds in step `n-1`'s, so we prove
//! "one more block" cheaply and never re-verify history. This is a *new* stack,
//! distinct from the shielded pool's Groth16 (`ghost-zkp`), which cannot recurse.
//!
//! ## Phases (this crate grows through them)
//! - **Phase 1** — recursive cumulative-PoW over the header chain (no UTXO yet).
//!   Stands up the IVC machinery and gives real prove/verify numbers. → [`cumulative_pow`]
//! - Phase 2 — UTXO accumulator (Utreexo) folded in-circuit.
//! - Phase 3 — script/tx validation in-circuit (the multi-month body).
//! - Phase 4 — prove-then-strip at the tip (wire to SwiftSync/checkpoint).
//! - Phase 5 — historical backfill + elder-quorum-proved tie-in.

pub mod cumulative_pow;
pub mod pow_step_circuit;
pub mod sha256d_gadget;
pub mod hashed_step;
pub mod compare;
pub mod merkle;
pub mod accumulator;
pub mod accumulator_add;
pub mod block_step;
pub mod smt_update;
pub mod block_tx_step;
pub mod coin;
pub mod coin_tx;
pub mod coin_tx_fanout;
pub mod sighash;
// Vendored foreign-field arithmetic (see src/nonnative/mod.rs).
#[allow(dead_code)]
pub mod nonnative;
#[allow(dead_code)]
mod u32;
pub mod secp256k1_field;
pub mod secp256k1_ec;
#[allow(dead_code)]
pub mod glv;
pub mod secp256k1_scalar;
pub mod ecdsa;
pub mod ripemd160;
pub mod pubkey;
pub mod p2wpkh;
pub mod ecdsa_step;
#[cfg(test)]
mod test_cs;
#[cfg(test)]
mod measure;

/// A 256-bit value (block hash / target), big-endian, as it appears on the wire
/// after the double-SHA256. Kept as raw bytes so the native spec and the future
/// in-circuit encoding agree byte-for-byte.
pub type U256 = [u8; 32];
