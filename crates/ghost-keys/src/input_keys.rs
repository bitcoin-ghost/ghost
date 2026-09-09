//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: input_keys.rs                                                                                                   |
//|======================================================================================================================|

//! Deriving a payment's shared secret from the transaction's own inputs.
//!
//! # Why this exists (#867)
//!
//! v1 announced the sender's ephemeral public key in an `OP_RETURN`. That made
//! every Ghost silent payment self-identifying: `6a 21` followed by exactly 33
//! bytes, beside a taproot output, is a shape an indexer can grep the whole
//! chain for at zero cost. It hid *who was paid* while advertising *that a
//! private payment happened*, and it is the same mistake as the `WL01` round
//! marker that was removed under #695.
//!
//! The fix is to stop announcing anything. A transaction already carries
//! material only its signers could have produced — its input public keys — so
//! both sides can arrive at the same secret from what is already on chain.
//!
//! # The construction
//!
//! Shaped after BIP-352, which solves exactly this problem:
//!
//! ```text
//!   a_sum      = Σ input private keys          (sender only)
//!   A_sum      = Σ input public keys           (both sides; on chain)
//!   outpoint_L = the lexicographically smallest input outpoint
//!   input_hash = SHA256(tag ‖ outpoint_L ‖ A_sum)
//!
//!   sender:    e = input_hash · a_sum          a scalar
//!   receiver:  E = input_hash · A_sum          the same point, e·G
//! ```
//!
//! `E` is what the `OP_RETURN` used to carry. Everything downstream — the ECDH
//! against the receiver's scan key, the tweak, the parity handling — is
//! unchanged, because from its point of view `e` is just an ephemeral key that
//! happens to be derived rather than random.
//!
//! Including `outpoint_L` is what stops two payments from the same input set
//! deriving the same output, and it is why the hash covers `A_sum` as well:
//! without it a sender could be induced to reuse a secret across transactions.
//!
//! ⚠ **This is not BIP-352 on the wire.** The tags are Ghost's, the address is
//! a Ghost ID rather than an `sp1` address, and the ECDH hash keeps
//! `ghost-keys/ecdh/v1`. What it buys is the privacy half — nothing marks the
//! transaction — not interoperability with BIP-352 wallets. That is a separate
//! format change.
//!
//! # The parity trap
//!
//! A taproot input publishes only the x-coordinate of its key. A receiver
//! reading `A_sum` off the chain therefore assumes even-Y for every taproot
//! input, and if the sender's actual key was odd-Y the two sides compute
//! different points and detection silently fails — no error, just a payment
//! nobody can find.
//!
//! So [`sender_secret`] normalises: any input key whose public counterpart is
//! odd-Y is negated first, which is the same key as far as a taproot output is
//! concerned. This is not optional and there is no way to detect getting it
//! wrong except by failing to find money.

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use crate::error::GhostKeyError;

/// Domain separation for the input hash. Distinct from `ghost-keys/ecdh/v1` so
/// the two hashes can never collide even on identical bytes.
const INPUT_HASH_TAG: &[u8] = b"ghost-keys/input-hash/v1";

/// One transaction input, as both sides must see it.
///
/// `txid` is the internal byte order — the bytes as they appear in the
/// serialised transaction, NOT the reversed display form. Getting this backwards
/// changes `outpoint_L` and so changes the secret, which is the kind of mistake
/// that costs a payment rather than raising an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputRef {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl InputRef {
    /// The 36 bytes an outpoint is compared and hashed as: txid ‖ vout, with
    /// the vout little-endian, exactly as a transaction serialises it.
    fn to_bytes(self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.txid);
        out[32..].copy_from_slice(&self.vout.to_le_bytes());
        out
    }
}

/// `input_hash` over the inputs and their summed public key.
fn input_hash(inputs: &[InputRef], a_sum: &PublicKey) -> Result<[u8; 32], GhostKeyError> {
    let smallest = inputs
        .iter()
        .map(|i| i.to_bytes())
        .min()
        .ok_or_else(|| GhostKeyError::DerivationError("a payment needs at least one input".into()))?;

    let mut hasher = Sha256::new();
    hasher.update(INPUT_HASH_TAG);
    hasher.update(smallest);
    hasher.update(a_sum.serialize());
    Ok(hasher.finalize().into())
}

/// Turn a 32-byte hash into a scalar the curve accepts.
fn scalar(bytes: [u8; 32]) -> Result<Scalar, GhostKeyError> {
    Scalar::from_be_bytes(bytes)
        .map_err(|_| GhostKeyError::DerivationError("input hash is not a valid scalar".into()))
}

/// The sender's side: the scalar that replaces the old random ephemeral key.
///
/// `input_keys` are the private keys of the inputs being spent, in any order.
/// Keys whose public counterpart is odd-Y are negated first — see the parity
/// note in the module docs.
pub fn sender_secret(
    inputs: &[InputRef],
    input_keys: &[SecretKey],
) -> Result<SecretKey, GhostKeyError> {
    let secp = Secp256k1::new();
    if input_keys.is_empty() {
        return Err(GhostKeyError::DerivationError(
            "a payment needs at least one input key".into(),
        ));
    }

    // Normalise to even-Y, because that is all the chain will show a receiver.
    let normalised: Vec<SecretKey> = input_keys
        .iter()
        .map(|k| {
            let (_, parity) = k.public_key(&secp).x_only_public_key();
            match parity {
                secp256k1::Parity::Even => *k,
                secp256k1::Parity::Odd => k.negate(),
            }
        })
        .collect();

    let mut a_sum = normalised[0];
    for k in &normalised[1..] {
        a_sum = a_sum
            .add_tweak(&Scalar::from(*k))
            .map_err(|e| GhostKeyError::DerivationError(format!("summing input keys: {e}")))?;
    }

    let hash = input_hash(inputs, &a_sum.public_key(&secp))?;
    a_sum
        .mul_tweak(&scalar(hash)?)
        .map_err(|e| GhostKeyError::DerivationError(format!("applying input hash: {e}")))
}

/// The receiver's side: the point the sender's scalar corresponds to, computed
/// from what the chain shows.
///
/// `input_pubkeys` are the public keys of the transaction's inputs. For taproot
/// inputs that is the x-only key lifted to even-Y, which is what the sender
/// normalised to.
pub fn receiver_pubkey(
    inputs: &[InputRef],
    input_pubkeys: &[PublicKey],
) -> Result<PublicKey, GhostKeyError> {
    let secp = Secp256k1::new();
    if input_pubkeys.is_empty() {
        return Err(GhostKeyError::DerivationError(
            "a transaction with no eligible inputs cannot carry a payment".into(),
        ));
    }

    let refs: Vec<&PublicKey> = input_pubkeys.iter().collect();
    let a_sum = if refs.len() == 1 {
        *refs[0]
    } else {
        PublicKey::combine_keys(&refs)
            .map_err(|e| GhostKeyError::DerivationError(format!("summing input pubkeys: {e}")))?
    };

    let hash = input_hash(inputs, &a_sum)?;
    a_sum
        .mul_tweak(&secp, &scalar(hash)?)
        .map_err(|e| GhostKeyError::DerivationError(format!("applying input hash: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).expect("valid key")
    }

    fn input(n: u8, vout: u32) -> InputRef {
        InputRef {
            txid: [n; 32],
            vout,
        }
    }

    /// The whole point: what the sender computes privately and what the
    /// receiver computes from the chain are the same point.
    #[test]
    fn both_sides_agree() {
        let secp = Secp256k1::new();
        let keys = [key(1), key(2), key(3)];
        let inputs = [input(9, 1), input(4, 0), input(7, 3)];

        let e = sender_secret(&inputs, &keys).expect("sender");
        // What a receiver reads off the chain: even-Y public keys.
        let pubs: Vec<PublicKey> = keys
            .iter()
            .map(|k| {
                let (xonly, _) = k.public_key(&secp).x_only_public_key();
                PublicKey::from_x_only_public_key(xonly, secp256k1::Parity::Even)
            })
            .collect();
        let big_e = receiver_pubkey(&inputs, &pubs).expect("receiver");

        assert_eq!(e.public_key(&secp), big_e, "sender scalar must match receiver point");
    }

    /// An odd-Y input key is the case that silently breaks detection if the
    /// sender does not normalise. One key is enough to prove the handling.
    #[test]
    fn an_odd_y_input_key_still_agrees() {
        let secp = Secp256k1::new();
        // Search for a key whose public counterpart is odd-Y.
        let odd = (1u8..=255)
            .map(key)
            .find(|k| {
                matches!(
                    k.public_key(&secp).x_only_public_key().1,
                    secp256k1::Parity::Odd
                )
            })
            .expect("some key in this range is odd-Y");

        let inputs = [input(3, 0)];
        let e = sender_secret(&inputs, &[odd]).expect("sender");
        let (xonly, _) = odd.public_key(&secp).x_only_public_key();
        let big_e = receiver_pubkey(
            &inputs,
            &[PublicKey::from_x_only_public_key(xonly, secp256k1::Parity::Even)],
        )
        .expect("receiver");

        assert_eq!(e.public_key(&secp), big_e);
    }

    /// Input order must not change the secret — a wallet does not control the
    /// order its coin selection hands back.
    #[test]
    fn input_order_does_not_change_the_secret() {
        let keys = [key(5), key(6)];
        let a = [input(2, 1), input(8, 0)];
        let b = [input(8, 0), input(2, 1)];
        assert_eq!(
            sender_secret(&a, &keys).unwrap().secret_bytes(),
            sender_secret(&b, &keys).unwrap().secret_bytes()
        );
    }

    /// Different inputs must give a different secret, or two payments from one
    /// wallet to one Ghost ID would land on the same output key.
    #[test]
    fn different_inputs_give_a_different_secret() {
        let keys = [key(5)];
        assert_ne!(
            sender_secret(&[input(1, 0)], &keys).unwrap().secret_bytes(),
            sender_secret(&[input(1, 1)], &keys).unwrap().secret_bytes(),
            "the vout alone must change the secret"
        );
    }

    #[test]
    fn no_inputs_is_an_error_not_a_panic() {
        assert!(sender_secret(&[], &[key(1)]).is_err());
        assert!(receiver_pubkey(&[], &[]).is_err());
    }
}
