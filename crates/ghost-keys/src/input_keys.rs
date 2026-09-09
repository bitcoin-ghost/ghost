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

/// A transaction outpoint, in the one byte order the derivation uses.
///
/// The field is private and there is no way to build one without saying which
/// order the bytes are in. That is deliberate: a txid reversed is still 32
/// valid-looking bytes, it changes which outpoint is smallest, and so it
/// changes the secret — producing a payment the recipient cannot find, with no
/// error at any point. The only defence is to make the question unavoidable at
/// the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Outpoint {
    /// Internal order: the bytes as a transaction serialises them.
    txid: [u8; 32],
    vout: u32,
}

impl Outpoint {
    /// From the bytes as a transaction serialises them — what `bitcoin::Txid`
    /// stores, and what `Txid::to_byte_array` returns.
    pub fn from_internal_bytes(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }

    /// From the reversed, human-facing hex a node reports in JSON.
    pub fn from_display_hex(txid_hex: &str, vout: u32) -> Result<Self, GhostKeyError> {
        let mut bytes = hex::decode(txid_hex.trim())
            .map_err(|e| GhostKeyError::DerivationError(format!("txid is not hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(GhostKeyError::DerivationError(format!(
                "a txid is 32 bytes, got {}",
                bytes.len()
            )));
        }
        bytes.reverse();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes);
        Ok(Self { txid, vout })
    }

    /// The 36 bytes an outpoint is compared and hashed as: txid ‖ vout, the
    /// vout little-endian, exactly as a transaction serialises it.
    fn to_bytes(self) -> [u8; 36] {
        let mut out = [0u8; 36];
        out[..32].copy_from_slice(&self.txid);
        out[32..].copy_from_slice(&self.vout.to_le_bytes());
        out
    }
}

/// One input the sender is spending: its outpoint and the key that controls it.
///
/// The two are bundled so they cannot be supplied as parallel lists that drift
/// apart, and the key is private so it can only arrive through
/// [`PaymentInput::spending_taproot_output`], which checks it.
#[derive(Debug, Clone)]
pub struct PaymentInput {
    outpoint: Outpoint,
    /// Parity-normalised at construction.
    key: SecretKey,
}

impl PaymentInput {
    /// The input spending a taproot output, checked against that output.
    ///
    /// `output_xonly` is the 32-byte key from the scriptPubKey being spent, and
    /// `key` must be the key that controls it — for a BIP-86 coin that is the
    /// **tweaked** key, not the internal one.
    ///
    /// This is verified rather than trusted. A BIP-86 output is controlled by
    /// the tweaked key, and it is the tweaked key that appears on chain and so
    /// the one a receiver sums into `A_sum` — but the untweaked key is the one
    /// sitting in the keystore, and passing it produces a payment nobody can
    /// ever find with nothing anywhere reporting a problem. Comparing the key
    /// against the output it claims to spend turns that into an error before a
    /// transaction exists.
    ///
    /// Parity is normalised here too: a taproot output records only an
    /// x-coordinate, so a receiver assumes even-Y, and an odd-Y key must be
    /// negated or the two sides derive different points.
    pub fn spending_taproot_output(
        outpoint: Outpoint,
        key: SecretKey,
        output_xonly: &[u8; 32],
    ) -> Result<Self, GhostKeyError> {
        let secp = Secp256k1::new();
        let (xonly, parity) = key.public_key(&secp).x_only_public_key();
        if &xonly.serialize() != output_xonly {
            return Err(GhostKeyError::DerivationError(format!(
                "this key does not control the output it claims to spend \
                 ({}:{}) — a BIP-86 coin is controlled by the TWEAKED key, and an \
                 untweaked one derives a payment the recipient can never find",
                hex::encode(outpoint.txid),
                outpoint.vout
            )));
        }
        let key = match parity {
            secp256k1::Parity::Even => key,
            secp256k1::Parity::Odd => key.negate(),
        };
        Ok(Self { outpoint, key })
    }
}

/// One input as the receiver sees it: an outpoint and the public key the chain
/// shows for it.
#[derive(Debug, Clone)]
pub struct ScannedInput {
    outpoint: Outpoint,
    pubkey: PublicKey,
}

impl ScannedInput {
    /// From the taproot scriptPubKey the input spends.
    ///
    /// Parses the `OP_1 PUSH32 <x-only>` shape and lifts to even-Y, which is
    /// what the sender normalised to. Anything else is not a usable input and
    /// says so, rather than contributing a wrong point to `A_sum`.
    pub fn from_taproot_script_pubkey(
        outpoint: Outpoint,
        script_pubkey: &[u8],
    ) -> Result<Self, GhostKeyError> {
        if script_pubkey.len() != 34 || script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20 {
            return Err(GhostKeyError::DerivationError(
                "not a taproot output: only P2TR inputs publish a usable key".into(),
            ));
        }
        let xonly = secp256k1::XOnlyPublicKey::from_slice(&script_pubkey[2..34])
            .map_err(|e| GhostKeyError::DerivationError(format!("input key: {e}")))?;
        Ok(Self {
            outpoint,
            pubkey: PublicKey::from_x_only_public_key(xonly, secp256k1::Parity::Even),
        })
    }
}

/// `input_hash` over the outpoints and their summed public key.
fn input_hash(outpoints: &[Outpoint], a_sum: &PublicKey) -> Result<[u8; 32], GhostKeyError> {
    let smallest = outpoints
        .iter()
        .map(|o| o.to_bytes())
        .min()
        .ok_or_else(|| {
            GhostKeyError::DerivationError("a payment needs at least one input".into())
        })?;

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
/// Every input of the transaction must be present. The receiver computes
/// `A_sum` from all of them, so a sender that omits one — a coin it cannot sign,
/// say — derives a different point and the payment is lost.
pub fn sender_secret(inputs: &[PaymentInput]) -> Result<SecretKey, GhostKeyError> {
    let secp = Secp256k1::new();
    let (first, rest) = inputs.split_first().ok_or_else(|| {
        GhostKeyError::DerivationError("a payment needs at least one input".into())
    })?;

    let mut a_sum = first.key;
    for input in rest {
        a_sum = a_sum
            .add_tweak(&Scalar::from(input.key))
            .map_err(|e| GhostKeyError::DerivationError(format!("summing input keys: {e}")))?;
    }

    let outpoints: Vec<Outpoint> = inputs.iter().map(|i| i.outpoint).collect();
    let hash = input_hash(&outpoints, &a_sum.public_key(&secp))?;
    a_sum
        .mul_tweak(&scalar(hash)?)
        .map_err(|e| GhostKeyError::DerivationError(format!("applying input hash: {e}")))
}

/// The receiver's side: the same point, from what the chain shows.
pub fn receiver_pubkey(inputs: &[ScannedInput]) -> Result<PublicKey, GhostKeyError> {
    let secp = Secp256k1::new();
    if inputs.is_empty() {
        return Err(GhostKeyError::DerivationError(
            "a transaction with no eligible inputs cannot carry a payment".into(),
        ));
    }

    let keys: Vec<&PublicKey> = inputs.iter().map(|i| &i.pubkey).collect();
    let a_sum = if keys.len() == 1 {
        *keys[0]
    } else {
        PublicKey::combine_keys(&keys)
            .map_err(|e| GhostKeyError::DerivationError(format!("summing input pubkeys: {e}")))?
    };

    let outpoints: Vec<Outpoint> = inputs.iter().map(|i| i.outpoint).collect();
    let hash = input_hash(&outpoints, &a_sum)?;
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

    /// The x-only bytes a taproot output would carry for this key.
    fn output_xonly(k: &SecretKey) -> [u8; 32] {
        let secp = Secp256k1::new();
        k.public_key(&secp).x_only_public_key().0.serialize()
    }

    fn spending(n: u8, vout: u32, k: &SecretKey) -> PaymentInput {
        PaymentInput::spending_taproot_output(
            Outpoint::from_internal_bytes([n; 32], vout),
            *k,
            &output_xonly(k),
        )
        .expect("key controls the output")
    }

    fn scanned(n: u8, vout: u32, k: &SecretKey) -> ScannedInput {
        let mut spk = vec![0x51u8, 0x20];
        spk.extend_from_slice(&output_xonly(k));
        ScannedInput::from_taproot_script_pubkey(Outpoint::from_internal_bytes([n; 32], vout), &spk)
            .expect("a taproot script")
    }

    /// The whole point: what the sender computes privately and what the
    /// receiver computes from the chain are the same point.
    #[test]
    fn both_sides_agree() {
        let secp = Secp256k1::new();
        let keys = [key(1), key(2), key(3)];
        let spend: Vec<PaymentInput> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| spending(9 - i as u8, i as u32, k))
            .collect();
        let seen: Vec<ScannedInput> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| scanned(9 - i as u8, i as u32, k))
            .collect();

        assert_eq!(
            sender_secret(&spend).unwrap().public_key(&secp),
            receiver_pubkey(&seen).unwrap(),
        );
    }

    /// TRAP 1, now impossible to get wrong: an odd-Y key is normalised inside
    /// the constructor, so no caller can forget.
    #[test]
    fn an_odd_y_input_key_still_agrees() {
        let secp = Secp256k1::new();
        let odd = (1u8..=255)
            .map(key)
            .find(|k| {
                matches!(
                    k.public_key(&secp).x_only_public_key().1,
                    secp256k1::Parity::Odd
                )
            })
            .expect("some key in this range is odd-Y");

        assert_eq!(
            sender_secret(&[spending(3, 0, &odd)])
                .unwrap()
                .public_key(&secp),
            receiver_pubkey(&[scanned(3, 0, &odd)]).unwrap(),
        );
    }

    /// TRAP 2, now impossible to get wrong: the two byte orders are different
    /// constructors, so the call site has to say which it has.
    #[test]
    fn the_two_byte_orders_are_different_outpoints() {
        let display = "00".repeat(31) + "ff";
        let from_display = Outpoint::from_display_hex(&display, 0).expect("valid hex");

        let mut internal = [0u8; 32];
        internal[31] = 0xff;
        let mistaken = Outpoint::from_internal_bytes(internal, 0);

        assert_ne!(
            from_display, mistaken,
            "a display txid read as internal bytes must not silently produce the same outpoint"
        );
        // And the correct reading is the reverse.
        let mut reversed = [0u8; 32];
        reversed[0] = 0xff;
        assert_eq!(from_display, Outpoint::from_internal_bytes(reversed, 0));
    }

    #[test]
    fn a_txid_of_the_wrong_length_is_refused() {
        assert!(Outpoint::from_display_hex("00ff", 0).is_err());
        assert!(Outpoint::from_display_hex("not hex", 0).is_err());
    }

    /// TRAP 3, now caught rather than silent: an untweaked BIP-86 key does not
    /// control the output it claims to spend, and saying so costs an error
    /// instead of a payment nobody can find.
    #[test]
    fn a_key_that_does_not_control_the_output_is_refused() {
        let internal = key(11);
        let actual_output = key(12); // stands in for the tweaked key
        let err = PaymentInput::spending_taproot_output(
            Outpoint::from_internal_bytes([1; 32], 0),
            internal,
            &output_xonly(&actual_output),
        )
        .expect_err("the mismatch must be caught");
        let msg = err.to_string();
        assert!(
            msg.contains("does not control the output"),
            "the error must name the problem, got: {msg}"
        );
    }

    #[test]
    fn a_non_taproot_input_is_refused_rather_than_summed() {
        // P2WPKH: OP_0 PUSH20 <hash>. Its key lives in the witness, not here.
        let mut spk = vec![0x00u8, 0x14];
        spk.extend_from_slice(&[0xab; 20]);
        assert!(ScannedInput::from_taproot_script_pubkey(
            Outpoint::from_internal_bytes([1; 32], 0),
            &spk
        )
        .is_err());
    }

    /// Input order must not change the secret — a wallet does not control the
    /// order its coin selection hands back.
    #[test]
    fn input_order_does_not_change_the_secret() {
        let (k5, k6) = (key(5), key(6));
        let a = [spending(2, 1, &k5), spending(8, 0, &k6)];
        let b = [spending(8, 0, &k6), spending(2, 1, &k5)];
        assert_eq!(
            sender_secret(&a).unwrap().secret_bytes(),
            sender_secret(&b).unwrap().secret_bytes()
        );
    }

    /// Different inputs must give a different secret, or two payments from one
    /// wallet to one Ghost ID would land on the same output key.
    #[test]
    fn different_inputs_give_a_different_secret() {
        let k = key(5);
        assert_ne!(
            sender_secret(&[spending(1, 0, &k)]).unwrap().secret_bytes(),
            sender_secret(&[spending(1, 1, &k)]).unwrap().secret_bytes(),
            "the vout alone must change the secret"
        );
    }

    #[test]
    fn no_inputs_is_an_error_not_a_panic() {
        assert!(sender_secret(&[]).is_err());
        assert!(receiver_pubkey(&[]).is_err());
    }
}
