//! Deriving a Lock co-signer's key from a BIP39 seed phrase.
//!
//! # Why this lives here and not in the signer
//!
//! Two things have to agree about which key a phrase produces: the device that
//! signs with it, and whatever registers the matching public key when the Lock
//! is built. If they disagreed, the Lock would be built around a key nobody
//! holds — and nothing would say so until a spend failed, long after the coins
//! went in.
//!
//! So the derivation has one definition and both sides call it.
//!
//! # A backup device needs its own seed
//!
//! The point of the backup key is that losing the wallet does not lose the
//! funds. A backup device seeded from the wallet's phrase is not a backup: it
//! is a second copy of the same secret, and both lanes it guards collapse to
//! single-sig the moment that phrase leaks.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::XOnlyPublicKey;
use zeroize::Zeroizing;

use crate::error::LockError;

/// SLIP-44 coin type this wallet family derives under.
///
/// Matches the wraith wallet's own derivation, so a key registered from one
/// side is the key the other derives.
pub const LOCK_COIN_TYPE: u32 = 531;

/// The path a Lock co-signer's key is derived at.
///
/// BIP-86 (`m/86'/…`), because these are Taproot keys.
pub fn derivation_path(index: u32) -> String {
    format!("m/86'/{LOCK_COIN_TYPE}'/0'/0/{index}")
}

/// Derive the secret key for `index` from a BIP39 phrase.
///
/// `passphrase` is BIP39's optional twenty-fifth word. Empty is the common
/// case and matches the wallet; a non-empty one produces a completely
/// different key, so a device configured with one must keep it — losing it
/// loses the funds exactly as losing the phrase would.
///
/// The seed is zeroized on the way out. The returned `SecretKey` is the
/// caller's to look after.
pub fn secret_key(phrase: &str, passphrase: &str, index: u32) -> Result<SecretKey, LockError> {
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, phrase.trim())
        .map_err(|e| LockError::Policy(format!("seed phrase is not valid BIP39: {e}")))?;
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));

    let mut xprv = bip32::XPrv::new(&seed[..])
        .map_err(|e| LockError::Policy(format!("seed is not a valid master key: {e}")))?;

    use std::str::FromStr;
    let path = bip32::DerivationPath::from_str(&derivation_path(index))
        .map_err(|e| LockError::Policy(format!("derivation path: {e}")))?;
    for child in path.into_iter() {
        xprv = xprv
            .derive_child(child)
            .map_err(|e| LockError::Policy(format!("derive: {e}")))?;
    }

    let bytes = Zeroizing::new(xprv.private_key().to_bytes());
    SecretKey::from_slice(&bytes[..])
        .map_err(|e| LockError::Policy(format!("derived key is not a valid secret: {e}")))
}

/// The x-only public key for `index` — what gets registered in the Lock.
///
/// Derived from the phrase rather than typed, so the key in the Lock is
/// provably the key the device will sign with.
pub fn public_key(phrase: &str, passphrase: &str, index: u32) -> Result<XOnlyPublicKey, LockError> {
    let sk = secret_key(phrase, passphrase, index)?;
    Ok(sk.x_only_public_key(&Secp256k1::new()).0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-known test vector phrase. Never use it for anything.
    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn derivation_is_deterministic() {
        let a = public_key(PHRASE, "", 0).unwrap();
        let b = public_key(PHRASE, "", 0).unwrap();
        assert_eq!(a, b, "the same phrase must always give the same key");
    }

    #[test]
    fn each_index_is_a_different_key() {
        let zero = public_key(PHRASE, "", 0).unwrap();
        let one = public_key(PHRASE, "", 1).unwrap();
        assert_ne!(zero, one);
    }

    /// The BIP39 passphrase changes the key completely.
    ///
    /// Pinned because it is the property that makes losing a passphrase
    /// equivalent to losing the phrase: there is no partial recovery.
    #[test]
    fn a_passphrase_gives_an_unrelated_key() {
        let plain = public_key(PHRASE, "", 0).unwrap();
        let salted = public_key(PHRASE, "correct horse", 0).unwrap();
        assert_ne!(plain, salted);
    }

    #[test]
    fn the_secret_matches_the_public() {
        let sk = secret_key(PHRASE, "", 3).unwrap();
        let pk = public_key(PHRASE, "", 3).unwrap();
        assert_eq!(sk.x_only_public_key(&Secp256k1::new()).0, pk);
    }

    #[test]
    fn a_bad_phrase_is_refused() {
        let err = public_key("not actually a seed phrase", "", 0).expect_err("must refuse");
        assert!(format!("{err}").contains("not valid BIP39"), "{err}");
    }

    /// Whitespace around a pasted phrase must not change the key.
    #[test]
    fn surrounding_whitespace_is_ignored() {
        let clean = public_key(PHRASE, "", 0).unwrap();
        let messy = public_key(&format!("  {PHRASE}\n"), "", 0).unwrap();
        assert_eq!(clean, messy);
    }

    #[test]
    fn the_path_is_bip86_under_the_wallet_s_coin_type() {
        assert_eq!(derivation_path(7), "m/86'/531'/0'/0/7");
    }
}
