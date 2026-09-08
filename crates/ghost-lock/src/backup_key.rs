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
use zeroize::{Zeroize, Zeroizing};

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

/// Derivation account for quorum keys, kept apart from an owner's `0'`.
///
/// A quorum's seed and an owner's seed are different secrets held by different
/// people; separating the accounts means a path collision cannot make one
/// derive the other's key even if a seed were ever shared by mistake.
pub const QUORUM_ACCOUNT: u32 = 1;

/// The path a quorum derives its key for one Lock at.
///
/// # One key per Lock, not one key for all of them
///
/// Deterministic derivation makes per-Lock keys free, and the alternative is
/// costly: a single quorum key appears in every Lock it guards, so anyone who
/// sees two addresses can tell they answer to the same quorum. Per-Lock keys
/// leave nothing to correlate.
///
/// The index comes from the Lock's own id, so both sides reach it without
/// storing a mapping — the quorum does not need a database to know which key
/// belongs to which Lock, and losing one could not orphan a Lock.
///
/// Two levels of 31 bits, because BIP32 indices are 31 bits unhardened and one
/// level would leave a collision rate worth thinking about. At 62 bits it is
/// not.
pub fn quorum_derivation_path(lock_id: &str) -> String {
    use bitcoin::hashes::{sha256, Hash as _};
    let h = sha256::Hash::hash(lock_id.trim().as_bytes()).to_byte_array();
    let hi = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) & 0x7fff_ffff;
    let lo = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) & 0x7fff_ffff;
    format!("m/86'/{LOCK_COIN_TYPE}'/{QUORUM_ACCOUNT}'/{hi}/{lo}")
}

/// The quorum's secret key for one Lock.
pub fn quorum_secret_key(
    phrase: &str,
    passphrase: &str,
    lock_id: &str,
) -> Result<SecretKey, LockError> {
    derive_at(phrase, passphrase, &quorum_derivation_path(lock_id))
}

/// The quorum's public key for one Lock — what goes in the Lock.
pub fn quorum_public_key(
    phrase: &str,
    passphrase: &str,
    lock_id: &str,
) -> Result<XOnlyPublicKey, LockError> {
    Ok(quorum_secret_key(phrase, passphrase, lock_id)?
        .x_only_public_key(&Secp256k1::new())
        .0)
}

/// Generate a new seed phrase for a co-signing device.
///
/// # The entropy rule, and why it is not "use the OS RNG"
///
/// It is that, plus a floor. Every secret starts from the OS CSPRNG, and
/// optional user entropy is **mixed in, never substituted**:
///
/// ```text
/// seed = SHA256( tag ‖ os_bytes ‖ user_digest )
/// ```
///
/// The mixing is one-directional, which is the whole point. Supplying no
/// rolls, or entirely predictable ones, leaves the seed exactly as strong as
/// the OS bytes alone — an attacker still has to break those. Supplying good
/// rolls means they must break the OS source *and* guess the rolls. There is
/// no input a user can provide that makes the result weaker.
///
/// A "dice only" mode is deliberately not offered: it would make the seed
/// depend on somebody rolling honestly and well, with no safety net if they
/// did not.
///
/// # Why a floor is worth having at all
///
/// With a single source there is nothing to notice a silent degradation.
/// Coldcard firmware from March 2021 generated seeds through MicroPython's
/// Yasmarang PRNG rather than the hardware TRNG; effective entropy fell to
/// about 40 bits on Mk3. The output distribution looked fine — only the seed
/// *space* was small — and nothing in the device could tell. In July 2026 an
/// attacker enumerated it and swept roughly 1,816 BTC. Dice give a floor that
/// does not depend on any implementation being correct.
///
/// See [`ghost_entropy`] for collecting rolls and for what one is worth.
pub fn new_phrase(user_digest: Option<&[u8; 32]>) -> Result<Zeroizing<String>, LockError> {
    use rand::RngCore;

    let mut os_bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut os_bytes[..])
        .map_err(|e| LockError::Policy(format!("no secure randomness for a seed: {e}")))?;

    let mut entropy = Zeroizing::new(ghost_entropy::mix_seed_entropy(&os_bytes, user_digest));

    let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &entropy[..])
        .map_err(|e| LockError::Policy(format!("could not build a seed phrase: {e}")))?;
    let phrase = Zeroizing::new(mnemonic.to_string());
    entropy.zeroize();
    Ok(phrase)
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
    derive_at(phrase, passphrase, &derivation_path(index))
}

/// Derive a key at an explicit BIP32 path.
fn derive_at(phrase: &str, passphrase: &str, path: &str) -> Result<SecretKey, LockError> {
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, phrase.trim())
        .map_err(|e| LockError::Policy(format!("seed phrase is not valid BIP39: {e}")))?;
    let seed = Zeroizing::new(mnemonic.to_seed(passphrase));

    let mut xprv = bip32::XPrv::new(&seed[..])
        .map_err(|e| LockError::Policy(format!("seed is not a valid master key: {e}")))?;

    use std::str::FromStr;
    let path = bip32::DerivationPath::from_str(path)
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
    fn a_generated_phrase_is_24_words_and_usable() {
        let phrase = new_phrase(None).expect("generates");
        assert_eq!(
            phrase.split_whitespace().count(),
            24,
            "256 bits of entropy is a 24-word phrase"
        );
        // It must round-trip through the derivation it exists for.
        public_key(&phrase, "", 0).expect("the generated phrase must derive a key");
    }

    #[test]
    fn two_generated_phrases_differ() {
        let a = new_phrase(None).unwrap();
        let b = new_phrase(None).unwrap();
        assert_ne!(*a, *b, "seeds must not repeat");
    }

    /// **Mixed, never substituted.**
    ///
    /// The same user digest twice must still give different seeds, because the
    /// OS bytes are re-drawn. If user entropy replaced the OS source rather
    /// than being mixed with it, these would collide — and a user with
    /// predictable rolls would have a predictable seed.
    #[test]
    fn the_same_dice_do_not_produce_the_same_seed() {
        let digest = [7u8; 32];
        let a = new_phrase(Some(&digest)).unwrap();
        let b = new_phrase(Some(&digest)).unwrap();
        assert_ne!(
            *a, *b,
            "user entropy must be mixed with fresh OS bytes, not substituted for them"
        );
    }

    /// A quorum reaches the same key from the Lock id alone, with no mapping
    /// stored anywhere.
    #[test]
    fn a_quorum_key_is_determined_by_the_lock_id() {
        let a = quorum_public_key(PHRASE, "", "lock-abc").unwrap();
        let b = quorum_public_key(PHRASE, "", "lock-abc").unwrap();
        assert_eq!(a, b);
    }

    /// **Per Lock, not per quorum.** One key across every Lock would let
    /// anyone holding two addresses tell they answer to the same quorum.
    #[test]
    fn different_locks_get_different_quorum_keys() {
        let a = quorum_public_key(PHRASE, "", "lock-abc").unwrap();
        let b = quorum_public_key(PHRASE, "", "lock-def").unwrap();
        assert_ne!(a, b, "two Locks must not share a quorum key");
    }

    /// The quorum account is separate from an owner's, so the same seed could
    /// never derive one party's key at the other's path.
    #[test]
    fn quorum_keys_do_not_collide_with_owner_keys() {
        let owner = public_key(PHRASE, "", 0).unwrap();
        let quorum = quorum_public_key(PHRASE, "", "lock-abc").unwrap();
        assert_ne!(owner, quorum);
        assert!(quorum_derivation_path("lock-abc").contains("/1'/"));
        assert!(derivation_path(0).contains("/0'/"));
    }

    /// Indices must stay inside BIP32's unhardened range.
    #[test]
    fn the_quorum_path_indices_are_in_range() {
        for id in ["a", "lock-1", "zzzz", &"f".repeat(64)] {
            let path = quorum_derivation_path(id);
            for seg in path.split('/').skip(4) {
                let n: u64 = seg.parse().expect("a plain index");
                assert!(n < 0x8000_0000, "index {n} is hardened territory");
            }
        }
    }

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
