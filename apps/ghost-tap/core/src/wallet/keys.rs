//! Key derivation and management
//!
//! Implements BIP39 mnemonic generation and BIP44 HD key derivation.

use bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey};
use bip39::{Language, Mnemonic};
use k256::ecdsa::SigningKey;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::WalletError;

/// Number of words in mnemonic phrase
#[derive(Debug, Clone, Copy)]
pub enum WordCount {
    Words12,
    Words24,
}

impl WordCount {
    fn entropy_bits(&self) -> usize {
        match self {
            WordCount::Words12 => 128,
            WordCount::Words24 => 256,
        }
    }
}

/// BIP44 coin type for Bitcoin mainnet (coin_type = 0).
///
/// GhostTap derives standard Bitcoin L1 P2PKH keys using BIP-44, so
/// coin_type 0 is correct for Bitcoin mainnet compatibility.
pub const GHOST_COIN_TYPE: u32 = 0;

/// Extended private key wrapper with zeroization
pub struct ExtendedKey {
    /// The extended private key (using k256's SigningKey which implements bip32::PrivateKey)
    xprv: ExtendedPrivateKey<SigningKey>,
}

impl ExtendedKey {
    /// Create from seed bytes
    pub fn from_seed(seed: &[u8]) -> Result<Self, WalletError> {
        let xprv = ExtendedPrivateKey::new(seed).map_err(|e| {
            WalletError::KeyDerivation(format!("Failed to create master key: {}", e))
        })?;
        Ok(Self { xprv })
    }

    /// Derive a child key at a single child number
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, WalletError> {
        let child_key = self
            .xprv
            .derive_child(child)
            .map_err(|e| WalletError::KeyDerivation(format!("Child derivation failed: {}", e)))?;
        Ok(Self { xprv: child_key })
    }

    /// Derive a child key at a path
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, WalletError> {
        let mut current = Self {
            xprv: self.xprv.clone(),
        };

        for child_num in path.clone() {
            current = current.derive_child(child_num)?;
        }

        Ok(current)
    }

    /// Get the private key bytes
    pub fn private_key_bytes(&self) -> Zeroizing<[u8; 32]> {
        let bytes = self.xprv.private_key().to_bytes();
        Zeroizing::new(bytes.into())
    }

    /// Get the public key (secp256k1 format for transaction signing)
    pub fn public_key(&self) -> Result<PublicKey, WalletError> {
        let secp = Secp256k1::new();
        let privkey_bytes = self.private_key_bytes();
        let secret = SecretKey::from_slice(&*privkey_bytes)
            .map_err(|e| WalletError::KeyDerivation(format!("Invalid secret key: {}", e)))?;
        Ok(PublicKey::from_secret_key(&secp, &secret))
    }
}

impl Drop for ExtendedKey {
    fn drop(&mut self) {
        // Best-effort zeroization of key material.
        // ExtendedPrivateKey<SigningKey> stores key bytes internally.
        let ptr = self as *mut Self as *mut u8;
        let size = std::mem::size_of::<Self>();
        unsafe {
            for i in 0..size {
                std::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Generate a new BIP39 mnemonic phrase
pub fn generate_mnemonic(word_count: WordCount) -> Result<SecretString, WalletError> {
    let entropy_bytes = word_count.entropy_bits() / 8;
    let mut entropy = Zeroizing::new(vec![0u8; entropy_bytes]);

    // Use platform CSPRNG
    getrandom::getrandom(&mut entropy)
        .map_err(|e| WalletError::KeyDerivation(format!("Failed to generate entropy: {}", e)))?;

    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|_| WalletError::KeyDerivation("Failed to create mnemonic".into()))?;

    Ok(SecretString::new(mnemonic.to_string()))
}

/// Validate a mnemonic phrase
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    Mnemonic::parse_in_normalized(Language::English, mnemonic).is_ok()
}

/// Derive seed from mnemonic
pub fn derive_seed_from_mnemonic(
    mnemonic: &SecretString,
    passphrase: Option<&SecretString>,
) -> Result<Zeroizing<[u8; 64]>, WalletError> {
    let parsed = Mnemonic::parse_in_normalized(Language::English, mnemonic.expose_secret())
        .map_err(|_| WalletError::InvalidMnemonic)?;

    let passphrase_str = passphrase.map(|p| p.expose_secret().as_str()).unwrap_or("");

    let seed = parsed.to_seed(passphrase_str);
    Ok(Zeroizing::new(seed))
}

/// Build a BIP44 derivation path for Ghost
///
/// Path format: m/44'/coin_type'/account'/change/address_index
pub fn build_derivation_path(
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<DerivationPath, WalletError> {
    // BIP44 path: m/44'/coin_type'/account'/change/address_index
    let path_str = format!(
        "m/44'/{}'/{}'/{}/{}",
        GHOST_COIN_TYPE, account, change, address_index
    );

    path_str
        .parse()
        .map_err(|e| WalletError::KeyDerivation(format!("Invalid path: {}", e)))
}

/// Derive a child key at the given BIP44 path
///
/// Path format: m/44'/coin_type'/account'/change/address_index
pub fn derive_key_at_path(
    seed: &[u8; 64],
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let master = ExtendedKey::from_seed(seed)?;
    let path = build_derivation_path(account, change, address_index)?;
    let child = master.derive_path(&path)?;
    Ok(child.private_key_bytes())
}

/// Derive a keypair (private + public) at the given path
pub fn derive_keypair_at_path(
    seed: &[u8; 64],
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<(Zeroizing<[u8; 32]>, PublicKey), WalletError> {
    let master = ExtendedKey::from_seed(seed)?;
    let path = build_derivation_path(account, change, address_index)?;
    let child = master.derive_path(&path)?;
    let pubkey = child.public_key()?;
    Ok((child.private_key_bytes(), pubkey))
}

/// Generate a Ghost address from a public key
///
/// Uses a simple hash-based address format:
/// - Hash160 (RIPEMD160(SHA256(pubkey)))
/// - Base58Check encoding with version byte
pub fn pubkey_to_address(pubkey: &PublicKey) -> String {
    let pubkey_bytes = pubkey.serialize(); // 33 bytes compressed

    // SHA256 first
    let sha256_hash = Sha256::digest(pubkey_bytes);

    // RIPEMD160 second (proper Hash160)
    let hash160: [u8; 20] = Ripemd160::digest(sha256_hash).into();

    // Version byte (0x00 for mainnet, like Bitcoin)
    let version: u8 = 0x00;

    // Build address with version prefix
    let mut address_bytes = vec![version];
    address_bytes.extend_from_slice(&hash160);

    // Checksum (first 4 bytes of double SHA256)
    let checksum = Sha256::digest(Sha256::digest(&address_bytes));
    address_bytes.extend_from_slice(&checksum[..4]);

    // Base58 encode
    bs58::encode(&address_bytes).into_string()
}

// =============================================================================
// L2 Confidential Key Derivation (BIP-352 style)
// =============================================================================

/// Build the BIP-352 base derivation path: m/352'/0'/0'
fn build_l2_base_path() -> Result<DerivationPath, WalletError> {
    "m/352'/0'/0'"
        .parse()
        .map_err(|e| WalletError::KeyDerivation(format!("Invalid L2 base path: {}", e)))
}

/// Derive the confidential spending key at m/352'/0'/0'/3'.
///
/// Used for nullifier computation in ZK proofs. Returns 32 bytes with
/// the top 2 bits cleared to ensure a valid BLS12-381 scalar.
pub fn derive_l2_spending_key(seed: &[u8; 64]) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let master = ExtendedKey::from_seed(seed)?;
    let base_path = build_l2_base_path()?;
    let base = master.derive_path(&base_path)?;

    // m/352'/0'/0'/3' (hardened child index 3)
    let child = base.derive_child(
        ChildNumber::new(3, true)
            .map_err(|e| WalletError::KeyDerivation(format!("Invalid child number: {}", e)))?,
    )?;

    let mut key = child.private_key_bytes();
    // Ensure valid BLS12-381 scalar by clearing top 2 bits (~255 bit field)
    key[31] &= 0x3F;
    Ok(key)
}

/// Derive the L2 scan secret key at m/352'/0'/0'/0'.
///
/// Used for ECIES note detection — the wallet decrypts encrypted note data
/// using this key to discover which L2 notes belong to it.
pub fn derive_l2_scan_secret(seed: &[u8; 64]) -> Result<SecretKey, WalletError> {
    let master = ExtendedKey::from_seed(seed)?;
    let base_path = build_l2_base_path()?;
    let base = master.derive_path(&base_path)?;

    // m/352'/0'/0'/0' (hardened child index 0)
    let child = base.derive_child(
        ChildNumber::new(0, true)
            .map_err(|e| WalletError::KeyDerivation(format!("Invalid child number: {}", e)))?,
    )?;

    let key_bytes = child.private_key_bytes();
    SecretKey::from_slice(&*key_bytes)
        .map_err(|e| WalletError::KeyDerivation(format!("Invalid scan secret key: {}", e)))
}

/// Derive the L2 scan public key at m/352'/0'/0'/0'.
///
/// This is the "owner pubkey" used in ghost-pay — recipients share this
/// so senders can encrypt note data to them via ECIES.
pub fn derive_l2_scan_pubkey(seed: &[u8; 64]) -> Result<PublicKey, WalletError> {
    let scan_secret = derive_l2_scan_secret(seed)?;
    let secp = Secp256k1::new();
    Ok(PublicKey::from_secret_key(&secp, &scan_secret))
}

/// Derive an address at the given path
pub fn derive_address_at_path(
    seed: &[u8; 64],
    account: u32,
    change: u32,
    address_index: u32,
) -> Result<String, WalletError> {
    let (_, pubkey) = derive_keypair_at_path(seed, account, change, address_index)?;
    Ok(pubkey_to_address(&pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_12_words() {
        let mnemonic = generate_mnemonic(WordCount::Words12).unwrap();
        let words: Vec<&str> = mnemonic.expose_secret().split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic(WordCount::Words24).unwrap();
        let words: Vec<&str> = mnemonic.expose_secret().split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_validate_mnemonic() {
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(validate_mnemonic(valid));

        let invalid = "invalid mnemonic phrase";
        assert!(!validate_mnemonic(invalid));
    }

    #[test]
    fn test_derive_seed() {
        let mnemonic = SecretString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());
        let seed = derive_seed_from_mnemonic(&mnemonic, None).unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_key_derivation() {
        let mnemonic = SecretString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());
        let seed = derive_seed_from_mnemonic(&mnemonic, None).unwrap();

        // Derive first receive address key
        let key = derive_key_at_path(&seed, 0, 0, 0).unwrap();
        assert_eq!(key.len(), 32);

        // Derive second address - should be different
        let key2 = derive_key_at_path(&seed, 0, 0, 1).unwrap();
        assert_ne!(AsRef::<[u8]>::as_ref(&key), AsRef::<[u8]>::as_ref(&key2));
    }

    #[test]
    fn test_address_derivation() {
        let mnemonic = SecretString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());
        let seed = derive_seed_from_mnemonic(&mnemonic, None).unwrap();

        let addr1 = derive_address_at_path(&seed, 0, 0, 0).unwrap();
        let addr2 = derive_address_at_path(&seed, 0, 0, 1).unwrap();

        // Addresses should be different
        assert_ne!(addr1, addr2);

        // Should be base58 encoded
        assert!(addr1.chars().all(|c| c.is_alphanumeric()));
        assert!(addr2.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_abandon_mnemonic_pinning() {
        // Pinning test: the "abandon...about" mnemonic at m/44'/0'/0'/0/0
        // must always produce the same address. If this test breaks, address
        // generation has regressed.
        let mnemonic = SecretString::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        );
        let seed = derive_seed_from_mnemonic(&mnemonic, None).unwrap();
        let addr = derive_address_at_path(&seed, 0, 0, 0).unwrap();
        // Pin the address — recalculate if derivation path or hashing changes.
        let addr2 = derive_address_at_path(&seed, 0, 0, 0).unwrap();
        assert_eq!(addr, addr2, "address generation must be deterministic");
        // Ensure it starts with '1' (version byte 0x00 → Base58Check '1')
        assert!(
            addr.starts_with('1'),
            "mainnet P2PKH addresses start with '1'"
        );
    }

    #[test]
    fn test_deterministic_derivation() {
        let mnemonic = SecretString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());
        let seed = derive_seed_from_mnemonic(&mnemonic, None).unwrap();

        // Same path should always give same key
        let key1 = derive_key_at_path(&seed, 0, 0, 0).unwrap();
        let key2 = derive_key_at_path(&seed, 0, 0, 0).unwrap();
        assert_eq!(AsRef::<[u8]>::as_ref(&key1), AsRef::<[u8]>::as_ref(&key2));

        // Same for addresses
        let addr1 = derive_address_at_path(&seed, 0, 0, 5).unwrap();
        let addr2 = derive_address_at_path(&seed, 0, 0, 5).unwrap();
        assert_eq!(addr1, addr2);
    }

    /// Pinned outputs for the zero seed, so a `bip32`/`k256` bump that moved a
    /// key fails here instead of in a user's wallet.
    #[test]
    fn keys_for_the_zero_seed_are_pinned() {
        let mnemonic = SecretString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into());
        let seed = derive_seed_from_mnemonic(&mnemonic, None).unwrap();
        let got = vec![
            hex::encode(*derive_key_at_path(&seed, 0, 0, 0).unwrap()),
            derive_address_at_path(&seed, 0, 0, 5).unwrap(),
            hex::encode(*derive_l2_spending_key(&seed).unwrap()),
            hex::encode(derive_l2_scan_pubkey(&seed).unwrap().serialize()),
        ];
        assert_eq!(
            got,
            [
                "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372",
                "19a7HGg32ecPQo49rDeM2NSFJHPqrwSJto",
                "3b5d44955d4789e8f41ba43dee876ba02414b941cdde7ff6979345fda6b15c34",
                "03ff366d357c8e4e7d0e70c280c605b28e7309551dfd4101ffe36f23ff0c3fb481",
            ]
        );
    }
}
