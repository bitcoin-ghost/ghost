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
//| FILE: encryption.rs                                                                                                  |
//|======================================================================================================================|

//! H-6: Encryption for sensitive database fields
//!
//! Provides field-level encryption for sensitive data stored in the database,
//! such as payout addresses. Uses ChaCha20-Poly1305 for authenticated encryption.
//!
//! # Usage
//!
//! ```ignore
//! use ghost_storage::encryption::{encrypt_sensitive, decrypt_sensitive};
//!
//! // Encrypt before storing
//! let key = get_encryption_key();
//! let encrypted = encrypt_sensitive("bc1q...", &key)?;
//! db.store_address(&encrypted)?;
//!
//! // Decrypt after retrieval
//! let encrypted = db.get_address()?;
//! let plaintext = decrypt_sensitive(&encrypted, &key)?;
//! ```
//!
//! # Key Management
//!
//! The encryption key should be:
//! - 32 bytes (256 bits)
//! - Derived from a user password using a KDF (e.g., scrypt, Argon2)
//! - Stored securely (environment variable, HSM, or secure enclave)
//! - NEVER stored in the database
//!
//! For mainnet, the key MUST come from GHOST_ENCRYPTION_KEY environment variable
//! or be provided via configuration.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ghost_common::error::{GhostError, GhostResult};

/// Nonce size for ChaCha20-Poly1305 (12 bytes)
const NONCE_SIZE: usize = 12;

/// Encrypt a sensitive string before storing in database.
///
/// Uses ChaCha20-Poly1305 for authenticated encryption.
/// Output format: base64(nonce || ciphertext || tag)
///
/// # Arguments
/// * `plaintext` - The sensitive data to encrypt
/// * `key` - 32-byte encryption key
///
/// # Returns
/// Base64-encoded encrypted data suitable for database storage
///
/// # Security
/// - Uses a random nonce for each encryption
/// - Provides authentication (tampering detection)
/// - Ciphertext is base64-encoded for safe text storage
pub fn encrypt_sensitive(plaintext: &str, key: &[u8; 32]) -> GhostResult<String> {
    // Create cipher
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| GhostError::Crypto(format!("Invalid encryption key: {}", e)))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| GhostError::Crypto(format!("RNG failed: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| GhostError::Crypto(format!("Encryption failed: {}", e)))?;

    // Combine: nonce || ciphertext (tag is included in ciphertext by AEAD)
    let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    // Base64 encode for database storage
    Ok(BASE64.encode(&combined))
}

/// Decrypt a sensitive string retrieved from database.
///
/// Expects base64(nonce || ciphertext || tag) format.
///
/// # Arguments
/// * `encrypted` - Base64-encoded encrypted data from database
/// * `key` - 32-byte encryption key (must match encryption key)
///
/// # Returns
/// The original plaintext string
///
/// # Errors
/// - `GhostError::Crypto` if decryption fails (wrong key, tampered data, etc.)
pub fn decrypt_sensitive(encrypted: &str, key: &[u8; 32]) -> GhostResult<String> {
    // Decode base64
    let combined = BASE64
        .decode(encrypted)
        .map_err(|e| GhostError::Crypto(format!("Invalid base64: {}", e)))?;

    // Validate minimum length (nonce + at least 1 byte + tag)
    if combined.len() < NONCE_SIZE + 16 {
        return Err(GhostError::Crypto("Encrypted data too short".into()));
    }

    // Split nonce and ciphertext
    let nonce = Nonce::from_slice(&combined[..NONCE_SIZE]);
    let ciphertext = &combined[NONCE_SIZE..];

    // Create cipher and decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| GhostError::Crypto(format!("Invalid encryption key: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| GhostError::Crypto("Decryption failed - wrong key or tampered data".into()))?;

    // Convert to string
    String::from_utf8(plaintext).map_err(|e| GhostError::Crypto(format!("Invalid UTF-8: {}", e)))
}

/// LOW FIX: Check if a string could potentially be encrypted data.
///
/// This is a HEURISTIC check to help with migration from plaintext to encrypted storage.
/// It checks if the string is valid base64 and decodes to at least nonce + tag size.
///
/// **WARNING: This function can produce false positives.**
/// A string that passes this check is not necessarily encrypted data - it could be
/// any base64-encoded data of sufficient length. Use this only as a hint for migration
/// purposes, not as a security check.
///
/// Renamed from `is_likely_encrypted` to `could_be_encrypted` to clarify the heuristic nature.
pub fn could_be_encrypted(value: &str) -> bool {
    if let Ok(decoded) = BASE64.decode(value) {
        // Encrypted data must be at least nonce (12) + tag (16) = 28 bytes
        decoded.len() >= NONCE_SIZE + 16
    } else {
        false
    }
}

/// Deprecated alias for `could_be_encrypted`. Use `could_be_encrypted` instead.
#[deprecated(
    since = "1.0.0",
    note = "Renamed to could_be_encrypted() to clarify heuristic nature"
)]
pub fn is_likely_encrypted(value: &str) -> bool {
    could_be_encrypted(value)
}

/// LOW-STOR-7: Check if a key has sufficient entropy
///
/// Rejects keys that are clearly non-random:
/// - All zeros
/// - All same byte
/// - Sequential bytes
/// - Very low unique byte count
///
/// **SECURITY WARNING: This is a HEURISTIC check only.**
///
/// This function can detect obviously weak keys but CANNOT guarantee cryptographic
/// strength. Keys MUST be generated from a cryptographically secure pseudorandom
/// number generator (CSPRNG) such as:
/// - `openssl rand -hex 32`
/// - `getrandom` crate
/// - `/dev/urandom` on Unix
/// - `CryptGenRandom` on Windows
///
/// A key that passes this check is NOT necessarily secure - it simply isn't
/// obviously weak. Always use proper key generation, never derive keys from
/// passwords without a proper KDF (Argon2, scrypt), and never reuse keys.
#[cfg(test)]
fn has_sufficient_entropy(key: &[u8; 32]) -> bool {
    // Reject all zeros
    if key.iter().all(|&b| b == 0) {
        return false;
    }

    // Reject all same byte
    let first = key[0];
    if key.iter().all(|&b| b == first) {
        return false;
    }

    // Reject sequential patterns (0x00 0x01 0x02... or descending)
    let mut ascending = true;
    let mut descending = true;
    for i in 1..key.len() {
        if key[i] != key[i - 1].wrapping_add(1) {
            ascending = false;
        }
        if key[i] != key[i - 1].wrapping_sub(1) {
            descending = false;
        }
    }
    if ascending || descending {
        return false;
    }

    // Require at least 16 unique bytes (50% unique)
    // Random keys typically have >20 unique bytes out of 32
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in key.iter() {
        unique_bytes.insert(byte);
    }
    if unique_bytes.len() < 16 {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        // MEDIUM-STOR-2: Use a key with good entropy for tests
        // (not sequential, passes entropy validation)
        [
            0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7,
            0xf8, 0x09, 0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5,
            0xc6, 0xd7, 0xe8, 0xf9,
        ]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let encrypted =
            encrypt_sensitive(plaintext, &key).expect("MEDIUM-STOR-2: Failed to encrypt plaintext");
        let decrypted = decrypt_sensitive(&encrypted, &key)
            .expect("MEDIUM-STOR-2: Failed to decrypt ciphertext");

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypted_differs_from_plaintext() {
        let key = test_key();
        let plaintext = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

        let encrypted =
            encrypt_sensitive(plaintext, &key).expect("MEDIUM-STOR-2: Failed to encrypt plaintext");

        assert_ne!(plaintext, encrypted);
        assert!(encrypted.len() > plaintext.len()); // Adds nonce + tag
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xFF; // Different key

        let plaintext = "secret address";
        let encrypted = encrypt_sensitive(plaintext, &key1)
            .expect("MEDIUM-STOR-2: Failed to encrypt with key1");

        let result = decrypt_sensitive(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_data_fails() {
        let key = test_key();
        let plaintext = "secret address";
        let mut encrypted =
            encrypt_sensitive(plaintext, &key).expect("MEDIUM-STOR-2: Failed to encrypt plaintext");

        // Tamper with the encrypted data
        let mut bytes = BASE64
            .decode(&encrypted)
            .expect("MEDIUM-STOR-2: Failed to decode base64 encrypted data");
        bytes[NONCE_SIZE] ^= 0xFF;
        encrypted = BASE64.encode(&bytes);

        let result = decrypt_sensitive(&encrypted, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_could_be_encrypted() {
        let key = test_key();
        let encrypted =
            encrypt_sensitive("test", &key).expect("MEDIUM-STOR-2: Failed to encrypt test string");

        assert!(could_be_encrypted(&encrypted));
        assert!(!could_be_encrypted("bc1qtest")); // Plaintext address
        assert!(!could_be_encrypted("short")); // Too short

        // LOW FIX: Also test the deprecated alias still works
        #[allow(deprecated)]
        {
            assert!(is_likely_encrypted(&encrypted));
        }
    }

    #[test]
    fn test_empty_string() {
        let key = test_key();
        let encrypted =
            encrypt_sensitive("", &key).expect("MEDIUM-STOR-2: Failed to encrypt empty string");
        let decrypted = decrypt_sensitive(&encrypted, &key)
            .expect("MEDIUM-STOR-2: Failed to decrypt empty ciphertext");
        assert_eq!("", decrypted);
    }

    #[test]
    fn test_entropy_validation_rejects_weak_keys() {
        // All zeros
        let all_zeros = [0u8; 32];
        assert!(!has_sufficient_entropy(&all_zeros));

        // All same byte
        let all_same = [0x42u8; 32];
        assert!(!has_sufficient_entropy(&all_same));

        // Sequential ascending
        let mut sequential = [0u8; 32];
        for (i, byte) in sequential.iter_mut().enumerate() {
            *byte = i as u8;
        }
        assert!(!has_sufficient_entropy(&sequential));

        // Sequential descending
        let mut sequential_desc = [0u8; 32];
        for (i, byte) in sequential_desc.iter_mut().enumerate() {
            *byte = (31 - i) as u8;
        }
        assert!(!has_sufficient_entropy(&sequential_desc));

        // Low unique byte count (only 10 unique bytes)
        let mut low_unique = [0u8; 32];
        for (i, byte) in low_unique.iter_mut().enumerate() {
            *byte = (i % 10) as u8;
        }
        assert!(!has_sufficient_entropy(&low_unique));
    }

    #[test]
    fn test_entropy_validation_accepts_good_keys() {
        // Test key has good entropy
        assert!(has_sufficient_entropy(&test_key()));

        // Another random-looking key
        let good_key = [
            0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6,
            0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x91, 0xa2, 0xb3, 0xc4, 0xd5,
            0xe6, 0xf7, 0x08, 0x19,
        ];
        assert!(has_sufficient_entropy(&good_key));
    }
}
