//! Address keying and blob decoding for the shard's tables.
//!
//! ⚠ Rows are keyed by `H(plaintext address)`, **never the ciphertext**. Address encryption is
//! randomised, so the same address encrypts to a different blob every time and a ciphertext key
//! would silently create a second row for a payee already present — splitting one balance in two.
//! The hash is deterministic, so it collapses to one row and stays joinable.
//!
//! Written for the share-batch chain's store, which is deleted. The keying discipline outlived it:
//! `shard_store.rs` follows it exactly, and a second spelling would be a second way to split a
//! payee's balance.

use sha2::{Digest, Sha256};

use ghost_common::error::{GhostError, GhostResult};

/// Deterministic lookup key for a payout address.
///
/// NOT the ciphertext: `encrypt_sensitive` draws a fresh random nonce per call, so the same address
/// encrypts differently every time and a ciphertext key could never be matched — every write would
/// insert a new row and a miner's balance would scatter across duplicates instead of accumulating.
pub fn address_key(plaintext: &str) -> Vec<u8> {
    Sha256::digest(plaintext.as_bytes()).to_vec()
}

pub(crate) fn blob32(v: Vec<u8>, what: &str) -> GhostResult<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice())
        .map_err(|_| GhostError::Database(format!("{what} is not 32 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;

    fn db() -> Database {
        let db = Database::in_memory().expect("in-memory db");
        db.set_encryption_key([0x42u8; 32]);
        db
    }

    /// The same address must always produce the same key, or a lookup can never match.
    #[test]
    fn address_key_is_deterministic_unlike_the_ciphertext() {
        let db = db();
        let addr = "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492";

        assert_eq!(address_key(addr), address_key(addr));
        assert_ne!(address_key(addr), address_key("bc1qother"));

        // The reason the key is a hash and not the ciphertext.
        let a = db.encrypt_address(addr).expect("enc a");
        let b = db.encrypt_address(addr).expect("enc b");
        assert_ne!(
            a, b,
            "ciphertext is nonce-randomised, so it cannot be a key"
        );
    }
}
