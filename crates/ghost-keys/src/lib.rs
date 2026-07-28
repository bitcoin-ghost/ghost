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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Keys - Privacy-preserving key derivation for Ghost Pay
//!
//! Ghost Keys are the identity foundation of Ghost Pay. Based on BIP-352 Silent Payments,
//! they enable unlinkable stealth addresses where each payment creates a unique address
//! that only the recipient can detect.
//!
//! # Key Components
//!
//! - **Scan Key**: Used to detect incoming payments (shared secret derivation)
//! - **Spend Key**: Used to spend received funds
//! - **Ghost ID**: Public identifier (scan_pubkey + spend_pubkey) shared to receive payments
//!
//! # Example
//!
//! ```
//! use ghost_keys::{GhostKeys, GhostId};
//!
//! // Generate new Ghost Keys
//! let keys = GhostKeys::generate();
//!
//! // Get Ghost ID to share with senders
//! let ghost_id = keys.ghost_id();
//!
//! // Sender derives payment address (k=0 for first output to this recipient)
//! let (address, ephemeral_pubkey) = ghost_id.derive_payment_address_v2(0).unwrap();
//! ```

#![deny(unreachable_pub)]

mod config;
mod derivation;
pub mod encryption;
mod error;
mod ghost_id;
mod keys;
pub mod labels;
pub mod metadata;
mod scanning;

pub use config::ScanConfig;
pub use derivation::{
    compute_tweak_v2, derive_payment_address_v2, derive_shared_secret, derive_spend_key,
    tagged_hash,
};
// M-15/M-17: Re-export Zeroizing for callers who receive zeroizing wrappers
pub use encryption::{decrypt_note_data, encrypt_note_data, NoteData};
pub use error::GhostKeyError;
pub use ghost_id::{GhostId, GhostNetwork};
pub use keys::{GhostKeys, GhostKeysExport};
pub use labels::{LabelBackup, LabelDictionary};
pub use metadata::{
    decrypt_metadata, encrypt_metadata, PaymentMetadata, DEFAULT_LABEL, MAX_MEMO_LENGTH,
    METADATA_CIPHERTEXT_SIZE, METADATA_PLAINTEXT_SIZE,
};
pub use scanning::{BatchScanner, PaymentDetector, ScannedPayment};
pub use zeroize::Zeroizing;

/// Human-readable part for Ghost ID bech32 encoding (mainnet)
pub const GHOST_ID_HRP: &str = "ghost";

/// Human-readable part for Ghost ID bech32 encoding (testnet)
pub const GHOST_ID_HRP_TESTNET: &str = "tghost";

/// Human-readable part for Ghost ID bech32 encoding (signet)
pub const GHOST_ID_HRP_SIGNET: &str = "sghost";

/// Human-readable part for Ghost ID bech32 encoding (regtest)
pub const GHOST_ID_HRP_REGTEST: &str = "rghost";

/// Derivation path prefix for Ghost Keys (m/777'/...)
pub const GHOST_DERIVATION_PREFIX: u32 = 777;

/// OP_RETURN marker for Ghost Pay Ghost Lock
pub const GHOST_LOCK_MARKER: &[u8] = b"GPGL";

// ============================================================================
// Silent Payment v2 Constants (Counter-based k)
// ============================================================================

/// Default maximum k value to scan for payments
///
/// Most transactions have few outputs to the same recipient (typically 1-3),
/// so k=10 covers normal usage while keeping scanning fast.
pub const DEFAULT_MAX_K: u32 = 10;

/// Maximum configurable k value (hard limit)
///
/// Prevents excessive scanning time. Users can configure up to 10,000 to
/// recover payments that used higher k values.
pub const MAX_MAX_K: u32 = 10_000;

/// Domain separator for v2 tweak calculation
///
/// Used to ensure tweaks from v1 and v2 don't collide, and provides
/// domain separation per BIP-340 recommendations.
pub const DOMAIN_SEPARATOR_V2: &[u8] = b"ghost/silent-payment/v2";

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_key_generation() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Verify keys are valid
        assert!(keys.scan_secret().secret_bytes().len() == 32);
        assert!(keys.spend_secret().secret_bytes().len() == 32);

        // Verify Ghost ID encodes correctly
        let encoded = ghost_id.to_string();
        assert!(encoded.starts_with("ghost1"));

        // Verify round-trip
        let decoded = GhostId::from_str(&encoded).unwrap();
        assert_eq!(ghost_id.scan_pubkey(), decoded.scan_pubkey());
        assert_eq!(ghost_id.spend_pubkey(), decoded.spend_pubkey());
    }

    #[test]
    fn test_payment_derivation() {
        let receiver_keys = GhostKeys::generate();
        let ghost_id = receiver_keys.ghost_id();

        // Sender derives payment address using v2 (k-based)
        let (address, ephemeral_pubkey) = ghost_id.derive_payment_address_v2(0).unwrap();

        // Receiver can detect and spend using default config
        let detected = receiver_keys
            .detect_payment_default(&ephemeral_pubkey, &address)
            .unwrap();
        assert!(detected.is_some());

        let (spend_key, k) = detected.unwrap();
        // Verify spend key matches and k=0
        assert!(spend_key.secret_bytes().len() == 32);
        assert_eq!(k, 0);
    }

    #[test]
    fn test_unlinkable_addresses() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Multiple payments with different k values create different addresses
        let (addr0, _, _) = ghost_id.derive_payment_address_v2_full(0).unwrap();
        let (addr1, _, _) = ghost_id.derive_payment_address_v2_full(1).unwrap();
        let (addr2, _, _) = ghost_id.derive_payment_address_v2_full(2).unwrap();

        assert_ne!(addr0, addr1);
        assert_ne!(addr0, addr2);
        assert_ne!(addr1, addr2);
    }
}
