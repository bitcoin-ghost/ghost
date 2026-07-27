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

//! Ghost Locks - P2WSH UTXO management for Ghost Pay (Quantum-Safe)
//!
//! Ghost Locks are the on-chain representation of funds in Ghost Pay. They use
//! P2WSH (Pay-to-Witness-Script-Hash) outputs for quantum safety:
//!
//! - **P2WSH hides public keys**: Only a hash is visible on-chain until spending
//! - **Two spending paths**: Normal (lock key) and recovery (after timelock)
//! - **Quantum-safe**: Public keys are not exposed while funds are locked
//!
//! # Quantum Safety
//!
//! Unlike P2TR (Taproot) which exposes public keys on-chain, P2WSH outputs only
//! reveal a script hash. The actual public keys are only revealed at spend time,
//! providing protection against quantum computers that could derive private keys
//! from exposed public keys.
//!
//! # Features
//!
//! - **Standard Denominations**: Micro (10k sats) to XL (10 BTC) for privacy
//! - **Timelock Recovery**: 6 month, 1 year, or 2 year recovery options
//! - **Jump Locks**: Risk-tiered automatic key rotation
//!
//! # Example
//!
//! ```no_run
//! use ghost_locks::{GhostLock, Denomination, TimelockTier};
//! use bitcoin::secp256k1::{Secp256k1, SecretKey};
//!
//! // Generate keys (in production, use proper key derivation)
//! let lock_bytes = [1u8; 32]; // Example only - use proper entropy!
//! let recovery_bytes = [2u8; 32];
//!
//! let secp = Secp256k1::new();
//! let lock_secret = SecretKey::from_slice(&lock_bytes).unwrap();
//! let recovery_secret = SecretKey::from_slice(&recovery_bytes).unwrap();
//!
//! let lock = GhostLock::new(
//!     &secp,
//!     &lock_secret,
//!     &recovery_secret,
//!     Denomination::Small,
//!     TimelockTier::Standard,
//!     800_000,
//! );
//!
//! assert!(lock.is_ok());
//! let lock = lock.unwrap();
//!
//! // The lock provides a P2WSH scriptPubKey for creating outputs
//! let script_pubkey = lock.script_pubkey();
//!
//! // IMPORTANT: Store the witness_script - needed for spending!
//! let witness_script = lock.witness_script();
//! ```

#![deny(unreachable_pub)]

mod affordability;
mod denomination;
mod error;
mod jump;
mod lock;
mod script;
mod state;
mod timelock;

pub use affordability::{
    assess_affordability, recommended_action, remaining_jumps_estimate, CostEstimates,
    JumpAffordability, RecommendedAction,
};
pub use denomination::{optimal_denominations, Denomination};
pub use error::GhostLockError;
pub use jump::{JumpRiskTier, JumpSchedule};
pub use lock::{GhostLock, GhostLockData};
pub use script::{
    build_lock_script, build_normal_witness, build_p2wsh_script_pubkey, build_recovery_witness,
    build_wsh_witness_script, compute_wsh_script_hash, ghost_lock_id, is_p2tr, is_p2wsh,
    is_quantum_safe_address, validate_no_p2tr, RecoveryInputParams, MAX_RECOVERY_BLOCKS,
    MIN_RECOMMENDED_RECOVERY_BLOCKS, P2TR_REJECTION_MSG, RECOVERY_NSEQUENCE,
};
pub use state::{LockState, StateTransition};
pub use timelock::{TimelockTier, MAX_CREATION_HEIGHT, MIN_RECOVERY_BLOCKS};

/// OP_RETURN marker for Ghost Lock creation
pub const GHOST_LOCK_MARKER: &[u8] = b"GPGL";

/// Minimum lock amount (dust threshold)
pub const MIN_LOCK_SATS: u64 = 546;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use rand::RngCore;

    fn generate_secret_key() -> SecretKey {
        // M-2 FIX: Use OsRng for cryptographic security instead of thread_rng()
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        SecretKey::from_slice(&secret_bytes).expect("32 bytes, within curve order")
    }

    #[test]
    fn test_create_lock() {
        let secp = Secp256k1::new();
        let lock_secret = generate_secret_key();
        let recovery_secret = generate_secret_key();

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        );

        assert!(lock.is_ok());
        let lock = lock.unwrap();
        assert_eq!(lock.denomination(), Denomination::Small);
        assert_eq!(lock.timelock_tier(), TimelockTier::Standard);
        assert_eq!(lock.creation_height(), 800_000);

        // Verify P2WSH output
        assert!(is_p2wsh(lock.script_pubkey()));
    }

    #[test]
    fn test_lock_address() {
        let secp = Secp256k1::new();
        let lock_secret = generate_secret_key();
        let recovery_secret = generate_secret_key();

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Medium,
            TimelockTier::Short,
            800_000,
        )
        .unwrap();

        // Should have a valid P2WSH script pubkey
        let script_pubkey = lock.script_pubkey();
        assert!(is_p2wsh(script_pubkey));
        assert!(!is_p2tr(script_pubkey));
    }

    #[test]
    fn test_recovery_available() {
        let secp = Secp256k1::new();
        let lock_secret = generate_secret_key();
        let recovery_secret = generate_secret_key();

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            TimelockTier::Short, // 6 months
            800_000,
        )
        .unwrap();

        // Not available yet
        assert!(!lock.is_recovery_available(800_000));
        assert!(!lock.is_recovery_available(810_000));

        // Available after timelock
        let recovery_height = lock.recovery_height();
        assert!(lock.is_recovery_available(recovery_height));
        assert!(lock.is_recovery_available(recovery_height + 1000));
    }

    #[test]
    fn test_quantum_safe_address_validation() {
        // P2WPKH/P2WSH are quantum-safe
        assert!(is_quantum_safe_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));

        // P2TR is NOT quantum-safe
        assert!(!is_quantum_safe_address(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        ));
    }
}
