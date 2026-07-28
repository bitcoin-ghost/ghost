//! PIN-based authentication as a biometric fallback.
//!
//! Provides a 6-digit PIN manager that stores an Argon2id hash
//! in the platform keychain. Tracks failed attempts and locks
//! out after 5 consecutive failures (requiring mnemonic re-import).

use crate::storage::{Keychain, KeychainAccess, StorageError};
use subtle::ConstantTimeEq;

const MAX_ATTEMPTS: u32 = 5;
const KEYCHAIN_KEY_PIN_HASH: &str = "pin_hash";
const KEYCHAIN_KEY_FAIL_COUNT: &str = "pin_fail_count";

/// PIN validation errors.
#[derive(Debug, Clone, PartialEq)]
pub enum PinError {
    /// The PIN is not exactly 6 digits.
    InvalidFormat,
    /// Keychain storage operation failed.
    Storage(String),
    /// Too many failed attempts — mnemonic re-import required.
    LockedOut,
}

impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinError::InvalidFormat => write!(f, "PIN must be exactly 6 digits"),
            PinError::Storage(e) => write!(f, "storage error: {e}"),
            PinError::LockedOut => {
                write!(f, "too many failed attempts, re-import mnemonic required")
            }
        }
    }
}

impl std::error::Error for PinError {}

impl From<StorageError> for PinError {
    fn from(e: StorageError) -> Self {
        PinError::Storage(e.to_string())
    }
}

/// Manages a 6-digit PIN stored securely in the platform keychain.
pub struct PinManager {
    keychain: Keychain,
}

impl PinManager {
    /// Create a new PIN manager.
    pub fn new() -> Self {
        Self::with_service("com.ghost.tap.pin")
    }

    /// Create a PIN manager with a custom service identifier (for testing).
    fn with_service(service: &str) -> Self {
        Self {
            keychain: Keychain::new(service, KeychainAccess::WhenUnlockedThisDeviceOnly),
        }
    }

    /// Check if a PIN has been set.
    pub fn has_pin(&self) -> bool {
        self.keychain.retrieve(KEYCHAIN_KEY_PIN_HASH).is_ok()
    }

    /// Set (or replace) the PIN. Must be exactly 6 ASCII digits.
    ///
    /// Generates a random 16-byte salt and stores `salt(16) || hash(32)`.
    pub fn set_pin(&self, pin: &str) -> Result<(), PinError> {
        if !Self::is_valid_format(pin) {
            return Err(PinError::InvalidFormat);
        }

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)
            .map_err(|e| PinError::Storage(format!("RNG failed: {e}")))?;

        let hash = Self::hash_pin_with_salt(pin, &salt)?;
        let mut stored = Vec::with_capacity(48);
        stored.extend_from_slice(&salt);
        stored.extend_from_slice(&hash);
        self.keychain.store(KEYCHAIN_KEY_PIN_HASH, &stored)?;
        // Reset fail counter on PIN change
        self.keychain
            .store(KEYCHAIN_KEY_FAIL_COUNT, &0u32.to_le_bytes())?;
        Ok(())
    }

    /// Verify a PIN against the stored hash.
    ///
    /// Returns `Ok(true)` if correct, `Ok(false)` if wrong (and increments
    /// the fail counter). Returns `Err(PinError::LockedOut)` if the fail
    /// counter has reached the maximum.
    pub fn verify_pin(&self, pin: &str) -> Result<bool, PinError> {
        if self.remaining_attempts() == 0 {
            return Err(PinError::LockedOut);
        }

        let stored = self
            .keychain
            .retrieve(KEYCHAIN_KEY_PIN_HASH)
            .map_err(|_| PinError::Storage("no PIN set".into()))?;

        if stored.len() < 48 {
            return Err(PinError::Storage("corrupt PIN hash".into()));
        }

        let salt = &stored[..16];
        let stored_hash = &stored[16..48];
        let candidate_hash = Self::hash_pin_with_salt(pin, salt)?;

        if bool::from(stored_hash.ct_eq(&candidate_hash)) {
            // Reset fail counter on success
            self.keychain
                .store(KEYCHAIN_KEY_FAIL_COUNT, &0u32.to_le_bytes())?;
            Ok(true)
        } else {
            // Increment fail counter
            let count = self.fail_count() + 1;
            self.keychain
                .store(KEYCHAIN_KEY_FAIL_COUNT, &count.to_le_bytes())?;
            if count >= MAX_ATTEMPTS {
                Err(PinError::LockedOut)
            } else {
                Ok(false)
            }
        }
    }

    /// Number of remaining PIN attempts before lockout.
    pub fn remaining_attempts(&self) -> u32 {
        MAX_ATTEMPTS.saturating_sub(self.fail_count())
    }

    /// Clear the PIN and fail counter from the keychain.
    pub fn clear(&self) {
        let _ = self.keychain.delete(KEYCHAIN_KEY_PIN_HASH);
        let _ = self.keychain.delete(KEYCHAIN_KEY_FAIL_COUNT);
    }

    /// Authenticate with biometrics (delegates to keychain).
    pub fn authenticate_biometric() -> Result<bool, PinError> {
        Keychain::authenticate_biometric("Unlock GhostTap wallet").map_err(PinError::from)
    }

    // -- Private helpers --

    fn is_valid_format(pin: &str) -> bool {
        pin.len() == 6 && pin.bytes().all(|b| b.is_ascii_digit())
    }

    fn hash_pin_with_salt(pin: &str, salt: &[u8]) -> Result<[u8; 32], PinError> {
        use argon2::Argon2;
        let mut hash = [0u8; 32];
        Argon2::default()
            .hash_password_into(pin.as_bytes(), salt, &mut hash)
            .map_err(|e| PinError::Storage(format!("Argon2 KDF failed: {e}")))?;
        Ok(hash)
    }

    fn fail_count(&self) -> u32 {
        self.keychain
            .retrieve(KEYCHAIN_KEY_FAIL_COUNT)
            .ok()
            .and_then(|bytes| {
                if bytes.len() >= 4 {
                    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }
}

impl Default for PinManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test uses a unique service to avoid parallel test interference.
    fn test_pm(name: &str) -> PinManager {
        let pm = PinManager::with_service(&format!("test.pin.{name}"));
        pm.clear();
        pm
    }

    #[test]
    fn test_set_and_verify_pin() {
        let pm = test_pm("set_verify");
        assert!(!pm.has_pin());
        pm.set_pin("123456").unwrap();
        assert!(pm.has_pin());
        assert!(pm.verify_pin("123456").unwrap());
        assert_eq!(pm.remaining_attempts(), 5);
    }

    #[test]
    fn test_wrong_pin() {
        let pm = test_pm("wrong");
        pm.set_pin("111111").unwrap();
        assert!(!pm.verify_pin("000000").unwrap());
        assert_eq!(pm.remaining_attempts(), 4);
    }

    #[test]
    fn test_lockout_after_5_failures() {
        let pm = test_pm("lockout");
        pm.set_pin("999999").unwrap();

        for i in 0..4u32 {
            assert!(!pm.verify_pin("000000").unwrap());
            assert_eq!(pm.remaining_attempts(), 4 - i);
        }
        // 5th failure triggers lockout
        assert!(matches!(pm.verify_pin("000000"), Err(PinError::LockedOut)));
        assert_eq!(pm.remaining_attempts(), 0);

        // Even correct PIN is rejected when locked out
        assert!(matches!(pm.verify_pin("999999"), Err(PinError::LockedOut)));
    }

    #[test]
    fn test_correct_pin_resets_counter() {
        let pm = test_pm("reset");
        pm.set_pin("123456").unwrap();
        assert!(!pm.verify_pin("000000").unwrap());
        assert!(!pm.verify_pin("000000").unwrap());
        assert_eq!(pm.remaining_attempts(), 3);

        // Correct PIN resets counter
        assert!(pm.verify_pin("123456").unwrap());
        assert_eq!(pm.remaining_attempts(), 5);
    }

    #[test]
    fn test_has_pin_before_and_after() {
        let pm = test_pm("has_pin");
        assert!(!pm.has_pin());
        pm.set_pin("654321").unwrap();
        assert!(pm.has_pin());
        pm.clear();
        assert!(!pm.has_pin());
    }

    #[test]
    fn test_invalid_pin_format() {
        let pm = test_pm("format");
        assert!(matches!(pm.set_pin("12345"), Err(PinError::InvalidFormat)));
        assert!(matches!(
            pm.set_pin("1234567"),
            Err(PinError::InvalidFormat)
        ));
        assert!(matches!(pm.set_pin("abcdef"), Err(PinError::InvalidFormat)));
        assert!(matches!(pm.set_pin("12ab56"), Err(PinError::InvalidFormat)));
    }
}
