//! Worker-Specific Hashrate Tracking (extension_type=0x0002)
//!
//! This extension enables tracking of individual worker hashrates within aggregated extended channels
//! by appending TLV-encoded worker identity fields to SubmitSharesExtended messages.

use alloc::{
    fmt,
    string::{String, ToString},
    vec::Vec,
};

/// Maximum length for user identity in bytes.
///
/// The TLV `length` field is a `u16`, so the encoding permits far more than this; 255 matches
/// the `Str0255` limit used for identity strings elsewhere in SV2.
///
/// This was 32, which fits a bare worker name but not a full `<address>.<worker>` — a bech32
/// address is 42 bytes by itself. It was raised because `UserIdentity::new` returns `Err` past
/// the cap and the caller discards that error with `.ok()`, so an over-long identity did not
/// truncate — it silently sent NO TLV at all and the pool fell back to the channel identity.
/// The cap staying generous is what keeps that failure mode out of reach.
///
/// NOTE: this is the *wire* ceiling for the extension, not what the translator actually sends.
/// Since the revert of #447 the translator puts only the worker segment in the TLV, capped at 32
/// bytes by its own `tlv_compatible_username`; the payout address travels in the channel-level
/// identity and the pool recombines the two in `build_webhook_user_identity`. Do not read this
/// constant as evidence that the TLV carries a payout address — on `main` it does not.
pub const MAX_USER_IDENTITY_LENGTH: usize = 255;

/// Channel-level `user_identity` a translator sends when it opens a channel on
/// `mining.subscribe`, before the miner has authorised and its payout address is knowable.
///
/// A serialising SV1 client waits for the subscribe RESPONSE before it will authorise, and
/// that response must carry the real, pool-allocated extranonce — so the channel has to open
/// first, with no address to name. The address then travels per share in this extension's
/// [`UserIdentity`] TLV, which for such a channel carries the full `<address>.<worker>`
/// rather than the worker segment alone.
///
/// ⚠ Single owner, deliberately. The translator stamps it and the pool matches on it; a
/// second copy that drifted would leave the pool splicing a worker onto a sentinel and
/// crediting the address portion — `sri` — to nobody. Two copies of
/// [`MAX_USER_IDENTITY_LENGTH`] drifting is what produced that exact failure once already.
///
/// The value must be a shape `PayoutMode::try_from` already parses (it resolves to full
/// donation) or the channel open is rejected outright, and has three segments so it cannot
/// collide with a miner that genuinely authorises as `sri/donate`.
pub const PROVISIONAL_CHANNEL_IDENTITY: &str = "sri/donate/provisional";

/// Extension type for Worker-Specific Hashrate Tracking
pub const EXTENSION_TYPE: u16 = 0x0002;

/// TLV field type for user identity within this extension
pub const FIELD_TYPE_USER_IDENTITY: u8 = 0x01;

/// UserIdentity for Worker-Specific Hashrate Tracking.
///
/// This structure represents a UserIdentity that can be appended to
/// `SubmitSharesExtended` messages via TLV encoding when the Worker-Specific Hashrate Tracking
/// extension (0x0002) is negotiated.
///
/// The UserIdentity is stored as raw UTF-8 bytes (max [`MAX_USER_IDENTITY_LENGTH`]) to
/// match the TLV specification exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    /// UserIdentity as raw UTF-8 bytes (max [`MAX_USER_IDENTITY_LENGTH`]).
    ///
    /// The TLV Value field contains these raw bytes directly.
    pub(crate) user_identity: Vec<u8>,
}

impl UserIdentity {
    /// Creates a new UserIdentity from a string.
    pub fn new(user_identity: &str) -> Result<Self, &'static str> {
        Self::from_bytes(user_identity.as_bytes())
    }

    /// Creates a UserIdentity directly from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > MAX_USER_IDENTITY_LENGTH {
            return Err("UserIdentity exceeds MAX_USER_IDENTITY_LENGTH");
        }
        Ok(Self {
            user_identity: bytes.to_vec(),
        })
    }

    /// Returns the UserIdentity as a string slice (if valid UTF-8).
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.user_identity).ok()
    }

    /// Returns the UserIdentity as a String (if valid UTF-8) or hex representation.
    pub fn as_string_or_hex(&self) -> String {
        match core::str::from_utf8(&self.user_identity) {
            Ok(s) => s.to_string(),
            Err(_) => {
                let mut hex = String::from("0x");
                for byte in &self.user_identity {
                    use core::fmt::Write;
                    let _ = write!(&mut hex, "{:02x}", byte);
                }
                hex
            }
        }
    }

    /// Returns the raw bytes of the UserIdentity.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.user_identity.as_slice()
    }

    /// Returns the length of the UserIdentity in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.user_identity.as_slice().len()
    }

    /// Returns true if the UserIdentity is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.user_identity.is_empty()
    }
}

impl fmt::Display for UserIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserIdentity({})", self.as_string_or_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_user_identity() {
        let msg = UserIdentity::new("Worker_001").unwrap();
        assert_eq!(msg.as_str().unwrap(), "Worker_001");
        assert_eq!(msg.len(), 10);
    }

    #[test]
    fn test_user_identity_max_length() {
        let worker_name = "W".repeat(MAX_USER_IDENTITY_LENGTH);
        let msg = UserIdentity::new(&worker_name).unwrap();
        assert_eq!(msg.as_str().unwrap(), worker_name);
        assert_eq!(msg.len(), MAX_USER_IDENTITY_LENGTH);
    }

    #[test]
    fn test_user_identity_fits_full_address_and_worker() {
        // The TLV must carry a full `<address>.<worker>`, because for a channel opened before
        // `mining.authorize` it is the only place the miner's payout address travels. A bech32
        // address alone is 42 bytes, so the old 32-byte cap rejected these outright — and the
        // caller discards the error, so the TLV vanished and shares were credited to the
        // channel's provisional identity instead of the miner.
        for identity in [
            "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492.braiins",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr.worker1",
            "148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN.SKBitaxe",
        ] {
            let msg = UserIdentity::new(identity)
                .unwrap_or_else(|e| panic!("{identity} ({} bytes) rejected: {e}", identity.len()));
            assert_eq!(msg.as_str().unwrap(), identity);
        }
    }

    #[test]
    fn test_user_identity_short() {
        let msg = UserIdentity::new("W1").unwrap();
        assert_eq!(msg.as_str().unwrap(), "W1");
        assert_eq!(msg.len(), 2);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_user_identity_empty() {
        let msg = UserIdentity::new("").unwrap();
        assert!(msg.is_empty());
        assert_eq!(msg.len(), 0);
    }

    #[test]
    fn test_user_identity_too_long() {
        let too_long = "x".repeat(MAX_USER_IDENTITY_LENGTH + 1);
        let result = UserIdentity::new(&too_long);
        assert!(result.is_err());
    }

    #[test]
    fn test_as_string_or_hex() {
        let msg = UserIdentity::new("Worker").unwrap();
        assert_eq!(msg.as_string_or_hex(), "Worker");

        // Test with invalid UTF-8
        let invalid_utf8 = UserIdentity {
            user_identity: vec![0xFF, 0xFE],
        };
        assert!(invalid_utf8.as_string_or_hex().starts_with("0x"));
    }

    #[test]
    fn test_from_bytes() {
        let bytes = b"Worker_123";
        let identity = UserIdentity::from_bytes(bytes).unwrap();
        assert_eq!(identity.as_bytes(), bytes);
        assert_eq!(identity.len(), 10);
    }

    #[test]
    fn test_from_bytes_too_long() {
        let bytes = [b'x'; MAX_USER_IDENTITY_LENGTH + 1];
        let result = UserIdentity::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        let identity = UserIdentity::new("TestWorker").unwrap();
        let display = alloc::format!("{}", identity);
        assert!(display.contains("TestWorker"));
    }
}
