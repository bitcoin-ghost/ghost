//! The shared secret that authenticates one Ghost process to another.
//!
//! Every internal HTTP hop on a Ghost node — the dashboard's proxy, ghost-pay, and since #603 the
//! share webhook that writes the payout ledger — proves itself by signing
//! `HMAC-SHA256(secret, timestamp_le_bytes ‖ body)` under `internal_api_secret`, and sends it as
//! `X-Ghost-Signature` alongside `X-Ghost-Timestamp`.
//!
//! # Why this lives in `ghost-common` rather than beside the server that verifies it
//!
//! Because the signer and the verifier are different binaries, and the contract between them is
//! made of bytes nobody can see on the wire: the timestamp is hashed as a LITTLE-ENDIAN `u64`,
//! and it is hashed BEFORE the body. Nothing in a function signature says so.
//!
//! While `pool_sv2` carried its own copy of that construction it also carried its own copy of the
//! secret-validation rule, and the two drifted immediately: the verifier accepts a secret of 32
//! bytes **or longer** and uses the first 32, while the emitter's copy demanded exactly 32. An
//! operator with a 96-hex secret would have got a ghost-pool that authenticated happily and a
//! `pool_sv2` that discarded every share it was asked to report. One implementation of both the
//! rule and the construction makes that class of split impossible rather than merely unlikely.
//!
//! # What it does and does not defend
//!
//! It proves the caller holds the secret, and the drift window bounds how long a captured request
//! stays replayable through the middleware. It is **not** by itself a defence against a key holder
//! re-sending a captured body: the signature stays valid for as long as the timestamp does, and
//! re-signing an identical body with a fresh timestamp is trivial for anyone with the key. Any
//! endpoint where a repeated request is not idempotent must dedupe on its own content — for the
//! share webhook that is the ingest dedup in `ghost_verification::server`.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Maximum accepted difference between a request's timestamp and server time.
///
/// API-4: 30 seconds. Generous for NTP-synchronised nodes, and it halves the window in which a
/// captured request can be replayed compared with the 60 s this started at.
pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Minimum accepted secret length, in bytes.
///
/// A shorter secret is refused rather than stretched: padding a weak secret to look like a strong
/// one is how a 16-byte key ends up protecting a payout ledger.
pub const MIN_SECRET_BYTES: usize = 32;

/// What can be wrong with a secret, a signature, or a timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalAuthError {
    /// The secret is too short, or has too little entropy to be a secret.
    WeakSecret(String),
    /// The secret is not decodable (bad hex).
    InvalidSecret(String),
    /// The signature is malformed, or does not match.
    InvalidSignature(String),
    /// The timestamp is further from server time than [`MAX_TIMESTAMP_DRIFT_SECS`].
    TimestampOutOfRange { received: u64, server_time: u64 },
}

impl std::fmt::Display for InternalAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalAuthError::WeakSecret(r) => write!(f, "Weak secret: {r}"),
            InternalAuthError::InvalidSecret(r) => write!(f, "Invalid secret: {r}"),
            InternalAuthError::InvalidSignature(r) => write!(f, "Invalid signature: {r}"),
            InternalAuthError::TimestampOutOfRange {
                received,
                server_time,
            } => write!(
                f,
                "Timestamp {received} outside acceptable range (server time: {server_time})"
            ),
        }
    }
}

impl std::error::Error for InternalAuthError {}

/// A validated 32-byte internal-API secret, and the only place the signing construction lives.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InternalAuthKey {
    secret: [u8; MIN_SECRET_BYTES],
}

impl InternalAuthKey {
    /// Validate a secret and take its first 32 bytes.
    ///
    /// Longer secrets are ACCEPTED and truncated. That is not a preference — it is the rule the
    /// deployed verifier has always applied, so an emitter that refused them would silently
    /// disagree with the node it is trying to talk to. Both halves now reach this one function.
    pub fn new(secret: &[u8]) -> Result<Self, InternalAuthError> {
        if secret.len() < MIN_SECRET_BYTES {
            return Err(InternalAuthError::WeakSecret(format!(
                "Internal API secret must be at least {MIN_SECRET_BYTES} bytes"
            )));
        }

        // A secret of one repeated byte is a placeholder somebody forgot to replace, not a key.
        if secret.iter().all(|&b| b == secret[0]) {
            return Err(InternalAuthError::WeakSecret(
                "Internal API secret has insufficient entropy".to_string(),
            ));
        }

        let mut key = [0u8; MIN_SECRET_BYTES];
        key.copy_from_slice(&secret[..MIN_SECRET_BYTES]);
        Ok(Self { secret: key })
    }

    /// Validate a hex-encoded secret. Surrounding whitespace is tolerated, because a secret is
    /// usually pasted.
    pub fn from_hex(hex_secret: &str) -> Result<Self, InternalAuthError> {
        let bytes = hex::decode(hex_secret.trim())
            .map_err(|_| InternalAuthError::InvalidSecret("Invalid hex encoding".to_string()))?;
        Self::new(&bytes)
    }

    /// `hex(HMAC-SHA256(secret, timestamp.to_le_bytes() ‖ body))`.
    ///
    /// The byte order of the timestamp and its position before the body are both part of the wire
    /// contract; neither is recoverable from the output, so neither may be "tidied".
    pub fn sign(&self, timestamp: u64, body: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&timestamp.to_le_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Check a signature and its timestamp against this secret.
    ///
    /// The drift check runs FIRST, so an expired request costs no HMAC computation.
    pub fn verify(
        &self,
        signature: &str,
        timestamp: u64,
        body: &[u8],
    ) -> Result<(), InternalAuthError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if timestamp.abs_diff(now) > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(InternalAuthError::TimestampOutOfRange {
                received: timestamp,
                server_time: now,
            });
        }

        let expected = self.sign(timestamp, body);
        let (Ok(expected), Ok(provided)) = (hex::decode(&expected), hex::decode(signature)) else {
            return Err(InternalAuthError::InvalidSignature(
                "Invalid hex encoding".to_string(),
            ));
        };

        if !constant_time_eq(&expected, &provided) {
            return Err(InternalAuthError::InvalidSignature(
                "Signature verification failed".to_string(),
            ));
        }

        Ok(())
    }
}

/// Constant-time byte comparison.
///
/// L-18: the length check leaks whether the lengths match, which is safe here — HMAC-SHA256 output
/// is always 32 bytes and that is public. The byte loop reveals nothing about WHICH bytes differ,
/// which is the part that would matter.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Current time in whole seconds — the unit `X-Ghost-Timestamp` carries.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_key() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        s
    }

    #[test]
    fn a_signature_verifies_against_the_same_secret_and_nothing_else() {
        let key = InternalAuthKey::new(&a_key()).unwrap();
        let ts = now_secs();
        let body = b"{\"pool_id\":1}";

        assert!(key.verify(&key.sign(ts, body), ts, body).is_ok());
        assert!(key.verify(&key.sign(ts, body), ts, b"other body").is_err());
        assert!(key.verify(&key.sign(ts, body), ts + 1, body).is_err());

        let mut other_bytes = a_key();
        other_bytes[0] ^= 0xff;
        let other = InternalAuthKey::new(&other_bytes).unwrap();
        assert!(key.verify(&other.sign(ts, body), ts, body).is_err());
    }

    /// The rule that split the two halves apart before it lived in one place: a secret LONGER
    /// than 32 bytes is accepted, and only its first 32 bytes are used.
    ///
    /// If this ever becomes "exactly 32", an operator on signet with a 96-hex secret gets a node
    /// that authenticates and an emitter that cannot, and every share is silently discarded.
    #[test]
    fn a_longer_secret_is_accepted_and_truncated_to_the_first_32_bytes() {
        let long: Vec<u8> = (0u8..96).map(|i| i.wrapping_add(0x42)).collect();
        let from_long = InternalAuthKey::new(&long).expect("a 96-byte secret must be accepted");
        let from_first_32 = InternalAuthKey::new(&long[..32]).unwrap();

        let ts = now_secs();
        let body = b"body";
        assert_eq!(
            from_long.sign(ts, body),
            from_first_32.sign(ts, body),
            "truncation must take the FIRST 32 bytes, or the two halves disagree"
        );
    }

    #[test]
    fn a_short_or_patterned_secret_is_refused() {
        assert!(matches!(
            InternalAuthKey::new(&[0x11u8; 31]),
            Err(InternalAuthError::WeakSecret(_))
        ));
        assert!(matches!(
            InternalAuthKey::new(&[0x42u8; 32]),
            Err(InternalAuthError::WeakSecret(_))
        ));
        assert!(matches!(
            InternalAuthKey::from_hex("nothex"),
            Err(InternalAuthError::InvalidSecret(_))
        ));
        assert!(InternalAuthKey::from_hex(&format!("  {}  ", hex::encode(a_key()))).is_ok());
    }

    #[test]
    fn a_timestamp_beyond_the_drift_window_is_refused_in_both_directions() {
        let key = InternalAuthKey::new(&a_key()).unwrap();
        let body = b"body";
        for ts in [
            now_secs() - MAX_TIMESTAMP_DRIFT_SECS - 5,
            now_secs() + MAX_TIMESTAMP_DRIFT_SECS + 5,
        ] {
            assert!(
                matches!(
                    key.verify(&key.sign(ts, body), ts, body),
                    Err(InternalAuthError::TimestampOutOfRange { .. })
                ),
                "a correctly signed request at {ts} must still be refused as out of range"
            );
        }
        // Positive control: inside the window the same construction is accepted.
        let ts = now_secs();
        assert!(key.verify(&key.sign(ts, body), ts, body).is_ok());
    }
}
