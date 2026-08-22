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
//| FILE: auth.rs                                                                                                        |
//|======================================================================================================================|

//! Authentication for internal API endpoints (H10, H11 security fixes)
//!
//! Provides HMAC-SHA256 authentication for internal endpoints that should not be
//! publicly accessible. This prevents unauthorized share submissions and admin
//! operations from external sources.
//!
//! # Security Model
//!
//! Internal endpoints (`/api/internal/*`, `/admin/*`) are protected by HMAC-SHA256.
//! The shared secret must be configured at startup and shared between:
//! - ghost-pool (the pool server)
//! - ghost-verification (this service)
//! - Any other internal services that need to communicate
//!
//! # Usage
//!
//! Requests must include the `X-Ghost-Signature` header containing:
//! `HMAC-SHA256(secret, timestamp + body)`
//!
//! And the `X-Ghost-Timestamp` header with Unix timestamp (seconds).
//! Timestamps must be within 5 minutes of server time to prevent replay attacks.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use ghost_common::internal_auth::{InternalAuthError, InternalAuthKey};
use std::sync::Arc;
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Internal API authentication using HMAC-SHA256
///
/// # Security (H10)
///
/// All internal endpoints that receive share data or trigger privileged operations
/// must be protected by this authentication to prevent:
/// - Unauthorized share injection attacks
/// - Spoofed work credits
/// - Fake consensus triggers
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InternalAuth {
    /// The one implementation of the construction and of the secret rule.
    ///
    /// This type used to carry its own copy of both. That is how the verifier came to accept a
    /// secret of 32 bytes *or longer* while `pool_sv2`'s emitter demanded exactly 32 — a split
    /// that turns a perfectly valid 96-hex secret into total, silent share loss on one side of a
    /// loopback socket. Delegating means the two halves cannot disagree, because there is only
    /// one of them.
    key: InternalAuthKey,
}

impl InternalAuth {
    /// Create a new InternalAuth with the given secret
    ///
    /// # Errors
    ///
    /// Returns error if secret is too short or has insufficient entropy. A secret LONGER than 32
    /// bytes is accepted and truncated to its first 32 — see [`InternalAuthKey::new`].
    pub fn new(secret: &[u8]) -> Result<Self, AuthError> {
        Ok(Self {
            key: InternalAuthKey::new(secret)?,
        })
    }

    /// Create from a hex-encoded secret string
    pub fn from_hex(hex_secret: &str) -> Result<Self, AuthError> {
        Ok(Self {
            key: InternalAuthKey::from_hex(hex_secret)?,
        })
    }

    /// Verify a request signature
    ///
    /// # Arguments
    ///
    /// * `signature` - The HMAC-SHA256 signature from X-Ghost-Signature header
    /// * `timestamp` - The Unix timestamp from X-Ghost-Timestamp header
    /// * `body` - The request body bytes
    ///
    /// # Returns
    ///
    /// Ok(()) if signature is valid and timestamp is within acceptable range
    pub fn verify(&self, signature: &str, timestamp: u64, body: &[u8]) -> Result<(), AuthError> {
        Ok(self.key.verify(signature, timestamp, body)?)
    }

    /// Generate a signature for a request (for testing/client use)
    pub fn sign(&self, timestamp: u64, body: &[u8]) -> String {
        self.key.sign(timestamp, body)
    }
}

impl From<InternalAuthError> for AuthError {
    fn from(e: InternalAuthError) -> Self {
        match e {
            InternalAuthError::WeakSecret(r) => AuthError::WeakSecret(r),
            InternalAuthError::InvalidSecret(r) => AuthError::InvalidSecret(r),
            InternalAuthError::InvalidSignature(r) => AuthError::InvalidSignature(r),
            InternalAuthError::TimestampOutOfRange {
                received,
                server_time,
            } => AuthError::TimestampOutOfRange {
                received,
                server_time,
            },
        }
    }
}

/// Authentication error types
#[derive(Debug, Clone)]
pub enum AuthError {
    /// Missing required header
    MissingHeader(String),
    /// Invalid signature format or verification failed
    InvalidSignature(String),
    /// Timestamp outside acceptable range
    TimestampOutOfRange { received: u64, server_time: u64 },
    /// Secret key is too weak
    WeakSecret(String),
    /// Invalid secret format
    InvalidSecret(String),
}

impl AuthError {
    /// Return a generic message safe for HTTP responses (no internal details).
    pub fn client_message(&self) -> &'static str {
        match self {
            AuthError::MissingHeader(_) => "Missing required authentication header",
            AuthError::InvalidSignature(_) => "Invalid signature",
            AuthError::TimestampOutOfRange { .. } => "Request timestamp out of acceptable range",
            AuthError::WeakSecret(_) => "Authentication configuration error",
            AuthError::InvalidSecret(_) => "Authentication configuration error",
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingHeader(h) => write!(f, "Missing required header: {}", h),
            AuthError::InvalidSignature(reason) => write!(f, "Invalid signature: {}", reason),
            AuthError::TimestampOutOfRange {
                received,
                server_time,
            } => {
                write!(
                    f,
                    "Timestamp {} outside acceptable range (server time: {})",
                    received, server_time
                )
            }
            AuthError::WeakSecret(reason) => write!(f, "Weak secret: {}", reason),
            AuthError::InvalidSecret(reason) => write!(f, "Invalid secret: {}", reason),
        }
    }
}

impl std::error::Error for AuthError {}

/// Extract and verify HMAC authentication from request headers
///
/// # Usage with Axum
///
/// ```ignore
/// async fn internal_handler(
///     State(state): State<Arc<AppState>>,
///     headers: HeaderMap,
///     body: Bytes,
/// ) -> Result<impl IntoResponse, StatusCode> {
///     verify_internal_auth(&state.internal_auth, &headers, &body)?;
///     // ... handler logic
/// }
/// ```
pub fn verify_internal_auth(
    auth: &InternalAuth,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), (StatusCode, String)> {
    // SEC-ERR-3: Distinguish between missing and malformed headers
    // Extract signature header
    let signature_header = headers.get("X-Ghost-Signature").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Missing X-Ghost-Signature header".to_string(),
        )
    })?;
    let signature = signature_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Malformed X-Ghost-Signature header: contains non-ASCII characters".to_string(),
        )
    })?;

    // Extract timestamp header
    let timestamp_header = headers.get("X-Ghost-Timestamp").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Missing X-Ghost-Timestamp header".to_string(),
        )
    })?;
    let timestamp_str = timestamp_header.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Malformed X-Ghost-Timestamp header: contains non-ASCII characters".to_string(),
        )
    })?;

    let timestamp: u64 = timestamp_str.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid X-Ghost-Timestamp format".to_string(),
        )
    })?;

    // Verify signature
    auth.verify(signature, timestamp, body).map_err(|e| {
        warn!(error = %e, "Internal API authentication failed");
        (
            StatusCode::UNAUTHORIZED,
            format!("Authentication failed: {}", e.client_message()),
        )
    })
}

/// Middleware-style authentication for internal endpoints
///
/// Use this with axum's `from_fn_with_state` for route-layer protection:
///
/// ```ignore
/// Router::new()
///     .route("/api/internal/share", post(share_handler))
///     .route_layer(from_fn_with_state(auth.clone(), require_internal_auth))
/// ```
pub async fn require_internal_auth(
    State(auth): State<Arc<InternalAuth>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Bytes, (StatusCode, String)> {
    verify_internal_auth(&auth, &headers, &body)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        // Use a proper 32-byte secret for testing
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        secret
    }

    #[test]
    fn test_internal_auth_creation() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_weak_secret_rejected() {
        // Too short
        let short_secret = [0u8; 16];
        assert!(matches!(
            InternalAuth::new(&short_secret),
            Err(AuthError::WeakSecret(_))
        ));

        // All same byte
        let weak_secret = [0x42u8; 32];
        assert!(matches!(
            InternalAuth::new(&weak_secret),
            Err(AuthError::WeakSecret(_))
        ));
    }

    #[test]
    fn test_sign_and_verify() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"test body content";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature = auth.sign(timestamp, body);
        let result = auth.verify(&signature, timestamp, body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"test body content";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Wrong signature
        let bad_sig = "00".repeat(32);
        let result = auth.verify(&bad_sig, timestamp, body);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    #[test]
    fn test_old_timestamp_rejected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"test body content";
        // L-27: 2 minutes ago (beyond 60 second window)
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 120;

        let signature = auth.sign(old_timestamp, body);
        let result = auth.verify(&signature, old_timestamp, body);
        assert!(matches!(result, Err(AuthError::TimestampOutOfRange { .. })));
    }

    #[test]
    fn test_body_tampering_detected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();

        let body = b"original body";
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let signature = auth.sign(timestamp, body);

        // Try to verify with tampered body
        let tampered_body = b"modified body";
        let result = auth.verify(&signature, timestamp, tampered_body);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    /// This type must stay a thin forward to `ghost_common::internal_auth`, not a second
    /// implementation that merely happens to agree today.
    ///
    /// The construction is `timestamp.to_le_bytes() ‖ body`, and none of that is visible in a
    /// signature or recoverable from the output. When `pool_sv2` had its own copy, its secret
    /// rule drifted from this one within a single change. Asserting the two produce and accept
    /// each other's signatures is what makes a future fork fail here rather than in production.
    #[test]
    fn this_type_is_a_forward_to_the_shared_key_not_a_second_implementation() {
        let secret = test_secret();
        let wrapper = InternalAuth::new(&secret).unwrap();
        let shared = InternalAuthKey::new(&secret).unwrap();

        let ts = ghost_common::internal_auth::now_secs();
        let body = b"a share batch";

        assert_eq!(
            wrapper.sign(ts, body),
            shared.sign(ts, body),
            "the wrapper must produce the shared construction, byte for byte"
        );
        assert!(
            wrapper.verify(&shared.sign(ts, body), ts, body).is_ok(),
            "the wrapper must accept what the shared key signs"
        );
        assert!(
            shared.verify(&wrapper.sign(ts, body), ts, body).is_ok(),
            "the shared key must accept what the wrapper signs"
        );
    }

    /// A secret LONGER than 32 bytes must be accepted here, because `pool_sv2` accepts it too.
    /// If this side ever tightened to "exactly 32" the two would disagree and every share from a
    /// node with a longer secret would be discarded with a 401 nobody is watching for.
    #[test]
    fn a_longer_secret_is_accepted_and_matches_its_first_32_bytes() {
        let long: Vec<u8> = (0u8..96).map(|i| i.wrapping_add(0x42)).collect();
        let from_long = InternalAuth::new(&long).expect("a 96-byte secret must be accepted");
        let from_short = InternalAuth::new(&long[..32]).unwrap();

        let ts = ghost_common::internal_auth::now_secs();
        assert_eq!(from_long.sign(ts, b"body"), from_short.sign(ts, b"body"));
    }

    #[test]
    fn test_from_hex() {
        // Valid 32-byte hex secret
        let hex_secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let auth = InternalAuth::from_hex(hex_secret);
        assert!(auth.is_ok());

        // Invalid hex
        let bad_hex = "not valid hex";
        assert!(matches!(
            InternalAuth::from_hex(bad_hex),
            Err(AuthError::InvalidSecret(_))
        ));
    }

    #[test]
    fn test_secret_zeroized_on_drop() {
        use zeroize::Zeroize;

        let secret = test_secret();
        let mut auth = InternalAuth::new(&secret).unwrap();

        // Verify it works before zeroization
        let body = b"test";
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sig = auth.sign(ts, body);
        assert!(auth.verify(&sig, ts, body).is_ok());

        // Zeroize, then assert on the OUTCOME rather than on a private field: a key that has
        // been wiped can no longer produce the signature it produced a moment ago, and can no
        // longer accept it.
        let before = auth.sign(ts, body);
        auth.zeroize();
        assert_ne!(
            auth.sign(ts, body),
            before,
            "Secret must be zeroed after zeroize()"
        );
        assert!(
            auth.verify(&before, ts, body).is_err(),
            "a zeroized key must not still accept signatures made under the real secret"
        );
    }

    #[test]
    fn test_client_message_contains_no_timestamps() {
        let err = AuthError::TimestampOutOfRange {
            received: 1700000000,
            server_time: 1700000099,
        };
        let msg = err.client_message();
        // Must not contain any numeric timestamp values
        assert!(
            !msg.contains("1700000000"),
            "client_message must not leak received timestamp"
        );
        assert!(
            !msg.contains("1700000099"),
            "client_message must not leak server timestamp"
        );
        // Display (for logs) SHOULD contain timestamps
        let display = format!("{}", err);
        assert!(
            display.contains("1700000000") && display.contains("1700000099"),
            "Display should contain timestamps for logging"
        );
    }

    #[test]
    fn test_client_messages_are_generic() {
        let cases: Vec<AuthError> = vec![
            AuthError::MissingHeader("X-Ghost-Signature".to_string()),
            AuthError::InvalidSignature("bad hex".to_string()),
            AuthError::TimestampOutOfRange {
                received: 100,
                server_time: 200,
            },
            AuthError::WeakSecret("too short".to_string()),
            AuthError::InvalidSecret("bad encoding".to_string()),
        ];
        for err in &cases {
            let msg = err.client_message();
            assert!(!msg.is_empty(), "client_message should not be empty");
            // None should contain numeric details from the variant fields
            assert!(
                !msg.contains("100") && !msg.contains("200"),
                "client_message should not contain internal details: {}",
                msg
            );
        }
    }

    // L-27: Verify 60-second timestamp tolerance
    #[test]
    fn test_timestamp_within_60_seconds_accepted() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();
        let body = b"test body";

        // 30 seconds ago should be accepted (within 60 second window)
        let timestamp_30s_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 30;

        let signature = auth.sign(timestamp_30s_ago, body);
        let result = auth.verify(&signature, timestamp_30s_ago, body);
        assert!(
            result.is_ok(),
            "L-27: Timestamp 30s ago should be within 60s tolerance"
        );
    }

    #[test]
    fn test_timestamp_just_over_30_seconds_rejected() {
        let secret = test_secret();
        let auth = InternalAuth::new(&secret).unwrap();
        let body = b"test body";

        // API-4 FIX: 35 seconds ago should be rejected (outside 30 second window)
        let timestamp_35s_ago = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 35;

        let signature = auth.sign(timestamp_35s_ago, body);
        let result = auth.verify(&signature, timestamp_35s_ago, body);
        assert!(
            matches!(result, Err(AuthError::TimestampOutOfRange { .. })),
            "API-4: Timestamp 35s ago should be outside 30s tolerance"
        );
    }

    #[test]
    fn test_timestamp_tolerance_constant() {
        // API-4 FIX: Verify the constant is 30 seconds (reduced from 60)
        assert_eq!(
            ghost_common::internal_auth::MAX_TIMESTAMP_DRIFT_SECS,
            30,
            "API-4: Timestamp tolerance should be 30 seconds"
        );
    }
}
