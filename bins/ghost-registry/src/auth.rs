//|======================================================================================================================|
//|                                                                                                                      |
//|  Bitcoin Ghost - Auth Module                                                                                         |
//|                                                                                                                      |
//|  HMAC-SHA256 authentication for internal API endpoints (API-1, API-2 security fixes)                               |
//|                                                                                                                      |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: auth.rs                                                                                                        |
//|======================================================================================================================|

//! Authentication for ghost-registry API endpoints (API-1, API-2 security fixes)
//!
//! Provides HMAC-SHA256 authentication for state-modifying endpoints to prevent
//! unauthorized node registration, heartbeat, and deregistration.
//!
//! # Security Model
//!
//! State-modifying endpoints (register, heartbeat, deregister) are protected by HMAC-SHA256.
//! The shared secret must be configured at startup via API_SECRET environment variable.
//!
//! # Usage
//!
//! Requests must include the `X-Ghost-Signature` header containing:
//! `HMAC-SHA256(secret, timestamp + body)`
//!
//! And the `X-Ghost-Timestamp` header with Unix timestamp (seconds).
//! Timestamps must be within 30 seconds of server time to prevent replay attacks (API-4).

use axum::http::{HeaderMap, StatusCode};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::warn;

/// HMAC-SHA256 type alias
type HmacSha256 = Hmac<Sha256>;

/// API-4 FIX: Maximum timestamp drift allowed (30 seconds)
/// Reduced from 60 seconds to further minimize replay attack window.
/// 30 seconds is still generous for properly synchronized nodes while
/// reducing the attack surface by 50%. Nodes MUST use NTP for accurate time.
const MAX_TIMESTAMP_DRIFT_SECS: u64 = 30;

/// Internal API authentication using HMAC-SHA256
///
/// # Security (API-1, API-2)
///
/// All state-modifying endpoints that register, update, or delete nodes
/// must be protected by this authentication to prevent:
/// - Unauthorized node registration attacks
/// - Spoofed heartbeat updates
/// - Malicious node deregistration (API-1 CRITICAL)
#[derive(Clone)]
pub(crate) struct InternalAuth {
    secret: [u8; 32],
}

impl InternalAuth {
    /// Create a new InternalAuth with the given secret
    ///
    /// # Errors
    ///
    /// Returns error if secret is too short or has insufficient entropy
    pub(crate) fn new(secret: &[u8]) -> Result<Self, AuthError> {
        // Require minimum 32 bytes for security
        if secret.len() < 32 {
            return Err(AuthError::WeakSecret(
                "API secret must be at least 32 bytes".to_string(),
            ));
        }

        // Check for trivially weak secrets (all same byte)
        if secret.iter().all(|&b| b == secret[0]) {
            return Err(AuthError::WeakSecret(
                "API secret has insufficient entropy".to_string(),
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&secret[..32]);
        Ok(Self { secret: key })
    }

    /// Create from a hex-encoded secret string
    pub(crate) fn from_hex(hex_secret: &str) -> Result<Self, AuthError> {
        let bytes = hex::decode(hex_secret)
            .map_err(|_| AuthError::InvalidSecret("Invalid hex encoding".to_string()))?;
        Self::new(&bytes)
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
    pub(crate) fn verify(
        &self,
        signature: &str,
        timestamp: u64,
        body: &[u8],
    ) -> Result<(), AuthError> {
        // Check timestamp is within acceptable range (replay prevention)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let drift = timestamp.abs_diff(now);

        if drift > MAX_TIMESTAMP_DRIFT_SECS {
            return Err(AuthError::TimestampOutOfRange {
                received: timestamp,
                server_time: now,
            });
        }

        // Compute expected signature: HMAC-SHA256(secret, timestamp_bytes || body)
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&timestamp.to_le_bytes());
        mac.update(body);
        let expected = mac.finalize().into_bytes();

        // Decode provided signature
        let provided = hex::decode(signature)
            .map_err(|_| AuthError::InvalidSignature("Invalid hex encoding".to_string()))?;

        // Constant-time comparison
        if !constant_time_eq(&expected, &provided) {
            return Err(AuthError::InvalidSignature(
                "Signature verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Generate a signature for a request (for testing/client use)
    #[allow(dead_code)]
    pub(crate) fn sign(&self, timestamp: u64, body: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC can accept any key size");
        mac.update(&timestamp.to_le_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// Constant-time byte comparison to prevent timing attacks
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

/// Authentication error types
#[derive(Debug, Clone)]
pub(crate) enum AuthError {
    /// Invalid signature format or verification failed
    InvalidSignature(String),
    /// Timestamp outside acceptable range
    TimestampOutOfRange { received: u64, server_time: u64 },
    /// Secret key is too weak
    WeakSecret(String),
    /// Invalid secret format
    InvalidSecret(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
pub(crate) fn verify_internal_auth(
    auth: &InternalAuth,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), (StatusCode, String)> {
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
        warn!(error = %e, "API authentication failed");
        (
            StatusCode::UNAUTHORIZED,
            format!("Authentication failed: {}", e),
        )
    })
}

/// Rate limiter for status endpoint (API-3)
///
/// Uses a sliding window approach with per-IP tracking.
pub(crate) struct RateLimiter {
    /// Maximum requests per window
    max_requests: u32,
    /// Window duration
    window: Duration,
    /// Per-IP request counts and window start times
    state: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    ///
    /// * `max_requests` - Maximum requests allowed per window
    /// * `window` - Duration of the sliding window
    pub(crate) fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request from the given IP should be allowed
    ///
    /// # Returns
    ///
    /// Ok(()) if allowed, Err with retry-after seconds if rate limited
    pub(crate) fn check(&self, ip: &str) -> Result<(), u64> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();

        // Clean up old entries (older than 2x window)
        let cleanup_threshold = now - (self.window * 2);
        state.retain(|_, (_, window_start)| *window_start > cleanup_threshold);

        let entry = state.entry(ip.to_string()).or_insert((0, now));

        // Check if window has expired
        if now.duration_since(entry.1) >= self.window {
            // Reset window
            entry.0 = 1;
            entry.1 = now;
            return Ok(());
        }

        // Check if under limit
        if entry.0 < self.max_requests {
            entry.0 += 1;
            return Ok(());
        }

        // Rate limited - calculate retry-after
        let elapsed = now.duration_since(entry.1);
        let retry_after = self.window.saturating_sub(elapsed).as_secs() + 1;
        Err(retry_after)
    }
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
        // 2 minutes ago (beyond 60 second window)
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
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));

        assert!(limiter.check("192.168.1.1").is_ok());
        assert!(limiter.check("192.168.1.1").is_ok());
        assert!(limiter.check("192.168.1.1").is_ok());
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));

        assert!(limiter.check("192.168.1.1").is_ok());
        assert!(limiter.check("192.168.1.1").is_ok());
        // Third request should be blocked
        assert!(limiter.check("192.168.1.1").is_err());
    }

    #[test]
    fn test_rate_limiter_separate_ips() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));

        assert!(limiter.check("192.168.1.1").is_ok());
        assert!(limiter.check("192.168.1.2").is_ok());
        // First IP should be blocked
        assert!(limiter.check("192.168.1.1").is_err());
        // Second IP still has capacity
        assert!(limiter.check("192.168.1.2").is_err());
    }
}
