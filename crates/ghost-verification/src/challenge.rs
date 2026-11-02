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
//| FILE: challenge.rs                                                                                                   |
//|======================================================================================================================|

//! The `/health` response, its counters, and signed-response plumbing.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `Database::with_connection` usage counters surfaced on `/health` (#537).
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct DbConnectionStats {
    /// Total `with_connection` calls since process start.
    pub calls: u64,
    /// Total milliseconds the calling thread spent acquiring AND holding the connection.
    ///
    /// Acquisition is included deliberately: waiting for the mutex blocks the thread exactly as
    /// much as holding it, and under contention the wait is the larger half. Counting only the
    /// closure would report the system healthiest precisely when it is worst.
    pub total_ms_held: u64,
    /// Calls that took 250ms or longer.
    pub slow_calls: u64,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Whether the node can actually do its job.
    ///
    /// This was the literal `true` for as long as the HTTP server could answer — a check that
    /// cannot fail. On 2026-08-01 ghost-vm7 served `healthy: true` for an hour with its Ghost Core
    /// dead underneath it, and nothing noticed: not the dashboard, not the load balancer, not an
    /// operator. It now reflects the one dependency without which the node does nothing useful.
    pub healthy: bool,
    /// Whether Ghost Core answered recently.
    ///
    /// `None` means no probe was wired, which is reported as such rather than assumed good — so a
    /// monitor can tell "never checked" from "checked and failing".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_reachable: Option<bool>,
    /// Seconds since Ghost Core last answered, so a monitor sees how stale the answer is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_last_ok_secs: Option<u64>,
    /// Node ID (hex)
    pub node_id: String,
    /// Software version
    pub version: String,
    /// Current block height
    pub block_height: u64,
    /// Current round ID
    pub round_id: u64,
    /// Connected miners
    pub miner_count: u32,
    /// Always 0: the old mesh was removed. Kept so existing readers of `/health` still parse;
    /// share-chain relay peers are on `/api/v1/node-pool/status`.
    pub peer_count: u32,
    /// Uptime (seconds)
    pub uptime_secs: u64,
    /// Cumulative `Database::with_connection` usage: `(calls, total_ms_held, slow_calls)` (#537).
    ///
    /// Exposed because the counters are otherwise unreadable in production, and an unreadable
    /// counter answers "is the database blocking the runtime?" with a confident silence.
    ///
    /// How to read it: `total_ms_held` against `uptime_secs * 1000 * worker_threads` is the
    /// fraction of the runtime spent inside the single connection mutex. Approaching 1 means
    /// the reactor is saturated on database work, which is the mechanism #537 describes and the
    /// stalls in #535 look like. `slow_calls` counts individual calls past 250ms — the point
    /// above which a call is either an unusually heavy query or, more often, time spent waiting
    /// behind another caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_connection: Option<DbConnectionStats>,
}

/// Maximum age of a signed response before it's considered stale (5 minutes)
pub const MAX_RESPONSE_AGE_SECS: u64 = 300;

/// Maximum time in the future a response timestamp can be (2 minutes)
pub const MAX_FUTURE_TIME_SECS: u64 = 120;

/// Signed verification response wrapper
///
/// Wraps any verification response with a cryptographic signature to:
/// - Prove the response came from the claimed node
/// - Prevent proxying attacks (where an attacker relays another node's responses)
/// - Ensure freshness via timestamp and nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedResponse<T: Serialize> {
    /// The actual response payload
    pub payload: T,
    /// Node ID that signed this response (hex-encoded Ed25519 public key)
    pub signer: String,
    /// Unix timestamp when the response was generated
    pub timestamp: u64,
    /// Random nonce for uniqueness (hex-encoded 16 bytes)
    pub nonce: String,
    /// Challenge nonce from request (if provided) - ensures response matches request
    pub challenge_nonce: Option<String>,
    /// Ed25519 signature over (payload_hash || signer || timestamp || nonce || challenge_nonce)
    /// Hex-encoded 64-byte signature
    pub signature: String,
}

impl<T: Serialize> SignedResponse<T> {
    /// Create a new signed response
    ///
    /// # Arguments
    /// * `payload` - The response data to sign
    /// * `signer` - Node ID (hex-encoded public key)
    /// * `sign_fn` - Closure that takes a message hash and returns a signature
    /// * `challenge_nonce` - Optional nonce from the request
    pub fn new<F>(payload: T, signer: String, sign_fn: F, challenge_nonce: Option<String>) -> Self
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // C-4 FIX: Use OsRng for cryptographically secure nonce generation
        let mut nonce_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Compute message hash for signing
        let message_hash = Self::compute_message_hash(
            &payload,
            &signer,
            timestamp,
            &nonce,
            challenge_nonce.as_deref(),
        );

        // Sign the message hash
        let signature_bytes = sign_fn(&message_hash);
        let signature = hex::encode(signature_bytes);

        Self {
            payload,
            signer,
            timestamp,
            nonce,
            challenge_nonce,
            signature,
        }
    }

    /// Compute the message hash for signing/verification
    fn compute_message_hash(
        payload: &T,
        signer: &str,
        timestamp: u64,
        nonce: &str,
        challenge_nonce: Option<&str>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash the payload JSON
        if let Ok(payload_json) = serde_json::to_vec(payload) {
            hasher.update(&payload_json);
        }

        // Hash metadata
        hasher.update(signer.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(nonce.as_bytes());

        // Include challenge nonce if present
        if let Some(cn) = challenge_nonce {
            hasher.update(cn.as_bytes());
        }

        hasher.finalize().into()
    }

    /// Verify the signature is valid
    ///
    /// # Arguments
    /// * `verify_fn` - Closure that takes (public_key_hex, message_hash, signature_bytes)
    ///   and returns true if the signature is valid
    ///
    /// # Returns
    /// * `Ok(())` if signature is valid
    /// * `Err(reason)` if verification fails
    pub fn verify<F>(&self, verify_fn: F) -> Result<(), String>
    where
        F: FnOnce(&str, &[u8], &[u8]) -> bool,
    {
        // Check timestamp bounds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Not too far in the future
        if self.timestamp > now + MAX_FUTURE_TIME_SECS {
            return Err(format!(
                "Response timestamp {} is too far in the future (current: {})",
                self.timestamp, now
            ));
        }

        // Not too old
        if self.timestamp + MAX_RESPONSE_AGE_SECS < now {
            return Err(format!(
                "Response timestamp {} is too old (max age: {}s, current: {})",
                self.timestamp, MAX_RESPONSE_AGE_SECS, now
            ));
        }

        // Decode signature
        let signature_bytes =
            hex::decode(&self.signature).map_err(|e| format!("Invalid signature hex: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!(
                "Invalid signature length: {} (expected 64)",
                signature_bytes.len()
            ));
        }

        // Recompute message hash
        let message_hash = Self::compute_message_hash(
            &self.payload,
            &self.signer,
            self.timestamp,
            &self.nonce,
            self.challenge_nonce.as_deref(),
        );

        // Verify signature
        if verify_fn(&self.signer, &message_hash, &signature_bytes) {
            Ok(())
        } else {
            Err("Signature verification failed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_response_creation() {
        let health = HealthResponse {
            db_connection: None,
            healthy: true,
            core_reachable: Some(true),
            core_last_ok_secs: Some(0),
            node_id: "test_node".to_string(),
            version: "1.0.0".to_string(),
            block_height: 100,
            round_id: 1,
            miner_count: 10,
            peer_count: 5,
            uptime_secs: 3600,
        };

        // Mock signing function that returns a fake signature
        let sign_fn = |_message: &[u8]| -> [u8; 64] { [0xABu8; 64] };

        let signed = SignedResponse::new(
            health,
            "0123456789abcdef".to_string(),
            sign_fn,
            Some("challenge_nonce".to_string()),
        );

        assert_eq!(signed.signer, "0123456789abcdef");
        assert!(signed.timestamp > 0);
        assert!(!signed.nonce.is_empty());
        assert_eq!(signed.challenge_nonce, Some("challenge_nonce".to_string()));
        assert_eq!(signed.signature, hex::encode([0xABu8; 64]));
    }

    #[test]
    fn test_signed_response_timestamp_validation() {
        let health = HealthResponse {
            db_connection: None,
            healthy: true,
            core_reachable: Some(true),
            core_last_ok_secs: Some(0),
            node_id: "test".to_string(),
            version: "1.0".to_string(),
            block_height: 0,
            round_id: 0,
            miner_count: 0,
            peer_count: 0,
            uptime_secs: 0,
        };

        // Create a signed response with timestamp far in the past
        let mut signed = SignedResponse {
            payload: health,
            signer: "test".to_string(),
            timestamp: 1000, // Very old timestamp
            nonce: "abc123".to_string(),
            challenge_nonce: None,
            signature: hex::encode([0u8; 64]),
        };

        // Verification should fail due to old timestamp
        let result = signed.verify(|_, _, _| true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));

        // Test timestamp too far in future
        signed.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + MAX_FUTURE_TIME_SECS
            + 100;

        let result = signed.verify(|_, _, _| true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("future"));
    }
}
