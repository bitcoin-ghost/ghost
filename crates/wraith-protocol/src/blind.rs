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
//| FILE: blind.rs                                                                                                       |
//|======================================================================================================================|

//! Blind Signature System for Wraith Protocol
//!
//! Implements proper Schnorr blind signatures to ensure the coordinator
//! cannot link participants to their output addresses.
//!
//! # Protocol Flow (Interactive)
//!
//! 1. Coordinator generates nonce R = k*G and sends to participant
//! 2. Participant blinds: R' = R + α*G + β*X, computes c = H(X, R', m), c' = c + β
//! 3. Participant sends blinded challenge c' to coordinator
//! 4. Coordinator signs: s = k + c'*x
//! 5. Participant unblinds: s' = s + α
//! 6. Result: (R', s') is valid Schnorr signature on m, coordinator cannot link
//!
//! # Security Properties
//!
//! - **Blindness**: Coordinator cannot determine which message it signed
//! - **Unforgeability**: Only coordinator can produce valid signatures (DLOG + ROM)
//! - **Unlinkability**: No way to link blind signature request to unblinded signature
//!
//! # References
//!
//! - Schnorr blind signatures: <https://eprint.iacr.org/2019/877>
//! - Interactive demo: <https://blindsigs.utxo.club/>

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::WraithError;
use std::time::Instant;

/// Maximum number of active nonces per participant to prevent memory exhaustion
const MAX_NONCES_PER_PARTICIPANT: usize = 100;

/// Maximum total active nonces to prevent memory exhaustion
const MAX_TOTAL_NONCES: usize = 1000;

/// Default nonce expiry time (1 hour)
///
/// L-14: Now configurable via `CoordinatorSignerConfig::nonce_expiry_secs`.
const DEFAULT_NONCE_EXPIRY_SECS: u64 = 3600;

/// Fresh 32 bytes from the operating system's CSPRNG.
///
/// No statistical checking of the output. Master spec §6A rule E-5: a
/// boot-time health check asks whether the OS source is *available* and
/// fails closed if it is not; it never runs statistical tests on samples,
/// because those have a false-positive rate by construction, catch no real
/// failure mode, and were themselves a v1 finding in this very file.
///
/// The randomness itself stays — rule E-3 requires it. These bytes become
/// blind-signature nonces and per-round signing keys, which are multi-party
/// and single-use; deterministic nonces there are a key-extraction vector.
/// E-2's deterministic nonces are for *wallet-side single-signer* Schnorr,
/// which is a different code path.
///
/// # Errors
///
/// Fails closed if the OS source cannot be read at all, which is the one
/// failure that is real and detectable.
fn random_bytes_32() -> Result<[u8; 32], WraithError> {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| WraithError::SecurityError(format!("OS random source unavailable: {e}")))?;
    Ok(bytes)
}

/// Confirm the OS random source can be read, and fail closed if it cannot.
///
/// This is the whole of the health check permitted by E-5. Call it once at
/// startup so a host with no usable entropy source refuses to serve rather
/// than discovering the problem at the first signature.
pub fn ensure_os_rng_available() -> Result<(), WraithError> {
    random_bytes_32().map(|_| ())
}

/// A random secp256k1 secret key.
///
/// # Errors
///
/// Fails closed if the OS random source is unreadable.
fn random_secret_key() -> Result<SecretKey, WraithError> {
    // The retry is not an entropy check. `SecretKey::from_slice` rejects the
    // handful of 32-byte values that are not a valid scalar (zero, or ≥ the
    // curve order) — probability about 2^-128, so a few attempts is beyond
    // generous, and it is a domain check on the value rather than a judgement
    // about the randomness that produced it.
    const SCALAR_RANGE_ATTEMPTS: usize = 4;
    for _ in 0..SCALAR_RANGE_ATTEMPTS {
        let bytes = random_bytes_32()?;
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return Ok(sk);
        }
    }
    Err(WraithError::SecurityError(format!(
        "{SCALAR_RANGE_ATTEMPTS} consecutive random values fell outside the secp256k1 \
         scalar range; this is astronomically unlikely and indicates a broken RNG"
    )))
}

// Custom serde for [u8; 33] using hex encoding
mod bytes33_hex {
    use super::*;

    pub(super) fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

// Custom serde for [u8; 64] using hex encoding
#[allow(dead_code)]
mod bytes64_hex {
    use super::*;

    pub(super) fn serialize<S>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// Compute BIP-340 style tagged hash
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag);
    let mut engine = sha256::Hash::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    engine.input(data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Compute the Schnorr challenge: c = H(X || R' || m)
fn compute_challenge(pubkey: &PublicKey, nonce_point: &PublicKey, message: &[u8]) -> [u8; 32] {
    let x_only = pubkey.x_only_public_key().0;
    let r_only = nonce_point.x_only_public_key().0;

    let mut data = Vec::with_capacity(32 + 32 + message.len());
    data.extend_from_slice(&r_only.serialize());
    data.extend_from_slice(&x_only.serialize());
    data.extend_from_slice(message);

    tagged_hash(b"BIP0340/challenge", &data)
}

// ============================================================================
// Coordinator (Signer) Side
// ============================================================================

/// A signing session nonce created by the coordinator
///
/// The coordinator must keep track of (k, R) for each signing session.
/// This is sent to participants who want to obtain a blind signature.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct SigningNonce {
    /// The secret nonce scalar (must be kept secret!)
    secret_nonce: SecretKey,
    /// The public nonce point R = k*G
    pub public_nonce: PublicKey,
    /// Session identifier (includes ghost_id for binding)
    pub session_id: [u8; 32],
    /// Ghost ID of the participant this nonce was issued to (for verification)
    pub bound_ghost_id: Option<String>,
    /// Timestamp when nonce was created (for expiry)
    created_at: Instant,
}

/// M-10 FIX: Zeroize secret nonce on drop to prevent memory leakage
///
/// SecretKey doesn't implement Zeroize directly, but we can overwrite
/// its internal representation by calling non_secure_erase() and then
/// replacing with a dummy key to ensure the original bytes are cleared.
///
/// # CRYPT-5 FIX: Panic Safety in Drop
///
/// The dummy key creation uses a constant value `[1u8; 32]` which is guaranteed
/// to be a valid secp256k1 secret key (it's non-zero and less than the curve order).
/// We use `expect()` instead of `if let Ok()` to make it explicit that this cannot
/// fail in practice, while still providing a clear panic message in the impossible
/// case of failure.
///
/// Panicking in Drop is generally undesirable, but:
/// 1. The dummy value [1u8; 32] is mathematically guaranteed to be valid
/// 2. Silent failure would leave secret material in memory (worse than panic)
/// 3. If this ever panics, it indicates a fundamental issue with secp256k1 library
impl Drop for SigningNonce {
    fn drop(&mut self) {
        use std::sync::atomic::{compiler_fence, Ordering};

        // First, erase using secp256k1's built-in method
        self.secret_nonce.non_secure_erase();
        compiler_fence(Ordering::SeqCst);

        // CRYPT-5 FIX: Use explicit dummy value with expect() for guaranteed overwrite
        // The value [1u8; 32] is always valid:
        // - It's non-zero (required for secp256k1 secret keys)
        // - It's much smaller than the curve order n (starts with 0xFF...)
        // - SecretKey::from_slice only fails for value == 0 or value >= n
        let mut dummy = [1u8; 32];
        let dummy_key = SecretKey::from_slice(&dummy).expect(
            "CRYPT-5: dummy value [1u8; 32] is always a valid secp256k1 secret key \
             (non-zero and less than curve order). If this panics, the secp256k1 \
             library has a fundamental bug.",
        );
        self.secret_nonce = dummy_key;
        compiler_fence(Ordering::SeqCst);

        // Zeroize the dummy bytes (defense-in-depth)
        dummy.zeroize();
        compiler_fence(Ordering::SeqCst);

        // Final erase pass on the dummy key
        self.secret_nonce.non_secure_erase();
        compiler_fence(Ordering::SeqCst);
    }
}

/// Public nonce sent to participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicNonce {
    /// R = k*G (compressed point)
    #[serde(with = "bytes33_hex")]
    pub nonce_point: [u8; 33],
    /// Session identifier
    pub session_id: [u8; 32],
}

/// Blinded challenge sent from participant to coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedChallenge {
    /// The blinded challenge c' = c + β (mod n)
    pub challenge: [u8; 32],
    /// Session identifier (to match with nonce)
    pub session_id: [u8; 32],
}

/// Blind signature response from coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignatureResponse {
    /// s = k + c'*x (mod n)
    pub signature_scalar: [u8; 32],
    /// Session identifier
    pub session_id: [u8; 32],
}

/// WR4-L10 + H-WRAITH-2: Default key rotation grace period in seconds
/// Old keys are kept for this duration to verify in-flight signatures.
/// Extended to 7 days to match maximum Wraith session duration.
/// Note: rotate_key_if_safe() should be preferred to ensure no active sessions are broken.
///
/// LOW-CRYPTO-1: This is now configurable via CoordinatorSignerConfig::grace_period_secs
const DEFAULT_KEY_ROTATION_GRACE_PERIOD_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// LOW-CRYPTO-1 FIX: Configuration for CoordinatorSigner
///
/// Allows customization of security-critical parameters that were previously
/// hard-coded constants. All fields have secure defaults.
#[derive(Debug, Clone)]
pub struct CoordinatorSignerConfig {
    /// Key rotation grace period in seconds (default: 7 days)
    ///
    /// Old keys are kept for this duration to verify in-flight signatures.
    /// Must be at least as long as the maximum session duration.
    pub grace_period_secs: u64,
    /// L-14: Nonce expiry time in seconds (default: 3600 = 1 hour)
    ///
    /// Nonces older than this are automatically expired during cleanup.
    /// Must be > 0. Shorter values reduce memory usage but may cause
    /// in-flight signing operations to fail if participants are slow.
    pub nonce_expiry_secs: u64,
}

impl Default for CoordinatorSignerConfig {
    fn default() -> Self {
        Self {
            grace_period_secs: DEFAULT_KEY_ROTATION_GRACE_PERIOD_SECS,
            nonce_expiry_secs: DEFAULT_NONCE_EXPIRY_SECS,
        }
    }
}

/// WR4-L10: Previous key information for verification of in-flight signatures
#[derive(Debug)]
struct PreviousKey {
    /// The old signing key
    #[allow(dead_code)]
    signing_key: SecretKey,
    /// The old public key
    public_key: PublicKey,
    /// The old key ID
    key_id: [u8; 32],
    /// When this key was rotated out
    rotated_at: Instant,
}

/// Coordinator's signing key for a Wraith session
///
/// Each session has a unique signing key. The coordinator uses this to
/// sign blinded challenges without learning the actual messages.
pub struct CoordinatorSigner {
    /// Session-specific signing key (x)
    signing_key: SecretKey,
    /// Public key (X = x*G) for verification
    public_key: PublicKey,
    /// Session key identifier
    key_id: [u8; 32],
    /// Session ID (for key ID regeneration on rotation)
    session_id: [u8; 32],
    /// Active signing nonces (indexed by session_id)
    active_nonces: std::collections::HashMap<[u8; 32], SigningNonce>,
    /// Per-participant nonce count for rate limiting
    nonces_per_participant: std::collections::HashMap<String, usize>,
    /// WR4-L10: Previous keys kept for grace period to verify in-flight signatures
    previous_keys: Vec<PreviousKey>,
    /// LOW-CRYPTO-1: Configurable grace period in seconds
    grace_period_secs: u64,
    /// L-14: Configurable nonce expiry in seconds
    nonce_expiry_secs: u64,
}

impl std::fmt::Debug for CoordinatorSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordinatorSigner")
            .field("key_id", &hex::encode(self.key_id))
            .field("active_nonces", &self.active_nonces.len())
            .finish_non_exhaustive()
    }
}

impl CoordinatorSigner {
    /// Create a new coordinator signer for a session with default configuration
    ///
    /// # Errors
    ///
    /// Returns `WraithError::SecurityError` if the RNG fails to generate a valid signing key.
    pub fn new(session_id: &[u8; 32]) -> Result<Self, WraithError> {
        Self::with_config(session_id, CoordinatorSignerConfig::default())
    }

    /// LOW-CRYPTO-1 FIX: Create a new coordinator signer with custom configuration
    ///
    /// Allows customization of security-critical parameters like grace period.
    ///
    /// # Errors
    ///
    /// Returns `WraithError::SecurityError` if the RNG fails to generate a valid signing key.
    pub fn with_config(
        session_id: &[u8; 32],
        config: CoordinatorSignerConfig,
    ) -> Result<Self, WraithError> {
        let secp = Secp256k1::new();

        // Generate session-specific signing key
        let signing_key = random_secret_key()?;
        let public_key = PublicKey::from_secret_key(&secp, &signing_key);

        // Key ID is hash of session_id and public key
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(session_id);
        engine.input(&public_key.serialize());
        let key_id = sha256::Hash::from_engine(engine).to_byte_array();

        Ok(Self {
            signing_key,
            public_key,
            key_id,
            session_id: *session_id,
            active_nonces: std::collections::HashMap::new(),
            nonces_per_participant: std::collections::HashMap::new(),
            previous_keys: Vec::new(),                   // WR4-L10
            grace_period_secs: config.grace_period_secs, // LOW-CRYPTO-1
            nonce_expiry_secs: config.nonce_expiry_secs, // L-14
        })
    }

    /// Create from existing key bytes (for restoration) with default config
    pub fn from_bytes(key_bytes: &[u8; 32], session_id: &[u8; 32]) -> Result<Self, WraithError> {
        Self::from_bytes_with_config(key_bytes, session_id, CoordinatorSignerConfig::default())
    }

    /// LOW-CRYPTO-1 FIX: Create from existing key bytes with custom configuration
    pub fn from_bytes_with_config(
        key_bytes: &[u8; 32],
        session_id: &[u8; 32],
        config: CoordinatorSignerConfig,
    ) -> Result<Self, WraithError> {
        let secp = Secp256k1::new();

        let signing_key = SecretKey::from_slice(key_bytes)
            .map_err(|e| WraithError::MissingData(format!("Invalid key: {}", e)))?;
        let public_key = PublicKey::from_secret_key(&secp, &signing_key);

        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(session_id);
        engine.input(&public_key.serialize());
        let key_id = sha256::Hash::from_engine(engine).to_byte_array();

        Ok(Self {
            signing_key,
            public_key,
            key_id,
            session_id: *session_id,
            active_nonces: std::collections::HashMap::new(),
            nonces_per_participant: std::collections::HashMap::new(),
            previous_keys: Vec::new(),                   // WR4-L10
            grace_period_secs: config.grace_period_secs, // LOW-CRYPTO-1
            nonce_expiry_secs: config.nonce_expiry_secs, // L-14
        })
    }

    /// Get the key ID for this session signer
    pub fn key_id(&self) -> &[u8; 32] {
        &self.key_id
    }

    /// Get the public key for verification
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the per-signer session id. Stable across nonce issuance and
    /// the eventual `TokenVerifier::new(pubkey, &session_id)` call so
    /// wallets can verify their unblinded signatures end-to-end.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Step 1: Create a new signing nonce bound to a specific participant
    ///
    /// Returns a public nonce that should be sent to the participant.
    /// The coordinator must keep track of this nonce until signing completes.
    ///
    /// SECURITY: The ghost_id is included in session_id generation to bind
    /// the nonce to the requesting participant. This prevents nonce hijacking
    /// where a malicious participant uses another's nonce.
    ///
    /// RATE LIMITING: Enforces per-participant and total nonce limits to prevent
    /// memory exhaustion attacks. Returns error if limits exceeded.
    pub fn create_nonce_for_participant(
        &mut self,
        ghost_id: &str,
    ) -> Result<PublicNonce, WraithError> {
        // First, expire old nonces to free up capacity
        self.expire_old_nonces();

        // Check total nonce limit
        if self.active_nonces.len() >= MAX_TOTAL_NONCES {
            return Err(WraithError::PhaseError(format!(
                "Maximum total nonces reached ({}). Try again later.",
                MAX_TOTAL_NONCES
            )));
        }

        // Check per-participant limit
        let participant_count = self
            .nonces_per_participant
            .get(ghost_id)
            .copied()
            .unwrap_or(0);
        if participant_count >= MAX_NONCES_PER_PARTICIPANT {
            return Err(WraithError::PhaseError(format!(
                "Maximum nonces per participant reached ({}) for {}. Try again later.",
                MAX_NONCES_PER_PARTICIPANT, ghost_id
            )));
        }

        let secp = Secp256k1::new();

        // Generate random nonce k
        let secret_nonce = random_secret_key()?;
        let public_nonce = PublicKey::from_secret_key(&secp, &secret_nonce);

        // Create unique session ID for this nonce bound to coordinator's identity pubkey
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/nonce-session/v3"); // v3 binds to coordinator pubkey
        engine.input(&public_nonce.serialize());
        engine.input(&self.public_key.serialize()); // Bind to coordinator identity key
        engine.input(ghost_id.as_bytes()); // Also include participant ID
        engine.input(&random_bytes_32()?);
        let session_id = sha256::Hash::from_engine(engine).to_byte_array();

        let nonce = SigningNonce {
            secret_nonce,
            public_nonce,
            session_id,
            bound_ghost_id: Some(ghost_id.to_string()),
            created_at: Instant::now(),
        };

        let public = PublicNonce {
            nonce_point: public_nonce.serialize(),
            session_id,
        };

        self.active_nonces.insert(session_id, nonce);

        // Update per-participant count
        *self
            .nonces_per_participant
            .entry(ghost_id.to_string())
            .or_insert(0) += 1;

        Ok(public)
    }

    /// Expire nonces older than the configured expiry duration (default: 1 hour)
    ///
    /// This is called automatically before creating new nonces.
    /// L-14: Expiry duration is configurable via `CoordinatorSignerConfig::nonce_expiry_secs`.
    ///
    /// # L-22: Single-Node Limitation
    ///
    /// This function uses `std::time::Instant` (monotonic local time) for expiry
    /// calculations. This is intentional and correct for single-node deployments,
    /// but has the following implications:
    ///
    /// - Expiry timing is LOCAL to this process and not synchronized across nodes
    /// - If the system clock is adjusted, Instant remains monotonic (correct behavior)
    /// - In a multi-node deployment, each node tracks expiry independently
    /// - Nonces are inherently single-node (they're stored in local memory, not DB)
    ///
    /// This design is secure because:
    /// 1. Nonces are never shared between nodes (each node has its own NonceManager)
    /// 2. The expiry is purely for memory cleanup, not security (nonces are single-use)
    /// 3. Monotonic time prevents time-travel attacks that could extend nonce lifetime
    fn expire_old_nonces(&mut self) {
        let now = Instant::now();
        let expiry_duration = std::time::Duration::from_secs(self.nonce_expiry_secs);

        // Collect expired session IDs
        let expired: Vec<[u8; 32]> = self
            .active_nonces
            .iter()
            .filter(|(_, nonce)| now.duration_since(nonce.created_at) > expiry_duration)
            .map(|(id, _)| *id)
            .collect();

        // Remove expired nonces and update per-participant counts
        for session_id in expired {
            if let Some(nonce) = self.active_nonces.remove(&session_id) {
                if let Some(ref ghost_id) = nonce.bound_ghost_id {
                    if let Some(count) = self.nonces_per_participant.get_mut(ghost_id) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.nonces_per_participant.remove(ghost_id);
                        }
                    }
                }
            }
        }
    }

    /// Create a new signing nonce (unbound - DISABLED FOR SECURITY)
    ///
    /// Step 2: Sign a blinded challenge with participant verification
    ///
    /// Computes s = k + c'*x where k is the secret nonce and x is the signing key.
    /// The nonce is consumed (removed) after signing to prevent reuse.
    ///
    /// SECURITY: Verifies that the requestor matches the ghost_id bound to the nonce.
    /// This prevents nonce hijacking attacks.
    ///
    /// TIMING ATTACK PREVENTION (C-WRAITH-1): We verify binding BEFORE removing the nonce.
    /// This prevents attackers from probing which ghost_ids are bound to which nonces
    /// by observing timing differences. A generic error is returned regardless of
    /// whether the nonce exists or the binding fails, preventing information leakage.
    pub fn sign_blinded_challenge_for_participant(
        &mut self,
        challenge: &BlindedChallenge,
        requesting_ghost_id: &str,
    ) -> Result<BlindSignatureResponse, WraithError> {
        // C-WRAITH-1 FIX: Look up nonce WITHOUT removing to verify binding first
        // This prevents timing side-channel that could reveal nonce bindings
        let nonce = match self.active_nonces.get(&challenge.session_id) {
            Some(n) => n,
            None => {
                // Use generic error that doesn't reveal nonce state
                return Err(WraithError::InvalidSignature(
                    "Signature verification failed".to_string(),
                ));
            }
        };

        // Verify requestor matches the bound ghost_id BEFORE any state changes
        if let Some(ref bound_id) = nonce.bound_ghost_id {
            if bound_id != requesting_ghost_id {
                // WR4-L6: Log detection internally but return sanitized error to client
                // 4.24 SECURITY: Do NOT log ghost_id or any identifier - prevents identity correlation
                // CRITICAL: Do NOT remove the nonce here - just return error
                tracing::warn!(
                    "Nonce hijacking attempt detected: nonce bound to different participant"
                );
                return Err(WraithError::InvalidSignature(
                    "Signature verification failed".to_string(),
                ));
            }
        }
        // C-WRAITH-1 FIX: NOW remove the nonce - verification has passed
        // CRIT-7: Return error instead of panicking if nonce was removed between check and removal
        // This handles race conditions or internal inconsistencies gracefully
        let nonce = self
            .active_nonces
            .remove(&challenge.session_id)
            .ok_or_else(|| {
                WraithError::InvalidSignature("Signature verification failed".to_string())
            })?;

        // Update per-participant count
        if let Some(ref ghost_id) = nonce.bound_ghost_id {
            if let Some(count) = self.nonces_per_participant.get_mut(ghost_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.nonces_per_participant.remove(ghost_id);
                }
            }
        }

        // Parse challenge as scalar
        let c_prime = SecretKey::from_slice(&challenge.challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute s = k + c'*x
        let c_prime_scalar = Scalar::from(c_prime);
        let cx = self
            .signing_key
            .mul_tweak(&c_prime_scalar)
            .map_err(|e| WraithError::PhaseError(format!("Scalar multiply failed: {}", e)))?;

        let s = nonce
            .secret_nonce
            .add_tweak(&Scalar::from(cx))
            .map_err(|e| WraithError::PhaseError(format!("Scalar add failed: {}", e)))?;

        Ok(BlindSignatureResponse {
            signature_scalar: s.secret_bytes(),
            session_id: challenge.session_id,
        })
    }

    /// Verify a final unblinded signature
    ///
    /// This is standard Schnorr verification: s'*G = R' + c*X
    ///
    /// HIGH-CRYPTO-1 FIX: Uses constant-time comparison for key ID.
    pub fn verify_signature(&self, token: &UnblindedToken) -> Result<bool, WraithError> {
        let secp = Secp256k1::new();

        // HIGH-CRYPTO-1 FIX: Use constant-time comparison for key ID
        // This prevents timing attacks that could reveal key information
        let key_matches: bool = token.session_key_id.ct_eq(&self.key_id).into();
        if !key_matches {
            return Ok(false);
        }

        // Parse signature components
        let r_prime = PublicKey::from_slice(&token.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce point: {}", e)))?;

        let s_prime = SecretKey::from_slice(&token.signature_scalar).map_err(|e| {
            WraithError::InvalidSignature(format!("Invalid signature scalar: {}", e))
        })?;

        // Compute challenge c = H(X || R' || m)
        let challenge = compute_challenge(&self.public_key, &r_prime, &token.message);

        // Verify: s'*G == R' + c*X
        // Equivalent to: s'*G - c*X == R'
        let s_g = PublicKey::from_secret_key(&secp, &s_prime);

        let c_scalar = SecretKey::from_slice(&challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute c*X
        let c_x = self
            .public_key
            .mul_tweak(&secp, &Scalar::from(c_scalar))
            .map_err(|e| WraithError::PhaseError(format!("Point multiply failed: {}", e)))?;

        // Compute R' + c*X
        let expected = r_prime
            .combine(&c_x)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        Ok(s_g == expected)
    }

    /// Get count of active nonces (for monitoring)
    pub fn active_nonce_count(&self) -> usize {
        self.active_nonces.len()
    }

    /// Clear all nonces (for testing or session reset)
    pub fn clear_nonces(&mut self) {
        self.active_nonces.clear();
        self.nonces_per_participant.clear();
    }

    /// WR4-M1: Clean up expired nonces (call periodically from coordinator)
    ///
    /// This method is public to allow external scheduling of nonce cleanup.
    /// Returns the number of nonces that were expired and removed.
    ///
    /// Recommended: Call every 5 minutes or when memory pressure is detected.
    pub fn cleanup_expired_nonces(&mut self) -> usize {
        let now = Instant::now();
        let expiry_duration = std::time::Duration::from_secs(self.nonce_expiry_secs);

        let before = self.active_nonces.len();

        // Collect expired session IDs
        let expired: Vec<[u8; 32]> = self
            .active_nonces
            .iter()
            .filter(|(_, nonce)| now.duration_since(nonce.created_at) > expiry_duration)
            .map(|(id, _)| *id)
            .collect();

        // Remove expired nonces and update per-participant counts
        for session_id in &expired {
            if let Some(nonce) = self.active_nonces.remove(session_id) {
                if let Some(ref ghost_id) = nonce.bound_ghost_id {
                    if let Some(count) = self.nonces_per_participant.get_mut(ghost_id) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.nonces_per_participant.remove(ghost_id);
                        }
                    }
                }
            }
        }

        before - self.active_nonces.len()
    }

    /// Get the number of nonces per participant (for monitoring)
    pub fn nonces_per_participant(&self) -> &std::collections::HashMap<String, usize> {
        &self.nonces_per_participant
    }

    /// WR4-L10: Rotate the signing key
    ///
    /// Generates a new signing key while keeping the old key for a grace period
    /// to verify in-flight signatures. This allows key rotation without disrupting
    /// ongoing signing operations.
    ///
    /// # Returns
    ///
    /// The new public key after rotation.
    ///
    /// # Errors
    ///
    /// Returns `WraithError::SecurityError` if the RNG fails to generate a new signing key.
    pub fn rotate_key(&mut self) -> Result<PublicKey, WraithError> {
        let secp = Secp256k1::new();

        // Store old key for grace period
        let previous = PreviousKey {
            signing_key: self.signing_key,
            public_key: self.public_key,
            key_id: self.key_id,
            rotated_at: Instant::now(),
        };
        self.previous_keys.push(previous);

        // Generate new key
        let new_signing_key = random_secret_key()?;
        let new_public_key = PublicKey::from_secret_key(&secp, &new_signing_key);

        // Generate new key ID
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(&self.session_id);
        engine.input(&new_public_key.serialize());
        let new_key_id = sha256::Hash::from_engine(engine).to_byte_array();

        // Activate new key
        self.signing_key = new_signing_key;
        self.public_key = new_public_key;
        self.key_id = new_key_id;

        // Clean old keys past grace period
        self.cleanup_old_keys();

        tracing::info!(
            new_key_id = %hex::encode(&self.key_id[..8]),
            previous_keys = self.previous_keys.len(),
            "Signing key rotated"
        );

        Ok(self.public_key)
    }

    /// WR4-L10: Clean up old keys that are past the grace period
    /// LOW-CRYPTO-1: Now uses configurable grace_period_secs instead of constant
    fn cleanup_old_keys(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(self.grace_period_secs);
        let before = self.previous_keys.len();
        self.previous_keys.retain(|pk| pk.rotated_at > cutoff);
        let removed = before - self.previous_keys.len();
        if removed > 0 {
            tracing::debug!(
                removed = removed,
                remaining = self.previous_keys.len(),
                "Cleaned up expired previous keys"
            );
        }
    }

    /// WR4-L10: Verify a signature, checking both current and previous keys
    ///
    /// This allows verification of signatures created before a key rotation,
    /// as long as they're within the grace period.
    ///
    /// HIGH-CRYPTO-1 FIX: Uses constant-time comparison for key IDs to prevent
    /// timing side-channel attacks that could reveal which key was used.
    pub fn verify_signature_with_rotation(
        &self,
        token: &UnblindedToken,
    ) -> Result<bool, WraithError> {
        // HIGH-CRYPTO-1 FIX: Use constant-time comparison for key ID
        // This prevents timing attacks that could reveal which key was used
        let matches_current: bool = token.session_key_id.ct_eq(&self.key_id).into();
        if matches_current {
            return self.verify_signature(token);
        }

        // Check previous keys within grace period
        // HIGH-CRYPTO-1 FIX: Use constant-time comparison for all previous keys
        for prev in &self.previous_keys {
            let matches_prev: bool = token.session_key_id.ct_eq(&prev.key_id).into();
            if matches_prev {
                // Verify with the previous key
                return self.verify_signature_with_key(token, &prev.public_key, &prev.key_id);
            }
        }

        // Key ID not found in current or previous keys
        Ok(false)
    }

    /// WR4-L10: Verify a signature with a specific key
    ///
    /// HIGH-CRYPTO-1 FIX: Uses constant-time comparison for key ID.
    fn verify_signature_with_key(
        &self,
        token: &UnblindedToken,
        pubkey: &PublicKey,
        expected_key_id: &[u8; 32],
    ) -> Result<bool, WraithError> {
        let secp = Secp256k1::new();

        // HIGH-CRYPTO-1 FIX: Use constant-time comparison for key ID
        let key_matches: bool = token.session_key_id.ct_eq(expected_key_id).into();
        if !key_matches {
            return Ok(false);
        }

        // Parse signature components
        let r_prime = PublicKey::from_slice(&token.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce point: {}", e)))?;

        let s_prime = SecretKey::from_slice(&token.signature_scalar).map_err(|e| {
            WraithError::InvalidSignature(format!("Invalid signature scalar: {}", e))
        })?;

        // Compute challenge c = H(X || R' || m)
        let challenge = compute_challenge(pubkey, &r_prime, &token.message);

        // Verify: s'*G == R' + c*X
        let s_g = PublicKey::from_secret_key(&secp, &s_prime);

        let c_scalar = SecretKey::from_slice(&challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute c*X
        let c_x = pubkey
            .mul_tweak(&secp, &Scalar::from(c_scalar))
            .map_err(|e| WraithError::PhaseError(format!("Point multiply failed: {}", e)))?;

        // Compute R' + c*X
        let expected = r_prime
            .combine(&c_x)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        Ok(s_g == expected)
    }

    /// WR4-L10: Get the number of previous keys still in grace period
    pub fn previous_key_count(&self) -> usize {
        self.previous_keys.len()
    }

    /// H-WRAITH-2: Check if there are any active sessions that would be broken by rotation
    ///
    /// Returns true only if it's safe to rotate the key, meaning:
    /// - No active nonces exist (no in-flight signing operations)
    /// - No previous keys in grace period (previous rotations have settled)
    ///
    /// This prevents breaking active Wraith sessions which can last hours or days.
    pub fn can_rotate(&self) -> bool {
        self.active_nonces.is_empty() && self.previous_keys.is_empty()
    }

    /// H-WRAITH-2: Rotate key only if safe to do so
    ///
    /// This is the recommended way to rotate keys in production. It checks that
    /// no active sessions would be broken by the rotation before proceeding.
    ///
    /// # Returns
    ///
    /// - `Ok(PublicKey)` - The new public key after successful rotation
    /// - `Err(WraithError)` - If rotation would break active sessions
    ///
    /// # Example
    ///
    /// ```ignore
    /// match signer.rotate_key_if_safe() {
    ///     Ok(new_pubkey) => println!("Key rotated successfully"),
    ///     Err(_) => println!("Cannot rotate: active sessions exist"),
    /// }
    /// ```
    pub fn rotate_key_if_safe(&mut self) -> Result<PublicKey, WraithError> {
        // First clean up expired nonces and old keys
        self.cleanup_expired_nonces();
        self.cleanup_old_keys();

        if !self.can_rotate() {
            let active_nonces = self.active_nonces.len();
            let previous_keys = self.previous_keys.len();
            return Err(WraithError::PhaseError(format!(
                "Cannot rotate key while sessions are active: {} active nonces, {} previous keys in grace period",
                active_nonces, previous_keys
            )));
        }

        self.rotate_key()
    }

    /// H-WRAITH-2: Get the number of active nonces that would block rotation
    ///
    /// Useful for monitoring and deciding when to schedule key rotation.
    pub fn blocking_session_count(&self) -> usize {
        self.active_nonces.len() + self.previous_keys.len()
    }
}

// ============================================================================
// Participant (User) Side
// ============================================================================

/// Context for blinding a message and obtaining a blind signature
///
/// Stores the blinding factors needed to unblind the signature.
/// Must be kept secret by the participant until unblinding is complete.
#[derive(Clone)]
#[allow(dead_code)]
pub struct BlindingContext {
    /// Random blinding scalar α (alpha)
    alpha: SecretKey,
    /// Random blinding scalar β (beta)
    beta: SecretKey,
    /// The original message being signed
    message: Vec<u8>,
    /// The coordinator's public key X
    coordinator_pubkey: PublicKey,
    /// The original nonce R from coordinator
    original_nonce: PublicKey,
    /// The blinded nonce R' = R + α*G + β*X
    blinded_nonce: PublicKey,
    /// Session ID for this signing
    session_id: [u8; 32],
}

impl BlindingContext {
    /// Create a blinding context from a coordinator's nonce
    ///
    /// # Arguments
    /// * `message` - The message to be signed (e.g., address bytes)
    /// * `coordinator_pubkey` - The coordinator's public key X
    /// * `nonce` - The public nonce from coordinator
    pub fn new(
        message: Vec<u8>,
        coordinator_pubkey: &PublicKey,
        nonce: &PublicNonce,
    ) -> Result<Self, WraithError> {
        let secp = Secp256k1::new();

        // Parse the nonce point
        let original_nonce = PublicKey::from_slice(&nonce.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce: {}", e)))?;

        // Generate random blinding factors
        let alpha = random_secret_key()?;
        let beta = random_secret_key()?;

        // Compute R' = R + α*G + β*X
        let alpha_g = PublicKey::from_secret_key(&secp, &alpha);
        let beta_x = coordinator_pubkey
            .mul_tweak(&secp, &Scalar::from(beta))
            .map_err(|e| WraithError::PhaseError(format!("Point multiply failed: {}", e)))?;

        let r_plus_alpha = original_nonce
            .combine(&alpha_g)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        let blinded_nonce = r_plus_alpha
            .combine(&beta_x)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        Ok(Self {
            alpha,
            beta,
            message,
            coordinator_pubkey: *coordinator_pubkey,
            original_nonce,
            blinded_nonce,
            session_id: nonce.session_id,
        })
    }

    /// Create the blinded challenge to send to the coordinator
    ///
    /// Computes c = H(X || R' || m), then c' = c + β
    pub fn create_blinded_challenge(&self) -> Result<BlindedChallenge, WraithError> {
        // Compute unblinded challenge c = H(X || R' || m)
        let c = compute_challenge(&self.coordinator_pubkey, &self.blinded_nonce, &self.message);

        // Parse as scalar
        let c_scalar = SecretKey::from_slice(&c)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge hash: {}", e)))?;

        // Compute c' = c + β
        let c_prime = c_scalar
            .add_tweak(&Scalar::from(self.beta))
            .map_err(|e| WraithError::PhaseError(format!("Scalar add failed: {}", e)))?;

        Ok(BlindedChallenge {
            challenge: c_prime.secret_bytes(),
            session_id: self.session_id,
        })
    }

    /// Unblind the signature response to get a valid Schnorr signature
    ///
    /// Computes s' = s + α, producing signature (R', s') on the original message.
    pub fn unblind(
        &self,
        response: &BlindSignatureResponse,
        session_key_id: [u8; 32],
    ) -> Result<UnblindedToken, WraithError> {
        // Verify session matches
        if response.session_id != self.session_id {
            return Err(WraithError::MissingData("Session ID mismatch".into()));
        }

        // Parse s
        let s = SecretKey::from_slice(&response.signature_scalar)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid signature: {}", e)))?;

        // Compute s' = s + α
        let s_prime = s
            .add_tweak(&Scalar::from(self.alpha))
            .map_err(|e| WraithError::PhaseError(format!("Scalar add failed: {}", e)))?;

        Ok(UnblindedToken {
            message: self.message.clone(),
            nonce_point: self.blinded_nonce.serialize(),
            signature_scalar: s_prime.secret_bytes(),
            session_key_id,
        })
    }

    /// Get the blinded nonce R' (for debugging)
    pub fn blinded_nonce(&self) -> &PublicKey {
        &self.blinded_nonce
    }
}

/// M-9 FIX: Zeroize blinding factors (alpha, beta) on drop to prevent memory leakage
///
/// These secret scalars could allow an attacker to link participants to their
/// output addresses if recovered from memory. We use defense-in-depth:
/// 1. Call secp256k1's non_secure_erase()
/// 2. Overwrite with deterministic dummy values
/// 3. Zeroize the temporary buffer
///
/// HIGH-CRYPTO-4 FIX: Each zeroization step is wrapped to ensure subsequent
/// steps execute even if earlier ones panic. This prevents partial cleanup
/// where some secrets remain in memory if Drop panics midway.
impl Drop for BlindingContext {
    fn drop(&mut self) {
        // HIGH-CRYPTO-4: Zeroize message FIRST, unconditionally
        // This is the most likely to succeed and contains sensitive address info
        self.message.zeroize();

        // HIGH-CRYPTO-4: Use catch_unwind for each step to ensure all zeroization happens
        // Even if one step panics, the others will execute

        // Step 1: Erase alpha
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.alpha.non_secure_erase();
        }));

        // Step 2: Erase beta
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.beta.non_secure_erase();
        }));

        // Step 3: Overwrite with deterministic dummy values for defense-in-depth
        // HIGH-CRYPTO-4: Use pre-validated dummy key to avoid potential panic
        // These byte values are valid secp256k1 secret keys (within curve order)
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut dummy = [1u8; 32];
            if let Ok(dummy_key) = SecretKey::from_slice(&dummy) {
                self.alpha = dummy_key;
            }
            dummy[0] = 2; // Use different value for beta
            if let Ok(dummy_key) = SecretKey::from_slice(&dummy) {
                self.beta = dummy_key;
            }
            dummy.zeroize();
        }));
    }
}

/// WR4-M2: Maximum size for token messages to prevent memory exhaustion
const MAX_TOKEN_MESSAGE_SIZE: usize = 1024; // 1 KB max - more than enough for addresses

/// Unblinded token proving message was signed by coordinator
///
/// This is a standard Schnorr signature (R', s') on the message m.
/// The coordinator cannot link this to the blind signing request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnblindedToken {
    /// The signed message
    pub message: Vec<u8>,
    /// R' = R + α*G + β*X (the blinded nonce point)
    #[serde(with = "bytes33_hex")]
    pub nonce_point: [u8; 33],
    /// s' = s + α (the unblinded signature scalar)
    pub signature_scalar: [u8; 32],
    /// Session key ID for verification
    pub session_key_id: [u8; 32],
}

impl UnblindedToken {
    /// WR4-M2: Validate that the token message size is within limits
    ///
    /// Prevents memory exhaustion attacks via oversized messages.
    pub fn validate_size(&self) -> Result<(), WraithError> {
        if self.message.len() > MAX_TOKEN_MESSAGE_SIZE {
            return Err(WraithError::InvalidInput(format!(
                "Token message too large: {} bytes (max {})",
                self.message.len(),
                MAX_TOKEN_MESSAGE_SIZE
            )));
        }
        Ok(())
    }

    /// Convert to standard 64-byte Schnorr signature format
    ///
    /// Format: R' (32 bytes x-only) || s' (32 bytes)
    pub fn to_schnorr_bytes(&self) -> Result<[u8; 64], WraithError> {
        let r_point = PublicKey::from_slice(&self.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce: {}", e)))?;

        let r_x_only = r_point.x_only_public_key().0;

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_x_only.serialize());
        sig[32..].copy_from_slice(&self.signature_scalar);

        Ok(sig)
    }
}

/// Verifier for unblinded tokens (used by non-coordinators)
pub struct TokenVerifier {
    /// Coordinator's public key
    coordinator_pubkey: PublicKey,
    /// Expected key ID
    key_id: [u8; 32],
}

impl TokenVerifier {
    /// Create a verifier from coordinator's public key
    pub fn new(coordinator_pubkey: PublicKey, session_id: &[u8; 32]) -> Self {
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(session_id);
        engine.input(&coordinator_pubkey.serialize());
        let key_id = sha256::Hash::from_engine(engine).to_byte_array();

        Self {
            coordinator_pubkey,
            key_id,
        }
    }

    /// Verify an unblinded token
    ///
    /// Performs standard Schnorr verification: s'*G == R' + c*X
    ///
    /// HIGH-CRYPTO-1 FIX: Uses constant-time comparison for key ID.
    pub fn verify(&self, token: &UnblindedToken) -> Result<bool, WraithError> {
        let secp = Secp256k1::new();

        // HIGH-CRYPTO-1 FIX: Use constant-time comparison for key ID
        let key_matches: bool = token.session_key_id.ct_eq(&self.key_id).into();
        if !key_matches {
            return Ok(false);
        }

        // Parse signature components
        let r_prime = PublicKey::from_slice(&token.nonce_point)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid nonce point: {}", e)))?;

        let s_prime = SecretKey::from_slice(&token.signature_scalar).map_err(|e| {
            WraithError::InvalidSignature(format!("Invalid signature scalar: {}", e))
        })?;

        // Compute challenge c = H(X || R' || m)
        let challenge = compute_challenge(&self.coordinator_pubkey, &r_prime, &token.message);

        // Verify: s'*G == R' + c*X
        let s_g = PublicKey::from_secret_key(&secp, &s_prime);

        let c_scalar = SecretKey::from_slice(&challenge)
            .map_err(|e| WraithError::InvalidSignature(format!("Invalid challenge: {}", e)))?;

        // Compute c*X
        let c_x = self
            .coordinator_pubkey
            .mul_tweak(&secp, &Scalar::from(c_scalar))
            .map_err(|e| WraithError::PhaseError(format!("Point multiply failed: {}", e)))?;

        // Compute R' + c*X
        let expected = r_prime
            .combine(&c_x)
            .map_err(|e| WraithError::PhaseError(format!("Point add failed: {}", e)))?;

        Ok(s_g == expected)
    }
}

// ============================================================================
// Legacy API Compatibility Layer
// ============================================================================

/// A blinded address ready to be signed by coordinator (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedAddress {
    /// Blinded challenge c'
    pub blinded_challenge: [u8; 32],
    /// Session ID
    pub session_id: [u8; 32],
}

/// Coordinator's signature on a blinded address (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindSignature {
    /// The signature scalar s
    pub signature_scalar: [u8; 32],
    /// Session-specific signing key identifier
    pub session_key_id: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::XOnlyPublicKey;

    fn generate_test_address() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = random_secret_key().expect("test RNG should work");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        pk.x_only_public_key().0
    }

    #[test]
    fn test_blind_signature_full_protocol() {
        let session_id = [1u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();
        let participant = "test_participant";

        // Step 1: Coordinator creates signer and nonce bound to participant
        let mut signer = CoordinatorSigner::new(&session_id).unwrap();
        let nonce = signer.create_nonce_for_participant(participant).unwrap();

        // Step 2: Participant creates blinding context
        let context = BlindingContext::new(message.clone(), signer.public_key(), &nonce).unwrap();

        // Step 3: Participant creates blinded challenge
        let blinded_challenge = context.create_blinded_challenge().unwrap();

        // Step 4: Coordinator signs blinded challenge for participant
        let response = signer
            .sign_blinded_challenge_for_participant(&blinded_challenge, participant)
            .unwrap();

        // Step 5: Participant unblinds to get final signature
        let token = context.unblind(&response, *signer.key_id()).unwrap();

        // Verify the signature is valid
        assert!(signer.verify_signature(&token).unwrap());

        // Verify with external verifier
        let verifier = TokenVerifier::new(*signer.public_key(), &session_id);
        assert!(verifier.verify(&token).unwrap());

        // Verify the message is correct
        assert_eq!(token.message, message);
    }

    #[test]
    fn test_unlinkability() {
        let session_id = [2u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();
        let participant = "unlinkability_test";

        let mut signer = CoordinatorSigner::new(&session_id).unwrap();

        // Get two blind signatures on the same message
        let nonce1 = signer.create_nonce_for_participant(participant).unwrap();
        let nonce2 = signer.create_nonce_for_participant(participant).unwrap();

        let context1 = BlindingContext::new(message.clone(), signer.public_key(), &nonce1).unwrap();
        let context2 = BlindingContext::new(message.clone(), signer.public_key(), &nonce2).unwrap();

        let challenge1 = context1.create_blinded_challenge().unwrap();
        let challenge2 = context2.create_blinded_challenge().unwrap();

        // Challenges should be different (due to random blinding)
        assert_ne!(challenge1.challenge, challenge2.challenge);

        let response1 = signer
            .sign_blinded_challenge_for_participant(&challenge1, participant)
            .unwrap();
        let response2 = signer
            .sign_blinded_challenge_for_participant(&challenge2, participant)
            .unwrap();

        let token1 = context1.unblind(&response1, *signer.key_id()).unwrap();
        let token2 = context2.unblind(&response2, *signer.key_id()).unwrap();

        // Both should verify
        assert!(signer.verify_signature(&token1).unwrap());
        assert!(signer.verify_signature(&token2).unwrap());

        // The final signatures should be different (unlinkable)
        assert_ne!(token1.nonce_point, token2.nonce_point);
        assert_ne!(token1.signature_scalar, token2.signature_scalar);

        // But both are valid signatures on the same message
        assert_eq!(token1.message, token2.message);
    }

    #[test]
    fn test_nonce_single_use() {
        let session_id = [3u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();
        let participant = "single_use_test";

        let mut signer = CoordinatorSigner::new(&session_id).unwrap();
        let nonce = signer.create_nonce_for_participant(participant).unwrap();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();

        // First signing should succeed
        let _ = signer
            .sign_blinded_challenge_for_participant(&challenge, participant)
            .unwrap();

        // Second attempt with same session should fail (nonce consumed)
        let result = signer.sign_blinded_challenge_for_participant(&challenge, participant);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_sessions_different_keys() {
        let session1 = [1u8; 32];
        let session2 = [2u8; 32];

        let signer1 = CoordinatorSigner::new(&session1).unwrap();
        let signer2 = CoordinatorSigner::new(&session2).unwrap();

        assert_ne!(signer1.key_id(), signer2.key_id());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let session_id = [4u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();
        let participant = "wrong_key_test";

        let mut signer = CoordinatorSigner::new(&session_id).unwrap();
        let nonce = signer.create_nonce_for_participant(participant).unwrap();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        let response = signer
            .sign_blinded_challenge_for_participant(&challenge, participant)
            .unwrap();
        let mut token = context.unblind(&response, *signer.key_id()).unwrap();

        // Tamper with session key ID
        token.session_key_id = [0u8; 32];

        // Should fail verification
        assert!(!signer.verify_signature(&token).unwrap());
    }

    #[test]
    fn test_tampered_message_fails() {
        let session_id = [5u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();
        let participant = "tampered_msg_test";

        let mut signer = CoordinatorSigner::new(&session_id).unwrap();
        let nonce = signer.create_nonce_for_participant(participant).unwrap();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        let response = signer
            .sign_blinded_challenge_for_participant(&challenge, participant)
            .unwrap();
        let mut token = context.unblind(&response, *signer.key_id()).unwrap();

        // Tamper with message
        token.message[0] ^= 0xff;

        // Should fail verification
        assert!(!signer.verify_signature(&token).unwrap());
    }

    #[test]
    fn test_schnorr_bytes_conversion() {
        let session_id = [6u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();
        let participant = "schnorr_test";

        let mut signer = CoordinatorSigner::new(&session_id).unwrap();
        let nonce = signer.create_nonce_for_participant(participant).unwrap();

        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        let response = signer
            .sign_blinded_challenge_for_participant(&challenge, participant)
            .unwrap();
        let token = context.unblind(&response, *signer.key_id()).unwrap();

        // Should be able to convert to standard 64-byte format
        let schnorr_bytes = token.to_schnorr_bytes().unwrap();
        assert_eq!(schnorr_bytes.len(), 64);
    }

    /// WR-H1 Security Test: Nonces are bound to participants
    ///
    /// This test verifies that:
    /// 1. Nonces created for participant A cannot be used by participant B
    /// 2. The binding is enforced during signing
    /// 3. C-WRAITH-1: Nonce is NOT consumed on verification failure (timing attack fix)
    #[test]
    fn test_nonce_bound_to_participant() {
        let session_id = [7u8; 32];
        let address = generate_test_address();
        let message = address.serialize().to_vec();

        let mut signer = CoordinatorSigner::new(&session_id).unwrap();

        // Create a nonce bound to "ghost1"
        let nonce = signer.create_nonce_for_participant("ghost1").unwrap();

        // Participant creates blinding context
        let context = BlindingContext::new(message, signer.public_key(), &nonce).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();

        // Attempt to sign as "ghost2" (wrong participant) should FAIL
        let result = signer.sign_blinded_challenge_for_participant(&challenge, "ghost2");
        assert!(
            result.is_err(),
            "Signing with wrong participant should fail"
        );
        // WR4-L6: Error message is now sanitized to prevent information leakage
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Signature verification failed"));

        // C-WRAITH-1: The nonce should NOT be consumed on verification failure
        // This prevents timing attacks - we can now use the same nonce with correct participant
        // Signing as "ghost1" (correct participant) should SUCCEED with the SAME challenge
        let result = signer.sign_blinded_challenge_for_participant(&challenge, "ghost1");
        assert!(
            result.is_ok(),
            "Signing with correct participant should succeed"
        );
    }

    /// Test that nonce binding includes ghost_id in session_id generation
    #[test]
    fn test_nonce_session_id_includes_participant() {
        let session_id = [8u8; 32];

        let mut signer1 = CoordinatorSigner::new(&session_id).unwrap();
        let mut signer2 = CoordinatorSigner::new(&session_id).unwrap();

        // Create nonces for different participants on different signers
        let nonce1 = signer1.create_nonce_for_participant("ghost1").unwrap();
        let nonce2 = signer2.create_nonce_for_participant("ghost2").unwrap();

        // Even with same coordinator key, different participants get different session IDs
        // (due to random entropy AND ghost_id in hash)
        assert_ne!(
            nonce1.session_id, nonce2.session_id,
            "Different participants should get different session IDs"
        );
    }

    /// WR-M2 Security Test: Rate limiting on nonce generation
    ///
    /// This test verifies that:
    /// 1. Per-participant limits are enforced
    /// 2. Nonces are properly counted and decremented on use
    #[test]
    fn test_nonce_rate_limiting() {
        let session_id = [10u8; 32];
        let mut signer = CoordinatorSigner::new(&session_id).unwrap();

        // Create nonces up to the per-participant limit
        let mut nonces = Vec::new();
        for i in 0..super::MAX_NONCES_PER_PARTICIPANT {
            let result = signer.create_nonce_for_participant("rate_test_ghost");
            assert!(result.is_ok(), "Nonce {} should succeed", i);
            nonces.push(result.unwrap());
        }

        // Next nonce should fail due to rate limit
        let result = signer.create_nonce_for_participant("rate_test_ghost");
        assert!(
            result.is_err(),
            "Should fail after reaching per-participant limit"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Maximum nonces per participant"));

        // After consuming a nonce, we should be able to create another
        let address = generate_test_address();
        let message = address.serialize().to_vec();
        let context = BlindingContext::new(message, signer.public_key(), &nonces[0]).unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        signer
            .sign_blinded_challenge_for_participant(&challenge, "rate_test_ghost")
            .unwrap();

        // Now creating another should succeed
        let result = signer.create_nonce_for_participant("rate_test_ghost");
        assert!(result.is_ok(), "Should succeed after consuming a nonce");

        // Different participant should have their own limit
        let result = signer.create_nonce_for_participant("other_ghost");
        assert!(
            result.is_ok(),
            "Different participant should have separate limit"
        );
    }

    /// E-5: the only health check is that the OS source can be read.
    ///
    /// Deliberately not a statistical test. The Coldcard incident (July
    /// 2026) is the case in point: seed generation had silently fallen back
    /// to MicroPython's Yasmarang PRNG, cutting effective entropy to ~40-72
    /// bits. Its *output* is perfectly well distributed — every statistical
    /// test this file used to run would have passed it, right up to the
    /// point where ~1,816 BTC was swept out of 5,200 addresses.
    #[test]
    fn the_rng_health_check_is_availability_and_nothing_else() {
        assert!(
            ensure_os_rng_available().is_ok(),
            "the OS random source must be readable"
        );
    }

    /// Fresh calls must not repeat. A trivially broken RNG — one that
    /// returns a constant — is caught by using the values, not by grading
    /// them.
    #[test]
    fn successive_random_values_differ() {
        let a = random_bytes_32().expect("os rng");
        let b = random_bytes_32().expect("os rng");
        assert_ne!(a, b);
    }

    /// CRIT-7: Verify that malformed inputs return errors instead of panicking
    ///
    /// This test ensures the coordinator doesn't crash when receiving malformed
    /// blinding requests from potentially malicious participants.
    #[test]
    fn test_malformed_inputs_return_errors_not_panic() {
        let session_id = [42u8; 32];
        let mut signer = CoordinatorSigner::new(&session_id).unwrap();

        // Test 1: Invalid session_id in BlindedChallenge (nonce doesn't exist)
        let fake_challenge = BlindedChallenge {
            challenge: [0u8; 32],   // Valid scalar (all zeros)
            session_id: [0xff; 32], // Non-existent session
        };
        let result = signer.sign_blinded_challenge_for_participant(&fake_challenge, "test_ghost");
        assert!(
            result.is_err(),
            "Non-existent nonce should return error, not panic"
        );

        // Test 2: Invalid challenge scalar (not a valid secp256k1 scalar - all 0xff is > curve order)
        let nonce = signer.create_nonce_for_participant("test_ghost").unwrap();
        let invalid_challenge = BlindedChallenge {
            challenge: [0xff; 32], // Invalid scalar (exceeds curve order)
            session_id: nonce.session_id,
        };
        let result =
            signer.sign_blinded_challenge_for_participant(&invalid_challenge, "test_ghost");
        assert!(
            result.is_err(),
            "Invalid scalar should return error, not panic"
        );

        // Test 3: Invalid nonce point in PublicNonce (when creating BlindingContext)
        let fake_nonce = PublicNonce {
            nonce_point: [0u8; 33], // Invalid point (not on curve)
            session_id: [1u8; 32],
        };
        let secp = Secp256k1::new();
        let sk = random_secret_key().expect("test RNG should work");
        let pubkey = PublicKey::from_secret_key(&secp, &sk);
        let result = BlindingContext::new(vec![0u8; 32], &pubkey, &fake_nonce);
        assert!(
            result.is_err(),
            "Invalid nonce point should return error, not panic"
        );

        // Test 4: Verify signature on token with invalid nonce_point
        let session_id2 = [43u8; 32];
        let signer2 = CoordinatorSigner::new(&session_id2).unwrap();
        let token_with_bad_nonce = UnblindedToken {
            message: vec![1, 2, 3],
            nonce_point: [0u8; 33], // Invalid point
            signature_scalar: [0u8; 32],
            session_key_id: *signer2.key_id(),
        };
        let result = signer2.verify_signature(&token_with_bad_nonce);
        assert!(
            result.is_err(),
            "Invalid nonce point in token should return error, not panic"
        );

        // Test 5: Verify signature on token with invalid signature scalar
        let token_with_bad_scalar = UnblindedToken {
            message: vec![1, 2, 3],
            nonce_point: pubkey.serialize(), // Valid point
            signature_scalar: [0xff; 32],    // Invalid scalar (exceeds curve order)
            session_key_id: *signer2.key_id(),
        };
        let result = signer2.verify_signature(&token_with_bad_scalar);
        assert!(
            result.is_err(),
            "Invalid signature scalar should return error, not panic"
        );
    }

    /// CRIT-7: Verify TokenVerifier handles malformed tokens gracefully
    #[test]
    fn test_token_verifier_malformed_input() {
        let session_id = [44u8; 32];
        let secp = Secp256k1::new();
        let sk = random_secret_key().expect("test RNG should work");
        let pubkey = PublicKey::from_secret_key(&secp, &sk);

        let verifier = TokenVerifier::new(pubkey, &session_id);

        // Compute the correct key_id so tokens pass the early check
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let mut engine = sha256::Hash::engine();
        engine.input(b"wraith/key-id/v1");
        engine.input(&session_id);
        engine.input(&pubkey.serialize());
        let key_id: [u8; 32] = sha256::Hash::from_engine(engine).to_byte_array();

        // Test with invalid nonce point
        let bad_token = UnblindedToken {
            message: vec![1, 2, 3],
            nonce_point: [0u8; 33], // Invalid point (not on curve)
            signature_scalar: [0u8; 32],
            session_key_id: key_id, // Use correct key_id to pass early check
        };
        let result = verifier.verify(&bad_token);
        assert!(
            result.is_err(),
            "Invalid nonce point should return error, not panic"
        );

        // Test with invalid scalar (0xff repeated exceeds curve order)
        let bad_token2 = UnblindedToken {
            message: vec![1, 2, 3],
            nonce_point: pubkey.serialize(),
            signature_scalar: [0xff; 32], // Invalid scalar (exceeds curve order)
            session_key_id: key_id,       // Use correct key_id to pass early check
        };
        let result = verifier.verify(&bad_token2);
        assert!(
            result.is_err(),
            "Invalid signature scalar should return error, not panic"
        );
    }

    /// CRIT-7: Verify BlindingContext handles edge cases gracefully
    #[test]
    fn test_blinding_context_edge_cases() {
        let secp = Secp256k1::new();
        let sk = random_secret_key().expect("test RNG should work");
        let pubkey = PublicKey::from_secret_key(&secp, &sk);

        // Test with valid nonce - should succeed
        let mut signer = CoordinatorSigner::new(&[45u8; 32]).unwrap();
        let valid_nonce = signer.create_nonce_for_participant("test").unwrap();
        let result = BlindingContext::new(vec![0u8; 32], &pubkey, &valid_nonce);
        assert!(result.is_ok(), "Valid inputs should succeed");

        // Test to_schnorr_bytes with invalid nonce point
        let context = result.unwrap();
        let challenge = context.create_blinded_challenge().unwrap();
        let response = signer
            .sign_blinded_challenge_for_participant(&challenge, "test")
            .unwrap();
        let mut token = context.unblind(&response, *signer.key_id()).unwrap();

        // Corrupt the nonce_point
        token.nonce_point = [0u8; 33];
        let result = token.to_schnorr_bytes();
        assert!(
            result.is_err(),
            "Invalid nonce point in to_schnorr_bytes should return error"
        );
    }
}
