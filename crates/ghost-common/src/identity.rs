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
//| FILE: identity.rs                                                                                                    |
//|======================================================================================================================|

//! Node identity management using Ed25519 keys
//!
//! Each node has a unique Ed25519 keypair that identifies it in the network.
//! The public key (32 bytes) serves as the NodeId.
//!
//! ## Sybil Resistance via Proof-of-Work
//!
//! To prevent Sybil attacks on elder selection (which uses node_id ordering),
//! nodes must provide a proof-of-work nonce such that:
//!   SHA256(public_key || nonce) has at least `NODE_ID_POW_DIFFICULTY` leading zero bits
//!
//! This makes generating "favorable" node_ids computationally expensive.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use crate::error::{GhostError, GhostResult};
use crate::signer::{LocalSigner, Signer, SignerConfig};
use crate::types::NodeId;

/// M-6: Required leading zero bits for node_id proof-of-work.
/// 24 bits = ~16 million hashes on average (tens of seconds on modern hardware).
/// This increased difficulty (from 20 bits) makes mass Sybil attacks significantly
/// more expensive for mainnet while remaining feasible for legitimate nodes.
///
/// Debug builds use a lower difficulty (16 bits) to avoid slow test execution.
/// Release builds use the full 24-bit difficulty.
#[cfg(debug_assertions)]
pub const NODE_ID_POW_DIFFICULTY: u32 = 16;

/// Production difficulty for mainnet (release builds only)
#[cfg(not(debug_assertions))]
pub const NODE_ID_POW_DIFFICULTY: u32 = 24;

/// Maximum nonce value to try (prevents infinite loops)
const MAX_POW_ATTEMPTS: u64 = 100_000_000;

/// Proof-of-work for node identity
/// Proves computational work was done to create this identity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeIdProof {
    /// The nonce that satisfies the PoW requirement
    pub nonce: u64,
    /// The difficulty level (leading zero bits) achieved
    pub difficulty: u32,
}

impl NodeIdProof {
    /// Compute the proof hash for a given public key and nonce
    pub fn compute_hash(public_key: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        hasher.update(nonce.to_le_bytes());
        hasher.finalize().into()
    }

    /// Count leading zero bits in a hash
    pub fn leading_zeros(hash: &[u8; 32]) -> u32 {
        let mut zeros = 0u32;
        for byte in hash {
            if *byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros
    }

    /// Verify that this proof is valid for the given public key
    pub fn verify(&self, public_key: &[u8; 32], required_difficulty: u32) -> bool {
        let hash = Self::compute_hash(public_key, self.nonce);
        let zeros = Self::leading_zeros(&hash);
        zeros >= required_difficulty && self.difficulty >= required_difficulty
    }

    /// Mine a proof-of-work nonce for the given public key
    /// Returns None if max attempts exceeded (should not happen with reasonable difficulty)
    pub fn mine(public_key: &[u8; 32], required_difficulty: u32) -> Option<Self> {
        for nonce in 0..MAX_POW_ATTEMPTS {
            let hash = Self::compute_hash(public_key, nonce);
            let zeros = Self::leading_zeros(&hash);
            if zeros >= required_difficulty {
                return Some(Self {
                    nonce,
                    difficulty: zeros,
                });
            }
        }
        None
    }

    /// Serialize to bytes (for storage)
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..8].copy_from_slice(&self.nonce.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.difficulty.to_le_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 12 {
            return None;
        }
        let nonce = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let difficulty = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        Some(Self { nonce, difficulty })
    }

    /// Serialize to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserialize from hex string
    pub fn from_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str).ok()?;
        Self::from_bytes(&bytes)
    }
}

/// Node identity with Ed25519 keypair and proof-of-work
///
/// NodeIdentity wraps a [`Signer`] implementation to abstract the signing backend.
/// This enables future HSM/KMS integration without changing calling code.
///
/// # Signer Abstraction
///
/// By default, NodeIdentity uses [`LocalSigner`] which stores keys in a local file.
/// Future implementations will support HSM and KMS backends through the same interface.
#[derive(Debug)]
pub struct NodeIdentity {
    /// Signer implementation (LocalSigner, HSM, or KMS)
    signer: Arc<dyn Signer>,
    /// Cached public key (for efficiency)
    public_key: [u8; 32],
    /// Proof-of-work for Sybil resistance
    pow_proof: Option<NodeIdProof>,
    /// Display name (optional)
    display_name: Option<String>,
}

impl NodeIdentity {
    /// Create a new random identity with proof-of-work
    /// This will mine a nonce that satisfies the PoW difficulty requirement
    pub fn generate() -> Self {
        let signer = Arc::new(LocalSigner::generate());
        let public_key = signer.public_key();

        // Mine proof-of-work
        let pow_proof = NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY);

        if pow_proof.is_none() {
            tracing::warn!("Failed to mine node_id proof-of-work after max attempts");
        } else {
            tracing::debug!(
                difficulty = pow_proof.as_ref().map(|p| p.difficulty).unwrap_or(0),
                nonce = pow_proof.as_ref().map(|p| p.nonce).unwrap_or(0),
                "Node identity proof-of-work mined"
            );
        }

        Self {
            signer,
            public_key,
            pow_proof,
            display_name: None,
        }
    }

    /// Create a NodeIdentity from a Signer implementation
    ///
    /// This allows using custom signer backends (HSM, KMS) with NodeIdentity.
    /// Proof-of-work will be mined automatically.
    pub fn from_signer(signer: Arc<dyn Signer>) -> Self {
        let public_key = signer.public_key();
        let pow_proof = NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY);

        Self {
            signer,
            public_key,
            pow_proof,
            display_name: None,
        }
    }

    /// Create a NodeIdentity from a Signer with existing PoW proof
    ///
    /// Use this when restoring from database or file to avoid re-mining.
    pub fn from_signer_with_proof(signer: Arc<dyn Signer>, pow_proof: Option<NodeIdProof>) -> Self {
        let public_key = signer.public_key();

        Self {
            signer,
            public_key,
            pow_proof,
            display_name: None,
        }
    }

    /// Create a NodeIdentity from a SignerConfig
    ///
    /// This is the recommended way to create an identity from configuration.
    pub fn from_config(config: &SignerConfig) -> GhostResult<Self> {
        let signer = crate::signer::create_signer(config)
            .map_err(|e| GhostError::InvalidKey(format!("Failed to create signer: {}", e)))?;

        let public_key = signer.public_key();
        let pow_proof = NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY);

        Ok(Self {
            signer,
            public_key,
            pow_proof,
            display_name: None,
        })
    }

    /// Create identity without proof-of-work (for testing only)
    #[cfg(test)]
    pub fn generate_without_pow() -> Self {
        let signer = Arc::new(LocalSigner::generate());
        let public_key = signer.public_key();

        Self {
            signer,
            public_key,
            pow_proof: None,
            display_name: None,
        }
    }

    /// Get the underlying signer
    pub fn signer(&self) -> &Arc<dyn Signer> {
        &self.signer
    }

    /// Get the signer type (local, hsm, kms)
    pub fn signer_type(&self) -> &'static str {
        self.signer.signer_type()
    }

    /// Load identity from a key file (44 bytes: 32 key + 12 PoW proof)
    /// Legacy 32-byte files are supported but will lack PoW proof
    pub fn load<P: AsRef<Path>>(path: P) -> GhostResult<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(GhostError::KeyFileNotFound(
                path.to_string_lossy().to_string(),
            ));
        }

        let key_bytes = fs::read(path)
            .map_err(|e| GhostError::InvalidKey(format!("Failed to read key file: {}", e)))?;

        // Support both legacy (32 bytes) and new format (44 bytes with PoW)
        if key_bytes.len() != 32 && key_bytes.len() != 44 {
            return Err(GhostError::InvalidKey(format!(
                "Invalid key length: expected 32 or 44, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes[..32]);

        let signer = Arc::new(LocalSigner::from_bytes(&key_array));
        let public_key = signer.public_key();

        // Extract PoW proof if present
        let pow_proof = if key_bytes.len() == 44 {
            NodeIdProof::from_bytes(&key_bytes[32..])
        } else {
            // Legacy key without PoW - mine one now
            NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY)
        };

        Ok(Self {
            signer,
            public_key,
            pow_proof,
            display_name: None,
        })
    }

    /// Load identity from hex-encoded string (private key only, will mine PoW)
    pub fn from_hex(hex_str: &str) -> GhostResult<Self> {
        let signer = Arc::new(
            LocalSigner::from_hex(hex_str).map_err(|e| GhostError::InvalidKey(e.to_string()))?,
        );
        let public_key = signer.public_key();

        // Mine proof-of-work
        let pow_proof = NodeIdProof::mine(&public_key, NODE_ID_POW_DIFFICULTY);

        Ok(Self {
            signer,
            public_key,
            pow_proof,
            display_name: None,
        })
    }

    /// Load identity with existing PoW proof (for database restoration)
    pub fn from_hex_with_proof(hex_str: &str, proof_hex: &str) -> GhostResult<Self> {
        let signer = Arc::new(
            LocalSigner::from_hex(hex_str).map_err(|e| GhostError::InvalidKey(e.to_string()))?,
        );
        let public_key = signer.public_key();

        let pow_proof = NodeIdProof::from_hex(proof_hex);

        // Verify the proof is valid for this key
        if let Some(ref proof) = pow_proof {
            if !proof.verify(&public_key, NODE_ID_POW_DIFFICULTY) {
                return Err(GhostError::InvalidKey(
                    "PoW proof does not match public key".into(),
                ));
            }
        }

        Ok(Self {
            signer,
            public_key,
            pow_proof,
            display_name: None,
        })
    }

    /// Save identity to a key file (44 bytes: 32 key + 12 PoW proof)
    ///
    /// ⛔ REFUSES to overwrite an existing file (#985). `node.key` is not a cache: `node_id`
    /// derives from it, its first 32 bytes ARE the TDP authority secret, and the Elder slot is
    /// bound to it. Nothing backs it up. Generating over one does not recover an identity — it
    /// mints a DIFFERENT node and destroys the old one irrecoverably.
    ///
    /// `scripts/install-node.sh` called `--generate-identity` unconditionally on every run, so
    /// re-running the one-command installer — the most natural operator reflex there is — silently
    /// destroyed the node. The installer now guards it, and this refuses as well, so no future
    /// caller can reintroduce the same footgun.
    ///
    /// Callers that legitimately create a key check for absence first (see the `key_path.exists()`
    /// branch in `bins/ghost-pool/src/main.rs`), so this costs them nothing.
    ///
    /// Note: This only works for LocalSigner. HSM/KMS signers don't support
    /// exporting private keys.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> GhostResult<()> {
        let path = path.as_ref();

        if path.exists() {
            return Err(GhostError::InvalidKey(format!(
                "refusing to overwrite an existing identity at {} — node.key is irreplaceable \
                 (node_id, TDP authority secret and Elder slot all derive from it) and nothing \
                 backs it up. Move it aside deliberately if you really intend a NEW node.",
                path.display()
            )));
        }

        // For non-local signers, we can only save the PoW proof and public key reference
        // The actual key is managed by the HSM/KMS
        if self.signer.signer_type() != "local" {
            return Err(GhostError::InvalidKey(format!(
                "Cannot save {} signer to file - key is managed by external backend",
                self.signer.signer_type()
            )));
        }

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // For LocalSigner, we need to get the signing key bytes
        // We do this by downcasting, but fall back to just saving public key if that fails
        // In practice, LocalSigner always supports this
        let local_signer = self.signer.as_ref().as_any().downcast_ref::<LocalSigner>();

        if let Some(local) = local_signer {
            // Build 44-byte output: private key + PoW proof
            let mut output = Vec::with_capacity(44);
            output.extend_from_slice(&local.signing_key_bytes());

            if let Some(ref proof) = self.pow_proof {
                output.extend_from_slice(&proof.to_bytes());
            } else {
                // No proof - write zeros (legacy compatibility)
                output.extend_from_slice(&[0u8; 12]);
            }

            fs::write(path, &output)?;
        } else {
            return Err(GhostError::InvalidKey(
                "Cannot extract private key from signer".into(),
            ));
        }

        // Set restrictive permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(path, perms)?;
        }

        Ok(())
    }

    /// Get the node ID (public key bytes)
    pub fn node_id(&self) -> NodeId {
        self.public_key
    }

    /// Get the node ID as hex string
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id())
    }

    /// Get the short node ID (first 8 chars of hex)
    pub fn node_id_short(&self) -> String {
        self.node_id_hex()[..8].to_string()
    }

    /// Get the verifying key for signature verification
    ///
    /// Note: This creates a new VerifyingKey from the public key.
    /// For LocalSigner, this matches the internal key.
    ///
    /// # Errors
    ///
    /// Returns `GhostError::InvalidKey` if the public key bytes are not a valid
    /// Ed25519 public key. This should never happen for properly constructed
    /// `NodeIdentity` instances, but we handle it gracefully rather than panicking.
    pub fn verifying_key(&self) -> GhostResult<VerifyingKey> {
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|e| GhostError::InvalidKey(format!("Invalid public key: {}", e)))
    }

    /// Get the proof-of-work proof
    pub fn pow_proof(&self) -> Option<&NodeIdProof> {
        self.pow_proof.as_ref()
    }

    /// Get the PoW proof as hex string (for database storage)
    pub fn pow_proof_hex(&self) -> Option<String> {
        self.pow_proof.as_ref().map(|p| p.to_hex())
    }

    /// Check if this identity has a valid proof-of-work
    pub fn has_valid_pow(&self) -> bool {
        if let Some(ref proof) = self.pow_proof {
            proof.verify(&self.public_key, NODE_ID_POW_DIFFICULTY)
        } else {
            false
        }
    }

    /// Get the achieved PoW difficulty (leading zero bits)
    pub fn pow_difficulty(&self) -> u32 {
        self.pow_proof.as_ref().map(|p| p.difficulty).unwrap_or(0)
    }

    /// Set display name
    pub fn set_display_name(&mut self, name: impl Into<String>) {
        self.display_name = Some(name.into());
    }

    /// Get display name
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signer.sign(message)
    }

    /// Sign a hash (for consensus messages)
    pub fn sign_hash(&self, hash: &[u8; 32]) -> [u8; 64] {
        self.sign(hash)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.signer.verify(message, signature)
    }
}

/// Verify a signature from a remote node
pub fn verify_signature(
    node_id: &NodeId,
    message: &[u8],
    signature: &[u8; 64],
) -> GhostResult<bool> {
    let verifying_key = VerifyingKey::from_bytes(node_id)
        .map_err(|e| GhostError::InvalidKey(format!("Invalid public key: {}", e)))?;

    let sig = Signature::from_bytes(signature);

    Ok(verifying_key.verify(message, &sig).is_ok())
}

/// Verify a remote node_id has valid proof-of-work
/// This should be checked when accepting elder registrations
pub fn verify_node_id_pow(node_id: &NodeId, proof: &NodeIdProof, required_difficulty: u32) -> bool {
    proof.verify(node_id, required_difficulty)
}

/// Verify node_id PoW from hex strings (convenience for database values)
pub fn verify_node_id_pow_hex(
    node_id_hex: &str,
    proof_hex: &str,
    required_difficulty: u32,
) -> bool {
    let node_id_bytes = match hex::decode(node_id_hex) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return false,
    };
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&node_id_bytes);

    let proof = match NodeIdProof::from_hex(proof_hex) {
        Some(p) => p,
        None => return false,
    };

    proof.verify(&node_id, required_difficulty)
}

/// Hash a message using SHA-256
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Compute proposal hash for consensus
pub fn compute_proposal_hash(
    round_id: u64,
    block_hash: &[u8; 32],
    miner_payouts: &[(Vec<u8>, u64)],
    node_payouts: &[(Vec<u8>, u64)],
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    hasher.update(round_id.to_le_bytes());
    hasher.update(block_hash);

    for (address, amount) in miner_payouts {
        hasher.update(address);
        hasher.update(amount.to_le_bytes());
    }

    for (address, amount) in node_payouts {
        hasher.update(address);
        hasher.update(amount.to_le_bytes());
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_generate_identity() {
        let identity = NodeIdentity::generate();
        let node_id = identity.node_id();
        assert_eq!(node_id.len(), 32);
        // New identities should have valid PoW
        assert!(identity.has_valid_pow());
    }

    #[test]
    fn test_pow_proof_mining() {
        let identity = NodeIdentity::generate_without_pow();
        let public_key = identity.node_id();

        // Mine a proof
        let proof = NodeIdProof::mine(&public_key, 8).unwrap(); // Low difficulty for test speed
        assert!(proof.difficulty >= 8);
        assert!(proof.verify(&public_key, 8));

        // Verify the proof doesn't work with a different key
        // Use the specific nonce to find a key that definitely fails
        let mut wrong_key = public_key;
        wrong_key[0] ^= 0xff; // Flip bits in first byte

        // Compute what the hash would be for wrong_key
        let wrong_hash = NodeIdProof::compute_hash(&wrong_key, proof.nonce);
        let wrong_zeros = NodeIdProof::leading_zeros(&wrong_hash);

        // The wrong key should produce fewer leading zeros than required (with overwhelming probability)
        // If by extreme chance it passes, the test documents this edge case
        if wrong_zeros < 8 {
            assert!(!proof.verify(&wrong_key, 8));
        } else {
            // Extremely rare case (~1/256): document but don't fail
            eprintln!(
                "Note: wrong_key accidentally has {} leading zeros (test still valid)",
                wrong_zeros
            );
        }
    }

    #[test]
    fn test_pow_proof_deterministic() {
        // Deterministic test with pre-computed values to ensure no flakiness
        // This key and nonce were pre-computed to have exactly 8 leading zeros
        let known_key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        // Mine a proof for the known key (this is deterministic given the key)
        let proof = NodeIdProof::mine(&known_key, 8).unwrap();

        // Verify it works for the correct key
        assert!(proof.verify(&known_key, 8));

        // Verify the hash actually has the expected leading zeros
        let hash = NodeIdProof::compute_hash(&known_key, proof.nonce);
        let zeros = NodeIdProof::leading_zeros(&hash);
        assert!(
            zeros >= 8,
            "Hash should have at least 8 leading zeros, got {}",
            zeros
        );

        // A completely different key should fail (flip all bits)
        let wrong_key: [u8; 32] = [
            0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
            0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4, 0xe3,
            0xe2, 0xe1, 0xe0, 0xdf,
        ];

        let wrong_hash = NodeIdProof::compute_hash(&wrong_key, proof.nonce);
        let wrong_zeros = NodeIdProof::leading_zeros(&wrong_hash);

        // Document the actual zeros for debugging if this ever fails
        assert!(
            wrong_zeros < 8 || !proof.verify(&wrong_key, 8),
            "Wrong key with nonce {} has {} leading zeros - should not verify at difficulty 8",
            proof.nonce,
            wrong_zeros
        );
    }

    #[test]
    fn test_pow_leading_zeros() {
        // 0x00 has 8 leading zeros
        assert_eq!(
            NodeIdProof::leading_zeros(&[
                0, 0, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]),
            24
        );
        // 0x0f has 4 leading zeros
        assert_eq!(
            NodeIdProof::leading_zeros(&[
                0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]),
            4
        );
        // 0x80 has 0 leading zeros
        assert_eq!(
            NodeIdProof::leading_zeros(&[
                0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0
            ]),
            0
        );
    }

    #[test]
    fn test_pow_serialization() {
        let proof = NodeIdProof {
            nonce: 12345678,
            difficulty: 20,
        };

        let hex = proof.to_hex();
        let restored = NodeIdProof::from_hex(&hex).unwrap();

        assert_eq!(restored.nonce, proof.nonce);
        assert_eq!(restored.difficulty, proof.difficulty);
    }

    #[test]
    fn test_sign_verify() {
        let identity = NodeIdentity::generate();
        let message = b"Hello, Ghost!";

        let signature = identity.sign(message);
        assert!(identity.verify(message, &signature));

        // Wrong message should fail
        assert!(!identity.verify(b"Wrong message", &signature));
    }

    /// ⛔ The property #985 exists for: a second `save` to the same path must REFUSE, not
    /// overwrite. `node.key` carries `node_id`, the TDP authority secret and the Elder slot, and
    /// nothing backs it up — so an overwrite is unrecoverable identity loss, not a retry.
    ///
    /// This is what made re-running `install-node.sh` destructive: it called
    /// `--generate-identity` unconditionally, and the natural operator reflex of re-running an
    /// installer silently minted a different node.
    #[test]
    fn save_refuses_to_overwrite_an_existing_identity() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("node.key");

        let first = NodeIdentity::generate();
        first.save(&key_path).expect("first save must succeed");
        let first_id = first.node_id();

        // A different identity, saved to the same path, must be refused.
        let second = NodeIdentity::generate();
        let err = second
            .save(&key_path)
            .expect_err("saving over an existing identity must be refused");
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "the refusal must say what it refused and why, got: {err}"
        );

        // And the original must still be on disk, byte for byte.
        let reloaded = NodeIdentity::load(&key_path).expect("the original must survive");
        assert_eq!(
            reloaded.node_id(),
            first_id,
            "the identity on disk must be unchanged after a refused overwrite"
        );
    }

    #[test]
    fn test_save_load() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let identity = NodeIdentity::generate();
        let original_node_id = identity.node_id();
        let original_pow = identity.pow_proof().cloned();

        identity.save(&key_path).unwrap();
        let loaded = NodeIdentity::load(&key_path).unwrap();

        assert_eq!(loaded.node_id(), original_node_id);
        // PoW should also be preserved
        if let Some(orig) = original_pow {
            let loaded_pow = loaded.pow_proof().unwrap();
            assert_eq!(loaded_pow.nonce, orig.nonce);
            assert_eq!(loaded_pow.difficulty, orig.difficulty);
        }
    }

    #[test]
    fn test_from_hex() {
        let identity = NodeIdentity::generate_without_pow();
        // Get the signing key bytes from the LocalSigner
        let local_signer = identity
            .signer()
            .as_any()
            .downcast_ref::<LocalSigner>()
            .unwrap();
        let hex = hex::encode(local_signer.signing_key_bytes());

        let loaded = NodeIdentity::from_hex(&hex).unwrap();
        assert_eq!(loaded.node_id(), identity.node_id());
        // from_hex mines a new PoW
        assert!(loaded.has_valid_pow());
    }

    #[test]
    fn test_verify_remote_signature() {
        let identity = NodeIdentity::generate();
        let message = b"Consensus vote";
        let signature = identity.sign(message);

        let result = verify_signature(&identity.node_id(), message, &signature).unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_node_id_pow() {
        let identity = NodeIdentity::generate();
        let proof = identity.pow_proof().unwrap();

        assert!(verify_node_id_pow(
            &identity.node_id(),
            proof,
            NODE_ID_POW_DIFFICULTY
        ));
    }

    #[test]
    fn test_verify_node_id_pow_hex() {
        let identity = NodeIdentity::generate();
        let node_id_hex = identity.node_id_hex();
        let proof_hex = identity.pow_proof_hex().unwrap();

        assert!(verify_node_id_pow_hex(
            &node_id_hex,
            &proof_hex,
            NODE_ID_POW_DIFFICULTY
        ));
    }

    #[test]
    fn test_hash_message() {
        let message = b"Test message";
        let hash = hash_message(message);
        assert_eq!(hash.len(), 32);

        // Same message should produce same hash
        let hash2 = hash_message(message);
        assert_eq!(hash, hash2);

        // Different message should produce different hash
        let hash3 = hash_message(b"Different message");
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_node_id_short() {
        let identity = NodeIdentity::generate();
        let short = identity.node_id_short();
        assert_eq!(short.len(), 8);
        assert!(identity.node_id_hex().starts_with(&short));
    }

    #[test]
    fn test_verifying_key_returns_result() {
        let identity = NodeIdentity::generate();
        // A properly constructed identity should always have a valid verifying key
        let result = identity.verifying_key();
        assert!(result.is_ok());

        // The verifying key should match the node_id (public key)
        let vk = result.unwrap();
        assert_eq!(vk.as_bytes(), &identity.node_id());
    }

    #[test]
    fn test_verify_signature_rejects_invalid_node_id() {
        // Test that verify_signature properly handles invalid public key bytes
        // Use a 32-byte value that is definitely NOT a valid Ed25519 point
        // The last byte > 0x7f triggers the "non-canonical" check in Ed25519
        // and certain patterns don't represent valid curve points
        let mut invalid_node_id: [u8; 32] = [0x01; 32];
        invalid_node_id[31] = 0x80; // High bit set on y-coordinate = invalid

        let message = b"test message";
        let fake_signature = [0u8; 64];

        let result = verify_signature(&invalid_node_id, message, &fake_signature);
        // Should either return an error OR return Ok(false) for signature verification failure
        // The important thing is it shouldn't panic
        match result {
            Err(e) => {
                // Expected path - invalid public key
                assert!(e.to_string().contains("Invalid public key"));
            }
            Ok(verified) => {
                // Alternate valid path - signature verification failed
                assert!(!verified, "Invalid key should not verify any signature");
            }
        }
    }
}
