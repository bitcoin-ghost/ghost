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
//| FILE: task.rs                                                                                                        |
//|======================================================================================================================|

//! Periodic verification task
//!
//! Verifies peer capabilities every 5 minutes by:
//! 1. Selecting 3 random peers (excluding self)
//! 2. Querying their /health endpoint to discover claimed capabilities
//! 3. Issuing targeted challenges for each claimed capability
//! 4. Storing results in the local database
//! 5. Broadcasting results via P2P

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::NodeId;
use ghost_storage::Database;

use crate::client::VerificationClient;

/// Verification task configuration
#[derive(Debug, Clone)]
pub struct VerificationTaskConfig {
    /// Interval between verification cycles (default: 5 minutes)
    pub interval: Duration,
    /// Number of peers to verify per cycle (default: 3)
    pub peers_per_cycle: usize,
    /// HTTP timeout for verification requests
    pub request_timeout: Duration,
    /// LOW-VER-1: Stratum connection timeout (default: 5 seconds)
    /// Separate from HTTP timeout since stratum uses raw TCP
    pub stratum_timeout: Duration,
}

impl Default for VerificationTaskConfig {
    fn default() -> Self {
        use ghost_common::constants::{
            NODES_TO_VERIFY_PER_ROUND, VERIFICATION_INTERVAL_SECS, VERIFICATION_TIMEOUT_SECS,
        };
        Self {
            interval: Duration::from_secs(VERIFICATION_INTERVAL_SECS),
            peers_per_cycle: NODES_TO_VERIFY_PER_ROUND,
            request_timeout: Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
            // LOW-VER-1: Default stratum timeout of 5 seconds
            stratum_timeout: Duration::from_secs(5),
        }
    }
}

/// Information about a peer for verification
#[derive(Debug, Clone)]
pub struct VerifiablePeer {
    /// Node ID (32 bytes)
    pub node_id: NodeId,
    /// HTTP address for verification (e.g., "192.168.1.1:8080")
    pub http_address: String,
    /// CRIT-VER-1: Uptime percentage (0.0-1.0) for reputation weighting
    pub uptime: Option<f64>,
    /// CRIT-VER-1: IP address for diversity checks
    pub ip_address: Option<String>,
}

/// Trait for providing peers to verify
///
/// Implement this trait to provide the verification task with
/// a list of known peers that can be verified.
pub trait PeerProvider: Send + Sync {
    /// Get random peers for verification
    ///
    /// Should exclude the specified node_id (self) and return
    /// at most `count` peers that are currently connected.
    fn get_random_peers(&self, exclude: &NodeId, count: usize) -> Vec<VerifiablePeer>;
}

/// Result of a verification challenge that can be broadcast
///
/// CRIT-VER-2: This structure must be cryptographically signed when broadcast
/// over P2P to prevent forgery and ensure authenticity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationBroadcast {
    /// Target node ID
    pub target_node_id: NodeId,
    /// Challenger node ID
    pub challenger_id: NodeId,
    /// Capability type ("archive", "policy", "stratum", "ghostpay")
    pub capability: String,
    /// Whether the challenge passed
    pub passed: bool,
    /// Challenge data (JSON)
    pub challenge_data: String,
    /// Response data (JSON, optional)
    pub response_data: Option<String>,
    /// Timestamp
    pub timestamp: i64,
}

/// CRIT-VER-2: Signed verification broadcast for P2P transmission
///
/// This wraps VerificationBroadcast with a cryptographic signature to prevent:
/// - Forgery: Attackers cannot create fake verification results
/// - Impersonation: Only the actual challenger can sign the result
/// - Tampering: Any modification invalidates the signature
///
/// M-6 FIX: Now includes challenge_data_hash to bind the signature to the specific
/// challenge issued, preventing replay of signatures for different challenges.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedVerificationBroadcast {
    /// The verification result
    pub broadcast: VerificationBroadcast,
    /// Ed25519 signature over the broadcast data
    /// M-6 FIX: Signature = Sign(SHA256(target_id || challenger_id || capability || passed || timestamp || challenge_data_hash))
    /// The challenge_data_hash binds this signature to the specific challenge (block hash, tx hex, etc.)
    pub signature: String,
    /// M-6 FIX: SHA256 hash of challenge_data, included in signature to bind to specific challenge
    pub challenge_data_hash: String,
}

impl SignedVerificationBroadcast {
    /// CRIT-VER-2 + M-6 FIX: Create a signed broadcast with challenge binding
    ///
    /// # Arguments
    /// * `broadcast` - The verification result to sign
    /// * `sign_fn` - Function that signs the message hash and returns 64-byte signature
    ///
    /// # Security (M-6)
    /// The signature now includes a hash of the challenge_data, binding this broadcast
    /// to the specific challenge issued (block hash, tx hex, epoch, etc.). This prevents:
    /// - Replay attacks with signatures from different challenges
    /// - Signature reuse across unrelated verification attempts
    pub fn new<F>(broadcast: VerificationBroadcast, sign_fn: F) -> Self
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        use sha2::{Digest, Sha256};

        // M-6 FIX: Compute hash of challenge data to bind signature to specific challenge
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(broadcast.challenge_data.as_bytes());
        let challenge_data_hash_bytes = challenge_hasher.finalize();
        let challenge_data_hash = hex::encode(challenge_data_hash_bytes);

        // Compute message hash for signing - M-6 FIX: now includes challenge_data_hash
        let mut hasher = Sha256::new();
        hasher.update(broadcast.target_node_id);
        hasher.update(broadcast.challenger_id);
        hasher.update(broadcast.capability.as_bytes());
        hasher.update([if broadcast.passed { 1u8 } else { 0u8 }]);
        hasher.update(broadcast.timestamp.to_le_bytes());
        // M-6 FIX: Include challenge data hash in signature
        hasher.update(challenge_data_hash_bytes);
        let message_hash = hasher.finalize();

        // Sign the message hash
        let signature_bytes = sign_fn(message_hash.as_slice());
        let signature = hex::encode(signature_bytes);

        Self {
            broadcast,
            signature,
            challenge_data_hash,
        }
    }

    /// CRIT-VER-2 + MED-VER-7 + M-6 FIX: Verify the signature, timestamp, and challenge binding
    ///
    /// # Arguments
    /// * `verify_fn` - Function that verifies (pubkey, message, signature) -> bool
    ///
    /// # Returns
    /// * `Ok(())` if signature, timestamp, and challenge binding are valid
    /// * `Err(reason)` if verification fails
    ///
    /// # Security (M-6)
    /// Verifies that the signature includes the challenge_data_hash, ensuring the
    /// broadcast is bound to a specific challenge and cannot be replayed.
    pub fn verify<F>(&self, verify_fn: F) -> Result<(), String>
    where
        F: FnOnce(&[u8], &[u8], &[u8]) -> bool,
    {
        use sha2::{Digest, Sha256};

        // MED-VER-7: Validate timestamp bounds
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // MED-VER-7: Reject timestamps too far in the future (2 minutes)
        if self.broadcast.timestamp > now + 120 {
            return Err(format!(
                "MED-VER-7: Verification timestamp {} is too far in the future (current: {})",
                self.broadcast.timestamp, now
            ));
        }

        // MED-VER-7: Reject timestamps too old (10 minutes)
        // Verification results should be fresh to prevent replay of old results
        if self.broadcast.timestamp + 600 < now {
            return Err(format!(
                "MED-VER-7: Verification timestamp {} is too old (max age: 600s, current: {})",
                self.broadcast.timestamp, now
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

        // M-6 FIX: Validate and decode challenge_data_hash
        if self.challenge_data_hash.len() != 64 {
            return Err(format!(
                "M-6: Invalid challenge_data_hash length: {} (expected 64)",
                self.challenge_data_hash.len()
            ));
        }
        let challenge_hash_bytes = hex::decode(&self.challenge_data_hash)
            .map_err(|e| format!("M-6: Invalid challenge_data_hash hex: {}", e))?;

        // M-6 FIX: Verify that challenge_data_hash matches the actual challenge_data
        let mut challenge_hasher = Sha256::new();
        challenge_hasher.update(self.broadcast.challenge_data.as_bytes());
        let expected_challenge_hash = challenge_hasher.finalize();
        if challenge_hash_bytes != expected_challenge_hash.as_slice() {
            return Err(
                "M-6: Challenge data hash mismatch - signature not bound to this challenge"
                    .to_string(),
            );
        }

        // Recompute message hash - M-6 FIX: now includes challenge_data_hash
        let mut hasher = Sha256::new();
        hasher.update(self.broadcast.target_node_id);
        hasher.update(self.broadcast.challenger_id);
        hasher.update(self.broadcast.capability.as_bytes());
        hasher.update([if self.broadcast.passed { 1u8 } else { 0u8 }]);
        hasher.update(self.broadcast.timestamp.to_le_bytes());
        // M-6 FIX: Include challenge data hash in verification
        hasher.update(&challenge_hash_bytes);
        let message_hash = hasher.finalize();

        // Verify signature using challenger's public key (node ID)
        if verify_fn(
            &self.broadcast.challenger_id,
            message_hash.as_slice(),
            &signature_bytes,
        ) {
            Ok(())
        } else {
            Err("CRIT-VER-2: Signature verification failed".to_string())
        }
    }
}

/// Transform a host:port address to use GhostPay port (8800)
///
/// GhostPay runs on port 8800, separate from ghost-pool on port 8080.
/// This function transforms "host:8080" to "host:8800" for GhostPay verification.
fn transform_to_ghostpay_port(address: &str) -> String {
    // Handle IPv6 addresses: [::1]:8080 -> [::1]:8800
    if address.starts_with('[') {
        if let Some(bracket_pos) = address.rfind(']') {
            if address[bracket_pos..].contains(':') {
                let host = &address[..bracket_pos + 1];
                return format!("{}:8800", host);
            }
        }
        // No port found, append 8800
        return format!("{}:8800", address);
    }

    // Handle IPv4 addresses: 192.168.1.1:8080 -> 192.168.1.1:8800
    if let Some(colon_pos) = address.rfind(':') {
        let host = &address[..colon_pos];
        return format!("{}:8800", host);
    }

    // No port found, append 8800
    format!("{}:8800", address)
}

/// Channel for broadcasting verification results
pub type VerificationBroadcastSender = mpsc::Sender<VerificationBroadcast>;
pub type VerificationBroadcastReceiver = mpsc::Receiver<VerificationBroadcast>;

/// Create a broadcast channel for verification results
pub fn verification_broadcast_channel(
    buffer: usize,
) -> (VerificationBroadcastSender, VerificationBroadcastReceiver) {
    mpsc::channel(buffer)
}

/// Build a randomized T0 test transaction for policy verification (H-3)
///
/// # Security (H-3: Randomized Policy Challenge Transactions)
///
/// This function generates a cryptographically random test transaction each time
/// to prevent nodes from pre-computing policy classification responses. The
/// randomization includes:
/// - Random txid derived from cryptographic RNG
/// - Random output amounts within valid ranges
/// - Random script types (P2WPKH, P2TR, multisig)
/// - Random number of outputs (1-3)
///
/// # M-12 FIX: No Timestamp Fallback
///
/// Previously this function fell back to timestamp-based randomness if getrandom
/// failed. This is a security vulnerability as timestamps are predictable and
/// could allow nodes to pre-compute challenge responses. Now returns None
/// to fail closed instead.
fn build_test_transaction() -> Option<String> {
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::script::Builder;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::{Transaction, Version};
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};

    // H-3 + M-12 FIX: Use cryptographic randomness - FAIL if unavailable
    // M-12: Do NOT fall back to timestamp - that's predictable and insecure
    let mut rng_bytes = [0u8; 64];
    if getrandom::getrandom(&mut rng_bytes).is_err() {
        warn!(
            "M-12: Failed to get cryptographic randomness, skipping policy challenge (fail closed)"
        );
        return None;
    }

    // H-3: Generate random txid from cryptographic randomness
    let txid = Txid::from_raw_hash(sha256d::Hash::hash(&rng_bytes[..32]));

    // H-3: Randomize output amount (10,000 - 100,000 sats)
    let rand_amount = u64::from_le_bytes(rng_bytes[8..16].try_into().unwrap_or([0u8; 8]));
    let amount = 10_000 + (rand_amount % 90_000);

    // Generate ONLY T0-class scripts (standard financial transactions).
    // The challenge expects exactly T0 classification, so we must not include
    // OP_RETURN (T2), timelocked scripts (T2), or legacy P2PK (T1/T2).
    // Valid T0 types: P2WPKH, P2TR, P2WSH, P2SH
    let script_type = rng_bytes[16] % 4;
    let output_script = match script_type {
        0 => {
            // P2WPKH: OP_0 <20-byte-hash>
            let mut pubkey_hash = [0u8; 20];
            pubkey_hash.copy_from_slice(&rng_bytes[17..37]);
            Builder::new()
                .push_int(0)
                .push_slice(pubkey_hash)
                .into_script()
        }
        1 => {
            // P2TR (Taproot): OP_1 <32-byte-x-only-pubkey>
            let mut x_only_pubkey = [0u8; 32];
            x_only_pubkey.copy_from_slice(&rng_bytes[17..49]);
            Builder::new()
                .push_int(1)
                .push_slice(x_only_pubkey)
                .into_script()
        }
        2 => {
            // P2WSH: OP_0 <32-byte-script-hash>
            let mut script_hash = [0u8; 32];
            script_hash.copy_from_slice(&rng_bytes[17..49]);
            Builder::new()
                .push_int(0)
                .push_slice(script_hash)
                .into_script()
        }
        _ => {
            // P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL
            let mut script_hash = [0u8; 20];
            script_hash.copy_from_slice(&rng_bytes[17..37]);
            Builder::new()
                .push_opcode(bitcoin::opcodes::all::OP_HASH160)
                .push_slice(script_hash)
                .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
                .into_script()
        }
    };

    // H-3: Randomly vary the number of outputs (1-3)
    let output_count = 1 + (rng_bytes[49] % 3) as usize;
    let mut outputs = Vec::with_capacity(output_count);

    // First output uses the selected script type
    outputs.push(TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: output_script,
    });

    // Additional outputs use P2WPKH for simplicity
    for i in 1..output_count {
        let mut pubkey_hash = [0u8; 20];
        let offset = 50 + (i - 1) * 20;
        if offset + 20 <= rng_bytes.len() {
            pubkey_hash.copy_from_slice(&rng_bytes[offset..offset + 20]);
        }
        let additional_amount = 5_000 + (u64::from(rng_bytes[50]) * 100);
        outputs.push(TxOut {
            value: Amount::from_sat(additional_amount),
            script_pubkey: Builder::new()
                .push_int(0)
                .push_slice(pubkey_hash)
                .into_script(),
        });
    }

    // H-3: Randomize vout index
    let vout = (rng_bytes[51] % 4) as u32;

    // HIGH-VER-3: Add RBF (Replace-By-Fee) signaling with 50% probability
    // RBF is signaled by sequence < 0xFFFFFFFE
    let use_rbf = (rng_bytes[52] % 2) == 0;
    let sequence = if use_rbf {
        Sequence::from_consensus(0xFFFFFFFD) // RBF-enabled
    } else {
        Sequence::MAX // No RBF
    };

    // HIGH-VER-3: Randomize locktime (CLTV with 30% probability)
    let use_locktime = (rng_bytes[53] % 10) < 3;
    let lock_time = if use_locktime {
        let locktime_val =
            u32::from_le_bytes([rng_bytes[54], rng_bytes[55], rng_bytes[56], rng_bytes[57]])
                % 700_000;
        LockTime::from_consensus(locktime_val)
    } else {
        LockTime::ZERO
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    debug!(
        script_type = script_type,
        output_count = output_count,
        amount = amount,
        rbf = use_rbf,
        has_locktime = use_locktime,
        "H-3/HIGH-VER-3: Built randomized policy challenge transaction with expanded variety"
    );

    Some(serialize_hex(&tx))
}

/// GHOST-01: Build a randomized DIRTY (data-carrier) transaction for the policy
/// NEGATIVE CONTROL.
///
/// The positive challenge ([`build_test_transaction`]) only checks a node can
/// recognise a clean T0 tx — which a node that filters NOTHING (classifies
/// everything as T0) trivially passes, so the +2 "Reaper / BitcoinPure"
/// capability proved nothing about actual filtering. This builds a transaction
/// carrying a 100-byte OP_RETURN payload (well above the 83-byte data-carrier
/// limit), which any honest BitcoinPure/Reaper node must classify as non-T0 and
/// REFUSE to accept (`accepted = false`). A node that misclassifies it as T0,
/// or accepts it (e.g. a `full_open` profile), fails the negative control and
/// does not qualify for the capability.
///
/// Returns `None` (fail closed) if cryptographic randomness is unavailable.
fn build_dirty_test_transaction() -> Option<String> {
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::locktime::absolute::LockTime;
    use bitcoin::script::{Builder, PushBytesBuf, ScriptBuf};
    use bitcoin::transaction::{Transaction, Version};
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Txid, Witness};

    let mut rng_bytes = [0u8; 128];
    if getrandom::getrandom(&mut rng_bytes).is_err() {
        warn!("M-12: Failed to get randomness, skipping policy negative control (fail closed)");
        return None;
    }
    let txid = Txid::from_raw_hash(sha256d::Hash::hash(&rng_bytes[..32]));

    // 100 random bytes of OP_RETURN data — unambiguously a data carrier.
    let payload = PushBytesBuf::try_from(rng_bytes[28..128].to_vec()).ok()?;
    let op_return = Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(&payload)
        .into_script();

    // A normal P2WPKH output keeps the tx otherwise well-formed.
    let mut pkh = [0u8; 20];
    pkh.copy_from_slice(&rng_bytes[8..28]);
    let p2wpkh = Builder::new().push_int(0).push_slice(pkh).into_script();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint { txid, vout: 0 },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: p2wpkh,
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return,
            },
        ],
    };
    Some(serialize_hex(&tx))
}

/// LOW-VER-3: Per-target challenge tracker for rate limiting
/// Tracks recent challenges to ensure even distribution across targets
struct ChallengeTracker {
    /// Map of NodeId -> last challenge timestamp
    last_challenged: std::collections::HashMap<NodeId, i64>,
    /// Minimum interval between challenges to same target (seconds)
    min_interval_secs: i64,
}

impl ChallengeTracker {
    fn new() -> Self {
        Self {
            last_challenged: std::collections::HashMap::new(),
            // LOW-VER-3: Don't challenge same node more than once per 5 minutes
            // Matches the verification cycle interval so every cycle runs
            min_interval_secs: 300,
        }
    }

    /// Check if a target can be challenged (respects rate limit)
    fn can_challenge(&self, node_id: &NodeId) -> bool {
        let now = chrono::Utc::now().timestamp();
        match self.last_challenged.get(node_id) {
            Some(&last_time) => now - last_time >= self.min_interval_secs,
            None => true,
        }
    }

    /// Record that a target was challenged
    fn record_challenge(&mut self, node_id: NodeId) {
        self.last_challenged
            .insert(node_id, chrono::Utc::now().timestamp());
    }

    /// Clean up old entries to prevent unbounded growth
    fn cleanup(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now - self.min_interval_secs * 2;
        self.last_challenged.retain(|_, &mut ts| ts > cutoff);
    }
}

/// Periodic verification task
///
/// Runs in the background and periodically verifies peer capabilities.
///
/// # Security (H-1)
/// The task requires cryptographic identity verification to ensure that:
/// - `our_node_id` is derived from the node's actual cryptographic identity
/// - DB writes are only accepted from properly authenticated challengers
/// - The identity binding is verified at task creation time
pub struct VerificationTask {
    /// HTTP client for issuing challenges
    client: VerificationClient,
    /// Database for storing results
    db: Arc<Database>,
    /// Our node ID (to exclude from verification)
    our_node_id: NodeId,
    /// H-1 FIX: Flag indicating identity has been cryptographically verified
    /// When true, our_node_id has been verified to match a NodeIdentity's public key
    identity_verified: bool,
    /// Peer provider
    peer_provider: Arc<dyn PeerProvider>,
    /// Configuration
    config: VerificationTaskConfig,
    /// Broadcast channel for results
    broadcast_tx: Option<VerificationBroadcastSender>,
    /// Bitcoin RPC for fetching real block data
    rpc: Option<Arc<BitcoinRpc>>,
    /// LOW-VER-3: Track challenges per target for even distribution
    challenge_tracker: std::sync::Mutex<ChallengeTracker>,
}

/// C-3: Error type for verification task creation
#[derive(Debug, thiserror::Error)]
pub enum VerificationTaskError {
    #[error("Failed to create verification client: {0}")]
    ClientInit(String),
    /// H-1: Identity verification failed
    #[error("H-1: Identity verification failed: {0}")]
    IdentityMismatch(String),
}

impl VerificationTask {
    /// Create a new verification task
    ///
    /// C-3: Returns Result instead of panicking on client creation failure.
    ///
    /// # H-1 Security Note
    /// This constructor creates a task WITHOUT identity verification. The task will
    /// refuse to write to the database until `with_verified_identity` is called.
    /// For production use, prefer `new_with_identity` which verifies the binding.
    pub fn new(
        db: Arc<Database>,
        our_node_id: NodeId,
        peer_provider: Arc<dyn PeerProvider>,
    ) -> Result<Self, VerificationTaskError> {
        let client = VerificationClient::new()
            .map_err(|e| VerificationTaskError::ClientInit(e.to_string()))?;
        Ok(Self {
            client,
            db,
            our_node_id,
            identity_verified: false, // H-1: Not verified yet
            peer_provider,
            config: VerificationTaskConfig::default(),
            broadcast_tx: None,
            rpc: None,
            challenge_tracker: std::sync::Mutex::new(ChallengeTracker::new()),
        })
    }

    /// Create a new verification task configured for HTTP (non-TLS) connections
    /// with cryptographic identity binding.
    ///
    /// This should ONLY be used on signet/testnet where TLS is not configured.
    /// For mainnet, use `new_with_identity()` which requires HTTPS.
    ///
    /// # Security Warning
    /// Using HTTP instead of HTTPS allows man-in-the-middle attacks.
    /// Only use this for testing networks.
    pub fn new_for_signet(
        db: Arc<Database>,
        identity: &ghost_common::identity::NodeIdentity,
        peer_provider: Arc<dyn PeerProvider>,
    ) -> Result<Self, VerificationTaskError> {
        use crate::client::VerificationClientConfig;
        use ghost_common::constants::VERIFICATION_TIMEOUT_SECS;

        // Use HTTP for signet/testnet where TLS is not configured
        let config = VerificationClientConfig {
            use_https: false,
            timeout: std::time::Duration::from_secs(VERIFICATION_TIMEOUT_SECS),
            danger_accept_invalid_certs: false,
            is_mainnet: false,
        };

        let client = VerificationClient::with_config(config)
            .map_err(|e| VerificationTaskError::ClientInit(e.to_string()))?;

        // H-1: Derive node_id from identity for cryptographic binding
        let our_node_id = identity.node_id();

        Ok(Self {
            client,
            db,
            our_node_id,
            identity_verified: true, // H-1: Cryptographically verified via identity
            peer_provider,
            config: VerificationTaskConfig::default(),
            broadcast_tx: None,
            rpc: None,
            challenge_tracker: std::sync::Mutex::new(ChallengeTracker::new()),
        })
    }

    /// H-1 FIX: Create a verification task with cryptographic identity binding
    ///
    /// This constructor verifies that `our_node_id` matches the public key derived
    /// from the provided `NodeIdentity`. This cryptographic binding prevents:
    /// - Attackers from spoofing challenger IDs in DB writes
    /// - Nodes from claiming verification results they didn't perform
    ///
    /// # Arguments
    /// * `db` - Database for storing challenge results
    /// * `identity` - Node's cryptographic identity (must derive to our_node_id)
    /// * `peer_provider` - Provider for peers to verify
    ///
    /// # Errors
    /// Returns `IdentityMismatch` if the identity's public key doesn't match our_node_id
    pub fn new_with_identity(
        db: Arc<Database>,
        identity: &ghost_common::identity::NodeIdentity,
        peer_provider: Arc<dyn PeerProvider>,
    ) -> Result<Self, VerificationTaskError> {
        let client = VerificationClient::new()
            .map_err(|e| VerificationTaskError::ClientInit(e.to_string()))?;

        // H-1: Derive node_id from identity and verify binding
        let our_node_id = identity.node_id();

        Ok(Self {
            client,
            db,
            our_node_id,
            identity_verified: true, // H-1: Cryptographically verified
            peer_provider,
            config: VerificationTaskConfig::default(),
            broadcast_tx: None,
            rpc: None,
            challenge_tracker: std::sync::Mutex::new(ChallengeTracker::new()),
        })
    }

    /// Mainnet-correct constructor: HTTPS with identity-pinned TLS verification.
    ///
    /// This is the path you want when peers serve identity-derived certs (cert
    /// pubkey == node_id). The supplied `pubkey_allow_list` is consulted
    /// during the TLS handshake — return true iff the cert pubkey is a
    /// currently-registered peer.
    pub fn new_with_identity_pinned(
        db: Arc<Database>,
        identity: &ghost_common::identity::NodeIdentity,
        peer_provider: Arc<dyn PeerProvider>,
        pubkey_allow_list: ghost_common::tls::PubkeyAllowList,
    ) -> Result<Self, VerificationTaskError> {
        use crate::client::VerificationClientConfig;

        let config = VerificationClientConfig {
            use_https: true,
            timeout: std::time::Duration::from_secs(
                ghost_common::constants::VERIFICATION_TIMEOUT_SECS,
            ),
            danger_accept_invalid_certs: false,
            is_mainnet: true,
        };

        let client = VerificationClient::with_pinning(config, pubkey_allow_list)
            .map_err(|e| VerificationTaskError::ClientInit(e.to_string()))?;

        let our_node_id = identity.node_id();

        Ok(Self {
            client,
            db,
            our_node_id,
            identity_verified: true,
            peer_provider,
            config: VerificationTaskConfig::default(),
            broadcast_tx: None,
            rpc: None,
            challenge_tracker: std::sync::Mutex::new(ChallengeTracker::new()),
        })
    }

    /// Create with custom configuration
    ///
    /// C-3: Returns Result instead of panicking on client creation failure.
    pub fn with_config(
        db: Arc<Database>,
        our_node_id: NodeId,
        peer_provider: Arc<dyn PeerProvider>,
        config: VerificationTaskConfig,
    ) -> Result<Self, VerificationTaskError> {
        let client = VerificationClient::new()
            .map_err(|e| VerificationTaskError::ClientInit(e.to_string()))?;
        Ok(Self {
            client,
            db,
            our_node_id,
            identity_verified: false, // H-1: Not verified yet
            peer_provider,
            config,
            broadcast_tx: None,
            rpc: None,
            challenge_tracker: std::sync::Mutex::new(ChallengeTracker::new()),
        })
    }

    /// H-1 FIX: Verify identity binding and enable DB writes
    ///
    /// Call this method to cryptographically verify that `our_node_id` matches
    /// the provided identity. After successful verification, DB writes are allowed.
    ///
    /// # Errors
    /// Returns error if the identity's node_id doesn't match our_node_id
    pub fn with_verified_identity(
        mut self,
        identity: &ghost_common::identity::NodeIdentity,
    ) -> Result<Self, VerificationTaskError> {
        let derived_node_id = identity.node_id();
        if derived_node_id != self.our_node_id {
            return Err(VerificationTaskError::IdentityMismatch(format!(
                "NodeId mismatch: expected {}, got {} from identity",
                hex::encode(&self.our_node_id[..8]),
                hex::encode(&derived_node_id[..8])
            )));
        }
        self.identity_verified = true;
        info!(
            node_id = %hex::encode(&self.our_node_id[..8]),
            "H-1: Identity verification successful - DB writes enabled"
        );
        Ok(self)
    }

    /// Set the broadcast channel for verification results
    pub fn with_broadcast(mut self, tx: VerificationBroadcastSender) -> Self {
        self.broadcast_tx = Some(tx);
        self
    }

    /// Set the Bitcoin RPC client for fetching real block data
    pub fn with_rpc(mut self, rpc: Arc<BitcoinRpc>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// H-1 FIX: Check if identity has been verified before allowing DB writes
    ///
    /// Returns Ok(()) if identity is verified, Err if not.
    /// This prevents challenger ID spoofing in DB entries.
    fn require_identity_verified(&self) -> Result<(), String> {
        if !self.identity_verified {
            return Err("H-1: Cannot write to DB without verified identity. \
                 Call with_verified_identity() or use new_with_identity() constructor."
                .to_string());
        }
        Ok(())
    }

    /// Run the verification task loop
    ///
    /// This runs forever, periodically verifying peers.
    pub async fn run(&self) {
        info!(
            interval_secs = self.config.interval.as_secs(),
            peers_per_cycle = self.config.peers_per_cycle,
            "Starting verification task"
        );

        loop {
            // Perform verification cycle
            self.verify_cycle().await;

            // Wait for next cycle
            tokio::time::sleep(self.config.interval).await;
        }
    }

    /// Perform a single verification cycle
    pub async fn verify_cycle(&self) {
        // LOW-VER-3: Periodically cleanup old tracker entries to prevent memory growth
        {
            if let Ok(mut tracker) = self.challenge_tracker.lock() {
                tracker.cleanup();
            }
        }

        // CRIT-VER-1: Request 3x peers to allow filtering for Sybil resistance
        let peers = self
            .peer_provider
            .get_random_peers(&self.our_node_id, self.config.peers_per_cycle * 3);

        if peers.is_empty() {
            info!("Verification cycle: no connected peers");
            return;
        }

        // CRIT-VER-1: Apply Sybil-resistant selection
        let selected = self.select_sybil_resistant_peers(peers, self.config.peers_per_cycle);

        if selected.is_empty() {
            debug!("No peers passed Sybil resistance filters");
            return;
        }

        // LOW-VER-3: Filter out recently challenged peers for even distribution
        // H-13 FIX: On lock failure, return empty vector (fail closed) instead of using unfiltered list
        // Using unfiltered list could allow challenge flooding attacks if an attacker can cause lock poisoning
        let filtered: Vec<_> = match self.challenge_tracker.lock() {
            Ok(tracker) => selected
                .into_iter()
                .filter(|peer| {
                    let can_challenge = tracker.can_challenge(&peer.node_id);
                    if !can_challenge {
                        debug!(
                            node_id = %hex::encode(&peer.node_id[..8]),
                            "LOW-VER-3: Skipping recently challenged peer"
                        );
                    }
                    can_challenge
                })
                .collect(),
            Err(e) => {
                // H-13 FIX: Fail closed - return empty set instead of using unfiltered list
                // A poisoned lock indicates a panic occurred, which is a serious error.
                // Using the unfiltered list could allow challenge flooding attacks.
                tracing::error!(
                    error = %e,
                    "H-13: Challenge tracker lock poisoned - failing closed (no peers selected)"
                );
                Vec::new() // Fail closed - skip this verification cycle entirely
            }
        };
        let selected = filtered;

        if selected.is_empty() {
            info!("Verification cycle: all peers recently challenged, skipping");
            return;
        }

        info!(
            peer_count = selected.len(),
            requested = self.config.peers_per_cycle,
            "Starting verification cycle with Sybil-resistant selection"
        );

        // Verify each peer and record the challenge
        for peer in selected {
            self.verify_peer(&peer).await;

            // LOW-VER-3: Record that this peer was challenged
            if let Ok(mut tracker) = self.challenge_tracker.lock() {
                tracker.record_challenge(peer.node_id);
            }
        }
    }

    /// CRIT-VER-1: Select peers with Sybil resistance
    ///
    /// Implements multi-layer Sybil attack prevention:
    /// 1. IP diversity: Ensure geographic/network distribution
    /// 2. Reputation weighting: Prefer peers with high uptime
    /// 3. Cryptographic randomness: Unpredictable selection
    ///
    /// # Arguments
    /// * `candidates` - Pool of potential peers to verify
    /// * `target_count` - Desired number of peers to select
    ///
    /// # Returns
    /// Selected peers that maximize network diversity and security
    fn select_sybil_resistant_peers(
        &self,
        mut candidates: Vec<VerifiablePeer>,
        target_count: usize,
    ) -> Vec<VerifiablePeer> {
        use std::collections::HashSet;

        if candidates.is_empty() {
            return Vec::new();
        }

        // LOW-VER-5 FIX: Deduplicate by NodeId before selection
        // Nodes with multiple IPs could appear multiple times in the candidate list.
        // This ensures each node is only verified once per cycle.
        let mut seen_node_ids: HashSet<NodeId> = HashSet::new();
        candidates.retain(|peer| {
            if seen_node_ids.contains(&peer.node_id) {
                debug!(
                    node_id = %hex::encode(&peer.node_id[..8]),
                    "LOW-VER-5: Removing duplicate NodeId from candidates"
                );
                false
            } else {
                seen_node_ids.insert(peer.node_id);
                true
            }
        });

        // CRIT-VER-1: Extract IP addresses and build diversity map
        let mut ip_subnets: HashSet<String> = HashSet::new();
        let mut selected = Vec::new();

        // CRIT-VER-1 FIX: Shuffle candidates using cryptographic randomness
        // On RNG failure, return EMPTY set instead of falling back to a subset.
        // A fallback reduces diversity and enables Sybil attacks.
        // It's better to skip verification than verify a predictable/manipulated set.
        if Self::cryptographic_shuffle(&mut candidates).is_err() {
            warn!("CRIT-VER-1: Failed to get cryptographic randomness for peer selection, skipping verification cycle (fail closed)");
            return Vec::new();
        }

        // CRIT-VER-1: Select peers with IP diversity (prefer different /24 subnets)
        // First pass: collect diverse peers
        let mut remaining_candidates = Vec::new();
        for peer in candidates {
            if selected.len() >= target_count {
                remaining_candidates.push(peer);
                continue;
            }

            // Extract subnet (/24 for IPv4, /48 for IPv6)
            let subnet = if let Some(ref ip) = peer.ip_address {
                Self::extract_subnet(ip)
            } else {
                // No IP info, extract from http_address
                Self::extract_subnet_from_address(&peer.http_address)
            };

            // CRIT-VER-1: Prefer peers from different subnets
            // Allow 1 peer max per subnet to maximize diversity and prevent Sybil attacks
            // (Changed from 2 to 1 per subnet for stronger Sybil resistance)
            let subnet_count = ip_subnets.iter().filter(|s| s == &&subnet).count();
            if subnet_count >= 1 {
                remaining_candidates.push(peer);
                continue;
            }

            ip_subnets.insert(subnet.clone());
            selected.push(peer);
        }

        // CRIT-VER-1: If we couldn't get enough diverse peers, fill remaining slots
        // with any available peers (better to verify some peers than none)
        if selected.len() < target_count && !remaining_candidates.is_empty() {
            let selected_ids: HashSet<NodeId> = selected.iter().map(|p| p.node_id).collect();

            for peer in remaining_candidates {
                if selected.len() >= target_count {
                    break;
                }
                if !selected_ids.contains(&peer.node_id) {
                    selected.push(peer);
                }
            }
        }

        info!(
            selected = selected.len(),
            unique_subnets = ip_subnets.len(),
            target = target_count,
            "CRIT-VER-1: Sybil-resistant peer selection complete"
        );

        selected
    }

    /// CRIT-VER-1: Shuffle a vector using cryptographic randomness
    ///
    /// Uses getrandom() to ensure unpredictable ordering that cannot be
    /// manipulated by Sybil attackers.
    ///
    /// CRIT-VER-1 FIX: Returns Err(()) on RNG failure - caller must NOT use
    /// fallback that reduces diversity, as this enables Sybil attacks.
    fn cryptographic_shuffle(peers: &mut [VerifiablePeer]) -> Result<(), ()> {
        use rand::seq::SliceRandom;
        use rand::SeedableRng;

        // Get cryptographically random seed
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| ())?;

        // Use ChaCha8 RNG seeded with cryptographic randomness
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        peers.shuffle(&mut rng);

        Ok(())
    }

    /// CRIT-VER-1: Extract subnet identifier from IP address
    ///
    /// For IPv4: Returns first 3 octets (/24 subnet, e.g., "192.168.1" from "192.168.1.100")
    /// For IPv6: Returns first 4 segments (/64 subnet, e.g., "2001:db8:abcd:1234" from "2001:db8:abcd:1234::1")
    ///
    /// CRIT-VER-1 FIX: Changed IPv6 from /48 (3 segments) to /64 (4 segments).
    /// /48 subnets are too broad - many unrelated organizations can share a /48.
    /// /64 is the standard allocation for individual network segments.
    fn extract_subnet(ip: &str) -> String {
        // Parse IPv4
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            let octets = addr.octets();
            return format!("{}.{}.{}", octets[0], octets[1], octets[2]);
        }

        // Parse IPv6 - CRIT-VER-1 FIX: Use /64 (4 segments) not /48 (3 segments)
        if let Ok(addr) = ip.parse::<std::net::Ipv6Addr>() {
            let segments = addr.segments();
            return format!(
                "{:x}:{:x}:{:x}:{:x}",
                segments[0], segments[1], segments[2], segments[3]
            );
        }

        // Fallback: return as-is
        ip.to_string()
    }

    /// CRIT-VER-1: Extract subnet from http_address (host:port format)
    fn extract_subnet_from_address(address: &str) -> String {
        // Extract host part (before the port)
        let host = address.split(':').next().unwrap_or(address);
        Self::extract_subnet(host)
    }

    /// Verify a single peer's capabilities
    async fn verify_peer(&self, peer: &VerifiablePeer) {
        let peer_id_hex = hex::encode(peer.node_id);
        let short_id = &peer_id_hex[..8];
        let our_id_hex = hex::encode(self.our_node_id);

        debug!(peer = %short_id, address = %peer.http_address, "Verifying peer");

        // First, query their health endpoint to discover claimed capabilities
        let health = match self.client.health(&peer.http_address).await {
            Ok(h) => h,
            Err(e) => {
                warn!(peer = %short_id, error = %e, "Failed to get peer health");
                return;
            }
        };

        let capabilities = health.capabilities;
        let timestamp = chrono::Utc::now().timestamp();

        // Verify each claimed capability
        // CRIT-VER-3: Log DB errors but continue with other capabilities
        if capabilities.archive_mode {
            if let Err(e) = self
                .verify_archive(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await
            {
                warn!(peer = %short_id, error = %e, "Archive verification DB error");
            }
        }

        if capabilities.reaper {
            if let Err(e) = self
                .verify_policy(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await
            {
                warn!(peer = %short_id, error = %e, "Policy verification DB error");
            }
        }

        if capabilities.public_mining {
            if let Err(e) = self
                .verify_stratum(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await
            {
                warn!(peer = %short_id, error = %e, "Stratum verification DB error");
            }
        }

        if capabilities.ghost_pay {
            if let Err(e) = self
                .verify_ghostpay(peer, &peer_id_hex, &our_id_hex, timestamp)
                .await
            {
                warn!(peer = %short_id, error = %e, "GhostPay verification DB error");
            }
        }
    }

    /// Verify archive capability
    ///
    /// C-2 FIX: Now includes merkle root validation to verify block data authenticity.
    /// Previously only checked resp.success without validating the actual block data.
    ///
    /// CRIT-VER-3: Returns Result - DB write failures are propagated to caller
    async fn verify_archive(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) -> Result<(), String> {
        // L-11: Get a real block hash from the blockchain via RPC
        // Fail closed: if RPC is unavailable, skip the challenge rather than using
        // a predictable genesis block that could be pre-computed
        let (block_hash, block_height, expected_merkle_root) =
            match self.get_random_block_with_merkle().await {
                Some(data) => data,
                None => {
                    // L-11: Fail closed - do not use predictable fallback
                    warn!(
                        peer = %peer_id_hex[..8],
                        "RPC unavailable, skipping archive verification (fail closed)"
                    );
                    // Record as inconclusive - don't pass or fail, just skip
                    return Ok(());
                }
            };

        let challenge_data = serde_json::json!({
            "block_hash": block_hash,
            "block_height": block_height,
        })
        .to_string();

        let result = self
            .client
            .verify_archive(&peer.http_address, Some(&block_hash), None)
            .await;

        // C-2 FIX: Validate block data authenticity, not just success flag
        let (passed, response_data) = match result {
            Ok(resp) => {
                // C-2 FIX: Perform merkle root validation
                let validation_result = self.validate_archive_response(
                    &resp,
                    &block_hash,
                    block_height,
                    expected_merkle_root.as_deref(),
                );

                let response_json = serde_json::json!({
                    "success": resp.success,
                    "hash": resp.block_data.as_ref().map(|b| &b.hash),
                    "height": resp.block_data.as_ref().map(|b| b.height),
                    "merkle_root": resp.block_data.as_ref().map(|b| &b.merkle_root),
                    "validation": validation_result.1,
                });

                (validation_result.0, Some(response_json.to_string()))
            }
            Err(e) => {
                debug!(error = %e, "Archive verification failed");
                (false, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        info!(
            peer = %peer_id_hex[..8],
            block_height = block_height,
            passed = passed,
            "Archive verification complete"
        );

        // H-1 FIX: Verify identity before DB write to prevent challenger ID spoofing
        self.require_identity_verified()?;

        // CRIT-VER-3: Store result with proper error handling - return error if DB fails
        if let Err(e) = self.db.insert_archive_challenge(
            peer_id_hex,
            our_id_hex,
            block_height,
            &block_hash,
            None,
            passed,
        ) {
            warn!(
                peer = %peer_id_hex[..8],
                error = %e,
                "CRIT-VER-3: Failed to store archive challenge result - not broadcasting"
            );
            return Err(format!("CRIT-VER-3: DB write failed: {}", e));
        }

        // Broadcast result (only if DB write succeeded)
        self.broadcast_result(
            peer.node_id,
            "archive",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;

        Ok(())
    }

    /// C-2 FIX: Get a random block with merkle root for validation
    ///
    /// Returns (block_hash, height, Option<merkle_root>) to enable cross-checking
    /// the peer's response against our own RPC data.
    ///
    /// H-6: Uses cryptographic randomness via getrandom to ensure unpredictable
    /// block selection, preventing attackers from pre-computing challenge responses.
    ///
    /// HIGH-VER-2: Uniform distribution across ALL block heights, not just recent
    async fn get_random_block_with_merkle(&self) -> Option<(String, u64, Option<String>)> {
        let rpc = self.rpc.as_ref()?;

        // Get current chain height
        let height = match rpc.get_block_count().await {
            Ok(h) => h,
            Err(e) => {
                debug!(error = %e, "Failed to get block count");
                return None;
            }
        };

        if height < 100 {
            return None;
        }

        // HIGH-VER-2 FIX: True uniform distribution across ALL heights (0 to current)
        // Removed the 20% early block bias that existed previously.
        // Archive nodes must maintain full history and should be tested uniformly.
        let mut rand_bytes = [0u8; 8];
        if getrandom::getrandom(&mut rand_bytes).is_err() {
            warn!("Failed to get cryptographic randomness for block selection");
            return None;
        }
        let rand_val = u64::from_le_bytes(rand_bytes);

        // HIGH-VER-2 FIX: Select uniformly from blocks 0 through current height
        // No bias toward any particular range - every block has equal probability
        let challenge_height = rand_val % (height + 1);

        // Get block hash at that height
        let block_hash = match rpc.get_block_hash(challenge_height).await {
            Ok(hash) => hash,
            Err(e) => {
                debug!(error = %e, height = challenge_height, "Failed to get block hash");
                return None;
            }
        };

        // C-2 FIX: Also fetch the block header to get merkle root for validation
        let merkle_root = match rpc.get_block_header(&block_hash).await {
            Ok(header) => Some(header.merkleroot),
            Err(e) => {
                // MED-VER-4 FIX: Fail closed - if we can't verify merkle, skip the challenge
                // Previously we continued without merkle validation, which allows nodes
                // to pass with unverified block data
                warn!(
                    error = %e,
                    height = challenge_height,
                    "MED-VER-4: Can't get block header for merkle validation, skipping challenge (fail closed)"
                );
                return None;
            }
        };

        Some((block_hash, challenge_height, merkle_root))
    }

    /// C-2 FIX: Validate archive response against expected values
    ///
    /// Returns (passed, validation_details)
    fn validate_archive_response(
        &self,
        resp: &crate::challenge::ArchiveResponse,
        expected_hash: &str,
        expected_height: u64,
        expected_merkle_root: Option<&str>,
    ) -> (bool, String) {
        // Basic check: response must indicate success
        if !resp.success {
            return (false, "Response indicates failure".to_string());
        }

        // C-2 FIX: Block data must be present
        let block_data = match &resp.block_data {
            Some(data) => data,
            None => {
                return (false, "C-2: No block data in response".to_string());
            }
        };

        // C-2 FIX: Block hash must match what we requested
        if block_data.hash.to_lowercase() != expected_hash.to_lowercase() {
            return (
                false,
                format!(
                    "C-2: Block hash mismatch: got {}, expected {}",
                    block_data.hash, expected_hash
                ),
            );
        }

        // C-2 FIX: Height must match
        if block_data.height != expected_height {
            return (
                false,
                format!(
                    "C-2: Block height mismatch: got {}, expected {}",
                    block_data.height, expected_height
                ),
            );
        }

        // C-2 FIX: Validate merkle root format (64 hex chars)
        if block_data.merkle_root.len() != 64
            || !block_data
                .merkle_root
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                format!(
                    "C-2: Invalid merkle root format: {}",
                    block_data.merkle_root
                ),
            );
        }

        // C-2 FIX: If we have expected merkle root from our RPC, cross-check it
        if let Some(expected_mr) = expected_merkle_root {
            if block_data.merkle_root.to_lowercase() != expected_mr.to_lowercase() {
                return (
                    false,
                    format!(
                        "C-2: Merkle root mismatch: got {}, expected {}",
                        block_data.merkle_root, expected_mr
                    ),
                );
            }
        }

        // C-2 FIX: Validate tx_count is reasonable (at least 1 for coinbase)
        if block_data.tx_count == 0 {
            return (false, "C-2: Block has zero transactions".to_string());
        }

        // C-2 FIX + LOW-VER-4 FIX: Validate timestamp for historical blocks
        // Archive verification is for HISTORICAL blocks, so timestamps must be in the past.
        // The 2-hour future tolerance was for new blocks being mined, but archive challenges
        // request blocks that already exist in the chain - they cannot have future timestamps.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // LOW-VER-4 FIX: Historical blocks must have timestamp <= now
        // Only allow minimal clock skew (60 seconds) to account for verification timing
        if block_data.timestamp > now + 60 {
            return (
                false,
                format!(
                    "LOW-VER-4: Historical block timestamp {} is in the future (now: {})",
                    block_data.timestamp, now
                ),
            );
        }

        (true, "Validation passed".to_string())
    }

    /// Verify policy capability
    ///
    /// CRIT-VER-3: Returns Result - DB write failures are propagated to caller
    async fn verify_policy(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) -> Result<(), String> {
        // GHOST-01: randomly send a clean T0 tx OR a dirty data-carrier tx
        // (negative control). A node qualifies for Reaper/BitcoinPure only if it
        // both classifies clean txs as exactly T0 AND classifies the dirty tx as
        // non-T0 and refuses it — i.e. proves it actually filters spam, not just
        // that it can recognise a clean tx (which a no-op classifier passes).
        let dirty = {
            let mut b = [0u8; 1];
            getrandom::getrandom(&mut b).ok();
            b[0] & 1 == 1
        };
        let built = if dirty {
            build_dirty_test_transaction()
        } else {
            build_test_transaction()
        };
        let test_tx_hex = match built {
            Some(tx) => tx,
            None => {
                warn!(
                    peer = %peer_id_hex[..8],
                    "M-12: Skipping policy verification - cryptographic randomness unavailable"
                );
                return Ok(());
            }
        };
        let expected_tier = if dirty { "non-T0" } else { "T0" };
        debug!(
            dirty,
            tx_hex_len = test_tx_hex.len(),
            expected_tier,
            "Built policy challenge transaction"
        );

        let challenge_data = serde_json::json!({
            "tx_type": if dirty { "dirty" } else { "T0" },
            "expected_tier": expected_tier,
        })
        .to_string();

        let result = self
            .client
            .verify_policy(&peer.http_address, &test_tx_hex)
            .await;

        let (passed, tier, response_data) = match result {
            Ok(resp) => {
                let tier = resp.classification.as_ref().map(|c| c.tier.clone());
                let passed = if dirty {
                    // GHOST-01 negative control: a real filtering node classifies
                    // the data-carrier tx as non-T0 AND does not accept it.
                    let non_t0 = tier.as_ref().map(|t| t != "T0").unwrap_or(false);
                    resp.success && non_t0 && !resp.accepted
                } else {
                    // MED-VER-2: clean tx must classify EXACTLY T0 (not T0 OR T1).
                    let tier_ok = tier.as_ref().map(|t| t == "T0").unwrap_or(false);
                    resp.success && tier_ok
                };

                (
                    passed,
                    tier,
                    Some(
                        serde_json::json!({
                            "success": resp.success,
                            "tier": resp.classification.as_ref().map(|c| &c.tier),
                            "profile": resp.profile,
                            "accepted": resp.accepted,
                        })
                        .to_string(),
                    ),
                )
            }
            Err(e) => {
                warn!(error = %e, peer = %peer_id_hex[..8], "Policy verification failed");
                (false, None, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        // Convert tier string to numeric value for database
        let tier_num = tier.as_ref().and_then(|t| match t.as_str() {
            "T0" => Some(0),
            "T1" => Some(1),
            "T2" => Some(2),
            "T3" => Some(3),
            _ => None,
        });

        info!(
            peer = %peer_id_hex[..8],
            tier = ?tier,
            passed = passed,
            "Policy verification complete"
        );

        // H-1 FIX: Verify identity before DB write to prevent challenger ID spoofing
        self.require_identity_verified()?;

        // CRIT-VER-3: Store result with proper error handling - return error if DB fails
        if let Err(e) = self.db.insert_policy_challenge(
            peer_id_hex,
            our_id_hex,
            "T0_test",
            0, // expected_tier
            tier_num,
            passed,
        ) {
            warn!(
                peer = %peer_id_hex[..8],
                error = %e,
                "CRIT-VER-3: Failed to store policy challenge result - not broadcasting"
            );
            return Err(format!("CRIT-VER-3: DB write failed: {}", e));
        }

        // Broadcast result (only if DB write succeeded)
        self.broadcast_result(
            peer.node_id,
            "policy",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;

        Ok(())
    }

    /// Verify stratum capability
    ///
    /// CRIT-VER-3: Returns Result - DB write failures are propagated to caller
    async fn verify_stratum(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) -> Result<(), String> {
        use crate::challenge::StratumProtocol;

        let challenge_data = serde_json::json!({
            "protocol": "sv2",
        })
        .to_string();

        let result = self
            .client
            .verify_stratum(&peer.http_address, StratumProtocol::Sv2)
            .await;

        let short_id = &peer_id_hex[..8];
        let (passed, connected, latency_ms, response_data) = match result {
            Ok(resp) => (
                resp.success && resp.connected,
                resp.connected,
                resp.latency_ms,
                Some(
                    serde_json::json!({
                        "success": resp.success,
                        "connected": resp.connected,
                        "latency_ms": resp.latency_ms,
                    })
                    .to_string(),
                ),
            ),
            Err(e) => {
                warn!(peer = %short_id, error = %e, "Stratum verification failed");
                (false, false, None, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        info!(peer = %short_id, passed = passed, connected = connected, "Stratum verification complete");

        // H-1 FIX: Verify identity before DB write to prevent challenger ID spoofing
        self.require_identity_verified()?;

        // CRIT-VER-3: Store result with proper error handling - return error if DB fails
        if let Err(e) =
            self.db
                .insert_stratum_challenge(peer_id_hex, our_id_hex, connected, latency_ms, passed)
        {
            warn!(
                peer = %peer_id_hex[..8],
                error = %e,
                "CRIT-VER-3: Failed to store stratum challenge result - not broadcasting"
            );
            return Err(format!("CRIT-VER-3: DB write failed: {}", e));
        }

        // Broadcast result (only if DB write succeeded)
        self.broadcast_result(
            peer.node_id,
            "stratum",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;

        Ok(())
    }

    /// Verify ghostpay capability
    ///
    /// H-1 FIX: Always requires epoch state proof verification. Previously only checked
    /// l2_enabled: true when no challenge_epoch was provided, allowing nodes to claim
    /// GhostPay capability without actually maintaining L2 state.
    ///
    /// VER-2 FIX: Now includes a random challenge nonce that must be incorporated into
    /// the response's nonce_bound_proof field. This prevents precomputation attacks where
    /// an attacker pre-builds a lookup table of epoch_state_hash values.
    ///
    /// VER-3 FIX: Now requires verifiable proof (nonce binding) that can be checked locally.
    ///
    /// CRIT-VER-3: Returns Result - DB write failures are propagated to caller
    async fn verify_ghostpay(
        &self,
        peer: &VerifiablePeer,
        peer_id_hex: &str,
        our_id_hex: &str,
        timestamp: i64,
    ) -> Result<(), String> {
        let short_id = &peer_id_hex[..8];

        // Probe peer's current epoch to select a random challenge within their range.
        // This prevents nodes from pre-caching only genesis state and passing verification.
        let peer_epoch = match self.client.probe_ghostpay_epoch(&peer.http_address).await {
            Ok(epoch) => epoch,
            Err(e) => {
                warn!(
                    peer = %short_id,
                    error = %e,
                    "GhostPay epoch probe failed - falling back to epoch 0"
                );
                0
            }
        };

        let challenge_epoch = Self::generate_challenge_epoch_for_peer(peer_epoch);

        // VER-2 FIX: Generate a random challenge nonce to prevent precomputation attacks
        // This nonce must be incorporated into the response as nonce_bound_proof
        let challenge_nonce = match self.generate_challenge_nonce() {
            Some(nonce) => nonce,
            None => {
                warn!(
                    peer = %short_id,
                    "VER-2: Skipping GhostPay verification - failed to generate challenge nonce"
                );
                return Ok(());
            }
        };

        let challenge_data = serde_json::json!({
            "endpoint": "ghostpay",
            "challenge_epoch": challenge_epoch,
            "challenge_nonce": challenge_nonce,
        })
        .to_string();

        // GhostPay runs on port 8800, not 8080 (ghost-pool)
        // Transform the http_address from host:8080 to host:8800
        let ghostpay_address = transform_to_ghostpay_port(&peer.http_address);

        // H-1/VER-2 FIX: Pass both challenge_epoch and challenge_nonce
        let result = self
            .client
            .verify_ghostpay_with_nonce(
                &ghostpay_address,
                Some(challenge_epoch),
                Some(&challenge_nonce),
            )
            .await;

        let (passed, response_valid, response_data) = match result {
            Ok(resp) => {
                // H-1/VER-2/VER-3 FIX: Validate the response includes proper epoch state proof
                // and nonce-bound proof to prevent precomputation attacks
                let validation =
                    self.validate_ghostpay_response(&resp, challenge_epoch, &challenge_nonce);

                let response_json = serde_json::json!({
                    "success": resp.success,
                    "valid": resp.l2_enabled,
                    "virtual_block": resp.virtual_block,
                    "epoch": resp.epoch,
                    "epoch_state_hash": resp.epoch_state_hash,
                    "epoch_tx_count": resp.epoch_tx_count,
                    "nonce_bound_proof": resp.nonce_bound_proof,
                    "validation": validation.1,
                });

                (
                    validation.0,
                    resp.l2_enabled,
                    Some(response_json.to_string()),
                )
            }
            Err(e) => {
                warn!(peer = %short_id, error = %e, "GhostPay verification failed");
                (false, false, Some(format!("{{\"error\":\"{}\"}}", e)))
            }
        };

        info!(
            peer = %short_id,
            passed = passed,
            l2_enabled = response_valid,
            challenge_epoch = challenge_epoch,
            "GhostPay verification complete"
        );

        // H-1 FIX: Verify identity before DB write to prevent challenger ID spoofing
        self.require_identity_verified()?;

        // CRIT-VER-3: Store result with proper error handling - return error if DB fails
        if let Err(e) = self.db.insert_ghostpay_challenge(
            peer_id_hex,
            our_id_hex,
            "ghostpay",
            response_valid,
            passed,
        ) {
            warn!(
                peer = %short_id,
                error = %e,
                "CRIT-VER-3: Failed to store GhostPay challenge result - not broadcasting"
            );
            return Err(format!("CRIT-VER-3: DB write failed: {}", e));
        }

        // Broadcast result (only if DB write succeeded)
        self.broadcast_result(
            peer.node_id,
            "ghostpay",
            passed,
            challenge_data,
            response_data,
            timestamp,
        )
        .await;

        Ok(())
    }

    /// Generate a random challenge epoch within a peer's known epoch range.
    ///
    /// If peer_epoch == 0 (genesis only), returns 0.
    /// Otherwise, returns a cryptographically random epoch in [0, peer_epoch].
    /// Combined with the 256-bit challenge nonce, this ensures nodes must maintain
    /// full L2 state history to pass verification, not just genesis.
    fn generate_challenge_epoch_for_peer(peer_epoch: u64) -> u64 {
        if peer_epoch == 0 {
            return 0;
        }

        let mut bytes = [0u8; 8];
        if getrandom::getrandom(&mut bytes).is_err() {
            // Fallback to epoch 0 if RNG fails (should not happen)
            return 0;
        }
        let random_val = u64::from_le_bytes(bytes);
        random_val % (peer_epoch + 1)
    }

    /// VER-2 FIX: Generate a random challenge nonce for GhostPay verification
    ///
    /// Returns a random 32-byte hex string that must be incorporated into the response's
    /// nonce_bound_proof field as SHA256(epoch_state_hash || challenge_nonce).
    /// This prevents precomputation attacks where an attacker pre-builds a lookup table
    /// of epoch_state_hash values for all possible epochs.
    ///
    /// Security properties:
    /// - 256 bits of entropy from cryptographic RNG
    /// - Cannot be predicted by the responder before the challenge
    /// - Binds the response to this specific challenge instance
    fn generate_challenge_nonce(&self) -> Option<String> {
        let mut nonce_bytes = [0u8; 32];
        if getrandom::getrandom(&mut nonce_bytes).is_err() {
            warn!("VER-2: Failed to get cryptographic randomness for challenge nonce");
            return None;
        }
        Some(hex::encode(nonce_bytes))
    }

    /// H-1/VER-2/VER-3 FIX: Validate GhostPay response includes proper epoch state proof
    /// and nonce-bound proof to prevent precomputation attacks
    ///
    /// Returns (passed, validation_details)
    fn validate_ghostpay_response(
        &self,
        resp: &crate::challenge::GhostPayResponse,
        challenge_epoch: u64,
        challenge_nonce: &str,
    ) -> (bool, String) {
        // Basic checks
        if !resp.success {
            return (false, "Response indicates failure".to_string());
        }

        if !resp.l2_enabled {
            return (false, "L2 not enabled".to_string());
        }

        // H-1 FIX: Validate response field ranges (M-13 protection)
        if !resp.is_valid() {
            return (false, "H-1: Response fields out of valid range".to_string());
        }

        // H-1 FIX: Must have epoch_state_hash to prove L2 state exists
        let state_hash = match &resp.epoch_state_hash {
            Some(hash) => hash,
            None => {
                return (
                    false,
                    format!(
                        "H-1: Missing epoch_state_hash for challenge epoch {}",
                        challenge_epoch
                    ),
                );
            }
        };

        // H-1 FIX: Validate epoch_state_hash format (64 hex chars for SHA256)
        if state_hash.len() != 64 || !state_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return (
                false,
                format!("H-1: Invalid epoch_state_hash format: {}", state_hash),
            );
        }

        // H-1 FIX: epoch_state_hash must not be all zeros (indicates no state)
        if state_hash.chars().all(|c| c == '0') {
            return (
                false,
                "H-1: epoch_state_hash is all zeros (no state)".to_string(),
            );
        }

        // H-1 FIX: Must have epoch_tx_count to verify state is populated
        let tx_count = match resp.epoch_tx_count {
            Some(count) => count,
            None => {
                return (
                    false,
                    "H-1: Missing epoch_tx_count for challenged epoch".to_string(),
                );
            }
        };

        // H-1 FIX: tx_count must be reasonable (not suspiciously low for established epochs)
        // For challenge epochs > 10, we expect at least some transactions
        if challenge_epoch > 10 && tx_count == 0 {
            return (
                false,
                format!(
                    "H-1: Suspicious zero tx_count for epoch {} (expected some activity)",
                    challenge_epoch
                ),
            );
        }

        // H-1 FIX: Response epoch should be at least as recent as challenge
        // (node should have state up to at least the challenged epoch)
        if let Some(current_epoch) = resp.epoch {
            if current_epoch < challenge_epoch {
                return (
                    false,
                    format!(
                        "H-1: Node epoch {} is behind challenge epoch {}",
                        current_epoch, challenge_epoch
                    ),
                );
            }
        }

        // VER-2/VER-3 FIX: Verify nonce_bound_proof to prevent precomputation attacks
        // The nonce_bound_proof must be SHA256(epoch_state_hash || challenge_nonce)
        // This ensures the node actually computed the proof for THIS specific challenge,
        // not pre-computed it for a known epoch.
        let nonce_bound_proof = match &resp.nonce_bound_proof {
            Some(proof) => proof,
            None => {
                return (
                    false,
                    format!(
                        "VER-2/VER-3: Missing nonce_bound_proof for challenge nonce '{}'",
                        &challenge_nonce[..8.min(challenge_nonce.len())]
                    ),
                );
            }
        };

        // VER-3: Validate nonce_bound_proof format (64 hex chars for SHA256)
        if nonce_bound_proof.len() != 64
            || !nonce_bound_proof.chars().all(|c| c.is_ascii_hexdigit())
        {
            return (
                false,
                format!(
                    "VER-3: Invalid nonce_bound_proof format: {}",
                    nonce_bound_proof
                ),
            );
        }

        // VER-2/VER-3 FIX: Compute expected nonce_bound_proof and verify it matches
        // Expected = SHA256(epoch_state_hash || challenge_nonce)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(state_hash.as_bytes());
        hasher.update(challenge_nonce.as_bytes());
        let expected_proof = hex::encode(hasher.finalize());

        if nonce_bound_proof.to_lowercase() != expected_proof.to_lowercase() {
            return (
                false,
                format!(
                    "VER-2/VER-3: nonce_bound_proof mismatch - node may have precomputed epoch_state_hash. \
                     Expected: {}, Got: {}",
                    &expected_proof[..16],
                    &nonce_bound_proof[..16]
                ),
            );
        }

        (
            true,
            "Epoch state proof and nonce binding validated".to_string(),
        )
    }

    /// Broadcast a verification result via P2P
    ///
    /// MED-VER-7/VER-4: Validates timestamp before broadcasting to prevent stale/future results
    async fn broadcast_result(
        &self,
        target_node_id: NodeId,
        capability: &str,
        passed: bool,
        challenge_data: String,
        response_data: Option<String>,
        timestamp: i64,
    ) {
        // MED-VER-7/VER-4 FIX: Clock sanity check before broadcasting
        // VER-4: Standardized on 30 seconds max future tolerance (matches verification_handler.rs)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        // VER-4 FIX: Reject if timestamp is more than 30 seconds in the future
        // Standardized across both broadcast and handler to prevent inconsistent behavior.
        // Previously broadcast allowed 2 minutes but handler only allowed 30 seconds.
        const MAX_FUTURE_TOLERANCE_SECS: i64 = 30;
        if timestamp > now + MAX_FUTURE_TOLERANCE_SECS {
            warn!(
                timestamp = timestamp,
                now = now,
                capability = capability,
                "VER-4: Not broadcasting - timestamp too far in future (clock drift?)"
            );
            return;
        }

        // Reject if timestamp is more than 10 minutes old (stale result)
        if timestamp + 600 < now {
            warn!(
                timestamp = timestamp,
                now = now,
                capability = capability,
                "MED-VER-7: Not broadcasting - timestamp too old (stale result)"
            );
            return;
        }

        if let Some(ref tx) = self.broadcast_tx {
            let broadcast = VerificationBroadcast {
                target_node_id,
                challenger_id: self.our_node_id,
                capability: capability.to_string(),
                passed,
                challenge_data,
                response_data,
                timestamp,
            };

            if let Err(e) = tx.send(broadcast).await {
                warn!(error = %e, "Failed to broadcast verification result");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signing_fn(message: &[u8]) -> [u8; 64] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(b"test_secret_key");
        let hash = hasher.finalize();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&hash);
        sig[32..].copy_from_slice(&hash);
        sig
    }

    fn test_verify_fn(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(b"test_secret_key");
        let expected = hasher.finalize();
        signature.len() == 64 && signature[..32] == expected[..] && !pubkey.is_empty()
    }

    #[test]
    fn test_signed_verification_broadcast_challenge_binding() {
        // MEDIUM-5 verification: Test that signature is bound to challenge data
        let broadcast = VerificationBroadcast {
            target_node_id: [1u8; 32],
            challenger_id: [2u8; 32],
            capability: "archive".to_string(),
            passed: true,
            challenge_data: r#"{"block_hash":"00000000deadbeef","block_height":12345}"#.to_string(),
            response_data: Some(r#"{"success":true}"#.to_string()),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        let signed = SignedVerificationBroadcast::new(broadcast.clone(), test_signing_fn);

        // Verify challenge_data_hash is populated and correct
        assert_eq!(
            signed.challenge_data_hash.len(),
            64,
            "challenge_data_hash should be 64 hex chars"
        );

        // Verify the hash matches the challenge data
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(broadcast.challenge_data.as_bytes());
        let expected_hash = hex::encode(hasher.finalize());
        assert_eq!(
            signed.challenge_data_hash, expected_hash,
            "challenge_data_hash should match SHA256 of challenge_data"
        );

        // Verify signature is valid
        assert!(
            signed.verify(test_verify_fn).is_ok(),
            "Valid signature should verify"
        );
    }

    #[test]
    fn test_signed_verification_broadcast_challenge_tampering_detected() {
        // MEDIUM-5 verification: Test that modifying challenge_data invalidates signature
        let broadcast = VerificationBroadcast {
            target_node_id: [1u8; 32],
            challenger_id: [2u8; 32],
            capability: "archive".to_string(),
            passed: true,
            challenge_data: r#"{"block_hash":"00000000deadbeef","block_height":12345}"#.to_string(),
            response_data: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        let mut signed = SignedVerificationBroadcast::new(broadcast, test_signing_fn);

        // Tamper with challenge_data after signing
        signed.broadcast.challenge_data =
            r#"{"block_hash":"00000000cafebabe","block_height":99999}"#.to_string();

        // Verification should fail because challenge_data_hash no longer matches
        let result = signed.verify(test_verify_fn);
        assert!(
            result.is_err(),
            "Tampered challenge_data should fail verification"
        );
        assert!(
            result.unwrap_err().contains("Challenge data hash mismatch"),
            "Error should mention challenge data hash mismatch"
        );
    }

    #[test]
    fn test_signed_verification_broadcast_different_challenges() {
        // MEDIUM-5 verification: Test that different challenge data produces different hashes
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let broadcast1 = VerificationBroadcast {
            target_node_id: [1u8; 32],
            challenger_id: [2u8; 32],
            capability: "archive".to_string(),
            passed: true,
            challenge_data: r#"{"block_hash":"hash1","block_height":100}"#.to_string(),
            response_data: None,
            timestamp,
        };

        let broadcast2 = VerificationBroadcast {
            target_node_id: [1u8; 32],
            challenger_id: [2u8; 32],
            capability: "archive".to_string(),
            passed: true,
            challenge_data: r#"{"block_hash":"hash2","block_height":200}"#.to_string(),
            response_data: None,
            timestamp,
        };

        let signed1 = SignedVerificationBroadcast::new(broadcast1, test_signing_fn);
        let signed2 = SignedVerificationBroadcast::new(broadcast2, test_signing_fn);

        // Different challenge data should produce different hashes
        assert_ne!(
            signed1.challenge_data_hash, signed2.challenge_data_hash,
            "Different challenges should have different hashes"
        );

        // Different challenge data should produce different signatures
        assert_ne!(
            signed1.signature, signed2.signature,
            "Different challenges should have different signatures"
        );
    }

    #[test]
    fn test_signed_verification_broadcast_timestamp_validation() {
        // MED-VER-7 verification: Test timestamp bounds checking
        let broadcast = VerificationBroadcast {
            target_node_id: [1u8; 32],
            challenger_id: [2u8; 32],
            capability: "archive".to_string(),
            passed: true,
            challenge_data: r#"{"block":"test"}"#.to_string(),
            response_data: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 300, // 5 minutes in the future
        };

        let signed = SignedVerificationBroadcast::new(broadcast, test_signing_fn);
        let result = signed.verify(test_verify_fn);
        assert!(result.is_err(), "Timestamp too far in future should fail");
        assert!(
            result.unwrap_err().contains("too far in the future"),
            "Error should mention future timestamp"
        );
    }

    #[test]
    fn test_generate_challenge_epoch_for_peer_zero() {
        // Peer at epoch 0 (genesis only) must always return 0
        for _ in 0..100 {
            assert_eq!(VerificationTask::generate_challenge_epoch_for_peer(0), 0);
        }
    }

    #[test]
    fn test_generate_challenge_epoch_for_peer_range() {
        // Peer at epoch 100: all results must be in [0, 100]
        let peer_epoch = 100u64;
        let mut seen_nonzero = false;
        for _ in 0..1000 {
            let epoch = VerificationTask::generate_challenge_epoch_for_peer(peer_epoch);
            assert!(
                epoch <= peer_epoch,
                "epoch {} exceeds peer_epoch {}",
                epoch,
                peer_epoch
            );
            if epoch > 0 {
                seen_nonzero = true;
            }
        }
        assert!(
            seen_nonzero,
            "Should have seen non-zero epochs in 1000 trials with peer_epoch=100"
        );
    }

    #[test]
    fn test_generate_challenge_epoch_for_peer_one() {
        // Peer at epoch 1: results must be 0 or 1
        let mut seen_zero = false;
        let mut seen_one = false;
        for _ in 0..100 {
            let epoch = VerificationTask::generate_challenge_epoch_for_peer(1);
            assert!(epoch <= 1);
            if epoch == 0 {
                seen_zero = true;
            }
            if epoch == 1 {
                seen_one = true;
            }
        }
        assert!(
            seen_zero && seen_one,
            "Should see both 0 and 1 for peer_epoch=1"
        );
    }

    #[test]
    fn test_signed_verification_broadcast_stale_timestamp() {
        // MED-VER-7 verification: Test stale timestamp rejection
        let broadcast = VerificationBroadcast {
            target_node_id: [1u8; 32],
            challenger_id: [2u8; 32],
            capability: "archive".to_string(),
            passed: true,
            challenge_data: r#"{"block":"test"}"#.to_string(),
            response_data: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                - 700, // 11+ minutes in the past
        };

        let signed = SignedVerificationBroadcast::new(broadcast, test_signing_fn);
        let result = signed.verify(test_verify_fn);
        assert!(result.is_err(), "Stale timestamp should fail");
        assert!(
            result.unwrap_err().contains("too old"),
            "Error should mention old timestamp"
        );
    }

    /// GHOST-01: the negative-control dirty tx must be classified non-T0 AND
    /// rejected by a real BitcoinPure policy engine, and the clean tx accepted
    /// as T0 — against the SAME `ghost_policy` engine the verifier target uses.
    /// This is what makes the +2 Reaper/BitcoinPure capability prove actual
    /// filtering instead of merely recognising a clean tx.
    #[test]
    fn test_policy_negative_control_against_real_classifier() {
        use ghost_policy::{PolicyDecision, PolicyEngine};

        let decode = |hex_str: &str| -> bitcoin::Transaction {
            let bytes = hex::decode(hex_str).expect("valid hex");
            bitcoin::consensus::deserialize(&bytes).expect("valid tx")
        };

        // Dirty (data-carrier) tx → must be REJECTED and classified non-T0.
        let dirty_hex = build_dirty_test_transaction().expect("rng available");
        let dirty_tx = decode(&dirty_hex);
        let mut engine = PolicyEngine::bitcoin_pure();
        match engine.evaluate(&dirty_tx) {
            PolicyDecision::Reject { classification, .. } => {
                assert_ne!(
                    classification.tier.to_string(),
                    "T0",
                    "data-carrier tx must not be tier T0"
                );
            }
            PolicyDecision::Accept { classification, .. } => panic!(
                "BitcoinPure accepted a 100-byte OP_RETURN data carrier (tier {}) — negative control broken",
                classification.tier
            ),
        }

        // Clean tx → must be ACCEPTED and classified exactly T0.
        let clean_hex = build_test_transaction().expect("rng available");
        let clean_tx = decode(&clean_hex);
        let mut engine = PolicyEngine::bitcoin_pure();
        match engine.evaluate(&clean_tx) {
            PolicyDecision::Accept { classification, .. } => {
                assert_eq!(
                    classification.tier.to_string(),
                    "T0",
                    "clean financial tx must classify as T0"
                );
            }
            PolicyDecision::Reject { reason, .. } => {
                panic!("BitcoinPure rejected a clean T0 tx: {reason}")
            }
        }
    }
}
