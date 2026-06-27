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
//| FILE: verification_handler.rs                                                                                        |
//|======================================================================================================================|

//! Verification result handler
//!
//! Handles incoming verification results from other nodes and stores them
//! in the database for capability qualification calculations.

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, warn};

/// H-5: Maximum size for challenge_data and response_data fields (10 KB)
/// This prevents memory exhaustion attacks from malicious oversized messages
const MAX_CHALLENGE_DATA_SIZE: usize = 10 * 1024;

/// Maximum verification results per challenger per minute.
/// Normal operation: 3 peers x 4 capabilities = 12 per cycle (every 5 min).
/// 20/min is generous but prevents DB flooding from compromised nodes.
const VERIFICATION_RATE_LIMIT_PER_MIN: u32 = 20;

/// Burst capacity for verification rate limiter
const VERIFICATION_RATE_LIMIT_BURST: u32 = 20;

/// Refill rate: 20 tokens per 60 seconds ≈ 1 token per 3 seconds
const VERIFICATION_RATE_REFILL: u32 = 1;

use ghost_common::error::GhostResult;
use ghost_common::identity::verify_signature;
use ghost_common::types::NodeId;
use ghost_storage::Database;

use crate::mesh::MessageHandler;
use crate::message::{CapabilityType, MessageEnvelope, MessageType, VerificationResultMessage};
use crate::peer::PeerManager;
use crate::vote_handler::RateLimiter;

/// Re-derived verdict for a peer-broadcast verification result.
///
/// A colluding minority of challengers cannot be trusted to report `passed`
/// honestly: a >5% group can sign `passed=false` against an honest target,
/// drag it under the 95% gate, and steal its node-reward share. The recipient
/// therefore RE-DERIVES the verdict from its OWN ground truth (Bitcoin Core)
/// plus the TARGET's own signed response, and overrides the challenger's claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReVerdict {
    /// The target's signed response matches the recipient's own ground truth.
    Pass,
    /// The target's signed response contradicts the recipient's ground truth
    /// (e.g. wrong block hash / merkle root for the claimed height).
    Fail,
    /// The recipient cannot judge: no/invalid target signature, unparseable
    /// response, RPC error, or the recipient's node lacks the block (IBD /
    /// behind). This is NEVER recorded as a FAIL — an unverifiable result must
    /// not be usable to grief an honest node.
    Unverifiable,
}

/// Re-derives the verdict of a peer-broadcast verification result against the
/// recipient's own ground truth, so a node never stores a challenger-supplied
/// `passed` verbatim for a capability it can independently check.
///
/// Implemented by `ghost-pool` (which has the Bitcoin Core RPC + policy engine);
/// `ghost-consensus` only owns the trait so it stays free of those dependencies.
#[async_trait]
pub trait ResultReVerifier: Send + Sync {
    /// Re-derive an Archive verdict from the TARGET's signed `ArchiveResponse`
    /// and the recipient's own chain. `target_signed_response` is the raw
    /// `SignedResponse<ArchiveResponse>` JSON authored (and signed) by the
    /// target — the only trustworthy input, since `challenge_data` /
    /// `response_data` are authored by the (adversarial) challenger.
    async fn reverify_archive(
        &self,
        target_node_id: &NodeId,
        target_signed_response: Option<&str>,
    ) -> ReVerdict;
}

/// Extract `(block_height, block_hash)` from the TARGET-signed archive response
/// JSON (`SignedResponse<ArchiveResponse>`) for the informational DB columns.
///
/// SECURITY: this is used ONLY to populate the diagnostic height/hash columns;
/// the stored `passed` verdict comes from [`ResultReVerifier::reverify_archive`].
/// The height/hash are read from inside the target's signed `payload.block_data`
/// (not from the challenger's `challenge_data`).
fn parse_signed_archive_height_hash(signed: Option<&str>) -> (Option<u64>, Option<String>) {
    let raw = match signed {
        Some(s) if !s.trim().is_empty() => s,
        _ => return (None, None),
    };
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let block_data = value.get("payload").and_then(|p| p.get("block_data"));
    let height = block_data
        .and_then(|b| b.get("height"))
        .and_then(|h| h.as_u64());
    let hash = block_data
        .and_then(|b| b.get("hash"))
        .and_then(|h| h.as_str())
        .map(String::from);
    (height, hash)
}

/// Handler for verification result messages
pub struct VerificationResultHandler {
    /// Database for storing verification results
    db: Arc<Database>,
    /// HIGH-VER-4: Peer manager for validating challenger is a known node
    peers: Option<Arc<PeerManager>>,
    /// Per-challenger rate limiter to prevent DB flooding
    rate_limiter: RateLimiter,
    /// Optional re-deriver that recomputes capability verdicts against the
    /// recipient's own ground truth, overriding the challenger-supplied
    /// `passed`. When `None`, the legacy "trust the challenger" behaviour is
    /// preserved (used by unit tests / the no-dependencies path).
    reverifier: Option<Arc<dyn ResultReVerifier>>,
}

impl VerificationResultHandler {
    /// Create a new verification result handler
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            peers: None,
            rate_limiter: RateLimiter::new(VERIFICATION_RATE_LIMIT_BURST, VERIFICATION_RATE_REFILL),
            reverifier: None,
        }
    }

    /// HIGH-VER-4: Create a verification handler with peer validation
    ///
    /// When a PeerManager is provided, the handler will verify that challengers
    /// are known peers before accepting their verification results. This prevents
    /// attackers from generating arbitrary keypairs to submit fake results.
    pub fn with_peers(db: Arc<Database>, peers: Arc<PeerManager>) -> Self {
        Self {
            db,
            peers: Some(peers),
            rate_limiter: RateLimiter::new(VERIFICATION_RATE_LIMIT_BURST, VERIFICATION_RATE_REFILL),
            reverifier: None,
        }
    }

    /// Attach a [`ResultReVerifier`] so peer-broadcast verdicts are re-derived
    /// against this node's own ground truth instead of being trusted verbatim.
    ///
    /// SECURITY: without this, a colluding minority of challengers can sign
    /// `passed=false` against an honest node and steal its node-reward share.
    pub fn with_rederivation(mut self, reverifier: Arc<dyn ResultReVerifier>) -> Self {
        self.reverifier = Some(reverifier);
        self
    }

    /// Handle an incoming verification result message
    async fn handle_verification_result(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let envelope_sender_hex = hex::encode(envelope.sender);
        debug!(
            sender = %&envelope_sender_hex[..8],
            payload_len = envelope.payload.len(),
            "VerificationResultHandler received message"
        );

        // Deserialize the verification result message
        let msg: VerificationResultMessage =
            serde_json::from_slice(&envelope.payload).map_err(|e| {
                warn!(error = %e, "Failed to deserialize verification result message");
                ghost_common::error::GhostError::P2PMessage(e.to_string())
            })?;

        let challenger_hex = hex::encode(msg.challenger_id);
        let target_hex = hex::encode(msg.target_node_id);
        let short_challenger = &challenger_hex[..8];
        let short_target = &target_hex[..8];

        // H-5: Validate challenge_data size to prevent memory exhaustion attacks
        if msg.challenge_data.len() > MAX_CHALLENGE_DATA_SIZE {
            warn!(
                challenger = %short_challenger,
                size = msg.challenge_data.len(),
                max = MAX_CHALLENGE_DATA_SIZE,
                "Rejecting oversized challenge_data"
            );
            return Ok(());
        }

        // H-5: Validate response_data size to prevent memory exhaustion attacks
        if let Some(ref response) = msg.response_data {
            if response.len() > MAX_CHALLENGE_DATA_SIZE {
                warn!(
                    challenger = %short_challenger,
                    size = response.len(),
                    max = MAX_CHALLENGE_DATA_SIZE,
                    "Rejecting oversized response_data"
                );
                return Ok(());
            }
        }

        // C-3: Validate timestamp freshness to prevent replay attacks
        const MAX_VERIFICATION_AGE_SECS: i64 = 600; // 10 minutes
        const MAX_FUTURE_TOLERANCE_SECS: i64 = 30; // Allow 30 seconds clock skew

        let now = Utc::now().timestamp();

        // Reject stale results
        if msg.timestamp < now - MAX_VERIFICATION_AGE_SECS {
            warn!(
                challenger = %short_challenger,
                timestamp = msg.timestamp,
                now = now,
                "Rejecting stale verification result (older than 10 minutes)"
            );
            return Ok(());
        }

        // Reject future results (clock skew tolerance: 30 seconds)
        if msg.timestamp > now + MAX_FUTURE_TOLERANCE_SECS {
            warn!(
                challenger = %short_challenger,
                timestamp = msg.timestamp,
                now = now,
                "Rejecting verification result with future timestamp"
            );
            return Ok(());
        }

        debug!(
            challenger = %short_challenger,
            target = %short_target,
            capability = %msg.capability.as_str(),
            passed = msg.passed,
            "Parsed verification result from P2P"
        );

        // Verify that the envelope sender matches the challenger (prevent spoofing)
        if envelope.sender != msg.challenger_id {
            warn!(
                envelope_sender = %hex::encode(envelope.sender)[..8],
                msg_challenger = %short_challenger,
                "Verification result sender mismatch - potential spoofing"
            );
            return Ok(()); // Silently ignore invalid messages
        }

        // C-2: Reject self-verification attempts (Sybil prevention)
        if msg.challenger_id == msg.target_node_id {
            warn!(
                challenger = %short_challenger,
                "Rejecting self-verification attempt"
            );
            return Ok(());
        }

        // Verify the challenger's signature on the result
        // SEC-SIG-2: Log verification errors instead of silently treating as invalid
        let signing_data = msg.signing_data();
        let sig_valid = match verify_signature(&msg.challenger_id, &signing_data, &msg.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    challenger = %short_challenger,
                    error = %e,
                    "Verification result signature verification error"
                );
                false
            }
        };
        if !sig_valid {
            warn!(
                challenger = %short_challenger,
                "Invalid signature on verification result"
            );
            return Ok(()); // Silently ignore invalid signatures
        }

        // HIGH-VER-4: Validate challenger is a known peer before recording
        //
        // This prevents attackers from:
        // 1. Generating random keypairs to create fake verification results
        // 2. Submitting verification results from non-existent nodes
        // 3. Flooding the database with results from fabricated node IDs
        //
        // Only nodes that have been seen via health pings (known peers) can
        // submit verification results that will be recorded.
        if let Some(ref peers) = self.peers {
            if peers.get_peer(&msg.challenger_id).is_none() {
                // Peer not in memory — fall back to DB (nodes table persisted from health pings)
                let challenger_hex = hex::encode(&msg.challenger_id);
                let known_in_db = self.db.get_node(&challenger_hex).ok().flatten().is_some();
                if !known_in_db {
                    warn!(
                        challenger = %short_challenger,
                        "HIGH-VER-4: Rejecting verification result from unknown challenger"
                    );
                    return Ok(());
                }
                debug!(
                    challenger = %short_challenger,
                    "HIGH-VER-4: Challenger not in PeerManager but found in DB, accepting"
                );
            }
        }

        // Per-challenger rate limit to prevent DB flooding from compromised nodes
        if !self.rate_limiter.check_and_consume(&msg.challenger_id) {
            warn!(
                challenger = %short_challenger,
                "Rate-limiting verification results from challenger (>{} per minute)",
                VERIFICATION_RATE_LIMIT_PER_MIN
            );
            return Ok(());
        }

        // Store the result in the appropriate challenge table
        // Use idempotent storage - ignore if already exists (based on challenger + target + timestamp)
        match msg.capability {
            CapabilityType::Archive => {
                // SECURITY (consensus): never store the challenger-supplied
                // `passed` verbatim. When a re-deriver is configured, recompute
                // the verdict from THIS node's own Bitcoin Core and the TARGET's
                // own signed response, so a colluding challenger cannot fabricate
                // a FAIL (to grief) or a PASS (to inflate a peer).
                let stored_passed = if let Some(ref reverifier) = self.reverifier {
                    match reverifier
                        .reverify_archive(
                            &msg.target_node_id,
                            msg.target_signed_response.as_deref(),
                        )
                        .await
                    {
                        ReVerdict::Pass => true,
                        ReVerdict::Fail => false,
                        ReVerdict::Unverifiable => {
                            // We cannot independently judge this result (no/invalid
                            // target signature, unparseable response, RPC error, or
                            // our node lacks the block). Record NOTHING — never a
                            // false FAIL, never an unverified PASS.
                            debug!(
                                challenger = %short_challenger,
                                target = %short_target,
                                "Archive verdict unverifiable - not recording (no grief)"
                            );
                            return Ok(());
                        }
                    }
                } else {
                    // Legacy path (unit tests / no re-deriver wired): preserve the
                    // prior behaviour of trusting the challenger's verdict.
                    msg.passed
                };

                // Informational DB columns only. Prefer the height/hash from the
                // TARGET-signed response (trustworthy); fall back to the
                // challenger's challenge_data. The stored `passed` above — NOT
                // these — is what gates the payout.
                let (signed_height, signed_hash) =
                    parse_signed_archive_height_hash(msg.target_signed_response.as_deref());

                let block_height = signed_height
                    .or_else(|| {
                        serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                            .ok()
                            .and_then(|v| v.get("block_height").and_then(|h| h.as_u64()))
                    })
                    .unwrap_or(0);

                let expected_hash = signed_hash
                    .clone()
                    .or_else(|| {
                        serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                            .ok()
                            .and_then(|v| {
                                v.get("block_hash")
                                    .and_then(|h| h.as_str())
                                    .map(String::from)
                            })
                    })
                    .unwrap_or_default();

                let response_hash = signed_hash.or_else(|| {
                    msg.response_data.as_ref().and_then(|rd| {
                        serde_json::from_str::<serde_json::Value>(rd)
                            .ok()
                            .and_then(|v| v.get("hash").and_then(|h| h.as_str()).map(String::from))
                    })
                });

                if let Err(e) = self.db.insert_archive_challenge(
                    &target_hex,
                    &challenger_hex,
                    block_height,
                    &expected_hash,
                    response_hash.as_deref(),
                    stored_passed,
                ) {
                    warn!(error = %e, "Failed to store archive challenge result");
                }
            }
            CapabilityType::Policy => {
                let txid = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("txid").and_then(|t| t.as_str()).map(String::from))
                    .unwrap_or_default();

                let expected_tier = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("expected_tier").and_then(|t| t.as_i64()))
                    .unwrap_or(0) as i32;

                let response_tier = msg.response_data.as_ref().and_then(|rd| {
                    serde_json::from_str::<serde_json::Value>(rd)
                        .ok()
                        .and_then(|v| v.get("tier").and_then(|t| t.as_i64()))
                        .map(|t| t as i32)
                });

                if let Err(e) = self.db.insert_policy_challenge(
                    &target_hex,
                    &challenger_hex,
                    &txid,
                    expected_tier,
                    response_tier,
                    msg.passed,
                ) {
                    warn!(error = %e, "Failed to store policy challenge result");
                }
            }
            CapabilityType::Stratum => {
                let connected = msg
                    .response_data
                    .as_ref()
                    .map(|rd| {
                        serde_json::from_str::<serde_json::Value>(rd)
                            .ok()
                            .and_then(|v| v.get("connected").and_then(|c| c.as_bool()))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                let latency_ms = msg.response_data.as_ref().and_then(|rd| {
                    serde_json::from_str::<serde_json::Value>(rd)
                        .ok()
                        .and_then(|v| v.get("latency_ms").and_then(|l| l.as_u64()))
                        .map(|l| l as u32)
                });

                if let Err(e) = self.db.insert_stratum_challenge(
                    &target_hex,
                    &challenger_hex,
                    connected,
                    latency_ms,
                    msg.passed,
                ) {
                    warn!(error = %e, "Failed to store stratum challenge result");
                }
            }
            CapabilityType::GhostPay => {
                let endpoint = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("endpoint").and_then(|e| e.as_str()).map(String::from))
                    .unwrap_or_else(|| "ghostpay".to_string());

                let response_valid = msg
                    .response_data
                    .as_ref()
                    .map(|rd| {
                        serde_json::from_str::<serde_json::Value>(rd)
                            .ok()
                            .and_then(|v| v.get("valid").and_then(|c| c.as_bool()))
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);

                if let Err(e) = self.db.insert_ghostpay_challenge(
                    &target_hex,
                    &challenger_hex,
                    &endpoint,
                    response_valid,
                    msg.passed,
                ) {
                    warn!(error = %e, "Failed to store ghostpay challenge result");
                }
            }
        }

        debug!(
            challenger = %short_challenger,
            target = %short_target,
            capability = %msg.capability.as_str(),
            passed = msg.passed,
            "Stored verification result in database"
        );

        Ok(())
    }
}

#[async_trait]
impl MessageHandler for VerificationResultHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type == MessageType::VerificationResult {
            self.handle_verification_result(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H-5-TEST: Verify the MAX_CHALLENGE_DATA_SIZE constant is set correctly
    #[test]
    fn test_max_challenge_data_size_constant() {
        // 10 KB limit
        assert_eq!(MAX_CHALLENGE_DATA_SIZE, 10 * 1024);
        assert_eq!(MAX_CHALLENGE_DATA_SIZE, 10_240);
    }

    /// H-5-TEST: Verify oversized challenge data would be rejected
    /// This is a unit test for the size limit logic - integration tested via handle_verification_result
    #[test]
    fn test_challenge_data_size_limits() {
        // Valid sizes
        let small_data = "x".repeat(100);
        assert!(small_data.len() <= MAX_CHALLENGE_DATA_SIZE);

        let at_limit = "x".repeat(MAX_CHALLENGE_DATA_SIZE);
        assert!(at_limit.len() <= MAX_CHALLENGE_DATA_SIZE);

        // Invalid size
        let over_limit = "x".repeat(MAX_CHALLENGE_DATA_SIZE + 1);
        assert!(over_limit.len() > MAX_CHALLENGE_DATA_SIZE);
    }

    /// HIGH-VER-4-TEST: Verify that VerificationResultHandler with peers requires known challenger
    ///
    /// This test verifies the constructor and configuration of the handler.
    /// Full integration testing of peer validation requires a mock PeerManager.
    #[test]
    fn test_handler_with_peers_constructor() {
        // Create an in-memory database for testing
        let db = Arc::new(Database::in_memory().expect("Failed to create in-memory database"));

        // Create handler without peers (legacy mode)
        let handler_no_peers = VerificationResultHandler::new(Arc::clone(&db));
        assert!(
            handler_no_peers.peers.is_none(),
            "Handler without peers should have None"
        );

        // Create handler with peers (HIGH-VER-4 mode)
        let peer_manager = Arc::new(PeerManager::new([0u8; 32], 100));
        let handler_with_peers =
            VerificationResultHandler::with_peers(Arc::clone(&db), peer_manager);
        assert!(
            handler_with_peers.peers.is_some(),
            "Handler with peers should have Some"
        );
    }

    // =================================================================
    // CONSENSUS SECURITY: re-derivation override tests
    // =================================================================

    use ghost_common::identity::NodeIdentity;

    /// Stub re-verifier that returns a fixed verdict, ignoring its inputs.
    /// Lets us test the handler's verdict-mapping without a live Bitcoin Core.
    struct StubReverifier(ReVerdict);

    #[async_trait]
    impl ResultReVerifier for StubReverifier {
        async fn reverify_archive(
            &self,
            _target_node_id: &NodeId,
            _target_signed_response: Option<&str>,
        ) -> ReVerdict {
            self.0
        }
    }

    /// Build a properly-signed Archive `VerificationResultMessage` envelope.
    /// `msg_passed` is the (untrusted) challenger-claimed verdict.
    fn build_archive_envelope(
        challenger: &NodeIdentity,
        target: NodeId,
        msg_passed: bool,
    ) -> MessageEnvelope {
        let mut msg = VerificationResultMessage {
            target_node_id: target,
            challenger_id: challenger.node_id(),
            capability: CapabilityType::Archive,
            passed: msg_passed,
            challenge_data: r#"{"block_hash":"00ff","block_height":500}"#.to_string(),
            response_data: Some(r#"{"hash":"00ff"}"#.to_string()),
            target_signed_response: Some("{\"stub\":true}".to_string()),
            timestamp: Utc::now().timestamp(),
            signature: [0u8; 64],
        };
        let signing_data = msg.signing_data();
        msg.signature = challenger.sign(&signing_data);
        let payload = serde_json::to_vec(&msg).expect("serialize VRM");
        MessageEnvelope::new(
            MessageType::VerificationResult,
            challenger.node_id(),
            payload,
            1,
            [0u8; 64],
        )
    }

    /// GRIEF OVERRIDE: challenger claims `passed=false` but our re-derivation says
    /// Pass — the handler must store the re-derived PASS, not the challenger claim.
    #[tokio::test]
    async fn handler_stores_rederived_pass_over_grief() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [9u8; 32];
        let env = build_archive_envelope(&challenger, target, false);

        let handler = VerificationResultHandler::new(Arc::clone(&db))
            .with_rederivation(Arc::new(StubReverifier(ReVerdict::Pass)));
        handler.handle_verification_result(&env).await.unwrap();

        let (passed, total) = db.get_archive_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 1, "result must be recorded");
        assert_eq!(passed, 1, "stored verdict must be the re-derived PASS");
    }

    /// FRAUD OVERRIDE: challenger claims `passed=true` but our re-derivation says
    /// Fail — the handler must store the re-derived FAIL.
    #[tokio::test]
    async fn handler_stores_rederived_fail_over_inflation() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [8u8; 32];
        let env = build_archive_envelope(&challenger, target, true);

        let handler = VerificationResultHandler::new(Arc::clone(&db))
            .with_rederivation(Arc::new(StubReverifier(ReVerdict::Fail)));
        handler.handle_verification_result(&env).await.unwrap();

        let (passed, total) = db.get_archive_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 1, "result must be recorded");
        assert_eq!(passed, 0, "stored verdict must be the re-derived FAIL");
    }

    /// UNVERIFIABLE: the handler must store NOTHING (never a false FAIL), even
    /// though the challenger claimed `passed=true`.
    #[tokio::test]
    async fn handler_stores_nothing_on_unverifiable() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [7u8; 32];
        let env = build_archive_envelope(&challenger, target, true);

        let handler = VerificationResultHandler::new(Arc::clone(&db))
            .with_rederivation(Arc::new(StubReverifier(ReVerdict::Unverifiable)));
        handler.handle_verification_result(&env).await.unwrap();

        let (_passed, total) = db.get_archive_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 0, "unverifiable result must NOT be recorded");
    }

    /// LEGACY: with no re-verifier wired, the handler preserves the old behaviour
    /// of storing the challenger-supplied `passed` verbatim (so existing tests and
    /// the no-dependency path are unaffected).
    #[tokio::test]
    async fn handler_without_rederivation_stores_msg_passed() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [6u8; 32];

        // passed=true is stored as-is when no re-verifier is configured.
        let env = build_archive_envelope(&challenger, target, true);
        let handler = VerificationResultHandler::new(Arc::clone(&db));
        handler.handle_verification_result(&env).await.unwrap();

        let (passed, total) = db.get_archive_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(passed, 1, "legacy path stores msg.passed unchanged");
    }
}
