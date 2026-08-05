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
use ghost_storage::queries::VerificationProofInsert;
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
use serde::{Deserialize, Serialize};

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
        challenge_data: &str,
        target_signed_response: Option<&str>,
    ) -> ReVerdict;

    /// Re-derive a Policy (Bitcoin Pure) verdict from the TARGET's signed
    /// `PolicyResponse` and the recipient's OWN policy engine.
    ///
    /// `challenge_data` is the challenger-authored JSON; the recipient reads only
    /// the `tx_hex` from it (the exact transaction the target classified) — every
    /// value the verdict turns on otherwise comes from the TARGET-signed payload
    /// (the classification) or the recipient's own engine (ground truth). The
    /// recipient BINDS the two: it recomputes the txid of `tx_hex` and requires it
    /// to equal the signed `tx_txid`, so a colluder cannot pair a valid signed
    /// classification with a different `tx_hex` to grief the target.
    async fn reverify_policy(
        &self,
        target_node_id: &NodeId,
        challenge_data: &str,
        target_signed_response: Option<&str>,
    ) -> ReVerdict;

    // NOTE: there is deliberately NO `reverify_stratum`. Public-port reachability
    // is a NETWORK-POSITION fact, not chain/L2 content: it cannot be reproduced
    // from a transcript by a third party. The only sound evidence is the
    // challenger's OWN external TCP probe, which is exactly what is stored. Its
    // Sybil defence is the DISTINCT voter-set challenger supermajority + IP
    // diversity applied at qualification (Surface A-2), NOT recipient-side
    // re-derivation. (Re-deriving Stratum to a target SELF-attestation would be
    // strictly worse — it would discard the independent probe and let a target
    // vouch for its own reachability, defeating A-2.)

    /// Re-derive a GhostPay verdict from the TARGET's signed `GhostPayResponse`.
    ///
    /// The recipient BINDS the signed response to the challenge nonce by
    /// recomputing `nonce_bound_proof = SHA256(epoch_state_hash || challenge_nonce)`
    /// (the nonce is read from the challenger-authored `challenge_data`) and
    /// requiring it to equal the TARGET-signed `nonce_bound_proof`. This proves the
    /// target computed the response FRESH for this challenge (defeating precompute
    /// and replay) and that a colluding challenger cannot pair a stale/forged proof
    /// with an arbitrary nonce. A signed, epoch-proving, nonce-bound response is a
    /// PASS; a signed response that fails to prove epoch state is a FAIL; anything
    /// unsigned/invalid/unparseable is `Unverifiable` and records nothing.
    async fn reverify_ghostpay(
        &self,
        target_node_id: &NodeId,
        challenge_data: &str,
        target_signed_response: Option<&str>,
    ) -> ReVerdict;
}

/// Callback used to transmit a serialized [`ChallengeConvergencePayload`] to a
/// peer over the `verify` topic. Supplied by `main.rs`, which owns the mesh.
pub type ChallengeSendFn = Arc<dyn Fn(Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Upper bound on proofs served in one convergence response. Sized so a full
/// batch of worst-case proofs (`MAX_VERIFICATION_SIZE` each) stays under the 1MB
/// `MAX_CHALLENGE_CONVERGENCE_SIZE` envelope cap. A requester that is further
/// behind pulls the tail on the next sweep (each round it advertises the keys it
/// just gained, shrinking the "missing" set until it converges).
const MAX_CONVERGENCE_PROOFS: usize = 150;

/// Wire payload exchanged under [`MessageType::ChallengeConvergence`] to reconcile
/// the `verification_ledger` across nodes — the node-reward analogue of
/// GHOST-03 share backfill. A requester advertises the ledger keys it already
/// holds in a window; the responder returns the signed proofs it holds that the
/// requester lacks. Every served proof is re-verified on receipt exactly as the
/// live gossip path is, so backfill is no more trusted than a first-hand result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeConvergencePayload {
    /// "Here is what I already have in `[since_ts, until_ts)` — send me the rest."
    Request(ChallengeConvergenceRequest),
    /// "Here are the signed proofs you were missing."
    Response(ChallengeConvergenceResponse),
}

/// Advertises the verification-ledger keys held in a window so a peer can serve
/// only the difference. `keys` are `challenger|target|capability|timestamp`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConvergenceRequest {
    pub since_ts: i64,
    pub until_ts: i64,
    pub keys: Vec<String>,
}

/// The signed `VerificationResultMessage` blobs (as broadcast on the wire) the
/// responder holds in the requester's window that the requester did not advertise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeConvergenceResponse {
    pub proofs: Vec<Vec<u8>>,
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

/// Extract `(tx_txid, response_tier)` from the TARGET-signed policy response JSON
/// (`SignedResponse<PolicyResponse>`) for the informational DB columns.
///
/// SECURITY: this is used ONLY to populate the diagnostic txid/tier columns; the
/// stored `passed` verdict comes from [`ResultReVerifier::reverify_policy`]. The
/// txid/tier are read from inside the target's signed `payload` (not from the
/// challenger's `challenge_data`). `response_tier` maps the tier string to the
/// 0..=3 BUDS integer used by `insert_policy_challenge`.
fn parse_signed_policy_fields(signed: Option<&str>) -> (Option<String>, Option<i32>) {
    let raw = match signed {
        Some(s) if !s.trim().is_empty() => s,
        _ => return (None, None),
    };
    let value: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let payload = value.get("payload");
    let txid = payload
        .and_then(|p| p.get("tx_txid"))
        .and_then(|t| t.as_str())
        .map(String::from);
    let response_tier = payload
        .and_then(|p| p.get("classification"))
        .and_then(|c| c.get("tier"))
        .and_then(|t| t.as_str())
        .and_then(|t| match t {
            "T0" => Some(0),
            "T1" => Some(1),
            "T2" => Some(2),
            "T3" => Some(3),
            _ => None,
        });
    (txid, response_tier)
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
    /// Optional transmit callback for challenge-convergence exchanges. When
    /// `None`, this node still answers inbound requests but never initiates one.
    send: Option<ChallengeSendFn>,
}

impl VerificationResultHandler {
    /// Create a new verification result handler
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            peers: None,
            rate_limiter: RateLimiter::new(VERIFICATION_RATE_LIMIT_BURST, VERIFICATION_RATE_REFILL),
            reverifier: None,
            send: None,
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
            send: None,
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

    /// Attach a transmit callback so this node can INITIATE challenge-convergence
    /// requests (the node-reward analogue of GHOST-03 share backfill). Without
    /// one the node still answers inbound requests but never starts an exchange.
    pub fn with_challenge_send(mut self, send: ChallengeSendFn) -> Self {
        self.send = Some(send);
        self
    }

    /// Build a serialized convergence REQUEST advertising the ledger keys we hold
    /// in `[since_ts, until_ts)`, so a peer serves back only what we are missing.
    pub fn build_challenge_request(&self, since_ts: i64, until_ts: i64) -> GhostResult<Vec<u8>> {
        let keys = self.db.verification_keys_in(since_ts, until_ts)?;
        let payload = ChallengeConvergencePayload::Request(ChallengeConvergenceRequest {
            since_ts,
            until_ts,
            keys,
        });
        serde_json::to_vec(&payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))
    }

    /// Initiate a convergence sweep over `[since_ts, until_ts)` by broadcasting a
    /// request. A no-op when no transmit callback is configured.
    pub fn request_convergence(&self, since_ts: i64, until_ts: i64) -> GhostResult<()> {
        let Some(ref send) = self.send else {
            return Ok(());
        };
        let bytes = self.build_challenge_request(since_ts, until_ts)?;
        send(bytes)
    }

    /// Handle an inbound [`ChallengeConvergencePayload`] (request or response).
    /// A request is answered by transmitting the proofs the peer lacks; a
    /// response is applied to our ledger after per-proof re-verification.
    pub async fn handle_challenge_convergence(
        &self,
        envelope: &MessageEnvelope,
    ) -> GhostResult<()> {
        let payload: ChallengeConvergencePayload = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;
        match payload {
            ChallengeConvergencePayload::Request(req) => {
                let resp = self.build_challenge_response(&req)?;
                if resp.proofs.is_empty() {
                    return Ok(()); // nothing to serve — stay quiet
                }
                let Some(ref send) = self.send else {
                    return Ok(()); // cannot reply without a transmit callback
                };
                let bytes = serde_json::to_vec(&ChallengeConvergencePayload::Response(resp))
                    .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;
                send(bytes)?;
            }
            ChallengeConvergencePayload::Response(resp) => {
                let applied = self.apply_challenge_response(&resp).await;
                if applied > 0 {
                    debug!(
                        applied,
                        "Applied backfilled verification proofs from convergence"
                    );
                }
            }
        }
        Ok(())
    }

    /// Answer a peer's convergence REQUEST: the signed proofs we hold in their
    /// window that they did not advertise (capped at [`MAX_CONVERGENCE_PROOFS`]).
    fn build_challenge_response(
        &self,
        req: &ChallengeConvergenceRequest,
    ) -> GhostResult<ChallengeConvergenceResponse> {
        let theirs: std::collections::HashSet<String> = req.keys.iter().cloned().collect();
        let proofs = self.db.verification_proofs_missing_from(
            req.since_ts,
            req.until_ts,
            &theirs,
            MAX_CONVERGENCE_PROOFS,
        )?;
        Ok(ChallengeConvergenceResponse { proofs })
    }

    /// Apply a convergence RESPONSE: verify + (re-derive) + store each served
    /// proof. Returns the number newly stored.
    async fn apply_challenge_response(&self, resp: &ChallengeConvergenceResponse) -> usize {
        let mut applied = 0usize;
        for blob in &resp.proofs {
            if self.ingest_backfilled_proof(blob).await {
                applied += 1;
            }
        }
        applied
    }

    /// Verify, re-derive (archive/policy), and store ONE backfilled signed
    /// verification result into the ledger. This applies the same authenticity
    /// gates as the live gossip path — the challenger's signature over the
    /// canonical signing data, a known-peer check, and re-derivation of
    /// archive/policy verdicts against THIS node's own ground truth — so a
    /// backfilled proof is no more trusted than a first-hand one. Freshness and
    /// per-challenger rate limits are intentionally NOT applied: backfill is
    /// historical by nature and arrives in bulk. Returns whether it was stored.
    async fn ingest_backfilled_proof(&self, blob: &[u8]) -> bool {
        let msg: VerificationResultMessage = match serde_json::from_slice(blob) {
            Ok(m) => m,
            Err(_) => return false,
        };

        // Size sanity (mirror H-5 bounds on the live path).
        if msg.challenge_data.len() > MAX_CHALLENGE_DATA_SIZE {
            return false;
        }
        if let Some(ref rd) = msg.response_data {
            if rd.len() > MAX_CHALLENGE_DATA_SIZE {
                return false;
            }
        }

        // C-2: never accept a self-challenge.
        if msg.challenger_id == msg.target_node_id {
            return false;
        }

        // Authenticity: the challenger's signature over the canonical signing
        // data. Unlike the gossip path there is no envelope sender to cross-check
        // — the signature IS the binding, since `challenger_id` is inside the
        // signed message and the signature verifies against it.
        if !matches!(
            verify_signature(&msg.challenger_id, &msg.signing_data(), &msg.signature),
            Ok(true)
        ) {
            return false;
        }

        // HIGH-VER-4: challenger must be a known peer (PeerManager or the
        // persisted nodes table), the same gate as the live path.
        if let Some(ref peers) = self.peers {
            let challenger_hex = hex::encode(msg.challenger_id);
            if peers.get_peer(&msg.challenger_id).is_none()
                && self.db.get_node(&challenger_hex).ok().flatten().is_none()
            {
                return false;
            }
        }

        // Store the challenger's OWN signed verdict — NOT a re-derived one. A backfilled proof
        // is by construction older than the `MAX_RESPONSE_AGE_SECS` (5 min) freshness window, so
        // re-deriving the target's signed response would ALWAYS be Unverifiable and the capability
        // could never converge. The challenger's signature (verified above) is ageless, and
        // anti-grief comes from the distinct-challenger majority applied at qualification — the
        // same model as the live receive path.
        let challenger_hex = hex::encode(msg.challenger_id);
        let target_hex = hex::encode(msg.target_node_id);
        self.db
            .insert_verification_proof(VerificationProofInsert {
                challenger_id: &challenger_hex,
                target_node_id: &target_hex,
                capability: msg.capability.as_str(),
                passed: msg.passed,
                timestamp: msg.timestamp,
                proof: blob,
                round_height: msg.round_height.map(|h| h as i64),
            })
            .unwrap_or(false)
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
                let challenger_hex = hex::encode(msg.challenger_id);
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

        // CONVERGENCE SOURCE OF TRUTH: retain the challenger's OWN signed verdict in the
        // verification ledger for EVERY capability, keyed idempotently. This is what
        // deterministic qualification (and Component E) reads.
        //
        // We store `msg.passed` — the challenger's claim — NOT a re-derived verdict, on purpose.
        // Re-derivation checks the TARGET's signed response, which is rejected as stale after
        // `MAX_RESPONSE_AGE_SECS` (5 min); but `ChallengeConvergence` backfills proofs hours to
        // days later, so a re-derived verdict could never be reproduced on a backfilled proof and
        // the capability would never converge. The challenger's signature (verified above) is
        // ageless, so it converges. Anti-grief is provided instead by the DISTINCT-CHALLENGER
        // MAJORITY applied at qualification: a colluding minority can neither fabricate a PASS nor
        // a FAIL. Re-derivation is still applied below as a live filter on the legacy
        // `*_challenges` tables (the pre-gate qualification path), where freshness holds.
        if let Err(e) = self.db.insert_verification_proof(VerificationProofInsert {
            challenger_id: &challenger_hex,
            target_node_id: &target_hex,
            capability: msg.capability.as_str(),
            passed: msg.passed,
            timestamp: msg.timestamp,
            proof: &envelope.payload,
            round_height: msg.round_height.map(|h| h as i64),
        }) {
            warn!(error = %e, "Failed to persist verification proof to convergence ledger");
        }

        // Store the derived result in the appropriate legacy challenge table (live path).
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
                            &msg.challenge_data,
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
                // SECURITY (consensus): never store the challenger-supplied
                // `passed` verbatim. When a re-deriver is configured, recompute
                // the verdict from THIS node's own policy engine and the TARGET's
                // own signed classification (bound to the challenger's tx_hex by a
                // txid recompute), so a colluding challenger cannot fabricate a
                // FAIL (to grief) or a PASS (to inflate a peer).
                let stored_passed = if let Some(ref reverifier) = self.reverifier {
                    match reverifier
                        .reverify_policy(
                            &msg.target_node_id,
                            &msg.challenge_data,
                            msg.target_signed_response.as_deref(),
                        )
                        .await
                    {
                        ReVerdict::Pass => true,
                        ReVerdict::Fail => false,
                        ReVerdict::Unverifiable => {
                            // We cannot independently judge this result (no/invalid
                            // target signature, unparseable response, tx_hex
                            // missing/undeserializable, or txid binding mismatch).
                            // Record NOTHING — never a false FAIL, never an
                            // unverified PASS.
                            debug!(
                                challenger = %short_challenger,
                                target = %short_target,
                                "Policy verdict unverifiable - not recording (no grief)"
                            );
                            return Ok(());
                        }
                    }
                } else {
                    // Legacy path (unit tests / no re-deriver wired): preserve the
                    // prior behaviour of trusting the challenger's verdict.
                    msg.passed
                };

                // Informational DB columns only. Prefer the txid/tier from inside
                // the TARGET-signed response (trustworthy); fall back to the
                // challenger-authored fields. The stored `passed` above — NOT
                // these — is what gates the payout.
                let (signed_txid, signed_tier) =
                    parse_signed_policy_fields(msg.target_signed_response.as_deref());

                let txid = signed_txid
                    .or_else(|| {
                        serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                            .ok()
                            .and_then(|v| v.get("txid").and_then(|t| t.as_str()).map(String::from))
                    })
                    .unwrap_or_default();

                let expected_tier = serde_json::from_str::<serde_json::Value>(&msg.challenge_data)
                    .ok()
                    .and_then(|v| v.get("expected_tier").and_then(|t| t.as_i64()))
                    .unwrap_or(0) as i32;

                let response_tier = signed_tier.or_else(|| {
                    msg.response_data.as_ref().and_then(|rd| {
                        serde_json::from_str::<serde_json::Value>(rd)
                            .ok()
                            .and_then(|v| v.get("tier").and_then(|t| t.as_i64()))
                            .map(|t| t as i32)
                    })
                });

                if let Err(e) = self.db.insert_policy_challenge(
                    &target_hex,
                    &challenger_hex,
                    &txid,
                    expected_tier,
                    response_tier,
                    stored_passed,
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

                // GHOST-01: Stratum is NOT recipient-re-derived. Public-port
                // reachability is a network-position fact, not content, so the
                // challenger's OWN external TCP probe (`connected`/`passed`) is the
                // only sound evidence — recipient re-derivation to a target
                // self-attestation would discard that probe and defeat the A-2
                // distinct-challenger defence. A colluding challenger's lone
                // fabricated verdict is instead diluted by the DISTINCT voter-set
                // challenger supermajority + IP diversity applied at qualification.
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

                // SECURITY (GHOST-01): never store the challenger-supplied `passed`
                // verbatim. When a re-deriver is configured, require the TARGET's own
                // signed, nonce-bound L2 proof (recomputed against the challenge nonce),
                // so a colluding challenger cannot fabricate a PASS or FAIL.
                let stored_passed = if let Some(ref reverifier) = self.reverifier {
                    match reverifier
                        .reverify_ghostpay(
                            &msg.target_node_id,
                            &msg.challenge_data,
                            msg.target_signed_response.as_deref(),
                        )
                        .await
                    {
                        ReVerdict::Pass => true,
                        ReVerdict::Fail => false,
                        ReVerdict::Unverifiable => {
                            debug!(
                                challenger = %short_challenger,
                                target = %short_target,
                                "GhostPay verdict unverifiable - not recording (no grief)"
                            );
                            return Ok(());
                        }
                    }
                } else {
                    // Legacy path (unit tests / no re-deriver wired): preserve the
                    // prior behaviour of trusting the challenger's verdict.
                    msg.passed
                };

                if let Err(e) = self.db.insert_ghostpay_challenge(
                    &target_hex,
                    &challenger_hex,
                    &endpoint,
                    response_valid,
                    stored_passed,
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
        match envelope.msg_type {
            MessageType::VerificationResult => {
                self.handle_verification_result(&envelope).await?;
            }
            MessageType::ChallengeConvergence => {
                self.handle_challenge_convergence(&envelope).await?;
            }
            _ => {}
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
            _challenge_data: &str,
            _target_signed_response: Option<&str>,
        ) -> ReVerdict {
            self.0
        }

        async fn reverify_policy(
            &self,
            _target_node_id: &NodeId,
            _challenge_data: &str,
            _target_signed_response: Option<&str>,
        ) -> ReVerdict {
            self.0
        }

        async fn reverify_ghostpay(
            &self,
            _target_node_id: &NodeId,
            _challenge_data: &str,
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
            round_height: None,
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

    // ---- Policy (Bitcoin Pure) re-derivation, handler level ----

    /// Build a properly-signed Policy `VerificationResultMessage` envelope.
    fn build_policy_envelope(
        challenger: &NodeIdentity,
        target: NodeId,
        msg_passed: bool,
    ) -> MessageEnvelope {
        let mut msg = VerificationResultMessage {
            target_node_id: target,
            challenger_id: challenger.node_id(),
            capability: CapabilityType::Policy,
            passed: msg_passed,
            challenge_data: r#"{"tx_type":"T0","expected_tier":"T0","tx_hex":"00"}"#.to_string(),
            response_data: Some(r#"{"tier":"T0","accepted":true}"#.to_string()),
            target_signed_response: Some("{\"stub\":true}".to_string()),
            timestamp: Utc::now().timestamp(),
            round_height: None,
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

    /// GRIEF OVERRIDE (priority): challenger claims `passed=false` but our
    /// re-derivation says Pass — the handler stores the re-derived PASS.
    #[tokio::test]
    async fn handler_stores_rederived_policy_pass_over_grief() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [19u8; 32];
        let env = build_policy_envelope(&challenger, target, false);

        let handler = VerificationResultHandler::new(Arc::clone(&db))
            .with_rederivation(Arc::new(StubReverifier(ReVerdict::Pass)));
        handler.handle_verification_result(&env).await.unwrap();

        let (passed, total) = db.get_policy_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 1, "result must be recorded");
        assert_eq!(passed, 1, "stored verdict must be the re-derived PASS");
    }

    /// FRAUD OVERRIDE: challenger claims `passed=true` but our re-derivation says
    /// Fail — the handler stores the re-derived FAIL.
    #[tokio::test]
    async fn handler_stores_rederived_policy_fail_over_inflation() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [18u8; 32];
        let env = build_policy_envelope(&challenger, target, true);

        let handler = VerificationResultHandler::new(Arc::clone(&db))
            .with_rederivation(Arc::new(StubReverifier(ReVerdict::Fail)));
        handler.handle_verification_result(&env).await.unwrap();

        let (passed, total) = db.get_policy_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 1, "result must be recorded");
        assert_eq!(passed, 0, "stored verdict must be the re-derived FAIL");
    }

    /// UNVERIFIABLE: the handler must store NOTHING (never a false FAIL), even
    /// though the challenger claimed `passed=true`.
    #[tokio::test]
    async fn handler_stores_nothing_on_unverifiable_policy() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [17u8; 32];
        let env = build_policy_envelope(&challenger, target, true);

        let handler = VerificationResultHandler::new(Arc::clone(&db))
            .with_rederivation(Arc::new(StubReverifier(ReVerdict::Unverifiable)));
        handler.handle_verification_result(&env).await.unwrap();

        let (_passed, total) = db.get_policy_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 0, "unverifiable policy result must NOT be recorded");
    }

    /// LEGACY: with no re-verifier wired, the policy path preserves the old
    /// behaviour of storing the challenger-supplied `passed` verbatim.
    #[tokio::test]
    async fn handler_without_rederivation_stores_policy_msg_passed() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [16u8; 32];

        let env = build_policy_envelope(&challenger, target, true);
        let handler = VerificationResultHandler::new(Arc::clone(&db));
        handler.handle_verification_result(&env).await.unwrap();

        let (passed, total) = db.get_policy_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(passed, 1, "legacy path stores msg.passed unchanged");
    }

    /// THE FIX: the convergence ledger must capture the challenger's signed verdict for a
    /// re-derived capability EVEN WHEN re-derivation says `Unverifiable` — otherwise policy
    /// (rarely re-derivable inside the 5-min freshness window, never on a backfilled proof) could
    /// never converge and Component E could never count reaper. The legacy `*_challenges` table
    /// still honours the re-derivation filter and records nothing.
    #[tokio::test]
    async fn ledger_captures_policy_verdict_even_when_rederivation_unverifiable() {
        let db = Arc::new(Database::in_memory().unwrap());
        let challenger = NodeIdentity::generate();
        let target = [23u8; 32];
        let env = build_policy_envelope(&challenger, target, true); // challenger claims pass

        let handler = VerificationResultHandler::new(Arc::clone(&db))
            .with_rederivation(Arc::new(StubReverifier(ReVerdict::Unverifiable)));
        handler.handle_verification_result(&env).await.unwrap();

        // Legacy table: nothing — the re-derivation filter drops an Unverifiable result.
        let (_p, total) = db.get_policy_pass_rate(&hex::encode(target), 0).unwrap();
        assert_eq!(
            total, 0,
            "legacy policy table still honours the re-derivation filter"
        );

        // Ledger: the challenger's signed verdict IS retained, so policy can converge.
        let keys = db.verification_keys_in(0, i64::MAX).unwrap();
        assert_eq!(
            keys.len(),
            1,
            "the convergence ledger retains the challenger's signed policy verdict"
        );
    }

    // =================================================================
    // CHALLENGE CONVERGENCE: two divergent ledgers reconcile
    // =================================================================

    /// Capture outbound convergence bytes into a shared buffer so a test can
    /// hand-deliver them to the other node.
    fn capturing_send(buf: Arc<std::sync::Mutex<Vec<Vec<u8>>>>) -> ChallengeSendFn {
        Arc::new(move |bytes: Vec<u8>| {
            buf.lock().unwrap().push(bytes);
            Ok(())
        })
    }

    fn convergence_envelope(sender: NodeId, payload: Vec<u8>) -> MessageEnvelope {
        MessageEnvelope::new(
            MessageType::ChallengeConvergence,
            sender,
            payload,
            1,
            [0u8; 64],
        )
    }

    /// Two nodes start with disjoint verification ledgers. After a request/serve
    /// exchange in each direction, BOTH hold the union — the node-reward analogue
    /// of GHOST-03 share backfill. Backfill writes ONLY the `verification_ledger`
    /// (not the per-capability `*_challenges` tables), so we assert on the ledger.
    #[tokio::test]
    async fn challenge_convergence_reconciles_divergent_ledgers() {
        let db_a = Arc::new(Database::in_memory().unwrap());
        let db_b = Arc::new(Database::in_memory().unwrap());

        let outbox_a = Arc::new(std::sync::Mutex::new(Vec::new()));
        let outbox_b = Arc::new(std::sync::Mutex::new(Vec::new()));

        // No re-verifier and no PeerManager: archive proofs apply via msg.passed
        // and the known-peer gate is skipped — isolates the convergence plumbing.
        let handler_a = VerificationResultHandler::new(Arc::clone(&db_a))
            .with_challenge_send(capturing_send(Arc::clone(&outbox_a)));
        let handler_b = VerificationResultHandler::new(Arc::clone(&db_b))
            .with_challenge_send(capturing_send(Arc::clone(&outbox_b)));

        // A learns proof P1 (target T1); B learns proof P2 (target T2), first-hand.
        let challenger = NodeIdentity::generate();
        let target_1 = [21u8; 32];
        let target_2 = [22u8; 32];
        handler_a
            .handle_verification_result(&build_archive_envelope(&challenger, target_1, true))
            .await
            .unwrap();
        handler_b
            .handle_verification_result(&build_archive_envelope(&challenger, target_2, true))
            .await
            .unwrap();

        let window = (0i64, Utc::now().timestamp() + 100);
        assert_eq!(
            db_a.verification_keys_in(window.0, window.1).unwrap().len(),
            1
        );
        assert_eq!(
            db_b.verification_keys_in(window.0, window.1).unwrap().len(),
            1
        );

        // --- Direction 1: A pulls from B ---
        // A advertises what it holds (P1); B serves back what A lacks (P2).
        let a_req = handler_a
            .build_challenge_request(window.0, window.1)
            .unwrap();
        handler_b
            .handle_challenge_convergence(&convergence_envelope(challenger.node_id(), a_req))
            .await
            .unwrap();
        let b_reply = outbox_b
            .lock()
            .unwrap()
            .pop()
            .expect("B serves A's missing proof");
        handler_a
            .handle_challenge_convergence(&convergence_envelope(challenger.node_id(), b_reply))
            .await
            .unwrap();

        // --- Direction 2: B pulls from A ---
        let b_req = handler_b
            .build_challenge_request(window.0, window.1)
            .unwrap();
        handler_a
            .handle_challenge_convergence(&convergence_envelope(challenger.node_id(), b_req))
            .await
            .unwrap();
        let a_reply = outbox_a
            .lock()
            .unwrap()
            .pop()
            .expect("A serves B's missing proof");
        handler_b
            .handle_challenge_convergence(&convergence_envelope(
                challenger.node_id(),
                a_reply.clone(),
            ))
            .await
            .unwrap();

        // Both ledgers now hold the union {P1, P2}.
        assert_eq!(
            db_a.verification_keys_in(window.0, window.1).unwrap().len(),
            2,
            "A must hold both proofs after convergence"
        );
        assert_eq!(
            db_b.verification_keys_in(window.0, window.1).unwrap().len(),
            2,
            "B must hold both proofs after convergence"
        );

        // Re-applying an already-held proof is idempotent (INSERT OR IGNORE).
        handler_b
            .handle_challenge_convergence(&convergence_envelope(challenger.node_id(), a_reply))
            .await
            .unwrap();
        assert_eq!(
            db_b.verification_keys_in(window.0, window.1).unwrap().len(),
            2,
            "re-applying the same proof must not duplicate a ledger row"
        );
    }

    /// A served proof carrying a forged/invalid signature must be rejected on
    /// ingest — backfill is no more trusted than the live gossip path.
    #[tokio::test]
    async fn challenge_convergence_rejects_forged_proof() {
        let db = Arc::new(Database::in_memory().unwrap());
        let handler = VerificationResultHandler::new(Arc::clone(&db));

        // Build a valid envelope, then corrupt the signed blob's signature.
        let challenger = NodeIdentity::generate();
        let env = build_archive_envelope(&challenger, [30u8; 32], true);
        let mut msg: VerificationResultMessage = serde_json::from_slice(&env.payload).unwrap();
        msg.signature = [0xAA; 64]; // not a valid signature over signing_data
        let forged = serde_json::to_vec(&msg).unwrap();

        let resp = ChallengeConvergenceResponse {
            proofs: vec![forged],
        };
        let applied = handler.apply_challenge_response(&resp).await;
        assert_eq!(applied, 0, "forged proof must not be applied");

        let window = (0i64, Utc::now().timestamp() + 100);
        assert!(
            db.verification_keys_in(window.0, window.1)
                .unwrap()
                .is_empty(),
            "ledger must remain empty after rejecting a forged proof"
        );
    }
}
