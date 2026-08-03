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
//| FILE: message_validator.rs                                                                                           |
//|======================================================================================================================|

//! Message validation for P2P protocol
//!
//! Validates message envelopes BEFORE full deserialization to prevent
//! attacks via malformed messages. All external data is untrusted.

use thiserror::Error;
use tracing::warn;

use ghost_common::identity::verify_signature;

use crate::message::{MessageEnvelope, MessageType};

/// Minimum envelope size: version(1) + type(1) + sender(32) + seq(8) + sig(64) + min_payload(1)
pub const MIN_ENVELOPE_SIZE: usize = 107;

/// Maximum envelope size (1MB)
pub const MAX_ENVELOPE_SIZE: usize = 1_000_000;

/// Maximum JSON nesting depth (no legitimate message needs more than 16 levels)
pub const MAX_JSON_DEPTH: usize = 16;

/// Maximum payload sizes by message type
pub const MAX_SHARE_PROOF_SIZE: usize = 10_000;
pub const MAX_BLOCK_FOUND_SIZE: usize = 100_000;
pub const MAX_VOTE_SIZE: usize = 1_000;
/// Payout-ledger checkpoint vote. Sized for a voter REPORTING its own recomputed per-address work
/// (#606), not for a bare hash + signature.
///
/// A voter used to send `approve: bool` and throw its own numbers away, which is what let a proposer
/// skew every address within tolerance and still be ratified. Reporting the numbers is what makes a
/// per-address median possible — and it means the vote now carries up to `LEDGER_CAP` (1000) entries.
///
/// At `LEDGER_CAP = 1000` (defined in ghost-pool, which this crate cannot link to), an entry is a ~42-byte address plus a 16-byte micro-work integer plus
/// JSON overhead: on the order of 70 KB. Against the previous `MAX_VOTE_SIZE` of 1 KB that is a 70x
/// overrun, and the trap is that it would have looked fine — live canonical payouts currently carry
/// 4-6 addresses (~500 bytes), so the old limit passes today and would start silently dropping every
/// vote once the pool grows past roughly a dozen paid addresses. Votes dropped fleet-wide means no
/// checkpoint finalises, which means payouts stop.
///
/// 128 KB leaves headroom above the 70 KB worst case without approaching the envelope cap.
///
/// This constant must be DEPLOYED FLEET-WIDE BEFORE the gate that makes any node emit an enlarged
/// vote. A node on an older build validates against 1 KB and drops the message, so a partial roll
/// would cost quorum. That ordering is the reason #606 is gated on height at all.
pub const MAX_PAYOUT_LEDGER_VOTE_SIZE: usize = 128_000;
pub const MAX_HEALTH_PING_SIZE: usize = 2_000;
pub const MAX_DISCOVERY_SIZE: usize = 50_000;
pub const MAX_PAYOUT_PROPOSAL_SIZE: usize = 500_000;
/// Payout-checkpoint sync response: a small page of checkpoints (`MAX_SYNC_CHECKPOINTS`),
/// bounded by the hard envelope cap so a peer can't ship an oversized batch.
pub const MAX_PAYOUT_SYNC_SIZE: usize = MAX_ENVELOPE_SIZE;
pub const MAX_ELDER_UPDATE_SIZE: usize = 10_000;
/// ZK block proposal can include transactions + proof (up to 2MB)
pub const MAX_ZK_PROPOSAL_SIZE: usize = 2_000_000;
/// ZK vote is small (just signature + metadata)
pub const MAX_ZK_VOTE_SIZE: usize = 1_000;
/// Verification result is small (node IDs + capability + result + signature)
pub const MAX_VERIFICATION_SIZE: usize = 5_000;
/// Challenge-convergence exchange: a request advertises ledger keys for a window,
/// a response carries a batch of signed verification-result blobs. Bounded to the
/// 1MB envelope tier; the per-response proof count (`MAX_CONVERGENCE_PROOFS`) is
/// sized so a full batch of worst-case proofs stays under this.
pub const MAX_CHALLENGE_CONVERGENCE_SIZE: usize = 1_000_000;

/// GHOST-03 share/ledger convergence carries a BATCH of share proofs, not one proof, so it
/// cannot share `MAX_SHARE_PROOF_SIZE` — which bounds a SINGLE proof at 10 KB.
///
/// It did, and that is what #558 was. A real share proof averages ~1169 bytes, and the payload
/// expands ~3.1x as JSON (`proofs: Vec<Vec<u8>>` encodes each byte as a decimal integer), so a
/// 10 KB ceiling could not carry even **one** proof. Every window-convergence response was
/// rejected as oversized, historical divergence was never repaired, and the canaries sat 52-62k
/// shares short for nine days with payouts stalled behind them.
///
/// Mirrors `MAX_CHALLENGE_CONVERGENCE_SIZE` — the other batch-carrying convergence type, which
/// was correctly given its own limit.
pub const MAX_SHARE_CONVERGENCE_SIZE: usize = 1_000_000;
/// Share-batch chain: the largest proposed batch that may cross the wire.
///
/// **This number is the authority, and the packer derives its budget from it** — see
/// `share_batch_pack_budget`. The reverse, choosing a packing budget and hoping the wire accepts
/// it, is exactly how every convergence message-size bug happened: #559, #561, #562 and #568 were
/// all a sender bounding by the wrong thing and a receiver rejecting the result. A batch too large
/// to send is worse than a small one, because the chain cannot skip the sequence.
pub const MAX_SHARE_BATCH_SIZE: usize = MAX_ENVELOPE_SIZE;
/// Share-batch chain: a vote is a sequence, a hash and a signature.
pub const MAX_SHARE_BATCH_VOTE_SIZE: usize = MAX_VOTE_SIZE;
/// Share-batch chain: a sync response carries one batch, so it is bounded like one.
pub const MAX_SHARE_BATCH_SYNC_SIZE: usize = MAX_SHARE_BATCH_SIZE;

/// Bytes a proposer may fill with shares, after the batch's own fields and the JSON expansion.
///
/// Derived from [`MAX_SHARE_BATCH_SIZE`] rather than chosen. Two reservations:
///
/// * **JSON expansion.** The wire encoding is JSON and a `Vec<u8>` becomes a list of decimal
///   integers, so payload bytes are roughly 3.1x the underlying data — the ratio measured on real
///   share proofs when #558 was diagnosed. Ignoring it is how a 10 KB ceiling ended up unable to
///   carry one 1,169-byte proof.
/// * **Envelope and batch overhead.** Signature, roots, node shares and settled blocks all ride in
///   the same message.
///
/// Deliberately conservative: under-filling a batch costs one extra batch, while over-filling it
/// produces a message every peer rejects, at a sequence the chain cannot skip past.
pub const fn share_batch_pack_budget() -> usize {
    const JSON_EXPANSION_NUMERATOR: usize = 10;
    const JSON_EXPANSION_DENOMINATOR: usize = 31; // ~3.1x
    const BATCH_OVERHEAD: usize = 64 * 1024;

    MAX_SHARE_BATCH_SIZE
        .saturating_sub(BATCH_OVERHEAD)
        .saturating_mul(JSON_EXPANSION_NUMERATOR)
        / JSON_EXPANSION_DENOMINATOR
}
/// P2P-H3: Equivocation proof (two votes + metadata)
pub const MAX_EQUIVOCATION_PROOF_SIZE: usize = 10_000;
/// P2P-C1: Elder registration proposal (candidate + PoW + signatures)
pub const MAX_ELDER_REGISTRATION_PROPOSAL_SIZE: usize = 1_000;
/// P2P-C2: Elder list proposal (full list of up to 101 elders + metadata)
pub const MAX_ELDER_LIST_PROPOSAL_SIZE: usize = 100_000;
/// P2P-C3: Elder list approval (signature + epoch + merkle root)
pub const MAX_ELDER_LIST_APPROVAL_SIZE: usize = 500;
/// MPC-C1: MPC contribution (proof + params hash + signature)
pub const MAX_MPC_CONTRIBUTION_SIZE: usize = 50_000;
/// MPC-C2: MPC verification vote (signature + approval)
pub const MAX_MPC_VERIFICATION_VOTE_SIZE: usize = 500;
/// MPC-C3: MPC parameters request (hash + chunk indices)
pub const MAX_MPC_PARAMS_REQUEST_SIZE: usize = 5_000;
/// MPC-C4: MPC parameters response (chunked data ~1MB)
pub const MAX_MPC_PARAMS_RESPONSE_SIZE: usize = 1_100_000;
/// L2 confidential transfer (~490 bytes per tx + envelope overhead)
pub const MAX_L2_TRANSFER_SIZE: usize = 2_000;
/// L2 transfer confirmation (receipt ~200 bytes)
pub const MAX_L2_CONFIRMATION_SIZE: usize = 1_000;
/// L2 transfer broadcast (~600 bytes)
pub const MAX_L2_BROADCAST_SIZE: usize = 2_000;
/// L2 checkpoint block (1000 txs * ~490 bytes + header)
pub const MAX_L2_CHECKPOINT_SIZE: usize = 1_000_000;
/// L2 checkpoint vote (~200 bytes)
pub const MAX_L2_VOTE_SIZE: usize = 1_000;
/// L2 tree sync (up to 10000 notes for reconstruction)
pub const MAX_L2_TREE_SYNC_SIZE: usize = 1_000_000;
/// GhostGlyph claim (256 pixels + 32 bitmap_hash + 32 commitment + ghost_id + overhead)
pub const MAX_GLYPH_CLAIM_SIZE: usize = 2_000;
/// GhostGlyph registration (bitmap_hash + ghost_id + txid + timestamp)
pub const MAX_GLYPH_REGISTERED_SIZE: usize = 1_000;

/// L-13 SECURITY: Global pending message memory limit (100MB)
///
/// This limits the total memory that can be consumed by pending messages
/// across ALL message types. Without this limit, an attacker could send
/// many messages of different types, each within their per-type limit,
/// but collectively exhausting available memory.
///
/// The 100MB limit is generous for normal operation while providing
/// protection against memory exhaustion attacks.
pub const AGGREGATE_PENDING_MESSAGE_LIMIT_BYTES: usize = 100 * 1024 * 1024;

/// L-8 SECURITY: Default timestamp drift window (30 seconds in milliseconds)
///
/// This is the default value used when no explicit drift is configured.
/// 30 seconds provides a tighter security window while still allowing for:
/// - Clock drift: Nodes running NTP should stay well within 30s
/// - Network propagation: Even high-latency links are sub-second
/// - Processing delays: Normal message handling is milliseconds
///
/// The previous 60-second window was more permissive than necessary and
/// allowed a larger replay attack window. 30 seconds is still generous
/// for properly synchronized nodes while reducing attack surface.
///
/// Nodes MUST run NTP to maintain clock synchronization within this window.
pub const DEFAULT_TIMESTAMP_DRIFT_MS: u64 = 30 * 1000;

/// L-8 SECURITY: Legacy constant for backwards compatibility
/// Use DEFAULT_TIMESTAMP_DRIFT_MS for new code.
/// NOTE: Reduced from 60s to 30s for improved security.
pub const MAX_TIMESTAMP_DRIFT_MS: u64 = DEFAULT_TIMESTAMP_DRIFT_MS;

/// Minimum allowed timestamp drift (1 second)
/// Setting drift below this is dangerous as it may cause legitimate message rejection
pub const MIN_TIMESTAMP_DRIFT_MS: u64 = 1000;

/// Maximum allowed timestamp drift (5 minutes)
/// Higher values increase replay attack window
pub const MAX_TIMESTAMP_DRIFT_LIMIT_MS: u64 = 5 * 60 * 1000;

/// Message validation errors
#[derive(Debug, Clone, Error)]
pub enum MessageValidationError {
    #[error("Message too small: {0} bytes (min {MIN_ENVELOPE_SIZE})")]
    TooSmall(usize),

    #[error("Message too large: {0} bytes (max {MAX_ENVELOPE_SIZE})")]
    TooLarge(usize),

    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid message type: {0}")]
    InvalidType(u8),

    #[error("Payload too large for {0:?}: {1} bytes (max {2})")]
    PayloadTooLarge(MessageType, usize, usize),

    #[error("Invalid signature from {0}")]
    InvalidSignature(String),

    #[error("Sender node ID is all zeros")]
    ZeroSender,

    #[error("Sequence number is zero")]
    ZeroSequence,

    /// H-P2P-2: Signature is all zeros (indicates uninitialized/forged message)
    #[error("Signature is all zeros")]
    ZeroSignature,

    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),

    #[error("Timestamp too far in the future: {0}ms ahead")]
    TimestampInFuture(u64),

    #[error("Timestamp too far in the past: {0}ms behind")]
    TimestampInPast(u64),

    #[error("JSON nesting depth {0} exceeds maximum {MAX_JSON_DEPTH}")]
    ExcessiveNesting(usize),
}

/// Validate raw message bytes before any deserialization
///
/// This performs quick checks that can reject obviously malformed
/// messages without expensive parsing.
pub fn validate_envelope_header(data: &[u8]) -> Result<(), MessageValidationError> {
    // Size bounds
    if data.len() < MIN_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooSmall(data.len()));
    }

    if data.len() > MAX_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooLarge(data.len()));
    }

    // Check if this is JSON-serialized (starts with '{')
    // MessageEnvelope uses serde_json for serialization, so valid messages start with '{'
    if data[0] == b'{' {
        // JSON format - can't validate header bytes, will validate during deserialization
        return Ok(());
    }

    // Binary format (future use) - validate header bytes
    // Version check (first byte)
    let version = data[0];
    if version != 1 {
        return Err(MessageValidationError::UnsupportedVersion(version));
    }

    // Message type check (second byte)
    let msg_type_byte = data[1];
    if msg_type_byte > 13 {
        // We have 14 message types (0-13) including ZK payout types, verification, and equivocation
        return Err(MessageValidationError::InvalidType(msg_type_byte));
    }

    Ok(())
}

/// P2P-H1: Extract message type from raw JSON data without full deserialization
///
/// This enables topic validation BEFORE expensive full deserialization.
/// Messages received on a specific topic/socket must have the matching message type.
/// This prevents attackers from sending messages on the wrong topic to confuse handlers.
///
/// # Arguments
/// * `data` - Raw message bytes (expected to be JSON)
///
/// # Returns
/// * `Ok(Some(MessageType))` - Successfully extracted message type
/// * `Ok(None)` - Could not extract type (invalid format)
/// * `Err(MessageValidationError)` - Message too small/large
pub fn extract_message_type_fast(
    data: &[u8],
) -> Result<Option<MessageType>, MessageValidationError> {
    // Size bounds
    if data.len() < MIN_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooSmall(data.len()));
    }

    if data.len() > MAX_ENVELOPE_SIZE {
        return Err(MessageValidationError::TooLarge(data.len()));
    }

    // Only handle JSON format (starts with '{')
    if data[0] != b'{' {
        // Binary format - extract type from second byte
        let msg_type_byte = data[1];
        let msg_type = match msg_type_byte {
            0 => Some(MessageType::ShareProof),
            1 => Some(MessageType::BlockFound),
            2 => Some(MessageType::PayoutProposal),
            3 => Some(MessageType::Vote),
            4 => Some(MessageType::HealthPing),
            5 => Some(MessageType::Discovery),
            6 => Some(MessageType::ElderUpdate),
            7 => Some(MessageType::ShareConvergence),
            8 => Some(MessageType::ZkBlockProposal),
            9 => Some(MessageType::ZkVote),
            12 => Some(MessageType::VerificationResult),
            13 => Some(MessageType::EquivocationProof),
            _ => None,
        };
        return Ok(msg_type);
    }

    // JSON format - look for "msg_type" field without full parsing
    // The JSON format uses: {"msg_type":"ShareProof", ...}
    // We search for the pattern and extract just the type string

    // Convert to string for simple pattern matching
    // This is safe because JSON is UTF-8 and we're looking for ASCII patterns
    let data_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return Ok(None), // Invalid UTF-8, can't extract
    };

    // Look for "msg_type":"<TYPE>" pattern
    // We use a simple search rather than full JSON parsing
    let type_marker = r#""msg_type":"#;
    let type_pos = match data_str.find(type_marker) {
        Some(pos) => pos + type_marker.len(),
        None => return Ok(None), // No msg_type field found
    };

    // Extract the type value (should be a quoted string)
    // CRIT-PANIC-3: Use .get() for safe byte access instead of direct indexing
    // This prevents panics on UTF-8 multi-byte boundary issues
    let bytes = data_str.as_bytes();
    match bytes.get(type_pos) {
        Some(&b'"') => {}
        _ => return Ok(None),
    }

    let type_start = type_pos + 1;
    // Validate type_start is within bounds before slicing
    if type_start > data_str.len() {
        return Ok(None);
    }
    let remainder = match data_str.get(type_start..) {
        Some(s) => s,
        None => return Ok(None),
    };
    let type_end = match remainder.find('"') {
        Some(pos) => type_start + pos,
        None => return Ok(None),
    };

    // Validate slice bounds before extracting
    let type_str = match data_str.get(type_start..type_end) {
        Some(s) => s,
        None => return Ok(None),
    };

    // Map string to MessageType
    let msg_type = match type_str {
        "ShareProof" => MessageType::ShareProof,
        "ShareConvergence" => MessageType::ShareConvergence,
        "BlockFound" => MessageType::BlockFound,
        "Vote" => MessageType::Vote,
        "HealthPing" => MessageType::HealthPing,
        "Discovery" => MessageType::Discovery,
        "PayoutProposal" => MessageType::PayoutProposal,
        "ElderUpdate" => MessageType::ElderUpdate,
        "ZkBlockProposal" => MessageType::ZkBlockProposal,
        "ZkVote" => MessageType::ZkVote,
        "VerificationResult" => MessageType::VerificationResult,
        "EquivocationProof" => MessageType::EquivocationProof,
        _ => return Ok(None), // Unknown type
    };

    Ok(Some(msg_type))
}

/// P2P-H1: Validate that a message's type matches the expected topic
///
/// Call this BEFORE full deserialization to reject messages sent on the wrong topic.
/// This prevents type confusion attacks where an attacker sends a message on one
/// socket but with a different message type.
///
/// # Arguments
/// * `data` - Raw message bytes
/// * `expected_type` - The message type expected for this topic/socket
///
/// # Returns
/// * `Ok(())` - Type matches or could not be extracted (will be validated after deser)
/// * `Err(InvalidType)` - Extracted type does not match expected type
pub fn validate_topic_before_deser(
    data: &[u8],
    expected_type: MessageType,
) -> Result<(), MessageValidationError> {
    match extract_message_type_fast(data)? {
        Some(msg_type) if msg_type != expected_type => {
            warn!(
                expected = ?expected_type,
                actual = ?msg_type,
                "Message type mismatch - wrong topic"
            );
            // We return InvalidType but with a specific byte value to indicate topic mismatch
            // The actual type byte doesn't matter here since it's JSON
            Err(MessageValidationError::InvalidType(255))
        }
        _ => Ok(()), // Either matches or couldn't extract (validate after deser)
    }
}

/// Get the maximum allowed payload size for a message type
pub fn max_payload_size(msg_type: MessageType) -> usize {
    match msg_type {
        MessageType::ShareProof => MAX_SHARE_PROOF_SIZE,
        MessageType::ShareConvergence => MAX_SHARE_CONVERGENCE_SIZE,
        MessageType::BlockFound => MAX_BLOCK_FOUND_SIZE,
        MessageType::Vote => MAX_VOTE_SIZE,
        MessageType::HealthPing => MAX_HEALTH_PING_SIZE,
        MessageType::Discovery => MAX_DISCOVERY_SIZE,
        MessageType::PayoutProposal => MAX_PAYOUT_PROPOSAL_SIZE,
        MessageType::ElderUpdate => MAX_ELDER_UPDATE_SIZE,
        MessageType::ZkBlockProposal => MAX_ZK_PROPOSAL_SIZE,
        MessageType::ZkVote => MAX_ZK_VOTE_SIZE,
        MessageType::VerificationResult => MAX_VERIFICATION_SIZE,
        MessageType::ChallengeConvergence => MAX_CHALLENGE_CONVERGENCE_SIZE,
        MessageType::EquivocationProof => MAX_EQUIVOCATION_PROOF_SIZE,
        MessageType::ElderRegistrationProposal => MAX_ELDER_REGISTRATION_PROPOSAL_SIZE,
        MessageType::ElderListProposal => MAX_ELDER_LIST_PROPOSAL_SIZE,
        MessageType::ElderListApproval => MAX_ELDER_LIST_APPROVAL_SIZE,
        MessageType::MpcContribution => MAX_MPC_CONTRIBUTION_SIZE,
        MessageType::MpcVerificationVote => MAX_MPC_VERIFICATION_VOTE_SIZE,
        MessageType::MpcParametersRequest => MAX_MPC_PARAMS_REQUEST_SIZE,
        MessageType::MpcParametersResponse => MAX_MPC_PARAMS_RESPONSE_SIZE,
        MessageType::L2ConfidentialTransfer => MAX_L2_TRANSFER_SIZE,
        MessageType::L2TransferConfirmation => MAX_L2_CONFIRMATION_SIZE,
        MessageType::L2TransferBroadcast => MAX_L2_BROADCAST_SIZE,
        MessageType::L2CheckpointBlock => MAX_L2_CHECKPOINT_SIZE,
        MessageType::L2CheckpointVote => MAX_L2_VOTE_SIZE,
        // The checkpoint carries the CANONICAL payout (top-N miner addresses + top-N node
        // shares) so the fleet can adopt it on finalise (option c); bounded but not tiny.
        // The vote is just a hash + signature.
        MessageType::PayoutLedgerCheckpoint => MAX_PAYOUT_PROPOSAL_SIZE,
        // NOT MAX_VOTE_SIZE — the vote now reports the voter's own per-address work (#606).
        MessageType::PayoutLedgerCheckpointVote => MAX_PAYOUT_LEDGER_VOTE_SIZE,
        MessageType::PayoutLedgerCheckpointSync => MAX_PAYOUT_SYNC_SIZE,
        // One proposal per response, so the existing proposal bound applies.
        MessageType::PayoutProposalSync => MAX_PAYOUT_PROPOSAL_SIZE,
        MessageType::ShareBatchProposal => MAX_SHARE_BATCH_SIZE,
        MessageType::ShareBatchVote => MAX_SHARE_BATCH_VOTE_SIZE,
        MessageType::ShareBatchSync => MAX_SHARE_BATCH_SYNC_SIZE,
        MessageType::MeshNodeListCheckpoint => MAX_PAYOUT_PROPOSAL_SIZE,
        MessageType::MeshNodeListCheckpointVote => MAX_VOTE_SIZE,
        MessageType::MeshNodeListCheckpointSync => MAX_PAYOUT_SYNC_SIZE,
        MessageType::L2TreeSync => MAX_L2_TREE_SYNC_SIZE,
        MessageType::L2ShieldBroadcast => 256, // ShieldCommitment: 32-byte commitment + u64 index + u64 height
        MessageType::GhostGlyphClaim => MAX_GLYPH_CLAIM_SIZE,
        MessageType::GhostGlyphRegistered => MAX_GLYPH_REGISTERED_SIZE,
    }
}

/// Validate payload size against message type limits
pub fn validate_payload_size(
    msg_type: MessageType,
    payload_size: usize,
) -> Result<(), MessageValidationError> {
    let max_size = max_payload_size(msg_type);
    if payload_size > max_size {
        return Err(MessageValidationError::PayloadTooLarge(
            msg_type,
            payload_size,
            max_size,
        ));
    }
    Ok(())
}

/// Validate a deserialized envelope
pub fn validate_envelope(envelope: &MessageEnvelope) -> Result<(), MessageValidationError> {
    // H-P2P-2: Check for zero signatures (must be checked in all handlers, not just vote_handler)
    // Zero signatures indicate uninitialized or forged messages
    if envelope.signature == [0u8; 64] {
        return Err(MessageValidationError::ZeroSignature);
    }

    // Check sender is not all zeros
    if envelope.sender == [0u8; 32] {
        return Err(MessageValidationError::ZeroSender);
    }

    // Check sequence is not zero (indicates uninitialized)
    if envelope.sequence == 0 {
        return Err(MessageValidationError::ZeroSequence);
    }

    // Validate payload size for message type
    validate_payload_size(envelope.msg_type, envelope.payload.len())?;

    // Validate timestamp is within acceptable range
    validate_timestamp(envelope.timestamp)?;

    Ok(())
}

/// Validate that a timestamp is within acceptable range using default drift window
///
/// Rejects messages with timestamps that are:
/// - More than DEFAULT_TIMESTAMP_DRIFT_MS in the future (prevents replay attacks with future timestamps)
/// - More than DEFAULT_TIMESTAMP_DRIFT_MS in the past (prevents replay of old messages)
pub fn validate_timestamp(timestamp_ms: u64) -> Result<(), MessageValidationError> {
    validate_timestamp_with_drift(timestamp_ms, DEFAULT_TIMESTAMP_DRIFT_MS)
}

/// Validate that a timestamp is within a configurable drift window
///
/// # Arguments
/// * `timestamp_ms` - The timestamp to validate (Unix milliseconds)
/// * `drift_ms` - Maximum allowed drift in milliseconds (clamped to MIN..MAX range)
///
/// # Returns
/// * `Ok(())` if timestamp is within the acceptable window
/// * `Err(TimestampInFuture)` if timestamp is too far in the future
/// * `Err(TimestampInPast)` if timestamp is too far in the past
pub fn validate_timestamp_with_drift(
    timestamp_ms: u64,
    drift_ms: u64,
) -> Result<(), MessageValidationError> {
    // Clamp drift to safe bounds
    let drift_ms = drift_ms.clamp(MIN_TIMESTAMP_DRIFT_MS, MAX_TIMESTAMP_DRIFT_LIMIT_MS);

    let now_ms = chrono::Utc::now().timestamp_millis() as u64;

    // Check if timestamp is too far in the future
    if timestamp_ms > now_ms.saturating_add(drift_ms) {
        let drift = timestamp_ms - now_ms;
        warn!(
            timestamp_ms,
            now_ms,
            drift_ms = drift,
            allowed_drift_ms = drift_ms,
            "Message timestamp too far in the future"
        );
        return Err(MessageValidationError::TimestampInFuture(drift));
    }

    // Check if timestamp is too far in the past
    if now_ms > timestamp_ms.saturating_add(drift_ms) {
        let drift = now_ms - timestamp_ms;
        warn!(
            timestamp_ms,
            now_ms,
            drift_ms = drift,
            allowed_drift_ms = drift_ms,
            "Message timestamp too far in the past"
        );
        return Err(MessageValidationError::TimestampInPast(drift));
    }

    Ok(())
}

/// Verify envelope signature
///
/// MUST be called before trusting any message content.
pub fn verify_envelope_signature(envelope: &MessageEnvelope) -> Result<(), MessageValidationError> {
    // Reconstruct signed data (payload + sequence)
    let mut signed_data = envelope.payload.clone();
    signed_data.extend_from_slice(&envelope.sequence.to_le_bytes());

    // SEC-MSG-1: Log verification errors instead of silently treating as invalid
    let is_valid = match verify_signature(&envelope.sender, &signed_data, &envelope.signature) {
        Ok(valid) => valid,
        Err(e) => {
            warn!(
                sender = %hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                error = %e,
                "Envelope signature verification error"
            );
            false
        }
    };

    if !is_valid {
        let sender_hex = hex::encode(&envelope.sender[..8]);
        warn!(
            sender = %sender_hex,
            msg_type = ?envelope.msg_type,
            seq = envelope.sequence,
            "INVALID SIGNATURE - potential spoofing attempt"
        );
        return Err(MessageValidationError::InvalidSignature(sender_hex));
    }

    Ok(())
}

/// Check JSON nesting depth without full deserialization.
///
/// Scans raw bytes counting `{` and `[` nesting. Rejects if depth exceeds
/// `MAX_JSON_DEPTH`. This is O(n) and runs before the expensive serde parse
/// to prevent stack overflow from maliciously nested payloads.
fn check_json_depth(data: &[u8]) -> Result<(), MessageValidationError> {
    // Only check JSON-formatted messages
    if data.is_empty() || data[0] != b'{' {
        return Ok(());
    }

    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;

    for &byte in data {
        if escape {
            escape = false;
            continue;
        }

        if in_string {
            match byte {
                b'\\' => escape = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_DEPTH {
                    return Err(MessageValidationError::ExcessiveNesting(depth));
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    Ok(())
}

/// Extract the envelope timestamp from raw JSON without deserializing.
///
/// Same technique as `extract_message_type_fast`, for the same reason: so a message can be
/// judged before paying to parse it.
///
/// This exists because the drift check sat *downstream* of deserialization. A node that had
/// fallen behind would fully parse a message, discover it had waited 40 seconds, and throw it
/// away — burning CPU on work it was about to discard, which lengthened the queue, which made
/// the next message later still. The check could not protect anything; it converted a backlog
/// into wasted work (#517).
///
/// Measured on the fleet: nodes with a clean queue answered `/health` in under a millisecond,
/// while a node rejecting 854 stale messages in ten minutes could not answer at all.
///
/// Returns `None` when the timestamp cannot be read cheaply — an unreadable timestamp must fall
/// through to the full pipeline rather than be treated as stale, or a format change would
/// silently drop every message on the floor.
pub fn extract_timestamp_fast(data: &[u8]) -> Option<u64> {
    // Only the JSON format is scannable; binary envelopes fall through to full validation.
    if data.first() != Some(&b'{') {
        return None;
    }
    let data_str = std::str::from_utf8(data).ok()?;

    // `"timestamp":<digits>` — the envelope's own field. Payloads may carry their own
    // `timestamp`, so take the FIRST occurrence: serde writes envelope fields in declaration
    // order and `timestamp` precedes `payload`.
    let marker = r#""timestamp":"#;
    let start = data_str.find(marker)? + marker.len();
    let rest = &data_str[start..];
    let digits: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Is this message too old to be worth parsing?
///
/// Deliberately more lenient than `validate_timestamp_with_drift`: this is a cheap pre-filter,
/// and the authoritative check still runs afterwards on everything that survives. A message
/// rejected here would have been rejected there anyway.
///
/// Only the PAST direction is checked. A future-dated timestamp is a correctness concern that
/// belongs with the real validator, not a backlog symptom.
pub fn is_stale_before_deser(data: &[u8], drift_ms: u64) -> bool {
    let drift_ms = drift_ms.clamp(MIN_TIMESTAMP_DRIFT_MS, MAX_TIMESTAMP_DRIFT_LIMIT_MS);
    match extract_timestamp_fast(data) {
        Some(ts) => {
            let now_ms = chrono::Utc::now().timestamp_millis() as u64;
            now_ms > ts.saturating_add(drift_ms)
        }
        // Unreadable: not our call to make here.
        None => false,
    }
}

/// Full validation pipeline for incoming messages
///
/// 1. Validate raw bytes (size, version, type)
/// 2. Deserialize
/// 3. Validate envelope fields
/// 4. Verify signature
pub fn validate_and_verify(data: &[u8]) -> Result<MessageEnvelope, MessageValidationError> {
    // Step 1: Header validation (fast, no alloc)
    validate_envelope_header(data)?;

    // Step 1.2: cheap staleness check, BEFORE the depth scan and the parse (#517).
    //
    // The authoritative drift check is in `validate_envelope` below, but it only runs after a
    // full JSON parse. On a node that has fallen behind, that meant paying to walk and parse
    // every message just to discard it — the backlog feeding itself. Judging it here costs one
    // substring scan and an integer parse, and it runs ahead of `check_json_depth` so a stale
    // message does not even pay for that O(n) pass.
    if is_stale_before_deser(data, DEFAULT_TIMESTAMP_DRIFT_MS) {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let drift = extract_timestamp_fast(data)
            .map(|ts| now_ms.saturating_sub(ts))
            .unwrap_or(0);
        return Err(MessageValidationError::TimestampInPast(drift));
    }

    // Step 1.5: JSON depth check (O(n), prevents stack overflow from deeply nested payloads)
    check_json_depth(data)?;

    // Step 2: Deserialize
    let envelope = MessageEnvelope::deserialize(data)
        .map_err(|e| MessageValidationError::DeserializationFailed(e.to_string()))?;

    // Step 3: Envelope validation
    validate_envelope(&envelope)?;

    // Step 4: Signature verification (expensive, do last)
    verify_envelope_signature(&envelope)?;

    Ok(envelope)
}

/// Batch validation result
#[derive(Debug, Default, Clone)]
pub struct ValidationStats {
    pub total: u64,
    pub valid: u64,
    pub too_small: u64,
    pub too_large: u64,
    pub bad_version: u64,
    pub bad_type: u64,
    pub bad_signature: u64,
    pub bad_timestamp: u64,
    pub other_errors: u64,
    /// L-13: Messages rejected due to aggregate memory limit
    pub memory_limit_exceeded: u64,
}

/// L-13 SECURITY: Error type for aggregate memory limit exceeded
#[derive(Debug, Clone, Error)]
#[error(
    "Aggregate pending message memory limit exceeded: {current_bytes} bytes (limit: {limit_bytes})"
)]
pub struct AggregateMemoryLimitExceeded {
    pub current_bytes: usize,
    pub limit_bytes: usize,
}

/// L-13 SECURITY: Tracker for aggregate pending message memory
///
/// Tracks total memory used by pending messages across all types.
/// Must be updated when messages are added to and removed from queues.
///
/// Thread-safe via atomic operations.
#[derive(Debug)]
pub struct AggregateMemoryTracker {
    /// Current total bytes of pending messages
    current_bytes: std::sync::atomic::AtomicUsize,
    /// Maximum allowed bytes
    limit_bytes: usize,
}

impl AggregateMemoryTracker {
    /// Create a new tracker with default limit (100MB)
    pub fn new() -> Self {
        Self::with_limit(AGGREGATE_PENDING_MESSAGE_LIMIT_BYTES)
    }

    /// Create a new tracker with custom limit
    pub fn with_limit(limit_bytes: usize) -> Self {
        Self {
            current_bytes: std::sync::atomic::AtomicUsize::new(0),
            limit_bytes,
        }
    }

    /// Try to reserve space for a new message
    ///
    /// Returns Ok(()) if space is available and reserved.
    /// Returns Err if the message would exceed the limit.
    ///
    /// IMPORTANT: If Ok is returned, the caller MUST eventually call `release()`
    /// with the same size when the message is processed/dropped.
    pub fn try_reserve(&self, size_bytes: usize) -> Result<(), AggregateMemoryLimitExceeded> {
        use std::sync::atomic::Ordering;

        loop {
            let current = self.current_bytes.load(Ordering::Acquire);
            let new_total = current.saturating_add(size_bytes);

            if new_total > self.limit_bytes {
                return Err(AggregateMemoryLimitExceeded {
                    current_bytes: current,
                    limit_bytes: self.limit_bytes,
                });
            }

            // Try to atomically update
            match self.current_bytes.compare_exchange_weak(
                current,
                new_total,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue, // Retry on contention
            }
        }
    }

    /// Release space when a message is processed or dropped
    ///
    /// MUST be called exactly once for each successful `try_reserve()`.
    pub fn release(&self, size_bytes: usize) {
        use std::sync::atomic::Ordering;

        let previous = self.current_bytes.fetch_sub(size_bytes, Ordering::Release);

        // Sanity check: we should never go negative
        if previous < size_bytes {
            warn!(
                size_bytes,
                previous, "L-13: Released more memory than was reserved (underflow)"
            );
            // Reset to 0 to recover from inconsistent state
            self.current_bytes.store(0, Ordering::Release);
        }
    }

    /// Get the current total bytes of pending messages
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// Get the memory limit in bytes
    pub fn limit_bytes(&self) -> usize {
        self.limit_bytes
    }

    /// Get the percentage of the limit currently used
    pub fn usage_percent(&self) -> f64 {
        let current = self.current_bytes() as f64;
        let limit = self.limit_bytes as f64;
        (current / limit) * 100.0
    }

    /// Check if we're at high memory usage (>80%)
    pub fn is_high_usage(&self) -> bool {
        self.current_bytes() > (self.limit_bytes * 80) / 100
    }

    /// Reset the tracker (for testing or recovery)
    pub fn reset(&self) {
        self.current_bytes
            .store(0, std::sync::atomic::Ordering::Release);
    }
}

impl Default for AggregateMemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidationStats {
    pub fn record(&mut self, result: &Result<MessageEnvelope, MessageValidationError>) {
        self.total += 1;
        match result {
            Ok(_) => self.valid += 1,
            Err(MessageValidationError::TooSmall(_)) => self.too_small += 1,
            Err(MessageValidationError::TooLarge(_)) => self.too_large += 1,
            Err(MessageValidationError::UnsupportedVersion(_)) => self.bad_version += 1,
            Err(MessageValidationError::InvalidType(_)) => self.bad_type += 1,
            Err(MessageValidationError::InvalidSignature(_)) => self.bad_signature += 1,
            Err(MessageValidationError::TimestampInFuture(_)) => self.bad_timestamp += 1,
            Err(MessageValidationError::TimestampInPast(_)) => self.bad_timestamp += 1,
            Err(_) => self.other_errors += 1,
        }
    }

    pub fn rejection_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.total - self.valid) as f64 / self.total as f64
        }
    }
}

#[cfg(test)]
mod tests {

    /// **The budget must fit the wire, not the other way round.**
    ///
    /// #559, #561, #562 and #568 were all one shape: a sender bounding its payload by something
    /// other than what the receiver enforces. Deriving the budget from the limit makes that
    /// impossible by construction, and this asserts the derivation actually leaves room.
    #[test]
    fn the_pack_budget_fits_inside_the_wire_limit() {
        let budget = share_batch_pack_budget();
        assert!(budget > 0, "a zero budget would wedge the chain");
        assert!(
            budget < MAX_SHARE_BATCH_SIZE,
            "the budget must be smaller than the limit it is derived from"
        );

        // Worst case on the wire: every budgeted byte expands ~3.1x as JSON, plus overhead.
        let worst_case = budget * 31 / 10 + 64 * 1024;
        assert!(
            worst_case <= MAX_SHARE_BATCH_SIZE,
            "a full batch would be {worst_case} bytes against a {MAX_SHARE_BATCH_SIZE} limit"
        );
    }

    /// A batch big enough to matter must still fit. A budget that technically satisfies the
    /// arithmetic but holds three shares would be correct and useless.
    #[test]
    fn the_pack_budget_holds_a_useful_number_of_shares() {
        // ~1,169 bytes per real share proof, measured when #558 was diagnosed.
        const REAL_SHARE_PROOF_BYTES: usize = 1_169;
        let shares = share_batch_pack_budget() / REAL_SHARE_PROOF_BYTES;
        assert!(
            shares >= 200,
            "a batch would hold only {shares} shares, which is not a batch"
        );
    }

    /// Every batch-chain type has its own limit rather than inheriting a default. A message type
    /// that silently falls into someone else's bound is how a payload ends up rejected for a
    /// reason nobody wrote down.
    #[test]
    fn every_batch_message_type_has_its_own_bound() {
        assert_eq!(
            max_payload_size(MessageType::ShareBatchProposal),
            MAX_SHARE_BATCH_SIZE
        );
        assert_eq!(
            max_payload_size(MessageType::ShareBatchVote),
            MAX_SHARE_BATCH_VOTE_SIZE
        );
        assert_eq!(
            max_payload_size(MessageType::ShareBatchSync),
            MAX_SHARE_BATCH_SYNC_SIZE
        );
        assert!(
            max_payload_size(MessageType::ShareBatchVote)
                < max_payload_size(MessageType::ShareBatchProposal),
            "a vote is a hash and a signature; if it is bounded like a batch, something is wrong"
        );
    }

    /// A convergence BATCH must not be bounded by the SINGLE-proof limit.
    ///
    /// #558: `ShareConvergence` mapped to `MAX_SHARE_PROOF_SIZE` (10 KB). A real share proof
    /// averages ~1169 bytes and the payload expands ~3.1x as JSON, so that ceiling could not
    /// carry even one proof — every window-convergence response was rejected as oversized and
    /// historical ledger divergence was never repaired.
    #[test]
    fn share_convergence_is_not_bounded_by_the_single_proof_limit() {
        assert_ne!(
            max_payload_size(MessageType::ShareConvergence),
            MAX_SHARE_PROOF_SIZE,
            "ShareConvergence carries a batch; bounding it by the single-proof limit makes \
             window convergence structurally impossible (#558)"
        );

        // Headroom for a realistic batch: ~1169 raw bytes per proof, ~3.1x JSON expansion.
        const REAL_PROOF_BYTES: usize = 1169;
        const JSON_EXPANSION: usize = 4; // conservative
        let one_proof = REAL_PROOF_BYTES * JSON_EXPANSION;
        assert!(
            max_payload_size(MessageType::ShareConvergence) >= one_proof * 50,
            "limit {} cannot carry a useful batch (one proof is ~{} bytes encoded)",
            max_payload_size(MessageType::ShareConvergence),
            one_proof
        );
    }

    /// The whole point of #517: a stale message must be rejected WITHOUT paying to parse it.
    ///
    /// The drift check used to sit after deserialization, so a node that had fallen behind
    /// fully parsed every message just to discard it — burning CPU on work it was about to
    /// throw away, which lengthened the queue and made the next message later still.
    #[test]
    fn a_stale_message_is_rejected_before_deserialization() {
        let old_ms = (chrono::Utc::now().timestamp_millis() as u64)
            .saturating_sub(DEFAULT_TIMESTAMP_DRIFT_MS + 60_000);
        // Deliberately UNPARSEABLE past the timestamp, and padded past MIN_ENVELOPE_SIZE so
        // the size gate cannot be what rejects it. If this comes back TimestampInPast, nothing
        // downstream of the cheap scan can have run — the JSON never closes.
        let data = format!(
            r#"{{"msg_type":"HealthPing","sender":"00","timestamp":{old_ms},"garbage{}"#,
            "x".repeat(MIN_ENVELOPE_SIZE)
        );
        assert!(
            is_stale_before_deser(data.as_bytes(), DEFAULT_TIMESTAMP_DRIFT_MS),
            "a 90s-old message must be judged stale from the raw bytes alone"
        );
        let got = validate_and_verify(data.as_bytes());
        assert!(
            matches!(got, Err(MessageValidationError::TimestampInPast(_))),
            "expected TimestampInPast from the pre-filter, got {got:?}"
        );
    }

    /// A fresh message must NOT be caught by the pre-filter — otherwise the node silently stops
    /// participating in the mesh and everything still looks healthy.
    #[test]
    fn a_fresh_message_passes_the_prefilter() {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let data = format!(r#"{{"msg_type":"HealthPing","timestamp":{now_ms},"sequence":1}}"#);
        assert!(!is_stale_before_deser(
            data.as_bytes(),
            DEFAULT_TIMESTAMP_DRIFT_MS
        ));
    }

    /// An unreadable timestamp must fall THROUGH to the real validator, never be assumed stale.
    ///
    /// Treating "cannot read" as "too old" would turn any envelope format change into a node
    /// that silently drops every message on the floor while reporting itself healthy.
    #[test]
    fn an_unreadable_timestamp_is_not_assumed_stale() {
        assert_eq!(extract_timestamp_fast(b"not json at all"), None);
        assert!(!is_stale_before_deser(
            b"not json at all",
            DEFAULT_TIMESTAMP_DRIFT_MS
        ));

        // Present but not a number.
        let odd = br#"{"msg_type":"HealthPing","timestamp":"soon"}"#;
        assert_eq!(extract_timestamp_fast(odd), None);
        assert!(!is_stale_before_deser(odd, DEFAULT_TIMESTAMP_DRIFT_MS));

        // Absent entirely.
        assert!(!is_stale_before_deser(
            br#"{"msg_type":"HealthPing"}"#,
            DEFAULT_TIMESTAMP_DRIFT_MS
        ));
    }

    /// The scan must read the ENVELOPE's timestamp, not one that happens to appear inside the
    /// payload — reading a payload field would judge the message on the wrong clock.
    #[test]
    fn the_envelope_timestamp_is_read_not_a_payload_one() {
        let envelope_ts = 1_700_000_000_000u64;
        let payload_ts = 1_600_000_000_000u64;
        let data = format!(
            r#"{{"msg_type":"HealthPing","sender":"00","timestamp":{envelope_ts},"sequence":1,"payload":{{"timestamp":{payload_ts}}}}}"#
        );
        assert_eq!(extract_timestamp_fast(data.as_bytes()), Some(envelope_ts));
    }
    use super::*;

    #[test]
    fn test_validate_header_too_small() {
        let data = vec![0u8; 10];
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::TooSmall(_))
        ));
    }

    #[test]
    fn test_validate_header_too_large() {
        let data = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::TooLarge(_))
        ));
    }

    #[test]
    fn test_validate_header_bad_version() {
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE];
        data[0] = 99; // Invalid version
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn test_validate_header_bad_type() {
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE];
        data[0] = 1; // Valid version
        data[1] = 99; // Invalid type
        assert!(matches!(
            validate_envelope_header(&data),
            Err(MessageValidationError::InvalidType(99))
        ));
    }

    #[test]
    fn test_payload_size_limits() {
        assert!(validate_payload_size(MessageType::Vote, 500).is_ok());
        assert!(validate_payload_size(MessageType::Vote, MAX_VOTE_SIZE + 1).is_err());
    }

    #[test]
    fn test_validation_stats() {
        let mut stats = ValidationStats::default();

        stats.record(&Err(MessageValidationError::TooSmall(10)));
        stats.record(&Err(MessageValidationError::InvalidSignature("abc".into())));

        assert_eq!(stats.total, 2);
        assert_eq!(stats.valid, 0);
        assert_eq!(stats.too_small, 1);
        assert_eq!(stats.bad_signature, 1);
        assert_eq!(stats.rejection_rate(), 1.0);
    }

    #[test]
    fn test_timestamp_validation_current() {
        // Current timestamp should be valid
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        assert!(validate_timestamp(now_ms).is_ok());
    }

    #[test]
    fn test_timestamp_validation_slight_future() {
        // Slightly in the future (20 seconds) should be valid
        // SEC-TIME-1: Using 20s to stay within 30s drift limit
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let future_ms = now_ms + 20_000; // 20 seconds ahead
        assert!(validate_timestamp(future_ms).is_ok());
    }

    #[test]
    fn test_timestamp_validation_slight_past() {
        // Slightly in the past (20 seconds) should be valid
        // SEC-TIME-1: Using 20s to stay within 30s drift limit
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let past_ms = now_ms - 20_000; // 20 seconds behind
        assert!(validate_timestamp(past_ms).is_ok());
    }

    #[test]
    fn test_timestamp_validation_too_far_future() {
        // 10 minutes in the future should be rejected
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let future_ms = now_ms + 10 * 60_000; // 10 minutes ahead
        assert!(matches!(
            validate_timestamp(future_ms),
            Err(MessageValidationError::TimestampInFuture(_))
        ));
    }

    #[test]
    fn test_l8_timestamp_drift_is_30_seconds() {
        // L-8: Verify the default drift is 30 seconds (not the old 60s)
        assert_eq!(DEFAULT_TIMESTAMP_DRIFT_MS, 30_000);
        assert_eq!(MAX_TIMESTAMP_DRIFT_MS, 30_000);

        // 40 seconds in the future should be rejected (beyond 30s limit)
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let future_40s = now_ms + 40_000;
        assert!(
            matches!(
                validate_timestamp(future_40s),
                Err(MessageValidationError::TimestampInFuture(_))
            ),
            "L-8: 40s drift should be rejected with 30s limit"
        );

        // 25 seconds should still be valid (within 30s limit)
        let future_25s = now_ms + 25_000;
        assert!(
            validate_timestamp(future_25s).is_ok(),
            "L-8: 25s drift should be valid with 30s limit"
        );
    }

    #[test]
    fn test_timestamp_validation_too_far_past() {
        // 10 minutes in the past should be rejected
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let past_ms = now_ms - 10 * 60_000; // 10 minutes behind
        assert!(matches!(
            validate_timestamp(past_ms),
            Err(MessageValidationError::TimestampInPast(_))
        ));
    }

    #[test]
    fn test_timestamp_validation_edge_case() {
        // Test values safely inside the boundary (100ms buffer avoids TOCTOU race
        // between our Utc::now() and validate_timestamp's internal Utc::now())
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let inside_future = now_ms + MAX_TIMESTAMP_DRIFT_MS - 100;
        let inside_past = now_ms - MAX_TIMESTAMP_DRIFT_MS + 100;

        assert!(
            validate_timestamp(inside_future).is_ok(),
            "100ms inside future boundary should be valid"
        );
        assert!(
            validate_timestamp(inside_past).is_ok(),
            "100ms inside past boundary should be valid"
        );

        // Test values clearly outside the boundary
        let outside_future = now_ms + MAX_TIMESTAMP_DRIFT_MS + 1000;
        let outside_past = now_ms - MAX_TIMESTAMP_DRIFT_MS - 1000;

        assert!(
            matches!(
                validate_timestamp(outside_future),
                Err(MessageValidationError::TimestampInFuture(_))
            ),
            "1s outside future boundary should be rejected"
        );
        assert!(
            matches!(
                validate_timestamp(outside_past),
                Err(MessageValidationError::TimestampInPast(_))
            ),
            "1s outside past boundary should be rejected"
        );
    }

    #[test]
    fn test_zero_signature_rejected() {
        // H-P2P-2: Test that zero signatures are rejected by validate_envelope
        let envelope = MessageEnvelope {
            msg_type: MessageType::Vote,
            sender: [1u8; 32],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
            signature: [0u8; 64], // Zero signature
            payload: vec![1, 2, 3],
            ttl: 10,
        };

        let result = validate_envelope(&envelope);
        assert!(matches!(result, Err(MessageValidationError::ZeroSignature)));
    }

    #[test]
    fn test_non_zero_signature_passes_validation() {
        // Non-zero signature should pass the zero check (actual sig verification is separate)
        let envelope = MessageEnvelope {
            msg_type: MessageType::Vote,
            sender: [1u8; 32],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
            signature: [1u8; 64], // Non-zero signature (but invalid - that's ok for this test)
            payload: vec![1, 2, 3],
            ttl: 10,
        };

        // Should pass validate_envelope (signature validity check is separate)
        let result = validate_envelope(&envelope);
        assert!(result.is_ok());
    }

    // P2P-H1: Tests for extract_message_type_fast and validate_topic_before_deser

    #[test]
    fn test_extract_message_type_from_json() {
        // Valid JSON with msg_type field
        let json = r#"{"msg_type":"HealthPing","sender":"abc123","timestamp":1234567890}"#;
        let data = json.as_bytes();

        // Need enough bytes to pass size check
        let mut padded = data.to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(MessageType::HealthPing));
    }

    #[test]
    fn test_extract_message_type_vote() {
        let json = r#"{"msg_type":"Vote","sender":"abc123"}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), Some(MessageType::Vote));
    }

    #[test]
    fn test_extract_message_type_share_proof() {
        let json = r#"{"msg_type":"ShareProof","data":"..."}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), Some(MessageType::ShareProof));
    }

    #[test]
    fn test_extract_message_type_unknown() {
        let json = r#"{"msg_type":"UnknownType","data":"..."}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), None); // Unknown type returns None
    }

    #[test]
    fn test_extract_message_type_no_type_field() {
        let json = r#"{"sender":"abc123","timestamp":1234567890}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = extract_message_type_fast(&padded);
        assert_eq!(result.unwrap(), None); // No msg_type field returns None
    }

    #[test]
    fn test_validate_topic_correct_type() {
        let json = r#"{"msg_type":"HealthPing","sender":"abc123"}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        // Should pass when expected type matches
        let result = validate_topic_before_deser(&padded, MessageType::HealthPing);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_topic_wrong_type() {
        let json = r#"{"msg_type":"Vote","sender":"abc123"}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        // Should fail when expected type doesn't match
        let result = validate_topic_before_deser(&padded, MessageType::HealthPing);
        assert!(matches!(
            result,
            Err(MessageValidationError::InvalidType(255))
        ));
    }

    #[test]
    fn test_validate_topic_missing_type_passes() {
        // When type can't be extracted, we pass validation
        // (will be validated after full deserialization)
        let json = r#"{"sender":"abc123","timestamp":1234567890}"#;
        let mut padded = json.as_bytes().to_vec();
        padded.resize(MIN_ENVELOPE_SIZE + 100, b' ');

        let result = validate_topic_before_deser(&padded, MessageType::HealthPing);
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_binary_format() {
        // Binary format: version(1) + type(1) + rest
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE + 10];
        data[0] = 1; // Version 1
        data[1] = 4; // MessageType::HealthPing

        let result = extract_message_type_fast(&data);
        assert_eq!(result.unwrap(), Some(MessageType::HealthPing));
    }

    #[test]
    fn test_extract_binary_format_invalid_type() {
        let mut data = vec![0u8; MIN_ENVELOPE_SIZE + 10];
        data[0] = 1; // Version 1
        data[1] = 99; // Invalid type

        let result = extract_message_type_fast(&data);
        assert_eq!(result.unwrap(), None);
    }

    // =========================================================================
    // L-13 TESTS: Aggregate memory limit
    // =========================================================================

    #[test]
    fn test_l13_aggregate_limit_constant() {
        // L-13: Verify limit is 100MB
        assert_eq!(AGGREGATE_PENDING_MESSAGE_LIMIT_BYTES, 100 * 1024 * 1024);
    }

    #[test]
    fn test_l13_tracker_creation() {
        let tracker = AggregateMemoryTracker::new();
        assert_eq!(tracker.current_bytes(), 0);
        assert_eq!(tracker.limit_bytes(), AGGREGATE_PENDING_MESSAGE_LIMIT_BYTES);
    }

    #[test]
    fn test_l13_tracker_custom_limit() {
        let tracker = AggregateMemoryTracker::with_limit(1000);
        assert_eq!(tracker.limit_bytes(), 1000);
    }

    #[test]
    fn test_l13_reserve_and_release() {
        let tracker = AggregateMemoryTracker::with_limit(1000);

        // Reserve some space
        assert!(tracker.try_reserve(500).is_ok());
        assert_eq!(tracker.current_bytes(), 500);

        // Reserve more
        assert!(tracker.try_reserve(400).is_ok());
        assert_eq!(tracker.current_bytes(), 900);

        // This would exceed the limit
        assert!(tracker.try_reserve(200).is_err());
        assert_eq!(tracker.current_bytes(), 900); // Unchanged

        // Release some
        tracker.release(500);
        assert_eq!(tracker.current_bytes(), 400);

        // Now we can reserve more
        assert!(tracker.try_reserve(500).is_ok());
        assert_eq!(tracker.current_bytes(), 900);
    }

    #[test]
    fn test_l13_usage_percent() {
        let tracker = AggregateMemoryTracker::with_limit(1000);

        tracker.try_reserve(500).unwrap();
        assert!((tracker.usage_percent() - 50.0).abs() < 0.01);

        tracker.try_reserve(300).unwrap();
        assert!((tracker.usage_percent() - 80.0).abs() < 0.01);
    }

    #[test]
    fn test_l13_high_usage_detection() {
        let tracker = AggregateMemoryTracker::with_limit(1000);

        tracker.try_reserve(799).unwrap();
        assert!(!tracker.is_high_usage()); // 79.9% < 80%

        tracker.try_reserve(2).unwrap();
        assert!(tracker.is_high_usage()); // 80.1% > 80%
    }

    #[test]
    fn test_l13_reset() {
        let tracker = AggregateMemoryTracker::with_limit(1000);
        tracker.try_reserve(500).unwrap();
        assert_eq!(tracker.current_bytes(), 500);

        tracker.reset();
        assert_eq!(tracker.current_bytes(), 0);
    }

    #[test]
    fn test_l13_stats_memory_limit_field() {
        let mut stats = ValidationStats::default();
        assert_eq!(stats.memory_limit_exceeded, 0);

        stats.memory_limit_exceeded += 1;
        assert_eq!(stats.memory_limit_exceeded, 1);
    }
}
