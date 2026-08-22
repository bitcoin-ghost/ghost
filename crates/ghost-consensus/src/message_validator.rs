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
/// One signed endpoint advert. Generous against a long hostname while still far below any
/// bound that would let a peer spend our bandwidth: 2 KiB.
pub const MAX_MESH_ENDPOINT_ADVERT_SIZE: usize = 2 * 1024;

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

// ─── Share-shard caps (docs/SHARE_SHARD.md) ──────────────────────────────────
//
// All three are DERIVED, not guessed — guessed caps are how #558 happened, and every derivation
// below is pinned by a `shard_caps_*` test so the arithmetic cannot rot silently.
//
// The other half of the derivation is the ENVELOPE: `MessageEnvelope.payload` is `Vec<u8>`, which
// serde_json writes as decimal integers — ~3.7x for the ASCII JSON these payloads are. A per-type
// cap the 1 MB envelope cannot carry after that expansion is a message that validates locally and
// never arrives, so every cap here must satisfy `cap * 4 + overhead <= MAX_ENVELOPE_SIZE`
// (4 is the conservative ceiling of the measured ~3.1–3.7x).

/// Share-shard epoch summary (`ShardEpochSummaryMessage`).
///
/// Per address row of `EpochSummary.deltas` as JSON:
/// `"<addr>":{"delta_micro":N,"total_micro":N}` with a 62-byte bech32m address and two
/// 19-digit i64s ≈ 135 bytes; budget 160 with separators. Address budget: 1,000 rows — the live
/// fleet pays 4 distinct addresses and the design's whole NETWORK shard is "a few hundred rows"
/// (§4.3), so 1,000 for a single node's single epoch is growth headroom, not a fit.
/// Fixed fields (node_id as a 32-int array ~128, signature as a 64-int array ~256, hex root 66,
/// epoch/count/keys ~150) ≈ 600.
///
///   1,000 rows × 160 + 600 ≈ 161 KB  →  cap 200 KB (~25% headroom)
///   envelope: 200 KB × 4 = 800 KB ≤ 1 MB ✓
pub const MAX_SHARD_SUMMARY_SIZE: usize = 200_000;

/// Share-shard whole-table sync (`ShardTableSyncMessage`).
///
/// ⚠ A table sync is `nodes × addresses`, not addresses alone — it grows with fleet size in a
/// way a summary does not. Per cell as JSON: `["<addr>",N]` ≈ 88 bytes worst case; per column
/// ~110 bytes of node-id/wrapper overhead.
///
/// This cap is set by the ENVELOPE, not by a content budget: the largest raw payload the 1 MB
/// envelope can deliver after the ~4x `Vec<u8>`-as-integers expansion is
/// `(1,000,000 − 2,000) / 4 = 249,500`. That carries ≈ 2,800 cells — e.g. the 8-node fleet ×
/// 350 addresses, or 20 nodes × 140 — against the design's own ~15 KB estimate (§4.4), ~16x
/// headroom. Beyond ~3,000 cells (§10's 100-node × 500-address scenario is 50,000) a single
/// §12.6 whole-table message CANNOT fit any envelope and the exchange needs pagination — flagged
/// in the design review, deliberately not invented here.
pub const MAX_SHARD_TABLE_SYNC_SIZE: usize = (MAX_ENVELOPE_SIZE - 2_000) / 4;

/// Share-shard bad-share evidence (`ShardEvidenceMessage`).
///
/// Carries a whole `EpochSummary`, one share, and a Merkle path, so the cap is the SUM of what
/// its parts are allowed to be — an evidence message must be able to carry ANY summary that
/// itself passed `MAX_SHARD_SUMMARY_SIZE`, or the biggest liars would be the ones that cannot
/// be reported:
///
///   summary ≤ 200,000, share ≤ 10,000 (`MAX_SHARE_PROOF_SIZE`), Merkle path ≤ 64 hashes
///   × 70 hex-encoded = 4,480, reporter/signature/keys ≈ 1,000: together ≈ 215.5 KB
///   →  cap 240 KB; envelope: 240 KB × 4 = 960 KB ≤ 1 MB ✓
pub const MAX_SHARD_EVIDENCE_SIZE: usize = 240_000;

/// The most leaf indices one `ShardSampleRequestMessage` may name.
///
/// The default sample is λ = 20 (§6/§9), so 4,096 is two orders of magnitude of headroom for
/// deliberately heavier audits — while "audit EVERY leaf of a large epoch" is a paged exchange
/// (several requests), not one message, exactly as §12.6 repair is.
pub const MAX_SAMPLE_REQUEST_INDICES: usize = 4_096;

/// Share-shard sample request (`ShardSampleRequestMessage`).
///
/// Per index as JSON: a u32 is ≤ 10 digits plus a separator = 11 bytes, so
/// [`MAX_SAMPLE_REQUEST_INDICES`] × 11 = 45,056. Fixed fields: two hex node ids ≈ 68 each, hex
/// root ≈ 68, epoch ≤ 20 digits, keys/braces ≈ 130 — together ≈ 350.
///
///   4,096 × 11 + 350 ≈ 45.4 KB  →  cap 50 KB (~10% headroom)
///   envelope: 50 KB × 4 = 200 KB ≤ 1 MB ✓
pub const MAX_SHARD_SAMPLE_REQUEST_SIZE: usize = 50_000;

/// Share-shard sample response (`ShardSampleResponseMessage`).
///
/// Set by the ENVELOPE, like the table sync: `(1,000,000 − 2,000) / 4 = 249,500` is the largest
/// raw payload the 1 MB envelope can deliver after the ~4x `Vec<u8>`-as-integers expansion.
///
/// What that carries, worst case per leaf — and a response must be able to serve ANY share that
/// itself passed `MAX_SHARE_PROOF_SIZE`, or the biggest liars would be the ones that cannot be
/// sampled: share ≤ 10,000, path ≤ 64 × 70 hex = 4,480, index/keys ≈ 120 → ≈ 14,600. Fixed
/// fields (ids, root, signature, keys) ≈ 700. Guaranteed floor: (249,500 − 700) / 14,600 =
/// **17 leaves of absolute-worst-case shares**, i.e. a default λ = 20 sample is NOT guaranteed
/// to fit one message when every share is cap-sized — which is why the response contract allows
/// answering a subset and the handler surfaces unanswered indices for a follow-up request. At
/// the measured live share size (~1.3 KB JSON, path ≤ 20 hashes) a λ = 20 response is ≈ 56 KB,
/// ~4.4x headroom.
pub const MAX_SHARD_SAMPLE_RESPONSE_SIZE: usize = (MAX_ENVELOPE_SIZE - 2_000) / 4;

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
            // ⚠ Gaps are deliberate and must STAY gaps. These are explicit byte literals, not
            // enum positions, so removing a dead type leaves a hole rather than shifting its
            // neighbours — which is what keeps a mixed fleet reading the same bytes the same way.
            // Never renumber to close a gap: an old peer's byte would then decode as a different
            // type entirely.
            0 => Some(MessageType::ShareProof),
            2 => Some(MessageType::PayoutProposal),
            3 => Some(MessageType::Vote),
            4 => Some(MessageType::HealthPing),
            5 => Some(MessageType::Discovery),
            7 => Some(MessageType::ShareConvergence),
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
        "Vote" => MessageType::Vote,
        "HealthPing" => MessageType::HealthPing,
        "Discovery" => MessageType::Discovery,
        "PayoutProposal" => MessageType::PayoutProposal,
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
        MessageType::Vote => MAX_VOTE_SIZE,
        MessageType::HealthPing => MAX_HEALTH_PING_SIZE,
        MessageType::Discovery => MAX_DISCOVERY_SIZE,
        MessageType::PayoutProposal => MAX_PAYOUT_PROPOSAL_SIZE,
        MessageType::VerificationResult => MAX_VERIFICATION_SIZE,
        MessageType::ChallengeConvergence => MAX_CHALLENGE_CONVERGENCE_SIZE,
        MessageType::EquivocationProof => MAX_EQUIVOCATION_PROOF_SIZE,
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
        MessageType::ShareBatchVote
        | MessageType::ShareBatchPrevote
        | MessageType::ShareBatchPrecommit => MAX_SHARE_BATCH_VOTE_SIZE,
        MessageType::ShareBatchSync => MAX_SHARE_BATCH_SYNC_SIZE,
        MessageType::MeshNodeListCheckpoint => MAX_PAYOUT_PROPOSAL_SIZE,
        MessageType::MeshNodeListCheckpointVote => MAX_VOTE_SIZE,
        MessageType::MeshNodeListCheckpointSync => MAX_PAYOUT_SYNC_SIZE,
        // One advert: a 32-byte id, a host string, two ports, a flag, a seq and a 64-byte
        // signature — a few hundred bytes hex-encoded. Its OWN bound rather than borrowing a
        // neighbour's: a type that falls into someone else's limit is how an oversized payload
        // gets through the one check meant to stop it.
        MessageType::MeshEndpointAdvertisement => MAX_MESH_ENDPOINT_ADVERT_SIZE,
        // Share shard: each type has its own derived bound — see the constants for the
        // arithmetic. A type that silently falls into someone else's bound is how a payload
        // ends up rejected for a reason nobody wrote down.
        MessageType::ShardEpochSummary => MAX_SHARD_SUMMARY_SIZE,
        MessageType::ShardTableSync => MAX_SHARD_TABLE_SYNC_SIZE,
        MessageType::ShardEvidence => MAX_SHARD_EVIDENCE_SIZE,
        MessageType::ShardSampleRequest => MAX_SHARD_SAMPLE_REQUEST_SIZE,
        MessageType::ShardSampleResponse => MAX_SHARD_SAMPLE_RESPONSE_SIZE,
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
    // Reconstruct the signed bytes for the format this envelope declares. A version we cannot
    // reconstruct is a version we cannot authenticate, so it is an invalid signature and not a
    // deserialisation error — the message must be dropped, never trusted.
    let signed_data = match envelope.signing_bytes() {
        Ok(bytes) => bytes,
        Err(e) => {
            let sender_hex = hex::encode(&envelope.sender[..8]);
            warn!(
                sender = %sender_hex,
                msg_type = ?envelope.msg_type,
                envelope_version = envelope.version,
                error = %e,
                "Cannot reconstruct envelope signing bytes — rejecting"
            );
            return Err(MessageValidationError::InvalidSignature(sender_hex));
        }
    };

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

    /// Every share-shard type resolves to its OWN derived bound, and the bound is enforced at
    /// exactly the declared cap. A type that silently falls into someone else's bound is how a
    /// payload ends up rejected for a reason nobody wrote down (#558).
    #[test]
    fn shard_caps_are_dedicated_and_enforced() {
        let cases = [
            (MessageType::ShardEpochSummary, MAX_SHARD_SUMMARY_SIZE),
            (MessageType::ShardTableSync, MAX_SHARD_TABLE_SYNC_SIZE),
            (MessageType::ShardEvidence, MAX_SHARD_EVIDENCE_SIZE),
            (
                MessageType::ShardSampleRequest,
                MAX_SHARD_SAMPLE_REQUEST_SIZE,
            ),
            (
                MessageType::ShardSampleResponse,
                MAX_SHARD_SAMPLE_RESPONSE_SIZE,
            ),
        ];
        for (msg_type, cap) in cases {
            assert_eq!(
                max_payload_size(msg_type),
                cap,
                "{msg_type:?} bound mismatch"
            );
            assert!(
                validate_payload_size(msg_type, cap).is_ok(),
                "{msg_type:?}: a payload AT the cap must pass"
            );
            assert!(
                validate_payload_size(msg_type, cap + 1).is_err(),
                "{msg_type:?}: one byte over the cap must be refused"
            );
        }
    }

    /// The other half of #558: `MessageEnvelope.payload` is `Vec<u8>`, serialised as decimal
    /// integers (~3.7x for ASCII JSON), and the ENVELOPE has its own 1 MB cap. A per-type cap
    /// the envelope cannot carry after expansion is a message that validates locally and never
    /// arrives — the sender sees success, the receiver sees `TooLarge`, nobody sees why.
    #[test]
    fn shard_caps_survive_the_envelope_expansion() {
        const CONSERVATIVE_EXPANSION: usize = 4; // ceiling of the measured ~3.1–3.7x
        const ENVELOPE_OVERHEAD: usize = 2_000; // sender/signature/sequence/keys
        for (name, cap) in [
            ("summary", MAX_SHARD_SUMMARY_SIZE),
            ("table sync", MAX_SHARD_TABLE_SYNC_SIZE),
            ("evidence", MAX_SHARD_EVIDENCE_SIZE),
            ("sample request", MAX_SHARD_SAMPLE_REQUEST_SIZE),
            ("sample response", MAX_SHARD_SAMPLE_RESPONSE_SIZE),
        ] {
            assert!(
                cap * CONSERVATIVE_EXPANSION + ENVELOPE_OVERHEAD <= MAX_ENVELOPE_SIZE,
                "shard {name} cap {cap} cannot be delivered: {} bytes on the wire against the \
                 {MAX_ENVELOPE_SIZE} envelope cap",
                cap * CONSERVATIVE_EXPANSION + ENVELOPE_OVERHEAD
            );
        }
    }

    /// The summary cap is derived from a stated budget — 1,000 addresses, max-length bech32m,
    /// i64-max values — so MEASURE that budget against the cap instead of trusting the comment's
    /// arithmetic. If an encoding change inflates rows, this fails here rather than in the fleet.
    #[test]
    fn a_budgeted_worst_case_summary_fits_its_cap() {
        use ghost_common::share_shard::{EpochDelta, EpochSummary};
        use std::collections::BTreeMap;

        let mut deltas = BTreeMap::new();
        for i in 0..1_000u32 {
            // 62-char addresses — the bech32m maximum.
            let addr = format!("bc1q{:058}", i);
            assert_eq!(addr.len(), 62);
            deltas.insert(
                addr,
                EpochDelta {
                    delta_micro: i64::MAX,
                    total_micro: i64::MAX,
                },
            );
        }
        let msg = crate::message::ShardEpochSummaryMessage {
            summary: EpochSummary {
                epoch: u64::MAX,
                node_id: [0xAB; 32],
                deltas,
                genesis_marker: None,
                share_count: u32::MAX,
                share_root: [0xCD; 32],
                signature: vec![0xEE; 64],
            },
        };
        let payload = serde_json::to_vec(&msg).expect("serialises");
        assert!(
            payload.len() <= MAX_SHARD_SUMMARY_SIZE,
            "budgeted worst-case summary is {} bytes against the {MAX_SHARD_SUMMARY_SIZE} cap",
            payload.len()
        );
    }

    /// Same discipline for the table sync, whose payload is nodes × addresses — it grows with
    /// fleet size in a way a summary does not. Budget: 8 nodes × 300 max-length addresses at
    /// i64-max, i.e. today's fleet with ~75x the live payout-address count.
    #[test]
    fn a_budgeted_worst_case_table_sync_fits_its_cap() {
        use crate::message::{ShardColumn, ShardTableSyncMessage};

        let columns: Vec<ShardColumn> = (0..8u8)
            .map(|n| ShardColumn {
                node_id: [n; 32],
                cells: (0..300u32)
                    .map(|i| (format!("bc1q{:058}", i), i64::MAX))
                    .collect(),
            })
            .collect();
        let msg = ShardTableSyncMessage::Response {
            responding_node: [0xAA; 32],
            columns,
            table_root: [0xBB; 32],
            signature: vec![0xCC; 64],
        };
        let payload = serde_json::to_vec(&msg).expect("serialises");
        assert!(
            payload.len() <= MAX_SHARD_TABLE_SYNC_SIZE,
            "budgeted worst-case table sync is {} bytes against the {MAX_SHARD_TABLE_SYNC_SIZE} cap",
            payload.len()
        );
    }

    /// An evidence message must be able to carry ANY summary that itself passed the summary
    /// cap, plus a maximal share and Merkle path — otherwise the biggest liars are exactly the
    /// ones that cannot be reported.
    ///
    /// Deliberately an assertion over constants: the RELATIONSHIP between the caps is the
    /// invariant, and it must fail here if someone tunes one cap without the others.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn the_evidence_cap_can_carry_any_capped_summary() {
        const MAX_MERKLE_PATH_BYTES: usize = 64 * 70; // 64 hashes, hex-encoded with quotes
        const EVIDENCE_FIXED_OVERHEAD: usize = 1_000; // reporter, signature, index, keys
        assert!(
            MAX_SHARD_EVIDENCE_SIZE
                >= MAX_SHARD_SUMMARY_SIZE
                    + MAX_SHARE_PROOF_SIZE
                    + MAX_MERKLE_PATH_BYTES
                    + EVIDENCE_FIXED_OVERHEAD,
            "evidence cap cannot carry a cap-sized summary plus its share and path"
        );
    }

    /// The sample-request cap is derived from a stated budget — [`MAX_SAMPLE_REQUEST_INDICES`]
    /// ten-digit indices plus the fixed fields — so MEASURE that budget against the cap instead
    /// of trusting the comment's arithmetic.
    #[test]
    fn a_budgeted_worst_case_sample_request_fits_its_cap() {
        use crate::message::ShardSampleRequestMessage;

        let msg = ShardSampleRequestMessage {
            epoch: u64::MAX,
            target_node: [0xAB; 32],
            share_root: [0xCD; 32],
            // Every index at the ten-digit u32 maximum — the widest a legal index serialises.
            leaf_indices: vec![u32::MAX; MAX_SAMPLE_REQUEST_INDICES],
            requesting_node: [0xEF; 32],
        };
        let payload = serde_json::to_vec(&msg).expect("serialises");
        assert!(
            payload.len() <= MAX_SHARD_SAMPLE_REQUEST_SIZE,
            "budgeted worst-case sample request is {} bytes against the \
             {MAX_SHARD_SAMPLE_REQUEST_SIZE} cap",
            payload.len()
        );
    }

    /// Both halves of the sample-response derivation, measured:
    ///
    /// - the guaranteed floor — 17 leaves each carrying a CAP-SIZED share and a maximal path —
    ///   must fit, or the biggest liars are exactly the ones that cannot be sampled;
    /// - a realistic default sample — λ = 20 leaves at live share size — must fit comfortably,
    ///   or the default exchange needs pagination on day one.
    #[test]
    fn a_budgeted_worst_case_sample_response_fits_its_cap() {
        use crate::message::{ShardSampleLeaf, ShardSampleResponseMessage};
        use ghost_common::types::ShareProof;

        // A share padded to the single-share cap via its widest variable field. What matters is
        // total serialised size, not field realism: the cap argument is byte arithmetic.
        let cap_sized_share = |i: u32| {
            let mut s = ShareProof {
                round_id: u64::MAX,
                miner_id: [0xAA; 32],
                difficulty: f64::MAX,
                work: f64::MAX,
                share_hash: [i as u8; 32],
                timestamp: u64::MAX,
                received_by: [0xBB; 32],
                template_id: Some([0xCC; 32]),
                payout_address: Some(format!("bc1q{:058}", i)),
                header: Some(vec![0xDD; 80]),
                tier_log2: Some(u32::MAX),
                signature: Some(vec![0xEE; 64]),
            };
            // Grow the header until the serialised share reaches MAX_SHARE_PROOF_SIZE.
            let base = serde_json::to_vec(&s).expect("serialises").len();
            let room = MAX_SHARE_PROOF_SIZE.saturating_sub(base);
            // `Vec<u8>` serialises as decimal integers, ≤ 4 bytes per element ("255,").
            s.header = Some(vec![0xDD; 80 + room / 4]);
            let got = serde_json::to_vec(&s).expect("serialises").len();
            assert!(
                got <= MAX_SHARE_PROOF_SIZE && got > MAX_SHARE_PROOF_SIZE - 200,
                "padding missed the single-share cap: {got}"
            );
            s
        };

        let worst = ShardSampleResponseMessage {
            epoch: u64::MAX,
            responding_node: [0xAB; 32],
            share_root: [0xCD; 32],
            leaves: (0..17u32)
                .map(|i| ShardSampleLeaf {
                    leaf_index: u32::MAX,
                    share: cap_sized_share(i),
                    merkle_proof: vec![[0xEF; 32]; 64],
                })
                .collect(),
            signature: vec![0xFF; 64],
        };
        let payload = serde_json::to_vec(&worst).expect("serialises");
        assert!(
            payload.len() <= MAX_SHARD_SAMPLE_RESPONSE_SIZE,
            "17 absolute-worst-case leaves are {} bytes against the \
             {MAX_SHARD_SAMPLE_RESPONSE_SIZE} cap — the guaranteed floor is broken",
            payload.len()
        );

        // The realistic default: λ = 20 live-sized shares (~1.2 KB proof blob measured on the
        // fleet, 2026-08-12) with 20-hash paths (a million-leaf epoch).
        let realistic = ShardSampleResponseMessage {
            epoch: u64::MAX,
            responding_node: [0xAB; 32],
            share_root: [0xCD; 32],
            leaves: (0..20u32)
                .map(|i| {
                    let mut share = cap_sized_share(i);
                    share.header = Some(vec![0xDD; 80]);
                    ShardSampleLeaf {
                        leaf_index: i,
                        share,
                        merkle_proof: vec![[0xEF; 32]; 20],
                    }
                })
                .collect(),
            signature: vec![0xFF; 64],
        };
        let payload = serde_json::to_vec(&realistic).expect("serialises");
        assert!(
            payload.len() * 2 <= MAX_SHARD_SAMPLE_RESPONSE_SIZE,
            "a realistic λ=20 response is {} bytes — over half the \
             {MAX_SHARD_SAMPLE_RESPONSE_SIZE} cap, the default exchange has no headroom",
            payload.len()
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
    use crate::message::ENVELOPE_VERSION_V1;

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
            version: ENVELOPE_VERSION_V1,
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
            version: ENVELOPE_VERSION_V1,
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

/// H-11: what [`verify_envelope_signature`] accepts and refuses across the two signing formats.
///
/// These sit at the verifier rather than in `message.rs` because the claim that matters for the
/// deploy is not "the preimages differ" — it is "this binary accepts both, and refuses a replay of
/// either". A preimage test cannot show the second half.
#[cfg(test)]
mod envelope_version_tolerance_tests {
    use super::*;
    use crate::message::{ENVELOPE_VERSION_V1, ENVELOPE_VERSION_V2};
    use ghost_common::identity::NodeIdentity;

    fn signed(identity: &NodeIdentity, version: u8, msg_type: MessageType) -> MessageEnvelope {
        MessageEnvelope::signed(
            version,
            msg_type,
            identity.node_id(),
            b"a share proof would go here".to_vec(),
            77,
            8,
            |bytes| identity.sign(bytes),
        )
        .expect("sign envelope")
    }

    /// **The mixed-version fleet claim, as an assertion.** One binary, both formats, both
    /// accepted. This is what makes it safe to roll this release across eight nodes that restart
    /// at different times: an upgraded node keeps accepting its un-upgraded peers, and once the
    /// gate eventually arms it keeps accepting anything still emitting v1.
    #[test]
    fn both_signing_formats_verify_on_the_same_binary() {
        let identity = NodeIdentity::generate();

        for version in [ENVELOPE_VERSION_V1, ENVELOPE_VERSION_V2] {
            let env = signed(&identity, version, MessageType::ShareProof);
            assert!(
                verify_envelope_signature(&env).is_ok(),
                "v{version} envelope must verify — a receiver that refuses one of the two \
                 partitions the mesh"
            );
        }
    }

    /// H-11, at the verifier. A captured envelope re-stamped with a fresh timestamp is what walks
    /// a replay past the ±30 s drift window indefinitely. v1 cannot tell; v2 must.
    ///
    /// The v1 half is asserted deliberately: it documents the live hole this release does not yet
    /// close, and it fails the moment someone believes it is closed before the gate is armed.
    #[test]
    fn restamping_a_captured_envelope_defeats_v1_and_is_caught_by_v2() {
        let identity = NodeIdentity::generate();

        let mut v1 = signed(&identity, ENVELOPE_VERSION_V1, MessageType::ShareProof);
        v1.timestamp += 3_600_000;
        assert!(
            verify_envelope_signature(&v1).is_ok(),
            "v1 is expected to accept a re-stamped envelope — that IS finding H-11"
        );

        let mut v2 = signed(&identity, ENVELOPE_VERSION_V2, MessageType::ShareProof);
        v2.timestamp += 3_600_000;
        assert!(
            matches!(
                verify_envelope_signature(&v2),
                Err(MessageValidationError::InvalidSignature(_))
            ),
            "v2 must refuse a re-stamped envelope"
        );
    }

    /// Re-typing between two message types that share a ZMQ topic delivers a signed payload to a
    /// handler its signer never addressed. `topic()` cannot distinguish them, so only the
    /// signature can.
    #[test]
    fn retyping_across_a_shared_topic_is_caught_by_v2() {
        let identity = NodeIdentity::generate();

        let mut v1 = signed(&identity, ENVELOPE_VERSION_V1, MessageType::ShareProof);
        v1.msg_type = MessageType::ShareConvergence;
        assert!(
            verify_envelope_signature(&v1).is_ok(),
            "v1 is expected to accept a re-typed envelope — that IS finding H-11"
        );

        let mut v2 = signed(&identity, ENVELOPE_VERSION_V2, MessageType::ShareProof);
        v2.msg_type = MessageType::ShareConvergence;
        assert!(
            matches!(
                verify_envelope_signature(&v2),
                Err(MessageValidationError::InvalidSignature(_))
            ),
            "v2 must refuse a re-typed envelope"
        );
    }

    /// Forwarding decrements `ttl`, and every message on the mesh is forwarded up to eight times.
    /// If v2 bound `ttl` the format would look correct in every unit test and fail on the wire at
    /// the second hop.
    #[test]
    fn a_forwarded_v2_envelope_still_verifies() {
        let identity = NodeIdentity::generate();
        let mut env = signed(&identity, ENVELOPE_VERSION_V2, MessageType::HealthPing);

        for _ in 0..8 {
            assert!(env.decrement_ttl());
        }

        assert!(
            verify_envelope_signature(&env).is_ok(),
            "a relayed v2 envelope must still verify"
        );
    }

    /// Claiming a version the binary cannot reconstruct must be a REJECTION, not a panic and not
    /// a pass. A future v3 emitted early would otherwise be the same silent-drop trap
    /// `CapabilityType` set.
    #[test]
    fn an_unknown_claimed_version_is_rejected_not_trusted() {
        let identity = NodeIdentity::generate();
        let mut env = signed(&identity, ENVELOPE_VERSION_V2, MessageType::ShareProof);
        env.version = 3;

        assert!(matches!(
            verify_envelope_signature(&env),
            Err(MessageValidationError::InvalidSignature(_))
        ));
    }

    /// Flipping the version field is not a downgrade attack: the field SELECTS the preimage, so a
    /// flip makes the receiver reconstruct different bytes and the signature fails. Pinning this
    /// is why the field itself needs no integrity protection.
    #[test]
    fn flipping_the_version_field_invalidates_the_signature_in_both_directions() {
        let identity = NodeIdentity::generate();

        let mut down = signed(&identity, ENVELOPE_VERSION_V2, MessageType::ShareProof);
        down.version = ENVELOPE_VERSION_V1;
        assert!(matches!(
            verify_envelope_signature(&down),
            Err(MessageValidationError::InvalidSignature(_))
        ));

        let mut up = signed(&identity, ENVELOPE_VERSION_V1, MessageType::ShareProof);
        up.version = ENVELOPE_VERSION_V2;
        assert!(matches!(
            verify_envelope_signature(&up),
            Err(MessageValidationError::InvalidSignature(_))
        ));
    }

    /// End to end through the real inbound pipeline, not just the signature step: header checks,
    /// staleness prefilter, depth scan, deserialisation, field validation, signature. A v2
    /// envelope has to survive all of it, including `extract_timestamp_fast`, which scans for the
    /// FIRST `"timestamp":` in the JSON and would misread it if the new field shifted the layout.
    #[test]
    fn a_v2_envelope_survives_the_whole_inbound_pipeline() {
        let identity = NodeIdentity::generate();
        let env = signed(&identity, ENVELOPE_VERSION_V2, MessageType::ShareProof);
        let bytes = env.serialize().expect("serialise");

        assert_eq!(
            extract_timestamp_fast(&bytes),
            Some(env.timestamp),
            "the version field must not displace the timestamp the fast path scans for"
        );

        let parsed =
            validate_and_verify(&bytes).expect("v2 envelope must pass validate_and_verify");
        assert_eq!(parsed.version, ENVELOPE_VERSION_V2);
    }
}
