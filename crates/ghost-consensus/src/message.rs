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
//| FILE: message.rs                                                                                                     |
//|======================================================================================================================|

//! Consensus message types

use serde::{Deserialize, Serialize};

use ghost_common::types::{HealthPing, NodeCapabilities, NodeId};

/// Topic prefixes for ZMQ messages
pub mod topics {
    /// Health ping topic
    pub const HEALTH: &[u8] = b"health";
    /// Discovery topic
    pub const DISCOVERY: &[u8] = b"discovery";
}

/// Default TTL for gossip messages (number of hops before message is dropped)
pub const DEFAULT_MESSAGE_TTL: u8 = 8;

/// Minimum TTL for messages to be forwarded (messages with TTL 0 are not forwarded)
pub const MIN_FORWARD_TTL: u8 = 1;

/// Mesh envelope signing format 1: the preimage is `payload || sequence_le`, and nothing else.
///
/// `msg_type`, `timestamp` and `ttl` are outside it. A relay can therefore re-type a captured
/// envelope (`topic()` is not injective — `ShareProof` and `ShareConvergence` share `topics::SHARE`)
/// and can re-stamp its `timestamp` to defeat the ±30 s drift check in
/// [`crate::message_validator::validate_timestamp`]. That is audit finding H-11.
pub const ENVELOPE_VERSION_V1: u8 = 1;

/// Mesh envelope signing format 2: a domain-separated, length-prefixed preimage that binds
/// `sender`, `msg_type`, `timestamp`, `sequence` and `payload`.
///
/// `ttl` is deliberately still excluded — it is decremented on every forward by design
/// ([`MessageEnvelope::decrement_ttl`]), so binding it would invalidate the signature at the first
/// hop. Nothing trusts `ttl` beyond deciding whether to relay.
///
/// Binding `timestamp` is what turns the drift window into a real replay bound: an attacker
/// replaying a captured envelope can no longer move it forward, so it dies on
/// `validate_timestamp` once it is `DEFAULT_TIMESTAMP_DRIFT_MS` old — with no dependence on
/// per-sender sequence state surviving in memory.
pub const ENVELOPE_VERSION_V2: u8 = 2;

/// Domain separator for [`ENVELOPE_VERSION_V2`] preimages.
///
/// Its purpose is cross-protocol separation: every other signature this node produces over a
/// mesh-adjacent structure (`VerificationResultMessage::signing_data`, `EquivocationProof`,
/// GHOST-09 share binding) is a bare concatenation under the SAME ed25519 key. Without a prefix
/// that is unique to this structure, a preimage from one of them could in principle be presented
/// as a valid envelope for the other. The trailing NUL keeps the tag unambiguous against any
/// future `…/v2x` sibling.
const ENVELOPE_V2_DOMAIN: &[u8] = b"ghost/mesh/envelope/v2\0";

/// Serde default for [`MessageEnvelope::version`]: an envelope from a node that predates the
/// field carries no `v` key, and such a node signs the v1 preimage.
fn default_envelope_version() -> u8 {
    ENVELOPE_VERSION_V1
}

/// Keeps the pre-gate wire bytes byte-for-byte identical to what a pre-`v` binary emits.
///
/// This is load-bearing for the mixed-fleet roll, not cosmetics: while the gate is closed a new
/// node's envelope is indistinguishable from an old node's, so there is no window in which the
/// new binary is emitting something an old peer has never seen.
fn is_envelope_v1(version: &u8) -> bool {
    *version == ENVELOPE_VERSION_V1
}

/// Height at and above which this node SIGNS mesh envelopes with [`ENVELOPE_VERSION_V2`].
///
/// `u64::MAX` = never. **DORMANT.** Arming is a separate, observed change and must not ride the
/// release that introduces the tolerance.
///
/// This is an emit-side gate only. There is deliberately no matching verify-side gate: a receiver
/// picks the preimage from the envelope's own `v` field, so a v2 node accepts v1 and v2
/// simultaneously and forever, and needs no notion of height to do it.
/// [`crate::message_validator::validate_and_verify`] is a free function over `&[u8]` with no
/// access to a chain tip, and threading one into it would have bought nothing.
///
/// ⛔ Why a height and not a config flag: a node that signs v2 while a peer still verifies v1
/// has every one of its messages rejected as `InvalidSignature` by that peer — silently, from the
/// sender's point of view, because rejection happens at the far end. `CapabilityType` already
/// taught this fleet the cost of emitting before every receiver tolerates (see
/// `ghost-mining`'s `ADDRESS_PROOF_HEIGHT`). A height makes the flip simultaneous across eight nodes
/// that do not coordinate restarts.
///
/// The order is fixed and cannot be shortened:
/// 1. ship this release — every node VERIFIES both formats, every node EMITS v1;
/// 2. roll all eight and confirm each is on the new binary;
/// 3. only then set this constant to a height at least a few hundred blocks out, ship that, roll
///    again, and let the gate fire.
///
/// If the gate is armed while any node is on an older binary, that node rejects every mesh
/// message from every upgraded peer — total mesh partition, not degradation. There is no
/// self-healing path back other than upgrading it.
///
/// What to watch after it fires: `bad_signature` in [`crate::message_validator::ValidationStats`]
/// must stay flat, and `"Mesh envelope signing format"` is logged once per node at the flip.
///
/// ARMED at 966_400 on 2026-09-01. The fixed order above was completed, not shortened:
///
/// 1. The tolerance shipped in #740 (`d829c32f8`), which is an ancestor of the deployed commit —
///    so every node already VERIFIES both formats and EMITS v1.
/// 2. All eight were rolled to v1.11.33 at `bf3f822b5` and confirmed individually through
///    `--version`, which names the commit (#820) rather than only the version string.
/// 3. This is that separate, observed change. Observation before arming: `bad_signature` /
///    `InvalidSignature` were **0 across 6 hours** on the rolled binary.
///
/// 966_400 is deliberately ~400 blocks (~2.7 days) AFTER `ADDRESS_PROOF_HEIGHT`'s 966_000 rather
/// than sharing it. Both ride the same release, so if the mesh misbehaves in that window the
/// separation is what allows it to be attributed to one gate rather than two — the same reasoning
/// that placed `STRATUM_HANDSHAKE_PROOF_HEIGHT` clear of the gates already scheduled around it.
///
/// ⛔ The roll must reach ALL EIGHT before this height. This gate does not degrade: a node left
/// on an older binary rejects every mesh message from every upgraded peer, which is a partition,
/// and the only way back is to upgrade it.
pub const MESH_ENVELOPE_V2_HEIGHT: u64 = 966_400;

/// `ghost-mining`'s `ADDRESS_PROOF_HEIGHT`, mirrored so the separation between the two gates armed
/// in v1.11.34 can be asserted here.
///
/// A mirror, not an import: `ghost-consensus` sits BELOW `ghost-mining` in the dependency graph and
/// cannot reach it. Duplicating a consensus height is normally how the two drift apart, so this
/// exists only to be asserted against and is checked by
/// `bins/ghost-pool`'s `the_mirror_in_ghost_consensus_matches`.
pub const ADDRESS_PROOF_SEPARATION_REFERENCE: u64 = 966_000;

/// Resolved gate, so off-mainnet runs can rehearse the flip. Set once at startup by
/// `ghost_pool::init_activation_heights`; falls back to the shipped constant when unset.
static MESH_ENVELOPE_V2_GATE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Install the resolved [`MESH_ENVELOPE_V2_HEIGHT`] for this run. Call once, before the mesh
/// starts. Later calls are ignored, as are calls after the first read.
pub fn set_mesh_envelope_v2_height(height: u64) {
    let _ = MESH_ENVELOPE_V2_GATE.set(height);
}

/// The height at and above which this node signs [`ENVELOPE_VERSION_V2`].
pub fn mesh_envelope_v2_height() -> u64 {
    *MESH_ENVELOPE_V2_GATE.get_or_init(|| MESH_ENVELOPE_V2_HEIGHT)
}

/// Which signing format this node emits at `height`.
///
/// One predicate for the three places that build a signed envelope, so they cannot disagree about
/// which format is in force at a given block. An unknown height (0, the fallback when no L1
/// height provider is wired) resolves to v1 — the direction that cannot partition a mesh.
pub fn envelope_version_for_height(height: u64) -> u8 {
    if height >= mesh_envelope_v2_height() {
        ENVELOPE_VERSION_V2
    } else {
        ENVELOPE_VERSION_V1
    }
}

/// Failure to build a signing preimage.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EnvelopeSigningError {
    /// The envelope claims a signing format this binary does not implement. Treated as an invalid
    /// signature on receive: a version we cannot reconstruct is a version we cannot authenticate.
    #[error("unsupported mesh envelope signing version {0}")]
    UnsupportedVersion(u8),
    /// The message type could not be encoded for the preimage.
    #[error("could not encode message type for signing: {0}")]
    TypeTag(String),
}

/// Consensus message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Signing format of [`MessageEnvelope::signature`] — [`ENVELOPE_VERSION_V1`] or
    /// [`ENVELOPE_VERSION_V2`].
    ///
    /// Absent on the wire when it is v1, and absent entirely from envelopes built by binaries
    /// that predate the field, which is why the serde default is v1 rather than "latest".
    ///
    /// The field needs no integrity protection of its own: it SELECTS the preimage, so flipping
    /// it makes the receiver reconstruct a different byte string and the signature simply fails.
    /// A downgrade attacker gains nothing — it cannot produce a v1 signature it does not hold.
    #[serde(
        default = "default_envelope_version",
        skip_serializing_if = "is_envelope_v1",
        rename = "v"
    )]
    pub version: u8,
    /// Message type
    pub msg_type: MessageType,
    /// Sender node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub sender: NodeId,
    /// Message timestamp
    pub timestamp: u64,
    /// Message sequence number (for dedup)
    pub sequence: u64,
    /// Signature of payload
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Message payload (JSON)
    pub payload: Vec<u8>,
    /// Time-to-live: number of hops remaining before message is dropped.
    /// Decremented on each forward. Messages with TTL 0 are processed locally but not forwarded.
    /// Defaults to DEFAULT_MESSAGE_TTL for backwards compatibility with older messages.
    #[serde(default = "default_ttl")]
    pub ttl: u8,
}

/// Default TTL value for deserialization of messages without TTL field
fn default_ttl() -> u8 {
    DEFAULT_MESSAGE_TTL
}

impl MessageEnvelope {
    /// Create a message envelope carrying a signature produced elsewhere, with default TTL.
    ///
    /// ⚠ The timestamp is stamped HERE, so this cannot be used to carry an
    /// [`ENVELOPE_VERSION_V2`] signature: v2 binds `timestamp`, and the caller cannot have signed
    /// a timestamp this call had not yet chosen. Anything destined for the wire must go through
    /// [`MessageEnvelope::signed`], which owns both. What is left for this constructor is local
    /// and test delivery, where the signature is a placeholder and is never verified.
    pub fn new(
        msg_type: MessageType,
        sender: NodeId,
        payload: Vec<u8>,
        sequence: u64,
        signature: [u8; 64],
    ) -> Self {
        Self::with_ttl(
            msg_type,
            sender,
            payload,
            sequence,
            signature,
            DEFAULT_MESSAGE_TTL,
        )
    }

    /// Create a message envelope carrying a signature produced elsewhere, with custom TTL.
    ///
    /// Carries the same caveat as [`MessageEnvelope::new`].
    pub fn with_ttl(
        msg_type: MessageType,
        sender: NodeId,
        payload: Vec<u8>,
        sequence: u64,
        signature: [u8; 64],
        ttl: u8,
    ) -> Self {
        Self {
            version: ENVELOPE_VERSION_V1,
            msg_type,
            sender,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            signature,
            payload,
            ttl,
        }
    }

    /// Build a signed envelope: the only constructor that can produce a valid signature.
    ///
    /// It exists because v2 binds `timestamp`, and a caller that computed a preimage and then
    /// handed it to [`MessageEnvelope::new`] would be signing a timestamp different from the one
    /// the envelope ends up carrying — a signature that fails verification everywhere while
    /// looking correct at the call site. Stamping and signing in one place makes that
    /// unrepresentable, and collapses the three copies of the preimage that used to exist in
    /// `mesh.rs` into one.
    pub fn signed(
        version: u8,
        msg_type: MessageType,
        sender: NodeId,
        payload: Vec<u8>,
        sequence: u64,
        ttl: u8,
        sign: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Result<Self, EnvelopeSigningError> {
        let mut envelope = Self {
            version,
            msg_type,
            sender,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            signature: [0u8; 64],
            payload,
            ttl,
        };
        let preimage = envelope.signing_bytes()?;
        envelope.signature = sign(&preimage);
        Ok(envelope)
    }

    /// The exact bytes [`MessageEnvelope::signature`] covers, per this envelope's `version`.
    ///
    /// The single definition of the mesh signing preimage: every signer and every verifier calls
    /// this. Before it existed the formula was written out by hand in six places (three signers in
    /// `mesh.rs`, three verifiers in `message_validator.rs`, `vote_handler.rs` and
    /// `discovery_handler.rs`), each with a comment asking the reader to keep it in step with the
    /// others.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EnvelopeSigningError> {
        Self::signing_preimage(
            self.version,
            self.msg_type,
            &self.sender,
            self.timestamp,
            self.sequence,
            &self.payload,
        )
    }

    /// Build the signing preimage for `version` from the fields it covers.
    ///
    /// v1 is `payload || sequence_le` — reproduced verbatim, including its lack of any separator,
    /// because every envelope on the fleet today is signed that way.
    ///
    /// v2 is domain-separated and length-prefixed:
    ///
    /// ```text
    /// "ghost/mesh/envelope/v2\0"  (23)
    /// sender                      (32)
    /// timestamp                   (8, LE)
    /// sequence                    (8, LE)
    /// type_tag_len                (4, LE)
    /// type_tag                    (type_tag_len)
    /// payload_len                 (8, LE)
    /// payload                     (payload_len)
    /// ```
    ///
    /// Every variable-length field is length-prefixed so no two distinct field tuples can share a
    /// preimage. Unprefixed concatenation is what makes v1's `payload || sequence` ambiguous in
    /// principle as well as incomplete in practice.
    ///
    /// `type_tag` is the message type's own JSON encoding — the bytes actually on the wire — so
    /// the tag cannot drift from the transmitted discriminant when a variant is added or renamed.
    /// A hand-kept table of numeric tags could; this cannot. Binding the type matters because
    /// [`MessageType::topic`] is not injective: `ShareProof` and `ShareConvergence` both ride
    /// `topics::SHARE`, so under v1 a captured envelope can be re-typed between them and still
    /// verify.
    pub fn signing_preimage(
        version: u8,
        msg_type: MessageType,
        sender: &NodeId,
        timestamp: u64,
        sequence: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>, EnvelopeSigningError> {
        match version {
            ENVELOPE_VERSION_V1 => {
                let mut out = Vec::with_capacity(payload.len() + 8);
                out.extend_from_slice(payload);
                out.extend_from_slice(&sequence.to_le_bytes());
                Ok(out)
            }
            ENVELOPE_VERSION_V2 => {
                let type_tag = serde_json::to_vec(&msg_type)
                    .map_err(|e| EnvelopeSigningError::TypeTag(e.to_string()))?;
                let mut out = Vec::with_capacity(
                    ENVELOPE_V2_DOMAIN.len() + 32 + 8 + 8 + 4 + type_tag.len() + 8 + payload.len(),
                );
                out.extend_from_slice(ENVELOPE_V2_DOMAIN);
                out.extend_from_slice(sender);
                out.extend_from_slice(&timestamp.to_le_bytes());
                out.extend_from_slice(&sequence.to_le_bytes());
                out.extend_from_slice(&(type_tag.len() as u32).to_le_bytes());
                out.extend_from_slice(&type_tag);
                out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                out.extend_from_slice(payload);
                Ok(out)
            }
            other => Err(EnvelopeSigningError::UnsupportedVersion(other)),
        }
    }

    /// Decrement TTL and return whether the message should be forwarded
    ///
    /// Returns true if the message should be forwarded (TTL was > 0 before decrement)
    /// Returns false if the message should not be forwarded (TTL was already 0)
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl = self.ttl.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Check if this message should be forwarded to other peers
    pub fn should_forward(&self) -> bool {
        self.ttl >= MIN_FORWARD_TTL
    }

    /// Get the topic for this message
    pub fn topic(&self) -> &[u8] {
        self.msg_type.topic()
    }

    /// Serialize for transmission
    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Deserialize from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Message type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Health ping
    HealthPing,
    /// Peer discovery
    Discovery,
}

impl MessageType {
    /// Get the ZMQ topic for this message type
    pub fn topic(&self) -> &[u8] {
        match self {
            Self::HealthPing => topics::HEALTH,
            Self::Discovery => topics::DISCOVERY,
        }
    }

    /// M-P2P-1: Get the topic as a string for validation
    ///
    /// Used to validate that a message received on a topic actually matches
    /// the message type declared in the envelope.
    pub fn topic_str(&self) -> &'static str {
        match self {
            Self::HealthPing => "health",
            Self::Discovery => "discovery",
        }
    }
}

/// Health ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPingMessage {
    /// Health ping data
    pub ping: HealthPing,
}

/// Discovery message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    /// Requesting node
    pub node_id: NodeId,
    /// Node's public address
    pub public_address: String,
    /// Node's capabilities
    pub capabilities: NodeCapabilities,
    /// Known peers (for gossip)
    pub known_peers: Vec<PeerInfo>,
}

/// Peer information for discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Node ID
    pub node_id: NodeId,
    /// Public address
    pub public_address: String,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Capabilities
    pub capabilities: NodeCapabilities,
}

#[cfg(test)]
mod tests {
    // ── H-7 address capability (#605) ────────────────────────────────────────────────────

    // ── Deterministic node-list derivation (#625) ────────────────────────────────────────
}

#[cfg(test)]
mod envelope_signing_tests {
    use super::*;

    fn envelope(version: u8, msg_type: MessageType, timestamp: u64, ttl: u8) -> MessageEnvelope {
        MessageEnvelope {
            version,
            msg_type,
            sender: [7u8; 32],
            timestamp,
            sequence: 42,
            signature: [9u8; 64],
            payload: b"payload".to_vec(),
            ttl,
        }
    }

    /// v1 must stay EXACTLY `payload || sequence_le`. Every envelope on the eight-node fleet is
    /// signed that way right now, so this is the compatibility contract, not an implementation
    /// detail: if the refactor that centralised the preimage changed one byte, every node on the
    /// new binary would reject every node on the old one.
    #[test]
    fn v1_preimage_is_byte_identical_to_the_shipped_formula() {
        let env = envelope(
            ENVELOPE_VERSION_V1,
            MessageType::HealthPing,
            1_700_000_000_000,
            8,
        );

        let mut expected = env.payload.clone();
        expected.extend_from_slice(&env.sequence.to_le_bytes());

        assert_eq!(
            env.signing_bytes().expect("v1 preimage"),
            expected,
            "the v1 signing preimage moved — this breaks every peer on the current binary"
        );
    }

    /// The other half of the same contract: the pre-gate WIRE bytes must not gain a `v` key, so a
    /// node on the new binary emits JSON an old node has already been parsing for months.
    #[test]
    fn v1_wire_bytes_carry_no_version_key() {
        let json = serde_json::to_string(&envelope(
            ENVELOPE_VERSION_V1,
            MessageType::HealthPing,
            1_700_000_000_000,
            8,
        ))
        .expect("serialise");

        assert!(
            !json.contains("\"v\""),
            "a v1 envelope must serialise without the version key: {json}"
        );
    }

    /// And the reverse direction: an envelope from a binary that predates the field has no `v`,
    /// and must be read as v1 rather than failing to deserialise. `CapabilityType` is the standing
    /// reminder of what a hard-failing decode costs — the whole message is dropped, silently.
    #[test]
    fn envelope_without_version_key_deserialises_as_v1() {
        let json = r#"{"msg_type":"HealthPing","sender":"0707070707070707070707070707070707070707070707070707070707070707","timestamp":1700000000000,"sequence":42,"signature":"09090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909","payload":[1,2,3],"ttl":8}"#;

        let env = MessageEnvelope::deserialize(json.as_bytes()).expect("deserialise legacy");

        assert_eq!(env.version, ENVELOPE_VERSION_V1);
    }

    /// H-11 itself. Under v1 the timestamp is outside the signature, so a relay can re-stamp a
    /// captured envelope and walk it past the ±30 s drift check for ever. Under v2 it cannot.
    #[test]
    fn v2_binds_the_timestamp_and_v1_does_not() {
        let early = 1_700_000_000_000;
        let late = early + 60_000;

        let v1_early = envelope(ENVELOPE_VERSION_V1, MessageType::HealthPing, early, 8);
        let v1_late = envelope(ENVELOPE_VERSION_V1, MessageType::HealthPing, late, 8);
        assert_eq!(
            v1_early.signing_bytes().unwrap(),
            v1_late.signing_bytes().unwrap(),
            "v1 leaves the timestamp malleable — that is the finding being fixed"
        );

        let v2_early = envelope(ENVELOPE_VERSION_V2, MessageType::HealthPing, early, 8);
        let v2_late = envelope(ENVELOPE_VERSION_V2, MessageType::HealthPing, late, 8);
        assert_ne!(
            v2_early.signing_bytes().unwrap(),
            v2_late.signing_bytes().unwrap(),
            "v2 must bind the timestamp, or replay is bounded by nothing but in-memory state"
        );
    }

    /// The second half of H-11. `MessageType::topic` is not injective — `ShareProof` and
    /// `ShareConvergence` both ride `topics::SHARE` — so under v1 a captured envelope can be
    /// re-typed between them and still verify, arriving at a different handler than its signer
    /// intended.
    #[test]
    fn v2_binds_the_message_type_and_v1_does_not() {
        let ts = 1_700_000_000_000;
        let v1_proof = envelope(ENVELOPE_VERSION_V1, MessageType::HealthPing, ts, 8);
        let v1_conv = envelope(ENVELOPE_VERSION_V1, MessageType::Discovery, ts, 8);
        assert_eq!(
            v1_proof.signing_bytes().unwrap(),
            v1_conv.signing_bytes().unwrap(),
            "v1 leaves the message type malleable"
        );

        let v2_proof = envelope(ENVELOPE_VERSION_V2, MessageType::HealthPing, ts, 8);
        let v2_conv = envelope(ENVELOPE_VERSION_V2, MessageType::Discovery, ts, 8);
        assert_ne!(
            v2_proof.signing_bytes().unwrap(),
            v2_conv.signing_bytes().unwrap(),
            "v2 must bind the message type"
        );
    }

    /// `ttl` is decremented on every hop by design, so binding it would invalidate the signature
    /// at the first relay — a mesh that only works between direct neighbours. This pins the
    /// exclusion as deliberate rather than an oversight someone later "fixes".
    #[test]
    fn v2_does_not_bind_the_ttl() {
        let ts = 1_700_000_000_000;
        let fresh = envelope(ENVELOPE_VERSION_V2, MessageType::HealthPing, ts, 8);
        let forwarded = envelope(ENVELOPE_VERSION_V2, MessageType::HealthPing, ts, 3);

        assert_eq!(
            fresh.signing_bytes().unwrap(),
            forwarded.signing_bytes().unwrap(),
            "binding ttl would break every forwarded message"
        );
    }

    /// The domain separator exists for cross-protocol separation under a shared ed25519 key.
    #[test]
    fn v2_preimage_is_domain_separated() {
        let bytes = envelope(
            ENVELOPE_VERSION_V2,
            MessageType::Discovery,
            1_700_000_000_000,
            8,
        )
        .signing_bytes()
        .unwrap();

        assert!(
            bytes.starts_with(b"ghost/mesh/envelope/v2\0"),
            "v2 preimage lost its domain tag"
        );
    }

    /// Decode the v2 preimage field by field and check it against the documented layout.
    ///
    /// This replaces a test that asserted two envelopes with DIFFERENT-LENGTH payloads produce
    /// different preimages. That could not fail: the payloads already differed, so it held with
    /// either length prefix deleted. It read as a demonstration that the encoding is unambiguous
    /// and demonstrated nothing.
    ///
    /// A collision test cannot do the job here either. `type_tag` is drawn from a fixed set of
    /// `MessageType` JSON names, not chosen by an attacker, and no two of them line up to produce
    /// a colliding preimage even with the prefix removed. And `payload` is the LAST field, so
    /// `payload_len` is not what makes the encoding decodable at all — it is redundancy, and no
    /// collision can exist to catch its removal.
    ///
    /// So the honest check is the layout itself: parse it back, assert every field lands where the
    /// doc comment says, and assert the cursor ends exactly at the end. Delete either length
    /// prefix and the parse desynchronises immediately.
    #[test]
    fn v2_preimage_matches_its_documented_layout() {
        let env = envelope(
            ENVELOPE_VERSION_V2,
            MessageType::HealthPing,
            1_700_000_000_123,
            8,
        );
        let bytes = env.signing_bytes().expect("v2 preimage");
        let expected_tag = serde_json::to_vec(&env.msg_type).expect("tag");

        let mut cur = 0usize;
        let mut take = |n: usize| -> &[u8] {
            assert!(
                cur + n <= bytes.len(),
                "preimage ran out at offset {cur} wanting {n} of {}",
                bytes.len()
            );
            let out = &bytes[cur..cur + n];
            cur += n;
            out
        };

        assert_eq!(take(23), b"ghost/mesh/envelope/v2\0", "domain separator");
        assert_eq!(take(32), &env.sender[..], "sender");
        assert_eq!(
            u64::from_le_bytes(take(8).try_into().unwrap()),
            env.timestamp,
            "timestamp"
        );
        assert_eq!(
            u64::from_le_bytes(take(8).try_into().unwrap()),
            env.sequence,
            "sequence"
        );

        let tag_len = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
        assert_eq!(tag_len, expected_tag.len(), "type_tag length prefix");
        assert_eq!(take(tag_len), &expected_tag[..], "type_tag");

        let payload_len = u64::from_le_bytes(take(8).try_into().unwrap()) as usize;
        assert_eq!(payload_len, env.payload.len(), "payload length prefix");
        assert_eq!(take(payload_len), &env.payload[..], "payload");

        assert_eq!(cur, bytes.len(), "trailing bytes after the payload");
    }

    /// The property the layout is FOR: distinct field tuples must not share a preimage.
    ///
    /// Varying one field at a time from a common base is what makes this meaningful — it catches a
    /// field dropped from the preimage entirely, which is the realistic way this encoding breaks.
    /// `ttl` is varied too, and is the one field required to COLLIDE, since it changes on every
    /// hop.
    #[test]
    fn v2_preimages_are_distinct_for_distinct_field_tuples() {
        let base = envelope(
            ENVELOPE_VERSION_V2,
            MessageType::HealthPing,
            1_700_000_000_000,
            8,
        );

        let mut other_sender = base.clone();
        other_sender.sender = [8u8; 32];
        let mut other_ts = base.clone();
        other_ts.timestamp += 1;
        let mut other_seq = base.clone();
        other_seq.sequence += 1;
        let mut other_type = base.clone();
        other_type.msg_type = MessageType::Discovery;
        let mut other_payload = base.clone();
        other_payload.payload = b"payloae".to_vec(); // same length, one byte different

        let variants = [
            ("sender", other_sender),
            ("timestamp", other_ts),
            ("sequence", other_seq),
            ("msg_type", other_type),
            ("payload", other_payload),
        ];

        let base_bytes = base.signing_bytes().unwrap();
        for (field, variant) in &variants {
            assert_ne!(
                base_bytes,
                variant.signing_bytes().unwrap(),
                "changing {field} left the preimage unchanged — it is not bound"
            );
        }

        // And distinct from each other, not merely from the base.
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i].1.signing_bytes().unwrap(),
                    variants[j].1.signing_bytes().unwrap(),
                    "{} and {} collided",
                    variants[i].0,
                    variants[j].0
                );
            }
        }

        // Same tuple, same bytes — a preimage that varied run to run would be unverifiable.
        assert_eq!(base_bytes, base.signing_bytes().unwrap());
    }

    /// A version this binary cannot reconstruct is a version it cannot authenticate. It must be an
    /// error the verifier turns into a rejection, never a silently-empty preimage.
    #[test]
    fn unknown_envelope_version_cannot_produce_a_preimage() {
        let err = envelope(99, MessageType::Discovery, 1_700_000_000_000, 8)
            .signing_bytes()
            .expect_err("version 99 must not yield bytes");

        assert!(matches!(err, EnvelopeSigningError::UnsupportedVersion(99)));
    }

    /// [`MessageEnvelope::signed`] is the only constructor that can produce a valid v2 signature,
    /// because v2 binds the timestamp and this is the only place that chooses it. Pinning the
    /// round-trip here is what stops a future refactor from splitting the two apart again.
    #[test]
    fn signed_constructor_round_trips_both_formats() {
        use ghost_common::identity::NodeIdentity;

        let identity = NodeIdentity::generate();
        for version in [ENVELOPE_VERSION_V1, ENVELOPE_VERSION_V2] {
            let env = MessageEnvelope::signed(
                version,
                MessageType::HealthPing,
                identity.node_id(),
                b"a payload".to_vec(),
                17,
                DEFAULT_MESSAGE_TTL,
                |bytes| identity.sign(bytes),
            )
            .expect("sign");

            assert_eq!(env.version, version);
            assert!(
                ghost_common::identity::verify_signature(
                    &env.sender,
                    &env.signing_bytes().unwrap(),
                    &env.signature,
                )
                .unwrap(),
                "v{version} envelope did not verify against its own preimage"
            );
        }
    }

    /// The gate ships DORMANT. Arming it while any node is on an older binary partitions the mesh
    /// completely, so the value it ships with is the whole safety argument for this release.
    #[test]
    fn v2_emission_gate_is_armed_at_the_reviewed_height() {
        // Was `v2_emission_gate_ships_dormant`, asserting `u64::MAX`. It has done its job: it held
        // the gate closed until the fixed order in `MESH_ENVELOPE_V2_HEIGHT`'s docs was actually
        // completed — tolerance shipped in #740, all eight rolled to v1.11.33 (`bf3f822b5`) and
        // confirmed per binary, `bad_signature` observed at 0 over 6h. Arming is that separate
        // change, so the assertion flips rather than being deleted: the height still may not move
        // without review.
        assert_eq!(
            MESH_ENVELOPE_V2_HEIGHT, 966_400,
            "the envelope v2 emission height changed — this requires a fleet roll, see the docs"
        );
    }

    /// The boundary is inclusive at the gate height, matching every other gate in the codebase,
    /// and an unknown height (0, the health-ping provider's fallback) resolves to v1 — the only
    /// direction that cannot partition a mesh.
    #[test]
    fn emission_gate_boundary_is_inclusive_and_fails_closed() {
        let gate = mesh_envelope_v2_height();

        assert_eq!(envelope_version_for_height(0), ENVELOPE_VERSION_V1);
        assert_eq!(
            envelope_version_for_height(gate.saturating_sub(1)),
            ENVELOPE_VERSION_V1
        );
        assert_eq!(envelope_version_for_height(gate), ENVELOPE_VERSION_V2);
    }
}

#[cfg(test)]
mod mesh_envelope_v2_arming_tests {
    use super::{ADDRESS_PROOF_SEPARATION_REFERENCE, MESH_ENVELOPE_V2_HEIGHT};

    /// The armed height is consensus-visible and must not drift silently.
    #[test]
    fn the_armed_height_is_pinned() {
        assert_eq!(
            MESH_ENVELOPE_V2_HEIGHT, 966_400,
            "changing an armed mesh-envelope height requires a fleet roll — see the const's docs"
        );
    }

    /// Guards the arming being UNDONE. `u64::MAX` reads as an ordinary value, so a revert would
    /// leave any test that merely checks "the constant exists" passing while v2 never flips.
    #[test]
    fn the_gate_is_armed_not_dormant() {
        assert_ne!(
            MESH_ENVELOPE_V2_HEIGHT,
            u64::MAX,
            "MESH_ENVELOPE_V2_HEIGHT is dormant again — arming was reverted"
        );
    }

    /// The two gates riding this release must NOT share a height.
    ///
    /// Both are armed in v1.11.34. If the mesh misbehaves in that window, separated heights are
    /// what make the cause attributable to one gate rather than two — and this gate's failure
    /// mode is a partition, so attribution is not a nicety.
    #[test]
    fn it_does_not_share_a_height_with_the_address_proof_gate() {
        // Read through `black_box`: comparing two `const`s folds at compile time, which clippy
        // flags as `assertions_on_constants` — and it is right to, because a tautology that
        // cannot fail is not a check. This keeps the comparison a real runtime one.
        let envelope = std::hint::black_box(MESH_ENVELOPE_V2_HEIGHT);
        let address = std::hint::black_box(ADDRESS_PROOF_SEPARATION_REFERENCE);
        assert!(
            envelope > address,
            "must fire AFTER the address-proof gate ({address}), got {envelope}"
        );
        assert!(
            envelope - address >= 200,
            "the two gates are too close to attribute a divergence to one of them: {} blocks",
            envelope - address
        );
    }
}
