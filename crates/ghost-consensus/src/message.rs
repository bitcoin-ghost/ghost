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

use ghost_common::share_shard::{AccruedColumns, EpochSummary};
use ghost_common::types::{
    HealthPing, NodeCapabilities, NodeId, PayoutProposal, RoundId, ShareProof,
};

/// Topic prefixes for ZMQ messages
pub mod topics {
    /// Share propagation topic
    pub const SHARE: &[u8] = b"share";
    /// Block announcement topic
    pub const BLOCK: &[u8] = b"block";
    /// Payout proposal topic
    pub const PAYOUT_PROPOSAL: &[u8] = b"payout";
    /// Vote topic
    pub const VOTE: &[u8] = b"vote";
    /// Health ping topic
    pub const HEALTH: &[u8] = b"health";
    /// Discovery topic
    pub const DISCOVERY: &[u8] = b"discovery";
    /// Elder management topic
    pub const ELDER: &[u8] = b"elder";
    /// ZK block proposal topic
    pub const ZK_PROPOSAL: &[u8] = b"zkproposal";
    /// ZK vote topic
    pub const ZK_VOTE: &[u8] = b"zkvote";
    /// Verification result topic
    pub const VERIFICATION: &[u8] = b"verify";
    /// P2P-H3: Equivocation proof topic for Byzantine behavior evidence
    pub const EQUIVOCATION: &[u8] = b"equivoc";
    /// MPC ceremony messages (contribution, verification vote, parameter sync)
    pub const MPC: &[u8] = b"mpc";
    /// L2 confidential transfer submission
    pub const L2_TRANSFER: &[u8] = b"l2tx";
    /// L2 checkpoint block
    pub const L2_CHECKPOINT: &[u8] = b"l2chk";
    /// L2 checkpoint vote
    pub const L2_VOTE: &[u8] = b"l2vote";
    /// L2 tree sync
    pub const L2_SYNC: &[u8] = b"l2sync";
    /// Payout-ledger checkpoint proposal (BFT-finalised payout snapshot root)
    pub const PAYOUT_LEDGER_CHECKPOINT: &[u8] = b"plchk";
    /// Payout-ledger checkpoint vote
    pub const PAYOUT_LEDGER_VOTE: &[u8] = b"plvote";
    /// Payout-ledger checkpoint sync (on-demand backfill of missed checkpoints)
    pub const PAYOUT_LEDGER_SYNC: &[u8] = b"plsync";
    pub const PAYOUT_PROPOSAL_SYNC: &[u8] = b"ppsync";
    /// Share-batch chain: a proposed batch
    pub const SHARE_BATCH: &[u8] = b"sbatch";
    /// Share-batch chain: a vote on a proposed batch
    pub const SHARE_BATCH_VOTE: &[u8] = b"sbvote";
    /// Share-batch chain: on-demand backfill of adopted batches
    pub const SHARE_BATCH_SYNC: &[u8] = b"sbsync";
    /// Share-batch chain, two-phase: first-round vote. Evidence, not a decision.
    pub const SHARE_BATCH_PREVOTE: &[u8] = b"sbprev";
    /// Share-batch chain, two-phase: second-round vote. A quorum of these commits.
    pub const SHARE_BATCH_PRECOMMIT: &[u8] = b"sbprec";
    /// Mesh node-list checkpoint proposal (signed public-mining node set for discovery)
    pub const MESH_NODE_LIST_CHECKPOINT: &[u8] = b"mnlchk";
    /// Mesh node-list checkpoint vote
    pub const MESH_NODE_LIST_VOTE: &[u8] = b"mnlvote";
    /// Mesh node-list checkpoint sync (on-demand backfill of missed checkpoints)
    pub const MESH_NODE_LIST_SYNC: &[u8] = b"mnlsync";
    /// A node's own signed endpoint advert, feeding the node-list checkpoint.
    ///
    /// `mnladv` shares no prefix relation with `mnlchk`/`mnlvote`/`mnlsync` — they diverge at
    /// the fourth byte — which matters because ZMQ subscriptions match by PREFIX, so a topic
    /// that extended an existing one would be silently delivered to its subscribers too.
    pub const MESH_ENDPOINT_ADVERT: &[u8] = b"mnladv";
    /// L2 shield commitment broadcast
    pub const L2_SHIELD: &[u8] = b"l2shld";
    /// GhostGlyph visual identity
    pub const GLYPH: &[u8] = b"glyph";
    /// Share shard: a node's signed per-epoch summary (delta + running total per address).
    ///
    /// `shd` prefix, not `sh`: ZMQ subscriptions match by PREFIX, so a topic that extends an
    /// existing one (e.g. anything starting `share…`) would be delivered to that topic's
    /// subscribers as well. `shdsum`/`shdsync`/`shdevid` share no prefix relation with any other
    /// registered topic, or with each other — pinned by a test.
    pub const SHARD_EPOCH_SUMMARY: &[u8] = b"shdsum";
    /// Share shard: whole-table sync request/response (§12.6: ship the whole table and compare).
    pub const SHARD_TABLE_SYNC: &[u8] = b"shdsync";
    /// Share shard: bad-share evidence broadcast (§12.4: rejections are publishable evidence).
    pub const SHARD_EVIDENCE: &[u8] = b"shdevid";
    /// Share shard: §6 sampling — ask a node for specific leaves of an epoch it summarised.
    pub const SHARD_SAMPLE_REQUEST: &[u8] = b"shdsreq";
    /// Share shard: §6 sampling — the requested leaves, each with its Merkle path.
    pub const SHARD_SAMPLE_RESPONSE: &[u8] = b"shdsrsp";
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
/// `ghost-pool`'s `ADDRESS_PROOF_HEIGHT`). A height makes the flip simultaneous across eight nodes
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
pub const MESH_ENVELOPE_V2_HEIGHT: u64 = u64::MAX;

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
    /// Share proof propagation
    ShareProof,
    /// Payout proposal
    PayoutProposal,
    /// Vote on proposal
    Vote,
    /// Health ping
    HealthPing,
    /// Peer discovery
    Discovery,
    /// Share convergence request
    ShareConvergence,
    /// Capability verification result
    VerificationResult,
    /// Challenge-ledger convergence request/response (backfill of signed
    /// verification results, so the node-reward capability ledger converges the
    /// way the miner share ledger does). Rides the verification topic.
    ChallengeConvergence,
    /// P2P-H3: Equivocation proof broadcast for Byzantine behavior evidence
    EquivocationProof,
    /// MPC-C1: MPC contribution (new elder's contribution to ceremony)
    MpcContribution,
    /// MPC-C2: MPC verification vote (elder's vote on contribution)
    MpcVerificationVote,
    /// MPC-C3: MPC parameters request (request params from peer)
    MpcParametersRequest,
    /// MPC-C4: MPC parameters response (chunked parameter data)
    MpcParametersResponse,
    /// L2: Confidential transfer submission (sender → validator)
    L2ConfidentialTransfer,
    /// L2: Transfer confirmation receipt (validator → sender)
    L2TransferConfirmation,
    /// L2: Broadcast confirmed tx to all nodes (validator → all)
    L2TransferBroadcast,
    /// L2: Checkpoint block proposal (proposer → all)
    L2CheckpointBlock,
    /// L2: Checkpoint vote (validator → all)
    L2CheckpointVote,
    /// L2: Tree sync request/response (node → peer)
    L2TreeSync,
    /// L2: Shield commitment broadcast (node → all)
    L2ShieldBroadcast,
    /// GhostGlyph: Claim broadcast (user submits glyph design)
    GhostGlyphClaim,
    /// GhostGlyph: Registration confirmed (lock funded)
    GhostGlyphRegistered,
    /// Payout-ledger checkpoint proposal (proposer → all): the BFT-finalised
    /// snapshot the coinbase is a pure function of.
    PayoutLedgerCheckpoint,
    /// Payout-ledger checkpoint vote (validator → all)
    PayoutLedgerCheckpointVote,
    /// Payout-ledger checkpoint sync request/response (node ↔ peer): on-demand
    /// backfill of finalised checkpoints a node missed (proposals are broadcast
    /// once and never rebroadcast). Multiplexes request + response by trial-deser.
    PayoutLedgerCheckpointSync,
    /// Payout-proposal sync request/response (node ↔ peer).
    ///
    /// A node settling a won block reads the payout identity off its coinbase, then needs the
    /// proposal that identity names. If it never received that proposal — it was down when the
    /// proposal was gossiped, and proposals are broadcast once — the block cannot be settled and
    /// the ledger silently keeps owing work the pool already paid.
    ///
    /// Fetching it needs no trust: the chain names the payout, so a response is accepted only if
    /// the proposal it carries hashes to that identity. A forged one cannot.
    PayoutProposalSync,
    /// Share-batch chain: a proposed batch (dark until the chain is armed).
    ///
    /// Carries the shares themselves, so this is the one batch-chain message with real size — and
    /// the packing budget is derived from its wire limit rather than guessed at, because guessing
    /// is what produced a convergence response that could not carry a single proof (#558).
    ShareBatchProposal,
    /// Share-batch chain: a vote for a batch at a sequence. Hash plus signature; small.
    ShareBatchVote,
    /// Share-batch chain, two-phase: a PREVOTE for a batch at a `(seq, round)`.
    ///
    /// Separate from `ShareBatchVote` and from `ShareBatchPrecommit` rather than a phase field on
    /// one type, so a prevote can never be counted as a precommit by a receiver that mishandles
    /// the discriminant. A quorum of prevotes is a *polka* — evidence that a quorum considered the
    /// batch valid — which is what releases a lock. It decides nothing on its own.
    ShareBatchPrevote,
    /// Share-batch chain, two-phase: a PRECOMMIT for a batch at a `(seq, round)`.
    ///
    /// Sent only after seeing a polka, and only for the value the sender is locked on. A quorum of
    /// these at one round commits the sequence; nothing else adopts.
    ShareBatchPrecommit,
    /// Share-batch chain: request/response for an adopted batch a node missed.
    ///
    /// The chain is a hash chain, so a node that misses one link cannot verify any later batch
    /// against its own head — it must fetch, not guess. Verified by rehashing: an adopted batch is
    /// accepted only if it hashes to the parent the next one names.
    ShareBatchSync,
    /// Mesh node-list checkpoint proposal (proposer → all): the BFT-finalised, signed
    /// snapshot of the public-mining node set for decentralised mining discovery.
    MeshNodeListCheckpoint,
    /// Mesh node-list checkpoint vote (validator → all)
    MeshNodeListCheckpointVote,
    /// Mesh node-list checkpoint sync request/response (node ↔ peer): on-demand backfill.
    MeshNodeListCheckpointSync,
    /// A node's own signed endpoint advert (node → all): where miners reach it.
    ///
    /// Broadcast rather than requested, and self-signed rather than observed, because the
    /// checkpoint's whole determinism rests on every node holding the SAME bytes for a peer's
    /// endpoint. An address learned by observation differs per observer, which is what made
    /// the node list unable to converge (#625).
    MeshEndpointAdvertisement,
    /// Share shard: a node's signed epoch summary (node → all).
    ///
    /// Carries an `EpochSummary` — per-address `delta_micro` (evidenced by the epoch's Merkle
    /// root) and `total_micro` (the cumulative counter peers max-merge). The shares themselves
    /// never ride with it: the signed root commits to them so §6's sampling can audit any epoch
    /// after the fact. Verification strictly precedes any merge (§12.3) — a max cannot be undone,
    /// so an unverified counter that reaches the table has already won.
    ShardEpochSummary,
    /// Share shard: whole-table sync request/response (node ↔ peer).
    ///
    /// §12.6: at a few hundred rows the shard is small enough to ship whole and compare, so drift
    /// is visible the same day rather than discovered a quarter later. Multiplexes request and
    /// response in one type by trial-deserialise — the same shape as `ShareBatchSync`.
    ShardTableSync,
    /// Share shard: bad-share evidence broadcast (reporter → all), modelled on
    /// `EquivocationProofMessage`.
    ///
    /// §12.4: a rejection must be publishable evidence, never private sampling luck — otherwise
    /// two nodes can disagree permanently about a third's counter, which is exactly the divergence
    /// the shard design removes. The accused's own signed summary binds an epoch Merkle root, the
    /// carried Merkle path binds the share to that root, and the share fails a validity check any
    /// peer can re-run: everyone reaches the same verdict from the same bytes.
    ShardEvidence,
    /// Share shard: §6 sampling request (sampler → summarising node).
    ///
    /// Without this pair, §6's "sampled, asynchronous" layer is unreachable: a summary's root
    /// commits to shares nobody can ask for. The request names an epoch, the node that
    /// summarised it, the exact signed root being audited, and the leaf indices wanted — chosen
    /// by [`crate::shard_handler::select_sample_indices`] from randomness the responder cannot
    /// know in advance, which is the whole audit value (a node that can predict its samples
    /// keeps exactly those leaves honest).
    ShardSampleRequest,
    /// Share shard: §6 sampling response (summarising node → sampler).
    ///
    /// The requested shares, each with the Merkle path placing it under the signed root the
    /// request named. Separate from `ShardSampleRequest` rather than multiplexed one type
    /// (the `ShardTableSync` shape) because their size profiles differ by three orders of
    /// magnitude — a request is a list of integers, a response carries whole shares — and one
    /// shared cap would either strangle the response or hand request-flooders a huge budget.
    ShardSampleResponse,
}

impl MessageType {
    /// Get the ZMQ topic for this message type
    pub fn topic(&self) -> &[u8] {
        match self {
            Self::ShareProof => topics::SHARE,
            Self::PayoutProposal => topics::PAYOUT_PROPOSAL,
            Self::Vote => topics::VOTE,
            Self::HealthPing => topics::HEALTH,
            Self::Discovery => topics::DISCOVERY,
            Self::ShareConvergence => topics::SHARE,
            Self::VerificationResult => topics::VERIFICATION,
            Self::ChallengeConvergence => topics::VERIFICATION,
            Self::EquivocationProof => topics::EQUIVOCATION,
            Self::MpcContribution => topics::MPC,
            Self::MpcVerificationVote => topics::MPC,
            Self::MpcParametersRequest => topics::MPC,
            Self::MpcParametersResponse => topics::MPC,
            Self::L2ConfidentialTransfer => topics::L2_TRANSFER,
            Self::L2TransferConfirmation => topics::L2_TRANSFER,
            Self::L2TransferBroadcast => topics::L2_TRANSFER,
            Self::L2CheckpointBlock => topics::L2_CHECKPOINT,
            Self::L2CheckpointVote => topics::L2_VOTE,
            Self::PayoutLedgerCheckpoint => topics::PAYOUT_LEDGER_CHECKPOINT,
            Self::PayoutLedgerCheckpointVote => topics::PAYOUT_LEDGER_VOTE,
            Self::PayoutLedgerCheckpointSync => topics::PAYOUT_LEDGER_SYNC,
            Self::PayoutProposalSync => topics::PAYOUT_PROPOSAL_SYNC,
            Self::ShareBatchProposal => topics::SHARE_BATCH,
            Self::ShareBatchVote => topics::SHARE_BATCH_VOTE,
            Self::ShareBatchSync => topics::SHARE_BATCH_SYNC,
            Self::ShareBatchPrevote => topics::SHARE_BATCH_PREVOTE,
            Self::ShareBatchPrecommit => topics::SHARE_BATCH_PRECOMMIT,
            Self::MeshNodeListCheckpoint => topics::MESH_NODE_LIST_CHECKPOINT,
            Self::MeshNodeListCheckpointVote => topics::MESH_NODE_LIST_VOTE,
            Self::MeshNodeListCheckpointSync => topics::MESH_NODE_LIST_SYNC,
            Self::MeshEndpointAdvertisement => topics::MESH_ENDPOINT_ADVERT,
            Self::ShardEpochSummary => topics::SHARD_EPOCH_SUMMARY,
            Self::ShardTableSync => topics::SHARD_TABLE_SYNC,
            Self::ShardEvidence => topics::SHARD_EVIDENCE,
            Self::ShardSampleRequest => topics::SHARD_SAMPLE_REQUEST,
            Self::ShardSampleResponse => topics::SHARD_SAMPLE_RESPONSE,
            Self::L2TreeSync => topics::L2_SYNC,
            Self::L2ShieldBroadcast => topics::L2_SHIELD,
            Self::GhostGlyphClaim | Self::GhostGlyphRegistered => topics::GLYPH,
        }
    }

    /// M-P2P-1: Get the topic as a string for validation
    ///
    /// Used to validate that a message received on a topic actually matches
    /// the message type declared in the envelope.
    pub fn topic_str(&self) -> &'static str {
        match self {
            Self::ShareProof | Self::ShareConvergence => "share",
            Self::PayoutProposal => "payout",
            Self::Vote => "vote",
            Self::HealthPing => "health",
            Self::Discovery => "discovery",
            Self::VerificationResult | Self::ChallengeConvergence => "verify",
            Self::EquivocationProof => "equivoc",
            Self::MpcContribution => "mpc",
            Self::MpcVerificationVote => "mpc",
            Self::MpcParametersRequest => "mpc",
            Self::MpcParametersResponse => "mpc",
            Self::L2ConfidentialTransfer => "l2tx",
            Self::L2TransferConfirmation => "l2tx",
            Self::L2TransferBroadcast => "l2tx",
            Self::L2CheckpointBlock => "l2chk",
            Self::L2CheckpointVote => "l2vote",
            Self::PayoutLedgerCheckpoint => "plchk",
            Self::PayoutLedgerCheckpointVote => "plvote",
            Self::PayoutLedgerCheckpointSync => "plsync",
            Self::PayoutProposalSync => "ppsync",
            Self::ShareBatchProposal => "sbatch",
            Self::ShareBatchVote => "sbvote",
            Self::ShareBatchPrevote => "sbprev",
            Self::ShareBatchPrecommit => "sbprec",
            Self::ShareBatchSync => "sbsync",
            Self::MeshNodeListCheckpoint => "mnlchk",
            Self::MeshNodeListCheckpointVote => "mnlvote",
            Self::MeshNodeListCheckpointSync => "mnlsync",
            Self::MeshEndpointAdvertisement => "mnladv",
            Self::ShardEpochSummary => "shdsum",
            Self::ShardTableSync => "shdsync",
            Self::ShardEvidence => "shdevid",
            Self::ShardSampleRequest => "shdsreq",
            Self::ShardSampleResponse => "shdsrsp",
            Self::L2TreeSync => "l2sync",
            Self::L2ShieldBroadcast => "l2shield",
            Self::GhostGlyphClaim | Self::GhostGlyphRegistered => "glyph",
        }
    }
}

/// Share proof message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProofMessage {
    /// Share proof data
    pub proof: ShareProof,
}

/// Payout proposal message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutProposalMessage {
    /// Full payout proposal
    pub proposal: PayoutProposal,
}

/// Vote message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteMessage {
    /// Round ID
    pub round_id: RoundId,
    /// Proposal hash being voted on
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposal_hash: [u8; 32],
    /// Vote (true = approve, false = reject)
    pub approve: bool,
    /// Voter's signature on the proposal hash
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
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

/// Share convergence request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConvergenceMessage {
    /// Round ID to converge
    pub round_id: RoundId,
    /// Requesting node's share count
    pub share_count: u64,
    /// Requesting node's total work
    pub total_work: f64,
    /// Share hashes (for comparison)
    #[serde(with = "ghost_common::serde_hex::vec_bytes32")]
    pub share_hashes: Vec<[u8; 32]>,
}

/// Share convergence response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareConvergenceResponse {
    /// Round ID
    pub round_id: RoundId,
    /// Responding node's share count
    pub share_count: u64,
    /// Responding node's total work
    pub total_work: f64,
    /// Missing share hashes (shares the requestor doesn't have)
    pub missing_shares: Vec<ShareProof>,
    /// The responder held MORE missing proofs for this round than fitted in one response.
    ///
    /// Without it the requester cannot tell a complete answer from a truncated one, so it treats
    /// the round as reconciled and never asks again — which is how #558 hid for nine days on the
    /// ledger lane. `#[serde(default)]` keeps wire-compat: a peer predating this field sends
    /// `false`, i.e. exactly the old behaviour.
    #[serde(default)]
    pub more_available: bool,
}

// =============================================================================
// CAPABILITY VERIFICATION Messages
// =============================================================================

/// Capability type for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    /// Archive mode capability
    Archive,
    /// Policy (Bitcoin Pure) capability
    Policy,
    /// Stratum (Public Mining) capability
    Stratum,
    /// Ghost Pay capability
    GhostPay,
    /// H-7: the node proved it holds its identity key at the address it CLAIMS.
    ///
    /// Unlike the other four this is not a service the target offers — it is an
    /// observation the challenger made about WHERE the target answered. It cannot be
    /// re-derived by a third party: the signed reply binds the target's key to the
    /// challenger's nonce, but carries no address, so only the challenger knows which
    /// address it dialled. Convergence therefore rests entirely on the
    /// distinct-challenger majority, exactly as it does for a backfilled verdict.
    Address,
}

impl CapabilityType {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Policy => "policy",
            Self::Stratum => "stratum",
            Self::GhostPay => "ghostpay",
            Self::Address => "address",
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "archive" => Some(Self::Archive),
            "policy" => Some(Self::Policy),
            "stratum" => Some(Self::Stratum),
            "ghostpay" => Some(Self::GhostPay),
            "address" => Some(Self::Address),
            _ => None,
        }
    }
}

/// Verification result message - broadcast when a node verifies another's capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResultMessage {
    /// Node ID being verified (target)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub target_node_id: NodeId,
    /// Node ID that issued the challenge (challenger)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub challenger_id: NodeId,
    /// Capability being verified
    pub capability: CapabilityType,
    /// Whether the verification passed
    pub passed: bool,
    /// Challenge details (JSON, capability-specific)
    pub challenge_data: String,
    /// Response details (JSON, capability-specific)
    pub response_data: Option<String>,
    /// The TARGET's own signed response (`SignedResponse<…>` JSON), when the
    /// target returned one. This — not `response_data` (which the challenger
    /// authors) — is what lets a recipient RE-DERIVE the verdict against its own
    /// ground truth: the recipient verifies this is signed by `target_node_id`,
    /// then checks the attested response against its own Bitcoin Core / policy
    /// engine and overrides `passed`. `#[serde(default)]` so older peers that
    /// omit it still deserialize (backward-compatible fleet deploy).
    #[serde(default)]
    pub target_signed_response: Option<String>,
    /// Timestamp when challenge was issued
    pub timestamp: i64,
    /// Surface A-2b: the ROUND this challenge was issued in — the block height
    /// whose buried hash (`blockhash(round_height - CHALLENGER_ASSIGNMENT_SEED_LAG)`)
    /// seeds the consensus challenger draw. Qualification recomputes the draw for
    /// this round to decide whether this challenger was ASSIGNED to the target and
    /// therefore whether the verdict counts (only at/above CHALLENGER_ASSIGNMENT_HEIGHT).
    /// `#[serde(default)]` so older peers that omit it still deserialize.
    ///
    /// NOTE: not yet folded into `signing_data` — binding it into the signature
    /// (so a relay cannot tamper the round to drop an honest verdict) is a REQUIRED
    /// follow-up before the gate is armed; while the gate is dormant the field is
    /// only recorded, never consulted.
    #[serde(default)]
    pub round_height: Option<u64>,
    /// Challenger's signature over (target_node_id || capability || passed || timestamp)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

impl VerificationResultMessage {
    /// Get the data that should be signed
    pub fn signing_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.target_node_id);
        data.extend_from_slice(self.capability.as_str().as_bytes());
        data.push(if self.passed { 1 } else { 0 });
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        // A-2b: bind the round (so a relay can't retag a verdict to a round the
        // challenger WAS assigned in, to smuggle it past the filter). Appended ONLY
        // when present, so pre-A-2b verdicts (round_height = None, below the gate)
        // sign byte-identically to before and a mixed-version fleet verifies each
        // other across the roll. round_height becomes Some only at/above the gate,
        // by which point the fleet is uniform.
        if let Some(rh) = self.round_height {
            data.extend_from_slice(&rh.to_le_bytes());
        }
        data
    }
}

// =============================================================================
// ZK-BFT Message Types
// =============================================================================

/// Reason for rejecting a ZK block proposal
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZkRejectionReason {
    /// The ZK proof failed verification
    InvalidProof,
    /// State root doesn't match local computation
    StateRootMismatch,
    /// Block height is wrong (not sequential)
    InvalidHeight,
    /// Previous state root doesn't match current state
    PrevStateRootMismatch,
    /// Proposal came from non-eligible proposer
    InvalidProposer,
    /// Proposer signature is invalid
    InvalidSignature,
    /// Proposal timestamp is too old or in the future
    InvalidTimestamp,
    /// Block contains invalid transactions
    InvalidTransactions,
    /// Other validation failure
    Other(String),
}

// =============================================================================
// ZK Payout Message Types
// =============================================================================

/// ZK Payout Proposal - includes the payout distribution and validity proof
///
/// Generated by the epoch settler to prove fair distribution of rewards.
/// P2P-H3: Equivocation proof message for Byzantine behavior evidence
///
/// Broadcast when a node is detected voting for conflicting proposals in the same round.
/// Receiving nodes should:
/// 1. Verify the proof (both signatures must be valid for the claimed node)
/// 2. Ban the equivocating node
/// 3. Persist the proof for forensic analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationProofMessage {
    /// Node ID of the equivocating node
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub equivocator: [u8; 32],
    /// Round in which equivocation occurred
    pub round_id: u64,
    /// GHOST-11: proposal hash both conflicting votes were cast on. Lets a
    /// receiver verify the equivocator's two signatures INDEPENDENTLY of the
    /// reporter (so a malicious reporter can't frame an honest node).
    #[serde(with = "ghost_common::serde_hex::bytes32", default)]
    pub proposal_hash: [u8; 32],
    /// Type of vote (e.g., "payout_vote", "zk_vote")
    pub vote_type: String,
    /// First vote (serialized VoteMessage or similar)
    pub vote1_data: Vec<u8>,
    /// Second conflicting vote
    pub vote2_data: Vec<u8>,
    /// Node that detected the equivocation
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub reporter: [u8; 32],
    /// Reporter's signature over the proof
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub reporter_signature: [u8; 64],
    /// Timestamp when equivocation was detected
    pub timestamp: u64,
}

impl EquivocationProofMessage {
    /// Create a new equivocation proof message
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        equivocator: [u8; 32],
        round_id: u64,
        proposal_hash: [u8; 32],
        vote_type: String,
        vote1_data: Vec<u8>,
        vote2_data: Vec<u8>,
        reporter: [u8; 32],
    ) -> Self {
        Self {
            equivocator,
            round_id,
            proposal_hash,
            vote_type,
            vote1_data,
            vote2_data,
            reporter,
            reporter_signature: [0u8; 64], // Must be set via sign()
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Get the message to be signed by the reporter
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"EquivocationProof/v1");
        hasher.update(self.equivocator);
        hasher.update(self.round_id.to_le_bytes());
        hasher.update(self.proposal_hash);
        hasher.update(self.vote_type.as_bytes());
        hasher.update(&self.vote1_data);
        hasher.update(&self.vote2_data);
        hasher.update(self.reporter);
        hasher.finalize().into()
    }

    /// Sign the proof with the reporter's identity
    pub fn sign(&mut self, sign_fn: impl FnOnce(&[u8]) -> [u8; 64]) {
        let message = self.signing_message();
        self.reporter_signature = sign_fn(&message);
    }

    /// Verify the reporter's signature
    ///
    /// SEC-SIG-3: Logs errors instead of silently returning false
    pub fn verify_reporter_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(
            &self.reporter,
            &message,
            &self.reporter_signature,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    reporter = %hex::encode(&self.reporter[..8]),
                    error = %e,
                    "Equivocation proof signature verification error"
                );
                false
            }
        }
    }
}

// =============================================================================
// P2P-C1/C2/C3: CANONICAL ELDER LIST Messages
// =============================================================================

// =============================================================================
// MPC-C1/C2/C3/C4: MPC CEREMONY Messages
// =============================================================================

/// MPC-C1: MPC contribution message
///
/// Sent by a node becoming an elder to contribute to the MPC ceremony.
/// Contains the new parameters hash and proof of valid transformation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcContributionMessage {
    /// Candidate's node ID (must match pending registration)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub candidate: NodeId,
    /// Elder position (1-101)
    pub elder_position: u32,
    /// Hash of the previous parameters (chain link)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub prev_params_hash: [u8; 32],
    /// Hash of the new parameters after contribution
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub new_params_hash: [u8; 32],
    /// Proof of valid contribution (Schnorr proof data)
    pub contribution_proof: Vec<u8>,
    /// Candidate's signature over the contribution
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl MpcContributionMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MpcContribution/v1");
        hasher.update(self.candidate);
        hasher.update(self.elder_position.to_le_bytes());
        hasher.update(self.prev_params_hash);
        hasher.update(self.new_params_hash);
        hasher.update(sha2::Sha256::digest(&self.contribution_proof));
        hasher.finalize().into()
    }

    /// Get a hash of this contribution for voting reference
    ///
    /// Delegates to the single shared definition in `ghost_common::mpc` so the
    /// live voter and the genesis-anchored startup verifier (which re-derives
    /// this from retained DB rows) compute byte-identical hashes.
    pub fn contribution_hash(&self) -> [u8; 32] {
        ghost_common::mpc::contribution_hash(
            &self.candidate,
            self.elder_position,
            &self.new_params_hash,
        )
    }

    /// Verify the candidate's signature
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(&self.candidate, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    candidate = %hex::encode(&self.candidate[..8]),
                    position = self.elder_position,
                    error = %e,
                    "MPC contribution signature verification error"
                );
                false
            }
        }
    }
}

/// MPC-C2: MPC verification vote message
///
/// Sent by current elders to vote on an MPC contribution.
/// Requires >67% approval before contribution is applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcVerificationVoteMessage {
    /// Hash of the contribution being voted on
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub contribution_hash: [u8; 32],
    /// Voter's node ID (must be current elder)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Approve (true) or reject (false)
    pub approve: bool,
    /// Rejection reason if not approved
    pub rejection_reason: Option<String>,
    /// Voter's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl MpcVerificationVoteMessage {
    /// Get the message to be signed
    ///
    /// Delegates to `ghost_common::mpc` so a retained vote signature verifies
    /// identically whether checked live here or re-derived at startup.
    pub fn signing_message(&self) -> [u8; 32] {
        ghost_common::mpc::vote_signing_message(&self.contribution_hash, self.approve)
    }

    /// Verify the voter's signature
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(&self.voter, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    voter = %hex::encode(&self.voter[..8]),
                    contribution = %hex::encode(&self.contribution_hash[..8]),
                    error = %e,
                    "MPC verification vote signature verification error"
                );
                false
            }
        }
    }
}

/// MPC-C3: MPC parameters request message
///
/// Request parameter files from peers. Used during node startup
/// when local parameters are missing or outdated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcParametersRequestMessage {
    /// Requester's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub requester: NodeId,
    /// Hash of parameters being requested
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub params_hash: [u8; 32],
    /// Specific chunk indices to request (empty = all)
    pub chunk_indices: Vec<u32>,
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

/// MPC-C4: MPC parameters response message
///
/// Response containing chunked parameter data.
/// Parameters are ~200MB, so must be transferred in chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcParametersResponseMessage {
    /// Hash of the parameters being sent
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub params_hash: [u8; 32],
    /// Total size of parameters in bytes
    pub total_size: u64,
    /// Total number of chunks
    pub total_chunks: u32,
    /// Index of this chunk (0-based)
    pub chunk_index: u32,
    /// Chunk data (up to 1MB per chunk)
    pub chunk_data: Vec<u8>,
    /// Sender's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub sender: NodeId,
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

// =============================================================================
// L2 NOTE/UTXO MODEL MESSAGES
// =============================================================================

/// L2 transaction (sender creates, ~490 bytes)
///
/// Contains a ZK proof that a note spend is valid, plus encrypted
/// note data for sender and recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Transaction {
    /// Which epoch's tree this references
    pub epoch: u64,
    /// Nullifier (prevents double-spend, routes to validator)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub nullifier: [u8; 32],
    /// Change commitment (sender's new note)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub change_commitment: [u8; 32],
    /// Recipient commitment (recipient's new note)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub recipient_commitment: [u8; 32],
    /// Commitment root at proof time (Merkle inclusion)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub commitment_root: [u8; 32],
    /// Groth16 proof (192 bytes)
    pub proof: Vec<u8>,
    /// Encrypted note data for sender (change note)
    pub encrypted_change: Vec<u8>,
    /// Encrypted note data for recipient
    pub encrypted_recipient: Vec<u8>,
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

/// L2: Shield commitment (for checkpoint batching and transfer prerequisites)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldCommitment {
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub commitment: [u8; 32],
    pub note_index: u64,
    pub block_height: u64,
}

/// Epoch transition data (present at epoch boundary checkpoints)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochTransition {
    /// New epoch number
    pub new_epoch: u64,
    /// Compacted tree root
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub new_initial_root: [u8; 32],
}

/// L2: Confidential transfer submission (sender → assigned validator)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2ConfidentialTransferMessage {
    /// The transaction with proof
    pub transaction: L2Transaction,
    /// Sender's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub sender: NodeId,
}

/// L2: Transfer confirmation receipt (validator → sender)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TransferConfirmationMessage {
    /// Nullifier of the confirmed transaction
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub nullifier: [u8; 32],
    /// Validator that confirmed it
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub validator: NodeId,
    /// Confirmation timestamp
    pub timestamp: u64,
    /// Validator's signature over the nullifier
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

impl L2TransferConfirmationMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"L2TransferConfirmation/v1");
        hasher.update(self.nullifier);
        hasher.update(self.timestamp.to_le_bytes());
        hasher.finalize().into()
    }
}

/// L2: Broadcast confirmed tx to all nodes (validator → all)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TransferBroadcastMessage {
    /// The confirmed transaction
    pub transaction: L2Transaction,
    /// Validator that confirmed it
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub validator: NodeId,
    /// Validator's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Shield commitments that must be applied before validating this transfer's root.
    /// Piggybacked on the broadcast for instant (~100-200ms) network confirmation
    /// instead of waiting for the next checkpoint (~10s).
    #[serde(default)]
    pub prerequisites: Vec<ShieldCommitment>,
}

impl L2TransferBroadcastMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"L2TransferBroadcast/v1");
        hasher.update(self.transaction.nullifier);
        hasher.update(self.transaction.change_commitment);
        hasher.update(self.transaction.recipient_commitment);
        for p in &self.prerequisites {
            hasher.update(p.commitment);
            hasher.update(p.note_index.to_le_bytes());
        }
        hasher.finalize().into()
    }
}

/// L2: Checkpoint block proposal (proposer → all)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2CheckpointBlockMessage {
    /// Checkpoint height
    pub height: u64,
    /// Epoch number
    pub epoch: u64,
    /// Previous commitment root
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub prev_commitment_root: [u8; 32],
    /// New commitment root (after appending all new commitments)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub new_commitment_root: [u8; 32],
    /// Transactions included in this checkpoint
    pub transactions: Vec<L2Transaction>,
    /// Shield commitments included in this checkpoint (fallback distribution path).
    /// Nodes that missed piggybacked prerequisites get shields here.
    #[serde(default)]
    pub shield_commitments: Vec<ShieldCommitment>,
    /// Number of active nodes at this checkpoint
    pub active_node_count: u32,
    /// Proposer's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
    /// Epoch transition data (present at epoch boundary)
    pub epoch_transition: Option<EpochTransition>,
}

impl L2CheckpointBlockMessage {
    /// Compute the hash of this checkpoint for voting
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"L2CheckpointBlock/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.prev_commitment_root);
        hasher.update(self.new_commitment_root);
        hasher.update((self.transactions.len() as u64).to_le_bytes());
        for tx in &self.transactions {
            hasher.update(tx.nullifier);
        }
        hasher.update((self.shield_commitments.len() as u64).to_le_bytes());
        for sc in &self.shield_commitments {
            hasher.update(sc.commitment);
            hasher.update(sc.note_index.to_le_bytes());
        }
        hasher.finalize().into()
    }

    /// Get the deterministic signable bytes for the proposer signature.
    /// Covers all fields except the signature itself.
    pub fn to_signable_bytes(&self) -> [u8; 32] {
        self.checkpoint_hash()
    }
}

/// L2: Checkpoint vote (validator → all, all-node BFT)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2CheckpointVoteMessage {
    /// Checkpoint height being voted on
    pub height: u64,
    /// Hash of the checkpoint block
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub checkpoint_hash: [u8; 32],
    /// Voter's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Vote (true = approve)
    pub approve: bool,
    /// Voter's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl L2CheckpointVoteMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"L2CheckpointVote/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.checkpoint_hash);
        hasher.update([self.approve as u8]);
        hasher.finalize().into()
    }
}

/// Payout-ledger checkpoint proposal (proposer → all).
///
/// The BFT-finalised snapshot the coinbase is a pure function of: at a lagging
/// `height`, the `ledger_root` commits the canonical unpaid-miner set and
/// qualified-node set as of `cutoff_ts` (= the anchor block's time). Every node
/// recomputes the root from its own converged ledger and votes approve iff it
/// matches; 67% finalises it identically fleet-wide (see `payout::compute_ledger_root`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutLedgerCheckpointMessage {
    /// Lagging anchor height this checkpoint pins the payout ledger at.
    pub height: u64,
    /// Ledger cutoff = the anchor block's timestamp (deterministic, chain-committed).
    pub cutoff_ts: i64,
    /// Canonical payout-ledger root (miner set ‖ node set) as of `cutoff_ts`.
    /// Equals `H(miner_payouts ‖ node_shares)`, so the signed `checkpoint_hash`
    /// commits to the lists below and voters can verify their integrity.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub ledger_root: [u8; 32],
    /// The CANONICAL miner payout set the proposer computed: `(payout_address,
    /// WORK_SCALE-quantised work)`, top-N. Option (c): voters tolerance-check it and
    /// ADOPT it verbatim on finalise, so agreement doesn't need identical local ledgers.
    #[serde(default)]
    pub miner_payouts: Vec<(String, u128)>,
    /// The CANONICAL qualified-node set: `(node_id, 5-4-3-2-1 shares)`, top-N.
    #[serde(default)]
    pub node_shares: Vec<(NodeId, i32)>,
    /// Number of active nodes at this checkpoint.
    pub active_node_count: u32,
    /// Proposer's node ID (deterministic election for `height`).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature over `checkpoint_hash()`.
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
}

impl PayoutLedgerCheckpointMessage {
    /// Content hash (excludes the signature) — the object voters sign/compare.
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"PayoutLedgerCheckpoint/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.cutoff_ts.to_le_bytes());
        hasher.update(self.ledger_root);
        hasher.update(self.active_node_count.to_le_bytes());
        hasher.update(self.proposer);
        hasher.finalize().into()
    }
}

/// A vote for a batch at a sequence.
///
/// Small on purpose: a hash and a signature. The batch it names is fetched or already held, never
/// re-sent with every vote — eight nodes echoing a megabyte back at each other would make the
/// vote round cost more than the proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBatchVoteMessage {
    /// Chain position being voted on.
    pub seq: u64,
    /// The batch being approved.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub batch_hash: [u8; 32],
    /// Who is voting.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Signature over `(seq, batch_hash)`.
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

impl ShareBatchVoteMessage {
    /// The bytes a vote signs.
    ///
    /// **Both** the sequence and the hash, domain-separated. Signing the hash alone would let a
    /// vote be replayed at a different sequence, and signing the sequence alone would make every
    /// vote at that height interchangeable — either one turns a signature into a formality.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 + 24);
        out.extend_from_slice(b"ShareBatchVote/v1");
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.batch_hash);
        out
    }
}

/// A two-phase vote on a share batch: prevote or precommit, distinguished by `MessageType`.
///
/// One struct for both phases because the payload is identical; the PHASE is carried by the
/// message type and, critically, by the signing domain. `signing_bytes` takes the phase and
/// domain-separates on it, so a prevote's signature does not verify as a precommit. Without that
/// separation an attacker could replay a node's prevote as a precommit and manufacture a commit
/// from evidence that was only ever meant to release a lock — which collapses two-phase back into
/// the single-phase design that cannot be made safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareBatchPhaseVoteMessage {
    /// Chain position being voted on.
    pub seq: u64,
    /// The escalation step this vote belongs to. A sequence can have several candidates; without
    /// the round a receiver cannot tell which attempt a vote was cast in.
    pub round: u32,
    /// The batch being voted for.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub batch_hash: [u8; 32],
    /// Who is voting.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Signature over `(phase, seq, round, batch_hash)`.
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

/// Which phase a [`ShareBatchPhaseVoteMessage`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchVotePhase {
    /// Evidence that a quorum considered a batch valid. Releases locks; decides nothing.
    Prevote,
    /// A commitment to a locked value. A quorum of these decides the sequence.
    Precommit,
}

impl BatchVotePhase {
    /// The domain tag this phase signs under. Distinct by construction — see
    /// [`ShareBatchPhaseVoteMessage::signing_bytes`] for why sharing one would be fatal.
    pub fn domain(&self) -> &'static [u8] {
        match self {
            Self::Prevote => b"ShareBatchPrevote/v1",
            Self::Precommit => b"ShareBatchPrecommit/v1",
        }
    }
}

impl ShareBatchPhaseVoteMessage {
    /// The bytes this vote signs, domain-separated **by phase**.
    ///
    /// The phase tag is the first thing in the buffer and differs in length as well as content, so
    /// no prevote payload can be reinterpreted as a precommit payload by shifting bytes.
    ///
    /// Everything else is covered for the reasons the single-phase vote already documented: the
    /// hash alone replays at another sequence, the sequence alone makes every vote at that height
    /// interchangeable, and the round alone lets a vote from a losing round be replayed into the
    /// live one.
    pub fn signing_bytes(&self, phase: BatchVotePhase) -> Vec<u8> {
        let domain = phase.domain();
        let mut out = Vec::with_capacity(domain.len() + 8 + 4 + 32);
        out.extend_from_slice(domain);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.round.to_le_bytes());
        out.extend_from_slice(&self.batch_hash);
        out
    }
}

/// Request or response for an adopted batch a node is missing.
///
/// One type for both directions, disambiguated on deserialize — the same shape the convergence and
/// proposal-sync exchanges already use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShareBatchSyncMessage {
    /// "Send me the adopted batch at this sequence."
    ///
    /// By sequence rather than hash, because a node that is behind does not know the hash — that
    /// is precisely what it is missing.
    Request { seq: u64 },
    /// The batch, as stored JSON, with the certificate that proves it was committed.
    ///
    /// The certificate is what makes catch-up both safe and possible. A node that missed a
    /// sequence's consensus cannot tell from local state whether a batch it is offered was
    /// actually decided — every local heuristic for that question is either forgeable (an
    /// attacker induces the condition) or unreachable (an honest node can never satisfy it, which
    /// wedges catch-up entirely). The answer is not to infer it: the peer that HAS the proof
    /// supplies it, and the receiver checks it against the voter set.
    ///
    /// Optional so a node that adopted before certificates existed can still answer with the
    /// batch alone; such a response is only adoptable on the older, weaker path.
    Response {
        seq: u64,
        batch_json: String,
        #[serde(default)]
        cert: Option<CommitCertificate>,
    },
}

/// Proof that a quorum committed a specific batch at a specific `(seq, round)`.
///
/// Just the precommit signatures. It is unforgeable without an actual quorum of voter keys,
/// cannot be induced by manipulating a victim's local state, and is always available to any node
/// that witnessed the commit — the three properties every local heuristic lacked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitCertificate {
    pub seq: u64,
    /// The round the precommits were cast at. Signatures cover it, so a certificate cannot be
    /// re-presented for a different round.
    pub round: u32,
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub batch_hash: [u8; 32],
    /// The VOTER SET this certificate was minted against, as a hash of the sorted ids.
    ///
    /// Without this the proof is only as strong as the receiver's own membership view — and that
    /// view is a live per-node database query that shrinks during discovery warmup, restart and
    /// partition. A shrunken view lowers `bft_threshold`, so a bundle of GENUINE sub-quorum
    /// precommits from a losing round would verify: at a view of six the bar falls to four, and
    /// precommits are public signed gossip that anyone can collect. No key compromise, no
    /// inducement, no request needed.
    ///
    /// Binding the certificate to a membership means a receiver can only check a quorum it agrees
    /// on the shape of. Disagreeing is not a fault — it means "I cannot judge this", which is the
    /// honest answer.
    #[serde(default, with = "ghost_common::serde_hex::bytes32")]
    pub voter_set_hash: [u8; 32],
    /// `(voter, signature)` pairs over the PRECOMMIT signing domain.
    pub precommits: Vec<(String, String)>,
}

/// Identity of a voter set: SHA256 over its sorted, concatenated node ids.
///
/// Sorted so every node derives the same hash from the same membership regardless of the order it
/// learned them in — the same reason `ProposerSchedule` sorts.
pub fn voter_set_hash(voters: &[NodeId]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<NodeId> = voters.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut h = Sha256::new();
    for v in &sorted {
        h.update(v);
    }
    h.finalize().into()
}

impl CommitCertificate {
    /// Check this certificate against a voter set and a required quorum.
    ///
    /// Fail-closed and independent of any local opinion: every signature must verify over the
    /// precommit domain for exactly this `(seq, round, batch_hash)`, every signer must be a known
    /// voter, duplicates count once, and the total must reach quorum. Nothing here consults what
    /// the receiver believes, which is the point — a node catching up believes nothing.
    pub fn verify(&self, voters: &[NodeId], quorum: usize) -> bool {
        use std::collections::BTreeSet;

        // A quorum of zero is not a quorum. `bft_threshold(0) == 0`, so an empty voter view plus
        // an empty `precommits` vec satisfied `0 >= 0` and adopted anything — fail-open at exactly
        // the moment a node knows least, which is startup before discovery completes.
        if quorum == 0 || self.precommits.is_empty() {
            return false;
        }

        // The certificate must have been minted against the membership we are checking it with.
        // Otherwise the bar is set by OUR view, and a degraded view lowers it far enough that
        // genuine sub-quorum signatures from a losing round pass.
        if self.voter_set_hash != voter_set_hash(voters) {
            return false;
        }

        let mut seen: BTreeSet<NodeId> = BTreeSet::new();
        for (voter_hex, sig_hex) in &self.precommits {
            let Ok(voter_raw) = hex::decode(voter_hex) else {
                return false;
            };
            let Ok(voter) = <[u8; 32]>::try_from(voter_raw.as_slice()) else {
                return false;
            };
            if !voters.contains(&voter) {
                return false;
            }
            let Ok(sig_raw) = hex::decode(sig_hex) else {
                return false;
            };
            let Ok(sig) = <[u8; 64]>::try_from(sig_raw.as_slice()) else {
                return false;
            };
            let probe = ShareBatchPhaseVoteMessage {
                seq: self.seq,
                round: self.round,
                batch_hash: self.batch_hash,
                voter,
                signature: sig,
            };
            if !ghost_common::identity::verify_signature(
                &voter,
                &probe.signing_bytes(BatchVotePhase::Precommit),
                &sig,
            )
            .unwrap_or(false)
            {
                return false;
            }
            seen.insert(voter);
        }
        seen.len() >= quorum
    }
}

/// Payout-ledger checkpoint vote (validator → all).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutLedgerCheckpointVoteMessage {
    /// Checkpoint height being voted on.
    pub height: u64,
    /// Hash of the checkpoint being voted on (`PayoutLedgerCheckpointMessage::checkpoint_hash`).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub checkpoint_hash: [u8; 32],
    /// Voter's node ID.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Vote (true = approve; the voter reproduced the same `ledger_root`).
    pub approve: bool,
    /// Voter's signature over `signing_message()`.
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
    /// This voter's OWN recomputed per-address miner work, `(payout_address, quantised work)` (#606).
    ///
    /// Empty below the report-and-median gate, and empty on a reject. Above it, an approving voter
    /// reports the numbers it recomputed instead of discarding them, so finalisation can adopt the
    /// per-address median rather than the proposer's list — which is what stops a proposer skewing
    /// every address within tolerance and still being ratified.
    ///
    /// `#[serde(default)]` so a vote from a node on an older build still deserialises.
    #[serde(default)]
    pub reported_miner_work: Vec<(String, u128)>,
    /// This voter's own recomputed qualified-node set, `(node_id, 5-4-3-2-1 shares)` (#606).
    #[serde(default)]
    pub reported_node_shares: Vec<(NodeId, i32)>,
}

impl PayoutLedgerCheckpointVoteMessage {
    /// Get the message to be signed.
    ///
    /// The reported values are folded in DELIBERATELY. Without that, any relay could rewrite a
    /// voter's numbers in flight and steer the median — which would turn #606's fix into a strictly
    /// worse hole than the one it closes, since influence would pass from the proposer alone to any
    /// participant on the path.
    ///
    /// The domain tag stays `/v1` and the reported fields are appended with an explicit count
    /// prefix. An old-format vote carries empty vectors, so it hashes to exactly the same digest as
    /// it did before this change and its signature still verifies — the wire format is additive in
    /// both directions.
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"PayoutLedgerCheckpointVote/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.checkpoint_hash);
        hasher.update([self.approve as u8]);
        // Folded in ONLY when non-empty, so an empty report hashes byte-identically to the
        // pre-#606 format.
        //
        // This is not a nicety. Hashing the length prefixes unconditionally appends two zero u64s
        // and changes the digest of every ordinary vote — so a node on this build and a node on the
        // previous one would compute different digests for the same vote and each would reject the
        // other's signature. That is a fleet-wide loss of quorum the moment the binary ships,
        // whether or not the gate is armed. Caught by
        // `an_empty_report_hashes_as_the_old_format_did`, which failed against the first version of
        // this function.
        //
        // Within the non-empty branch, lengths are prefixed and fields framed so no two distinct
        // reports can collide by concatenation — [("ab", 1)] must not hash as
        // [("a", 1), ("b", 1)].
        if !self.reported_miner_work.is_empty() {
            hasher.update(b"miner_work");
            hasher.update((self.reported_miner_work.len() as u64).to_le_bytes());
            for (addr, work) in &self.reported_miner_work {
                hasher.update((addr.len() as u64).to_le_bytes());
                hasher.update(addr.as_bytes());
                hasher.update(work.to_le_bytes());
            }
        }
        if !self.reported_node_shares.is_empty() {
            hasher.update(b"node_shares");
            hasher.update((self.reported_node_shares.len() as u64).to_le_bytes());
            for (node, shares) in &self.reported_node_shares {
                hasher.update(node);
                hasher.update(shares.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }
}

/// One finalised payout checkpoint carried in a sync response. Deliberately
/// signature-free: the requester adopts it only after independently recomputing
/// the canonical payout and tolerance-checking these lists (trustless apply), so
/// no trust is placed in the serving peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutCheckpointSyncEntry {
    /// Lagging anchor height.
    pub height: u64,
    /// Ledger cutoff = anchor block's timestamp.
    pub cutoff_ts: i64,
    /// Canonical payout-ledger root as of `cutoff_ts` (= `H(miner_payouts ‖ node_shares)`).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub ledger_root: [u8; 32],
    /// Canonical miner payout set `(payout_address, quantised work)`.
    #[serde(default)]
    pub miner_payouts: Vec<(String, u128)>,
    /// Canonical qualified-node set `(node_id, 5-4-3-2-1 shares)`.
    #[serde(default)]
    pub node_shares: Vec<(NodeId, i32)>,
    /// Active-node count at this checkpoint.
    pub active_node_count: u32,
    /// Deterministic proposer for `height` (checked against `proposer_for(height)` on apply).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
}

/// Payout-ledger checkpoint sync REQUEST (node → peers): "send me finalised
/// checkpoints from `from_height` up." Backfills holes left by missed proposals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutCheckpointSyncRequest {
    /// The node asking to be backfilled.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub requesting_node: NodeId,
    /// Lowest height the requester lacks (its `latest_finalised + 1`).
    pub from_height: u64,
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
}

/// Payout-ledger checkpoint sync RESPONSE (peer → requester): a bounded, ascending
/// page of finalised checkpoints. `has_more` signals the requester to paginate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutCheckpointSyncResponse {
    /// The peer serving the backfill.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub responding_node: NodeId,
    /// Finalised checkpoints, ascending from the requested height (bounded page).
    pub checkpoints: Vec<PayoutCheckpointSyncEntry>,
    /// True if the responder hit its page cap — the requester should re-request.
    pub has_more: bool,
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Mesh node-list checkpoint (decentralised mining discovery).
//
// A BFT-finalised, signed snapshot of the public-mining node set that an
// UNTRUSTED miner-side client can verify offline. Mirrors the payout-ledger
// checkpoint machinery. Trust model (design decision C, hybrid): a shim carries
// a baked-in genesis signer set and advances it via the signed forward chain —
// each checkpoint's `signer_set_delta` is attested by ≥67% of the PRIOR set
// (the approver signatures over `checkpoint_hash`, which commits `signer_set_root`).
// Because `node_id` IS the node's Ed25519 public key, a shim verifies every
// signature with no key distribution. See tasks/design_mesh_node_list_checkpoint.md.
// ─────────────────────────────────────────────────────────────────────────────

/// One public-mining node in a mesh node-list checkpoint: the {identity, endpoint}
/// tuple a miner-side shim needs to connect. `node_id` is the node's Ed25519 public
/// key, so a shim can verify anything this node signs with no key distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshNodeEntry {
    /// Node identity = Ed25519 public key.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub node_id: NodeId,
    /// Public host WITHOUT a port, e.g. "203.0.113.7" or a hostname.
    pub host: String,
    /// Stratum V1 port (SV1 miners: Bitaxe/CGMiner).
    pub sv1_port: u16,
    /// Stratum V2 port.
    pub sv2_port: u16,
}

/// A node's own signed statement of where miners reach it.
///
/// The endpoint is the one field in a node-list checkpoint that consensus does not already
/// know. Membership comes from the ratified qualified set — objective, and backed by the
/// stratum handshake challenge — but nothing on-chain records the host a miner should dial.
/// Previously each node filled that in from its OWN peer table, which is why the list could
/// never converge (#625: six distinct sets across seven reporters).
///
/// So the subject signs it. An advert is verifiable from its own bytes against `node_id`,
/// which is the Ed25519 public key, so a voter needs no local view of the advertised node —
/// exactly the self-proving property a `ShareProof` has. Nobody can advertise on another
/// node's behalf, and nobody has to have met a node to agree where it lives.
///
/// `seq` is monotonic per node so a re-homed node supersedes its own earlier advert; ties
/// (a node reusing a `seq`) are broken by taking the lexicographically smaller signature, so
/// the choice is deterministic rather than arrival-ordered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshEndpointAdvert {
    /// Subject and signer. Ed25519 public key.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub node_id: NodeId,
    /// Public host WITHOUT a port, e.g. "203.0.113.7" or a hostname.
    pub host: String,
    /// Stratum V1 port (SV1 miners: Bitaxe/CGMiner).
    pub sv1_port: u16,
    /// Stratum V2 port.
    pub sv2_port: u16,
    /// Whether this node offers public mining at all. Carried rather than implied: the
    /// proposal must cover EVERY qualified node, so a node that does not serve miners is
    /// carried with `false` and filtered out deterministically. Selective omission by a
    /// proposer is then detectable, because a short list fails the coverage check.
    pub public_mining: bool,
    /// Monotonic per node. A higher `seq` supersedes.
    pub seq: u64,
    /// The subject's signature over [`MeshEndpointAdvert::signing_bytes`].
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
}

impl MeshEndpointAdvert {
    /// Domain-tagged, every variable-length field length-prefixed, so no two distinct adverts
    /// can serialise to the same bytes by running fields together.
    ///
    /// The signature is NOT covered, for the obvious reason.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(64 + self.host.len());
        v.extend_from_slice(b"MeshEndpointAdvert/v1");
        v.extend_from_slice(&self.node_id);
        let hb = self.host.as_bytes();
        v.extend_from_slice(&(hb.len() as u32).to_le_bytes());
        v.extend_from_slice(hb);
        v.extend_from_slice(&self.sv1_port.to_le_bytes());
        v.extend_from_slice(&self.sv2_port.to_le_bytes());
        v.push(u8::from(self.public_mining));
        v.extend_from_slice(&self.seq.to_le_bytes());
        v
    }

    /// Does this advert prove itself? Signature by the subject over its own contents.
    ///
    /// Fail-closed on a verification error, the same sense as
    /// `ShareProof::has_valid_bound_signature`: an error is not a valid signature.
    pub fn is_self_signed(&self) -> bool {
        ghost_common::identity::verify_signature(
            &self.node_id,
            &self.signing_bytes(),
            &self.signature,
        )
        .unwrap_or(false)
    }

    /// The rendered directory entry, once membership and signature have been established.
    pub fn to_entry(&self) -> MeshNodeEntry {
        MeshNodeEntry {
            node_id: self.node_id,
            host: self.host.clone(),
            sv1_port: self.sv1_port,
            sv2_port: self.sv2_port,
        }
    }
}

/// Why a proposed node list is not the one this node would have derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshListRejection {
    /// An advert's signature does not verify against its own `node_id`.
    AdvertNotSelfSigned { node_id: NodeId },
    /// Two adverts for one node with the same `seq` and the same signature.
    DuplicateAdvert { node_id: NodeId },
    /// The adverts do not cover a node that the ratified qualified set contains.
    MissingAdvert { node_id: NodeId },
    /// An advert for a node that is not in the ratified qualified set.
    UnqualifiedAdvert { node_id: NodeId },
    /// An advertised host is empty, so there is nothing for a miner to dial.
    EmptyHost { node_id: NodeId },
}

/// Derive the canonical node list from the ratified qualified set and the carried adverts.
///
/// **One spelling, two callers.** The proposer builds a checkpoint with this and a voter
/// re-derives with it; a second spelling is how a proposer and its verifier drift apart, and
/// here the disagreement would be permanent rather than transient — an exact-set consensus
/// that never converges produces no checkpoint at all, silently (#625).
///
/// The result is a pure function of `qualified` and `adverts`. It reads no clock, no peer
/// table and no database, which is the whole point: the previous derivation consulted a
/// 120-second liveness window and produced six distinct sets across seven nodes.
///
/// Liveness is not lost by removing that window. Membership comes from the qualified set,
/// and qualification already requires an independent challenger to complete a stratum
/// handshake against the node (`STRATUM_HANDSHAKE_PROOF`), ratified by consensus. That is a
/// stronger liveness signal than "some peer had a socket open recently", and unlike the
/// window it is the same for everyone.
pub fn derive_mesh_node_list(
    qualified: &[NodeId],
    adverts: &[MeshEndpointAdvert],
) -> Result<Vec<MeshNodeEntry>, MeshListRejection> {
    use std::collections::BTreeMap;

    let qualified_set: std::collections::BTreeSet<NodeId> = qualified.iter().copied().collect();

    // Signature first: it is cheap, and an advert nobody signed should not reach the
    // membership checks at all.
    let mut best: BTreeMap<NodeId, &MeshEndpointAdvert> = BTreeMap::new();
    for a in adverts {
        if !a.is_self_signed() {
            return Err(MeshListRejection::AdvertNotSelfSigned { node_id: a.node_id });
        }
        if a.host.is_empty() {
            return Err(MeshListRejection::EmptyHost { node_id: a.node_id });
        }
        if !qualified_set.contains(&a.node_id) {
            return Err(MeshListRejection::UnqualifiedAdvert { node_id: a.node_id });
        }
        match best.get(&a.node_id) {
            None => {
                best.insert(a.node_id, a);
            }
            Some(prev) => {
                // Higher `seq` wins. On an equal `seq` the smaller signature wins, so a node
                // that reuses a `seq` cannot make the outcome depend on arrival order — an
                // identical duplicate is a genuine error rather than a tie.
                if a.seq > prev.seq {
                    best.insert(a.node_id, a);
                } else if a.seq == prev.seq {
                    match a.signature.cmp(&prev.signature) {
                        std::cmp::Ordering::Less => {
                            best.insert(a.node_id, a);
                        }
                        std::cmp::Ordering::Equal => {
                            return Err(MeshListRejection::DuplicateAdvert { node_id: a.node_id })
                        }
                        std::cmp::Ordering::Greater => {}
                    }
                }
            }
        }
    }

    // Coverage must be TOTAL. Without this a proposer could omit a node it dislikes and the
    // shorter list would still be internally consistent.
    for id in &qualified_set {
        if !best.contains_key(id) {
            return Err(MeshListRejection::MissingAdvert { node_id: *id });
        }
    }

    // `best` is a BTreeMap, so this is already ordered by node_id.
    Ok(best
        .values()
        .filter(|a| a.public_mining)
        .map(|a| a.to_entry())
        .collect())
}

/// Canonical root over the ADVERTS a checkpoint adopts.
///
/// Distinct from [`mesh_node_list_root`], which roots the rendered entries a shim consumes.
/// Both are committed: the entry root is what a miner acts on, the advert root is what makes
/// the entries attributable, and binding only the former would let a proposer swap in an
/// unsigned host.
pub fn mesh_advert_set_root(adverts: &[MeshEndpointAdvert]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&MeshEndpointAdvert> = adverts.iter().collect();
    sorted.sort_by_key(|a| a.node_id);
    let mut hasher = Sha256::new();
    hasher.update(b"MeshAdvertSet/v1");
    hasher.update((sorted.len() as u32).to_le_bytes());
    for a in sorted {
        hasher.update(a.signing_bytes());
        hasher.update(a.signature);
    }
    hasher.finalize().into()
}

/// Canonical Merkle-free root over a node list: sort by `node_id`, then hash each
/// entry length-prefixed. Every node derives the byte-identical root from the same
/// set, so `list_root` binds the list inside `checkpoint_hash`.
pub fn mesh_node_list_root(nodes: &[MeshNodeEntry]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&MeshNodeEntry> = nodes.iter().collect();
    sorted.sort_by_key(|n| n.node_id);
    let mut hasher = Sha256::new();
    hasher.update(b"MeshNodeList/v1");
    hasher.update((sorted.len() as u32).to_le_bytes());
    for n in sorted {
        hasher.update(n.node_id);
        let hb = n.host.as_bytes();
        hasher.update((hb.len() as u32).to_le_bytes());
        hasher.update(hb);
        hasher.update(n.sv1_port.to_le_bytes());
        hasher.update(n.sv2_port.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Canonical root over a signer set (sort + dedup, then hash). Binds the resulting
/// signer set inside `checkpoint_hash` so the forward-chain delta is authenticated.
pub fn mesh_signer_set_root(set: &[NodeId]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut sorted = set.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut hasher = Sha256::new();
    hasher.update(b"MeshSignerSet/v1");
    hasher.update((sorted.len() as u32).to_le_bytes());
    for id in sorted {
        hasher.update(id);
    }
    hasher.finalize().into()
}

/// How the signer set changed versus the previous checkpoint — the signed forward
/// chain (decision C). A shim applies this to advance its trusted set; the delta is
/// authenticated because `checkpoint_hash` commits `signer_set_root` (the root of
/// the set AFTER applying it) and the checkpoint is approved by ≥67% of the prior set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSetDelta {
    /// Node IDs added to the signer set since the previous checkpoint.
    #[serde(default)]
    pub added: Vec<NodeId>,
    /// Node IDs removed from the signer set since the previous checkpoint.
    #[serde(default)]
    pub removed: Vec<NodeId>,
}

/// Mesh node-list checkpoint proposal (proposer → all). The BFT-finalised, signed
/// snapshot a miner-side shim consumes for trustless discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNodeListCheckpointMessage {
    /// Lagging anchor height this checkpoint pins the node list at.
    pub height: u64,
    /// Cutoff = the anchor block's timestamp (deterministic, chain-committed).
    pub cutoff_ts: i64,
    /// The canonical public-mining node set as of `cutoff_ts` — the RENDERED entries a
    /// shim acts on, derived from `adverts` by keeping those with `public_mining`.
    #[serde(default)]
    pub nodes: Vec<MeshNodeEntry>,
    /// One self-signed advert for EVERY node in the qualified set at `cutoff_ts`, including
    /// those not offering public mining (carried with `public_mining = false`).
    ///
    /// Coverage is total on purpose. It makes `nodes` a pure function of the ratified
    /// qualified set plus these bytes, so a voter re-derives it without consulting any local
    /// view — and a proposer that drops a node it dislikes produces a list that fails the
    /// coverage check rather than one that merely looks smaller.
    #[serde(default)]
    pub adverts: Vec<MeshEndpointAdvert>,
    /// `mesh_advert_set_root(adverts)` — binds the signed endpoints inside `checkpoint_hash`,
    /// so the rendered `nodes` cannot be swapped for hosts nobody signed.
    #[serde(with = "ghost_common::serde_hex::bytes32", default)]
    pub advert_root: [u8; 32],
    /// `mesh_node_list_root(nodes)` — binds the list inside `checkpoint_hash`.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub list_root: [u8; 32],
    /// Signer-set change vs the previous checkpoint (the signed forward chain).
    #[serde(default)]
    pub signer_set_delta: SignerSetDelta,
    /// `mesh_signer_set_root(set)` of the signer set AFTER applying the delta —
    /// committed in `checkpoint_hash`, so a shim can authenticate the new set.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub signer_set_root: [u8; 32],
    /// Number of active nodes at this checkpoint.
    pub active_node_count: u32,
    /// Proposer's node ID (deterministic election for `height`).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature over `checkpoint_hash()`.
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
}

impl MeshNodeListCheckpointMessage {
    /// Content hash (excludes the signature) — the object voters sign/compare.
    /// Commits the list root AND the resulting signer-set root, so both the node
    /// list and the forward-chain delta are authenticated by every approval.
    pub fn checkpoint_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        // v2: `advert_root` joined the commitment when the node set moved from each node's
        // local liveness view to the ratified qualified set plus signed endpoints (#625).
        // Bumped freely: the gate is `u64::MAX` and no checkpoint has ever finalised, so
        // there is no chain of prior hashes to stay compatible with.
        hasher.update(b"MeshNodeListCheckpoint/v2");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.cutoff_ts.to_le_bytes());
        hasher.update(self.list_root);
        hasher.update(self.advert_root);
        hasher.update(self.signer_set_root);
        hasher.update(self.active_node_count.to_le_bytes());
        hasher.update(self.proposer);
        hasher.finalize().into()
    }
}

/// Mesh node-list checkpoint vote (validator → all).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNodeListCheckpointVoteMessage {
    /// Checkpoint height being voted on.
    pub height: u64,
    /// Hash of the checkpoint being voted on (`MeshNodeListCheckpointMessage::checkpoint_hash`).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub checkpoint_hash: [u8; 32],
    /// Voter's node ID.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub voter: NodeId,
    /// Vote (true = approve; the voter reproduced the same `list_root`).
    pub approve: bool,
    /// Voter's signature over `signing_message()`.
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
}

impl MeshNodeListCheckpointVoteMessage {
    /// Get the message to be signed.
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MeshNodeListCheckpointVote/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.checkpoint_hash);
        hasher.update([self.approve as u8]);
        hasher.finalize().into()
    }
}

/// One finalised mesh node-list checkpoint carried in a sync response. Unlike the payout
/// sync entry, this carries the FULL signed blob — the proposer signature and the ≥67%
/// approver signatures — so a syncing peer verifies the quorum itself (never trusting the
/// serving peer) and can then serve the same verifiable blob to shims. Approver signatures
/// are `Vec<u8>` (64 bytes) because serde's array impls stop at 32.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNodeListCheckpointSyncEntry {
    /// Lagging anchor height.
    pub height: u64,
    /// Cutoff = anchor block's timestamp.
    pub cutoff_ts: i64,
    /// Canonical public-mining node set as of `cutoff_ts`.
    #[serde(default)]
    pub nodes: Vec<MeshNodeEntry>,
    /// The self-signed adverts the checkpoint adopted. Carried through sync so a lagging peer
    /// — or a shim — re-derives and re-verifies rather than trusting the serving node's
    /// rendering of `nodes`.
    #[serde(default)]
    pub adverts: Vec<MeshEndpointAdvert>,
    /// `mesh_advert_set_root(adverts)`. Part of `checkpoint_hash`, so it must survive sync or
    /// the proposer signature cannot be reconstructed.
    #[serde(with = "ghost_common::serde_hex::bytes32", default)]
    pub advert_root: [u8; 32],
    /// `mesh_node_list_root(nodes)`.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub list_root: [u8; 32],
    /// Signer-set change vs the previous checkpoint.
    #[serde(default)]
    pub signer_set_delta: SignerSetDelta,
    /// `mesh_signer_set_root` of the set after the delta.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub signer_set_root: [u8; 32],
    /// Active-node count at this checkpoint.
    pub active_node_count: u32,
    /// Deterministic proposer for `height` (checked against `proposer_for(height)` on apply).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature over the checkpoint hash.
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// The ≥67% approver signatures over the vote signing message: `(voter, signature)`.
    #[serde(default)]
    pub approvals: Vec<(NodeId, Vec<u8>)>,
}

/// Mesh node-list checkpoint sync REQUEST (node → peers): backfill finalised
/// checkpoints from `from_height` up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNodeListCheckpointSyncRequest {
    /// The node asking to be backfilled.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub requesting_node: NodeId,
    /// Lowest height the requester lacks (its `latest_finalised + 1`).
    pub from_height: u64,
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
}

/// Mesh node-list checkpoint sync RESPONSE (peer → requester): a bounded, ascending
/// page of finalised checkpoints. `has_more` signals the requester to paginate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNodeListCheckpointSyncResponse {
    /// The peer serving the backfill.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub responding_node: NodeId,
    /// Finalised checkpoints, ascending from the requested height (bounded page).
    pub checkpoints: Vec<MeshNodeListCheckpointSyncEntry>,
    /// True if the responder hit its page cap — the requester should re-request.
    pub has_more: bool,
    /// Timestamp (Unix milliseconds).
    pub timestamp: u64,
}

/// L2: Tree sync request (new node → peer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TreeSyncRequest {
    /// Requesting node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub requesting_node: NodeId,
    /// Start syncing from this checkpoint height
    pub from_height: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// L2: Tree sync response (peer → requesting node)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TreeSyncResponse {
    /// Responding node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub responding_node: NodeId,
    /// Who asked. Responses go out over the broadcast transport, so without an addressee every
    /// node processes every response in the mesh — with N nodes that is N(N-1) handler runs for
    /// (N-1) real answers, and each run recomputes a Merkle root. On the 8-node fleet each node
    /// was processing ~175 responses per 10 minutes of which ~150 were answers to somebody
    /// else's question (#517).
    ///
    /// `Option` + `#[serde(default)]` for wire-compat: a peer that predates this field sends
    /// `None`, which the handler treats as "cannot tell, process it" — the old behaviour. The
    /// amplification only disappears once both ends are upgraded, which is the honest ordering
    /// for a mixed-version fleet.
    #[serde(default, with = "ghost_common::serde_hex::opt_bytes32")]
    pub requesting_node: Option<NodeId>,
    /// Checkpoint blocks (batched, max 100 per response)
    pub checkpoints: Vec<L2CheckpointBlockMessage>,
    /// Current epoch number
    pub current_epoch: u64,
    /// Current commitment root for verification
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub commitment_root: [u8; 32],
    /// Epoch records for every epoch referenced by the checkpoints above.
    ///
    /// Sent so a joining node can materialise the parent `l2_epochs` rows
    /// BEFORE persisting checkpoints that reference them, satisfying the
    /// `l2_checkpoints.epoch -> l2_epochs.epoch` foreign-key trigger even when
    /// the batch begins past an epoch boundary (e.g. early checkpoints were
    /// pruned, or a prior boundary batch was dropped). Without this, a fresh
    /// node relied on locally re-deriving epoch rows by replaying every
    /// boundary in sequence — any gap left the epoch row missing and every
    /// sync round re-failed the FK. `#[serde(default)]` keeps wire-compat with
    /// peers that predate this field.
    #[serde(default)]
    pub epochs: Vec<L2EpochSync>,
    /// Whether there are more checkpoints to sync
    pub has_more: bool,
    /// The `from_height` of the request this answers.
    ///
    /// Responses are broadcast and several peers answer the same question, so without the echo
    /// the requester cannot tell WHICH gap an answer is about — and therefore cannot tell that
    /// the gap it asked for came back unserved. `#[serde(default)]` keeps wire-compat; a peer
    /// predating this field reports 0.
    #[serde(default)]
    pub served_from_height: u64,
    /// Why the responder sent what it sent.
    ///
    /// Only the SERVER knows why a batch came back empty, and until this field it threw that
    /// away: "no rows at all" (peer is behind — ask someone else), "rows present but their
    /// payload was pruned" (permanently unfillable) and "payload failed to deserialize"
    /// (corruption) all collapsed into `checkpoints_sent=0`. A node missing one pruned
    /// checkpoint re-derived the same gap and re-asked for it forever (#621).
    ///
    /// `None` means the peer predates the field and MUST NOT be read as "nothing wrong" —
    /// only an explicit report may retire a gap.
    #[serde(default)]
    pub serve_report: Option<TreeSyncServeReport>,
    /// Timestamp
    pub timestamp: u64,
}

/// What the responder found at and above the requested height, and what it did with it.
///
/// Counts, not a verdict: the requester decides what an empty answer means. Serving is
/// bounded by `MAX_SYNC_CHECKPOINTS`, so every count describes the batch that was examined,
/// not the responder's whole ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeSyncServeReport {
    /// Rows at or above the requested height that were examined, before any filtering.
    pub rows_found: u64,
    /// Rows whose `block_data` was empty. Checkpoint payloads are blanked by the 90-day
    /// retention sweep (`prune_old_l2_checkpoints`), so these heights can never be served
    /// by this peer again — the row survives, the block to replay it does not.
    pub rows_pruned: u64,
    /// Rows whose `block_data` was present but failed to deserialize. Distinct from pruned:
    /// this is corruption, and it used to be skipped in silence.
    pub rows_corrupt: u64,
    /// Lowest height whose payload was pruned in this batch, if any. The requester compares
    /// this against what it asked for: only a pruned row AT the requested height proves that
    /// height unfillable.
    pub pruned_from: Option<u64>,
    /// Highest height whose payload was pruned in this batch, if any.
    pub pruned_through: Option<u64>,
}

/// L2: Epoch metadata carried inside a tree-sync response.
///
/// Mirrors `ghost_storage::L2EpochRecord` on the wire (hex-encoded roots) so a
/// joining node can upsert the parent epoch row for each synced checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2EpochSync {
    /// Epoch number
    pub epoch: u64,
    /// First checkpoint height of this epoch
    pub start_height: u64,
    /// Last checkpoint height of this epoch (None while active)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_height: Option<u64>,
    /// Commitment root at epoch start
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub initial_root: [u8; 32],
    /// Commitment root at epoch end (None while active)
    #[serde(default, with = "ghost_common::serde_hex::option_bytes32")]
    pub final_root: Option<[u8; 32]>,
    /// Number of notes migrated into this epoch at compaction
    pub notes_migrated: u64,
    /// Lifecycle status ("active" | "archived")
    pub status: String,
}

/// L2: Note gap request — sent when tree sync replay didn't fix root mismatch.
/// Asks peer for specific notes we're missing (SIGKILL recovery / fresh node bootstrap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2NoteGapRequest {
    /// Requesting node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub requesting_node: NodeId,
    /// Our note count (peer compares to theirs)
    pub our_note_count: u64,
    /// Our note indices (peer diffs against theirs to find missing)
    pub our_note_indices: Vec<u64>,
    /// Only send missing notes with index >= from_index (pagination cursor)
    #[serde(default)]
    pub from_index: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// L2: Note gap response — peer responds with a batch of notes we're missing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2NoteGapResponse {
    /// Responding node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub responding_node: NodeId,
    /// Batch of notes the requester is missing (max 100 per response)
    pub missing_notes: Vec<ShieldCommitment>,
    /// Peer's total note count
    pub their_note_count: u64,
    /// Peer's current commitment root for verification
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub commitment_root: [u8; 32],
    /// Whether there are more missing notes beyond this batch
    pub has_more: bool,
    /// Timestamp
    pub timestamp: u64,
}

// =============================================================================
// GhostGlyph Messages
// =============================================================================

/// Broadcast when a user submits a glyph claim (design chosen, pending funding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostGlyphClaimMessage {
    /// bech32m ghost1... address
    pub ghost_id: String,
    /// 256 bytes, each 0..25
    pub pixels: Vec<u8>,
    /// SHA256("GhostGlyphBitmap/v1" || pixels)
    pub bitmap_hash: Vec<u8>,
    /// SHA256("GhostGlyph/v1" || pixels || ghost_id_bytes)
    pub commitment: Vec<u8>,
    /// Claim timestamp
    pub timestamp: u64,
}

/// Broadcast when a glyph claim is confirmed (Ghost Lock funded via Wraith)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostGlyphRegisteredMessage {
    /// bech32m ghost1... address
    pub ghost_id: String,
    /// SHA256("GhostGlyphBitmap/v1" || pixels)
    pub bitmap_hash: Vec<u8>,
    /// Wraith deposit txid that funded the lock
    pub funding_txid: String,
    /// Unix timestamp of registration
    pub registered_at: u64,
}

// =============================================================================
// SHARE SHARD Messages (docs/SHARE_SHARD.md — §4.4 merge rule, §6 verification,
// §12.4 publishable rejection, §12.6 ship-the-whole-table)
// =============================================================================

/// Share shard: a node's signed epoch summary (node → all).
///
/// The summary carries its own `node_id` (= the signer's ed25519 verifying key) and signature,
/// so the mesh envelope's sender adds nothing to its trust story: relaying a THIRD node's
/// summary is legitimate gossip, and a receiver verifies the summary's own signature, never the
/// relay's. Pure-handler side: `shard_handler::apply_shard_epoch_summary`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardEpochSummaryMessage {
    /// The signed summary. Shares never ride with it — `summary.share_root` commits to them for
    /// §6's asynchronous sampling.
    pub summary: EpochSummary,
}

/// One node's column of the accrued table, in wire form.
///
/// `AccruedColumns` itself cannot cross the wire: serde_json refuses non-string map keys, and
/// its keys are 32-byte node ids. The wire form is vectors in CANONICAL order — columns strictly
/// ascending by `node_id`, cells strictly ascending by address, every value strictly positive —
/// and the handler rejects anything else, so content-equal tables are byte-equal on the wire
/// exactly as they are under `ShardTable::compute_table_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardColumn {
    /// The node this column belongs to (= its ed25519 verifying key).
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub node_id: NodeId,
    /// `(payout_address, accrued micro-work)`, ascending by address, values > 0.
    pub cells: Vec<(String, i64)>,
}

/// The wire form of an accrued table. Canonical by construction: `BTreeMap` iteration is
/// key-ascending on both levels, and zero cells / empty columns are dropped the same way
/// `compute_table_root` drops them — an explicit zero and an absent cell are the same balance.
pub fn shard_columns_from_accrued(accrued: &AccruedColumns) -> Vec<ShardColumn> {
    accrued
        .iter()
        .map(|(node, column)| ShardColumn {
            node_id: *node,
            cells: column
                .iter()
                .filter(|(_, &v)| v != 0)
                .map(|(addr, &v)| (addr.clone(), v))
                .collect(),
        })
        .filter(|col| !col.cells.is_empty())
        .collect()
}

/// Canonical bytes a table-sync response signs: domain tag, responder, root, then every column
/// with every field length-prefixed, in wire order — the `compute_state_root` discipline, so no
/// two distinct tables can serialise to the same bytes by running fields together.
pub fn shard_table_sync_signing_bytes(
    responding_node: &NodeId,
    columns: &[ShardColumn],
    table_root: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"ShardTableSync/v1");
    m.extend_from_slice(responding_node);
    m.extend_from_slice(table_root);
    m.extend_from_slice(&(columns.len() as u32).to_le_bytes());
    for col in columns {
        m.extend_from_slice(&col.node_id);
        m.extend_from_slice(&(col.cells.len() as u32).to_le_bytes());
        for (addr, value) in &col.cells {
            m.extend_from_slice(&(addr.len() as u32).to_le_bytes());
            m.extend_from_slice(addr.as_bytes());
            m.extend_from_slice(&value.to_le_bytes());
        }
    }
    m
}

/// Share shard: whole-table sync (node ↔ peer). One type for both directions, disambiguated on
/// deserialise — the same shape `ShareBatchSync` and the convergence exchanges already use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShardTableSyncMessage {
    /// "Send me your whole table." Carries the requester's own root so the comparison §12.6
    /// exists for is visible to the responder too — either side can log the drift.
    Request {
        /// The node asking.
        #[serde(with = "ghost_common::serde_hex::bytes32")]
        requesting_node: NodeId,
        /// The requester's current whole-table root.
        #[serde(with = "ghost_common::serde_hex::bytes32")]
        table_root: [u8; 32],
    },
    /// The responder's whole accrued table plus its whole-table root.
    ///
    /// Only `accrued` ships: `settled` NEVER crosses the mesh (§4.4) — every node derives it
    /// from the chain it already holds, and gossiping it would create exactly the stale copy the
    /// two-quantity split exists to make impossible. The root therefore covers MORE than this
    /// payload (it commits `settled` too), so it is compared for drift, not recomputed from the
    /// payload: a mismatch after merge means either accrued the responder has and we lack —
    /// closed by the merge itself — or a settlement one side has not yet read off the chain,
    /// and that difference is real.
    Response {
        /// The node answering.
        #[serde(with = "ghost_common::serde_hex::bytes32")]
        responding_node: NodeId,
        /// The whole accrued table in canonical wire form ([`shard_columns_from_accrued`]).
        columns: Vec<ShardColumn>,
        /// The responder's `ShardTable::compute_table_root()` at the moment of serving.
        #[serde(with = "ghost_common::serde_hex::bytes32")]
        table_root: [u8; 32],
        /// ed25519 by `responding_node` over [`shard_table_sync_signing_bytes`]. The cells are
        /// not individually signed by their owning nodes (that is §6's summary/sampling trust
        /// surface); this signature makes the SERVED TABLE attributable — a peer that serves an
        /// inflated cell has signed the inflation, which is what makes it publishable evidence.
        /// `Vec<u8>` because serde's array impls stop at 32.
        signature: Vec<u8>,
    },
}

/// Share shard: bad-share evidence (reporter → all), modelled on [`EquivocationProofMessage`].
///
/// Self-contained on purpose (§12.4): the verdict must be re-derivable by every peer from the
/// message alone, with no reliance on the reporter's honesty or the receiver's local state.
/// The accused's own signed summary binds `(node_id, epoch, share_root, share_count)`; the
/// Merkle path binds `share` to that root; and the share fails a validity check
/// (PoW preimage / GHOST-09 / binding) that any peer can re-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardEvidenceMessage {
    /// The accused node's signed summary for the epoch, carried whole because the signature
    /// covers ALL its fields — there is no shorter blob that still proves the accused committed
    /// to this `share_root` and `share_count`.
    pub summary: EpochSummary,
    /// The offending share, exactly as committed under `summary.share_root`.
    pub share: ShareProof,
    /// Index of `share.share_hash` among the epoch's canonical leaves (< `summary.share_count`).
    pub leaf_index: u32,
    /// Sibling path for `ghost_reconciliation::verify_merkle_proof`. The verifier is injected at
    /// the handler (`shard_handler::MerkleProofFn`) for the same no-cycle reason as
    /// `share_shard::MerkleRootFn`.
    #[serde(with = "ghost_common::serde_hex::vec_bytes32")]
    pub merkle_proof: Vec<[u8; 32]>,
    /// The node that found the bad share.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub reporter: NodeId,
    /// Reporter's signature over [`Self::signing_message`].
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub reporter_signature: [u8; 64],
    /// Timestamp when the bad share was found (Unix milliseconds).
    pub timestamp: u64,
}

impl ShardEvidenceMessage {
    /// The node this evidence accuses — the summary's signer.
    pub fn accused(&self) -> NodeId {
        self.summary.node_id
    }

    /// The message the reporter signs.
    ///
    /// Binds the accused's summary and the share via their own canonical signing bytes — both
    /// length-prefixed, because both are variable-length and concatenating them raw would let
    /// two distinct (summary, share) pairs serialise identically. `share.signing_bytes()` covers
    /// the share's CONTENT (hash, work, header and tier when present), not just its leaf hash,
    /// so a relay cannot swap share fields while keeping the Merkle path valid.
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let summary_bytes = self.summary.signing_bytes();
        let share_bytes = self.share.signing_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"ShardEvidence/v1");
        hasher.update((summary_bytes.len() as u32).to_le_bytes());
        hasher.update(&summary_bytes);
        hasher.update((share_bytes.len() as u32).to_le_bytes());
        hasher.update(&share_bytes);
        hasher.update(self.leaf_index.to_le_bytes());
        hasher.update((self.merkle_proof.len() as u32).to_le_bytes());
        for node in &self.merkle_proof {
            hasher.update(node);
        }
        hasher.update(self.reporter);
        hasher.finalize().into()
    }

    /// Verify the reporter's signature.
    ///
    /// SEC-SIG-3: logs errors instead of silently returning false.
    pub fn verify_reporter_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(
            &self.reporter,
            &message,
            &self.reporter_signature,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    reporter = %hex::encode(&self.reporter[..8]),
                    error = %e,
                    "Shard evidence signature verification error"
                );
                false
            }
        }
    }
}

/// Share shard: §6 sampling request (sampler → summarising node).
///
/// Deliberately unsigned, like `ShardTableSyncMessage::Request`: a request asserts nothing that
/// needs a signature to be safe — the response self-authenticates against the ACCUSED's already
/// signed root, and the mesh envelope authenticates the transport. What the request must pin is
/// WHICH commitment is being audited, hence `share_root` alongside the epoch: a node that signed
/// two different summaries for one epoch (equivocation) must not get to choose which tree it
/// answers from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardSampleRequestMessage {
    /// The epoch being audited.
    pub epoch: u64,
    /// The node whose summary is being audited — the only party holding the leaves, since share
    /// evidence never leaves its node (§4.3) and is kept `RETENTION_EPOCHS` for exactly this.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub target_node: NodeId,
    /// The signed `share_root` the requester holds for `(target_node, epoch)`. The response is
    /// verified against THIS root, not against whatever the responder currently claims.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub share_root: [u8; 32],
    /// Leaf indices wanted, strictly ascending (the canonical form
    /// [`crate::shard_handler::select_sample_indices`] emits) — without replacement, each
    /// `< share_count`. Ascending order leaks nothing: the SET is what was sampled, and by the
    /// time the responder sees it the root is already signed.
    pub leaf_indices: Vec<u32>,
    /// The node asking.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub requesting_node: NodeId,
}

/// One served leaf: a share and the Merkle path placing it under the audited root.
///
/// Deliberately the same `(share, leaf_index, merkle_proof)` triple that rides in
/// [`ShardEvidenceMessage`] — a leaf that fails validity is republished as evidence VERBATIM,
/// so there is exactly one evidence format and nothing to translate (or to get wrong) between
/// "what I sampled" and "what I accuse with".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardSampleLeaf {
    /// Index of `share.share_hash` among the epoch's canonical leaves (< the signed
    /// `share_count`).
    pub leaf_index: u32,
    /// The share exactly as committed under the epoch's root.
    pub share: ShareProof,
    /// Sibling path for the injected `verify_merkle_proof`.
    #[serde(with = "ghost_common::serde_hex::vec_bytes32")]
    pub merkle_proof: Vec<[u8; 32]>,
}

/// Share shard: §6 sampling response (summarising node → sampler).
///
/// A response MAY answer a subset of the request: the worst-case leaf (a cap-sized share plus a
/// maximal path) is large enough that a full default-λ sample is not guaranteed to fit one
/// envelope — see `MAX_SHARD_SAMPLE_RESPONSE_SIZE` for the arithmetic. Unanswered indices are
/// surfaced by the handler for the caller to chase; they are never silently forgiven.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardSampleResponseMessage {
    /// The epoch served.
    pub epoch: u64,
    /// The node answering — necessarily the summarising node, the only holder of the evidence.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub responding_node: NodeId,
    /// The signed root the served leaves are claimed against — must equal the request's.
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub share_root: [u8; 32],
    /// The served leaves, in the request's (ascending) index order.
    pub leaves: Vec<ShardSampleLeaf>,
    /// ed25519 by `responding_node` over [`Self::signing_message`]. The leaves already
    /// self-authenticate against the signed root, so this signature exists for the OTHER
    /// direction: it makes a junk response — wrong leaves, unbindable paths — attributable to
    /// its author instead of deniable as transport noise. `Vec<u8>` because serde's array impls
    /// stop at 32.
    pub signature: Vec<u8>,
}

impl ShardSampleResponseMessage {
    /// The message the responder signs.
    ///
    /// Domain-tagged, every variable-length part length-prefixed (the `compute_state_root`
    /// discipline), and the share bound by its own canonical `signing_bytes()` — its CONTENT,
    /// not just its leaf hash — so no two distinct responses can serialise to the same bytes and
    /// no field can be swapped in flight without breaking the signature.
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ShardSampleResponse/v1");
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.responding_node);
        hasher.update(self.share_root);
        hasher.update((self.leaves.len() as u32).to_le_bytes());
        for leaf in &self.leaves {
            hasher.update(leaf.leaf_index.to_le_bytes());
            let share_bytes = leaf.share.signing_bytes();
            hasher.update((share_bytes.len() as u32).to_le_bytes());
            hasher.update(&share_bytes);
            hasher.update((leaf.merkle_proof.len() as u32).to_le_bytes());
            for node in &leaf.merkle_proof {
                hasher.update(node);
            }
        }
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    // ── H-7 address capability (#605) ────────────────────────────────────────────────────

    /// The wire string is the ledger's `capability` column and the key
    /// `ChallengeConvergence` reconciles on, so it is a stored format, not a label.
    #[test]
    fn address_capability_round_trips_on_the_wire() {
        use super::CapabilityType;
        assert_eq!(CapabilityType::Address.as_str(), "address");
        assert_eq!(
            CapabilityType::parse("address"),
            Some(CapabilityType::Address)
        );
        assert_eq!(
            serde_json::to_string(&CapabilityType::Address).unwrap(),
            "\"address\""
        );
        assert_eq!(
            serde_json::from_str::<CapabilityType>("\"address\"").unwrap(),
            CapabilityType::Address
        );
    }

    /// Documents the constraint that forces the H-7 emission gate to exist. There is no
    /// `#[serde(other)]` fallback, so a peer on a binary predating `Address` does not
    /// merely ignore the new variant — it fails to deserialise the message carrying it and
    /// drops the verdict whole. Adding such a fallback here would NOT fix a rollout, since
    /// the nodes that need it are the ones running the old binary; the gate is what fixes
    /// it. If this test ever starts failing because a fallback was added, the gate still
    /// has to stay for every already-deployed node.
    #[test]
    fn an_unknown_capability_fails_to_deserialise_rather_than_degrading() {
        use super::CapabilityType;
        assert!(serde_json::from_str::<CapabilityType>("\"not_a_capability\"").is_err());
    }

    // ── Deterministic node-list derivation (#625) ────────────────────────────────────────

    fn advert_for(
        id: &ghost_common::identity::NodeIdentity,
        host: &str,
        public_mining: bool,
        seq: u64,
    ) -> MeshEndpointAdvert {
        let mut a = MeshEndpointAdvert {
            node_id: id.node_id(),
            host: host.to_string(),
            sv1_port: 3333,
            sv2_port: 34255,
            public_mining,
            seq,
            signature: [0u8; 64],
        };
        a.signature = id.sign(&a.signing_bytes());
        a
    }

    /// THE property #625 is about. Three nodes deriving from the same ratified set and the
    /// same adverts must reach the same list — whatever order those adverts arrived in.
    ///
    /// The old derivation could not satisfy this: it read a 120-second liveness window, so
    /// the answer depended on who each node happened to be talking to.
    #[test]
    fn the_list_is_identical_whatever_order_the_adverts_arrive_in() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let b = ghost_common::identity::NodeIdentity::generate();
        let c = ghost_common::identity::NodeIdentity::generate();
        let qualified = {
            let mut q = vec![a.node_id(), b.node_id(), c.node_id()];
            q.sort_unstable();
            q
        };
        let forwards = vec![
            advert_for(&a, "203.0.113.1", true, 1),
            advert_for(&b, "203.0.113.2", true, 1),
            advert_for(&c, "203.0.113.3", true, 1),
        ];
        let mut backwards = forwards.clone();
        backwards.reverse();

        let l1 = derive_mesh_node_list(&qualified, &forwards).expect("forwards");
        let l2 = derive_mesh_node_list(&qualified, &backwards).expect("backwards");
        assert_eq!(l1, l2);
        assert_eq!(mesh_node_list_root(&l1), mesh_node_list_root(&l2));
        assert_eq!(l1.len(), 3);
    }

    /// A node that does not serve miners is carried, not omitted, and filtered out here.
    /// Carrying it is what makes the coverage check meaningful.
    #[test]
    fn a_node_that_does_not_offer_mining_is_carried_but_not_listed() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let b = ghost_common::identity::NodeIdentity::generate();
        let mut qualified = vec![a.node_id(), b.node_id()];
        qualified.sort_unstable();
        let adverts = vec![
            advert_for(&a, "203.0.113.1", true, 1),
            advert_for(&b, "203.0.113.2", false, 1),
        ];
        let list = derive_mesh_node_list(&qualified, &adverts).expect("derives");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].node_id, a.node_id());
    }

    /// Selective omission must be a REJECTION, not a shorter list. Otherwise a proposer can
    /// quietly drop a competitor and still produce something internally consistent.
    #[test]
    fn omitting_a_qualified_node_is_rejected_rather_than_shortening_the_list() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let b = ghost_common::identity::NodeIdentity::generate();
        let mut qualified = vec![a.node_id(), b.node_id()];
        qualified.sort_unstable();
        let only_a = vec![advert_for(&a, "203.0.113.1", true, 1)];
        assert_eq!(
            derive_mesh_node_list(&qualified, &only_a),
            Err(MeshListRejection::MissingAdvert {
                node_id: b.node_id()
            })
        );
    }

    /// Nobody may advertise on another node's behalf. This is the property that lets a voter
    /// accept an endpoint for a node it has never met.
    #[test]
    fn an_advert_signed_by_the_wrong_node_is_refused() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let impostor = ghost_common::identity::NodeIdentity::generate();
        let qualified = vec![a.node_id()];

        // Same claimed subject, signed by somebody else.
        let mut forged = advert_for(&a, "evil.example", true, 1);
        forged.signature = impostor.sign(&forged.signing_bytes());
        assert_eq!(
            derive_mesh_node_list(&qualified, &[forged]),
            Err(MeshListRejection::AdvertNotSelfSigned {
                node_id: a.node_id()
            })
        );
    }

    /// Rewriting the host after signing must invalidate the advert, or the signature is
    /// decorative and a proposer can redirect miners anywhere.
    #[test]
    fn editing_the_host_after_signing_invalidates_the_advert() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let mut tampered = advert_for(&a, "203.0.113.1", true, 1);
        tampered.host = "attacker.example".to_string();
        assert!(!tampered.is_self_signed());
        assert_eq!(
            derive_mesh_node_list(&[a.node_id()], &[tampered]),
            Err(MeshListRejection::AdvertNotSelfSigned {
                node_id: a.node_id()
            })
        );
    }

    /// A re-homed node supersedes its own earlier advert by `seq`, and the outcome must not
    /// depend on which one arrived first.
    #[test]
    fn a_higher_seq_supersedes_regardless_of_order() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let old = advert_for(&a, "203.0.113.1", true, 1);
        let new = advert_for(&a, "203.0.113.9", true, 2);
        let q = vec![a.node_id()];
        let f = derive_mesh_node_list(&q, &[old.clone(), new.clone()]).expect("f");
        let b = derive_mesh_node_list(&q, &[new, old]).expect("b");
        assert_eq!(f, b);
        assert_eq!(f[0].host, "203.0.113.9");
    }

    /// An advert for a node outside the ratified set is refused, or the qualified set stops
    /// being what decides membership.
    #[test]
    fn an_advert_from_an_unqualified_node_is_refused() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let outsider = ghost_common::identity::NodeIdentity::generate();
        let adverts = vec![
            advert_for(&a, "203.0.113.1", true, 1),
            advert_for(&outsider, "203.0.113.99", true, 1),
        ];
        assert_eq!(
            derive_mesh_node_list(&[a.node_id()], &adverts),
            Err(MeshListRejection::UnqualifiedAdvert {
                node_id: outsider.node_id()
            })
        );
    }

    /// The advert root must cover the signatures, or two different signed endpoint sets could
    /// share a root and the commitment would not bind what was adopted.
    #[test]
    fn the_advert_root_changes_when_an_endpoint_does() {
        let a = ghost_common::identity::NodeIdentity::generate();
        let one = vec![advert_for(&a, "203.0.113.1", true, 1)];
        let two = vec![advert_for(&a, "203.0.113.2", true, 1)];
        assert_ne!(mesh_advert_set_root(&one), mesh_advert_set_root(&two));
        // ...and is order-independent, like the list itself.
        let b = ghost_common::identity::NodeIdentity::generate();
        let mut pair = vec![
            advert_for(&a, "203.0.113.1", true, 1),
            advert_for(&b, "203.0.113.2", true, 1),
        ];
        let root_fwd = mesh_advert_set_root(&pair);
        pair.reverse();
        assert_eq!(root_fwd, mesh_advert_set_root(&pair));
    }

    /// `MessageType` goes on the wire as its NAME, not a positional discriminant.
    ///
    /// This is what makes removing a dead variant safe. The enum has no explicit discriminants, so
    /// if the encoding were positional, deleting `BlockFound` (position 1) would shift every later
    /// variant down by one and a mixed fleet would silently reinterpret every message type during
    /// a rolling deploy — `PayoutProposal` read as `Vote`, and so on.
    ///
    /// Because the form is the name, a removed variant simply fails to deserialise on a new node,
    /// which for a type nothing dispatched is the same no-op it already was.
    #[test]
    fn message_type_encodes_by_name_not_by_position() {
        assert_eq!(
            serde_json::to_string(&MessageType::PayoutProposal).unwrap(),
            "\"PayoutProposal\"",
            "the wire form must be the variant NAME — deleting a dead variant is only safe \
             because later variants do not shift"
        );
    }

    use ghost_common::identity::NodeIdentity;

    fn signed_precommit(
        id: &NodeIdentity,
        seq: u64,
        round: u32,
        batch_hash: [u8; 32],
    ) -> (String, String) {
        let mut v = ShareBatchPhaseVoteMessage {
            seq,
            round,
            batch_hash,
            voter: id.node_id(),
            signature: [0u8; 64],
        };
        v.signature = id.sign(&v.signing_bytes(BatchVotePhase::Precommit));
        (hex::encode(id.node_id()), hex::encode(v.signature))
    }

    /// A genuine quorum of precommits verifies.
    #[test]
    fn a_real_quorum_produces_a_valid_certificate() {
        let ids: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let voters: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        let h = [0xAB; 32];
        let cert = CommitCertificate {
            seq: 7,
            round: 3,
            batch_hash: h,
            voter_set_hash: voter_set_hash(&voters),
            precommits: ids[..6]
                .iter()
                .map(|i| signed_precommit(i, 7, 3, h))
                .collect(),
        };
        assert!(cert.verify(&voters, 6));
    }

    /// Short of quorum is refused. The count is the whole guarantee.
    #[test]
    fn fewer_than_quorum_is_refused() {
        let ids: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let voters: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        let h = [0xAB; 32];
        let cert = CommitCertificate {
            seq: 7,
            round: 3,
            batch_hash: h,
            voter_set_hash: voter_set_hash(&voters),
            precommits: ids[..5]
                .iter()
                .map(|i| signed_precommit(i, 7, 3, h))
                .collect(),
        };
        assert!(!cert.verify(&voters, 6));
    }

    /// **The forgery this exists to stop.** Signatures from non-voters do not count.
    ///
    /// Minting six fresh keypairs is exactly the attack that beat the earlier local heuristics.
    /// Here it produces six perfectly valid signatures over the right bytes — and still fails,
    /// because none of the signers is in the voter set.
    #[test]
    fn minted_keypairs_cannot_forge_a_certificate() {
        let real: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let voters: Vec<NodeId> = real.iter().map(|i| i.node_id()).collect();
        let attackers: Vec<NodeIdentity> = (0..6).map(|_| NodeIdentity::generate()).collect();
        let h = [0xAB; 32];
        let cert = CommitCertificate {
            seq: 7,
            round: 3,
            batch_hash: h,
            voter_set_hash: voter_set_hash(&voters),
            precommits: attackers
                .iter()
                .map(|i| signed_precommit(i, 7, 3, h))
                .collect(),
        };
        assert!(
            !cert.verify(&voters, 6),
            "six self-minted signatures must not pass — this is the attack the design turns on"
        );
    }

    /// One voter repeated does not reach quorum on its own.
    #[test]
    fn duplicate_signers_count_once() {
        let ids: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let voters: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        let h = [0xAB; 32];
        let cert = CommitCertificate {
            seq: 7,
            round: 3,
            batch_hash: h,
            voter_set_hash: voter_set_hash(&voters),
            precommits: (0..6).map(|_| signed_precommit(&ids[0], 7, 3, h)).collect(),
        };
        assert!(!cert.verify(&voters, 6), "one voter six times is one voter");
    }

    /// **Audit-5 blocker A.** Genuine SUB-QUORUM signatures must not pass under a shrunken view.
    ///
    /// The voter set is a live per-node database query that shrinks during discovery warmup,
    /// restart and partition. Quorum came from THAT view, so at a view of six the bar fell to
    /// four — and precommits are public signed gossip. An attacker collects four real signatures
    /// from a losing round and the node adopts a batch that never committed. No key compromise, no
    /// inducement, no request. The certificate is now bound to the membership it was minted
    /// against, so a receiver can only check a quorum it agrees on the shape of.
    #[test]
    fn genuine_subquorum_signatures_do_not_pass_under_a_degraded_view() {
        let ids: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let full: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        let h = [0xAB; 32];

        // Four REAL signatures — a losing round that never reached the true quorum of 6.
        let cert = CommitCertificate {
            seq: 7,
            round: 3,
            batch_hash: h,
            voter_set_hash: voter_set_hash(&full),
            precommits: ids[..4]
                .iter()
                .map(|i| signed_precommit(i, 7, 3, h))
                .collect(),
        };

        // The receiver's view has shrunk to six, so its own threshold is only four.
        let degraded: Vec<NodeId> = full[..6].to_vec();
        assert!(
            !cert.verify(&degraded, 4),
            "four genuine signatures must not adopt just because our view shrank"
        );
        // And against the full set it is still short of six.
        assert!(!cert.verify(&full, 6));
    }

    /// A certificate minted against a DIFFERENT membership is not checkable here.
    ///
    /// Disagreeing about the voter set is not a fault — it means "I cannot judge this", which is
    /// the honest answer and strictly safer than judging against the wrong bar.
    #[test]
    fn a_certificate_from_another_voter_set_is_refused() {
        let ids: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let full: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        let h = [0xAB; 32];
        let cert = CommitCertificate {
            seq: 7,
            round: 3,
            batch_hash: h,
            // Minted against a set that is not the one we will check against.
            voter_set_hash: voter_set_hash(&full[..7]),
            precommits: ids[..6]
                .iter()
                .map(|i| signed_precommit(i, 7, 3, h))
                .collect(),
        };
        assert!(!cert.verify(&full, 6));
    }

    /// **Audit-5 blocker B.** An empty certificate must not pass an empty voter set.
    ///
    /// `bft_threshold(0) == 0`, so `0 >= 0` adopted anything — fail-open at exactly the moment a
    /// node knows least, which is startup before discovery completes.
    #[test]
    fn an_empty_certificate_never_passes() {
        let empty: Vec<NodeId> = Vec::new();
        let cert = CommitCertificate {
            seq: 7,
            round: 3,
            batch_hash: [0xAB; 32],
            voter_set_hash: voter_set_hash(&empty),
            precommits: Vec::new(),
        };
        assert!(
            !cert.verify(&empty, 0),
            "a quorum of zero is not a quorum, and no signatures prove nothing"
        );
    }

    /// A certificate cannot be replayed at another sequence, round, or batch.
    #[test]
    fn a_certificate_does_not_transfer() {
        let ids: Vec<NodeIdentity> = (0..8).map(|_| NodeIdentity::generate()).collect();
        let voters: Vec<NodeId> = ids.iter().map(|i| i.node_id()).collect();
        let h = [0xAB; 32];
        let good: Vec<(String, String)> = ids[..6]
            .iter()
            .map(|i| signed_precommit(i, 7, 3, h))
            .collect();

        for (seq, round, hash, what) in [
            (8u64, 3u32, h, "sequence"),
            (7, 4, h, "round"),
            (7, 3, [0xCD; 32], "batch"),
        ] {
            let cert = CommitCertificate {
                seq,
                round,
                batch_hash: hash,
                voter_set_hash: voter_set_hash(&voters),
                precommits: good.clone(),
            };
            assert!(
                !cert.verify(&voters, 6),
                "signatures must not carry to a different {what}"
            );
        }
    }

    /// A prevote's signed bytes must NOT verify as a precommit.
    ///
    /// This is the property two-phase rests on. If both phases signed the same bytes, an attacker
    /// could replay a node's prevote — which is only ever evidence that releases a lock — as a
    /// precommit, and manufacture a commit from votes nobody cast. That collapses the protocol
    /// back to single-phase, which cannot be made safe.
    #[test]
    fn a_prevote_cannot_be_replayed_as_a_precommit() {
        let v = ShareBatchPhaseVoteMessage {
            seq: 7,
            round: 3,
            batch_hash: [0xAB; 32],
            voter: [1u8; 32],
            signature: [0u8; 64],
        };
        let pre = v.signing_bytes(BatchVotePhase::Prevote);
        let com = v.signing_bytes(BatchVotePhase::Precommit);
        assert_ne!(pre, com, "the two phases must not sign identical bytes");
        assert!(
            pre.starts_with(b"ShareBatchPrevote/v1"),
            "the phase tag must lead the buffer"
        );
        assert!(com.starts_with(b"ShareBatchPrecommit/v1"));
    }

    /// Seq, round and batch_hash are each covered by the signature.
    ///
    /// Each omission is separately exploitable: without seq a vote replays at another height,
    /// without round a vote from a losing round replays into the live one, and without the hash
    /// every vote at that position is interchangeable.
    #[test]
    fn every_field_that_identifies_the_vote_is_signed() {
        let base = ShareBatchPhaseVoteMessage {
            seq: 7,
            round: 3,
            batch_hash: [0xAB; 32],
            voter: [1u8; 32],
            signature: [0u8; 64],
        };
        let b0 = base.signing_bytes(BatchVotePhase::Prevote);

        let mut other_seq = base.clone();
        other_seq.seq = 8;
        assert_ne!(b0, other_seq.signing_bytes(BatchVotePhase::Prevote), "seq");

        let mut other_round = base.clone();
        other_round.round = 4;
        assert_ne!(
            b0,
            other_round.signing_bytes(BatchVotePhase::Prevote),
            "round"
        );

        let mut other_hash = base.clone();
        other_hash.batch_hash = [0xCD; 32];
        assert_ne!(
            b0,
            other_hash.signing_bytes(BatchVotePhase::Prevote),
            "batch_hash"
        );
    }

    /// #606: the reported values MUST be covered by the signature.
    ///
    /// If they are not, any relay can rewrite a voter's numbers in flight and steer the median —
    /// which would make the #606 fix strictly WORSE than the bug it closes, moving influence from
    /// the proposer alone to any participant on the network path.
    #[test]
    fn payout_ledger_vote_signature_covers_the_reported_values() {
        let base = PayoutLedgerCheckpointVoteMessage {
            height: 900_000,
            checkpoint_hash: [7u8; 32],
            voter: [1u8; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 1_700_000_000_000,
            reported_miner_work: vec![("bc1qhonest".to_string(), 1_000_000u128)],
            reported_node_shares: vec![([2u8; 32], 5)],
        };

        // Tamper with the reported work only.
        let mut tampered = base.clone();
        tampered.reported_miner_work = vec![("bc1qhonest".to_string(), 9_999_999u128)];
        assert_ne!(
            base.signing_message(),
            tampered.signing_message(),
            "#606: rewriting a voter's reported work must change the signed digest"
        );

        // Swapping the payee must also change it.
        let mut renamed = base.clone();
        renamed.reported_miner_work = vec![("bc1qattacker".to_string(), 1_000_000u128)];
        assert_ne!(
            base.signing_message(),
            renamed.signing_message(),
            "#606: rewriting a reported ADDRESS must change the signed digest"
        );

        // And the node shares.
        let mut nodes = base.clone();
        nodes.reported_node_shares = vec![([2u8; 32], 15)];
        assert_ne!(
            base.signing_message(),
            nodes.signing_message(),
            "#606: rewriting reported node shares must change the signed digest"
        );

        // Length-prefixing must stop concatenation collisions: [("ab",1)] vs [("a",1),("b",1)]
        // would hash alike if the fields were simply appended.
        let mut joined = base.clone();
        joined.reported_miner_work = vec![("ab".to_string(), 1)];
        let mut split = base.clone();
        split.reported_miner_work = vec![("a".to_string(), 1), ("b".to_string(), 1)];
        assert_ne!(
            joined.signing_message(),
            split.signing_message(),
            "#606: field framing must prevent concatenation collisions"
        );
    }

    /// A vote from a node on an OLDER build carries empty reports, and must hash exactly as it did
    /// before #606 — otherwise every pre-gate signature stops verifying and the fleet loses quorum
    /// the moment this binary ships, gate dormant or not.
    #[test]
    fn an_empty_report_hashes_as_the_old_format_did() {
        let v = PayoutLedgerCheckpointVoteMessage {
            height: 900_000,
            checkpoint_hash: [7u8; 32],
            voter: [1u8; 32],
            approve: true,
            signature: [0u8; 64],
            timestamp: 1_700_000_000_000,
            reported_miner_work: Vec::new(),
            reported_node_shares: Vec::new(),
        };
        // The pre-#606 digest, recomputed here exactly as the old implementation did.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"PayoutLedgerCheckpointVote/v1");
        h.update(900_000u64.to_le_bytes());
        h.update([7u8; 32]);
        h.update([1u8]);
        let old: [u8; 32] = h.finalize().into();
        assert_eq!(
            v.signing_message(),
            old,
            "an empty report must hash identically to the old format, or pre-gate votes stop verifying"
        );
    }
    use super::*;

    /// Registration net for the share-shard message types — the failure this guards is SILENT:
    /// a subscriber only joins known topics and an unknown variant is dropped at deserialise
    /// with no error, so a half-registered type simply never arrives.
    ///
    /// The exhaustive matches (`topic`, `topic_str`, `max_payload_size`, `should_use_noise`,
    /// both port matches) are compiler-enforced; what the compiler CANNOT catch is a variant
    /// registered with the wrong VALUE — a topic that collides, a `topic_str` that disagrees
    /// with `topic`. That is what this pins.
    #[test]
    fn shard_message_types_are_fully_and_consistently_registered() {
        let cases: [(MessageType, &[u8], &str); 5] = [
            (
                MessageType::ShardEpochSummary,
                topics::SHARD_EPOCH_SUMMARY,
                "shdsum",
            ),
            (
                MessageType::ShardTableSync,
                topics::SHARD_TABLE_SYNC,
                "shdsync",
            ),
            (
                MessageType::ShardEvidence,
                topics::SHARD_EVIDENCE,
                "shdevid",
            ),
            (
                MessageType::ShardSampleRequest,
                topics::SHARD_SAMPLE_REQUEST,
                "shdsreq",
            ),
            (
                MessageType::ShardSampleResponse,
                topics::SHARD_SAMPLE_RESPONSE,
                "shdsrsp",
            ),
        ];
        for (msg_type, topic, expected) in cases {
            assert_eq!(
                msg_type.topic(),
                topic,
                "{msg_type:?} topic constant mismatch"
            );
            assert_eq!(
                msg_type.topic_str(),
                expected,
                "{msg_type:?} topic_str mismatch"
            );
            assert_eq!(
                msg_type.topic_str().as_bytes(),
                topic,
                "{msg_type:?}: topic() and topic_str() must be the same spelling — the \
                 subscriber matches on one and the M-P2P-1 validation on the other"
            );
        }

        // ZMQ subscriptions match by PREFIX: a topic that extends another (or is extended by
        // one) delivers cross-traffic to the wrong subscriber. Check the new topics against
        // every registered topic, both directions.
        let all: [&[u8]; 35] = [
            topics::SHARE,
            topics::BLOCK,
            topics::PAYOUT_PROPOSAL,
            topics::VOTE,
            topics::HEALTH,
            topics::DISCOVERY,
            topics::ELDER,
            topics::ZK_PROPOSAL,
            topics::ZK_VOTE,
            topics::VERIFICATION,
            topics::EQUIVOCATION,
            topics::MPC,
            topics::L2_TRANSFER,
            topics::L2_CHECKPOINT,
            topics::L2_VOTE,
            topics::L2_SYNC,
            topics::PAYOUT_LEDGER_CHECKPOINT,
            topics::PAYOUT_LEDGER_VOTE,
            topics::PAYOUT_LEDGER_SYNC,
            topics::PAYOUT_PROPOSAL_SYNC,
            topics::SHARE_BATCH,
            topics::SHARE_BATCH_VOTE,
            topics::SHARE_BATCH_SYNC,
            topics::SHARE_BATCH_PREVOTE,
            topics::SHARE_BATCH_PRECOMMIT,
            topics::MESH_NODE_LIST_CHECKPOINT,
            topics::MESH_NODE_LIST_VOTE,
            topics::MESH_NODE_LIST_SYNC,
            topics::L2_SHIELD,
            topics::GLYPH,
            topics::SHARD_EPOCH_SUMMARY,
            topics::SHARD_TABLE_SYNC,
            topics::SHARD_EVIDENCE,
            topics::SHARD_SAMPLE_REQUEST,
            topics::SHARD_SAMPLE_RESPONSE,
        ];
        for new in [
            topics::SHARD_EPOCH_SUMMARY,
            topics::SHARD_TABLE_SYNC,
            topics::SHARD_EVIDENCE,
            topics::SHARD_SAMPLE_REQUEST,
            topics::SHARD_SAMPLE_RESPONSE,
        ] {
            for existing in all {
                if existing == new {
                    continue;
                }
                assert!(
                    !existing.starts_with(new) && !new.starts_with(existing),
                    "topic prefix collision: {:?} vs {:?}",
                    String::from_utf8_lossy(new),
                    String::from_utf8_lossy(existing)
                );
            }
        }
    }

    #[test]
    fn test_message_serialization() {
        let msg = VoteMessage {
            round_id: 1,
            proposal_hash: [0u8; 32],
            approve: true,
            signature: [0u8; 64],
        };

        let json = serde_json::to_vec(&msg).unwrap();
        let decoded: VoteMessage = serde_json::from_slice(&json).unwrap();

        assert_eq!(decoded.round_id, 1);
        assert!(decoded.approve);
    }

    // ── Mesh node-list checkpoint wire types ────────────────────────────────
    fn mesh_entry(i: u8) -> MeshNodeEntry {
        let mut id = [0u8; 32];
        id[0] = i;
        id[1] = i.wrapping_mul(7);
        MeshNodeEntry {
            node_id: id,
            host: format!("10.0.0.{i}"),
            sv1_port: 3333,
            sv2_port: 34255,
        }
    }

    fn sample_mesh_checkpoint() -> MeshNodeListCheckpointMessage {
        let nodes = vec![mesh_entry(1), mesh_entry(2)];
        let signer_set = vec![[1u8; 32], [2u8; 32]];
        MeshNodeListCheckpointMessage {
            height: 959_400,
            cutoff_ts: 1_760_000_000,
            list_root: mesh_node_list_root(&nodes),
            nodes,
            // This fixture predates signed adverts and exercises the hash/serde shape, not
            // the derivation; the derivation has its own tests above.
            adverts: vec![],
            advert_root: mesh_advert_set_root(&[]),
            signer_set_delta: SignerSetDelta {
                added: vec![[2u8; 32]],
                removed: vec![],
            },
            signer_set_root: mesh_signer_set_root(&signer_set),
            active_node_count: 2,
            proposer: [1u8; 32],
            proposer_signature: [0u8; 64],
            timestamp: 1,
        }
    }

    #[test]
    fn mesh_node_list_root_is_order_independent_and_content_sensitive() {
        let a = vec![mesh_entry(1), mesh_entry(2), mesh_entry(3)];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(
            mesh_node_list_root(&a),
            mesh_node_list_root(&b),
            "collection order must not change the root"
        );
        let mut c = a.clone();
        c[0].host = "changed".to_string();
        assert_ne!(
            mesh_node_list_root(&a),
            mesh_node_list_root(&c),
            "a changed endpoint must change the root"
        );
    }

    #[test]
    fn mesh_signer_set_root_is_order_and_dup_independent() {
        let s1 = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut s2 = vec![[3u8; 32], [2u8; 32], [1u8; 32], [2u8; 32]]; // reordered + dup
        assert_eq!(mesh_signer_set_root(&s1), mesh_signer_set_root(&s2));
        s2.push([9u8; 32]);
        assert_ne!(
            mesh_signer_set_root(&s1),
            mesh_signer_set_root(&s2),
            "a genuinely different member must change the root"
        );
    }

    #[test]
    fn mesh_checkpoint_hash_excludes_signature_and_binds_content() {
        let cp = sample_mesh_checkpoint();
        let h = cp.checkpoint_hash();
        let mut cp2 = cp.clone();
        cp2.proposer_signature = [7u8; 64];
        assert_eq!(
            h,
            cp2.checkpoint_hash(),
            "signature must not affect the hash"
        );
        let mut cp3 = cp.clone();
        cp3.list_root = [9u8; 32];
        assert_ne!(h, cp3.checkpoint_hash(), "list_root is bound");
        let mut cp4 = cp.clone();
        cp4.signer_set_root = [9u8; 32];
        assert_ne!(h, cp4.checkpoint_hash(), "signer_set_root is bound");
    }

    #[test]
    fn mesh_checkpoint_vote_signing_message_flips_with_approve() {
        let cp = sample_mesh_checkpoint();
        let mk = |approve: bool| MeshNodeListCheckpointVoteMessage {
            height: cp.height,
            checkpoint_hash: cp.checkpoint_hash(),
            voter: [5u8; 32],
            approve,
            signature: [0u8; 64],
            timestamp: 1,
        };
        assert_ne!(mk(true).signing_message(), mk(false).signing_message());
        assert_eq!(mk(true).signing_message(), mk(true).signing_message());
    }

    #[test]
    fn mesh_checkpoint_serde_roundtrip() {
        let cp = sample_mesh_checkpoint();
        let json = serde_json::to_vec(&cp).unwrap();
        let back: MeshNodeListCheckpointMessage = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.checkpoint_hash(), cp.checkpoint_hash());
        assert_eq!(back.nodes, cp.nodes);
        assert_eq!(back.signer_set_delta, cp.signer_set_delta);
    }

    /// ZMQ subscriptions match by PREFIX, so a topic that extends another is silently
    /// delivered to that other topic's subscribers as well — a cross-wiring with no error and
    /// no log line.
    ///
    /// The `topics` module has always documented this invariant and claimed it was "pinned by
    /// a test". It was not. `test_message_topics` asserts two topics and
    /// `test_topic_str_matches_topic_bytes` walks six hardcoded types; neither compares topics
    /// against each other. The rule was enforced by whoever remembered to check by hand.
    ///
    /// ⚠ If a new topic makes this fail, RENAME IT. Do not relax the assertion: the failure is
    /// telling you two message streams would land in one subscriber.
    #[test]
    fn no_topic_is_a_prefix_of_another() {
        let all: &[(&str, &[u8])] = &[
            ("SHARE", topics::SHARE),
            ("BLOCK", topics::BLOCK),
            ("PAYOUT_PROPOSAL", topics::PAYOUT_PROPOSAL),
            ("VOTE", topics::VOTE),
            ("HEALTH", topics::HEALTH),
            ("DISCOVERY", topics::DISCOVERY),
            ("ELDER", topics::ELDER),
            ("ZK_PROPOSAL", topics::ZK_PROPOSAL),
            ("ZK_VOTE", topics::ZK_VOTE),
            ("VERIFICATION", topics::VERIFICATION),
            ("EQUIVOCATION", topics::EQUIVOCATION),
            ("MPC", topics::MPC),
            ("L2_TRANSFER", topics::L2_TRANSFER),
            ("L2_CHECKPOINT", topics::L2_CHECKPOINT),
            ("L2_VOTE", topics::L2_VOTE),
            ("L2_SYNC", topics::L2_SYNC),
            ("PAYOUT_LEDGER_CHECKPOINT", topics::PAYOUT_LEDGER_CHECKPOINT),
            ("PAYOUT_LEDGER_VOTE", topics::PAYOUT_LEDGER_VOTE),
            ("PAYOUT_LEDGER_SYNC", topics::PAYOUT_LEDGER_SYNC),
            ("PAYOUT_PROPOSAL_SYNC", topics::PAYOUT_PROPOSAL_SYNC),
            ("SHARE_BATCH", topics::SHARE_BATCH),
            ("SHARE_BATCH_VOTE", topics::SHARE_BATCH_VOTE),
            ("SHARE_BATCH_SYNC", topics::SHARE_BATCH_SYNC),
            ("SHARE_BATCH_PREVOTE", topics::SHARE_BATCH_PREVOTE),
            ("SHARE_BATCH_PRECOMMIT", topics::SHARE_BATCH_PRECOMMIT),
            (
                "MESH_NODE_LIST_CHECKPOINT",
                topics::MESH_NODE_LIST_CHECKPOINT,
            ),
            ("MESH_NODE_LIST_VOTE", topics::MESH_NODE_LIST_VOTE),
            ("MESH_NODE_LIST_SYNC", topics::MESH_NODE_LIST_SYNC),
            ("MESH_ENDPOINT_ADVERT", topics::MESH_ENDPOINT_ADVERT),
            ("L2_SHIELD", topics::L2_SHIELD),
            ("GLYPH", topics::GLYPH),
            ("SHARD_EPOCH_SUMMARY", topics::SHARD_EPOCH_SUMMARY),
            ("SHARD_TABLE_SYNC", topics::SHARD_TABLE_SYNC),
            ("SHARD_EVIDENCE", topics::SHARD_EVIDENCE),
            ("SHARD_SAMPLE_REQUEST", topics::SHARD_SAMPLE_REQUEST),
            ("SHARD_SAMPLE_RESPONSE", topics::SHARD_SAMPLE_RESPONSE),
        ];

        // The count is pinned so a new topic cannot be added without visiting this test and
        // being confronted with the invariant.
        assert_eq!(
            all.len(),
            36,
            "a topic was added or removed — extend `all` above, then check the invariant still holds"
        );

        for (name_a, a) in all {
            for (name_b, b) in all {
                if name_a == name_b {
                    continue;
                }
                assert!(
                    !b.starts_with(a),
                    "topic {} ({}) is a prefix of {} ({}) — ZMQ would deliver {} to {} subscribers",
                    name_a,
                    String::from_utf8_lossy(a),
                    name_b,
                    String::from_utf8_lossy(b),
                    name_b,
                    name_a
                );
            }
        }
    }

    /// Two message types sharing one topic is legitimate (the glyph pair does it), but two
    /// DIFFERENT topics with identical bytes would make `validate_topic` ambiguous.
    #[test]
    fn no_two_distinct_topics_share_bytes() {
        let all: &[(&str, &[u8])] = &[
            ("SHARE", topics::SHARE),
            ("BLOCK", topics::BLOCK),
            ("PAYOUT_PROPOSAL", topics::PAYOUT_PROPOSAL),
            ("VOTE", topics::VOTE),
            ("HEALTH", topics::HEALTH),
            ("DISCOVERY", topics::DISCOVERY),
            ("ELDER", topics::ELDER),
            ("ZK_PROPOSAL", topics::ZK_PROPOSAL),
            ("ZK_VOTE", topics::ZK_VOTE),
            ("VERIFICATION", topics::VERIFICATION),
            ("EQUIVOCATION", topics::EQUIVOCATION),
            ("MPC", topics::MPC),
            ("L2_TRANSFER", topics::L2_TRANSFER),
            ("L2_CHECKPOINT", topics::L2_CHECKPOINT),
            ("L2_VOTE", topics::L2_VOTE),
            ("L2_SYNC", topics::L2_SYNC),
            ("PAYOUT_LEDGER_CHECKPOINT", topics::PAYOUT_LEDGER_CHECKPOINT),
            ("PAYOUT_LEDGER_VOTE", topics::PAYOUT_LEDGER_VOTE),
            ("PAYOUT_LEDGER_SYNC", topics::PAYOUT_LEDGER_SYNC),
            ("PAYOUT_PROPOSAL_SYNC", topics::PAYOUT_PROPOSAL_SYNC),
            ("SHARE_BATCH", topics::SHARE_BATCH),
            ("SHARE_BATCH_VOTE", topics::SHARE_BATCH_VOTE),
            ("SHARE_BATCH_SYNC", topics::SHARE_BATCH_SYNC),
            ("SHARE_BATCH_PREVOTE", topics::SHARE_BATCH_PREVOTE),
            ("SHARE_BATCH_PRECOMMIT", topics::SHARE_BATCH_PRECOMMIT),
            (
                "MESH_NODE_LIST_CHECKPOINT",
                topics::MESH_NODE_LIST_CHECKPOINT,
            ),
            ("MESH_NODE_LIST_VOTE", topics::MESH_NODE_LIST_VOTE),
            ("MESH_NODE_LIST_SYNC", topics::MESH_NODE_LIST_SYNC),
            ("MESH_ENDPOINT_ADVERT", topics::MESH_ENDPOINT_ADVERT),
            ("L2_SHIELD", topics::L2_SHIELD),
            ("GLYPH", topics::GLYPH),
            ("SHARD_EPOCH_SUMMARY", topics::SHARD_EPOCH_SUMMARY),
            ("SHARD_TABLE_SYNC", topics::SHARD_TABLE_SYNC),
            ("SHARD_EVIDENCE", topics::SHARD_EVIDENCE),
            ("SHARD_SAMPLE_REQUEST", topics::SHARD_SAMPLE_REQUEST),
            ("SHARD_SAMPLE_RESPONSE", topics::SHARD_SAMPLE_RESPONSE),
        ];
        for (i, (name_a, a)) in all.iter().enumerate() {
            for (name_b, b) in all.iter().skip(i + 1) {
                assert_ne!(
                    a, b,
                    "topics {} and {} have identical bytes",
                    name_a, name_b
                );
            }
        }
    }

    #[test]
    fn test_message_topics() {
        assert_eq!(MessageType::ShareProof.topic(), topics::SHARE);
        assert_eq!(MessageType::Vote.topic(), topics::VOTE);
    }

    #[test]
    fn test_message_topic_str() {
        // M-P2P-1: Test that topic_str() returns correct string for each message type
        assert_eq!(MessageType::ShareProof.topic_str(), "share");
        assert_eq!(MessageType::ShareConvergence.topic_str(), "share");
        assert_eq!(MessageType::PayoutProposal.topic_str(), "payout");
        assert_eq!(MessageType::Vote.topic_str(), "vote");
        assert_eq!(MessageType::HealthPing.topic_str(), "health");
        assert_eq!(MessageType::Discovery.topic_str(), "discovery");
        assert_eq!(MessageType::VerificationResult.topic_str(), "verify");
    }

    #[test]
    fn test_topic_str_matches_topic_bytes() {
        // M-P2P-1: Verify that topic_str() is consistent with topic() bytes
        // This ensures the validation logic works correctly
        let message_types = [
            MessageType::ShareProof,
            MessageType::PayoutProposal,
            MessageType::Vote,
            MessageType::HealthPing,
            MessageType::Discovery,
            MessageType::VerificationResult,
        ];

        for msg_type in message_types {
            let topic_bytes = msg_type.topic();
            let topic_str = msg_type.topic_str();
            assert_eq!(
                topic_bytes,
                topic_str.as_bytes(),
                "topic() and topic_str() mismatch for {:?}",
                msg_type
            );
        }
    }

    /// The list root is what makes every node derive the SAME `checkpoint_hash` from
    /// the same node set, so it must not depend on the order the set arrives in. That
    /// is the whole convergence property #402 is accepted on, and nothing covered it.
    #[test]
    fn mesh_node_list_root_is_order_independent_and_set_sensitive() {
        let mk = |id: u8, host: &str, sv1: u16, sv2: u16| MeshNodeEntry {
            node_id: [id; 32],
            host: host.to_string(),
            sv1_port: sv1,
            sv2_port: sv2,
        };
        let a = mk(3, "203.0.113.7", 3333, 34255);
        let b = mk(1, "198.51.100.9", 3333, 34255);
        let c = mk(2, "example.invalid", 4444, 34255);

        // Same set, three different input orders -> one root.
        let r1 = mesh_node_list_root(&[a.clone(), b.clone(), c.clone()]);
        let r2 = mesh_node_list_root(&[c.clone(), a.clone(), b.clone()]);
        let r3 = mesh_node_list_root(&[b.clone(), c.clone(), a.clone()]);
        assert_eq!(r1, r2, "root changed with input order");
        assert_eq!(r1, r3, "root changed with input order");

        // A different set must not collide.
        assert_ne!(
            r1,
            mesh_node_list_root(&[a.clone(), b.clone()]),
            "dropping a node kept the root"
        );
        let mut moved = c.clone();
        moved.host = "203.0.113.8".to_string();
        assert_ne!(
            r1,
            mesh_node_list_root(&[a.clone(), b.clone(), moved]),
            "changing a host kept the root"
        );
        let mut reported = c.clone();
        reported.sv1_port = 3334;
        assert_ne!(
            r1,
            mesh_node_list_root(&[a, b, reported]),
            "changing a port kept the root"
        );
    }
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
            MessageType::ShareProof,
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

        let v1_early = envelope(ENVELOPE_VERSION_V1, MessageType::ShareProof, early, 8);
        let v1_late = envelope(ENVELOPE_VERSION_V1, MessageType::ShareProof, late, 8);
        assert_eq!(
            v1_early.signing_bytes().unwrap(),
            v1_late.signing_bytes().unwrap(),
            "v1 leaves the timestamp malleable — that is the finding being fixed"
        );

        let v2_early = envelope(ENVELOPE_VERSION_V2, MessageType::ShareProof, early, 8);
        let v2_late = envelope(ENVELOPE_VERSION_V2, MessageType::ShareProof, late, 8);
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
        assert_eq!(
            MessageType::ShareProof.topic(),
            MessageType::ShareConvergence.topic(),
            "this test is only meaningful while these two types share a topic"
        );

        let ts = 1_700_000_000_000;
        let v1_proof = envelope(ENVELOPE_VERSION_V1, MessageType::ShareProof, ts, 8);
        let v1_conv = envelope(ENVELOPE_VERSION_V1, MessageType::ShareConvergence, ts, 8);
        assert_eq!(
            v1_proof.signing_bytes().unwrap(),
            v1_conv.signing_bytes().unwrap(),
            "v1 leaves the message type malleable"
        );

        let v2_proof = envelope(ENVELOPE_VERSION_V2, MessageType::ShareProof, ts, 8);
        let v2_conv = envelope(ENVELOPE_VERSION_V2, MessageType::ShareConvergence, ts, 8);
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
        let fresh = envelope(ENVELOPE_VERSION_V2, MessageType::ShareProof, ts, 8);
        let forwarded = envelope(ENVELOPE_VERSION_V2, MessageType::ShareProof, ts, 3);

        assert_eq!(
            fresh.signing_bytes().unwrap(),
            forwarded.signing_bytes().unwrap(),
            "binding ttl would break every forwarded message"
        );
    }

    /// The domain separator exists for cross-protocol separation under a shared ed25519 key.
    #[test]
    fn v2_preimage_is_domain_separated() {
        let bytes = envelope(ENVELOPE_VERSION_V2, MessageType::Vote, 1_700_000_000_000, 8)
            .signing_bytes()
            .unwrap();

        assert!(
            bytes.starts_with(b"ghost/mesh/envelope/v2\0"),
            "v2 preimage lost its domain tag"
        );
    }

    /// Length prefixes, not just concatenation: `payload="ab", seq=1` and `payload="a", seq=…`
    /// style ambiguities are what unprefixed formats admit. Two envelopes that differ only in
    /// where the boundary between payload and the fields after it falls must not share a preimage.
    #[test]
    fn v2_preimage_is_unambiguous_across_field_boundaries() {
        let mut a = envelope(ENVELOPE_VERSION_V2, MessageType::Vote, 1_700_000_000_000, 8);
        let mut b = a.clone();
        a.payload = b"abc".to_vec();
        b.payload = b"ab".to_vec();
        b.sequence = a.sequence;

        assert_ne!(
            a.signing_bytes().unwrap(),
            b.signing_bytes().unwrap(),
            "a shorter payload must not be absorbable into a neighbouring field"
        );
    }

    /// A version this binary cannot reconstruct is a version it cannot authenticate. It must be an
    /// error the verifier turns into a rejection, never a silently-empty preimage.
    #[test]
    fn unknown_envelope_version_cannot_produce_a_preimage() {
        let err = envelope(99, MessageType::Vote, 1_700_000_000_000, 8)
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
                MessageType::ShareProof,
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
    fn v2_emission_gate_ships_dormant() {
        assert_eq!(
            MESH_ENVELOPE_V2_HEIGHT,
            u64::MAX,
            "the envelope v2 gate must ship dormant — arming is a separate, observed change"
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
