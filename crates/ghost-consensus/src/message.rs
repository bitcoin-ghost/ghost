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
    /// L2 shield commitment broadcast
    pub const L2_SHIELD: &[u8] = b"l2shld";
    /// GhostGlyph visual identity
    pub const GLYPH: &[u8] = b"glyph";
}

/// Default TTL for gossip messages (number of hops before message is dropped)
pub const DEFAULT_MESSAGE_TTL: u8 = 8;

/// Minimum TTL for messages to be forwarded (messages with TTL 0 are not forwarded)
pub const MIN_FORWARD_TTL: u8 = 1;

/// Consensus message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
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
    /// Create a new message envelope with default TTL
    pub fn new(
        msg_type: MessageType,
        sender: NodeId,
        payload: Vec<u8>,
        sequence: u64,
        signature: [u8; 64],
    ) -> Self {
        Self {
            msg_type,
            sender,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            signature,
            payload,
            ttl: DEFAULT_MESSAGE_TTL,
        }
    }

    /// Create a new message envelope with custom TTL
    pub fn with_ttl(
        msg_type: MessageType,
        sender: NodeId,
        payload: Vec<u8>,
        sequence: u64,
        signature: [u8; 64],
        ttl: u8,
    ) -> Self {
        Self {
            msg_type,
            sender,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            signature,
            payload,
            ttl,
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
    /// Block found announcement
    BlockFound,
    /// Payout proposal
    PayoutProposal,
    /// Vote on proposal
    Vote,
    /// Health ping
    HealthPing,
    /// Peer discovery
    Discovery,
    /// Elder status update
    ElderUpdate,
    /// Share convergence request
    ShareConvergence,
    /// ZK block proposal (includes proof)
    ZkBlockProposal,
    /// ZK vote on block validity
    ZkVote,
    /// Capability verification result
    VerificationResult,
    /// Challenge-ledger convergence request/response (backfill of signed
    /// verification results, so the node-reward capability ledger converges the
    /// way the miner share ledger does). Rides the verification topic.
    ChallengeConvergence,
    /// P2P-H3: Equivocation proof broadcast for Byzantine behavior evidence
    EquivocationProof,
    /// P2P-C1: Elder registration proposal (new elder candidate)
    ElderRegistrationProposal,
    /// P2P-C2: Elder list proposal (proposed canonical list for new epoch)
    ElderListProposal,
    /// P2P-C3: Elder list approval (vote for proposed list)
    ElderListApproval,
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
}

impl MessageType {
    /// Get the ZMQ topic for this message type
    pub fn topic(&self) -> &[u8] {
        match self {
            Self::ShareProof => topics::SHARE,
            Self::BlockFound => topics::BLOCK,
            Self::PayoutProposal => topics::PAYOUT_PROPOSAL,
            Self::Vote => topics::VOTE,
            Self::HealthPing => topics::HEALTH,
            Self::Discovery => topics::DISCOVERY,
            Self::ElderUpdate => topics::ELDER,
            Self::ShareConvergence => topics::SHARE,
            Self::ZkBlockProposal => topics::ZK_PROPOSAL,
            Self::ZkVote => topics::ZK_VOTE,
            Self::VerificationResult => topics::VERIFICATION,
            Self::ChallengeConvergence => topics::VERIFICATION,
            Self::EquivocationProof => topics::EQUIVOCATION,
            Self::ElderRegistrationProposal => topics::ELDER,
            Self::ElderListProposal => topics::ELDER,
            Self::ElderListApproval => topics::ELDER,
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
            Self::BlockFound => "block",
            Self::PayoutProposal => "payout",
            Self::Vote => "vote",
            Self::HealthPing => "health",
            Self::Discovery => "discovery",
            Self::ElderUpdate => "elder",
            Self::ZkBlockProposal => "zkproposal",
            Self::ZkVote => "zkvote",
            Self::VerificationResult | Self::ChallengeConvergence => "verify",
            Self::EquivocationProof => "equivoc",
            Self::ElderRegistrationProposal => "elder",
            Self::ElderListProposal => "elder",
            Self::ElderListApproval => "elder",
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
}

impl CapabilityType {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Archive => "archive",
            Self::Policy => "policy",
            Self::Stratum => "stratum",
            Self::GhostPay => "ghostpay",
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "archive" => Some(Self::Archive),
            "policy" => Some(Self::Policy),
            "stratum" => Some(Self::Stratum),
            "ghostpay" => Some(Self::GhostPay),
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

/// ZK Block Proposal - includes the block data and validity proof
///
/// Proposers generate this every 10 seconds. The proof demonstrates
/// that all transactions in the block are valid without validators
/// needing to re-execute them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkBlockProposalMessage {
    /// L2 block height
    pub height: u64,
    /// Previous state root (merkle root of balances before block)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub prev_state_root: [u8; 32],
    /// New state root (merkle root of balances after block)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub new_state_root: [u8; 32],
    /// Number of transactions in the block
    pub tx_count: u32,
    /// Hash of the block transactions (for reference)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub transactions_hash: [u8; 32],
    /// Serialized block transactions (can be empty if not broadcasting full block)
    pub transactions: Vec<u8>,
    /// ZK validity proof bytes
    pub proof: Vec<u8>,
    /// Proposer's signature on the proposal
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp of proposal
    pub timestamp: u64,
}

impl ZkBlockProposalMessage {
    /// Compute the proposal hash (used for voting)
    pub fn proposal_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ZkBlockProposal/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.prev_state_root);
        hasher.update(self.new_state_root);
        hasher.update(self.tx_count.to_le_bytes());
        hasher.update(self.transactions_hash);
        hasher.finalize().into()
    }
}

/// ZK Vote - validator's vote on a ZK block proposal
///
/// Validators verify the ZK proof (~10ms) and vote to approve or reject.
/// Once 67% of validators approve, the block is finalized and the proof
/// is discarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVoteMessage {
    /// Block height being voted on
    pub height: u64,
    /// Proposal hash (computed from ZkBlockProposalMessage)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposal_hash: [u8; 32],
    /// Vote (true = approve, false = reject)
    pub approve: bool,
    /// Rejection reason (if any)
    pub rejection_reason: Option<ZkRejectionReason>,
    /// Voter's signature on (height || proposal_hash || approve)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp of vote
    pub timestamp: u64,
}

impl ZkVoteMessage {
    /// Create a new ZK vote
    pub fn new(
        height: u64,
        proposal_hash: [u8; 32],
        approve: bool,
        rejection_reason: Option<ZkRejectionReason>,
        signature: [u8; 64],
    ) -> Self {
        Self {
            height,
            proposal_hash,
            approve,
            rejection_reason,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Get the message that was signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ZkVote/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.proposal_hash);
        hasher.update([if self.approve { 1u8 } else { 0u8 }]);
        hasher.finalize().into()
    }
}

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
    /// The canonical public-mining node set as of `cutoff_ts`. Voters recompute
    /// their own connected public-mining set and approve iff it matches; adopted
    /// verbatim on finalise.
    #[serde(default)]
    pub nodes: Vec<MeshNodeEntry>,
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
        hasher.update(b"MeshNodeListCheckpoint/v1");
        hasher.update(self.height.to_le_bytes());
        hasher.update(self.cutoff_ts.to_le_bytes());
        hasher.update(self.list_root);
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

#[cfg(test)]
mod tests {

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

    #[test]
    fn test_message_topics() {
        assert_eq!(MessageType::ShareProof.topic(), topics::SHARE);
        assert_eq!(MessageType::BlockFound.topic(), topics::BLOCK);
        assert_eq!(MessageType::Vote.topic(), topics::VOTE);
        assert_eq!(MessageType::ZkBlockProposal.topic(), topics::ZK_PROPOSAL);
        assert_eq!(MessageType::ZkVote.topic(), topics::ZK_VOTE);
    }

    #[test]
    fn test_message_topic_str() {
        // M-P2P-1: Test that topic_str() returns correct string for each message type
        assert_eq!(MessageType::ShareProof.topic_str(), "share");
        assert_eq!(MessageType::ShareConvergence.topic_str(), "share");
        assert_eq!(MessageType::BlockFound.topic_str(), "block");
        assert_eq!(MessageType::PayoutProposal.topic_str(), "payout");
        assert_eq!(MessageType::Vote.topic_str(), "vote");
        assert_eq!(MessageType::HealthPing.topic_str(), "health");
        assert_eq!(MessageType::Discovery.topic_str(), "discovery");
        assert_eq!(MessageType::ElderUpdate.topic_str(), "elder");
        assert_eq!(MessageType::ZkBlockProposal.topic_str(), "zkproposal");
        assert_eq!(MessageType::ZkVote.topic_str(), "zkvote");
        assert_eq!(MessageType::VerificationResult.topic_str(), "verify");
    }

    #[test]
    fn test_topic_str_matches_topic_bytes() {
        // M-P2P-1: Verify that topic_str() is consistent with topic() bytes
        // This ensures the validation logic works correctly
        let message_types = [
            MessageType::ShareProof,
            MessageType::BlockFound,
            MessageType::PayoutProposal,
            MessageType::Vote,
            MessageType::HealthPing,
            MessageType::Discovery,
            MessageType::ElderUpdate,
            MessageType::ZkBlockProposal,
            MessageType::ZkVote,
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

    #[test]
    fn test_zk_proposal_hash() {
        let proposal = ZkBlockProposalMessage {
            height: 100,
            prev_state_root: [1u8; 32],
            new_state_root: [2u8; 32],
            tx_count: 5,
            transactions_hash: [3u8; 32],
            transactions: vec![],
            proof: vec![0u8; 72],
            proposer_signature: [0u8; 64],
            timestamp: 1700000000,
        };

        let hash1 = proposal.proposal_hash();
        let hash2 = proposal.proposal_hash();
        assert_eq!(hash1, hash2, "Proposal hash should be deterministic");
    }

    #[test]
    fn test_zk_vote_message() {
        let vote = ZkVoteMessage::new(100, [1u8; 32], true, None, [0u8; 64]);

        assert_eq!(vote.height, 100);
        assert!(vote.approve);
        assert!(vote.rejection_reason.is_none());
    }

    #[test]
    fn test_zk_vote_rejection() {
        let vote = ZkVoteMessage::new(
            100,
            [1u8; 32],
            false,
            Some(ZkRejectionReason::InvalidProof),
            [0u8; 64],
        );

        assert!(!vote.approve);
        assert_eq!(vote.rejection_reason, Some(ZkRejectionReason::InvalidProof));
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
