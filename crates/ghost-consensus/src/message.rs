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
    BlockFoundEvent, HealthPing, NodeCapabilities, NodeId, PayoutProposal, RoundId, ShareProof,
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
            Self::VerificationResult => "verify",
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

/// Block found message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFoundMessage {
    /// Block event data
    pub event: BlockFoundEvent,
    /// Preliminary payout proposal (pre-consensus)
    pub preliminary_proposal: Option<PayoutProposal>,
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

/// Elder update message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderUpdateMessage {
    /// Node ID
    pub node_id: NodeId,
    /// Is now an elder
    pub is_elder: bool,
    /// Elder registration order
    pub elder_order: Option<u32>,
    /// Reason for update
    pub reason: ElderUpdateReason,
}

/// Reason for elder status change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ElderUpdateReason {
    /// New elder registration
    Registration,
    /// Elder resigned
    Resignation,
    /// Elder revoked by consensus
    Revocation { votes_for: u32, votes_against: u32 },
    /// Elder offline too long
    OfflineTimeout { offline_days: u64 },
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
    /// Timestamp when challenge was issued
    pub timestamp: i64,
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

/// ZK consensus result for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZkConsensusResult {
    /// Block approved by consensus
    Approved {
        height: u64,
        new_state_root: [u8; 32],
        approvals: u32,
        total_validators: u32,
    },
    /// Block rejected by consensus
    Rejected {
        height: u64,
        rejections: u32,
        total_validators: u32,
        primary_reason: ZkRejectionReason,
    },
    /// Consensus timed out
    Timeout {
        height: u64,
        approvals: u32,
        rejections: u32,
        total_validators: u32,
    },
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

/// P2P-C1: Elder registration proposal message
///
/// Sent when a node wants to register as an elder. Requires PoW proof
/// and 7-day uptime at 95%+. Current elders vote on the proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderRegistrationProposalMessage {
    /// Candidate's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub candidate: NodeId,
    /// PoW nonce that was mined
    pub pow_nonce: u64,
    /// PoW difficulty achieved
    pub pow_difficulty: u32,
    /// Candidate's first seen timestamp (Unix seconds)
    pub first_seen: u64,
    /// Current uptime percentage (must be >= 95%)
    pub uptime_percent: f64,
    /// Proposer's node ID (the candidate or an elder nominating them)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature over the proposal data
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Target epoch (current epoch + 1)
    pub target_epoch: u64,
    /// Timestamp of proposal (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderRegistrationProposalMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ElderRegistrationProposal/v1");
        hasher.update(self.candidate);
        hasher.update(self.pow_nonce.to_le_bytes());
        hasher.update(self.pow_difficulty.to_le_bytes());
        hasher.update(self.first_seen.to_le_bytes());
        hasher.update(self.uptime_percent.to_le_bytes());
        hasher.update(self.target_epoch.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the proposer's signature
    ///
    /// SEC-SIG-4: Logs errors instead of silently returning false
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(
            &self.proposer,
            &message,
            &self.proposer_signature,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    proposer = %hex::encode(&self.proposer[..8]),
                    candidate = %hex::encode(&self.candidate[..8]),
                    error = %e,
                    "Elder registration proposal signature verification error"
                );
                false
            }
        }
    }
}

/// P2P-C2: Elder list proposal message
///
/// Proposes a new canonical elder list for a new epoch. Contains all
/// elders and the merkle root. Requires >67% approval from current elders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderListProposalMessage {
    /// Proposed epoch number
    pub epoch: u64,
    /// Merkle root of the elder list
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub merkle_root: [u8; 32],
    /// Number of elders in the list
    pub elder_count: u32,
    /// Serialized elder entries (for nodes that need the full list)
    pub elders_data: Vec<u8>,
    /// Proposer's node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub proposer: NodeId,
    /// Proposer's signature
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub proposer_signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderListProposalMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ElderListProposal/v1");
        hasher.update(self.epoch.to_le_bytes());
        hasher.update(self.merkle_root);
        hasher.update(self.elder_count.to_le_bytes());
        hasher.finalize().into()
    }

    /// Verify the proposer's signature
    ///
    /// SEC-SIG-5: Logs errors instead of silently returning false
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(
            &self.proposer,
            &message,
            &self.proposer_signature,
        ) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    proposer = %hex::encode(&self.proposer[..8]),
                    epoch = self.epoch,
                    error = %e,
                    "Elder list proposal signature verification error"
                );
                false
            }
        }
    }
}

/// P2P-C3: Elder list approval message
///
/// An approval vote from an elder for a proposed elder list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderListApprovalMessage {
    /// Epoch being approved
    pub epoch: u64,
    /// Merkle root being approved
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub merkle_root: [u8; 32],
    /// Previous epoch's merkle root (required for epoch > 0 to prevent replay attacks)
    #[serde(with = "ghost_common::serde_hex::option_bytes32", default)]
    pub prev_merkle_root: Option<[u8; 32]>,
    /// Approver's node ID (must be an elder in current epoch)
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub approver: NodeId,
    /// Approver's signature over (epoch || merkle_root || prev_merkle_root)
    #[serde(with = "ghost_common::serde_hex::bytes64")]
    pub signature: [u8; 64],
    /// Timestamp (Unix milliseconds)
    pub timestamp: u64,
}

impl ElderListApprovalMessage {
    // Domain separator - MUST match ElderApproval::signing_message* in elder_list.rs
    const APPROVAL_DOMAIN: &'static [u8] = b"ghost/elder-approval/v1";

    /// Get the message to be signed (v1, for genesis epoch 0 only)
    pub fn signing_message(epoch: u64, merkle_root: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(Self::APPROVAL_DOMAIN.len() + 8 + 32);
        msg.extend_from_slice(Self::APPROVAL_DOMAIN);
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(merkle_root);
        msg
    }

    /// Get the message to be signed (v2, for epoch > 0 with chain binding)
    pub fn signing_message_v2(
        epoch: u64,
        merkle_root: &[u8; 32],
        prev_merkle_root: &[u8; 32],
    ) -> Vec<u8> {
        let mut msg = Vec::with_capacity(Self::APPROVAL_DOMAIN.len() + 8 + 32 + 32);
        msg.extend_from_slice(Self::APPROVAL_DOMAIN);
        msg.extend_from_slice(&epoch.to_le_bytes());
        msg.extend_from_slice(merkle_root);
        msg.extend_from_slice(prev_merkle_root);
        msg
    }

    /// Create a new approval message (v1, for genesis)
    pub fn new(
        epoch: u64,
        merkle_root: [u8; 32],
        approver: NodeId,
        sign_fn: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Self {
        let message = Self::signing_message(epoch, &merkle_root);
        let signature = sign_fn(&message);
        Self {
            epoch,
            merkle_root,
            prev_merkle_root: None,
            approver,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Create a new approval message with chain binding (v2, for epoch > 0)
    pub fn new_with_prev(
        epoch: u64,
        merkle_root: [u8; 32],
        prev_merkle_root: [u8; 32],
        approver: NodeId,
        sign_fn: impl FnOnce(&[u8]) -> [u8; 64],
    ) -> Self {
        let message = Self::signing_message_v2(epoch, &merkle_root, &prev_merkle_root);
        let signature = sign_fn(&message);
        Self {
            epoch,
            merkle_root,
            prev_merkle_root: Some(prev_merkle_root),
            approver,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        }
    }

    /// Verify the approver's signature
    ///
    /// SEC-SIG-6: Logs errors instead of silently returning false
    /// Uses v2 message format if prev_merkle_root is present, v1 for genesis
    pub fn verify_signature(&self) -> bool {
        let message = match &self.prev_merkle_root {
            Some(prev) => Self::signing_message_v2(self.epoch, &self.merkle_root, prev),
            None => Self::signing_message(self.epoch, &self.merkle_root),
        };
        match ghost_common::identity::verify_signature(&self.approver, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    approver = %hex::encode(&self.approver[..8]),
                    epoch = self.epoch,
                    error = %e,
                    "Elder list approval signature verification error"
                );
                false
            }
        }
    }
}

/// Elder registration vote message
///
/// An elder's vote on whether to approve a new elder registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElderRegistrationVoteMessage {
    /// Candidate being voted on
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub candidate: NodeId,
    /// Target epoch
    pub target_epoch: u64,
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

impl ElderRegistrationVoteMessage {
    /// Get the message to be signed
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ElderRegistrationVote/v1");
        hasher.update(self.candidate);
        hasher.update(self.target_epoch.to_le_bytes());
        hasher.update([self.approve as u8]);
        hasher.finalize().into()
    }

    /// Verify the voter's signature
    ///
    /// SEC-SIG-7: Logs errors instead of silently returning false
    pub fn verify_signature(&self) -> bool {
        let message = self.signing_message();
        match ghost_common::identity::verify_signature(&self.voter, &message, &self.signature) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::warn!(
                    voter = %hex::encode(&self.voter[..8]),
                    candidate = %hex::encode(&self.candidate[..8]),
                    error = %e,
                    "Elder registration vote signature verification error"
                );
                false
            }
        }
    }
}

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
    pub fn contribution_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MpcContributionHash/v1");
        hasher.update(self.candidate);
        hasher.update(self.elder_position.to_le_bytes());
        hasher.update(self.new_params_hash);
        hasher.finalize().into()
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
    pub fn signing_message(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"MpcVerificationVote/v1");
        hasher.update(self.contribution_hash);
        hasher.update([self.approve as u8]);
        hasher.finalize().into()
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

/// L2: Tree sync request/response (node → peer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TreeSyncMessage {
    /// Requester/responder node ID
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub node: NodeId,
    /// Epoch to sync
    pub epoch: u64,
    /// Whether this is a request (true) or response (false)
    pub is_request: bool,
    /// Notes to sync (only present in response)
    pub notes: Option<Vec<L2TreeSyncNote>>,
    /// Commitment root for verification (only present in response)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_root: Option<String>,
    /// Timestamp
    pub timestamp: u64,
}

/// A note in a tree sync response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TreeSyncNote {
    /// Note index in tree
    pub index: u64,
    /// Commitment value
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub commitment: [u8; 32],
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
    /// Checkpoint blocks (batched, max 100 per response)
    pub checkpoints: Vec<L2CheckpointBlockMessage>,
    /// Current epoch number
    pub current_epoch: u64,
    /// Current commitment root for verification
    #[serde(with = "ghost_common::serde_hex::bytes32")]
    pub commitment_root: [u8; 32],
    /// Whether there are more checkpoints to sync
    pub has_more: bool,
    /// Timestamp
    pub timestamp: u64,
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
}
