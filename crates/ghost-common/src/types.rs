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
//| FILE: types.rs                                                                                                       |
//|======================================================================================================================|

//! Common types used across Bitcoin Ghost

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 32-byte Node ID (Ed25519 public key)
pub type NodeId = [u8; 32];

/// 32-byte block hash
pub type BlockHash = [u8; 32];

/// 32-byte transaction ID
pub type Txid = [u8; 32];

/// 64-byte Ed25519 signature
pub type Signature = [u8; 64];

/// Round identifier
pub type RoundId = u64;

/// Block height
pub type BlockHeight = u64;

/// Amount in satoshis
pub type Satoshis = u64;

/// Node capabilities flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NodeCapabilities {
    /// Archive mode enabled (+5 shares)
    pub archive_mode: bool,
    /// Ghost Pay L2 enabled (+4 shares)
    pub ghost_pay: bool,
    /// Public mining enabled (+3 shares)
    pub public_mining: bool,
    /// Reaper strict mode enabled (+2 shares)
    pub reaper: bool,
    /// Elder status (+1 share)
    pub elder_status: bool,
    /// Wraith coordinator role opted in. Earns the mixing service fee, NOT
    /// 5-4-3-2-1 shares — so it is deliberately excluded from `total_shares()`
    /// and needs no verification challenge. `#[serde(default)]` so health pings
    /// from peers on pre-coordinator builds (which omit the field) still
    /// deserialize as `coordinator = false`.
    #[serde(default)]
    pub coordinator: bool,
}

impl NodeCapabilities {
    /// Create new capabilities with all disabled
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate total shares (0-15)
    ///
    /// MEDIUM-STOR-1: Uses checked arithmetic to prevent overflow.
    /// The compile-time assertion below ensures max possible shares < i32::MAX.
    pub fn total_shares(&self) -> i32 {
        let mut shares = 0i32;
        if self.archive_mode {
            shares = shares
                .checked_add(crate::constants::ARCHIVE_MODE_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        if self.ghost_pay {
            shares = shares
                .checked_add(crate::constants::GHOST_PAY_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        if self.public_mining {
            shares = shares
                .checked_add(crate::constants::PUBLIC_MINING_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        if self.reaper {
            shares = shares.checked_add(crate::constants::REAPER_SHARES).expect(
                "BUG: share calculation overflow - max possible shares verified < i32::MAX",
            );
        }
        if self.elder_status {
            shares = shares
                .checked_add(crate::constants::ELDER_STATUS_SHARES)
                .expect(
                    "BUG: share calculation overflow - max possible shares verified < i32::MAX",
                );
        }
        shares
    }

    /// Check if node has any capabilities
    pub fn has_any(&self) -> bool {
        self.archive_mode
            || self.ghost_pay
            || self.public_mining
            || self.reaper
            || self.elder_status
            || self.coordinator
    }
}

/// Capacity state for load balancing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityState {
    /// Below 50% capacity
    Healthy,
    /// 50-75% capacity
    Normal,
    /// 75-90% capacity
    SoftLimit,
    /// Above 90% capacity
    HardLimit,
}

impl CapacityState {
    /// Calculate from current/max miners
    ///
    /// M-25: Uses integer arithmetic to avoid floating-point imprecision.
    /// `(current * 100) / max` gives the integer percentage (truncated).
    pub fn from_load(current: u32, max: u32) -> Self {
        if max == 0 {
            return Self::HardLimit;
        }
        // M-25: Integer percentage — u64 intermediate prevents u32 overflow
        let percent = (current as u64 * 100) / max as u64;
        if percent < 50 {
            Self::Healthy
        } else if percent < 75 {
            Self::Normal
        } else if percent < 90 {
            Self::SoftLimit
        } else {
            Self::HardLimit
        }
    }

    /// Get load penalty for scoring
    pub fn load_penalty(&self) -> f64 {
        match self {
            Self::Healthy => 0.0,
            Self::Normal => 0.1,
            Self::SoftLimit => 0.3,
            Self::HardLimit => 1.0,
        }
    }
}

/// Consensus result types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusResult {
    /// Proposal approved by 67%+
    Approved {
        proposal_hash: [u8; 32],
        approval_count: u32,
        total_nodes: u32,
    },
    /// Proposal rejected by 67%+
    Rejected {
        proposal_hash: [u8; 32],
        rejection_count: u32,
        total_nodes: u32,
        reason: Option<String>,
    },
    /// Voting timed out
    Timeout {
        proposal_hash: [u8; 32],
        approvals: u32,
        rejections: u32,
        total_nodes: u32,
    },
    /// Error during consensus
    Error(String),
}

/// Vote type for consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    /// Vote on payout proposal
    PayoutApproval,
    /// Vote on elder revocation
    ElderRevocation,
    /// Vote on share allocation
    ShareAllocation,
}

/// Revocation reason for elders
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Offline for 7+ days
    ExtendedOffline { offline_days: u64 },
    /// Malicious behavior detected
    MaliciousBehavior { description: String },
    /// Voluntary resignation
    Voluntary,
}

/// Block found event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockFoundEvent {
    /// Block hash
    pub block_hash: BlockHash,
    /// Block height
    pub block_height: BlockHeight,
    /// Round ID
    pub round_id: RoundId,
    /// Winning miner pubkey hash
    pub winning_miner: [u8; 32],
    /// Node that found the block
    pub found_by_node: NodeId,
    /// Transaction fees in satoshis
    pub tx_fees_satoshis: Satoshis,
    /// Block subsidy in satoshis
    pub subsidy_satoshis: Satoshis,
    /// Timestamp
    pub timestamp: u64,
}

/// Share proof for P2P propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProof {
    /// Round ID
    pub round_id: RoundId,
    /// Miner pubkey hash
    pub miner_id: [u8; 32],
    /// Share difficulty met
    pub difficulty: f64,
    /// Work value
    pub work: f64,
    /// Share hash
    pub share_hash: [u8; 32],
    /// Timestamp
    pub timestamp: u64,
    /// Node that received the share
    pub received_by: NodeId,
    /// M-MINE-1: Template ID (prev_block_hash) this share is for
    /// Used to validate share is for current or recent template
    #[serde(default)]
    pub template_id: Option<[u8; 32]>,
    /// Payout address for the miner (needed by remote nodes that haven't seen this miner)
    #[serde(default)]
    pub payout_address: Option<String>,
    /// Multi-operator PoW verification: the raw 80-byte Bitcoin block header this share
    /// solved, so ANY node can independently recompute `sha256d(header) == share_hash`
    /// (see `DifficultyCalculator::verify_pow_preimage`) rather than trusting the origin's
    /// signed numeric claim. `None` below `SHARE_POW_VERIFY_HEIGHT` (populated only at/above
    /// the gate, so while dormant `signing_bytes` is byte-identical to pre-header proofs and
    /// a mixed-version fleet stays compatible). Bound by the GHOST-09 signature when present,
    /// so it can't be stripped or swapped. `Vec<u8>` (not `[u8;80]`) for serde simplicity;
    /// verifiers require `len()==80`.
    #[serde(default)]
    pub header: Option<Vec<u8>>,
    /// GHOST-09: ed25519 signature by `received_by` over [`ShareProof::signing_bytes`].
    /// Authenticates the node-reward credit recipient so a relayed proof can't be
    /// re-credited to a different node. `None` on pre-GHOST-09 proofs, which fail
    /// verification (secure by default). Stored as bytes for serde simplicity.
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
}

/// Map an `f64` to the value it deserializes to after a serde_json round-trip.
///
/// serde_json's f64 (de)serialization is not guaranteed bit-exact, so a value
/// signed before serialization can deserialize ~1 ULP off on a peer. This
/// round-trip is idempotent, so applying it on both the signer and the verifier
/// yields the identical value that actually crossed the wire — used by
/// `ShareProof::signing_bytes` so GHOST-09 signatures survive gossip.
fn canonical_json_f64(x: f64) -> f64 {
    serde_json::to_string(&x)
        .ok()
        .and_then(|s| serde_json::from_str::<f64>(&s).ok())
        .unwrap_or(x)
}

impl ShareProof {
    /// GHOST-09 v1: canonical bytes the `received_by` node signs.
    ///
    /// Binds the fields that identify the WORK — a relay that mutates `received_by`, the share
    /// hash, the work or the header invalidates the signature.
    ///
    /// ⚠ It does NOT bind `payout_address`, which since `PAYOUT_ADDRESS_GROUPING_HEIGHT` is the
    /// field payouts are grouped by. This comment previously claimed to bind "every credit-relevant
    /// field"; that became false when grouping moved from miner_id to the address, and the gap is
    /// exploitable — see [`Self::signing_bytes_bound`], which closes it behind a height gate.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(120);
        m.extend_from_slice(&self.round_id.to_le_bytes());
        m.extend_from_slice(&self.miner_id);
        // GHOST-09: `work` is an f64 and the proof is gossiped as JSON, but
        // serde_json's f64 (de)serialization is NOT guaranteed bit-exact (it can
        // differ by ~1 ULP). Committing to the raw bits would make a verifier's
        // recomputed signing_bytes differ from the signer's and reject every
        // share — and then GHOST-02 rejects every payout for lack of shares.
        // Commit to the JSON-canonical value instead: the round-trip is
        // idempotent, so signer and verifier agree on the value that crossed the
        // wire regardless of the original f64's exact bits.
        m.extend_from_slice(&canonical_json_f64(self.work).to_le_bytes());
        m.extend_from_slice(&self.share_hash);
        m.extend_from_slice(&self.timestamp.to_le_bytes());
        m.extend_from_slice(&self.received_by);
        if let Some(ref t) = self.template_id {
            m.extend_from_slice(t);
        }
        // Bind the PoW header when present (populated at/above SHARE_POW_VERIFY_HEIGHT), so
        // a relay can't strip or swap it. Absent while the gate is dormant → identical to
        // pre-header proofs, keeping a mixed-version fleet's signatures compatible.
        if let Some(ref h) = self.header {
            m.extend_from_slice(h);
        }
        m
    }

    /// GHOST-09: sign this proof as the receiving node. `received_by` must equal
    /// `identity.node_id()` for the signature to verify on the receive side.
    pub fn sign(&mut self, identity: &crate::identity::NodeIdentity) {
        self.signature = Some(identity.sign(&self.signing_bytes()).to_vec());
    }

    /// GHOST-09: consume-and-sign convenience (builder/test ergonomics).
    pub fn signed(mut self, identity: &crate::identity::NodeIdentity) -> Self {
        self.sign(identity);
        self
    }

    /// GHOST-09 v2: [`Self::signing_bytes`] extended to bind `payout_address`.
    ///
    /// The v1 encoding covers everything that identifies the *work* but not the field that decides
    /// who gets *paid* for it. Since payouts are grouped by payout address, and the address is
    /// adopted first-writer-wins from whichever signed proof arrives first, an unbound address lets
    /// any mesh peer rewrite a relayed proof's destination without breaking the signature.
    ///
    /// Length-prefixed rather than appended raw: the address is variable-width, so without a length
    /// two different (address, next-field) pairs could serialize identically. `header` above is
    /// fixed at 80 bytes and does not have that problem.
    ///
    /// When `payout_address` is `None` this is byte-identical to v1, which keeps a proof that never
    /// carried an address verifying the same way under either encoding.
    pub fn signing_bytes_bound(&self) -> Vec<u8> {
        let mut m = self.signing_bytes();
        if let Some(ref addr) = self.payout_address {
            m.extend_from_slice(&(addr.len() as u32).to_le_bytes());
            m.extend_from_slice(addr.as_bytes());
        }
        m
    }

    /// GHOST-09 v2: sign this proof as the receiving node, binding the payout address.
    pub fn sign_bound(&mut self, identity: &crate::identity::NodeIdentity) {
        self.signature = Some(identity.sign(&self.signing_bytes_bound()).to_vec());
    }

    /// GHOST-09 v2: true iff the signature covers this proof *including* its payout address.
    ///
    /// Stripping the address, adding one, or swapping it all change the signed bytes, so all three
    /// fail here. Unsigned or malformed returns false — secure by default, as v1.
    pub fn has_valid_bound_signature(&self) -> bool {
        let Some(ref sig) = self.signature else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
            return false;
        };
        crate::identity::verify_signature(&self.received_by, &self.signing_bytes_bound(), &sig)
            .unwrap_or(false)
    }

    /// GHOST-09: true iff the proof carries a valid signature by `received_by`.
    /// Unsigned (`None`) or malformed signatures return false — secure by default.
    pub fn has_valid_received_by_signature(&self) -> bool {
        let Some(ref sig) = self.signature else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(sig.as_slice()) else {
            return false;
        };
        crate::identity::verify_signature(&self.received_by, &self.signing_bytes(), &sig)
            .unwrap_or(false)
    }
}

/// Payout proposal for consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutProposal {
    /// Proposal hash (for voting)
    pub proposal_hash: [u8; 32],
    /// Round ID
    pub round_id: RoundId,
    /// Block hash
    pub block_hash: BlockHash,
    /// Block height
    pub block_height: BlockHeight,
    /// Proposing node
    pub proposer: NodeId,
    /// Miner payouts
    pub miner_payouts: Vec<PayoutEntry>,
    /// Node reward payouts
    pub node_payouts: Vec<PayoutEntry>,
    /// Treasury amount
    pub treasury_amount: Satoshis,
    /// H-MINE-3: Treasury address snapshot taken at round/proposal creation
    /// This prevents TOCTOU issues where the config might change between
    /// proposal creation and coinbase building. Used instead of live config.
    #[serde(default)]
    pub treasury_address: Vec<u8>,
    /// TX fees (to node operator)
    pub tx_fees: Satoshis,
    /// Total subsidy
    pub subsidy: Satoshis,
    /// Timestamp
    pub timestamp: u64,
    /// TX fees that could not be allocated (e.g., block finder has no address)
    /// This field tracks satoshis that would otherwise be lost (PO-H4)
    #[serde(default)]
    pub tx_fees_unallocated: Satoshis,
}

/// Single payout entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutEntry {
    /// Recipient address (script pubkey)
    pub address: Vec<u8>,
    /// Amount in satoshis
    pub amount: Satoshis,
    /// Recipient identifier (miner_id or node_id)
    pub recipient_id: [u8; 32],
    /// Payout type
    pub payout_type: PayoutType,
}

/// Type of payout
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayoutType {
    /// Mining reward
    Mining,
    /// Node capability reward
    NodeReward,
    /// Treasury allocation
    Treasury,
    /// TX fees to node operator
    TxFees,
}

/// Health ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPing {
    /// Sender node ID
    pub node_id: NodeId,
    /// Public address for P2P connections
    pub public_address: String,
    /// Current block height
    pub block_height: BlockHeight,
    /// Current round ID
    pub round_id: RoundId,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Connected miners count
    pub miner_count: u32,
    /// Timestamp
    pub timestamp: u64,
    /// PoW proof for Sybil resistance (nonce, difficulty)
    /// Proves computational work was done to create this identity
    #[serde(default)]
    pub pow_proof: Option<(u64, u32)>,
    /// Truncated SHA-256 hashes of miner_ids active in the last N seconds on
    /// the sender. Used by peers to compute a deduplicated mesh-wide active
    /// miner count without leaking miner_ids in cleartext.
    /// Field is `#[serde(default)]` for backward compatibility — older nodes
    /// that don't include it deserialize to an empty Vec.
    #[serde(default, with = "ghost_common_active_hashes")]
    pub active_miner_id_hashes: Vec<[u8; 16]>,
    /// This node's own realized hashrate (TH/s) over a trailing window,
    /// computed from shares THIS node received directly (scoped by
    /// `received_by`, so replicated peer share-proofs aren't counted). Peers
    /// SUM these across the mesh for a pool-wide total: shares are partitioned
    /// by node, so the sum can't double-count and is identical on every node,
    /// and a miner migrating between nodes shifts work from one term to another
    /// without changing the total. `#[serde(default)]` for backward
    /// compatibility — older nodes that don't send it contribute 0.
    #[serde(default)]
    pub local_hashrate_th: f64,
    /// Hardware-derived effective miner capacity. Translator's load balancer
    /// uses `miner_count / max_capacity` to compute utilisation and route
    /// new arrivals to the under-utilised peer. 0 = pre-update node (treated
    /// as unknown / excluded from utilisation routing).
    #[serde(default)]
    pub max_capacity: u32,
    /// This node's best (rarest) valid share per public records window
    /// (`block | day | week | month`). Gossiped so every node knows the
    /// global best per window and the `/api/v1/pool/records` endpoint can
    /// return the mesh-wide rarest record instead of only its local one —
    /// without that, the pool-wide record lives on a single node and the
    /// website (which fans out and takes the min) flickers whenever that
    /// node is momentarily unreachable. `#[serde(default)]` for backward
    /// compatibility — older nodes that don't send it deserialise to an
    /// empty Vec, and newer nodes simply ignore peers that omit it.
    #[serde(default)]
    pub best_records: Vec<WindowBestRecord>,
    /// This node's SV1 **hobby** stratum listener, and its **farm** listener when it runs one.
    ///
    /// The load balancer became tier-aware in #494 but nothing advertised which listeners a node
    /// actually runs, so no peer was ever a farm-routing candidate and the busiest node could not
    /// shed a farm miner. This is the half that switches it on (#495).
    ///
    /// Deliberately NOT in `NodeCapabilities`: every field there feeds `total_shares()` for the
    /// 5-4-3-2-1 scoring model, and a port number would corrupt the score.
    ///
    /// `None` on a peer that predates this field. The consumer treats absent-hobby as "serves the
    /// default 3333", which is what every node did before the farm tier existed, and absent-farm
    /// as "not a farm target" — assuming a farm port is how a farm miner lands on a hobby floor,
    /// so absence disqualifies rather than defaults. A partial rollout therefore degrades to
    /// "no farm routing", never to misrouting.
    #[serde(default)]
    pub hobby_port: Option<u16>,
    /// See `hobby_port`. `None` means either "no farm tier" or "too old to say", and both must be
    /// treated identically: not a farm routing target.
    #[serde(default)]
    pub farm_port: Option<u16>,
    /// If this node has opted in as a Wraith coordinator
    /// (`capabilities.coordinator`), the reachable endpoint a wallet should dial
    /// to mix with it: a public `host:port` or a `.onion`. This is a DELIBERATE,
    /// operator-chosen advertisement (unlike `public_address`, which is withheld
    /// per S-7) — a coordinator is useless if unreachable, and operators wanting
    /// privacy advertise a Tor hidden service instead of an IP. `None` for nodes
    /// that haven't opted in. `#[serde(default)]` for backward compatibility.
    #[serde(default)]
    pub coordinator_endpoint: Option<String>,
    /// If this node is an active coordinator, the number of Wraith mixing
    /// sessions it handled over a recent trailing window. Summed across the mesh
    /// at each epoch boundary to size the next epoch's coordinator seat count
    /// (demand-driven scaling). 0 for non-coordinators and idle coordinators.
    /// `#[serde(default)]` for backward compatibility.
    #[serde(default)]
    pub coordinator_sessions: u32,
    /// This node's own trailing-7-day uptime, as a PERCENTAGE (0-100) — the
    /// qualification gatekeeper metric (>=95% before capabilities count).
    /// Gossiped so the dashboard Swarm page can render each mesh peer's uptime
    /// instead of a dash. `Option` (not a plain `f64` defaulting to 0.0) so an
    /// older peer that omits it — or one with no uptime samples yet — is shown
    /// as "—" rather than a misleading 0.0%. `#[serde(default)]` → `None` when
    /// absent, keeping the wire change additive for a mixed-version fleet.
    #[serde(default)]
    pub uptime_percent: Option<f64>,
    /// The number of mesh peers THIS node currently sees (its own deduplicated
    /// peer count). Gossiped so the Swarm page can show each peer's connectivity.
    /// `Option` so absence (older peer) renders as "—", never a misleading 0.
    /// `#[serde(default)]` for backward compatibility.
    #[serde(default)]
    pub peer_count: Option<u32>,
    /// This node's Ghost Pay L2 virtual-block height, when it runs ghost-pay.
    /// Gossiped so the Swarm page can show each mesh peer's L2 tip. `None` for
    /// nodes that don't run ghost-pay (or older peers that predate this field),
    /// so the frontend renders "—" instead of a fabricated 0. `#[serde(default)]`
    /// for backward compatibility.
    #[serde(default)]
    pub l2_height: Option<u64>,
    /// This node's node-reward payout address (a Bitcoin address string). Gossiped
    /// so EVERY node learns EVERY node's payout address — without this, each node
    /// only knows its own (written from local config), so the qualified-node
    /// candidate set (`get_all_node_ids_with_payout`, which filters
    /// `payout_address IS NOT NULL`) is `{self}` on every node and the payout-ledger
    /// checkpoint can never converge. Public information (it is a coinbase output),
    /// and authenticated: the receiver stores it only for the Noise-authenticated
    /// `envelope.sender`, so a node can only advertise its OWN address. `None` for
    /// nodes with no configured payout address (or older peers); `#[serde(default)]`
    /// keeps the wire change additive for a mixed-version fleet.
    #[serde(default)]
    pub payout_address: Option<String>,
}

/// One node's best (rarest) valid share in a public records window.
///
/// Carried in [`HealthPing::best_records`] so every node can converge on the
/// mesh-wide rarest record per window. The `share_hash` is the canonical
/// record (lower = rarer); all other fields are derived presentation data
/// already shaped the way the records API returns them, so a receiving node
/// can serve a peer's record verbatim without re-querying.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct WindowBestRecord {
    /// Records window this record belongs to: `block | day | week | month`.
    pub window: String,
    /// 64-char zero-padded big-endian hex of the share hash. Fixed width, so
    /// lexicographic string comparison matches numeric order (lower = rarer).
    pub share_hash: String,
    /// Achieved difficulty derived from `share_hash` (the score), matching the
    /// `difficulty` the records API returns.
    pub difficulty: f64,
    /// Unix-seconds timestamp of the share.
    pub timestamp: i64,
    /// Redacted miner_id (e.g. `bc1q7z…y492.avalon1`), already shaped the same
    /// way the records API redacts — never the raw miner_id.
    pub miner_id_redacted: String,
}

/// Hex-encoded serialization for the active miner-id hash list.
/// Keeps health-ping JSON human-readable and matches the `serde_hex` style
/// used elsewhere for fixed-size byte arrays in this module.
mod ghost_common_active_hashes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &[[u8; 16]], s: S) -> Result<S::Ok, S::Error> {
        let hex_strs: Vec<String> = v.iter().map(hex::encode).collect();
        serde::Serialize::serialize(&hex_strs, s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 16]>, D::Error> {
        let hex_strs: Vec<String> = Vec::deserialize(d)?;
        let mut out = Vec::with_capacity(hex_strs.len());
        for s in hex_strs {
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 16 {
                return Err(serde::de::Error::custom(format!(
                    "expected 16 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            out.push(arr);
        }
        Ok(out)
    }
}

/// Errors for treasury address validation
#[derive(Debug, Error)]
pub enum TreasuryAddressError {
    /// Invalid M-of-N parameters
    #[error("Invalid M-of-N: M={m} must be <= N={n} and both must be between 1 and 15")]
    InvalidMofN { m: u8, n: u8 },

    /// Empty address
    #[error("Treasury address cannot be empty")]
    EmptyAddress,

    /// Invalid witness script
    #[error("Invalid witness script: {0}")]
    InvalidWitnessScript(String),

    /// Public key count mismatch
    #[error("Expected {expected} public keys, got {actual}")]
    PubkeyCountMismatch { expected: u8, actual: usize },

    /// P2TR address (quantum-unsafe)
    #[error("P2TR addresses (bc1p...) are quantum-vulnerable. Use P2WPKH (bc1q...) instead.")]
    QuantumUnsafe,
}

/// Treasury address configuration
///
/// Supports both single-sig and multi-sig (P2WSH) addresses for treasury payouts.
/// Multi-sig provides enhanced security for mainnet deployments.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TreasuryAddress {
    /// Single-sig address (bech32 format)
    ///
    /// Example: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    Single(String),

    /// Multi-sig P2WSH address
    ///
    /// Requires M-of-N signatures to spend.
    MultiSig {
        /// P2WSH bech32 address
        address: String,

        /// Witness script (redeem script) in hex
        ///
        /// This is the actual multi-sig script that gets hashed to create
        /// the P2WSH address. Required for spending.
        witness_script: String,

        /// Required signatures (M in M-of-N)
        required: u8,

        /// Total signers (N in M-of-N)
        total: u8,

        /// Public keys of all signers (optional, for verification)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pubkeys: Vec<String>,
    },
}

impl TreasuryAddress {
    /// Create a single-sig treasury address
    pub fn single(address: impl Into<String>) -> Self {
        Self::Single(address.into())
    }

    /// Create a multi-sig treasury address
    ///
    /// # Arguments
    /// * `address` - P2WSH bech32 address
    /// * `witness_script` - Witness script (redeem script) in hex
    /// * `required` - Required signatures (M)
    /// * `total` - Total signers (N)
    pub fn multisig(
        address: impl Into<String>,
        witness_script: impl Into<String>,
        required: u8,
        total: u8,
    ) -> Result<Self, TreasuryAddressError> {
        // Validate M-of-N parameters
        if required == 0 || total == 0 || required > total || total > 15 {
            return Err(TreasuryAddressError::InvalidMofN {
                m: required,
                n: total,
            });
        }

        Ok(Self::MultiSig {
            address: address.into(),
            witness_script: witness_script.into(),
            required,
            total,
            pubkeys: Vec::new(),
        })
    }

    /// Create a multi-sig treasury address with public keys
    pub fn multisig_with_pubkeys(
        address: impl Into<String>,
        witness_script: impl Into<String>,
        required: u8,
        total: u8,
        pubkeys: Vec<String>,
    ) -> Result<Self, TreasuryAddressError> {
        // Validate M-of-N parameters
        if required == 0 || total == 0 || required > total || total > 15 {
            return Err(TreasuryAddressError::InvalidMofN {
                m: required,
                n: total,
            });
        }

        // Validate pubkey count if provided
        if !pubkeys.is_empty() && pubkeys.len() != total as usize {
            return Err(TreasuryAddressError::PubkeyCountMismatch {
                expected: total,
                actual: pubkeys.len(),
            });
        }

        Ok(Self::MultiSig {
            address: address.into(),
            witness_script: witness_script.into(),
            required,
            total,
            pubkeys,
        })
    }

    /// Get the address string (works for both single and multi-sig)
    pub fn address(&self) -> &str {
        match self {
            Self::Single(addr) => addr,
            Self::MultiSig { address, .. } => address,
        }
    }

    /// Check if this is a multi-sig address
    pub fn is_multisig(&self) -> bool {
        matches!(self, Self::MultiSig { .. })
    }

    /// Get M-of-N parameters for multi-sig
    pub fn multisig_params(&self) -> Option<(u8, u8)> {
        match self {
            Self::Single(_) => None,
            Self::MultiSig {
                required, total, ..
            } => Some((*required, *total)),
        }
    }

    /// Get the witness script for multi-sig
    pub fn witness_script(&self) -> Option<&str> {
        match self {
            Self::Single(_) => None,
            Self::MultiSig { witness_script, .. } => Some(witness_script),
        }
    }

    /// Validate the treasury address configuration
    ///
    /// # Quantum Safety
    ///
    /// Rejects P2TR addresses (bc1p...) for quantum safety. P2TR exposes
    /// public keys on-chain, making them vulnerable to quantum computer
    /// attacks while funds are locked.
    pub fn validate(&self) -> Result<(), TreasuryAddressError> {
        // Helper to check if address is P2TR (quantum-unsafe)
        fn is_p2tr_address(addr: &str) -> bool {
            addr.starts_with("bc1p") || addr.starts_with("tb1p") || addr.starts_with("bcrt1p")
        }

        match self {
            Self::Single(addr) => {
                if addr.is_empty() {
                    return Err(TreasuryAddressError::EmptyAddress);
                }
                // QUANTUM SAFETY: Reject P2TR addresses
                if is_p2tr_address(addr) {
                    return Err(TreasuryAddressError::QuantumUnsafe);
                }
                Ok(())
            }
            Self::MultiSig {
                address,
                witness_script,
                required,
                total,
                pubkeys,
            } => {
                if address.is_empty() {
                    return Err(TreasuryAddressError::EmptyAddress);
                }

                // QUANTUM SAFETY: Reject P2TR addresses
                if is_p2tr_address(address) {
                    return Err(TreasuryAddressError::QuantumUnsafe);
                }

                if *required == 0 || *total == 0 || *required > *total || *total > 15 {
                    return Err(TreasuryAddressError::InvalidMofN {
                        m: *required,
                        n: *total,
                    });
                }

                if witness_script.is_empty() {
                    return Err(TreasuryAddressError::InvalidWitnessScript(
                        "witness script cannot be empty".into(),
                    ));
                }

                // Validate hex encoding
                if hex::decode(witness_script).is_err() {
                    return Err(TreasuryAddressError::InvalidWitnessScript(
                        "witness script must be valid hex".into(),
                    ));
                }

                // Validate pubkey count if provided
                if !pubkeys.is_empty() && pubkeys.len() != *total as usize {
                    return Err(TreasuryAddressError::PubkeyCountMismatch {
                        expected: *total,
                        actual: pubkeys.len(),
                    });
                }

                Ok(())
            }
        }
    }

    /// Check if the address is empty
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(addr) => addr.is_empty(),
            Self::MultiSig { address, .. } => address.is_empty(),
        }
    }
}

impl Default for TreasuryAddress {
    fn default() -> Self {
        Self::Single(String::new())
    }
}

impl From<String> for TreasuryAddress {
    fn from(address: String) -> Self {
        Self::Single(address)
    }
}

impl From<&str> for TreasuryAddress {
    fn from(address: &str) -> Self {
        Self::Single(address.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_proof_signature_survives_json_roundtrip() {
        // GHOST-09 over real transport: a ShareProof signed by `received_by` must
        // still verify after a serde_json round-trip (gossip serializes the proof
        // inside ShareProofMessage). If any signed field doesn't round-trip
        // bit-exactly, peers drop the share as "invalid received_by signature".
        let id = crate::identity::NodeIdentity::generate();
        let mut proof = ShareProof {
            round_id: 7,
            miner_id: [3u8; 32],
            difficulty: 2.3305991803113107e-07,
            work: 2.3305991803113107e-07,
            share_hash: [5u8; 32],
            timestamp: 1_781_964_482,
            received_by: id.node_id(),
            template_id: Some([9u8; 32]),
            payout_address: Some("bcrt1qexample".to_string()),
            header: None,
            signature: None,
        };
        proof.sign(&id);
        assert!(
            proof.has_valid_received_by_signature(),
            "signature must be valid immediately after signing"
        );

        let json = serde_json::to_vec(&proof).expect("serialize");
        let proof2: ShareProof = serde_json::from_slice(&json).expect("deserialize");
        assert!(
            proof2.has_valid_received_by_signature(),
            "signature must still verify after a serde_json round-trip (gossip path)"
        );
    }

    #[test]
    fn share_proof_header_is_bound_by_signature_and_backcompat() {
        let id = crate::identity::NodeIdentity::generate();
        let base = ShareProof {
            round_id: 1,
            miner_id: [1u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: [2u8; 32],
            timestamp: 100,
            received_by: id.node_id(),
            template_id: Some([3u8; 32]),
            payout_address: Some("bc1qx".to_string()),
            header: None,
            signature: None,
        };

        // Back-compat: a header-less proof's signing_bytes is unchanged from before the
        // field existed (the `None` branch appends nothing), so mixed-version peers agree.
        let no_header = base.clone();
        let mut with_header = base.clone();
        with_header.header = Some(vec![0xabu8; 80]);
        assert_ne!(
            no_header.signing_bytes(),
            with_header.signing_bytes(),
            "a present header must change the signed bytes (so it's bound)"
        );

        // Sign WITH a header, then strip it → signature must FAIL (can't remove the PoW).
        let mut signed = with_header.clone();
        signed.sign(&id);
        assert!(signed.has_valid_received_by_signature(), "valid as signed");
        let mut stripped = signed.clone();
        stripped.header = None;
        assert!(
            !stripped.has_valid_received_by_signature(),
            "stripping the signed header must invalidate the signature"
        );
        // Swapping the header for a different one also breaks it.
        let mut swapped = signed.clone();
        swapped.header = Some(vec![0xcdu8; 80]);
        assert!(
            !swapped.has_valid_received_by_signature(),
            "swapping the signed header must invalidate the signature"
        );
    }

    /// The hole this closes: today a relayed proof's payout address can be rewritten and the
    /// signature still verifies, because v1 does not cover the field payouts are grouped by.
    ///
    /// Asserts both directions — v1 accepts the tampered proof (documenting the exploit), v2
    /// rejects it — so if anyone ever "simplifies" the bound encoding back to v1 the test says why
    /// that is not a simplification.
    #[test]
    fn payout_address_is_bound_only_under_the_v2_signature() {
        let id = crate::identity::NodeIdentity::generate();
        let honest = ShareProof {
            round_id: 7,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 2.5,
            share_hash: [4u8; 32],
            timestamp: 1_700_000_000,
            received_by: id.node_id(),
            template_id: Some([5u8; 32]),
            payout_address: Some("bc1qhonestminer".to_string()),
            header: Some(vec![0xab; 80]),
            signature: None,
        };

        // Signed the old way, an attacker can redirect the payout and the signature still passes.
        let mut v1 = honest.clone();
        v1.sign(&id);
        assert!(v1.has_valid_received_by_signature());
        let mut redirected = v1.clone();
        redirected.payout_address = Some("bc1qattacker".to_string());
        assert!(
            redirected.has_valid_received_by_signature(),
            "v1 does not bind the address — this is the vulnerability, asserted so it is not \
             mistaken for safe"
        );

        // Signed the new way, the same tamper fails.
        let mut v2 = honest.clone();
        v2.sign_bound(&id);
        assert!(v2.has_valid_bound_signature(), "valid as signed");
        let mut redirected2 = v2.clone();
        redirected2.payout_address = Some("bc1qattacker".to_string());
        assert!(
            !redirected2.has_valid_bound_signature(),
            "rewriting the payout address must invalidate a bound signature"
        );

        // Stripping the address entirely, and adding one where there was none, both fail too.
        let mut stripped = v2.clone();
        stripped.payout_address = None;
        assert!(!stripped.has_valid_bound_signature(), "stripping must fail");

        let mut addrless = honest.clone();
        addrless.payout_address = None;
        addrless.sign_bound(&id);
        let mut added = addrless.clone();
        added.payout_address = Some("bc1qattacker".to_string());
        assert!(
            !added.has_valid_bound_signature(),
            "adding an address to a proof signed without one must fail"
        );
    }

    /// Mixed-fleet safety: with no payout address the two encodings are byte-identical, so a proof
    /// that predates the field verifies the same either side of the gate.
    #[test]
    fn bound_encoding_matches_v1_when_there_is_no_address() {
        let id = crate::identity::NodeIdentity::generate();
        let mut p = ShareProof {
            round_id: 1,
            miner_id: [1u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: [2u8; 32],
            timestamp: 100,
            received_by: id.node_id(),
            template_id: None,
            payout_address: None,
            header: None,
            signature: None,
        };
        assert_eq!(p.signing_bytes(), p.signing_bytes_bound());
        p.sign(&id);
        assert!(
            p.has_valid_bound_signature(),
            "a v1 signature over an address-less proof must satisfy the v2 check"
        );
    }

    #[test]
    fn test_node_capabilities_shares() {
        let mut caps = NodeCapabilities::new();
        assert_eq!(caps.total_shares(), 0);

        caps.archive_mode = true;
        assert_eq!(caps.total_shares(), 5);

        caps.public_mining = true;
        assert_eq!(caps.total_shares(), 8); // 5 + 3

        caps.reaper = true;
        assert_eq!(caps.total_shares(), 10); // 5 + 3 + 2

        caps.ghost_pay = true;
        caps.elder_status = true;
        assert_eq!(caps.total_shares(), 15); // 5 + 3 + 2 + 4 + 1
    }

    #[test]
    fn test_coordinator_earns_no_shares_but_counts_as_a_capability() {
        // Coordinator is fee-incentivised, not share-bearing — it must add 0 to
        // the 5-4-3-2-1 total even when every share-bearing capability is set.
        let mut caps = NodeCapabilities {
            archive_mode: true,
            ghost_pay: true,
            public_mining: true,
            reaper: true,
            elder_status: true,
            coordinator: true,
        };
        assert_eq!(
            caps.total_shares(),
            15,
            "coordinator must not change the share total"
        );

        // But a coordinator-only node still "has a capability".
        caps = NodeCapabilities::new();
        caps.coordinator = true;
        assert_eq!(caps.total_shares(), 0);
        assert!(caps.has_any());
    }

    #[test]
    fn test_node_capabilities_coordinator_serde_default() {
        // A health ping from a pre-coordinator build omits the field entirely;
        // it must still deserialize (as coordinator = false), not error.
        let legacy = r#"{"archive_mode":true,"ghost_pay":false,"public_mining":true,"reaper":false,"elder_status":false}"#;
        let caps: NodeCapabilities =
            serde_json::from_str(legacy).expect("legacy caps must deserialize");
        assert!(!caps.coordinator);
        assert!(caps.archive_mode && caps.public_mining);

        // Round-trips with the field present.
        let mut on = caps;
        on.coordinator = true;
        let json = serde_json::to_string(&on).expect("serialize");
        let back: NodeCapabilities = serde_json::from_str(&json).expect("deserialize");
        assert!(back.coordinator);
    }

    #[test]
    fn test_reaper_works_independently() {
        // Reaper works with private mining (no public_mining flag)
        let mut caps = NodeCapabilities::new();
        caps.reaper = true;
        assert_eq!(caps.total_shares(), 2); // Reaper alone counts

        // Also works with public mining
        caps.public_mining = true;
        assert_eq!(caps.total_shares(), 5); // 2 + 3
    }

    #[test]
    fn test_capacity_state() {
        assert_eq!(CapacityState::from_load(10, 100), CapacityState::Healthy);
        assert_eq!(CapacityState::from_load(60, 100), CapacityState::Normal);
        assert_eq!(CapacityState::from_load(80, 100), CapacityState::SoftLimit);
        assert_eq!(CapacityState::from_load(95, 100), CapacityState::HardLimit);
    }

    #[test]
    fn test_treasury_address_single() {
        let addr = TreasuryAddress::single("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(!addr.is_multisig());
        assert_eq!(addr.address(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(addr.validate().is_ok());
    }

    #[test]
    fn test_treasury_address_single_empty() {
        let addr = TreasuryAddress::single("");
        assert!(addr.is_empty());
        assert!(matches!(
            addr.validate(),
            Err(TreasuryAddressError::EmptyAddress)
        ));
    }

    #[test]
    fn test_treasury_address_rejects_p2tr() {
        // P2TR addresses should be rejected for quantum safety

        // Mainnet P2TR
        let p2tr_mainnet = TreasuryAddress::single(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        );
        assert!(matches!(
            p2tr_mainnet.validate(),
            Err(TreasuryAddressError::QuantumUnsafe)
        ));

        // Testnet P2TR
        let p2tr_testnet = TreasuryAddress::single(
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        );
        assert!(matches!(
            p2tr_testnet.validate(),
            Err(TreasuryAddressError::QuantumUnsafe)
        ));

        // Regtest P2TR
        let p2tr_regtest = TreasuryAddress::single(
            "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6",
        );
        assert!(matches!(
            p2tr_regtest.validate(),
            Err(TreasuryAddressError::QuantumUnsafe)
        ));

        // P2WPKH should be accepted (quantum-safe)
        let p2wpkh = TreasuryAddress::single("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(p2wpkh.validate().is_ok());
    }

    #[test]
    fn test_treasury_address_multisig() {
        let addr =
            TreasuryAddress::multisig("bc1qmultisigaddress...", "522102abc...02def...52ae", 2, 3)
                .unwrap();

        assert!(addr.is_multisig());
        assert_eq!(addr.multisig_params(), Some((2, 3)));
        assert_eq!(addr.witness_script(), Some("522102abc...02def...52ae"));
    }

    #[test]
    fn test_treasury_address_multisig_invalid_m_of_n() {
        // M > N
        assert!(TreasuryAddress::multisig("addr", "script", 3, 2).is_err());

        // M = 0
        assert!(TreasuryAddress::multisig("addr", "script", 0, 2).is_err());

        // N = 0
        assert!(TreasuryAddress::multisig("addr", "script", 1, 0).is_err());

        // N > 15
        assert!(TreasuryAddress::multisig("addr", "script", 1, 16).is_err());
    }

    #[test]
    fn test_treasury_address_multisig_with_pubkeys() {
        let pubkeys = vec![
            "02abc...".to_string(),
            "02def...".to_string(),
            "02ghi...".to_string(),
        ];

        let addr = TreasuryAddress::multisig_with_pubkeys(
            "bc1qmultisigaddress...",
            "522102abc...52ae",
            2,
            3,
            pubkeys,
        )
        .unwrap();

        assert!(addr.is_multisig());
    }

    #[test]
    fn test_treasury_address_multisig_pubkey_mismatch() {
        let pubkeys = vec!["02abc...".to_string(), "02def...".to_string()];

        // 2 pubkeys but total is 3
        let result = TreasuryAddress::multisig_with_pubkeys(
            "bc1qmultisigaddress...",
            "522102abc...52ae",
            2,
            3,
            pubkeys,
        );

        assert!(matches!(
            result,
            Err(TreasuryAddressError::PubkeyCountMismatch { .. })
        ));
    }

    #[test]
    fn test_treasury_address_from_string() {
        let addr: TreasuryAddress = "bc1qtest...".into();
        assert!(!addr.is_multisig());
        assert_eq!(addr.address(), "bc1qtest...");
    }

    #[test]
    fn test_treasury_address_serde_single() {
        let addr = TreasuryAddress::single("bc1qtest...");
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, "\"bc1qtest...\"");

        let parsed: TreasuryAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_treasury_address_serde_multisig() {
        let addr = TreasuryAddress::multisig("bc1qmultisig", "abcd1234", 2, 3).unwrap();

        let json = serde_json::to_string(&addr).unwrap();
        let parsed: TreasuryAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, parsed);
    }

    fn sample_health_ping() -> HealthPing {
        HealthPing {
            node_id: [7u8; 32],
            public_address: String::new(),
            block_height: 0,
            round_id: 0,
            capabilities: NodeCapabilities::new(),
            miner_count: 2,
            timestamp: 1,
            pow_proof: None,
            active_miner_id_hashes: vec![[1u8; 16], [2u8; 16]],
            local_hashrate_th: 4.0,
            max_capacity: 0,
            hobby_port: None,
            farm_port: None,
            best_records: vec![WindowBestRecord {
                window: "day".to_string(),
                share_hash: "0".repeat(8) + &"f".repeat(56),
                difficulty: 4096.0,
                timestamp: 1,
                miner_id_redacted: "bc1q7z…y492.avalon1".to_string(),
            }],
            coordinator_endpoint: None,
            coordinator_sessions: 0,
            uptime_percent: Some(99.5),
            peer_count: Some(3),
            l2_height: Some(12_345),
            payout_address: Some("bc1qexamplepayoutaddr".to_string()),
        }
    }

    #[test]
    fn health_ping_telemetry_roundtrip() {
        // The new Swarm telemetry fields survive a round-trip.
        let ping = sample_health_ping();
        let back: HealthPing =
            serde_json::from_str(&serde_json::to_string(&ping).unwrap()).unwrap();
        assert_eq!(back.uptime_percent, Some(99.5));
        assert_eq!(back.peer_count, Some(3));
        assert_eq!(back.l2_height, Some(12_345));
    }

    #[test]
    fn health_ping_deserializes_without_telemetry_fields() {
        // Emulate an OLDER node's ping that predates the Swarm telemetry fields:
        // serialize, strip each new field, and confirm every one defaults to
        // `None` (rendered as "—", never a fabricated 0). Proves the wire change
        // is additive so a mixed-version rolling deploy stays compatible.
        let ping = sample_health_ping();
        let mut v = serde_json::to_value(&ping).unwrap();
        let obj = v.as_object_mut().unwrap();
        assert!(obj.remove("uptime_percent").is_some());
        assert!(obj.remove("peer_count").is_some());
        assert!(obj.remove("l2_height").is_some());
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert_eq!(back.uptime_percent, None);
        assert_eq!(back.peer_count, None);
        assert_eq!(back.l2_height, None);
        // Unrelated fields are unaffected.
        assert_eq!(back.miner_count, 2);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
    }

    #[test]
    fn health_ping_payout_address_roundtrips_and_defaults_none() {
        // The payout address drives the qualified-node candidate set, so its wire
        // behaviour is consensus-relevant: it must roundtrip, and an older peer that
        // omits it must default to None (not qualify, rather than qualify with junk).
        let ping = sample_health_ping();
        let back: HealthPing = serde_json::from_slice(&serde_json::to_vec(&ping).unwrap()).unwrap();
        assert_eq!(back.payout_address, ping.payout_address);

        let mut v = serde_json::to_value(&ping).unwrap();
        assert!(v
            .as_object_mut()
            .unwrap()
            .remove("payout_address")
            .is_some());
        let old: HealthPing = serde_json::from_value(v).unwrap();
        assert_eq!(old.payout_address, None);
    }

    #[test]
    fn health_ping_hashrate_roundtrip() {
        let ping = sample_health_ping();
        let json = serde_json::to_string(&ping).unwrap();
        let back: HealthPing = serde_json::from_str(&json).unwrap();
        assert_eq!(back.local_hashrate_th, 4.0);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
    }

    #[test]
    fn health_ping_coordinator_endpoint_roundtrip_and_back_compat() {
        // Present-and-set survives a round-trip.
        let mut ping = sample_health_ping();
        ping.coordinator_endpoint = Some("abc123def456.onion:9100".to_string());
        let back: HealthPing =
            serde_json::from_str(&serde_json::to_string(&ping).unwrap()).unwrap();
        assert_eq!(
            back.coordinator_endpoint.as_deref(),
            Some("abc123def456.onion:9100")
        );

        // An older node's ping omits the field entirely → defaults to None,
        // proving the wire change is additive.
        let mut v = serde_json::to_value(sample_health_ping()).unwrap();
        v.as_object_mut().unwrap().remove("coordinator_endpoint");
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert_eq!(back.coordinator_endpoint, None);
    }

    #[test]
    fn health_ping_deserializes_without_hashrate_field() {
        // Emulate an OLDER node's ping that predates `local_hashrate_th`:
        // serialize, strip the field, and confirm it defaults to 0.0 (and the
        // rest of the ping is unaffected). Proves the wire change is additive.
        let ping = sample_health_ping();
        let mut v = serde_json::to_value(&ping).unwrap();
        assert!(v
            .as_object_mut()
            .unwrap()
            .remove("local_hashrate_th")
            .is_some());
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert_eq!(back.local_hashrate_th, 0.0);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
        assert_eq!(back.miner_count, 2);
    }

    #[test]
    fn health_ping_best_records_roundtrip() {
        let ping = sample_health_ping();
        let json = serde_json::to_string(&ping).unwrap();
        let back: HealthPing = serde_json::from_str(&json).unwrap();
        assert_eq!(back.best_records, ping.best_records);
    }

    #[test]
    fn health_ping_deserializes_without_best_records_field() {
        // Emulate an OLDER node's ping that predates `best_records`: serialize,
        // strip the field, and confirm it defaults to an empty Vec (and the
        // rest of the ping is unaffected). Proves the wire change is additive
        // so a mixed-version rolling deploy stays compatible.
        let ping = sample_health_ping();
        let mut v = serde_json::to_value(&ping).unwrap();
        assert!(v.as_object_mut().unwrap().remove("best_records").is_some());
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert!(back.best_records.is_empty());
        assert_eq!(back.miner_count, 2);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
    }

    // ---- GHOST-09: ShareProof received_by authentication ----

    fn ghost09_base_proof(received_by: NodeId) -> ShareProof {
        ShareProof {
            round_id: 7,
            miner_id: [9u8; 32],
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: [3u8; 32],
            timestamp: 1_700_000_000,
            received_by,
            template_id: Some([4u8; 32]),
            payout_address: None,
            header: None,
            signature: None,
        }
    }

    #[test]
    fn ghost09_honest_signed_proof_verifies() {
        let node = crate::identity::NodeIdentity::generate();
        let proof = ghost09_base_proof(node.node_id()).signed(&node);
        assert!(proof.has_valid_received_by_signature());
    }

    #[test]
    fn ghost09_unsigned_proof_rejected() {
        let node = crate::identity::NodeIdentity::generate();
        let proof = ghost09_base_proof(node.node_id()); // signature: None
        assert!(
            !proof.has_valid_received_by_signature(),
            "an unsigned proof must not authenticate (secure by default)"
        );
    }

    #[test]
    fn ghost09_forged_received_by_rejected() {
        // Attacker signs with their OWN key but claims received_by = victim to
        // steal the victim's node-reward credit.
        let attacker = crate::identity::NodeIdentity::generate();
        let victim = crate::identity::NodeIdentity::generate();
        let mut proof = ghost09_base_proof(victim.node_id());
        proof.sign(&attacker);
        assert!(
            !proof.has_valid_received_by_signature(),
            "an attacker cannot sign as the victim received_by"
        );
    }

    #[test]
    fn ghost09_relay_mutating_received_by_invalidates_signature() {
        // A relay re-credits a valid proof to itself in flight.
        let origin = crate::identity::NodeIdentity::generate();
        let relay = crate::identity::NodeIdentity::generate();
        let mut proof = ghost09_base_proof(origin.node_id()).signed(&origin);
        assert!(proof.has_valid_received_by_signature());
        proof.received_by = relay.node_id();
        assert!(
            !proof.has_valid_received_by_signature(),
            "mutating received_by must break the origin's signature"
        );
    }
}
