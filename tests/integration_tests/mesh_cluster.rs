//! Multi-node in-process consensus harness (payout-integrity cluster validation).
//!
//! Stands up N nodes — each with a REAL [`RoundManager`], [`ShareProofHandler`]
//! and in-memory [`Database`] — and connects them with a deterministic in-memory
//! router that substitutes the ZMQ/Noise transport. This lets the consensus
//! LOGIC be validated in one process, deterministically, with trivial fault
//! injection (forgery, partition) and no socket/timing flakiness:
//!
//! - **GHOST-09 (today):** a forged `received_by` signature is dropped by every
//!   peer before it can be credited; an honest signed share replicates to all.
//! - **GHOST-02/03/11 (as they land):** the same harness extends to payout
//!   proposals, ledger convergence, and ban propagation.
//!
//! The real ZMQ/Noise transport itself is exercised separately by the live
//! 4-VM `tests/cluster_chaos` suite; this harness targets the decision logic.

use std::sync::Arc;

use chrono::Utc;
use ghost_common::identity::NodeIdentity;
use ghost_common::types::{NodeId, ShareProof};
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{
    MessageEnvelope, MessageType, ShareConvergenceResponse, ShareProofMessage,
};
use ghost_pool::convergence::ConvergenceHandler;
use ghost_pool::round::{RoundConfig, RoundManager};
use ghost_pool::share_handler::ShareProofHandler;
use ghost_storage::Database;

/// Shared test template every node accepts (so share-proof validation passes).
const TEST_TEMPLATE_ID: [u8; 32] = [0x7c; 32];

/// A difficulty-1.0 share hash: exactly 32 leading zero bits (`bytes[28..32] = 0`)
/// then a non-zero byte, which `DifficultyCalculator::difficulty_from_hash` maps
/// to `2^(32-32) = 1.0`. The low 8 bytes carry a unique nonce (never examined by
/// the leading-zero count) so each share is distinct and not deduplicated.
fn diff1_share_hash(nonce: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&nonce.to_le_bytes());
    h[27] = 0xFF; // first non-zero byte from the top → 0 leading bits in it
    h
}

/// One in-process node with its real consensus components.
struct ClusterNode {
    identity: Arc<NodeIdentity>,
    node_id: NodeId,
    db: Arc<Database>,
    #[allow(dead_code)] // held so the RoundManager outlives the handler
    round_manager: Arc<RoundManager>,
    share_handler: Arc<ShareProofHandler>,
}

impl ClusterNode {
    fn new() -> Self {
        let identity = Arc::new(NodeIdentity::generate());
        let node_id = identity.node_id();
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let cfg = RoundConfig {
            // Pool difficulty 1.0 makes the diff-1.0 test shares valid PoW.
            share_difficulty: 1.0,
            network_difficulty: 1_000_000.0,
            ..RoundConfig::default()
        };
        let round_manager = Arc::new(RoundManager::new(node_id, cfg));
        round_manager.set_template_id(TEST_TEMPLATE_ID);
        let share_handler = Arc::new(ShareProofHandler::new(
            Arc::clone(&round_manager),
            Arc::clone(&db),
            node_id,
        ));
        Self {
            identity,
            node_id,
            db,
            round_manager,
            share_handler,
        }
    }

    /// True once this node has recorded (credited) a share for `miner_id`.
    fn has_recorded_miner(&self, miner_id: [u8; 32]) -> bool {
        let hex = hex::encode(&miner_id[..8]);
        self.db.get_miner_stats(&hex).ok().flatten().is_some()
    }

    /// True once this node's share LEDGER (the `RoundManager`, the consensus-
    /// relevant state) holds `share_hash` for `round_id`. Set by both gossip and
    /// GHOST-03 convergence backfill.
    fn ledger_has(&self, round_id: u64, share_hash: [u8; 32]) -> bool {
        self.round_manager
            .round_share_hashes(round_id)
            .contains(&share_hash)
    }
}

/// In-process cluster of `n` nodes wired by a deterministic in-memory router.
pub struct TestMeshCluster {
    nodes: Vec<ClusterNode>,
    /// `connected[i][j]` — can node `i` deliver to node `j`. Full mesh by default.
    connected: Vec<Vec<bool>>,
}

impl TestMeshCluster {
    pub fn new(n: usize) -> Self {
        let nodes = (0..n).map(|_| ClusterNode::new()).collect();
        Self {
            nodes,
            connected: vec![vec![true; n]; n],
        }
    }

    #[allow(dead_code)] // part of the harness API for the upcoming GHOST-02/03/11 tests
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Sever the link between `a` and `b` in both directions.
    pub fn partition(&mut self, a: usize, b: usize) {
        self.connected[a][b] = false;
        self.connected[b][a] = false;
    }

    fn base_proof(&self, from: usize, miner_id: [u8; 32], nonce: u64) -> ShareProof {
        ShareProof {
            round_id: 1,
            miner_id,
            difficulty: 1.0,
            work: 1.0,
            share_hash: diff1_share_hash(nonce),
            timestamp: Utc::now().timestamp() as u64,
            received_by: self.nodes[from].node_id,
            template_id: Some(TEST_TEMPLATE_ID),
            payout_address: None,
            signature: None,
        }
    }

    /// Deliver a (possibly forged) proof from `from` to every connected peer's
    /// REAL `ShareProofHandler` — the in-memory analogue of a mesh broadcast.
    async fn deliver(&self, from: usize, proof: ShareProof) {
        let payload = serde_json::to_vec(&ShareProofMessage { proof }).expect("serialize proof");
        let envelope = Arc::new(MessageEnvelope {
            msg_type: MessageType::ShareProof,
            sender: self.nodes[from].node_id,
            timestamp: Utc::now().timestamp() as u64,
            sequence: 1,
            signature: [0u8; 64],
            payload,
            ttl: 3,
        });
        for (j, node) in self.nodes.iter().enumerate() {
            if j == from || !self.connected[from][j] {
                continue;
            }
            // Errors are logged-and-dropped inside the handler; delivery is fire-and-forget.
            let _ = node
                .share_handler
                .handle_message(Arc::clone(&envelope))
                .await;
        }
    }

    /// Honest path: node `from` signs a share as itself and gossips it.
    pub async fn gossip_honest_share(&self, from: usize, miner_id: [u8; 32], nonce: u64) {
        let mut proof = self.base_proof(from, miner_id, nonce);
        proof.sign(self.nodes[from].identity.as_ref());
        self.deliver(from, proof).await;
    }

    /// Attack path: a proof claiming `received_by = node[from]` but signed by a
    /// DIFFERENT key — models credit theft / a relay re-crediting itself.
    /// GHOST-09 requires every honest peer to drop it.
    pub async fn gossip_forged_share(&self, from: usize, miner_id: [u8; 32], nonce: u64) {
        let attacker = NodeIdentity::generate();
        let mut proof = self.base_proof(from, miner_id, nonce);
        proof.sign(&attacker);
        self.deliver(from, proof).await;
    }

    /// Attack path: an entirely unsigned proof. GHOST-09 is secure-by-default, so
    /// every honest peer must drop it.
    pub async fn gossip_unsigned_share(&self, from: usize, miner_id: [u8; 32], nonce: u64) {
        let proof = self.base_proof(from, miner_id, nonce); // signature stays None
        self.deliver(from, proof).await;
    }

    /// Count peers (excluding `origin`) that recorded a share for `miner_id`.
    pub fn peers_with_share(&self, origin: usize, miner_id: [u8; 32]) -> usize {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != origin)
            .filter(|(_, n)| n.has_recorded_miner(miner_id))
            .count()
    }

    fn peer_has_share(&self, peer: usize, miner_id: [u8; 32]) -> bool {
        self.nodes[peer].has_recorded_miner(miner_id)
    }

    /// True if `node`'s share ledger holds `share_hash` for `round_id`.
    fn node_ledger_has(&self, node: usize, round_id: u64, share_hash: [u8; 32]) -> bool {
        self.nodes[node].ledger_has(round_id, share_hash)
    }

    /// GHOST-03: run a convergence exchange — `requester` advertises the shares
    /// it holds for `round_id`, `responder` replies with the signed proofs the
    /// requester is missing, and the requester applies them. Returns the number
    /// of shares backfilled.
    pub fn converge(&self, requester: usize, responder: usize, round_id: u64) -> usize {
        let req = ConvergenceHandler::new(Arc::clone(&self.nodes[requester].round_manager));
        let resp = ConvergenceHandler::new(Arc::clone(&self.nodes[responder].round_manager));
        let request = req.build_request(round_id);
        let response = resp.handle_request(&request);
        req.apply_response(&response)
    }

    /// Feed `node` a single proof as if it arrived in a convergence response
    /// (used to prove forged backfills are rejected). Returns the number applied.
    pub fn apply_backfill(&self, node: usize, proof: ShareProof) -> usize {
        let handler = ConvergenceHandler::new(Arc::clone(&self.nodes[node].round_manager));
        let resp = ShareConvergenceResponse {
            round_id: proof.round_id,
            share_count: 1,
            total_work: proof.work,
            missing_shares: vec![proof],
        };
        handler.apply_response(&resp)
    }
}

// ---------------------------------------------------------------------------
// Validation tests
// ---------------------------------------------------------------------------

/// Sanity: an honest signed share gossiped from one node replicates to every
/// other node in the cluster (the harness's happy path + GHOST-09 accept path).
#[tokio::test]
async fn honest_signed_share_replicates_to_all_peers() {
    let cluster = TestMeshCluster::new(4);
    let miner = [0xA1; 32];
    cluster.gossip_honest_share(0, miner, 1).await;
    assert_eq!(
        cluster.peers_with_share(0, miner),
        3,
        "an honest signed share must replicate to all 3 peers"
    );
}

/// GHOST-09: a forged `received_by` (attacker signs claiming another node's id)
/// is dropped by EVERY peer — credit theft fails cluster-wide, not just locally.
#[tokio::test]
async fn ghost09_forged_share_is_dropped_clusterwide() {
    let cluster = TestMeshCluster::new(4);
    let miner = [0xB2; 32];
    cluster.gossip_forged_share(0, miner, 2).await;
    assert_eq!(
        cluster.peers_with_share(0, miner),
        0,
        "a forged-received_by share must be dropped by every peer (GHOST-09)"
    );
}

/// GHOST-09 secure-by-default: an unsigned share is dropped cluster-wide.
#[tokio::test]
async fn ghost09_unsigned_share_is_dropped_clusterwide() {
    let cluster = TestMeshCluster::new(4);
    let miner = [0xD4; 32];
    cluster.gossip_unsigned_share(0, miner, 4).await;
    assert_eq!(
        cluster.peers_with_share(0, miner),
        0,
        "an unsigned share must be dropped by every peer (GHOST-09 secure-by-default)"
    );
}

/// Fault injection: a partition stops delivery to the severed node only.
#[tokio::test]
async fn partition_blocks_delivery_to_severed_node() {
    let mut cluster = TestMeshCluster::new(4);
    cluster.partition(0, 2);
    let miner = [0xC3; 32];
    cluster.gossip_honest_share(0, miner, 3).await;
    assert_eq!(
        cluster.peers_with_share(0, miner),
        2,
        "the share reaches the 2 connected peers but not the partitioned one"
    );
    assert!(
        !cluster.peer_has_share(2, miner),
        "node 2 is partitioned from node 0 and must not receive the share"
    );
}

/// GHOST-03: a node that missed a gossiped share (partition) reconciles its
/// share ledger with a peer that has it, and backfills the exact signed proof.
#[tokio::test]
async fn ghost03_convergence_backfills_partitioned_node() {
    let mut cluster = TestMeshCluster::new(4);
    cluster.partition(0, 2); // node 2 will miss node 0's broadcast
    let miner = [0xE5; 32];
    let nonce = 5;
    let share_hash = diff1_share_hash(nonce);

    cluster.gossip_honest_share(0, miner, nonce).await;

    // Precondition: a connected peer holds it; the partitioned node does not.
    assert!(
        cluster.node_ledger_has(1, 1, share_hash),
        "connected peer 1 holds the share in its ledger"
    );
    assert!(
        !cluster.node_ledger_has(2, 1, share_hash),
        "partitioned node 2 is missing the share before convergence"
    );

    // GHOST-03: node 2 converges with node 1 → backfills exactly the missing share.
    let applied = cluster.converge(2, 1, 1);
    assert_eq!(
        applied, 1,
        "convergence backfills exactly the one missing share"
    );
    assert!(
        cluster.node_ledger_has(2, 1, share_hash),
        "node 2's ledger contains the share after convergence"
    );
}

/// GHOST-03 safety: convergence cannot smuggle in a forged share. A response
/// carrying a proof whose `received_by` signature is invalid is rejected by
/// `apply_response` (GHOST-09 re-checked on the backfill path), not applied.
#[tokio::test]
async fn ghost03_convergence_rejects_forged_backfill() {
    let cluster = TestMeshCluster::new(2);
    let attacker = NodeIdentity::generate();
    // Proof claims node 0's received_by but is signed by an unrelated key.
    let mut proof = cluster.base_proof(0, [0xF6; 32], 6);
    proof.sign(&attacker);

    let applied = cluster.apply_backfill(1, proof);
    assert_eq!(
        applied, 0,
        "a forged backfilled proof must be rejected by convergence (GHOST-09)"
    );
    assert!(
        !cluster.node_ledger_has(1, 1, diff1_share_hash(6)),
        "the forged share never enters node 1's ledger"
    );
}
