//! Multi-Node Consensus Integration Tests
//!
//! Tests BFT consensus across multiple nodes:
//! 1. Proposal creation
//! 2. Vote propagation
//! 3. 67% threshold verification (using BFT_THRESHOLD_PERCENT from ghost_common)
//! 4. Consensus achievement
//! 5. Timeout handling

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use ghost_common::constants::BFT_THRESHOLD_PERCENT;

use super::helpers::*;

/// Simulated consensus session using real BFT threshold
#[allow(dead_code)]
struct ConsensusSession {
    proposal_hash: [u8; 32],
    votes: HashMap<[u8; 32], bool>, // node_id -> approve
    total_nodes: usize,
}

impl ConsensusSession {
    fn new(proposal_hash: [u8; 32], total_nodes: usize) -> Self {
        Self {
            proposal_hash,
            votes: HashMap::new(),
            total_nodes,
        }
    }

    fn add_vote(&mut self, node_id: [u8; 32], approve: bool) {
        self.votes.insert(node_id, approve);
    }

    fn approval_count(&self) -> usize {
        self.votes.values().filter(|&&v| v).count()
    }

    fn rejection_count(&self) -> usize {
        self.votes.values().filter(|&&v| !v).count()
    }

    /// Calculate required threshold using real BFT_THRESHOLD_PERCENT constant
    /// Uses ceiling division: (total * 67 + 99) / 100
    fn threshold(&self) -> usize {
        (self.total_nodes as u64 * BFT_THRESHOLD_PERCENT).div_ceil(100) as usize
    }

    fn is_approved(&self) -> bool {
        self.approval_count() >= self.threshold()
    }

    fn is_rejected(&self) -> bool {
        let rejections = self.rejection_count();
        // If rejections >= (total - threshold + 1), approval is impossible
        let can_block = self.total_nodes.saturating_sub(self.threshold()) + 1;
        rejections >= can_block
    }

    fn is_complete(&self) -> bool {
        self.votes.len() == self.total_nodes || self.is_approved() || self.is_rejected()
    }
}

/// Test basic 67% BFT threshold
#[test]
fn test_bft_threshold() {
    let proposal = random_id();
    let node_ids = sequential_node_ids(10);

    let mut session = ConsensusSession::new(proposal, 10);

    // 6 approvals should not be enough (need 67% = 7)
    for node_id in node_ids.iter().take(6) {
        session.add_vote(*node_id, true);
    }
    assert!(
        !session.is_approved(),
        "6/10 should not reach 67% threshold"
    );
    assert_eq!(session.approval_count(), 6);

    // 7th approval reaches threshold
    session.add_vote(node_ids[6], true);
    assert!(session.is_approved(), "7/10 should reach 67% threshold");
}

/// Test rejection threshold
#[test]
fn test_rejection_threshold() {
    let proposal = random_id();
    let node_ids = sequential_node_ids(10);

    let mut session = ConsensusSession::new(proposal, 10);

    // Need 67% (7) to approve, so 4 rejections can block
    for node_id in node_ids.iter().take(3) {
        session.add_vote(*node_id, false);
    }
    assert!(!session.is_rejected(), "3/10 rejections should not block");

    // 4th rejection blocks
    session.add_vote(node_ids[3], false);
    assert!(
        session.is_rejected(),
        "4/10 rejections should block (can't reach 67%)"
    );
}

/// Test vote propagation across nodes
#[test]
fn test_vote_propagation() {
    let node_ids = sequential_node_ids(5);
    let nodes: Vec<TestNode> = node_ids
        .iter()
        .enumerate()
        .map(|(i, &id)| TestNode::new(id, 8080 + i as u16))
        .collect();

    // Setup peer connections (full mesh)
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i != j {
                nodes[i].add_peer(nodes[j].id);
            }
        }
    }

    // Verify peer counts
    for node in &nodes {
        assert_eq!(node.peer_count(), 4, "Each node should have 4 peers");
    }

    // Simulate vote broadcast from node 0
    let proposal = random_id();
    let vote = TestVote::approve(proposal, nodes[0].id);

    // Node 0 sends vote to all peers
    nodes[0].send_vote(vote.clone());

    // Simulate reception at other nodes
    for node in nodes.iter().skip(1) {
        node.receive_vote(vote.clone());
    }

    assert_eq!(nodes[0].votes_sent_count(), 1);
    for node in nodes.iter().skip(1) {
        assert_eq!(node.votes_received_count(), 1);
    }
}

/// Test consensus with mixed votes
#[test]
fn test_mixed_votes_consensus() {
    let proposal = random_id();
    let node_ids = sequential_node_ids(15);

    let mut session = ConsensusSession::new(proposal, 15);

    // 15 nodes, need 67% = 10.05 -> 11 approvals
    // 8 approve, 2 reject, 5 pending
    for node_id in node_ids.iter().take(8) {
        session.add_vote(*node_id, true);
    }
    for node_id in &node_ids[8..10] {
        session.add_vote(*node_id, false);
    }

    assert!(!session.is_approved(), "8/15 approvals not enough");
    assert!(
        !session.is_rejected(),
        "2/15 rejections not enough to block"
    );
    assert!(
        !session.is_complete(),
        "Session not complete with 10/15 votes"
    );

    // 3 more approvals
    for node_id in &node_ids[10..13] {
        session.add_vote(*node_id, true);
    }

    assert!(
        session.is_approved(),
        "11/15 approvals should reach threshold"
    );
    assert!(session.is_complete());
}

/// Test consensus manager tracking multiple proposals
#[test]
fn test_multiple_proposals() {
    struct ConsensusManager {
        sessions: HashMap<[u8; 32], ConsensusSession>,
    }

    impl ConsensusManager {
        fn new() -> Self {
            Self {
                sessions: HashMap::new(),
            }
        }

        fn create_session(&mut self, proposal_hash: [u8; 32], total_nodes: usize) {
            self.sessions.insert(
                proposal_hash,
                ConsensusSession::new(proposal_hash, total_nodes),
            );
        }

        fn vote(
            &mut self,
            proposal_hash: &[u8; 32],
            node_id: [u8; 32],
            approve: bool,
        ) -> Option<bool> {
            if let Some(session) = self.sessions.get_mut(proposal_hash) {
                session.add_vote(node_id, approve);
                if session.is_complete() {
                    return Some(session.is_approved());
                }
            }
            None
        }

        fn session_count(&self) -> usize {
            self.sessions.len()
        }
    }

    let mut manager = ConsensusManager::new();
    let node_ids = sequential_node_ids(5);

    // Create 3 proposals
    let proposals = [random_id(), random_id(), random_id()];
    for proposal in &proposals {
        manager.create_session(*proposal, 5);
    }

    assert_eq!(manager.session_count(), 3);

    // Vote on proposal 0 - all approve
    for (i, node_id) in node_ids.iter().enumerate().take(4) {
        let result = manager.vote(&proposals[0], *node_id, true);
        if i < 3 {
            assert!(result.is_none(), "Not enough votes yet");
        } else {
            assert_eq!(result, Some(true), "Should be approved with 4/5");
        }
    }

    // Vote on proposal 1 - rejections
    // With 5 nodes and 67% threshold, need 4 approvals
    // So 2 rejections (5 - 4 + 1 = 2) can block
    for (i, node_id) in node_ids.iter().enumerate().take(3) {
        let result = manager.vote(&proposals[1], *node_id, false);
        if i < 1 {
            assert!(result.is_none(), "1 rejection not enough to block");
        } else {
            // 2+ rejections block the proposal
            assert_eq!(result, Some(false), "Should be rejected with 2+ rejections");
        }
    }
}

/// Test network partition simulation
#[test]
fn test_network_partition() {
    let node_ids = sequential_node_ids(10);
    let proposal = random_id();

    // Simulate partition: nodes 0-4 can communicate, nodes 5-9 can communicate
    // but the two groups can't reach each other

    let mut partition_a = ConsensusSession::new(proposal, 5); // Only sees 5 nodes
    let mut partition_b = ConsensusSession::new(proposal, 5);

    // Partition A: all 5 nodes approve
    for node_id in node_ids.iter().take(5) {
        partition_a.add_vote(*node_id, true);
    }

    // Partition B: all 5 nodes approve
    for node_id in &node_ids[5..10] {
        partition_b.add_vote(*node_id, true);
    }

    // Each partition thinks it has consensus
    assert!(partition_a.is_approved(), "Partition A has 5/5 = 100%");
    assert!(partition_b.is_approved(), "Partition B has 5/5 = 100%");

    // But with full view, we'd need 10 nodes at 67% = 7 approvals
    let mut full_view = ConsensusSession::new(proposal, 10);

    // Only partition A's votes are received before partition heals
    for node_id in node_ids.iter().take(5) {
        full_view.add_vote(*node_id, true);
    }

    assert!(
        !full_view.is_approved(),
        "5/10 is only 50%, not enough for full network"
    );

    // After partition heals, more votes come in
    for node_id in &node_ids[5..7] {
        full_view.add_vote(*node_id, true);
    }

    assert!(full_view.is_approved(), "7/10 = 70% reaches threshold");
}

/// Test vote deduplication
#[test]
fn test_vote_deduplication() {
    let proposal = random_id();
    let node_id = random_id();

    let mut session = ConsensusSession::new(proposal, 5);

    // First vote
    session.add_vote(node_id, true);
    assert_eq!(session.approval_count(), 1);

    // Duplicate vote (same node voting again)
    session.add_vote(node_id, true);
    assert_eq!(
        session.approval_count(),
        1,
        "Duplicate vote should be ignored"
    );

    // Changed vote (node changes mind)
    session.add_vote(node_id, false);
    assert_eq!(session.approval_count(), 0, "Changed vote should update");
    assert_eq!(session.rejection_count(), 1);
}

/// Test consensus timeout handling
#[test]
fn test_consensus_timeout() {
    use std::time::{Duration, Instant};

    struct TimedConsensusSession {
        session: ConsensusSession,
        created_at: Instant,
        timeout: Duration,
    }

    impl TimedConsensusSession {
        fn new(proposal_hash: [u8; 32], total_nodes: usize, timeout: Duration) -> Self {
            Self {
                session: ConsensusSession::new(proposal_hash, total_nodes),
                created_at: Instant::now(),
                timeout,
            }
        }

        fn is_timed_out(&self) -> bool {
            self.created_at.elapsed() >= self.timeout
        }

        fn status(&self) -> ConsensusStatus {
            if self.session.is_approved() {
                ConsensusStatus::Approved
            } else if self.session.is_rejected() {
                ConsensusStatus::Rejected
            } else if self.is_timed_out() {
                ConsensusStatus::TimedOut
            } else {
                ConsensusStatus::Pending
            }
        }
    }

    #[derive(Debug, PartialEq)]
    enum ConsensusStatus {
        Pending,
        Approved,
        Rejected,
        TimedOut,
    }

    // Create session with very short timeout
    let proposal = random_id();
    let timed_session = TimedConsensusSession::new(proposal, 10, Duration::from_millis(1));

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(5));

    assert!(timed_session.is_timed_out());
    assert_eq!(timed_session.status(), ConsensusStatus::TimedOut);
}

/// Test elder node priority in consensus
#[test]
fn test_elder_priority() {
    // In Ghost Pool, elder nodes (top 5 by tenure) have priority
    #[allow(dead_code)]
    struct NodeWithTenure {
        id: [u8; 32],
        tenure_days: u64,
        is_elder: bool,
    }

    let mut nodes: Vec<NodeWithTenure> = (0..10)
        .map(|i| {
            let mut id = [0u8; 32];
            id[0] = i as u8;
            NodeWithTenure {
                id,
                tenure_days: (i as u64 + 1) * 30, // 30, 60, 90, ... days
                is_elder: false,
            }
        })
        .collect();

    // Sort by tenure (descending) and mark top 5 as elders
    nodes.sort_by_key(|n| std::cmp::Reverse(n.tenure_days));
    for node in nodes.iter_mut().take(5) {
        node.is_elder = true;
    }

    let elder_count = nodes.iter().filter(|n| n.is_elder).count();
    assert_eq!(elder_count, 5);

    // Elders should be the ones with highest tenure (270+)
    for node in nodes.iter().take(5) {
        assert!(node.is_elder);
        assert!(node.tenure_days >= 180);
    }
}

#[cfg(test)]
mod async_consensus_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_async_vote_collection() {
        let proposal = random_id();
        let session = Arc::new(RwLock::new(ConsensusSession::new(proposal, 10)));
        let node_ids = sequential_node_ids(10);
        let votes_collected = Arc::new(AtomicUsize::new(0));

        // Spawn tasks to simulate nodes voting
        let mut handles = Vec::new();
        for (i, node_id) in node_ids.iter().enumerate().take(10) {
            let session = Arc::clone(&session);
            let votes_collected = Arc::clone(&votes_collected);
            let node_id = *node_id;

            handles.push(tokio::spawn(async move {
                // Simulate network delay
                tokio::time::sleep(Duration::from_millis((i as u64) * 5)).await;

                let mut session = session.write();
                session.add_vote(node_id, true);
                votes_collected.fetch_add(1, Ordering::SeqCst);
            }));
        }

        // Wait for all votes
        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(votes_collected.load(Ordering::SeqCst), 10);
        assert!(session.read().is_approved());
    }

    #[tokio::test]
    async fn test_concurrent_proposals() {
        let proposals = [random_id(), random_id(), random_id()];
        let results = Arc::new(RwLock::new(Vec::new()));

        // Process proposals concurrently
        let mut handles = Vec::new();
        for (i, proposal) in proposals.iter().enumerate() {
            let proposal = *proposal;
            let results = Arc::clone(&results);

            handles.push(tokio::spawn(async move {
                // Simulate proposal processing
                tokio::time::sleep(Duration::from_millis((i as u64) * 10)).await;

                results.write().push((i, proposal));
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        let final_results = results.read();
        assert_eq!(final_results.len(), 3);
    }
}
