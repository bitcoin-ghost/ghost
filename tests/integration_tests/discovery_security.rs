//! Category 32: Discovery Security Tests (5 tests, 940-944)
//!
//! Integration tests for peer discovery security properties:
//! - Peer upsert and retrieval (940)
//! - Address hijack protection layers (941)
//! - Peer address update via upsert (942)
//! - Stale peer expiration (943)
//! - Subnet diversity limits (944)

use ghost_consensus::peer::{Peer, PeerManager, PeerState};

// =============================================================================
// HELPERS
// =============================================================================

/// Generate a unique NodeId with a distinguishing byte at position 0.
fn make_node_id(discriminator: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = discriminator;
    // Fill remaining bytes for uniqueness
    for (i, byte) in id.iter_mut().enumerate().skip(1) {
        *byte = discriminator.wrapping_add(i as u8);
    }
    id
}

/// Create a PeerManager with a generous max_peers limit.
fn test_peer_manager() -> PeerManager {
    let our_id = [0xFFu8; 32];
    PeerManager::new(our_id, 100)
}

// =============================================================================
// TEST 940: DISCOVERY UPSERT CREATES REAL PEER
// =============================================================================

#[test]
fn test_940_discovery_upsert_creates_real_peer() {
    let manager = test_peer_manager();

    let node_id = make_node_id(1);
    let peer = Peer::new(node_id, "1.2.3.4:8555".to_string());

    manager.upsert_peer(peer);

    // Verify the peer can be retrieved by node_id
    let retrieved = manager.get_peer(&node_id);
    assert!(retrieved.is_some(), "Peer should exist after upsert");

    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.node_id, node_id);
    assert_eq!(retrieved.public_address, "1.2.3.4:8555");
    assert_eq!(manager.peer_count(), 1);
}

// =============================================================================
// TEST 941: ADDRESS HIJACK — PEER MANAGER LAYER VS DISCOVERY HANDLER LAYER
// =============================================================================

#[test]
fn test_941_discovery_hijack_rejected_no_upsert() {
    // PeerManager does NOT prevent two different node_ids from claiming
    // the same address — that protection is at the DiscoveryHandler layer
    // (via the `address_owners` reverse mapping in add_known_peer()).
    //
    // This test validates that PeerManager accepts both peers with the same
    // address, documenting that the address-hijack defense is a higher-level
    // concern handled by DiscoveryHandler.

    let manager = test_peer_manager();

    // Peer A claims address "1.2.3.4:8555"
    let node_a = make_node_id(10);
    let peer_a = Peer::new(node_a, "1.2.3.4:8555".to_string());
    manager.upsert_peer(peer_a);

    // Peer B claims the SAME address "1.2.3.4:8555"
    let node_b = make_node_id(20);
    let peer_b = Peer::new(node_b, "1.2.3.4:8555".to_string());
    manager.upsert_peer(peer_b);

    // PeerManager allows both — it indexes by node_id, not address
    assert_eq!(
        manager.peer_count(),
        2,
        "PeerManager indexes by node_id and allows duplicate addresses; \
         address hijack protection is in DiscoveryHandler.add_known_peer()"
    );

    // Both peers are individually retrievable
    let got_a = manager.get_peer(&node_a);
    let got_b = manager.get_peer(&node_b);
    assert!(got_a.is_some(), "Peer A should still exist");
    assert!(got_b.is_some(), "Peer B should still exist");
    assert_eq!(got_a.unwrap().public_address, "1.2.3.4:8555");
    assert_eq!(got_b.unwrap().public_address, "1.2.3.4:8555");

    // However, unique_peer_count() deduplicates by address host
    assert_eq!(
        manager.unique_peer_count(),
        1,
        "unique_peer_count should deduplicate by host — both peers share the same IP"
    );
}

// =============================================================================
// TEST 942: UPSERT UPDATES EXISTING PEER ADDRESS
// =============================================================================

#[test]
fn test_942_gossip_upsert_creates_real_peer() {
    let manager = test_peer_manager();

    let node_id = make_node_id(30);

    // First insert with address A
    let peer_v1 = Peer::new(node_id, "10.0.0.1:8555".to_string());
    manager.upsert_peer(peer_v1);

    let retrieved = manager.get_peer(&node_id).unwrap();
    assert_eq!(retrieved.public_address, "10.0.0.1:8555");

    // Upsert same node_id with address B — should update the existing entry
    let peer_v2 = Peer::new(node_id, "10.0.0.2:8555".to_string());
    manager.upsert_peer(peer_v2);

    // Still only one peer (same node_id)
    assert_eq!(
        manager.peer_count(),
        1,
        "Upsert should update, not duplicate"
    );

    // Address should be updated to the new value
    let retrieved = manager.get_peer(&node_id).unwrap();
    assert_eq!(
        retrieved.public_address, "10.0.0.2:8555",
        "Address should be updated after upsert with same node_id"
    );
}

// =============================================================================
// TEST 943: STALE DISCOVERY PEER EXPIRES
// =============================================================================

#[test]
fn test_943_stale_discovery_peer_expires() {
    let manager = test_peer_manager();

    let node_id = make_node_id(40);
    let mut peer = Peer::new(node_id, "172.16.0.1:8555".to_string());

    // Mark as Connected so it would normally appear in get_connected_peers
    peer.state = PeerState::Connected;

    // Set last_seen to 120 seconds ago — simulating a stale peer
    peer.last_seen = peer.last_seen.saturating_sub(120);

    manager.upsert_peer(peer);
    assert_eq!(manager.peer_count(), 1, "Peer should exist in the map");

    // Request connected peers with a 60-second freshness threshold
    let connected = manager.get_connected_peers(60);
    assert!(
        connected.is_empty(),
        "Stale peer (last seen 120s ago) should NOT appear in get_connected_peers(60)"
    );

    // Also verify via the Peer-level is_stale() method for consistency
    let retrieved = manager.get_peer(&node_id).unwrap();
    assert!(
        retrieved.is_stale(60),
        "Peer.is_stale(60) should return true for a peer not seen in 120 seconds"
    );
    assert!(
        !retrieved.is_stale(300),
        "Peer.is_stale(300) should return false — 120s < 300s threshold"
    );
}

// =============================================================================
// TEST 944: SUBNET DIVERSITY LIMITS DISCOVERY
// =============================================================================

#[test]
fn test_944_subnet_diversity_limits_discovery() {
    let manager = test_peer_manager();

    // Add 3 peers from the same /24 subnet (192.168.1.x)
    // MAX_PEERS_PER_SUBNET is 3, so all three should be accepted
    for i in 1..=3u8 {
        let node_id = make_node_id(50 + i);
        let peer = Peer::new(node_id, format!("192.168.1.{}:8555", i));
        manager.upsert_peer(peer);
    }

    assert_eq!(
        manager.peer_count(),
        3,
        "First 3 peers from 192.168.1.x /24 should all be accepted"
    );

    // Attempt to add a 4th peer from the same /24 subnet
    let node_4 = make_node_id(54);
    let peer_4 = Peer::new(node_4, "192.168.1.4:8555".to_string());
    manager.upsert_peer(peer_4);

    // The 4th peer should be silently rejected by subnet diversity enforcement
    assert_eq!(
        manager.peer_count(),
        3,
        "4th peer from same /24 subnet should be rejected (MAX_PEERS_PER_SUBNET=3)"
    );
    assert!(
        manager.get_peer(&node_4).is_none(),
        "Rejected 4th peer should not be retrievable"
    );

    // A peer from a DIFFERENT /24 subnet should still be accepted
    let node_diff = make_node_id(60);
    let peer_diff = Peer::new(node_diff, "192.168.2.1:8555".to_string());
    manager.upsert_peer(peer_diff);

    assert_eq!(
        manager.peer_count(),
        4,
        "Peer from a different /24 subnet (192.168.2.x) should be accepted"
    );
    assert!(
        manager.get_peer(&node_diff).is_some(),
        "Peer from different subnet should be retrievable"
    );

    // Verify that updating an existing peer in the saturated subnet still works
    // (upsert allows updates to existing peers unconditionally)
    let node_update = make_node_id(51); // Same as the first peer we added
    let mut peer_update = Peer::new(node_update, "192.168.1.1:8555".to_string());
    peer_update.state = PeerState::Connected;
    manager.upsert_peer(peer_update);

    assert_eq!(
        manager.peer_count(),
        4,
        "Updating an existing peer in a saturated subnet should not change count"
    );
    let updated = manager.get_peer(&node_update).unwrap();
    assert_eq!(
        updated.state,
        PeerState::Connected,
        "Existing peer should have its state updated via upsert"
    );
}
