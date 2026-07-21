//! Onboarding fan-out: a JOINING node must become symmetrically visible to an
//! established fleet. ZMQ PUB/SUB is one-directional and only an inbound Noise
//! handshake triggers the callee's reverse-subscribe, so a late joiner can pull
//! the fleet (SUB to their PUBs) but the fleet never learns about the joiner —
//! the documented asymmetry. This drives the REAL [`MeshNetwork`] transport over
//! localhost ZMQ + Noise and asserts that `bootstrap_fanout()` closes it: after
//! the joiner warms a Noise handshake to the established node, the established
//! node reverse-subscribes and registers the joiner.
//!
//! Red against `main` (no `bootstrap_fanout`/`warm_noise_peer` there).
//!
//! Single established node + single joiner: on 127.0.0.1 the nodes cannot share
//! one Noise port, so a K-node fleet each binding the shared port is impossible
//! here; one established node exercises the exact reverse-subscribe path.

use std::sync::Arc;
use std::time::Duration;

use ghost_common::config::P2PPortConfig;
use ghost_common::identity::NodeIdentity;
use ghost_consensus::mesh::{MeshConfig, MeshNetwork};

fn mesh_config(zmq_base: u16, noise_port: u16) -> MeshConfig {
    MeshConfig {
        public_address: "127.0.0.1".to_string(),
        ports: P2PPortConfig {
            share_propagation: zmq_base,
            block_announcement: zmq_base + 1,
            consensus_voting: zmq_base + 2,
            health_monitoring: zmq_base + 3,
            discovery: zmq_base + 4,
            elder_management: zmq_base + 5,
            payout_proposal: zmq_base + 6,
            payout_transaction: zmq_base + 7,
        },
        noise_enabled: true,
        noise_port,
        noise_required: true,
        ..MeshConfig::default()
    }
}

/// Run the REAL mesh Noise listener (`is_mainnet=false` so the loopback
/// reverse-subscribe SSRF guard doesn't skip 127.0.0.1 — that reverse-subscribe
/// is exactly what we assert).
fn spawn_noise_listener(mesh: Arc<MeshNetwork>) {
    let (tx, rx) = tokio::sync::broadcast::channel::<()>(1);
    tokio::spawn(async move {
        let _keep_shutdown_open = tx;
        mesh.run_noise_listener(false, rx).await;
    });
}

#[tokio::test]
async fn onboarding_fanout_makes_joiner_visible_to_established_node() {
    let noise_port = 19399u16;

    // Established node: serves inbound Noise (the prod receive plane) and will
    // reverse-subscribe to any node that dials it.
    let established_id = Arc::new(NodeIdentity::generate());
    let established = Arc::new(
        MeshNetwork::try_new(Arc::clone(&established_id), mesh_config(19300, noise_port))
            .expect("established mesh init"),
    );
    established.start().await.expect("established start");
    spawn_noise_listener(Arc::clone(&established));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Joiner: comes up knowing only the established node's address (seed
    // bootstrap), but the established node has never heard of it.
    let joiner_id = Arc::new(NodeIdentity::generate());
    let joiner = Arc::new(
        MeshNetwork::try_new(Arc::clone(&joiner_id), mesh_config(19310, noise_port))
            .expect("joiner mesh init"),
    );
    joiner.start().await.expect("joiner start");
    joiner.connect_peer("127.0.0.1").await.expect("joiner learns established (seed)");

    // Baseline asymmetry: the joiner knows the established node, but the
    // established node does NOT yet know the joiner (nothing pushed it there).
    assert_eq!(
        established.peers().unique_peer_count(),
        0,
        "established node should not know the joiner before fan-out (asymmetry)"
    );

    // The fix: the joiner proactively warms a Noise handshake to its known peers.
    let warmed = joiner.bootstrap_fanout().await;
    assert!(warmed >= 1, "joiner should warm at least the established peer");

    // The established node reverse-subscribes to the joiner (a spawned task on
    // handshake completion), so it now registers the joiner — symmetric visibility.
    let mut became_symmetric = false;
    for _ in 0..60 {
        if established.peers().unique_peer_count() >= 1 {
            became_symmetric = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        became_symmetric,
        "onboarding fan-out: established node never registered the joiner \
         (reverse-subscribe did not fire — asymmetry unresolved)"
    );
}
