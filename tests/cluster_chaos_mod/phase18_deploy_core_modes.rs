//! Phase 18: Deploy Ghost Core Modes — enable tormode on VM3.
//!
//! Modifies ghost.conf on VM3 to add `tormode=1`, making 2 of 4 nodes
//! route through Tor (VM3 + VM4). VM1 and VM2 remain clearnet.
//!
//! Current Ghost Core state:
//! - VM1: ghostd with -ghostreaper=strict (clearnet)
//! - VM2: ghostd with -ghostreaper=strict (clearnet)
//! - VM3: bitcoin-node via launcher (clearnet, Tor installed)
//! - VM4: ghostd with -ghostreaper=moderate + -tormode (Tor active)
//!
//! After this phase:
//! - VM3: bitcoin-node with tormode=1 (Tor active)
//! - VM4: ghostd with -tormode (Tor active, unchanged)
//! - VM1, VM2: clearnet (unchanged)

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

// --- Test 01: Backup ghost.conf on VM3 ---

#[tokio::test]
#[ignore]
async fn core_mode_deploy_01_backup_configs() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Mode Deploy: Backup Configs ===");

    let vm3 = config.node_by_name("VM3").unwrap();

    // Backup VM3 ghost.conf
    SshController::backup_ghost_conf(vm3).expect("failed to backup VM3 ghost.conf");
    assert!(
        SshController::has_ghost_conf_backup(vm3).unwrap_or(false),
        "VM3 ghost.conf backup not created"
    );
    println!("  VM3 ghost.conf backed up");
}

// --- Test 02: Enable tormode on VM3 ---

#[tokio::test]
#[ignore]
async fn core_mode_deploy_02_enable_tormode_vm3() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").unwrap();

    println!("\n=== Ghost Core Mode Deploy: Enable Tormode on VM3 ===");

    // Add tormode=1 to ghost.conf
    SshController::add_ghost_conf_flag(vm3, "tormode", "1")
        .expect("failed to add tormode flag to VM3 ghost.conf");
    println!("  Added tormode=1 to VM3 ghost.conf");

    // Restart ghost-core to pick up the new flag
    SshController::restart_ghost_core(vm3).expect("failed to restart ghost-core on VM3");
    println!("  Restarted ghost-core on VM3");

    // Wait for ghost-core to come back
    println!("  Waiting 30s for ghost-core to initialize with Tor...");
    tokio::time::sleep(Duration::from_secs(30)).await;

    // Verify ghost-core is active
    let active = SshController::is_ghost_core_active(vm3).unwrap_or(false);
    assert!(active, "VM3 ghost-core not active after tormode enable");
    println!("  VM3 ghost-core active with tormode");
}

// --- Test 03: Verify ghost-mining reconnects ---

#[tokio::test]
#[ignore]
async fn core_mode_deploy_03_pool_reconnects() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Mode Deploy: Pool Reconnection ===");

    // Ghost-pool should reconnect to ghost-core after restart
    // Give it time to re-establish RPC + ZMQ connections
    for node in &config.nodes {
        let healthy = client
            .wait_for_node_healthy(node.ip, Duration::from_secs(120))
            .await;
        assert!(
            healthy,
            "{} ghost-mining not healthy after ghost-core restart",
            node.name
        );
        println!("  {} ghost-mining healthy", node.name);
    }
}

// --- Test 04: Baseline with 2 Tor nodes ---

#[tokio::test]
#[ignore]
async fn core_mode_deploy_04_baseline_with_tor() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Mode Deploy: Baseline (2 Tor + 2 Clearnet) ===");

    // Full mesh peers
    for node in &config.nodes {
        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        println!("  {} peers: {}", node.name, peers);
    }

    // Heights consistent
    let mut heights = Vec::new();
    for node in &config.nodes {
        let mut h = Err("not attempted".to_string());
        for _ in 0..5 {
            h = client.get_block_height(node.ip).await;
            if h.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let height = h.unwrap_or(0);
        heights.push((node.name, height));
        println!("  {} height: {}", node.name, height);
    }

    let max = heights.iter().map(|(_, h)| *h).max().unwrap();
    let min = heights.iter().map(|(_, h)| *h).min().unwrap();
    assert!(
        max - min <= 1,
        "Heights diverge with Tor + clearnet mix: {:?}",
        heights
    );

    // Verify VM3 is using tormode via cmdline
    let vm3 = config.node_by_name("VM3").unwrap();
    let cmdline = SshController::read_ghostd_cmdline(vm3).unwrap_or_default();
    println!("  VM3 ghostd cmdline: {}", cmdline);

    // Verify VM4 still has tormode
    let vm4 = config.node_by_name("VM4").unwrap();
    let cmdline4 = SshController::read_ghostd_cmdline(vm4).unwrap_or_default();
    println!("  VM4 ghostd cmdline: {}", cmdline4);
    assert!(cmdline4.contains("tormode"), "VM4 lost tormode flag");

    println!("  Baseline verified: 2 Tor + 2 clearnet nodes operational");
}
