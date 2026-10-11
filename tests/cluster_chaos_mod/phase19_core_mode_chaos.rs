//! Phase 19: Ghost Core Mode Chaos — stress test with Tor/clearnet mix.
//!
//! Tests that a cluster with mixed Ghost Core modes (Tor vs clearnet,
//! different ghostreaper levels) survives load, ghost-core kills,
//! and network partitions.
//!
//! Depends on Phase 18 having enabled tormode on VM3:
//! - VM1: clearnet + ghostreaper=strict
//! - VM2: clearnet + ghostreaper=strict
//! - VM3: tormode + (launcher defaults)
//! - VM4: tormode + ghostreaper=moderate
#![allow(clippy::expect_fun_call)]

use std::sync::Arc;
use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> Arc<ClusterClient> {
    Arc::new(ClusterClient::new(ClusterConfig::signet()))
}

/// Wait for a node to reach a target peer count within a timeout.
async fn wait_for_peers(
    client: &ClusterClient,
    ip: &str,
    min_peers: usize,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if let Ok(peers) = client.get_peer_count(ip).await {
            if peers >= min_peers {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    false
}

// --- Test 01: Load test with Tor + clearnet mix ---

#[tokio::test]
#[ignore]
async fn core_chaos_01_mixed_load() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Chaos: Mixed Load (100 concurrent requests) ===");
    println!("  VM1+VM2: clearnet, VM3+VM4: tormode");

    let all_ips: Vec<String> = config.all_ips().into_iter().map(String::from).collect();

    let mut handles = Vec::new();
    for i in 0..100 {
        let c = client.clone();
        let ip = all_ips[i % all_ips.len()].clone();
        handles.push(tokio::spawn(async move { c.get(&ip, "/health").await }));
    }

    let mut metrics = TestMetrics::new();
    for h in handles {
        if let Ok(r) = h.await {
            metrics.record(r);
        }
    }
    metrics.finish();
    metrics.print_report("Ghost Core Chaos: 100 Concurrent (Tor+Clearnet)");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Tor+clearnet load success rate {:.1}% below 95%",
        rate * 100.0
    );

    // Per-node breakdown
    for node in &config.nodes {
        let node_rate = metrics.success_rate_excluding_429_for_node(node.ip);
        println!(
            "  {} success rate (excl 429): {:.1}%",
            node.name,
            node_rate * 100.0
        );
    }
}

// --- Test 02: Kill ghost-core on Tor node (VM3) ---

#[tokio::test]
#[ignore]
async fn core_chaos_02_kill_tor_node_core() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    println!("\n=== Ghost Core Chaos: Kill Ghost-Core on Tor Node (VM3) ===");

    SshController::stop_ghost_core(vm3).expect("failed to stop ghost-core on VM3");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // VM3's ghost-mining should detect the disconnection — /health may degrade
    // VM1, VM2, VM4 should continue serving
    let survivor_ips: Vec<String> = ["VM1", "VM2", "VM4"]
        .iter()
        .map(|name| config.node_by_name(name).unwrap().ip.to_string())
        .collect();

    let mut metrics = TestMetrics::new();
    for i in 0..30 {
        let ip = &survivor_ips[i % survivor_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    metrics.finish();
    metrics.print_report("Ghost Core Chaos: Survivors Without VM3 Ghost-Core");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.90,
        "Survivor success rate {:.1}% below 90% after Tor node ghost-core killed",
        rate * 100.0
    );
    println!("  3 survivors serve traffic while VM3 ghost-core is down");
}

// --- Test 03: Restore ghost-core on VM3 ---

#[tokio::test]
#[ignore]
async fn core_chaos_03_restore_tor_node_core() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    println!("\n=== Ghost Core Chaos: Restore Ghost-Core on VM3 ===");

    SshController::start_ghost_core(vm3).expect("failed to start ghost-core on VM3");

    // Ghost-core with Tor needs extra time to bootstrap
    println!("  Waiting for ghost-core + Tor to initialize...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut active = false;
    while tokio::time::Instant::now() < deadline {
        if SshController::is_ghost_core_active(vm3).unwrap_or(false) {
            active = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    assert!(
        active,
        "VM3 ghost-core not active after restore (90s timeout)"
    );

    // Wait for ghost-mining to become healthy
    let healthy = client
        .wait_for_node_healthy(vm3.ip, Duration::from_secs(120))
        .await;
    assert!(
        healthy,
        "VM3 ghost-mining not healthy after ghost-core restore"
    );
    println!("  VM3 ghost-core restored, ghost-mining reconnected");
}

// --- Test 04: Kill ghost-core on clearnet node (VM2) ---

#[tokio::test]
#[ignore]
async fn core_chaos_04_kill_clearnet_node_core() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Ghost Core Chaos: Kill Ghost-Core on Clearnet Node (VM2) ===");

    // Ensure VM3 ghost-core is up from previous test
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");
    if !SshController::is_ghost_core_active(vm3).unwrap_or(false) {
        SshController::start_ghost_core(vm3).ok();
        tokio::time::sleep(Duration::from_secs(15)).await;
    }

    SshController::stop_ghost_core(vm2).expect("failed to stop ghost-core on VM2");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Tor nodes (VM3, VM4) + clearnet VM1 should serve
    let survivor_ips: Vec<String> = ["VM1", "VM3", "VM4"]
        .iter()
        .map(|name| config.node_by_name(name).unwrap().ip.to_string())
        .collect();

    let mut metrics = TestMetrics::new();
    for i in 0..30 {
        let ip = &survivor_ips[i % survivor_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    metrics.finish();

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.80,
        "Survivor success rate {:.1}% below 80% after clearnet ghost-core killed",
        rate * 100.0
    );
    println!("  Tor nodes + clearnet survivors serve traffic without VM2 ghost-core");

    // Restore VM2
    SshController::start_ghost_core(vm2).expect("failed to start ghost-core on VM2");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        if SshController::is_ghost_core_active(vm2).unwrap_or(false) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let active = SshController::is_ghost_core_active(vm2).unwrap_or(false);
    assert!(active, "VM2 ghost-core not active after restore");
    let healthy = client
        .wait_for_node_healthy(vm2.ip, Duration::from_secs(120))
        .await;
    assert!(
        healthy,
        "VM2 ghost-mining not healthy after ghost-core restore"
    );
    println!("  VM2 ghost-core restored");
}

// --- Test 05: Partition Tor nodes from clearnet nodes ---

#[tokio::test]
#[ignore]
async fn core_chaos_05_partition_tor_vs_clearnet() {
    let client = setup();
    let config = &client.config;

    // Safety cleanup
    SshController::cleanup_all_partitions(config).ok();

    println!("\n=== Ghost Core Chaos: Partition Tor vs Clearnet ===");
    println!("  Group A (clearnet): VM1 + VM2");
    println!("  Group B (tormode):  VM3 + VM4");

    let group_a = ["VM1", "VM2"];
    let group_b = ["VM3", "VM4"];

    // Set up partition chains
    for node in &config.nodes {
        SshController::setup_partition_chain(node)
            .expect(&format!("failed to setup chain on {}", node.name));
    }

    // Block cross-group traffic on mesh ports
    for a_name in &group_a {
        let a_node = config.node_by_name(a_name).unwrap();
        for b_name in &group_b {
            let b_node = config.node_by_name(b_name).unwrap();
            SshController::block_peer(a_node, b_node.ip)
                .expect(&format!("failed to block {} on {}", b_name, a_name));
        }
    }
    for b_name in &group_b {
        let b_node = config.node_by_name(b_name).unwrap();
        for a_name in &group_a {
            let a_node = config.node_by_name(a_name).unwrap();
            SshController::block_peer(b_node, a_node.ip)
                .expect(&format!("failed to block {} on {}", a_name, b_name));
        }
    }

    println!("  Waiting 20s for partition to take effect...");
    tokio::time::sleep(Duration::from_secs(20)).await;

    // All nodes should still serve API (ghost-mining doesn't need mesh for /health)
    for node in &config.nodes {
        let r = client.get_with_retry(node.ip, "/health").await;
        let status = r.status.unwrap_or(0);
        println!("  {} /health → {}", node.name, status);
        assert_ne!(
            status, 0,
            "{} unreachable during Tor/clearnet partition",
            node.name
        );
    }
    println!("  Both Tor and clearnet groups serve API during partition");
}

// --- Test 06: Heal partition ---

#[tokio::test]
#[ignore]
async fn core_chaos_06_heal_partition() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Chaos: Healing Tor/Clearnet Partition ===");

    SshController::cleanup_all_partitions(config).ok();
    println!("  Partition rules removed");

    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not regain 3 peers after partition heal (got {})",
            ip, peers
        );
    }
    println!("  Full mesh restored after Tor/clearnet partition");
}

// --- Test 07: Full recovery verification ---

#[tokio::test]
#[ignore]
async fn core_chaos_07_full_recovery() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Chaos: Full Recovery Verification ===");

    // Ensure all ghost-core daemons are running (start if not)
    for node in &config.nodes {
        if !SshController::is_ghost_core_active(node).unwrap_or(false) {
            println!("  {} ghost-core not running, starting...", node.name);
            SshController::start_ghost_core(node).ok();
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
        let active = SshController::is_ghost_core_active(node).unwrap_or(false);
        assert!(
            active,
            "{} ghost-core not active during recovery check",
            node.name
        );
    }
    println!("  All ghost-core daemons active");

    // All ghost-mining nodes healthy
    for node in &config.nodes {
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Post-chaos: {} not healthy: {:?}",
            node.name,
            r.error
        );
    }
    println!("  All ghost-mining nodes healthy");

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
        "Post-chaos heights diverge with Tor+clearnet: {:?}",
        heights
    );
    println!("  Heights consistent across Tor + clearnet nodes");
}

// --- Test 08: Post-chaos consistency ---

#[tokio::test]
#[ignore]
async fn core_chaos_08_post_chaos_consistency() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Chaos: Post-Chaos Consistency ===");

    // Zero panics in ghost-mining
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "30 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post-chaos: {} had {} ghost-mining panics",
            node.name, panics
        );
        println!("  {} ghost-mining — zero panics", node.name);
    }

    // Zero panics/crashes in ghost-core
    for node in &config.nodes {
        let crashes = SshController::count_log_matches(
            node,
            SshController::GHOST_CORE_SERVICE,
            "Aborted\\|SIGABRT\\|Segmentation fault",
            "30 min ago",
        )
        .unwrap_or(0);
        assert_eq!(
            crashes, 0,
            "Post-chaos: {} had {} ghost-core crashes",
            node.name, crashes
        );
        println!("  {} ghost-core — zero crashes", node.name);
    }

    // MPC consistent
    let mut mpc_counts = Vec::new();
    for ip in config.all_ips() {
        if let Ok(c) = client.get_mpc_contribution_count(ip).await {
            mpc_counts.push(c);
        }
    }
    if mpc_counts.len() == config.nodes.len() {
        let first = mpc_counts[0];
        for c in &mpc_counts {
            assert_eq!(
                *c, first,
                "Post-chaos MPC mismatch with Tor+clearnet: {:?}",
                mpc_counts
            );
        }
        println!("  MPC contributions consistent: {}", first);
    }

    println!("  Full consistency verified with Tor + clearnet Ghost Core modes");
}
