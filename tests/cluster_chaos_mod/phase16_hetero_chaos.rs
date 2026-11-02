//! Phase 16: Heterogeneous Chaos — stress test with mixed configs.
//!
//! Tests that a cluster with diverse configs (archive, pruned, reaper, different policies)
//! survives load, node kills, and network partitions.
//!
//! Depends on Phase 14 having deployed heterogeneous configs:
//! - VM1: archive + reaper strict + bitcoin_pure (genesis)
//! - VM2: pruned + reaper disabled + permissive
//! - VM3: archive + reaper strict + full_open
//! - VM4: non-archive + reaper disabled + bitcoin_pure
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

// --- Test 01: Mixed load across heterogeneous cluster ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_01_mixed_load() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Chaos: Mixed Load (100 concurrent requests) ===");

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
    metrics.print_report("Heterogeneous: 100 Concurrent Requests");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Mixed-config load success rate {:.1}% below 95%",
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

// --- Test 02: Kill pruned node (VM2), verify archive nodes serve ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_02_kill_pruned_node() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Heterogeneous Chaos: Kill Pruned Node (VM2) ===");

    SshController::stop_node(vm2, config.service_name).expect("failed to stop VM2");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // VM1 (archive), VM3 (archive), VM4 (non-archive) should serve traffic
    let survivor_ips: Vec<String> = ["VM1", "VM3", "VM4"]
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
    metrics.print_report("Heterogeneous: 30 Requests Without Pruned Node");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Survivor success rate {:.1}% below 95% after pruned node killed",
        rate * 100.0
    );
    println!("  Cluster serves traffic without pruned node");
}

// --- Test 03: Restore VM2, kill reaper-strict node (VM3) ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_03_restore_vm2_kill_reaper() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    println!("\n=== Heterogeneous Chaos: Restore VM2, Kill Reaper Node (VM3) ===");

    // Restore pruned node
    SshController::start_node(vm2, config.service_name).expect("failed to start VM2");
    assert!(
        client
            .wait_for_node_healthy(vm2.ip, config.recovery_timeout)
            .await,
        "VM2 did not become healthy"
    );
    println!("  VM2 (pruned) restored");

    // Kill reaper-strict + full_open node
    SshController::stop_node(vm3, config.service_name).expect("failed to stop VM3");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // VM1 (reaper strict), VM2 (no reaper), VM4 (no reaper) should serve
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

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Survivor success rate {:.1}% below 95% after reaper node killed",
        rate * 100.0
    );
    println!("  Cluster serves traffic without reaper-strict node (VM3)");

    // Restore VM3
    SshController::start_node(vm3, config.service_name).expect("failed to start VM3");
    assert!(
        client
            .wait_for_node_healthy(vm3.ip, config.recovery_timeout)
            .await,
        "VM3 did not become healthy"
    );
    println!("  VM3 (reaper strict + full_open) restored");
}

// --- Test 04: Partition reaper vs non-reaper nodes ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_04_partition_by_reaper() {
    let client = setup();
    let config = &client.config;

    // Safety cleanup
    SshController::cleanup_all_partitions(config).ok();

    println!("\n=== Heterogeneous Chaos: Partition Reaper vs Non-Reaper ===");
    println!("  Group A (reaper strict): VM1 + VM3");
    println!("  Group B (reaper disabled): VM2 + VM4");

    let group_a = ["VM1", "VM3"];
    let group_b = ["VM2", "VM4"];

    // Set up partition chains
    for node in &config.nodes {
        SshController::setup_partition_chain(node)
            .expect(&format!("failed to setup chain on {}", node.name));
    }

    // Block cross-group traffic
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

    // All nodes should still serve API
    for node in &config.nodes {
        let r = client.get_with_retry(node.ip, "/health").await;
        let status = r.status.unwrap_or(0);
        println!("  {} /health → {}", node.name, status);
        assert_ne!(
            status, 0,
            "{} unreachable during reaper partition",
            node.name
        );
    }
    println!("  Both groups serve API during reaper-based partition");
}

// --- Test 05: Heal partition, verify recovery ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_05_heal_partition() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Chaos: Healing Reaper Partition ===");

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
    println!("  Full mesh restored after reaper-based partition");
}

// --- Test 06: Kill non-archive node (VM4), verify consensus ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_06_kill_nonarchive_node() {
    let client = setup();
    let config = &client.config;
    let vm4 = config.node_by_name("VM4").expect("VM4 not found");

    println!("\n=== Heterogeneous Chaos: Kill Non-Archive Node (VM4) ===");

    SshController::stop_node(vm4, config.service_name).expect("failed to stop VM4");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // VM1 (archive), VM2 (pruned), VM3 (archive) — consensus continues
    let survivor_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm4.ip)
        .collect();

    // Heights should be consistent among survivors
    let mut heights = Vec::new();
    for ip in &survivor_ips {
        if let Ok(h) = client.get_block_height(ip).await {
            heights.push((*ip, h));
            println!("  {} height: {}", ip, h);
        }
    }
    if heights.len() >= 2 {
        let max = heights.iter().map(|(_, h)| *h).max().unwrap();
        let min = heights.iter().map(|(_, h)| *h).min().unwrap();
        assert!(
            max - min <= 1,
            "Survivor heights diverge without non-archive node: {:?}",
            heights
        );
    }
    println!("  Consensus continues without non-archive node");

    // Restore VM4
    SshController::start_node(vm4, config.service_name).expect("failed to start VM4");
    assert!(
        client
            .wait_for_node_healthy(vm4.ip, config.recovery_timeout)
            .await,
        "VM4 did not become healthy"
    );
    println!("  VM4 (non-archive + bitcoin_pure) restored");
}

// --- Test 07: Full recovery verification ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_07_full_recovery() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Chaos: Full Recovery Verification ===");

    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(rejoined, "{} did not regain 3 peers (got {})", ip, peers);
    }

    // All nodes healthy
    for node in &config.nodes {
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Post-chaos: {} not healthy: {:?}",
            node.name,
            r.error
        );
    }
    println!("  All nodes healthy with full mesh");
}

// --- Test 08: Post-chaos consistency ---

#[tokio::test]
#[ignore]
async fn hetero_chaos_08_post_chaos_consistency() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Heterogeneous Chaos: Post-Chaos Consistency ===");

    // Heights ±1
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
        "Post-chaos heights diverge with heterogeneous configs: {:?}",
        heights
    );

    // Zero panics
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "20 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post-chaos: {} had {} panics with heterogeneous config",
            node.name, panics
        );
        println!("  {} — zero panics", node.name);
    }
    println!("  Full consistency verified with heterogeneous configs");
}
