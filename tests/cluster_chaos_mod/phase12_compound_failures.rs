//! Phase 12: Compound Failures — multiple simultaneous failure types.
//!
//! The hardest real-world scenario: partitions + kills happening together.
//!
//! Scenario A (tests 01-03): Split-Brain + Kill
//! Scenario B (tests 04-06): Kill + Partition
//! Scenario C (tests 07-08): Full Chaos Sequence
#![allow(clippy::expect_fun_call)]

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
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

/// Set up a bidirectional split-brain partition: group A cannot talk to group B.
fn setup_split_brain(config: &ClusterConfig, group_a: &[&str], group_b: &[&str]) {
    for node in &config.nodes {
        SshController::setup_partition_chain(node)
            .expect(&format!("failed to setup chain on {}", node.name));
    }

    for a_name in group_a {
        let a_node = config.node_by_name(a_name).unwrap();
        for b_name in group_b {
            let b_node = config.node_by_name(b_name).unwrap();
            SshController::block_peer(a_node, b_node.ip)
                .expect(&format!("failed to block {} on {}", b_name, a_name));
        }
    }
    for b_name in group_b {
        let b_node = config.node_by_name(b_name).unwrap();
        for a_name in group_a {
            let a_node = config.node_by_name(a_name).unwrap();
            SshController::block_peer(b_node, a_node.ip)
                .expect(&format!("failed to block {} on {}", a_name, b_name));
        }
    }
}

// ========== Scenario A: Split-Brain + Kill ==========

#[tokio::test]
#[ignore]
async fn compound_01_split_brain_then_kill() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    // Safety cleanup
    SshController::cleanup_all_partitions(config).ok();

    println!("\n=== Compound: Split-Brain (VM1+VM2 vs VM3+VM4) Then Kill VM3 ===");

    // Step 1: Create split-brain
    setup_split_brain(config, &["VM1", "VM2"], &["VM3", "VM4"]);

    println!("  Waiting 15s for partition to take effect...");
    tokio::time::sleep(Duration::from_secs(15)).await;

    // Step 2: Kill VM3 — now VM4 is alone in group B
    SshController::stop_node(vm3, config.service_name).expect("failed to stop VM3");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // VM1+VM2 should be healthy (they have each other)
    for name in ["VM1", "VM2"] {
        let node = config.node_by_name(name).unwrap();
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Group A {} not healthy: {:?}",
            name,
            r.error
        );
    }
    println!("  Group A (VM1+VM2) healthy");

    // VM4 alone in group B — should still serve API (even if degraded)
    let vm4 = config.node_by_name("VM4").unwrap();
    let r = client.get_with_retry(vm4.ip, "/health").await;
    let status = r.status.unwrap_or(0);
    println!("  VM4 (alone in group B) /health → {}", status);
    assert_ne!(status, 0, "VM4 unreachable during compound failure");
}

#[tokio::test]
#[ignore]
async fn compound_02_split_kill_traffic() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Compound: Traffic During Split-Brain + Kill ===");

    // VM1, VM2, VM4 are alive (VM3 killed)
    let live_ips: Vec<String> = ["VM1", "VM2", "VM4"]
        .iter()
        .map(|name| config.node_by_name(name).unwrap().ip.to_string())
        .collect();

    let mut metrics = TestMetrics::new();
    for i in 0..30 {
        let ip = &live_ips[i % live_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    metrics.finish();
    metrics.print_report("Compound: 30 Requests During Split-Brain + Kill");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.90,
        "Success rate {:.1}% below 90% during compound failure",
        rate * 100.0
    );
    println!("  Traffic success rate (excl 429): {:.1}%", rate * 100.0);
}

#[tokio::test]
#[ignore]
async fn compound_03_heal_split_restore_vm3() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    println!("\n=== Compound: Healing Split-Brain + Restoring VM3 ===");

    // Step 1: Remove partition rules
    SshController::cleanup_all_partitions(config).ok();
    println!("  Partition rules removed");

    // Step 2: Start VM3
    SshController::start_node(vm3, config.service_name).expect("failed to start VM3");

    // Wait for full mesh
    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, Duration::from_secs(120)).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not regain 3 peers after compound heal (got {})",
            ip, peers
        );
    }

    // Heights converge
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut heights = Vec::new();
    for ip in config.all_ips() {
        if let Ok(h) = client.get_block_height(ip).await {
            heights.push((ip, h));
            println!("  {} height: {}", ip, h);
        }
    }
    if heights.len() == config.nodes.len() {
        let max = heights.iter().map(|(_, h)| *h).max().unwrap();
        let min = heights.iter().map(|(_, h)| *h).min().unwrap();
        assert!(
            max - min <= 1,
            "Heights diverge after compound heal: {:?}",
            heights
        );
    }
    println!("  Full mesh restored, heights converged");
}

// ========== Scenario B: Kill + Partition ==========

#[tokio::test]
#[ignore]
async fn compound_04_kill_then_partition() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");
    let vm1 = config.node_by_name("VM1").unwrap();
    let vm4 = config.node_by_name("VM4").unwrap();

    // Safety cleanup
    SshController::cleanup_all_partitions(config).ok();

    println!("\n=== Compound: Kill VM2, Then Partition VM3 from VM1+VM4 ===");

    // Step 1: Kill VM2
    SshController::stop_node(vm2, config.service_name).expect("failed to stop VM2");
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("  VM2 killed");

    // Step 2: Partition VM3 from VM1 and VM4 (bidirectional)
    for node in [vm1, vm3, vm4] {
        SshController::setup_partition_chain(node)
            .expect(&format!("failed to setup chain on {}", node.name));
    }
    SshController::block_peer(vm3, vm1.ip).expect("failed to block VM1 on VM3");
    SshController::block_peer(vm3, vm4.ip).expect("failed to block VM4 on VM3");
    SshController::block_peer(vm1, vm3.ip).expect("failed to block VM3 on VM1");
    SshController::block_peer(vm4, vm3.ip).expect("failed to block VM3 on VM4");

    println!("  Waiting 15s for partition to take effect...");
    tokio::time::sleep(Duration::from_secs(15)).await;

    // Three failure states: VM2 dead, VM3 partitioned, VM1+VM4 surviving together
    for name in ["VM1", "VM4"] {
        let node = config.node_by_name(name).unwrap();
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Survivor {} not healthy: {:?}",
            name,
            r.error
        );
    }
    println!("  VM1+VM4 healthy (VM2 dead, VM3 partitioned)");
}

#[tokio::test]
#[ignore]
async fn compound_05_survivors_serve_under_compound() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Compound: Survivor Traffic (VM1+VM4) ===");

    let survivor_ips: Vec<String> = ["VM1", "VM4"]
        .iter()
        .map(|name| config.node_by_name(name).unwrap().ip.to_string())
        .collect();

    let mut metrics = TestMetrics::new();
    for i in 0..20 {
        let ip = &survivor_ips[i % survivor_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    metrics.finish();
    metrics.print_report("Compound: 20 Requests to VM1+VM4");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.90,
        "Survivor success rate {:.1}% below 90%",
        rate * 100.0
    );
    println!(
        "  Survivor traffic success rate (excl 429): {:.1}%",
        rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn compound_06_progressive_heal() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Compound: Progressive Heal ===");

    // Step 1: Heal partition first → VM1+VM3+VM4 should form 3-node mesh
    SshController::cleanup_all_partitions(config).ok();
    println!("  Partition rules removed");

    // Wait for 3-node mesh
    for name in ["VM1", "VM3", "VM4"] {
        let node = config.node_by_name(name).unwrap();
        let rejoined = wait_for_peers(&client, node.ip, 2, config.recovery_timeout).await;
        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        println!("  {} peers: {} (3-node mesh phase)", name, peers);
        assert!(
            rejoined,
            "{} did not reach 2 peers in 3-node mesh (got {})",
            name, peers
        );
    }

    // Step 2: Restore VM2 → full 4-node mesh
    SshController::start_node(vm2, config.service_name).expect("failed to start VM2");
    assert!(
        client
            .wait_for_node_healthy(vm2.ip, config.recovery_timeout)
            .await,
        "VM2 did not become healthy after restore"
    );

    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {} (full mesh phase)", ip, peers);
        assert!(
            rejoined,
            "{} did not regain 3 peers after full restore (got {})",
            ip, peers
        );
    }

    // Zero panics
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "15 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post compound heal: {} had {} panics",
            node.name, panics
        );
    }
    println!("  Full mesh restored, zero panics");
}

// ========== Scenario C: Full Chaos Sequence ==========

#[tokio::test]
#[ignore]
async fn compound_07_full_chaos_sequence() {
    let client = setup();
    let config = &client.config;
    let vm1 = config.node_by_name("VM1").unwrap();
    let vm2 = config.node_by_name("VM2").unwrap();
    let vm3 = config.node_by_name("VM3").unwrap();
    let vm4 = config.node_by_name("VM4").unwrap();
    let svc = config.service_name;

    // Safety cleanup
    SshController::cleanup_all_partitions(config).ok();

    println!("\n=== Compound: Full Chaos Sequence ===");

    // Step 1: Partition VM4 from VM1
    println!("  [10s] Partitioning VM4 from VM1...");
    SshController::setup_partition_chain(vm4).expect("failed to setup chain on VM4");
    SshController::setup_partition_chain(vm1).expect("failed to setup chain on VM1");
    SshController::block_peer(vm4, vm1.ip).expect("failed to block VM1 on VM4");
    SshController::block_peer(vm1, vm4.ip).expect("failed to block VM4 on VM1");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Step 2: Kill VM3
    println!("  [10s] Killing VM3...");
    SshController::stop_node(vm3, svc).expect("failed to stop VM3");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Step 3: Heal VM4 partition
    println!("  [10s] Healing VM4 partition...");
    SshController::cleanup_all_partitions(config).ok();
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Step 4: Start VM3
    println!("  [10s] Starting VM3...");
    SshController::start_node(vm3, svc).expect("failed to start VM3");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Step 5: Kill VM2
    println!("  [10s] Killing VM2...");
    SshController::stop_node(vm2, svc).expect("failed to stop VM2");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Step 6: Start VM2
    println!("  [10s] Starting VM2...");
    SshController::start_node(vm2, svc).expect("failed to start VM2");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Allow settling time
    println!("  Waiting 60s for full recovery...");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // Verify full recovery
    for ip in config.all_ips() {
        assert!(
            client
                .wait_for_node_healthy(ip, config.recovery_timeout)
                .await,
            "{} not healthy after full chaos sequence",
            ip
        );

        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        assert!(
            peers >= 3,
            "{} has {} peers after chaos sequence (expected >=3)",
            ip,
            peers
        );
        println!("  {} healthy, {} peers", ip, peers);
    }
    println!("  Full recovery after chaos sequence");
}

#[tokio::test]
#[ignore]
async fn compound_08_post_compound_consistency() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Compound: Post-Compound Consistency Check ===");

    // All healthy with 3 peers
    for ip in config.all_ips() {
        let r = client.get_with_retry(ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Post-compound: {} not healthy: {:?}",
            ip,
            r.error
        );
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        assert!(
            peers >= 3,
            "Post-compound: {} has {} peers (expected >=3)",
            ip,
            peers
        );
        println!("  {} healthy, {} peers", ip, peers);
    }

    // Heights ±1
    let mut heights = Vec::new();
    for ip in config.all_ips() {
        let mut h = Err("not attempted".to_string());
        for _ in 0..5 {
            h = client.get_block_height(ip).await;
            if h.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let height = h.unwrap_or(0);
        heights.push((ip, height));
        println!("  {} height: {}", ip, height);
    }
    let max = heights.iter().map(|(_, h)| *h).max().unwrap();
    let min = heights.iter().map(|(_, h)| *h).min().unwrap();
    assert!(
        max - min <= 1,
        "Post-compound heights diverge: {:?}",
        heights
    );

    // Zero panics (25 min window)
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "25 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post-compound: {} had {} panics in last 25 min",
            node.name, panics
        );
        println!("  {} — zero panics (25 min)", node.name);
    }
    println!("  Full consistency verified after compound failures");
}
