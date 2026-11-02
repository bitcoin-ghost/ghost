//! Phase 5: Multi-Kill — kill VM2+VM3 simultaneously (50% < 67% BFT threshold).
//!
//! Restore one at a time and verify progressive recovery.

use std::sync::Arc;
use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> Arc<ClusterClient> {
    Arc::new(ClusterClient::new(ClusterConfig::signet()))
}

// --- Kill both VM2 and VM3 ---

#[tokio::test]
#[ignore]
async fn multi_kill_01_stop_vm2_vm3() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    println!("\n=== Multi-Kill: Stopping VM2 + VM3 ===");

    SshController::stop_node(vm2, config.service_name).expect("failed to stop VM2");
    SshController::stop_node(vm3, config.service_name).expect("failed to stop VM3");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // VM1 and VM4 should still be healthy
    let survivors = ["VM1", "VM4"];
    for name in &survivors {
        let node = config.node_by_name(name).unwrap();
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Survivor {} not healthy after multi-kill: {:?}",
            name,
            r.error
        );

        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        assert!(
            peers >= 1,
            "Survivor {} has {} peers (expected >=1)",
            name,
            peers
        );
        println!("  {} healthy, {} peers", name, peers);
    }
    println!("  VM2 + VM3 killed — VM1 + VM4 surviving with >=1 peer each");
}

#[tokio::test]
#[ignore]
async fn multi_kill_02_survivors_serve_traffic() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").unwrap();
    let vm3 = config.node_by_name("VM3").unwrap();

    let survivor_ips: Vec<String> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip && *ip != vm3.ip)
        .map(String::from)
        .collect();

    println!("\n=== Multi-Kill: Survivor Traffic Test (30 requests) ===");

    let mut metrics = TestMetrics::new();
    for i in 0..30 {
        let ip = &survivor_ips[i % survivor_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    metrics.finish();
    metrics.print_report("Multi-Kill: 30 Requests to Survivors");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Survivor success rate {:.1}% below 95% during multi-kill",
        rate * 100.0
    );

    // Per-node breakdown
    for ip in &survivor_ips {
        let node_rate = metrics.success_rate_excluding_429_for_node(ip);
        println!(
            "  {} success rate (excl 429): {:.1}%",
            ip,
            node_rate * 100.0
        );
    }
}

#[tokio::test]
#[ignore]
async fn multi_kill_03_consensus_state() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").unwrap();
    let vm3 = config.node_by_name("VM3").unwrap();

    println!("\n=== Multi-Kill: Consensus State on Survivors ===");

    let survivor_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip && *ip != vm3.ip)
        .collect();

    for ip in &survivor_ips {
        let (status, _) = client.probe_endpoint(ip, "/consensus-state").await;
        assert_ne!(
            status, 404,
            "/consensus-state returned 404 on {} during multi-kill",
            ip
        );
        println!("  {} /consensus-state → {}", ip, status);
    }
}

#[tokio::test]
#[ignore]
async fn multi_kill_04_verification_works() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").unwrap();
    let vm3 = config.node_by_name("VM3").unwrap();

    println!("\n=== Multi-Kill: Verification Endpoints on Survivors ===");

    let survivor_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip && *ip != vm3.ip)
        .collect();

    let endpoints = ["/verify/stratum", "/verify/ghostpay"];

    for endpoint in &endpoints {
        for ip in &survivor_ips {
            let r = client.get_with_retry(ip, endpoint).await;
            assert!(
                r.error.is_none() && r.status == Some(200),
                "{} {} failed during multi-kill: status={:?} error={:?}",
                ip,
                endpoint,
                r.status,
                r.error
            );
        }
        println!("  {} passes on survivors", endpoint);
    }
}

// --- Restore VM2 first (3/4 = 75% > 67% BFT) ---

#[tokio::test]
#[ignore]
async fn multi_kill_05_restore_vm2() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Multi-Kill: Restoring VM2 (3/4 nodes = 75%) ===");

    SshController::start_node(vm2, config.service_name).expect("failed to start VM2");
    assert!(
        client
            .wait_for_node_healthy(vm2.ip, config.recovery_timeout)
            .await,
        "VM2 did not become healthy within {:?}",
        config.recovery_timeout
    );

    // Wait for peer discovery
    let deadline = tokio::time::Instant::now() + config.recovery_timeout;
    loop {
        if let Ok(peers) = client.get_peer_count(vm2.ip).await {
            if peers >= 2 {
                println!("  VM2 healthy with {} peers (3/4 nodes up)", peers);
                return;
            }
        }
        if tokio::time::Instant::now() > deadline {
            let peers = client.get_peer_count(vm2.ip).await.unwrap_or(0);
            panic!(
                "VM2 has only {} peers after {:?}",
                peers, config.recovery_timeout
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
#[ignore]
async fn multi_kill_06_three_nodes_consistent() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").unwrap();

    println!("\n=== Multi-Kill: 3-Node Height Consistency ===");

    let live_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm3.ip)
        .collect();

    // Retry loop for height consistency
    let mut heights = Vec::new();
    for _ in 0..5 {
        heights.clear();
        for ip in &live_ips {
            if let Ok(h) = client.get_block_height(ip).await {
                heights.push((*ip, h));
            }
        }
        if heights.len() == live_ips.len() {
            let max = heights.iter().map(|(_, h)| *h).max().unwrap();
            let min = heights.iter().map(|(_, h)| *h).min().unwrap();
            if max - min <= 1 {
                for (ip, h) in &heights {
                    println!("  {} height: {}", ip, h);
                }
                println!("  3-node heights consistent (diff <=1)");
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    for (ip, h) in &heights {
        println!("  {} height: {}", ip, h);
    }
    let max = heights.iter().map(|(_, h)| *h).max().unwrap_or(0);
    let min = heights.iter().map(|(_, h)| *h).min().unwrap_or(0);
    assert!(
        max - min <= 1,
        "3-node heights not consistent: {:?}",
        heights
    );
}

// --- Restore VM3 (back to 4/4) ---

#[tokio::test]
#[ignore]
async fn multi_kill_07_restore_vm3() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").expect("VM3 not found");

    println!("\n=== Multi-Kill: Restoring VM3 (4/4 nodes) ===");

    SshController::start_node(vm3, config.service_name).expect("failed to start VM3");
    assert!(
        client
            .wait_for_node_healthy(vm3.ip, config.recovery_timeout)
            .await,
        "VM3 did not become healthy within {:?}",
        config.recovery_timeout
    );

    // Wait for full mesh
    let deadline = tokio::time::Instant::now() + config.recovery_timeout;
    loop {
        if let Ok(peers) = client.get_peer_count(vm3.ip).await {
            if peers >= 3 {
                println!("  VM3 healthy with {} peers (full mesh)", peers);
                return;
            }
        }
        if tokio::time::Instant::now() > deadline {
            let peers = client.get_peer_count(vm3.ip).await.unwrap_or(0);
            panic!(
                "VM3 has only {} peers after {:?}",
                peers, config.recovery_timeout
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
#[ignore]
async fn multi_kill_08_full_cluster_consistent() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Multi-Kill: Full Cluster Consistency Check ===");

    // All nodes healthy
    for ip in config.all_ips() {
        let r = client.get_with_retry(ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Post multi-kill: {} not healthy: {:?}",
            ip,
            r.error
        );
    }
    println!("  All nodes healthy");

    // Heights consistent (retry for 429 recovery)
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
        heights.push((ip, h.unwrap_or(0)));
    }
    let max = heights.iter().map(|(_, h)| *h).max().unwrap();
    let min = heights.iter().map(|(_, h)| *h).min().unwrap();
    for (ip, h) in &heights {
        println!("  {} height: {}", ip, h);
    }
    assert!(
        max - min <= 1,
        "Post multi-kill heights diverge: {:?}",
        heights
    );

    // Zero panics
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "15 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post multi-kill: {} had {} panics",
            node.name, panics
        );
    }
    println!("  Zero panics across all nodes");
}
