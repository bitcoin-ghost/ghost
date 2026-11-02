//! Phase 13: Genesis Resilience — force-stop the genesis node (VM1).
//!
//! The most critical node has never been tested. Uses `force_stop_node` to bypass
//! the genesis guard. **Runs last — highest risk.**
//!
//! Scenario A (tests 01-05): Single Genesis Kill
//! Scenario B (tests 06-08): Dual Kill (Genesis + Non-Genesis)

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

// ========== Scenario A: Single Genesis Kill ==========

#[tokio::test]
#[ignore]
async fn genesis_01_force_stop_vm1() {
    let client = setup();
    let config = &client.config;
    let vm1 = config.node_by_name("VM1").expect("VM1 not found");

    println!("\n=== Genesis Resilience: Force-Stop VM1 ===");

    // Force-stop bypasses the is_genesis guard
    SshController::force_stop_node(vm1, config.service_name).expect("failed to force-stop VM1");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // VM2+VM3+VM4 should be healthy with ≥2 peers
    let survivors = ["VM2", "VM3", "VM4"];
    for name in &survivors {
        let node = config.node_by_name(name).unwrap();
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Survivor {} not healthy after genesis kill: {:?}",
            name,
            r.error
        );

        let peers = client.get_peer_count(node.ip).await.unwrap_or(0);
        assert!(
            peers >= 2,
            "Survivor {} has {} peers (expected >=2)",
            name,
            peers
        );
        println!("  {} healthy, {} peers", name, peers);
    }
    println!("  VM1 killed — 3 survivors healthy with >=2 peers");
}

#[tokio::test]
#[ignore]
async fn genesis_02_survivors_serve_traffic() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Genesis Resilience: Survivor Traffic (50 requests) ===");

    let survivor_ips: Vec<String> = ["VM2", "VM3", "VM4"]
        .iter()
        .map(|name| config.node_by_name(name).unwrap().ip.to_string())
        .collect();

    let mut metrics = TestMetrics::new();
    for i in 0..50 {
        let ip = &survivor_ips[i % survivor_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    metrics.finish();
    metrics.print_report("Genesis Kill: 50 Requests to Survivors");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Survivor success rate {:.1}% below 95% without genesis",
        rate * 100.0
    );
    println!(
        "  Survivor traffic success rate (excl 429): {:.1}%",
        rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn genesis_03_consensus_without_genesis() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Genesis Resilience: Consensus Without Genesis ===");

    let survivor_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != config.nodes[0].ip)
        .collect();

    // Heights consistent among survivors (±1)
    let mut heights = Vec::new();
    for ip in &survivor_ips {
        let mut h = Err("not attempted".to_string());
        for _ in 0..5 {
            h = client.get_block_height(ip).await;
            if h.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let height = h.unwrap_or(0);
        heights.push((*ip, height));
        println!("  {} height: {}", ip, height);
    }

    if heights.len() >= 2 {
        let max = heights.iter().map(|(_, h)| *h).max().unwrap();
        let min = heights.iter().map(|(_, h)| *h).min().unwrap();
        assert!(
            max - min <= 1,
            "Survivor heights diverge without genesis: {:?}",
            heights
        );
    }

    // /consensus-state responds
    for ip in &survivor_ips {
        let (status, _) = client.probe_endpoint(ip, "/consensus-state").await;
        assert_ne!(
            status, 404,
            "/consensus-state returned 404 on {} without genesis",
            ip
        );
        println!("  {} /consensus-state → {}", ip, status);
    }
    println!("  Consensus consistent among survivors without genesis");
}

#[tokio::test]
#[ignore]
async fn genesis_04_verification_without_genesis() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Genesis Resilience: Verification Without Genesis ===");

    let survivor_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != config.nodes[0].ip)
        .collect();

    let endpoints = ["/verify/stratum", "/verify/ghostpay"];

    for endpoint in &endpoints {
        for ip in &survivor_ips {
            let r = client.get_with_retry(ip, endpoint).await;
            assert!(
                r.error.is_none() && r.status == Some(200),
                "{} {} failed without genesis: status={:?} error={:?}",
                ip,
                endpoint,
                r.status,
                r.error
            );
        }
        println!("  {} passes on all survivors", endpoint);
    }
}

#[tokio::test]
#[ignore]
async fn genesis_05_restore_vm1() {
    let client = setup();
    let config = &client.config;
    let vm1 = config.node_by_name("VM1").expect("VM1 not found");

    println!("\n=== Genesis Resilience: Restoring VM1 ===");

    SshController::start_node(vm1, config.service_name).expect("failed to start VM1");

    assert!(
        client
            .wait_for_node_healthy(vm1.ip, Duration::from_secs(120))
            .await,
        "VM1 did not become healthy after restart"
    );
    println!("  VM1 healthy");

    // Wait for full mesh
    let rejoined = wait_for_peers(&client, vm1.ip, 3, config.recovery_timeout).await;
    let peers = client.get_peer_count(vm1.ip).await.unwrap_or(0);
    assert!(
        rejoined,
        "VM1 did not regain 3 peers after restart (got {})",
        peers
    );
    println!("  VM1 restored: {} peers", peers);

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
            "Heights diverge after VM1 restore: {:?}",
            heights
        );
    }
    println!("  Full mesh restored, heights converged");
}

// ========== Scenario B: Dual Kill (Genesis + Non-Genesis) ==========

#[tokio::test]
#[ignore]
async fn genesis_06_dual_kill_vm1_vm2() {
    let client = setup();
    let config = &client.config;
    let vm1 = config.node_by_name("VM1").expect("VM1 not found");
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Genesis Resilience: Dual Kill VM1 + VM2 (50% failure) ===");

    // Force-stop VM1 (genesis)
    SshController::force_stop_node(vm1, config.service_name).expect("failed to force-stop VM1");

    // Stop VM2 (non-genesis)
    SshController::stop_node(vm2, config.service_name).expect("failed to stop VM2");

    tokio::time::sleep(Duration::from_secs(10)).await;

    // VM3+VM4 survive (50% failure, below BFT threshold)
    for name in ["VM3", "VM4"] {
        let node = config.node_by_name(name).unwrap();
        let r = client.get_with_retry(node.ip, "/health").await;
        let status = r.status.unwrap_or(0);
        println!("  {} /health → {}", name, status);
        assert_ne!(status, 0, "{} unreachable during dual kill", name);
    }
    println!("  VM3+VM4 surviving (VM1+VM2 killed, 50% failure)");
}

#[tokio::test]
#[ignore]
async fn genesis_07_dual_kill_traffic() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Genesis Resilience: Dual Kill Traffic (relaxed threshold) ===");

    let survivor_ips: Vec<String> = ["VM3", "VM4"]
        .iter()
        .map(|name| config.node_by_name(name).unwrap().ip.to_string())
        .collect();

    let mut metrics = TestMetrics::new();
    for i in 0..20 {
        let ip = &survivor_ips[i % survivor_ips.len()];
        let r = client.get(ip, "/health").await;
        metrics.record(r);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    metrics.finish();
    metrics.print_report("Dual Kill: 20 Requests to VM3+VM4");

    // Below BFT (2/4 dead) — survivors correctly rate-limit (HTTP 429).
    // We only require that at least some requests succeed, not a high rate.
    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.10,
        "Survivor success rate {:.1}% below 10% during dual kill (below BFT)",
        rate * 100.0
    );
    println!(
        "  Dual kill traffic success rate (excl 429): {:.1}% (below-BFT: >10%)",
        rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn genesis_08_full_restore_and_consistency() {
    let client = setup();
    let config = &client.config;
    let vm1 = config.node_by_name("VM1").expect("VM1 not found");
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Genesis Resilience: Full Restore + Consistency ===");

    // Start VM1 first (genesis), then VM2
    SshController::start_node(vm1, config.service_name).expect("failed to start VM1");
    assert!(
        client
            .wait_for_node_healthy(vm1.ip, Duration::from_secs(120))
            .await,
        "VM1 did not become healthy after dual-kill restore"
    );
    println!("  VM1 healthy");

    SshController::start_node(vm2, config.service_name).expect("failed to start VM2");
    assert!(
        client
            .wait_for_node_healthy(vm2.ip, config.recovery_timeout)
            .await,
        "VM2 did not become healthy after dual-kill restore"
    );
    println!("  VM2 healthy");

    // Wait for full mesh
    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not regain 3 peers after full restore (got {})",
            ip, peers
        );
    }

    // Heights ±1
    tokio::time::sleep(Duration::from_secs(5)).await;
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
        "Post dual-kill heights diverge: {:?}",
        heights
    );

    // Zero panics
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "25 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Post dual-kill: {} had {} panics",
            node.name, panics
        );
        println!("  {} — zero panics (25 min)", node.name);
    }
    println!("  Full cluster restored and consistent after genesis resilience tests");
}
