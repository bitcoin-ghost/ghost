//! Phase 1: Baseline — verify the cluster is healthy before any chaos.

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

#[tokio::test]
#[ignore]
async fn baseline_01_all_nodes_healthy() {
    let client = setup();
    let results = client.get_all_nodes("/health").await;

    for r in &results {
        assert!(
            r.error.is_none() && r.status == Some(200),
            "{} /health failed: status={:?} error={:?}",
            r.node_ip,
            r.status,
            r.error
        );
    }
    println!("All {} nodes returned 200 on /health", results.len());
}

#[tokio::test]
#[ignore]
async fn baseline_02_block_height_consistent() {
    let client = setup();
    let mut heights = Vec::new();

    for ip in client.config.all_ips() {
        match client.get_block_height(ip).await {
            Ok(h) => {
                println!("  {} height: {}", ip, h);
                heights.push((ip.to_string(), h));
            }
            Err(e) => panic!("{} failed to get height: {}", ip, e),
        }
    }

    let max = heights.iter().map(|(_, h)| *h).max().unwrap();
    let min = heights.iter().map(|(_, h)| *h).min().unwrap();
    assert!(
        max - min <= 1,
        "Block heights diverge by more than 1: min={} max={} ({:?})",
        min,
        max,
        heights
    );
    println!("Heights consistent: min={} max={} (tolerance ±1)", min, max);
}

#[tokio::test]
#[ignore]
async fn baseline_03_peer_count_consistent() {
    let client = setup();
    let expected_peers = client.config.nodes.len() - 1; // Each node sees N-1 peers

    for ip in client.config.all_ips() {
        match client.get_peer_count(ip).await {
            Ok(count) => {
                println!("  {} peers: {}", ip, count);
                assert!(
                    count >= expected_peers,
                    "{} has {} peers, expected at least {}",
                    ip,
                    count,
                    expected_peers
                );
            }
            Err(e) => panic!("{} failed to get peer count: {}", ip, e),
        }
    }
}

#[tokio::test]
#[ignore]
async fn baseline_05_verification_endpoints() {
    let client = setup();

    // Endpoints that work without query params
    let simple_endpoints = ["/verify/stratum", "/verify/ghostpay"];
    for endpoint in &simple_endpoints {
        let results = client.get_all_nodes(endpoint).await;
        for r in &results {
            assert!(
                r.error.is_none() && r.status == Some(200),
                "{} {} failed: status={:?} error={:?}",
                r.node_ip,
                endpoint,
                r.status,
                r.error
            );
        }
        println!("  {} → 200 on all nodes", endpoint);
    }

    // /verify/archive and /verify/policy require query params.
    // Test that the routes are mounted and responding (not 404/timeout).
    let parameterized = [
        ("/verify/archive?unsigned=true", &[400u16, 500][..]),
        ("/verify/policy?unsigned=true&tx=dead", &[200, 400, 500][..]),
    ];
    for (endpoint, acceptable) in &parameterized {
        let results = client.get_all_nodes(endpoint).await;
        for r in &results {
            let status = r.status.unwrap_or(0);
            assert!(
                r.error.is_none() || acceptable.contains(&status),
                "{} {} unreachable: status={:?} error={:?}",
                r.node_ip,
                endpoint,
                r.status,
                r.error
            );
            // 404 would mean the route doesn't exist — that's a real failure
            assert_ne!(
                r.status,
                Some(404),
                "{} {} returned 404 — route not mounted",
                r.node_ip,
                endpoint
            );
        }
        println!("  {} → route mounted on all nodes", endpoint);
    }
}

#[tokio::test]
#[ignore]
async fn baseline_06_metrics_available() {
    let client = setup();

    for ip in client.config.all_ips() {
        let result = client.get(ip, "/metrics").await;
        assert!(
            result.error.is_none() && result.status == Some(200),
            "{} /metrics failed: {:?}",
            ip,
            result.error
        );
        let body = result.body.unwrap_or_default();
        assert!(
            body.contains("ghost_"),
            "{} /metrics does not contain ghost_ prefixed metrics",
            ip
        );
        println!(
            "  {} /metrics OK ({} bytes, contains ghost_* metrics)",
            ip,
            body.len()
        );
    }
}

#[tokio::test]
#[ignore]
async fn baseline_07_response_time_snapshot() {
    let client = setup();
    let endpoints = ["/health", "/api/v1/node/status", "/api/v1/network/peers"];
    let rounds = 10;
    let ips = client.config.all_ips();

    let mut metrics = TestMetrics::new();

    // Sequential requests with delay to avoid triggering rate limiting.
    // This test measures latency, not throughput.
    for _ in 0..rounds {
        for endpoint in &endpoints {
            for ip in &ips {
                let result = client.get(ip, endpoint).await;
                metrics.record(result);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    metrics.finish();

    metrics.print_report("Baseline Response Times (10 rounds × 3 endpoints × 4 nodes)");

    let rate_limited = metrics.rate_limited_count();
    if rate_limited > 0 {
        println!(
            "  Note: {} requests rate-limited (429) — excluded from success rate",
            rate_limited
        );
    }

    let success_rate = metrics.success_rate_excluding_429();
    assert!(
        success_rate > 0.95,
        "Baseline success rate too low: {:.1}% (excluding 429s)",
        success_rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn baseline_08_services_active() {
    let config = ClusterConfig::signet();

    for node in &config.nodes {
        let active = SshController::is_node_active(node, config.service_name)
            .unwrap_or_else(|e| panic!("SSH check failed for {}: {}", node.name, e));
        assert!(
            active,
            "{} ({}) service {} is not active",
            node.name, node.ip, config.service_name
        );
        println!("  {} {} is active", node.name, config.service_name);
    }
}
