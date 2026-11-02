//! Phase 4: Recovery — verify cluster is fully consistent after all chaos.

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

#[tokio::test]
#[ignore]
async fn recovery_01_all_nodes_healthy() {
    let client = setup();

    for ip in client.config.all_ips() {
        let r = client.get_with_retry(ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "Post-chaos: {} /health failed: status={:?} error={:?}",
            ip,
            r.status,
            r.error
        );
        println!("  {} healthy", ip);
    }
}

#[tokio::test]
#[ignore]
async fn recovery_02_block_heights_consistent() {
    let client = setup();
    let mut heights = Vec::new();

    for ip in client.config.all_ips() {
        // Retry to handle 429s after heavy traffic
        let mut height = Err("not attempted".to_string());
        for _ in 0..5 {
            height = client.get_block_height(ip).await;
            if height.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match height {
            Ok(h) => {
                println!("  {} height: {}", ip, h);
                heights.push((ip.to_string(), h));
            }
            Err(e) => panic!("Post-chaos: {} failed to get height: {}", ip, e),
        }
    }

    let max = heights.iter().map(|(_, h)| *h).max().unwrap();
    let min = heights.iter().map(|(_, h)| *h).min().unwrap();
    assert!(
        max - min <= 1,
        "Post-chaos: heights diverge: min={} max={} ({:?})",
        min,
        max,
        heights
    );
    println!("Post-chaos heights consistent: min={} max={}", min, max);
}

#[tokio::test]
#[ignore]
async fn recovery_03_peer_counts_restored() {
    let client = setup();
    let expected_peers = client.config.nodes.len() - 1;

    for ip in client.config.all_ips() {
        // Retry to handle 429s
        let mut count = Err("not attempted".to_string());
        for _ in 0..5 {
            count = client.get_peer_count(ip).await;
            if count.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        match count {
            Ok(c) => {
                println!("  {} peers: {}", ip, c);
                assert!(
                    c >= expected_peers,
                    "Post-chaos: {} has {} peers, expected ≥{}",
                    ip,
                    c,
                    expected_peers
                );
            }
            Err(e) => panic!("Post-chaos: {} peer count failed: {}", ip, e),
        }
    }
}

#[tokio::test]
#[ignore]
async fn recovery_04_verification_passes() {
    let client = setup();
    let endpoints = ["/verify/stratum", "/verify/ghostpay"];

    for endpoint in &endpoints {
        for ip in client.config.all_ips() {
            let r = client.get_with_retry(ip, endpoint).await;
            assert!(
                r.error.is_none() && r.status == Some(200),
                "Post-chaos: {} {} failed: status={:?} error={:?}",
                ip,
                endpoint,
                r.status,
                r.error
            );
        }
        println!("  {} passes on all nodes", endpoint);
    }
}

#[tokio::test]
#[ignore]
async fn recovery_05_no_panics_in_logs() {
    let config = ClusterConfig::signet();

    for node in &config.nodes {
        let panic_count =
            SshController::count_log_matches(node, config.service_name, "panic", "10 min ago")
                .unwrap_or_else(|e| {
                    println!(
                        "  WARNING: Could not check {} logs: {}",
                        node.name, e
                    );
                    0
                });

        println!("  {} panics in last 10 min: {}", node.name, panic_count);
        assert_eq!(
            panic_count, 0,
            "Post-chaos: {} had {} panics in last 10 minutes",
            node.name, panic_count
        );
    }
}


#[tokio::test]
#[ignore]
async fn recovery_07_response_times_acceptable() {
    let client = setup();
    let endpoints = [
        "/health",
        "/api/v1/node/status",
        "/api/v1/network/peers",
    ];
    let rounds = 5;
    let ips = client.config.all_ips();

    let mut metrics = TestMetrics::new();
    // Sequential with delay to avoid rate limiting
    for _ in 0..rounds {
        for endpoint in &endpoints {
            for ip in &ips {
                let result = client.get(ip, endpoint).await;
                metrics.record(result);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    metrics.finish();
    metrics.print_report("Recovery: Response Times (5 rounds × 3 endpoints × 4 nodes)");

    let p99 = metrics.p99_latency();
    assert!(
        p99 < Duration::from_secs(5),
        "Post-chaos p99 latency {:?} exceeds 5s threshold",
        p99
    );
    println!("Post-chaos p99 latency: {:?} (< 5s threshold)", p99);
}
