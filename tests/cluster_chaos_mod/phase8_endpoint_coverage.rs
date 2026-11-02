//! Phase 8: Endpoint Coverage
//!
//! Probes ~50 untested endpoints using `get_with_retry()` or `probe_endpoint()`.
//! Asserts not-404 (route is mounted). Does not assert specific response shapes.

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

/// Helper: probe a list of endpoints on one node and assert none return 404.
async fn assert_endpoints_mounted(client: &ClusterClient, ip: &str, endpoints: &[&str]) {
    for endpoint in endpoints {
        let (status, _) = client.probe_endpoint(ip, endpoint).await;
        assert_ne!(
            status, 404,
            "Endpoint {} returned 404 on {} — route not mounted",
            endpoint, ip
        );
        println!("  {} → {} on {}", endpoint, status, ip);
        // Small delay to avoid rate limiting
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
#[ignore]
async fn endpoints_01_consensus_and_mesh() {
    let client = setup();
    let ip = client.config.nodes[0].ip;

    println!("\n=== Endpoint Coverage: Consensus & Mesh ===");
    let endpoints = [
        "/consensus-state",
        "/api/v1/mesh/status",
        "/node-info",
        "/api/v1/node/info",
    ];
    assert_endpoints_mounted(&client, ip, &endpoints).await;
}

#[tokio::test]
#[ignore]
async fn endpoints_02_swarm_and_network() {
    let client = setup();
    let ip = client.config.nodes[0].ip;

    println!("\n=== Endpoint Coverage: Swarm & Network ===");
    let endpoints = [
        "/api/v1/swarm/status",
        "/api/v1/swarm/peers",
        "/api/v1/swarm/topology",
        "/api/v1/network/treasury",
        "/api/v1/network/elder",
        "/api/v1/network/pool",
        "/api/v1/network/public-nodes",
        "/api/v1/network/payout-history",
    ];
    assert_endpoints_mounted(&client, ip, &endpoints).await;
}

#[tokio::test]
#[ignore]
async fn endpoints_03_mining_and_rewards() {
    let client = setup();
    let ip = client.config.nodes[0].ip;

    println!("\n=== Endpoint Coverage: Mining & Rewards ===");
    let endpoints = [
        "/api/v1/mining/status",
        "/api/v1/mining/private",
        "/api/v1/mining/public",
        "/api/v1/mining/payout_address",
        "/api/v1/mining/best-hash",
        "/api/v1/mining/miners",
        "/api/v1/rewards/status",
        "/api/v1/rewards/history",
        "/api/v1/rewards/distribution",
    ];
    assert_endpoints_mounted(&client, ip, &endpoints).await;
}

#[tokio::test]
#[ignore]
async fn endpoints_04_config() {
    let client = setup();
    let ip = client.config.nodes[0].ip;

    println!("\n=== Endpoint Coverage: Config ===");
    let endpoints = [
        "/api/v1/config/network",
        "/api/v1/config/mining",
        "/api/v1/config/pool",
        "/api/v1/config/consensus",
        "/api/v1/config/verification",
        "/api/v1/config/payout",
        "/api/v1/config/mesh",
        "/api/v1/config/elder",
        "/api/v1/config/treasury",
        "/api/v1/config/stratum",
        "/api/v1/config/ghostpay",
        "/api/v1/config/watchdog",
        "/api/v1/config/resources",
        "/api/v1/config/all",
    ];
    assert_endpoints_mounted(&client, ip, &endpoints).await;
}

#[tokio::test]
#[ignore]
async fn endpoints_05_system_and_resources() {
    let client = setup();
    let ip = client.config.nodes[0].ip;

    println!("\n=== Endpoint Coverage: System & Resources ===");
    let endpoints = [
        "/api/v1/system/version",
        "/api/v1/resources/status",
        "/api/v1/watchdog/status",
    ];
    assert_endpoints_mounted(&client, ip, &endpoints).await;
}

#[tokio::test]
#[ignore]
async fn endpoints_06_payments_and_ghostpay() {
    let client = setup();
    let ip = client.config.nodes[0].ip;

    println!("\n=== Endpoint Coverage: Payments & GhostPay ===");
    let endpoints = [
        "/api/v1/ghostpay/status",
        "/api/v1/ghostpay/channels",
        "/api/v1/ghostpay/history",
        "/api/v1/settlement/status",
        "/api/v1/payments",
    ];
    assert_endpoints_mounted(&client, ip, &endpoints).await;
}

#[tokio::test]
#[ignore]
async fn endpoints_07_buds_and_misc() {
    let client = setup();
    let ip = client.config.nodes[0].ip;

    println!("\n=== Endpoint Coverage: BUDs & Misc ===");
    let endpoints = [
        "/api/v1/buds/status",
        "/api/v1/buds/supported",
        "/api/v1/buds/active",
        "/peers",
        "/shares",
        "/rounds",
        "/payouts",
    ];
    assert_endpoints_mounted(&client, ip, &endpoints).await;
}

#[tokio::test]
#[ignore]
async fn endpoints_08_degraded_mode() {
    let client = setup();
    let config = &client.config;
    let vm2 = config.node_by_name("VM2").expect("VM2 not found");

    println!("\n=== Endpoint Coverage: Degraded Mode (VM2 down) ===");

    // Kill VM2
    SshController::stop_node(vm2, config.service_name).expect("failed to stop VM2");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Probe key endpoints on surviving nodes
    let key_endpoints = [
        "/health",
        "/api/v1/node/status",
        "/api/v1/network/peers",
        "/api/v1/mining/status",
        "/api/v1/mining/miners",
        "/consensus-state",
        "/api/v1/mesh/status",
        "/verify/stratum",
        "/verify/ghostpay",
        "/metrics",
        "/api/v1/rewards/status",
        "/api/v1/config/all",
        "/api/v1/system/version",
        "/api/v1/watchdog/status",
    ];

    let survivor_ips: Vec<&str> = config
        .all_ips()
        .into_iter()
        .filter(|ip| *ip != vm2.ip)
        .collect();

    for ip in &survivor_ips {
        println!(
            "  Probing {} endpoints on {} (VM2 down)...",
            key_endpoints.len(),
            ip
        );
        for endpoint in &key_endpoints {
            let (status, _) = client.probe_endpoint(ip, endpoint).await;
            assert_ne!(
                status, 404,
                "Endpoint {} returned 404 on {} during degraded mode",
                endpoint, ip
            );
            // Allow 429 and 5xx — we only care that routes are mounted
            println!("    {} → {}", endpoint, status);
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    // Restore VM2
    SshController::start_node(vm2, config.service_name).expect("failed to start VM2");
    assert!(
        client
            .wait_for_node_healthy(vm2.ip, config.recovery_timeout)
            .await,
        "VM2 did not recover after endpoint degraded test"
    );
    println!("  VM2 restored and healthy");
}
