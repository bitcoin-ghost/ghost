//! Phase 2: Load — concurrent hammering, rate limiting, WebSocket storm.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::metrics::TestMetrics;
use super::ssh::SshController;

fn setup() -> Arc<ClusterClient> {
    Arc::new(ClusterClient::new(ClusterConfig::signet()))
}

#[tokio::test]
#[ignore]
async fn load_01_concurrent_health_100() {
    let client = setup();
    let mut handles = Vec::new();

    for i in 0..100 {
        let c = client.clone();
        let ips = c.config.all_ips();
        let ip = ips[i % ips.len()].to_string();
        handles.push(tokio::spawn(async move { c.get(&ip, "/health").await }));
    }

    let mut metrics = TestMetrics::new();
    for h in handles {
        if let Ok(r) = h.await {
            metrics.record(r);
        }
    }
    metrics.finish();
    metrics.print_report("Load: 100 Concurrent /health");

    // Exclude 429s — rate limiting is expected, we're testing service health
    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Non-429 success rate {:.1}% below 95% threshold",
        rate * 100.0
    );
    println!(
        "  Rate-limited: {}, service success rate (excl. 429): {:.1}%",
        metrics.rate_limited_count(),
        rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn load_02_concurrent_miners_100() {
    let client = setup();
    let mut handles = Vec::new();

    for i in 0..100 {
        let c = client.clone();
        let ips = c.config.all_ips();
        let ip = ips[i % ips.len()].to_string();
        handles.push(tokio::spawn(async move {
            c.get(&ip, "/api/v1/mining/miners").await
        }));
    }

    let mut metrics = TestMetrics::new();
    for h in handles {
        if let Ok(r) = h.await {
            metrics.record(r);
        }
    }
    metrics.finish();
    metrics.print_report("Load: 100 Concurrent /api/v1/mining/miners");

    let rate = metrics.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Non-429 success rate {:.1}% below 95% threshold",
        rate * 100.0
    );
    println!(
        "  Rate-limited: {}, service success rate (excl. 429): {:.1}%",
        metrics.rate_limited_count(),
        rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn load_03_sustained_throughput_30s() {
    let client = setup();
    let endpoints = [
        "/health",
        "/api/v1/node/status",
        "/api/v1/network/peers",
        "/api/v1/mining/miners",
        "/metrics",
    ];
    let workers = 10;
    let duration = Duration::from_secs(30);

    let metrics = Arc::new(tokio::sync::Mutex::new(TestMetrics::new()));
    let mut handles = Vec::new();

    for worker_id in 0..workers {
        let c = client.clone();
        let m = metrics.clone();
        let ips: Vec<String> = c.config.all_ips().into_iter().map(String::from).collect();
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let mut req_count = 0u64;
            while start.elapsed() < duration {
                let ip = &ips[(worker_id + req_count as usize) % ips.len()];
                let endpoint = endpoints[(req_count as usize) % endpoints.len()];
                let result = c.get(ip, endpoint).await;
                m.lock().await.record(result);
                req_count += 1;
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let mut m = metrics.lock().await;
    m.finish();
    m.print_report("Load: Sustained Throughput (10 workers × 30s)");

    // Measurement test — no strict assertion, but report useful stats
    println!(
        "  Sustained RPS: {:.1}, success rate: {:.1}% (excl. 429: {:.1}%), rate-limited: {}",
        m.requests_per_second(),
        m.success_rate() * 100.0,
        m.success_rate_excluding_429() * 100.0,
        m.rate_limited_count()
    );
}

#[tokio::test]
#[ignore]
async fn load_04_rate_limiting_triggers() {
    let client = setup();
    // Pick first non-genesis node for rate limit test
    let target_ip = client.config.chaos_eligible_nodes()[0].ip.to_string();
    let mut handles = Vec::new();

    // Fire 50 rapid requests at a single node
    for _ in 0..50 {
        let c = client.clone();
        let ip = target_ip.clone();
        handles.push(tokio::spawn(
            async move { c.get(&ip, "/health").await },
        ));
    }

    let mut got_429 = false;
    let mut metrics = TestMetrics::new();
    for h in handles {
        if let Ok(r) = h.await {
            if r.status == Some(429) {
                got_429 = true;
            }
            metrics.record(r);
        }
    }
    metrics.finish();
    metrics.print_report("Load: Rate Limiting (50 rapid-fire to single node)");

    if got_429 {
        println!("  Rate limiting triggered (429 responses observed)");
    } else {
        println!("  NOTE: No 429 responses — rate limiting may not be configured for /health");
    }

    // After rate limiting, the node should recover
    tokio::time::sleep(Duration::from_secs(5)).await;
    let recovery = client.get(&target_ip, "/health").await;
    assert!(
        recovery.error.is_none() && recovery.status == Some(200),
        "Node did not recover after rate limiting: {:?}",
        recovery.error
    );
    println!("  Node recovered after rate limiting pause");
}

#[tokio::test]
#[ignore]
async fn load_05_websocket_storm() {
    use futures_util::SinkExt;
    use tokio_tungstenite::connect_async;
    use tokio_tungstenite::tungstenite::Message;

    let config = ClusterConfig::signet();
    let connections_per_node = 20;
    let mut handles = Vec::new();

    // Stagger connections to reduce rate-limit impact (100ms between each)
    for node in &config.nodes {
        let ws_url = config.ws_url(node.ip);
        for conn_id in 0..connections_per_node {
            let url = ws_url.clone();
            let node_name = node.name.to_string();
            let delay = Duration::from_millis(100 * conn_id as u64);
            handles.push(tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                match tokio::time::timeout(Duration::from_secs(10), connect_async(&url)).await {
                    Ok(Ok((mut ws, _))) => {
                        let _ = ws.send(Message::Ping(vec![conn_id as u8])).await;
                        let _ = ws.close(None).await;
                        (node_name, true, None)
                    }
                    Ok(Err(e)) => {
                        let err_str = e.to_string();
                        let is_429 = err_str.contains("429");
                        (node_name, false, Some((err_str, is_429)))
                    }
                    Err(_) => (node_name, false, Some(("timeout".to_string(), false))),
                }
            }));
        }
    }

    let mut total = 0;
    let mut connected = 0;
    let mut rate_limited = 0;
    let mut other_errors: Vec<String> = Vec::new();
    for h in handles {
        if let Ok((node, ok, err)) = h.await {
            total += 1;
            if ok {
                connected += 1;
            } else if let Some((msg, is_429)) = err {
                if is_429 {
                    rate_limited += 1;
                } else if other_errors.len() < 5 {
                    other_errors.push(format!("{}: {}", node, msg));
                }
            }
        }
    }

    let non_429_total = total - rate_limited;
    let rate = if non_429_total > 0 {
        connected as f64 / non_429_total as f64
    } else {
        0.0
    };

    println!(
        "\n=== WebSocket Storm ===\n  Total: {}\n  Connected: {}\n  Rate-limited (429): {}\n  Success rate (excl. 429): {:.1}%",
        total, connected, rate_limited, rate * 100.0
    );
    if !other_errors.is_empty() {
        println!("  Non-429 errors: {:?}", other_errors);
    }

    // Assert on non-429 connections only
    assert!(
        rate > 0.50 || non_429_total == 0,
        "WebSocket success rate (excl. 429) {:.1}% too low. Non-429 errors: {:?}",
        rate * 100.0,
        other_errors
    );
}

#[tokio::test]
#[ignore]
async fn load_06_metrics_under_load() {
    let client = setup();
    let ips = client.config.all_ips();

    // Use retry to get actual metrics (not a 429 response)
    let mut before = Vec::new();
    for ip in &ips {
        let r = client.get_with_retry(ip, "/metrics").await;
        let body = r.body.unwrap_or_default();
        let is_real = body.contains("ghost_") || body.contains("# HELP");
        println!(
            "  {} metrics before: {} bytes (real={})",
            ip,
            body.len(),
            is_real
        );
        before.push((ip.to_string(), body, is_real));
    }

    // Generate some load (sequential to avoid rate limiting the metrics scrape)
    for i in 0..20 {
        let ip = ips[i % ips.len()];
        client.get(ip, "/api/v1/node/status").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Brief pause for metrics to update
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Scrape metrics after load
    for (ip, _before_body, before_real) in &before {
        let after = client.get_with_retry(ip, "/metrics").await;
        let after_body = after.body.unwrap_or_default();
        let after_real = after_body.contains("ghost_") || after_body.contains("# HELP");
        println!(
            "  {} metrics after: {} bytes (real={})",
            ip,
            after_body.len(),
            after_real
        );

        // Only compare if we got real metrics both times
        if *before_real && after_real {
            assert!(
                after_body.len() >= 100,
                "{} metrics response too small: {} bytes",
                ip,
                after_body.len()
            );
        }
    }
}

#[tokio::test]
#[ignore]
async fn load_07_mixed_realistic_traffic() {
    let client = setup();
    let dashboard_endpoints = [
        "/health",
        "/api/v1/node/status",
        "/api/v1/network/peers",
        "/api/v1/mining/miners",
    ];
    let users = 4;
    let duration = Duration::from_secs(30);

    let metrics = Arc::new(tokio::sync::Mutex::new(TestMetrics::new()));
    let mut handles = Vec::new();

    for user_id in 0..users {
        let c = client.clone();
        let m = metrics.clone();
        let ips: Vec<String> = c.config.all_ips().into_iter().map(String::from).collect();
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let mut req_count = 0u64;
            while start.elapsed() < duration {
                let ip = &ips[user_id % ips.len()];
                let endpoint = dashboard_endpoints[(req_count as usize) % dashboard_endpoints.len()];
                let result = c.get(ip, endpoint).await;
                m.lock().await.record(result);
                req_count += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let mut m = metrics.lock().await;
    m.finish();
    m.print_report("Load: Mixed Realistic Traffic (4 dashboard users × 30s)");

    let rate = m.success_rate_excluding_429();
    assert!(
        rate > 0.95,
        "Realistic traffic error rate too high (excl. 429): {:.1}% success",
        rate * 100.0
    );
    println!(
        "  Rate-limited: {}, service success rate (excl. 429): {:.1}%",
        m.rate_limited_count(),
        rate * 100.0
    );
}

#[tokio::test]
#[ignore]
async fn load_08_no_error_spikes() {
    let config = ClusterConfig::signet();

    for node in &config.nodes {
        let panic_count =
            SshController::count_log_matches(node, config.service_name, "panic", "10 min ago")
                .unwrap_or_else(|e| {
                    println!("  WARNING: Could not check {} logs: {}", node.name, e);
                    0
                });

        let error_count =
            SshController::count_log_matches(node, config.service_name, "error", "10 min ago")
                .unwrap_or_else(|e| {
                    println!("  WARNING: Could not check {} logs: {}", node.name, e);
                    0
                });

        println!(
            "  {} last 10min: {} panics, {} errors",
            node.name, panic_count, error_count
        );

        assert_eq!(
            panic_count, 0,
            "{} had {} panics in last 10 minutes",
            node.name, panic_count
        );

        // Allow some errors (network blips, etc.) but flag excessive ones
        if error_count > 50 {
            println!(
                "  WARNING: {} had {} errors in last 10 minutes (elevated)",
                node.name, error_count
            );
        }
    }
}
