// Dedicated integration tests for monitoring/metrics endpoints.
//
// These tests spin up various SV2 topologies with monitoring enabled and validate
// that the correct Prometheus metrics and JSON API endpoints are exposed.

use integration_tests_sv2::{
    interceptor::MessageDirection, prometheus_metrics_assertions::*,
    template_provider::DifficultyLevel, *,
};
use stratum_apps::stratum_core::mining_sv2::*;

// ---------------------------------------------------------------------------
// 1. Pool + SV2 Mining Device (standard channel) Pool role exposes: client metrics (connections,
//    channels, shares, hashrate) Pool has NO upstream, so server metrics should be absent.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pool_monitoring_with_sv2_mining_device() {
    start_tracing();
    let (tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (pool, pool_addr, pool_monitoring) = start_pool(
        sv2_tp_config(tp_addr),
        tp.bitcoin_core(),
        vec![],
        vec![],
        true,
    )
    .await;
    let (sniffer, sniffer_addr) = start_sniffer("A", pool_addr, false, vec![], None);
    start_mining_device_sv2(sniffer_addr, None, None, None, 1, None, true);

    // Wait for a share to be accepted so metrics are populated
    sniffer
        .wait_for_message_type(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
        )
        .await;
    sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
        )
        .await;

    let pool_mon = pool_monitoring.expect("pool monitoring should be enabled");

    // Health API
    assert_api_health(pool_mon).await;

    // Poll until per-channel share metric is populated in the monitoring cache
    let pool_metrics = poll_until_metric_gte(
        pool_mon,
        "sv2_client_shares_accepted_total",
        1.0,
        std::time::Duration::from_secs(10),
    )
    .await;
    assert_uptime(&pool_metrics);

    // Pool has no upstream — server metrics should be absent
    assert_metric_not_present(&pool_metrics, "sv2_server_channels");
    assert_metric_not_present(&pool_metrics, "sv2_server_hashrate_total");

    // Pool should see 1 SV2 client (the mining device) with a standard channel
    assert_metric_eq(&pool_metrics, "sv2_clients_total", 1.0);

    shutdown_all!(pool);
}

// ---------------------------------------------------------------------------
// 2. Pool + tProxy + SV1 miner (non-aggregated) Pool: client metrics (1 SV2 client = tProxy,
//    extended channel; no shares, see below) tProxy: server metrics (upstream channel to pool), SV1 metrics (1
//    SV1 client) tProxy has no SV2 downstreams so sv2_clients_total should be absent
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pool_and_tproxy_monitoring_with_sv1_miner() {
    start_tracing();
    let (tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (pool, pool_addr, pool_monitoring) = start_pool(
        sv2_tp_config(tp_addr),
        tp.bitcoin_core(),
        vec![],
        vec![],
        true,
    )
    .await;
    let (sniffer, sniffer_addr) = start_sniffer("0", pool_addr, false, vec![], None);
    let (tproxy, tproxy_addr, tproxy_monitoring) =
        start_sv2_translator(&[sniffer_addr], false, vec![], vec![], None, true).await;
    let (_minerd_process, _minerd_addr) = start_minerd(tproxy_addr, None, None, false).await;

    // Wait for the miner's channel to be served a job. Not for shares: the node pool floors every
    // channel at difficulty 2^10 (about 2^42 hashes a share), and minerd, a CPU miner whose SV1
    // difficulty is the channel's, submits none in the life of the test. So the share counters
    // are not asserted here; the device test above covers them through a block share.
    sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        )
        .await;

    // -- Pool metrics --
    let pool_mon = pool_monitoring.expect("pool monitoring should be enabled");
    assert_api_health(pool_mon).await;
    let pool_metrics = poll_until_metric_gte(
        pool_mon,
        "sv2_clients_total",
        1.0,
        std::time::Duration::from_secs(10),
    )
    .await;
    assert_uptime(&pool_metrics);
    assert_metric_eq(&pool_metrics, "sv2_clients_total", 1.0);
    // Pool has no upstream
    assert_metric_not_present(&pool_metrics, "sv2_server_channels");

    // -- tProxy metrics --
    let tproxy_mon = tproxy_monitoring.expect("tproxy monitoring should be enabled");
    assert_api_health(tproxy_mon).await;
    let tproxy_metrics = poll_until_metric_gte(
        tproxy_mon,
        "sv2_server_channels{channel_type=\"extended\"}",
        1.0,
        std::time::Duration::from_secs(10),
    )
    .await;
    assert_uptime(&tproxy_metrics);
    // tProxy has 1 upstream extended channel
    assert_metric_eq(
        &tproxy_metrics,
        "sv2_server_channels{channel_type=\"extended\"}",
        1.0,
    );
    // tProxy should see at least 1 SV1 client
    assert_metric_eq(&tproxy_metrics, "sv1_clients_total", 1.0);
    // tProxy has no SV2 downstreams
    assert_metric_not_present(&tproxy_metrics, "sv2_clients_total");

    shutdown_all!(pool, tproxy);
}
