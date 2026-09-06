//! The AGGREGATED-topology monitoring case, split out of `monitoring_integration.rs`.
//!
//! ⛔ Its own file because a file boundary is the only PROCESS boundary available here.
//! `TPROXY_MODE` is a process-global `OnceLock` set from the translator config; re-setting it to
//! a different value is fatal by design, since one global cannot represent two translators that
//! disagree. This test starts an AGGREGATED translator while the other three in
//! `monitoring_integration.rs` start non-aggregated ones, so whichever ran second aborted with
//! "TPROXY_MODE re-initialised with a different value" and the target could never report better
//! than 3 passed / 1 failed (#617).
//!
//! `--test-threads=1` does not help — it serialises tests within one process.

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
async fn jd_aggregated_topology_monitoring() {
    start_tracing();
    let (tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (pool, pool_addr, jds_addr, pool_monitoring) =
        start_pool_with_jds(tp.bitcoin_core(), vec![], vec![], true).await;
    let (jdc_pool_sniffer, jdc_pool_sniffer_addr) =
        start_sniffer("0", pool_addr, false, vec![], None);
    let (jdc, jdc_addr, _jdc_monitoring) = start_jdc(
        &[(jdc_pool_sniffer_addr, jds_addr)],
        sv2_tp_config(tp_addr),
        vec![],
        vec![],
        true,
        None,
    );
    let (_tproxy_jdc_sniffer, tproxy_jdc_sniffer_addr) =
        start_sniffer("1", jdc_addr, false, vec![], None);
    let (tproxy, tproxy_addr, tproxy_monitoring) =
        start_sv2_translator(&[tproxy_jdc_sniffer_addr], true, vec![], vec![], None, true).await;

    // Start two minerd processes
    let (_minerd_process_1, _minerd_addr_1) = start_minerd(tproxy_addr, None, None, false).await;
    let (_minerd_process_2, _minerd_addr_2) = start_minerd(tproxy_addr, None, None, false).await;

    // Wait for shares to flow through the topology
    jdc_pool_sniffer
        .wait_for_message_type(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
        )
        .await;
    jdc_pool_sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
        )
        .await;

    // -- Pool metrics: sees 1 SV2 client (JDC), shares accepted --
    let pool_mon = pool_monitoring.expect("pool monitoring should be enabled");
    assert_api_health(pool_mon).await;
    let pool_metrics = poll_until_metric_gte(
        pool_mon,
        "sv2_client_shares_accepted_total",
        1.0,
        std::time::Duration::from_secs(10),
    )
    .await;
    assert_uptime(&pool_metrics);
    assert_metric_eq(&pool_metrics, "sv2_clients_total", 1.0);
    assert_metric_not_present(&pool_metrics, "sv2_server_channels");

    // -- tProxy metrics (aggregated): 2 SV1 clients, 1 upstream extended channel --
    let tproxy_mon = tproxy_monitoring.expect("tproxy monitoring should be enabled");
    assert_api_health(tproxy_mon).await;
    let tproxy_metrics = fetch_metrics(tproxy_mon).await;
    assert_uptime(&tproxy_metrics);
    assert_metric_eq(
        &tproxy_metrics,
        "sv2_server_channels{channel_type=\"extended\"}",
        1.0,
    );
    assert_metric_eq(&tproxy_metrics, "sv1_clients_total", 2.0);
    assert_metric_not_present(&tproxy_metrics, "sv2_clients_total");

    shutdown_all!(pool, jdc, tproxy);
}

// ---------------------------------------------------------------------------
// 4. Block found detection via metrics Uses JDC topology (which finds regtest blocks). After a
//    block is found, the pool's sv2_client_blocks_found_total metric should be >= 1.
// ---------------------------------------------------------------------------
