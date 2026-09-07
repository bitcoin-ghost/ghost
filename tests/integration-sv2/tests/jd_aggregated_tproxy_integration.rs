//! The AGGREGATED half of the tproxy JD integration, split out of
//! `jd_tproxy_integration.rs`.
//!
//! ⛔ It has to live in its own file, and the reason is structural rather than stylistic.
//! `TPROXY_MODE` and `VARDIFF_ENABLED` are process-global `OnceLock`s set from the translator's
//! config on `start()`. Re-setting them to the SAME value is a no-op, but re-setting to a
//! DIFFERENT one is fatal on purpose — a single global cannot represent two translators that
//! disagree, and the alternative is the second silently running under the first one's mode.
//!
//! `--test-threads=1` does NOT help: it serialises tests without giving them separate processes.
//! Each `tests/*.rs` is its own binary, so a file boundary is a process boundary — which is the
//! only thing that actually separates them.
//!
//! Keeping the aggregated and non-aggregated cases in one file meant whichever ran second died
//! with "TPROXY_MODE re-initialised with a different value", so the target could never report
//! better than 1 passed / 1 failed (#617).

use integration_tests_sv2::{interceptor::MessageDirection, template_provider::DifficultyLevel, *};
use stratum_apps::stratum_core::{common_messages_sv2::*, mining_sv2::*};

#[tokio::test]
async fn jd_aggregated_tproxy_integration() {
    start_tracing();
    let (tp, _tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (pool, pool_addr, jds_addr, _) =
        start_pool_with_jds(tp.bitcoin_core(), vec![], vec![], false).await;
    let (jdc_pool_sniffer, jdc_pool_sniffer_addr) =
        start_sniffer("0", pool_addr, false, vec![], None);
    let (jdc, jdc_addr, _) = start_jdc(
        &[(jdc_pool_sniffer_addr, jds_addr)],
        ipc_config(
            tp.bitcoin_core().data_dir().clone(),
            tp.bitcoin_core().is_signet(),
            None,
        ),
        vec![],
        vec![],
        false,
        None,
    );
    let (tproxy_jdc_sniffer, tproxy_jdc_sniffer_addr) =
        start_sniffer("1", jdc_addr, false, vec![], None);
    let (translator, tproxy_addr, _) = start_sv2_translator(
        &[tproxy_jdc_sniffer_addr],
        true,
        vec![],
        vec![],
        None,
        false,
    )
    .await;

    // start two minerd processes
    let (_minerd_process, _minerd_addr) = start_minerd(tproxy_addr, None, None, false).await;
    let (_minerd_process, _minerd_addr) = start_minerd(tproxy_addr, None, None, false).await;

    // assert that only one OpenExtendedMiningChannel message is present in the queue
    {
        tproxy_jdc_sniffer
            .wait_for_message_type_and_clean_queue(
                MessageDirection::ToUpstream,
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
            )
            .await;
        assert!(
            tproxy_jdc_sniffer
                .assert_message_not_present(
                    MessageDirection::ToUpstream,
                    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                    std::time::Duration::from_secs(2),
                )
                .await,
            "Expected only one OpenExtendedMiningChannel but found another one."
        );
    }

    jdc_pool_sniffer
        .wait_for_message_type(MessageDirection::ToUpstream, MESSAGE_TYPE_SETUP_CONNECTION)
        .await;
    jdc_pool_sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        )
        .await;
    jdc_pool_sniffer
        .wait_for_message_type(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        )
        .await;
    jdc_pool_sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
        )
        .await;
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
    shutdown_all!(translator, jdc, pool);
}
