//! The AGGREGATED translator cases, split out of `translator_integration.rs`.
//!
//! ⛔ Own file because a file boundary is the only PROCESS boundary available. `TPROXY_MODE` is a
//! process-global `OnceLock` set from the translator config, and re-setting it to a DIFFERENT
//! value is fatal by design — one global cannot represent two translators that disagree, and the
//! alternative is the second silently running under the first one's mode.
//!
//! `translator_integration.rs` held 13 tests mixing both modes, so whichever ran second aborted
//! the whole binary and the target never finished at all — it read as a >420s TIMEOUT rather than
//! as a configuration conflict (#617). `--test-threads=1` does not help; it serialises tests
//! inside one process.

// This file contains integration tests for the `TranslatorSv2` module.
use integration_tests_sv2::{
    interceptor::{IgnoreMessage, MessageDirection, ReplaceMessage},
    mock_roles::{MockUpstream, WithSetup},
    sv1_sniffer::SV1MessageFilter,
    template_provider::DifficultyLevel,
    utils::get_available_address,
    *,
};
use stratum_apps::stratum_core::mining_sv2::*;
use tokio::net::{TcpListener, TcpStream};

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use stratum_apps::stratum_core::{
    binary_sv2::{Seq0255, Sv2Option},
    common_messages_sv2::{
        Protocol, SetupConnectionError, SetupConnectionSuccess, MESSAGE_TYPE_SETUP_CONNECTION,
        MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
    },
    mining_sv2::{
        CloseChannel, OpenMiningChannelError, MESSAGE_TYPE_CLOSE_CHANNEL,
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    },
    parsers_sv2::{self, AnyMessage, CommonMessages},
    sv1_api,
    template_distribution_sv2::MESSAGE_TYPE_SUBMIT_SOLUTION,
};

// This test runs an sv2 translator between an sv1 mining device and a pool. the connection between
// the translator and the pool is intercepted by a sniffer. The test checks if the translator and
// the pool exchange the correct messages upon connection. And that the miner is able to submit
// shares.

#[tokio::test]
async fn aggregated_translator_correctly_deals_with_group_channels() {
    start_tracing();
    let (tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    tp.fund_wallet().unwrap();

    // block SubmitSolution messages from arriving to TP
    // so we avoid shares triggering chain tip updates
    // which we want to do explicitly via generate_blocks()
    let ignore_submit_solution =
        IgnoreMessage::new(MessageDirection::ToUpstream, MESSAGE_TYPE_SUBMIT_SOLUTION);
    let (_sniffer_pool_tp, sniffer_pool_tp_addr) = start_sniffer(
        "0",
        tp_addr,
        false,
        vec![ignore_submit_solution.into()],
        None,
    );

    let (pool, pool_addr, _) =
        start_pool(sv2_tp_config(sniffer_pool_tp_addr), vec![], vec![], false).await;

    // ignore SubmitSharesSuccess messages, so we can keep the assertion flow simple
    let ignore_submit_shares_success = IgnoreMessage::new(
        MessageDirection::ToDownstream,
        MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
    );
    let (sniffer, sniffer_addr) = start_sniffer(
        "0",
        pool_addr,
        false,
        vec![ignore_submit_shares_success.into()],
        None,
    );

    // aggregated tProxy
    let (translator, tproxy_addr, _) =
        start_sv2_translator(&[sniffer_addr], true, vec![], vec![], None, false).await;

    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        )
        .await;

    let mut minerd_vec = Vec::new();

    // start the first minerd process, to trigger the first OpenExtendedMiningChannel message
    let (minerd_process, _minerd_addr) = start_minerd(tproxy_addr, None, None, false).await;
    minerd_vec.push(minerd_process);

    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        )
        .await;
    sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
        )
        .await;

    // save the aggregated and group channel IDs
    let (aggregated_channel_id, group_channel_id) = match sniffer.next_message_from_upstream() {
        Some((
            _,
            AnyMessage::Mining(parsers_sv2::Mining::OpenExtendedMiningChannelSuccess(msg)),
        )) => (msg.channel_id, msg.group_channel_id),
        msg => panic!(
            "Expected OpenExtendedMiningChannelSuccess message, found: {:?}",
            msg
        ),
    };

    // wait for the expected NewExtendedMiningJob and SetNewPrevHash messages
    // and clean the queue
    sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        )
        .await;
    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
        )
        .await;

    // open a few more extended channels to be aggregated with the first one
    const N_MINERDS: u32 = 5;
    for _i in 0..N_MINERDS {
        let (minerd_process, _minerd_addr) = start_minerd(tproxy_addr, None, None, false).await;
        minerd_vec.push(minerd_process);

        // wait a bit
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // assert no furter OpenExtendedMiningChannel messages are sent
        sniffer
            .assert_message_not_present(
                MessageDirection::ToUpstream,
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                std::time::Duration::from_secs(1),
            )
            .await;
    }

    // wait for a SubmitSharesExtended message
    sniffer
        .wait_for_message_type(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
        )
        .await;

    let share_channel_id = match sniffer.next_message_from_downstream() {
        Some((_, AnyMessage::Mining(parsers_sv2::Mining::SubmitSharesExtended(msg)))) => {
            msg.channel_id
        }
        msg => panic!("Expected SubmitSharesExtended message, found: {:?}", msg),
    };

    assert_eq!(
        aggregated_channel_id, share_channel_id,
        "Share submitted to the correct channel ID"
    );
    assert_ne!(
        share_channel_id, group_channel_id,
        "Share NOT submitted to the group channel ID"
    );

    // wait for another share, so we can clean the queue
    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
        )
        .await;

    // now let's force a mempool update, so we trigger a NewExtendedMiningJob message
    // it's actually directed to the group channel Id, not the aggregated channel Id
    // nevertheless, tProxy should still submit the share to the aggregated channel Id
    tp.create_mempool_transaction().unwrap();

    sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        )
        .await;
    let new_extended_mining_job = match sniffer.next_message_from_upstream() {
        Some((_, AnyMessage::Mining(parsers_sv2::Mining::NewExtendedMiningJob(msg)))) => msg,
        msg => panic!("Expected NewExtendedMiningJob message, found: {:?}", msg),
    };

    // here we're actually asserting pool behavior, not tProxy
    // but still good to have, to ensure the global sanity of the test
    assert_ne!(new_extended_mining_job.channel_id, aggregated_channel_id);
    assert_eq!(new_extended_mining_job.channel_id, group_channel_id);

    loop {
        sniffer
            .wait_for_message_type(
                MessageDirection::ToUpstream,
                MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
            )
            .await;
        let submit_shares_extended = match sniffer.next_message_from_downstream() {
            Some((_, AnyMessage::Mining(parsers_sv2::Mining::SubmitSharesExtended(msg)))) => msg,
            msg => panic!("Expected SubmitSharesExtended message, found: {:?}", msg),
        };

        // assert the share is submitted to the aggregated channel Id
        assert_eq!(submit_shares_extended.channel_id, aggregated_channel_id);
        assert_ne!(submit_shares_extended.channel_id, group_channel_id);

        if submit_shares_extended.job_id == 2 {
            break;
        }
    }

    // now let's force a chain tip update, so we trigger a SetNewPrevHash + NewExtendedMiningJob
    // message pair
    tp.generate_blocks(1);

    sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        )
        .await;
    let new_extended_mining_job = match sniffer.next_message_from_upstream() {
        Some((_, AnyMessage::Mining(parsers_sv2::Mining::NewExtendedMiningJob(msg)))) => msg,
        msg => panic!("Expected NewExtendedMiningJob message, found: {:?}", msg),
    };

    // again, asserting pool behavior, not tProxy
    // just to ensure the global sanity of the test
    assert_ne!(new_extended_mining_job.channel_id, aggregated_channel_id);
    assert_eq!(new_extended_mining_job.channel_id, group_channel_id);

    sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
        )
        .await;
    let set_new_prev_hash = match sniffer.next_message_from_upstream() {
        Some((_, AnyMessage::Mining(parsers_sv2::Mining::SetNewPrevHash(msg)))) => msg,
        msg => panic!("Expected SetNewPrevHash message, found: {:?}", msg),
    };

    // again, asserting pool behavior, not tProxy
    // just to ensure the global sanity of the test
    assert_eq!(set_new_prev_hash.channel_id, group_channel_id);
    assert_ne!(set_new_prev_hash.channel_id, aggregated_channel_id);

    loop {
        sniffer
            .wait_for_message_type(
                MessageDirection::ToUpstream,
                MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
            )
            .await;
        let submit_shares_extended = match sniffer.next_message_from_downstream() {
            Some((_, AnyMessage::Mining(parsers_sv2::Mining::SubmitSharesExtended(msg)))) => msg,
            msg => panic!("Expected SubmitSharesExtended message, found: {:?}", msg),
        };

        // assert the share is submitted to the aggregated channel Id
        assert_eq!(submit_shares_extended.channel_id, aggregated_channel_id);
        assert_ne!(submit_shares_extended.channel_id, group_channel_id);

        if submit_shares_extended.job_id == 3 {
            break;
        }
    }
    shutdown_all!(translator, pool);
}

// This test launches a tProxy in non-aggregated mode and leverages a MockUpstream to test the
// correct functionalities of grouping extended channels.

#[tokio::test]
async fn aggregated_translator_handles_downstream_connecting_during_future_job() {
    start_tracing();

    let mock_upstream_addr = get_available_address();
    let mock_upstream = MockUpstream::new(mock_upstream_addr, WithSetup::no());
    let send_to_tproxy = mock_upstream.start().await;

    // ignore SubmitSharesSuccess messages to simplify the test flow
    let ignore_submit_shares_success = IgnoreMessage::new(
        MessageDirection::ToDownstream,
        MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
    );
    let (sniffer, sniffer_addr) = start_sniffer(
        "future_job_test",
        mock_upstream_addr,
        false,
        vec![ignore_submit_shares_success.into()],
        None,
    );

    // Start translator in aggregated mode
    let (translator, tproxy_addr, _) =
        start_sv2_translator(&[sniffer_addr], true, vec![], vec![], None, false).await;

    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_SETUP_CONNECTION,
        )
        .await;

    let setup_connection_success = AnyMessage::Common(CommonMessages::SetupConnectionSuccess(
        SetupConnectionSuccess {
            used_version: 2,
            flags: 0,
        },
    ));
    send_to_tproxy.send(setup_connection_success).await.unwrap();

    // Keep references to minerd processes and SV1 sniffers so they don't get dropped
    let mut minerd_vec = Vec::new();

    // Start SV1 sniffer for the first miner
    let (sv1_sniffer_1, sv1_sniffer_addr_1) = start_sv1_sniffer(tproxy_addr);

    // Start the first minerd (through SV1 sniffer) to trigger OpenExtendedMiningChannel
    let (minerd_process_1, _minerd_addr_1) =
        start_minerd(sv1_sniffer_addr_1, None, None, false).await;
    minerd_vec.push(minerd_process_1);

    sniffer
        .wait_for_message_type(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        )
        .await;

    let open_extended_mining_channel: OpenExtendedMiningChannel = loop {
        match sniffer.next_message_from_downstream() {
            Some((_, AnyMessage::Mining(parsers_sv2::Mining::OpenExtendedMiningChannel(msg)))) => {
                break msg;
            }
            _ => continue,
        };
    };

    // Send OpenExtendedMiningChannelSuccess for the aggregated channel
    let open_extended_mining_channel_success = AnyMessage::Mining(
        parsers_sv2::Mining::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
            request_id: open_extended_mining_channel.request_id,
            channel_id: 2, // aggregated channel ID
            target: hex::decode("0000137c578190689425e3ecf8449a1af39db0aed305d9206f45ac32fe8330fc")
                .unwrap()
                .try_into()
                .unwrap(),
            // full extranonce has a total of 12 bytes
            extranonce_size: 8,
            extranonce_prefix: vec![0x00, 0x01, 0x00, 0x00].try_into().unwrap(),
            group_channel_id: 1,
        }),
    );
    send_to_tproxy
        .send(open_extended_mining_channel_success)
        .await
        .unwrap();

    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
        )
        .await;

    // Send a FUTURE job (min_ntime: None) - this job is not active yet!
    let future_job = AnyMessage::Mining(parsers_sv2::Mining::NewExtendedMiningJob(
        NewExtendedMiningJob {
            channel_id: 2,
            job_id: 1,
            min_ntime: Sv2Option::new(None), // This makes it a future job!
            version: 0x20000000,
            version_rolling_allowed: true,
            merkle_path: Seq0255::new(vec![]).unwrap(),
            coinbase_tx_prefix: hex::decode("02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff265200162f5374726174756d2056322053524920506f6f6c2f2f0c").unwrap().try_into().unwrap(),
            coinbase_tx_suffix: hex::decode("feffffff0200f2052a01000000160014ebe1b7dcc293ccaa0ee743a86f89df8258c208fc0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf901000000").unwrap().try_into().unwrap(),
        },
    ));

    send_to_tproxy.send(future_job).await.unwrap();
    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        )
        .await;

    // CRITICAL: Start a SECOND minerd BEFORE sending SetNewPrevHash
    // This is the race condition we're testing - the new downstream connects
    // while a future job is pending but not yet activated

    // Start SV1 sniffer for the second miner
    let (sv1_sniffer_2, sv1_sniffer_addr_2) = start_sv1_sniffer(tproxy_addr);

    let (minerd_process_2, _minerd_addr_2) =
        start_minerd(sv1_sniffer_addr_2, None, None, false).await;
    minerd_vec.push(minerd_process_2);

    // Give time for the second minerd to connect and the channel to be created
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Now send SetNewPrevHash to activate the future job
    // Without the fix, this would cause "Failed to set new prev hash: JobIdNotFound"
    // because the second downstream's channel wouldn't have the future job
    let set_new_prev_hash =
        AnyMessage::Mining(parsers_sv2::Mining::SetNewPrevHash(SetNewPrevHash {
            channel_id: 2,
            job_id: 1,
            prev_hash: hex::decode(
                "3ab7089cd2cd30f133552cfde82c4cb239cd3c2310306f9d825e088a1772cc39",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            min_ntime: 1766782170,
            nbits: 0x207fffff,
        }));

    send_to_tproxy.send(set_new_prev_hash).await.unwrap();
    sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
        )
        .await;

    // Verify BOTH miners receive the mining.notify message
    sv1_sniffer_1
        .wait_for_message(&["mining.notify"], MessageDirection::ToDownstream)
        .await;
    sv1_sniffer_2
        .wait_for_message(&["mining.notify"], MessageDirection::ToDownstream)
        .await;

    // Verify BOTH miners submit shares (mining.submit)
    // This proves both miners are working correctly after the future job was activated
    sv1_sniffer_1
        .wait_for_message(&["mining.submit"], MessageDirection::ToUpstream)
        .await;
    sv1_sniffer_2
        .wait_for_message(&["mining.submit"], MessageDirection::ToUpstream)
        .await;
    translator.shutdown().await;
}

// This test verifies that the pool server continues accepting new connection
// requests while performing handshakes with other clients. It also checks the
// scenario where a downstream client connects but never completes the handshake.
//
// The goal is to ensure such incomplete handshakes do not block the server or
// render it unresponsive.
//
// For more context see:
// https://github.com/stratum-mining/sv2-apps/issues/241
