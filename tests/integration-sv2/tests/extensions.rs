// Integration test for translator extension negotiation with extension 0x0002
// (EXTENSION_TYPE_WORKER_HASHRATE_TRACKING) and the Ghost agent extension (0x4748), and for the
// miner's identity reaching the node pool.
//
// This test validates:
// 1. Pool and translator negotiate 0x0002 and 0x4748 during SetupConnection
// 2. The channel opens on subscribe under the provisional identity
// 3. When the SV1 miner authorises, the translator binds the channel with an UpdateChannel
//    carrying the miner's full identity in the payee TLV
// 4. The pool then serves the channel its first job

use integration_tests_sv2::{interceptor::MessageDirection, template_provider::DifficultyLevel, *};
use stratum_apps::stratum_core::{
    binary_sv2::Seq064K,
    common_messages_sv2::*,
    extensions_sv2::EXTENSION_TYPE_WORKER_HASHRATE_TRACKING,
    extensions_sv2::PROVISIONAL_CHANNEL_IDENTITY,
    mining_sv2::*,
    parsers_sv2::{AnyMessage, Extensions, ExtensionsNegotiation, Mining},
};
use tracing::info;

/// The SV1 username the miner authorises with, and therefore the `user_identity` that must reach
/// the pool. Declared once and asserted against, so the two cannot drift apart again.
///
/// ⚠ It must be `<bitcoin_address>.<worker_name>`. #479 made a bare username a REJECTED
/// authorize — "shares from this username could not be attributed and would earn nothing" — so a
/// fixture using a bare name never opens a channel at all, and the test then fails much later as
/// a timeout waiting for `OpenExtendedMiningChannel`, which reads like a protocol fault rather
/// than a bad fixture. The address is the harness's own signet coinbase address.
const MINER_USERNAME: &str = "tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8.SRI-miner";

/// Tests that the translator negotiates extensions 0x0002 and 0x4748 with the pool, and binds
/// the miner's identity to its channel with the payee TLV.
#[tokio::test]
async fn test_extension_negotiation_and_payee_binding() {
    start_tracing();
    // Extension 0x0002 for worker hashrate tracking
    let supported_extensions = vec![EXTENSION_TYPE_WORKER_HASHRATE_TRACKING];
    // The translator requires the Ghost agent extension as well, as every node's does: the node
    // pool accepts a channel opened on subscribe only over it (see `start_sv2_translator`). The
    // pool supports it whatever its config lists, so both are negotiated.
    let required_extensions = vec![
        EXTENSION_TYPE_WORKER_HASHRATE_TRACKING,
        AGENT_TLV_EXTENSION_TYPE,
    ];

    let (tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    // Start pool with extension 0x0002 support
    let (pool, pool_addr, _) = start_pool(
        sv2_tp_config(tp_addr),
        tp.bitcoin_core(),
        supported_extensions.clone(),
        vec![],
        false,
    )
    .await;
    let (pool_translator_sniffer, pool_translator_sniffer_addr) =
        start_sniffer("pool-translator", pool_addr, false, vec![], None);
    // Start translator with extension 0x0002 support and user_identity configured
    // aggregate_channels = false ensures TLV fields are added
    let (translator, tproxy_addr, _) = start_sv2_translator(
        &[pool_translator_sniffer_addr],
        false, // aggregate_channels = false
        supported_extensions.clone(),
        required_extensions.clone(),
        None,
        false,
    )
    .await;
    // Start SV1 miner (minerd) connected to translator with username "SRI-miner"
    let (_minerd_process, _minerd_addr) = start_minerd(
        tproxy_addr,
        Some(MINER_USERNAME.to_string()),
        Some("password".to_string()),
        false,
    )
    .await;

    pool_translator_sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_SETUP_CONNECTION,
        )
        .await;

    pool_translator_sniffer
        .wait_for_message_type_and_clean_queue(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        )
        .await;

    // Verify RequestExtensions includes extension 0x0002
    let request_extensions_msg = match pool_translator_sniffer.next_message_from_downstream() {
        Some((
            _,
            AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
                ExtensionsNegotiation::RequestExtensions(msg),
            )),
        )) => msg,
        _ => panic!(
            "received unexpected message: {:?}",
            pool_translator_sniffer.next_message_from_downstream()
        ),
    };
    assert_eq!(
        request_extensions_msg.requested_extensions,
        Seq064K::new(required_extensions.clone()).unwrap()
    );

    // Verify RequestExtensionsSuccess acknowledges the extension
    let request_extensions_success_msg = pool_translator_sniffer.next_message_from_upstream();
    match request_extensions_success_msg {
        Some((
            _,
            AnyMessage::Extensions(Extensions::ExtensionsNegotiation(
                ExtensionsNegotiation::RequestExtensionsSuccess(msg),
            )),
        )) => {
            assert_eq!(
                msg.supported_extensions,
                Seq064K::new(required_extensions).unwrap()
            );
        }
        _ => panic!("Expected RequestExtensionsSuccess message"),
    }

    pool_translator_sniffer
        .wait_for_message_type(
            MessageDirection::ToUpstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        )
        .await;

    // The CHANNEL carries the provisional sentinel, not the miner's identity — and that is the
    // point of `open_channel_on_subscribe`, which every production node runs.
    //
    // A serialising SV1 client waits for the subscribe response before it authorises, so the
    // channel has to open at subscribe, before any user_identity is known. It therefore opens
    // under `PROVISIONAL_CHANNEL_IDENTITY`, and the real payout identity follows in the payee TLV
    // of the binding `UpdateChannel`, asserted below.
    //
    // ⚠ Asserting the miner's username here instead would pass only with the flag OFF, i.e. only
    // in the configuration where the miner is handed a placeholder extranonce and every share it
    // submits is invalid. A green assertion bought at the cost of the test never reaching a
    // single share.
    let open_channel_msg = pool_translator_sniffer.next_message_from_downstream();
    match open_channel_msg {
        Some((_, AnyMessage::Mining(Mining::OpenExtendedMiningChannel(msg)))) => {
            let user_identity = msg.user_identity.as_utf8_or_hex();
            assert_eq!(user_identity, PROVISIONAL_CHANNEL_IDENTITY.to_string());
        }
        _ => panic!(
            "received unexpected message: {:?}",
            pool_translator_sniffer.next_message_from_downstream()
        ),
    }

    pool_translator_sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
        )
        .await;

    // The miner's identity reaches the node pool when it authorises: the translator binds the
    // provisional channel with an `UpdateChannel` carrying the Ghost payee TLV (extension 0x4748),
    // and only then does the pool build the channel a job, since a job credits its payee.
    //
    // ⚠ This used to assert the 0x0002 user_identity TLV on a `SubmitSharesExtended`. The node
    // pool floors every channel at difficulty 2^10 (about 2^42 hashes a share), so minerd, a CPU
    // miner taking its SV1 difficulty from the channel, never submits a share in the life of the
    // test, and the translator forwards none. The per-share TLV is covered by the translator's
    // unit tests (`channel_manager.rs`); what a CPU miner CAN show end to end is the binding.
    pool_translator_sniffer
        .wait_for_message_type(MessageDirection::ToUpstream, MESSAGE_TYPE_UPDATE_CHANNEL)
        .await;
    let payee = loop {
        match pool_translator_sniffer.next_message_from_downstream_with_tlvs() {
            Some((_, AnyMessage::Mining(Mining::UpdateChannel(msg)), tlv_fields)) => {
                info!("UpdateChannel received - channel_id: {}", msg.channel_id);
                let tlvs = tlv_fields.expect("the binding UpdateChannel carries TLV fields");
                let payee = tlvs
                    .iter()
                    .find(|tlv| {
                        tlv.r#type.extension_type == AGENT_TLV_EXTENSION_TYPE
                            && tlv.r#type.field_type == PAYEE_TLV_FIELD_TYPE
                    })
                    .expect("the payee TLV (0x4748) is present");
                break String::from_utf8(payee.value.clone()).expect("the payee is UTF-8");
            }
            Some(_) => continue,
            None => panic!("UpdateChannel was seen going upstream, then not found"),
        }
    };
    // The FULL `<address>.<worker>` identity, not just the worker half: under
    // `open_channel_on_subscribe` the channel opened on the provisional sentinel, so this is where
    // the payout address travels.
    assert_eq!(
        payee, MINER_USERNAME,
        "the payee TLV carries the full identity"
    );

    // Bound, the channel gets its first job.
    pool_translator_sniffer
        .wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
        )
        .await;
    shutdown_all!(translator, pool);
}
