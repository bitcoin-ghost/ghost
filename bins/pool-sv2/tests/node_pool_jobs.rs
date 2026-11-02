//! Node pool job layer on real SV2 channels: the coinbase a miner is handed carries the
//! `GhostShare/v2` tag of the job's preimage, the parent anchor in the payout-tag slot, the slot
//! class its miner was sensed at, a fresh tag after an anchor publish or a class change, and
//! exactly the canonical outputs of its slot class (the reference's 503/504-output goldens).
//!
//! This drives the vendored `channels_sv2` channels directly, as the channel manager does, with
//! no network and no bitcoind: the full SV2 harness (`tests/integration-sv2`) needs a template
//! provider that emits Ghost's `GHPP`/`GHNT` prefix and a download of Bitcoin Core, so it cannot
//! reach an active node pool template.

use std::sync::Arc;

use ghost_common::{
    canonical_payout::{
        coinbase_outputs, outputs_bytes, outputs_digest, subsidy, Balance, CoinbaseOutput, Table,
    },
    coinbase_tags::{encode_node_tag, encode_payout_tag, extract_node_tag, extract_payout_tag},
    node_pool_constants::{FACE_PER_SAT, SLOT_CLASSES},
    share_commit::ShareTagPreimage,
    slot_class_sensing::{MinerIdentity, ShareVerdict},
};
use pool_sv2::node_pool::{AnchorUpdate, ChannelKey, ChannelKind, NodePool};
use stratum_apps::stratum_core::{
    bitcoin::{
        consensus::deserialize,
        hashes::{sha256, Hash},
        transaction::TxOut,
        Amount, ScriptBuf, Target, Transaction,
    },
    channels_sv2::server::{
        extended::ExtendedChannel,
        jobs::{extended::ExtendedJob, job_store::DefaultJobStore, standard::StandardJob},
        standard::StandardChannel,
    },
    template_distribution_sv2::{NewTemplate, SetNewPrevHash},
};

const NODE: [u8; 32] = [0x7A; 32];
const SATS: u64 = 312_500_000;
const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const KEY: ChannelKey = (1, 1);

type Extended = ExtendedChannel<'static, DefaultJobStore<ExtendedJob<'static>>>;
type Standard = StandardChannel<'static, DefaultJobStore<StandardJob<'static>>>;

/// A template as ghost-mining shapes it at height 960,000: height, `GHPP`, `GHNT`, the whole
/// value, and the witness commitment as its only output.
fn ghost_template(id: u64, future: bool) -> NewTemplate<'static> {
    template_at(id, future, 960_000, SATS, [0x11; 32])
}

fn template_at(
    id: u64,
    future: bool,
    height: u32,
    value: u64,
    witness_commitment: [u8; 32],
) -> NewTemplate<'static> {
    let mut p = vec![0x03];
    p.extend(&height.to_le_bytes()[..3]);
    p.extend(encode_payout_tag(&[0xC3; 16]));
    p.extend(encode_node_tag(&[0xD4; 20]));
    let mut witness = vec![0u8; 8];
    witness.extend([38, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
    witness.extend(witness_commitment);
    NewTemplate {
        template_id: id,
        future_template: future,
        version: 0x2000_0000,
        coinbase_tx_version: 2,
        coinbase_prefix: p.try_into().unwrap(),
        coinbase_tx_input_sequence: 0xffff_fffe,
        coinbase_tx_value_remaining: value,
        coinbase_tx_outputs_count: 1,
        coinbase_tx_outputs: witness.try_into().unwrap(),
        coinbase_tx_locktime: 0,
        merkle_path: vec![].try_into().unwrap(),
    }
}

/// The reference's `p2tr(tag)`: `OP_1 PUSH32 sha256(tag)`.
fn p2tr(tag: &str) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend(sha256::Hash::hash(tag.as_bytes()).to_byte_array());
    s
}

fn node_pool() -> NodePool {
    NodePool::from_parts(NODE, p2tr("finder"), 60.0, 2)
}

/// A single output for the whole value: a plain SRI channel, for the length comparison only.
fn reward() -> Vec<TxOut> {
    vec![TxOut {
        value: Amount::from_sat(SATS),
        script_pubkey: ScriptBuf::from(NodePool::payee_for_identity(ADDR).unwrap()),
    }]
}

fn prev_hash(id: u64) -> SetNewPrevHash<'static> {
    SetNewPrevHash {
        template_id: id,
        prev_hash: [5u8; 32].into(),
        header_timestamp: 1_800_000_000,
        n_bits: 0x1702_1be5,
        target: [0xff; 32].into(),
    }
}

fn extended() -> Extended {
    ExtendedChannel::new_for_pool(
        KEY.1,
        format!("{ADDR}.rig1"),
        vec![7u8; 4],
        Target::from_le_bytes([0xff; 32]),
        1.0e12,
        true,
        16,
        100,
        60.0,
        DefaultJobStore::new(),
        "GHOST PublicPool".to_string(),
    )
    .unwrap()
}

/// The coinbase a miner would hash for `job`, extranonce zeroed.
fn coinbase(channel: &Extended, job: &ExtendedJob<'static>) -> Transaction {
    let mut raw = job.get_coinbase_tx_prefix_without_bip141();
    raw.extend(job.get_extranonce_prefix());
    raw.extend(vec![0u8; channel.get_rollable_extranonce_size() as usize]);
    raw.extend(job.get_coinbase_tx_suffix_without_bip141());
    deserialize(&raw).expect("the job's coinbase parses")
}

fn script_sig(tx: &Transaction) -> Vec<u8> {
    tx.input[0].script_sig.to_bytes()
}

/// Stamp, build an active job against the active template, bind it, return the job.
fn rebuild(np: &NodePool, channel: &mut Extended) -> ExtendedJob<'static> {
    let template = np.active_template().expect("active template");
    let stamp = np.stamp(
        KEY,
        ChannelKind::Extended,
        &channel.get_user_identity().clone(),
        &channel.get_target().clone(),
    );
    channel.set_tier_commitment(Some(stamp));
    let outputs = np.job_outputs(KEY, &template).unwrap();
    channel
        .on_new_template(np.prepare_template(&template), outputs)
        .unwrap();
    let job = channel.get_active_job().unwrap();
    np.bind_job(KEY, job.get_job_id());
    job
}

fn assert_carries(tx: &Transaction, preimage: &ShareTagPreimage) {
    let sig = script_sig(tx);
    assert_eq!(extract_node_tag(&sig), Some(preimage.tag()));
    assert_eq!(extract_payout_tag(&sig), Some(preimage.parent_anchor_tag()));
}

#[test]
fn the_miner_is_handed_the_tag_of_its_jobs_preimage() {
    let np = node_pool();
    let template = ghost_template(1, true);
    np.on_new_template(&template);

    // The same channel today, untouched, for the length comparison.
    let mut today = extended();
    today.on_new_template(template.clone(), reward()).unwrap();
    today.on_set_new_prev_hash(prev_hash(1)).unwrap();
    let todays = coinbase(&today, &today.get_active_job().unwrap());

    // Open: the translator's agent arrives, the channel is stamped and its future job built.
    let mut channel = extended();
    np.note_identity(KEY, Some(MinerIdentity::Agent("Avalon Nano 3s".into())));
    let stamp = np.stamp(
        KEY,
        ChannelKind::Extended,
        &format!("{ADDR}.rig1"),
        channel.get_target(),
    );
    channel.set_tier_commitment(Some(stamp));
    let outputs = np.job_outputs(KEY, &template).unwrap();
    channel
        .on_new_template(np.prepare_template(&template), outputs)
        .unwrap();
    let future_id = channel.get_future_job_id_from_template_id(1).unwrap();
    np.bind_job(KEY, future_id);
    channel.on_set_new_prev_hash(prev_hash(1)).unwrap();
    np.on_set_new_prev_hash(1);

    let job = channel.get_active_job().unwrap();
    assert_eq!(job.get_job_id(), future_id);
    let tx = coinbase(&channel, &job);
    assert_eq!(
        script_sig(&tx).len(),
        script_sig(&todays).len(),
        "the node pool stamp must not move the scriptSig length"
    );
    let first = np.job_preimage(KEY, future_id).unwrap();
    assert_eq!(
        first.slot_class, 3,
        "an Avalon starts at the smallest class"
    );
    assert_eq!(first.parent_anchor, [0; 32], "no anchor published yet");
    assert_eq!(first.payee_script, reward()[0].script_pubkey.to_bytes());
    assert_carries(&tx, &first);

    // An anchor arrives: the next job carries it.
    np.anchor_driver().publish(AnchorUpdate {
        parent_anchor: [0xA1; 32],
        batch_root: [0xB2; 32],
    });
    let job = rebuild(&np, &mut channel);
    let anchored = np.job_preimage(KEY, job.get_job_id()).unwrap();
    assert_eq!(anchored.parent_anchor, [0xA1; 32]);
    assert_eq!(anchored.batch_root, [0xB2; 32]);
    assert_carries(&coinbase(&channel, &job), &anchored);
    assert_eq!(
        np.job_preimage(KEY, future_id),
        Some(first),
        "older jobs keep their own preimage"
    );

    // Two valid shares pass class 3; the next job is built at class 9.
    assert_eq!(
        np.on_share(KEY, job.get_job_id(), ShareVerdict::Valid),
        None
    );
    let up = np
        .on_share(KEY, job.get_job_id(), ShareVerdict::Valid)
        .unwrap();
    assert_eq!((up.from, up.to), (3, 9));
    let job = rebuild(&np, &mut channel);
    let stepped = np.job_preimage(KEY, job.get_job_id()).unwrap();
    assert_eq!(stepped.slot_class, 9);
    assert_carries(&coinbase(&channel, &job), &stepped);

    // A share that does not recompute drops it back; 9 is not tried again.
    let down = np
        .on_share(KEY, job.get_job_id(), ShareVerdict::Corrupt)
        .unwrap();
    assert_eq!((down.from, down.to), (9, 3));
    let job = rebuild(&np, &mut channel);
    assert_eq!(
        np.job_preimage(KEY, job.get_job_id()).unwrap().slot_class,
        3
    );
    for _ in 0..10 {
        assert_eq!(
            np.on_share(KEY, job.get_job_id(), ShareVerdict::Valid),
            None
        );
    }
}

#[test]
fn a_standard_channel_is_stamped_at_the_full_class() {
    let np = node_pool();
    let template = ghost_template(1, true);
    np.on_new_template(&template);
    let mut channel: Standard = StandardChannel::new_for_pool(
        2,
        ADDR.to_string(),
        vec![9u8; 20],
        Target::from_le_bytes([0xff; 32]),
        1.0e12,
        100,
        60.0,
        DefaultJobStore::new(),
        "GHOST PublicPool".to_string(),
    )
    .unwrap();
    let key = (1, 2);
    let stamp = np.stamp(key, ChannelKind::Standard, ADDR, channel.get_target());
    channel.set_tier_commitment(Some(stamp));
    let outputs = np.job_outputs(key, &template).unwrap();
    channel
        .on_new_template(np.prepare_template(&template), outputs)
        .unwrap();
    let id = channel.get_future_job_id_from_template_id(1).unwrap();
    np.bind_job(key, id);
    let job = channel.get_future_job(id).unwrap();
    let preimage = np.job_preimage(key, id).unwrap();
    assert_eq!(preimage.slot_class, 500);
    let push = job.get_extra_script_sig();
    assert_eq!(extract_node_tag(push), Some(preimage.tag()));
    assert_eq!(extract_payout_tag(push), Some(preimage.parent_anchor_tag()));
}

const VECTORS: &str = include_str!("../../../docs/node-pool-reference/test_vectors_v3.json");

/// The reference's 503/504-output table: 400 small balances and 300 large ones.
fn golden_table(script: fn(&str) -> Vec<u8>, nm: &str) -> Table {
    let mut t = Table::new();
    for i in 0..400u32 {
        let b = Balance {
            owed: (5000 + i as i128) * FACE_PER_SAT,
            queue_since: Some(900_000 + i / 450),
        };
        t.insert(script(&format!("g{nm}{i}")), b);
    }
    for i in 0..300u32 {
        let b = Balance {
            owed: (600_000 + i as i128) * FACE_PER_SAT,
            queue_since: Some(900_100),
        };
        t.insert(script(&format!("top{nm}{i}")), b);
    }
    t
}

fn p2wpkh(tag: &str) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend(&sha256::Hash::hash(tag.as_bytes()).to_byte_array()[..20]);
    s
}

fn outputs_of(tx: &Transaction) -> Vec<CoinbaseOutput> {
    tx.output
        .iter()
        .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect()
}

fn standard(id: u32) -> Standard {
    StandardChannel::new_for_pool(
        id,
        ADDR.to_string(),
        vec![9u8; 20],
        Target::from_le_bytes([0xff; 32]),
        1.0e12,
        100,
        60.0,
        DefaultJobStore::new(),
        "GHOST PublicPool".to_string(),
    )
    .unwrap()
}

/// The coinbase of a standard channel's active job, as the pool reassembles it for a solved
/// share (the miner itself only ever sees the header).
fn standard_coinbase(channel: &Standard) -> Transaction {
    let (prefix, suffix, _) = channel.coinbase_skeleton().expect("an active job");
    let mut raw = prefix;
    raw.extend(channel.get_extranonce_prefix());
    raw.extend(suffix);
    deserialize(&raw).expect("the job's coinbase parses")
}

/// The full class on a real standard channel builds the reference's golden coinbases byte for
/// byte: 504 outputs with the finder, 503 without, for P2TR and P2WPKH payees.
#[test]
fn a_full_class_job_pays_the_reference_goldens() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let h = 974_500;
    let mut seen = 0;
    for v in doc["vectors"].as_array().unwrap() {
        let Some(count) = v.get("coinbase_outputs") else {
            continue;
        };
        let name = v["name"].as_str().unwrap();
        assert_eq!(v["height"].as_u64(), Some(h as u64));
        let table = if name.contains("P2TR") {
            golden_table(p2tr, "t")
        } else {
            golden_table(p2wpkh, "w")
        };
        let finder_script = if name.contains("P2TR") {
            p2tr("finder")
        } else {
            p2wpkh("finder")
        };
        let fees = if name.contains("finder 0") {
            0
        } else {
            123_456
        };
        let np = NodePool::from_parts(NODE, finder_script.clone(), 60.0, 2);
        np.anchor_driver().publish(AnchorUpdate {
            parent_anchor: [0xA1; 32],
            batch_root: [0xB2; 32],
        });
        let template = template_at(9, true, h, subsidy(h) + fees, [0; 32]);
        np.on_new_template(&template);
        np.insert_table([0xA1; 32], h, Arc::new(table.clone()));

        let mut channel = standard(3);
        let key = (4, 3);
        channel.set_tier_commitment(Some(np.stamp(
            key,
            ChannelKind::Standard,
            ADDR,
            channel.get_target(),
        )));
        let outputs = np.job_outputs(key, &template).unwrap();
        channel
            .on_new_template(np.prepare_template(&template), outputs)
            .unwrap();
        let id = channel.get_future_job_id_from_template_id(9).unwrap();
        np.bind_job(key, id);
        channel.on_set_new_prev_hash(prev_hash(9)).unwrap();
        let tx = standard_coinbase(&channel);
        let got = outputs_of(&tx);

        assert_eq!(got.len() as u64, count.as_u64().unwrap(), "{name}");
        assert_eq!(
            hex::encode(outputs_digest(&got)),
            v["output_digest"].as_str().unwrap(),
            "{name}"
        );
        assert_eq!(
            outputs_bytes(&got) as u64,
            v["output_section_bytes"].as_u64().unwrap(),
            "{name}"
        );
        let (want, _) = coinbase_outputs(h, &table, 500, &finder_script, fees, &[0; 32]).unwrap();
        assert_eq!(got, want, "{name}");
        assert_eq!(
            got.iter().filter(|o| o.0 == 0).count(),
            2,
            "{name}: only the two commitments carry no value (no zero-value pool output)"
        );
        assert_eq!(
            got.iter().map(|o| o.0).sum::<u64>(),
            subsidy(h) + fees,
            "{name}"
        );
        assert_eq!(np.check_block(key, id, &tx), Ok(()), "{name}");
        seen += 1;
    }
    assert_eq!(seen, 4, "the four golden vectors");
}

/// Every slot class on a real extended channel: the miner's coinbase pays the canonical outputs
/// of that class, and the submit check accepts exactly that coinbase.
#[test]
fn every_slot_class_job_pays_its_canonical_outputs() {
    let h = 960_000;
    let table = golden_table(p2tr, "t");
    let fees = 777;
    for class in SLOT_CLASSES {
        let np = node_pool();
        np.anchor_driver().publish(AnchorUpdate {
            parent_anchor: [0xA1; 32],
            batch_root: [0xB2; 32],
        });
        let template = template_at(1, false, h, subsidy(h) + fees, [0x11; 32]);
        np.on_new_template(&template);
        np.insert_table([0xA1; 32], h, Arc::new(table.clone()));
        let mut channel = extended();
        // The class is set here directly; the sensing loop that steps a miner through the
        // classes is the test above.
        let stamp = np.stamp(KEY, ChannelKind::Extended, ADDR, channel.get_target());
        channel.set_tier_commitment(Some(stamp));
        let (reward, _) = np.canonical_outputs(&[0xA1; 32], class, &template).unwrap();
        let future = template_at(2, true, h, subsidy(h) + fees, [0x11; 32]);
        channel
            .on_new_template(np.prepare_template(&future), reward)
            .unwrap();
        let id = channel.get_future_job_id_from_template_id(2).unwrap();
        let job = channel.get_future_job(id).unwrap();
        let got = outputs_of(&coinbase(&channel, &job));
        let (want, _) = coinbase_outputs(
            h,
            &table,
            class as usize,
            &p2tr("finder"),
            fees,
            &[0x11; 32],
        )
        .unwrap();
        assert_eq!(got, want, "class {class}");
        assert_eq!(got.len(), class as usize + 4, "class {class}");
    }
}
