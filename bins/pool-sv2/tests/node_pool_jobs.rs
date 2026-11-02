//! Node pool job layer on real SV2 channels: the coinbase a miner is handed carries the
//! `GhostShare/v2` tag of the job's preimage, the parent anchor in the payout-tag slot, the slot
//! class its miner was sensed at, and a fresh tag after an anchor publish or a class change.
//!
//! This drives the vendored `channels_sv2` channels directly, as the channel manager does, with
//! no network and no bitcoind: the full SV2 harness (`tests/integration-sv2`) needs a template
//! provider that emits Ghost's `GHPP`/`GHNT` prefix and a download of Bitcoin Core, so it cannot
//! reach an active node pool template.

use ghost_common::{
    coinbase_tags::{encode_node_tag, encode_payout_tag, extract_node_tag, extract_payout_tag},
    share_commit::ShareTagPreimage,
    slot_class_sensing::ShareVerdict,
};
use pool_sv2::node_pool::{AnchorUpdate, ChannelKey, ChannelKind, NodePool};
use stratum_apps::stratum_core::{
    bitcoin::{consensus::deserialize, transaction::TxOut, Amount, ScriptBuf, Target, Transaction},
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

/// A template as ghost-mining shapes it at height 960,000: height, `GHPP`, `GHNT`.
fn ghost_template(id: u64, future: bool) -> NewTemplate<'static> {
    let mut p = vec![0x03, 0x00, 0xa6, 0x0e];
    p.extend(encode_payout_tag(&[0xC3; 16]));
    p.extend(encode_node_tag(&[0xD4; 20]));
    let mut witness = vec![0u8; 8];
    witness.extend([38, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
    witness.extend([0x11; 32]);
    NewTemplate {
        template_id: id,
        future_template: future,
        version: 0x2000_0000,
        coinbase_tx_version: 2,
        coinbase_prefix: p.try_into().unwrap(),
        coinbase_tx_input_sequence: 0xffff_fffe,
        coinbase_tx_value_remaining: SATS,
        coinbase_tx_outputs_count: 1,
        coinbase_tx_outputs: witness.try_into().unwrap(),
        coinbase_tx_locktime: 0,
        merkle_path: vec![].try_into().unwrap(),
    }
}

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
    channel
        .on_new_template(np.prepare_template(&template), reward())
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
    let np = NodePool::from_parts(NODE, 960_000, 60.0, 2);
    let template = ghost_template(1, true);
    assert!(np.template_is_active(&template));
    np.on_new_template(&template);

    // The same channel today, untouched, for the length comparison.
    let mut today = extended();
    today.on_new_template(template.clone(), reward()).unwrap();
    today.on_set_new_prev_hash(prev_hash(1)).unwrap();
    let todays = coinbase(&today, &today.get_active_job().unwrap());

    // Open: the translator's agent arrives, the channel is stamped and its future job built.
    let mut channel = extended();
    np.note_agent(KEY, Some("Avalon Nano 3s".into()));
    let stamp = np.stamp(
        KEY,
        ChannelKind::Extended,
        &format!("{ADDR}.rig1"),
        channel.get_target(),
    );
    channel.set_tier_commitment(Some(stamp));
    channel
        .on_new_template(np.prepare_template(&template), reward())
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
    let np = NodePool::from_parts(NODE, 960_000, 60.0, 20);
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
    channel
        .on_new_template(np.prepare_template(&template), reward())
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
