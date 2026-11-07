//! The solo coinbase on real SV2 channels: two miners on two channels at once, each mining a
//! block on its own job, and each block's coinbase paying exactly the treasury `subsidy / 200`
//! and that channel's miner `subsidy - subsidy / 200 + fees`, nothing else but the witness
//! commitment.
//!
//! This drives the vendored `channels_sv2` channels directly, as the channel manager does, with
//! no network and no bitcoind, on regtest's easiest target so a block is found in a few nonces.

use std::sync::Arc;

use ghost_common::{
    coinbase_tags::{encode_node_tag, encode_payout_tag, extract_node_tag, extract_payout_tag},
    solo::{subsidy, Halving, SoloNetwork, TREASURY_SCRIPT},
};
use pool_sv2::solo::{ChannelKey, ChannelKind, Solo};
use stratum_apps::stratum_core::{
    bitcoin::{consensus::deserialize, Target, Transaction},
    channels_sv2::server::{
        extended::ExtendedChannel,
        jobs::{extended::ExtendedJob, job_store::DefaultJobStore, standard::StandardJob},
        share_accounting::ShareValidationResult,
        standard::StandardChannel,
    },
    mining_sv2::{SubmitSharesExtended, SubmitSharesStandard},
    template_distribution_sv2::{NewTemplate, SetNewPrevHash},
};

const HEIGHT: u32 = 960_000;
const FEES: u64 = 54_321;
const MINER_A: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const MINER_B: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
/// Regtest's proof-of-work limit: about every other hash is a block.
const EASY_BITS: u32 = 0x207f_ffff;

type Extended = ExtendedChannel<'static, DefaultJobStore<ExtendedJob<'static>>>;
type Standard = StandardChannel<'static, DefaultJobStore<StandardJob<'static>>>;

/// A template as ghost-mining shapes it: height, the `GHPP` and `GHNT` placeholders, the whole
/// value (subsidy and fees), and the witness commitment as its only output.
fn template(id: u64) -> NewTemplate<'static> {
    let mut p = vec![0x03];
    p.extend(&HEIGHT.to_le_bytes()[..3]);
    p.extend(encode_payout_tag(&[0; 16]));
    p.extend(encode_node_tag(&[0xD4; 20]));
    let mut witness = vec![0u8; 8];
    witness.extend([38, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]);
    witness.extend([0x11; 32]);
    NewTemplate {
        template_id: id,
        future_template: true,
        version: 0x2000_0000,
        coinbase_tx_version: 2,
        coinbase_prefix: p.try_into().unwrap(),
        coinbase_tx_input_sequence: 0xffff_fffe,
        coinbase_tx_value_remaining: subsidy(HEIGHT, Halving::MAINNET) + FEES,
        coinbase_tx_outputs_count: 1,
        coinbase_tx_outputs: witness.try_into().unwrap(),
        coinbase_tx_locktime: 0,
        merkle_path: vec![].try_into().unwrap(),
    }
}

fn prev_hash(id: u64) -> SetNewPrevHash<'static> {
    SetNewPrevHash {
        template_id: id,
        prev_hash: [5u8; 32].into(),
        header_timestamp: 1_800_000_000,
        n_bits: EASY_BITS,
        target: [0xff; 32].into(),
    }
}

fn extended(id: u32, identity: &str) -> Extended {
    ExtendedChannel::new_for_pool(
        id,
        identity.to_string(),
        vec![7u8, 0, 0, id as u8],
        Target::from_le_bytes([0xff; 32]),
        1.0e12,
        true,
        16,
        100,
        60.0,
        DefaultJobStore::new(),
        "- G H O S T -".to_string(),
    )
    .unwrap()
}

fn standard(id: u32, identity: &str) -> Standard {
    StandardChannel::new_for_pool(
        id,
        identity.to_string(),
        vec![9u8; 20],
        Target::from_le_bytes([0xff; 32]),
        1.0e12,
        100,
        60.0,
        DefaultJobStore::new(),
        "- G H O S T -".to_string(),
    )
    .unwrap()
}

/// Mine on an extended channel's active job until a block is found: its coinbase and header.
fn mine_extended(channel: &mut Extended, job_id: u32) -> (Vec<u8>, Vec<u8>) {
    for nonce in 0..10_000u32 {
        let share = SubmitSharesExtended {
            channel_id: channel.get_channel_id(),
            sequence_number: nonce,
            job_id,
            nonce,
            ntime: 1_800_000_001,
            version: 0x2000_0000,
            extranonce: vec![0u8; 16].try_into().unwrap(),
        };
        if let Ok(ShareValidationResult::BlockFound(_, Some(_), coinbase, header80)) =
            channel.validate_share(share)
        {
            return (coinbase, header80);
        }
    }
    panic!("no block in 10,000 nonces on the easiest target");
}

fn mine_standard(channel: &mut Standard, job_id: u32) -> (Vec<u8>, Vec<u8>) {
    for nonce in 0..10_000u32 {
        let share = SubmitSharesStandard {
            channel_id: channel.get_channel_id(),
            sequence_number: nonce,
            job_id,
            nonce,
            ntime: 1_800_000_001,
            version: 0x2000_0000,
        };
        if let Ok(ShareValidationResult::BlockFound(_, Some(_), coinbase, header80)) =
            channel.validate_share(share)
        {
            return (coinbase, header80);
        }
    }
    panic!("no block in 10,000 nonces on the easiest target");
}

fn script_of(identity: &str) -> Vec<u8> {
    Solo::payee_for_identity(identity).unwrap()
}

/// What a block's coinbase must pay `miner`: the treasury, the miner, the witness commitment.
fn assert_pays(tx: &Transaction, miner: &[u8]) {
    let s = subsidy(HEIGHT, Halving::MAINNET);
    assert_eq!(s, 312_500_000);
    assert_eq!(tx.output.len(), 3, "treasury, miner, witness commitment");
    assert_eq!(
        tx.output[0].script_pubkey.as_bytes(),
        TREASURY_SCRIPT.as_slice()
    );
    assert_eq!(tx.output[0].value.to_sat(), s / 200);
    assert_eq!(tx.output[0].value.to_sat(), 1_562_500);
    assert_eq!(tx.output[1].script_pubkey.as_bytes(), miner);
    assert_eq!(tx.output[1].value.to_sat(), s - s / 200 + FEES);
    assert_eq!(tx.output[2].value.to_sat(), 0);
    assert!(tx.output[2]
        .script_pubkey
        .as_bytes()
        .starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]));
    // No share-chain tags in the scriptSig.
    let sig = tx.input[0].script_sig.to_bytes();
    assert_eq!(extract_node_tag(&sig), None);
    assert_eq!(extract_payout_tag(&sig), None);
}

#[test]
fn two_miners_on_two_channels_each_mine_a_block_that_pays_them() {
    let solo = Arc::new(Solo::new(SoloNetwork::Mainnet));
    let t = template(1);
    solo.on_new_template(&t);
    let prepared = solo.prepare_template(&t);

    // Miner A on an extended channel, miner B on a standard channel, at the same time.
    let key_a: ChannelKey = (1, 1);
    let key_b: ChannelKey = (2, 1);
    let ident_a = format!("{MINER_A}.rig1");
    let ident_b = format!("{MINER_B}.rig2");
    let mut a = extended(1, &ident_a);
    let mut b = standard(1, &ident_b);

    let outs_a = solo
        .job_outputs(key_a, ChannelKind::Extended, &ident_a, &t)
        .unwrap();
    a.on_new_template(prepared.clone(), outs_a).unwrap();
    let job_a = a.get_future_job_id_from_template_id(1).unwrap();
    solo.bind_job(key_a, job_a);

    let outs_b = solo
        .job_outputs(key_b, ChannelKind::Standard, &ident_b, &t)
        .unwrap();
    b.on_new_template(prepared, outs_b).unwrap();
    let job_b = b.get_future_job_id_from_template_id(1).unwrap();
    solo.bind_job(key_b, job_b);

    a.on_set_new_prev_hash(prev_hash(1)).unwrap();
    b.on_set_new_prev_hash(prev_hash(1)).unwrap();
    solo.on_set_new_prev_hash(&prev_hash(1));

    let (cb_a, header_a) = mine_extended(&mut a, job_a);
    let (cb_b, header_b) = mine_standard(&mut b, job_b);
    let tx_a: Transaction = deserialize(&cb_a).unwrap();
    let tx_b: Transaction = deserialize(&cb_b).unwrap();
    assert_pays(&tx_a, &script_of(MINER_A));
    assert_pays(&tx_b, &script_of(MINER_B));

    // The post-submit check agrees, and refuses one miner's block checked as the other's job.
    let paid = solo.check_block(key_a, job_a, &tx_a).unwrap();
    assert_eq!((paid.treasury, paid.fees), (1_562_500, FEES));
    assert!(solo.check_block(key_b, job_b, &tx_b).is_ok());
    assert!(solo.check_block(key_b, job_b, &tx_a).is_err());

    // Submitted first, then recorded: both blocks are on the list with their finders' rewards.
    for (key, job, cb, header, ident) in [
        (key_a, job_a, &cb_a, &header_a, &ident_a),
        (key_b, job_b, &cb_b, &header_b, &ident_b),
    ] {
        let mut submitted = None;
        let ok = solo
            .submit_then_check(key, job, Some(1), cb, header, ident, |tid| {
                submitted = Some(tid);
                Ok::<(), ()>(())
            })
            .unwrap();
        assert!(ok);
        assert_eq!(submitted, Some(1), "the template provider gets it first");
    }
    let blocks = solo.blocks_found().all();
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].address, MINER_A);
    assert_eq!(blocks[1].address, MINER_B);
    assert_eq!(blocks[0].worker, "rig1");
    for blk in &blocks {
        assert_eq!(blk.height, HEIGHT);
        assert_eq!(blk.reward_sats, 312_500_000 - 1_562_500 + FEES);
        assert_eq!(blk.treasury_sats, 1_562_500);
        assert_eq!(blk.fees_sats, FEES);
    }
}

#[test]
fn a_channel_without_a_payout_address_gets_no_job() {
    let solo = Solo::new(SoloNetwork::Mainnet);
    let t = template(1);
    for bad in [
        "",
        "rig1",
        "sri/donate",
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
    ] {
        assert!(
            solo.job_outputs((9, 9), ChannelKind::Extended, bad, &t)
                .is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(
        Solo::payee_for_identity("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
        Err("payout-address-type-refused"),
        "P2PKH is refused"
    );
}

#[test]
fn a_template_paying_anyone_else_is_refused() {
    let solo = Solo::new(SoloNetwork::Mainnet);
    let mut t = template(1);
    // An output with value: a template provider that pays someone itself.
    let mut out = 1_000u64.to_le_bytes().to_vec();
    out.extend([22, 0x00, 0x14]);
    out.extend([0x22; 20]);
    t.coinbase_tx_outputs = out.try_into().unwrap();
    assert!(solo.template_parts(&t).is_err());
    // A template worth less than the subsidy.
    let mut t = template(1);
    t.coinbase_tx_value_remaining = 1;
    assert!(solo.template_parts(&t).is_err());
}
