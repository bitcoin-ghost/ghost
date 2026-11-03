//! The channel manager's template path under a held tip, driven through its real handlers with a
//! real group channel and a real extended channel behind a downstream with no connection.
//!
//! The 24 h signet soak (node0, after 6 h) shut `pool_sv2` down on this sequence:
//!
//! 1. `NewTemplate(6775, future)`: no snapshot table within 2 s, not served.
//! 2. `SetNewPrevHash(6775)`: the tip is held for its table.
//! 3. `NewTemplate(6776, future)`, same height: the table arrived meanwhile, served; every
//!    channel got a future job on 6776.
//! 4. The tick serves the held tip: it replays 6775 as a future template and activates it, and
//!    activating a template drops every other future job: 6776 was gone from every channel.
//! 5. `SetNewPrevHash(6776)`: the group channel held no future job, `TemplateIdNotFound`, and
//!    the template path escalated that to `Action::Shutdown`: every miner on the node dropped.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use async_channel::Receiver;
use ghost_common::{
    canonical_payout::{subsidy, Balance, Halving, Table},
    coinbase_tags::{encode_node_tag, encode_payout_tag, node_commitment_plain},
    node_pool_network::{NetworkStart, NodePoolNetwork, StartSource},
    node_pool_u256::U256,
};
use ghost_np_relay::{
    net::TableRequest,
    relay::{RelayStats, RelayStatus},
    settlement::SettlementStatus,
};
use ghost_storage::Database;
use stratum_apps::stratum_core::{
    bitcoin::Target,
    channels_sv2::server::{
        extended::ExtendedChannel,
        jobs::{extended::ExtendedJob, job_store::DefaultJobStore, JobOrigin},
    },
    handlers_sv2::HandleTemplateDistributionMessagesFromServerAsync,
    parsers_sv2::Mining,
    template_distribution_sv2::{NewTemplate, SetNewPrevHash},
};
use tokio::sync::{mpsc, watch};

use super::ChannelManager;
use crate::{
    downstream::Downstream,
    node_pool::{AnchorUpdate, NodePool},
    node_pool_api::NodePoolApi,
    node_pool_relay::RelayParts,
    utils::DownstreamMessage,
};

const NODE: [u8; 32] = [0x7A; 32];
/// The miner's payee: a bech32 P2WPKH address (BIP173 test vector).
const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
/// The operator's fee address (BIP173 P2WSH test vector).
const FEE: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
const H: u32 = 960_000;
const DOWNSTREAM: usize = 1;
const CHANNEL: u32 = 1;

fn pool() -> NodePool {
    NodePool::from_parts(NODE, NodePool::fee_script(FEE).unwrap(), 60.0, 2)
}

fn api() -> NodePoolApi {
    let db = Arc::new(Database::in_memory().unwrap());
    let (_s, status) = watch::channel(RelayStatus {
        best: [0; 32],
        height: 0,
        work: U256::pow2(20).unwrap(),
        btc_height: 0,
        t_net: 10,
        loose: 0,
        unseen: 0,
        peers: 0,
        stats: RelayStats::default(),
    });
    let (_t, settlement) = watch::channel(SettlementStatus::default());
    let parts = RelayParts {
        db,
        start: NetworkStart {
            network: NodePoolNetwork::Regtest,
            genesis_anchor: [0xEE; 32],
            genesis_btc_height: 0,
            pinned_table_digest: None,
            source: StartSource::Config,
        },
        genesis_tier: 10,
        genesis_table_digest: [0x42; 32],
        status,
        settlement,
        checkpoint_depth: 288,
        prune: true,
    };
    NodePoolApi::new(parts, FEE.into(), Arc::new(pool()))
}

fn table() -> Table {
    (0..3u8)
        .map(|i| {
            let mut script = vec![0x51, 0x20];
            script.extend_from_slice(&[i + 1; 32]);
            (
                script,
                Balance {
                    owed: (5_000 + i as i128) * ghost_common::node_pool_constants::FACE_PER_SAT,
                    queue_since: Some(900_000),
                },
            )
        })
        .collect()
}

/// A relay that answers every table request while `ready` is set, and `None` otherwise.
fn relay(np: &NodePool, ready: Arc<AtomicBool>) {
    let (tx, mut rx) = mpsc::channel::<TableRequest>(16);
    np.set_table_source(tx);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let t = ready.load(Ordering::SeqCst).then(|| Arc::new(table()));
            let _ = req.reply.send(t);
        }
    });
    np.anchor_driver().publish(AnchorUpdate {
        parent_anchor: [1; 32],
        batch_root: [1; 32],
    });
}

/// A template as the node pool's template provider sends it at height `h`: both Ghost tags in
/// the prefix, the whole value, the witness commitment as its only output.
fn template(id: u64, h: u32, future: bool) -> NewTemplate<'static> {
    let mut prefix = vec![0x03];
    prefix.extend_from_slice(&h.to_le_bytes()[..3]);
    prefix.extend_from_slice(&encode_payout_tag(&[0xC3; 16]));
    prefix.extend_from_slice(&encode_node_tag(&node_commitment_plain(&NODE)));
    let mut w = vec![0u8; 8];
    w.push(38);
    w.extend(ghost_common::canonical_payout::witness_script(&[0x11; 32]));
    NewTemplate {
        template_id: id,
        future_template: future,
        version: 0x2000_0000,
        coinbase_tx_version: 2,
        coinbase_prefix: prefix.try_into().unwrap(),
        coinbase_tx_input_sequence: 0xffff_ffff,
        coinbase_tx_value_remaining: subsidy(h, Halving::MAINNET) + 1_000,
        coinbase_tx_outputs_count: 1,
        coinbase_tx_outputs: w.try_into().unwrap(),
        coinbase_tx_locktime: 0,
        merkle_path: vec![].try_into().unwrap(),
    }
}

fn prev_hash(id: u64, tip: u8) -> SetNewPrevHash<'static> {
    SetNewPrevHash {
        template_id: id,
        prev_hash: [tip; 32].into(),
        header_timestamp: 1_793_733_160,
        n_bits: 0x1e03_77ae,
        target: [0xff; 32].into(),
    }
}

fn extended_channel() -> ExtendedChannel<'static, DefaultJobStore<ExtendedJob<'static>>> {
    ExtendedChannel::new_for_pool(
        CHANNEL,
        format!("{ADDR}.rig"),
        vec![0, 0, 0, 1],
        Target::MAX,
        1e12,
        true,
        4,
        100,
        6.0,
        DefaultJobStore::new(),
        String::new(),
    )
    .expect("channel must build")
}

/// A channel manager on tip `1` (template 1, height `H`), with one downstream holding one
/// extended channel that mines a job on tip `2` (template 2, height `H + 1`). Returns it, the
/// relay's readiness switch and what the downstream receives.
async fn world() -> (ChannelManager, Arc<AtomicBool>, Receiver<DownstreamMessage>) {
    let np = pool();
    let ready = Arc::new(AtomicBool::new(true));
    relay(&np, ready.clone());
    let mut cm = ChannelManager::for_tests(np, api());
    cm.handle_new_template(None, template(1, H, true), None)
        .await
        .unwrap();
    cm.handle_set_new_prev_hash(None, prev_hash(1, 1), None)
        .await
        .unwrap();
    let group = cm.bootstrap_group_channel(0).expect("group channel");
    let downstream = Downstream::for_tests(DOWNSTREAM, group);
    downstream.downstream_data.super_safe_lock(|d| {
        d.extended_channels.insert(CHANNEL, extended_channel());
    });
    let (tx, rx) = async_channel::unbounded();
    cm.channel_manager_channel
        .downstream_sender
        .super_safe_lock(|m| m.insert(DOWNSTREAM, tx));
    cm.channel_manager_data
        .super_safe_lock(|d| d.downstream.insert(DOWNSTREAM, downstream));

    cm.handle_new_template(None, template(2, H + 1, true), None)
        .await
        .unwrap();
    cm.handle_set_new_prev_hash(None, prev_hash(2, 2), None)
        .await
        .unwrap();
    let sent = drain(&rx);
    assert_eq!(active_template(&cm), Some(2), "the channel mines on tip 2");
    assert!(
        matches!(sent.last(), Some(Mining::SetNewPrevHash(_))),
        "{sent:?}"
    );
    (cm, ready, rx)
}

fn drain(rx: &Receiver<DownstreamMessage>) -> Vec<Mining<'static>> {
    std::iter::from_fn(|| rx.try_recv().ok().map(|(m, _)| m)).collect()
}

/// The template the extended channel's active job was built from.
fn active_template(cm: &ChannelManager) -> Option<u64> {
    cm.channel_manager_data.super_safe_lock(|d| {
        d.downstream[&DOWNSTREAM]
            .downstream_data
            .super_safe_lock(|d| {
                match d.extended_channels[&CHANNEL].get_active_job()?.get_origin() {
                    JobOrigin::NewTemplate(t) => Some(t.template_id),
                    JobOrigin::SetCustomMiningJob(_) => None,
                }
            })
    })
}

/// The job id of the last `NewExtendedMiningJob` in `sent`, and the job id the last
/// `SetNewPrevHash` in it activates.
fn last_job_and_activation(sent: &[Mining<'static>]) -> (Option<u32>, Option<u32>) {
    let job = sent.iter().rev().find_map(|m| match m {
        Mining::NewExtendedMiningJob(j) => Some(j.job_id),
        _ => None,
    });
    let activated = sent.iter().rev().find_map(|m| match m {
        Mining::SetNewPrevHash(p) => Some(p.job_id),
        _ => None,
    });
    (job, activated)
}

/// The soak's sequence, message for message. The pool must stay up, and the `SetNewPrevHash`
/// for the future template that arrived during the hold must move the miner to that template's
/// job at once: no repair hold, no mismatch.
#[tokio::test]
async fn a_future_template_that_arrives_while_the_tip_is_held_survives_its_replay() {
    let (mut cm, ready, rx) = world().await;
    let np = cm.node_pool();

    // 6775: no table in time; its tip is held.
    ready.store(false, Ordering::SeqCst);
    cm.handle_new_template(None, template(6775, H + 2, true), None)
        .await
        .unwrap();
    cm.handle_set_new_prev_hash(None, prev_hash(6775, 3), None)
        .await
        .unwrap();
    assert!(np.pending_tip().is_some(), "the tip is held");
    assert!(
        drain(&rx).is_empty(),
        "the miner keeps its current job while held"
    );

    // 6776, same height, served: the table arrived meanwhile.
    ready.store(true, Ordering::SeqCst);
    cm.handle_new_template(None, template(6776, H + 2, true), None)
        .await
        .unwrap();

    // The tick serves the held tip before 6776's SetNewPrevHash is read.
    cm.node_pool_tick().await;
    assert!(np.pending_tip().is_none(), "the held tip is served");
    assert_eq!(active_template(&cm), Some(6775));

    // 6776's SetNewPrevHash: used to be `TemplateIdNotFound` from the group channel, escalated
    // to `Action::Shutdown`.
    cm.handle_set_new_prev_hash(None, prev_hash(6776, 3), None)
        .await
        .expect("a SetNewPrevHash for a template that arrived during the hold is handled");
    assert_eq!(
        active_template(&cm),
        Some(6776),
        "the channel mines the template the prev hash names"
    );
    assert!(
        np.pending_tip().is_none(),
        "no repair was needed: the channels held 6776"
    );
    let sent = drain(&rx);
    let (job, activated) = last_job_and_activation(&sent);
    assert!(job.is_some(), "6776's job was given back: {sent:?}");
    assert_eq!(
        activated, job,
        "the miner is told to mine 6776's job on the new tip"
    );
}

/// The hold outlives several templates: a future template that is itself not served, then a
/// served one, then the tick, then both prev hashes in order. Nothing shuts down and the miner
/// ends on the last template.
#[tokio::test]
async fn several_templates_during_one_hold_replay_in_order() {
    let (mut cm, ready, rx) = world().await;
    let np = cm.node_pool();
    ready.store(false, Ordering::SeqCst);
    cm.handle_new_template(None, template(10, H + 2, true), None)
        .await
        .unwrap();
    cm.handle_set_new_prev_hash(None, prev_hash(10, 3), None)
        .await
        .unwrap();
    // Unserved too: its tip replaces the held one when its prev hash comes.
    cm.handle_new_template(None, template(11, H + 2, true), None)
        .await
        .unwrap();
    ready.store(true, Ordering::SeqCst);
    cm.handle_new_template(None, template(12, H + 2, true), None)
        .await
        .unwrap();
    cm.node_pool_tick().await;
    assert!(np.pending_tip().is_none());
    cm.handle_set_new_prev_hash(None, prev_hash(12, 3), None)
        .await
        .expect("handled");
    assert_eq!(active_template(&cm), Some(12));
    let (job, activated) = last_job_and_activation(&drain(&rx));
    assert_eq!(activated, job);
    assert!(job.is_some());
}

/// Defence in depth: a `SetNewPrevHash` naming a template the channels do not hold never shuts
/// the pool down. A template the job layer knows is rebuilt for every channel on the next tick;
/// one it does not know leaves the miners on their current job.
#[tokio::test]
async fn a_prev_hash_for_a_template_the_channels_lost_is_repaired_not_fatal() {
    let (mut cm, _ready, rx) = world().await;
    let np = cm.node_pool();
    cm.handle_new_template(None, template(20, H + 2, true), None)
        .await
        .unwrap();
    // Every channel loses template 20: something activated another template in between (the
    // shape of the soak's crash, without the hold).
    cm.handle_new_template(None, template(21, H + 2, true), None)
        .await
        .unwrap();
    cm.channel_manager_data.super_safe_lock(|d| {
        d.downstream[&DOWNSTREAM]
            .downstream_data
            .super_safe_lock(|d| {
                d.group_channel
                    .on_set_new_prev_hash(prev_hash(21, 3))
                    .unwrap();
                d.extended_channels
                    .get_mut(&CHANNEL)
                    .unwrap()
                    .on_set_new_prev_hash(prev_hash(21, 3))
                    .unwrap();
            })
    });
    drain(&rx);

    // Unknown to the job layer too: logged, the miner keeps its job, nothing is held.
    cm.handle_set_new_prev_hash(None, prev_hash(999, 4), None)
        .await
        .expect("an unknown template is not fatal");
    assert!(np.pending_tip().is_none());
    assert!(
        drain(&rx).is_empty(),
        "no SetNewPrevHash on a job the miner was never given"
    );

    // Known to the job layer: held for repair, rebuilt on the next tick.
    cm.handle_set_new_prev_hash(None, prev_hash(20, 3), None)
        .await
        .expect("a template the channels lost is not fatal");
    assert!(np.pending_tip().is_some(), "held for repair");
    assert!(drain(&rx).is_empty());
    cm.node_pool_tick().await;
    assert!(np.pending_tip().is_none(), "repaired");
    assert_eq!(active_template(&cm), Some(20));
    let (job, activated) = last_job_and_activation(&drain(&rx));
    assert!(job.is_some());
    assert_eq!(activated, job);
}
