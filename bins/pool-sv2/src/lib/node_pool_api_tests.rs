//! Tests for the ledger and status API over a temporary node pool store.

use std::collections::BTreeMap;

use ghost_common::{
    canonical_payout::{build_outputs, select, split_slots, Balance, Halving},
    node_pool_network::{NetworkStart, StartSource},
    node_pool_u256::U256,
    share_commit::ShareTagPreimage,
    slot_class_sensing::{FirmwareWarning, SensingStatus},
};
use ghost_np_relay::{
    relay::{RelayStats, RelayStatus},
    settlement::{SettlementStats, SettlementStatus},
};
use ghost_storage::{
    node_pool_store::{NpAnchorRecord, NpBatchShare, NpCheckpoint, NpShareRecord},
    Database,
};
use stratum_apps::stratum_core::bitcoin::{
    hashes::{sha256d, Hash},
    Network, ScriptBuf,
};
use tokio::sync::watch;

use super::*;

pub(crate) const ONE: i128 = FACE_PER_SAT;
/// The next block's height in these tests.
pub(crate) const NEXT: u32 = 1_000;

pub(crate) fn payee(b: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[b; 20]);
    s
}

pub(crate) fn addr(script: &[u8]) -> String {
    Address::from_script(&ScriptBuf::from_bytes(script.to_vec()), Network::Regtest)
        .unwrap()
        .to_string()
}

pub(crate) struct Fixed {
    pub(crate) table: Option<Arc<Table>>,
    pub(crate) miners: Vec<ChannelStatus>,
}

impl LiveView for Fixed {
    fn miners(&self) -> Vec<ChannelStatus> {
        self.miners.clone()
    }

    fn next_table(&self) -> NextTableFuture<'_> {
        let t = self.table.clone();
        Box::pin(async move {
            Some(NextTable {
                height: NEXT,
                parent_anchor: [0xAA; 32],
                table: t?,
            })
        })
    }
}

fn member(seed: u8, who: &[u8], job_height: u32, face: u128) -> NpBatchShare {
    let mut header = [seed; 80];
    header[0] = 0x20;
    NpBatchShare {
        share: NpShareRecord {
            share_id: sha256d::Hash::hash(&header).to_byte_array(),
            header,
            coinbase: vec![1, 2, 3],
            merkle_branch: vec![],
            tag: ShareTagPreimage {
                node_id: [9; 32],
                tier: 10,
                slot_class: 9,
                payee_script: who.to_vec(),
                parent_anchor: [0xEE; 32],
                batch_root: [0; 32],
            },
            job_height,
        },
        credited_tier: 10,
        face,
    }
}

fn anchor(db: &Database, hash: u8, btc_height: u32) {
    db.np_insert_anchor(&NpAnchorRecord {
        hash: [hash; 32],
        parent: Some([0xEE; 32]),
        height: 1,
        t_net: 10,
        btc_height,
        cum_work: U256::pow2(18).unwrap(),
        batch_root: [hash; 32],
        received_at: 1_000 + hash as i64,
    })
    .unwrap();
}

/// A store where payee 1 is credited by anchor 1's batch (applied) and appears in anchor 2's
/// batch whose credit event is not applied (a losing fork), payee 2 and 3 are credited too,
/// and two blocks paid payee 1: block 0xB1 settled, block 0xB2 provisional.
pub(crate) struct World {
    pub(crate) api: NodePoolApi,
    pub(crate) table: Arc<Table>,
    pub(crate) settlement_tx: watch::Sender<SettlementStatus>,
}

/// Payee 1's exact credit: 9,000 sats and a fraction.
pub(crate) const P1_CREDIT: i128 = 9_000 * ONE + 123_456_789;

pub(crate) fn world() -> World {
    world_on(None)
}

/// The cutover's export height in the genesis worlds.
pub(crate) const EXPORT_H: u64 = 850;

/// A genesis table as the import writes it: payee 1 carried over below the floor, payee 4 above
/// it (and never seen on the share chain since), payee 5 just under it.
pub(crate) fn genesis() -> Table {
    let mut t = Table::new();
    for (who, sats) in [(1u8, 500i128), (4, 3_000), (5, 900)] {
        t.insert(
            payee(who),
            Balance {
                owed: sats * ONE,
                queue_since: (sats >= MIN_PAYOUT_SATS as i128).then_some(EXPORT_H as u32),
            },
        );
    }
    t
}

/// [`world`], on a store whose genesis table is `genesis` (imported before the relay ran, as
/// `--np-import-genesis` does); the next block's table is folded onto it.
pub(crate) fn world_on(genesis: Option<Table>) -> World {
    let db = Arc::new(Database::in_memory().unwrap());
    if let Some(g) = &genesis {
        db.np_import_genesis(
            g,
            &ghost_storage::node_pool_genesis::NpGenesisMeta {
                export_digest: [0x0E; 32],
                network: "regtest".into(),
                export_height: EXPORT_H,
                queue_since: EXPORT_H as u32,
                row_count: g.len() as u64,
                table_root: ghost_common::canonical_payout::table_root(g),
                imported_at: 1_900,
            },
        )
        .unwrap();
    }
    anchor(&db, 1, 900);
    anchor(&db, 2, 901);
    db.np_insert_batch(
        &[1; 32],
        &[
            member(10, &payee(1), 901, P1_CREDIT as u128),
            member(11, &payee(2), 901, 1),
        ],
        2_000,
    )
    .unwrap();
    db.np_insert_batch(&[2; 32], &[member(12, &payee(1), 902, 77)], 3_000)
        .unwrap();
    let mut credits = BTreeMap::new();
    credits.insert(payee(1), P1_CREDIT);
    credits.insert(payee(2), 20_000 * ONE);
    credits.insert(payee(3), 4_000 * ONE);
    db.np_apply_credits(&credit_event_key(&[1; 32], 901), 901, &credits, 2_100)
        .unwrap();
    db.np_apply_block(&[0xB1; 32], 950, &[(payee(1), 1_500 * ONE)], 2_200)
        .unwrap();
    db.np_apply_block(&[0xB2; 32], 960, &[(payee(1), 1_000 * ONE)], 2_300)
        .unwrap();

    // The table the next block pays: the store's own fold at NEXT, or with a genesis table the
    // same events folded onto it, as the relay's `block_table` does.
    let table = Arc::new(match genesis {
        None => db.np_table_for_block(NEXT).unwrap(),
        Some(g) => ghost_common::canonical_payout::table_for_from(
            g,
            NEXT,
            &[(901, credits)].into(),
            &[
                (950, vec![(payee(1), 1_500 * ONE)]),
                (960, vec![(payee(1), 1_000 * ONE)]),
            ]
            .into(),
        )
        .unwrap(),
    });
    let status = RelayStatus {
        best: [0xAB; 32],
        height: 7,
        work: U256::pow2(20).unwrap(),
        btc_height: 998,
        t_net: 10,
        loose: 3,
        unseen: 1,
        peers: 2,
        stats: RelayStats {
            shares_accepted: 40,
            shares_stale: 2,
            shares_invalid: 1,
            anchors_valid: 7,
            anchors_invalid: 0,
            reorgs: 1,
        },
    };
    db.np_put_checkpoint(&NpCheckpoint {
        anchor_hash: [0xC1; 32],
        height: 3,
        btc_height: 700,
        payload: vec![1, 2, 3],
        digest: [0xD1; 32],
        created_at: 1_500,
    })
    .unwrap();
    let (_status_tx, status_rx) = watch::channel(status);
    let (settlement_tx, settlement_rx) = watch::channel(SettlementStatus {
        synced_height: Some(999),
        bitcoin_tip: Some(999),
        provisional: vec![(960, [0xB2; 32])],
        stats: SettlementStats {
            matched: 1,
            provisional: 1,
            ..Default::default()
        },
    });
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
        status: status_rx,
        settlement: settlement_rx,
        checkpoint_depth: 288,
        prune: true,
        tier0_hashes: 4_295_032_833.0,
    };
    let miners = vec![ChannelStatus {
        key: (4, 1),
        kind: ChannelKind::Extended,
        payee_script: payee(1),
        user_identity: format!("{}.rig1", addr(&payee(1))),
        slot_class: 9,
        sensing: Some(SensingStatus {
            agent: Some("bmminer/2.0.0".into()),
            firmware: Some("2.0.0".into()),
            model: "Stock Antminer",
            ceiling_bytes: 730,
            ceiling_class: 9,
            serving_class: 9,
            settled: true,
            highest_passed: Some(9),
            failed: vec![],
            valid_shares: 30,
            warning: Some(FirmwareWarning {
                model: "Stock Antminer",
                limited_to_class: 9,
                ceiling_bytes: 730,
            }),
        }),
    }];
    let live = Arc::new(Fixed {
        table: Some(table.clone()),
        miners,
    });
    World {
        api: NodePoolApi::new(parts, "bcrt1qfee".into(), live),
        table,
        settlement_tx,
    }
}

#[tokio::test]
async fn the_balance_is_exact_in_units_and_floored_in_sats() {
    let w = world();
    let r = w.api.ledger(&addr(&payee(1))).await.unwrap();
    let owed = P1_CREDIT - 1_500 * ONE - 1_000 * ONE;
    assert!(r.known);
    assert_eq!(r.balance.units, owed.to_string());
    assert_eq!(r.balance.sats, 6_500, "floor of {owed} / 2^32");
    assert_eq!(r.units_per_sat, 1u64 << 32);
    assert_eq!(r.min_payout_sats, 1_000);
    assert_eq!(r.queue_since, Some(901));
    assert_eq!(r.script_hex, hex::encode(payee(1)));
    assert_eq!(r.network, "regtest");
}

#[tokio::test]
async fn the_queue_position_is_canonical_payouts_on_the_same_table() {
    let w = world();
    let t = w.table.as_ref();
    for who in [1u8, 2, 3] {
        let script = payee(who);
        let q = w.api.ledger(&addr(&script)).await.unwrap().queue.unwrap();
        assert_eq!(q.next_block_height, NEXT);
        assert_eq!(q.snapshot_height, Some(NEXT - 20));
        let p = queue_position(t, &script).unwrap().unwrap();
        assert_eq!(
            (q.is_top, q.age_rank, q.size_rank, q.eligible_count),
            (p.is_top, p.age_rank, p.size_rank, p.eligible_count)
        );
        assert_eq!(q.owed.units, p.owed.to_string());
        for c in &q.next_block {
            let slots = c.slot_class as usize;
            let (oldest, largest) = select(t, slots).unwrap();
            assert_eq!(c.oldest_slots, split_slots(slots).0);
            assert_eq!(c.in_oldest, oldest.iter().any(|x| *x.0 == script));
            let paid = build_outputs(NEXT, Halving::MAINNET, t, slots)
                .unwrap()
                .outputs
                .into_iter()
                .find(|(a, _)| *a == script)
                .map_or(0, |x| x.1);
            assert_eq!(c.sats, paid, "class {}", c.slot_class);
            if largest.first().is_some_and(|x| *x.0 == script) {
                assert!(q.is_top);
            }
        }
    }
    // Payee 2 holds the largest balance: top.
    let top = w.api.ledger(&addr(&payee(2))).await.unwrap().queue.unwrap();
    assert!(top.is_top && top.size_rank == Some(1) && top.age_rank.is_none());
}

#[tokio::test]
async fn shares_are_listed_only_where_their_credit_is_applied() {
    let w = world();
    let r = w.api.ledger(&addr(&payee(1))).await.unwrap();
    assert_eq!(r.recent_shares.len(), 1, "anchor 2's batch is not credited");
    let s = &r.recent_shares[0];
    assert_eq!(s.anchor, hex::encode([1u8; 32]));
    assert_eq!((s.job_height, s.anchor_btc_height), (901, 900));
    assert_eq!(s.credit.units, P1_CREDIT.to_string());
    assert_eq!(s.credit.sats, 9_000);
}

#[tokio::test]
async fn payouts_are_settled_or_provisional_with_their_heights() {
    let w = world();
    let r = w.api.ledger(&addr(&payee(1))).await.unwrap();
    let got: Vec<(u32, i64, &str, Option<u32>)> = r
        .payouts
        .iter()
        .map(|p| (p.height, p.sats, p.status, p.confirmations))
        .collect();
    assert_eq!(
        got,
        vec![
            (960, 1_000, "provisional", Some(40)),
            (950, 1_500, "settled", Some(50)),
        ]
    );
    let mut hash = [0xB2u8; 32];
    hash.reverse();
    assert_eq!(r.payouts[0].block_hash, hex::encode(hash));
    assert_eq!(r.payouts[0].mature, Some(false));
    assert_eq!(r.payouts[1].units, (1_500 * ONE).to_string());
    assert!(r.settlement.caught_up);
    assert_eq!(r.settlement.provisional_blocks, 1);

    // The anchor arrives and the block matches: it is settled.
    w.settlement_tx.send_modify(|s| s.provisional.clear());
    let r = w.api.ledger(&addr(&payee(1))).await.unwrap();
    assert!(r.payouts.iter().all(|p| p.status == "settled"));
}

#[tokio::test]
async fn an_unknown_address_is_a_clear_empty_result() {
    let w = world();
    let r = w.api.ledger(&addr(&payee(0x77))).await.unwrap();
    assert!(!r.known);
    assert!(r.message.unwrap().contains("no balance"));
    assert_eq!(r.balance.units, "0");
    assert!(r.recent_shares.is_empty() && r.payouts.is_empty());
    let q = r.queue.unwrap();
    assert!(!q.eligible && q.age_rank.is_none() && q.size_rank.is_none());
    assert!(q.next_block.iter().all(|c| c.sats == 0));
    assert_eq!(q.eligible_count, 3);
}

#[tokio::test]
async fn bad_addresses_are_refused_with_400() {
    let w = world();
    let mainnet = Address::from_script(&ScriptBuf::from_bytes(payee(1)), Network::Bitcoin)
        .unwrap()
        .to_string();
    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&[5; 20]);
    p2pkh.extend_from_slice(&[0x88, 0xac]);
    for (bad, why) in [
        ("not-an-address", "is not a Bitcoin address"),
        ("", "is not a Bitcoin address"),
        (mainnet.as_str(), "is not a regtest address"),
        (addr(&p2pkh).as_str(), "only P2SH, P2WPKH, P2WSH and P2TR"),
    ] {
        let e = w.api.ledger(bad).await.unwrap_err();
        assert_eq!(e.status(), 400, "{bad}");
        assert!(e.message().contains(why), "{bad}: {}", e.message());
    }
}

#[tokio::test]
async fn without_a_next_table_the_queue_says_why() {
    let w = world();
    let api = NodePoolApi::new(
        w.api.parts.clone(),
        "x".into(),
        Arc::new(Fixed {
            table: None,
            miners: vec![],
        }),
    );
    let r = api.ledger(&addr(&payee(1))).await.unwrap();
    assert!(r.queue.is_none());
    assert!(r.queue_unavailable.unwrap().contains("no table"));
    assert_eq!(r.balance.sats, 6_500, "the balance does not need it");
}

#[tokio::test]
async fn the_status_has_its_documented_shape() {
    let w = world();
    let s = w.api.status().await.unwrap();
    assert_eq!(s.network, "regtest");
    assert_eq!(s.peers, 2);
    assert_eq!(s.share_chain.anchor_height, 7);
    assert_eq!(s.share_chain.tip, hex::encode([0xAB; 32]));
    assert!(s.settlement.caught_up);
    assert_eq!(s.settlement.provisional.len(), 1);
    assert_eq!(s.ledger_rows, 3);
    assert_eq!(s.fee_address, "bcrt1qfee");
    assert_eq!(s.start.genesis_table_digest, "42".repeat(32));
    assert_eq!(s.recent_blocks.len(), 2);
    assert_eq!(
        s.pool_blocks_found, 2,
        "every applied pool block, not only the listed ones"
    );
    let b = &s.recent_blocks[0];
    assert_eq!((b.height, b.status), (960, "provisional"));
    // A regtest relay: block 960 is in regtest era 6 (150-block halvings), not mainnet era 0.
    let (base, rm) = split(960, Halving::REGTEST);
    assert_eq!(b.subsidy_sats, subsidy(960, Halving::REGTEST));
    assert_eq!(b.subsidy_sats, 5_000_000_000 >> 6);
    assert_eq!(b.treasury_base_sats, base);
    assert_eq!(b.miners_paid_sats, 1_000);
    // No coinbase held for it: the leftover is shown as change.
    assert_eq!(b.treasury_change_sats, rm as i64 - 1_000);
    assert_eq!(b.finder_surplus_sats, 0);
    assert_eq!(b.treasury_sats, base as i64 + rm as i64 - 1_000);
    assert_eq!(b.payouts[0].address, addr(&payee(1)));
    let m = &s.miners[0];
    assert_eq!((m.kind, m.slot_class), ("extended", 9));
    assert_eq!(m.address, addr(&payee(1)));
    assert!(m
        .firmware_warning
        .as_ref()
        .unwrap()
        .contains("Stock Antminer"));
    assert!(m.sensing.as_ref().unwrap().settled);

    let v = serde_json::to_value(&s).unwrap();
    for key in [
        "network",
        "start",
        "share_chain",
        "peers",
        "settlement",
        "fee_address",
        "ledger_rows",
        "pool_blocks_found",
        "pool_expected_block_interval_secs",
        "recent_blocks",
        "miners",
    ] {
        assert!(v.get(key).is_some(), "status lacks {key}");
    }
    for key in ["tip", "anchor_height", "btc_height", "t_net"] {
        assert!(
            v["share_chain"].get(key).is_some(),
            "share_chain lacks {key}"
        );
    }
    assert!(v["settlement"]["caught_up"].is_boolean());
}

/// The dashboard's share-chain page reads the relay's counters and its retention from the
/// status: checkpoints come without their folded state, and an unknown node id is `null`.
#[tokio::test]
async fn the_status_carries_relay_counters_and_retention() {
    let w = world();
    let s = w.api.status().await.unwrap();
    assert_eq!(s.node_id, None);
    assert_eq!(
        s.relay_stats,
        RelayStatsView {
            shares_accepted: 40,
            shares_stale: 2,
            shares_invalid: 1,
            anchors_valid: 7,
            anchors_invalid: 0,
            reorgs: 1,
        }
    );
    assert_eq!(
        (s.retention.checkpoint_depth, s.retention.prune),
        (288, true)
    );
    assert_eq!(
        s.retention.checkpoints,
        vec![CheckpointView {
            anchor: "c1".repeat(32),
            anchor_height: 3,
            btc_height: 700,
            digest: "d1".repeat(32),
            created_at: 1_500,
        }]
    );
    let v = serde_json::to_value(&s).unwrap();
    assert!(v["node_id"].is_null());
    assert!(v["retention"]["checkpoints"][0].get("payload").is_none());
    assert_eq!(v["relay_stats"]["reorgs"], 1);
}

#[cfg(feature = "monitoring")]
#[tokio::test]
async fn the_routes_answer_over_http() {
    let w = world();
    let app = router(Arc::new(w.api));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        stratum_apps::monitoring::axum::serve(listener, app)
            .await
            .unwrap()
    });
    let get = |p: String| async move { reqwest::get(p).await.unwrap() };

    let r = get(format!("{base}/api/v1/node-pool/status")).await;
    assert_eq!(r.status().as_u16(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["network"], "regtest");

    let r = get(format!(
        "{base}/api/v1/node-pool/ledger/{}",
        addr(&payee(1))
    ))
    .await;
    assert_eq!(r.status().as_u16(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["balance"]["sats"], 6_500);

    let r = get(format!(
        "{base}/api/v1/node-pool/ledger/{}",
        addr(&payee(0x66))
    ))
    .await;
    assert_eq!(r.status().as_u16(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["known"], false);

    let r = get(format!("{base}/api/v1/node-pool/ledger/nope")).await;
    assert_eq!(r.status().as_u16(), 400);
    let v: serde_json::Value = r.json().await.unwrap();
    assert!(v["error"]
        .as_str()
        .unwrap()
        .contains("not a Bitcoin address"));
}

/// A carried-over balance shows: alone, added to share-chain credits and payouts, and in the
/// queue the next block's table gives. Payee 5 crosses the floor only with its genesis amount,
/// so its `queue_since` is the fold's, not the share chain's own row's.
#[tokio::test]
async fn balances_include_the_genesis_table() {
    let w = world_on(Some(genesis()));
    let db = w.api.parts.db.clone();
    let mut late = BTreeMap::new();
    late.insert(payee(5), 200 * ONE);
    db.np_apply_credits(&credit_event_key(&[3; 32], 905), 905, &late, 2_400)
        .unwrap();

    // Only carried over: known, its whole balance, queued since the export height.
    let r = w.api.ledger(&addr(&payee(4))).await.unwrap();
    assert!(r.known && r.message.is_none());
    assert_eq!(r.balance.sats, 3_000);
    assert_eq!(r.queue_since, Some(EXPORT_H as u32));
    let g = r.genesis.unwrap();
    assert_eq!((g.owed.sats, g.export_height), (3_000, EXPORT_H));
    assert_eq!(g.queue_since, Some(EXPORT_H as u32));
    assert!(r.recent_shares.is_empty() && r.payouts.is_empty());
    let q = r.queue.unwrap();
    let p = queue_position(&w.table, &payee(4)).unwrap().unwrap();
    assert!(q.eligible && p.eligible);
    assert_eq!(q.owed.sats, 3_000);
    assert_eq!((q.age_rank, q.size_rank), (p.age_rank, p.size_rank));

    // Carried over, then credited and paid on the share chain.
    let r = w.api.ledger(&addr(&payee(1))).await.unwrap();
    let owed = 500 * ONE + P1_CREDIT - 2_500 * ONE;
    assert_eq!(r.balance.units, owed.to_string());
    assert_eq!(
        r.genesis.unwrap().queue_since,
        None,
        "below the floor when carried"
    );
    assert_eq!(r.queue_since, Some(901));
    assert_eq!(r.payouts.len(), 2);

    // Over the floor only with its carried-over 900 sats.
    let r = w.api.ledger(&addr(&payee(5))).await.unwrap();
    assert_eq!(r.balance.sats, 1_100);
    assert_eq!(r.queue_since, Some(905));
    assert_eq!(db.np_balance(&payee(5)).unwrap().unwrap().queue_since, None);

    // Payees 1, 2, 3 credited, 4 and 5 carried over (1 and 5 both).
    assert_eq!(w.api.status().await.unwrap().ledger_rows, 5);

    // Without a genesis table nothing is carried.
    let r = world().api.ledger(&addr(&payee(4))).await.unwrap();
    assert!(!r.known && r.genesis.is_none());
}

/// The status sums every balance, and estimates the pool's hashrate from the shares credited on
/// the best chain over the last day of Bitcoin blocks: anchor 1's two shares at job height 901
/// (its credit event is applied), not anchor 2's share at 902 (a losing fork, not applied).
#[tokio::test]
async fn the_status_carries_total_owed_and_the_pool_hashrate() {
    let w = world();
    let s = w.api.status().await.unwrap();
    let owed = P1_CREDIT + 24_000 * ONE - 2_500 * ONE;
    assert_eq!(s.total_owed.units, owed.to_string());
    assert_eq!(s.total_owed.sats, 30_500);
    let folded: i128 = [1u8, 2, 3]
        .iter()
        .map(|p| {
            w.api
                .parts
                .db
                .np_payee_balance(&payee(*p))
                .unwrap()
                .unwrap()
                .owed
        })
        .sum();
    assert_eq!(
        s.total_owed.units,
        folded.to_string(),
        "every balance summed"
    );

    let h = &s.pool_hashrate;
    assert_eq!((h.from_job_height, h.to_job_height), (Some(856), Some(999)));
    assert_eq!((h.window_blocks, h.credited_shares), (144, 2));
    let want = 2.0 * 1024.0 * 4_295_032_833.0 / (144.0 * 600.0);
    assert!((h.hashes_per_sec.unwrap() - want).abs() < 1e-6, "{h:?}");
    assert!(h.unavailable.is_none());
    let v = serde_json::to_value(&s).unwrap();
    assert!(v["pool_hashrate"]["hashes_per_sec"].is_f64());
    assert!(v["total_owed"]["sats"].is_i64() && v["total_owed"]["units"].is_string());

    // The share at 902 counts once its credit event is applied, and nothing above the tip does.
    w.api
        .parts
        .db
        .np_apply_credits(
            &credit_event_key(&[2; 32], 902),
            902,
            &[(payee(1), 77)].into(),
            3_100,
        )
        .unwrap();
    assert_eq!(w.api.pool_hashrate(Some(999)).unwrap().credited_shares, 3);
    assert_eq!(w.api.pool_hashrate(Some(901)).unwrap().credited_shares, 2);

    // A young share chain: the window starts at the first earning height.
    let young = w.api.pool_hashrate(Some(30)).unwrap();
    assert_eq!((young.from_job_height, young.window_blocks), (Some(21), 10));
    assert_eq!(young.hashes_per_sec, Some(0.0));
    // Before it, and with no tip, there is no figure, and the reason is given.
    for tip in [Some(20), None] {
        let h = w.api.pool_hashrate(tip).unwrap();
        assert!(
            h.hashes_per_sec.is_none() && h.unavailable.is_some(),
            "{tip:?}"
        );
    }
}

/// A node that prunes inside the window would count only part of its work: no figure.
#[tokio::test]
async fn a_pruned_window_gives_no_hashrate() {
    // The world keeps one checkpoint at Bitcoin height 700; pruning deletes batches below it.
    let mut w = world();
    let h = w.api.pool_hashrate(Some(800)).unwrap();
    assert_eq!(h.from_job_height, None);
    assert!(h.hashes_per_sec.is_none(), "{h:?}");
    assert!(h.unavailable.unwrap().contains("pruned"));
    assert!(w
        .api
        .pool_hashrate(Some(999))
        .unwrap()
        .hashes_per_sec
        .is_some());
    // An archive node keeps every batch: the same window is measured.
    w.api.parts.prune = false;
    assert!(w
        .api
        .pool_hashrate(Some(800))
        .unwrap()
        .hashes_per_sec
        .is_some());
}

/// Finding E: work below the first earning height (genesis + 21) earns nothing; the status and
/// miner pages say so in plain words while it lasts, and nothing once it is over.
#[test]
fn work_before_the_first_earning_height_is_flagged() {
    use crate::node_pool_api::EarningView;
    let early = EarningView::new(0, Some(20));
    assert_eq!((early.first_earning_height, early.earns), (21, Some(false)));
    assert!(early
        .notice
        .unwrap()
        .contains("earns nothing until Bitcoin height 21"));
    let paid = EarningView::new(0, Some(21));
    assert_eq!((paid.earns, paid.notice), (Some(true), None));
    let idle = EarningView::new(974_500, None);
    assert_eq!(
        (idle.first_earning_height, idle.earns, idle.notice),
        (974_521, None, None)
    );
}

/// A block whose coinbase is held: a treasury of exactly `S/200` means the leftover went to the
/// finder as a cleared ledger's surplus (draft 3.2), and the status says so.
#[tokio::test]
async fn a_cleared_ledgers_surplus_is_shown_as_the_finders() {
    use ghost_storage::node_pool_store::NpBtcBlock;
    use stratum_apps::stratum_core::bitcoin::{
        absolute::LockTime, consensus::serialize, transaction::Version, Amount, ScriptBuf,
        Transaction, TxIn, TxOut,
    };
    let w = world();
    let (base, rm) = split(970, Halving::REGTEST);
    let cb = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![
            TxOut {
                value: Amount::from_sat(base),
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(payee(1)),
            },
            TxOut {
                value: Amount::from_sat(rm - 1_000),
                script_pubkey: ScriptBuf::new(),
            },
        ],
    };
    use stratum_apps::stratum_core::bitcoin::hashes::{sha256d, Hash};
    let header = [7u8; 80];
    let hash = sha256d::Hash::hash(&header).to_byte_array();
    let db = &w.api.parts.db;
    db.np_put_btc_block(&NpBtcBlock {
        hash,
        height: 970,
        header,
        coinbase: Some((serialize(&cb), vec![])),
        received_at: 1,
    })
    .unwrap();
    db.np_apply_block(&hash, 970, &[(payee(1), 1_000 * ONE)], 2_400)
        .unwrap();
    let s = w.api.status().await.unwrap();
    let b = &s.recent_blocks[0];
    assert_eq!(b.height, 970);
    assert_eq!(b.treasury_change_sats, 0);
    assert_eq!(b.finder_surplus_sats, rm as i64 - 1_000);
    assert_eq!(b.treasury_sats, base as i64);
}
