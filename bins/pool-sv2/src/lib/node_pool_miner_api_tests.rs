//! Tests for the miner pages' API over the ledger and status API's test store.

use std::sync::Arc;

use crate::{
    miner_stats::{MinerStats, Outcome, RejectReason},
    node_pool_api::tests::{addr, payee, world, ONE},
};

use super::*;

/// The tests' now: the 24-hour window's first bucket starts at 2,100, where the test store's
/// ledger events are (credit at 2,100, payouts at 2,200 and 2,300).
const NOW: u64 = 2_100 + 287 * 300 + 120;

fn now() -> u64 {
    NOW
}

fn stats() -> Arc<MinerStats> {
    let m = MinerStats::in_memory(NOW - 3_600);
    let p1 = payee(1);
    // rig1: connected (the test store's open channel), 1,000-difficulty shares for the last
    // hour, one every 6 s, plus a stale and two duplicates.
    for i in 0..600 {
        m.record(
            &p1,
            "rig1",
            Outcome::Accepted {
                difficulty: 1_000.0,
            },
            NOW - 3_600 + i * 6,
        );
    }
    m.record(&p1, "rig1", Outcome::Stale, NOW - 10);
    m.record(
        &p1,
        "rig1",
        Outcome::Rejected(RejectReason::DuplicateShare),
        NOW - 9,
    );
    m.record(
        &p1,
        "rig1",
        Outcome::Rejected(RejectReason::DuplicateShare),
        NOW - 8,
    );
    // rig2: not connected, last seen 40 minutes ago.
    m.record(
        &p1,
        "rig2",
        Outcome::Accepted { difficulty: 500.0 },
        NOW - 2_400,
    );
    // Someone else's worker never shows.
    m.record(
        &payee(2),
        "x",
        Outcome::Accepted { difficulty: 1.0 },
        NOW - 5,
    );
    Arc::new(m)
}

fn api() -> NodePoolApi {
    world().api.with_miner_stats(stats()).with_clock(now)
}

#[tokio::test]
async fn the_miner_lists_its_workers_with_status_rates_and_connections() {
    let r = api().miner(&addr(&payee(1))).await.unwrap();
    assert_eq!(r.network, "regtest");
    assert_eq!(r.generated_at, NOW);
    assert_eq!(r.collecting_since, NOW - 3_600);
    assert_eq!(r.node_id, None, "the test view has no node id");
    let names: Vec<(&str, &str)> = r
        .workers
        .iter()
        .map(|w| (w.name.as_str(), w.status))
        .collect();
    assert_eq!(names, vec![("rig1", "online"), ("rig2", "offline")]);

    let rig1 = &r.workers[0];
    assert_eq!(rig1.slot_class, Some(9));
    assert!(rig1
        .firmware_warning
        .as_ref()
        .unwrap()
        .contains("Stock Antminer"));
    assert_eq!(rig1.connections.len(), 1);
    let c = &rig1.connections[0];
    assert_eq!(
        (c.kind, c.model, c.settled),
        ("extended", Some("Stock Antminer"), Some(true))
    );
    assert_eq!(rig1.shares_24h.accepted, 600);
    assert_eq!(rig1.shares_24h.stale, 1);
    assert_eq!(rig1.shares_24h.rejected, 2);
    assert_eq!(rig1.shares_24h.reject_reasons["duplicate-share"], 2);
    assert_eq!(rig1.last_share_at, Some(NOW - 6));
    assert_eq!(rig1.last_submit_at, Some(NOW - 6));
    // 1,000 difficulty every 6 s.
    let want = 1_000.0 * 4_294_967_296.0 / 6.0;
    let h1 = rig1.hashrate_hs.h1.unwrap();
    assert!((h1 - want).abs() / want < 0.01, "{h1} vs {want}");
    // The 24-hour rate covers only the hour this node observed, not 24 hours.
    let h24 = rig1.hashrate_hs.h24.unwrap();
    assert!((h24 - h1).abs() / want < 0.01);

    let rig2 = &r.workers[1];
    assert!(rig2.connections.is_empty() && rig2.slot_class.is_none());
    assert_eq!(
        rig2.hashrate_hs.m15,
        Some(0.0),
        "quiet for the last 15 minutes"
    );

    assert_eq!(
        (
            r.summary.workers,
            r.summary.online,
            r.summary.idle,
            r.summary.offline
        ),
        (2, 1, 0, 1)
    );
    assert_eq!(r.summary.shares_24h.accepted, 601);
    assert_eq!(r.summary.last_share_at, Some(NOW - 6));
    let sum = r.summary.hashrate_hs.h1.unwrap();
    let want = (600.0 * 1_000.0 + 500.0) * 4_294_967_296.0 / 3_600.0;
    assert!((sum - want).abs() / want < 1e-9, "{sum} vs {want}");
}

#[tokio::test]
async fn a_connected_worker_with_no_share_yet_is_idle() {
    let w = world();
    let api = w
        .api
        .with_miner_stats(Arc::new(MinerStats::in_memory(NOW)))
        .with_clock(now);
    let r = api.miner(&addr(&payee(1))).await.unwrap();
    assert_eq!(r.workers.len(), 1);
    assert_eq!(
        (r.workers[0].name.as_str(), r.workers[0].status),
        ("rig1", "idle")
    );
    assert_eq!(
        r.workers[0].hashrate_hs,
        Rates::default(),
        "under a minute observed"
    );
    assert_eq!(r.summary.hashrate_hs.h1, None);
}

#[tokio::test]
async fn the_wait_is_unknown_on_two_pool_blocks() {
    let r = api().miner(&addr(&payee(1))).await.unwrap();
    let w = &r.expected_wait;
    assert!(!w.known);
    assert_eq!(w.pool_blocks_counted, 2);
    assert!(w.reason.as_ref().unwrap().contains("2 blocks"));
    assert!(w.seconds.is_none() && w.blocks_needed.is_none());
}

#[tokio::test]
async fn the_history_has_aligned_series_and_unknown_before_collection() {
    let r = api().miner_history(&addr(&payee(1)), "24h").await.unwrap();
    assert_eq!((r.window, r.bucket_seconds), ("24h", 300));
    assert_eq!(r.buckets.len(), 288);
    assert_eq!(r.buckets[0], 2_100);
    for s in [&r.total]
        .into_iter()
        .chain(r.workers.iter().map(|w| &w.series))
    {
        assert_eq!(s.hashrate_hs.len(), 288);
        assert_eq!(s.accepted.len(), 288);
        assert_eq!(s.rejected.len(), 288);
    }
    // Collection began an hour ago: every bucket before it is unknown, not zero.
    let first_known = r
        .buckets
        .iter()
        .position(|t| t + 300 > NOW - 3_600)
        .unwrap();
    assert!(r.total.accepted[..first_known].iter().all(Option::is_none));
    assert!(r.total.accepted[first_known..].iter().all(Option::is_some));
    let total: u64 = r.total.accepted.iter().flatten().sum();
    assert_eq!(total, 601);
    assert_eq!(r.reject_reasons["duplicate-share"], 2);
    assert_eq!(r.workers[0].name, "rig1", "most work first");
    assert_eq!(r.workers_omitted, 0);

    // The balance: credited 9,000 and paid 1,500 + 1,000 in the first bucket.
    let b = &r.balance;
    assert_eq!(b.start_sats, 0);
    assert_eq!(b.end_sats.len(), 288);
    assert_eq!(b.credited_sats[0], 9_000);
    assert_eq!(b.paid_sats[0], 2_500);
    assert_eq!(b.end_sats[0], 6_500);
    assert_eq!(*b.end_sats.last().unwrap(), 6_500, "carried to now");
    let heights: Vec<u32> = b.payouts.iter().map(|p| p.height).collect();
    assert_eq!(heights, vec![950, 960]);

    fn later() -> u64 {
        1_800_000_000
    }
    let later_api = || world().api.with_miner_stats(stats()).with_clock(later);
    let r7 = later_api()
        .miner_history(&addr(&payee(1)), "7d")
        .await
        .unwrap();
    assert_eq!((r7.buckets.len(), r7.bucket_seconds), (168, 3_600));
    assert_eq!(*r7.buckets.last().unwrap(), later() - later() % 3_600);
    let r30 = later_api()
        .miner_history(&addr(&payee(1)), "30d")
        .await
        .unwrap();
    assert_eq!(r30.buckets.len(), 720);
    assert!(
        r30.balance.payouts.is_empty(),
        "the payouts are long before the window"
    );
    assert_eq!(*r30.balance.end_sats.last().unwrap(), 6_500);
}

#[tokio::test]
async fn bad_addresses_and_windows_are_refused_with_400() {
    let a = api();
    let e = a.miner("nope").await.unwrap_err();
    assert_eq!(e.status(), 400);
    assert!(e.message().contains("not a Bitcoin address"));
    let e = a.miner_history("nope", "24h").await.unwrap_err();
    assert_eq!(e.status(), 400);
    let e = a.miner_history(&addr(&payee(1)), "1y").await.unwrap_err();
    assert_eq!(e.status(), 400);
    assert!(e.message().contains("24h, 7d or 30d"));
}

#[tokio::test]
async fn the_history_lists_at_most_its_cap_of_workers() {
    let m = MinerStats::in_memory(NOW - 600);
    for i in 0..(MAX_HISTORY_WORKERS + 6) {
        m.record(
            &payee(1),
            &format!("w{i:03}"),
            Outcome::Accepted {
                difficulty: 1.0 + i as f64,
            },
            NOW - 100,
        );
    }
    let api = world().api.with_miner_stats(Arc::new(m)).with_clock(now);
    let r = api.miner_history(&addr(&payee(1)), "24h").await.unwrap();
    assert_eq!(r.workers.len(), MAX_HISTORY_WORKERS);
    assert_eq!(r.workers_omitted, 6);
    let last_accepted: u64 = r.total.accepted.iter().flatten().sum();
    assert_eq!(
        last_accepted,
        MAX_HISTORY_WORKERS as u64 + 6,
        "the total keeps them all"
    );
    assert_eq!(
        r.workers[0].name,
        format!("w{:03}", MAX_HISTORY_WORKERS + 5)
    );
}

fn input() -> WaitInput {
    WaitInput {
        have_table: true,
        eligible: true,
        is_top: false,
        eligible_count: 40,
        age_rank: Some(25),
        paid_next_at_typical: Some(0),
        balance_sats: 5_000,
        // Blocks 1, 2 and 3 days ago, each paying 10 balances.
        block_times: vec![
            1_800_000_000 - 86_400,
            1_800_000_000 - 2 * 86_400,
            1_800_000_000 - 3 * 86_400,
        ],
        block_outputs: vec![10, 10, 10],
        credited_sats_24h: Some(200),
        now: 1_800_000_000,
    }
}

#[test]
fn the_wait_comes_from_the_queue_and_the_recent_block_rate() {
    let w = estimate_wait(&input());
    assert!(w.known, "{:?}", w.reason);
    // Two blocks after the first over three days to now: one every 1.5 days.
    assert_eq!(w.pool_block_interval_secs, Some(3 * 86_400 / 2));
    assert_eq!(w.typical_outputs_per_block, Some(10));
    // 25th oldest, 5 oldest slots a block: 5 blocks.
    assert_eq!(w.blocks_needed, Some(5));
    assert_eq!(w.seconds, Some(5 * 3 * 86_400 / 2));
    assert!(w.assumptions.iter().any(|a| a.contains("half or double")));

    // Paid by the next block at the typical size: one block.
    let mut i = input();
    i.paid_next_at_typical = Some(1_234);
    assert_eq!(estimate_wait(&i).blocks_needed, Some(1));
    let mut i = input();
    i.is_top = true;
    i.age_rank = None;
    assert_eq!(estimate_wait(&i).blocks_needed, Some(1));
}

#[test]
fn the_wait_is_unknown_when_the_data_is_thin() {
    let mut i = input();
    i.have_table = false;
    assert!(!estimate_wait(&i).known);

    let mut i = input();
    i.block_times.truncate(2);
    let w = estimate_wait(&i);
    assert!(!w.known && w.reason.unwrap().contains("2 blocks"));

    // Old blocks do not count.
    let mut i = input();
    i.block_times = vec![1, 2, 3, 4];
    let w = estimate_wait(&i);
    assert!(!w.known && w.pool_blocks_counted == 0);

    // Below the floor with nothing credited in a day.
    let mut i = input();
    i.eligible = false;
    i.age_rank = None;
    i.balance_sats = 400;
    i.credited_sats_24h = Some(0);
    let w = estimate_wait(&i);
    assert!(!w.known);
    assert_eq!(w.sats_to_floor, Some(600));
    assert!(w.reason.unwrap().contains("600 sats to go"));
}

#[test]
fn below_the_floor_the_wait_adds_reaching_it_and_the_snapshot_lag() {
    let mut i = input();
    i.eligible = false;
    i.age_rank = None;
    i.balance_sats = 400;
    i.credited_sats_24h = Some(300);
    let w = estimate_wait(&i);
    assert!(w.known);
    // 600 sats at 300 a day: 2 days; the 20-block lag; then the back of 41 at 5 a block.
    let interval = 3 * 86_400 / 2;
    assert_eq!(w.blocks_needed, Some(9));
    assert_eq!(w.seconds, Some(2 * 86_400 + 20 * 600 + 9 * interval));
}

#[test]
fn events_applied_long_after_their_block_sit_at_its_time() {
    assert_eq!(event_time(5_000, Some(4_000)), 5_000, "within two hours");
    assert_eq!(event_time(50_000, Some(4_000)), 4_000, "a syncing node");
    assert_eq!(event_time(5_000, None), 5_000);
}

#[test]
fn the_balance_history_starts_from_the_last_event_before_the_window() {
    let ev = |time, seq, kind, amount: i128, prior: i128| BalanceEvent {
        time,
        seq,
        kind,
        amount: amount * ONE,
        prior_owed: prior * ONE,
        height: 900 + seq as u32,
        block_hash: (kind == NpLedgerEventKind::Block).then_some([seq as u8; 32]),
    };
    let events = vec![
        ev(50, 1, NpLedgerEventKind::Credit, 2_000, 0),
        ev(150, 2, NpLedgerEventKind::Credit, 1_000, 2_000),
        ev(450, 3, NpLedgerEventKind::Block, 2_500, 3_000),
    ];
    let starts = [100, 200, 300, 400];
    let h = balance_history(&events, &starts, 100, 500 * ONE);
    assert_eq!(h.start_sats, 2_000);
    assert_eq!(h.end_sats, vec![3_000, 3_000, 3_000, 500]);
    assert_eq!(h.credited_sats, vec![1_000, 0, 0, 0]);
    assert_eq!(h.paid_sats, vec![0, 0, 0, 2_500]);
    assert_eq!(h.payouts.len(), 1);
    assert_eq!(h.payouts[0].height, 903);

    // No events: flat at the balance now.
    let h = balance_history(&[], &starts, 100, 777 * ONE);
    assert_eq!(h.start_sats, 777);
    assert_eq!(h.end_sats, vec![777; 4]);
}

#[cfg(feature = "monitoring")]
#[tokio::test]
async fn the_miner_routes_answer_over_http() {
    let app = router(Arc::new(api()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        stratum_apps::monitoring::axum::serve(listener, app)
            .await
            .unwrap()
    });
    let a = addr(&payee(1));
    let r = reqwest::get(format!("{base}/api/v1/node-pool/miner/{a}"))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["workers"][0]["name"], "rig1");
    for k in [
        "summary",
        "workers",
        "expected_wait",
        "collecting_since",
        "node_id",
    ] {
        assert!(v.get(k).is_some(), "miner lacks {k}");
    }
    assert!(v["summary"]["hashrate_hs"].get("15m").is_some());
    assert_eq!(v["expected_wait"]["known"], false);

    let r = reqwest::get(format!(
        "{base}/api/v1/node-pool/miner/{a}/history?window=24h"
    ))
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["window"], "24h");
    assert_eq!(v["buckets"].as_array().unwrap().len(), 288);
    assert_eq!(v["balance"]["end_sats"][0], 6_500);
    assert!(
        v["total"]["accepted"][0].is_null(),
        "unknown before collection"
    );

    let r = reqwest::get(format!("{base}/api/v1/node-pool/miner/{a}/history"))
        .await
        .unwrap();
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["window"], "24h", "the default window");

    let r = reqwest::get(format!(
        "{base}/api/v1/node-pool/miner/{a}/history?window=x"
    ))
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let r = reqwest::get(format!("{base}/api/v1/node-pool/miner/nope"))
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
}

#[test]
fn the_typical_block_is_the_median_and_never_below_the_smallest_class() {
    assert_eq!(typical_outputs(&[]), None);
    assert_eq!(
        typical_outputs(&[1, 1, 2]),
        Some(3),
        "few balances, not few outputs"
    );
    assert_eq!(typical_outputs(&[9, 500, 44, 9, 143]), Some(44));
}
