//! Tests for the miner and pool status API.

use super::*;
use crate::miner_stats::{MinerStats, Outcome};

const T0: u64 = 1_800_000_000;
const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

fn api() -> SoloApi {
    let stats = Arc::new(MinerStats::in_memory(T0 - 7_200));
    let solo = Arc::new(Solo::new(ghost_common::solo::SoloNetwork::Regtest).with_miner_stats(stats));
    let mut api = SoloApi::new(solo, vec![3333, 4444], 34255, vec![]);
    api.clock = || T0;
    api
}

#[test]
fn addresses_of_another_network_or_class_are_refused() {
    let api = api();
    assert!(api.payee_script(ADDR).is_ok());
    let e = api
        .payee_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        .unwrap_err();
    assert!(e.message().contains("not a regtest address"), "{e:?}");
    assert!(api.payee_script("not-an-address").is_err());
    assert_eq!(e.status(), 400);
}

#[test]
fn a_miners_shares_hashrate_and_best_share_are_reported() {
    let api = api();
    let script = api.payee_script(ADDR).unwrap();
    // 100 shares of difficulty 1,000 over the last hour, one of them a 9e6 hash.
    for i in 0..100u64 {
        let sd = if i == 50 { 9.0e6 } else { 1_500.0 };
        api.solo.miner_stats().record(
            &script,
            "rig1",
            Outcome::Accepted {
                difficulty: 1_000.0,
                share_difficulty: sd,
            },
            T0 - 3_600 + i * 36,
        );
    }
    let r = api.miner(ADDR).unwrap();
    assert_eq!(r.network, "regtest");
    assert_eq!(r.summary.workers, 1);
    assert_eq!(r.workers[0].name, "rig1");
    assert_eq!(r.workers[0].status, "offline", "no open channel");
    assert_eq!(r.summary.shares_24h.accepted, 100);
    assert_eq!(r.summary.best_share.ever, 9.0e6);
    assert_eq!(r.summary.best_share.h24, 9.0e6);
    let h1 = r.summary.hashrate_hs.h1.unwrap();
    let want = 100.0 * 1_000.0 * 4_294_967_296.0 / 3_600.0;
    assert!((h1 - want).abs() / want < 0.05, "{h1} vs {want}");
    // No tip yet: the time to a block is unknown, and says why.
    assert!(!r.expected_time_to_block.known);
    assert!(r.expected_time_to_block.reason.is_some());
    assert!(r.blocks_found.is_empty());

    let s = api.status();
    assert_eq!(s.ports.sv1, vec![3333, 4444]);
    assert_eq!(s.ports.sv2, 34255);
    assert_eq!(s.best_share.ever, 9.0e6);
    assert!(s.pool_hashrate_hs.h1.unwrap() > 0.0);
    assert_eq!(s.fee_policy.fees_to, "miner");
    assert_eq!(
        s.fee_policy.treasury_address,
        api.solo.address_of(&ghost_common::solo::TREASURY_SCRIPT)
    );
    assert_eq!(s.bitcoin.tip_height, None);
    let v = serde_json::to_value(&s).unwrap();
    assert!(v["pool_hashrate_hs"]["15m"].is_number() || v["pool_hashrate_hs"]["15m"].is_null());
    assert!(v.get("blocks_found").is_some());

    let h = api.miner_history(ADDR, "24h").unwrap();
    assert_eq!(h.buckets.len(), 288);
    assert_eq!(h.total.best_share.len(), 288);
    assert!(api.miner_history(ADDR, "1y").is_err());
}

#[test]
fn the_expected_time_is_difficulty_times_2_32_over_hashrate() {
    let rates = Rates {
        m15: None,
        h1: Some(1.0e12),
        h24: Some(5.0e11),
    };
    let e = expected_time(&rates, Some(1.0e6));
    assert!(e.known);
    assert_eq!(e.hashrate_window, Some("1h"));
    assert_eq!(e.seconds, Some(1.0e6 * 4_294_967_296.0 / 1.0e12));
    let e = expected_time(
        &Rates {
            h1: None,
            ..rates.clone()
        },
        Some(1.0e6),
    );
    assert_eq!(e.hashrate_window, Some("24h"));
    assert!(!expected_time(&Rates::default(), Some(1.0e6)).known);
    assert!(!expected_time(&rates, None).known);
}
