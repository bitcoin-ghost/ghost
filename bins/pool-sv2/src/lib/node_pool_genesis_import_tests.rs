//|======================================================================================================================|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: node_pool_genesis_import_tests.rs                                                                              |
//|======================================================================================================================|

//! Tests for the genesis import, on exports built to `docs/LEDGER_EXPORT.md`'s byte layout.

use super::*;
use crate::config::NodePoolConfig;
use crate::node_pool::NodePool;
use ghost_common::node_pool_constants::{FACE_PER_SAT, PAYOUT_FLOOR_FACE};
use ghost_common::node_pool_genesis_export::{
    parse_export, sample_export, EXPORT_BIN, EXPORT_JSON,
};
use ghost_common::node_pool_network::genesis_table_digest;

const H: u64 = 974_500;
const GENESIS: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/// Three payees: one well above the 1,000-sat floor, one exactly at it, one below.
fn rows() -> Vec<(Vec<u8>, u128)> {
    let mut r = vec![
        (
            [&[0x00, 0x14][..], &[0xAA; 20]].concat(),
            5_000 * FACE_PER_SAT as u128 + 7,
        ),
        (
            [&[0x51, 0x20][..], &[0xBB; 32]].concat(),
            PAYOUT_FLOOR_FACE as u128,
        ),
        (
            [&[0x51, 0x20][..], &[0xCC; 32]].concat(),
            999 * FACE_PER_SAT as u128,
        ),
    ];
    r.sort();
    r
}

struct Export {
    bin: Vec<u8>,
    json: Vec<u8>,
    digest: [u8; 32],
}

/// An export as `ghost-mining --np-export` writes it (the shared sample layout).
fn export_with(
    network: &str,
    height: u64,
    rows: &[(Vec<u8>, u128)],
    json_rows: &[(Vec<u8>, u128)],
) -> Export {
    let (bin, json, digest) = sample_export(network, height, rows, json_rows);
    Export { bin, json, digest }
}

fn export(network: &str) -> Export {
    export_with(network, H, &rows(), &rows())
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "np-genesis-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("export")).unwrap();
        Self { dir }
    }

    fn write(&self, e: &Export) -> PathBuf {
        let d = self.dir.join("export");
        std::fs::write(d.join(EXPORT_BIN), &e.bin).unwrap();
        std::fs::write(d.join(EXPORT_JSON), &e.json).unwrap();
        d
    }

    fn cfg(&self, network: &str, extra: &str) -> NodePoolRelayConfig {
        let toml = format!(
            "fee_address = \"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"\n[relay]\nnetwork = \
             \"{network}\"\nlisten = \"127.0.0.1:0\"\ndb_path = {:?}\ngenesis_anchor = \
             \"{GENESIS}\"\ngenesis_btc_height = 974600\nrpc_host = \"127.0.0.1\"\nrpc_port = \
             1\nrpc_user = \"u\"\nrpc_password = \"p\"\n{extra}",
            self.dir.join("relay.db").display().to_string()
        );
        let c: NodePoolConfig = ext_config::Config::builder()
            .add_source(ext_config::File::from_str(
                &toml,
                ext_config::FileFormat::Toml,
            ))
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        c.relay.unwrap()
    }

    fn stored_meta(&self) -> Option<NpGenesisMeta> {
        let p = self.dir.join("relay.db");
        if !p.exists() {
            return None;
        }
        Database::open(&p).unwrap().np_genesis_meta().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn an_import_writes_the_table_and_prints_the_root_the_pin_check_computes() {
    let f = Fixture::new("ok");
    let e = export("regtest");
    let dir = f.write(&e);
    let cfg = f.cfg("regtest", "");
    let s = run(&cfg, &dir, &e.digest, false, 1_000).unwrap();
    assert!(!s.verified_only);
    let root = s.export.table_root;
    let lines = s.lines();
    assert!(
        lines[0].starts_with("NODE_POOL_GENESIS_IMPORTED:"),
        "{lines:?}"
    );
    assert!(lines[0].contains(&format!("table_root={}", hex::encode(root))));
    assert!(lines[0].contains("rows=3"));
    assert!(lines[1].contains(&hex::encode(root)));

    // What W2.8's pin check computes from what the store holds.
    let db = Database::open(cfg.db_path.clone()).unwrap();
    let stored = db.np_genesis_table().unwrap();
    assert_eq!(genesis_table_digest(&stored), root);
    let mut pinned = cfg.clone();
    pinned.genesis_table_digest = Some(hex::encode(root));
    let start = pinned.network_start().unwrap();
    assert_eq!(start.check_table(&stored).unwrap(), root);
    pinned.genesis_table_digest = Some(hex::encode([9u8; 32]));
    assert!(pinned
        .network_start()
        .unwrap()
        .check_table(&stored)
        .is_err());

    let m = db.np_genesis_meta().unwrap().unwrap();
    assert_eq!(m.export_digest, e.digest);
    assert_eq!(
        (m.export_height, m.queue_since, m.row_count),
        (H, H as u32, 3)
    );
    assert_eq!(m.network, "regtest");
    assert_eq!(m.imported_at, 1_000);
}

#[test]
fn queue_since_is_the_export_height_at_or_above_the_floor_and_none_below() {
    let t = parse_export(
        &export("regtest").bin,
        &export("regtest").json,
        &export("regtest").digest,
    )
    .unwrap()
    .table;
    let r = rows();
    assert_eq!(t.len(), 3);
    for (s, f) in r {
        let b = t[&s];
        assert_eq!(b.owed, f as i128, "units are taken as they are");
        let want = (b.owed >= PAYOUT_FLOOR_FACE).then_some(H as u32);
        assert_eq!(b.queue_since, want, "{}", hex::encode(&s));
    }
    assert_eq!(
        t.values().filter(|b| b.queue_since.is_some()).count(),
        2,
        "above and exactly at the floor queue, below does not"
    );
}

#[test]
fn a_digest_mismatch_is_refused_and_nothing_is_written() {
    let f = Fixture::new("digest");
    let e = export("regtest");
    let dir = f.write(&e);
    let mut wrong = e.digest;
    wrong[0] ^= 1;
    let err = run(&f.cfg("regtest", ""), &dir, &wrong, false, 0).unwrap_err();
    assert!(err.contains("not the expected"), "{err}");
    assert!(f.stored_meta().is_none());

    // A JSON that names another digest is refused too.
    let mut j: serde_json::Value = serde_json::from_slice(&e.json).unwrap();
    j["digest_sha256"] = serde_json::Value::String(hex::encode(wrong));
    let e2 = Export {
        json: serde_json::to_vec(&j).unwrap(),
        ..export("regtest")
    };
    let dir = f.write(&e2);
    let err = run(&f.cfg("regtest", ""), &dir, &e2.digest, false, 0).unwrap_err();
    assert!(err.contains("not one export"), "{err}");
    assert!(f.stored_meta().is_none());
}

#[test]
fn json_rows_that_differ_from_the_digested_rows_are_refused() {
    let mut fake = rows();
    fake[0].1 += 1;
    let e = export_with("regtest", H, &rows(), &fake);
    let err = parse_export(&e.bin, &e.json, &e.digest).unwrap_err();
    assert!(err.contains("not the one in"), "{err}");
    let e = export_with("regtest", H, &rows(), &rows()[..2]);
    assert!(parse_export(&e.bin, &e.json, &e.digest).is_err());
}

#[test]
fn rows_out_of_order_or_too_large_are_refused() {
    let mut r = rows();
    r.swap(0, 1);
    let e = export_with("regtest", H, &r, &r);
    let err = parse_export(&e.bin, &e.json, &e.digest).unwrap_err();
    assert!(err.contains("ascending"), "{err}");
    let big = vec![(vec![0x51], u128::MAX)];
    let e = export_with("regtest", H, &big, &big);
    let err = parse_export(&e.bin, &e.json, &e.digest).unwrap_err();
    assert!(err.contains("i128::MAX"), "{err}");
}

#[test]
fn the_wrong_network_is_refused() {
    let f = Fixture::new("net");
    let e = export("signet");
    let dir = f.write(&e);
    let err = run(&f.cfg("regtest", ""), &dir, &e.digest, false, 0).unwrap_err();
    assert!(err.contains("runs on regtest"), "{err}");
    assert!(f.stored_meta().is_none());
    // `bitcoin` (the export's name for mainnet) is mainnet.
    let e = export("bitcoin");
    assert_eq!(
        parse_export(&e.bin, &e.json, &e.digest).unwrap().network,
        NodePoolNetwork::Mainnet
    );
    let e = export("testnet");
    assert!(parse_export(&e.bin, &e.json, &e.digest).is_err());
}

#[test]
fn a_second_import_is_refused() {
    let f = Fixture::new("twice");
    let e = export("regtest");
    let dir = f.write(&e);
    let cfg = f.cfg("regtest", "");
    run(&cfg, &dir, &e.digest, false, 1).unwrap();
    let err = run(&cfg, &dir, &e.digest, false, 2).unwrap_err();
    assert!(err.contains("already imported"), "{err}");
    assert_eq!(f.stored_meta().unwrap().imported_at, 1);
}

#[test]
fn an_import_over_a_used_ledger_is_refused() {
    let f = Fixture::new("used");
    let e = export("regtest");
    let dir = f.write(&e);
    let cfg = f.cfg("regtest", "");
    Database::open(&cfg.db_path)
        .unwrap()
        .np_apply_block(&[0xA0; 32], 121, &[(vec![0x51], 1)], 0)
        .unwrap();
    let err = run(&cfg, &dir, &e.digest, false, 0).unwrap_err();
    assert!(err.contains("np_ledger"), "{err}");
    assert!(f.stored_meta().is_none());
}

#[test]
fn a_configured_pin_that_differs_is_refused() {
    let f = Fixture::new("pin");
    let e = export("regtest");
    let dir = f.write(&e);
    let cfg = f.cfg(
        "regtest",
        &format!("genesis_table_digest = \"{}\"\n", hex::encode([3u8; 32])),
    );
    let err = run(&cfg, &dir, &e.digest, false, 0).unwrap_err();
    assert!(err.contains("would refuse it"), "{err}");
    assert!(f.stored_meta().is_none());
}

#[test]
fn verify_round_trips_and_writes_nothing() {
    let f = Fixture::new("verify");
    let e = export("regtest");
    let dir = f.write(&e);
    let cfg = f.cfg("regtest", "");
    let err = run(&cfg, &dir, &e.digest, true, 0).unwrap_err();
    assert!(err.contains("no store"), "{err}");
    assert!(!cfg.db_path.exists(), "verify does not create a store");

    let imported = run(&cfg, &dir, &e.digest, false, 5).unwrap();
    for _ in 0..2 {
        let v = run(&cfg, &dir, &e.digest, true, 99).unwrap();
        assert!(v.verified_only);
        assert_eq!(v.export.table_root, imported.export.table_root);
        assert!(v.lines()[0].starts_with("NODE_POOL_GENESIS_VERIFIED:"));
    }
    assert_eq!(f.stored_meta().unwrap().imported_at, 5, "nothing rewritten");

    // Another export does not verify against this store.
    let other_rows = vec![([&[0x51, 0x20][..], &[0xDD; 32]].concat(), 7u128)];
    let other = export_with("regtest", H, &other_rows, &other_rows);
    let dir = f.write(&other);
    let err = run(&cfg, &dir, &other.digest, true, 0).unwrap_err();
    assert!(err.contains("came from export"), "{err}");
}

/// The relay builds on the stored genesis table and holds it to the pin.
#[tokio::test]
async fn the_relay_starts_on_the_imported_table_and_checks_the_pin() {
    let f = Fixture::new("relay");
    let e = export("regtest");
    let dir = f.write(&e);
    let cfg = f.cfg("regtest", "");
    let root = run(&cfg, &dir, &e.digest, false, 0)
        .unwrap()
        .export
        .table_root;
    let np = NodePool::from_parts([0x7A; 32], vec![0x51, 0x20], 60.0, 20)
        .with_halving(ghost_common::canonical_payout::Halving::REGTEST);

    let mut wrong = cfg.clone();
    wrong.genesis_table_digest = Some(hex::encode([5u8; 32]));
    let err = crate::node_pool_relay::start(&wrong, &np)
        .await
        .err()
        .expect("a wrong pin is refused");
    assert!(err.contains("differs from the pinned"), "{err}");

    let mut pinned = cfg.clone();
    pinned.genesis_table_digest = Some(hex::encode(root));
    let (h, parts) = crate::node_pool_relay::start_with_parts(&pinned, &np, None)
        .await
        .unwrap();
    assert_eq!(parts.genesis_table_digest, root);
    h.task.abort();
}
