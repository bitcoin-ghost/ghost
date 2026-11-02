//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: e2e.rs                                                                                                         |
//|======================================================================================================================|

//! ghost-audit end to end, in process: real `ghost-np-relay` nodes over loopback TCP (the audited
//! node's, which serves job stamps, and the auditor's own, which settles from a Bitcoin chain and
//! answers its table requests), and a stratum server speaking SV1 that serves honest and hostile
//! jobs built the way pool_sv2 builds them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use ghost_audit::check::{FailReason, JobReport, Verdict};
use ghost_audit::job::to_sv1_prev_hash;
use ghost_audit::probe::{probe, ProbeConfig, ProbeVerdict};
use ghost_audit::source::RelayChain;
use ghost_audit::sv1::Sv1Config;
use ghost_audit::{audit_jobs, AuditTarget, RelayStamps};
use ghost_common::canonical_payout::{coinbase_outputs, Balance, CoinbaseOutput, Table};
use ghost_common::coinbase_tags::{encode_node_tag, encode_payout_tag};
use ghost_common::node_pool_constants::FACE_PER_SAT;
use ghost_common::node_pool_u256::U256;
use ghost_common::share_commit::ShareTagPreimage;
use ghost_np_relay::archive::{ArchivedBlock, BtcArchive};
use ghost_np_relay::headers::{HeaderOracle, MemHeaders};
use ghost_np_relay::net::{spawn_with_settlement, NetConfig, RelayHandle};
use ghost_np_relay::relay::{Genesis, JobAnchor, Relay, RelayParams};
use ghost_np_relay::settlement::{BlockSource, MemBlocks, SettledView, Settlement};
use ghost_storage::Database;

const GENESIS: [u8; 32] = [0xEE; 32];
const G: u32 = 1_000;
const TIP: u32 = G + 5;
const H: u32 = TIP + 1;
const NODE_ID: [u8; 32] = [0xA1; 32];
const BITS: u32 = 0x207f_ffff;

fn p2tr(tag: &str) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&Sha256::digest(tag.as_bytes()));
    s
}

fn genesis_table() -> Table {
    (0..30u32)
        .map(|i| {
            let b = Balance {
                owed: (2_000 + 100 * i as i128) * FACE_PER_SAT,
                queue_since: Some(900 + i),
            };
            (p2tr(&format!("m{i}")), b)
        })
        .collect()
}

/// A plain Bitcoin chain from `G - 10` to `TIP`.
fn bitcoin_chain() -> MemBlocks {
    let blocks = MemBlocks::default();
    let mut prev = [0u8; 32];
    for h in G - 10..=TIP {
        let sig = bitcoin::script::Builder::new()
            .push_int(h as i64)
            .push_slice([0xAB; 4])
            .into_bytes();
        let cb = tx(sig, vec![(1, p2tr("someone"))]);
        let header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::from_byte_array(cb.compute_txid().to_byte_array()),
            time: 1_700_000_000 + 600 * h,
            bits: CompactTarget::from_consensus(BITS),
            nonce: 0,
        };
        let b = ArchivedBlock {
            header,
            height: h,
            coinbase: Some((cb, vec![])),
        };
        prev = b.hash();
        blocks.set(b);
    }
    blocks
}

fn tx(script_sig: Vec<u8>, outputs: Vec<CoinbaseOutput>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs
            .into_iter()
            .map(|(v, s)| TxOut {
                value: Amount::from_sat(v),
                script_pubkey: ScriptBuf::from_bytes(s),
            })
            .collect(),
    }
}

/// A relay node on the test genesis, settling from `blocks`.
async fn relay(
    blocks: &MemBlocks,
    listen: bool,
    node_id: Option<[u8; 32]>,
    stamp: Arc<Mutex<Option<JobAnchor>>>,
) -> RelayHandle {
    let db = Arc::new(Database::in_memory().unwrap());
    let params = RelayParams::new(
        Genesis {
            hash: GENESIS,
            btc_height: G,
            tier: 10,
            table: genesis_table(),
        },
        U256::from_be_bytes([0xFF; 32]),
    );
    let r = Relay::open(params, db.clone(), BtcArchive::in_memory()).unwrap();
    let headers = MemHeaders::default();
    headers.set_tip(TIP);
    let oracle: Arc<dyn HeaderOracle> = Arc::new(headers);
    let settlement = Settlement::new(db.clone(), SettledView::load(&db).unwrap(), G);
    let src: Arc<dyn BlockSource> = Arc::new(blocks.clone());
    spawn_with_settlement(
        r,
        NetConfig {
            listen: listen.then(|| "127.0.0.1:0".parse().unwrap()),
            tick_ms: 100,
            node_id,
            ..NetConfig::default()
        },
        oracle,
        Arc::new(move |j| *stamp.lock().unwrap() = Some(j)),
        Some((settlement, src)),
    )
    .await
    .unwrap()
}

/// How a served job departs from the canonical one.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Hostile {
    Honest,
    TagToTheNode,
    WrongTreasury,
    FeeSkim,
    RelabelledPayee,
    InflatedBalance,
    WrongSlotClass,
}

/// `mining.notify` params for a job pool_sv2 would build on `stamp` for `payee`, then bent.
fn notify(id: usize, prev: [u8; 32], stamp: JobAnchor, payee: &[u8], how: Hostile) -> Vec<Value> {
    let table = genesis_table();
    let class: u16 = 9;
    let mut tag = ShareTagPreimage {
        node_id: NODE_ID,
        tier: 10,
        slot_class: class,
        payee_script: payee.to_vec(),
        parent_anchor: stamp.parent_anchor,
        batch_root: stamp.batch_root,
    };
    let outs = |t: &Table, c: u16| {
        coinbase_outputs(H, t, c as usize, &p2tr("finder"), 25_000, &[7; 32])
            .unwrap()
            .0
    };
    let mut o = outs(&table, class);
    let finder = o.len() - 3;
    match how {
        Hostile::Honest => {}
        Hostile::TagToTheNode => tag.payee_script = p2tr("the node"),
        Hostile::WrongTreasury => o[0].1 = p2tr("the node"),
        Hostile::FeeSkim => {
            o[1].0 -= 500;
            o[finder].0 += 500;
        }
        Hostile::RelabelledPayee => o[3].1 = p2tr("the node"),
        Hostile::InflatedBalance => {
            let mut t = table.clone();
            t.insert(
                p2tr("the node"),
                Balance {
                    owed: 5_000_000 * FACE_PER_SAT,
                    queue_since: Some(950),
                },
            );
            o = outs(&t, class);
        }
        Hostile::WrongSlotClass => o = outs(&table, 3),
    }
    let mut sig = bitcoin::script::Builder::new()
        .push_int(H as i64)
        .into_bytes();
    sig.extend(encode_payout_tag(&tag.parent_anchor_tag()));
    sig.extend(encode_node_tag(&tag.tag()));
    sig.extend([0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
    let sig_len = sig.len();
    let raw = bitcoin::consensus::serialize(&tx(sig, o));
    // version 4, one input 1, prevout 36, scriptSig length 1: the extranonce is its last 8 bytes.
    let en = 4 + 1 + 36 + 1 + sig_len - 8;
    vec![
        json!(id.to_string()),
        json!(to_sv1_prev_hash(&prev)),
        json!(hex::encode(&raw[..en])),
        json!(hex::encode(&raw[en + 8..])),
        json!([]),
        json!("20000000"),
        json!(format!("{BITS:08x}")),
        json!("65f00000"),
        json!(true),
    ]
}

/// An SV1 server that answers subscribe and authorize, then sends `jobs` on every connection.
async fn stratum(jobs: Vec<Vec<Value>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let jobs = jobs.clone();
            tokio::spawn(async move {
                let (r, mut w) = s.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let m: Value = serde_json::from_str(&line).unwrap();
                    let id = m["id"].clone();
                    let mut out = Vec::new();
                    match m["method"].as_str() {
                        Some("mining.subscribe") => out.push(json!({
                            "id": id, "error": null,
                            "result": [[["mining.notify", "1"]], "00000000", 4]
                        })),
                        Some("mining.authorize") => {
                            out.push(json!({"id": id, "error": null, "result": true}));
                            out.push(json!({"id": null, "method": "mining.set_difficulty",
                                "params": [1024.0]}));
                            for j in &jobs {
                                out.push(
                                    json!({"id": null, "method": "mining.notify", "params": j}),
                                );
                            }
                        }
                        Some("mining.submit") => panic!("the auditor submitted a share"),
                        _ => {}
                    }
                    for v in out {
                        let mut b = serde_json::to_vec(&v).unwrap();
                        b.push(b'\n');
                        if w.write_all(&b).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

struct World {
    node: RelayHandle,
    chain: RelayChain,
    stamp: JobAnchor,
    prev: [u8; 32],
}

async fn world() -> World {
    let blocks = bitcoin_chain();
    let prev = blocks.at(TIP).unwrap().hash();
    let stamp = Arc::new(Mutex::new(None));
    let node = relay(&blocks, true, Some(NODE_ID), stamp.clone()).await;
    let mine = relay(&blocks, false, None, Arc::new(Mutex::new(None))).await;
    let chain = RelayChain::from_handle(mine, Arc::new(blocks));
    for _ in 0..100 {
        if stamp.lock().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stamp = stamp
        .lock()
        .unwrap()
        .expect("the node published a job stamp");
    assert_eq!(stamp.parent_anchor, GENESIS);
    World {
        node,
        chain,
        stamp,
        prev,
    }
}

fn target(stratum: String, payee: &[u8], jobs: usize) -> AuditTarget {
    AuditTarget {
        stratum: Sv1Config {
            addr: stratum,
            username: "bcrt1p-the-miner".into(),
            password: "x".into(),
            user_agent: "ghost-audit/test".into(),
            timeout: Duration::from_secs(10),
        },
        payee: payee.to_vec(),
        jobs,
        wait: Duration::from_secs(20),
        job_timeout: Duration::from_secs(10),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_jobs_pass_and_each_hostile_job_gets_its_named_fail() {
    let w = world().await;
    let me = p2tr("the miner");
    let cases = [
        (Hostile::Honest, None),
        (Hostile::TagToTheNode, Some(FailReason::TagNotBinding)),
        (Hostile::WrongTreasury, Some(FailReason::WrongTreasury)),
        (Hostile::FeeSkim, Some(FailReason::FeeSkim)),
        (Hostile::RelabelledPayee, Some(FailReason::RelabelledPayee)),
        (Hostile::InflatedBalance, Some(FailReason::InflatedBalance)),
        (Hostile::WrongSlotClass, Some(FailReason::WrongSlotClass)),
        (Hostile::Honest, None),
    ];
    let jobs = cases
        .iter()
        .enumerate()
        .map(|(i, (how, _))| notify(i, w.prev, w.stamp, &me, *how))
        .collect();
    let addr = stratum(jobs).await;
    let stamps = RelayStamps {
        addr: w.node.listen_addr.unwrap(),
        genesis: GENESIS,
        timeout: Duration::from_secs(5),
    };
    let mut printed = 0;
    let reports: Vec<JobReport> =
        audit_jobs(&target(addr, &me, cases.len()), &stamps, &w.chain, |_| {
            printed += 1
        })
        .await
        .unwrap();
    assert_eq!(printed, cases.len());
    for ((how, want), r) in cases.iter().zip(&reports) {
        assert_eq!(r.reason, *want, "{how:?}: {}", r.detail);
        let v = if want.is_some() {
            Verdict::Fail
        } else {
            Verdict::Pass
        };
        assert_eq!(r.verdict, v, "{how:?}: {}", r.detail);
        assert_eq!(r.height, Some(H));
    }
    assert_eq!(reports[0].slot_class, Some(9));
    assert_eq!(reports[0].parent_anchor, Some(hex::encode(GENESIS)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_prober_verdict_has_its_shape() {
    let w = world().await;
    let me = p2tr("the prober");
    let cfg = |stratum: String| ProbeConfig {
        stratum,
        relay: w.node.listen_addr.unwrap(),
        genesis: GENESIS,
        address: "bcrt1p-the-prober".into(),
        payee: me.clone(),
        user_agent: "ghost-audit-probe/test".into(),
        jobs: 2,
        wait: Duration::from_secs(20),
        timeout: Duration::from_secs(10),
    };

    // An honest node is listable.
    let honest = stratum(vec![
        notify(1, w.prev, w.stamp, &me, Hostile::Honest),
        notify(2, w.prev, w.stamp, &me, Hostile::Honest),
    ])
    .await;
    let r = probe(&cfg(honest.clone()), &w.chain).await;
    assert_eq!(r.verdict, ProbeVerdict::Pass, "{:?}", r.reasons);
    assert!(r.listable && r.reasons.is_empty());
    let v = serde_json::to_value(&r).unwrap();
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "advert",
            "checked_at",
            "jobs",
            "listable",
            "node",
            "reasons",
            "schema",
            "stratum",
            "summary",
            "verdict"
        ]
    );
    assert_eq!(v["schema"], "ghost-audit/probe/v1");
    assert_eq!(v["verdict"], "pass");
    assert_eq!(v["advert"]["reachable"], true);
    assert_eq!(v["advert"]["genesis_match"], true);
    assert_eq!(v["advert"]["protocol_version"], 1);
    assert_eq!(v["advert"]["stamps_served"], true);
    assert_eq!(v["advert"]["node_id"], hex::encode(NODE_ID));
    assert_eq!(v["stratum"]["reachable"], true);
    assert_eq!(v["stratum"]["jobs_seen"], 2);
    assert_eq!(v["summary"], json!({"pass": 2, "fail": 0, "unchecked": 0}));
    assert_eq!(v["jobs"][0]["verdict"], "PASS");
    for k in [
        "job_id",
        "verdict",
        "reason",
        "detail",
        "height",
        "prev_hash",
        "parent_anchor",
        "slot_class",
        "tier",
        "outputs",
        "coinbase_bytes",
    ] {
        assert!(v["jobs"][0].get(k).is_some(), "job field {k}");
    }

    // A node serving a relabelled payee fails, by named reason.
    let hostile = stratum(vec![
        notify(1, w.prev, w.stamp, &me, Hostile::Honest),
        notify(2, w.prev, w.stamp, &me, Hostile::RelabelledPayee),
    ])
    .await;
    let r = probe(&cfg(hostile), &w.chain).await;
    assert_eq!(r.verdict, ProbeVerdict::Fail);
    assert!(!r.listable);
    assert_eq!(r.reasons, ["job_relabelled_payee"]);
    assert_eq!(r.summary.fail, 1);

    // A relay on another share chain fails before any job is judged.
    let mut other = cfg(honest.clone());
    other.genesis = [7; 32];
    let r = probe(&other, &w.chain).await;
    assert_eq!(r.verdict, ProbeVerdict::Fail);
    assert_eq!(r.reasons, ["relay_genesis"]);
    assert!(r.jobs.is_empty());

    // Nothing listening: unmeasured, not listed and not condemned.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead = closed.local_addr().unwrap();
    drop(closed);
    let mut gone = cfg(honest);
    gone.relay = dead;
    gone.stratum = dead.to_string();
    gone.timeout = Duration::from_secs(2);
    let r = probe(&gone, &w.chain).await;
    assert_eq!(r.verdict, ProbeVerdict::Unmeasured, "{:?}", r.reasons);
    assert!(!r.listable);
    assert!(r.reasons.contains(&"relay_unreachable".to_string()));
}
