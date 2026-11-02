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
//! answers its table requests), a stratum server speaking SV1 that serves honest and hostile
//! jobs built the way pool_sv2 builds them, and an SV2 server (real Noise handshake, real SV2
//! framing) whose jobs are built by the vendored channel and job-factory code pool_sv2 runs.

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
use ghost_audit::probe::{probe, ProbeConfig, ProbeVerdict, Sv2Endpoint};
use ghost_audit::source::{
    start_share_chain_on, ChainConfig, ExportSource, GenesisSource, RelayChain,
};
use ghost_audit::sv1::Sv1Config;
use ghost_audit::sv2::{Sv2Config, Sv2Device, Sv2Error, DEFAULT_HASH_RATE};
use ghost_audit::{audit_jobs, audit_sv2_jobs, AuditTarget, RelayStamps, Sv2Target};
use ghost_common::canonical_payout::{
    coinbase_outputs, table_root, Balance, CoinbaseOutput, Table,
};
use ghost_common::coinbase_tags::{encode_node_tag, encode_payout_tag};
use ghost_common::node_pool_constants::FACE_PER_SAT;
use ghost_common::node_pool_genesis_export::{sample_export, EXPORT_BIN, EXPORT_JSON};
use ghost_common::node_pool_network::NodePoolNetwork;
use ghost_common::node_pool_u256::U256;
use ghost_common::share_commit::ShareTagPreimage;
use ghost_np_relay::archive::{ArchivedBlock, BtcArchive};
use ghost_np_relay::headers::{HeaderOracle, MemHeaders};
use ghost_np_relay::net::{spawn_with_settlement, NetConfig, RelayHandle};
use ghost_np_relay::relay::{Genesis, JobAnchor, Relay, RelayParams};
use ghost_np_relay::settlement::{BlockSource, MemBlocks, SettledView, Settlement};
use ghost_np_relay::wire::NodeAdvert;
use ghost_storage::Database;
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use stratum_apps::network_helpers::accept_noise_connection;
use stratum_apps::network_helpers::noise_stream::NoiseTcpWriteHalf;
use stratum_apps::stratum_core::bitcoin::Target;
use stratum_apps::stratum_core::channels_sv2::server::extended::ExtendedChannel;
use stratum_apps::stratum_core::channels_sv2::server::jobs::job_store::DefaultJobStore;
use stratum_apps::stratum_core::channels_sv2::server::standard::StandardChannel;
use stratum_apps::stratum_core::channels_sv2::target::tier_target;
use stratum_apps::stratum_core::codec_sv2::StandardSv2Frame;
use stratum_apps::stratum_core::common_messages_sv2::SetupConnectionSuccess;
use stratum_apps::stratum_core::mining_sv2::{
    OpenExtendedMiningChannelSuccess, OpenStandardMiningChannelSuccess,
    SetNewPrevHash as MiningPrevHash,
};
use stratum_apps::stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining};
use stratum_apps::stratum_core::template_distribution_sv2::{
    NewTemplate, SetNewPrevHash as TemplatePrevHash,
};
use stratum_apps::utils::protocol_message_type::{protocol_message_type, MessageType};

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

/// The cutover export's height in these tests.
const EXPORT_H: u64 = 900;

/// The rows of the network's published ledger export: 30 balances carried over at the cutover.
fn export_rows(extra: u128) -> Vec<(Vec<u8>, u128)> {
    let mut r: Vec<(Vec<u8>, u128)> = (0..30u32)
        .map(|i| {
            let face = (2_000 + 100 * i as u128) * FACE_PER_SAT as u128;
            (
                p2tr(&format!("m{i}")),
                face + if i == 0 { extra } else { 0 },
            )
        })
        .collect();
    r.sort();
    r
}

/// The network's genesis table: the export's, as every node imports it.
fn genesis_table() -> Table {
    ghost_common::node_pool_genesis_export::genesis_table(&export_rows(0), EXPORT_H as u32).unwrap()
}

/// The digest the network pins: the genesis table's `table_root`.
fn pinned() -> [u8; 32] {
    table_root(&genesis_table())
}

/// An export directory as the network publishes it, removed on drop.
struct ExportDir(std::path::PathBuf);

impl Drop for ExportDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn export_dir(tag: &str, extra: u128) -> (ExportDir, ExportSource) {
    let p = std::env::temp_dir().join(format!(
        "ghost-audit-e2e-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    let rows = export_rows(extra);
    let (bin, json, digest) = sample_export("regtest", EXPORT_H, &rows, &rows);
    std::fs::write(p.join(EXPORT_BIN), bin).unwrap();
    std::fs::write(p.join(EXPORT_JSON), json).unwrap();
    let src = ExportSource {
        dir: p.clone(),
        digest,
    };
    (ExportDir(p), src)
}

/// The auditor's own relay node, started as `ghost-audit` starts it: its genesis table loaded
/// from `export` and held to `pin` before anything is judged.
async fn auditor_chain(
    blocks: &MemBlocks,
    export: Option<ExportSource>,
    pin: Option<[u8; 32]>,
) -> Result<RelayChain, String> {
    let cfg = ChainConfig {
        data_dir: std::env::temp_dir(),
        genesis_table: GenesisSource {
            network: NodePoolNetwork::Regtest,
            export,
            pinned: pin,
        },
        genesis_anchor: GENESIS,
        genesis_height: G,
        genesis_tier: 10,
        tier_base: U256::from_be_bytes([0xFF; 32]),
        relay_peers: vec![],
        rpc_host: String::new(),
        rpc_port: 0,
        rpc_user: String::new(),
        rpc_password: String::new(),
    };
    let headers = MemHeaders::default();
    headers.set_tip(TIP);
    start_share_chain_on(
        &cfg,
        Arc::new(Database::in_memory().unwrap()),
        BtcArchive::in_memory(),
        Arc::new(headers),
        Arc::new(blocks.clone()),
        NetConfig {
            tick_ms: 100,
            dial_secs: 1,
            ..NetConfig::default()
        },
    )
    .await
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
    relay_with(blocks, listen, node_id, stamp, None, vec![]).await
}

/// [`relay`], advertising `advert` and dialling `peers`.
async fn relay_with(
    blocks: &MemBlocks,
    listen: bool,
    node_id: Option<[u8; 32]>,
    stamp: Arc<Mutex<Option<JobAnchor>>>,
    advert: Option<NodeAdvert>,
    peers: Vec<std::net::SocketAddr>,
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
            advert,
            peers,
            dial_secs: 1,
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

/// The stamp push (`GHPP` slot and `GHNT` tag) and outputs (witness commitment last) of a job
/// pool_sv2 would build on `stamp` for `payee` with `class` and `tier`, then bent.
fn job_parts(
    stamp: JobAnchor,
    payee: &[u8],
    how: Hostile,
    class: u16,
    tier: u8,
    fees: u64,
) -> (Vec<u8>, Vec<CoinbaseOutput>) {
    let table = genesis_table();
    let mut tag = ShareTagPreimage {
        node_id: NODE_ID,
        tier,
        slot_class: class,
        payee_script: payee.to_vec(),
        parent_anchor: stamp.parent_anchor,
        batch_root: stamp.batch_root,
    };
    let outs = |t: &Table, c: u16| {
        coinbase_outputs(H, t, c as usize, &p2tr("finder"), fees, &[7; 32])
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
    let mut push = encode_payout_tag(&tag.parent_anchor_tag());
    push.extend(encode_node_tag(&tag.tag()));
    (push, o)
}

/// `mining.notify` params for a job pool_sv2 would build on `stamp` for `payee`, then bent.
fn notify(id: usize, prev: [u8; 32], stamp: JobAnchor, payee: &[u8], how: Hostile) -> Vec<Value> {
    let (push, o) = job_parts(stamp, payee, how, 9, 10, 25_000);
    let mut sig = bitcoin::script::Builder::new()
        .push_int(H as i64)
        .into_bytes();
    sig.extend(push);
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
    stratum_on(TcpListener::bind("127.0.0.1:0").await.unwrap(), jobs)
}

/// [`stratum`] on a listener already bound.
fn stratum_on(l: TcpListener, jobs: Vec<Vec<Value>>) -> String {
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
    _export: ExportDir,
}

async fn world() -> World {
    let blocks = bitcoin_chain();
    let prev = blocks.at(TIP).unwrap().hash();
    let stamp = Arc::new(Mutex::new(None));
    let node = relay(&blocks, true, Some(NODE_ID), stamp.clone()).await;
    let (export, src) = export_dir("world", 0);
    let chain = auditor_chain(&blocks, Some(src), Some(pinned()))
        .await
        .expect("the auditor starts on the network's genesis table");
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
        _export: export,
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

/// The genesis table is not empty here (30 balances carried over at the cutover): the honest
/// jobs above pass because the auditor started from the network's own table. An auditor on any
/// other table refuses to start, so nothing is audited, probed or listed on it; and one that did
/// run on another table (no pin, regtest) would condemn the honest node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_auditor_on_another_genesis_table_refuses_to_start() {
    assert_eq!(genesis_table().len(), 30);
    let blocks = bitcoin_chain();

    let (_a, other) = export_dir("other", 1);
    let e = auditor_chain(&blocks, Some(other.clone()), Some(pinned()))
        .await
        .err()
        .expect("refused");
    assert!(e.contains("refusing to audit"), "{e}");
    let e = auditor_chain(&blocks, None, Some(pinned()))
        .await
        .err()
        .expect("an empty table is refused too");
    assert!(
        e.contains("refusing to audit") && e.contains("(0 rows)"),
        "{e}"
    );

    // Why: unpinned, the auditor runs on the other table and fails honest jobs.
    let prev = blocks.at(TIP).unwrap().hash();
    let stamp = Arc::new(Mutex::new(None));
    let node = relay(&blocks, true, Some(NODE_ID), stamp.clone()).await;
    let stamp = stamp_of(&stamp).await;
    let wrong = auditor_chain(&blocks, Some(other), None).await.unwrap();
    let me = p2tr("the miner");
    let addr = stratum(vec![notify(1, prev, stamp, &me, Hostile::Honest)]).await;
    let stamps = RelayStamps {
        addr: node.listen_addr.unwrap(),
        genesis: GENESIS,
        timeout: Duration::from_secs(5),
    };
    let r = audit_jobs(&target(addr, &me, 1), &stamps, &wrong, |_| {})
        .await
        .unwrap();
    assert_eq!(r[0].verdict, Verdict::Fail, "{}", r[0].detail);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_prober_verdict_has_its_shape() {
    let w = world().await;
    let me = p2tr("the prober");
    let cfg = |stratum: String| ProbeConfig {
        stratum: Some(stratum),
        sv2: None,
        relay: w.node.listen_addr.unwrap(),
        genesis: GENESIS,
        address: "bcrt1p-the-prober".into(),
        payee: me.clone(),
        user_agent: "ghost-audit-probe/test".into(),
        sv2_device: Sv2Device::default(),
        sv2_hash_rate: DEFAULT_HASH_RATE,
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
            "jobs_sv2",
            "listable",
            "node",
            "reasons",
            "schema",
            "stratum",
            "summary",
            "sv2",
            "verdict"
        ]
    );
    assert_eq!(v["schema"], "ghost-audit/probe/v2");
    assert_eq!(v["sv2"], Value::Null);
    assert_eq!(v["node"]["sv2"], Value::Null);
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
    gone.stratum = Some(dead.to_string());
    gone.timeout = Duration::from_secs(2);
    let r = probe(&gone, &w.chain).await;
    assert_eq!(r.verdict, ProbeVerdict::Unmeasured, "{:?}", r.reasons);
    assert!(!r.listable);
    assert!(r.reasons.contains(&"relay_unreachable".to_string()));

    // No stratum port at all: unmeasured.
    let mut none = cfg(String::new());
    none.stratum = None;
    let r = probe(&none, &w.chain).await;
    assert_eq!(r.verdict, ProbeVerdict::Unmeasured);
    assert_eq!(r.reasons, ["no_stratum"]);
}

/// Wait for a relay's job stamp.
async fn stamp_of(stamp: &Arc<Mutex<Option<JobAnchor>>>) -> JobAnchor {
    for _ in 0..100 {
        if let Some(s) = *stamp.lock().unwrap() {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no job stamp published");
}

/// Open listing end to end: nodes found from relay gossip alone (the lister is told only the
/// first), each read for its advert and probed on every advertised stratum port over several
/// rounds. The honest node (SV1 and SV2) is listed with its advertised endpoints, and so is an
/// SV2-only node, probed on SV2 alone; the one serving a coinbase with the wrong treasury is
/// probed every round and never listed; a relay that advertises no stratum port is a candidate
/// that is never listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_listing_lists_the_honest_node_and_never_the_cheat() {
    use ghost_audit::discover::{ask, Limits};
    use ghost_audit::lister::{run_round, LiveProber, RoundConfig};
    use ghost_audit::listing::{
        render_dns, render_node_list, DnsConfig, ListMeta, ListState, Policy,
    };

    let blocks = bitcoin_chain();
    let prev = blocks.at(TIP).unwrap().hash();
    let me = p2tr("the lister");

    // The cheat, its stratum port bound first so its relay can advertise it.
    let cheat_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cheat_sv1 = cheat_l.local_addr().unwrap().port();
    let cheat_stamp = Arc::new(Mutex::new(None));
    let cheat = relay_with(
        &blocks,
        true,
        Some(NODE_ID),
        cheat_stamp.clone(),
        Some(NodeAdvert {
            sv1_port: cheat_sv1,
            sv2_port: 0,
            sv2_authority_key: String::new(),
        }),
        vec![],
    )
    .await;
    let cs = stamp_of(&cheat_stamp).await;
    stratum_on(
        cheat_l,
        vec![
            notify(1, prev, cs, &me, Hostile::Honest),
            notify(2, prev, cs, &me, Hostile::WrongTreasury),
        ],
    );

    // A relay with no pool: no advert.
    let bare = relay_with(
        &blocks,
        true,
        None,
        Arc::new(Mutex::new(None)),
        None,
        vec![],
    )
    .await;

    // A node that serves SV2 only, honestly.
    let only2_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let only2_sv2 = only2_l.local_addr().unwrap().port();
    let only2_stamp = Arc::new(Mutex::new(None));
    let only2 = relay_with(
        &blocks,
        true,
        Some(NODE_ID),
        only2_stamp.clone(),
        Some(NodeAdvert {
            sv1_port: 0,
            sv2_port: only2_sv2,
            sv2_authority_key: SV2_PUB.into(),
        }),
        vec![],
    )
    .await;
    let os = stamp_of(&only2_stamp).await;
    sv2_pool_on(
        only2_l,
        Sv2Pool {
            prev,
            stamp: os,
            bend: HONEST,
            templates: 2,
        },
        me.clone(),
    );

    // The honest node, serving SV1 and SV2, which dials the other three, so its gossip names
    // them.
    let honest_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let honest_sv1 = honest_l.local_addr().unwrap().port();
    let honest_l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let honest_sv2 = honest_l2.local_addr().unwrap().port();
    let honest_stamp = Arc::new(Mutex::new(None));
    let honest = relay_with(
        &blocks,
        true,
        Some(NODE_ID),
        honest_stamp.clone(),
        Some(NodeAdvert {
            sv1_port: honest_sv1,
            sv2_port: honest_sv2,
            sv2_authority_key: SV2_PUB.into(),
        }),
        vec![
            cheat.listen_addr.unwrap(),
            bare.listen_addr.unwrap(),
            only2.listen_addr.unwrap(),
        ],
    )
    .await;
    let hs = stamp_of(&honest_stamp).await;
    stratum_on(
        honest_l,
        vec![
            notify(1, prev, hs, &me, Hostile::Honest),
            notify(2, prev, hs, &me, Hostile::Honest),
        ],
    );
    sv2_pool_on(
        honest_l2,
        Sv2Pool {
            prev,
            stamp: hs,
            bend: HONEST,
            templates: 2,
        },
        me.clone(),
    );
    // Let the honest node connect to all three.
    for _ in 0..100 {
        if honest.status.borrow().peers >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        honest.status.borrow().peers >= 3,
        "the honest node reached its peers"
    );

    let (_export, src) = export_dir("list", 0);
    let chain = auditor_chain(&blocks, Some(src), Some(pinned()))
        .await
        .unwrap();
    let prober = Arc::new(LiveProber {
        genesis: GENESIS,
        address: "bcrt1p-the-lister".into(),
        payee: me.clone(),
        user_agent: "ghost-audit-list/test".into(),
        sv2_device: Sv2Device::default(),
        sv2_hash_rate: DEFAULT_HASH_RATE,
        jobs: 2,
        wait: Duration::from_secs(20),
        timeout: Duration::from_secs(10),
        data: Arc::new(chain),
    });
    let cfg = RoundConfig {
        seeds: vec![honest.listen_addr.unwrap()],
        limits: Limits {
            allow_private: true,
            max_per_ip: 8,
            timeout: Duration::from_secs(5),
            ..Limits::default()
        },
        policy: Policy::default(),
        probe_concurrency: 4,
        forget_after_secs: 3_600,
    };
    let mut state = ListState::default();
    for round in 0..4u64 {
        let r = run_round(
            &mut state,
            &cfg,
            |a| ask(a, GENESIS, Duration::from_secs(5)),
            prober.clone(),
            round,
        )
        .await;
        assert_eq!(r.candidates, 4, "round {round}: {r:?}");
        assert_eq!(r.probed, 4);
        assert_eq!(
            r.outcomes,
            (2, 1, 1),
            "round {round}: {:?}",
            state.candidates
        );
    }
    let h = honest.listen_addr.unwrap();
    let o = only2.listen_addr.unwrap();
    let listed: Vec<_> = state.listed().map(|c| c.relay).collect();
    let mut want = vec![h, o];
    want.sort();
    assert_eq!(listed, want);
    let cheat_c = &state.candidates[&cheat.listen_addr.unwrap()];
    assert_eq!(cheat_c.counts(), (0, 4, 0));
    assert_eq!(
        cheat_c.history.back().unwrap().reasons,
        ["job_wrong_treasury"]
    );
    let bare_c = &state.candidates[&bare.listen_addr.unwrap()];
    assert_eq!(bare_c.counts(), (0, 0, 4));
    assert_eq!(bare_c.history.back().unwrap().reasons, ["advert_none"]);

    let meta = ListMeta {
        generated_at: 1_793_620_800,
        network: "regtest".into(),
        genesis_anchor: hex::encode(GENESIS),
        policy: Policy::default(),
    };
    let v: Value = serde_json::from_str(&render_node_list(&state, &meta)).unwrap();
    assert_eq!(v["listed"], 2);
    assert_eq!(v["candidates"], 4);
    let node = |relay: std::net::SocketAddr| {
        v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["relay"] == relay.to_string())
            .unwrap()
            .clone()
    };
    let n = node(h);
    assert_eq!(n["sv1"], format!("stratum+tcp://127.0.0.1:{honest_sv1}"));
    assert_eq!(n["sv2"], format!("127.0.0.1:{honest_sv2}"));
    assert_eq!(n["sv2_authority_key"], SV2_PUB);
    assert_eq!(n["node_id"], hex::encode(NODE_ID));
    assert_eq!(n["protocol_version"], 1);
    assert_eq!(n["recent"]["pass"], 4);
    let n = node(o);
    assert_eq!(n["sv1"], Value::Null);
    assert_eq!(n["sv2"], format!("127.0.0.1:{only2_sv2}"));
    assert_eq!(n["recent"]["pass"], 4);
    let dns = render_dns(
        &state,
        &DnsConfig {
            sv1_port: honest_sv1,
            ..DnsConfig::default()
        },
        0,
    );
    let records: Vec<&str> = dns.lines().filter(|l| !l.starts_with(';')).collect();
    assert_eq!(records, ["pool 300 IN A 127.0.0.1"]);
}

// ---------------------------------------------------------------------------------------------
// Stratum V2
// ---------------------------------------------------------------------------------------------

/// The test pool's authority key pair: pool_sv2's example config.
const SV2_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const SV2_SEC: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
/// A valid authority key that is not the pool's (the generator point's x coordinate).
const WRONG_KEY: &str = "9bZBweHhn6px2Quf1hADVUTrWxX65vtRBweWHP66kfkKGFTQRHs";
/// The class pool_sv2 serves a standard channel, and the one this test pool's extended channels
/// are sensed at.
const STD_CLASS: u16 = 500;
const EXT_CLASS: u16 = 9;
const NTIME: u32 = 1_700_003_600;

type Msg = AnyMessage<'static>;

/// How each channel kind's jobs depart from the canonical ones.
#[derive(Clone, Copy, Debug)]
struct Sv2Bend {
    ext: Hostile,
    std: Hostile,
}

const HONEST: Sv2Bend = Sv2Bend {
    ext: Hostile::Honest,
    std: Hostile::Honest,
};

/// What the test pool builds its jobs on.
#[derive(Clone)]
struct Sv2Pool {
    prev: [u8; 32],
    stamp: JobAnchor,
    bend: Sv2Bend,
    /// Templates per connection: the first future and activated, the rest live.
    templates: u64,
}

/// Template `k`: a BIP34 push and nothing else in the prefix (pool_sv2 strips the template's
/// own Ghost tags before stamping each channel's back in), a two-entry merkle path, the witness
/// commitment as the template's output, and fees that differ per template.
fn template(k: u64) -> NewTemplate<'static> {
    let prefix = bitcoin::script::Builder::new()
        .push_int(H as i64)
        .into_bytes();
    let witness = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(ghost_common::canonical_payout::witness_script(
            &[7; 32],
        )),
    };
    let path: Vec<stratum_apps::stratum_core::binary_sv2::U256<'static>> =
        vec![[0x11; 32].into(), [0x22; 32].into()];
    NewTemplate {
        template_id: k,
        future_template: k == 1,
        version: 0x2000_0000,
        coinbase_tx_version: 2,
        coinbase_prefix: prefix.try_into().unwrap(),
        coinbase_tx_input_sequence: u32::MAX,
        coinbase_tx_value_remaining: ghost_common::canonical_payout::subsidy(H) + fees_of(k),
        coinbase_tx_outputs_count: 1,
        coinbase_tx_outputs: bitcoin::consensus::serialize(&witness).try_into().unwrap(),
        coinbase_tx_locktime: 0,
        merkle_path: path.into(),
    }
}

fn fees_of(k: u64) -> u64 {
    25_000 + 1_000 * k
}

/// The reward outputs a channel factory takes: the canonical outputs without the witness
/// commitment, which the template supplies.
fn reward(o: Vec<CoinbaseOutput>) -> Vec<TxOut> {
    o[..o.len() - 1]
        .iter()
        .map(|(v, s)| TxOut {
            value: Amount::from_sat(*v),
            script_pubkey: ScriptBuf::from_bytes(s.clone()),
        })
        .collect()
}

async fn send(w: &mut NoiseTcpWriteHalf<Msg>, m: Msg) -> bool {
    let f: StandardSv2Frame<Msg> = m.try_into().unwrap();
    w.write_frame(f.into()).await.is_ok()
}

/// The tier pool_sv2 commits for a channel target, and the target quantised to it.
fn tier_of(target: &Target) -> (u8, Target) {
    let t = ghost_common::coinbase_tags::difficulty_to_tier_log2(target.difficulty_float());
    (t as u8, tier_target(t))
}

fn prev_hash_msg(channel_id: u32, job_id: u32, prev: [u8; 32]) -> Msg {
    AnyMessage::Mining(Mining::SetNewPrevHash(MiningPrevHash {
        channel_id,
        job_id,
        prev_hash: prev.into(),
        min_ntime: NTIME,
        nbits: BITS,
    }))
}

fn template_prev_hash(prev: [u8; 32]) -> TemplatePrevHash<'static> {
    TemplatePrevHash {
        template_id: 1,
        prev_hash: prev.into(),
        header_timestamp: NTIME,
        n_bits: BITS,
        target: [0xFF; 32].into(),
    }
}

/// The messages that open a channel and carry its jobs: the success, the first (future) job and
/// its `SetNewPrevHash`, then one live job per further template.
fn open_standard(pool: &Sv2Pool, request_id: u32, identity: String, payee: &[u8]) -> Vec<Msg> {
    let mut ch = StandardChannel::new_for_pool(
        1,
        identity,
        (0..16u8).map(|i| 0xC0 ^ i).collect(),
        Target::from_le_bytes([0xFF; 32]),
        DEFAULT_HASH_RATE,
        100,
        6.0,
        DefaultJobStore::new(),
        "GHOST".into(),
    )
    .unwrap();
    let (tier, q) = tier_of(ch.get_target());
    ch.set_target(q);
    let mut out = vec![AnyMessage::Mining(
        Mining::OpenStandardMiningChannelSuccess(OpenStandardMiningChannelSuccess {
            request_id: request_id.into(),
            channel_id: 1,
            target: ch.get_target().to_le_bytes().into(),
            extranonce_prefix: ch.get_extranonce_prefix().clone().try_into().unwrap(),
            group_channel_id: 0,
        }),
    )];
    for k in 1..=pool.templates {
        let (push, o) = job_parts(
            pool.stamp,
            payee,
            pool.bend.std,
            STD_CLASS,
            tier,
            fees_of(k),
        );
        ch.set_tier_commitment(Some((tier as u32, push)));
        ch.on_new_template(template(k), reward(o)).unwrap();
        if k == 1 {
            let id = ch.get_future_job_id_from_template_id(1).unwrap();
            let job = ch.get_future_job(id).unwrap().get_job_message().clone();
            out.push(AnyMessage::Mining(Mining::NewMiningJob(job)));
            ch.on_set_new_prev_hash(template_prev_hash(pool.prev))
                .unwrap();
            out.push(prev_hash_msg(1, id, pool.prev));
        } else {
            let job = ch.get_active_job().unwrap().get_job_message().clone();
            out.push(AnyMessage::Mining(Mining::NewMiningJob(job)));
        }
    }
    out
}

/// [`open_standard`] for an extended channel.
fn open_extended(pool: &Sv2Pool, request_id: u32, identity: String, payee: &[u8]) -> Vec<Msg> {
    let mut ch = ExtendedChannel::new_for_pool(
        1,
        identity,
        vec![0xE0, 0, 0, 1],
        Target::from_le_bytes([0xFF; 32]),
        DEFAULT_HASH_RATE,
        true,
        8,
        100,
        6.0,
        DefaultJobStore::new(),
        "GHOST".into(),
    )
    .unwrap();
    let (tier, q) = tier_of(ch.get_target());
    ch.set_target(q);
    let mut out = vec![AnyMessage::Mining(
        Mining::OpenExtendedMiningChannelSuccess(OpenExtendedMiningChannelSuccess {
            request_id,
            channel_id: 1,
            target: ch.get_target().to_le_bytes().into(),
            extranonce_size: ch.get_rollable_extranonce_size(),
            extranonce_prefix: ch.get_extranonce_prefix().clone().try_into().unwrap(),
            group_channel_id: 0,
        }),
    )];
    for k in 1..=pool.templates {
        let (push, o) = job_parts(
            pool.stamp,
            payee,
            pool.bend.ext,
            EXT_CLASS,
            tier,
            fees_of(k),
        );
        ch.set_tier_commitment(Some((tier as u32, push)));
        ch.on_new_template(template(k), reward(o)).unwrap();
        if k == 1 {
            let id = ch.get_future_job_id_from_template_id(1).unwrap();
            let job = ch.get_future_job(id).unwrap().get_job_message().clone();
            out.push(AnyMessage::Mining(Mining::NewExtendedMiningJob(job)));
            ch.on_set_new_prev_hash(template_prev_hash(pool.prev))
                .unwrap();
            out.push(prev_hash_msg(1, id, pool.prev));
        } else {
            let job = ch.get_active_job().unwrap().get_job_message().clone();
            out.push(AnyMessage::Mining(Mining::NewExtendedMiningJob(job)));
        }
    }
    out
}

/// An SV2 pool on `l`: the Noise responder for [`SV2_PUB`], `SetupConnection`, and channels of
/// either kind whose jobs pay `payee` (the test's miner; the pool does not parse the identity).
/// Panics if a share is ever submitted.
fn sv2_pool_on(l: TcpListener, pool: Sv2Pool, payee: Vec<u8>) -> String {
    let addr = l.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let (pool, payee) = (pool.clone(), payee.clone());
            tokio::spawn(async move {
                let Ok(noise) = accept_noise_connection::<Msg>(
                    s,
                    Secp256k1PublicKey::try_from(SV2_PUB.to_string()).unwrap(),
                    SV2_SEC.parse::<Secp256k1SecretKey>().unwrap(),
                    3_600,
                )
                .await
                else {
                    return;
                };
                let (mut r, mut w) = noise.into_split();
                while let Ok(f) = r.read_frame().await {
                    let mut f: StandardSv2Frame<Msg> = f.try_into().unwrap();
                    let h = f.get_header().unwrap();
                    let (ext, mt) = (h.ext_type(), h.msg_type());
                    let payload = f.payload();
                    let out = match protocol_message_type(ext, mt) {
                        MessageType::Common => {
                            let m: CommonMessages<'_> = (mt, payload).try_into().unwrap();
                            match m {
                                CommonMessages::SetupConnection(_) => {
                                    vec![AnyMessage::Common(
                                        SetupConnectionSuccess {
                                            used_version: 2,
                                            flags: 0,
                                        }
                                        .into(),
                                    )]
                                }
                                _ => vec![],
                            }
                        }
                        MessageType::Mining => {
                            let m: Mining<'_> = (mt, payload).try_into().unwrap();
                            match m {
                                Mining::OpenStandardMiningChannel(o) => open_standard(
                                    &pool,
                                    o.request_id.as_u32(),
                                    o.user_identity.as_utf8_or_hex(),
                                    &payee,
                                ),
                                Mining::OpenExtendedMiningChannel(o) => open_extended(
                                    &pool,
                                    o.request_id,
                                    o.user_identity.as_utf8_or_hex(),
                                    &payee,
                                ),
                                Mining::SubmitSharesStandard(_)
                                | Mining::SubmitSharesExtended(_) => {
                                    panic!("the auditor submitted a share")
                                }
                                _ => vec![],
                            }
                        }
                        _ => vec![],
                    };
                    for m in out {
                        if !send(&mut w, m).await {
                            return;
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn sv2_pool(pool: Sv2Pool, payee: &[u8]) -> String {
    sv2_pool_on(
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        pool,
        payee.to_vec(),
    )
}

fn sv2_target(addr: String, key: &str, payee: &[u8], jobs: usize, wait: u64) -> Sv2Target {
    Sv2Target {
        node: Sv2Config {
            addr,
            authority_key: key.into(),
            username: "bcrt1p-the-miner".into(),
            device: Sv2Device::parse("ghost-audit//test"),
            nominal_hash_rate: DEFAULT_HASH_RATE,
            timeout: Duration::from_secs(10),
        },
        payee: payee.to_vec(),
        jobs,
        wait: Duration::from_secs(wait),
        job_timeout: Duration::from_secs(10),
    }
}

fn verdicts(r: &[JobReport]) -> Vec<(String, Verdict, Option<FailReason>)> {
    let mut v: Vec<_> = r
        .iter()
        .map(|j| (j.job_id.clone(), j.verdict, j.reason))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

/// Honest SV2 jobs pass on both channels: the extended job's coinbase is judged directly, and
/// each standard job, which shows only a merkle root, is rebuilt from the extended job on the
/// same template and passes for the full slot class. Nothing is submitted (the pool panics).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_sv2_jobs_pass_on_extended_and_standard_channels() {
    let w = world().await;
    let me = p2tr("the miner");
    let pool = Sv2Pool {
        prev: w.prev,
        stamp: w.stamp,
        bend: HONEST,
        templates: 2,
    };
    let addr = sv2_pool(pool, &me).await;
    let stamps = RelayStamps {
        addr: w.node.listen_addr.unwrap(),
        genesis: GENESIS,
        timeout: Duration::from_secs(5),
    };
    let r = audit_sv2_jobs(
        &sv2_target(addr, SV2_PUB, &me, 2, 20),
        &stamps,
        &w.chain,
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(r.len(), 4, "{r:#?}");
    for j in &r {
        assert_eq!(j.verdict, Verdict::Pass, "{}: {}", j.job_id, j.detail);
        assert_eq!(j.height, Some(H));
        assert_eq!(j.parent_anchor, Some(hex::encode(GENESIS)));
        let class = if j.job_id.starts_with("std-") {
            STD_CLASS
        } else {
            EXT_CLASS
        };
        assert_eq!(j.slot_class, Some(class), "{}", j.job_id);
        assert!(j.tier.unwrap() >= 10);
    }
    let ids: Vec<String> = verdicts(&r).into_iter().map(|v| v.0).collect();
    assert_eq!(ids, ["ext-1", "ext-2", "std-1", "std-2"]);
}

/// Each channel kind is judged on its own: a node that bends only its standard jobs, or only
/// its extended jobs, is caught on that channel while the other passes. A standard job's
/// failure is named `standard_job_not_canonical`: a merkle root shows only that no canonical
/// coinbase crediting the miner is behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hostile_sv2_jobs_fail_on_the_channel_that_serves_them() {
    let w = world().await;
    let me = p2tr("the miner");
    let stamps = RelayStamps {
        addr: w.node.listen_addr.unwrap(),
        genesis: GENESIS,
        timeout: Duration::from_secs(5),
    };
    let not_canonical = Some(FailReason::StandardJobNotCanonical);
    let cases = [
        (
            Hostile::Honest,
            Hostile::RelabelledPayee,
            None,
            not_canonical,
        ),
        (Hostile::Honest, Hostile::TagToTheNode, None, not_canonical),
        (Hostile::Honest, Hostile::FeeSkim, None, not_canonical),
        (
            Hostile::Honest,
            Hostile::WrongSlotClass,
            None,
            not_canonical,
        ),
        (
            Hostile::WrongTreasury,
            Hostile::Honest,
            Some(FailReason::WrongTreasury),
            None,
        ),
        (
            Hostile::InflatedBalance,
            Hostile::Honest,
            Some(FailReason::InflatedBalance),
            None,
        ),
    ];
    for (ext, std, want_ext, want_std) in cases {
        let pool = Sv2Pool {
            prev: w.prev,
            stamp: w.stamp,
            bend: Sv2Bend { ext, std },
            templates: 1,
        };
        let addr = sv2_pool(pool, &me).await;
        let r = audit_sv2_jobs(
            &sv2_target(addr, SV2_PUB, &me, 1, 6),
            &stamps,
            &w.chain,
            |_| {},
        )
        .await
        .unwrap();
        let v = verdicts(&r);
        let verdict = |w: Option<FailReason>| {
            if w.is_some() {
                Verdict::Fail
            } else {
                Verdict::Pass
            }
        };
        assert_eq!(
            v,
            [
                ("ext-1".to_string(), verdict(want_ext), want_ext),
                ("std-1".to_string(), verdict(want_std), want_std)
            ],
            "ext {ext:?} std {std:?}: {r:#?}"
        );
    }
}

/// The authority key is checked in the Noise handshake: a node that cannot prove the key it is
/// audited against is refused before anything else is read, and a key that is not a key is
/// refused before connecting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_authority_key_is_refused() {
    let w = world().await;
    let me = p2tr("the miner");
    let pool = Sv2Pool {
        prev: w.prev,
        stamp: w.stamp,
        bend: HONEST,
        templates: 1,
    };
    let addr = sv2_pool(pool, &me).await;
    let stamps = RelayStamps {
        addr: w.node.listen_addr.unwrap(),
        genesis: GENESIS,
        timeout: Duration::from_secs(5),
    };
    let e = audit_sv2_jobs(
        &sv2_target(addr.clone(), WRONG_KEY, &me, 1, 5),
        &stamps,
        &w.chain,
        |_| panic!("no job may be judged"),
    )
    .await
    .expect_err("refused");
    assert!(matches!(e, Sv2Error::WrongKey(_)), "{e}");
    let e = audit_sv2_jobs(
        &sv2_target(addr, "not-a-key", &me, 1, 5),
        &stamps,
        &w.chain,
        |_| {},
    )
    .await
    .expect_err("refused");
    assert!(matches!(e, Sv2Error::BadKey(_)), "{e}");
}

/// The case SV1 alone cannot see: a node serving honest SV1 jobs and a bent coinbase to SV2
/// standard channels. The prober checks both protocols the node serves and fails it; with the
/// wrong authority key it fails it too, and an SV2-only node passes on SV2 alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_serving_sv2_differently_fails_the_probe() {
    let w = world().await;
    let me = p2tr("the prober");
    let sv1 = stratum(vec![
        notify(1, w.prev, w.stamp, &me, Hostile::Honest),
        notify(2, w.prev, w.stamp, &me, Hostile::Honest),
    ])
    .await;
    let pool = |std: Hostile| Sv2Pool {
        prev: w.prev,
        stamp: w.stamp,
        bend: Sv2Bend {
            ext: Hostile::Honest,
            std,
        },
        templates: 2,
    };
    let honest_sv2 = sv2_pool(pool(Hostile::Honest), &me).await;
    let bent_sv2 = sv2_pool(pool(Hostile::RelabelledPayee), &me).await;
    let cfg = |stratum: Option<String>, sv2: Option<(String, &str)>| ProbeConfig {
        stratum,
        sv2: sv2.map(|(addr, key)| Sv2Endpoint {
            addr,
            authority_key: key.into(),
        }),
        relay: w.node.listen_addr.unwrap(),
        genesis: GENESIS,
        address: "bcrt1p-the-prober".into(),
        payee: me.clone(),
        user_agent: "ghost-audit-probe/test".into(),
        sv2_device: Sv2Device::default(),
        sv2_hash_rate: DEFAULT_HASH_RATE,
        jobs: 2,
        wait: Duration::from_secs(6),
        timeout: Duration::from_secs(10),
    };

    // Both protocols honest: pass, with every job from both.
    let r = probe(
        &cfg(Some(sv1.clone()), Some((honest_sv2.clone(), SV2_PUB))),
        &w.chain,
    )
    .await;
    assert_eq!(r.verdict, ProbeVerdict::Pass, "{:?}", r.reasons);
    assert_eq!((r.jobs.len(), r.jobs_sv2.len()), (2, 4));
    assert_eq!(r.summary.pass, 6);
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["sv2"]["reachable"], true);
    assert_eq!(v["sv2"]["jobs_seen"], 4);
    assert_eq!(v["node"]["sv2"], honest_sv2);
    assert_eq!(v["node"]["sv2_authority_key"], SV2_PUB);

    // SV1 honest, SV2 standard jobs bent: SV1 alone would pass it; the probe fails it.
    let only_sv1 = probe(&cfg(Some(sv1.clone()), None), &w.chain).await;
    assert_eq!(only_sv1.verdict, ProbeVerdict::Pass);
    let r = probe(
        &cfg(Some(sv1.clone()), Some((bent_sv2.clone(), SV2_PUB))),
        &w.chain,
    )
    .await;
    assert_eq!(r.verdict, ProbeVerdict::Fail);
    assert!(!r.listable);
    assert_eq!(r.reasons, ["sv2_job_standard_job_not_canonical"]);
    assert!(r.jobs.iter().all(|j| j.verdict == Verdict::Pass));
    assert!(r
        .jobs_sv2
        .iter()
        .filter(|j| j.job_id.starts_with("ext-"))
        .all(|j| j.verdict == Verdict::Pass));

    // The wrong authority key fails the probe, whatever SV1 does.
    let r = probe(
        &cfg(Some(sv1), Some((honest_sv2.clone(), WRONG_KEY))),
        &w.chain,
    )
    .await;
    assert_eq!(r.verdict, ProbeVerdict::Fail);
    assert_eq!(r.reasons, ["sv2_authority_key"]);

    // An SV2-only node is probed on SV2 alone and passes.
    let r = probe(&cfg(None, Some((honest_sv2, SV2_PUB))), &w.chain).await;
    assert_eq!(r.verdict, ProbeVerdict::Pass, "{:?}", r.reasons);
    assert!(r.listable && r.stratum.is_none() && r.jobs.is_empty());
    assert_eq!(r.jobs_sv2.len(), 4);
}
