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
//| FILE: net_tests.rs                                                                                                   |
//|======================================================================================================================|

//! The relay over real TCP on loopback: discovery, convergence, credits, and a ban for garbage.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use ghost_common::anchor_chain::ShareId;
use ghost_common::share_commit::batch_root;
use ghost_storage::Database;

use crate::headers::HeaderOracle;
use crate::net::{spawn, NetConfig, RelayHandle};
use crate::relay::{JobAnchor, Relay};
use crate::testkit::*;

struct TestNode {
    handle: RelayHandle,
    db: Arc<Database>,
    job: Arc<Mutex<Option<JobAnchor>>>,
    miner: Miner,
}

fn wall() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn node(i: u8, btc: &Btc, peers: Vec<std::net::SocketAddr>) -> TestNode {
    node_with(i, btc, peers, None).await
}

async fn node_with(
    i: u8,
    btc: &Btc,
    peers: Vec<std::net::SocketAddr>,
    node_id: Option<[u8; 32]>,
) -> TestNode {
    let db = Arc::new(Database::in_memory().unwrap());
    let mut p = params();
    p.backstop_secs = 1;
    let mut relay = Relay::open(p, db.clone(), fed_archive(START_TIP)).unwrap();
    relay.set_btc_tip(btc.tip);
    let job = Arc::new(Mutex::new(relay.job_anchor()));
    let sink = job.clone();
    let cfg = NetConfig {
        listen: Some("127.0.0.1:0".parse().unwrap()),
        peers,
        tick_ms: 100,
        dial_secs: 1,
        node_id,
        ..NetConfig::default()
    };
    let oracle: Arc<dyn HeaderOracle> = Arc::new(btc.headers.clone());
    let handle = spawn(
        relay,
        cfg,
        oracle,
        Arc::new(move |j| *sink.lock().unwrap() = Some(j)),
    )
    .await
    .unwrap();
    let mut miner = Miner::new(&format!("tcp-miner-{i}"), i);
    miner.time = wall() as u32;
    TestNode {
        handle,
        db,
        job,
        miner,
    }
}

impl TestNode {
    /// A share on this node's latest job, through its local queue. Returns its id.
    async fn mine(&mut self, btc: &Btc, anchor: bool) -> ShareId {
        let job = self.job.lock().unwrap().expect("published");
        let tier = if anchor { 18 } else { 10 };
        let s = self.miner.build(job, &genesis_table(), btc.tip, tier);
        let id = s.id();
        self.handle.local.send(s).await.unwrap();
        id
    }

    /// The batch root of this node's latest published job.
    fn job_batch_root(&self) -> Option<[u8; 32]> {
        self.job.lock().unwrap().map(|j| j.batch_root)
    }

    fn status(&self) -> crate::relay::RelayStatus {
        *self.handle.status.borrow()
    }
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let t = Instant::now();
    while !f() {
        assert!(t.elapsed() < Duration::from_secs(30), "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_over_tcp_discover_each_other_and_converge() {
    let btc = Btc::with_time(START_TIP, wall());
    let mut a = node(1, &btc, vec![]).await;
    let mut b = node(2, &btc, vec![a.handle.listen_addr.unwrap()]).await;
    // C knows only B, and finds A through B's address list.
    let mut c = node(3, &btc, vec![b.handle.listen_addr.unwrap()]).await;
    wait_for("full mesh", || {
        [&a, &b, &c].iter().all(|n| n.status().peers >= 2)
    })
    .await;

    let mut ids = Vec::new();
    for n in [&mut a, &mut b, &mut c] {
        ids.push(n.mine(&btc, false).await);
        ids.push(n.mine(&btc, false).await);
    }
    wait_for("shares relayed", || {
        [&a, &b, &c].iter().all(|n| n.status().loose == 6)
    })
    .await;
    // The 1 s backstop re-batches them into every node's job. Wait for that job rather than for
    // a fixed time: the re-batch runs on the relay's tick, and on a slow runner a fixed sleep let
    // B mine its anchor on a job that still committed fewer than six shares, so a miner was
    // missing from the ledger. All six share one job height, so the batch orders them by id.
    ids.sort_unstable();
    let all_six = batch_root(&ids);
    wait_for("every job commits all six shares", || {
        [&a, &b, &c]
            .iter()
            .all(|n| n.job_batch_root() == Some(all_six))
    })
    .await;
    b.mine(&btc, true).await;
    wait_for("one anchor everywhere", || {
        [&a, &b, &c].iter().all(|n| n.status().height == 1)
    })
    .await;
    let best = a.status().best;
    assert!([&b, &c].iter().all(|n| n.status().best == best));
    let ledger = a.db.np_ledger_table().unwrap();
    assert_eq!(b.db.np_ledger_table().unwrap(), ledger);
    assert_eq!(c.db.np_ledger_table().unwrap(), ledger);
    for n in [&a, &b, &c] {
        assert!(ledger[&n.miner.payee].owed > 0, "every miner credited");
        assert_eq!(n.status().stats.shares_invalid, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_sending_garbage_is_banned() {
    let btc = Btc::with_time(START_TIP, wall());
    let a = node(1, &btc, vec![]).await;
    let addr = a.handle.listen_addr.unwrap();

    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 4096];
    let n = s.read(&mut buf).await.unwrap();
    assert!(n > 5 && buf[4] == 0, "the node speaks first with Hello");
    // A known type over its payload cap (a 33-byte `GetBatch`): refused from its header.
    s.write_all(&[33, 0, 0, 0, 4]).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "the connection is closed");

    // The address is banned: a new connection is dropped before any Hello.
    let mut s = TcpStream::connect(addr).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await;
    assert!(matches!(r, Ok(Ok(0)) | Ok(Err(_))), "{r:?}");
}

/// Read one frame of a known type off a raw stream.
async fn raw_frame(s: &mut TcpStream) -> crate::wire::Message {
    use crate::wire::{FrameHead, Message, FRAME_HEADER_LEN};
    let mut h = [0u8; FRAME_HEADER_LEN];
    s.read_exact(&mut h).await.unwrap();
    let FrameHead::Known(t, len) = Message::read_header(&h).unwrap() else {
        panic!("the node sent a type it does not know")
    };
    let mut p = vec![0u8; len];
    s.read_exact(&mut p).await.unwrap();
    Message::decode_payload(t, &p).unwrap()
}

/// Forward compatibility: a newer peer's message types are skipped without penalty, so the
/// connection carries on, and only a malformed frame of a known type is scored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_message_types_are_ignored_without_penalty() {
    use crate::wire::{Hello, Message, PROTOCOL_VERSION};
    let btc = Btc::with_time(START_TIP, wall());
    let a = node(1, &btc, vec![]).await;
    let addr = a.handle.listen_addr.unwrap();

    let mut s = TcpStream::connect(addr).await.unwrap();
    let Message::Hello(theirs) = raw_frame(&mut s).await else {
        panic!("the node speaks first with Hello")
    };
    let ours = Hello {
        version: PROTOCOL_VERSION,
        genesis: genesis_hash(),
        nonce: 0x5EED,
        listen_port: 0,
        tip: theirs.tip,
        tip_work: theirs.tip_work,
        user_agent: "newer-build/test".into(),
    };
    s.write_all(&Message::Hello(ours).encode()).await.unwrap();
    // Types this build does not know, empty and with a payload, before and after the handshake
    // settles: each is skipped.
    for (code, payload) in [
        (200u8, vec![]),
        (77, vec![7u8; 1_000]),
        (255, vec![1, 2, 3]),
    ] {
        let mut f = (payload.len() as u32).to_le_bytes().to_vec();
        f.push(code);
        f.extend_from_slice(&payload);
        s.write_all(&f).await.unwrap();
    }
    // The connection still works: a known request after them is answered.
    s.write_all(&Message::GetAddr.encode()).await.unwrap();
    let answered = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Message::Addr(_) = raw_frame(&mut s).await {
                return;
            }
        }
    })
    .await;
    assert!(
        answered.is_ok(),
        "a request after unknown frames is answered"
    );
    wait_for("the peer counted", || a.status().peers == 1).await;

    // Not banned: a fresh connection gets a Hello.
    let mut s2 = TcpStream::connect(addr).await.unwrap();
    let hello = tokio::time::timeout(Duration::from_secs(5), raw_frame(&mut s2)).await;
    assert!(matches!(hello, Ok(Message::Hello(_))), "{hello:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_node_serves_its_job_stamps_and_a_bare_relay_does_not() {
    use crate::client::{fetch_stamps, ClientError, Session};
    let btc = Btc::with_time(START_TIP, wall());
    let a = node_with(1, &btc, vec![], Some([0xA1; 32])).await;
    let addr = a.handle.listen_addr.unwrap();
    let t = Duration::from_secs(5);
    let job = a.job.lock().unwrap().expect("published at start");

    let (hello, stamps) = fetch_stamps(addr, genesis_hash(), "ghost-audit/test", t)
        .await
        .unwrap();
    assert_eq!(hello.genesis, genesis_hash());
    assert_eq!(stamps.node_id, [0xA1; 32]);
    assert_eq!(stamps.recent.first(), Some(&job), "newest first");

    // Another share chain is refused by name, before anything is asked.
    let wrong = Session::open(addr, [9; 32], "ghost-audit/test", t).await;
    assert!(matches!(wrong, Err(ClientError::Genesis { .. })));

    // A relay with no pool attached has nothing to stamp.
    let b = node(2, &btc, vec![]).await;
    let r = fetch_stamps(b.handle.listen_addr.unwrap(), genesis_hash(), "x", t).await;
    assert!(matches!(r, Err(ClientError::NoStamps)), "{:?}", r.err());
}
