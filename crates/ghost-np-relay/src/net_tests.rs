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
    /// A share on this node's latest job, through its local queue.
    async fn mine(&mut self, btc: &Btc, anchor: bool) {
        let job = self.job.lock().unwrap().expect("published");
        let tier = if anchor { 18 } else { 10 };
        let s = self.miner.build(job, &genesis_table(), btc.tip, tier);
        self.handle.local.send(s).await.unwrap();
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

    for n in [&mut a, &mut b, &mut c] {
        n.mine(&btc, false).await;
        n.mine(&btc, false).await;
    }
    wait_for("shares relayed", || {
        [&a, &b, &c].iter().all(|n| n.status().loose == 6)
    })
    .await;
    // The 1 s backstop re-batches them into every node's job.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
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
    // A frame of an unknown type: refused from its header.
    s.write_all(&[0, 0, 0, 0, 99]).await.unwrap();
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
