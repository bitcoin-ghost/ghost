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
//| FILE: sync_tests.rs                                                                                                  |
//|======================================================================================================================|

//! Share-chain sync (W2.13) over the in-process network: a fresh node reaches the same chain and
//! root as the nodes that relayed it live, across share-chain and Bitcoin reorgs, after a
//! restart, past lying peers and from a pruned peer; checkpoints restart and rebuild; and
//! settlement is deterministic once archives agree.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bitcoin::consensus::deserialize;
use ghost_common::canonical_payout::{table_root, Table};
use ghost_storage::Database;

use crate::archive::{ArchivedBlock, BtcArchive};
use crate::checkpoint::digest;
use crate::peers::penalty;
use crate::relay::{Relay, RelayParams};
use crate::settlement::MemBlocks;
use crate::testkit::*;
use crate::wire::{Message, MsgType};

/// Relay parameters with checkpoints every `interval` blocks at `depth` (0: none).
fn params_with(depth: u32, interval: u32, prune: bool) -> RelayParams {
    let mut p = params();
    p.checkpoint_depth = depth;
    p.checkpoint_interval = interval;
    p.prune = prune;
    p
}

fn open(p: RelayParams, db: Arc<Database>) -> Relay {
    Relay::open(p, db, fed_archive(START_TIP)).expect("open")
}

/// A relay whose archive is persisted in its store, as a running node's is.
fn open_persistent(p: RelayParams, db: Arc<Database>) -> Relay {
    let a = BtcArchive::open(db.clone()).expect("archive");
    a.trust_work_for_tests();
    Relay::open(p, db, a).expect("open")
}

fn mem() -> Arc<Database> {
    Arc::new(Database::in_memory().expect("db"))
}

/// Node `i` mines `blocks` Bitcoin blocks' worth of chain: in each, `per` rounds of one network
/// share and one anchor, then the Bitcoin tip moves on. Everyone linked receives it.
fn grow(s: &mut Sim, i: usize, blocks: u32, per: u32) {
    for _ in 0..blocks {
        for _ in 0..per {
            s.mine(i, false);
            s.mine(i, true);
        }
        let t = s.btc.tip + 1;
        s.btc.extend_to(t);
        s.tick(1);
    }
}

/// The root of the table a job on node `i`'s best tip pays on Bitcoin block `prev`.
fn root_on(s: &mut Sim, i: usize, prev: &[u8; 32]) -> [u8; 32] {
    let r = &mut s.nodes[i].relay;
    let h = r.archive().get(prev).expect("archived").height + 1;
    let best = r.best();
    table_root(&r.block_table_on(&best, h, prev).expect("table"))
}

fn root(s: &mut Sim, i: usize) -> [u8; 32] {
    let tip = btc_hash(s.btc.tip);
    root_on(s, i, &tip)
}

fn ledger(s: &Sim, i: usize) -> Table {
    s.nodes[i].relay.db().np_ledger_table().expect("ledger")
}

/// Tick until `nodes` share node `of`'s tip, or give up after `rounds`.
fn settle_sync(s: &mut Sim, rounds: usize) {
    for _ in 0..rounds {
        s.tick(6);
        let best = s.nodes[0].relay.best();
        if s.nodes
            .iter()
            .all(|n| n.relay.best() == best && n.relay.status().unseen == 0)
        {
            return;
        }
    }
}

fn assert_same(s: &mut Sim, nodes: &[usize]) {
    let best = s.nodes[nodes[0]].relay.best();
    let r0 = root(s, nodes[0]);
    let l0 = ledger(s, nodes[0]);
    for &i in nodes {
        assert_eq!(s.nodes[i].relay.best(), best, "node {i} tip");
        assert_eq!(root(s, i), r0, "node {i} root");
        assert_eq!(ledger(s, i), l0, "node {i} stored ledger");
        assert_eq!(s.nodes[i].relay.status().unseen, 0, "node {i} unseen");
    }
}

fn height(s: &Sim, i: usize) -> u32 {
    s.nodes[i].relay.status().height
}

#[test]
fn a_fresh_node_syncs_from_scratch_to_the_same_root() {
    let mut s = Sim::new(1);
    grow(&mut s, 0, 4, 10);
    assert_eq!(
        height(&s, 0),
        40,
        "more anchors than one Headers reply carries"
    );
    let i = s.add(open(params(), mem()));
    let headers = Arc::new(AtomicUsize::new(0));
    let h2 = headers.clone();
    s.drop = Box::new(move |_, _, m| {
        if m.msg_type() == MsgType::Headers {
            h2.fetch_add(1, Ordering::Relaxed);
        }
        false
    });
    s.link(0, i);
    settle_sync(&mut s, 20);
    assert_same(&mut s, &[0, i]);
    assert!(
        headers.load(Ordering::Relaxed) >= 2,
        "headers came in more than one reply"
    );
    for n in &s.nodes {
        assert!(n.penalties.is_empty(), "{:?}", n.penalties);
    }
    // And it keeps up afterwards, as a relay.
    grow(&mut s, 0, 1, 2);
    settle_sync(&mut s, 5);
    assert_same(&mut s, &[0, i]);
}

#[test]
fn three_nodes_sync_across_a_share_chain_reorg() {
    let mut s = Sim::mesh(2);
    grow(&mut s, 0, 1, 3);
    s.unlink(0, 1);
    // Two sides: node 0 grows a light branch, node 1 a heavier one.
    grow(&mut s, 0, 1, 2);
    for _ in 0..4 {
        s.mine(1, false);
        s.mine(1, true);
    }
    s.tick(1);
    let heavy = s.nodes[1].relay.best();
    assert_ne!(s.nodes[0].relay.best(), heavy);
    // A fresh node syncs the light side first, then meets the heavy one.
    let i = s.add(open(params(), mem()));
    s.link(0, i);
    settle_sync(&mut s, 10);
    assert_eq!(s.nodes[i].relay.best(), s.nodes[0].relay.best());
    s.link(1, i);
    s.link(0, 1);
    settle_sync(&mut s, 20);
    assert_eq!(s.nodes[0].relay.best(), heavy, "the heavier side wins");
    assert!(s.nodes[i].relay.status().stats.reorgs >= 1);
    assert_same(&mut s, &[0, 1, i]);
    for n in &s.nodes {
        assert!(n.penalties.is_empty(), "{:?}", n.penalties);
    }
}

/// A restart halfway through a sync resumes from what was stored, and ends where an
/// uninterrupted sync does.
#[test]
fn a_restart_mid_sync_resumes() {
    let dir = std::env::temp_dir().join(format!("np-sync-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pool.db");
    let mut s = Sim::new(1);
    grow(&mut s, 0, 3, 10);
    let i = s.add(
        Relay::open(
            params(),
            Arc::new(Database::open(&path).unwrap()),
            fed_archive(START_TIP),
        )
        .unwrap(),
    );
    // Only the first dozen batches get through.
    let batches = Arc::new(AtomicUsize::new(0));
    let b2 = batches.clone();
    s.drop = Box::new(move |from, _, m| {
        from == 0 && m.msg_type() == MsgType::Batch && b2.fetch_add(1, Ordering::Relaxed) >= 12
    });
    s.link(0, i);
    settle_sync(&mut s, 3);
    let part = height(&s, i);
    assert!(part > 0 && part < height(&s, 0), "stopped part way: {part}");
    // Restart on the same store.
    s.drop = Box::new(|_, _, _| false);
    let r = Relay::open(
        params(),
        Arc::new(Database::open(&path).unwrap()),
        fed_archive(START_TIP),
    )
    .unwrap();
    assert_eq!(r.status().height, part, "what was stored is kept");
    s.replace(i, r);
    s.link(0, i);
    settle_sync(&mut s, 20);
    assert_same(&mut s, &[0, i]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Peers that lie are penalized and passed over; the node syncs from an honest one.
#[test]
fn lying_peers_are_refused_and_another_peer_is_used() {
    // Node 1 is a full copy of node 0's chain that lies to newcomers.
    let mut s = Sim::mesh(2);
    grow(&mut s, 0, 2, 6);
    assert_same(&mut s, &[0, 1]);
    for case in ["bad batch", "bad header", "bad body", "withheld"] {
        let i = s.add(open(params(), mem()));
        let liar = 1;
        s.tamper = Box::new(move |from, to, m| {
            if from != liar || to != i {
                return m;
            }
            match (case, m) {
                ("bad batch", Message::Batch { anchor, mut ids }) => {
                    ids.pop();
                    Message::Batch { anchor, ids }
                }
                ("bad header", Message::Headers(mut v)) => {
                    if let Some(a) = v.get_mut(1) {
                        a.share.tag.batch_root[0] ^= 1;
                    }
                    Message::Headers(v)
                }
                ("bad body", Message::Shares(mut v)) => {
                    for x in &mut v {
                        x.tag.payee_script = p2tr("thief");
                    }
                    Message::Shares(v)
                }
                (_, m) => m,
            }
        });
        s.drop = Box::new(move |from, to, m| {
            case == "withheld"
                && from == liar
                && to == i
                && matches!(
                    m.msg_type(),
                    MsgType::Batch | MsgType::Shares | MsgType::Anchor
                )
        });
        // The liar first, alone; then an honest peer too.
        s.link(liar, i);
        settle_sync(&mut s, 3);
        if case != "withheld" {
            assert!(
                !s.nodes[i].penalties.is_empty(),
                "{case}: the liar was penalized"
            );
            assert!(
                s.nodes[i].penalties.iter().all(|p| p.0 == liar as u64),
                "{case}: only the liar: {:?}",
                s.nodes[i].penalties
            );
        }
        s.link(0, i);
        settle_sync(&mut s, 30);
        assert_same(&mut s, &[0, i]);
        let want = match case {
            "bad batch" => Some(penalty::BAD_BATCH_ROOT),
            "bad header" => Some(penalty::INVALID_ANCHOR),
            "bad body" => Some(penalty::BAD_BODY),
            _ => None,
        };
        if let Some(w) = want {
            assert!(
                s.nodes[i].penalties.iter().any(|p| p.1 == w),
                "{case}: {:?}",
                s.nodes[i].penalties
            );
        } else {
            assert!(
                s.nodes[i].penalties.is_empty(),
                "withholding is not penalized"
            );
        }
        s.tamper = Box::new(|_, _, m| m);
        s.drop = Box::new(|_, _, _| false);
        s.unlink(0, i);
        s.unlink(liar, i);
    }
}

/// A pool block found on a Bitcoin branch that was later orphaned, and shares built on it. Only
/// node 0's Bitcoin node ever saw that branch; a fresh node fetches it from node 0's archive and
/// reaches the same root.
#[test]
fn a_fresh_node_syncs_across_a_bitcoin_reorg() {
    let mut s = Sim::new(1);
    grow(&mut s, 0, 1, 3);
    let tip = s.btc.tip;
    let h = tip + 1;
    // Node 0's Bitcoin node mines pool block X at h, paying the table of node 0's job.
    let own = main_node(tip);
    s.nodes[0].node = own.clone();
    let job = s.nodes[0].relay.job_anchor().unwrap();
    let table = s.nodes[0].relay.block_table(&job.parent_anchor, h).unwrap();
    let cb = deserialize(&Miner::new("finder", 9).build(job, &table, tip, 0).coinbase).unwrap();
    let x = make_block(btc_hash(tip), h, cb);
    assert!(x.pool_tag().is_some());
    own.set(x.clone());
    s.tick(1);
    // Shares and an anchor on X.
    s.mine_on(0, x.hash(), h, false);
    s.mine_on(0, x.hash(), h, false);
    s.tick(31);
    s.mine_on(0, x.hash(), h, true);
    let on_x = s.nodes[0].relay.best();
    let on_x_credits = s.nodes[0].relay.batch_credits(&on_x).unwrap();
    assert!(
        on_x_credits
            .iter()
            .filter(|c| c.job_height == h + 1)
            .count()
            >= 2
    );
    // Bitcoin reorgs X away; the chain goes on without it.
    own.set(main_block(h));
    s.btc.extend_to(h);
    s.nodes[0].node = s.btc.node.clone();
    s.nodes[0].node.know(x.clone());
    s.tick(1);
    grow(&mut s, 0, 2, 2);
    assert!(s.nodes[0]
        .relay
        .chain()
        .is_ancestor(&on_x, &s.nodes[0].relay.best()));
    // A fresh node whose Bitcoin node never saw X.
    let fresh = MemBlocks::default();
    for k in BTC_FLOOR..=s.btc.tip {
        fresh.set(main_block(k));
    }
    let i = s.add(open(params(), mem()));
    s.nodes[i].node = fresh;
    let fetched = Arc::new(AtomicUsize::new(0));
    let f2 = fetched.clone();
    s.drop = Box::new(move |_, _, m| {
        if m.msg_type() == MsgType::BtcBlocks {
            f2.fetch_add(1, Ordering::Relaxed);
        }
        false
    });
    s.link(0, i);
    settle_sync(&mut s, 20);
    assert!(
        fetched.load(Ordering::Relaxed) >= 1,
        "X came from the archive"
    );
    assert!(s.nodes[i].relay.archive().has_full(&x.hash()));
    assert_same(&mut s, &[0, i]);
    assert_eq!(
        s.nodes[i].relay.batch_credits(&on_x).unwrap(),
        on_x_credits,
        "the shares on X are credited alike"
    );
    // Tables on top of X subtract what X paid, on both nodes alike.
    let rx0 = root_on(&mut s, 0, &x.hash());
    assert_eq!(root_on(&mut s, i, &x.hash()), rx0);
    for n in &s.nodes {
        assert!(n.penalties.is_empty(), "{:?}", n.penalties);
    }
}

/// Settlement is deterministic: two nodes whose Bitcoin nodes sit on different tips (one on a
/// pool block, one on a plain block at the same height) judge each other's shares alike once
/// each has fetched the other's block, and agree on the table on either tip.
#[test]
fn nodes_on_different_bitcoin_tips_agree_once_the_archive_is_shared() {
    let mut s = Sim::mesh(2);
    grow(&mut s, 0, 1, 2);
    let tip = s.btc.tip;
    let h = tip + 1;
    let job = s.nodes[0].relay.job_anchor().unwrap();
    let table = s.nodes[0].relay.block_table(&job.parent_anchor, h).unwrap();
    let cb = deserialize(&Miner::new("finder", 9).build(job, &table, tip, 0).coinbase).unwrap();
    let x: ArchivedBlock = make_block(btc_hash(tip), h, cb);
    let y = main_block(h);
    // Node 0's Bitcoin node is on X, node 1's on Y; neither has seen the other.
    for (i, b) in [(0, &x), (1, &y)] {
        let n = main_node(tip);
        n.set(b.clone());
        s.nodes[i].node = n;
    }
    s.tick(1);
    assert!(!s.nodes[1].relay.archive().has_full(&x.hash()));
    // Each mines on its own tip; the other must fetch that tip to judge the anchor.
    s.mine_on(0, x.hash(), h, false);
    s.tick(31);
    s.mine_on(0, x.hash(), h, true);
    settle_sync(&mut s, 5);
    s.mine_on(1, y.hash(), h, false);
    s.tick(31);
    s.mine_on(1, y.hash(), h, true);
    settle_sync(&mut s, 5);
    let best = s.nodes[0].relay.best();
    assert_eq!(s.nodes[1].relay.best(), best);
    assert_eq!(s.nodes[0].relay.chain().get(&best).unwrap().height, 4);
    for i in 0..2 {
        assert!(s.nodes[i].relay.archive().has_full(&x.hash()), "node {i}");
        assert!(s.nodes[i].relay.archive().has_full(&y.hash()), "node {i}");
        assert!(
            s.nodes[i].penalties.is_empty(),
            "{:?}",
            s.nodes[i].penalties
        );
    }
    let (x0, y0) = (root_on(&mut s, 0, &x.hash()), root_on(&mut s, 0, &y.hash()));
    assert_eq!(root_on(&mut s, 1, &x.hash()), x0, "the same table on X");
    assert_eq!(root_on(&mut s, 1, &y.hash()), y0, "the same table on Y");
    assert_ne!(x0, y0, "X's payouts are subtracted on X only");
}

/// A pruning node keeps checkpoints and drops old batches, still serves every batch inside its
/// window, and sends a fresh node to an archive peer for the rest.
#[test]
fn a_pruned_node_serves_within_its_window() {
    let mut s = Sim::with_relays(2, |i| open(params_with(40, 5, i == 0), mem()));
    s.link(0, 1);
    s.run();
    let behind = s.add(open(params(), mem()));
    s.link(0, behind);
    s.link(1, behind);
    s.run();
    grow(&mut s, 0, 50, 2);
    assert_same(&mut s, &[0, 1, behind]);
    s.unlink(0, behind);
    s.unlink(1, behind);
    grow(&mut s, 0, 12, 2);
    let first = s.nodes[0]
        .relay
        .chain()
        .get(&s.nodes[0].relay.best())
        .unwrap()
        .height;
    assert!(first >= 120);
    // Node 0 pruned below its older checkpoint; node 1 kept everything.
    let cp = s.nodes[0].relay.checkpoint().clone();
    assert_ne!(cp.anchor, genesis_hash(), "a checkpoint was folded");
    let rows = s.nodes[0].relay.db().np_load_checkpoints().unwrap();
    assert_eq!(rows.len(), 2);
    let mut first_anchor = cp.anchor;
    while let Some(p) = s.nodes[0].relay.chain().get(&first_anchor).unwrap().parent {
        if p == genesis_hash() {
            break;
        }
        first_anchor = p;
    }
    assert!(
        !s.nodes[0].relay.db().np_has_batch(&first_anchor).unwrap(),
        "pruned"
    );
    assert!(
        s.nodes[1].relay.db().np_has_batch(&first_anchor).unwrap(),
        "archived"
    );
    assert!(s.nodes[0]
        .relay
        .db()
        .np_has_batch(&s.nodes[0].relay.best())
        .unwrap());
    // A node a few blocks behind catches up from the pruned node alone.
    s.link(0, behind);
    settle_sync(&mut s, 20);
    assert_same(&mut s, &[0, behind]);
    // A fresh node cannot sync from genesis off the pruned node...
    let fresh = s.add(open(params(), mem()));
    s.link(0, fresh);
    for _ in 0..5 {
        s.tick(6);
    }
    assert_eq!(
        height(&s, fresh),
        0,
        "the pruned node lacks the oldest batches"
    );
    // ...and finishes once an archive peer is there.
    s.link(1, fresh);
    settle_sync(&mut s, 40);
    assert_same(&mut s, &[0, 1, fresh]);
    for n in &s.nodes {
        assert!(n.penalties.is_empty(), "{:?}", n.penalties);
    }
}

/// A node restarts from its checkpoint; a corrupt checkpoint is detected and rewritten; with
/// both corrupt it replays from genesis. The root never changes.
#[test]
fn checkpoints_restart_verify_and_rebuild() {
    let dir = std::env::temp_dir().join(format!("np-checkpoint-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pool.db");
    let file = || Arc::new(Database::open(&path).unwrap());
    let mut s = Sim::with_relays(1, |_| open_persistent(params_with(40, 5, false), file()));
    grow(&mut s, 0, 60, 1);
    let cp = s.nodes[0].relay.checkpoint().clone();
    assert_ne!(cp.anchor, genesis_hash());
    let rows = s.nodes[0].relay.db().np_load_checkpoints().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].anchor_hash, cp.anchor);
    let (r0, l0, best) = (root(&mut s, 0), ledger(&s, 0), s.nodes[0].relay.best());
    let reopen = |s: &mut Sim| {
        let r = open_persistent(params_with(40, 5, false), file());
        s.replace(0, r);
        s.tick(1);
    };
    let check = |s: &mut Sim, what: &str| {
        assert_eq!(s.nodes[0].relay.best(), best, "{what}: tip");
        assert_eq!(root(s, 0), r0, "{what}: root");
        assert_eq!(ledger(s, 0), l0, "{what}: stored ledger");
        assert_eq!(
            s.nodes[0].relay.checkpoint().anchor,
            cp.anchor,
            "{what}: base"
        );
        let key = |v: Vec<ghost_storage::node_pool_store::NpCheckpoint>| {
            v.into_iter()
                .map(|r| (r.anchor_hash, digest(&r.payload), r.digest))
                .collect::<Vec<_>>()
        };
        let now = s.nodes[0].relay.db().np_load_checkpoints().unwrap();
        assert!(
            key(now) == key(rows.clone()),
            "{what}: stored checkpoints are the originals, digests intact"
        );
    };
    reopen(&mut s);
    check(&mut s, "restart");

    let corrupt = |s: &Sim, sql: &str| {
        s.nodes[0]
            .relay
            .db()
            .with_connection(|c| {
                c.execute(sql, [])
                    .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
            })
            .unwrap();
    };
    corrupt(
        &s,
        "UPDATE np_checkpoints SET payload = substr(payload, 1, length(payload) - 1) \
         WHERE height = (SELECT MAX(height) FROM np_checkpoints)",
    );
    reopen(&mut s);
    check(&mut s, "newest corrupt");
    corrupt(&s, "UPDATE np_checkpoints SET digest = zeroblob(32)");
    reopen(&mut s);
    check(&mut s, "both corrupt");
    let _ = std::fs::remove_dir_all(&dir);
}
