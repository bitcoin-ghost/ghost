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
//| FILE: multi_node.rs                                                                                                  |
//|======================================================================================================================|

//! Multi-node tests over the in-process network: convergence, credits, forks, withholding, and
//! the penalties for invalid data.

use std::collections::BTreeMap;
use std::sync::Arc;

use bitcoin::hashes::Hash;
use ghost_common::anchor_chain::AnchorHash;
use ghost_common::canonical_payout::{share_face, Halving, Script, Table};
use ghost_common::share_commit::batch_root;
use ghost_storage::Database;

use crate::peers::penalty;
use crate::relay::{JobAnchor, Relay};
use crate::testkit::*;
use crate::wire::{AnchorMsg, Message, MsgType};

fn ledger(s: &Sim, i: usize) -> Table {
    s.nodes[i].relay.db().np_ledger_table().expect("ledger")
}

fn assert_converged(s: &Sim) -> AnchorHash {
    let best = s.nodes[0].relay.best();
    let l0 = ledger(s, 0);
    for (i, n) in s.nodes.iter().enumerate() {
        assert_eq!(n.relay.best(), best, "node {i} tip");
        assert_eq!(ledger(s, i), l0, "node {i} ledger");
        assert_eq!(
            n.relay.status().unseen,
            0,
            "node {i} holds an unseen anchor"
        );
    }
    best
}

fn assert_no_penalties(s: &Sim) {
    for (i, n) in s.nodes.iter().enumerate() {
        assert!(n.penalties.is_empty(), "node {i}: {:?}", n.penalties);
    }
}

/// Credits on the best chain of node `i`, summed per payee from its batches.
fn best_chain_credits(s: &Sim, i: usize) -> (usize, BTreeMap<Script, i128>) {
    let r = &s.nodes[i].relay;
    let mut cur = r.best();
    let (mut n, mut by) = (0, BTreeMap::new());
    while cur != genesis_hash() {
        let cs = r.batch_credits(&cur).expect("held");
        n += cs.len();
        for c in cs.iter() {
            *by.entry(c.script.clone()).or_insert(0) += c.face;
        }
        cur = r.chain().get(&cur).unwrap().parent.unwrap();
    }
    (n, by)
}

/// A share from node `i`'s miner that node `i` does not take.
fn mine_only(s: &mut Sim, i: usize) -> crate::wire::NetShare {
    let n = &mut s.nodes[i];
    n.miner.mine(&mut n.relay, &s.btc, false)
}

fn face() -> i128 {
    share_face(10, BITS, START_TIP + 1, Halving::MAINNET).unwrap() as i128
}

#[test]
fn tips_converge_and_credits_match_on_every_node() {
    let mut s = Sim::mesh(4);
    for round in 0..4 {
        for i in 0..4 {
            s.mine(i, false);
            s.mine(i, false);
        }
        s.mine(round, true);
    }
    s.mine(0, true);
    let best = assert_converged(&s);
    assert_no_penalties(&s);
    assert_eq!(s.nodes[0].relay.chain().get(&best).unwrap().height, 5);

    // 32 network shares plus the first four anchors' own shares, each included exactly once.
    let (n, by) = best_chain_credits(&s, 0);
    assert_eq!(n, 36);
    let l = ledger(&s, 0);
    for i in 0..4 {
        // Eight network shares and one anchor's own share each; the last anchor's is still loose.
        let payee = &s.nodes[i].miner.payee;
        let want = 9 * face();
        assert_eq!(by[payee], want, "miner {i}");
        assert_eq!(l[payee].owed, want, "miner {i} ledger");
    }
    for (i, n) in s.nodes.iter().enumerate() {
        assert_eq!(n.relay.status().stats.anchors_valid, 5, "node {i}");
        assert_eq!(n.relay.status().stats.anchors_invalid, 0, "node {i}");
        assert_eq!(
            n.relay.status().loose,
            1,
            "node {i}: only the last anchor's share"
        );
        // Jobs re-stamped on every new anchor: the last publish builds on the tip.
        assert_eq!(n.published.last().unwrap().parent_anchor, best, "node {i}");
    }
}

#[test]
fn a_fork_resolves_by_work_and_the_losing_shares_are_re_included() {
    let mut s = Sim::mesh(4);
    s.mine(0, false);
    s.mine(0, true);
    let base = assert_converged(&s);

    for (a, b) in [(0, 2), (0, 3), (1, 2), (1, 3)] {
        s.unlink(a, b);
    }
    // Side X {0, 1}: one anchor. Side Y {2, 3}: two. Shares join a job's batch when the node
    // re-batches: on a new anchor, or at the 30 s backstop.
    s.mine(0, false);
    s.mine(1, false);
    s.mine(2, false);
    s.mine(3, false);
    s.tick(31);
    s.mine(1, true);
    // Built on side X's anchor, which is about to become a dead fork.
    s.mine(0, false);
    s.mine(2, true);
    s.mine(3, false);
    s.mine(3, true);
    let x = s.nodes[0].relay.best();
    let y = s.nodes[2].relay.best();
    assert_ne!(x, y);
    assert_eq!(s.nodes[1].relay.best(), x);
    assert_eq!(s.nodes[3].relay.best(), y);
    assert_ne!(ledger(&s, 0), ledger(&s, 2));
    let x_payees = [
        s.nodes[0].miner.payee.clone(),
        s.nodes[1].miner.payee.clone(),
    ];
    let before: Vec<i128> = x_payees.iter().map(|p| ledger(&s, 0)[p].owed).collect();

    for (a, b) in [(0, 2), (0, 3), (1, 2), (1, 3)] {
        s.link(a, b);
    }
    s.run();
    assert_eq!(assert_converged(&s), y, "the heavier side wins");
    assert_no_penalties(&s);
    assert_eq!(s.nodes[0].relay.status().stats.reorgs, 1);
    assert_eq!(s.nodes[2].relay.status().stats.reorgs, 0);
    // Side X's network shares lost their credit with their anchor...
    let after: Vec<i128> = x_payees
        .iter()
        .map(|p| ledger(&s, 0).get(p).map_or(0, |b| b.owed))
        .collect();
    assert!(after.iter().zip(&before).all(|(a, b)| a < b));
    assert!(s.nodes[2].relay.chain().is_ancestor(&base, &y));

    // ...until the next anchor, built by a node of side X on the winning tip, re-includes them.
    s.mine(0, true);
    assert_converged(&s);
    assert_no_penalties(&s);
    for (p, b) in x_payees.iter().zip(&before) {
        assert!(ledger(&s, 2)[p].owed >= *b, "re-included on every node");
    }
    // Node 2 fetched the dead-fork anchor those shares were built on, and holds it seen.
    assert!(s.nodes[2].relay.has_batch(&x));
}

#[test]
fn a_withheld_batch_is_not_counted_until_fetched() {
    let mut s = Sim::mesh(4);
    s.mine(0, true);
    let before = assert_converged(&s);
    let l_before = ledger(&s, 1);

    s.drop = Box::new(|from, _, m| from == 0 && m.msg_type() == MsgType::Batch);
    s.mine(0, false);
    s.mine(0, true);
    let a = s.nodes[0].relay.best();
    assert_ne!(a, before);
    for i in 1..4 {
        let r = &s.nodes[i].relay;
        assert_eq!(
            r.best(),
            before,
            "node {i} counts an anchor without its batch"
        );
        assert!(
            r.chain().get(&a).is_some_and(|x| !x.seen),
            "node {i} holds it unseen"
        );
        assert_eq!(r.status().unseen, 1);
        assert_eq!(
            ledger(&s, i),
            l_before,
            "node {i} credited a withheld batch"
        );
    }
    // The holders do not pass an anchor on before they can check it.
    for _ in 0..4 {
        s.tick(6);
    }
    for i in 1..4 {
        assert_eq!(s.nodes[i].relay.best(), before);
    }

    s.drop = Box::new(|_, _, _| false);
    for _ in 0..6 {
        s.tick(6);
    }
    assert_eq!(assert_converged(&s), a);
    assert_no_penalties(&s);
    assert_ne!(ledger(&s, 1), l_before);
}

#[test]
fn invalid_network_shares_are_penalized_and_stale_ones_are_not() {
    let mut s = Sim::mesh(2);
    // A relabelled share: the claimed payee is not what the coinbase commits.
    let mut bad = mine_only(&mut s, 0);
    bad.tag.payee_script = p2tr("thief");
    s.inject(0, 1, Message::Share(bad));
    assert_eq!(s.nodes[1].penalties.len(), 1);
    assert_eq!(s.nodes[1].penalties[0].1, penalty::INVALID_SHARE);
    s.nodes[1].penalties.clear();

    // Outputs built on another table: a view-dependent mismatch, dropped without penalty.
    let job = s.nodes[0].relay.job_anchor().unwrap();
    let wrong = s.nodes[0].miner.build(job, &Table::new(), s.btc.tip, 10);
    s.inject(0, 1, Message::Share(wrong));
    // A share from a job 20 blocks old: too old to include, dropped without penalty.
    let old = s.nodes[0]
        .miner
        .build(job, &genesis_table(), START_TIP - 20, 10);
    s.inject(0, 1, Message::Share(old));
    // A share whose Bitcoin header nobody knows: waits, no penalty.
    let mut unknown = mine_only(&mut s, 0);
    unknown.header.prev_blockhash = bitcoin::BlockHash::from_byte_array([0x42; 32]);
    s.inject(0, 1, Message::Share(unknown));
    assert_no_penalties(&s);
    let st = s.nodes[1].relay.status().stats;
    assert_eq!(
        (st.shares_accepted, st.shares_invalid, st.shares_stale),
        (0, 1, 3)
    );
}

#[test]
fn a_batch_off_its_root_and_an_anchor_with_a_bad_share_are_refused() {
    let mut s = Sim::mesh(2);
    let tip = s.nodes[1].relay.best();

    // An anchor over a batch holding a share that does not pay the snapshot.
    let job0 = s.nodes[0].relay.job_anchor().unwrap();
    let bad = s.nodes[0].miner.build(job0, &Table::new(), s.btc.tip, 10);
    let bad_id = bad.id();
    let job = JobAnchor {
        parent_anchor: job0.parent_anchor,
        batch_root: batch_root(&[bad_id]),
    };
    let table = s.nodes[0]
        .relay
        .job_table(&job.parent_anchor, s.btc.tip + 1)
        .unwrap();
    let anchor = s.nodes[0].miner.build(job, &table, s.btc.tip, 18);
    let a = anchor.id();
    s.inject(
        0,
        1,
        Message::Anchor(AnchorMsg {
            btc_height: s.btc.tip,
            share: anchor,
        }),
    );
    // A list that does not hash to the committed root: the sender pays, the anchor does not die.
    s.inject(
        0,
        1,
        Message::Batch {
            anchor: a,
            ids: vec![[7; 32]],
        },
    );
    assert_eq!(s.nodes[1].penalties.len(), 1);
    assert_eq!(s.nodes[1].penalties[0].1, penalty::BAD_BATCH_ROOT);
    // The real list: node 1 asks node 0 for the body and checks it.
    s.inject(
        0,
        1,
        Message::Batch {
            anchor: a,
            ids: vec![bad_id],
        },
    );
    s.inject(0, 1, Message::Shares(vec![bad]));
    let r = &s.nodes[1].relay;
    assert_eq!(r.best(), tip, "an invalid anchor never wins");
    assert!(!r.has_batch(&a));
    assert_eq!(r.status().stats.anchors_invalid, 1);
    assert_eq!(
        s.nodes[1].penalties.last().unwrap().1,
        penalty::INVALID_ANCHOR
    );
}

/// A job's batch follows the Bitcoin tip: when the tip moves past a loose share's window, the
/// next tick re-batches without it, not the 30 s backstop.
#[test]
fn a_new_bitcoin_tip_re_batches_at_the_next_tick() {
    let mut s = Sim::mesh(1);
    let id = s.mine(0, false).id();
    s.tick(31);
    let carried = s.nodes[0].published.last().unwrap().batch_root;
    assert_eq!(
        carried,
        batch_root(&[id]),
        "the backstop batches the loose share"
    );

    // The tip moves well past the share's job height; one second later, not thirty.
    let now = s.now + 1;
    let n = &mut s.nodes[0];
    n.relay.set_btc_tip(START_TIP + 30);
    let outs = n.relay.tick(&s.btc.headers, now);
    let jobs: Vec<JobAnchor> = outs
        .into_iter()
        .filter_map(|o| match o {
            crate::relay::Out::Publish(j) => Some(j),
            _ => None,
        })
        .collect();
    assert_eq!(jobs.len(), 1, "re-batched at once");
    assert_eq!(jobs[0].batch_root, batch_root(&[]));

    // And only once: an unchanged tip waits for the backstop again.
    let outs = s.nodes[0].relay.tick(&s.btc.headers, now + 1);
    assert!(!outs
        .iter()
        .any(|o| matches!(o, crate::relay::Out::Publish(_))));
}

/// Regtest halves every 150 blocks, so 1,050 starts era 7. A batch is carried by jobs until the
/// next re-batch, which can be a block or two after the tip moved; a batch built two blocks
/// before the halving must not hold era-6 shares, or a job past the halving commits them and
/// its anchor breaks share rule 5 on every peer (seen once in the 24 h regtest soak).
#[test]
fn a_batch_built_just_before_a_halving_holds_no_shares_a_job_past_it_cannot_include() {
    let mut s = Sim::with_relays(2, |_| {
        let mut p = params();
        p.halving = Halving::REGTEST;
        Relay::open(
            p,
            Arc::new(Database::in_memory().expect("db")),
            fed_archive(START_TIP),
        )
        .expect("open")
    });
    for n in &mut s.nodes {
        n.miner.halving = Halving::REGTEST;
    }
    s.link(0, 1);
    s.run();
    assert_eq!(Halving::REGTEST.era(1_050), 7);
    assert_eq!(Halving::REGTEST.era(1_049), 6);

    // Three blocks out, an anchor up to two blocks ahead is still in era 6: the share is batched.
    s.btc.extend_to(1_045);
    s.tick(1);
    let early = s.mine(0, false).id();
    s.tick(31);
    assert_eq!(
        s.nodes[0].published.last().unwrap().batch_root,
        batch_root(&[early]),
        "far from the halving the share is batched"
    );
    s.mine(0, true);
    s.tick(1);

    // At 1,047 an anchor up to two blocks ahead may sit at 1,049, whose jobs are era 7.
    s.btc.extend_to(1_046);
    s.tick(1);
    let late = s.mine(0, false).id();
    s.btc.extend_to(1_047);
    s.tick(1);
    assert_eq!(
        s.nodes[0].published.last().unwrap().batch_root,
        batch_root(&[]),
        "within the margin of a halving the era-6 share {late:?} is left out"
    );

    // The tip crosses before the next re-batch: a job on block 1,049 carries that batch.
    s.btc.extend_to(1_049);
    for n in &mut s.nodes {
        feed(n.relay.archive(), &n.node);
    }
    s.mine(0, true);
    s.tick(1);
    assert_no_penalties(&s);
    assert_converged(&s);
    for n in &s.nodes {
        assert_eq!(n.relay.status().stats.anchors_invalid, 0);
    }
}

#[test]
fn a_restarted_node_reloads_its_chain_and_ledger() {
    let dir = std::env::temp_dir().join(format!("np-relay-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pool.db");
    let mut s = Sim::mesh(2);
    s.nodes[1].relay = Relay::open(
        params(),
        Arc::new(Database::open(&path).unwrap()),
        fed_archive(START_TIP),
    )
    .unwrap();
    s.nodes[1].relay.set_btc_tip(START_TIP);
    s.unlink(0, 1);
    s.link(0, 1);
    s.run();
    for _ in 0..2 {
        s.mine(0, false);
        s.mine(1, false);
        s.mine(0, true);
    }
    let best = assert_converged(&s);
    let l = ledger(&s, 1);
    drop(s);

    let r = Relay::open(
        params(),
        Arc::new(Database::open(&path).unwrap()),
        fed_archive(START_TIP),
    )
    .unwrap();
    assert_eq!(r.best(), best);
    assert_eq!(
        r.db().np_ledger_table().unwrap(),
        l,
        "the ledger is not applied twice"
    );
    assert!(r.has_batch(&best));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_reorg_parks_block_retirements_above_the_credits_and_re_applies_them() {
    use ghost_common::node_pool_constants::FACE_PER_SAT;
    let mut s = Sim::mesh(2);
    s.unlink(0, 1);
    s.mine(0, false);
    s.mine(1, false);
    s.tick(31);
    s.mine(0, true);
    s.mine(1, true);
    s.mine(1, true);
    // Settlement (W2.7) applied a block's retirements on node 0 after its anchor's credits.
    let r = vec![(s.nodes[0].miner.payee.clone(), 5 * FACE_PER_SAT)];
    let block = [0xB0; 32];
    s.nodes[0]
        .relay
        .db()
        .np_apply_block(&block, START_TIP + 1, &r, 0)
        .unwrap();

    s.link(0, 1);
    s.run();
    let best = s.nodes[1].relay.best();
    assert_eq!(s.nodes[0].relay.best(), best);
    assert_eq!(s.nodes[0].relay.status().stats.reorgs, 1);
    assert_eq!(
        s.nodes[0].relay.db().np_block_retirements(&block).unwrap(),
        Some(r.clone()),
        "the block is applied again after the move"
    );
    s.nodes[1]
        .relay
        .db()
        .np_apply_block(&block, START_TIP + 1, &r, 0)
        .unwrap();
    assert_eq!(ledger(&s, 0), ledger(&s, 1));
}

#[test]
fn a_peer_that_missed_the_shares_fetches_a_large_batch_in_chunks() {
    let mut s = Sim::mesh(2);
    s.unlink(0, 1);
    for _ in 0..300 {
        s.mine(0, false);
    }
    s.tick(31);
    s.mine(0, true);
    let a = s.nodes[0].relay.best();
    assert_eq!(s.nodes[0].relay.batch_credits(&a).unwrap().len(), 300);
    assert_eq!(s.nodes[1].relay.status().loose, 0);
    // Node 1 learns of the tip on connect, fetches the anchor, then the bodies, 256 at a time.
    s.link(0, 1);
    s.run();
    assert_eq!(assert_converged(&s), a);
    assert_no_penalties(&s);
    assert_eq!(ledger(&s, 1)[&s.nodes[0].miner.payee].owed, 300 * face());
}
