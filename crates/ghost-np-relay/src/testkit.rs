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
//| FILE: testkit.rs                                                                                                     |
//|======================================================================================================================|

//! Test support: a fake Bitcoin chain of real headers (mainnet bits without the work), simulated
//! miners that build canonical coinbases on a node's published job, and a deterministic in-process
//! network of relay cores, each with its own Bitcoin node and archive.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use sha2::{Digest, Sha256};

use ghost_common::anchor_chain::AnchorHash;
use ghost_common::canonical_payout::{coinbase_outputs, Balance, Script, Table};
use ghost_common::coinbase_tags::{encode_node_tag, encode_payout_tag};
use ghost_common::node_pool_constants::{ANCHOR_TIER_OFFSET, FACE_PER_SAT};
use ghost_common::node_pool_u256::U256;
use ghost_common::share_commit::{hash_meets_tier, ShareTagPreimage};
use ghost_storage::Database;

use crate::archive::{ArchivedBlock, BtcArchive, MTP_SPAN};
use crate::headers::{HeaderFacts, MemHeaders};
use crate::relay::{Genesis, JobAnchor, LocalOutcome, Out, PeerId, Relay, RelayParams};
use crate::settlement::MemBlocks;
use crate::wire::{Message, NetShare};

/// Header bits of every fake block.
pub const BITS: u32 = 0x1702_1be5;
/// The genesis anchor's `btc_height`.
pub const GENESIS_BTC: u32 = 1_000;
/// Bitcoin tip at the start of a test: job height 1,026 cuts at 1,006, above genesis.
pub const START_TIP: u32 = 1_025;
/// The test clock.
pub const T0: u64 = 1_800_000_000;
/// Miner outputs per job.
pub const SLOTS: u16 = 9;

/// Tier 0 target in tests: the largest, so tier `t` costs `2^t` hashes.
pub fn base() -> U256 {
    U256::from_be_bytes([0xFF; 32])
}

/// A P2TR script from a label.
pub fn p2tr(label: &str) -> Script {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&Sha256::digest(label.as_bytes()));
    s
}

/// The genesis anchor.
pub fn genesis_hash() -> AnchorHash {
    [0xEE; 32]
}

/// A genesis table with a few owed balances, so canonical outputs pay someone.
pub fn genesis_table() -> Table {
    (0..4u32)
        .map(|i| {
            (
                p2tr(&format!("genesis-{i}")),
                Balance {
                    owed: (2_000 + 1_000 * i as i128) * FACE_PER_SAT,
                    queue_since: Some(900 + i),
                },
            )
        })
        .collect()
}

/// Relay parameters on the test genesis.
pub fn params() -> RelayParams {
    RelayParams::new(
        Genesis {
            hash: genesis_hash(),
            btc_height: GENESIS_BTC,
            tier: 10,
            table: genesis_table(),
        },
        base(),
    )
}

/// The first fake Bitcoin block.
pub const BTC_FLOOR: u32 = GENESIS_BTC - 40;

/// The header time of fake block `h`: ten minutes apart, well below every share's time.
pub fn btc_time(h: u32) -> u32 {
    1_000_000_000 + 600 * h
}

/// A coinbase at height `h` with no node pool layout, varied by `tag`.
pub fn plain_coinbase(h: u32, tag: u8) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::script::Builder::new()
                .push_int(h as i64)
                .push_slice([tag; 4])
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(312_500_000),
            script_pubkey: ScriptBuf::from_bytes(p2tr("solo")),
        }],
    }
}

/// A one-transaction block at `h` on `prev` with coinbase `cb`.
pub fn make_block(prev: [u8; 32], h: u32, cb: Transaction) -> ArchivedBlock {
    ArchivedBlock {
        header: Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::from_byte_array(cb.compute_txid().to_byte_array()),
            time: btc_time(h),
            bits: CompactTarget::from_consensus(BITS),
            nonce: 0,
        },
        height: h,
        coinbase: Some((cb, vec![])),
    }
}

/// Fake main-chain block `h`, from [`BTC_FLOOR`] up. The same in every test.
pub fn main_block(h: u32) -> ArchivedBlock {
    static CHAIN: OnceLock<Mutex<BTreeMap<u32, ArchivedBlock>>> = OnceLock::new();
    let mut c = CHAIN
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    assert!(h >= BTC_FLOOR);
    let mut next = c.keys().next_back().map_or(BTC_FLOOR, |k| k + 1);
    while next <= h {
        let prev = if next == BTC_FLOOR {
            [0; 32]
        } else {
            c[&(next - 1)].hash()
        };
        c.insert(next, make_block(prev, next, plain_coinbase(next, 0)));
        next += 1;
    }
    c[&h].clone()
}

/// The hash of fake main-chain block `h`.
pub fn btc_hash(h: u32) -> [u8; 32] {
    main_block(h).hash()
}

/// The facts a node derives for block `b` from its chain `at` (median of the last 11 times).
pub fn facts_of(b: &ArchivedBlock, time_at: impl Fn(u32) -> u32) -> HeaderFacts {
    let lo = b.height.saturating_sub(MTP_SPAN - 1).max(BTC_FLOOR);
    let mut t: Vec<u32> = (lo..b.height).map(time_at).collect();
    t.push(b.header.time);
    t.sort_unstable();
    HeaderFacts {
        height: b.height,
        next_bits: CompactTarget::from_consensus(BITS),
        median_time_past: t[t.len() / 2],
    }
}

/// An archive holding the fake main chain from [`BTC_FLOOR`] to `tip`, as this node's best.
pub fn fed_archive(tip: u32) -> Arc<BtcArchive> {
    let a = BtcArchive::in_memory();
    a.trust_work_for_tests();
    feed(&a, &main_node(tip));
    a
}

/// A Bitcoin node holding the fake main chain up to `tip`.
pub fn main_node(tip: u32) -> MemBlocks {
    let n = MemBlocks::default();
    for h in BTC_FLOOR..=tip {
        n.set(main_block(h));
    }
    n
}

/// What settlement does for an archive: archive the node's best chain and record it as best.
pub fn feed(a: &BtcArchive, node: &MemBlocks) {
    let tip = node.best_height().unwrap_or(BTC_FLOOR);
    for h in BTC_FLOOR..=tip {
        let Some(b) = node.at(h) else { break };
        let hash = b.hash();
        if a.main_at(h) == Some(hash) {
            continue;
        }
        a.insert_local(b, 0).expect("local block");
        a.set_main(h, hash);
    }
    a.truncate_main(tip);
}

/// What the network layer does with the blocks a relay wanted: read them back from the node's
/// own Bitcoin node to an archived ancestor, and ask peers for the rest.
pub fn fetch_wanted(r: &mut Relay, node: &MemBlocks) {
    let mut missing = Vec::new();
    for h in r.take_needed_headers() {
        let mut cur = h;
        loop {
            if r.archive().has_full(&cur) {
                break;
            }
            let Some(b) = node.get(&cur) else {
                missing.push(cur);
                break;
            };
            cur = b.prev();
            r.archive().insert_local(b, 0).expect("local block");
        }
    }
    if !missing.is_empty() {
        r.request_btc_blocks(&missing);
    }
}

/// A relay over a fresh in-memory store.
pub fn relay() -> Relay {
    Relay::open(
        params(),
        Arc::new(Database::in_memory().expect("db")),
        fed_archive(START_TIP),
    )
    .expect("open")
}

/// A fake Bitcoin header chain.
pub struct Btc {
    /// What the relays look headers up in.
    pub headers: MemHeaders,
    /// Current tip height.
    pub tip: u32,
    /// The shared Bitcoin node every simulated node reads unless given its own.
    pub node: MemBlocks,
}

impl Btc {
    /// Headers from below genesis up to `tip`.
    pub fn new(tip: u32) -> Btc {
        let mut b = Btc {
            headers: MemHeaders::default(),
            tip: 0,
            node: MemBlocks::default(),
        };
        b.extend_to(tip);
        b
    }

    /// The same chain; header times are fixed, so `t0` no longer matters.
    pub fn with_time(tip: u32, _t0: u64) -> Btc {
        Btc::new(tip)
    }

    /// Mine fake blocks up to `tip`.
    pub fn extend_to(&mut self, tip: u32) {
        for h in BTC_FLOOR..=tip {
            let b = main_block(h);
            self.headers.insert(b.hash(), facts_of(&b, btc_time));
            if self.node.at(h).is_none() {
                self.node.set(b);
            }
        }
        self.tip = tip;
        self.headers.set_tip(tip);
    }
}

/// A simulated miner on one node.
pub struct Miner {
    /// Who its shares credit.
    pub payee: Script,
    /// The node its jobs come from.
    pub node_id: [u8; 32],
    /// Header time of its shares.
    pub time: u32,
    extranonce: u64,
}

impl Miner {
    /// A miner paying `label`.
    pub fn new(label: &str, node: u8) -> Miner {
        Miner {
            payee: p2tr(label),
            node_id: [node; 32],
            time: T0 as u32,
            extranonce: 0,
        }
    }

    /// Build a share on `job` on top of main-chain Bitcoin block `prev_height`, paying the
    /// canonical outputs of the table `table`, and grind it to `tier`.
    pub fn build(&mut self, job: JobAnchor, table: &Table, prev_height: u32, tier: u8) -> NetShare {
        self.build_on(job, table, btc_hash(prev_height), prev_height, tier)
    }

    /// [`Miner::build`] on Bitcoin block `prev` at `prev_height`, on any branch.
    pub fn build_on(
        &mut self,
        job: JobAnchor,
        table: &Table,
        prev: [u8; 32],
        prev_height: u32,
        tier: u8,
    ) -> NetShare {
        self.extranonce += 1;
        let h = prev_height + 1;
        let tag = ShareTagPreimage {
            node_id: self.node_id,
            tier: 0,
            slot_class: SLOTS,
            payee_script: self.payee.clone(),
            parent_anchor: job.parent_anchor,
            batch_root: job.batch_root,
        };
        let (outs, _) =
            coinbase_outputs(h, table, SLOTS as usize, &p2tr("finder"), 25_000, &[9; 32])
                .expect("outputs");
        let mut sig = bitcoin::script::Builder::new()
            .push_int(h as i64)
            .into_bytes();
        sig.extend(encode_payout_tag(&tag.parent_anchor_tag()));
        sig.extend(encode_node_tag(&tag.tag()));
        sig.push(8);
        sig.extend_from_slice(&self.extranonce.to_le_bytes());
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(sig),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outs
                .into_iter()
                .map(|(v, s)| TxOut {
                    value: Amount::from_sat(v),
                    script_pubkey: ScriptBuf::from_bytes(s),
                })
                .collect(),
        };
        let header = Header {
            version: Version::from_consensus(0x2000_0000),
            prev_blockhash: BlockHash::from_byte_array(prev),
            merkle_root: TxMerkleNode::from_byte_array(tx.compute_txid().to_byte_array()),
            time: self.time,
            bits: CompactTarget::from_consensus(BITS),
            nonce: 0,
        };
        NetShare {
            header: grind(header, tier),
            coinbase: serialize(&tx),
            merkle_branch: vec![],
            tag,
        }
    }

    /// A share on `relay`'s published job at the Bitcoin tip, at `T_net` (`anchor`: `T_net + 8`).
    pub fn mine(&mut self, relay: &mut Relay, btc: &Btc, anchor: bool) -> NetShare {
        let job = relay.job_anchor().expect("published");
        let h = btc.tip + 1;
        let table = relay.job_table(&job.parent_anchor, h).expect("table");
        let t = relay
            .required_tier(&job.parent_anchor, btc.tip)
            .expect("tier");
        let tier = if anchor { t + ANCHOR_TIER_OFFSET } else { t };
        let mut s = self.build(job, &table, btc.tip, tier);
        if !anchor {
            // An anchor-grade hash by luck would change what the test means; mine again.
            while hash_meets_tier(&s.id(), base(), t + ANCHOR_TIER_OFFSET) {
                s = self.build(job, &table, btc.tip, tier);
            }
        }
        s
    }
}

/// Grind the nonce until the header meets `tier`, on several threads.
pub fn grind(header: Header, tier: u8) -> Header {
    let found = AtomicBool::new(false);
    let nonce = AtomicU32::new(0);
    let threads = 8u32;
    std::thread::scope(|sc| {
        for t in 0..threads {
            let (found, nonce) = (&found, &nonce);
            sc.spawn(move || {
                let mut h = header;
                h.nonce = t;
                while !found.load(Ordering::Relaxed) {
                    if hash_meets_tier(&h.block_hash().to_byte_array(), base(), tier) {
                        if !found.swap(true, Ordering::SeqCst) {
                            nonce.store(h.nonce, Ordering::SeqCst);
                        }
                        return;
                    }
                    h.nonce = h.nonce.wrapping_add(threads);
                }
            });
        }
    });
    let mut h = header;
    h.nonce = nonce.load(Ordering::SeqCst);
    h
}

/// One simulated node.
pub struct SimNode {
    /// Its relay core.
    pub relay: Relay,
    /// Its own Bitcoin node (shared with the others unless a test gives it its own).
    pub node: MemBlocks,
    /// Its miner.
    pub miner: Miner,
    /// Penalties it handed out: `(peer, score, reason)`.
    pub penalties: Vec<(PeerId, u32, String)>,
    /// Every job anchor it published, in order.
    pub published: Vec<JobAnchor>,
}

/// Decides whether a message in flight is dropped: `(from, to, message)`.
pub type DropRule = Box<dyn Fn(usize, usize, &Message) -> bool>;

/// Rewrites a message in flight: `(from, to, message)`.
pub type TamperRule = Box<dyn Fn(usize, usize, Message) -> Message>;

/// An in-process network of relay cores with controllable links.
pub struct Sim {
    /// The nodes; node `i` is peer `i` to the others.
    pub nodes: Vec<SimNode>,
    links: HashSet<(usize, usize)>,
    queue: VecDeque<(usize, usize, Message)>,
    /// The Bitcoin chain every node sees.
    pub btc: Btc,
    /// The clock.
    pub now: u64,
    /// Messages to lose.
    pub drop: DropRule,
    /// Messages to rewrite (a lying peer).
    pub tamper: TamperRule,
    /// Messages delivered so far.
    pub delivered: usize,
}

impl Sim {
    /// `n` nodes, no links.
    pub fn new(n: usize) -> Sim {
        Sim::with_relays(n, |_| relay())
    }

    /// `n` nodes on relays from `make`, no links.
    pub fn with_relays(n: usize, make: impl Fn(usize) -> Relay) -> Sim {
        let btc = Btc::new(START_TIP);
        let mut s = Sim {
            nodes: Vec::new(),
            links: HashSet::new(),
            queue: VecDeque::new(),
            btc,
            now: T0,
            drop: Box::new(|_, _, _| false),
            tamper: Box::new(|_, _, m| m),
            delivered: 0,
        };
        for i in 0..n {
            let mut r = make(i);
            r.set_btc_tip(START_TIP);
            r.archive().trust_work_for_tests();
            feed(r.archive(), &s.btc.node);
            s.nodes.push(SimNode {
                node: s.btc.node.clone(),
                relay: r,
                miner: Miner::new(&format!("miner-{i}"), i as u8 + 1),
                penalties: Vec::new(),
                published: Vec::new(),
            });
            let outs = s.nodes[i].relay.take_out();
            s.route(i, outs);
        }
        s
    }

    /// `n` nodes, every pair linked.
    pub fn mesh(n: usize) -> Sim {
        let mut s = Sim::new(n);
        for a in 0..n {
            for b in a + 1..n {
                s.link(a, b);
            }
        }
        s.run();
        s
    }

    /// Whether `a` and `b` are linked.
    pub fn linked(&self, a: usize, b: usize) -> bool {
        self.links.contains(&(a.min(b), a.max(b)))
    }

    /// Connect `a` and `b`; each sends the other its tip.
    pub fn link(&mut self, a: usize, b: usize) {
        self.links.insert((a.min(b), a.max(b)));
        let o = self.nodes[a].relay.peer_connected(b as PeerId);
        self.route(a, o);
        let o = self.nodes[b].relay.peer_connected(a as PeerId);
        self.route(b, o);
    }

    /// Disconnect `a` and `b`.
    pub fn unlink(&mut self, a: usize, b: usize) {
        self.links.remove(&(a.min(b), a.max(b)));
        self.nodes[a].relay.peer_disconnected(b as PeerId);
        self.nodes[b].relay.peer_disconnected(a as PeerId);
    }

    fn route(&mut self, from: usize, outs: Vec<Out>) {
        for o in outs {
            match o {
                Out::Send(p, m) => self.queue.push_back((from, p as usize, m)),
                Out::Broadcast { msg, except } => {
                    for to in 0..self.nodes.len() {
                        if to != from && Some(to as PeerId) != except && self.linked(from, to) {
                            self.queue.push_back((from, to, msg.clone()));
                        }
                    }
                }
                Out::Penalize {
                    peer,
                    score,
                    reason,
                } => self.nodes[from].penalties.push((peer, score, reason)),
                Out::Publish(j) => self.nodes[from].published.push(j),
            }
        }
    }

    /// Deliver until nothing is in flight.
    pub fn run(&mut self) {
        let mut steps = 0;
        while let Some((f, t, m)) = self.queue.pop_front() {
            steps += 1;
            assert!(steps < 200_000, "message storm");
            if !self.linked(f, t) || (self.drop)(f, t, &m) {
                continue;
            }
            let m = (self.tamper)(f, t, m);
            self.delivered += 1;
            let outs = self.nodes[t]
                .relay
                .on_message(f as PeerId, m, &self.btc.headers, self.now);
            self.route(t, outs);
        }
    }

    /// Advance the clock by `dt` seconds and run every node's timers: archive its Bitcoin
    /// node's best chain, fetch the blocks its checks wanted, then its relay timers.
    pub fn tick(&mut self, dt: u64) {
        self.now += dt;
        for i in 0..self.nodes.len() {
            let tip = self.btc.tip;
            let n = &mut self.nodes[i];
            feed(n.relay.archive(), &n.node);
            n.relay.set_btc_tip(tip);
            fetch_wanted(&mut n.relay, &n.node);
            let outs = n.relay.take_out();
            self.route(i, outs);
            let outs = self.nodes[i].relay.tick(&self.btc.headers, self.now);
            self.route(i, outs);
        }
        self.run();
    }

    /// Replace node `i`'s relay (a restart or a fresh node), linked to nobody.
    pub fn replace(&mut self, i: usize, mut r: Relay) {
        for j in 0..self.nodes.len() {
            if j != i {
                self.unlink(i, j);
            }
        }
        r.set_btc_tip(self.btc.tip);
        r.archive().trust_work_for_tests();
        feed(r.archive(), &self.nodes[i].node);
        self.nodes[i].relay = r;
        self.nodes[i].penalties.clear();
        let outs = self.nodes[i].relay.take_out();
        self.route(i, outs);
    }

    /// Add a node on relay `r`, linked to nobody. Returns its index.
    pub fn add(&mut self, r: Relay) -> usize {
        let i = self.nodes.len();
        self.nodes.push(SimNode {
            node: self.btc.node.clone(),
            relay: r,
            miner: Miner::new(&format!("miner-{i}"), i as u8 + 1),
            penalties: Vec::new(),
            published: Vec::new(),
        });
        let n = &mut self.nodes[i];
        n.relay.set_btc_tip(self.btc.tip);
        n.relay.archive().trust_work_for_tests();
        feed(n.relay.archive(), &n.node);
        let outs = n.relay.take_out();
        self.route(i, outs);
        i
    }

    /// Node `i`'s miner finds a share (`anchor`: an anchor) and node `i` takes it.
    pub fn mine(&mut self, i: usize, anchor: bool) -> NetShare {
        let n = &mut self.nodes[i];
        let s = n.miner.mine(&mut n.relay, &self.btc, anchor);
        let r = n
            .relay
            .on_local_share(s.clone(), &self.btc.headers, self.now);
        let want = if anchor {
            LocalOutcome::Anchor
        } else {
            LocalOutcome::Share
        };
        assert_eq!(r, Ok(want), "node {i}");
        let outs = self.nodes[i].relay.take_out();
        self.route(i, outs);
        self.run();
        s
    }

    /// Node `i`'s miner finds a share on Bitcoin block `prev` at `prev_height` (any branch the
    /// node has archived), on node `i`'s published job, and node `i` takes it.
    pub fn mine_on(
        &mut self,
        i: usize,
        prev: [u8; 32],
        prev_height: u32,
        anchor: bool,
    ) -> NetShare {
        let n = &mut self.nodes[i];
        let job = n.relay.job_anchor().expect("published");
        let table = n
            .relay
            .block_table_on(&job.parent_anchor, prev_height + 1, &prev)
            .expect("table");
        let t = n
            .relay
            .required_tier(&job.parent_anchor, prev_height)
            .expect("tier");
        let tier = if anchor { t + ANCHOR_TIER_OFFSET } else { t };
        let mut s = n.miner.build_on(job, &table, prev, prev_height, tier);
        while !anchor && hash_meets_tier(&s.id(), base(), t + ANCHOR_TIER_OFFSET) {
            s = n.miner.build_on(job, &table, prev, prev_height, tier);
        }
        let want = if anchor {
            LocalOutcome::Anchor
        } else {
            LocalOutcome::Share
        };
        let r = n
            .relay
            .on_local_share(s.clone(), &self.btc.headers, self.now);
        assert_eq!(r, Ok(want), "node {i}");
        let outs = self.nodes[i].relay.take_out();
        self.route(i, outs);
        self.run();
        s
    }

    /// Inject a message as if `from` had sent it to `to`, and run.
    pub fn inject(&mut self, from: usize, to: usize, m: Message) {
        self.queue.push_back((from, to, m));
        self.run();
    }
}
