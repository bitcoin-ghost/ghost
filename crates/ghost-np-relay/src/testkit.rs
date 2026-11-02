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

//! Test support: a fake Bitcoin header chain, simulated miners that build canonical coinbases on a
//! node's published job, and a deterministic in-process network of relay cores.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

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

use crate::headers::{HeaderFacts, MemHeaders};
use crate::relay::{
    Genesis, JobAnchor, LocalOutcome, NoRetirements, Out, PeerId, Relay, RelayParams,
};
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

/// A relay over a fresh in-memory store.
pub fn relay() -> Relay {
    Relay::open(
        params(),
        Arc::new(Database::in_memory().expect("db")),
        Box::new(NoRetirements),
    )
    .expect("open")
}

/// The hash of fake Bitcoin block `h`.
pub fn btc_hash(h: u32) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(b"fake bitcoin block");
    s.update(h.to_le_bytes());
    s.finalize().into()
}

/// A fake Bitcoin header chain.
pub struct Btc {
    /// What the relays look headers up in.
    pub headers: MemHeaders,
    /// Current tip height.
    pub tip: u32,
    /// Median time past of block `h` is `t0 - 100_000 + h`.
    pub t0: u64,
}

impl Btc {
    /// Headers from below genesis up to `tip`.
    pub fn new(tip: u32) -> Btc {
        Btc::with_time(tip, T0)
    }

    /// Headers whose times sit just below `t0`.
    pub fn with_time(tip: u32, t0: u64) -> Btc {
        let mut b = Btc {
            headers: MemHeaders::default(),
            tip: 0,
            t0,
        };
        b.extend_to(tip);
        b
    }

    /// Mine fake blocks up to `tip`.
    pub fn extend_to(&mut self, tip: u32) {
        for h in GENESIS_BTC - 40..=tip {
            self.headers.insert(
                btc_hash(h),
                HeaderFacts {
                    height: h,
                    next_bits: CompactTarget::from_consensus(BITS),
                    median_time_past: (self.t0 - 100_000) as u32 + h,
                },
            );
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

    /// Build a share on `job` on top of Bitcoin block `prev_height`, paying the canonical outputs
    /// of the table `table`, and grind it to `tier`.
    pub fn build(&mut self, job: JobAnchor, table: &Table, prev_height: u32, tier: u8) -> NetShare {
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
            prev_blockhash: BlockHash::from_byte_array(btc_hash(prev_height)),
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
    /// Its miner.
    pub miner: Miner,
    /// Penalties it handed out: `(peer, score, reason)`.
    pub penalties: Vec<(PeerId, u32, String)>,
    /// Every job anchor it published, in order.
    pub published: Vec<JobAnchor>,
}

/// Decides whether a message in flight is dropped: `(from, to, message)`.
pub type DropRule = Box<dyn Fn(usize, usize, &Message) -> bool>;

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
            delivered: 0,
        };
        for i in 0..n {
            let mut r = make(i);
            r.set_btc_tip(START_TIP);
            s.nodes.push(SimNode {
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
            self.delivered += 1;
            let outs = self.nodes[t]
                .relay
                .on_message(f as PeerId, m, &self.btc.headers, self.now);
            self.route(t, outs);
        }
    }

    /// Advance the clock by `dt` seconds and run every node's timers.
    pub fn tick(&mut self, dt: u64) {
        self.now += dt;
        for i in 0..self.nodes.len() {
            let tip = self.btc.tip;
            self.nodes[i].relay.set_btc_tip(tip);
            let outs = self.nodes[i].relay.tick(&self.btc.headers, self.now);
            self.route(i, outs);
        }
        self.run();
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

    /// Inject a message as if `from` had sent it to `to`, and run.
    pub fn inject(&mut self, from: usize, to: usize, m: Message) {
        self.queue.push_back((from, to, m));
        self.run();
    }
}
