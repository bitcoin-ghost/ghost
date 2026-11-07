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
//| FILE: anchor_chain.rs                                                                                                |
//|======================================================================================================================|

//! The node pool's anchor chain, in memory (spec 2.2).
//!
//! An anchor is a network share meeting `T_net + 8`. Its job committed `parent_anchor` and
//! `batch_root` before hashing, so anchors form a tree. This module holds that tree and answers
//! what the rules need from it:
//!
//! - **Fork choice**: most cumulative anchor work, lower hash breaks ties. An anchor's work is
//!   `2^(T_net + 8)` for the tier it was required to meet. An anchor counts as unseen until its
//!   batch is held, here and on every ancestor (correction 6).
//! - **Ancestry**: the snapshot anchor `S(H)` of an including anchor, and the rule 6 check that a
//!   share's parent agrees on it. The share's own parent may sit on a dead fork.
//! - **Retarget**: `T_net` from Bitcoin heights. Per Bitcoin interval (anchors stamped with one
//!   `btc_height`) a 36-block non-overlapping window moves the tier by one when it reads more than
//!   0.75 tiers off; every 6 blocks a fast path jumps by the rounded error when it reads more than
//!   3 tiers off; any change resets the window. Empty intervals count, so `T_net` falls on Bitcoin
//!   height alone. Floor 10.
//! - **`btc_height`** is non-decreasing along a chain.
//!
//! `btc_height` is the Bitcoin tip height the anchor's job saw, so the job height is
//! `btc_height + 1`. Pure and in memory: no I/O, no clock, nothing wired into the running node.

use std::collections::{HashMap, HashSet};

use crate::canonical_payout::cut;
use crate::node_pool_constants::{
    ANCHOR_SPACING_SECS, ANCHOR_TIER_OFFSET, BTC_BLOCK_INTERVAL_SECS, RETARGET_FAST_BLOCKS,
    RETARGET_FAST_TIERS, RETARGET_MAX_COUNT_PER_BLOCK, RETARGET_WINDOW_BLOCKS, T_NET_CEILING,
    T_NET_FLOOR,
};
use crate::node_pool_u256::U256;
use crate::share_commit::hash_meets_tier;

/// An anchor's hash: its header hash in Bitcoin's internal byte order.
pub type AnchorHash = [u8; 32];

/// A share's identity within batches (its header hash).
pub type ShareId = [u8; 32];

/// The retarget state after some prefix of Bitcoin intervals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetargetState {
    tier: u8,
    /// Anchor counts per Bitcoin interval since the last reset, oldest first.
    window: Vec<u32>,
}

/// The rate error as an exact fraction `A / B`, where `log2(A / B)` is the error in tiers. With
/// `n` anchors over `k` blocks the measured rate is `max(n, 1/2) / k` anchors per block, against an
/// expected `600 / 54`, so `A = 54 * max(2n, 1)` and `B = 2 * 600 * k`, both divided by their
/// common factor 6 to keep `A^4` inside `u128` (`A = 9 * max(2n, 1)`, `B = 200 * k`).
fn ratio(sum: u64, blocks: u64) -> (u128, u128) {
    const G: u64 = gcd(ANCHOR_SPACING_SECS, 2 * BTC_BLOCK_INTERVAL_SECS);
    let n2 = (2 * sum).max(1) as u128;
    (
        (ANCHOR_SPACING_SECS / G) as u128 * n2,
        (2 * BTC_BLOCK_INTERVAL_SECS / G) as u128 * blocks as u128,
    )
}

const fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// `x * 2^e`, or `None` if it leaves `u128`.
fn mul_pow2(x: u128, e: u32) -> Option<u128> {
    1u128.checked_shl(e).and_then(|p| x.checked_mul(p))
}

/// Whether `a2 >= b2 * 2^two_m`, exactly, for any sign of `two_m`.
fn ge_scaled(a2: u128, b2: u128, two_m: i32) -> bool {
    if two_m >= 0 {
        mul_pow2(b2, two_m as u32).is_some_and(|r| a2 >= r)
    } else {
        mul_pow2(a2, (-two_m) as u32).is_none_or(|l| l >= b2)
    }
}

/// `round(log2(a / b))`: the largest `m` with `a / b >= 2^(m - 1/2)`, i.e. `2a^2 >= b^2 * 2^2m`.
/// Exact halves cannot occur (`2^(m + 1/2)` is irrational).
fn round_log2(a: u128, b: u128) -> i32 {
    let (a2, b2) = (2 * a * a, b * b);
    (-126..=126)
        .rev()
        .find(|m| ge_scaled(a2, b2, 2 * m))
        .unwrap_or(-126)
}

impl RetargetState {
    /// A fresh state at `tier`, clamped to the floor and ceiling.
    pub fn new(tier: u8) -> RetargetState {
        RetargetState {
            tier: tier.clamp(T_NET_FLOOR, T_NET_CEILING),
            window: Vec::new(),
        }
    }

    /// The network tier `T_net` this state sets.
    pub fn tier(&self) -> u8 {
        self.tier
    }

    /// Process Bitcoin interval `b`, in which `count` anchors were stamped. Returns whether a change
    /// was applied (it may leave the tier where it was, at the floor or ceiling).
    pub fn step(&mut self, b: u32, count: u32) -> bool {
        self.window.push(count.min(RETARGET_MAX_COUNT_PER_BLOCK));
        let mut change: Option<i32> = None;
        let fast = RETARGET_FAST_BLOCKS as usize;
        if b % RETARGET_FAST_BLOCKS == RETARGET_FAST_BLOCKS - 1 && self.window.len() >= fast {
            let sum: u64 = self.window[self.window.len() - fast..]
                .iter()
                .map(|x| *x as u64)
                .sum();
            let (a, bb) = ratio(sum, fast as u64);
            let off = 1u128 << RETARGET_FAST_TIERS;
            if a > off * bb || off * a < bb {
                change = Some(round_log2(a, bb));
            }
        }
        if change.is_none() && self.window.len() >= RETARGET_WINDOW_BLOCKS as usize {
            let sum: u64 = self.window.iter().map(|x| *x as u64).sum();
            let (a, bb) = ratio(sum, self.window.len() as u64);
            self.window.clear();
            // |log2(a / b)| > 3/4  <=>  a^4 > 8 b^4  or  8 a^4 < b^4.
            // Counts are capped, so these stay inside u128; a miss would read as "far above".
            let b4 = bb.pow(4);
            match a.checked_pow(4) {
                None => change = Some(1),
                Some(a4) if a4 > 8 * b4 => change = Some(1),
                Some(a4) if 8 * a4 < b4 => change = Some(-1),
                _ => {}
            }
        }
        match change {
            Some(c) if c != 0 => {
                let t = (self.tier as i32 + c).clamp(T_NET_FLOOR as i32, T_NET_CEILING as i32);
                self.tier = t as u8;
                self.window.clear();
                true
            }
            _ => false,
        }
    }

    /// Process intervals `from..to` with no anchors. At the floor with an empty window the state
    /// repeats every 6 empty blocks, so whole cycles are skipped: a far-future `btc_height` costs
    /// at most a few hundred steps whatever the gap.
    pub fn step_empty(&mut self, from: u32, to: u32) {
        let mut b = from;
        while b < to {
            let cycle = RETARGET_FAST_BLOCKS;
            if self.tier == T_NET_FLOOR
                && self.window.is_empty()
                && b.is_multiple_of(cycle)
                && to - b >= cycle
            {
                b += (to - b) / cycle * cycle;
                continue;
            }
            self.step(b, 0);
            b += 1;
        }
    }
}

/// An anchor header as the chain needs it. Its share validity (spec 2.1) is checked elsewhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorHeader {
    /// The anchor's header hash.
    pub hash: AnchorHash,
    /// The `parent_anchor` its job committed.
    pub parent: AnchorHash,
    /// The Bitcoin tip height its job saw.
    pub btc_height: u32,
}

/// What the chain knows about one anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorInfo {
    /// Parent, `None` for genesis.
    pub parent: Option<AnchorHash>,
    /// Anchors between genesis and this one (genesis is 0).
    pub height: u32,
    /// The Bitcoin tip height its job saw.
    pub btc_height: u32,
    /// `T_net` in force for it; it met `t_net + 8`.
    pub t_net: u8,
    /// Cumulative anchor work, genesis to here.
    pub work: U256,
    /// Its batch is held here and on every ancestor.
    pub seen: bool,
}

/// Why the chain refused an anchor or a batch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnchorError {
    /// The parent is not in the chain.
    #[error("unknown parent")]
    UnknownParent,
    /// The anchor is not in the chain.
    #[error("unknown anchor")]
    UnknownAnchor,
    /// Already held.
    #[error("duplicate anchor")]
    Duplicate,
    /// `btc_height` below the parent's.
    #[error("btc_height {child} below parent's {parent}")]
    BtcHeightDecreases {
        /// The parent's `btc_height`.
        parent: u32,
        /// The child's `btc_height`.
        child: u32,
    },
    /// The hash does not meet `T_net + 8`.
    #[error("hash does not meet anchor tier {0}")]
    InsufficientWork(u8),
    /// The batch was already attached.
    #[error("batch already held")]
    BatchAlreadyHeld,
    /// The batch lists one share twice.
    #[error("share listed twice in one batch")]
    DuplicateInBatch,
    /// The batch re-includes a share already on its ancestry.
    #[error("share already included on the ancestry")]
    AlreadyIncluded,
}

/// Why a share fails rule 6 against an including anchor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AncestryError {
    /// The including anchor is not in the chain.
    #[error("unknown including anchor")]
    UnknownAnchor,
    /// The share's parent anchor is not in the chain.
    #[error("unknown share parent")]
    UnknownParent,
    /// The including anchor has no anchor below `cut(H)` on its ancestry.
    #[error("no snapshot anchor below the cut")]
    NoSnapshot,
    /// `S(H)` of the including anchor is not an ancestor of the share's parent.
    #[error("share parent does not descend from the snapshot anchor")]
    NotDescended,
    /// The share's parent sees a later snapshot anchor than the including anchor does.
    #[error("share parent's snapshot differs from the including anchor's")]
    SnapshotMismatch,
    /// The share is already in a batch on the including anchor's ancestry.
    #[error("share already included")]
    Duplicate,
}

#[derive(Debug, Clone)]
struct Node {
    info: AnchorInfo,
    retarget: RetargetState,
    /// Anchors on the ancestry, self included, stamped with this `btc_height`.
    run: u32,
    /// `skip[k]` is the `2^k`-th ancestor.
    skip: Vec<AnchorHash>,
    batch_held: bool,
}

/// The anchor tree with fork choice and ancestry queries.
#[derive(Debug, Clone)]
pub struct AnchorChain {
    nodes: HashMap<AnchorHash, Node>,
    children: HashMap<AnchorHash, Vec<AnchorHash>>,
    /// Every anchor whose held batch lists a share.
    carriers: HashMap<ShareId, Vec<AnchorHash>>,
    genesis: AnchorHash,
    best: AnchorHash,
    tier_base: U256,
}

/// Work of an anchor that met `t_net + 8`: `2^(t_net + 8)`.
fn anchor_work(t_net: u8) -> U256 {
    U256::pow2(t_net as u32 + ANCHOR_TIER_OFFSET as u32).expect("tier below 248")
}

/// Fork choice: more work wins; equal work, the numerically lower hash wins.
fn better(a: (&U256, &AnchorHash), b: (&U256, &AnchorHash)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && U256::from_le_bytes(*a.1) < U256::from_le_bytes(*b.1))
}

impl AnchorChain {
    /// A chain from a trusted genesis anchor at `btc_height` with `T_net = tier`. `tier_base` is the
    /// tier-0 target (`share_commit::diff1_target()` on mainnet and signet).
    pub fn new(genesis: AnchorHash, btc_height: u32, tier: u8, tier_base: U256) -> AnchorChain {
        let retarget = RetargetState::new(tier);
        let info = AnchorInfo {
            parent: None,
            height: 0,
            btc_height,
            t_net: retarget.tier(),
            work: anchor_work(retarget.tier()),
            seen: true,
        };
        let node = Node {
            info,
            retarget,
            run: 1,
            skip: Vec::new(),
            batch_held: true,
        };
        AnchorChain {
            nodes: HashMap::from([(genesis, node)]),
            children: HashMap::new(),
            carriers: HashMap::new(),
            genesis,
            best: genesis,
            tier_base,
        }
    }

    /// The genesis anchor.
    pub fn genesis(&self) -> AnchorHash {
        self.genesis
    }

    /// The best seen tip.
    pub fn best(&self) -> AnchorHash {
        self.best
    }

    /// What the chain knows about `hash`.
    pub fn get(&self, hash: &AnchorHash) -> Option<&AnchorInfo> {
        self.nodes.get(hash).map(|n| &n.info)
    }

    /// `T_net` for a job (share or anchor) built on `parent` while the Bitcoin tip is `btc_height`:
    /// the parent's retarget state carried through interval `btc_height - 1`.
    pub fn required_tier(&self, parent: &AnchorHash, btc_height: u32) -> Result<u8, AnchorError> {
        let p = self.nodes.get(parent).ok_or(AnchorError::UnknownParent)?;
        Ok(Self::child_retarget(p, btc_height)?.tier())
    }

    fn child_retarget(p: &Node, btc_height: u32) -> Result<RetargetState, AnchorError> {
        let ph = p.info.btc_height;
        if btc_height < ph {
            return Err(AnchorError::BtcHeightDecreases {
                parent: ph,
                child: btc_height,
            });
        }
        let mut r = p.retarget.clone();
        if btc_height > ph {
            r.step(ph, p.run);
            r.step_empty(ph + 1, btc_height);
        }
        Ok(r)
    }

    /// Add an anchor header. It meets `T_net + 8` for its parent and `btc_height`, and stays unseen
    /// until [`AnchorChain::attach_batch`].
    pub fn insert(&mut self, a: AnchorHeader) -> Result<(), AnchorError> {
        if self.nodes.contains_key(&a.hash) {
            return Err(AnchorError::Duplicate);
        }
        let p = self
            .nodes
            .get(&a.parent)
            .ok_or(AnchorError::UnknownParent)?;
        let retarget = Self::child_retarget(p, a.btc_height)?;
        let t_net = retarget.tier();
        let need = t_net + ANCHOR_TIER_OFFSET;
        if !hash_meets_tier(&a.hash, self.tier_base, need) {
            return Err(AnchorError::InsufficientWork(need));
        }
        let work = p
            .info
            .work
            .checked_add(anchor_work(t_net))
            .expect("anchor work below 2^256");
        let run = if a.btc_height == p.info.btc_height {
            p.run + 1
        } else {
            1
        };
        let mut skip = vec![a.parent];
        while let Some(next) = self
            .nodes
            .get(&skip[skip.len() - 1])
            .and_then(|n| n.skip.get(skip.len() - 1))
        {
            skip.push(*next);
        }
        let info = AnchorInfo {
            parent: Some(a.parent),
            height: p.info.height + 1,
            btc_height: a.btc_height,
            t_net,
            work,
            seen: false,
        };
        self.nodes.insert(
            a.hash,
            Node {
                info,
                retarget,
                run,
                skip,
                batch_held: false,
            },
        );
        self.children.entry(a.parent).or_default().push(a.hash);
        Ok(())
    }

    /// Attach an anchor's batch: the shares it locks in. Checking each share (spec 2.1) and that
    /// the list matches the committed `batch_root` is the caller's job; this refuses a share listed
    /// twice or already included on the ancestry. Marks the anchor, and any descendants whose
    /// batches are held, as seen, and updates the best tip.
    pub fn attach_batch(
        &mut self,
        hash: &AnchorHash,
        shares: &[ShareId],
    ) -> Result<(), AnchorError> {
        let n = self.nodes.get(hash).ok_or(AnchorError::UnknownAnchor)?;
        if n.batch_held {
            return Err(AnchorError::BatchAlreadyHeld);
        }
        let mut uniq = HashSet::with_capacity(shares.len());
        if !shares.iter().all(|s| uniq.insert(*s)) {
            return Err(AnchorError::DuplicateInBatch);
        }
        if let Some(parent) = n.info.parent {
            if shares.iter().any(|s| self.included_on_ancestry(&parent, s)) {
                return Err(AnchorError::AlreadyIncluded);
            }
        }
        for s in shares {
            self.carriers.entry(*s).or_default().push(*hash);
        }
        self.nodes.get_mut(hash).expect("present").batch_held = true;
        let parent_seen = n_parent_seen(&self.nodes, hash);
        if parent_seen {
            self.mark_seen_from(*hash);
        }
        Ok(())
    }

    fn mark_seen_from(&mut self, root: AnchorHash) {
        let mut stack = vec![root];
        while let Some(h) = stack.pop() {
            let node = self.nodes.get_mut(&h).expect("present");
            if !node.batch_held || node.info.seen {
                continue;
            }
            node.info.seen = true;
            let (work, best) = (node.info.work, self.best);
            let best_work = self.nodes[&best].info.work;
            if better((&work, &h), (&best_work, &best)) {
                self.best = h;
            }
            stack.extend(self.children.get(&h).into_iter().flatten().copied());
        }
    }

    /// Whether `a` is `b` or an ancestor of `b`.
    pub fn is_ancestor(&self, a: &AnchorHash, b: &AnchorHash) -> bool {
        let (Some(na), Some(nb)) = (self.nodes.get(a), self.nodes.get(b)) else {
            return false;
        };
        let Some(d) = nb.info.height.checked_sub(na.info.height) else {
            return false;
        };
        self.ancestor_by(*b, d) == Some(*a)
    }

    /// The ancestor `d` anchors above `h`.
    fn ancestor_by(&self, mut h: AnchorHash, mut d: u32) -> Option<AnchorHash> {
        let mut k = 0;
        while d > 0 {
            if d & 1 == 1 {
                h = *self.nodes.get(&h)?.skip.get(k)?;
            }
            d >>= 1;
            k += 1;
        }
        Some(h)
    }

    /// The last anchor on `a`'s ancestry, `a` included, with `btc_height < bound`.
    pub fn last_below(&self, a: &AnchorHash, bound: u32) -> Option<AnchorHash> {
        let mut n = self.nodes.get(a)?;
        if n.info.btc_height < bound {
            return Some(*a);
        }
        // btc_height is non-decreasing, so climb while still at or above the bound.
        for k in (0..n.skip.len()).rev() {
            while let Some(up) = n.skip.get(k) {
                let un = &self.nodes[up];
                if un.info.btc_height < bound {
                    break;
                }
                n = un;
            }
        }
        n.info.parent
    }

    /// `S(H)` as seen from anchor `a`: the last anchor on its ancestry with `btc_height < cut(H)`.
    /// Its table holds credits of job height `<= cut(H)`, since job height is `btc_height + 1`.
    pub fn snapshot_anchor(&self, a: &AnchorHash, job_height: u32) -> Option<AnchorHash> {
        self.last_below(a, cut(job_height)?)
    }

    /// Whether `share` is in the batch of `a` or of any ancestor of `a`.
    pub fn included_on_ancestry(&self, a: &AnchorHash, share: &ShareId) -> bool {
        self.carriers
            .get(share)
            .is_some_and(|cs| cs.iter().any(|c| self.is_ancestor(c, a)))
    }

    /// Rule 6 for a share of job height `job_height` built on `share_parent`, included by
    /// `including`. Returns `S(H)`, the anchor whose table the share's outputs must match.
    ///
    /// `S(H)` is taken from the including anchor's ancestry and must also be the snapshot the
    /// share's parent saw; the parent itself may sit on a dead fork. The share must not already be
    /// in a batch on the including anchor's ancestry above it.
    pub fn check_share_ancestry(
        &self,
        including: &AnchorHash,
        share_parent: &AnchorHash,
        job_height: u32,
        share: &ShareId,
    ) -> Result<AnchorHash, AncestryError> {
        let inc = self
            .nodes
            .get(including)
            .ok_or(AncestryError::UnknownAnchor)?;
        if !self.nodes.contains_key(share_parent) {
            return Err(AncestryError::UnknownParent);
        }
        let s = self
            .snapshot_anchor(including, job_height)
            .ok_or(AncestryError::NoSnapshot)?;
        if !self.is_ancestor(&s, share_parent) {
            return Err(AncestryError::NotDescended);
        }
        if self.snapshot_anchor(share_parent, job_height) != Some(s) {
            return Err(AncestryError::SnapshotMismatch);
        }
        if let Some(p) = inc.info.parent {
            if self.included_on_ancestry(&p, share) {
                return Err(AncestryError::Duplicate);
            }
        }
        Ok(s)
    }
}

fn n_parent_seen(nodes: &HashMap<AnchorHash, Node>, h: &AnchorHash) -> bool {
    nodes[h].info.parent.is_none_or(|p| nodes[&p].info.seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share_commit::diff1_target;

    /// A synthetic anchor hash: numeric value `v` in internal byte order, with `id` in the high
    /// bytes so distinct anchors differ. `v` small means plenty of work for any tier used here.
    fn hash(id: u16, v: u64) -> AnchorHash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&v.to_le_bytes());
        h[8..10].copy_from_slice(&id.to_le_bytes());
        h
    }

    fn g() -> AnchorHash {
        hash(0, 0)
    }

    fn chain(tier: u8) -> AnchorChain {
        AnchorChain::new(g(), 1_000, tier, diff1_target())
    }

    fn add(c: &mut AnchorChain, id: u16, parent: AnchorHash, btc: u32) -> AnchorHash {
        let h = hash(id, 1);
        c.insert(AnchorHeader {
            hash: h,
            parent,
            btc_height: btc,
        })
        .unwrap();
        c.attach_batch(&h, &[]).unwrap();
        h
    }

    /// The trace of the simulator's final policy (`sims/anchor-sim/sim_retarget3.py`, W36 with the
    /// fast path at 3 tiers), floor 10, on a fixed count sequence, computed in Python with floats:
    /// `(height, tier)` at every applied change.
    #[test]
    fn retarget_matches_the_simulated_policy() {
        let counts = |b: u32| match b - 1000 {
            0..=49 => 11,
            50..=89 => 30,
            90..=149 => 0,
            150..=199 => 200,
            200..=279 => 11,
            280..=299 => 2,
            300..=339 => 25,
            340..=419 => 16,
            _ => 9,
        };
        let want = [
            (1071, 21),
            (1097, 14),
            (1103, 10),
            (1109, 10),
            (1115, 10),
            (1121, 10),
            (1127, 10),
            (1133, 10),
            (1139, 10),
            (1145, 10),
            (1157, 14),
            (1163, 18),
            (1169, 22),
            (1175, 26),
            (1181, 30),
            (1187, 34),
            (1193, 38),
            (1199, 42),
            (1343, 43),
        ];
        let mut r = RetargetState::new(20);
        let mut got = Vec::new();
        for b in 1000..1500 {
            if r.step(b, counts(b)) {
                got.push((b, r.tier()));
            }
        }
        assert_eq!(got, want);
    }

    #[test]
    fn retarget_band_and_steady_state() {
        // On target (11 or 12 a block, mean ~11.1) the tier never moves.
        let mut r = RetargetState::new(25);
        for b in 0..2_000u32 {
            assert!(!r.step(b, 11 + (b % 9 == 0) as u32));
        }
        // 1.5x fast is 0.58 tiers: inside the band. 2x is a whole tier: one step after 36 blocks.
        let mut r = RetargetState::new(25);
        (0..36).for_each(|b| assert!(!r.step(b, 17)));
        let mut r = RetargetState::new(25);
        (0..35).for_each(|b| assert!(!r.step(b, 22)));
        assert!(r.step(35, 22));
        assert_eq!(r.tier(), 26);
        // The fast path rounds: 6 blocks at 100 a block is log2(100 / 11.1) = 3.17 tiers -> +3.
        let mut r = RetargetState::new(25);
        (0..5).for_each(|b| assert!(!r.step(b, 100)));
        assert!(r.step(5, 100));
        assert_eq!(r.tier(), 28);
        assert_eq!(round_log2(3, 1), 2); // log2 3 = 1.58
        assert_eq!(round_log2(1, 3), -2);
        assert_eq!(round_log2(5, 4), 0);
    }

    #[test]
    fn t_net_falls_on_bitcoin_height_alone() {
        let c = chain(30);
        assert_eq!(c.required_tier(&g(), 1_000).unwrap(), 30);
        // Genesis is the one anchor of interval 1,000. The fast path reads the last six intervals
        // at heights = 5 mod 6: at 1,001 the window is too short, at 1,007 six empty blocks read
        // 7 tiers low, so a job above 1,007 needs tier 23.
        assert_eq!(c.required_tier(&g(), 1_007).unwrap(), 30);
        assert_eq!(c.required_tier(&g(), 1_008).unwrap(), 23);
        assert_eq!(c.required_tier(&g(), 1_014).unwrap(), 16);
        assert_eq!(c.required_tier(&g(), 1_030).unwrap(), T_NET_FLOOR);
        // A far-future height is cheap and lands on the floor.
        assert_eq!(c.required_tier(&g(), u32::MAX).unwrap(), T_NET_FLOOR);
    }

    #[test]
    fn empty_fast_forward_equals_stepping() {
        let mut seed = 7u64;
        let mut next = || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u32
        };
        for _ in 0..200 {
            let mut fast = RetargetState::new(10 + (next() % 30) as u8);
            let start = next() % 1_000;
            for b in start..start + next() % 40 {
                fast.step(b, next() % 40);
            }
            let mut slow = fast.clone();
            let from = start + 40;
            let to = from + next() % 500;
            fast.step_empty(from, to);
            (from..to).for_each(|b| {
                slow.step(b, 0);
            });
            assert_eq!(fast, slow);
        }
    }

    #[test]
    fn insert_rules() {
        let mut c = chain(20);
        let a = hash(1, 1);
        let header = AnchorHeader {
            hash: a,
            parent: g(),
            btc_height: 1_000,
        };
        c.insert(header).unwrap();
        assert_eq!(c.insert(header), Err(AnchorError::Duplicate));
        let orphan = AnchorHeader {
            hash: hash(2, 1),
            parent: hash(9, 9),
            btc_height: 1_000,
        };
        assert_eq!(c.insert(orphan), Err(AnchorError::UnknownParent));
        let back = AnchorHeader {
            hash: hash(3, 1),
            parent: a,
            btc_height: 999,
        };
        let err = AnchorError::BtcHeightDecreases {
            parent: 1_000,
            child: 999,
        };
        assert_eq!(c.insert(back), Err(err));
        // Tier 28 target is diff1 >> 28; a hash just above it is refused.
        let limit = diff1_target().shr_floor(28);
        let mut over = limit.checked_add(U256::from_u128(1)).unwrap().to_be_bytes();
        over.reverse();
        let weak = AnchorHeader {
            hash: over,
            parent: a,
            btc_height: 1_000,
        };
        assert_eq!(c.insert(weak), Err(AnchorError::InsufficientWork(28)));
        let mut at = limit.to_be_bytes();
        at.reverse();
        c.insert(AnchorHeader {
            hash: at,
            parent: a,
            btc_height: 1_000,
        })
        .unwrap();
        assert_eq!(c.get(&at).unwrap().t_net, 20);
        assert_eq!(c.get(&at).unwrap().height, 2);
    }

    #[test]
    fn fork_choice_is_work_not_length_and_lower_hash_breaks_ties() {
        let mut c = chain(20);
        // Branch A: two anchors at tier 20, 2^28 each.
        let a1 = add(&mut c, 1, g(), 1_000);
        let a2 = add(&mut c, 2, a1, 1_000);
        // Branch B: after 60 silent blocks the tier is at the floor: three anchors of 2^18.
        let b1 = add(&mut c, 3, g(), 1_060);
        let b2 = add(&mut c, 4, b1, 1_060);
        let b3 = add(&mut c, 5, b2, 1_060);
        assert_eq!(c.get(&b3).unwrap().t_net, T_NET_FLOOR);
        assert_eq!(c.best(), a2, "fewer anchors, more work");

        // Equal work: the numerically lower hash wins, whatever the arrival order.
        let mut c = chain(20);
        let hi = hash(1, 5);
        let lo = hash(1, 4);
        for h in [hi, lo] {
            c.insert(AnchorHeader {
                hash: h,
                parent: g(),
                btc_height: 1_000,
            })
            .unwrap();
            c.attach_batch(&h, &[]).unwrap();
        }
        assert_eq!(c.best(), lo);
    }

    #[test]
    fn an_anchor_is_unseen_until_its_batch_is_held() {
        let mut c = chain(20);
        let a1 = add(&mut c, 1, g(), 1_000);
        let b1 = hash(2, 1);
        let b2 = hash(3, 1);
        c.insert(AnchorHeader {
            hash: b1,
            parent: g(),
            btc_height: 1_000,
        })
        .unwrap();
        c.insert(AnchorHeader {
            hash: b2,
            parent: b1,
            btc_height: 1_000,
        })
        .unwrap();
        c.attach_batch(&b2, &[[0xB2; 32]]).unwrap();
        assert_eq!(c.best(), a1, "b2 is heavier but b1's batch is missing");
        assert!(!c.get(&b2).unwrap().seen);
        c.attach_batch(&b1, &[[0xB1; 32]]).unwrap();
        assert!(c.get(&b2).unwrap().seen);
        assert_eq!(c.best(), b2);
        assert_eq!(c.attach_batch(&b1, &[]), Err(AnchorError::BatchAlreadyHeld));
    }

    #[test]
    fn batches_refuse_duplicates_on_their_own_ancestry_only() {
        let mut c = chain(20);
        let s = [0x55; 32];
        let a1 = hash(1, 1);
        c.insert(AnchorHeader {
            hash: a1,
            parent: g(),
            btc_height: 1_000,
        })
        .unwrap();
        assert_eq!(
            c.attach_batch(&a1, &[s, s]),
            Err(AnchorError::DuplicateInBatch)
        );
        c.attach_batch(&a1, &[s]).unwrap();
        let a2 = hash(2, 1);
        c.insert(AnchorHeader {
            hash: a2,
            parent: a1,
            btc_height: 1_000,
        })
        .unwrap();
        assert_eq!(c.attach_batch(&a2, &[s]), Err(AnchorError::AlreadyIncluded));
        // A competing anchor re-includes the losing side's share.
        let b1 = hash(3, 1);
        c.insert(AnchorHeader {
            hash: b1,
            parent: g(),
            btc_height: 1_000,
        })
        .unwrap();
        c.attach_batch(&b1, &[s]).unwrap();
        assert!(c.included_on_ancestry(&a1, &s) && c.included_on_ancestry(&b1, &s));
        assert!(!c.included_on_ancestry(&g(), &s));
    }

    /// Main chain G(1000) A1(1000) A2(1010) A3(1025) A4(1030), with forks off it.
    fn ancestry_fixture() -> (AnchorChain, [AnchorHash; 4]) {
        let mut c = chain(20);
        let a1 = add(&mut c, 1, g(), 1_000);
        let a2 = add(&mut c, 2, a1, 1_010);
        let a3 = add(&mut c, 3, a2, 1_025);
        let a4 = add(&mut c, 4, a3, 1_030);
        (c, [a1, a2, a3, a4])
    }

    #[test]
    fn ancestry_queries() {
        let (c, [a1, a2, a3, a4]) = ancestry_fixture();
        assert!(c.is_ancestor(&g(), &a4) && c.is_ancestor(&a2, &a4) && c.is_ancestor(&a4, &a4));
        assert!(!c.is_ancestor(&a4, &a2));
        assert_eq!(c.last_below(&a4, 1_031), Some(a4));
        assert_eq!(c.last_below(&a4, 1_030), Some(a3));
        assert_eq!(c.last_below(&a4, 1_020), Some(a2));
        assert_eq!(c.last_below(&a4, 1_010), Some(a1));
        assert_eq!(c.last_below(&a4, 1_000), None);
        // S(H) with cut(H) = H - 20: job height 1,040 cuts at 1,020.
        assert_eq!(c.snapshot_anchor(&a4, 1_040), Some(a2));
        assert_eq!(c.snapshot_anchor(&a3, 1_046), Some(a3));
    }

    #[test]
    fn deep_ancestry_uses_skip_pointers() {
        let mut c = chain(20);
        let mut tip = g();
        let mut all = vec![g()];
        for i in 1..=300u16 {
            tip = add(&mut c, i, tip, 1_000 + i as u32);
            all.push(tip);
        }
        assert_eq!(c.get(&tip).unwrap().height, 300);
        assert!(c.is_ancestor(&all[1], &tip) && c.is_ancestor(&all[257], &tip));
        assert!(!c.is_ancestor(&tip, &all[299]));
        for bound in [1_001u32, 1_002, 1_128, 1_129, 1_257, 1_300] {
            let want = all[(bound - 1_001) as usize];
            assert_eq!(c.last_below(&tip, bound), Some(want), "bound {bound}");
        }
    }

    #[test]
    fn rule_6_share_parent_may_sit_on_a_dead_fork() {
        let (mut c, [a1, a2, _a3, a4]) = ancestry_fixture();
        let share = [0x77; 32];
        let h = 1_040; // cut 1,020: S = a2 from a4's ancestry

        // Dead fork off a2 above the cut: same snapshot, valid.
        let dead = add(&mut c, 10, a2, 1_026);
        assert_eq!(c.check_share_ancestry(&a4, &dead, h, &share), Ok(a2));
        // The includer's own ancestry.
        assert_eq!(c.check_share_ancestry(&a4, &a4, h, &share), Ok(a2));
        // A parent below S: built before the snapshot existed.
        let err = c.check_share_ancestry(&a4, &a1, h, &share);
        assert_eq!(err, Err(AncestryError::NotDescended));
        // A fork off a1 below the cut sees itself as S.
        let other = add(&mut c, 11, a1, 1_015);
        let err = c.check_share_ancestry(&a4, &other, h, &share);
        assert_eq!(err, Err(AncestryError::NotDescended));
        // A fork off a2 that stamps a height below the cut sees a later snapshot than the includer.
        let late = add(&mut c, 12, a2, 1_019);
        let err = c.check_share_ancestry(&a4, &late, h, &share);
        assert_eq!(err, Err(AncestryError::SnapshotMismatch));
        // No anchor below the cut at all.
        let err = c.check_share_ancestry(&a4, &a4, 1_015, &share);
        assert_eq!(err, Err(AncestryError::NoSnapshot));
        let err = c.check_share_ancestry(&a4, &hash(99, 1), h, &share);
        assert_eq!(err, Err(AncestryError::UnknownParent));
    }

    #[test]
    fn rule_6_refuses_a_share_already_on_the_includers_ancestry() {
        let (mut c, [_a1, a2, a3, _a4]) = ancestry_fixture();
        let share = [0x88; 32];
        let x = hash(20, 1);
        c.insert(AnchorHeader {
            hash: x,
            parent: a3,
            btc_height: 1_030,
        })
        .unwrap();
        c.attach_batch(&x, &[share]).unwrap();
        let y = hash(21, 1);
        c.insert(AnchorHeader {
            hash: y,
            parent: x,
            btc_height: 1_030,
        })
        .unwrap();
        let err = c.check_share_ancestry(&y, &a3, 1_040, &share);
        assert_eq!(err, Err(AncestryError::Duplicate));
        // x itself including it is fine: its own batch is what is being checked.
        assert_eq!(c.check_share_ancestry(&x, &a3, 1_040, &share), Ok(a2));
    }
}
