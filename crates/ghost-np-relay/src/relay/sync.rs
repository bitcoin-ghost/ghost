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
//| FILE: sync.rs                                                                                                        |
//|======================================================================================================================|

//! Share-chain sync, checkpoints and pruning (W2.13, spec 2.2 correction 7).
//!
//! ## Initial sync
//!
//! A node that hears of a heavier tip than its own asks that peer for anchor headers with a
//! locator of its own chain (`GetHeaders`). The peer answers with up to
//! [`MAX_HEADERS_PER_MESSAGE`](crate::wire::MAX_HEADERS_PER_MESSAGE) anchors of its best chain after the first locator hash it holds
//! on that chain, parents first (`Headers`). Each is checked as any anchor is (its own share's
//! self-checks, its work against `T_net + 8` on its parent) and held unseen. A full reply asks
//! for more after its last anchor. The batches of held-but-unseen anchors are then requested,
//! oldest first and at most [`RelayParams::sync_inflight`](crate::relay::RelayParams::sync_inflight) at a time, and checked against the
//! including anchor's ancestry exactly as relayed ones are, from the genesis table up. A peer
//! that does not answer, answers `NotFound`, or sends data that does not check is passed over
//! for the next peer (`retry_request`). Nothing is trusted from a peer: a node that syncs reaches
//! the same chain, credits and tables as one that relayed every anchor live.
//!
//! Sync is resumable: anchors are stored only once their batch checks, so after a restart the
//! locator starts from the stored best tip.
//!
//! Bitcoin blocks a share needs and the local Bitcoin node does not have (stale branches) are
//! fetched from peers' archives (`GetBtcBlocks`, [`crate::archive`]).
//!
//! ## Checkpoints
//!
//! Every [`RelayParams::checkpoint_interval`](crate::relay::RelayParams::checkpoint_interval) Bitcoin
//! blocks the relay folds a [`Checkpoint`](crate::checkpoint::Checkpoint) at the last best-chain anchor [`RelayParams::checkpoint_depth`](crate::relay::RelayParams::checkpoint_depth) blocks below its
//! tip, stores it with its digest, and drops from memory the batches and credits it folded. The
//! two newest are kept. On start the relay replays from the older one that verifies (digest,
//! genesis, and an anchor stored with the same height, `btc_height` and work), recomputes the
//! newer one from the stored batches between them and compares: a corrupt or mismatching
//! checkpoint is logged and rewritten. With neither, it replays from genesis; batches missing from
//! the store are fetched from peers.
//!
//! A checkpoint at depth `D` assumes no share-chain reorg forks below it (an anchor forking below
//! the checkpoint is held but never judged) and no Bitcoin reorg deeper than about `D - 32`
//! blocks.
//!
//! ## Retention and pruning
//!
//! Kept forever: every anchor header and its own share, the Bitcoin archive, the ledger and its
//! journals, and the two newest checkpoints. With [`RelayParams::prune`](crate::relay::RelayParams::prune) on, batches (membership
//! and share bodies) of anchors below the older kept checkpoint are deleted. Such a node still
//! serves every batch above that checkpoint, so it can feed any peer within its window and every
//! reorg it can follow; a peer that needs older batches gets `NotFound` and asks another peer. A
//! fresh node needs at least one archive peer (`prune` off) for batches older than its peers'
//! windows.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use bitcoin::consensus::{deserialize, serialize};
use tracing::{debug, info, warn};

use ghost_common::anchor_chain::AnchorHash;
use ghost_common::canonical_payout::table_for_from;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::node_pool_constants::SNAPSHOT_CUT_LAG;
use ghost_storage::node_pool_store::NpCheckpoint;

use super::{PeerId, Relay, TableErr};
use crate::archive::{ArchiveError, ArchivedBlock};
use crate::checkpoint::{digest, Checkpoint};
use crate::headers::HeaderLookup;
use crate::peers::penalty;
use crate::relay::Out;
use crate::wire::{
    AnchorMsg, BtcBlockMsg, Message, NotFoundKind, MAX_BTC_BLOCKS_PER_MESSAGE,
    MAX_HEADERS_PER_MESSAGE, MAX_LOCATOR,
};

/// Default [`RelayParams::checkpoint_depth`](super::RelayParams::checkpoint_depth): two days.
pub const DEFAULT_CHECKPOINT_DEPTH: u32 = 288;
/// Default [`RelayParams::checkpoint_interval`](super::RelayParams::checkpoint_interval): a day.
pub const DEFAULT_CHECKPOINT_INTERVAL: u32 = 144;
/// The shallowest checkpoint: below every snapshot a live share can need (`cut` lag 20 plus the
/// 12-block share window) with margin.
pub const MIN_CHECKPOINT_DEPTH: u32 = 40;
/// Checkpoints kept in the store.
pub const CHECKPOINTS_KEPT: usize = 2;

/// Sync bookkeeping.
#[derive(Default)]
pub struct SyncState {
    /// Peers with a `GetHeaders` outstanding, and since when.
    pub(crate) headers_asked: HashMap<PeerId, u64>,
    /// When each peer was last asked for headers.
    headers_last: HashMap<PeerId, u64>,
    /// The last anchor of the last full `Headers` reply: the next locator starts there.
    sync_tip: Option<AnchorHash>,
    /// Anchors whose batch is still to be requested, and from whom.
    queue: VecDeque<(AnchorHash, PeerId)>,
    /// Anchors whose batch was requested and has not completed.
    pub(crate) inflight: HashSet<AnchorHash>,
    /// Bitcoin blocks wanted from peers: since when, and who was asked.
    btc_wanted: HashMap<[u8; 32], (u64, Vec<PeerId>)>,
    /// Peers not to sync from until a time: they sent data that did not check.
    avoid: HashMap<PeerId, u64>,
}

impl SyncState {
    pub(crate) fn forget(&mut self, peer: PeerId) {
        self.headers_last.remove(&peer);
        self.avoid.remove(&peer);
    }
}

impl Relay {
    // ---------------------------------------------------------------------------------------
    // Headers
    // ---------------------------------------------------------------------------------------

    /// Ask `peer` for anchor headers after this node's chain, unless a header request is
    /// outstanding or `peer` was asked within the request timeout.
    pub(crate) fn request_headers(&mut self, peer: PeerId) {
        let now = self.now;
        let timeout = self.p.request_timeout_secs;
        let recent = |t: &u64| now.saturating_sub(*t) < timeout;
        if self.sync.headers_asked.values().any(recent)
            || self.sync.headers_last.get(&peer).is_some_and(recent)
        {
            return;
        }
        self.send_get_headers(peer);
    }

    fn send_get_headers(&mut self, peer: PeerId) {
        let now = self.now;
        if self.sync.avoid.get(&peer).is_some_and(|t| *t > now) {
            return;
        }
        let loc = self.locator();
        self.sync.headers_asked.insert(peer, now);
        self.sync.headers_last.insert(peer, now);
        self.out.push(Out::Send(peer, Message::GetHeaders(loc)));
    }

    /// Hashes of this node's chain, newest first: ten in a row, then at doubling steps, then
    /// genesis. Starts from the last full `Headers` reply's tip when it is ahead of the best.
    fn locator(&self) -> Vec<AnchorHash> {
        let best = self.chain.best();
        let bw = self.chain.get(&best).expect("best").work;
        let start = self
            .sync
            .sync_tip
            .filter(|t| self.chain.get(t).is_some_and(|i| i.work > bw))
            .unwrap_or(best);
        let mut v = Vec::new();
        let mut cur = start;
        let mut step = 1u32;
        loop {
            if cur == self.p.genesis.hash || v.len() + 1 >= MAX_LOCATOR {
                break;
            }
            v.push(cur);
            if v.len() >= 10 {
                step = step.saturating_mul(2);
            }
            for _ in 0..step {
                match self.chain.get(&cur).and_then(|i| i.parent) {
                    Some(p) => cur = p,
                    None => break,
                }
            }
        }
        v.push(self.p.genesis.hash);
        v
    }

    pub(super) fn serve_headers(&mut self, peer: PeerId, loc: &[AnchorHash]) {
        let start = loc
            .iter()
            .find(|h| **h == self.p.genesis.hash || self.on_path(h))
            .and_then(|h| self.chain.get(h))
            .map_or(0, |i| i.height as usize);
        let v: Vec<AnchorMsg> = self
            .path
            .iter()
            .skip(start)
            .take(MAX_HEADERS_PER_MESSAGE)
            .filter_map(|a| {
                self.anchors.get(a).map(|e| AnchorMsg {
                    btc_height: e.btc_height,
                    share: (*e.share).clone(),
                })
            })
            .collect();
        self.out.push(Out::Send(peer, Message::Headers(v)));
    }

    pub(super) fn on_headers(&mut self, peer: PeerId, v: Vec<AnchorMsg>, hdr: &dyn HeaderLookup) {
        self.sync.headers_asked.remove(&peer);
        let full = v.len() == MAX_HEADERS_PER_MESSAGE;
        let mut prev: Option<AnchorHash> = None;
        let mut last = None;
        for m in v {
            let h = m.share.id();
            let parent = m.share.tag.parent_anchor;
            if self.chain.get(&parent).is_none() && prev != Some(parent) {
                self.penalize(
                    Some(peer),
                    penalty::UNCONNECTED_HEADERS,
                    "headers that do not connect".into(),
                );
                self.avoid(peer);
                return;
            }
            let had = self.anchors.contains_key(&h);
            self.on_anchor(Some(peer), m, hdr);
            if !self.anchors.contains_key(&h) {
                // Refused (and penalized) by the anchor checks.
                self.avoid(peer);
                return;
            }
            if !had && !self.batch_ids.contains_key(&h) && !self.credits.contains_key(&h) {
                self.sync.queue.push_back((h, peer));
            }
            prev = Some(h);
            last = Some(h);
        }
        if full {
            self.sync.sync_tip = last;
            self.send_get_headers(peer);
        }
        self.drive_sync();
    }

    fn avoid(&mut self, peer: PeerId) {
        let until = self.now + 10 * self.p.request_timeout_secs.max(1);
        self.sync.avoid.insert(peer, until);
    }

    /// Ask the heaviest peer for headers when behind, and keep the batch requests topped up.
    pub(super) fn drive_sync(&mut self) {
        let now = self.now;
        self.sync.avoid.retain(|_, t| *t > now);
        let ours = self.chain.get(&self.chain.best()).expect("best").work;
        let heaviest = self
            .tip_peers
            .iter()
            .filter(|(p, (h, w))| {
                *w > ours && !self.credits.contains_key(h) && !self.sync.avoid.contains_key(p)
            })
            .max_by_key(|(p, (_, w))| (*w, std::cmp::Reverse(**p)))
            .map(|(p, _)| *p);
        if let Some(p) = heaviest {
            self.request_headers(p);
        }
        self.sync.inflight.retain(|a| self.awaiting.contains_key(a));
        while self.sync.inflight.len() < self.p.sync_inflight.max(1) {
            let Some((a, from)) = self.sync.queue.pop_front() else {
                break;
            };
            if !self.awaiting.contains_key(&a) || self.batch_ids.contains_key(&a) {
                continue;
            }
            let peer = if self.peers.contains(&from) {
                from
            } else if let Some(p) = self.peers.first() {
                *p
            } else {
                break;
            };
            if let Some(aw) = self.awaiting.get_mut(&a) {
                aw.since = now;
                aw.asked = vec![peer];
            }
            self.sync.inflight.insert(a);
            self.out.push(Out::Send(peer, Message::GetBatch(a)));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Bitcoin blocks
    // ---------------------------------------------------------------------------------------

    /// Ask peers for Bitcoin blocks the local Bitcoin node could not supply.
    pub fn request_btc_blocks(&mut self, hashes: &[[u8; 32]]) {
        let mut by: HashMap<PeerId, Vec<[u8; 32]>> = HashMap::new();
        for h in hashes {
            if self.archive.has_full(h) || self.sync.btc_wanted.contains_key(h) {
                continue;
            }
            let Some(p) = self.btc_peer(&[]) else {
                return;
            };
            self.sync.btc_wanted.insert(*h, (self.now, vec![p]));
            by.entry(p).or_default().push(*h);
        }
        self.send_btc_requests(by);
    }

    fn btc_peer(&self, asked: &[PeerId]) -> Option<PeerId> {
        let now = self.now;
        self.peers
            .iter()
            .copied()
            .filter(|p| !self.sync.avoid.get(p).is_some_and(|t| *t > now))
            .find(|p| !asked.contains(p))
    }

    fn send_btc_requests(&mut self, by: HashMap<PeerId, Vec<[u8; 32]>>) {
        for (p, v) in by {
            for c in v.chunks(MAX_BTC_BLOCKS_PER_MESSAGE) {
                self.out
                    .push(Out::Send(p, Message::GetBtcBlocks(c.to_vec())));
            }
        }
    }

    pub(super) fn retry_btc_requests(&mut self) {
        let now = self.now;
        let timeout = self.p.request_timeout_secs;
        let due: Vec<[u8; 32]> = self
            .sync
            .btc_wanted
            .iter()
            .filter(|(_, (t, _))| now.saturating_sub(*t) >= timeout)
            .map(|(h, _)| *h)
            .collect();
        let mut by: HashMap<PeerId, Vec<[u8; 32]>> = HashMap::new();
        for h in due {
            if self.archive.has_full(&h) {
                self.sync.btc_wanted.remove(&h);
                continue;
            }
            let asked = self.sync.btc_wanted[&h].1.clone();
            let p = match self.btc_peer(&asked) {
                Some(p) => p,
                None => match self.btc_peer(&[]) {
                    Some(p) => {
                        self.sync.btc_wanted.get_mut(&h).expect("listed").1.clear();
                        p
                    }
                    None => continue,
                },
            };
            let w = self.sync.btc_wanted.get_mut(&h).expect("listed");
            w.0 = now;
            w.1.push(p);
            by.entry(p).or_default().push(h);
        }
        self.send_btc_requests(by);
    }

    pub(super) fn btc_not_found(&mut self, _peer: PeerId, h: [u8; 32]) {
        if let Some(w) = self.sync.btc_wanted.get_mut(&h) {
            w.0 = 0;
        }
    }

    pub(super) fn serve_btc_blocks(&mut self, peer: PeerId, hashes: &[[u8; 32]]) {
        let mut found = Vec::new();
        for h in hashes.iter().take(MAX_BTC_BLOCKS_PER_MESSAGE) {
            match self.archive.get(h) {
                Some(b) if b.coinbase.is_some() => {
                    let (cb, br) = b.coinbase.as_ref().expect("checked");
                    found.push(BtcBlockMsg {
                        header: b.header,
                        height: b.height,
                        coinbase: serialize(cb),
                        branch: br.clone(),
                    });
                }
                _ => self.out.push(Out::Send(
                    peer,
                    Message::NotFound(NotFoundKind::BtcBlock, *h),
                )),
            }
        }
        if !found.is_empty() {
            self.out.push(Out::Send(peer, Message::BtcBlocks(found)));
        }
    }

    pub(super) fn on_btc_blocks(
        &mut self,
        peer: PeerId,
        v: Vec<BtcBlockMsg>,
        hdr: &dyn HeaderLookup,
    ) {
        let mut got = false;
        for m in v {
            let h = m.header.block_hash();
            let h: [u8; 32] = bitcoin::hashes::Hash::to_byte_array(h);
            if !self.sync.btc_wanted.contains_key(&h) {
                continue;
            }
            let Ok(tx) = deserialize(&m.coinbase) else {
                self.penalize(
                    Some(peer),
                    penalty::INVALID_BTC_BLOCK,
                    "archived block: coinbase does not decode".into(),
                );
                continue;
            };
            let b = ArchivedBlock {
                header: m.header,
                height: m.height,
                coinbase: Some((tx, m.branch)),
            };
            match self.archive.insert_from_peer(b, self.now as i64) {
                Ok(new) => {
                    self.sync.btc_wanted.remove(&h);
                    for x in new {
                        self.sync.btc_wanted.remove(&x);
                    }
                    got = true;
                }
                Err(ArchiveError::Unlinked(parent)) => {
                    // Kept waiting in the archive; its parent comes from the same peer.
                    self.sync.btc_wanted.remove(&h);
                    if !self.archive.has_full(&parent)
                        && !self.sync.btc_wanted.contains_key(&parent)
                    {
                        self.sync.btc_wanted.insert(parent, (self.now, vec![peer]));
                        self.out
                            .push(Out::Send(peer, Message::GetBtcBlocks(vec![parent])));
                    }
                }
                Err(ArchiveError::Invalid(e)) => {
                    self.penalize(
                        Some(peer),
                        penalty::INVALID_BTC_BLOCK,
                        format!("archived block: {e}"),
                    );
                    self.avoid(peer);
                    if let Some(w) = self.sync.btc_wanted.get_mut(&h) {
                        w.0 = 0;
                    }
                }
                Err(ArchiveError::Unverifiable(e)) => {
                    debug!(
                        "NP_RELAY: archived block {} not checkable here: {e}",
                        hex::encode(h)
                    );
                    self.sync.btc_wanted.remove(&h);
                }
                Err(ArchiveError::Store(e)) => {
                    warn!("NP_RELAY: archiving a block failed: {e}");
                }
            }
        }
        if got {
            self.retry_waiting(hdr);
        }
    }

    /// Anchors whose batch is held but whose checks waited: try again.
    pub(crate) fn retry_waiting(&mut self, hdr: &dyn HeaderLookup) {
        let ready: Vec<AnchorHash> = self
            .awaiting
            .keys()
            .filter(|a| self.batch_ids.contains_key(*a))
            .copied()
            .collect();
        for a in ready {
            self.complete_from(a, hdr);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Checkpoints
    // ---------------------------------------------------------------------------------------

    /// The stored checkpoints: the oldest that verifies on its own (to replay from), and every
    /// newer row (to verify against the chain once replayed, or rebuild).
    pub(super) fn load_checkpoints(
        &mut self,
    ) -> GhostResult<(Option<Checkpoint>, Vec<NpCheckpoint>)> {
        let rows = self.db.np_load_checkpoints()?;
        let mut valid: Vec<(Checkpoint, NpCheckpoint)> = Vec::new();
        let mut rest = Vec::new();
        for r in rows {
            match self.check_stored(&r) {
                Ok(cp) => valid.push((cp, r)),
                Err(e) => {
                    warn!(
                        anchor = %hex::encode(r.anchor_hash),
                        "NP_RELAY: stored checkpoint is corrupt ({e}); it will be rebuilt"
                    );
                    rest.push(r);
                }
            }
        }
        let base = valid.pop();
        rest.extend(valid.into_iter().map(|(_, r)| r));
        rest.sort_by_key(|r| r.height);
        Ok((base.map(|(cp, _)| cp), rest))
    }

    fn check_stored(&self, r: &NpCheckpoint) -> Result<Checkpoint, String> {
        if digest(&r.payload) != r.digest {
            return Err("digest mismatch".into());
        }
        let cp = Checkpoint::decode(&r.payload).map_err(|e| e.to_string())?;
        if cp.genesis != self.p.genesis.hash || cp.anchor != r.anchor_hash {
            return Err("not this chain's".into());
        }
        let a = self
            .db
            .np_get_anchor(&cp.anchor)
            .map_err(|e| e.to_string())?
            .ok_or("its anchor is not stored")?;
        if (a.height, a.btc_height, a.cum_work) != (cp.height, cp.btc_height, cp.work)
            || cp.fold_height != cp.btc_height + 1
        {
            return Err("does not match its stored anchor".into());
        }
        Ok(cp)
    }

    /// Recompute every newer checkpoint from the replayed chain: keep one that matches, rewrite
    /// one that does not, and adopt the newest as the base.
    pub(super) fn verify_newer_checkpoints(&mut self, rows: Vec<NpCheckpoint>) -> GhostResult<()> {
        for r in rows {
            let a = r.anchor_hash;
            if !self.on_path(&a)
                || !self.chain.is_ancestor(&self.base.anchor, &a)
                || a == self.base.anchor
            {
                if a != self.base.anchor {
                    self.db.np_delete_checkpoint(&a)?;
                }
                continue;
            }
            let Some(cp) = self.make_checkpoint(a)? else {
                warn!(anchor = %hex::encode(a), "NP_RELAY: checkpoint cannot be recomputed yet");
                continue;
            };
            let payload = cp.encode();
            if payload == r.payload && digest(&payload) == r.digest {
                info!(anchor = %hex::encode(a), "NP_RELAY: checkpoint verified against the chain");
            } else {
                warn!(anchor = %hex::encode(a), "NP_RELAY: checkpoint did not verify; rebuilt");
                self.write_checkpoint(&cp)?;
            }
            self.adopt_base(cp);
        }
        Ok(())
    }

    /// Fold a new checkpoint if the target anchor has moved far enough.
    pub(super) fn maybe_checkpoint(&mut self, _hdr: &dyn HeaderLookup) -> GhostResult<()> {
        let depth = match self.p.checkpoint_depth {
            0 => return Ok(()),
            d => d.max(MIN_CHECKPOINT_DEPTH),
        };
        let best = self.chain.best();
        let bi = self.chain.get(&best).expect("best");
        let Some(target) = bi.btc_height.checked_sub(depth) else {
            return Ok(());
        };
        let Some(c) = self.chain.last_below(&best, target + 1) else {
            return Ok(());
        };
        if c == self.p.genesis.hash
            || c == self.base.anchor
            || !self.chain.is_ancestor(&self.base.anchor, &c)
        {
            return Ok(());
        }
        let cb = self.chain.get(&c).expect("held").btc_height;
        if self.base.anchor != self.p.genesis.hash
            && cb < self.base.btc_height + self.p.checkpoint_interval
        {
            return Ok(());
        }
        let Some(cp) = self.make_checkpoint(c)? else {
            return Ok(());
        };
        self.write_checkpoint(&cp)?;
        info!(
            anchor = %hex::encode(c),
            btc_height = cb,
            rows = cp.base.len(),
            "NP_RELAY: checkpoint folded"
        );
        self.adopt_base(cp);
        Ok(())
    }

    /// The checkpoint at best-chain anchor `c`, which descends from the current base. `None`
    /// while a Bitcoin block it needs is not archived (it is wanted).
    pub(crate) fn make_checkpoint(&mut self, c: AnchorHash) -> GhostResult<Option<Checkpoint>> {
        let info = self.chain.get(&c).expect("held").clone();
        let f = info.btc_height + 1;
        let prev = self.anchors[&c].share.prev_hash();
        // Pool blocks just above the fold whose tables reach below `c`: decide them now.
        for b in self.archive.blocks_between(f, f + SNAPSHOT_CUT_LAG) {
            let Some((prefix, _)) = b.pool_tag() else {
                continue;
            };
            for a in self.anchors_with_prefix(&prefix) {
                if self.is_complete(&a) {
                    let _ = self.check_block(&b, &a);
                }
            }
        }
        let view = match self.retirements_for(&c, &prev, f) {
            Ok(v) => v,
            Err(TableErr::Wait(x)) => {
                self.needed_headers.insert(x);
                return Ok(None);
            }
            Err(TableErr::Unavailable) => return Ok(None),
            Err(TableErr::Arith(e)) => return Err(GhostError::PayoutCalculation(e)),
        };
        let cum = self.cum_credits(c);
        let base = table_for_from(self.base.base.clone(), f, &cum, &view.0)
            .map_err(|e| GhostError::PayoutCalculation(e.to_string()))?;
        let residual = cum
            .iter()
            .filter(|(h, _)| **h + SNAPSHOT_CUT_LAG > f)
            .map(|(h, m)| (*h, m.clone()))
            .collect();
        let mut checks: Vec<_> = self
            .block_checks
            .iter()
            .filter(|((b, _), _)| {
                self.archive
                    .get(b)
                    .is_some_and(|x| x.height >= f && x.height <= f + SNAPSHOT_CUT_LAG)
            })
            .map(|((b, a), r)| (*b, *a, r.clone()))
            .collect();
        checks.sort();
        Ok(Some(Checkpoint {
            genesis: self.p.genesis.hash,
            anchor: c,
            height: info.height,
            btc_height: info.btc_height,
            work: info.work,
            fold_height: f,
            base,
            residual,
            checks,
        }))
    }

    /// Store `cp`, keep the newest [`CHECKPOINTS_KEPT`], and prune batches below the older kept
    /// one when pruning is on.
    fn write_checkpoint(&mut self, cp: &Checkpoint) -> GhostResult<()> {
        let payload = cp.encode();
        self.db.np_put_checkpoint(&NpCheckpoint {
            anchor_hash: cp.anchor,
            height: cp.height,
            btc_height: cp.btc_height,
            digest: digest(&payload),
            payload,
            created_at: self.now as i64,
        })?;
        let rows = self.db.np_load_checkpoints()?;
        for r in rows.iter().skip(CHECKPOINTS_KEPT) {
            self.db.np_delete_checkpoint(&r.anchor_hash)?;
        }
        if self.p.prune && rows.len() >= CHECKPOINTS_KEPT {
            let older = &rows[CHECKPOINTS_KEPT - 1];
            let rep = self.db.np_prune_batches_below(older.btc_height)?;
            if rep.batches > 0 {
                info!(
                    below = older.btc_height,
                    batches = rep.batches,
                    shares = rep.shares,
                    "NP_RELAY: pruned batches below the older checkpoint"
                );
            }
        }
        Ok(())
    }

    /// Make `cp` the base: every table folds onto it, and the batches and credits it folded
    /// leave memory.
    pub(super) fn adopt_base(&mut self, cp: Checkpoint) {
        for (b, a, r) in &cp.checks {
            self.block_checks.insert((*b, *a), r.clone());
        }
        self.base = Arc::new(cp);
        self.cum_cache.clear();
        self.cum_order.clear();
        self.table_cache.clear();
        self.table_order.clear();
        self.retire_cache.clear();
        self.retire_order.clear();
        let base = self.base.anchor;
        let gone: Vec<AnchorHash> = self
            .credits
            .keys()
            .filter(|x| **x == base || !self.chain.is_ancestor(&base, x))
            .copied()
            .collect();
        for x in &gone {
            self.credits.remove(x);
            self.batch_ids.remove(x);
            self.batch_source.remove(x);
        }
        if !gone.is_empty() {
            let keep: HashSet<[u8; 32]> = self
                .batch_ids
                .values()
                .flat_map(|v| v.iter().copied())
                .chain(self.loose.keys().copied())
                .chain(self.anchors.keys().copied())
                .chain(self.wanted.keys().copied())
                .collect();
            self.shares.retain(|k, _| keep.contains(k));
        }
        let fold = self.base.fold_height;
        let archive = self.archive.clone();
        self.block_checks.retain(|(b, _), _| {
            archive
                .get(b)
                .is_none_or(|x| x.height + SNAPSHOT_CUT_LAG >= fold)
        });
    }
}
