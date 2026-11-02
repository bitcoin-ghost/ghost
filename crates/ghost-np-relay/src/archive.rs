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
//| FILE: archive.rs                                                                                                     |
//|======================================================================================================================|

//! The Bitcoin block archive (W2.13, spec 2.2 correction 7).
//!
//! Every Bitcoin block the node pool meets above its genesis is kept here, on every branch: its
//! header and its coinbase with the merkle branch that binds the coinbase to the header. Stale
//! blocks stay. Bitcoin peers do not serve stale blocks, yet shares are built on them and pool
//! blocks are found on them, so a node that never saw a branch fetches it from node pool peers.
//!
//! The archive serves three things:
//!
//! - **Header facts** ([`HeaderLookup`](crate::headers::HeaderLookup)) for any archived header: its height, the bits a child
//!   must carry, and its median time past, computed from the archived headers alone.
//! - **Settlement's input**: the node pool blocks on a share's Bitcoin ancestry
//!   ([`BtcArchive::pool_blocks_on`](crate::archive::BtcArchive::pool_blocks_on)). The retirement rule is in [`crate::relay`]; it reads the
//!   ancestry of the share's own `prev_hash`, never this node's best chain, so every viewer with
//!   the same archive reaches the same table.
//! - **Sync**: peers ask for blocks by hash (`GetBtcBlocks`); a block from a peer is checked
//!   before it is kept
//!   ([`BtcArchive::insert_from_peer`](crate::archive::BtcArchive::insert_from_peer)): it extends an archived parent at the
//!   next height, its hash meets its own bits, its bits are its parent's (a retarget boundary
//!   off this node's best chain cannot be checked and is refused without penalty), and its
//!   coinbase folds to its merkle root and carries its BIP34 height. A block whose parent is
//!   missing waits in a bounded pool while the parent is fetched.
//!
//! Blocks from the local Bitcoin node
//! ([`BtcArchive::insert_local`](crate::archive::BtcArchive::insert_local)) are trusted for work,
//! and define this node's best chain
//! ([`BtcArchive::set_main`](crate::archive::BtcArchive::set_main)), which only jobs and settlement's
//! materialised ledger read.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction;

use ghost_common::canonical_payout::ledger_root_of;
use ghost_common::coinbase_tags::{extract_payout_tag, PAYOUT_ID_LEN};
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::share_commit::fold_coinbase_branch;
use ghost_storage::node_pool_store::NpBtcBlock;
use ghost_storage::Database;

use crate::headers::{HeaderFacts, HeaderLookup};

/// Headers in a median time past: the block and its ten ancestors.
pub const MTP_SPAN: u32 = 11;
/// Blocks per difficulty period.
const RETARGET_INTERVAL: u32 = 2_016;
/// Peer blocks kept while their parent is fetched.
pub const MAX_PENDING_BLOCKS: usize = 256;

/// A Bitcoin block as the archive keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedBlock {
    /// The header.
    pub header: Header,
    /// Its height.
    pub height: u32,
    /// The coinbase (non-witness) and the merkle branch from its txid to the header's merkle
    /// root. Absent only for the headers below the archive floor kept for median time past.
    pub coinbase: Option<(Transaction, Vec<[u8; 32]>)>,
}

impl ArchivedBlock {
    /// The block hash, internal byte order.
    pub fn hash(&self) -> [u8; 32] {
        self.header.block_hash().to_byte_array()
    }

    /// The parent's hash, internal byte order.
    pub fn prev(&self) -> [u8; 32] {
        self.header.prev_blockhash.to_byte_array()
    }

    /// The `GHPP` anchor prefix and the `GHNP` table root, if the coinbase is laid out as a node
    /// pool block.
    pub fn pool_tag(&self) -> Option<([u8; PAYOUT_ID_LEN], [u8; 32])> {
        let (cb, _) = self.coinbase.as_ref()?;
        let sig = cb.input.first()?.script_sig.as_bytes();
        let tag = extract_payout_tag(sig)?;
        let outs: Vec<(u64, Vec<u8>)> = cb
            .output
            .iter()
            .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
            .collect();
        Some((tag, ledger_root_of(&outs)?))
    }

    fn to_record(&self, now: i64) -> NpBtcBlock {
        let mut header = [0u8; 80];
        header.copy_from_slice(&serialize(&self.header));
        NpBtcBlock {
            hash: self.hash(),
            height: self.height,
            header,
            coinbase: self
                .coinbase
                .as_ref()
                .map(|(tx, br)| (serialize(tx), br.clone())),
            received_at: now,
        }
    }

    fn from_record(r: &NpBtcBlock) -> GhostResult<ArchivedBlock> {
        let header: Header = deserialize(&r.header)
            .map_err(|e| GhostError::Database(format!("archived header: {e}")))?;
        let coinbase = match &r.coinbase {
            Some((c, br)) => Some((
                deserialize(c)
                    .map_err(|e| GhostError::Database(format!("archived coinbase: {e}")))?,
                br.clone(),
            )),
            None => None,
        };
        Ok(ArchivedBlock {
            header,
            height: r.height,
            coinbase,
        })
    }
}

/// Why a block was not archived.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArchiveError {
    /// Its parent is not archived yet. Not a fault: the block waits and the parent is wanted.
    #[error("parent {} not archived", hex::encode(.0))]
    Unlinked([u8; 32]),
    /// It cannot be checked here (a retarget boundary off this node's best chain). Not a fault.
    #[error("unverifiable: {0}")]
    Unverifiable(String),
    /// It is not a valid Bitcoin block of this chain: the sender's fault.
    #[error("invalid: {0}")]
    Invalid(String),
    /// The store failed.
    #[error("store: {0}")]
    Store(String),
}

#[derive(Default)]
struct Inner {
    blocks: HashMap<[u8; 32], Arc<ArchivedBlock>>,
    main: BTreeMap<u32, [u8; 32]>,
    pending: HashMap<[u8; 32], Vec<ArchivedBlock>>,
    pending_count: usize,
    version: u64,
}

/// The archive. Cheap to share: every holder sees the same blocks.
pub struct BtcArchive {
    db: Option<Arc<Database>>,
    check_pow: AtomicBool,
    inner: Mutex<Inner>,
}

impl BtcArchive {
    /// An archive over `db`, loaded from it.
    pub fn open(db: Arc<Database>) -> GhostResult<Arc<BtcArchive>> {
        let mut inner = Inner::default();
        for r in db.np_load_btc_blocks()? {
            let b = ArchivedBlock::from_record(&r)?;
            inner.blocks.insert(r.hash, Arc::new(b));
        }
        Ok(Arc::new(BtcArchive {
            db: Some(db),
            check_pow: AtomicBool::new(true),
            inner: Mutex::new(inner),
        }))
    }

    /// An archive that is not persisted.
    pub fn in_memory() -> Arc<BtcArchive> {
        Arc::new(BtcArchive {
            db: None,
            check_pow: AtomicBool::new(true),
            inner: Mutex::new(Inner::default()),
        })
    }

    /// Tests build fake Bitcoin chains whose headers carry mainnet bits without the work.
    #[cfg(test)]
    pub(crate) fn trust_work_for_tests(&self) {
        self.check_pow.store(false, Ordering::Relaxed);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Bumped whenever a block is archived or the best chain moves.
    pub fn version(&self) -> u64 {
        self.lock().version
    }

    /// Archived blocks.
    pub fn len(&self) -> usize {
        self.lock().blocks.len()
    }

    /// Whether nothing is archived.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A block, if archived.
    pub fn get(&self, hash: &[u8; 32]) -> Option<Arc<ArchivedBlock>> {
        self.lock().blocks.get(hash).cloned()
    }

    /// Whether `hash` is archived with its coinbase.
    pub fn has_full(&self, hash: &[u8; 32]) -> bool {
        self.lock()
            .blocks
            .get(hash)
            .is_some_and(|b| b.coinbase.is_some())
    }

    /// This node's best-chain block at `h`, as the local Bitcoin node last reported it.
    pub fn main_at(&self, h: u32) -> Option<[u8; 32]> {
        self.lock().main.get(&h).copied()
    }

    /// Record the local best chain's block at `h`, dropping any recorded above it (a reorg
    /// replaces them as it is followed). The block itself stays archived on any branch.
    pub fn set_main(&self, h: u32, hash: [u8; 32]) {
        let mut g = self.lock();
        if g.main.get(&h) == Some(&hash) {
            return;
        }
        let _above = g.main.split_off(&h);
        g.main.insert(h, hash);
        g.version += 1;
    }

    /// Forget the local best chain above `h`.
    pub fn truncate_main(&self, h: u32) {
        let mut g = self.lock();
        if g.main.range(h + 1..).next().is_some() {
            let _above = g.main.split_off(&(h + 1));
            g.version += 1;
        }
    }

    /// Archive a block from the local Bitcoin node: trusted for work. Its height must agree
    /// with an archived parent.
    pub fn insert_local(&self, b: ArchivedBlock, now: i64) -> Result<bool, ArchiveError> {
        if let Some(p) = self.get(&b.prev()) {
            if p.height + 1 != b.height {
                return Err(ArchiveError::Invalid(format!(
                    "height {} on a parent at {}",
                    b.height, p.height
                )));
            }
        }
        if let Some((cb, br)) = &b.coinbase {
            check_coinbase(&b.header, b.height, cb, br)?;
        }
        let (added, _) = self.store(b, now)?;
        Ok(added)
    }

    /// Archive a block from a peer, after checking it (see the module docs). Returns the hashes
    /// newly archived: the block and any waiting descendants it linked.
    pub fn insert_from_peer(
        &self,
        b: ArchivedBlock,
        now: i64,
    ) -> Result<Vec<[u8; 32]>, ArchiveError> {
        let hash = b.hash();
        if self.has_full(&hash) {
            return Ok(Vec::new());
        }
        let Some(parent) = self.get(&b.prev()) else {
            let prev = b.prev();
            let mut g = self.lock();
            if g.pending_count < MAX_PENDING_BLOCKS {
                let list = g.pending.entry(prev).or_default();
                if !list.iter().any(|x| x.hash() == hash) {
                    list.push(b);
                    g.pending_count += 1;
                }
            }
            return Err(ArchiveError::Unlinked(prev));
        };
        self.check_peer_block(&parent, &b)?;
        let mut out = Vec::new();
        let mut queue = vec![b];
        while let Some(x) = queue.pop() {
            let h = x.hash();
            let (added, kids) = self.store(x, now)?;
            if added {
                out.push(h);
            }
            for k in kids {
                let p = self.get(&k.prev()).expect("just stored");
                // A waiting child is checked like any peer block; a bad one is dropped.
                if self.check_peer_block(&p, &k).is_ok() {
                    queue.push(k);
                }
            }
        }
        Ok(out)
    }

    fn check_peer_block(
        &self,
        parent: &ArchivedBlock,
        b: &ArchivedBlock,
    ) -> Result<(), ArchiveError> {
        if b.height != parent.height + 1 {
            return Err(ArchiveError::Invalid(format!(
                "height {} on a parent at {}",
                b.height, parent.height
            )));
        }
        if self.check_pow.load(Ordering::Relaxed)
            && b.header.validate_pow(b.header.target()).is_err()
        {
            return Err(ArchiveError::Invalid("hash does not meet its bits".into()));
        }
        if b.height % RETARGET_INTERVAL != 0 {
            if b.header.bits != parent.header.bits {
                return Err(ArchiveError::Invalid(
                    "bits differ from the parent's inside a difficulty period".into(),
                ));
            }
        } else if self.main_at(b.height) != Some(b.hash()) {
            return Err(ArchiveError::Unverifiable(
                "a retarget block off this node's best chain".into(),
            ));
        }
        let Some((cb, br)) = &b.coinbase else {
            return Err(ArchiveError::Invalid("no coinbase".into()));
        };
        check_coinbase(&b.header, b.height, cb, br)
    }

    /// Insert and persist; returns whether anything changed and the waiting children released.
    fn store(
        &self,
        b: ArchivedBlock,
        now: i64,
    ) -> Result<(bool, Vec<ArchivedBlock>), ArchiveError> {
        let hash = b.hash();
        {
            let g = self.lock();
            if let Some(held) = g.blocks.get(&hash) {
                if held.coinbase.is_some() || b.coinbase.is_none() {
                    return Ok((false, Vec::new()));
                }
            }
        }
        if let Some(db) = &self.db {
            db.np_put_btc_block(&b.to_record(now))
                .map_err(|e| ArchiveError::Store(e.to_string()))?;
        }
        let mut g = self.lock();
        g.blocks.insert(hash, Arc::new(b));
        g.version += 1;
        let kids = g.pending.remove(&hash).unwrap_or_default();
        g.pending_count -= kids.len();
        Ok((true, kids))
    }

    /// Every archived block with its coinbase at height `from..=to`.
    pub fn blocks_between(&self, from: u32, to: u32) -> Vec<Arc<ArchivedBlock>> {
        let mut v: Vec<Arc<ArchivedBlock>> = self
            .lock()
            .blocks
            .values()
            .filter(|b| b.height >= from && b.height <= to && b.coinbase.is_some())
            .cloned()
            .collect();
        v.sort_by_key(|b| (b.height, b.hash()));
        v
    }

    /// Header facts from the archive alone. `next_bits` across a retarget boundary is read from
    /// this node's best-chain child, so a stale boundary header has no facts here.
    pub fn facts(&self, hash: &[u8; 32]) -> Option<HeaderFacts> {
        let g = self.lock();
        let b = g.blocks.get(hash)?;
        let next_bits = if (b.height + 1) % RETARGET_INTERVAL != 0 {
            b.header.bits
        } else {
            let c = g.blocks.get(g.main.get(&(b.height + 1))?)?;
            if c.prev() != *hash {
                return None;
            }
            c.header.bits
        };
        let mut times = Vec::with_capacity(MTP_SPAN as usize);
        let mut cur = b.clone();
        loop {
            times.push(cur.header.time);
            if times.len() == MTP_SPAN as usize {
                break;
            }
            cur = g.blocks.get(&cur.prev())?.clone();
        }
        times.sort_unstable();
        Some(HeaderFacts {
            height: b.height,
            next_bits,
            median_time_past: times[times.len() / 2],
        })
    }

    /// The node pool blocks on `prev`'s ancestry (`prev` included) with height in
    /// `from..below`, lowest first. `Err(hash)`: a block on the way is not archived with its
    /// coinbase, so the answer is not known yet; fetch `hash`.
    pub fn pool_blocks_on(
        &self,
        prev: &[u8; 32],
        from: u32,
        below: u32,
    ) -> Result<Vec<Arc<ArchivedBlock>>, [u8; 32]> {
        let g = self.lock();
        let mut out = Vec::new();
        let mut cur = *prev;
        loop {
            let b = g.blocks.get(&cur).ok_or(cur)?;
            if b.height < from {
                break;
            }
            if b.height < below {
                if b.coinbase.is_none() {
                    return Err(cur);
                }
                if b.pool_tag().is_some() {
                    out.push(b.clone());
                }
            }
            if b.height == from {
                break;
            }
            cur = b.prev();
        }
        out.reverse();
        Ok(out)
    }
}

impl HeaderLookup for BtcArchive {
    fn facts(&self, hash: &[u8; 32]) -> Option<HeaderFacts> {
        BtcArchive::facts(self, hash)
    }
}

/// The coinbase is a coinbase, folds to the header's merkle root, and carries `height` (BIP34).
fn check_coinbase(
    header: &Header,
    height: u32,
    cb: &Transaction,
    branch: &[[u8; 32]],
) -> Result<(), ArchiveError> {
    if !cb.is_coinbase() || cb.input.len() != 1 {
        return Err(ArchiveError::Invalid("not a coinbase".into()));
    }
    let txid = cb.compute_txid().to_byte_array();
    if fold_coinbase_branch(txid, branch) != header.merkle_root.to_byte_array() {
        return Err(ArchiveError::Invalid(
            "coinbase does not fold to the header".into(),
        ));
    }
    let bip34 = bitcoin::script::Builder::new()
        .push_int(height as i64)
        .into_bytes();
    if !cb.input[0].script_sig.as_bytes().starts_with(&bip34) {
        return Err(ArchiveError::Invalid("BIP34 height mismatch".into()));
    }
    Ok(())
}

/// The merkle branch from the first txid of `txids` to their root, as Bitcoin builds it
/// (an odd node pairs with itself).
pub fn coinbase_branch(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut level = txids.to_vec();
    let mut idx = 0usize;
    let mut branch = Vec::new();
    while level.len() > 1 {
        let sib = if idx ^ 1 < level.len() {
            level[idx ^ 1]
        } else {
            level[idx]
        };
        branch.push(sib);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let (a, b) = (pair[0], *pair.get(1).unwrap_or(&pair[0]));
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&a);
            buf[32..].copy_from_slice(&b);
            next.push(Sha256::digest(Sha256::digest(buf)).into());
        }
        level = next;
        idx /= 2;
    }
    branch
}
