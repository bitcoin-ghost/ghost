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
//| FILE: settlement.rs                                                                                                  |
//|======================================================================================================================|

//! Settlement (W2.7, spec 2.3): retiring what pool blocks paid, at tip.
//!
//! A node pool block records which anchor its coinbase was built on: `parent_anchor[..16]` sits
//! in the `GHPP` scriptSig slot and the snapshot table's root in the `GHNP` output. When such a
//! block enters the Bitcoin best chain, [`Settlement`] finds the anchor, recomputes the table the
//! block had to pay ([`Relay::block_table`]) and retires the paid amounts through the store only
//! if the outputs are canonical for it ([`share_commit::settle_outputs`]). A block whose anchor
//! this node does not hold yet (after a partition, say) retires provisionally from its coinbase
//! alone ([`canonical_payout::provisional_retirements`]) so its miners' later shares are not
//! voided, and is checked again when the anchor arrives: kept if it matches, undone if not. A
//! block that does not match retires nothing. On a Bitcoin reorg the disconnected blocks are
//! undone.
//!
//! Settlement also feeds the [`crate::archive::BtcArchive`]: every best-chain block it reads (and
//! the 11 at genesis, for median time past) is archived with its coinbase and recorded as this
//! node's best chain. Blocks it leaves on a reorg stay archived.
//!
//! What it retires here is this node's stored ledger (`np_ledger`), which follows this node's
//! Bitcoin best chain and the anchors it holds. Share checks and snapshot tables do not read it:
//! they apply the deterministic rule in [`crate::relay`] (W2.13) to the share's own Bitcoin
//! ancestry, so two nodes on different Bitcoin tips judge every share alike once their archives
//! hold the same blocks.
//!
//! [`share_commit::settle_outputs`]: ghost_common::share_commit::settle_outputs
//! [`canonical_payout::provisional_retirements`]: ghost_common::canonical_payout::provisional_retirements

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::Transaction;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use ghost_common::anchor_chain::AnchorHash;
use ghost_common::canonical_payout::{
    ledger_root_of, provisional_retirements, table_root, CoinbaseOutput, Retirement,
};
use ghost_common::coinbase_tags::{extract_payout_tag, PAYOUT_ID_LEN};
use ghost_common::error::GhostResult;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::share_commit::settle_outputs;
use ghost_storage::Database;

use crate::archive::{coinbase_branch, ArchivedBlock, MTP_SPAN};
use crate::relay::Relay;

/// Best-chain heights remembered for reorg detection.
const RECENT_KEPT: usize = 1_024;
/// Most blocks scanned in one sync, so a long catch-up never stalls the relay task.
const MAX_SCAN_PER_SYNC: u32 = 500;

// -------------------------------------------------------------------------------------------
// The view
// -------------------------------------------------------------------------------------------

#[derive(Default)]
struct ViewInner {
    blocks: BTreeMap<u32, ([u8; 32], Vec<Retirement>)>,
    tag: [u8; 32],
}

impl ViewInner {
    fn retag(&mut self) {
        let mut s = Sha256::new();
        s.update(b"GhostNP/settled/v1");
        for (h, (hash, _)) in &self.blocks {
            s.update(h.to_le_bytes());
            s.update(hash);
        }
        self.tag = s.finalize().into();
    }
}

/// The settled pool blocks on the best chain and what each retired: settlement's own record of
/// the stored ledger. Cheap to clone; every clone sees the same blocks.
#[derive(Clone, Default)]
pub struct SettledView {
    inner: Arc<Mutex<ViewInner>>,
}

impl SettledView {
    /// The blocks the store holds as applied.
    pub fn load(db: &Database) -> GhostResult<SettledView> {
        let mut inner = ViewInner::default();
        for (h, hash) in db.np_applied_blocks()? {
            let r = db.np_block_retirements(&hash)?.unwrap_or_default();
            inner.blocks.insert(h, (hash, r));
        }
        inner.retag();
        Ok(SettledView {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ViewInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn insert(&self, h: u32, hash: [u8; 32], r: Vec<Retirement>) {
        let mut v = self.lock();
        v.blocks.insert(h, (hash, r));
        v.retag();
    }

    fn remove(&self, h: u32) {
        let mut v = self.lock();
        if v.blocks.remove(&h).is_some() {
            v.retag();
        }
    }

    /// The settled block at height `h`, if any.
    pub fn at(&self, h: u32) -> Option<[u8; 32]> {
        self.lock().blocks.get(&h).map(|(hash, _)| *hash)
    }

    /// Every settled block as `(height, hash)`.
    pub fn blocks(&self) -> Vec<(u32, [u8; 32])> {
        self.lock()
            .blocks
            .iter()
            .map(|(h, (hash, _))| (*h, *hash))
            .collect()
    }
}

// -------------------------------------------------------------------------------------------
// Where blocks come from
// -------------------------------------------------------------------------------------------

/// The Bitcoin best chain, as settlement reads it.
#[async_trait]
pub trait BlockSource: Send + Sync {
    /// The best chain's height.
    async fn tip(&self) -> Option<u32>;
    /// The best-chain block at height `h`, internal byte order.
    async fn hash_at(&self, h: u32) -> Option<[u8; 32]>;
    /// A block's header, height, and coinbase with its merkle branch, on any branch the Bitcoin
    /// node holds.
    async fn block(&self, hash: &[u8; 32]) -> Option<ArchivedBlock>;
}

/// The local Bitcoin node over RPC. Works without `txindex`: the coinbase is fetched with its
/// block hash.
pub struct RpcBlockSource {
    rpc: BitcoinRpc,
}

impl RpcBlockSource {
    /// A source over `rpc`.
    pub fn new(rpc: BitcoinRpc) -> Self {
        RpcBlockSource { rpc }
    }
}

/// The coinbase of a block given as `getblock <hash> 0` hex.
fn coinbase_of_raw_block(raw_hex: &str) -> Option<Transaction> {
    let block: bitcoin::Block =
        bitcoin::consensus::deserialize(&hex::decode(raw_hex).ok()?).ok()?;
    block.txdata.into_iter().next()
}

fn display_hex(hash: &[u8; 32]) -> String {
    let mut be = *hash;
    be.reverse();
    hex::encode(be)
}

#[async_trait]
impl BlockSource for RpcBlockSource {
    async fn tip(&self) -> Option<u32> {
        u32::try_from(self.rpc.get_block_count().await.ok()?).ok()
    }

    async fn hash_at(&self, h: u32) -> Option<[u8; 32]> {
        let s = self.rpc.get_block_hash(h as u64).await.ok()?;
        let mut v: [u8; 32] = hex::decode(s.trim()).ok()?.try_into().ok()?;
        v.reverse();
        Some(v)
    }

    async fn block(&self, hash: &[u8; 32]) -> Option<ArchivedBlock> {
        let block = display_hex(hash);
        let info = self.rpc.get_block_header(&block).await.ok()?;
        let raw = self
            .rpc
            .call_raw("getblockheader", vec![block.clone().into(), false.into()])
            .await
            .ok()?;
        let header: bitcoin::block::Header =
            bitcoin::consensus::deserialize(&hex::decode(raw.as_str()?).ok()?).ok()?;
        let b = self.rpc.get_block(&block, 1).await.ok()?;
        let txids: Vec<[u8; 32]> = b
            .get("tx")?
            .as_array()?
            .iter()
            .map(|t| {
                let mut v: [u8; 32] = hex::decode(t.as_str()?).ok()?.try_into().ok()?;
                v.reverse();
                Some(v)
            })
            .collect::<Option<_>>()?;
        let txid = display_hex(txids.first()?);
        let raw = self
            .rpc
            .call_raw(
                "getrawtransaction",
                vec![txid.into(), false.into(), block.clone().into()],
            )
            .await
            .ok();
        let tx = match raw {
            Some(raw) => bitcoin::consensus::deserialize(&hex::decode(raw.as_str()?).ok()?).ok()?,
            // Bitcoin Core will not serve the genesis block's coinbase as a transaction ("not
            // considered an ordinary transaction"), and settlement archives the blocks at and
            // below a genesis anchor near height 0 (regtest's is at 0): read it from the raw
            // block instead, or settlement never starts.
            None => {
                let raw = self.rpc.get_block(&block, 0).await.ok()?;
                coinbase_of_raw_block(raw.as_str()?)?
            }
        };
        let mut tx: Transaction = tx;
        for i in &mut tx.input {
            i.witness.clear();
        }
        Some(ArchivedBlock {
            header,
            height: u32::try_from(info.height).ok()?,
            coinbase: Some((tx, coinbase_branch(&txids))),
        })
    }
}

#[derive(Default)]
struct MemInner {
    best: BTreeMap<u32, ArchivedBlock>,
    known: HashMap<[u8; 32], ArchivedBlock>,
}

/// An in-memory Bitcoin node: tests, and a node handed its blocks.
#[derive(Clone, Default)]
pub struct MemBlocks {
    inner: Arc<Mutex<MemInner>>,
}

impl MemBlocks {
    /// Put `b` on the best chain at its height, replacing whatever was there. It stays known.
    pub fn set(&self, b: ArchivedBlock) {
        let mut g = self.lock();
        g.known.insert(b.hash(), b.clone());
        g.best.insert(b.height, b);
    }

    /// Make `b` known without putting it on the best chain (a stale block this node saw).
    pub fn know(&self, b: ArchivedBlock) {
        self.lock().known.insert(b.hash(), b);
    }

    /// Drop every best-chain block above `h` from the best chain. They stay known.
    pub fn truncate(&self, h: u32) {
        let _dropped = self.lock().best.split_off(&(h + 1));
    }

    /// The best-chain block at `h`.
    pub fn at(&self, h: u32) -> Option<ArchivedBlock> {
        self.lock().best.get(&h).cloned()
    }

    /// Any known block by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<ArchivedBlock> {
        self.lock().known.get(hash).cloned()
    }

    /// The best chain's height.
    pub fn best_height(&self) -> Option<u32> {
        self.lock().best.keys().next_back().copied()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[async_trait]
impl BlockSource for MemBlocks {
    async fn tip(&self) -> Option<u32> {
        self.lock().best.keys().next_back().copied()
    }

    async fn hash_at(&self, h: u32) -> Option<[u8; 32]> {
        self.lock().best.get(&h).map(|b| b.hash())
    }

    async fn block(&self, hash: &[u8; 32]) -> Option<ArchivedBlock> {
        self.lock().known.get(hash).cloned()
    }
}

// -------------------------------------------------------------------------------------------
// Settlement
// -------------------------------------------------------------------------------------------

/// Archive a block from the local Bitcoin node.
fn archive_local(relay: &Relay, b: ArchivedBlock) -> GhostResult<()> {
    relay
        .archive()
        .insert_local(b, now_secs())
        .map(|_| ())
        .map_err(|e| ghost_common::error::GhostError::Database(format!("archive: {e}")))
}

/// What settlement made of one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// At or below the share chain's genesis: settled by the cutover's genesis table.
    BelowGenesis,
    /// No `GHPP` tag or `GHNP` output: not a node pool block.
    NotPool,
    /// Its anchor is held and its outputs are canonical: retired.
    Matched {
        /// The anchor it was built on.
        anchor: AnchorHash,
        /// The slot class its outputs are canonical for.
        slot_class: u16,
    },
    /// Its anchor is not held: retired from its coinbase, checked again when the anchor arrives.
    Provisional,
    /// Its anchor is held but its outputs are not canonical for it: nothing retired.
    Mismatch,
}

/// Counters for logs and tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettlementStats {
    /// Blocks retired on a canonical match.
    pub matched: u64,
    /// Blocks retired provisionally.
    pub provisional: u64,
    /// Provisional blocks later confirmed by their anchor.
    pub confirmed: u64,
    /// Blocks refused: anchor held, outputs not canonical (including provisional ones undone).
    pub mismatched: u64,
    /// Blocks undone by a Bitcoin reorg.
    pub disconnected: u64,
}

/// Settlement's progress, for the status API (W2.11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettlementStatus {
    /// The highest best-chain height settlement has looked at, if it has run.
    pub synced_height: Option<u32>,
    /// The local Bitcoin node's tip at the last sync, if it answered.
    pub bitcoin_tip: Option<u32>,
    /// Blocks retired provisionally, waiting for their anchor: `(height, block hash)`.
    pub provisional: Vec<(u32, [u8; 32])>,
    /// Counters.
    pub stats: SettlementStats,
}

impl SettlementStatus {
    /// Settlement has looked at every block up to the Bitcoin tip it last saw.
    pub fn caught_up(&self) -> bool {
        matches!((self.synced_height, self.bitcoin_tip), (Some(s), Some(t)) if s >= t)
    }
}

struct Pending {
    height: u32,
    prev: [u8; 32],
    tag: [u8; PAYOUT_ID_LEN],
    coinbase: Transaction,
    retired: Vec<Retirement>,
}

/// Follows the Bitcoin best chain and retires what pool blocks paid.
pub struct Settlement {
    db: Arc<Database>,
    view: SettledView,
    genesis_btc_height: u32,
    recent: BTreeMap<u32, [u8; 32]>,
    pending: HashMap<[u8; 32], Pending>,
    started: bool,
    stats: SettlementStats,
    synced: Option<u32>,
    last_tip: Option<u32>,
}

fn outputs_of(tx: &Transaction) -> Vec<CoinbaseOutput> {
    tx.output
        .iter()
        .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Settlement {
    /// Settlement over the relay's store, recording what it applied in `view`.
    pub fn new(db: Arc<Database>, view: SettledView, genesis_btc_height: u32) -> Settlement {
        Settlement {
            db,
            view,
            genesis_btc_height,
            recent: BTreeMap::new(),
            pending: HashMap::new(),
            started: false,
            stats: SettlementStats::default(),
            synced: None,
            last_tip: None,
        }
    }

    /// Progress: how far settlement has looked, the tip it saw, and what is provisional.
    pub fn status(&self) -> SettlementStatus {
        let mut provisional: Vec<(u32, [u8; 32])> =
            self.pending.iter().map(|(h, p)| (p.height, *h)).collect();
        provisional.sort_unstable();
        SettlementStatus {
            synced_height: self.synced,
            bitcoin_tip: self.last_tip,
            provisional,
            stats: self.stats,
        }
    }

    /// Counters.
    pub fn stats(&self) -> SettlementStats {
        self.stats
    }

    /// Blocks retired provisionally and not yet checked against their anchor.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Bring settlement to `src`'s best chain: undo blocks a reorg disconnected, settle new ones,
    /// and archive every block read.
    ///
    /// The first call also archives the headers at genesis that median time past needs, and
    /// re-checks every block the store holds as applied: it must still be on the best chain, and
    /// one whose anchor is not held goes back to provisional.
    pub async fn sync(&mut self, relay: &mut Relay, src: &dyn BlockSource) -> GhostResult<()> {
        let Some(tip) = src.tip().await else {
            return Ok(());
        };
        self.last_tip = Some(tip);
        if !self.started {
            let floor = self.genesis_btc_height.saturating_sub(MTP_SPAN - 1);
            for h in floor..=self.genesis_btc_height.min(tip) {
                let Some(hash) = src.hash_at(h).await else {
                    return Ok(());
                };
                if !relay.archive().has_full(&hash) {
                    let Some(b) = src.block(&hash).await else {
                        return Ok(());
                    };
                    archive_local(relay, b)?;
                }
                relay.archive().set_main(h, hash);
            }
            for (h, hash) in self.view.blocks() {
                if src.hash_at(h).await != Some(hash) {
                    self.disconnect(h, hash)?;
                    continue;
                }
                let Some(b) = src.block(&hash).await else {
                    continue;
                };
                let Some((cb, _)) = b.coinbase.clone() else {
                    continue;
                };
                // A block whose anchor is still not held goes back to provisional, to be checked
                // when it arrives. A matched block was matched against a table that is a pure
                // function of its anchor and the chain below it, so it stands.
                let sig = cb
                    .input
                    .first()
                    .map_or(&[][..], |i| i.script_sig.as_bytes());
                let Some(tag) = extract_payout_tag(sig) else {
                    continue;
                };
                if relay.anchors_with_prefix(&tag).is_empty() {
                    let retired = self.db.np_block_retirements(&hash)?.unwrap_or_default();
                    self.pending.insert(
                        hash,
                        Pending {
                            height: h,
                            prev: b.prev(),
                            tag,
                            coinbase: cb,
                            retired,
                        },
                    );
                }
            }
            self.started = true;
        }
        // A reorg: walk back while the remembered hash is no longer the best chain's.
        while let Some((&h, &hash)) = self.recent.iter().next_back() {
            if h <= tip && src.hash_at(h).await == Some(hash) {
                break;
            }
            self.recent.remove(&h);
            relay.archive().truncate_main(h.saturating_sub(1));
            if let Some(applied) = self.view.at(h) {
                self.disconnect(h, applied)?;
            }
        }
        let start = match self.recent.keys().next_back() {
            Some(h) => h + 1,
            None => self
                .view
                .blocks()
                .last()
                .map_or(self.genesis_btc_height + 1, |(h, _)| h + 1)
                .max(self.genesis_btc_height + 1),
        };
        // Below the first settled height, the best chain is only archived (once): share checks
        // walk it.
        if self.recent.is_empty() {
            let mut h = self.genesis_btc_height + 1;
            while h < start {
                let Some(hash) = src.hash_at(h).await else {
                    break;
                };
                if !relay.archive().has_full(&hash) {
                    let Some(b) = src.block(&hash).await else {
                        break;
                    };
                    archive_local(relay, b)?;
                }
                relay.archive().set_main(h, hash);
                self.recent.insert(h, hash);
                h += 1;
            }
        }
        let end = tip.min(start.saturating_add(MAX_SCAN_PER_SYNC - 1));
        for h in start..=end {
            let Some(hash) = src.hash_at(h).await else {
                break;
            };
            let Some(b) = src.block(&hash).await else {
                break;
            };
            archive_local(relay, b.clone())?;
            relay.archive().set_main(h, hash);
            match self.view.at(h) {
                Some(x) if x == hash => {}
                other => {
                    if let Some(stale) = other {
                        self.disconnect(h, stale)?;
                    }
                    self.settle(relay, &b)?;
                }
            }
            self.recent.insert(h, hash);
        }
        while self.recent.len() > RECENT_KEPT {
            self.recent.pop_first();
        }
        // Everything below `start` was settled by an earlier sync (or is at or below genesis).
        self.synced = Some(
            self.recent
                .keys()
                .next_back()
                .copied()
                .unwrap_or(start.saturating_sub(1)),
        );
        Ok(())
    }

    /// Settle one best-chain block. Public for tests and for callers that follow the chain
    /// themselves; [`Settlement::sync`] is the usual entry.
    pub fn settle(&mut self, relay: &mut Relay, b: &ArchivedBlock) -> GhostResult<Outcome> {
        let (h, hash, prev) = (b.height, b.hash(), b.prev());
        if h <= self.genesis_btc_height {
            return Ok(Outcome::BelowGenesis);
        }
        let Some((cb, _)) = b.coinbase.as_ref() else {
            return Ok(Outcome::NotPool);
        };
        let outs = outputs_of(cb);
        let sig = cb
            .input
            .first()
            .map_or(&[][..], |i| i.script_sig.as_bytes());
        let Some(tag) = extract_payout_tag(sig) else {
            return Ok(Outcome::NotPool);
        };
        let Some(root) = ledger_root_of(&outs) else {
            // Built on one of our anchors but committing no table: it pays no ledger, so it
            // retires nothing (the deterministic rule reads it as no pool block at all), and it
            // is named, as any other block that does not pay its anchor's outputs is.
            if !relay.anchors_with_prefix(&tag).is_empty() {
                self.stats.mismatched += 1;
                warn!(
                    height = h,
                    block = %display_hex(&hash),
                    "NP_SETTLE: pool block does not pay its anchor's canonical outputs; nothing \
                     retired (it carries no GHNP ledger commitment)"
                );
                return Ok(Outcome::Mismatch);
            }
            return Ok(Outcome::NotPool);
        };
        let candidates = relay.anchors_with_prefix(&tag);
        if candidates.is_empty() {
            let Some(retired) = provisional_retirements(h, relay.halving(), &outs) else {
                warn!(
                    height = h,
                    block = %display_hex(&hash),
                    "NP_SETTLE: a tagged block is not laid out as a node pool coinbase; nothing \
                     retired"
                );
                return Ok(Outcome::NotPool);
            };
            self.apply(h, hash, &retired)?;
            self.pending.insert(
                hash,
                Pending {
                    height: h,
                    prev,
                    tag,
                    coinbase: cb.clone(),
                    retired,
                },
            );
            self.stats.provisional += 1;
            info!(
                height = h,
                block = %display_hex(&hash),
                "NP_SETTLE: pool block retired provisionally; its anchor is not held yet"
            );
            return Ok(Outcome::Provisional);
        }
        for a in candidates {
            if let Some((slot_class, retired)) = Self::check(relay, &a, h, &prev, &root, cb) {
                self.apply(h, hash, &retired)?;
                self.stats.matched += 1;
                info!(
                    height = h,
                    block = %display_hex(&hash),
                    anchor = %hex::encode(a),
                    slot_class,
                    payees = retired.len(),
                    "NP_SETTLE: pool block settled"
                );
                return Ok(Outcome::Matched {
                    anchor: a,
                    slot_class,
                });
            }
        }
        self.stats.mismatched += 1;
        warn!(
            height = h,
            block = %display_hex(&hash),
            "NP_SETTLE: pool block does not pay its anchor's canonical outputs; nothing retired"
        );
        Ok(Outcome::Mismatch)
    }

    fn check(
        relay: &mut Relay,
        a: &AnchorHash,
        h: u32,
        prev: &[u8; 32],
        root: &[u8; 32],
        cb: &Transaction,
    ) -> Option<(u16, Vec<Retirement>)> {
        let table = relay.block_table_on(a, h, prev)?;
        if table_root(&table) != *root {
            return None;
        }
        settle_outputs(cb, &table, h, relay.halving())
    }

    /// Check provisional blocks whose anchor has arrived: keep a match, undo anything else.
    pub fn reconcile(&mut self, relay: &mut Relay) -> GhostResult<()> {
        let ready: Vec<[u8; 32]> = self
            .pending
            .iter()
            .filter(|(_, p)| !relay.anchors_with_prefix(&p.tag).is_empty())
            .map(|(k, _)| *k)
            .collect();
        for hash in ready {
            let p = self.pending.remove(&hash).expect("listed");
            let outs = outputs_of(&p.coinbase);
            let matched = ledger_root_of(&outs).and_then(|root| {
                relay
                    .anchors_with_prefix(&p.tag)
                    .into_iter()
                    .find_map(|a| Self::check(relay, &a, p.height, &p.prev, &root, &p.coinbase))
            });
            match matched {
                Some((_, retired)) if retired == p.retired => {
                    self.stats.confirmed += 1;
                    info!(
                        height = p.height,
                        block = %display_hex(&hash),
                        "NP_SETTLE: provisional block confirmed by its anchor"
                    );
                }
                Some((_, retired)) => {
                    // Cannot happen (both are the paid outputs), but if it did, the anchor wins.
                    self.undo(p.height, hash)?;
                    self.apply(p.height, hash, &retired)?;
                    self.stats.confirmed += 1;
                }
                None => {
                    self.undo(p.height, hash)?;
                    self.stats.mismatched += 1;
                    warn!(
                        height = p.height,
                        block = %display_hex(&hash),
                        "NP_SETTLE: provisional block does not match its anchor; its retirements \
                         are undone"
                    );
                }
            }
        }
        Ok(())
    }

    fn apply(&mut self, h: u32, hash: [u8; 32], retired: &[Retirement]) -> GhostResult<()> {
        self.db.np_apply_block(&hash, h, retired, now_secs())?;
        self.view.insert(h, hash, retired.to_vec());
        Ok(())
    }

    /// Undo a block's retirements in the store and the view.
    fn undo(&mut self, h: u32, hash: [u8; 32]) -> GhostResult<()> {
        if self.db.np_block_retirements(&hash)?.is_some() {
            self.db.np_undo_block_anywhere(&hash)?;
        }
        self.view.remove(h);
        self.pending.remove(&hash);
        Ok(())
    }

    /// A block left the best chain.
    fn disconnect(&mut self, h: u32, hash: [u8; 32]) -> GhostResult<()> {
        self.undo(h, hash)?;
        self.stats.disconnected += 1;
        info!(
            height = h,
            block = %display_hex(&hash),
            "NP_SETTLE: block left the best chain; its retirements are undone"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::JobAnchor;
    use crate::testkit::{
        btc_hash, fed_archive, main_block, main_node, make_block, params, plain_coinbase, Miner,
        Sim, GENESIS_BTC, START_TIP,
    };
    use bitcoin::consensus::deserialize;
    use ghost_common::canonical_payout::Table;

    /// The genesis block's coinbase, which `getrawtransaction` refuses, is read from the raw
    /// block: settlement archives the blocks at a genesis anchor near height 0 before anything
    /// else, and stopped there for good on regtest.
    #[test]
    fn the_genesis_coinbase_is_read_from_the_raw_block() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let raw = hex::encode(bitcoin::consensus::serialize(&genesis));
        let cb = coinbase_of_raw_block(&raw).expect("genesis has a coinbase");
        assert_eq!(
            cb.compute_txid().to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert!(coinbase_of_raw_block("00").is_none());
        assert!(coinbase_of_raw_block("not hex").is_none());
    }

    /// A relay with its archive, and the settlement over its store.
    fn settled() -> (Relay, Settlement) {
        let db = Arc::new(Database::in_memory().unwrap());
        let view = SettledView::load(&db).unwrap();
        let r = Relay::open(params(), db.clone(), fed_archive(START_TIP)).unwrap();
        (r, Settlement::new(db, view, GENESIS_BTC))
    }

    fn sim(n: usize) -> (Sim, Vec<Settlement>) {
        let made = std::cell::RefCell::new(Vec::new());
        let sim = Sim::with_relays(n, |_| {
            let (r, s) = settled();
            made.borrow_mut().push(s);
            r
        });
        (sim, made.into_inner())
    }

    /// The coinbase of a block at `tip + 1` mined on `job`, paying `table`.
    fn pool_coinbase(job: JobAnchor, table: &Table, tip: u32) -> Transaction {
        let s = Miner::new("finder", 9).build(job, table, tip, 0);
        deserialize(&s.coinbase).unwrap()
    }

    /// A block at `h` on the main chain's block `h - 1`.
    fn on_main(h: u32, cb: Transaction) -> ArchivedBlock {
        make_block(btc_hash(h - 1), h, cb)
    }

    /// Node 0 of `sim` produces an anchor; returns the job built on it.
    fn anchored(sim: &mut Sim) -> JobAnchor {
        sim.mine(0, true);
        sim.nodes[0].relay.job_anchor().unwrap()
    }

    /// What a job at `h` on `job`'s anchor owes in all, on Bitcoin block `prev`.
    fn owed(r: &mut Relay, job: &JobAnchor, h: u32, prev: &[u8; 32]) -> i128 {
        r.block_table_on(&job.parent_anchor, h, prev)
            .unwrap()
            .values()
            .map(|b| b.owed)
            .sum()
    }

    fn archive(r: &Relay, b: &ArchivedBlock) {
        r.archive().insert_local(b.clone(), 0).unwrap();
    }

    #[test]
    fn a_canonical_block_retires_and_tables_on_top_of_it_subtract_it() {
        let (mut sim, mut st) = sim(1);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let r = &mut sim.nodes[0].relay;
        let table = r.block_table(&job.parent_anchor, h).unwrap();
        assert_eq!(table.len(), 4, "the genesis table, still above the cut");
        let b = on_main(h, pool_coinbase(job, &table, tip));
        archive(r, &b);
        archive(r, &main_block(h));

        let out = st[0].settle(r, &b).unwrap();
        assert_eq!(
            out,
            Outcome::Matched {
                anchor: job.parent_anchor,
                slot_class: 9
            }
        );
        let retired = r.db().np_block_retirements(&b.hash()).unwrap().unwrap();
        assert_eq!(retired.len(), 4, "every genesis balance was paid");
        let paid: i128 = retired.iter().map(|x| x.1).sum();
        let on_block = owed(r, &job, h + 1, &b.hash());
        let on_sibling = owed(r, &job, h + 1, &btc_hash(h));
        assert_eq!(
            on_sibling - on_block,
            paid,
            "a table on top of it subtracts it"
        );
        assert_eq!(
            owed(r, &job, h, &btc_hash(tip)),
            on_sibling,
            "its own table does not"
        );
        assert_eq!(st[0].stats().matched, 1);
        assert!(r
            .block_table_on(&job.parent_anchor, h + 1, &b.hash())
            .unwrap()
            .values()
            .all(|b| b.owed == 0));
    }

    #[test]
    fn a_block_that_does_not_pay_its_anchors_table_retires_nothing() {
        let (mut sim, mut st) = sim(1);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let r = &mut sim.nodes[0].relay;
        let mut table = (*r.block_table(&job.parent_anchor, h).unwrap()).clone();

        // The right root, the payees in the wrong order.
        let mut swapped = pool_coinbase(job, &table, tip);
        swapped.output.swap(1, 2);
        let swapped = on_main(h, swapped);
        archive(r, &swapped);
        assert_eq!(st[0].settle(r, &swapped).unwrap(), Outcome::Mismatch);
        // The ledger commitment left out: named and counted, nothing retired.
        let mut rootless = pool_coinbase(job, &table, tip);
        let at = rootless.output.len() - 2;
        rootless.output.remove(at);
        let rootless = on_main(h, rootless);
        archive(r, &rootless);
        assert_eq!(st[0].settle(r, &rootless).unwrap(), Outcome::Mismatch);
        // Another table altogether (a balance inflated).
        table.values_mut().next().unwrap().owed *= 2;
        let inflated = on_main(h, pool_coinbase(job, &table, tip));
        archive(r, &inflated);
        assert_eq!(st[0].settle(r, &inflated).unwrap(), Outcome::Mismatch);
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![]);
        assert_eq!(st[0].stats().mismatched, 3);
        // The deterministic rule agrees: a table on top of either subtracts nothing.
        archive(r, &main_block(h));
        let plain = owed(r, &job, h + 1, &btc_hash(h));
        assert_eq!(owed(r, &job, h + 1, &swapped.hash()), plain);
        assert_eq!(owed(r, &job, h + 1, &inflated.hash()), plain);
        assert_eq!(owed(r, &job, h + 1, &rootless.hash()), plain);
        // Not a pool block, and below genesis: ignored.
        assert_eq!(
            st[0].settle(r, &on_main(h, plain_coinbase(h, 3))).unwrap(),
            Outcome::NotPool
        );
        assert_eq!(
            st[0]
                .settle(
                    r,
                    &make_block(
                        btc_hash(GENESIS_BTC - 1),
                        GENESIS_BTC,
                        plain_coinbase(GENESIS_BTC, 4)
                    )
                )
                .unwrap(),
            Outcome::BelowGenesis
        );
    }

    #[test]
    fn an_unknown_anchor_retires_provisionally_and_is_confirmed_when_it_arrives() {
        let (mut sim, mut st) = sim(2);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let table = sim.nodes[0]
            .relay
            .block_table(&job.parent_anchor, h)
            .unwrap();
        let good = on_main(h, pool_coinbase(job, &table, tip));
        let mut wrong_table = (*table).clone();
        wrong_table.pop_first();
        let wrong = make_block(good.hash(), h + 1, pool_coinbase(job, &wrong_table, h));

        // Node 1 has never heard of the anchor.
        let r1 = &mut sim.nodes[1].relay;
        assert!(r1.block_table(&job.parent_anchor, h).is_none());
        archive(r1, &good);
        archive(r1, &wrong);
        assert_eq!(st[1].settle(r1, &good).unwrap(), Outcome::Provisional);
        assert_eq!(st[1].settle(r1, &wrong).unwrap(), Outcome::Provisional);
        assert_eq!(st[1].pending(), 2);
        assert_eq!(
            st[1].status().provisional,
            vec![(h, good.hash()), (h + 1, wrong.hash())]
        );
        let applied = r1.db().np_applied_blocks().unwrap();
        assert_eq!(applied.len(), 2, "both retire from their coinbase alone");
        let provisional = r1.db().np_block_retirements(&good.hash()).unwrap().unwrap();
        st[1].reconcile(r1).unwrap();
        assert_eq!(
            st[1].pending(),
            2,
            "nothing to check until the anchor arrives"
        );

        // The partition heals; node 1 fetches the anchor and its batch.
        sim.link(0, 1);
        sim.run();
        let r1 = &mut sim.nodes[1].relay;
        assert!(r1.has_batch(&job.parent_anchor));
        st[1].reconcile(r1).unwrap();
        assert_eq!(st[1].pending(), 0);
        assert!(st[1].status().provisional.is_empty());
        assert_eq!(st[1].stats().confirmed, 1);
        assert_eq!(st[1].stats().mismatched, 1);
        assert_eq!(
            r1.db().np_applied_blocks().unwrap(),
            vec![(h, good.hash())],
            "the block that did not match is undone"
        );
        assert_eq!(
            r1.db().np_block_retirements(&good.hash()).unwrap().unwrap(),
            provisional,
            "a confirmed block keeps exactly what it retired"
        );
        // Both nodes agree on what a block on top of either must pay.
        archive(&sim.nodes[0].relay, &good);
        archive(&sim.nodes[0].relay, &wrong);
        for prev in [good.hash(), wrong.hash()] {
            let t0 = sim.nodes[0]
                .relay
                .block_table_on(&job.parent_anchor, h + 2, &prev);
            let t1 = sim.nodes[1]
                .relay
                .block_table_on(&job.parent_anchor, h + 2, &prev);
            assert!(t0.is_some());
            assert_eq!(t0, t1);
        }
    }

    #[tokio::test]
    async fn sync_follows_the_best_chain_archives_it_and_undoes_a_reorg() {
        let (mut sim, mut st) = sim(1);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let r = &mut sim.nodes[0].relay;
        let table = r.block_table(&job.parent_anchor, h).unwrap();
        let chain = main_node(h - 1);
        let pool = on_main(h, pool_coinbase(job, &table, tip));
        let after = make_block(pool.hash(), h + 1, plain_coinbase(h + 1, 0));
        chain.set(pool.clone());
        chain.set(after.clone());

        assert!(!st[0].status().caught_up(), "nothing synced yet");
        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![(h, pool.hash())]);
        assert_eq!(r.archive().main_at(h + 1), Some(after.hash()));
        assert!(
            r.archive().has_full(&pool.hash()),
            "archived with its coinbase"
        );
        let s = st[0].status();
        assert_eq!((s.synced_height, s.bitcoin_tip), (Some(h + 1), Some(h + 1)));
        assert!(s.caught_up() && s.provisional.is_empty());
        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(
            st[0].stats().matched,
            1,
            "a settled height is not settled twice"
        );

        // A two-block reorg replaces the pool block.
        chain.truncate(h - 1);
        let mut prev = btc_hash(h - 1);
        for x in h..h + 3 {
            let b = make_block(prev, x, plain_coinbase(x, 7));
            prev = b.hash();
            chain.set(b);
        }
        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(st[0].stats().disconnected, 1);
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![]);
        assert!(r.db().np_block_retirements(&pool.hash()).unwrap().is_none());
        assert_eq!(r.archive().main_at(h + 2), Some(prev));
        assert!(
            r.archive().has_full(&pool.hash()),
            "the stale pool block stays archived for shares built on it"
        );

        // The pool block comes back on a third branch.
        chain.truncate(h - 1);
        chain.set(pool.clone());
        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![(h, pool.hash())]);
    }

    #[tokio::test]
    async fn a_restart_reloads_the_view_and_re_checks_the_store() {
        let (mut sim, mut st) = sim(1);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let r = &mut sim.nodes[0].relay;
        let table = r.block_table(&job.parent_anchor, h).unwrap();
        let chain = main_node(h - 1);
        let pool = on_main(h, pool_coinbase(job, &table, tip));
        chain.set(pool.clone());
        st[0].sync(r, &chain).await.unwrap();

        // Restart: the view comes back from the store; the block left the chain meanwhile.
        let db = r.db().clone();
        let view = SettledView::load(&db).unwrap();
        assert_eq!(view.blocks(), vec![(h, pool.hash())]);
        let mut again = Settlement::new(db.clone(), view.clone(), GENESIS_BTC);
        chain.set(on_main(h, plain_coinbase(h, 2)));
        again.sync(r, &chain).await.unwrap();
        assert_eq!(db.np_applied_blocks().unwrap(), vec![]);
        assert_eq!(view.blocks(), vec![]);
    }

    /// End to end on the relay core: a miner's shares are batched by an anchor and credited; the
    /// credit lifts its balance over the floor once it passes the cut; a pool block built on the
    /// anchor pays it the canonical outputs; settlement retires exactly what was paid; and the
    /// stored ledger and every later table show the balance fall by that amount.
    #[tokio::test]
    async fn shares_to_anchor_to_block_to_settlement_to_balances() {
        use crate::testkit::{p2tr, BITS};
        use ghost_common::canonical_payout::{share_face, Balance, Halving};
        use ghost_common::node_pool_constants::{FACE_PER_SAT, PAYOUT_FLOOR_FACE};

        // The miner starts just under the floor, so its credited shares make it eligible.
        let miner = p2tr("miner-0");
        let start = PAYOUT_FLOOR_FACE - 1;
        let made = std::cell::RefCell::new(Vec::new());
        let mut sim = Sim::with_relays(1, |_| {
            let db = Arc::new(Database::in_memory().unwrap());
            let view = SettledView::load(&db).unwrap();
            let mut p = params();
            p.genesis.table.insert(
                miner.clone(),
                Balance {
                    owed: start,
                    queue_since: None,
                },
            );
            let r = Relay::open(p, db.clone(), fed_archive(START_TIP)).unwrap();
            made.borrow_mut()
                .push(Settlement::new(db, view, GENESIS_BTC));
            r
        });
        let mut st = made.into_inner().remove(0);

        // Two network shares and an anchor that batches them, all at job height tip + 1.
        let job_height = sim.btc.tip + 1;
        sim.mine(0, false);
        sim.mine(0, false);
        // The 30 s re-batch publishes a job whose batch holds them.
        sim.tick(31);
        sim.mine(0, true);
        let r = &mut sim.nodes[0].relay;
        let anchor = r.best();
        let credits: i128 = r
            .batch_credits(&anchor)
            .unwrap()
            .iter()
            .filter(|c| c.script == miner)
            .map(|c| c.face)
            .sum();
        assert_eq!(
            r.batch_credits(&anchor).unwrap().len(),
            2,
            "both shares batched"
        );
        let t_net = r
            .required_tier(&crate::testkit::genesis_hash(), job_height - 1)
            .unwrap();
        let face = share_face(t_net as u32, BITS, job_height, Halving::MAINNET).unwrap() as i128;
        assert_eq!(credits, 2 * face, "each share credits its face at T_net");
        assert_eq!(
            r.db().np_balance(&miner).unwrap().map(|b| b.owed),
            Some(credits),
            "the stored ledger holds the credits (the genesis table is the snapshot's base)"
        );

        // Twenty Bitcoin blocks later the credit is below the cut: a block pays it.
        let h = job_height + 20;
        sim.btc.extend_to(h - 1);
        sim.tick(1);
        let r = &mut sim.nodes[0].relay;
        let job = r.job_anchor().unwrap();
        let table = r.block_table(&job.parent_anchor, h).unwrap();
        let owed = table[&miner].owed;
        assert_eq!(owed, start + credits);
        assert!(owed >= PAYOUT_FLOOR_FACE, "eligible once credited");
        let below_cut = r.block_table(&job.parent_anchor, h - 1).unwrap();
        assert_eq!(below_cut[&miner].owed, start, "not before the cut");

        let chain = main_node(h - 1);
        let cb = pool_coinbase(job, &table, h - 1);
        let paid: u64 = cb
            .output
            .iter()
            .filter(|o| o.script_pubkey.as_bytes() == &miner[..])
            .map(|o| o.value.to_sat())
            .sum();
        assert_eq!(
            paid as i128,
            owed / FACE_PER_SAT,
            "paid its whole sats, nothing more"
        );
        let block = on_main(h, cb.clone());
        chain.set(block.clone());
        st.sync(r, &chain).await.unwrap();
        assert_eq!(st.stats().matched, 1);
        let retired = r.db().np_block_retirements(&block.hash()).unwrap().unwrap();
        assert!(retired.contains(&(miner.clone(), paid as i128 * FACE_PER_SAT)));

        // The balances fall by exactly what was paid, in the store and in every later table.
        let after = r.block_table(&job.parent_anchor, h + 1).unwrap();
        assert_eq!(after[&miner].owed, owed - paid as i128 * FACE_PER_SAT);
        assert_eq!(after[&miner].queue_since, None, "below the floor again");
        assert_eq!(
            r.db().np_balance(&miner).unwrap().unwrap().owed,
            credits - paid as i128 * FACE_PER_SAT,
            "the stored ledger (credits and retirements; the genesis table is the snapshot's)"
        );
        // Every genesis balance was paid too, so the ledger cleared: the treasury took exactly
        // S/200 and the rest of Rm went to the finder output as the surplus (draft 3.2).
        let (base, rm) = ghost_common::canonical_payout::split(h, Halving::MAINNET);
        let treasury = cb.output[0].value.to_sat();
        let miners: u64 = retired.iter().map(|x| (x.1 / FACE_PER_SAT) as u64).sum();
        assert_eq!(treasury, base, "a cleared ledger leaves no change");
        let n = cb.output.len();
        let finder = cb.output[n - 3].value.to_sat();
        assert!(finder >= rm - miners, "the finder output holds the surplus");
        assert_eq!(
            treasury + miners + (rm - miners),
            ghost_common::canonical_payout::subsidy(h, Halving::MAINNET),
        );
    }
}
