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
//! Every retirement also lands in the [`SettledView`], the relay's [`Retirements`] hook, so every
//! later snapshot table subtracts it.
//!
//! The view is this node's Bitcoin best chain: the retirements a table subtracts for job height
//! `H` are those of the settled pool blocks below `H` on the best chain, whatever the including
//! anchor. Two nodes on different Bitcoin tips can disagree for the time it takes a block to
//! propagate; a pool block on a stale branch is never in the view.
//!
//! [`share_commit::settle_outputs`]: ghost_common::share_commit::settle_outputs
//! [`canonical_payout::provisional_retirements`]: ghost_common::canonical_payout::provisional_retirements

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::Transaction;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use ghost_common::anchor_chain::{AnchorChain, AnchorHash};
use ghost_common::canonical_payout::{
    ledger_root_of, provisional_retirements, table_root, CoinbaseOutput, Retirement,
};
use ghost_common::coinbase_tags::{extract_payout_tag, PAYOUT_ID_LEN};
use ghost_common::error::GhostResult;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::share_commit::settle_outputs;
use ghost_storage::Database;

use crate::relay::{Relay, Retirements};

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

/// The settled pool blocks on the best chain and what each retired: the relay's [`Retirements`]
/// hook. Cheap to clone; every clone sees the same blocks.
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

impl Retirements for SettledView {
    fn blocks_below(
        &self,
        _chain: &AnchorChain,
        _including: &AnchorHash,
        h: u32,
    ) -> BTreeMap<u32, Vec<Retirement>> {
        self.lock()
            .blocks
            .range(..h)
            .map(|(k, (_, r))| (*k, r.clone()))
            .collect()
    }

    fn view_tag(&self, _chain: &AnchorChain, _including: &AnchorHash) -> [u8; 32] {
        self.lock().tag
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
    /// A block's coinbase transaction.
    async fn coinbase(&self, hash: &[u8; 32]) -> Option<Transaction>;
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

    async fn coinbase(&self, hash: &[u8; 32]) -> Option<Transaction> {
        let block = display_hex(hash);
        let b = self.rpc.get_block(&block, 1).await.ok()?;
        let txid = b.get("tx")?.get(0)?.as_str()?.to_string();
        let raw = self
            .rpc
            .call_raw(
                "getrawtransaction",
                vec![txid.into(), false.into(), block.into()],
            )
            .await
            .ok()?;
        let bytes = hex::decode(raw.as_str()?).ok()?;
        bitcoin::consensus::deserialize(&bytes).ok()
    }
}

/// An in-memory best chain: tests, and a node handed its blocks.
#[derive(Clone, Default)]
pub struct MemBlocks {
    inner: Arc<Mutex<BTreeMap<u32, ([u8; 32], Transaction)>>>,
}

impl MemBlocks {
    /// Put block `hash` with `coinbase` at height `h`, replacing whatever was there.
    pub fn set(&self, h: u32, hash: [u8; 32], coinbase: Transaction) {
        self.lock().insert(h, (hash, coinbase));
    }

    /// Drop every block above `h`.
    pub fn truncate(&self, h: u32) {
        let _dropped = self.lock().split_off(&(h + 1));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<u32, ([u8; 32], Transaction)>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[async_trait]
impl BlockSource for MemBlocks {
    async fn tip(&self) -> Option<u32> {
        self.lock().keys().next_back().copied()
    }

    async fn hash_at(&self, h: u32) -> Option<[u8; 32]> {
        self.lock().get(&h).map(|(hash, _)| *hash)
    }

    async fn coinbase(&self, hash: &[u8; 32]) -> Option<Transaction> {
        self.lock()
            .values()
            .find(|(x, _)| x == hash)
            .map(|(_, tx)| tx.clone())
    }
}

// -------------------------------------------------------------------------------------------
// Settlement
// -------------------------------------------------------------------------------------------

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

struct Pending {
    height: u32,
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
    /// Settlement over the relay's store, publishing to `view` (the relay's [`Retirements`]).
    pub fn new(db: Arc<Database>, view: SettledView, genesis_btc_height: u32) -> Settlement {
        Settlement {
            db,
            view,
            genesis_btc_height,
            recent: BTreeMap::new(),
            pending: HashMap::new(),
            started: false,
            stats: SettlementStats::default(),
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

    /// Bring settlement to `src`'s best chain: undo blocks a reorg disconnected, settle new ones.
    ///
    /// The first call also re-checks every block the store holds as applied: it must still be on
    /// the best chain, and one whose anchor is not held goes back to provisional.
    pub async fn sync(&mut self, relay: &mut Relay, src: &dyn BlockSource) -> GhostResult<()> {
        let Some(tip) = src.tip().await else {
            return Ok(());
        };
        if !self.started {
            for (h, hash) in self.view.blocks() {
                if src.hash_at(h).await != Some(hash) {
                    self.disconnect(h, hash)?;
                    continue;
                }
                let Some(cb) = src.coinbase(&hash).await else {
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
        let end = tip.min(start.saturating_add(MAX_SCAN_PER_SYNC - 1));
        for h in start..=end {
            let Some(hash) = src.hash_at(h).await else {
                break;
            };
            match self.view.at(h) {
                Some(x) if x == hash => {}
                other => {
                    if let Some(stale) = other {
                        self.disconnect(h, stale)?;
                    }
                    let Some(cb) = src.coinbase(&hash).await else {
                        break;
                    };
                    self.settle(relay, h, hash, &cb)?;
                }
            }
            self.recent.insert(h, hash);
        }
        while self.recent.len() > RECENT_KEPT {
            self.recent.pop_first();
        }
        Ok(())
    }

    /// Settle one best-chain block. Public for tests and for callers that follow the chain
    /// themselves; [`Settlement::sync`] is the usual entry.
    pub fn settle(
        &mut self,
        relay: &mut Relay,
        h: u32,
        hash: [u8; 32],
        cb: &Transaction,
    ) -> GhostResult<Outcome> {
        if h <= self.genesis_btc_height {
            return Ok(Outcome::BelowGenesis);
        }
        let outs = outputs_of(cb);
        let sig = cb
            .input
            .first()
            .map_or(&[][..], |i| i.script_sig.as_bytes());
        let (Some(root), Some(tag)) = (ledger_root_of(&outs), extract_payout_tag(sig)) else {
            return Ok(Outcome::NotPool);
        };
        let candidates = relay.anchors_with_prefix(&tag);
        if candidates.is_empty() {
            let Some(retired) = provisional_retirements(h, &outs) else {
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
            if let Some((slot_class, retired)) = Self::check(relay, &a, h, &root, cb) {
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
        root: &[u8; 32],
        cb: &Transaction,
    ) -> Option<(u16, Vec<Retirement>)> {
        let table = relay.block_table(a, h)?;
        if table_root(&table) != *root {
            return None;
        }
        settle_outputs(cb, &table, h)
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
                    .find_map(|a| Self::check(relay, &a, p.height, &root, &p.coinbase))
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
    use crate::testkit::{p2tr, params, Miner, Sim, GENESIS_BTC};
    use bitcoin::consensus::deserialize;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use ghost_common::canonical_payout::Table;

    /// A relay whose snapshot hook is settlement's view, and the settlement over its store.
    fn settled() -> (Relay, Settlement) {
        let db = Arc::new(Database::in_memory().unwrap());
        let view = SettledView::load(&db).unwrap();
        let r = Relay::open(params(), db.clone(), Box::new(view.clone())).unwrap();
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

    /// A coinbase with no node pool layout.
    fn plain_coinbase(h: u32) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: bitcoin::script::Builder::new()
                    .push_int(h as i64)
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

    fn hash(h: u32, tag: u8) -> [u8; 32] {
        let mut x = [tag; 32];
        x[..4].copy_from_slice(&h.to_le_bytes());
        x
    }

    /// Node 0 of `sim` produces an anchor; returns the job built on it.
    fn anchored(sim: &mut Sim) -> JobAnchor {
        sim.mine(0, true);
        sim.nodes[0].relay.job_anchor().unwrap()
    }

    fn owed(r: &mut Relay, job: &JobAnchor, h: u32) -> i128 {
        r.block_table(&job.parent_anchor, h)
            .unwrap()
            .values()
            .map(|b| b.owed)
            .sum()
    }

    #[test]
    fn a_canonical_block_retires_and_later_tables_subtract_it() {
        let (mut sim, mut st) = sim(1);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let r = &mut sim.nodes[0].relay;
        let table = r.block_table(&job.parent_anchor, h).unwrap();
        assert_eq!(table.len(), 4, "the genesis table, still above the cut");
        let cb = pool_coinbase(job, &table, tip);
        let before = owed(r, &job, h + 1);

        let out = st[0].settle(r, h, hash(h, 1), &cb).unwrap();
        assert_eq!(
            out,
            Outcome::Matched {
                anchor: job.parent_anchor,
                slot_class: 9
            }
        );
        let retired = r.db().np_block_retirements(&hash(h, 1)).unwrap().unwrap();
        assert_eq!(retired.len(), 4, "every genesis balance was paid");
        let paid: i128 = retired.iter().map(|x| x.1).sum();
        assert_eq!(
            owed(r, &job, h + 1),
            before - paid,
            "the next table subtracts it"
        );
        assert_eq!(owed(r, &job, h), before, "the block's own table does not");
        assert_eq!(st[0].stats().matched, 1);
        // A share for the next height now pays nobody from the genesis table.
        assert!(r
            .block_table(&job.parent_anchor, h + 1)
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
        assert_eq!(
            st[0].settle(r, h, hash(h, 1), &swapped).unwrap(),
            Outcome::Mismatch
        );
        // Another table altogether (a balance inflated).
        table.values_mut().next().unwrap().owed *= 2;
        let inflated = pool_coinbase(job, &table, tip);
        assert_eq!(
            st[0].settle(r, h, hash(h, 2), &inflated).unwrap(),
            Outcome::Mismatch
        );
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![]);
        assert_eq!(st[0].stats().mismatched, 2);
        // Not a pool block, and below genesis: ignored.
        assert_eq!(
            st[0].settle(r, h, hash(h, 3), &plain_coinbase(h)).unwrap(),
            Outcome::NotPool
        );
        assert_eq!(
            st[0].settle(r, GENESIS_BTC, hash(h, 4), &inflated).unwrap(),
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
        let good = pool_coinbase(job, &table, tip);
        let mut wrong_table = (*table).clone();
        wrong_table.pop_first();
        let wrong = pool_coinbase(job, &wrong_table, tip);

        // Node 1 has never heard of the anchor.
        let r1 = &mut sim.nodes[1].relay;
        assert!(r1.block_table(&job.parent_anchor, h).is_none());
        assert_eq!(
            st[1].settle(r1, h, hash(h, 1), &good).unwrap(),
            Outcome::Provisional
        );
        assert_eq!(
            st[1].settle(r1, h + 1, hash(h + 1, 1), &wrong).unwrap(),
            Outcome::Provisional
        );
        assert_eq!(st[1].pending(), 2);
        let applied = r1.db().np_applied_blocks().unwrap();
        assert_eq!(applied.len(), 2, "both retire from their coinbase alone");
        let provisional = r1.db().np_block_retirements(&hash(h, 1)).unwrap().unwrap();
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
        assert_eq!(st[1].stats().confirmed, 1);
        assert_eq!(st[1].stats().mismatched, 1);
        assert_eq!(
            r1.db().np_applied_blocks().unwrap(),
            vec![(h, hash(h, 1))],
            "the block that did not match is undone"
        );
        assert_eq!(
            r1.db().np_block_retirements(&hash(h, 1)).unwrap().unwrap(),
            provisional,
            "a confirmed block keeps exactly what it retired"
        );
        // Node 1 now agrees with node 0 on what the next block must pay.
        let mut st0 = st.remove(0);
        st0.settle(&mut sim.nodes[0].relay, h, hash(h, 1), &good)
            .unwrap();
        let t0 = sim.nodes[0].relay.block_table(&job.parent_anchor, h + 2);
        let t1 = sim.nodes[1].relay.block_table(&job.parent_anchor, h + 2);
        assert_eq!(t0, t1);
    }

    #[tokio::test]
    async fn sync_follows_the_best_chain_and_undoes_a_reorg() {
        let (mut sim, mut st) = sim(1);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let r = &mut sim.nodes[0].relay;
        let table = r.block_table(&job.parent_anchor, h).unwrap();
        let chain = MemBlocks::default();
        for x in GENESIS_BTC - 3..h {
            chain.set(x, hash(x, 0), plain_coinbase(x));
        }
        chain.set(h, hash(h, 1), pool_coinbase(job, &table, tip));
        chain.set(h + 1, hash(h + 1, 0), plain_coinbase(h + 1));

        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![(h, hash(h, 1))]);
        let settled_owed = owed(r, &job, h + 2);
        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(
            st[0].stats().matched,
            1,
            "a settled height is not settled twice"
        );

        // A two-block reorg replaces the pool block.
        chain.truncate(h - 1);
        chain.set(h, hash(h, 7), plain_coinbase(h));
        chain.set(h + 1, hash(h + 1, 7), plain_coinbase(h + 1));
        chain.set(h + 2, hash(h + 2, 7), plain_coinbase(h + 2));
        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(st[0].stats().disconnected, 1);
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![]);
        assert!(r.db().np_block_retirements(&hash(h, 1)).unwrap().is_none());
        assert!(
            owed(r, &job, h + 2) > settled_owed,
            "the balances are owed again"
        );

        // The pool block comes back on a third branch.
        chain.truncate(h - 1);
        chain.set(h, hash(h, 1), pool_coinbase(job, &table, tip));
        st[0].sync(r, &chain).await.unwrap();
        assert_eq!(r.db().np_applied_blocks().unwrap(), vec![(h, hash(h, 1))]);
        assert_eq!(owed(r, &job, h + 2), settled_owed);
    }

    #[tokio::test]
    async fn a_restart_reloads_the_view_and_re_checks_the_store() {
        let (mut sim, mut st) = sim(1);
        let job = anchored(&mut sim);
        let tip = sim.btc.tip;
        let h = tip + 1;
        let r = &mut sim.nodes[0].relay;
        let table = r.block_table(&job.parent_anchor, h).unwrap();
        let chain = MemBlocks::default();
        for x in GENESIS_BTC + 1..h {
            chain.set(x, hash(x, 0), plain_coinbase(x));
        }
        chain.set(h, hash(h, 1), pool_coinbase(job, &table, tip));
        st[0].sync(r, &chain).await.unwrap();

        // Restart: the view comes back from the store; the block left the chain meanwhile.
        let db = r.db().clone();
        let view = SettledView::load(&db).unwrap();
        assert_eq!(view.blocks(), vec![(h, hash(h, 1))]);
        let mut again = Settlement::new(db.clone(), view.clone(), GENESIS_BTC);
        chain.set(h, hash(h, 2), plain_coinbase(h));
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
        use ghost_common::canonical_payout::{share_face, Balance};
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
            let r = Relay::open(p, db.clone(), Box::new(view.clone())).unwrap();
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
        let face = share_face(t_net as u32, BITS, job_height).unwrap() as i128;
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

        let chain = MemBlocks::default();
        for x in GENESIS_BTC + 1..h {
            chain.set(x, hash(x, 0), plain_coinbase(x));
        }
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
        chain.set(h, hash(h, 1), cb);
        st.sync(r, &chain).await.unwrap();
        assert_eq!(st.stats().matched, 1);
        let retired = r.db().np_block_retirements(&hash(h, 1)).unwrap().unwrap();
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
        // Every genesis balance was paid too, and the treasury took S/200 plus the change.
        let treasury = cb_value(&chain, h, 0);
        let miners: u64 = retired.iter().map(|x| (x.1 / FACE_PER_SAT) as u64).sum();
        assert_eq!(
            treasury + miners,
            ghost_common::canonical_payout::subsidy(h),
            "treasury plus miners is the subsidy exactly"
        );
    }

    fn cb_value(chain: &MemBlocks, h: u32, i: usize) -> u64 {
        chain.lock()[&h].1.output[i].value.to_sat()
    }
}
