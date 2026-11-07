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
//| FILE: headers.rs                                                                                                     |
//|======================================================================================================================|

//! Bitcoin header facts the share checks need (spec 2.1 rule 5).
//!
//! A share names its Bitcoin parent by `prev_hash`. To judge it a node needs that header's height,
//! the bits Bitcoin requires on top of it and its median time past. The relay core reads them
//! through the synchronous [`HeaderLookup`]; the network layer fills a cache from an async
//! [`HeaderOracle`] before it hands the core a message. An unknown header is never a fault of the
//! sender: the item waits (anchors) or is dropped without penalty (loose shares).
//!
//! The RPC oracle asks the local Bitcoin node. A node that has never seen a stale header cannot
//! answer for shares built on it; the archive of stale headers that fixes this is W2.13, and plugs
//! in here as another [`HeaderOracle`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::CompactTarget;

use ghost_common::rpc::BitcoinRpc;

/// What the share checks need about a share's `prev_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFacts {
    /// Height of the header. A share on it has job height `height + 1`.
    pub height: u32,
    /// Bits Bitcoin requires of a block on top of it.
    pub next_bits: CompactTarget,
    /// Its median time past: a block on top must have a later time.
    pub median_time_past: u32,
}

/// Synchronous lookup, as the relay core reads it.
pub trait HeaderLookup {
    /// Facts for header `hash` (internal byte order), if known.
    fn facts(&self, hash: &[u8; 32]) -> Option<HeaderFacts>;
}

impl HeaderLookup for HashMap<[u8; 32], HeaderFacts> {
    fn facts(&self, hash: &[u8; 32]) -> Option<HeaderFacts> {
        self.get(hash).copied()
    }
}

/// Where header facts come from.
#[async_trait]
pub trait HeaderOracle: Send + Sync {
    /// Make the facts for `hashes` available to [`HeaderOracle::lookup`], as far as possible.
    async fn prefetch(&self, hashes: &[[u8; 32]]);
    /// The current Bitcoin tip height, if known.
    async fn tip_height(&self) -> Option<u32>;
    /// A synchronous view of what has been fetched.
    fn lookup(&self) -> &dyn HeaderLookup;
}

/// A fixed, in-memory header set: tests, and a node that is handed its headers.
#[derive(Default, Clone)]
pub struct MemHeaders {
    inner: Arc<Mutex<MemInner>>,
}

#[derive(Default)]
struct MemInner {
    facts: HashMap<[u8; 32], HeaderFacts>,
    tip: Option<u32>,
}

impl MemHeaders {
    /// Add a header.
    pub fn insert(&self, hash: [u8; 32], f: HeaderFacts) {
        self.lock().facts.insert(hash, f);
    }

    /// Set the tip height.
    pub fn set_tip(&self, h: u32) {
        self.lock().tip = Some(h);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl HeaderLookup for MemHeaders {
    fn facts(&self, hash: &[u8; 32]) -> Option<HeaderFacts> {
        self.lock().facts.get(hash).copied()
    }
}

#[async_trait]
impl HeaderOracle for MemHeaders {
    async fn prefetch(&self, _hashes: &[[u8; 32]]) {}

    async fn tip_height(&self) -> Option<u32> {
        self.lock().tip
    }

    fn lookup(&self) -> &dyn HeaderLookup {
        self
    }
}

/// Blocks per difficulty period.
const RETARGET_INTERVAL: u32 = 2_016;
/// Headers kept in the RPC oracle's cache.
const RPC_CACHE_MAX: usize = 4_096;

/// Header facts from the local Bitcoin node over RPC, cached.
///
/// `next_bits` is the header's own bits except where the next block starts a difficulty period;
/// there it is the bits of the main-chain successor, and unknown for a stale header. Networks
/// with a minimum-difficulty exception (testnet) are not supported.
pub struct RpcHeaderOracle {
    rpc: BitcoinRpc,
    cache: MemHeaders,
}

impl RpcHeaderOracle {
    /// An oracle over `rpc`.
    pub fn new(rpc: BitcoinRpc) -> Self {
        RpcHeaderOracle {
            rpc,
            cache: MemHeaders::default(),
        }
    }

    async fn fetch(&self, hash: &[u8; 32]) -> Option<HeaderFacts> {
        let mut be = *hash;
        be.reverse();
        let h = self.rpc.get_block_header(&hex::encode(be)).await.ok()?;
        let height = u32::try_from(h.height).ok()?;
        let bits = u32::from_str_radix(&h.bits, 16).ok()?;
        let next_bits = if (height + 1) % RETARGET_INTERVAL != 0 {
            bits
        } else {
            let next = self
                .rpc
                .get_block_header(h.nextblockhash.as_deref()?)
                .await
                .ok()?;
            u32::from_str_radix(&next.bits, 16).ok()?
        };
        Some(HeaderFacts {
            height,
            next_bits: CompactTarget::from_consensus(next_bits),
            median_time_past: u32::try_from(h.mediantime).ok()?,
        })
    }
}

#[async_trait]
impl HeaderOracle for RpcHeaderOracle {
    async fn prefetch(&self, hashes: &[[u8; 32]]) {
        for h in hashes {
            if self.cache.facts(h).is_some() {
                continue;
            }
            if let Some(f) = self.fetch(h).await {
                let mut inner = self.cache.lock();
                if inner.facts.len() >= RPC_CACHE_MAX {
                    inner.facts.clear();
                }
                inner.facts.insert(*h, f);
            }
        }
    }

    async fn tip_height(&self) -> Option<u32> {
        let h = self.rpc.get_block_count().await.ok()?;
        u32::try_from(h).ok()
    }

    fn lookup(&self) -> &dyn HeaderLookup {
        &self.cache
    }
}
