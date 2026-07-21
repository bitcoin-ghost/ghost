//! A-2b: cached L1 block-hash oracle for the consensus challenger draw.
//!
//! Qualification is synchronous, but block-hash lookups are async RPC — and the
//! qualification closures run inside the tokio runtime, where a blocking
//! `block_on` would panic. So a background task keeps a trailing window of
//! `height -> blockhash` warm, and the sync [`BlockHashProvider::hash_at`] is a
//! pure cache read.
//!
//! Determinism: every node fills the SAME trailing window from its OWN complete
//! Bitcoin Core, so the seed for any round in the qualification window is
//! identical fleet-wide. A height not yet cached returns `None`, and its verdicts
//! are simply not counted (fail-safe) — this self-heals as the backfill catches
//! up, and by the rollout discipline the window is fully warm before the gate is
//! armed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ghost_common::rpc::BitcoinRpc;
use ghost_verification::challenger_assignment::BlockHashProvider;
use parking_lot::RwLock;
use tracing::debug;

/// Trailing window of heights to keep cached: the 7-day lookback (~1008 blocks)
/// plus the seed lag and a comfortable margin.
const WINDOW_BLOCKS: u64 = 1200;

/// Max hashes fetched per refresh tick, to bound the RPC burst while backfilling.
const MAX_FETCH_PER_TICK: usize = 64;

/// Refresh cadence for the background window updater.
const REFRESH_INTERVAL: Duration = Duration::from_secs(20);

/// A block-hash oracle backed by an in-memory trailing window that a background
/// task keeps warm from Bitcoin Core. Cheap to clone (shares the cache).
#[derive(Clone, Default)]
pub struct CachedBlockHashOracle {
    cache: Arc<RwLock<HashMap<u64, [u8; 32]>>>,
}

impl CachedBlockHashOracle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn the background refresher against `rpc` and return the oracle sharing
    /// the cache it fills. Call once at startup; clone the result to every
    /// qualification provider that needs it.
    pub fn spawn(rpc: Arc<BitcoinRpc>) -> Self {
        let oracle = Self::new();
        let cache = Arc::clone(&oracle.cache);
        tokio::spawn(async move {
            loop {
                if let Ok(tip) = rpc.get_block_count().await {
                    let lo = tip.saturating_sub(WINDOW_BLOCKS);
                    // Drop heights that have fallen out of the trailing window.
                    cache.write().retain(|h, _| *h >= lo);
                    // Fetch the still-missing heights in the window (bounded per tick).
                    let missing: Vec<u64> = {
                        let c = cache.read();
                        (lo..=tip)
                            .filter(|h| !c.contains_key(h))
                            .take(MAX_FETCH_PER_TICK)
                            .collect()
                    };
                    for h in missing {
                        if let Ok(hash_hex) = rpc.get_block_hash(h).await {
                            if let Some(bytes) = decode_hash(&hash_hex) {
                                cache.write().insert(h, bytes);
                            }
                        }
                    }
                    debug!(
                        tip,
                        cached = cache.read().len(),
                        "A-2b block-hash oracle window refreshed"
                    );
                }
                tokio::time::sleep(REFRESH_INTERVAL).await;
            }
        });
        oracle
    }
}

/// Decode a 32-byte block hash from its RPC hex string. Byte order is irrelevant
/// to the draw (the hash is only a seed input) as long as every node decodes the
/// same hex identically — which they do.
fn decode_hash(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

impl BlockHashProvider for CachedBlockHashOracle {
    fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        self.cache.read().get(&height).copied()
    }
}
