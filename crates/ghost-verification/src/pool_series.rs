//! In-memory rolling time-series for pool-wide mining metrics.
//!
//! The dashboard Node Pool page charts pool hashrate + connected miners, but
//! the backend historically exposed only *current* values, so the page had to
//! accumulate history in a client-side session buffer that resets on every
//! reload. This module keeps a bounded, process-local ring of periodic samples
//! (fed by a sampler task in `bins/ghost-pool`) so the page can fetch real
//! server-side history from `GET /api/v1/pool/series`.
//!
//! It mirrors the bounded-`VecDeque` shape of `log_buffer`, but hangs off
//! `VerificationState` (Arc-shared) instead of a process `static` so the
//! sampler task and the route handler share one instance.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// One periodic sample of pool-wide metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSample {
    /// Unix timestamp (seconds) the sample was taken.
    pub t: i64,
    /// Mesh-wide pool hashrate (TH/s) — sum of every node's realized hashrate.
    pub mesh_hashrate_th: f64,
    /// This node's own realized hashrate (TH/s).
    pub local_hashrate_th: f64,
    /// Mesh-wide deduplicated connected-miner count.
    pub miners: u32,
    /// Local ghostd mempool transaction count at sample time (`getmempoolinfo.size`).
    /// `#[serde(default)]` so samples serialised before this field deserialise as 0.
    #[serde(default)]
    pub mempool_txs: u64,
    /// Transaction count of the current block template (including coinbase).
    /// `#[serde(default)]` so samples serialised before this field deserialise as 0.
    #[serde(default)]
    pub block_txs: u64,
}

/// Bounded FIFO ring of [`PoolSample`], shared between the sampler task and the
/// `/api/v1/pool/series` handler. Cheap reads/writes behind a single `RwLock`.
pub struct PoolSeries {
    inner: RwLock<VecDeque<PoolSample>>,
    capacity: usize,
}

impl PoolSeries {
    /// Create a ring holding at most `capacity` samples.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            // Cap the pre-allocation so a large retention window doesn't reserve
            // a huge buffer up front; it grows as samples arrive.
            inner: RwLock::new(VecDeque::with_capacity(capacity.min(512))),
            capacity,
        }
    }

    /// Append a sample, evicting the oldest when at capacity (FIFO).
    pub fn push(&self, sample: PoolSample) {
        let mut buf = self.inner.write();
        while buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(sample);
    }

    /// All samples with `t >= cutoff`, oldest first.
    pub fn since(&self, cutoff: i64) -> Vec<PoolSample> {
        self.inner
            .read()
            .iter()
            .filter(|s| s.t >= cutoff)
            .cloned()
            .collect()
    }

    /// Number of samples currently retained.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Whether the ring holds no samples yet.
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(t: i64) -> PoolSample {
        PoolSample {
            t,
            mesh_hashrate_th: t as f64,
            local_hashrate_th: 0.0,
            miners: 1,
            mempool_txs: t as u64,
            block_txs: (t as u64) + 1,
        }
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let s = PoolSeries::new(3);
        for t in 0..5 {
            s.push(sample(t));
        }
        assert_eq!(s.len(), 3);
        // Oldest two (t=0,1) evicted; t=2,3,4 retained.
        let all = s.since(i64::MIN);
        assert_eq!(all.iter().map(|x| x.t).collect::<Vec<_>>(), vec![2, 3, 4]);
    }

    #[test]
    fn since_filters_by_cutoff() {
        let s = PoolSeries::new(100);
        for t in 0..10 {
            s.push(sample(t));
        }
        let recent = s.since(7);
        assert_eq!(recent.iter().map(|x| x.t).collect::<Vec<_>>(), vec![7, 8, 9]);
    }

    #[test]
    fn empty_series_reports_empty() {
        let s = PoolSeries::new(10);
        assert!(s.is_empty());
        assert!(s.since(0).is_empty());
    }

    #[test]
    fn mempool_and_block_txs_survive_push_and_since() {
        let s = PoolSeries::new(10);
        s.push(sample(5));
        let out = s.since(i64::MIN);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mempool_txs, 5);
        assert_eq!(out[0].block_txs, 6);
    }

    #[test]
    fn serde_round_trip_preserves_new_fields() {
        let json = serde_json::to_string(&sample(42)).unwrap();
        let back: PoolSample = serde_json::from_str(&json).unwrap();
        assert_eq!(back.t, 42);
        assert_eq!(back.mempool_txs, 42);
        assert_eq!(back.block_txs, 43);
    }

    #[test]
    fn old_samples_without_new_fields_default_to_zero() {
        // A payload serialised before mempool_txs/block_txs existed.
        let legacy = r#"{"t":100,"mesh_hashrate_th":1.5,"local_hashrate_th":0.5,"miners":3}"#;
        let s: PoolSample = serde_json::from_str(legacy).unwrap();
        assert_eq!(s.t, 100);
        assert_eq!(s.miners, 3);
        assert_eq!(s.mempool_txs, 0);
        assert_eq!(s.block_txs, 0);
    }
}
