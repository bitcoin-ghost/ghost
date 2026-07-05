//! Reaper runtime stats — cumulative counters incremented every time the
//! template builder runs `ghost_reaper::analyze` on a candidate transaction.
//!
//! These are pure observability — they don't influence consensus or payouts.
//! The dashboard reads them via `/api/v1/reaper/status` so operators can see
//! how often Reaper is firing and against what.
//!
//! Counters survive across template builds (atomics are process-lived) but
//! reset on ghost-pool restart — matching the rest of the metric surface.

use ghost_reaper::{DeadCodeType, ReaperVerdict};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Lock-free counter set. Writes happen on the template-build hot path, so
/// every increment is a single relaxed atomic add. Reads (the API handler)
/// load each counter independently — values may not be consistent with each
/// other for a single instant but always trend correctly. Good enough for a
/// dashboard tile.
#[derive(Debug, Default)]
pub struct ReaperStats {
    txs_evaluated: AtomicU64,
    txs_reaped: AtomicU64,
    txs_accepted: AtomicU64,
    /// Total dead bytes across all reaped transactions. Useful for
    /// "block-space saved" headline.
    dead_bytes_total: AtomicU64,
    /// One counter per `DeadCodeType`. Indexes match `DeadCodeType` order in
    /// `crates/ghost-reaper/src/verdict.rs:32`.
    by_type: [AtomicU64; 10],
    /// Last reap timestamp (Unix seconds). 0 = never.
    last_reaped_unix: AtomicU64,
    /// Transactions reaped while building the most-recently-built block
    /// template. SNAPSHOT of the latest template — overwritten each build,
    /// NOT cumulative. Powers the dashboard's "Reaped this block" tile.
    last_block_reaped: AtomicU64,
    /// Dead bytes reaped while building the most-recently-built block
    /// template. Snapshot, overwritten each build.
    last_block_dead_bytes: AtomicU64,
    /// Unix seconds when the most recent block template was built. 0 = no
    /// template built yet this run — lets the dashboard distinguish "0 reaped
    /// this block" from "no block data yet".
    last_block_unix: AtomicU64,
}

impl ReaperStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Called for every transaction evaluated, whether reaped or accepted.
    pub fn record(&self, verdict: &ReaperVerdict) {
        self.txs_evaluated.fetch_add(1, Ordering::Relaxed);
        if verdict.is_corpse() {
            self.txs_reaped.fetch_add(1, Ordering::Relaxed);
            self.dead_bytes_total
                .fetch_add(verdict.total_dead_bytes as u64, Ordering::Relaxed);
            self.last_reaped_unix.store(now_unix(), Ordering::Relaxed);
            for region in &verdict.dead_regions {
                let idx = type_index(region.dead_code_type);
                self.by_type[idx].fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.txs_accepted.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records a snapshot of the most-recently-built block template's Reaper
    /// impact: how many transactions it reaped and how many dead bytes those
    /// carried. Called ONCE per template build. Overwrites the previous
    /// snapshot — these are per-template values, NOT cumulative (the running
    /// totals live in `record`). The build timestamp is stamped so the
    /// dashboard can distinguish "0 reaped this block" from "no block yet".
    pub fn record_block(&self, reaped: u64, dead_bytes: u64) {
        self.last_block_reaped.store(reaped, Ordering::Relaxed);
        self.last_block_dead_bytes
            .store(dead_bytes, Ordering::Relaxed);
        self.last_block_unix.store(now_unix(), Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ReaperStatsSnapshot {
        ReaperStatsSnapshot {
            txs_evaluated: self.txs_evaluated.load(Ordering::Relaxed),
            txs_reaped: self.txs_reaped.load(Ordering::Relaxed),
            txs_accepted: self.txs_accepted.load(Ordering::Relaxed),
            dead_bytes_total: self.dead_bytes_total.load(Ordering::Relaxed),
            last_reaped_unix: {
                let v = self.last_reaped_unix.load(Ordering::Relaxed);
                if v == 0 {
                    None
                } else {
                    Some(v as i64)
                }
            },
            last_block_reaped: self.last_block_reaped.load(Ordering::Relaxed),
            last_block_dead_bytes: self.last_block_dead_bytes.load(Ordering::Relaxed),
            last_block_unix: {
                let v = self.last_block_unix.load(Ordering::Relaxed);
                if v == 0 {
                    None
                } else {
                    Some(v as i64)
                }
            },
            by_type: ByDeadCodeType {
                inscription_envelope: self.by_type[0].load(Ordering::Relaxed),
                drop_stuffing: self.by_type[1].load(Ordering::Relaxed),
                unreachable_code: self.by_type[2].load(Ordering::Relaxed),
                fake_pubkey: self.by_type[3].load(Ordering::Relaxed),
                fake_pubkey_curve_point: self.by_type[4].load(Ordering::Relaxed),
                annex_present: self.by_type[5].load(Ordering::Relaxed),
                oversized_op_return: self.by_type[6].load(Ordering::Relaxed),
                excess_witness_data: self.by_type[7].load(Ordering::Relaxed),
                excess_stack_items: self.by_type[8].load(Ordering::Relaxed),
                legacy_scriptsig_data: self.by_type[9].load(Ordering::Relaxed),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ReaperStatsSnapshot {
    pub txs_evaluated: u64,
    pub txs_reaped: u64,
    pub txs_accepted: u64,
    pub dead_bytes_total: u64,
    /// Unix seconds of the most recent reap. None if never.
    pub last_reaped_unix: Option<i64>,
    /// Transactions reaped while building the most recent block template.
    /// Snapshot of the latest template only (not cumulative). Interpret
    /// alongside `last_block_unix`: 0 with a present timestamp means "a block
    /// was built and it reaped nothing".
    pub last_block_reaped: u64,
    /// Dead bytes reaped in the most recent block template. Snapshot only.
    pub last_block_dead_bytes: u64,
    /// Unix seconds when the most recent block template was built. None = no
    /// template built yet this run (so `last_block_reaped` is "no data", not
    /// a real zero).
    pub last_block_unix: Option<i64>,
    pub by_type: ByDeadCodeType,
}

#[derive(Debug, Clone, Serialize)]
pub struct ByDeadCodeType {
    pub inscription_envelope: u64,
    pub drop_stuffing: u64,
    pub unreachable_code: u64,
    pub fake_pubkey: u64,
    pub fake_pubkey_curve_point: u64,
    pub annex_present: u64,
    pub oversized_op_return: u64,
    pub excess_witness_data: u64,
    pub excess_stack_items: u64,
    pub legacy_scriptsig_data: u64,
}

fn type_index(t: DeadCodeType) -> usize {
    match t {
        DeadCodeType::InscriptionEnvelope => 0,
        DeadCodeType::DropStuffing => 1,
        DeadCodeType::UnreachableCode => 2,
        DeadCodeType::FakePubkey => 3,
        DeadCodeType::FakePubkeyCurvePoint => 4,
        DeadCodeType::AnnexPresent => 5,
        DeadCodeType::OversizedOpReturn => 6,
        DeadCodeType::ExcessWitnessData => 7,
        DeadCodeType::ExcessStackItems => 8,
        DeadCodeType::LegacyScriptSigData => 9,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_reaper::{AnalysisLocation, DeadCodeRegion, Verdict};

    fn corpse_verdict(types: Vec<DeadCodeType>, dead_bytes: usize) -> ReaperVerdict {
        ReaperVerdict {
            verdict: Verdict::Corpse,
            dead_regions: types
                .into_iter()
                .map(|t| DeadCodeRegion {
                    location: AnalysisLocation::Input(0),
                    dead_code_type: t,
                    offset: 0,
                    size: 16,
                    description: "test".into(),
                })
                .collect(),
            input_analyses: vec![],
            total_dead_bytes: dead_bytes,
            total_witness_bytes: 0,
            dead_code_ratio: 1.0,
            total_essential_bytes: 0,
            total_excess_bytes: 0,
        }
    }

    #[test]
    fn accepted_increments_only_accept_counters() {
        let s = ReaperStats::new();
        s.record(&ReaperVerdict::accept());
        let snap = s.snapshot();
        assert_eq!(snap.txs_evaluated, 1);
        assert_eq!(snap.txs_accepted, 1);
        assert_eq!(snap.txs_reaped, 0);
        assert_eq!(snap.last_reaped_unix, None);
    }

    #[test]
    fn corpse_increments_reaped_and_per_type() {
        let s = ReaperStats::new();
        s.record(&corpse_verdict(
            vec![
                DeadCodeType::InscriptionEnvelope,
                DeadCodeType::DropStuffing,
            ],
            128,
        ));
        let snap = s.snapshot();
        assert_eq!(snap.txs_evaluated, 1);
        assert_eq!(snap.txs_reaped, 1);
        assert_eq!(snap.dead_bytes_total, 128);
        assert_eq!(snap.by_type.inscription_envelope, 1);
        assert_eq!(snap.by_type.drop_stuffing, 1);
        assert_eq!(snap.by_type.unreachable_code, 0);
        assert!(snap.last_reaped_unix.is_some());
    }

    #[test]
    fn no_block_snapshot_before_any_build() {
        let s = ReaperStats::new();
        let snap = s.snapshot();
        // Distinguishable "no data" state: timestamp absent, count reads 0.
        assert_eq!(snap.last_block_unix, None);
        assert_eq!(snap.last_block_reaped, 0);
        assert_eq!(snap.last_block_dead_bytes, 0);
    }

    #[test]
    fn record_block_updates_snapshot_and_is_not_cumulative() {
        let s = ReaperStats::new();
        s.record_block(3, 256);
        let snap = s.snapshot();
        assert_eq!(snap.last_block_reaped, 3);
        assert_eq!(snap.last_block_dead_bytes, 256);
        assert!(
            snap.last_block_unix.is_some(),
            "building a block stamps the timestamp"
        );
        // A quieter subsequent block OVERWRITES (snapshot, not a running sum).
        s.record_block(0, 0);
        let snap = s.snapshot();
        assert_eq!(snap.last_block_reaped, 0);
        assert_eq!(snap.last_block_dead_bytes, 0);
        // A zero-reap block still counts as a built block (timestamp present),
        // so the dashboard shows "0 reaped this block", not "no data".
        assert!(snap.last_block_unix.is_some());
    }

    #[test]
    fn record_block_is_independent_of_cumulative_counters() {
        let s = ReaperStats::new();
        s.record(&corpse_verdict(vec![DeadCodeType::InscriptionEnvelope], 40));
        s.record(&corpse_verdict(vec![DeadCodeType::DropStuffing], 40));
        // Only the latest template reaped a single tx.
        s.record_block(1, 40);
        let snap = s.snapshot();
        // Cumulative untouched by record_block…
        assert_eq!(snap.txs_reaped, 2);
        assert_eq!(snap.dead_bytes_total, 80);
        // …and per-block reflects just the latest template.
        assert_eq!(snap.last_block_reaped, 1);
        assert_eq!(snap.last_block_dead_bytes, 40);
    }

    #[test]
    fn cumulative_across_calls() {
        let s = ReaperStats::new();
        s.record(&ReaperVerdict::accept());
        s.record(&ReaperVerdict::accept());
        s.record(&corpse_verdict(vec![DeadCodeType::OversizedOpReturn], 80));
        s.record(&corpse_verdict(vec![DeadCodeType::OversizedOpReturn], 80));
        let snap = s.snapshot();
        assert_eq!(snap.txs_evaluated, 4);
        assert_eq!(snap.txs_accepted, 2);
        assert_eq!(snap.txs_reaped, 2);
        assert_eq!(snap.dead_bytes_total, 160);
        assert_eq!(snap.by_type.oversized_op_return, 2);
    }
}
