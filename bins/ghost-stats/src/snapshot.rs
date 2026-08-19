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
//| FILE: bins/ghost-stats/src/snapshot.rs                                                                               |

//! The shared snapshot: the single thing this service exists to hold.
//!
//! The contract is one sentence: **a section is only ever replaced by a better one, never emptied
//! by a failure.** A refresh that fails leaves the previous answer in place and says so through
//! `updated_at`, so the page shows data that is a few minutes old rather than a blank tile. That is
//! the whole point of moving the fan-out server-side, so it is enforced here in one place instead of
//! being re-derived by each caller.
//!
//! The snapshot is mirrored to disk on every update and reloaded at startup. Without that, a
//! service restart would serve empty sections until the first cycle finished -- reintroducing
//! exactly the blank-while-loading behaviour this service removes, at the worst possible moment.

use crate::merge::{LeaderboardMerged, PayoutMerged, StatusSummary};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One refreshable section, with the provenance a caller needs to judge it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section<T> {
    pub data: T,
    /// When this section last successfully refreshed (unix seconds).
    pub updated_at: u64,
    /// How many nodes contributed to it, out of how many were asked.
    pub ok_nodes: usize,
    pub total_nodes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub status: Option<Section<StatusSummary>>,
    pub payout: Option<Section<PayoutMerged>>,
    /// Latched best record per window, keyed `block` | `day` | `week` | `month`.
    #[serde(default)]
    pub records: BTreeMap<String, Option<serde_json::Value>>,
    #[serde(default)]
    pub records_updated: BTreeMap<String, u64>,
    /// Keyed `<category>:<window>`, e.g. `best_hash:day`, `shares:lifetime`.
    #[serde(default)]
    pub leaderboards: BTreeMap<String, Section<LeaderboardMerged>>,
    /// When any section last refreshed.
    #[serde(default)]
    pub generated_at: u64,
}

impl Snapshot {
    /// True once at least one section has ever loaded.
    ///
    /// The page uses this to distinguish "still warming up" from "everything is fine but the pool
    /// genuinely has no miners", which look identical in the payload alone.
    pub fn ready(&self) -> bool {
        self.status.is_some()
            || self.payout.is_some()
            || !self.leaderboards.is_empty()
            || self.records.values().any(|r| r.is_some())
    }
}

#[derive(Clone)]
pub struct SharedSnapshot {
    inner: Arc<RwLock<Snapshot>>,
    path: Arc<String>,
}

impl SharedSnapshot {
    /// Load the previous snapshot from disk if there is a readable one.
    ///
    /// A missing or corrupt file is not an error: it means a cold start, and the first refresh
    /// cycle will fill it. Warn rather than fail, because refusing to start over an unreadable
    /// cache would take the page down to protect a performance optimisation.
    pub fn load_or_empty(path: &str) -> Self {
        let snap = match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<Snapshot>(&raw) {
                Ok(s) => {
                    tracing::info!(
                        path,
                        age_secs = now_secs().saturating_sub(s.generated_at),
                        "restored snapshot from disk"
                    );
                    s
                }
                Err(e) => {
                    tracing::warn!(path, error = %e, "snapshot file unreadable — starting cold");
                    Snapshot::default()
                }
            },
            Err(e) => {
                tracing::info!(path, error = %e, "no snapshot on disk — starting cold");
                Snapshot::default()
            }
        };
        Self {
            inner: Arc::new(RwLock::new(snap)),
            path: Arc::new(path.to_string()),
        }
    }

    pub async fn read(&self) -> Snapshot {
        self.inner.read().await.clone()
    }

    /// Apply a mutation, stamp `generated_at`, and mirror to disk.
    pub async fn update<F: FnOnce(&mut Snapshot)>(&self, f: F) {
        let serialised = {
            let mut guard = self.inner.write().await;
            f(&mut guard);
            guard.generated_at = now_secs();
            serde_json::to_string(&*guard).ok()
        };
        // Write outside the lock: readers must never queue behind disk I/O.
        if let Some(json) = serialised {
            let path = self.path.clone();
            tokio::task::spawn_blocking(move || {
                // Write-then-rename so a crash mid-write cannot leave a truncated file that would
                // silently start the next boot cold.
                let tmp = format!("{path}.tmp");
                if let Some(dir) = std::path::Path::new(path.as_str()).parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Err(e) =
                    std::fs::write(&tmp, json).and_then(|_| std::fs::rename(&tmp, path.as_str()))
                {
                    tracing::warn!(error = %e, "could not persist snapshot");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_snapshot_is_not_ready() {
        assert!(!Snapshot::default().ready());
    }

    #[test]
    fn a_snapshot_with_one_loaded_record_is_ready() {
        let mut s = Snapshot::default();
        s.records.insert(
            "day".into(),
            Some(serde_json::json!({"share_hash": "0000"})),
        );
        assert!(
            s.ready(),
            "one loaded section is enough to stop showing the loading state"
        );
    }

    #[test]
    fn a_snapshot_whose_records_are_all_empty_is_not_ready() {
        let mut s = Snapshot::default();
        s.records.insert("day".into(), None);
        assert!(
            !s.ready(),
            "a present-but-empty window must not count as loaded"
        );
    }

    #[tokio::test]
    async fn a_failed_update_never_empties_an_existing_section() {
        let dir = std::env::temp_dir().join("ghost-stats-test-persist");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("snapshot.json");
        let shared = SharedSnapshot::load_or_empty(path.to_str().unwrap());

        shared
            .update(|s| {
                s.records.insert(
                    "day".into(),
                    Some(serde_json::json!({"share_hash": "0000aa"})),
                );
            })
            .await;

        // A cycle where every node failed: the refresh task simply does not touch the section.
        shared.update(|_s| {}).await;

        let after = shared.read().await;
        assert_eq!(
            after.records["day"].as_ref().unwrap()["share_hash"],
            "0000aa",
            "a failed cycle must leave the previous answer standing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_snapshot_survives_a_restart_via_disk() {
        let dir = std::env::temp_dir().join("ghost-stats-test-restart");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("snapshot.json");
        let p = path.to_str().unwrap();

        let first = SharedSnapshot::load_or_empty(p);
        first
            .update(|s| {
                s.records.insert(
                    "month".into(),
                    Some(serde_json::json!({"share_hash": "0000beef"})),
                );
            })
            .await;
        // The mirror is written on a blocking task; give it a moment to land.
        for _ in 0..50 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let restarted = SharedSnapshot::load_or_empty(p).read().await;
        assert!(restarted.ready(), "a restart must not serve a blank page");
        assert_eq!(
            restarted.records["month"].as_ref().unwrap()["share_hash"],
            "0000beef"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
