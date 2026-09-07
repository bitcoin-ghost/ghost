//! File-backed [`SpendLog`] — the layer that survives a restart.
//!
//! # Why this is not optional
//!
//! A rolling spend limit kept only in memory is bypassed by restarting the
//! service: the total resets and the next window starts empty. That is a
//! cheaper attack than stealing the key the limit exists to bound, so a
//! forgetful implementation is worse than no limit — it reports a protection
//! it does not have.
//!
//! Same shape as [`crate::signing_ledger_file`]: write-temp, fsync, rename,
//! fsync-dir, and a record is durable before the call returns. The caller
//! co-signs immediately afterwards, so a record written lazily is one that can
//! be lost while the signature is already out.
//!
//! # It prunes, and only on write
//!
//! Entries older than the longest window are dropped when the log is rewritten,
//! so the file tracks the window rather than growing forever. Pruning on read
//! would make a read mutate the file, which is the sort of thing that turns a
//! diagnostic `cat` into a data change.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::lock_cosign::SpendLog;

/// One co-signature the quorum has already given.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct Row {
    /// Unix seconds.
    at: u64,
    /// What left the lane.
    sats: u64,
}

/// File-backed [`SpendLog`]. Safe for production use.
#[derive(Debug)]
pub struct FileSpendLog {
    path: PathBuf,
    entries: Vec<Row>,
    /// Entries older than this are dropped on write. Set to the longest window
    /// the policy uses; anything shorter would discard history a longer window
    /// still needs.
    retain_secs: u64,
}

impl FileSpendLog {
    /// Open (or create) the log at `path`, retaining `retain_secs` of history.
    ///
    /// A malformed file is an error rather than an empty log. Starting fresh
    /// would forget every spend in the current window and hand an attacker the
    /// reset they would otherwise have to crash the process for.
    pub fn open(path: impl AsRef<Path>, retain_secs: u64) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str::<Vec<Row>>(&raw).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "spend log at {} is unreadable ({e}); refusing to continue with an \
                         empty one, which would clear the window it exists to enforce",
                        path.display()
                    ),
                )
            })?
        } else {
            Vec::new()
        };
        Ok(Self {
            path,
            entries,
            retain_secs,
        })
    }

    /// How many records are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn flush(&self) -> std::io::Result<()> {
        let body = serde_json::to_vec_pretty(&self.entries).map_err(std::io::Error::other)?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&body)?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = fs::metadata(&tmp)?.permissions();
            perm.set_mode(0o600);
            fs::set_permissions(&tmp, perm)?;
        }
        fs::rename(&tmp, &self.path)?;
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

impl SpendLog for FileSpendLog {
    fn total_since(&self, since_secs: u64) -> u64 {
        self.entries
            .iter()
            .filter(|r| r.at >= since_secs)
            .map(|r| r.sats)
            .sum()
    }

    /// Record durably before returning.
    ///
    /// A failed write is an error, not a warning. Returning `Ok` on an
    /// unpersisted record would let the caller co-sign a spend the window has
    /// no memory of — which is the reset case, one restart later.
    fn record(&mut self, at_secs: u64, sats: u64) -> Result<(), String> {
        let cutoff = at_secs.saturating_sub(self.retain_secs);
        let before = std::mem::take(&mut self.entries);
        self.entries = before.into_iter().filter(|r| r.at >= cutoff).collect();
        self.entries.push(Row { at: at_secs, sats });
        if let Err(e) = self.flush() {
            self.entries.pop();
            return Err(format!(
                "could not record the spend at {} ({e}); refusing to co-sign, because a \
                 spend the window cannot see is one it will allow again",
                self.path.display()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spends.json");
        {
            let mut log = FileSpendLog::open(&path, 86_400).unwrap();
            log.record(1_000, 50_000).unwrap();
        }
        // The restart the volatile log cannot survive.
        let reopened = FileSpendLog::open(&path, 86_400).unwrap();
        assert_eq!(
            reopened.total_since(0),
            50_000,
            "a restart must not clear the window"
        );
    }

    #[test]
    fn the_window_only_counts_what_is_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = FileSpendLog::open(dir.path().join("s.json"), 86_400).unwrap();
        log.record(1_000, 10_000).unwrap();
        log.record(5_000, 20_000).unwrap();
        assert_eq!(log.total_since(0), 30_000);
        assert_eq!(log.total_since(2_000), 20_000, "the older spend is outside");
    }

    /// Old entries are dropped, so the file tracks the window rather than
    /// growing without limit.
    #[test]
    fn entries_older_than_the_retention_are_pruned_on_write() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = FileSpendLog::open(dir.path().join("s.json"), 3_600).unwrap();
        log.record(1_000, 10_000).unwrap();
        log.record(10_000, 20_000).unwrap();
        assert_eq!(log.len(), 1, "the first entry is far outside the retention");
        assert_eq!(log.total_since(0), 20_000);
    }

    /// A corrupt log must not read as an empty one.
    #[test]
    fn a_corrupt_log_is_refused_not_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        fs::write(&path, "{ not json").unwrap();
        let err = FileSpendLog::open(&path, 86_400).expect_err("must refuse");
        assert!(
            format!("{err}").contains("refusing to continue with an empty one"),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.json");
        let mut log = FileSpendLog::open(&path, 86_400).unwrap();
        log.record(1, 1).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
