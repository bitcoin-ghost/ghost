//! How far the block scanner has read.
//!
//! Two fields, and the second is the one that matters: the hash of the last
//! block scanned. A height alone cannot tell you whether the chain you read is
//! still the chain that exists. After a reorg the same height holds a
//! different block, and a scanner that trusted the number would carry on from
//! a fork it had already left, never noticing that some of what it recorded
//! never happened.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The last block the scanner processed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanPoint {
    pub height: u32,
    pub hash: String,
}

/// A JSON file holding one [`ScanPoint`].
#[derive(Debug)]
pub struct ScanState {
    path: PathBuf,
    point: Option<ScanPoint>,
}

impl ScanState {
    /// Open (or create) the scan state at `path`.
    ///
    /// A malformed file resets to "never scanned" rather than erroring. Unlike
    /// the history, nothing here is a record of something that happened — it
    /// is a bookmark, and the cost of losing it is re-reading blocks, not
    /// losing a fact. Refusing to start over a corrupt bookmark would take the
    /// wallet down for the cheapest possible reason.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let point = fs::read_to_string(&path).ok().and_then(|raw| {
            match serde_json::from_str::<ScanPoint>(&raw) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "scan bookmark unreadable; starting again from the tip"
                    );
                    None
                }
            }
        });
        Ok(Self { path, point })
    }

    /// Where the scanner got to, or `None` if it has never run.
    pub fn point(&self) -> Option<&ScanPoint> {
        self.point.as_ref()
    }

    /// Record progress, durably.
    pub fn set(&mut self, height: u32, hash: impl Into<String>) -> std::io::Result<()> {
        let next = ScanPoint {
            height,
            hash: hash.into(),
        };
        let previous = self.point.replace(next);
        if let Err(e) = self.flush() {
            self.point = previous;
            return Err(e);
        }
        Ok(())
    }

    fn flush(&self) -> std::io::Result<()> {
        let Some(p) = self.point.as_ref() else {
            return Ok(());
        };
        let body = serde_json::to_vec_pretty(p).map_err(std::io::Error::other)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bookmark_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.json");
        {
            let mut s = ScanState::open(&path).unwrap();
            s.set(900_123, "abcd").unwrap();
        }
        let s = ScanState::open(&path).unwrap();
        assert_eq!(s.point().unwrap().height, 900_123);
        assert_eq!(s.point().unwrap().hash, "abcd");
    }

    #[test]
    fn a_fresh_wallet_has_never_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let s = ScanState::open(dir.path().join("scan.json")).unwrap();
        assert!(s.point().is_none());
    }

    /// A corrupt bookmark costs re-reading, not an outage. This is the
    /// opposite call from the history, where a corrupt file is refused —
    /// there, silence would be mistaken for a fact.
    #[test]
    fn a_corrupt_bookmark_starts_over_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.json");
        fs::write(&path, "{ not json").unwrap();
        let s = ScanState::open(&path).expect("must still open");
        assert!(s.point().is_none());
    }
}
