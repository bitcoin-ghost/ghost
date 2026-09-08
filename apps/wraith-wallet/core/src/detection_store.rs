//! Silent payments the wallet has found.
//!
//! # Why these are not just history entries
//!
//! A silent payment does not land on an address the wallet derived. It lands
//! on a key built from the sender's ephemeral key and the receiver's Ghost ID,
//! at a derivation index `k` only the scan can recover. Lose `k` and the coin
//! is still yours in principle and unspendable in practice — the key that
//! opens it cannot be re-derived without re-scanning the block it arrived in.
//!
//! So the detection is kept, not merely reported. The history entry beside it
//! says money arrived; this says which coin, and how to get at it.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::candidate_scan::DetectedPayment;

/// A JSON file of [`DetectedPayment`], keyed by outpoint.
#[derive(Debug)]
pub struct DetectionStore {
    path: PathBuf,
    entries: BTreeMap<String, DetectedPayment>,
}

fn key_for(d: &DetectedPayment) -> String {
    format!("{}:{}", d.txid, d.vout)
}

impl DetectionStore {
    /// Open (or create) the detections at `path`.
    ///
    /// A malformed file is an error, not an empty store. These are spending
    /// keys in all but name; starting fresh would report "no silent payments"
    /// about coins that exist, and the wallet would have no way to know it had
    /// forgotten them.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let rows: Vec<DetectedPayment> = serde_json::from_str(&raw).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "detections at {} are unreadable ({e}); refusing to continue with an \
                         empty set, which would hide coins the wallet cannot otherwise find",
                        path.display()
                    ),
                )
            })?;
            rows.into_iter().map(|r| (key_for(&r), r)).collect()
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, entries })
    }

    /// Every detection, newest first.
    pub fn list(&self) -> Vec<DetectedPayment> {
        let mut all: Vec<DetectedPayment> = self.entries.values().cloned().collect();
        all.sort_by(|a, b| {
            b.block_height
                .cmp(&a.block_height)
                .then_with(|| a.txid.cmp(&b.txid))
                .then_with(|| a.vout.cmp(&b.vout))
        });
        all
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record detections, keyed by outpoint.
    ///
    /// Re-scanning a block — after a reorg, or a restart mid-catch-up — finds
    /// the same coins again. One outpoint is one coin, so this is idempotent
    /// rather than accumulating duplicates that would each read as money.
    ///
    /// Returns how many were new.
    pub fn record_all(&mut self, found: Vec<DetectedPayment>) -> std::io::Result<usize> {
        if found.is_empty() {
            return Ok(0);
        }
        let snapshot = self.entries.clone();
        let mut added = 0;
        for d in found {
            if self.entries.insert(key_for(&d), d).is_none() {
                added += 1;
            }
        }
        if added == 0 && self.entries == snapshot {
            return Ok(0);
        }
        if let Err(e) = self.flush() {
            self.entries = snapshot;
            return Err(e);
        }
        Ok(added)
    }

    fn flush(&self) -> std::io::Result<()> {
        let rows: Vec<&DetectedPayment> = self.entries.values().collect();
        let body = serde_json::to_vec_pretty(&rows).map_err(std::io::Error::other)?;
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

    fn found(txid: &str, vout: u32, k: u32, height: Option<u32>) -> DetectedPayment {
        DetectedPayment {
            txid: txid.into(),
            block_height: height,
            vout,
            amount_sats: Some(50_000),
            k,
            received_at: 1_700_000_000,
        }
    }

    #[test]
    fn a_detection_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("detections.json");
        {
            let mut d = DetectionStore::open(&path).unwrap();
            assert_eq!(
                d.record_all(vec![found("aa", 2, 0, Some(900_000))])
                    .unwrap(),
                1
            );
        }
        let d = DetectionStore::open(&path).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d.list()[0].k, 0, "the index that makes it spendable");
        assert_eq!(d.list()[0].vout, 2);
    }

    /// Rescanning a block after a reorg or a restart finds the same coins.
    /// One outpoint is one coin.
    #[test]
    fn rescanning_does_not_duplicate_a_coin() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = DetectionStore::open(dir.path().join("d.json")).unwrap();
        d.record_all(vec![found("aa", 2, 0, Some(900_000))])
            .unwrap();
        let added = d
            .record_all(vec![found("aa", 2, 0, Some(900_000))])
            .unwrap();
        assert_eq!(added, 0, "already known");
        assert_eq!(d.len(), 1);
    }

    /// Two outputs of one transaction are two coins, not one seen twice.
    #[test]
    fn two_outputs_of_one_transaction_are_two_coins() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = DetectionStore::open(dir.path().join("d.json")).unwrap();
        d.record_all(vec![
            found("aa", 1, 0, Some(900_000)),
            found("aa", 2, 1, Some(900_000)),
        ])
        .unwrap();
        assert_eq!(d.len(), 2);
    }

    /// Losing these silently would hide coins nothing else can find.
    #[test]
    fn a_corrupt_file_is_refused_not_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.json");
        fs::write(&path, "{ not json").unwrap();
        let err = DetectionStore::open(&path).expect_err("must refuse");
        assert!(format!("{err}").contains("hide coins"), "got: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn the_detections_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.json");
        let mut d = DetectionStore::open(&path).unwrap();
        d.record_all(vec![found("aa", 0, 0, None)]).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
