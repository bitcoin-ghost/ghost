//! Durable backing for the once-per-coin rule.
//!
//! `wraith_protocol::signing_ledger` states the contract plainly: `record` must
//! not return until the authorisation is durable. `VolatileStore` is named to be
//! uncomfortable to type in production because a ledger that forgets is worse
//! than none — it reports a guarantee it stops providing the moment the process
//! restarts.
//!
//! # What the rule buys
//!
//! A coin signed into two rounds double-spends itself. One of those rounds dies
//! at broadcast, and every other participant in it loses their round through no
//! fault of their own — and, once the no-sign sweep runs, has their coin put in
//! cooldown for it.
//!
//! The wallet is the only party that can prevent it, because it is the only one
//! that knows it is about to sign the same coin twice.
//!
//! # Why the writes look paranoid
//!
//! A crash between "signed" and "recorded" is exactly the window the rule exists
//! to close, so the record is written **before** the signature is produced, and
//! is fsynced before the call returns. Write-temp, fsync, rename, fsync-dir is
//! the sequence that survives power loss on the filesystems this runs on;
//! skipping the directory fsync leaves the rename itself unpersisted.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use wraith_protocol::signing_ledger::{OutPointKey, SignatureStore};

/// File-backed [`SignatureStore`]. Safe for production use.
#[derive(Debug)]
pub struct FileSignatureStore {
    path: PathBuf,
    /// Mirror of the file, so reads do not hit the disk on every check.
    entries: HashMap<OutPointKey, [u8; 32]>,
}

/// On-disk row. Hex so the file stays readable by a human diagnosing an
/// equivocation — the one moment somebody will be reading it by hand.
#[derive(serde::Serialize, serde::Deserialize)]
struct Row {
    txid: String,
    vout: u32,
    spending_txid: String,
}

impl FileSignatureStore {
    /// Open (or create) the ledger at `path`.
    ///
    /// A malformed file is an error rather than an empty ledger. Starting fresh
    /// would silently drop every recorded authorisation and re-permit exactly
    /// the double-signs this exists to refuse.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let rows: Vec<Row> = serde_json::from_str(&raw).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "signing ledger at {} is unreadable ({e}); refusing to \
                         continue with an empty one, which would re-permit \
                         every double-sign it has already refused",
                        path.display()
                    ),
                )
            })?;
            let mut map = HashMap::with_capacity(rows.len());
            for r in rows {
                let (Some(txid), Some(spending)) = (decode32(&r.txid), decode32(&r.spending_txid))
                else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("signing ledger row has a malformed hash: {}", r.txid),
                    ));
                };
                map.insert(OutPointKey::new(txid, r.vout), spending);
            }
            map
        } else {
            HashMap::new()
        };
        Ok(Self { path, entries })
    }

    /// Persist the whole table, durably.
    ///
    /// Rewrites rather than appends: the file is small (one row per coin this
    /// wallet has ever mixed) and a rewrite-and-rename is atomic, where an
    /// append can leave a half-written row that fails the strict parse above.
    fn flush(&self) -> std::io::Result<()> {
        let rows: Vec<Row> = self
            .entries
            .iter()
            .map(|(k, v)| Row {
                txid: hex::encode(k.txid),
                vout: k.vout,
                spending_txid: hex::encode(v),
            })
            .collect();
        let body = serde_json::to_vec_pretty(&rows)?;

        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&body)?;
            // Contents before the rename, or the rename can land pointing at an
            // empty file.
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;

        // The rename itself is metadata and needs its own sync, or a power loss
        // here leaves the old file in place and the authorisation lost.
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

fn decode32(hexstr: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(hexstr).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Some(out)
}

impl SignatureStore for FileSignatureStore {
    fn signed_txid(&self, coin: &OutPointKey) -> Option<[u8; 32]> {
        self.entries.get(coin).copied()
    }

    /// # Panics
    ///
    /// If the write fails. The trait says this must not return until the record
    /// is durable, and there is no honest way to signal failure through a
    /// `()` return — carrying on would report a guarantee that is no longer
    /// being provided, which is the failure this whole module exists to
    /// prevent. Failing loudly at the moment of the write is the lesser harm,
    /// and the caller has not signed anything yet.
    fn record(&mut self, coin: OutPointKey, spending_txid: [u8; 32]) {
        self.entries.insert(coin, spending_txid);
        if let Err(e) = self.flush() {
            panic!(
                "signing ledger at {} could not be persisted: {e}. Refusing to \
                 continue, because an unrecorded authorisation permits the same \
                 coin to be signed into a second round after a restart.",
                self.path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wraith_protocol::signing_ledger::{Decision, LedgerError, SigningLedger};

    fn coin(b: u8) -> OutPointKey {
        OutPointKey::new([b; 32], 0)
    }

    #[test]
    fn an_authorisation_survives_a_restart() {
        // The whole point. A ledger that forgets on restart re-permits exactly
        // the double-sign it refused a moment earlier.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.json");

        {
            let mut l = SigningLedger::new(FileSignatureStore::open(&path).unwrap());
            assert_eq!(l.authorise(coin(1), [9; 32]), Ok(Decision::Sign));
        }

        let mut reopened = SigningLedger::new(FileSignatureStore::open(&path).unwrap());
        assert_eq!(
            reopened.authorise(coin(1), [7; 32]),
            Err(LedgerError::Conflict {
                existing_txid: [9; 32]
            }),
            "a restart must not forget"
        );
    }

    #[test]
    fn retrying_the_same_round_is_allowed_after_a_restart() {
        // A wallet that crashed mid-round must be able to finish it. Only a
        // DIFFERENT spending txid is a conflict.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.json");
        {
            let mut l = SigningLedger::new(FileSignatureStore::open(&path).unwrap());
            assert_eq!(l.authorise(coin(2), [4; 32]), Ok(Decision::Sign));
        }
        let mut reopened = SigningLedger::new(FileSignatureStore::open(&path).unwrap());
        assert_eq!(
            reopened.authorise(coin(2), [4; 32]),
            Ok(Decision::AlreadyCommitted)
        );
    }

    #[test]
    fn a_corrupt_ledger_is_an_error_not_a_fresh_start() {
        // Starting fresh would drop every recorded authorisation and re-permit
        // every double-sign already refused. Loud beats convenient.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.json");
        fs::write(&path, b"{ this is not the ledger }").unwrap();
        let err = FileSignatureStore::open(&path).expect_err("must refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(format!("{err}").contains("re-permit"), "{err}");
    }

    #[test]
    fn a_row_with_a_malformed_hash_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.json");
        fs::write(&path, br#"[{"txid":"abcd","vout":0,"spending_txid":"ef"}]"#).unwrap();
        assert!(FileSignatureStore::open(&path).is_err());
    }

    #[test]
    fn an_absent_file_opens_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mut l =
            SigningLedger::new(FileSignatureStore::open(dir.path().join("new.json")).unwrap());
        assert_eq!(l.authorise(coin(3), [1; 32]), Ok(Decision::Sign));
    }

    #[test]
    fn distinct_coins_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.json");
        let mut l = SigningLedger::new(FileSignatureStore::open(&path).unwrap());
        assert_eq!(l.authorise(coin(1), [9; 32]), Ok(Decision::Sign));
        assert_eq!(l.authorise(coin(2), [9; 32]), Ok(Decision::Sign));
        // Same txid, different vout, is a different coin.
        assert_eq!(
            l.authorise(OutPointKey::new([1u8; 32], 1), [9; 32]),
            Ok(Decision::Sign)
        );
    }
}
