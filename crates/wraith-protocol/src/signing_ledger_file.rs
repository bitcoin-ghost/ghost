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
//!
//! # Concurrency
//!
//! Writes go through [`ghost_lock::atomic_file`], which stages each one
//! through a path private to it, so concurrent writers on one ledger file
//! cannot truncate or unlink each other's staging file.
//!
//! That is the limit of what this type guarantees. `record` rewrites the whole
//! table from the snapshot [`FileSignatureStore::open`] read, so two stores
//! opened on the same path before either wrote will each persist a table
//! missing the other's row — a lost authorisation, which is precisely the
//! failure the once-per-coin rule exists to prevent. **A caller that opens a
//! store per operation must serialise open-through-record itself**, so the
//! read-modify-write is atomic. `wraithd` does this with a daemon-wide lock.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::signing_ledger::{OutPointKey, SignatureStore};

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
        // 0o600: the ledger names every coin this wallet has authorised.
        ghost_lock::atomic_file::write_atomic(&self.path, &body, Some(0o600))
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
    use crate::signing_ledger::{Decision, LedgerError, SigningLedger};

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

    /// Concurrent writers on one ledger path must not destroy each other.
    ///
    /// This is a regression test for a real failure: `flush` staged every
    /// write through a single fixed `.tmp` sibling, so racing writers
    /// truncated each other's staging file and the loser's rename failed with
    /// `ENOENT` — which `record` turns into a panic. Ten concurrent mixes in
    /// one wallet daemon reproduced it every run.
    ///
    /// Lost updates are *not* asserted against here: this layer does not
    /// promise them (see the module docs). What it promises is that no writer
    /// panics and the file is always parseable afterwards.
    #[test]
    fn concurrent_writers_neither_panic_nor_corrupt_the_file() {
        let dir = std::env::temp_dir().join(format!(
            "wraith-ledger-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("signed-coins.json");

        let threads: Vec<_> = (0..10u8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut store = FileSignatureStore::open(&path).expect("open");
                    store.record(coin(i), [i; 32]);
                })
            })
            .collect();
        for (i, t) in threads.into_iter().enumerate() {
            t.join().unwrap_or_else(|_| {
                panic!("writer {i} panicked — the ledger write is not race-safe")
            });
        }

        // Whatever survived, the file must still parse. A store that refuses
        // to open here would strand the wallet: `open` treats a malformed
        // ledger as fatal rather than starting empty.
        let reopened = FileSignatureStore::open(&path).expect("ledger is parseable after the race");
        assert!(
            !reopened.entries.is_empty(),
            "every concurrent write was lost"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
