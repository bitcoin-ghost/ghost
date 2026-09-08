//! The wallet's own record of what it has done.
//!
//! # Why this exists
//!
//! Transaction history came from the GSP session — the operator kept the
//! ledger and the wallet asked. Ghost Pay is being removed, so the wallet has
//! to remember for itself, and it has nowhere to remember *to*: the daemon has
//! never had local storage of any kind.
//!
//! # What it can and cannot know
//!
//! It records what the wallet **did**: every transaction it broadcast, with
//! what that spend was for. It does not index the chain, so it cannot show a
//! payment that arrived while it was not looking — incoming coins surface in
//! the balance and UTXO scan instead, which is where they actually live.
//!
//! That is a real limitation and stating it is better than an empty list that
//! looks like "no transactions". A history that silently omits half the story
//! is worse than one that says which half it keeps.
//!
//! # Durability
//!
//! Same shape as the other stores: write-temp, fsync, rename, fsync-dir, mode
//! 0600. A history entry is not money, so a lost write costs a record rather
//! than a coin — but the record is written *before* the broadcast is reported,
//! because the case that matters is a crash between sending and remembering.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// One thing the wallet did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryEntry {
    pub txid: String,
    /// Unix seconds the wallet broadcast it.
    pub broadcast_at: i64,
    /// Net change to the wallet, negative for a spend.
    ///
    /// `None` when the wallet could not work it out — broadcasting a finished
    /// PSBT does not require an unlocked wallet, and without the keys there is
    /// no way to tell which outputs are ours. `None` and `Some(0)` are
    /// different facts and are kept apart: one is "not recorded", the other is
    /// "moved nothing".
    pub amount_sats: Option<i64>,
    /// Miner fee, when the wallet built the transaction and therefore knows it.
    pub fee_sats: Option<u64>,
    /// What kind of spend: `send`, `lock_fund`, `lock_escape`, `mix`.
    pub kind: String,
    pub memo: Option<String>,
}

/// A JSON file of [`HistoryEntry`], keyed by txid.
#[derive(Debug)]
pub struct HistoryStore {
    path: PathBuf,
    entries: BTreeMap<String, HistoryEntry>,
}

impl HistoryStore {
    /// Open (or create) the history at `path`.
    ///
    /// A malformed file is an error rather than an empty history. Silently
    /// starting fresh would present "you have never sent anything" as a fact,
    /// and somebody checking whether a payment went out would believe it.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let rows: Vec<HistoryEntry> = serde_json::from_str(&raw).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "history at {} is unreadable ({e}); refusing to continue with an \
                         empty one, which would read as 'you have never sent anything'",
                        path.display()
                    ),
                )
            })?;
            rows.into_iter().map(|r| (r.txid.clone(), r)).collect()
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, entries })
    }

    /// Every entry, newest broadcast first.
    pub fn list(&self) -> Vec<HistoryEntry> {
        let mut all: Vec<HistoryEntry> = self.entries.values().cloned().collect();
        all.sort_by_key(|e| std::cmp::Reverse(e.broadcast_at));
        all
    }

    /// How many are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a broadcast.
    ///
    /// Keyed by txid, so re-recording one transaction updates rather than
    /// duplicates it — a rebroadcast is the same payment, and showing it twice
    /// would read as having paid twice.
    pub fn record(&mut self, entry: HistoryEntry) -> std::io::Result<()> {
        let key = entry.txid.clone();
        let previous = self.entries.insert(key.clone(), entry);
        if let Err(e) = self.flush() {
            match previous {
                Some(p) => {
                    self.entries.insert(key, p);
                }
                None => {
                    self.entries.remove(&key);
                }
            }
            return Err(e);
        }
        Ok(())
    }

    fn flush(&self) -> std::io::Result<()> {
        let rows: Vec<&HistoryEntry> = self.entries.values().collect();
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

    fn entry(txid: &str, at: i64, sats: i64) -> HistoryEntry {
        HistoryEntry {
            txid: txid.into(),
            broadcast_at: at,
            amount_sats: Some(sats),
            fee_sats: Some(500),
            kind: "send".into(),
            memo: None,
        }
    }

    #[test]
    fn a_record_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.json");
        {
            let mut h = HistoryStore::open(&path).unwrap();
            h.record(entry("aa", 100, -1_000)).unwrap();
        }
        let h = HistoryStore::open(&path).unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(h.list()[0].amount_sats, Some(-1_000));
    }

    /// Newest first — a history that starts at the beginning buries the thing
    /// somebody just did.
    #[test]
    fn entries_come_back_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = HistoryStore::open(dir.path().join("h.json")).unwrap();
        h.record(entry("old", 100, -1)).unwrap();
        h.record(entry("new", 900, -2)).unwrap();
        let list = h.list();
        assert_eq!(list[0].txid, "new");
    }

    /// A rebroadcast is the same payment, not a second one.
    #[test]
    fn recording_one_txid_twice_updates_rather_than_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = HistoryStore::open(dir.path().join("h.json")).unwrap();
        h.record(entry("aa", 100, -1_000)).unwrap();
        h.record(entry("aa", 200, -1_000)).unwrap();
        assert_eq!(h.len(), 1, "one transaction is one history entry");
        assert_eq!(h.list()[0].broadcast_at, 200);
    }

    /// A corrupt file must not read as "you have never sent anything".
    #[test]
    fn a_corrupt_history_is_refused_not_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        fs::write(&path, "{ not json").unwrap();
        let err = HistoryStore::open(&path).expect_err("must refuse");
        assert!(
            format!("{err}").contains("never sent anything"),
            "the error must say what the empty reading would imply: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_history_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.json");
        let mut h = HistoryStore::open(&path).unwrap();
        h.record(entry("aa", 1, -1)).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a spending history is private");
    }
}
