//! The wallet's own record of what it has done.
//!
//! # Why this exists
//!
//! Transaction history came from the GSP session — the operator kept the
//! ledger and the wallet asked. Ghost Pay is being removed, so the wallet has
//! to remember for itself, and it has nowhere to remember *to*: the daemon has
//! never had local storage of any kind.
//!
//! # Two writers
//!
//! Entries arrive from two places and meet on the txid. A broadcast writes one
//! the moment the node accepts it, knowing the memo and the exact fee. The
//! block scanner writes one when it sees the transaction mined, knowing the
//! height and the block time. Neither knows what the other knows, so
//! [`HistoryStore::record`] merges rather than replaces: a field the newcomer
//! left empty keeps the value already there.
//!
//! Getting that wrong is not an abstract concern — the scanner runs after
//! every broadcast, so a replacing write would erase the memo and the fee on
//! every payment the wallet made, a few minutes after making it.
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
    /// When it happened, unix seconds: the block time once it is mined, and
    /// the moment of broadcast until then.
    ///
    /// The alias keeps files written before incoming payments were recorded
    /// readable — back then every entry was a broadcast, so the name was
    /// accurate and is now too narrow.
    #[serde(alias = "broadcast_at")]
    pub at: i64,
    /// The block it was mined in. `None` while it is unconfirmed — which is
    /// distinct from height zero, and is why a caller must not compute
    /// confirmations by subtracting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,
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
    /// What happened: `receive`, `send`, `lock_fund`, `lock_escape`, `mix`.
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

    /// Every entry, newest first.
    pub fn list(&self) -> Vec<HistoryEntry> {
        let mut all: Vec<HistoryEntry> = self.entries.values().cloned().collect();
        // Tie-broken by txid so the order is stable across calls. Two
        // transactions in one block share a timestamp, and a list that
        // reshuffles between refreshes is a list nobody can point at.
        all.sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.txid.cmp(&b.txid)));
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

    /// Record what one writer knows about a transaction.
    ///
    /// Keyed by txid, so a transaction seen twice is one entry — a rebroadcast
    /// is the same payment, and showing it twice would read as having paid
    /// twice. Where both writers have something to say, the newcomer wins on
    /// what it actually measured and leaves the rest alone:
    ///
    /// * a confirmed height and block time replace an unconfirmed guess, but
    ///   an entry that is already mined is not un-mined by a later mempool
    ///   sighting;
    /// * a memo, a fee or an amount is never overwritten with `None`, because
    ///   the block scanner cannot see a memo and must not delete one.
    pub fn record(&mut self, entry: HistoryEntry) -> std::io::Result<()> {
        let key = entry.txid.clone();
        let merged = match self.entries.get(&key) {
            None => entry,
            Some(old) => HistoryEntry {
                txid: entry.txid,
                // A mined entry keeps its block time; nothing later is a
                // better answer to "when did this happen".
                at: if old.block_height.is_some() && entry.block_height.is_none() {
                    old.at
                } else {
                    entry.at
                },
                block_height: entry.block_height.or(old.block_height),
                amount_sats: entry.amount_sats.or(old.amount_sats),
                fee_sats: entry.fee_sats.or(old.fee_sats),
                // The broadcast path knows what a spend was *for*
                // (`lock_fund`, `mix`); the scanner only ever sees `send` or
                // `receive`. Keep the more specific label.
                kind: if entry.kind == "send" && old.kind != "send" {
                    old.kind.clone()
                } else {
                    entry.kind
                },
                memo: entry.memo.or_else(|| old.memo.clone()),
            },
        };
        let previous = self.entries.insert(key.clone(), merged);
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

    /// Forget the confirmations of everything mined at `height` or above.
    ///
    /// Called when the scanner finds the chain has moved out from under it.
    /// The entries stay — the wallet really did make those payments, and a
    /// reorg does not unmake a broadcast — but their heights came from blocks
    /// that are no longer in the chain, so keeping them would state a fact
    /// about a chain nobody is on. They go back to unconfirmed and the rescan
    /// re-confirms whichever ones survived.
    ///
    /// Returns how many entries were affected.
    pub fn unconfirm_from(&mut self, height: u32) -> std::io::Result<usize> {
        let affected: Vec<String> = self
            .entries
            .values()
            .filter(|e| e.block_height.is_some_and(|h| h >= height))
            .map(|e| e.txid.clone())
            .collect();
        if affected.is_empty() {
            return Ok(0);
        }
        let snapshot = self.entries.clone();
        for txid in &affected {
            if let Some(e) = self.entries.get_mut(txid) {
                e.block_height = None;
            }
        }
        if let Err(e) = self.flush() {
            self.entries = snapshot;
            return Err(e);
        }
        Ok(affected.len())
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
            at,
            block_height: None,
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
        assert_eq!(h.list()[0].at, 200);
    }

    /// The scanner sees every payment the wallet made, a few minutes after it
    /// made it. If its write replaced rather than merged, every memo and every
    /// measured fee would quietly disappear on confirmation.
    #[test]
    fn confirming_a_broadcast_keeps_what_only_the_broadcast_knew() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = HistoryStore::open(dir.path().join("h.json")).unwrap();
        h.record(HistoryEntry {
            txid: "aa".into(),
            at: 100,
            block_height: None,
            amount_sats: Some(-50_500),
            fee_sats: Some(500),
            kind: "lock_fund".into(),
            memo: Some("rent".into()),
        })
        .unwrap();
        // What the block scanner knows, and only that.
        h.record(HistoryEntry {
            txid: "aa".into(),
            at: 900,
            block_height: Some(900_001),
            amount_sats: Some(-50_500),
            fee_sats: None,
            kind: "send".into(),
            memo: None,
        })
        .unwrap();

        let e = &h.list()[0];
        assert_eq!(e.block_height, Some(900_001), "the height is news");
        assert_eq!(
            e.at, 900,
            "the block time dates it better than the broadcast"
        );
        assert_eq!(e.memo.as_deref(), Some("rent"), "the memo must survive");
        assert_eq!(e.fee_sats, Some(500), "the measured fee must survive");
        assert_eq!(
            e.kind, "lock_fund",
            "the specific label beats the generic one"
        );
    }

    /// A mempool sighting after confirmation must not un-mine the entry.
    #[test]
    fn a_later_unconfirmed_sighting_does_not_clear_the_height() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = HistoryStore::open(dir.path().join("h.json")).unwrap();
        let mut mined = entry("aa", 100, -1_000);
        mined.block_height = Some(900_000);
        mined.at = 500;
        h.record(mined).unwrap();
        h.record(entry("aa", 900, -1_000)).unwrap();

        let e = &h.list()[0];
        assert_eq!(e.block_height, Some(900_000));
        assert_eq!(e.at, 500, "a confirmed entry keeps its block time");
    }

    /// A reorg unmakes a confirmation, never the entry. The payment still
    /// happened; what changed is the chain it was mined into.
    #[test]
    fn a_reorg_unconfirms_without_deleting() {
        let dir = tempfile::tempdir().unwrap();
        let mut h = HistoryStore::open(dir.path().join("h.json")).unwrap();
        for (txid, height) in [
            ("old", 899_998u32),
            ("forked", 900_001),
            ("deeper", 900_005),
        ] {
            let mut e = entry(txid, 1, -1_000);
            e.block_height = Some(height);
            h.record(e).unwrap();
        }
        let n = h.unconfirm_from(900_000).unwrap();
        assert_eq!(n, 2, "both entries at or above the fork");

        let by_txid: std::collections::HashMap<_, _> =
            h.list().into_iter().map(|e| (e.txid.clone(), e)).collect();
        assert_eq!(by_txid.len(), 3, "nothing is deleted");
        assert_eq!(
            by_txid["old"].block_height,
            Some(899_998),
            "a block below the fork is untouched"
        );
        assert_eq!(by_txid["forked"].block_height, None);
        assert_eq!(by_txid["deeper"].block_height, None);
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
