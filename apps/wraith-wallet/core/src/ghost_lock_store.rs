//! Where a Ghost Lock's definition lives.
//!
//! Until now the wallet's Locks screen was the source of truth: the user typed
//! three keys and two heights into a form, and nothing remembered them. That is
//! fine for viewing and useless for anything else — a Lock the wallet cannot
//! name cannot be spent from, migrated to, or listed.
//!
//! # What is stored, and what is not
//!
//! Public keys and two heights. Nothing secret: the owner's key never appears
//! here, because it is derived from the keystore on demand. Losing this file
//! loses convenience, not funds — the lanes are reconstructible from the same
//! three keys and the keystore.
//!
//! That is worth stating precisely, because it is *not* true of the signing
//! ledger next door, where losing the file re-permits a double-sign. These two
//! files sit in the same directory and mean very different things.
//!
//! # Content-addressed, so the same Lock is the same Lock
//!
//! `lock_id` is a hash of the keys and heights rather than a random string.
//! Entering the same Lock twice therefore updates one record instead of
//! creating a second, and a user who re-enters their keys after losing the file
//! gets their Lock back under its original id rather than a stranger.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use bitcoin::hashes::{sha256, Hash};

/// Domain tag for the Lock id. Versioned.
const LOCK_ID_TAG: &str = "ghost-lock/id/v1";

/// A stored Lock definition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredLock {
    /// Content hash of the fields below. Stable for the same Lock.
    pub lock_id: String,
    /// Optional name the user gave it.
    #[serde(default)]
    pub label: Option<String>,
    pub backup_pubkey: String,
    pub heir_pubkey: String,
    pub quorum_pubkey: String,
    pub anchor_height: u32,
    pub inherit_height: u32,
    /// BIP86 index the owner key is derived at.
    pub bip86_index: u32,
}

impl StoredLock {
    /// The id a Lock with these parameters always has.
    ///
    /// Derived from every field that changes the resulting addresses — and from
    /// none that do not. `label` is excluded deliberately: renaming a Lock must
    /// not make it a different Lock.
    pub fn derive_id(
        backup: &str,
        heir: &str,
        quorum: &str,
        anchor_height: u32,
        inherit_height: u32,
        bip86_index: u32,
    ) -> String {
        let mut h = sha256::Hash::engine();
        use bitcoin::hashes::HashEngine;
        h.input(LOCK_ID_TAG.as_bytes());
        for k in [backup, heir, quorum] {
            let k = k.trim().to_ascii_lowercase();
            h.input(&(k.len() as u64).to_be_bytes());
            h.input(k.as_bytes());
        }
        h.input(&anchor_height.to_be_bytes());
        h.input(&inherit_height.to_be_bytes());
        h.input(&bip86_index.to_be_bytes());
        hex::encode(&sha256::Hash::from_engine(h).to_byte_array()[..16])
    }

    /// Build a record, computing its id.
    pub fn new(
        label: Option<String>,
        backup_pubkey: String,
        heir_pubkey: String,
        quorum_pubkey: String,
        anchor_height: u32,
        inherit_height: u32,
        bip86_index: u32,
    ) -> Self {
        let lock_id = Self::derive_id(
            &backup_pubkey,
            &heir_pubkey,
            &quorum_pubkey,
            anchor_height,
            inherit_height,
            bip86_index,
        );
        Self {
            lock_id,
            label,
            backup_pubkey,
            heir_pubkey,
            quorum_pubkey,
            anchor_height,
            inherit_height,
            bip86_index,
        }
    }
}

/// File-backed store of Lock definitions.
#[derive(Debug)]
pub struct GhostLockStore {
    path: PathBuf,
    locks: BTreeMap<String, StoredLock>,
}

impl GhostLockStore {
    /// Open (or create) the store.
    ///
    /// A malformed file is an error rather than an empty store. Silently
    /// starting fresh would hide every Lock the user has, and they would find
    /// out by their balances reading zero — which looks exactly like being
    /// robbed.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let locks = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let list: Vec<StoredLock> = serde_json::from_str(&raw).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Ghost Lock store at {} is unreadable ({e}); refusing to \
                         start empty, because that would hide every Lock and read \
                         to the user as their money having vanished",
                        path.display()
                    ),
                )
            })?;
            list.into_iter().map(|l| (l.lock_id.clone(), l)).collect()
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, locks })
    }

    /// Every stored Lock, in a stable order.
    pub fn list(&self) -> Vec<StoredLock> {
        self.locks.values().cloned().collect()
    }

    /// One Lock by id.
    pub fn get(&self, lock_id: &str) -> Option<&StoredLock> {
        self.locks.get(lock_id)
    }

    /// Store a Lock, replacing any with the same id.
    ///
    /// Replacing rather than rejecting a duplicate: the id is content-derived,
    /// so a "duplicate" is the same Lock re-entered, and the only thing that can
    /// differ is its label. Refusing would make renaming impossible.
    pub fn put(&mut self, lock: StoredLock) -> std::io::Result<()> {
        self.locks.insert(lock.lock_id.clone(), lock);
        self.flush()
    }

    /// Forget a Lock. Returns whether it was there.
    ///
    /// The funds are untouched — this removes a definition, not a Lock. The
    /// lanes remain spendable by anyone holding the keys.
    pub fn remove(&mut self, lock_id: &str) -> std::io::Result<bool> {
        let had = self.locks.remove(lock_id).is_some();
        if had {
            self.flush()?;
        }
        Ok(had)
    }

    /// Write the whole store, durably.
    ///
    /// Same write-temp, fsync, rename, fsync-dir sequence as the signing ledger.
    /// Losing a Lock definition costs less than losing an authorisation, but a
    /// half-written file fails the strict parse above and locks the user out of
    /// their own list until they fix it by hand.
    fn flush(&self) -> std::io::Result<()> {
        let list: Vec<&StoredLock> = self.locks.values().collect();
        let body = serde_json::to_vec_pretty(&list)?;
        // 0o600: a stored Lock lays out the owner's whole account structure.
        ghost_lock::atomic_file::write_atomic(&self.path, &body, Some(0o600))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(label: Option<&str>, backup: &str) -> StoredLock {
        StoredLock::new(
            label.map(str::to_string),
            backup.into(),
            "bb".into(),
            "cc".into(),
            900_000,
            1_000_000,
            0,
        )
    }

    #[test]
    fn the_same_lock_has_the_same_id() {
        // Content-addressed, so re-entering keys after losing the file gives the
        // Lock back under its original id rather than as a stranger.
        assert_eq!(lock(None, "aa").lock_id, lock(None, "aa").lock_id);
    }

    #[test]
    fn renaming_does_not_make_it_a_different_lock() {
        // `label` is excluded from the id on purpose.
        assert_eq!(
            lock(Some("Main"), "aa").lock_id,
            lock(Some("Renamed"), "aa").lock_id
        );
    }

    #[test]
    fn changing_anything_that_moves_the_addresses_changes_the_id() {
        let base = lock(None, "aa");
        assert_ne!(base.lock_id, lock(None, "ab").lock_id, "backup key");

        let other_height = StoredLock::new(
            None,
            "aa".into(),
            "bb".into(),
            "cc".into(),
            900_001,
            1_000_000,
            0,
        );
        assert_ne!(base.lock_id, other_height.lock_id, "anchor height");

        let other_index = StoredLock::new(
            None,
            "aa".into(),
            "bb".into(),
            "cc".into(),
            900_000,
            1_000_000,
            1,
        );
        assert_ne!(base.lock_id, other_index.lock_id, "bip86 index");
    }

    #[test]
    fn the_id_ignores_case_and_surrounding_space() {
        // A key pasted with a trailing newline is the same key.
        let a = StoredLock::derive_id("AA", "BB", "CC", 1, 2, 0);
        let b = StoredLock::derive_id(" aa ", "bb\n", "cc", 1, 2, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn a_lock_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locks.json");
        let id = {
            let mut s = GhostLockStore::open(&path).unwrap();
            let l = lock(Some("Main"), "aa");
            let id = l.lock_id.clone();
            s.put(l).unwrap();
            id
        };
        let reopened = GhostLockStore::open(&path).unwrap();
        assert_eq!(reopened.list().len(), 1);
        assert_eq!(reopened.get(&id).unwrap().label.as_deref(), Some("Main"));
    }

    #[test]
    fn re_entering_a_lock_updates_it_rather_than_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locks.json");
        let mut s = GhostLockStore::open(&path).unwrap();
        s.put(lock(Some("Main"), "aa")).unwrap();
        s.put(lock(Some("Renamed"), "aa")).unwrap();
        assert_eq!(s.list().len(), 1, "same keys are the same Lock");
        assert_eq!(s.list()[0].label.as_deref(), Some("Renamed"));
    }

    #[test]
    fn a_corrupt_store_is_an_error_not_an_empty_list() {
        // Starting empty would hide every Lock, and the user would find out by
        // their balances reading zero — which looks like being robbed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locks.json");
        fs::write(&path, b"not json").unwrap();
        let e = GhostLockStore::open(&path).expect_err("must refuse");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(format!("{e}").contains("vanished"), "{e}");
    }

    #[test]
    fn forgetting_a_lock_removes_only_the_definition() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locks.json");
        let mut s = GhostLockStore::open(&path).unwrap();
        let l = lock(None, "aa");
        let id = l.lock_id.clone();
        s.put(l).unwrap();
        assert!(s.remove(&id).unwrap());
        assert!(!s.remove(&id).unwrap(), "already gone");
        assert!(s.list().is_empty());
    }

    #[test]
    fn an_absent_file_opens_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = GhostLockStore::open(dir.path().join("new.json")).unwrap();
        assert!(s.list().is_empty());
    }
}
