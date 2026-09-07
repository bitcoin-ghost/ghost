//! File-backed [`NonceLedger`] — the layer that survives a restart.
//!
//! # Why this is not optional
//!
//! A MuSig2 secret nonce used for two signatures publishes the signer's key.
//! `ghost_lock::signing` stops that twice inside one process — the message is
//! bound at nonce creation, and signing consumes the session — but neither
//! survives the daemon dying between rounds. This does.
//!
//! `VolatileNonceLedger` satisfies the trait and not its purpose: correct until
//! the process restarts, which is exactly the moment it matters.
//!
//! # Durability, in the same shape as the signing ledger
//!
//! A burn is fsynced before the call returns, because the caller signs
//! immediately afterwards: a record written lazily is a record that can be lost
//! while the signature is already out. Write-temp, fsync, rename, fsync-dir is
//! the sequence that survives power loss on the filesystems this runs on;
//! skipping the directory fsync leaves the rename itself unpersisted.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use ghost_lock::signing::{NonceId, NonceLedger};

/// File-backed [`NonceLedger`]. Safe for production use.
#[derive(Debug)]
pub struct FileNonceLedger {
    path: PathBuf,
    /// Mirror of the file, so a check does not hit the disk.
    spent: BTreeSet<[u8; 32]>,
}

impl FileNonceLedger {
    /// Open (or create) the ledger at `path`.
    ///
    /// A malformed file is an error rather than an empty ledger. Starting
    /// fresh would forget every nonce already spent and re-permit exactly the
    /// reuse this exists to refuse — the failure would be silent, and the
    /// consequence is key disclosure.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let spent = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let rows: Vec<String> = serde_json::from_str(&raw).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "nonce ledger at {} is unreadable ({e}); refusing to continue \
                         with an empty one, which would re-permit the nonce reuse it \
                         has already refused — and reuse publishes the key",
                        path.display()
                    ),
                )
            })?;
            let mut set = BTreeSet::new();
            for r in rows {
                let bytes = hex::decode(&r)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok());
                let Some(bytes) = bytes else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("nonce ledger row is not a 32-byte hex id: {r}"),
                    ));
                };
                set.insert(bytes);
            }
            set
        } else {
            BTreeSet::new()
        };
        Ok(Self { path, spent })
    }

    /// How many nonces have been burned. For diagnostics.
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    /// Whether the ledger is empty.
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }

    /// Rewrite the whole file atomically.
    ///
    /// Rewritten rather than appended: the set is small (one row per signature
    /// this wallet has ever produced) and a rewrite-and-rename is atomic, where
    /// an append can leave a half-written row that fails the strict parse above.
    fn flush(&self) -> std::io::Result<()> {
        let rows: Vec<String> = self.spent.iter().map(hex::encode).collect();
        let body = serde_json::to_vec_pretty(&rows).map_err(std::io::Error::other)?;

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&body)?;
            // Contents before the rename, or the rename can land pointing at an
            // empty file.
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

        // The rename itself is metadata and needs its own sync, or a power loss
        // here leaves the old file in place and the burn lost.
        if let Some(dir) = self.path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

impl NonceLedger for FileNonceLedger {
    /// Burn `id`, durably, before returning.
    ///
    /// A failed write is an error, not a warning. Returning `Ok` on an
    /// unpersisted burn would hand out a signature the ledger has no record of
    /// — which is the reuse case, one restart later.
    fn spend(&mut self, id: &NonceId) -> Result<(), ghost_lock::LockError> {
        let key = *id.as_bytes();
        if self.spent.contains(&key) {
            return Err(ghost_lock::LockError::Policy(format!(
                "nonce {} has already produced a signature — signing with it again \
                 publishes this key",
                hex::encode(key)
            )));
        }
        self.spent.insert(key);
        if let Err(e) = self.flush() {
            // Roll back the in-memory view: a burn that is not on disk must not
            // read as burned, or a later restart would disagree with this
            // process about what is safe.
            self.spent.remove(&key);
            return Err(ghost_lock::LockError::Policy(format!(
                "could not record the nonce burn at {} ({e}); refusing to sign, \
                 because an unrecorded signature is one a restart would let happen \
                 twice",
                self.path.display()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NonceId {
        NonceId::for_public_nonce(&[b; 66])
    }

    #[test]
    fn a_burn_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.json");

        {
            let mut ledger = FileNonceLedger::open(&path).unwrap();
            ledger.spend(&id(1)).expect("first burn");
        }

        // The restart the volatile ledger cannot survive.
        let mut reopened = FileNonceLedger::open(&path).unwrap();
        assert_eq!(reopened.len(), 1);
        let err = reopened
            .spend(&id(1))
            .expect_err("a burned nonce must stay burned across a restart");
        assert!(format!("{err}").contains("publishes this key"), "{err}");
    }

    #[test]
    fn distinct_nonces_are_independent_across_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        {
            let mut l = FileNonceLedger::open(&path).unwrap();
            l.spend(&id(1)).unwrap();
            l.spend(&id(2)).unwrap();
        }
        let mut l = FileNonceLedger::open(&path).unwrap();
        assert!(l.spend(&id(3)).is_ok());
        assert!(l.spend(&id(1)).is_err());
    }

    /// A corrupt ledger must not read as an empty one.
    #[test]
    fn a_corrupt_ledger_is_refused_not_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        fs::write(&path, "{ not json").unwrap();
        let err = FileNonceLedger::open(&path).expect_err("must refuse");
        assert!(
            format!("{err}").contains("refusing to continue with an empty one"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_file_is_an_empty_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let l = FileNonceLedger::open(dir.path().join("nope.json")).unwrap();
        assert!(l.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_ledger_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonces.json");
        let mut l = FileNonceLedger::open(&path).unwrap();
        l.spend(&id(9)).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a nonce ledger must not be world-readable");
    }
}
