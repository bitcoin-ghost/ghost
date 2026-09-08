//! What the wallet knows about itself, beside its keys.
//!
//! One field so far, and it is the one a restore depends on: the height the
//! wallet came into existence. Without it a restored wallet has no way to say
//! how far back the scanner should read, and the only safe defaults are both
//! bad — start at the tip and its past is invisible, start at genesis and it
//! reads twenty years of blocks to find a wallet that is usually a week old.

use std::fs;
use std::path::{Path, PathBuf};

/// Per-wallet facts that are not secret and not derivable from the seed.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WalletMeta {
    /// The chain height at or before which this wallet can have no history.
    ///
    /// Set to the tip when a wallet is created — a wallet cannot have been
    /// paid before it existed. On a restore it is whatever the owner says, and
    /// `None` means they did not say: the scanner then starts at the tip and
    /// the history begins there, which is stated rather than silently assumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_height: Option<u32>,
}

/// Read `path`, or a default if it is absent or unreadable.
///
/// Losing this costs history depth on a rescan, not money, so a malformed file
/// falls back rather than failing. That is the opposite call from the
/// detections beside it, where silence would hide coins.
pub fn load(path: impl AsRef<Path>) -> WalletMeta {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
            tracing::warn!(path = %path.display(), error = %e, "wallet metadata unreadable");
            WalletMeta::default()
        }),
        Err(_) => WalletMeta::default(),
    }
}

/// Write `meta` to `path`, durably.
pub fn save(path: impl AsRef<Path>, meta: &WalletMeta) -> std::io::Result<()> {
    let path: PathBuf = path.as_ref().to_path_buf();
    let body = serde_json::to_vec_pretty(meta).map_err(std::io::Error::other)?;
    // 0o600: the birth height dates the wallet.
    ghost_lock::atomic_file::write_atomic(&path, &body, Some(0o600))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_birth_height_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.json");
        save(
            &path,
            &WalletMeta {
                birth_height: Some(900_123),
            },
        )
        .unwrap();
        assert_eq!(load(&path).birth_height, Some(900_123));
    }

    #[test]
    fn an_absent_file_reads_as_no_birth_height() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path().join("nope.json")).birth_height, None);
    }

    /// A corrupt metadata file costs scan depth, not money — falling back
    /// beats refusing to open the wallet.
    #[test]
    fn a_corrupt_file_falls_back_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.json");
        fs::write(&path, "{ not json").unwrap();
        assert_eq!(load(&path).birth_height, None);
    }
}
