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
    load_with_source(path).0
}

/// Where the returned [`WalletMeta`] actually came from.
///
/// ⛔ This exists because [`load`] cannot tell a caller the difference between "the file is not
/// there" and "the file says `birth_height: null`", and the scanner reports both as
/// `"this wallet has no recorded birth height"`. That single sentence asserts a fact the code
/// cannot distinguish from a failed read, which is why #865 — an imported `--birth-height`
/// being written and then not seen — has an unestablished root cause: the one log line that
/// would name which of the two happened does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaSource {
    /// Read and parsed.
    Loaded,
    /// No file at that path.
    Missing,
    /// A file that could not be parsed; its contents were discarded.
    Unreadable,
}

/// Like [`load`], but says where the value came from.
///
/// The leniency is deliberate and unchanged — losing this costs history depth on a rescan, not
/// money, so a bad file must not stop a wallet opening. What changes is that the caller can now
/// SAY which case it hit.
pub fn load_with_source(path: impl AsRef<Path>) -> (WalletMeta, MetaSource) {
    let path = path.as_ref();
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str(&raw) {
            Ok(meta) => (meta, MetaSource::Loaded),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "wallet metadata unreadable");
                (WalletMeta::default(), MetaSource::Unreadable)
            }
        },
        Err(_) => (WalletMeta::default(), MetaSource::Missing),
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

    /// ⛔ The distinction #865 needed and did not have.
    ///
    /// A missing file and a file saying `birth_height: null` both yield the same `WalletMeta`,
    /// and the scanner reported both as "this wallet has no recorded birth height". They have
    /// opposite fixes — one means the owner did not supply one, the other means the write
    /// landed somewhere the reader is not looking — so collapsing them cost the root cause.
    #[test]
    fn a_missing_file_is_distinguishable_from_no_birth_height() {
        let dir = tempfile::tempdir().unwrap();

        // Missing.
        let absent = dir.path().join("does-not-exist.json");
        let (meta, source) = load_with_source(&absent);
        assert_eq!(source, MetaSource::Missing);
        assert_eq!(meta.birth_height, None);

        // Present, explicitly no birth height.
        let null = dir.path().join("null.json");
        save(&null, &WalletMeta { birth_height: None }).unwrap();
        let (meta, source) = load_with_source(&null);
        assert_eq!(
            source,
            MetaSource::Loaded,
            "a file that exists and parses must not report as Missing — that is the whole point"
        );
        assert_eq!(meta.birth_height, None);

        // Present and set.
        let set = dir.path().join("set.json");
        save(
            &set,
            &WalletMeta {
                birth_height: Some(101),
            },
        )
        .unwrap();
        let (meta, source) = load_with_source(&set);
        assert_eq!(source, MetaSource::Loaded);
        assert_eq!(meta.birth_height, Some(101));

        // Present but corrupt — discarded, and SAID to be discarded.
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, b"{not json").unwrap();
        let (meta, source) = load_with_source(&bad);
        assert_eq!(
            source,
            MetaSource::Unreadable,
            "a corrupt file must not look like an absent one"
        );
        assert_eq!(
            meta.birth_height, None,
            "leniency is deliberate and unchanged"
        );
    }

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
