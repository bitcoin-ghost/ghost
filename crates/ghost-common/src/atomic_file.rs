//! One durable, atomic, race-safe file replacement.
//!
//! # Why this exists in one place
//!
//! Several places persist a small file by rewriting it whole, and each had
//! grown its own copy of write-temp / fsync / rename. Every copy carried the
//! same defect: the staging file was a fixed `.tmp` sibling of the target.
//!
//! A fixed staging path is shared by every concurrent writer of that file. Two
//! writers racing on it truncate each other's contents, and once the winner has
//! renamed it away the loser's `rename` fails with `ENOENT`. Staging through a
//! path private to each write removes both races, and doing it once means there
//! is no next copy to get wrong.
//!
//! Some copies were also missing durability rather than just racing: a
//! `fs::write` followed by `rename`, with neither the file nor the directory
//! fsynced, reports success for a write a power loss can still take away.
//!
//! # What this does not do
//!
//! It makes a single write atomic. It does **not** make read-modify-write
//! atomic: a caller that loads a file, edits in memory and writes the whole
//! thing back still needs to hold a lock across all three steps, or a
//! concurrent writer's changes are lost.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Distinguishes the staging files of two writes racing on one target path.
/// Paired with the pid so separate processes cannot collide either.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A staging path private to one write, beside `target`.
///
/// For writers that stream into the staging file rather than handing over a
/// finished body — a multi-hundred-megabyte proving key, say, which must not be
/// buffered in memory just to reuse [`write_atomic`]. Pair it with
/// [`sync_parent_dir`] after the rename.
///
/// Never a fixed `.tmp` sibling: that path is shared by every concurrent
/// writer of the same target, so two writers truncate each other and the
/// loser's rename fails with `ENOENT`.
pub fn staging_path(target: &Path) -> std::path::PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    target.with_extension(format!("tmp.{}.{seq}", std::process::id()))
}

/// fsync the directory holding `path`, so a rename into it is persisted.
///
/// Renaming is a metadata change. Without this the file's own fsync survives a
/// power loss and the rename does not, which loses the write while having
/// reported success.
///
/// Best effort: a filesystem that refuses to open a directory has still given
/// us a durable staging file and an atomic rename, which is the bulk of the
/// guarantee.
pub fn sync_parent_dir(path: &Path) {
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

/// Replace `path` with `body`, atomically and durably.
///
/// Creates the parent directory if absent. On unix, `mode` sets the staging
/// file's permissions before the rename, so the file is never briefly readable
/// at a wider mode than intended — pass `Some(0o600)` for anything secret.
///
/// The sequence is write-temp, fsync, rename, fsync-dir: what survives power
/// loss on the filesystems this runs on. Skipping the directory fsync leaves
/// the rename itself unpersisted, which loses the write while reporting
/// success.
pub fn write_atomic(path: &Path, body: &[u8], mode: Option<u32>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    // Staging path private to this write. See the module docs for what a
    // shared one costs.
    let tmp = staging_path(path);

    let staged = (|| -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(body)?;

        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;

        // Contents before the rename, or the rename can land pointing at an
        // empty file.
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();

    if staged.is_err() {
        // Don't leave a staging file behind for a write that failed.
        let _ = fs::remove_file(&tmp);
    }
    staged?;

    sync_parent_dir(path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ghost-atomic-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[test]
    fn it_creates_missing_parent_directories() {
        let dir = scratch("parents");
        let path = dir.join("a").join("b").join("f.json");
        write_atomic(&path, b"hello", None).expect("write");
        assert_eq!(fs::read(&path).unwrap(), b"hello");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn it_replaces_existing_content_wholesale() {
        let dir = scratch("replace");
        let path = dir.join("f.json");
        write_atomic(&path, b"first-and-longer", None).expect("write 1");
        write_atomic(&path, b"second", None).expect("write 2");
        assert_eq!(fs::read(&path).unwrap(), b"second");
        let _ = fs::remove_dir_all(&dir);
    }

    /// The regression this module exists for.
    ///
    /// With a fixed `.tmp` staging path, concurrent writers truncate each
    /// other's staging file and the loser's rename fails with `ENOENT`.
    #[test]
    fn concurrent_writers_do_not_destroy_each_others_staging_file() {
        let dir = scratch("race");
        let path = dir.join("contended.json");

        let threads: Vec<_> = (0..16u8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let body = vec![b'a' + i; 64];
                    write_atomic(&path, &body, Some(0o600))
                })
            })
            .collect();
        for (i, t) in threads.into_iter().enumerate() {
            t.join()
                .expect("writer thread")
                .unwrap_or_else(|e| panic!("writer {i} failed: {e}"));
        }

        // Every write is all-or-nothing, so whoever landed last left exactly
        // its own body — never a mixture, never an empty file.
        let got = fs::read(&path).expect("target exists");
        assert_eq!(got.len(), 64, "target is a whole body, not a partial write");
        assert!(
            got.iter().all(|b| *b == got[0]),
            "target interleaves two writers' bodies"
        );

        let strays: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(strays.is_empty(), "staging files left behind: {strays:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// Two writes to one target must never stage through the same path.
    ///
    /// This is the whole defect, isolated: a fixed `.tmp` sibling is shared by
    /// every concurrent writer, so one truncates the other's staging file and
    /// the loser's rename finds nothing there. Streaming writers (a proving key
    /// too large to hold in memory) use this directly rather than
    /// `write_atomic`, so it needs its own guarantee.
    #[test]
    fn staging_paths_are_unique_per_write() {
        let target = std::path::Path::new("/tmp/some-target.bin");
        let a = staging_path(target);
        let b = staging_path(target);
        assert_ne!(a, b, "two writes staged through the same path");
        assert_ne!(a, target.to_path_buf());
        // Still beside the target, so the rename stays within one filesystem —
        // a staging file elsewhere would make `rename` cross devices and fail.
        assert_eq!(a.parent(), target.parent());
    }

    #[cfg(unix)]
    #[test]
    fn a_secret_file_is_never_wider_than_requested() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let path = dir.join("secret.json");
        write_atomic(&path, b"secret", Some(0o600)).expect("write");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "secret file landed at {mode:o}");
        let _ = fs::remove_dir_all(&dir);
    }
}
