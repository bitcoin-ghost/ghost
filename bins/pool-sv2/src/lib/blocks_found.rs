//! The blocks this pool found: height, hash, who found it and what it paid them, whether its
//! coinbase passed the post-submit check, and what the other nodes said when it was sent to
//! them.
//!
//! Kept in memory and, when `[solo] state_dir` is set, in `blocks-found.json` there (mode 0600,
//! written through a temporary file on every change), so a restart keeps the list. At most
//! [`MAX_BLOCKS`] are kept, newest last. A block is recorded when it is submitted, before anyone
//! knows whether Bitcoin accepted it: the list is what this pool found, not what the chain kept.

use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use tracing::warn;

/// Blocks kept.
pub const MAX_BLOCKS: usize = 1_000;
/// The file's format version.
const FILE_VERSION: u32 = 1;

/// What one other node said to a found block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitResult {
    /// The node, as `scheme://host:port` (never its credentials).
    pub node: String,
    /// `accepted`, or why not.
    pub result: String,
}

/// One block this pool found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoundBlock {
    /// Its height.
    pub height: u32,
    /// Its hash, as explorers show it.
    pub hash: String,
    /// The finder's payout address.
    pub address: String,
    /// The finder's worker name (empty when it has none).
    pub worker: String,
    /// Sats the coinbase pays the finder: `subsidy - subsidy / 200 + fees`.
    pub reward_sats: u64,
    /// Sats it pays the treasury: `subsidy / 200`.
    pub treasury_sats: u64,
    /// The block's transaction fees, all of them the finder's.
    pub fees_sats: u64,
    /// When it was submitted, unix seconds.
    pub found_at: u64,
    /// The post-submit check: `ok`, or what was wrong. `None` until it has run.
    pub check: Option<String>,
    /// What the other configured nodes said.
    pub submitted: Vec<SubmitResult>,
}

#[derive(Serialize, Deserialize)]
struct SavedFile {
    version: u32,
    blocks: Vec<FoundBlock>,
}

/// The found blocks.
pub struct BlocksFound {
    blocks: Mutex<Vec<FoundBlock>>,
    path: Option<PathBuf>,
}

impl BlocksFound {
    /// Blocks kept in memory only.
    pub fn in_memory() -> BlocksFound {
        BlocksFound {
            blocks: Mutex::new(Vec::new()),
            path: None,
        }
    }

    /// Blocks saved to `path`, read back from it if it holds any. A file that does not parse is
    /// set aside (renamed `.bad`) and the list starts empty.
    pub fn open(path: PathBuf) -> BlocksFound {
        let mut blocks = Vec::new();
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<SavedFile>(&bytes) {
                Ok(f) if f.version == FILE_VERSION => blocks = f.blocks,
                Ok(f) => warn!(
                    path = %path.display(),
                    version = f.version,
                    "SOLO: found-blocks file has an unknown version; starting afresh"
                ),
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        "SOLO: found-blocks file does not parse ({e}); set aside, starting afresh"
                    );
                    let _ = std::fs::rename(&path, path.with_extension("json.bad"));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => warn!(
                path = %path.display(),
                "SOLO: cannot read the found-blocks file ({e}); starting afresh"
            ),
        }
        BlocksFound {
            blocks: Mutex::new(blocks),
            path: Some(path),
        }
    }

    /// Where the found blocks of a pool whose state directory is `dir` are saved.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join("blocks-found.json")
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<FoundBlock>> {
        self.blocks.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Every found block, oldest first.
    pub fn all(&self) -> Vec<FoundBlock> {
        self.lock().clone()
    }

    /// Record a block just submitted.
    pub fn record(&self, block: FoundBlock) {
        {
            let mut b = self.lock();
            b.retain(|x| x.hash != block.hash);
            b.push(block);
            while b.len() > MAX_BLOCKS {
                b.remove(0);
            }
        }
        self.save();
    }

    /// The post-submit check's verdict on the block `hash`.
    pub fn note_check(&self, hash: &str, verdict: Result<(), String>) {
        {
            let mut b = self.lock();
            if let Some(x) = b.iter_mut().find(|x| x.hash == hash) {
                x.check = Some(match verdict {
                    Ok(()) => "ok".to_string(),
                    Err(e) => e,
                });
            }
        }
        self.save();
    }

    /// What the other nodes said to the block `hash`.
    pub fn note_submitted(&self, hash: &str, results: Vec<(String, Result<(), String>)>) {
        {
            let mut b = self.lock();
            if let Some(x) = b.iter_mut().find(|x| x.hash == hash) {
                x.submitted
                    .extend(results.into_iter().map(|(node, r)| SubmitResult {
                        node,
                        result: match r {
                            Ok(()) => "accepted".to_string(),
                            Err(e) => e,
                        },
                    }));
            }
        }
        self.save();
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let file = SavedFile {
            version: FILE_VERSION,
            blocks: self.all(),
        };
        if let Err(e) = write_private(path, &file) {
            warn!(path = %path.display(), "SOLO: could not save the found blocks: {e}");
        }
    }
}

/// Write `value` as JSON to `path` through a temporary file renamed over it, mode 0600.
pub(crate) fn write_private<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(hash: &str) -> FoundBlock {
        FoundBlock {
            height: 960_000,
            hash: hash.into(),
            address: "bc1q".into(),
            worker: "rig1".into(),
            reward_sats: 310_937_500,
            treasury_sats: 1_562_500,
            fees_sats: 0,
            found_at: 1_800_000_000,
            check: None,
            submitted: vec![],
        }
    }

    #[test]
    fn blocks_survive_a_restart_with_their_check_and_submissions() {
        let dir = std::env::temp_dir().join(format!("solo-blocks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = BlocksFound::path_in(&dir);
        let _ = std::fs::remove_file(&path);
        let b = BlocksFound::open(path.clone());
        b.record(block("aa"));
        b.note_check("aa", Ok(()));
        b.note_submitted(
            "aa",
            vec![
                ("http://n2:8332".into(), Ok(())),
                ("http://n3:8332".into(), Err("duplicate".into())),
            ],
        );
        let again = BlocksFound::open(path.clone());
        let all = again.all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].check.as_deref(), Some("ok"));
        assert_eq!(all[0].submitted[0].result, "accepted");
        assert_eq!(all[0].submitted[1].result, "duplicate");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_list_is_bounded() {
        let b = BlocksFound::in_memory();
        for i in 0..(MAX_BLOCKS + 5) {
            b.record(block(&format!("{i:064x}")));
        }
        assert_eq!(b.all().len(), MAX_BLOCKS);
        assert_eq!(b.all()[0].hash, format!("{:064x}", 5));
    }
}
