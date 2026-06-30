//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: params.rs                                                                                                      |
//|======================================================================================================================|

//! Parameter file I/O and management
//!
//! Handles loading and saving of ZK parameters to disk, with support for
//! both block proving parameters and payout proving parameters.

use crate::errors::{MpcError, MpcResult};
use bellperson::groth16::{Parameters, PreparedVerifyingKey, VerifyingKey};
use blstrs::Bls12;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Container for note spend, payout, and unshield parameters
/// Note: Not Clone because PreparedVerifyingKey doesn't implement Clone.
/// Use `Arc<MpcParameters>` for shared ownership.
#[derive(Default)]
pub struct MpcParameters {
    /// Parameters for note spend proofs (GhostNoteSpendCircuit)
    pub note_spend_params: Option<Parameters<Bls12>>,
    /// Parameters for payout proofs
    pub payout_params: Option<Parameters<Bls12>>,
    /// Parameters for unshield proofs (L2 -> L1 withdrawal)
    pub unshield_params: Option<Parameters<Bls12>>,
    /// Prepared verifying key for note spend proofs (for fast verification)
    pub note_spend_vk: Option<PreparedVerifyingKey<Bls12>>,
    /// Prepared verifying key for payout proofs
    pub payout_vk: Option<PreparedVerifyingKey<Bls12>>,
    /// Prepared verifying key for unshield proofs
    pub unshield_vk: Option<PreparedVerifyingKey<Bls12>>,
}

/// File paths for parameter storage
pub struct ParameterFiles {
    /// Base directory for parameter files
    pub dir: PathBuf,
}

impl ParameterFiles {
    /// Create a new parameter files manager
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Path to note spend parameters file
    pub fn note_spend_params_path(&self, contribution_count: u32) -> PathBuf {
        self.dir
            .join(format!("note_spend_params_v{}.bin", contribution_count))
    }

    /// Path to payout parameters file
    pub fn payout_params_path(&self, contribution_count: u32) -> PathBuf {
        self.dir
            .join(format!("payout_params_v{}.bin", contribution_count))
    }

    /// Path to the current (latest) note spend parameters
    pub fn current_note_spend_params_path(&self) -> PathBuf {
        self.dir.join("note_spend_params_current.bin")
    }

    /// Path to the current (latest) payout parameters
    pub fn current_payout_params_path(&self) -> PathBuf {
        self.dir.join("payout_params_current.bin")
    }

    /// Path to the note spend verifying key
    pub fn note_spend_vk_path(&self) -> PathBuf {
        self.dir.join("note_spend_vk.bin")
    }

    /// Path to the payout verifying key
    pub fn payout_vk_path(&self) -> PathBuf {
        self.dir.join("payout_vk.bin")
    }

    /// Path to unshield (L2 -> L1 withdrawal) parameters file
    pub fn unshield_params_path(&self, contribution_count: u32) -> PathBuf {
        self.dir
            .join(format!("unshield_params_v{}.bin", contribution_count))
    }

    /// Path to the current (latest) unshield parameters
    pub fn current_unshield_params_path(&self) -> PathBuf {
        self.dir.join("unshield_params_current.bin")
    }

    /// Path to the unshield verifying key
    pub fn unshield_vk_path(&self) -> PathBuf {
        self.dir.join("unshield_vk.bin")
    }

    /// Ensure the parameters directory exists
    pub fn ensure_dir(&self) -> MpcResult<()> {
        if !self.dir.exists() {
            fs::create_dir_all(&self.dir)?;
            info!(path = %self.dir.display(), "Created MPC parameters directory");
        }
        Ok(())
    }

    /// List all parameter versions available
    ///
    /// 4.16 SECURITY: Handles version gaps gracefully
    /// If versions [1, 2, 5] exist (gaps at 3, 4), this returns [1, 2, 5] sorted.
    /// Use `has_version_gaps()` to detect if gaps exist.
    pub fn list_versions(&self) -> MpcResult<Vec<u32>> {
        let mut versions = Vec::new();

        if !self.dir.exists() {
            return Ok(versions);
        }

        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Some(rest) = name_str.strip_prefix("note_spend_params_v") {
                if let Some(version_str) = rest.strip_suffix(".bin") {
                    if let Ok(version) = version_str.parse::<u32>() {
                        versions.push(version);
                    }
                }
            }
        }

        versions.sort();
        Ok(versions)
    }

    /// Get the highest version number available
    pub fn latest_version(&self) -> MpcResult<Option<u32>> {
        Ok(self.list_versions()?.into_iter().max())
    }

    /// 4.16 SECURITY: Check if there are gaps in the version sequence
    ///
    /// Gaps indicate missing intermediate contributions, which could mean:
    /// - Failed/reverted contributions
    /// - Corrupted parameter files
    /// - Incomplete ceremony state
    ///
    /// Returns the list of missing version numbers, if any.
    pub fn find_version_gaps(&self) -> MpcResult<Vec<u32>> {
        let versions = self.list_versions()?;

        // HIGH-7: Use pattern matching instead of unwrap after empty check
        let (min_version, max_version) = match (versions.first(), versions.last()) {
            (Some(&min), Some(&max)) => (min, max),
            // Empty or single-element list has no gaps
            _ => return Ok(vec![]),
        };

        let mut gaps = Vec::new();
        for expected in min_version..=max_version {
            if !versions.contains(&expected) {
                gaps.push(expected);
            }
        }

        Ok(gaps)
    }

    /// 4.16: Check if there are any version gaps
    pub fn has_version_gaps(&self) -> MpcResult<bool> {
        Ok(!self.find_version_gaps()?.is_empty())
    }
}

/// Save parameters to a file
///
/// S-5 SECURITY: Uses atomic write (temp file + rename) to prevent corruption
/// if the process crashes mid-write. Also uses fsync for durability.
pub fn save_parameters(path: &Path, params: &Parameters<Bls12>) -> MpcResult<()> {
    let temp_path = path.with_extension("tmp");

    // Write to temp file first
    let result = (|| -> MpcResult<()> {
        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);

        params
            .write(&mut writer)
            .map_err(|e| MpcError::Serialization(e.to_string()))?;

        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    })();

    // Clean up temp file on error
    if let Err(e) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    // Atomic rename to target path
    fs::rename(&temp_path, path)?;

    let file_size = fs::metadata(path)?.len();
    info!(
        path = %path.display(),
        size_bytes = file_size,
        "Saved MPC parameters (atomic write)"
    );

    Ok(())
}

/// Load parameters from a file
pub fn load_parameters(path: &Path) -> MpcResult<Parameters<Bls12>> {
    if !path.exists() {
        return Err(MpcError::ParamsNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let params = Parameters::read(reader, false) // false = don't check for safety
        .map_err(|e| MpcError::InvalidParams(e.to_string()))?;

    debug!(path = %path.display(), "Loaded MPC parameters");

    Ok(params)
}

/// Parse Groth16 parameters directly from an in-memory byte buffer.
///
/// Used by the BFT voter to verify a fetched candidate parameter set WITHOUT
/// writing hundreds of megabytes to disk (verification is read-only; only the
/// post-approval apply persists parameters). Mirrors [`load_parameters`]'s
/// decoding (`checked = false`).
pub fn read_parameters_from_bytes(bytes: &[u8]) -> MpcResult<Parameters<Bls12>> {
    Parameters::read(std::io::Cursor::new(bytes), false)
        .map_err(|e| MpcError::InvalidParams(e.to_string()))
}

/// Save a verifying key to a file
///
/// S-5 SECURITY: Uses atomic write (temp file + rename) to prevent corruption.
pub fn save_verifying_key(path: &Path, vk: &VerifyingKey<Bls12>) -> MpcResult<()> {
    let temp_path = path.with_extension("tmp");

    let result = (|| -> MpcResult<()> {
        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);

        vk.write(&mut writer)
            .map_err(|e| MpcError::Serialization(e.to_string()))?;

        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    fs::rename(&temp_path, path)?;

    info!(path = %path.display(), "Saved verifying key (atomic write)");

    Ok(())
}

/// Load a verifying key from a file
pub fn load_verifying_key(path: &Path) -> MpcResult<VerifyingKey<Bls12>> {
    if !path.exists() {
        return Err(MpcError::ParamsNotFound(path.display().to_string()));
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);

    let vk = VerifyingKey::read(reader).map_err(|e| MpcError::InvalidParams(e.to_string()))?;

    debug!(path = %path.display(), "Loaded verifying key");

    Ok(vk)
}

/// Hash a parameters file for verification
pub fn hash_params_file(path: &Path) -> MpcResult<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();

    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().into())
}

/// Atomically update the "current" params to point to new version
///
/// S-6 SECURITY: Uses read → write temp → rename pattern for atomic updates,
/// preventing corruption if the process crashes mid-copy.
pub fn update_current_params(files: &ParameterFiles, version: u32) -> MpcResult<()> {
    let note_spend_src = files.note_spend_params_path(version);
    let payout_src = files.payout_params_path(version);
    let unshield_src = files.unshield_params_path(version);
    let note_spend_dst = files.current_note_spend_params_path();
    let payout_dst = files.current_payout_params_path();
    let unshield_dst = files.current_unshield_params_path();

    if note_spend_src.exists() {
        atomic_copy(&note_spend_src, &note_spend_dst)?;
        info!(
            version = version,
            path = %note_spend_dst.display(),
            "Updated current note spend parameters"
        );
    }

    if payout_src.exists() {
        atomic_copy(&payout_src, &payout_dst)?;
        info!(
            version = version,
            path = %payout_dst.display(),
            "Updated current payout parameters"
        );
    }

    if unshield_src.exists() {
        atomic_copy(&unshield_src, &unshield_dst)?;
        info!(
            version = version,
            path = %unshield_dst.display(),
            "Updated current unshield parameters"
        );
    }

    Ok(())
}

/// Atomically copy a file by writing to a temp file and renaming.
fn atomic_copy(src: &Path, dst: &Path) -> MpcResult<()> {
    let temp_path = dst.with_extension("tmp");

    let result = (|| -> MpcResult<()> {
        let mut reader = BufReader::new(File::open(src)?);
        let file = File::create(&temp_path)?;
        let mut writer = BufWriter::new(file);

        std::io::copy(&mut reader, &mut writer)?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    })();

    if let Err(e) = result {
        let _ = fs::remove_file(&temp_path);
        return Err(e);
    }

    fs::rename(&temp_path, dst)?;
    Ok(())
}

/// Metadata about a parameter file
#[derive(Debug, Clone)]
pub struct ParamsMetadata {
    /// Hash of the parameters
    pub hash: [u8; 32],
    /// File size in bytes
    pub size_bytes: u64,
    /// Contribution count (version)
    pub contribution_count: u32,
    /// Path to the file
    pub path: PathBuf,
}

impl ParamsMetadata {
    /// Load metadata for a parameter file
    pub fn from_file(path: &Path, contribution_count: u32) -> MpcResult<Self> {
        let hash = hash_params_file(path)?;
        let size_bytes = fs::metadata(path)?.len();

        Ok(Self {
            hash,
            size_bytes,
            contribution_count,
            path: path.to_path_buf(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parameter_files_paths() {
        let dir = PathBuf::from("/tmp/mpc");
        let files = ParameterFiles::new(&dir);

        assert_eq!(
            files.note_spend_params_path(5),
            PathBuf::from("/tmp/mpc/note_spend_params_v5.bin")
        );
        assert_eq!(
            files.payout_params_path(10),
            PathBuf::from("/tmp/mpc/payout_params_v10.bin")
        );
    }

    #[test]
    fn test_list_versions_empty() {
        let temp_dir = TempDir::new().unwrap();
        let files = ParameterFiles::new(temp_dir.path());

        let versions = files.list_versions().unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn test_ensure_dir_creates() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("mpc");
        let files = ParameterFiles::new(&subdir);

        assert!(!subdir.exists());
        files.ensure_dir().unwrap();
        assert!(subdir.exists());
    }
}
