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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost ZKP - Zero-Knowledge Proof Infrastructure for Ghost Pay
//!
//! This crate provides ZK validity proofs for Ghost Pay's BFT consensus.
//! Each block is proven valid by the proposer and verified by validators
//! in approximately 10ms. Proofs are ephemeral - once verified and the
//! block is finalized, they are discarded.
//!
//! # H-1: Trusted Setup Requirements
//!
//! **SECURITY WARNING**: This crate uses Groth16 which requires a trusted setup
//! ceremony (MPC) to generate secure parameters. Without completing this ceremony:
//!
//! - **Default parameters are for testing only**
//! - A malicious prover could forge proofs
//! - ZK proofs should NOT be relied upon for mainnet security
//!
//! For production deployment, you must:
//!
//! 1. Complete an MPC ceremony (see `docs/ZK_TRUSTED_SETUP.md`)
//! 2. Set `ZK_PARAMS_PATH` to the ceremony output directory
//! 3. Compile with `--features zk-production`
//!
//! When `zk-production` is enabled:
//! - Parameter loading verifies against known ceremony hashes
//! - Proof generation fails if parameters are missing/invalid
//! - Additional safety checks prevent accidental test parameter use
//!
//! # Proving Modes
//!
//! ## Legacy Mode (prove)
//! Proves payment validity only. Validators must re-execute state to verify
//! the state root transition.
//!
//! ## Full ZK Mode (prove_v2)
//! Proves complete state root transitions cryptographically. Validators verify
//! the proof only - no re-execution required. This makes Ghost Pay fully trustless.
//!
//! # Architecture
//!
//! ```text
//! Proposer                    Validators
//! ┌──────────────┐           ┌──────────────┐
//! │ 1. Execute   │           │ 1. Receive   │
//! │    txs       │           │    proposal  │
//! │              │           │              │
//! │ 2. Generate  │──────────►│ 2. Verify    │
//! │    witness   │           │    proof     │
//! │              │           │    (~10ms)   │
//! │ 3. Generate  │           │              │
//! │    proof     │           │ 3. Vote      │
//! │    (~2 sec)  │           │    approve   │
//! └──────────────┘           └──────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use ghost_zkp::{BlockProver, BlockVerifier, BlockWitness, BlockWitnessV2};
//!
//! // One-time setup (slow)
//! let prover = BlockProver::new_with_state_transitions(100, 20);
//! let verifier = BlockVerifier::new(prover.verification_key());
//!
//! // Per-block proving with full state transition proof (~2 seconds)
//! let witness = BlockWitnessV2::new(height, prev_root, new_root, transitions, 20);
//! let proof = prover.prove_v2(&witness)?;
//!
//! // Per-block verification (~10ms) - NO RE-EXECUTION NEEDED
//! assert!(verifier.verify(&proof)?);
//! ```

pub mod circuit;
pub mod commitment_tree;
pub mod consolidation_prover;
pub mod consolidation_verifier;
pub mod errors;
pub mod field_utils;
pub mod note_prover;
pub mod note_verifier;
pub mod prover;
pub mod state_tree;
pub mod types;
pub mod unshield_prover;
pub mod unshield_verifier;
pub mod verifier;

// Re-export main types
pub use errors::{ZkError, ZkResult};
pub use prover::BlockProver;
pub use types::{
    BlockProof, BlockWitness, BlockWitnessV2, MerkleProof, PaymentTransitionWitness,
    PaymentWitness, ProvingParams, StateSnapshot, VerificationKey,
};
pub use verifier::BlockVerifier;

// Re-export state tree utilities
pub use commitment_tree::{CommitmentTree, CommitmentTreeBuilder};
pub use state_tree::{BalanceTree, BalanceTreeBuilder};

// Re-export note spend types (L2 sender-side proofs)
pub use note_prover::{
    GhostNoteProver, GhostNoteSpendProof, GhostNoteSpendPublicInputs, GhostNoteSpendWitness,
};
pub use note_verifier::GhostNoteVerifier;

// Re-export consolidation types (merge multiple notes into one)
pub use consolidation_prover::{
    ConsolidationInputNote, ConsolidationProof, ConsolidationPublicInputs, ConsolidationWitness,
    GhostConsolidateProver,
};
pub use consolidation_verifier::GhostConsolidateVerifier;

// Re-export unshield types (L2 -> L1 full withdrawal proofs)
pub use unshield_prover::{
    GhostUnshieldProver, UnshieldProof, UnshieldPublicInputs, UnshieldWitness,
};
pub use unshield_verifier::GhostUnshieldVerifier;

// Re-export circuit types for advanced usage
pub use circuit::{
    bytes_to_field, compute_nullifier_native, field_to_bytes, pedersen_commit_native,
    COMMITMENT_DOMAIN_SEPARATOR, NULLIFIER_DOMAIN_SEPARATOR,
};
pub use circuit::{
    compute_note_id_with_epoch_native, compute_note_root_native,
    compute_nullifier_with_epoch_native, BlockCircuit, BlockCircuitBuilder, GhostNoteSpendCircuit,
    GhostUnshieldCircuit, MerkleCircuit, NoteConsolidateCircuit, PaymentCircuit,
    PaymentStateTransitionCircuit, StateTransitionOutputs, MAX_CONSOLIDATION_INPUTS,
    NOTE_TREE_DEPTH, UNSHIELD_TREE_DEPTH,
};

// ============================================================================
// Byte-level commitment helpers for application layer
// ============================================================================

/// Compute a Pedersen commitment from byte-level inputs.
///
/// C = MiMC(MiMC(value, blinding), COMMITMENT_DOMAIN_SEPARATOR)
///
/// This is a convenience wrapper for application code that doesn't
/// want to deal with field element types directly.
pub fn compute_commitment_bytes(value_sats: u64, blinding: &[u8; 32]) -> ZkResult<[u8; 32]> {
    use blstrs::Scalar;
    use circuit::mimc::{bytes_to_field, field_to_bytes};

    let value_fr = Scalar::from(value_sats);
    let blinding_fr: Scalar = bytes_to_field(blinding)
        .map_err(|e| ZkError::FieldConversionError(format!("Invalid blinding: {}", e)))?;
    let commitment_fr = pedersen_commit_native(value_fr, blinding_fr);
    Ok(field_to_bytes(commitment_fr))
}

// ============================================================================
// H-1: ZK Production Mode Safety
// ============================================================================

/// H-1: Check if ZK production mode is enabled
///
/// Returns true if the `zk-production` feature flag is set, indicating
/// that trusted setup ceremony artifacts should be used.
#[cfg(feature = "zk-production")]
pub const fn is_production_mode() -> bool {
    true
}

/// H-1: Check if ZK production mode is enabled
///
/// Returns false when `zk-production` is not enabled, indicating
/// that only test parameters should be used.
#[cfg(not(feature = "zk-production"))]
pub const fn is_production_mode() -> bool {
    false
}

/// H-1: Environment variable for trusted setup parameters path
pub const ZK_PARAMS_PATH_ENV: &str = "ZK_PARAMS_PATH";

/// H-1: Environment variable for expected parameter hashes (from MPC ceremony)
///
/// Format: "BLOCK:sha256hex"
/// Example: "BLOCK:abc123..."
pub const ZK_PARAMS_HASH_ENV: &str = "ZK_PARAMS_HASH";

/// Stage C: Environment variable for the IMMUTABLE genesis lineage anchor.
///
/// This is the trust root for the unpinned, rolling-ceremony verification path.
/// Unlike [`ZK_PARAMS_HASH_ENV`] (a raw-file SHA-256 of the *current* params,
/// which changes on every contribution and therefore cannot be pinned while
/// rolling), this is the STRUCTURED lineage hash (`ghost_mpc::contribution::
/// hash_parameters`) of the GENESIS parameters — equivalently
/// `mpc_contributions[1].prev_params_hash`. It is constant for the entire life
/// of the ceremony, so an operator can pin/distribute it exactly like the old
/// static hash.
///
/// Format: 64 lowercase hex characters (32 bytes), no `TYPE:` prefix. Example:
/// `ZK_GENESIS_PARAMS_HASH=c9c907f688fc1102...` (64 hex). For mainnet this is
/// `c9c907f688fc1102…` — the genesis anchor verified from production data.
pub const ZK_GENESIS_PARAMS_HASH_ENV: &str = "ZK_GENESIS_PARAMS_HASH";

/// Parse the immutable genesis lineage anchor from the environment.
///
/// * `Ok(None)` — the variable is unset.
/// * `Ok(Some(hash))` — a well-formed 64-hex value (the 32-byte lineage anchor).
/// * `Err(..)` — the variable is SET but malformed. Fail-closed: a malformed
///   anchor must never be silently treated as "unset", which could downgrade a
///   node out of the verified rolling path.
pub fn genesis_params_hash() -> ZkResult<Option<[u8; 32]>> {
    let raw = match std::env::var(ZK_GENESIS_PARAMS_HASH_ENV) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(e) => {
            return Err(ZkError::InvalidParams(format!(
                "Failed to read {}: {}",
                ZK_GENESIS_PARAMS_HASH_ENV, e
            )))
        }
    };
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(ZkError::InvalidParams(format!(
            "{} must be exactly 64 hex chars (32-byte lineage hash), got {}",
            ZK_GENESIS_PARAMS_HASH_ENV,
            trimmed.len()
        )));
    }
    let bytes: [u8; 32] = hex::decode(trimmed)
        .map_err(|e| {
            ZkError::InvalidParams(format!(
                "{} is not valid hex: {}",
                ZK_GENESIS_PARAMS_HASH_ENV, e
            ))
        })?
        .try_into()
        .map_err(|_| {
            ZkError::InvalidParams(format!(
                "{} decode to 32 bytes failed",
                ZK_GENESIS_PARAMS_HASH_ENV
            ))
        })?;
    Ok(Some(bytes))
}

/// Stage C: which trusted-setup verification path a node engages at startup.
///
/// These are MUTUALLY EXCLUSIVE and there is deliberately NO variant where the
/// trusted setup is left unverified. The selection is made by
/// [`select_startup_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkStartupMode {
    /// `ZK_PARAMS_HASH` is set: verify the on-disk *current* params against the
    /// pinned raw-file SHA-256. This is the existing frozen/pinned behaviour and
    /// the post-ossification path. Bit-identical to prior releases.
    StaticPin,
    /// `ZK_PARAMS_HASH` is ABSENT but `ZK_GENESIS_PARAMS_HASH` is set: the static
    /// current pin is intentionally removed for rolling. The node instead
    /// validates the evolving setup by the immutable genesis anchor + the lineage
    /// chain + the retained BFT quorum per position (see ghost-storage). Carries
    /// the genesis anchor (a LINEAGE hash) that roots the chain.
    GenesisAnchoredRolling { genesis_anchor: [u8; 32] },
    /// AUTONOMOUS OSSIFIED PIN: the DB ceremony singleton has ossified (reached
    /// `MAX_CEREMONY_CONTRIBUTORS`) and recorded the final params FILE hash. This
    /// mode is selected AUTOMATICALLY from that DB latch — with NO operator action
    /// and REGARDLESS of env vars — and takes precedence over both `StaticPin` and
    /// `GenesisAnchoredRolling`. Startup verifies the on-disk current params hash
    /// to this pin (fail-closed), then STILL runs the genesis-anchored lineage +
    /// retained-quorum verification once so the frozen params stay cryptographically
    /// anchored to the genesis root — not merely file-hash-trusted. Carries the
    /// pinned raw-file SHA-256 (the SAME digest a `ZK_PARAMS_HASH` static pin holds).
    OssifiedPinned { file_hash: [u8; 32] },
}

/// Stage C: choose the startup verification mode from the environment.
///
/// Precedence — explicit and mutually consistent:
/// 1. `ZK_PARAMS_HASH` set            → [`ZkStartupMode::StaticPin`] (pinned/frozen
///    or post-ossification). Unchanged from prior releases.
/// 2. else `ZK_GENESIS_PARAMS_HASH`   → [`ZkStartupMode::GenesisAnchoredRolling`]
///    (the new genesis-anchored lineage path engages ONLY when the static current
///    pin is absent).
/// 3. else                            → `Err`. There is NEVER a mode where nothing
///    is verified; a mainnet node with neither pin refuses to start.
///
/// After ossification at 101 the operator re-pins `ZK_PARAMS_HASH` to the v101
/// file hash and selection returns to `StaticPin` automatically.
pub fn select_startup_mode() -> ZkResult<ZkStartupMode> {
    let static_pin_set = std::env::var(ZK_PARAMS_HASH_ENV).is_ok();
    if static_pin_set {
        return Ok(ZkStartupMode::StaticPin);
    }
    match genesis_params_hash()? {
        Some(genesis_anchor) => Ok(ZkStartupMode::GenesisAnchoredRolling { genesis_anchor }),
        None => Err(ZkError::InvalidParams(format!(
            "Trusted-setup verification is unconfigured: neither {} (static pin) nor {} \
             (genesis anchor) is set. Refusing to start — the trusted setup must never run \
             unverified. Set {} to the pinned current-params SHA-256 (frozen/ossified), or \
             {} to the immutable genesis lineage hash (rolling).",
            ZK_PARAMS_HASH_ENV,
            ZK_GENESIS_PARAMS_HASH_ENV,
            ZK_PARAMS_HASH_ENV,
            ZK_GENESIS_PARAMS_HASH_ENV
        ))),
    }
}

/// AUTONOMOUS OSSIFICATION selector: choose the startup verification mode with
/// the DB ossification latch taking ABSOLUTE precedence over the environment.
///
/// `ossified_file_hash` is the `mpc_ceremony.ossified_file_hash` column: `Some`
/// exactly when the ceremony has reached `MAX_CEREMONY_CONTRIBUTORS` and the final
/// params file hash was durably recorded. When present, this returns
/// [`ZkStartupMode::OssifiedPinned`] REGARDLESS of `ZK_PARAMS_HASH` /
/// `ZK_GENESIS_PARAMS_HASH` — the trusted setup is final, so no env var (which an
/// operator may have left pointing at a now-stale intermediate hash) can override
/// the frozen pin. When absent, selection falls back to [`select_startup_mode`]
/// (StaticPin / GenesisAnchoredRolling), unchanged.
///
/// This is the mechanism that lets a node self-pin at the cap with no operator
/// action, surviving restarts and fresh joins forever: the DB flag drives it.
pub fn select_startup_mode_with_ossification(
    ossified_file_hash: Option<[u8; 32]>,
) -> ZkResult<ZkStartupMode> {
    if let Some(file_hash) = ossified_file_hash {
        return Ok(ZkStartupMode::OssifiedPinned { file_hash });
    }
    select_startup_mode()
}

/// Streaming raw-file SHA-256 (available in every build, unlike the
/// zk-production-gated [`compute_params_file_hash`]). Matches
/// `ghost_mpc::params::hash_params_file` and a `ZK_PARAMS_HASH=BLOCK:<hex>` pin.
fn sha256_file_raw(path: &std::path::Path) -> ZkResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to open params file: {e}")))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| ZkError::InvalidParams(format!("Failed to read params file: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher.finalize().into())
}

/// FAIL-CLOSED verification for [`ZkStartupMode::OssifiedPinned`]: the on-disk
/// `note_spend_params_current.bin` in `params_dir` MUST hash to `expected`.
///
/// A missing file, an unreadable file, or ANY hash mismatch returns `Err`, so a
/// tampered or wrong params file can never run under the ossified pin. This is
/// the ossified analogue of the `ZK_PARAMS_HASH` BLOCK check `load_trusted_params`
/// performs — same digest, same fail-closed posture — but sourcing the pin from
/// the DB latch instead of an env var.
pub fn verify_ossified_current_params(
    params_dir: &std::path::Path,
    expected: &[u8; 32],
) -> ZkResult<()> {
    let current = params_dir.join("note_spend_params_current.bin");
    if !current.exists() {
        return Err(ZkError::InvalidParams(format!(
            "OSSIFIED PIN: {} is missing — refusing to start (fail-closed). The ceremony has \
             ossified; the final trusted-setup params must be present and match the recorded pin.",
            current.display()
        )));
    }
    let actual = sha256_file_raw(&current)?;
    if &actual != expected {
        return Err(ZkError::InvalidParams(format!(
            "OSSIFIED PIN MISMATCH: {} hashes to {} but the permanently-recorded ossified pin is \
             {}. The trusted-setup params are tampered or wrong — refusing to start (fail-closed).",
            current.display(),
            hex::encode(actual),
            hex::encode(expected)
        )));
    }
    tracing::info!(
        pin = %hex::encode(expected),
        "OSSIFIED PIN verified: on-disk trusted-setup params match the permanent ossified file hash"
    );
    Ok(())
}

/// 2.4 HIGH: Compute SHA-256 hash of a parameters file
///
/// Streams the file to handle large parameter sets efficiently.
#[cfg(feature = "zk-production")]
fn compute_params_file_hash(path: &std::path::Path) -> ZkResult<[u8; 32]> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to open params file: {}", e)))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| ZkError::InvalidParams(format!("Failed to read params file: {}", e)))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().into())
}

/// 2.4 HIGH: Parse expected hashes from environment variable
#[cfg(feature = "zk-production")]
fn parse_expected_hashes() -> ZkResult<std::collections::HashMap<String, [u8; 32]>> {
    use std::env;

    let hash_env = env::var(ZK_PARAMS_HASH_ENV).map_err(|_| {
        ZkError::InvalidParams(format!(
            "2.4 HIGH: Production mode requires {} environment variable. \
             Set to ceremony output hashes in format: BLOCK:sha256hex,PAYOUT:sha256hex",
            ZK_PARAMS_HASH_ENV
        ))
    })?;

    let mut hashes = std::collections::HashMap::new();

    for pair in hash_env.split(',') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() != 2 {
            return Err(ZkError::InvalidParams(format!(
                "Invalid hash format: {}. Expected TYPE:sha256hex",
                pair
            )));
        }

        let param_type = parts[0].to_uppercase();
        let hash_hex = parts[1];

        if hash_hex.len() != 64 {
            return Err(ZkError::InvalidParams(format!(
                "Invalid hash length for {}: expected 64 hex chars, got {}",
                param_type,
                hash_hex.len()
            )));
        }

        let hash_bytes: [u8; 32] = hex::decode(hash_hex)
            .map_err(|e| ZkError::InvalidParams(format!("Invalid hex in hash: {}", e)))?
            .try_into()
            .map_err(|_| ZkError::InvalidParams("Hash decode failed".to_string()))?;

        hashes.insert(param_type, hash_bytes);
    }

    Ok(hashes)
}

/// H-1: Load and validate trusted setup parameters
///
/// In production mode (`zk-production` feature enabled):
/// - Loads parameters from `ZK_PARAMS_PATH` environment variable
/// - Verifies parameters match expected hash from ceremony (2.4 HIGH)
/// - Returns error if parameters are missing, invalid, or tampered
///
/// In test mode (default):
/// - Uses default test parameters
/// - Logs a warning that these should not be used for production
///
/// # Errors
///
/// Returns `ZkError::InvalidParams` if production mode is enabled but
/// parameters are missing, corrupted, or don't match expected hashes.
#[cfg(feature = "zk-production")]
pub fn load_trusted_params() -> ZkResult<()> {
    use std::env;
    use std::path::PathBuf;

    let params_path = env::var(ZK_PARAMS_PATH_ENV).map_err(|_| {
        ZkError::InvalidParams(format!(
            "H-1: Production mode enabled but {} environment variable not set. \
             Complete MPC ceremony and set path to ceremony output.",
            ZK_PARAMS_PATH_ENV
        ))
    })?;

    let base_path = PathBuf::from(&params_path);
    if !base_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "H-1: Trusted setup parameters not found at {}. \
             Complete MPC ceremony first.",
            params_path
        )));
    }

    // 2.4 HIGH: Verify parameter hashes against ceremony output
    let expected_hashes = parse_expected_hashes()?;

    // Check note spend parameters
    let note_spend_params_path = base_path.join("note_spend_params_current.bin");
    if note_spend_params_path.exists() {
        let actual_hash = compute_params_file_hash(&note_spend_params_path)?;
        // GHOST-06: fail closed. Previously a MISSING BLOCK hash silently skipped
        // verification, so a tampered trusted-setup file would load unchecked in
        // production. In zk-production the param file present without a pinned
        // BLOCK hash is a hard error.
        let expected = expected_hashes.get("BLOCK").ok_or_else(|| {
            ZkError::InvalidParams(
                "GHOST-06: note_spend params present but ZK_PARAMS_HASH has no BLOCK entry — \
                 refusing to load unverified trusted-setup parameters. \
                 Set ZK_PARAMS_HASH=BLOCK:<sha256hex> from the ceremony output."
                    .to_string(),
            )
        })?;
        if &actual_hash != expected {
            return Err(ZkError::InvalidParams(format!(
                "2.4 HIGH: Note spend parameter hash mismatch! \
                 Expected: {}, Got: {}. \
                 Parameters may be corrupted or tampered.",
                hex::encode(expected),
                hex::encode(actual_hash)
            )));
        }
        tracing::info!(
            hash = %hex::encode(actual_hash),
            "2.4 HIGH: Note spend parameters hash verified"
        );
    }

    tracing::info!(
        path = %params_path,
        "H-1: Loaded and verified trusted setup parameters for production mode"
    );

    Ok(())
}

/// H-1: Load trusted setup parameters (test mode)
#[cfg(not(feature = "zk-production"))]
pub fn load_trusted_params() -> ZkResult<()> {
    tracing::warn!(
        "H-1: ZK production mode NOT enabled. Using test parameters only. \
         These proofs should NOT be trusted for mainnet security. \
         Enable 'zk-production' feature for production deployment."
    );
    Ok(())
}

// ============================================================================
// C-5: Startup Verification for Mainnet Deployment
// ============================================================================

/// C-5: Verify ZK trusted setup is properly configured for mainnet
///
/// This function MUST be called at startup on mainnet deployments.
/// It performs comprehensive checks to ensure ZK proofs can be trusted:
///
/// 1. Checks if `zk-production` feature is enabled
/// 2. Verifies `ZK_PARAMS_PATH` environment variable is set
/// 3. Verifies parameter files exist at the specified path
/// 4. Validates parameter hashes match ceremony output
///
/// # Errors
///
/// Returns `ZkError::InvalidParams` if:
/// - Production feature is not enabled but `is_mainnet` is true
/// - `ZK_PARAMS_PATH` is not set
/// - Parameter files are missing
/// - Parameter hashes don't match expected values
///
/// # Example
///
/// ```ignore
/// // At startup:
/// if is_mainnet {
///     verify_zk_setup_for_mainnet()?;
/// }
/// ```
#[cfg(feature = "zk-production")]
pub fn verify_zk_setup_for_mainnet() -> ZkResult<()> {
    use std::path::PathBuf;

    tracing::info!("C-5: Verifying ZK trusted setup for mainnet deployment");

    // Step 1: Verify ZK_PARAMS_PATH is set
    let params_path = std::env::var(ZK_PARAMS_PATH_ENV).map_err(|_| {
        ZkError::InvalidParams(format!(
            "C-5 CRITICAL: Mainnet requires {} environment variable. \
             Set path to trusted setup ceremony output directory.",
            ZK_PARAMS_PATH_ENV
        ))
    })?;

    // Step 2: Verify base path exists
    let base_path = PathBuf::from(&params_path);
    if !base_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "C-5 CRITICAL: Trusted setup directory not found: {}. \
             Complete MPC ceremony first.",
            params_path
        )));
    }

    // Step 3: Verify note spend parameter file exists
    let note_spend_params = base_path.join("note_spend_params_current.bin");

    if !note_spend_params.exists() {
        return Err(ZkError::InvalidParams(format!(
            "C-5 CRITICAL: note_spend_params_current.bin not found in {}. \
             Complete MPC ceremony first.",
            params_path
        )));
    }

    // Step 4: Verify parameter hashes are configured
    if std::env::var(ZK_PARAMS_HASH_ENV).is_err() {
        return Err(ZkError::InvalidParams(format!(
            "C-5 CRITICAL: {} environment variable not set. \
             Set to ceremony output hash: BLOCK:sha256hex",
            ZK_PARAMS_HASH_ENV
        )));
    }

    // Step 5: Load and verify parameters (this validates hashes)
    load_trusted_params()?;

    tracing::info!(
        path = %params_path,
        "C-5: ZK trusted setup verified successfully for mainnet"
    );

    Ok(())
}

/// C-5: Verify ZK trusted setup (non-production mode)
///
/// In non-production mode, this returns an error when called on mainnet,
/// as ZK proofs cannot be trusted without the proper ceremony parameters.
#[cfg(not(feature = "zk-production"))]
pub fn verify_zk_setup_for_mainnet() -> ZkResult<()> {
    Err(ZkError::InvalidParams(
        "C-5 CRITICAL: zk-production feature is NOT enabled. \
         Mainnet deployment REQUIRES trusted setup ceremony. \
         Compile with --features zk-production after completing MPC ceremony."
            .to_string(),
    ))
}

/// C-5: Check if ZK setup is valid for mainnet (non-throwing version)
///
/// Returns true if ZK trusted setup is properly configured for mainnet,
/// false otherwise. Use this for conditional logic; use
/// `verify_zk_setup_for_mainnet()` when you want detailed error messages.
pub fn is_zk_setup_valid_for_mainnet() -> bool {
    verify_zk_setup_for_mainnet().is_ok()
}

// ============================================================================
// NoteSpend Verifier Loading
// ============================================================================

/// Load a NoteSpend verifying key from disk.
///
/// Reads a `VerifyingKey<Bls12>` file, prepares it for efficient verification,
/// and returns a `GhostNoteVerifier` ready to verify NoteSpend Groth16 proofs.
///
/// The VK file is typically `note_spend_vk.bin` from the MPC ceremony or
/// extracted from `note_spend_params_current.bin`.
pub fn load_note_spend_verifier(
    vk_path: &std::path::Path,
    tree_depth: usize,
) -> ZkResult<GhostNoteVerifier> {
    use bellperson::groth16::{prepare_verifying_key, VerifyingKey};
    use blstrs::Bls12;
    use std::io::BufReader;

    if !vk_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "NoteSpend VK not found: {}",
            vk_path.display()
        )));
    }

    let file = std::fs::File::open(vk_path)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to open VK: {}", e)))?;
    let reader = BufReader::new(file);

    let vk: VerifyingKey<Bls12> = VerifyingKey::read(reader)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to read VK: {}", e)))?;

    let prepared_vk = prepare_verifying_key(&vk);

    // Compute prover ID (must match what GhostNoteProver uses)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-note-prover-v1");
    hasher.update(tree_depth.to_le_bytes());
    let prover_id: [u8; 32] = hasher.finalize().into();

    Ok(GhostNoteVerifier::new(
        std::sync::Arc::new(prepared_vk),
        prover_id,
    ))
}

// ============================================================================
// Consolidation Verifier Loading
// ============================================================================

/// Load a NoteConsolidate verifying key from disk.
///
/// Reads a `VerifyingKey<Bls12>` file, prepares it for efficient verification,
/// and returns a `GhostConsolidateVerifier` ready to verify consolidation Groth16 proofs.
///
/// The VK file is typically `consolidation_vk.bin` from the MPC ceremony (slot 2).
pub fn load_consolidation_verifier(
    vk_path: &std::path::Path,
    tree_depth: usize,
) -> ZkResult<GhostConsolidateVerifier> {
    use bellperson::groth16::{prepare_verifying_key, VerifyingKey};
    use blstrs::Bls12;
    use std::io::BufReader;

    if !vk_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "Consolidation VK not found: {}",
            vk_path.display()
        )));
    }

    let file = std::fs::File::open(vk_path)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to open VK: {}", e)))?;
    let reader = BufReader::new(file);

    let vk: VerifyingKey<Bls12> = VerifyingKey::read(reader)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to read VK: {}", e)))?;

    let prepared_vk = prepare_verifying_key(&vk);

    // Compute prover ID (must match what GhostConsolidateProver uses)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-consolidation-prover-v1");
    hasher.update(tree_depth.to_le_bytes());
    let prover_id: [u8; 32] = hasher.finalize().into();

    Ok(GhostConsolidateVerifier::new(
        std::sync::Arc::new(prepared_vk),
        prover_id,
    ))
}

// ============================================================================
// Unshield Verifier Loading
// ============================================================================

/// Load an Unshield verifying key from disk.
///
/// Reads a `VerifyingKey<Bls12>` file, prepares it for efficient verification,
/// and returns a `GhostUnshieldVerifier` ready to verify unshield Groth16 proofs.
///
/// The VK file is typically `unshield_vk.bin` from the MPC ceremony (slot 3).
pub fn load_unshield_verifier(
    vk_path: &std::path::Path,
    tree_depth: usize,
) -> ZkResult<GhostUnshieldVerifier> {
    use bellperson::groth16::{prepare_verifying_key, VerifyingKey};
    use blstrs::Bls12;
    use std::io::BufReader;

    if !vk_path.exists() {
        return Err(ZkError::InvalidParams(format!(
            "Unshield VK not found: {}",
            vk_path.display()
        )));
    }

    let file = std::fs::File::open(vk_path)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to open VK: {}", e)))?;
    let reader = BufReader::new(file);

    let vk: VerifyingKey<Bls12> = VerifyingKey::read(reader)
        .map_err(|e| ZkError::InvalidParams(format!("Failed to read VK: {}", e)))?;

    let prepared_vk = prepare_verifying_key(&vk);

    // Compute prover ID (must match what GhostUnshieldProver uses)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-zkp-unshield-prover-v1");
    hasher.update(tree_depth.to_le_bytes());
    let prover_id: [u8; 32] = hasher.finalize().into();

    Ok(GhostUnshieldVerifier::new(
        std::sync::Arc::new(prepared_vk),
        prover_id,
    ))
}

// ============================================================================
// L-8: Startup Warning for Simulated Proofs
// ============================================================================

/// L-8 FIX: Check and log warning if simulated proofs are enabled at startup.
///
/// This function should be called during application initialization to provide
/// a clear warning at startup if the GHOST_ALLOW_SIMULATED_PROOFS environment
/// variable is set. This makes it immediately visible in logs that the system
/// is running in an insecure development mode.
///
/// # Security Warning
///
/// Simulated proofs bypass all cryptographic verification. They should NEVER
/// be enabled in production. This startup check ensures operators are immediately
/// aware if this dangerous setting is enabled.
///
/// # Example
///
/// ```ignore
/// // In main.rs or server initialization:
/// ghost_zkp::check_simulated_proofs_warning();
/// ```
pub fn check_simulated_proofs_warning() {
    // Check if on mainnet - simulated proofs are NEVER allowed regardless of env var
    let is_mainnet = std::env::var("GHOST_NETWORK")
        .map(|v| v.to_lowercase() == "mainnet" || v.to_lowercase() == "bitcoin")
        .unwrap_or(false);

    if is_mainnet {
        // On mainnet, simulated proofs are blocked at runtime anyway
        // Just log that we're in production mode
        tracing::info!(
            "L-8: Running on mainnet - simulated proofs are blocked regardless of environment settings"
        );
        return;
    }

    // Check if GHOST_ALLOW_SIMULATED_PROOFS is set
    let allow_simulated = std::env::var("GHOST_ALLOW_SIMULATED_PROOFS")
        .map(|v| v == "1")
        .unwrap_or(false);

    if allow_simulated {
        // L-8: Log a prominent startup warning
        tracing::error!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        tracing::error!("L-8 SECURITY WARNING: GHOST_ALLOW_SIMULATED_PROOFS=1 is enabled!");
        tracing::error!("Simulated proofs bypass ALL cryptographic verification.");
        tracing::error!("This MUST NOT be used in production - proofs can be forged!");
        tracing::error!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    } else {
        tracing::debug!(
            "L-8: Simulated proofs are disabled (GHOST_ALLOW_SIMULATED_PROOFS not set to 1)"
        );
    }
}

// ============================================================================
// Stage C: Genesis anchor + startup mode-selection tests
// ============================================================================

#[cfg(test)]
mod startup_mode_tests {
    use super::*;
    use std::sync::Mutex;

    // Env vars are process-global; serialize the mode-selection tests so they
    // do not clobber each other's `ZK_PARAMS_HASH` / `ZK_GENESIS_PARAMS_HASH`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard that clears both vars on entry and on drop, so each test runs
    /// against a known-clean environment regardless of ordering.
    struct EnvScrub;
    impl EnvScrub {
        fn new() -> Self {
            std::env::remove_var(ZK_PARAMS_HASH_ENV);
            std::env::remove_var(ZK_GENESIS_PARAMS_HASH_ENV);
            EnvScrub
        }
    }
    impl Drop for EnvScrub {
        fn drop(&mut self) {
            std::env::remove_var(ZK_PARAMS_HASH_ENV);
            std::env::remove_var(ZK_GENESIS_PARAMS_HASH_ENV);
        }
    }

    const ANCHOR_HEX: &str = "c9c907f688fc1102000000000000000000000000000000000000000000000000";

    fn anchor_bytes() -> [u8; 32] {
        hex::decode(ANCHOR_HEX).unwrap().try_into().unwrap()
    }

    #[test]
    fn test_genesis_hash_unset_is_none() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        assert_eq!(genesis_params_hash().unwrap(), None);
    }

    #[test]
    fn test_genesis_hash_valid_parses() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, ANCHOR_HEX);
        assert_eq!(genesis_params_hash().unwrap(), Some(anchor_bytes()));
    }

    #[test]
    fn test_genesis_hash_malformed_is_error_not_none() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        // Wrong length — must FAIL, never silently degrade to None.
        std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, "deadbeef");
        assert!(genesis_params_hash().is_err());
        // Non-hex of the right length — must FAIL.
        std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, "z".repeat(64));
        assert!(genesis_params_hash().is_err());
    }

    #[test]
    fn test_mode_static_pin_when_zk_params_hash_set() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        std::env::set_var(ZK_PARAMS_HASH_ENV, "BLOCK:00");
        assert_eq!(select_startup_mode().unwrap(), ZkStartupMode::StaticPin);
        // Static pin wins even if the genesis anchor is ALSO set (frozen path).
        std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, ANCHOR_HEX);
        assert_eq!(select_startup_mode().unwrap(), ZkStartupMode::StaticPin);
    }

    #[test]
    fn test_mode_rolling_when_only_genesis_anchor_set() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, ANCHOR_HEX);
        assert_eq!(
            select_startup_mode().unwrap(),
            ZkStartupMode::GenesisAnchoredRolling {
                genesis_anchor: anchor_bytes()
            }
        );
    }

    #[test]
    fn test_mode_refuses_when_neither_set() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        // Neither pin present → never an unverified mode; selection errors.
        assert!(select_startup_mode().is_err());
    }

    #[test]
    fn test_ossified_pin_overrides_static_pin_env() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        // Operator left a STALE static pin in the env — the DB ossification latch
        // must take absolute precedence and select OssifiedPinned with the DB hash.
        std::env::set_var(ZK_PARAMS_HASH_ENV, "BLOCK:00");
        let db_pin = [0xEE; 32];
        assert_eq!(
            select_startup_mode_with_ossification(Some(db_pin)).unwrap(),
            ZkStartupMode::OssifiedPinned { file_hash: db_pin }
        );
    }

    #[test]
    fn test_ossified_pin_overrides_genesis_anchor_env() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, ANCHOR_HEX);
        let db_pin = [0x11; 32];
        assert_eq!(
            select_startup_mode_with_ossification(Some(db_pin)).unwrap(),
            ZkStartupMode::OssifiedPinned { file_hash: db_pin }
        );
    }

    #[test]
    fn test_ossified_pin_absent_falls_back_to_env_mode() {
        let _g = ENV_LOCK.lock().unwrap();
        let _s = EnvScrub::new();
        std::env::set_var(ZK_GENESIS_PARAMS_HASH_ENV, ANCHOR_HEX);
        // No DB latch → behave exactly like select_startup_mode (rolling here).
        assert_eq!(
            select_startup_mode_with_ossification(None).unwrap(),
            ZkStartupMode::GenesisAnchoredRolling {
                genesis_anchor: anchor_bytes()
            }
        );
        // And with NOTHING configured, absence still refuses (never unverified).
        std::env::remove_var(ZK_GENESIS_PARAMS_HASH_ENV);
        assert!(select_startup_mode_with_ossification(None).is_err());
    }

    #[test]
    fn test_verify_ossified_params_pass_and_tamper_fail() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("note_spend_params_current.bin");
        let bytes = b"final ossified trusted-setup parameters blob";
        std::fs::write(&path, bytes).unwrap();
        let expected: [u8; 32] = Sha256::digest(bytes).into();

        // Matching file → OK.
        assert!(verify_ossified_current_params(dir.path(), &expected).is_ok());

        // Tampered file (same path, different bytes) → FAIL closed.
        std::fs::write(&path, b"tampered params blob of a different length!!").unwrap();
        assert!(verify_ossified_current_params(dir.path(), &expected).is_err());

        // Missing file → FAIL closed.
        std::fs::remove_file(&path).unwrap();
        assert!(verify_ossified_current_params(dir.path(), &expected).is_err());
    }
}
