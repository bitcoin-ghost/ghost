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

//! Ghost MPC - Rolling Multi-Party Computation Ceremony
//!
//! This crate implements a rolling MPC ceremony for generating trusted setup
//! parameters for Ghost's ZK proofs. Each new elder (up to 101) contributes
//! to the ceremony during registration.
//!
//! # Security Model
//!
//! The ceremony provides 1-of-N security: only ONE honest participant is needed
//! to ensure the toxic waste (tau, alpha, beta) is never recoverable. With 101
//! elders contributing, this provides extremely strong security guarantees.
//!
//! # Ceremony Lifecycle
//!
//! ```text
//! Elder 1  → Genesis params (founder contribution)
//! Elder 2  → Contributes → Parameters v2 active immediately
//! ...
//! Elder 100 → Contributes → Parameters v100 active immediately
//! Elder 101 → Contributes → OSSIFICATION (parameters permanent forever)
//! Elder 102+ → Normal registration, no MPC (ceremony closed)
//! ```
//!
//! # Integration with Elder Registration
//!
//! The MPC ceremony runs PARALLEL to elder registration:
//! 1. Candidate generates MPC contribution
//! 2. Candidate broadcasts contribution to network
//! 3. Elders verify contribution (>67% BFT approval required)
//! 4. On epoch transition, contribution is applied
//! 5. Parameters update immediately
//!
//! If MPC contribution fails, elder registration still proceeds - they just
//! don't contribute to the ceremony.
//!
//! # Ossification
//!
//! At elder 101, the ceremony ossifies permanently:
//! - No more contributions accepted
//! - Parameters become immutable
//! - New elders skip MPC step entirely

pub mod contribution;
pub mod errors;
pub mod manager;
pub mod params;
pub mod sync;

// Re-export main types
pub use contribution::{
    verify_contribution, verify_contribution_lineage, ContributionProof, MpcContribution,
    MultiContributionResult,
};
pub use errors::{MpcError, MpcResult};
pub use manager::{CeremonyManager, CeremonyState};
pub use params::{MpcParameters, ParameterFiles};
pub use sync::ParameterSync;

/// Concrete Groth16 proving-parameter type used throughout the ceremony.
///
/// Re-exported as a stable alias so downstream crates (notably
/// `ghost-consensus`, which wires the BFT voter to real cryptographic
/// verification) can name and hold the candidate parameters WITHOUT taking a
/// direct dependency on `bellperson`/`blstrs`. This is exactly the type
/// accepted by [`CeremonyManager::verify_contribution`] and
/// [`CeremonyManager::apply_contribution_multi`].
pub type Groth16Params = bellperson::groth16::Parameters<blstrs::Bls12>;

/// Maximum number of elders that contribute to the ceremony.
/// After this, the ceremony ossifies and parameters are permanent.
pub const MAX_CEREMONY_CONTRIBUTORS: u32 = 101;

/// Chunk size for P2P parameter transfer (1MB)
pub const PARAM_CHUNK_SIZE: usize = 1024 * 1024;

/// BFT threshold for contribution approval (67%).
///
/// Re-exported from `ghost-common` so `ghost-mpc` and `ghost-consensus`
/// (the voter/quorum path) share ONE definition. Changing the quorum on only
/// one side would split consensus — see `ghost_common::constants`.
pub use ghost_common::constants::{MPC_BFT_BOOTSTRAP_COUNT, MPC_BFT_THRESHOLD_PERCENT};

/// Re-export the single shared BFT-threshold FUNCTION (not just the constants)
/// so the ghost-mpc library, the ghost-consensus voter, and the ghost-storage
/// retained-quorum check all compute the required approve-vote count identically.
pub use ghost_common::mpc::mpc_bft_threshold;

/// Cross-check that on-disk parameters match the recorded lineage head.
///
/// Stage A task 3: this is the pure decision used at startup before a node may
/// enter the rolling ceremony. All three arguments are LINEAGE hashes
/// (`hash_parameters` — structured VK + h + l), NOT raw-file pin hashes.
///
/// * `file_lineage` — `hash_parameters()` of the parameters loaded from disk.
/// * `singleton_head` — `mpc_ceremony.current_params_hash`; `[0u8; 32]` means
///   "unknown" (pre-backfill / not established) and is not enforced.
/// * `contribution_head` — `mpc_contributions[MAX].new_params_hash`; `None`
///   means no head row exists, which is a failure for an advanced ceremony.
///
/// Returns `true` only when `file_lineage` matches the contribution head AND
/// (when known) the singleton head. Fail-closed: any missing/mismatched head
/// returns `false`.
pub fn lineage_head_matches(
    file_lineage: &[u8; 32],
    singleton_head: &[u8; 32],
    contribution_head: Option<&[u8; 32]>,
) -> bool {
    // The contribution head must be present and must match.
    match contribution_head {
        Some(head) if head == file_lineage => {}
        _ => return false,
    }
    // The singleton head, when established (non-zero), must also match.
    if *singleton_head != [0u8; 32] && singleton_head != file_lineage {
        return false;
    }
    true
}

#[cfg(test)]
mod lineage_tests {
    use super::lineage_head_matches;

    const A: [u8; 32] = [0xAA; 32];
    const B: [u8; 32] = [0xBB; 32];
    const ZERO: [u8; 32] = [0u8; 32];

    #[test]
    fn test_lineage_matches_when_all_agree() {
        assert!(lineage_head_matches(&A, &A, Some(&A)));
    }

    #[test]
    fn test_lineage_matches_when_singleton_unknown() {
        // Singleton head zero (pre-backfill) is not enforced; contribution head decides.
        assert!(lineage_head_matches(&A, &ZERO, Some(&A)));
    }

    #[test]
    fn test_lineage_rejects_mismatching_file_vs_contribution() {
        // A mismatching on-disk file is rejected (the plan's "reject a mismatching file").
        assert!(!lineage_head_matches(&B, &A, Some(&A)));
    }

    #[test]
    fn test_lineage_rejects_mismatching_singleton() {
        assert!(!lineage_head_matches(&A, &B, Some(&A)));
    }

    #[test]
    fn test_lineage_rejects_missing_contribution_head() {
        assert!(!lineage_head_matches(&A, &A, None));
    }
}

#[cfg(test)]
mod threshold_tests {
    //! Stage A task 1: the MPC BFT threshold must be a single, documented value
    //! (67%) shared between the `ghost-mpc` library and the `ghost-consensus`
    //! voter/quorum path. A divergence here would split consensus.

    /// The MPC quorum percentage is exactly the documented 67%.
    #[test]
    fn test_mpc_bft_threshold_is_67() {
        assert_eq!(super::MPC_BFT_THRESHOLD_PERCENT, 67);
        assert_eq!(super::MPC_BFT_BOOTSTRAP_COUNT, 4);
    }

    /// `ghost-mpc`'s re-export and the `ghost-common` source of truth agree.
    /// The `ghost-consensus` handler also sources `bft_threshold()` from this
    /// same `ghost_common::constants` value (see `mpc_handler::bft_threshold`),
    /// so all three agree by construction.
    #[test]
    fn test_mpc_bft_threshold_single_source() {
        assert_eq!(
            super::MPC_BFT_THRESHOLD_PERCENT,
            ghost_common::constants::MPC_BFT_THRESHOLD_PERCENT
        );
        assert_eq!(
            super::MPC_BFT_BOOTSTRAP_COUNT,
            ghost_common::constants::MPC_BFT_BOOTSTRAP_COUNT
        );
    }
}
