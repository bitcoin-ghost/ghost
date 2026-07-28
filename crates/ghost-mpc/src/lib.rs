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

#![deny(unreachable_pub)]

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
///
/// CONSENSUS CONSTANT — the mainnet value is 101 and is NOT runtime-tunable.
/// There is deliberately no environment variable or config knob: a consensus
/// constant that could be lowered at runtime on a production node would let an
/// attacker force an early ossification (or change the quorum geometry) on a
/// single node and split it from the fleet.
///
/// The ONLY way to obtain a smaller value is the compile-time `mpc-test-cap`
/// cargo feature, which exists solely so the regtest lifecycle harness (Stage D)
/// can walk genesis → contributions → ossification in seconds instead of needing
/// 101 multi-hundred-megabyte Groth16 contributions. The feature is:
///   * NOT in `default` features,
///   * never enabled by `ghost-pool`, `ghost-consensus`, or any shipping crate,
///   * only ever turned on by an explicit `--features mpc-test-cap` on a targeted
///     `-p ghost-mpc` test invocation,
/// so the production build (`cargo build -p ghost-pool --features zk-production`)
/// and a default `cargo build` both compile this as 101. A compile-time test
/// (`cap_tests::test_cap_is_mainnet_value_without_feature`) locks the invariant.
#[cfg(not(feature = "mpc-test-cap"))]
pub const MAX_CEREMONY_CONTRIBUTORS: u32 = 101;

/// TEST-ONLY ceremony cap (see [`MAX_CEREMONY_CONTRIBUTORS`] docs). Enabled ONLY
/// under the non-default `mpc-test-cap` cargo feature so the Stage D regtest
/// lifecycle harness can ossify quickly. NEVER compiled into a shipping binary.
#[cfg(feature = "mpc-test-cap")]
pub const MAX_CEREMONY_CONTRIBUTORS: u32 = 4;

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

#[cfg(test)]
mod cap_tests {
    //! Stage D: the ceremony cap must be the immutable mainnet value (101) in
    //! every build that does NOT explicitly opt into the `mpc-test-cap` test
    //! feature. This locks the invariant that the production binary keeps 101
    //! and that the small test cap can never leak into a shipping build.

    /// Without `mpc-test-cap`, the cap is exactly the mainnet 101. `cargo test
    /// -p ghost-mpc` (no `--features`) runs this and fails if the test cap ever
    /// leaks into the default build.
    #[cfg(not(feature = "mpc-test-cap"))]
    #[test]
    fn test_cap_is_mainnet_value_without_feature() {
        const {
            assert!(
                super::MAX_CEREMONY_CONTRIBUTORS == 101,
                "MAX_CEREMONY_CONTRIBUTORS must be 101 unless mpc-test-cap is explicitly enabled"
            )
        };
    }

    /// With `mpc-test-cap`, the cap is small enough to ossify a real-crypto
    /// ceremony in seconds, and is still strictly greater than the BFT bootstrap
    /// count so the supermajority-vs-bootstrap boundary remains meaningful.
    #[cfg(feature = "mpc-test-cap")]
    #[test]
    fn test_cap_is_small_under_test_feature() {
        const {
            assert!(
                super::MAX_CEREMONY_CONTRIBUTORS < 101,
                "test cap must be smaller than mainnet"
            )
        };
        const {
            assert!(
                super::MAX_CEREMONY_CONTRIBUTORS >= super::MPC_BFT_BOOTSTRAP_COUNT,
                "test cap should reach at least the bootstrap count"
            )
        };
    }
}
