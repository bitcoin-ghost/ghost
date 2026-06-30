//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| FILE: mpc.rs                                                                                                         |
//|======================================================================================================================|

//! Shared MPC ceremony primitives.
//!
//! These are the consensus-critical, wire-format building blocks of the rolling
//! MPC ceremony that must be IDENTICAL on every code path that hashes a
//! contribution, signs/verifies a vote, or computes the BFT quorum.
//!
//! They live in `ghost-common` (the leaf dependency) so that all of the
//! following observe ONE definition and can never silently diverge:
//!
//! * `ghost-consensus` (the live voter/handler) — builds the wire messages.
//! * `ghost-storage` (the genesis-anchored startup verifier) — re-derives the
//!   contribution hash + vote signing message from retained DB rows to check the
//!   retained BFT quorum, WITHOUT keeping every historical parameter blob.
//! * `ghost-mpc` — re-exports the threshold so the library and the handler agree.
//!
//! A change to any of these byte layouts is a hard consensus fork; they are
//! pinned with explicit `v1` domain separators and round-trip tests.

use crate::constants::{MPC_BFT_BOOTSTRAP_COUNT, MPC_BFT_THRESHOLD_PERCENT};
use crate::types::NodeId;
use sha2::{Digest, Sha256};

/// Domain separator for the contribution identity hash.
const CONTRIBUTION_HASH_DOMAIN: &[u8] = b"MpcContributionHash/v1";
/// Domain separator for the per-vote signing message.
const VOTE_SIGNING_DOMAIN: &[u8] = b"MpcVerificationVote/v1";

/// Compute the stable identity hash of a contribution.
///
/// This is the value a verification vote references (and signs over). It binds
/// the contribution to its `contributor`, `position`, and resulting
/// `new_params_hash` (the lineage hash). It deliberately does NOT include the
/// proof bytes or prev hash — the vote attests to "I approve THIS new params at
/// THIS position from THIS contributor"; the prev/lineage link is enforced
/// separately by the chain-link check.
///
/// SECURITY: byte layout is consensus-critical and matches the live wire
/// message (`MpcContributionMessage::contribution_hash`) exactly.
pub fn contribution_hash(
    contributor: &NodeId,
    elder_position: u32,
    new_params_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CONTRIBUTION_HASH_DOMAIN);
    hasher.update(contributor);
    hasher.update(elder_position.to_le_bytes());
    hasher.update(new_params_hash);
    hasher.finalize().into()
}

/// Compute the message an elder signs when voting on a contribution.
///
/// Binds the `contribution_hash` and the approve/reject bit. SECURITY: byte
/// layout matches the live wire message (`MpcVerificationVoteMessage::
/// signing_message`) exactly so a retained vote signature verifies identically
/// whether checked live or re-derived at startup from DB rows.
pub fn vote_signing_message(contribution_hash: &[u8; 32], approve: bool) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VOTE_SIGNING_DOMAIN);
    hasher.update(contribution_hash);
    hasher.update([approve as u8]);
    hasher.finalize().into()
}

/// Compute the BFT threshold (number of approve votes required) for an MPC
/// contribution given the number of *eligible* contributors at the time it was
/// voted on.
///
/// SINGLE SOURCE OF TRUTH. The live voter (`ghost-consensus`) and the retained
/// quorum check at startup (`ghost-storage`) MUST use this identical function:
/// the startup check verifies a contribution under EXACTLY the same rule it was
/// approved under. If startup demanded a stricter quorum than the live path
/// applied, a legitimately-approved chain would fail-closed and brick the node;
/// if it demanded a weaker one, a forged chain could slip in. Both are avoided
/// by sharing this one definition.
///
/// During bootstrap (fewer than `MPC_BFT_BOOTSTRAP_COUNT` contributors) the
/// threshold is 1; at or above it the threshold is the
/// `MPC_BFT_THRESHOLD_PERCENT` supermajority `ceil(count * percent / 100)`.
pub fn mpc_bft_threshold(contributor_count: u32) -> u32 {
    if contributor_count < MPC_BFT_BOOTSTRAP_COUNT {
        1
    } else {
        contributor_count
            .saturating_mul(MPC_BFT_THRESHOLD_PERCENT)
            .div_ceil(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contribution_hash_is_stable_and_layout_pinned() {
        let contributor = [0x11u8; 32];
        let new = [0x22u8; 32];
        let h = contribution_hash(&contributor, 7, &new);

        // Recompute the expected digest independently (the pinned layout).
        let mut hasher = Sha256::new();
        hasher.update(b"MpcContributionHash/v1");
        hasher.update(contributor);
        hasher.update(7u32.to_le_bytes());
        hasher.update(new);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(h, expected);

        // Different position / contributor / hash all change the digest.
        assert_ne!(h, contribution_hash(&contributor, 8, &new));
        assert_ne!(h, contribution_hash(&[0x33; 32], 7, &new));
        assert_ne!(h, contribution_hash(&contributor, 7, &[0x44; 32]));
    }

    #[test]
    fn test_vote_signing_message_distinguishes_approve_reject() {
        let ch = [0xAB; 32];
        let approve = vote_signing_message(&ch, true);
        let reject = vote_signing_message(&ch, false);
        assert_ne!(
            approve, reject,
            "approve and reject must sign distinct bytes"
        );

        let mut hasher = Sha256::new();
        hasher.update(b"MpcVerificationVote/v1");
        hasher.update(ch);
        hasher.update([1u8]);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(approve, expected);
    }

    #[test]
    fn test_mpc_bft_threshold_matches_documented_rule() {
        // Bootstrap range (< 4): threshold 1.
        assert_eq!(mpc_bft_threshold(0), 1);
        assert_eq!(mpc_bft_threshold(1), 1);
        assert_eq!(mpc_bft_threshold(3), 1);
        // Supermajority at/above bootstrap.
        assert_eq!(mpc_bft_threshold(4), 3); // ceil(268/100)
        assert_eq!(mpc_bft_threshold(10), 7); // ceil(670/100)
        assert_eq!(mpc_bft_threshold(100), 67);
        assert_eq!(mpc_bft_threshold(101), 68); // ceil(6767/100)
    }
}
