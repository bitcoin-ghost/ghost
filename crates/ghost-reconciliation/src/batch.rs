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
//| FILE: batch.rs                                                                                                       |
//|======================================================================================================================|

//! The settlement Merkle tree: domain-separated, leaf-count-bound, odd leaves carried forward.
//!
//! The share shard commits each epoch's shares under this tree, so it outlives the settlement
//! batches it was written for.

use sha2::{Digest, Sha256};

/// Domain separator for Ghost settlement merkle trees
const MERKLE_DOMAIN: &[u8] = b"GhostSettlementMerkle";

/// Compute merkle root from leaf hashes
///
/// This implementation is collision-resistant by:
/// 1. Including leaf count in the final hash (prevents `[A,B,C]` == `[A,B,C,C]`)
/// 2. Using domain separation (prevents cross-protocol attacks)
/// 3. Carrying forward odd elements instead of duplicating (prevents internal collisions)
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        // Empty tree has deterministic zero root with domain separation
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_DOMAIN);
        hasher.update(0u64.to_le_bytes());
        return hasher.finalize().into();
    }

    if leaves.len() == 1 {
        // Single leaf: hash with domain and count
        let mut hasher = Sha256::new();
        hasher.update(MERKLE_DOMAIN);
        hasher.update(1u64.to_le_bytes());
        hasher.update(leaves[0]);
        return hasher.finalize().into();
    }

    // Store original count for final hash
    let leaf_count = leaves.len() as u64;

    let mut current_level = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                // Two elements: hash them together
                let mut hasher = Sha256::new();
                hasher.update(current_level[i]);
                hasher.update(current_level[i + 1]);
                next_level.push(hasher.finalize().into());
                i += 2;
            } else {
                // Odd element: carry forward WITHOUT duplicating
                // This prevents [A,B,C] from colliding with [A,B,C,C]
                next_level.push(current_level[i]);
                i += 1;
            }
        }

        current_level = next_level;
    }

    // Final hash includes domain separator and leaf count
    // This makes roots unique per list length
    let mut final_hasher = Sha256::new();
    final_hasher.update(MERKLE_DOMAIN);
    final_hasher.update(leaf_count.to_le_bytes());
    final_hasher.update(current_level[0]);
    final_hasher.finalize().into()
}

/// Compute merkle proof for an element at given index
///
/// The proof includes sibling hashes needed to recompute the root.
/// For odd elements that are carried forward, we use a special marker.
pub fn compute_merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.is_empty() || index >= leaves.len() {
        return vec![];
    }

    let mut proof = Vec::new();
    let mut current_level = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };

        if sibling_idx < current_level.len() {
            // Normal case: include sibling
            proof.push(current_level[sibling_idx]);
        }
        // If no sibling (odd element at end), don't add anything
        // The verifier will know to carry forward

        // Build next level (same algorithm as compute_merkle_root)
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < current_level.len() {
            if i + 1 < current_level.len() {
                let mut hasher = Sha256::new();
                hasher.update(current_level[i]);
                hasher.update(current_level[i + 1]);
                next_level.push(hasher.finalize().into());
                i += 2;
            } else {
                // Carry forward odd element
                next_level.push(current_level[i]);
                i += 1;
            }
        }

        current_level = next_level;
        idx /= 2;
    }

    proof
}

/// M-17: Maximum merkle proof length to prevent DoS via oversized proofs
/// For a tree with N leaves, the maximum proof length is log2(N)
/// With MAX_BATCH_SIZE of 100, max proof length is ceil(log2(100)) = 7
/// We use 64 as a generous upper bound (supports up to 2^64 leaves)
const MAX_MERKLE_PROOF_LENGTH: usize = 64;

/// Verify a merkle proof
///
/// The proof must be verified against the original leaf count to prevent
/// collision attacks where `[A,B,C]` could be confused with `[A,B,C,C]`.
pub fn verify_merkle_proof(
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    root: &[u8; 32],
    index: usize,
    leaf_count: usize,
) -> bool {
    if leaf_count == 0 || index >= leaf_count {
        return false;
    }

    // M-17: Validate proof length to prevent DoS via oversized proofs
    if proof.len() > MAX_MERKLE_PROOF_LENGTH {
        return false;
    }

    // M-17: Validate proof length is consistent with leaf count
    // For N leaves, proof length should be at most ceil(log2(N))
    let expected_max_depth = if leaf_count <= 1 {
        0
    } else {
        (leaf_count as f64).log2().ceil() as usize
    };
    if proof.len() > expected_max_depth {
        return false;
    }

    let mut current = *leaf;
    let mut idx = index;
    let mut level_size = leaf_count;
    let mut proof_idx = 0;

    while level_size > 1 {
        let is_right = idx % 2 == 1;
        let has_sibling = if is_right {
            true // Right nodes always have a left sibling
        } else {
            idx + 1 < level_size // Left nodes only have sibling if not at end
        };

        if has_sibling {
            if proof_idx >= proof.len() {
                return false; // Proof too short
            }
            let sibling = &proof[proof_idx];
            proof_idx += 1;

            let mut hasher = Sha256::new();
            if is_right {
                hasher.update(sibling);
                hasher.update(current);
            } else {
                hasher.update(current);
                hasher.update(sibling);
            }
            current = hasher.finalize().into();
        }
        // If no sibling, current is carried forward unchanged

        idx /= 2;
        level_size = level_size.div_ceil(2);
    }

    // Final hash must include domain and leaf count
    let mut final_hasher = Sha256::new();
    final_hasher.update(MERKLE_DOMAIN);
    final_hasher.update((leaf_count as u64).to_le_bytes());
    final_hasher.update(current);
    let computed_root: [u8; 32] = final_hasher.finalize().into();

    &computed_root == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root() {
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        // Verify root is deterministic
        let root2 = compute_merkle_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_proof() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = compute_merkle_proof(&leaves, i);
            assert!(verify_merkle_proof(leaf, &proof, &root, i, leaves.len()));
        }
    }

    #[test]
    fn test_merkle_proof_odd_count() {
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = compute_merkle_proof(&leaves, i);
            assert!(verify_merkle_proof(leaf, &proof, &root, i, leaves.len()));
        }
    }

    #[test]
    fn test_merkle_collision_resistance() {
        // This test verifies the fix for CVE-2012-2459 style attacks
        // [A,B,C] and [A,B,C,C] must produce DIFFERENT roots

        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];

        let list1 = vec![a, b, c];
        let list2 = vec![a, b, c, c]; // C duplicated

        let root1 = compute_merkle_root(&list1);
        let root2 = compute_merkle_root(&list2);

        assert_ne!(
            root1, root2,
            "CRITICAL: Merkle roots must differ for different leaf counts"
        );

        // Also verify empty vs single element
        let empty_root = compute_merkle_root(&[]);
        let single_root = compute_merkle_root(&[a]);

        assert_ne!(empty_root, single_root, "Empty and single must differ");
        assert_ne!(single_root, a, "Single root must be hashed, not raw");
    }

    #[test]
    fn test_merkle_wrong_count_fails() {
        // Verify that proofs fail if wrong leaf count is used
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        let proof = compute_merkle_proof(&leaves, 0);

        // Correct count works
        assert!(verify_merkle_proof(&leaves[0], &proof, &root, 0, 4));

        // Wrong count fails
        assert!(!verify_merkle_proof(&leaves[0], &proof, &root, 0, 5));
        assert!(!verify_merkle_proof(&leaves[0], &proof, &root, 0, 3));
    }

    #[test]
    fn test_merkle_proof_length_validation() {
        // M-17: Test that oversized merkle proofs are rejected
        let leaf = [1u8; 32];
        let root = [2u8; 32];

        // Proof longer than MAX_MERKLE_PROOF_LENGTH should fail
        let oversized_proof: Vec<[u8; 32]> = (0..65).map(|i| [i as u8; 32]).collect();
        assert!(
            !verify_merkle_proof(&leaf, &oversized_proof, &root, 0, 4),
            "Oversized proof should be rejected"
        );

        // Proof longer than log2(leaf_count) should fail
        let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i; 32]).collect();
        let root = compute_merkle_root(&leaves);
        // For 4 leaves, proof should be at most 2 elements (log2(4) = 2)
        let oversized_for_tree: Vec<[u8; 32]> = (0..5).map(|i| [i as u8; 32]).collect();
        assert!(
            !verify_merkle_proof(&leaves[0], &oversized_for_tree, &root, 0, 4),
            "Proof longer than tree depth should be rejected"
        );
    }
}
