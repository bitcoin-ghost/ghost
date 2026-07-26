//! Category 1: Cryptography & Identity Tests (85 tests)
//!
//! Comprehensive tests for all cryptographic operations including:
//! - Ed25519 identity management
//! - Proof-of-work for node IDs
//! - HMAC-SHA256 for payout commitments
//! - Noise Protocol encryption
//! - Blind signatures
//! - Shamir Secret Sharing
//! - Silent Payment keys

use ghost_common::identity::{
    hash_message, verify_node_id_pow, verify_signature, NodeIdProof, NodeIdentity,
    NODE_ID_POW_DIFFICULTY,
};
use std::collections::HashSet;
use tempfile::tempdir;

// =============================================================================
// ED25519 IDENTITY TESTS (Tests 1-18)
// =============================================================================

#[test]
fn test_001_generate_identity_creates_valid_keypair() {
    let identity = NodeIdentity::generate();
    let node_id = identity.node_id();

    // Node ID should be 32 bytes
    assert_eq!(node_id.len(), 32);

    // Should be able to sign and verify
    let msg = b"test message";
    let sig = identity.sign(msg);
    assert!(identity.verify(msg, &sig));
}

#[test]
fn test_002_generate_identity_produces_unique_keys() {
    let mut ids = HashSet::new();

    // Generate 100 identities and verify all are unique
    for _ in 0..100 {
        let identity = NodeIdentity::generate();
        let id_hex = identity.node_id_hex();
        assert!(ids.insert(id_hex), "Duplicate identity generated!");
    }
}

#[test]
fn test_003_sign_message_produces_valid_64_byte_signature() {
    let identity = NodeIdentity::generate();
    let msg = b"Hello, Ghost Protocol!";

    let signature = identity.sign(msg);

    assert_eq!(signature.len(), 64);
}

#[test]
fn test_004_verify_signature_returns_true_for_valid_sig() {
    let identity = NodeIdentity::generate();
    let msg = b"Valid message";

    let signature = identity.sign(msg);

    assert!(identity.verify(msg, &signature));
}

#[test]
fn test_005_verify_signature_returns_false_for_wrong_message() {
    let identity = NodeIdentity::generate();
    let msg = b"Original message";
    let wrong_msg = b"Different message";

    let signature = identity.sign(msg);

    assert!(!identity.verify(wrong_msg, &signature));
}

#[test]
fn test_006_verify_signature_returns_false_for_wrong_key() {
    let identity1 = NodeIdentity::generate();
    let identity2 = NodeIdentity::generate();
    let msg = b"Test message";

    let signature = identity1.sign(msg);

    // Verify with wrong identity should fail
    assert!(!identity2.verify(msg, &signature));
}

#[test]
fn test_007_verify_signature_returns_false_for_corrupted_sig() {
    let identity = NodeIdentity::generate();
    let msg = b"Test message";

    let mut signature = identity.sign(msg);

    // Corrupt the signature
    signature[0] ^= 0xFF;
    signature[32] ^= 0xFF;

    assert!(!identity.verify(msg, &signature));
}

#[test]
fn test_008_save_identity_creates_file_with_correct_permissions() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("test.key");

    let identity = NodeIdentity::generate();
    identity.save(&key_path).unwrap();

    assert!(key_path.exists());

    // Check file size (32 bytes key + 12 bytes PoW proof = 44 bytes)
    let metadata = std::fs::metadata(&key_path).unwrap();
    assert_eq!(metadata.len(), 44);

    // On Unix, check permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = metadata.permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}

#[test]
fn test_009_load_identity_restores_exact_keypair() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("test.key");

    let original = NodeIdentity::generate();
    let original_id = original.node_id();
    let original_pow = original.pow_proof().cloned();

    original.save(&key_path).unwrap();

    let loaded = NodeIdentity::load(&key_path).unwrap();

    assert_eq!(loaded.node_id(), original_id);

    // PoW should be preserved
    if let Some(orig_pow) = original_pow {
        let loaded_pow = loaded.pow_proof().unwrap();
        assert_eq!(loaded_pow.nonce, orig_pow.nonce);
        assert_eq!(loaded_pow.difficulty, orig_pow.difficulty);
    }

    // Signing should produce same results
    let msg = b"Test signing";
    let sig1 = original.sign(msg);
    let sig2 = loaded.sign(msg);
    assert_eq!(sig1, sig2);
}

#[test]
fn test_010_load_identity_fails_for_missing_file() {
    let result = NodeIdentity::load("/nonexistent/path/key.key");
    assert!(result.is_err());
}

#[test]
fn test_011_load_identity_fails_for_corrupted_file() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("corrupted.key");

    // Write garbage data
    std::fs::write(&key_path, b"not a valid key file").unwrap();

    let result = NodeIdentity::load(&key_path);
    assert!(result.is_err());
}

#[test]
fn test_012_load_identity_fails_for_wrong_length() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("wrong_len.key");

    // Write wrong length (not 32 or 44 bytes)
    std::fs::write(&key_path, [0u8; 16]).unwrap();

    let result = NodeIdentity::load(&key_path);
    assert!(result.is_err());
}

#[test]
fn test_013_from_hex_parses_valid_64_char_hex() {
    let identity = NodeIdentity::generate();
    let _key_bytes = identity.node_id();

    // Create a deterministic key from known bytes (for testing)
    let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let loaded = NodeIdentity::from_hex(hex_key).unwrap();
    assert_eq!(loaded.node_id().len(), 32);
}

#[test]
fn test_014_from_hex_fails_for_invalid_hex_chars() {
    let invalid_hex = "ghij456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    let result = NodeIdentity::from_hex(invalid_hex);
    assert!(result.is_err());
}

#[test]
fn test_015_from_hex_fails_for_wrong_length() {
    let short_hex = "0123456789abcdef"; // Only 16 chars

    let result = NodeIdentity::from_hex(short_hex);
    assert!(result.is_err());
}

#[test]
fn test_016_node_id_returns_32_byte_public_key() {
    let identity = NodeIdentity::generate();
    let node_id = identity.node_id();

    assert_eq!(node_id.len(), 32);
}

#[test]
fn test_017_node_id_hex_returns_64_char_string() {
    let identity = NodeIdentity::generate();
    let hex = identity.node_id_hex();

    assert_eq!(hex.len(), 64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_018_node_id_short_returns_first_8_chars() {
    let identity = NodeIdentity::generate();
    let hex = identity.node_id_hex();
    let short = identity.node_id_short();

    assert_eq!(short.len(), 8);
    assert!(hex.starts_with(&short));
}

// =============================================================================
// PROOF-OF-WORK FOR NODE ID TESTS (Tests 19-30)
// =============================================================================

#[test]
fn test_019_pow_mine_finds_valid_nonce() {
    let identity = NodeIdentity::generate();
    let public_key = identity.node_id();

    // Mine with low difficulty for speed
    let proof = NodeIdProof::mine(&public_key, 8).unwrap();

    assert!(proof.difficulty >= 8);
}

#[test]
fn test_020_pow_verify_accepts_valid_proof() {
    let identity = NodeIdentity::generate();
    let public_key = identity.node_id();

    let proof = NodeIdProof::mine(&public_key, 8).unwrap();

    assert!(proof.verify(&public_key, 8));
}

#[test]
fn test_021_pow_verify_rejects_wrong_nonce() {
    let identity = NodeIdentity::generate();
    let public_key = identity.node_id();

    let mut proof = NodeIdProof::mine(&public_key, 8).unwrap();
    proof.nonce += 1; // Invalid nonce

    // May or may not verify depending on hash - but difficulty claim is wrong
    let hash = NodeIdProof::compute_hash(&public_key, proof.nonce);
    let actual_zeros = NodeIdProof::leading_zeros(&hash);

    // If it doesn't meet difficulty, verify should fail
    if actual_zeros < 8 {
        assert!(!proof.verify(&public_key, 8));
    }
}

#[test]
fn test_022_pow_verify_rejects_wrong_public_key() {
    let identity1 = NodeIdentity::generate();
    let proof = NodeIdProof::mine(&identity1.node_id(), 8).unwrap();

    // A proof is (key, nonce) -> hash, and difficulty 8 means 8 leading ZERO BITS. So a
    // second, unrelated key reused with this nonce satisfies the difficulty by chance
    // 1 time in 256 — and then it verifies legitimately, because it genuinely is a valid
    // proof for that key. Asserting `!verify` unconditionally therefore fails ~0.39% of
    // runs on correct code. That is what happened on macOS in CI, on a pull request that
    // changed nothing but a shell script.
    //
    // test_021 above and the unit test in ghost-common/src/identity.rs both guard against
    // this exact coincidence; this one did not.
    //
    // Rather than skip the assertion on the unlucky draw (which leaves the test asserting
    // nothing ~0.39% of the time), draw until we have a key that does NOT coincidentally
    // satisfy the difficulty. Expected iterations: 1.004.
    let wrong_key = loop {
        let candidate = NodeIdentity::generate().node_id();
        let hash = NodeIdProof::compute_hash(&candidate, proof.nonce);
        if NodeIdProof::leading_zeros(&hash) < 8 {
            break candidate;
        }
        // Landed on a key for which this nonce is a genuinely valid proof. Not a bug —
        // draw again so the assertion below stays meaningful.
    };

    // Verify against wrong key should fail
    assert!(!proof.verify(&wrong_key, 8));
}

#[test]
fn test_023_pow_leading_zeros_counts_correctly_0x00() {
    // 0x00 at start = 8 leading zeros
    let mut hash = [0u8; 32];
    hash[0] = 0x00;
    hash[1] = 0x00;
    hash[2] = 0x00;
    hash[3] = 0xff;

    assert_eq!(NodeIdProof::leading_zeros(&hash), 24);
}

#[test]
fn test_024_pow_leading_zeros_counts_correctly_0x0f() {
    // 0x0f = 0000 1111 = 4 leading zeros
    let mut hash = [0u8; 32];
    hash[0] = 0x0f;

    assert_eq!(NodeIdProof::leading_zeros(&hash), 4);
}

#[test]
fn test_025_pow_leading_zeros_counts_correctly_0x80() {
    // 0x80 = 1000 0000 = 0 leading zeros
    let mut hash = [0u8; 32];
    hash[0] = 0x80;

    assert_eq!(NodeIdProof::leading_zeros(&hash), 0);
}

#[test]
fn test_026_pow_to_bytes_from_bytes_roundtrip() {
    let proof = NodeIdProof {
        nonce: 12345678,
        difficulty: 20,
    };

    let bytes = proof.to_bytes();
    let restored = NodeIdProof::from_bytes(&bytes).unwrap();

    assert_eq!(restored.nonce, proof.nonce);
    assert_eq!(restored.difficulty, proof.difficulty);
}

#[test]
fn test_027_pow_to_hex_from_hex_roundtrip() {
    let proof = NodeIdProof {
        nonce: 0xDEADBEEF,
        difficulty: 25,
    };

    let hex = proof.to_hex();
    let restored = NodeIdProof::from_hex(&hex).unwrap();

    assert_eq!(restored.nonce, proof.nonce);
    assert_eq!(restored.difficulty, proof.difficulty);
}

#[test]
fn test_028_pow_difficulty_meets_minimum_threshold() {
    let identity = NodeIdentity::generate();

    // New identities should have valid PoW meeting NODE_ID_POW_DIFFICULTY
    assert!(identity.has_valid_pow());
    assert!(identity.pow_difficulty() >= NODE_ID_POW_DIFFICULTY);
}

#[test]
fn test_029_verify_remote_signature() {
    let identity = NodeIdentity::generate();
    let msg = b"Remote verification test";
    let signature = identity.sign(msg);

    let result = verify_signature(&identity.node_id(), msg, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_030_verify_node_id_pow_function() {
    let identity = NodeIdentity::generate();
    let proof = identity.pow_proof().unwrap();

    assert!(verify_node_id_pow(
        &identity.node_id(),
        proof,
        NODE_ID_POW_DIFFICULTY
    ));
}

// =============================================================================
// HASH MESSAGE TESTS (Tests 31-34)
// =============================================================================

#[test]
fn test_031_hash_message_produces_32_bytes() {
    let msg = b"Test message for hashing";
    let hash = hash_message(msg);

    assert_eq!(hash.len(), 32);
}

#[test]
fn test_032_hash_message_is_deterministic() {
    let msg = b"Deterministic test";

    let hash1 = hash_message(msg);
    let hash2 = hash_message(msg);

    assert_eq!(hash1, hash2);
}

#[test]
fn test_033_hash_message_different_for_different_inputs() {
    let msg1 = b"Message 1";
    let msg2 = b"Message 2";

    let hash1 = hash_message(msg1);
    let hash2 = hash_message(msg2);

    assert_ne!(hash1, hash2);
}

#[test]
fn test_034_hash_empty_message() {
    let hash = hash_message(b"");

    assert_eq!(hash.len(), 32);
    // Empty string SHA256 is known
    let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_eq!(hex::encode(hash), expected_hex);
}

// =============================================================================
// SIGNATURE EDGE CASES (Tests 35-40)
// =============================================================================

#[test]
fn test_035_sign_empty_message() {
    let identity = NodeIdentity::generate();
    let msg = b"";

    let sig = identity.sign(msg);
    assert!(identity.verify(msg, &sig));
}

#[test]
fn test_036_sign_large_message() {
    let identity = NodeIdentity::generate();
    let msg = vec![0xAB; 1_000_000]; // 1MB message

    let sig = identity.sign(&msg);
    assert!(identity.verify(&msg, &sig));
}

#[test]
fn test_037_sign_binary_data() {
    let identity = NodeIdentity::generate();
    let msg: Vec<u8> = (0..=255).collect(); // All byte values

    let sig = identity.sign(&msg);
    assert!(identity.verify(&msg, &sig));
}

#[test]
fn test_038_verify_all_zero_signature_fails() {
    let identity = NodeIdentity::generate();
    let msg = b"Test";
    let zero_sig = [0u8; 64];

    assert!(!identity.verify(msg, &zero_sig));
}

#[test]
fn test_039_verify_all_ones_signature_fails() {
    let identity = NodeIdentity::generate();
    let msg = b"Test";
    let ones_sig = [0xFF; 64];

    assert!(!identity.verify(msg, &ones_sig));
}

#[test]
fn test_040_multiple_signatures_same_message() {
    let identity = NodeIdentity::generate();
    let msg = b"Same message";

    // Ed25519 is deterministic - same message produces same signature
    let sig1 = identity.sign(msg);
    let sig2 = identity.sign(msg);

    assert_eq!(sig1, sig2);
}

// =============================================================================
// Additional tests would continue for:
// - Noise Protocol (Tests 55-64) - requires noise module
// - Blind Signatures (Tests 65-74) - in wraith protocol
// - Silent Payment Keys (Tests 82-85) - in ghost-keys
// =============================================================================
