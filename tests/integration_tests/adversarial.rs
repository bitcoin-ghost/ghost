//! Category 32: Adversarial Integration Tests (10 tests, 930-939)
//!
//! Tests for adversarial attack vectors against Ghost pool components:
//! - JSON depth bomb (930)
//! - Concurrent nullifier double-spend (931)
//! - Rate limiter exhaustion (932)
//! - Forged verification signatures (933)
//! - Self-verification Sybil attack (934)
//! - Stale verification replay (935)
//! - Zero-signature envelope (936)
//! - Crash recovery nullifier persistence (937)
//! - Replay attack dedup (938)
//! - Oversized challenge data (939)

use std::sync::Arc;

use chrono::Utc;
use ghost_common::identity::NodeIdentity;
use ghost_consensus::epoch_manager::{EpochManager, EpochManagerConfig};
use ghost_consensus::mesh::MessageId;
use ghost_consensus::message::{
    CapabilityType, MessageEnvelope, MessageType, VerificationResultMessage,
};
use ghost_consensus::message_validator::{
    validate_and_verify, MessageValidationError, MAX_JSON_DEPTH,
};
use ghost_consensus::verification_handler::VerificationResultHandler;
use ghost_consensus::vote_handler::RateLimiter;
use ghost_storage::Database;

// =============================================================================
// HELPERS
// =============================================================================

/// Create an in-memory database with all migrations applied.
fn test_db() -> Database {
    Database::in_memory().expect("in-memory DB")
}

/// Build a properly signed MessageEnvelope using a NodeIdentity.
fn make_signed_envelope(
    identity: &NodeIdentity,
    msg_type: MessageType,
    payload: &[u8],
    sequence: u64,
) -> MessageEnvelope {
    let mut signed_data = payload.to_vec();
    signed_data.extend_from_slice(&sequence.to_le_bytes());
    let signature = identity.sign(&signed_data);

    MessageEnvelope::new(
        msg_type,
        identity.node_id(),
        payload.to_vec(),
        sequence,
        signature,
    )
}

/// Build a VerificationResultMessage and wrap it in a properly signed envelope.
fn make_verification_envelope(
    challenger: &NodeIdentity,
    target_node_id: [u8; 32],
    capability: CapabilityType,
    passed: bool,
    challenge_data: String,
    timestamp: i64,
) -> MessageEnvelope {
    let mut vrm = VerificationResultMessage {
        target_node_id,
        challenger_id: challenger.node_id(),
        capability,
        passed,
        challenge_data,
        response_data: None,
        target_signed_response: None,
        timestamp,
        signature: [0u8; 64],
    };

    // Sign the verification result itself
    let signing_data = vrm.signing_data();
    vrm.signature = challenger.sign(&signing_data);

    let payload = serde_json::to_vec(&vrm).expect("serialize VRM");
    make_signed_envelope(challenger, MessageType::VerificationResult, &payload, 1)
}

// =============================================================================
// TEST 930: DEEPLY NESTED JSON REJECTED
// =============================================================================

#[test]
fn test_930_deeply_nested_json_rejected() {
    // Build a JSON byte string with 100 levels of `{` nesting.
    // This should trigger ExcessiveNesting because MAX_JSON_DEPTH is 16.
    let deep_json = "{\"a\":".repeat(100) + "1" + &"}".repeat(100);
    let data = deep_json.as_bytes();

    let result = validate_and_verify(data);
    assert!(result.is_err(), "100-level nested JSON must be rejected");
    match result.unwrap_err() {
        MessageValidationError::ExcessiveNesting(depth) => {
            assert!(
                depth > MAX_JSON_DEPTH,
                "Reported depth {} should exceed MAX_JSON_DEPTH {}",
                depth,
                MAX_JSON_DEPTH
            );
        }
        other => panic!("Expected ExcessiveNesting error, got: {:?}", other),
    }

    // Verify 16 levels of nesting is fine (passes depth check, may fail at
    // other validation stages like deserialization -- that is OK; the point
    // is it does NOT fail with ExcessiveNesting).
    let ok_json = "{\"a\":".repeat(MAX_JSON_DEPTH) + "1" + &"}".repeat(MAX_JSON_DEPTH);
    let ok_data = ok_json.as_bytes();
    let result = validate_and_verify(ok_data);
    match result {
        Err(MessageValidationError::ExcessiveNesting(_)) => {
            panic!(
                "{}-level nesting should NOT trigger ExcessiveNesting",
                MAX_JSON_DEPTH
            );
        }
        // Any other error (TooSmall, DeserializationFailed, etc.) is acceptable
        // -- we only care that the depth check itself passes.
        _ => {}
    }
}

// =============================================================================
// TEST 931: CONCURRENT NULLIFIER DOUBLE-SPEND
// =============================================================================

#[test]
fn test_931_concurrent_nullifier_double_spend() {
    let db = Arc::new(test_db());
    let config = EpochManagerConfig::default();
    let em = Arc::new(EpochManager::new(db, config));

    // Initialize genesis epoch so the DB has an active epoch.
    em.initialize_genesis().expect("genesis init");

    let nullifier = [0xABu8; 32];
    let thread_count = 10;

    // Spawn 10 threads all trying to spend the same nullifier at once.
    let handles: Vec<_> = (0..thread_count)
        .map(|_| {
            let em = Arc::clone(&em);
            std::thread::spawn(move || em.spend_nullifier(nullifier, 1).expect("no IO error"))
        })
        .collect();

    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let success_count = results.iter().filter(|&&r| r).count();
    let fail_count = results.iter().filter(|&&r| !r).count();

    assert_eq!(
        success_count, 1,
        "Exactly 1 thread should succeed spending nullifier, got {}",
        success_count
    );
    assert_eq!(
        fail_count,
        thread_count - 1,
        "Exactly {} threads should fail, got {}",
        thread_count - 1,
        fail_count
    );

    // Confirm the nullifier is indeed spent.
    assert!(em.is_nullifier_spent(&nullifier));
}

// =============================================================================
// TEST 932: VERIFICATION RESULT RATE LIMIT
// =============================================================================

#[test]
fn test_932_verification_result_rate_limit() {
    // Create a RateLimiter with capacity 20, refill 1 token/sec.
    let limiter = RateLimiter::new(20, 1);

    let node_id = [0x42u8; 32];

    // Consume all 20 tokens rapidly (no time passes between calls).
    let mut successes = 0;
    let mut failures = 0;

    for _ in 0..25 {
        if limiter.check_and_consume(&node_id) {
            successes += 1;
        } else {
            failures += 1;
        }
    }

    assert_eq!(successes, 20, "First 20 calls should succeed");
    assert_eq!(failures, 5, "Last 5 calls should fail (bucket empty)");
}

// =============================================================================
// TEST 933: FORGED VERIFICATION RESULT — WRONG SIGNATURE
// =============================================================================

#[tokio::test]
async fn test_933_forged_verification_result_wrong_signature() {
    let db = Arc::new(test_db());
    let handler = VerificationResultHandler::new(Arc::clone(&db));

    // Create two different identities.
    let real_challenger = NodeIdentity::generate();
    let target = NodeIdentity::generate();

    // Build a VRM signed by the WRONG key (real_challenger signs, but
    // we set challenger_id to real_challenger's ID, then corrupt the signature).
    let now = Utc::now().timestamp();

    let mut vrm = VerificationResultMessage {
        target_node_id: target.node_id(),
        challenger_id: real_challenger.node_id(),
        capability: CapabilityType::Archive,
        passed: true,
        challenge_data: r#"{"block_height":100,"expected_hash":"abc"}"#.to_string(),
        response_data: Some(r#"{"hash":"abc"}"#.to_string()),
        target_signed_response: None,
        timestamp: now,
        signature: [0u8; 64],
    };

    // Sign with a DIFFERENT identity (forged).
    let forger = NodeIdentity::generate();
    let signing_data = vrm.signing_data();
    vrm.signature = forger.sign(&signing_data);

    let payload = serde_json::to_vec(&vrm).unwrap();

    // The envelope sender must match challenger_id for the handler to proceed
    // past the sender-mismatch check. We sign the envelope with real_challenger.
    let envelope = make_signed_envelope(
        &real_challenger,
        MessageType::VerificationResult,
        &payload,
        1,
    );

    // Feed through handler (MessageHandler trait)
    use ghost_consensus::mesh::MessageHandler;
    handler
        .handle_message(Arc::new(envelope))
        .await
        .expect("handler should return Ok(()) even for rejected messages");

    // Verify NO DB record was created — the forged VRM signature is invalid
    // so it should be silently dropped.
    let target_hex = hex::encode(target.node_id());
    let (passed, total) = db.get_archive_pass_rate(&target_hex, 0).unwrap();
    assert_eq!(
        total, 0,
        "No archive challenge should be recorded for forged sig"
    );
    assert_eq!(passed, 0);
}

// =============================================================================
// TEST 934: SELF-VERIFICATION REJECTED (SYBIL PREVENTION)
// =============================================================================

#[tokio::test]
async fn test_934_self_verification_rejected() {
    let db = Arc::new(test_db());
    let handler = VerificationResultHandler::new(Arc::clone(&db));

    let identity = NodeIdentity::generate();
    let now = Utc::now().timestamp();

    // challenger_id == target_node_id (self-verification attempt)
    let envelope = make_verification_envelope(
        &identity,
        identity.node_id(), // target == challenger
        CapabilityType::Archive,
        true,
        r#"{"block_height":100,"expected_hash":"abc"}"#.to_string(),
        now,
    );

    use ghost_consensus::mesh::MessageHandler;
    handler
        .handle_message(Arc::new(envelope))
        .await
        .expect("handler should return Ok");

    // Verify the handler silently dropped it — no DB record.
    let node_hex = hex::encode(identity.node_id());
    let (_, total) = db.get_archive_pass_rate(&node_hex, 0).unwrap();
    assert_eq!(total, 0, "Self-verification must not create a DB record");
}

// =============================================================================
// TEST 935: STALE VERIFICATION RESULT REJECTED
// =============================================================================

#[tokio::test]
async fn test_935_stale_verification_result_rejected() {
    let db = Arc::new(test_db());
    let handler = VerificationResultHandler::new(Arc::clone(&db));

    let challenger = NodeIdentity::generate();
    let target = NodeIdentity::generate();

    // Timestamp 15 minutes in the past (handler rejects > 10 minutes).
    let stale_ts = Utc::now().timestamp() - 15 * 60;

    let envelope = make_verification_envelope(
        &challenger,
        target.node_id(),
        CapabilityType::Archive,
        true,
        r#"{"block_height":200,"expected_hash":"def"}"#.to_string(),
        stale_ts,
    );

    use ghost_consensus::mesh::MessageHandler;
    handler
        .handle_message(Arc::new(envelope))
        .await
        .expect("handler should return Ok");

    // Verify rejected — no DB record.
    let target_hex = hex::encode(target.node_id());
    let (_, total) = db.get_archive_pass_rate(&target_hex, 0).unwrap();
    assert_eq!(total, 0, "Stale verification result must be rejected");
}

// =============================================================================
// TEST 936: L2 CHECKPOINT VOTE — ZERO SIGNATURE REJECTED
// =============================================================================

#[test]
fn test_936_l2_checkpoint_vote_zero_signature() {
    let identity = NodeIdentity::generate();

    // Create an envelope with an all-zeros signature.
    let payload = b"{}";
    let envelope = MessageEnvelope::new(
        MessageType::L2CheckpointVote,
        identity.node_id(),
        payload.to_vec(),
        1,
        [0u8; 64], // All-zeros signature
    );

    let data = envelope.serialize().expect("serialize envelope");
    let result = validate_and_verify(&data);

    assert!(result.is_err(), "Zero signature must be rejected");
    match result.unwrap_err() {
        MessageValidationError::ZeroSignature => {} // Expected
        other => panic!("Expected ZeroSignature error, got: {:?}", other),
    }
}

// =============================================================================
// TEST 937: CRASH RECOVERY — NULLIFIER PERSISTENCE
// =============================================================================

#[test]
fn test_937_crash_recovery_nullifier_persistence() {
    // Use a shared in-memory DB (with shared cache so two EpochManagers
    // can share the same underlying database, simulating crash + restart).
    let db = Arc::new(test_db());
    let config = EpochManagerConfig::default();

    // --- Phase 1: Create EpochManager, spend a nullifier, do NOT flush ---
    let nullifier = [0xDEu8; 32];
    {
        let em1 = EpochManager::new(Arc::clone(&db), config.clone());
        em1.initialize_genesis().expect("genesis init");
        let ok = em1.spend_nullifier(nullifier, 42).expect("spend");
        assert!(ok, "First spend should succeed");

        // Deliberately do NOT call flush_pending_nullifiers().
        // The write-ahead log (pending_nullifiers table) should have the entry.
    }

    // --- Phase 2: "Crash" — drop em1, create a fresh EpochManager ---
    {
        let em2 = EpochManager::new(Arc::clone(&db), config);
        em2.initialize().expect("initialize from DB");

        // The nullifier should be recovered from the write-ahead log.
        assert!(
            em2.is_nullifier_spent(&nullifier),
            "Nullifier must survive simulated crash via write-ahead log"
        );
    }
}

// =============================================================================
// TEST 938: REPLAY ATTACK DEDUP
// =============================================================================

#[test]
fn test_938_replay_attack_dedup() {
    // Test that two MessageEnvelopes with the same sender + sequence produce
    // the same MessageId, which is the key the dedup cache uses for rejection.
    //
    // The dedup cache itself (SeenMessageCache) is internal to MeshNetwork,
    // but we can verify the foundational dedup invariant: identical sender +
    // sequence yields identical MessageId, and different sequence yields
    // a different MessageId.

    let identity = NodeIdentity::generate();
    let payload = b"test payload";

    // Two envelopes with SAME sender and sequence.
    let env1 = make_signed_envelope(&identity, MessageType::HealthPing, payload, 42);
    let env2 = make_signed_envelope(&identity, MessageType::HealthPing, payload, 42);

    let id1 = MessageId {
        sender: env1.sender,
        sequence: env1.sequence,
    };
    let id2 = MessageId {
        sender: env2.sender,
        sequence: env2.sequence,
    };

    // Same sender + sequence => same MessageId (dedup key).
    assert_eq!(
        id1, id2,
        "Identical sender+sequence must produce same MessageId"
    );

    // Different sequence => different MessageId.
    let env3 = make_signed_envelope(&identity, MessageType::HealthPing, payload, 43);
    let id3 = MessageId {
        sender: env3.sender,
        sequence: env3.sequence,
    };
    assert_ne!(
        id1, id3,
        "Different sequence must produce different MessageId"
    );

    // Different sender => different MessageId.
    let other = NodeIdentity::generate();
    let env4 = make_signed_envelope(&other, MessageType::HealthPing, payload, 42);
    let id4 = MessageId {
        sender: env4.sender,
        sequence: env4.sequence,
    };
    assert_ne!(
        id1, id4,
        "Different sender must produce different MessageId"
    );

    // Additionally, validate_and_verify on the same data twice should both succeed
    // (validator is stateless; dedup happens in MeshNetwork layer).
    let data1 = env1.serialize().expect("serialize");
    let r1 = validate_and_verify(&data1);
    let r2 = validate_and_verify(&data1);
    assert!(r1.is_ok(), "First validation should succeed");
    assert!(
        r2.is_ok(),
        "Second validation should also succeed (stateless)"
    );
}

// =============================================================================
// TEST 939: OVERSIZED CHALLENGE DATA REJECTED
// =============================================================================

#[tokio::test]
async fn test_939_oversized_challenge_data_rejected() {
    let db = Arc::new(test_db());
    let handler = VerificationResultHandler::new(Arc::clone(&db));

    let challenger = NodeIdentity::generate();
    let target = NodeIdentity::generate();
    let now = Utc::now().timestamp();

    // challenge_data > 10KB (H-5 limit is 10 * 1024 = 10240 bytes)
    let oversized_data = "x".repeat(11_000);

    let envelope = make_verification_envelope(
        &challenger,
        target.node_id(),
        CapabilityType::Archive,
        true,
        oversized_data,
        now,
    );

    use ghost_consensus::mesh::MessageHandler;
    handler
        .handle_message(Arc::new(envelope))
        .await
        .expect("handler should return Ok");

    // Verify no DB record was created.
    let target_hex = hex::encode(target.node_id());
    let (_, total) = db.get_archive_pass_rate(&target_hex, 0).unwrap();
    assert_eq!(
        total, 0,
        "Oversized challenge_data must not create a DB record"
    );
}
