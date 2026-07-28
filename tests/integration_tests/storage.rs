//! Category 9: Storage & Database Tests (50 tests)
//!
//! Tests for the REAL ghost-storage persistence layer:
//!
//! - Share storage and retrieval
//! - Round management
//! - Node registry
//! - Miner statistics
//! - Database integrity
//! - Concurrent access

use ghost_storage::{Database, NodeRecord, PayoutStatus, RoundRecord, ShareRecord};
use std::sync::Arc;

// =============================================================================
// SHARE STORAGE (Tests 551-565)
// =============================================================================

#[test]
fn test_551_store_share_basic() {
    let db = Database::in_memory().expect("Failed to create in-memory database");

    // Create a round first (shares need a round)
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).expect("Failed to create round");

    let share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1_pubkey_hash".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "abcd1234".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };

    let id = db.insert_share(&share).expect("Failed to insert share");
    assert!(id > 0);
}

#[test]
fn test_552_retrieve_shares_by_round() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    let share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "hash1".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };

    db.insert_share(&share).unwrap();
    let shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].miner_id, "miner1");
}

#[test]
fn test_553_share_not_found() {
    let db = Database::in_memory().unwrap();
    let shares = db.get_shares_by_round(999).unwrap();
    assert!(shares.is_empty());
}

#[test]
fn test_554_list_shares_by_miner() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    for i in 0..10 {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: if i % 2 == 0 {
                "miner1".to_string()
            } else {
                "miner2".to_string()
            },
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: format!("hash{}", i),
            timestamp: 1700000000 + i,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    let miner1_shares = db.get_miner_shares(1, "miner1").unwrap();
    assert_eq!(miner1_shares.len(), 5);
}

#[test]
fn test_555_list_shares_by_time_range() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    for i in 0..10i64 {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: format!("hash{}", i),
            timestamp: 1700000000 + i * 100,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    // Get all shares for round and filter by time manually
    let shares = db.get_shares_by_round(1).unwrap();
    let range_shares: Vec<_> = shares
        .iter()
        .filter(|s| s.timestamp >= 1700000200 && s.timestamp <= 1700000600)
        .collect();
    assert!(!range_shares.is_empty());
}

#[test]
fn test_556_share_duplicate_hash_rejected() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    // The real schema has UNIQUE constraint on share_hash - duplicates are rejected
    let share1 = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "same_hash".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };
    let share2 = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner2".to_string(),
        difficulty: 2000.0,
        work: 2000.0,
        share_hash: "same_hash".to_string(), // Same hash - should be rejected
        timestamp: 1700000001,
        received_by: "node1".to_string(),
        valid: true,
    };

    let id1 = db.insert_share(&share1).unwrap();
    assert!(id1 > 0);

    // Duplicate share_hash should fail
    let result = db.insert_share(&share2);
    assert!(result.is_err());
}

#[test]
fn test_557_share_count_total() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    for i in 0..100 {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: format!("hash{}", i),
            timestamp: 1700000000,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    let shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(shares.len(), 100);
}

#[test]
fn test_558_share_work_sum() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    for i in 0..10 {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "miner1".to_string(),
            difficulty: 100.0 * (i + 1) as f64,
            work: 100.0 * (i + 1) as f64,
            share_hash: format!("hash{}", i),
            timestamp: 1700000000,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    // Sum of 100 + 200 + ... + 1000 = 5500
    let total = db.get_miner_work(1, "miner1").unwrap();
    assert!((total - 5500.0).abs() < 0.001);
}

// NOTE: the former `test_559_prune_old_shares` was removed along with the
// `Database::prune_old_shares` function. That round-count-based bulk share
// delete unconditionally wiped unpaid shares of active miners (the payout-
// correctness bug). Share-row lifecycle is now owned solely by
// `delete_old_shares` (Path A); see the dedicated protection tests in
// `crates/ghost-storage/src/queries.rs` and `database.rs`.

#[test]
fn test_560_get_round_miners() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    // Multiple miners with different work amounts
    for (miner_id, work) in [("miner1", 1000.0), ("miner2", 2000.0), ("miner3", 500.0)] {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: miner_id.to_string(),
            difficulty: work,
            work,
            share_hash: format!("hash_{}", miner_id),
            timestamp: 1700000000,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    let miners = db.get_round_miners(1).unwrap();
    assert_eq!(miners.len(), 3);
    // Should be ordered by work DESC
    assert_eq!(miners[0].0, "miner2");
    assert_eq!(miners[0].1, 2000.0);
}

#[test]
fn test_561_invalid_shares_excluded_from_work() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    // Valid share
    let valid_share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "valid_hash".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };
    db.insert_share(&valid_share).unwrap();

    // Invalid share (should not count toward work)
    let invalid_share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 5000.0,
        work: 5000.0,
        share_hash: "invalid_hash".to_string(),
        timestamp: 1700000001,
        received_by: "node1".to_string(),
        valid: false,
    };
    db.insert_share(&invalid_share).unwrap();

    // get_miner_work only counts valid shares
    let total_work = db.get_miner_work(1, "miner1").unwrap();
    assert_eq!(total_work, 1000.0); // Only valid share counted
}

#[test]
fn test_562_multiple_rounds_isolation() {
    let db = Database::in_memory().unwrap();

    // Create two rounds
    for round_id in 1..=2u64 {
        let round = RoundRecord {
            round_id,
            block_height: 800000 + round_id,
            block_hash: None,
            start_time: 1700000000,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };
        db.create_round(&round).unwrap();
    }

    // Add shares to round 1
    for i in 0..5 {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: format!("round1_hash{}", i),
            timestamp: 1700000000,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    // Add shares to round 2
    for i in 0..3 {
        let share = ShareRecord {
            id: None,
            round_id: 2,
            miner_id: "miner1".to_string(),
            difficulty: 2000.0,
            work: 2000.0,
            share_hash: format!("round2_hash{}", i),
            timestamp: 1700000000,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    // Verify isolation
    let round1_shares = db.get_shares_by_round(1).unwrap();
    let round2_shares = db.get_shares_by_round(2).unwrap();
    assert_eq!(round1_shares.len(), 5);
    assert_eq!(round2_shares.len(), 3);
}

#[test]
fn test_563_share_pagination_via_limit() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    for i in 0..100 {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: format!("hash{}", i),
            timestamp: 1700000000 + i,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    // The real API returns all shares - pagination would be done at app level
    let all_shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(all_shares.len(), 100);

    // Manual pagination
    let page1: Vec<_> = all_shares.iter().take(10).collect();
    let page2: Vec<_> = all_shares.iter().skip(10).take(10).collect();
    assert_eq!(page1.len(), 10);
    assert_eq!(page2.len(), 10);
}

#[test]
fn test_564_in_memory_database_is_temporary() {
    let db = Database::in_memory().unwrap();
    assert!(db.is_in_memory());

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    let share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "hash1".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };
    db.insert_share(&share).unwrap();

    // Data exists while db is alive
    let shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(shares.len(), 1);

    // Memory database loses data on drop (expected behavior for tests)
    drop(db);
}

#[test]
fn test_565_share_work_vs_difficulty() {
    let db = Database::in_memory().unwrap();

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    // Work and difficulty can be different values
    let share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0, // Share difficulty
        work: 1500.0,       // Work contribution (can differ)
        share_hash: "hash1".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };

    db.insert_share(&share).unwrap();

    let shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(shares[0].difficulty, 1000.0);
    assert_eq!(shares[0].work, 1500.0);
}

// =============================================================================
// ROUND RECORDS (Tests 566-575)
// =============================================================================

#[test]
fn test_566_create_round() {
    let db = Database::in_memory().unwrap();
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };

    assert!(db.create_round(&round).is_ok());
}

#[test]
fn test_567_retrieve_round_by_id() {
    let db = Database::in_memory().unwrap();
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };

    db.create_round(&round).unwrap();
    let retrieved = db.get_round(1).unwrap();
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().block_height, 800000);
}

#[test]
fn test_568_round_not_found() {
    let db = Database::in_memory().unwrap();
    let retrieved = db.get_round(999).unwrap();
    assert!(retrieved.is_none());
}

#[test]
fn test_569_get_recent_rounds() {
    let db = Database::in_memory().unwrap();

    for i in 1..=10u64 {
        let round = RoundRecord {
            round_id: i,
            block_height: 800000 + i,
            block_hash: None,
            start_time: 1700000000 + i as i64,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };
        db.create_round(&round).unwrap();
    }

    let recent = db.get_recent_rounds(5).unwrap();
    assert_eq!(recent.len(), 5);
    // Should be ordered by round_id DESC
    assert_eq!(recent[0].round_id, 10);
}

#[test]
fn test_570_update_round_status() {
    let db = Database::in_memory().unwrap();
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    db.update_round_status(1, PayoutStatus::Confirmed).unwrap();

    let updated = db.get_round(1).unwrap().unwrap();
    assert_eq!(updated.payout_status, PayoutStatus::Confirmed);
}

#[test]
fn test_571_update_round_block_found() {
    let db = Database::in_memory().unwrap();
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    db.update_round_block_found(
        1,
        "000000000000000000012345",
        "miner1",
        "node1",
        625_000_000,
        1_000_000,
    )
    .unwrap();

    let updated = db.get_round(1).unwrap().unwrap();
    assert_eq!(
        updated.block_hash,
        Some("000000000000000000012345".to_string())
    );
    assert_eq!(updated.winning_miner, Some("miner1".to_string()));
    assert_eq!(updated.subsidy_sats, Some(625_000_000));
    assert_eq!(updated.payout_status, PayoutStatus::Pending);
}

#[test]
fn test_572_end_round() {
    let db = Database::in_memory().unwrap();
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    // Add some shares
    let share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "hash1".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };
    db.insert_share(&share).unwrap();

    db.end_round(1, 1700000600).unwrap();

    let ended = db.get_round(1).unwrap().unwrap();
    assert_eq!(ended.end_time, Some(1700000600));
    assert_eq!(ended.total_shares, 1);
    assert_eq!(ended.total_work, 1000.0);
}

#[test]
fn test_573_mark_rounds_orphaned_by_hash() {
    let db = Database::in_memory().unwrap();

    // create_round only sets round_id, block_height, start_time, payout_status
    // block_hash is set via update_round_block_found
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    // Now set block_hash via update_round_block_found
    db.update_round_block_found(1, "blockhash123", "miner1", "node1", 625_000_000, 1_000_000)
        .unwrap();

    // Verify block_hash was set and status is Pending
    let before = db.get_round(1).unwrap().unwrap();
    assert_eq!(before.block_hash, Some("blockhash123".to_string()));
    assert_eq!(before.payout_status, PayoutStatus::Pending);

    // Simulate reorg - mark round as orphaned
    let affected = db.mark_rounds_orphaned_by_hash("blockhash123").unwrap();
    assert_eq!(affected, 1);

    let orphaned = db.get_round(1).unwrap().unwrap();
    assert_eq!(orphaned.payout_status, PayoutStatus::Orphaned);
}

#[test]
fn test_574_get_rounds_by_block_hash() {
    let db = Database::in_memory().unwrap();

    // create_round doesn't set block_hash - must use update_round_block_found
    for i in 1..=3u64 {
        let round = RoundRecord {
            round_id: i,
            block_height: 800000 + i,
            block_hash: None,
            start_time: 1700000000 + i as i64,
            end_time: None,
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        };
        db.create_round(&round).unwrap();

        // Set block_hash - first two get "same_block_hash", third gets "other_hash"
        let hash = if i <= 2 {
            "same_block_hash"
        } else {
            "other_hash"
        };
        db.update_round_block_found(i, hash, "miner1", "node1", 625_000_000, 1_000_000)
            .unwrap();
    }

    let rounds = db.get_rounds_by_block_hash("same_block_hash").unwrap();
    assert_eq!(rounds.len(), 2);
}

#[test]
fn test_575_prune_old_rounds() {
    let db = Database::in_memory().unwrap();

    for i in 1..=10u64 {
        let round = RoundRecord {
            round_id: i,
            block_height: 800000 + i,
            block_hash: Some(format!("hash{}", i)),
            start_time: 1700000000 + i as i64 * 1000,
            end_time: Some(1700000600 + i as i64 * 1000),
            total_shares: 10,
            total_work: 10000.0,
            winning_miner: Some("miner1".to_string()),
            found_by_node: Some("node1".to_string()),
            payout_status: PayoutStatus::Confirmed,
            subsidy_sats: Some(625_000_000),
            tx_fees_sats: Some(1_000_000),
        };
        db.create_round(&round).unwrap();
    }

    // Keep only 5 rounds
    let deleted = db.prune_old_rounds(5).unwrap();
    assert!(deleted > 0);

    // Old rounds should be gone
    assert!(db.get_round(1).unwrap().is_none());
    // Recent rounds should remain
    assert!(db.get_round(10).unwrap().is_some());
}

// =============================================================================
// NODE REGISTRY (Tests 576-585)
// =============================================================================

#[test]
fn test_576_upsert_node() {
    let db = Database::in_memory().unwrap();
    let node = NodeRecord {
        node_id: "node1_pubkey".to_string(),
        public_address: Some("192.168.1.1:8333".to_string()),
        display_name: Some("TestNode".to_string()),
        first_seen: 1700000000,
        last_seen: 1700000000,
        is_elder: false,
        elder_order: None,
        capabilities: "{}".to_string(),
        total_uptime_secs: 0,
        uptime_7d_percent: 100.0,
        verification_pass_rate: 100.0,
        total_shares_received: 0,
        total_blocks_found: 0,
        payout_address: None,
    };

    assert!(db.upsert_node(&node).is_ok());
}

#[test]
fn test_577_retrieve_node() {
    let db = Database::in_memory().unwrap();
    let node = NodeRecord {
        node_id: "node1_pubkey".to_string(),
        public_address: Some("192.168.1.1:8333".to_string()),
        display_name: Some("TestNode".to_string()),
        first_seen: 1700000000,
        last_seen: 1700000000,
        is_elder: false,
        elder_order: None,
        capabilities: "{}".to_string(),
        total_uptime_secs: 0,
        uptime_7d_percent: 100.0,
        verification_pass_rate: 100.0,
        total_shares_received: 0,
        total_blocks_found: 0,
        payout_address: None,
    };
    db.upsert_node(&node).unwrap();

    let retrieved = db.get_node("node1_pubkey").unwrap();
    assert!(retrieved.is_some());
    assert_eq!(
        retrieved.unwrap().display_name,
        Some("TestNode".to_string())
    );
}

#[test]
fn test_578_update_node_last_seen() {
    let db = Database::in_memory().unwrap();
    let node = NodeRecord {
        node_id: "node1_pubkey".to_string(),
        public_address: Some("192.168.1.1:8333".to_string()),
        display_name: Some("TestNode".to_string()),
        first_seen: 1700000000,
        last_seen: 1700000000,
        is_elder: false,
        elder_order: None,
        capabilities: "{}".to_string(),
        total_uptime_secs: 0,
        uptime_7d_percent: 100.0,
        verification_pass_rate: 100.0,
        total_shares_received: 0,
        total_blocks_found: 0,
        payout_address: None,
    };
    db.upsert_node(&node).unwrap();

    db.update_node_last_seen("node1_pubkey", 1700003600)
        .unwrap();

    let updated = db.get_node("node1_pubkey").unwrap().unwrap();
    assert_eq!(updated.last_seen, 1700003600);
}

#[test]
fn test_579_get_elders() {
    let db = Database::in_memory().unwrap();

    for i in 0..5 {
        let node = NodeRecord {
            node_id: format!("node{}_pubkey", i),
            public_address: Some(format!("192.168.1.{}:8333", i)),
            display_name: Some(format!("Node{}", i)),
            first_seen: 1700000000,
            last_seen: 1700000000,
            is_elder: i < 3, // First 3 are elders
            elder_order: if i < 3 { Some(i as u32) } else { None },
            capabilities: "{}".to_string(),
            total_uptime_secs: 0,
            uptime_7d_percent: 100.0,
            verification_pass_rate: 100.0,
            total_shares_received: 0,
            total_blocks_found: 0,
            payout_address: None,
        };
        db.upsert_node(&node).unwrap();
    }

    let elders = db.get_elders().unwrap();
    assert_eq!(elders.len(), 3);
}

#[test]
fn test_580_get_elder_count() {
    let db = Database::in_memory().unwrap();

    for i in 0..10 {
        let node = NodeRecord {
            node_id: format!("node{}_pubkey", i),
            public_address: None,
            display_name: None,
            first_seen: 1700000000,
            last_seen: 1700000000,
            is_elder: i % 2 == 0, // Every other is elder
            elder_order: if i % 2 == 0 { Some(i as u32) } else { None },
            capabilities: "{}".to_string(),
            total_uptime_secs: 0,
            uptime_7d_percent: 100.0,
            verification_pass_rate: 100.0,
            total_shares_received: 0,
            total_blocks_found: 0,
            payout_address: None,
        };
        db.upsert_node(&node).unwrap();
    }

    let count = db.get_elder_count().unwrap();
    assert_eq!(count, 5);
}

#[test]
fn test_581_increment_node_shares() {
    let db = Database::in_memory().unwrap();
    let node = NodeRecord {
        node_id: "node1_pubkey".to_string(),
        public_address: None,
        display_name: None,
        first_seen: 1700000000,
        last_seen: 1700000000,
        is_elder: false,
        elder_order: None,
        capabilities: "{}".to_string(),
        total_uptime_secs: 0,
        uptime_7d_percent: 100.0,
        verification_pass_rate: 100.0,
        total_shares_received: 0,
        total_blocks_found: 0,
        payout_address: None,
    };
    db.upsert_node(&node).unwrap();

    db.increment_node_shares("node1_pubkey", 100).unwrap();
    db.increment_node_shares("node1_pubkey", 50).unwrap();

    let updated = db.get_node("node1_pubkey").unwrap().unwrap();
    assert_eq!(updated.total_shares_received, 150);
}

#[test]
fn test_582_get_top_nodes_by_shares() {
    let db = Database::in_memory().unwrap();

    // upsert_node doesn't set total_shares_received - must use increment_node_shares
    for i in 0..10 {
        let node = NodeRecord {
            node_id: format!("node{}_pubkey", i),
            public_address: None,
            display_name: None,
            first_seen: 1700000000,
            last_seen: 1700000000,
            is_elder: false,
            elder_order: None,
            capabilities: "{}".to_string(),
            total_uptime_secs: 0,
            uptime_7d_percent: 100.0,
            verification_pass_rate: 100.0,
            total_shares_received: 0, // upsert_node ignores this field
            total_blocks_found: 0,
            payout_address: None,
        };
        db.upsert_node(&node).unwrap();

        // Use increment_node_shares to set the share counts
        db.increment_node_shares(&format!("node{}_pubkey", i), ((i + 1) * 100) as u64)
            .unwrap();
    }

    let top = db.get_top_nodes_by_shares(3).unwrap();
    assert_eq!(top.len(), 3);
    assert_eq!(top[0].total_shares_received, 1000); // node9 has most
}

#[test]
fn test_584_node_not_found() {
    let db = Database::in_memory().unwrap();
    let node = db.get_node("nonexistent_node").unwrap();
    assert!(node.is_none());
}

#[test]
fn test_585_upsert_updates_existing() {
    let db = Database::in_memory().unwrap();

    let node1 = NodeRecord {
        node_id: "node1_pubkey".to_string(),
        public_address: Some("192.168.1.1:8333".to_string()),
        display_name: Some("OldName".to_string()),
        first_seen: 1700000000,
        last_seen: 1700000000,
        is_elder: false,
        elder_order: None,
        capabilities: "{}".to_string(),
        total_uptime_secs: 0,
        uptime_7d_percent: 100.0,
        verification_pass_rate: 100.0,
        total_shares_received: 0,
        total_blocks_found: 0,
        payout_address: None,
    };
    db.upsert_node(&node1).unwrap();

    let node2 = NodeRecord {
        node_id: "node1_pubkey".to_string(),
        public_address: Some("192.168.1.2:8333".to_string()),
        display_name: Some("NewName".to_string()),
        first_seen: 1700000000,
        last_seen: 1700001000,
        is_elder: true,
        elder_order: Some(1),
        capabilities: r#"{"btc": true}"#.to_string(),
        total_uptime_secs: 0,
        uptime_7d_percent: 100.0,
        verification_pass_rate: 100.0,
        total_shares_received: 0,
        total_blocks_found: 0,
        payout_address: None,
    };
    db.upsert_node(&node2).unwrap();

    let updated = db.get_node("node1_pubkey").unwrap().unwrap();
    assert_eq!(updated.display_name, Some("NewName".to_string()));
    assert_eq!(updated.last_seen, 1700001000);
    assert!(updated.is_elder);
}

// =============================================================================
// DATABASE INTEGRITY (Tests 586-595)
// =============================================================================

#[test]
fn test_586_transaction_commit() {
    let db = Database::in_memory().unwrap();

    // Create a round first
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    let result = db.transaction(|tx| {
        tx.execute(
            "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
             VALUES (1, 'miner1', 1000.0, 1000.0, 'hash1', 1700000000, 'node1', 1)",
            [],
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(42)
    });

    assert_eq!(result.unwrap(), 42);
    let shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(shares.len(), 1);
}

#[test]
fn test_587_transaction_rollback() {
    let db = Database::in_memory().unwrap();

    // Create a round first
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    let result: Result<(), ghost_common::error::GhostError> = db.transaction(|tx| {
        tx.execute(
            "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
             VALUES (1, 'miner1', 1000.0, 1000.0, 'hash1', 1700000000, 'node1', 1)",
            [],
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;

        // Return error to trigger rollback
        Err(ghost_common::error::GhostError::Database("simulated error".into()))
    });

    assert!(result.is_err());
    // Share should not exist due to rollback
    let shares = db.get_shares_by_round(1).unwrap();
    assert!(shares.is_empty());
}

#[test]
fn test_588_shares_table_has_no_fk_to_rounds() {
    let db = Database::in_memory().unwrap();

    // The shares table does NOT have a foreign key to rounds
    // This is intentional - shares can be inserted before round is created
    // for performance reasons (round is created lazily)
    let share = ShareRecord {
        id: None,
        round_id: 999, // Non-existent round - but no FK constraint
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "hash1".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };

    // This succeeds because shares table has no FK to rounds
    let result = db.insert_share(&share);
    assert!(result.is_ok());

    // Verify share was inserted
    let shares = db.get_shares_by_round(999).unwrap();
    assert_eq!(shares.len(), 1);
}

#[test]
fn test_589_database_stats() {
    let db = Database::in_memory().unwrap();

    let stats = db.stats().unwrap();
    assert!(stats.page_count > 0);
    assert!(stats.page_size > 0);
}

#[test]
fn test_590_database_optimize() {
    let db = Database::in_memory().unwrap();

    // Create and delete data
    for i in 1..=100u64 {
        let round = RoundRecord {
            round_id: i,
            block_height: 800000 + i,
            block_hash: Some(format!("hash{}", i)),
            start_time: 1700000000,
            end_time: Some(1700000600),
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Confirmed,
            subsidy_sats: Some(625_000_000),
            tx_fees_sats: Some(1_000_000),
        };
        db.create_round(&round).unwrap();
    }

    // Prune most rounds
    db.prune_old_rounds(5).unwrap();

    // Optimize (vacuum + analyze)
    let result = db.optimize();
    assert!(result.is_ok());
}

#[test]
fn test_591_checkpoint() {
    let db = Database::in_memory().unwrap();

    // Checkpoint WAL
    let result = db.checkpoint();
    assert!(result.is_ok());
}

#[test]
fn test_592_database_path() {
    let db = Database::in_memory().unwrap();
    assert_eq!(db.path(), ":memory:");
}

#[test]
fn test_593_is_in_memory() {
    let db = Database::in_memory().unwrap();
    assert!(db.is_in_memory());
}

#[test]
fn test_594_with_connection() {
    let db = Database::in_memory().unwrap();

    let result = db.with_connection(|conn| {
        let version: i64 = conn
            .query_row("SELECT sqlite_version() IS NOT NULL", [], |row| row.get(0))
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(version)
    });

    assert!(result.is_ok());
}

#[test]
fn test_595_run_maintenance() {
    use ghost_storage::MaintenanceConfig;

    let db = Database::in_memory().unwrap();

    // Create some data
    for i in 1..=20u64 {
        let round = RoundRecord {
            round_id: i,
            block_height: 800000 + i,
            block_hash: Some(format!("hash{}", i)),
            start_time: 1700000000,
            end_time: Some(1700000600),
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Confirmed,
            subsidy_sats: Some(625_000_000),
            tx_fees_sats: Some(1_000_000),
        };
        db.create_round(&round).unwrap();
    }

    let config = MaintenanceConfig {
        keep_rounds: 5,
        keep_health_ping_days: 1,
        keep_uptime_sample_days: 7,
        keep_challenge_days: 30,
        keep_verification_days: 30,
        keep_checkpoint_days: 90,
        force_optimize: false,
    };

    let result = db.run_maintenance(config);
    assert!(result.is_ok());

    let maintenance = result.unwrap();
    assert!(maintenance.rounds_deleted > 0);
}

// =============================================================================
// CONCURRENT ACCESS (Tests 596-600)
// =============================================================================

#[test]
fn test_596_concurrent_reads() {
    let db = Arc::new(Database::in_memory().unwrap());

    // Setup data
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    let share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "hash1".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };
    db.insert_share(&share).unwrap();

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let db_clone = Arc::clone(&db);
            std::thread::spawn(move || {
                let shares = db_clone.get_shares_by_round(1).unwrap();
                shares.len() == 1
            })
        })
        .collect();

    for handle in handles {
        assert!(handle.join().unwrap());
    }
}

#[test]
fn test_597_concurrent_writes() {
    let db = Arc::new(Database::in_memory().unwrap());

    // Setup round
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let db_clone = Arc::clone(&db);
            std::thread::spawn(move || {
                let share = ShareRecord {
                    id: None,
                    round_id: 1,
                    miner_id: format!("miner{}", i),
                    difficulty: 1000.0,
                    work: 1000.0,
                    share_hash: format!("hash{}", i),
                    timestamp: 1700000000 + i,
                    received_by: "node1".to_string(),
                    valid: true,
                };
                db_clone.insert_share(&share).is_ok()
            })
        })
        .collect();

    for handle in handles {
        assert!(handle.join().unwrap());
    }

    let shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(shares.len(), 10);
}

#[test]
fn test_598_read_write_interleave() {
    let db = Arc::new(Database::in_memory().unwrap());

    // Setup round and initial data
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    for i in 0..100i64 {
        let share = ShareRecord {
            id: None,
            round_id: 1,
            miner_id: "miner1".to_string(),
            difficulty: 1000.0,
            work: 1000.0,
            share_hash: format!("initial_hash{}", i),
            timestamp: 1700000000 + i,
            received_by: "node1".to_string(),
            valid: true,
        };
        db.insert_share(&share).unwrap();
    }

    let db_read = Arc::clone(&db);
    let db_write = Arc::clone(&db);

    let reader = std::thread::spawn(move || {
        for _ in 0..100 {
            let _ = db_read.get_shares_by_round(1);
        }
    });

    let writer = std::thread::spawn(move || {
        for i in 100..200i64 {
            let share = ShareRecord {
                id: None,
                round_id: 1,
                miner_id: "miner1".to_string(),
                difficulty: 1000.0,
                work: 1000.0,
                share_hash: format!("new_hash{}", i),
                timestamp: 1700000000 + i,
                received_by: "node1".to_string(),
                valid: true,
            };
            let _ = db_write.insert_share(&share);
        }
    });

    reader.join().unwrap();
    writer.join().unwrap();
}

#[test]
fn test_599_database_clone_shares_connection() {
    let db1 = Database::in_memory().unwrap();
    let db2 = db1.clone(); // Clone shares the same Arc<DatabaseInner>

    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db1.create_round(&round).unwrap();

    // Write via db1
    let share = ShareRecord {
        id: None,
        round_id: 1,
        miner_id: "miner1".to_string(),
        difficulty: 1000.0,
        work: 1000.0,
        share_hash: "hash1".to_string(),
        timestamp: 1700000000,
        received_by: "node1".to_string(),
        valid: true,
    };
    db1.insert_share(&share).unwrap();

    // Read via db2 - should see the same data
    let shares = db2.get_shares_by_round(1).unwrap();
    assert_eq!(shares.len(), 1);
}

#[test]
fn test_600_concurrent_transactions() {
    let db = Arc::new(Database::in_memory().unwrap());

    // Setup round
    let round = RoundRecord {
        round_id: 1,
        block_height: 800000,
        block_hash: None,
        start_time: 1700000000,
        end_time: None,
        total_shares: 0,
        total_work: 0.0,
        winning_miner: None,
        found_by_node: None,
        payout_status: PayoutStatus::Active,
        subsidy_sats: None,
        tx_fees_sats: None,
    };
    db.create_round(&round).unwrap();

    // Multiple threads doing transactions
    let handles: Vec<_> = (0..5)
        .map(|i| {
            let db_clone = Arc::clone(&db);
            std::thread::spawn(move || {
                for j in 0..10 {
                    let idx = i * 10 + j;
                    let result: Result<(), ghost_common::error::GhostError> = db_clone.transaction(|tx| {
                        tx.execute(
                            "INSERT INTO shares (round_id, miner_id, difficulty, work, share_hash, timestamp, received_by, valid)
                             VALUES (1, ?, 1000.0, 1000.0, ?, 1700000000, 'node1', 1)",
                            rusqlite::params![format!("miner{}", idx), format!("hash{}", idx)],
                        )
                        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
                        Ok(())
                    });
                    if result.is_err() {
                        return false;
                    }
                }
                true
            })
        })
        .collect();

    for handle in handles {
        assert!(handle.join().unwrap());
    }

    let shares = db.get_shares_by_round(1).unwrap();
    assert_eq!(shares.len(), 50);
}
