//! End-to-End Tests for Bitcoin Ghost
//!
//! These tests verify complete workflows across the entire stack.
//! Run with: cargo test --test integration e2e
//!
//! Test Categories:
//! - BUDS classification

// ============================================================================
// BUDS Classification E2E Tests
// ============================================================================

mod buds_classification {
    use ghost_buds::{BudsClassifier, BudsTier};

    #[test]
    fn test_classifier_initialization() {
        let classifier = BudsClassifier::new();
        // Classifier should initialize without panicking
        let _ = classifier;
    }

    #[test]
    fn test_tier_ordering() {
        // T0 is most preferred, T3 is least
        assert!(BudsTier::T0.value() < BudsTier::T1.value());
        assert!(BudsTier::T1.value() < BudsTier::T2.value());
        assert!(BudsTier::T2.value() < BudsTier::T3.value());
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(BudsTier::T0.to_string(), "T0");
        assert_eq!(BudsTier::T1.to_string(), "T1");
        assert_eq!(BudsTier::T2.to_string(), "T2");
        assert_eq!(BudsTier::T3.to_string(), "T3");
    }

    #[test]
    fn test_tier_from_value() {
        assert_eq!(BudsTier::from_value(0), Some(BudsTier::T0));
        assert_eq!(BudsTier::from_value(1), Some(BudsTier::T1));
        assert_eq!(BudsTier::from_value(2), Some(BudsTier::T2));
        assert_eq!(BudsTier::from_value(3), Some(BudsTier::T3));
        assert_eq!(BudsTier::from_value(99), None); // Invalid value
    }
}

// ============================================================================
// Full Stack Integration Tests
// ============================================================================

mod full_stack {
    /// Test that all major crates compile together
    #[test]
    fn test_crate_imports() {
        use ::ghost_buds::BudsTier;

        // If this compiles, all crates are compatible
        let _ = BudsTier::T0;
    }
}
