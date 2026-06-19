//! Integration Tests for Bitcoin Ghost
//!
//! These tests verify end-to-end functionality across multiple components.
//!
//! # Test Categories
//!
//! The legacy two-phase Wraith mixing tests (categories 10, 23, 24, 28, 30, 31)
//! were removed when the protocol moved to single-round atomic CoinJoin.
//! Single-round coverage now lives in the wraith-coordinator and
//! wraith-wallet-core test crates.
//!
//! # Running Tests
//!
//! ```bash
//! # Run all integration tests
//! cargo test --test integration
//!
//! # Run specific category
//! cargo test --test integration cryptography
//! cargo test --test integration config_validation
//! cargo test --test integration stratum_validation
//! cargo test --test integration consensus_voting
//! cargo test --test integration buds_classification
//! cargo test --test integration security
//! cargo test --test integration ghost_pay
//! cargo test --test integration round_management
//! cargo test --test integration edge_cases
//! cargo test --test integration ghost_lock_types
//! cargo test --test integration settlement_reconciliation
//! cargo test --test integration gsp_payment_messages
//! cargo test --test integration l2_nullifier_route
//! ```

pub mod adversarial;
pub mod block_template;
pub mod buds_classification;
pub mod config_validation;
pub mod consensus;
pub mod consensus_voting;
pub mod cryptography;
pub mod discovery_security;
pub mod e2e;
pub mod edge_cases;
pub mod fund_safety;
pub mod ghost_lock_types;
pub mod ghost_pay;
pub mod gsp;
pub mod gsp_payment_messages;
pub mod helpers;
pub mod historical_bugs;
pub mod hypothetical_bugs;
pub mod l2_nullifier_route;
pub mod mesh_cluster;
pub mod policy_enforcement;
pub mod pool_cycle;
pub mod round_management;
pub mod rpc_client;
pub mod security;
pub mod settlement_reconciliation;
pub mod silent_payment_v2;
pub mod storage;
pub mod stratum_payout_consensus;
pub mod stratum_validation;
