//! Integration Tests for Bitcoin Ghost
//!
//! These tests verify end-to-end functionality across multiple components.
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
//! cargo test --test integration buds_classification
//! cargo test --test integration security
//! cargo test --test integration round_management
//! cargo test --test integration edge_cases
//! ```

pub mod buds_classification;
pub mod config_validation;
pub mod cryptography;
pub mod discovery_security;
pub mod e2e;
pub mod edge_cases;
pub mod helpers;
pub mod historical_bugs;
pub mod hypothetical_bugs;
pub mod policy_enforcement;
pub mod pool_cycle;
pub mod round_management;
pub mod rpc_client;
pub mod security;
pub mod storage;
pub mod stratum_validation;
