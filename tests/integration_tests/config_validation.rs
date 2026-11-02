//! Category 2: Configuration & Validation Tests (65 tests)
//!
//! Comprehensive tests for all configuration validation including:
//! - Config loading and defaults
//! - Network configuration
//! - Bitcoin RPC configuration
//! - Pool configuration
//! - Policy configuration
//! - Storage configuration

use ghost_common::config::*;

// =============================================================================
// CONFIG LOADING TESTS (Tests 86-90)
// =============================================================================

#[test]
fn test_086_default_config_has_sensible_values() {
    let config = NodeConfig::default();

    // Network defaults
    assert_eq!(config.network.sv2_port, 34255);
    assert_eq!(config.network.sv1_port, 3333);
    assert!(config.network.signing_key.is_none());

    // Bitcoin defaults
    assert_eq!(config.bitcoin.rpc_host, "127.0.0.1");
    assert_eq!(config.bitcoin.network, BitcoinNetwork::Signet);
}

#[test]
fn test_087_bitcoin_network_default_ports() {
    assert_eq!(BitcoinNetwork::Mainnet.default_rpc_port(), 8332);
    assert_eq!(BitcoinNetwork::Signet.default_rpc_port(), 38332);
    assert_eq!(BitcoinNetwork::Testnet.default_rpc_port(), 18332);
    assert_eq!(BitcoinNetwork::Regtest.default_rpc_port(), 18443);
}

#[test]
fn test_088_bitcoin_network_p2p_ports() {
    assert_eq!(BitcoinNetwork::Mainnet.default_p2p_port(), 8333);
    assert_eq!(BitcoinNetwork::Signet.default_p2p_port(), 38333);
    assert_eq!(BitcoinNetwork::Testnet.default_p2p_port(), 18333);
    assert_eq!(BitcoinNetwork::Regtest.default_p2p_port(), 18444);
}

#[test]
fn test_089_policy_profiles_exist() {
    let bitcoin_pure = PolicyConfig {
        profile: PolicyProfile::BitcoinPure,
        custom: None,
    };
    assert_eq!(bitcoin_pure.profile, PolicyProfile::BitcoinPure);

    let permissive = PolicyConfig {
        profile: PolicyProfile::Permissive,
        custom: None,
    };
    assert_eq!(permissive.profile, PolicyProfile::Permissive);

    let full_open = PolicyConfig {
        profile: PolicyProfile::FullOpen,
        custom: None,
    };
    assert_eq!(full_open.profile, PolicyProfile::FullOpen);
}

#[test]
fn test_090_custom_policy_defaults() {
    let custom = CustomPolicyConfig::default();

    assert!(custom.allowed_tiers.contains(&BudsTier::T0));
    assert!(custom.allowed_tiers.contains(&BudsTier::T1));
    assert!(custom.allowed_tiers.contains(&BudsTier::T2));
    assert!(!custom.allow_inscriptions);
    assert!(!custom.allow_runes);
}

// =============================================================================
// NETWORK CONFIG VALIDATION TESTS (Tests 91-102)
// =============================================================================

#[test]
fn test_091_zero_port_rejected() {
    let mut config = NodeConfig::default();
    config.network.sv2_port = 0;

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result.errors.iter().any(|e| e.field.contains("sv2_port")));
}

#[test]
fn test_092_duplicate_ports_rejected() {
    let mut config = NodeConfig::default();
    config.network.sv2_port = 3333;
    config.network.sv1_port = 3333; // Duplicate!

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result
        .errors
        .iter()
        .any(|e| e.message.contains("Port conflict")));
}

#[test]
fn test_093_valid_port_range_accepted() {
    let mut config = NodeConfig::default();
    config.network.sv2_port = 34255;
    config.network.sv1_port = 3333;
    config.network.http_port = 8080;

    let result = config.validate();
    // Should not have port-related errors
    assert!(!result
        .errors
        .iter()
        .any(|e| e.field.contains("port") && e.message.contains("Invalid port 0")));
}

#[test]
fn test_096_invalid_signing_key_length_rejected() {
    let mut config = NodeConfig::default();
    config.network.signing_key = Some("0123456789abcdef".to_string()); // Only 16 chars

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result
        .errors
        .iter()
        .any(|e| e.field == "network.signing_key" && e.message.contains("64 hex")));
}

#[test]
fn test_097_invalid_signing_key_chars_rejected() {
    let mut config = NodeConfig::default();
    // Contains 'g', 'h', 'i', 'j' which are not hex
    config.network.signing_key =
        Some("ghij456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result
        .errors
        .iter()
        .any(|e| e.field == "network.signing_key" && e.message.contains("hexadecimal")));
}

#[test]
fn test_098_valid_signing_key_accepted() {
    let mut config = NodeConfig::default();
    config.network.signing_key =
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

    let result = config.validate();
    // Should not have signing_key REQUIRED error
    assert!(!result
        .errors
        .iter()
        .any(|e| e.field == "network.signing_key" && e.message.contains("REQUIRED")));
}

#[test]
fn test_100_seed_nodes_http_remote_rejected() {
    let mut config = NodeConfig::default();
    config.network.seed_nodes = vec!["http://192.168.1.100:8080".to_string()];

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result
        .errors
        .iter()
        .any(|e| e.field.contains("seed_nodes") && e.message.contains("Insecure HTTP")));
}

#[test]
fn test_101_seed_nodes_https_accepted() {
    let mut config = NodeConfig::default();
    config.network.seed_nodes = vec!["https://seed.example.com:8080".to_string()];

    let result = config.validate();
    // Should not have seed_nodes error for HTTPS
    assert!(!result
        .errors
        .iter()
        .any(|e| e.field.contains("seed_nodes") && e.message.contains("Insecure HTTP")));
}

#[test]
fn test_102_seed_nodes_localhost_http_warning() {
    let mut config = NodeConfig::default();
    config.network.seed_nodes = vec!["http://127.0.0.1:8080".to_string()];

    let result = config.validate();
    // Should be a warning, not an error
    assert!(result
        .warnings
        .iter()
        .any(|e| e.field.contains("seed_nodes") && e.message.contains("localhost")));
    // Should NOT be an error
    assert!(!result.errors.iter().any(|e| e.field.contains("seed_nodes")));
}

// =============================================================================
// BITCOIN RPC CONFIG TESTS (Tests 103-112)
// =============================================================================

#[test]
fn test_103_empty_rpc_user_rejected() {
    let mut config = NodeConfig::default();
    config.bitcoin.rpc_user = String::new();

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result.errors.iter().any(|e| e.field == "bitcoin.rpc_user"));
}

#[test]
fn test_104_empty_rpc_password_rejected() {
    let mut config = NodeConfig::default();
    config.bitcoin.rpc_password = String::new();

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result
        .errors
        .iter()
        .any(|e| e.field == "bitcoin.rpc_password"));
}

#[test]
fn test_105_default_credentials_produce_warning() {
    let mut config = NodeConfig::default();
    config.bitcoin.rpc_user = "bitcoin".to_string();
    config.bitcoin.rpc_password = "bitcoin".to_string();

    let result = config.validate();
    assert!(result
        .warnings
        .iter()
        .any(|e| e.field.contains("rpc_user") || e.field.contains("rpc_password")));
}

#[test]
fn test_106_zero_rpc_port_rejected() {
    let mut config = NodeConfig::default();
    config.bitcoin.rpc_port = 0;

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result.errors.iter().any(|e| e.field == "bitcoin.rpc_port"));
}

#[test]
fn test_107_non_standard_port_produces_warning() {
    let mut config = NodeConfig::default();
    config.bitcoin.network = BitcoinNetwork::Mainnet;
    config.bitcoin.rpc_port = 9999; // Not 8332

    let result = config.validate();
    assert!(result
        .warnings
        .iter()
        .any(|e| e.field == "bitcoin.rpc_port" && e.message.contains("differs from default")));
}

#[test]
fn test_108_missing_zmq_hashblock_warning() {
    let mut config = NodeConfig::default();
    config.bitcoin.zmq_hashblock = None;

    let result = config.validate();
    assert!(result
        .warnings
        .iter()
        .any(|e| e.field == "bitcoin.zmq_hashblock"));
}

#[test]
fn test_109_zmq_endpoints_valid() {
    let config = NodeConfig::default();

    // Default should have ZMQ endpoints
    assert!(config.bitcoin.zmq_hashblock.is_some());
    assert!(config.bitcoin.zmq_hashtx.is_some());
    assert!(config.bitcoin.zmq_sequence.is_some());
}

// =============================================================================
// POOL CONFIG TESTS (Tests 113-120)
// =============================================================================

// =============================================================================
// STORAGE CONFIG TESTS (Tests 129-131)
// =============================================================================

#[test]
fn test_129_empty_db_path_rejected() {
    let mut config = NodeConfig::default();
    config.storage.db_path = std::path::PathBuf::new();

    let result = config.validate();
    assert!(!result.is_valid());
    assert!(result.errors.iter().any(|e| e.field == "storage.db_path"));
}

#[test]
fn test_130_archive_mode_with_pruning_warning() {
    let mut config = NodeConfig::default();
    config.storage.archive_mode = true;
    config.storage.prune_height = 1000;

    let result = config.validate();
    assert!(result
        .warnings
        .iter()
        .any(|e| e.field.contains("archive_mode") || e.field.contains("prune_height")));
}

#[test]
fn test_131_wal_mode_defaults_enabled() {
    let config = NodeConfig::default();
    assert!(config.storage.wal_mode);
}

// =============================================================================
// POOL CONFIG VALIDATE METHOD TESTS
// =============================================================================
