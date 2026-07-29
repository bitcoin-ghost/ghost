//! Phase 17: Restore Original Configs — undo Phase 14's heterogeneous deployment.
//!
//! Restores all VMs to their pre-test configurations from backup files.
//! This phase MUST run after Phases 14-16 to leave the cluster in its original state.
#![allow(clippy::expect_fun_call)]

use std::time::Duration;

/// One config setting to restore: (file, key, value).
type ConfigSetting = (&'static str, &'static str, &'static str);

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

/// Wait for a node to reach a target peer count within a timeout.
async fn wait_for_peers(
    client: &ClusterClient,
    ip: &str,
    min_peers: usize,
    timeout: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if let Ok(peers) = client.get_peer_count(ip).await {
            if peers >= min_peers {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    false
}

// --- Test 01: Restore all configs from backup ---

#[tokio::test]
#[ignore]
async fn restore_01_restore_all_configs() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Config Restore: Restoring All Configs From Backup ===");

    // Restore VM2, VM3, VM4 (VM1 was not modified).
    // If a backup exists, restore from it. Otherwise, force-patch the expected
    // original values — the backup may have been lost due to SSH timeouts in a
    // prior run, leaving the config in a modified state.
    let original_values: &[(&str, &[ConfigSetting])] = &[
        (
            "VM2",
            &[
                ("storage", "archive_mode", "true"),
                ("storage", "prune_height", "0"),
                ("reaper", "enabled", "true"),
                ("reaper", "mode", "strict"),
                ("policy", "profile", "bitcoin_pure"),
            ],
        ),
        (
            "VM3",
            &[
                ("reaper", "enabled", "false"),
                ("reaper", "mode", "monitor"),
                ("policy", "profile", "permissive"),
            ],
        ),
        (
            "VM4",
            &[
                ("storage", "archive_mode", "true"),
                ("policy", "profile", "permissive"),
            ],
        ),
    ];

    for (name, fields) in original_values {
        let node = config.node_by_name(name).unwrap();

        let has_backup = SshController::has_config_backup(node).unwrap_or(false);
        if has_backup {
            SshController::restore_config(node)
                .expect(&format!("failed to restore config on {}", name));
            println!("  {} config restored from backup", name);
        } else {
            println!(
                "  {} no backup found — force-patching original values",
                name
            );
            for (section, key, value) in *fields {
                SshController::patch_config_field(node, section, key, value)
                    .expect(&format!("failed to patch {}.{} on {}", section, key, name));
            }
            println!("  {} config force-patched to original values", name);
        }
    }

    // Also clean up VM1 backup if it exists (from safety backup in deploy_01)
    let vm1 = config.node_by_name("VM1").unwrap();
    if SshController::has_config_backup(vm1).unwrap_or(false) {
        // VM1 config was not modified, just remove the backup
        SshController::restore_config(vm1).ok();
        println!("  VM1 backup cleaned up (config was not modified)");
    }
}

// --- Test 02: Restart services with original configs ---

#[tokio::test]
#[ignore]
async fn restore_02_restart_services() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Config Restore: Restarting Services ===");

    // Restart VM2, VM3, VM4 to pick up restored configs
    for name in ["VM2", "VM3", "VM4"] {
        let node = config.node_by_name(name).unwrap();
        SshController::restart_service(node, config.service_name)
            .expect(&format!("failed to restart {} service", name));
        println!("  {} restarted", name);
    }

    // Wait for health
    for name in ["VM1", "VM2", "VM3", "VM4"] {
        let node = config.node_by_name(name).unwrap();
        assert!(
            client
                .wait_for_node_healthy(node.ip, Duration::from_secs(120))
                .await,
            "{} did not become healthy after config restore",
            name
        );
        println!("  {} healthy", name);
    }
}

// --- Test 03: Full mesh restored ---

#[tokio::test]
#[ignore]
async fn restore_03_full_mesh() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Config Restore: Full Mesh Verification ===");

    for ip in config.all_ips() {
        let rejoined = wait_for_peers(&client, ip, 3, config.recovery_timeout).await;
        let peers = client.get_peer_count(ip).await.unwrap_or(0);
        println!("  {} peers: {}", ip, peers);
        assert!(
            rejoined,
            "{} did not reach 3 peers after config restore (got {})",
            ip, peers
        );
    }

    // Heights consistent
    let mut heights = Vec::new();
    for ip in config.all_ips() {
        if let Ok(h) = client.get_block_height(ip).await {
            heights.push((ip, h));
            println!("  {} height: {}", ip, h);
        }
    }
    if heights.len() == config.nodes.len() {
        let max = heights.iter().map(|(_, h)| *h).max().unwrap();
        let min = heights.iter().map(|(_, h)| *h).min().unwrap();
        assert!(
            max - min <= 1,
            "Heights diverge after config restore: {:?}",
            heights
        );
    }
    println!("  Full mesh restored with original configs");
}

// --- Test 04: Original config values verified ---

#[tokio::test]
#[ignore]
async fn restore_04_original_configs_verified() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Config Restore: Verifying Original Config Values ===");

    // VM1: archive=true, reaper=true/strict, policy=bitcoin_pure (unchanged)
    let vm1 = config.node_by_name("VM1").unwrap();
    let v = SshController::read_config_field(vm1, "storage", "archive_mode").unwrap_or_default();
    assert_eq!(v, "true", "VM1 archive_mode not restored");
    let v = SshController::read_config_field(vm1, "policy", "profile").unwrap_or_default();
    assert_eq!(v, "bitcoin_pure", "VM1 policy not correct");
    println!("  VM1: archive=true, policy=bitcoin_pure ✓");

    // VM2: archive=true, prune=0, reaper=true/strict, policy=bitcoin_pure (restored)
    let vm2 = config.node_by_name("VM2").unwrap();
    let v = SshController::read_config_field(vm2, "storage", "archive_mode").unwrap_or_default();
    assert_eq!(v, "true", "VM2 archive_mode not restored");
    let v = SshController::read_config_field(vm2, "storage", "prune_height").unwrap_or_default();
    assert_eq!(v, "0", "VM2 prune_height not restored");
    let v = SshController::read_config_field(vm2, "reaper", "enabled").unwrap_or_default();
    assert_eq!(v, "true", "VM2 reaper not restored");
    let v = SshController::read_config_field(vm2, "policy", "profile").unwrap_or_default();
    assert_eq!(v, "bitcoin_pure", "VM2 policy not restored");
    println!("  VM2: archive=true, prune=0, reaper=true, policy=bitcoin_pure ✓");

    // VM3: archive=true, reaper=false/monitor, policy=permissive (restored)
    let vm3 = config.node_by_name("VM3").unwrap();
    let v = SshController::read_config_field(vm3, "reaper", "enabled").unwrap_or_default();
    assert_eq!(v, "false", "VM3 reaper not restored");
    let v = SshController::read_config_field(vm3, "policy", "profile").unwrap_or_default();
    assert_eq!(v, "permissive", "VM3 policy not restored");
    println!("  VM3: reaper=false, policy=permissive ✓");

    // VM4: archive=true, reaper=false/monitor, policy=permissive (restored)
    let vm4 = config.node_by_name("VM4").unwrap();
    let v = SshController::read_config_field(vm4, "storage", "archive_mode").unwrap_or_default();
    assert_eq!(v, "true", "VM4 archive_mode not restored");
    let v = SshController::read_config_field(vm4, "policy", "profile").unwrap_or_default();
    assert_eq!(v, "permissive", "VM4 policy not restored");
    println!("  VM4: archive=true, policy=permissive ✓");

    // Zero panics across the entire session
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "30 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Config test session: {} had {} panics",
            node.name, panics
        );
    }
    println!("  All original configs verified, zero panics");
}
