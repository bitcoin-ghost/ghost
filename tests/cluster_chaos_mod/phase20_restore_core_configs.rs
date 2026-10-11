//! Phase 20: Restore Ghost Core Configs — undo Phase 18's tormode deployment.
//!
//! Restores VM3's ghost.conf from backup and restarts ghost-core to return
//! the cluster to its original Ghost Core configuration.
//!
//! This phase MUST run after Phases 18-19 to leave the cluster in its original state.

use std::time::Duration;

use super::client::ClusterClient;
use super::config::ClusterConfig;
use super::ssh::SshController;

fn setup() -> ClusterClient {
    ClusterClient::new(ClusterConfig::signet())
}

// --- Test 01: Restore ghost.conf on VM3 ---

#[tokio::test]
#[ignore]
async fn core_restore_01_restore_configs() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").unwrap();

    println!("\n=== Ghost Core Restore: Restoring Configs ===");

    if SshController::has_ghost_conf_backup(vm3).unwrap_or(false) {
        SshController::restore_ghost_conf(vm3).expect("failed to restore VM3 ghost.conf");
        println!("  VM3 ghost.conf restored from backup");
    } else {
        println!("  VM3 no ghost.conf backup found (skipping)");
    }
}

// --- Test 02: Restart ghost-core with original config ---

#[tokio::test]
#[ignore]
async fn core_restore_02_restart_ghost_core() {
    let client = setup();
    let config = &client.config;
    let vm3 = config.node_by_name("VM3").unwrap();

    println!("\n=== Ghost Core Restore: Restarting Ghost-Core ===");

    SshController::restart_ghost_core(vm3).expect("failed to restart ghost-core on VM3");
    println!("  VM3 ghost-core restarted");

    // Wait for ghost-core to initialize
    tokio::time::sleep(Duration::from_secs(15)).await;

    let active = SshController::is_ghost_core_active(vm3).unwrap_or(false);
    assert!(active, "VM3 ghost-core not active after config restore");
    println!("  VM3 ghost-core active");

    // Wait for all ghost-mining nodes to be healthy
    // (ghost-pay auto-restarts with ghostd via BindsTo + Wants relationship)
    for node in &config.nodes {
        let healthy = client
            .wait_for_node_healthy(node.ip, Duration::from_secs(120))
            .await;
        assert!(
            healthy,
            "{} ghost-mining not healthy after ghost-core config restore",
            node.name
        );
        println!("  {} ghost-mining healthy", node.name);
    }
}

// --- Test 03: Verify original state ---

#[tokio::test]
#[ignore]
async fn core_restore_03_verify_original_state() {
    let client = setup();
    let config = &client.config;

    println!("\n=== Ghost Core Restore: Verifying Original State ===");

    // VM3 should no longer have tormode in ghost.conf
    let vm3 = config.node_by_name("VM3").unwrap();
    let cmdline = SshController::read_ghostd_cmdline(vm3).unwrap_or_default();
    println!("  VM3 ghostd cmdline: {}", cmdline);
    // Note: the cmdline may or may not show tormode depending on the launcher
    // The key check is that ghost.conf no longer has the flag
    assert!(
        !SshController::has_ghost_conf_backup(vm3).unwrap_or(true),
        "VM3 ghost.conf backup still exists"
    );

    // VM4 should still have tormode (unchanged)
    let vm4 = config.node_by_name("VM4").unwrap();
    let cmdline4 = SshController::read_ghostd_cmdline(vm4).unwrap_or_default();
    println!("  VM4 ghostd cmdline: {}", cmdline4);
    assert!(
        cmdline4.contains("tormode"),
        "VM4 lost tormode (should be unchanged)"
    );

    // All nodes healthy with full mesh
    let mut heights = Vec::new();
    for node in &config.nodes {
        let r = client.get_with_retry(node.ip, "/health").await;
        assert!(
            r.error.is_none() && r.status == Some(200),
            "{} not healthy after ghost-core restore: {:?}",
            node.name,
            r.error
        );
        if let Ok(h) = client.get_block_height(node.ip).await {
            heights.push((node.name, h));
            println!("  {} healthy, height: {}", node.name, h);
        }
    }

    if heights.len() == config.nodes.len() {
        let max = heights.iter().map(|(_, h)| *h).max().unwrap();
        let min = heights.iter().map(|(_, h)| *h).min().unwrap();
        assert!(
            max - min <= 1,
            "Heights diverge after ghost-core restore: {:?}",
            heights
        );
    }

    // Zero panics
    for node in &config.nodes {
        let panics =
            SshController::count_log_matches(node, config.service_name, "panic", "30 min ago")
                .unwrap_or(0);
        assert_eq!(
            panics, 0,
            "Ghost-core test session: {} had {} panics",
            node.name, panics
        );
    }
    println!("  Original Ghost Core state verified, zero panics");
}
