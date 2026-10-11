//! SSH controller using std::process::Command.
//!
//! Shells out to `ssh ghost-vmN "sudo ..."` using the host's SSH config.

use std::process::Command;

use super::config::{ClusterConfig, NodeInfo};

pub struct SshController;

impl SshController {
    /// Run an arbitrary command on a remote node via SSH (public).
    pub fn run_raw(node: &NodeInfo, cmd: &str) -> Result<String, String> {
        Self::run(node, cmd)
    }

    /// Run a command on a remote node via SSH.
    fn run(node: &NodeInfo, cmd: &str) -> Result<String, String> {
        let output = Command::new("ssh")
            .arg(node.ssh_alias)
            .arg(cmd)
            .output()
            .map_err(|e| format!("SSH to {} failed: {}", node.ssh_alias, e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // Some commands (like systemctl is-active) use exit code to indicate state
            if !stdout.is_empty() {
                Ok(stdout)
            } else {
                Err(format!(
                    "SSH command failed on {}: {}",
                    node.ssh_alias, stderr
                ))
            }
        }
    }

    /// Stop the ghost-mining service. Refuses if node is genesis.
    pub fn stop_node(node: &NodeInfo, service: &str) -> Result<String, String> {
        if node.is_genesis {
            return Err(format!(
                "REFUSED: cannot stop genesis node {} ({})",
                node.name, node.ip
            ));
        }
        println!("  [SSH] Stopping {} on {}", service, node.name);
        Self::run(node, &format!("sudo systemctl stop {}", service))
    }

    /// Start the ghost-mining service.
    pub fn start_node(node: &NodeInfo, service: &str) -> Result<String, String> {
        println!("  [SSH] Starting {} on {}", service, node.name);
        Self::run(node, &format!("sudo systemctl start {}", service))
    }

    /// Check if the service is active.
    pub fn is_node_active(node: &NodeInfo, service: &str) -> Result<bool, String> {
        let output = Self::run(node, &format!("systemctl is-active {}", service))?;
        Ok(output.trim() == "active")
    }

    // --- iptables partition methods ---

    /// Create (or flush) a dedicated iptables chain for chaos partitioning.
    /// Never touches port 22 (SSH) — only mesh ports 8080, 8555-8562.
    pub fn setup_partition_chain(node: &NodeInfo) -> Result<String, String> {
        println!(
            "  [SSH] Setting up GHOST_CHAOS iptables chain on {}",
            node.name
        );
        // Create chain if it doesn't exist, flush it if it does
        Self::run(
            node,
            "sudo iptables -N GHOST_CHAOS 2>/dev/null || sudo iptables -F GHOST_CHAOS; \
             sudo iptables -C INPUT -j GHOST_CHAOS 2>/dev/null || sudo iptables -I INPUT 1 -j GHOST_CHAOS; \
             sudo iptables -C OUTPUT -j GHOST_CHAOS 2>/dev/null || sudo iptables -I OUTPUT 1 -j GHOST_CHAOS",
        )
    }

    /// Block traffic between this node and a peer on mesh ports (8080, 8555-8562).
    /// Never blocks port 22 — SSH access is always preserved.
    pub fn block_peer(node: &NodeInfo, peer_ip: &str) -> Result<String, String> {
        println!("  [SSH] Blocking {} ↔ {} on mesh ports", node.name, peer_ip);
        Self::run(
            node,
            &format!(
                "sudo iptables -A GHOST_CHAOS -s {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -s {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset",
                peer_ip, peer_ip, peer_ip, peer_ip
            ),
        )
    }

    /// Get the total packet count rejected by the GHOST_CHAOS chain on a node.
    /// Returns 0 if the chain doesn't exist.
    pub fn partition_hit_count(node: &NodeInfo) -> Result<u64, String> {
        let output = Self::run(
            node,
            "sudo iptables -L GHOST_CHAOS -n -v 2>/dev/null | awk 'NR>2 {sum+=$1} END {print sum+0}'",
        )?;
        output
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("failed to parse hit count '{}': {}", output.trim(), e))
    }

    /// Flush and remove the GHOST_CHAOS chain, restoring normal connectivity.
    pub fn cleanup_partition(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Cleaning up GHOST_CHAOS chain on {}", node.name);
        Self::run(
            node,
            "sudo iptables -F GHOST_CHAOS 2>/dev/null; \
             sudo iptables -D INPUT -j GHOST_CHAOS 2>/dev/null; \
             sudo iptables -D OUTPUT -j GHOST_CHAOS 2>/dev/null; \
             sudo iptables -X GHOST_CHAOS 2>/dev/null; true",
        )
    }

    /// Safety cleanup: remove partition rules from all nodes in the cluster.
    pub fn cleanup_all_partitions(config: &ClusterConfig) -> Result<(), String> {
        println!("  [SSH] Cleaning up partitions on all nodes");
        for node in &config.nodes {
            // Best-effort: don't fail if chain doesn't exist
            let _ = Self::cleanup_partition(node);
        }
        Ok(())
    }

    /// Force-stop a node, bypassing the genesis guard.
    /// Used only by Phase 13 (genesis resilience) tests.
    pub fn force_stop_node(node: &NodeInfo, service: &str) -> Result<String, String> {
        println!(
            "  [SSH] FORCE stopping {} on {} (genesis guard bypassed)",
            service, node.name
        );
        Self::run(node, &format!("sudo systemctl stop {}", service))
    }

    /// Block only outgoing traffic from this node to a peer on mesh ports.
    /// Creates an asymmetric partition: node cannot send to peer, but peer can send to node.
    pub fn block_peer_outgoing(node: &NodeInfo, peer_ip: &str) -> Result<String, String> {
        println!(
            "  [SSH] Blocking {} → {} outgoing on mesh ports",
            node.name, peer_ip
        );
        Self::run(
            node,
            &format!(
                "sudo iptables -A GHOST_CHAOS -d {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -d {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset",
                peer_ip, peer_ip
            ),
        )
    }

    /// Block only incoming traffic from a peer to this node on mesh ports.
    /// Creates an asymmetric partition: peer cannot send to node, but node can send to peer.
    #[allow(dead_code)]
    pub fn block_peer_incoming(node: &NodeInfo, peer_ip: &str) -> Result<String, String> {
        println!(
            "  [SSH] Blocking {} ← {} incoming on mesh ports",
            node.name, peer_ip
        );
        Self::run(
            node,
            &format!(
                "sudo iptables -A GHOST_CHAOS -s {} -p tcp --dport 8080 -j REJECT --reject-with tcp-reset; \
                 sudo iptables -A GHOST_CHAOS -s {} -p tcp --match multiport --dports 8555:8562 -j REJECT --reject-with tcp-reset",
                peer_ip, peer_ip
            ),
        )
    }

    // --- Config management methods ---

    /// Config file path on remote nodes.
    const CONFIG_PATH: &'static str = "/etc/ghost/pool.toml";
    const CONFIG_BACKUP: &'static str = "/etc/ghost/pool.toml.chaos_backup";

    /// Backup the current config file. Fails if backup already exists (prevents double-backup).
    pub fn backup_config(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Backing up config on {}", node.name);
        Self::run(
            node,
            &format!(
                "test ! -f {} && sudo cp {} {}",
                Self::CONFIG_BACKUP,
                Self::CONFIG_PATH,
                Self::CONFIG_BACKUP
            ),
        )
    }

    /// Restore config from backup. Removes the backup file after restore.
    pub fn restore_config(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Restoring config on {}", node.name);
        Self::run(
            node,
            &format!(
                "sudo cp {} {} && sudo rm -f {}",
                Self::CONFIG_BACKUP,
                Self::CONFIG_PATH,
                Self::CONFIG_BACKUP
            ),
        )
    }

    /// Check if a config backup exists.
    pub fn has_config_backup(node: &NodeInfo) -> Result<bool, String> {
        let output = Self::run(
            node,
            &format!("test -f {} && echo yes || echo no", Self::CONFIG_BACKUP),
        )?;
        Ok(output.trim() == "yes")
    }

    /// Patch a TOML field within a specific section using section-aware sed.
    /// Example: `patch_config_field(node, "storage", "archive_mode", "false")`
    pub fn patch_config_field(
        node: &NodeInfo,
        section: &str,
        key: &str,
        value: &str,
    ) -> Result<String, String> {
        // TOML requires string values to be quoted. Booleans (true/false) and
        // numbers are written bare. Anything else gets double-quoted.
        let is_bool = value == "true" || value == "false";
        let is_number = value.parse::<f64>().is_ok();
        let toml_value = if is_bool || is_number {
            value.to_string()
        } else {
            format!(r#""{}""#, value)
        };
        println!(
            "  [SSH] Patching {}.{} = {} on {}",
            section, key, toml_value, node.name
        );
        // Section-aware sed: only modify lines between [section] and the next [
        Self::run(
            node,
            &format!(
                r#"sudo sed -i '/^\[{}\]/,/^\[/{{s/^{} = .*/{} = {}/}}' {}"#,
                section,
                key,
                key,
                toml_value,
                Self::CONFIG_PATH
            ),
        )
    }

    /// Read a TOML field value from a specific section.
    pub fn read_config_field(node: &NodeInfo, section: &str, key: &str) -> Result<String, String> {
        let output = Self::run(
            node,
            &format!(
                r#"sed -n '/^\[{}\]/,/^\[/{{/^{} = /p}}' {} | head -1 | sed 's/.*= //' | tr -d '"'"#,
                section,
                key,
                Self::CONFIG_PATH
            ),
        )?;
        Ok(output.trim().to_string())
    }

    /// Restart the service (stop + start). Does NOT use genesis guard.
    pub fn restart_service(node: &NodeInfo, service: &str) -> Result<String, String> {
        println!("  [SSH] Restarting {} on {}", service, node.name);
        Self::run(node, &format!("sudo systemctl restart {}", service))
    }

    /// Count log lines matching a pattern since a given time.
    pub fn count_log_matches(
        node: &NodeInfo,
        service: &str,
        pattern: &str,
        since: &str,
    ) -> Result<u64, String> {
        let output = Self::run(
            node,
            &format!(
                "sudo journalctl -u {} --since='{}' --no-pager | grep -ci '{}' || true",
                service, since, pattern
            ),
        )?;
        output
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("failed to parse count from '{}': {}", output.trim(), e))
    }

    // --- Ghost Core (C++ daemon) management ---

    /// Ghost Core systemd service name.
    pub const GHOST_CORE_SERVICE: &'static str = "ghostd";

    /// Systemd drop-in directory for ghostd overrides.
    const GHOSTD_DROPIN_DIR: &'static str = "/etc/systemd/system/ghostd.service.d";

    /// Backup the ghostd drop-in config (reaper.conf) before chaos mutations.
    pub fn backup_ghost_conf(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Backing up ghostd drop-in config on {}", node.name);
        Self::run(
            node,
            &format!(
                "sudo mkdir -p {} && \
                 if [ -f {}/reaper.conf ]; then \
                   sudo cp {}/reaper.conf {}/reaper.conf.chaos_backup; \
                 else \
                   sudo rm -f {}/reaper.conf.chaos_backup; \
                 fi",
                Self::GHOSTD_DROPIN_DIR,
                Self::GHOSTD_DROPIN_DIR,
                Self::GHOSTD_DROPIN_DIR,
                Self::GHOSTD_DROPIN_DIR,
                Self::GHOSTD_DROPIN_DIR,
            ),
        )
    }

    /// Restore ghostd drop-in config from backup, removing chaos overrides.
    pub fn restore_ghost_conf(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Restoring ghostd drop-in config on {}", node.name);
        Self::run(
            node,
            &format!(
                "if [ -f {dir}/reaper.conf.chaos_backup ]; then \
                   sudo cp {dir}/reaper.conf.chaos_backup {dir}/reaper.conf && \
                   sudo rm -f {dir}/reaper.conf.chaos_backup; \
                 else \
                   sudo rm -f {dir}/reaper.conf; \
                 fi && \
                 sudo systemctl daemon-reload",
                dir = Self::GHOSTD_DROPIN_DIR
            ),
        )
    }

    /// Check if a ghostd config backup exists.
    pub fn has_ghost_conf_backup(node: &NodeInfo) -> Result<bool, String> {
        let output = Self::run(
            node,
            &format!(
                "test -f {}/reaper.conf.chaos_backup && echo yes || echo no",
                Self::GHOSTD_DROPIN_DIR
            ),
        )?;
        Ok(output.trim() == "yes")
    }

    /// Add a flag to ghostd via systemd drop-in override.
    ///
    /// Reads the effective ExecStart (from reaper.conf or main unit), appends
    /// the flag, and writes an updated reaper.conf. Requires daemon-reload + restart.
    pub fn add_ghost_conf_flag(node: &NodeInfo, key: &str, _value: &str) -> Result<String, String> {
        println!("  [SSH] Adding ghostd flag -{} on {}", key, node.name);
        // Read the effective ExecStart command, append the flag, update reaper.conf
        Self::run(
            node,
            &format!(
                r#"sudo mkdir -p {dir} && \
                   EXEC=$(systemctl cat ghostd 2>/dev/null | grep '^ExecStart=/opt' | tail -1) && \
                   if echo "$EXEC" | grep -q '\-{key}'; then echo 'flag already present'; exit 0; fi && \
                   printf '[Service]\nExecStart=\n%s   -{key}\n' "$EXEC" | sudo tee {dir}/reaper.conf > /dev/null && \
                   sudo systemctl daemon-reload"#,
                dir = Self::GHOSTD_DROPIN_DIR,
                key = key,
            ),
        )
    }

    /// Remove a flag from ghostd by regenerating the drop-in without it.
    #[allow(dead_code)]
    pub fn remove_ghost_conf_flag(node: &NodeInfo, key: &str) -> Result<String, String> {
        println!("  [SSH] Removing ghostd flag -{} on {}", key, node.name);
        Self::run(
            node,
            &format!(
                r#"EXEC=$(systemctl cat ghostd 2>/dev/null | grep '^ExecStart=/opt' | tail -1 | sed 's/  *-{key}//' ) && \
                   printf '[Service]\nExecStart=\n%s\n' "$EXEC" | sudo tee {dir}/reaper.conf > /dev/null && \
                   sudo systemctl daemon-reload"#,
                key = key,
                dir = Self::GHOSTD_DROPIN_DIR,
            ),
        )
    }

    /// Restart the ghost-core daemon (ghostd.service).
    /// Uses ghost-cli RPC to stop, then systemctl to start.
    /// Also restarts ghost-pay since it has Requires=ghostd.service
    /// (systemd stops ghost-pay when ghostd stops, but doesn't restart it).
    pub fn restart_ghost_core(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Restarting ghost-core on {}", node.name);
        Self::run(
            node,
            "/opt/ghost/bin/ghost-cli -signet -datadir=/var/lib/bitcoin \
             -rpcport=38332 -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 \
             stop 2>/dev/null; \
             sleep 3; \
             sudo systemctl reset-failed ghostd 2>/dev/null; \
             sudo systemctl start ghostd; \
             sleep 2; \
             sudo systemctl start ghost-pay 2>/dev/null; true",
        )
    }

    /// Stop the ghost-core daemon via RPC.
    /// Note: ghost-pay will also be stopped by systemd (Requires=ghostd.service).
    pub fn stop_ghost_core(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Stopping ghost-core on {}", node.name);
        Self::run(
            node,
            "/opt/ghost/bin/ghost-cli -signet -datadir=/var/lib/bitcoin \
             -rpcport=38332 -rpcuser=ghostrpc -rpcpassword=ghost_signet_rpc_2024 \
             stop 2>/dev/null; \
             sleep 2; \
             sudo systemctl stop ghostd 2>/dev/null; true",
        )
    }

    /// Start the ghost-core service.
    /// Also restarts ghost-pay since it has Requires=ghostd.service
    /// (systemd stops ghost-pay when ghostd stops, but doesn't restart it).
    pub fn start_ghost_core(node: &NodeInfo) -> Result<String, String> {
        println!("  [SSH] Starting ghost-core on {}", node.name);
        Self::run(
            node,
            "sudo systemctl reset-failed ghostd 2>/dev/null; \
             sudo systemctl start ghostd; \
             sleep 2; \
             sudo systemctl start ghost-pay 2>/dev/null; true",
        )
    }

    /// Check if ghost-core daemon is running (checks process, not systemd state).
    pub fn is_ghost_core_active(node: &NodeInfo) -> Result<bool, String> {
        let output = Self::run(
            node,
            "pidof ghostd >/dev/null 2>&1 || pidof bitcoin-node >/dev/null 2>&1; echo $?",
        )?;
        Ok(output.trim() == "0")
    }

    /// Read the ghostd/bitcoin-node process command line to verify active flags.
    pub fn read_ghostd_cmdline(node: &NodeInfo) -> Result<String, String> {
        Self::run(
            node,
            "cat /proc/$(pidof ghostd || pidof bitcoin-node)/cmdline 2>/dev/null | tr '\\0' ' '",
        )
    }
}
