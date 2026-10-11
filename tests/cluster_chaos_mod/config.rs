//! Cluster configuration for live chaos tests.
//!
//! Node IPs, SSH aliases, ports, and timeout constants.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub name: &'static str,
    pub ip: &'static str,
    pub ssh_alias: &'static str,
    pub is_genesis: bool,
}

#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub nodes: Vec<NodeInfo>,
    pub http_port: u16,
    pub ws_path: &'static str,
    pub http_timeout: Duration,
    pub recovery_timeout: Duration,
    pub retry_count: u32,
    pub retry_backoff: Duration,
    pub service_name: &'static str,
}

impl ClusterConfig {
    /// Production signet cluster configuration.
    pub fn signet() -> Self {
        Self {
            nodes: vec![
                NodeInfo {
                    name: "VM1",
                    ip: "83.136.251.162",
                    ssh_alias: "ghost-vm1",
                    is_genesis: true,
                },
                NodeInfo {
                    name: "VM2",
                    ip: "85.9.198.212",
                    ssh_alias: "ghost-vm2",
                    is_genesis: false,
                },
                NodeInfo {
                    name: "VM3",
                    ip: "213.163.207.46",
                    ssh_alias: "ghost-vm3",
                    is_genesis: false,
                },
                NodeInfo {
                    name: "VM4",
                    ip: "95.111.221.169",
                    ssh_alias: "ghost-vm4",
                    is_genesis: false,
                },
            ],
            http_port: 8080,
            ws_path: "/ws",
            http_timeout: Duration::from_secs(15),
            recovery_timeout: Duration::from_secs(90),
            retry_count: 3,
            retry_backoff: Duration::from_secs(2),
            service_name: "ghost-mining",
        }
    }

    /// Returns only nodes eligible for chaos (non-genesis).
    pub fn chaos_eligible_nodes(&self) -> Vec<&NodeInfo> {
        self.nodes.iter().filter(|n| !n.is_genesis).collect()
    }

    /// Returns all node IPs.
    pub fn all_ips(&self) -> Vec<&str> {
        self.nodes.iter().map(|n| n.ip).collect()
    }

    /// Build a full HTTP URL for a node.
    pub fn url(&self, ip: &str, endpoint: &str) -> String {
        format!("http://{}:{}{}", ip, self.http_port, endpoint)
    }

    /// Build a WebSocket URL for a node.
    pub fn ws_url(&self, ip: &str) -> String {
        format!("ws://{}:{}{}", ip, self.http_port, self.ws_path)
    }

    /// Find a node by name (e.g. "VM2").
    pub fn node_by_name(&self, name: &str) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| n.name == name)
    }
}
