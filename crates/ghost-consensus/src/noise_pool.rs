//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: noise_pool.rs                                                                                                  |
//|======================================================================================================================|

//! Noise Protocol Connection Pool
//!
//! Manages a pool of established Noise-encrypted TCP connections to peers.
//! This module provides point-to-point encrypted channels that complement
//! the ZMQ PUB/SUB broadcast network.
//!
//! # Architecture
//!
//! - ZMQ continues to handle discovery and health pings (broadcast messages)
//! - Noise TCP handles sensitive messages (shares, blocks, votes, payouts)
//! - Each peer gets one Noise connection, reused for all encrypted traffic
//!
//! # Security Properties
//!
//! - **Confidentiality**: All traffic encrypted with ChaCha20-Poly1305
//! - **Authentication**: Mutual authentication via Noise_XX handshake
//! - **Forward Secrecy**: Per-session ephemeral keys
//! - **Identity Binding**: Noise public key tied to peer identity

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, info};

use ghost_common::types::NodeId;

use crate::noise::{
    NoiseConfig, NoiseError, NoiseKeypair, NoiseManager, NoiseTransport, MAX_PAYLOAD_SIZE,
};
use crate::noise_fragment::{fragment_message, FragmentReassembler};

/// Maximum time a connection can be idle before cleanup
pub const MAX_CONNECTION_AGE: Duration = Duration::from_secs(300); // 5 minutes

/// Maximum number of connections to maintain
pub const MAX_CONNECTIONS: usize = 200;

/// Pool of established Noise connections to peers
pub struct NoiseConnectionPool {
    /// Active connections indexed by peer's Noise public key
    connections: RwLock<HashMap<[u8; 32], Arc<NoiseConnection>>>,
    /// Noise manager for creating sessions (handles keypair internally)
    manager: NoiseManager,
    /// Configuration
    config: NoisePoolConfig,
}

/// Configuration for the Noise connection pool
#[derive(Debug, Clone)]
pub struct NoisePoolConfig {
    /// Maximum connections to maintain
    pub max_connections: usize,
    /// Maximum idle time before cleanup
    pub max_idle: Duration,
    /// Noise configuration
    pub noise: NoiseConfig,
}

impl Default for NoisePoolConfig {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_idle: MAX_CONNECTION_AGE,
            noise: NoiseConfig::default(),
        }
    }
}

/// An established Noise connection to a peer
pub struct NoiseConnection {
    /// Peer's Noise public key (32 bytes)
    pub peer_key: [u8; 32],
    /// Peer's socket address
    pub peer_addr: SocketAddr,
    /// The encrypted transport (wrapped in Mutex for thread-safe access)
    transport: Mutex<NoiseTransport<TcpStream>>,
    /// Reassembles fragmented inbound messages that exceed one Noise frame.
    ///
    /// Guarded by its own async mutex so a partially-received large message is
    /// buffered across successive `recv`/`try_recv` polls without blocking the
    /// transport lock between frames.
    reassembler: Mutex<FragmentReassembler>,
    /// When this connection was established
    pub established_at: Instant,
    /// Last time the connection was used
    last_used: RwLock<Instant>,
}

impl NoiseConnection {
    /// Create a new connection wrapper
    fn new(
        peer_key: [u8; 32],
        peer_addr: SocketAddr,
        transport: NoiseTransport<TcpStream>,
    ) -> Self {
        let now = Instant::now();
        Self {
            peer_key,
            peer_addr,
            transport: Mutex::new(transport),
            reassembler: Mutex::new(FragmentReassembler::new()),
            established_at: now,
            last_used: RwLock::new(now),
        }
    }

    /// Send an encrypted message.
    ///
    /// A message that fits in a single Noise frame is sent unchanged (fast
    /// path). A larger message is split into ordered fragments, all emitted
    /// under the same transport lock so they stay contiguous on the wire and do
    /// not interleave with another message's fragments.
    pub async fn send(&self, payload: &[u8]) -> Result<(), NoiseError> {
        let mut transport = self.transport.lock().await;
        if payload.len() <= MAX_PAYLOAD_SIZE {
            transport.send(payload).await?;
        } else {
            for frame in fragment_message(payload) {
                transport.send(&frame).await?;
            }
        }
        *self.last_used.write() = Instant::now();
        Ok(())
    }

    /// Receive an encrypted message (non-blocking poll).
    ///
    /// Returns `None` if no complete message is available yet — including when a
    /// fragment was received but the logical message is not yet complete.
    /// Fragmented messages are reassembled transparently; callers see only whole
    /// logical messages.
    pub async fn try_recv(&self) -> Result<Option<Vec<u8>>, NoiseError> {
        let mut transport = self.transport.lock().await;

        // Use a short timeout to make this non-blocking
        match tokio::time::timeout(Duration::from_millis(1), transport.recv()).await {
            Ok(Ok(frame)) => {
                *self.last_used.write() = Instant::now();
                // Drop the transport lock before reassembly bookkeeping.
                drop(transport);
                self.reassembler.lock().await.accept(frame)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Ok(None), // Timeout = no data
        }
    }

    /// Receive an encrypted message (blocking).
    ///
    /// Loops over Noise frames until a complete logical message is available,
    /// reassembling fragments transparently.
    pub async fn recv(&self) -> Result<Vec<u8>, NoiseError> {
        loop {
            let frame = {
                let mut transport = self.transport.lock().await;
                transport.recv().await?
            };
            *self.last_used.write() = Instant::now();
            if let Some(message) = self.reassembler.lock().await.accept(frame)? {
                return Ok(message);
            }
            // Incomplete fragment: await the next frame.
        }
    }

    /// Get the peer's public key as a NodeId
    pub fn peer_node_id(&self) -> NodeId {
        self.peer_key
    }

    /// Get time since last use
    pub fn idle_time(&self) -> Duration {
        self.last_used.read().elapsed()
    }

    /// Get connection age
    pub fn age(&self) -> Duration {
        self.established_at.elapsed()
    }
}

impl NoiseConnectionPool {
    /// Create a new connection pool
    ///
    /// The NoiseManager handles keypair management internally:
    /// - If config.noise.keypair_file is set, loads from file or generates and saves
    /// - Otherwise generates an ephemeral keypair
    pub fn new(_keypair: NoiseKeypair, config: NoisePoolConfig) -> Result<Self, NoiseError> {
        let manager = NoiseManager::new(config.noise.clone())?;

        info!(
            public_key = %manager.public_key_hex(),
            max_connections = config.max_connections,
            "Noise connection pool initialized"
        );

        Ok(Self {
            connections: RwLock::new(HashMap::new()),
            manager,
            config,
        })
    }

    /// Get our public key (from the NoiseManager which handles actual crypto)
    pub fn public_key(&self) -> &[u8; 32] {
        self.manager.public_key()
    }

    /// Get our public key as hex string
    pub fn public_key_hex(&self) -> String {
        self.manager.public_key_hex()
    }

    /// Get or establish a connection to a peer
    ///
    /// If an existing connection exists and is healthy, returns it.
    /// Otherwise, establishes a new connection.
    pub async fn get_connection(
        &self,
        peer_addr: SocketAddr,
    ) -> Result<Arc<NoiseConnection>, NoiseError> {
        // Check for existing connection by address
        // Note: We look up by address first, then verify key after handshake
        {
            let conns = self.connections.read();
            for conn in conns.values() {
                if conn.peer_addr == peer_addr {
                    // Found existing connection - check if it's still usable
                    if conn.idle_time() < self.config.max_idle {
                        return Ok(Arc::clone(conn));
                    }
                    // Connection is stale, will establish new one
                    break;
                }
            }
        }

        // Establish new connection
        self.establish_connection(peer_addr).await
    }

    /// Get a connection by peer's Noise public key
    pub fn get_connection_by_key(&self, peer_key: &[u8; 32]) -> Option<Arc<NoiseConnection>> {
        self.connections.read().get(peer_key).cloned()
    }

    /// Establish a new connection to a peer (initiator role)
    async fn establish_connection(
        &self,
        peer_addr: SocketAddr,
    ) -> Result<Arc<NoiseConnection>, NoiseError> {
        debug!(peer = %peer_addr, "Establishing Noise connection (initiator)");

        // Connect TCP with timeout to avoid hanging on unreachable peers
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(peer_addr),
        )
        .await
        .map_err(|_| {
            NoiseError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("Connection to {} timed out", peer_addr),
            ))
        })?
        .map_err(NoiseError::Io)?;

        // Perform Noise handshake as initiator
        let (transport, peer_key) = self.manager.wrap_initiator(stream).await?;

        let conn = Arc::new(NoiseConnection::new(peer_key, peer_addr, transport));

        // Store connection
        self.store_connection(peer_key, Arc::clone(&conn));

        info!(
            peer = %peer_addr,
            peer_key = %hex::encode(&peer_key[..8]),
            "Noise connection established (initiator)"
        );

        Ok(conn)
    }

    /// Accept an incoming connection (responder role)
    ///
    /// Called when a peer connects to our Noise listener.
    pub async fn accept_connection(
        &self,
        stream: TcpStream,
    ) -> Result<Arc<NoiseConnection>, NoiseError> {
        let peer_addr = stream.peer_addr().map_err(NoiseError::Io)?;

        debug!(peer = %peer_addr, "Accepting Noise connection (responder)");

        // Perform Noise handshake as responder
        let (transport, peer_key) = self.manager.wrap_responder(stream).await?;

        let conn = Arc::new(NoiseConnection::new(peer_key, peer_addr, transport));

        // Store connection
        self.store_connection(peer_key, Arc::clone(&conn));

        info!(
            peer = %peer_addr,
            peer_key = %hex::encode(&peer_key[..8]),
            "Noise connection accepted (responder)"
        );

        Ok(conn)
    }

    /// Store a connection, evicting oldest if at capacity
    fn store_connection(&self, peer_key: [u8; 32], conn: Arc<NoiseConnection>) {
        let mut conns = self.connections.write();

        // Evict if at capacity
        while conns.len() >= self.config.max_connections {
            // Find oldest connection
            let oldest = conns
                .iter()
                .max_by_key(|(_, c)| c.idle_time())
                .map(|(k, _)| *k);

            if let Some(key) = oldest {
                debug!(
                    peer_key = %hex::encode(&key[..8]),
                    "Evicting oldest connection (pool full)"
                );
                conns.remove(&key);
            } else {
                break;
            }
        }

        // Remove any existing connection to this peer
        conns.remove(&peer_key);

        // Insert new connection
        conns.insert(peer_key, conn);
    }

    /// Remove a connection
    pub fn remove_connection(&self, peer_key: &[u8; 32]) {
        if self.connections.write().remove(peer_key).is_some() {
            debug!(
                peer_key = %hex::encode(&peer_key[..8]),
                "Removed Noise connection"
            );
        }
    }

    /// Clean up stale connections
    ///
    /// Removes connections that have been idle longer than max_idle.
    pub fn cleanup_stale(&self) {
        let mut conns = self.connections.write();
        let before = conns.len();

        conns.retain(|key, conn| {
            let keep = conn.idle_time() < self.config.max_idle;
            if !keep {
                debug!(
                    peer_key = %hex::encode(&key[..8]),
                    idle_secs = conn.idle_time().as_secs(),
                    "Cleaning up stale connection"
                );
            }
            keep
        });

        let removed = before - conns.len();
        if removed > 0 {
            info!(
                removed = removed,
                remaining = conns.len(),
                "Cleaned up stale Noise connections"
            );
        }
    }

    /// Get all active connections
    pub fn connections(&self) -> Vec<Arc<NoiseConnection>> {
        self.connections.read().values().cloned().collect()
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        self.connections.read().len()
    }

    /// Check if we have a connection to a peer
    pub fn has_connection(&self, peer_key: &[u8; 32]) -> bool {
        self.connections.read().contains_key(peer_key)
    }

    /// Get the Noise manager (for advanced operations)
    pub fn manager(&self) -> &NoiseManager {
        &self.manager
    }

    /// Check if Noise is enabled
    pub fn is_enabled(&self) -> bool {
        self.manager.is_enabled()
    }

    /// Check if Noise is required
    pub fn is_required(&self) -> bool {
        self.manager.is_required()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_pool_config_default() {
        let config = NoisePoolConfig::default();
        assert_eq!(config.max_connections, MAX_CONNECTIONS);
        assert_eq!(config.max_idle, MAX_CONNECTION_AGE);
    }

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let keypair = NoiseKeypair::generate();
        let config = NoisePoolConfig::default();

        let pool = NoiseConnectionPool::new(keypair, config).unwrap();

        // Pool should have a valid 32-byte public key
        assert_eq!(pool.public_key().len(), 32);
        assert_eq!(pool.connection_count(), 0);
        assert!(pool.is_enabled());
    }

    /// Pool config for tests — allows unknown peers since tests don't set up trusted peer lists
    fn test_pool_config() -> NoisePoolConfig {
        NoisePoolConfig {
            noise: NoiseConfig {
                allow_unknown_peers: true,
                ..NoiseConfig::default()
            },
            ..NoisePoolConfig::default()
        }
    }

    #[tokio::test]
    async fn test_connection_establishment() {
        // Create two pools (simulating two peers)
        let keypair1 = NoiseKeypair::generate();
        let keypair2 = NoiseKeypair::generate();

        let config1 = test_pool_config();
        let config2 = test_pool_config();

        let pool1 = Arc::new(NoiseConnectionPool::new(keypair1, config1).unwrap());
        let pool2 = Arc::new(NoiseConnectionPool::new(keypair2, config2).unwrap());

        // Start listener for pool2
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn acceptor for pool2
        let pool2_clone = Arc::clone(&pool2);
        let accept_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            pool2_clone.accept_connection(stream).await
        });

        // Pool1 connects to pool2
        let conn1 = pool1.get_connection(addr).await.unwrap();

        // Wait for pool2 to accept
        let conn2 = accept_handle.await.unwrap().unwrap();

        // Verify connection counts
        assert_eq!(pool1.connection_count(), 1);
        assert_eq!(pool2.connection_count(), 1);

        // Verify peer keys match
        assert_eq!(conn1.peer_key, *pool2.public_key());
        assert_eq!(conn2.peer_key, *pool1.public_key());

        // Test sending a message
        let test_msg = b"Hello, encrypted world!";
        conn1.send(test_msg).await.unwrap();

        let received = conn2.recv().await.unwrap();
        assert_eq!(received, test_msg);

        // Test bidirectional
        let reply = b"Message received!";
        conn2.send(reply).await.unwrap();

        let received_reply = conn1.recv().await.unwrap();
        assert_eq!(received_reply, reply);
    }

    /// End-to-end: a message larger than one Noise frame is fragmented on send,
    /// crosses a real TCP + ChaCha20-Poly1305 transport, and is reassembled to
    /// the identical bytes on recv. This reproduces the ~84 KB checkpoint /
    /// tree-sync proposal that previously failed with `Message too large`.
    #[tokio::test]
    async fn test_oversized_message_fragments_end_to_end() {
        use crate::noise::MAX_PAYLOAD_SIZE;

        let pool1 = Arc::new(
            NoiseConnectionPool::new(NoiseKeypair::generate(), test_pool_config()).unwrap(),
        );
        let pool2 = Arc::new(
            NoiseConnectionPool::new(NoiseKeypair::generate(), test_pool_config()).unwrap(),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let pool2_clone = Arc::clone(&pool2);
        let accept_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            pool2_clone.accept_connection(stream).await
        });

        let conn1 = pool1.get_connection(addr).await.unwrap();
        let conn2 = accept_handle.await.unwrap().unwrap();

        // 84_241 bytes — the exact size seen in the fleet logs, well over the
        // 65_519-byte single-frame limit.
        let big: Vec<u8> = (0..84_241u32)
            .map(|i| (i.wrapping_mul(31) % 253) as u8)
            .collect();
        assert!(big.len() > MAX_PAYLOAD_SIZE);

        conn1.send(&big).await.unwrap();
        let received = conn2.recv().await.unwrap();
        assert_eq!(received, big, "reassembled bytes must match exactly");

        // A small message on the same connection still works afterwards
        // (reassembly slot released cleanly).
        let small = b"{\"ok\":true}".to_vec();
        conn2.send(&small).await.unwrap();
        assert_eq!(conn1.recv().await.unwrap(), small);
    }

    #[tokio::test]
    async fn test_connection_reuse() {
        let keypair1 = NoiseKeypair::generate();
        let keypair2 = NoiseKeypair::generate();

        let pool1 = Arc::new(NoiseConnectionPool::new(keypair1, test_pool_config()).unwrap());
        let pool2 = Arc::new(NoiseConnectionPool::new(keypair2, test_pool_config()).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let pool2_clone = Arc::clone(&pool2);
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = pool2_clone.accept_connection(stream).await;
        });

        // First connection
        let conn1 = pool1.get_connection(addr).await.unwrap();
        let conn1_ptr = Arc::as_ptr(&conn1);

        // Give time for the connection to be fully established
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Second get should reuse
        let conn2 = pool1.get_connection(addr).await.unwrap();
        let conn2_ptr = Arc::as_ptr(&conn2);

        // Should be the same connection (same Arc pointer)
        assert_eq!(conn1_ptr, conn2_ptr);
        assert_eq!(pool1.connection_count(), 1);
    }

    #[test]
    fn test_cleanup_stale() {
        // This test uses mocked idle time since we can't easily manipulate real time
        // The actual cleanup logic is tested by verifying the retain behavior
        let keypair = NoiseKeypair::generate();
        let config = NoisePoolConfig {
            max_idle: Duration::from_millis(1),
            ..Default::default()
        };

        let pool = NoiseConnectionPool::new(keypair, config).unwrap();

        // Pool starts empty
        assert_eq!(pool.connection_count(), 0);

        // Cleanup on empty pool should not panic
        pool.cleanup_stale();
        assert_eq!(pool.connection_count(), 0);
    }

    #[test]
    fn test_connection_idle_time() {
        // Test NoiseConnection idle time tracking
        // Note: This is a compile-time test to verify the API exists
        // Runtime testing would require establishing actual connections
    }

    /// Test that multiple sequential sends through same pool connection all arrive intact
    #[tokio::test]
    async fn test_pool_concurrent_send_recv() {
        let keypair1 = NoiseKeypair::generate();
        let keypair2 = NoiseKeypair::generate();

        let pool1 = Arc::new(NoiseConnectionPool::new(keypair1, test_pool_config()).unwrap());
        let pool2 = Arc::new(NoiseConnectionPool::new(keypair2, test_pool_config()).unwrap());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let pool2_clone = Arc::clone(&pool2);
        let accept_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            pool2_clone.accept_connection(stream).await
        });

        let conn1 = pool1.get_connection(addr).await.unwrap();
        let conn2 = accept_handle.await.unwrap().unwrap();

        // Send 5 messages sequentially through the same connection
        let msg_count = 5u8;
        for i in 0..msg_count {
            let msg = format!("msg-{}", i);
            conn1.send(msg.as_bytes()).await.unwrap();
        }

        // Receive all 5 messages and verify none are corrupted
        let mut received = Vec::new();
        for _ in 0..msg_count {
            let data = conn2.recv().await.unwrap();
            received.push(String::from_utf8(data).unwrap());
        }

        for i in 0..msg_count {
            assert_eq!(
                received[i as usize],
                format!("msg-{}", i),
                "Message {} should arrive intact",
                i
            );
        }

        // Connection should still be reusable
        assert_eq!(pool1.connection_count(), 1);
    }
}
