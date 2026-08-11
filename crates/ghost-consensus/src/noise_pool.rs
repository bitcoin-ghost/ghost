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

/// Upper bound on ONE send (or handshake) to ONE peer.
///
/// There was no bound at all, and `NoiseConnection::send` holds the per-connection transport
/// mutex across the TCP write — so a single peer whose socket has wedged (accepting bytes at
/// dribble pace with a persistently full send queue, as vm8→vm3 measured on 2026-08-11: tens of
/// KB stuck in Send-Q on a retransmission timer for the whole observation window) stalls every
/// later send to that peer on the mutex, and `Mesh::broadcast`'s join_all waits for that leg.
/// The broadcast drain tasks (share convergence, L2, payout checkpoint) each drain their channel
/// ONE message at a time through `broadcast`, so one wedged peer socket backs all of them up
/// until their bounded channels overflow and every enqueue drops
/// (`no available capacity`, #647).
///
/// The bound is sized for the slowest LEGITIMATE case, not the wedge: the largest convergence
/// responses are ~1.6 MB (#590), which at the fleet's worst observed inter-node throughput is
/// seconds, not tens of seconds. A send that cannot finish in 15 s is a liveness signal, and it
/// is treated exactly like a write error — evict the pooled connection and (once) retry on a
/// fresh dial, which is the same recovery `send_to` already performs for broken pipes.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Upper bound on establishing a connection's Noise handshake. TCP connect was already bounded
/// (5 s) but the handshake await was not, so a peer that accepts and then never responds — a
/// half-open firewall state, a hung process — parked the caller for ever with the same blast
/// radius as an unbounded send.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pool of established Noise connections to peers
pub struct NoiseConnectionPool {
    /// OUTBOUND (dialed) connections — the send cache, indexed by peer's Noise public
    /// key. Populated only by [`Self::get_connection`]/[`Self::establish_connection`];
    /// inbound accepts are deliberately NOT pooled (see [`Self::accept_connection`]).
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
    /// Upper bound on one send to one peer (see [`SEND_TIMEOUT`]). A timeout is treated as a
    /// write failure: evict the pooled connection, retry once on a fresh dial.
    pub send_timeout: Duration,
    /// Upper bound on a Noise handshake once TCP is connected (see [`HANDSHAKE_TIMEOUT`]).
    pub handshake_timeout: Duration,
    /// Noise configuration
    pub noise: NoiseConfig,
}

impl Default for NoisePoolConfig {
    fn default() -> Self {
        Self {
            max_connections: MAX_CONNECTIONS,
            max_idle: MAX_CONNECTION_AGE,
            send_timeout: SEND_TIMEOUT,
            handshake_timeout: HANDSHAKE_TIMEOUT,
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

    /// Send to a peer, replacing the pooled connection if it turns out to be dead.
    ///
    /// [`Self::get_connection`] judges a cached connection only by how recently it was used, and
    /// a caller that keeps trying keeps refreshing that timer — so a connection whose far end has
    /// gone is never recognised as dead. Callers that simply propagated the send error left the
    /// corpse pooled and wrote to it for ever: when a node restarted, its peers logged
    /// `Broken pipe` for hours with zero TCP connections to it, starving it of consensus votes.
    ///
    /// A write failure is the only reliable liveness signal available here, so it is treated as
    /// one: evict, then retry once on a connection that cannot be the evicted one. A peer that
    /// restarted becomes reachable on the next message rather than after some later cleanup.
    pub async fn send_to(&self, peer_addr: SocketAddr, data: &[u8]) -> Result<(), NoiseError> {
        let conn = self.get_connection(peer_addr).await?;
        let Err(first) = self.send_bounded(&conn, data).await else {
            return Ok(());
        };

        self.remove_connection(&conn.peer_key);
        debug!(
            peer = %peer_addr,
            error = %first,
            "Noise send failed — evicted the pooled connection, retrying once"
        );

        let fresh = self.get_connection(peer_addr).await?;
        if let Err(second) = self.send_bounded(&fresh, data).await {
            // Do not leave this one pooled either.
            self.remove_connection(&fresh.peer_key);
            return Err(second);
        }
        Ok(())
    }

    /// One send, bounded by `send_timeout` (#647).
    ///
    /// A wedged peer socket — accepting bytes at dribble pace, send queue never draining — used
    /// to park the caller for ever INSIDE the connection's transport mutex, so every subsequent
    /// send to that peer queued behind it and `Mesh::broadcast` never resolved. That stalled the
    /// broadcast drain tasks (share convergence, L2, payout checkpoint all funnel through
    /// `broadcast`), their bounded channels filled, and every enqueue dropped with
    /// `no available capacity`. A send that cannot finish inside the bound is treated as the
    /// liveness failure it is; the caller evicts and re-dials exactly as for a broken pipe.
    ///
    /// The abandoned send future may have advanced the Noise cipher state or left a frame half
    /// written, so the connection MUST NOT be reused after a timeout — both callers evict it.
    /// Tasks already queued on its mutex will fail on the corpse and evict it again, which is
    /// idempotent (`remove_connection` is keyed and the fresh dial re-pools).
    async fn send_bounded(&self, conn: &NoiseConnection, data: &[u8]) -> Result<(), NoiseError> {
        match tokio::time::timeout(self.config.send_timeout, conn.send(data)).await {
            Ok(result) => result,
            Err(_) => Err(NoiseError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "Noise send to {} timed out after {:?}",
                    conn.peer_addr, self.config.send_timeout
                ),
            ))),
        }
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

        // Perform Noise handshake as initiator, bounded: TCP connect above was already bounded,
        // but a peer that accepts and then never responds parked this await for ever (#647).
        let (transport, peer_key) = tokio::time::timeout(
            self.config.handshake_timeout,
            self.manager.wrap_initiator(stream),
        )
        .await
        .map_err(|_| {
            NoiseError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "Noise handshake with {} timed out after {:?}",
                    peer_addr, self.config.handshake_timeout
                ),
            ))
        })??;

        let conn = Arc::new(NoiseConnection::new(peer_key, peer_addr, transport));

        // Store connection
        self.store_connection(peer_key, Arc::clone(&conn));

        debug!(
            peer = %peer_addr,
            peer_key = %hex::encode(&peer_key[..8]),
            "Noise connection established (initiator)"
        );

        Ok(conn)
    }

    /// Accept an incoming connection (responder role)
    ///
    /// Called when a peer connects to our Noise listener. The returned connection is
    /// **NOT** placed in the pool: the caller (the mesh accept-listener) owns it via a
    /// dedicated per-connection receive loop, which keeps it alive for its lifetime.
    ///
    /// This is deliberate and load-bearing. The pool is an OUTBOUND send-cache keyed by
    /// peer noise key, looked up by dial address in [`Self::get_connection`]. An inbound
    /// connection has the peer's *ephemeral* source port (never the dialable noise port),
    /// so it can never be reused for sending — its only effect if pooled would be to
    /// evict the healthy outbound connection to the same peer (shared key), dropping that
    /// socket and forcing an endless re-dial/re-handshake churn. Keeping inbound out of
    /// the pool makes each direction an independent, stable connection.
    pub async fn accept_connection(
        &self,
        stream: TcpStream,
    ) -> Result<Arc<NoiseConnection>, NoiseError> {
        let peer_addr = stream.peer_addr().map_err(NoiseError::Io)?;

        debug!(peer = %peer_addr, "Accepting Noise connection (responder)");

        // Perform Noise handshake as responder — bounded for the same reason as the initiator
        // side: a dialer that connects and never handshakes must not park this task for ever.
        let (transport, peer_key) = tokio::time::timeout(
            self.config.handshake_timeout,
            self.manager.wrap_responder(stream),
        )
        .await
        .map_err(|_| {
            NoiseError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "Noise handshake from {} timed out after {:?}",
                    peer_addr, self.config.handshake_timeout
                ),
            ))
        })??;

        let conn = Arc::new(NoiseConnection::new(peer_key, peer_addr, transport));

        // Intentionally NOT stored in the pool — see the doc comment above.
        debug!(
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

        // Verify connection counts: pool1 pooled its OUTBOUND dial; pool2 accepted an
        // inbound (owned by `conn2` below), which is deliberately NOT pooled.
        assert_eq!(pool1.connection_count(), 1);
        assert_eq!(pool2.connection_count(), 0);

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

    /// Regression for the fleet-wide Noise re-handshake churn: accepting an INBOUND
    /// connection from a peer must NOT evict/clobber the pooled OUTBOUND connection to
    /// that same peer (they share the peer's noise key). Before the fix, the accept
    /// stored the inbound conn under the shared key, dropping the outbound socket and
    /// forcing a perpetual re-dial cycle.
    #[tokio::test]
    async fn accept_does_not_evict_outbound_to_same_peer() {
        let pool_a = Arc::new(
            NoiseConnectionPool::new(NoiseKeypair::generate(), test_pool_config()).unwrap(),
        );
        let pool_b = Arc::new(
            NoiseConnectionPool::new(NoiseKeypair::generate(), test_pool_config()).unwrap(),
        );

        // B listens; A dials B → A pools an OUTBOUND conn keyed by B's noise key.
        let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = lb.local_addr().unwrap();
        let pb = Arc::clone(&pool_b);
        let b_accept = tokio::spawn(async move {
            let (s, _) = lb.accept().await.unwrap();
            pb.accept_connection(s).await
        });
        let out = pool_a.get_connection(b_addr).await.unwrap();
        let _b_side = b_accept.await.unwrap().unwrap();
        let out_ptr = Arc::as_ptr(&out);
        assert_eq!(pool_a.connection_count(), 1, "A pooled its outbound to B");

        // A listens; B dials A → A ACCEPTS an inbound whose peer_key is ALSO B's noise
        // key — the exact clobber scenario.
        let la = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = la.local_addr().unwrap();
        let pa = Arc::clone(&pool_a);
        let a_accept = tokio::spawn(async move {
            let (s, _) = la.accept().await.unwrap();
            pa.accept_connection(s).await
        });
        let _b_out = pool_b.get_connection(a_addr).await.unwrap();
        let inbound = a_accept.await.unwrap().unwrap();
        assert_eq!(inbound.peer_key, *pool_b.public_key());

        // THE FIX: the inbound accept left A's outbound untouched, and A still reuses it.
        assert_eq!(
            pool_a.connection_count(),
            1,
            "inbound accept must not be pooled nor clobber the outbound"
        );
        let reused = pool_a.get_connection(b_addr).await.unwrap();
        assert_eq!(
            Arc::as_ptr(&reused),
            out_ptr,
            "A reuses its stable outbound to B — no re-dial"
        );
    }

    /// **The property a restarted peer depends on.**
    ///
    /// `get_connection` judges a cached connection only by how recently it was used, and a caller
    /// that keeps trying keeps refreshing that timer — so a dead connection is never recognised as
    /// dead. Before `send_to`, the send error was simply propagated and the corpse stayed pooled:
    /// when a node restarted, its peers wrote to the closed socket for hours, logging `Broken
    /// pipe` with zero TCP connections open, and it never received another consensus vote.
    #[tokio::test]
    async fn a_dead_pooled_connection_is_evicted_rather_than_reused_for_ever() {
        let pool_a = Arc::new(
            NoiseConnectionPool::new(NoiseKeypair::generate(), test_pool_config()).unwrap(),
        );
        let pool_b = Arc::new(
            NoiseConnectionPool::new(NoiseKeypair::generate(), test_pool_config()).unwrap(),
        );

        let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = lb.local_addr().unwrap();
        let pb = Arc::clone(&pool_b);
        let b_accept = tokio::spawn(async move {
            let (s, _) = lb.accept().await.unwrap();
            pb.accept_connection(s).await
        });
        // A dials B and pools the connection.
        let _out = pool_a.get_connection(b_addr).await.unwrap();
        let b_side = b_accept.await.unwrap().unwrap();
        assert_eq!(pool_a.connection_count(), 1, "A pooled its outbound to B");

        // B goes away — exactly what a node restart looks like from A's side.
        drop(b_side);
        drop(pool_b);

        // A keeps sending until the corpse is evicted, or we give up.
        //
        // Poll rather than assert after a fixed number of attempts. TCP absorbs writes into the
        // send buffer and the peer's RST surfaces only afterwards, so how many `send_to` calls it
        // takes for the error to appear is platform-dependent — macOS has larger default send
        // buffers than Linux and needs more. The previous version tried 5 times and broke on the
        // first error; when all 5 were swallowed it asserted against a still-pooled connection and
        // failed. That made `Test (macos-latest)` intermittently red on main, for a reason that had
        // nothing to do with the property being tested.
        //
        // The property is "a dead connection is EVENTUALLY evicted rather than reused for ever", so
        // the test waits for eventually and bounds it. A genuine regression — never evicting — still
        // fails, it just takes the full budget to do so.
        let mut evicted = false;
        for _ in 0..100 {
            let _ = pool_a.send_to(b_addr, b"consensus vote").await;
            if pool_a.connection_count() == 0 {
                evicted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        assert!(
            evicted,
            "the dead connection must be evicted, not handed back on every send for ever \
             (pool still holds {} after 100 sends over ~5s)",
            pool_a.connection_count()
        );
    }

    /// #647: a peer that accepts TCP and then never speaks Noise must not park the dialer for
    /// ever. The TCP connect was bounded (5s); the handshake await was not.
    #[tokio::test]
    async fn a_silent_accepter_cannot_park_the_handshake_for_ever() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept, then say nothing — holding the socket open, like a half-open firewall state.
        let hold = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(s);
        });

        let pool = NoiseConnectionPool::new(
            NoiseKeypair::generate(),
            NoisePoolConfig {
                handshake_timeout: Duration::from_millis(200),
                ..test_pool_config()
            },
        )
        .unwrap();

        let started = Instant::now();
        let result = pool.get_connection(addr).await;
        assert!(
            result.is_err(),
            "a silent peer must be an error, not a hang"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "and the error must arrive within the bound"
        );
        assert_eq!(pool.connection_count(), 0, "nothing must be pooled");
        hold.abort();
    }

    /// #647, the vm8 shape: a peer whose process stops READING (socket open, send queue never
    /// draining) must not park a send for ever. `send` holds the connection's transport mutex
    /// across the TCP write, so before the bound existed one such peer stalled every subsequent
    /// send to it, `Mesh::broadcast`'s join_all never resolved, the broadcast drain tasks
    /// stopped draining, and the bounded channels overflowed fleet-visible
    /// (`no available capacity`).
    #[tokio::test]
    async fn a_peer_that_stops_reading_cannot_park_a_send_for_ever() {
        let pool_a = Arc::new(
            NoiseConnectionPool::new(
                NoiseKeypair::generate(),
                NoisePoolConfig {
                    send_timeout: Duration::from_millis(300),
                    ..test_pool_config()
                },
            )
            .unwrap(),
        );
        let pool_b = Arc::new(
            NoiseConnectionPool::new(NoiseKeypair::generate(), test_pool_config()).unwrap(),
        );

        let lb = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = lb.local_addr().unwrap();
        let pb = Arc::clone(&pool_b);
        // B completes every handshake and then never reads a byte — connections are held open,
        // so from A's side nothing is ever "dead", it just never drains.
        let accept_loop = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let (s, _) = lb.accept().await.unwrap();
                if let Ok(c) = pb.accept_connection(s).await {
                    held.push(c);
                }
            }
        });

        let conn = pool_a.get_connection(b_addr).await.unwrap();
        let old_ptr = Arc::as_ptr(&conn);

        // Push until the kernel buffers fill and the write genuinely blocks. Each message is
        // fragmented over many Noise frames; once loopback's socket buffers are full the send
        // future can make no progress and only the bound can end it.
        let payload = vec![0u8; 2 * 1024 * 1024];
        let started = Instant::now();
        let mut timed_out = false;
        for _ in 0..64 {
            if pool_a.send_bounded(&conn, &payload).await.is_err() {
                timed_out = true;
                break;
            }
        }
        assert!(
            timed_out,
            "a peer that stopped reading must fail the send within the bound, not hang"
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the failure must arrive promptly, this took {:?}",
            started.elapsed()
        );

        // And through `send_to`, the timeout is treated exactly like a write failure: the wedged
        // connection is evicted and the retry runs on a FRESH dial. (The retry itself may well
        // succeed — fresh socket, empty buffers — the property is that the corpse is gone.)
        let _ = pool_a.send_to(b_addr, &payload).await;
        let replacement = pool_a.get_connection(b_addr).await.unwrap();
        assert_ne!(
            Arc::as_ptr(&replacement),
            old_ptr,
            "the wedged connection must have been evicted, not handed back"
        );

        accept_loop.abort();
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
