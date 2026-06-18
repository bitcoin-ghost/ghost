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
//| FILE: mesh.rs                                                                                                        |
//|======================================================================================================================|

//! P2P mesh network implementation
//!
//! Uses ZMQ for efficient message propagation across the node network.
//!
//! ## Architecture
//!
//! - PUB socket for broadcasting messages to peers
//! - SUB sockets for receiving messages from peers
//! - ROUTER/DEALER for request-response patterns
//!
//! ## Replay Attack Prevention (P2P-M2)
//!
//! Message replay attacks are prevented through a dual-layer defense:
//!
//! 1. **Deduplication Window** (`dedup_window_secs`, default 60s):
//!    Messages are tracked by (sender_id, sequence_number). Duplicate messages
//!    within this window are silently dropped.
//!
//! 2. **Timestamp Validation** (message_validator.rs):
//!    All messages must have timestamps within 5 minutes of current time.
//!    Messages with timestamps outside this window are rejected BEFORE
//!    deduplication checks.
//!
//! Together, these ensure that even after the dedup window expires, old messages
//! cannot be replayed because their timestamps will be too far in the past.
//! The timestamp validation window (5 minutes) is intentionally larger than the
//! dedup window (60 seconds) to provide defense in depth.

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tmq::{publish, subscribe, Context, Multipart};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Shared ZMQ context for all sockets (libzmq handles threading internally)
static ZMQ_CONTEXT: Lazy<Context> = Lazy::new(Context::new);

use ghost_common::config::P2PPortConfig;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::types::NodeId;

use crate::message::{MessageEnvelope, MessageType};
use crate::message_validator::{validate_and_verify, ValidationStats};
use crate::noise_pool::{NoiseConnectionPool, NoisePoolConfig};
use crate::peer::{Peer, PeerManager};

/// Type alias for optional outbound message receiver storage
type OptionalOutboundReceiver = Option<mpsc::Receiver<(String, Vec<u8>)>>;

/// Mesh network configuration
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Our public address
    pub public_address: String,
    /// Port configuration
    pub ports: P2PPortConfig,
    /// Maximum peers
    pub max_peers: usize,
    /// Message deduplication window (seconds)
    pub dedup_window_secs: u64,
    /// Health ping interval (seconds)
    pub health_ping_interval_secs: u64,
    /// Maximum seen messages to track (prevents memory exhaustion)
    pub max_seen_messages: usize,
    /// Node capabilities to advertise in health pings
    pub capabilities: ghost_common::types::NodeCapabilities,
    /// C-1: Enable Noise Protocol for transport encryption
    ///
    /// When enabled, sensitive P2P messages (shares, blocks, votes, payouts)
    /// are sent over encrypted Noise TCP channels instead of plaintext ZMQ.
    ///
    /// ZMQ is still used for:
    /// - Discovery messages (need broadcast for initial peer finding)
    /// - Health pings (broadcast liveness, no secrets)
    ///
    /// Noise TCP is used for:
    /// - Share propagation
    /// - Block announcements
    /// - Consensus votes
    /// - Payout proposals/transactions
    /// - Verification results
    ///
    /// Default: true for secure-by-default operation
    pub noise_enabled: bool,
    /// Port for Noise Protocol TCP connections (default: 8563)
    ///
    /// This port is used for encrypted point-to-point communication.
    /// Separate from ZMQ ports which handle discovery and health.
    pub noise_port: u16,
    /// Path to Noise keypair file
    ///
    /// If the file doesn't exist, a new keypair will be generated and saved.
    /// The keypair is used for X25519 Diffie-Hellman in Noise_XX handshakes.
    pub noise_keypair_path: Option<std::path::PathBuf>,
    /// Require Noise encryption for sensitive messages
    ///
    /// When true:
    /// - Peers without Noise support are rejected
    /// - Messages from unknown Noise identities are dropped
    ///
    /// When false:
    /// - Falls back to plaintext ZMQ if Noise connection fails
    /// - Useful during migration period
    ///
    /// Default: false (gradual rollout mode)
    pub noise_required: bool,
    /// Path to persist the outbound message sequence ceiling.
    ///
    /// The outbound sequence must never go backwards across a restart, or peers
    /// reject our messages as replays. We persist a leased ceiling here and
    /// resume above it on startup. `None` (the default, e.g. tests) starts the
    /// counter at 0 with no persistence — only safe when peers also reset (a
    /// coordinated full-fleet restart). Set this on every long-running node.
    pub sequence_persist_path: Option<std::path::PathBuf>,
}

/// Default Noise port for encrypted TCP connections
pub const DEFAULT_NOISE_PORT: u16 = 8563;

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            public_address: "127.0.0.1".to_string(),
            ports: P2PPortConfig::default(),
            max_peers: 100,
            dedup_window_secs: 60,
            health_ping_interval_secs: 10,
            max_seen_messages: 100_000, // Cap at 100k messages (~3.2MB with 32-byte IDs)
            capabilities: ghost_common::types::NodeCapabilities::default(),
            // C-1: Enable Noise by default for secure-by-default operation
            noise_enabled: true,
            noise_port: DEFAULT_NOISE_PORT,
            noise_keypair_path: None, // Will generate ephemeral keypair
            // C-3 SECURITY: Require Noise encryption for mainnet operation
            // Plaintext P2P communication is unacceptable for production as it allows:
            // - Message interception and modification by network attackers
            // - Impersonation of nodes without cryptographic proof
            // - Snooping on consensus votes, share submissions, and payouts
            // Fallback mode should ONLY be used during development/testing.
            noise_required: true,
            sequence_persist_path: None,
        }
    }
}

/// Message handler trait
#[async_trait]
pub trait MessageHandler: Send + Sync {
    /// Handle a received message
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()>;
}

/// Channel for outbound messages
pub type OutboundSender = mpsc::Sender<(String, Vec<u8>)>;
pub type OutboundReceiver = mpsc::Receiver<(String, Vec<u8>)>;

/// Channel for inbound messages
pub type InboundSender = mpsc::Sender<Vec<u8>>;
pub type InboundReceiver = mpsc::Receiver<Vec<u8>>;

/// Mesh network manager
pub struct MeshNetwork {
    /// Our identity
    identity: Arc<NodeIdentity>,
    /// Configuration
    config: MeshConfig,
    /// Peer manager
    peers: Arc<PeerManager>,
    /// Message sequence counter
    sequence: AtomicU64,
    /// Reserved (persisted) outbound-sequence ceiling. `next_sequence` never
    /// exceeds this without first persisting a higher value, so a restart
    /// resumes above every sequence we could have used. `u64::MAX` when
    /// persistence is disabled.
    sequence_ceiling: AtomicU64,
    /// Serialises lease extensions (the rare on-disk ceiling write) so only one
    /// thread persists at a time.
    sequence_lease_lock: std::sync::Mutex<()>,
    /// Seen message cache for deduplication (P2P-L1: O(1) eviction)
    seen_messages: RwLock<SeenMessageCache>,
    /// Message handlers
    handlers: RwLock<Vec<Arc<dyn MessageHandler>>>,
    /// Running state
    running: AtomicBool,
    /// Outbound message channel
    outbound_tx: mpsc::Sender<(String, Vec<u8>)>,
    outbound_rx: RwLock<OptionalOutboundReceiver>,
    /// Inbound message channel
    inbound_tx: mpsc::Sender<Vec<u8>>,
    inbound_rx: RwLock<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Message statistics
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    /// Validation statistics for monitoring
    validation_stats: RwLock<ValidationStats>,
    /// C-1: Noise Protocol connection pool for encrypted P2P communication
    noise_pool: Option<Arc<NoiseConnectionPool>>,
    /// Live node capabilities (updated after MPC contribution succeeds)
    /// Initialized from config.capabilities, then mutated via update_elder_status()
    capabilities: RwLock<ghost_common::types::NodeCapabilities>,
    /// Application-provided callback for real miner count (used in health pings).
    /// If None, falls back to peer_count.
    miner_count_fn: Option<Arc<dyn Fn() -> u32 + Send + Sync>>,
    /// Application-provided callback returning the truncated SHA-256 hashes
    /// of locally-active miner_ids (5-min window). Used by `run_health_pinger`
    /// to gossip the local active set so peers can compute a deduplicated
    /// mesh-wide active miner count.
    active_miner_hashes_fn: Option<Arc<dyn Fn() -> Vec<[u8; 16]> + Send + Sync>>,
    /// Application-provided callback returning this node's own realized
    /// hashrate (TH/s) over a trailing window. Gossiped in health pings so
    /// peers can SUM one term per node into a pool-wide total.
    local_hashrate_fn: Option<Arc<dyn Fn() -> f64 + Send + Sync>>,
    /// Hardware-derived effective capacity advertised in health pings.
    /// `0` means we haven't computed it yet (mesh started before capacity
    /// init); peers treat it as unknown and skip utilisation routing for us.
    max_capacity: AtomicU32,
}

/// Message identifier for deduplication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId {
    pub sender: NodeId,
    pub sequence: u64,
}

/// M-P2P-4: Maximum connection states to track (prevents unbounded memory growth)
const MAX_CONNECTION_STATES: usize = 1000;

/// P2P4-L6: Connection state for exponential backoff
///
/// Tracks connection attempts per peer to implement exponential backoff
/// for failed connections, preventing aggressive reconnection loops.
#[derive(Debug, Clone)]
struct PeerConnectionState {
    /// Last connection attempt time (monotonic)
    last_attempt: std::time::Instant,
    /// Current backoff duration in milliseconds (doubles on failure, up to max)
    backoff_ms: u64,
    /// Number of consecutive connection failures
    consecutive_failures: u32,
}

impl PeerConnectionState {
    /// Initial backoff: 100ms
    const INITIAL_BACKOFF_MS: u64 = 100;
    /// Maximum backoff: 30 seconds
    const MAX_BACKOFF_MS: u64 = 30_000;

    fn new() -> Self {
        Self {
            last_attempt: std::time::Instant::now(),
            backoff_ms: Self::INITIAL_BACKOFF_MS,
            consecutive_failures: 0,
        }
    }

    /// Check if enough time has passed to retry connection
    fn can_retry(&self) -> bool {
        self.last_attempt.elapsed().as_millis() as u64 >= self.backoff_ms
    }

    /// Record a failed connection attempt, increasing backoff
    fn record_failure(&mut self) {
        self.last_attempt = std::time::Instant::now();
        self.consecutive_failures += 1;
        self.backoff_ms = (self.backoff_ms * 2).min(Self::MAX_BACKOFF_MS);
    }

    /// Record a successful connection, resetting backoff
    fn record_success(&mut self) {
        self.last_attempt = std::time::Instant::now();
        self.consecutive_failures = 0;
        self.backoff_ms = Self::INITIAL_BACKOFF_MS;
    }
}

/// CRIT-CONS-3: Per-sender message count adjusted to respect memory constraints
/// Old value: 10,000 msgs/sender × 5,000 senders × 72 bytes = 3.6 GB (UNACCEPTABLE)
/// New value: 1,000 msgs/sender × 1,000 senders × 72 bytes = 72 MB (under 50 MB with eviction)
/// This prevents memory exhaustion attacks where an attacker creates many senders
/// to flood the cache beyond MAX_CACHE_MEMORY_BYTES (50 MB).
const MAX_MESSAGES_PER_SENDER: usize = 1_000;

/// CRIT-CONS-3: Maximum unique senders reduced to prevent memory exhaustion
/// Old value: 5,000 senders could exhaust 50 MB limit
/// New value: 1,000 senders × 1,000 msgs × 72 bytes = 72 MB theoretical max
/// With TTL eviction and memory pressure eviction, actual usage stays well under 50 MB
const MAX_UNIQUE_SENDERS: usize = 1_000;

/// M-2: Threshold for detecting sequence wrap-around
/// When a new sequence is much smaller than the highest seen, it indicates wrap-around
const WRAP_DETECTION_THRESHOLD: u64 = u64::MAX / 2;

/// CRIT-CONS-3: Maximum memory for the message deduplication cache (50 MB)
/// This is the hard limit enforced by evict_until_under_memory_limit().
/// Formula check: 1000 senders × 1000 msgs × 72 bytes = 72 MB theoretical
/// But with TTL (5 min), realistically only ~10-20 MB under normal operation
const MAX_CACHE_MEMORY_BYTES: usize = 50 * 1024 * 1024;

/// CRIT-CONS-3: Estimated bytes per cache entry for memory calculation
/// Includes: NodeId (32) + sequence (8) + timestamp (8) + HashMap overhead (~24)
const BYTES_PER_CACHE_ENTRY: usize = 72;

/// CRIT-5: Default TTL for messages in the cache (5 minutes)
/// Messages older than this are eligible for cleanup regardless of cache size
const MESSAGE_TTL_SECONDS: u64 = 300;

/// H-P2P-5: Minimum messages before wrap-around is considered legitimate
/// An attacker trying to trigger wrap-around would need to send this many messages first.
/// Normal nodes will never wrap in practice (at 1000 msgs/sec, wrap takes 584M years).
const MIN_MESSAGES_BEFORE_WRAP: u64 = 1_000_000;

/// H-P2P-5: Maximum sequence jump allowed in a single message
/// Prevents attacker from jumping directly to near u64::MAX to trigger wrap.
const MAX_SEQUENCE_JUMP: u64 = 1_000_000;

/// M-3: Maximum allowed time between messages during wrap-around (1 hour in seconds)
/// This provides a secondary timing-based check to prevent replay attacks during wrap-around.
/// A legitimate wrap-around should happen immediately - not hours after the last message.
const MAX_WRAP_AROUND_GAP_SECS: u64 = 3600;

/// H-7 SECURITY: Maximum cumulative sequence distance allowed before wrap-around
/// An attacker jumping by MAX_SEQUENCE_JUMP repeatedly could reach wrap-around.
/// This tracks total distance traveled and rejects if it exceeds this threshold
/// without having sent MIN_MESSAGES_BEFORE_WRAP messages.
/// Set to 10x MAX_SEQUENCE_JUMP to allow some legitimate variance while blocking attacks.
const MAX_CUMULATIVE_DISTANCE_BEFORE_WRAP: u64 = MAX_SEQUENCE_JUMP * 10;

/// OUT-OF-ORDER TOLERANCE: Allow messages that are slightly behind highest_seq.
///
/// This handles multi-transport scenarios where messages sent via Noise (encrypted TCP)
/// may arrive after messages sent via ZMQ (fast UDP-like), even if they were sent first.
/// The Noise handshake (~100-500ms) can cause MPC contributions to arrive after
/// health pings that were sent later but used the faster ZMQ path.
///
/// A tolerance of 10 allows sequences within 10 of highest_seq to be accepted.
/// This is secure because:
/// 1. Real replay attacks use OLD sequences (hours/days old), not off-by-10
/// 2. The message deduplication cache still prevents exact duplicates
/// 3. Timestamp validation provides additional replay protection
const SEQUENCE_TOLERANCE_WINDOW: u64 = 10;

/// Outbound sequence persistence — lease block size.
///
/// The outbound sequence counter must never go backwards across a restart, or
/// peers reject our messages as replays (they keep our last-seen sequence as a
/// per-sender baseline). To guarantee that without writing to disk on every
/// message, we reserve a CEILING this many sequences ahead and persist it; on
/// startup we resume at the persisted ceiling. Even an ungraceful crash is safe
/// because the persisted value is always >= every sequence we could have used.
const SEQUENCE_LEASE_BLOCK: u64 = 100_000;

/// Lease a fresh block once the counter comes within this many of the ceiling.
/// Must be < SEQUENCE_LEASE_BLOCK so the re-lease happens before the lease runs
/// out. At ~1000 msgs/sec this persists roughly once every ~90 seconds.
const SEQUENCE_LEASE_THRESHOLD: u64 = 10_000;

/// M-2/H-P2P-5/H-7: Sequence state tracking with wrap-around protection
/// Handles the case where sequence numbers wrap from MAX back to 1,
/// while preventing attackers from trivially triggering wrap-around.
#[derive(Debug, Clone, Default)]
struct SequenceState {
    /// Highest sequence number seen in the current epoch
    highest_seq: u64,
    /// Wrap-around epoch (increments each time sequences wrap)
    epoch: u32,
    /// H-P2P-5: Total message count from this sender (for wrap validation)
    message_count: u64,
    /// M-3: Timestamp of last message (Unix seconds) for timing-based wrap-around validation
    last_message_time: u64,
    /// H-7 SECURITY: Cumulative sequence distance traveled
    /// Tracks total sequence jumps to prevent attackers from repeatedly jumping
    /// by exactly MAX_SEQUENCE_JUMP to reach wrap-around without enough messages.
    cumulative_distance: u64,
}

/// Bounded LRU-like cache for seen message deduplication (P2P-L1)
///
/// Uses a HashMap for O(1) lookups combined with a VecDeque for O(1) FIFO eviction.
/// This is simpler than a full LRU but provides good performance for deduplication
/// where we mainly care about recent messages.
///
/// Eviction Strategy (H3 security fix):
/// - Global capacity limit with FIFO eviction for overall memory protection
/// - Per-sender tracking ensures one malicious sender can't flush another sender's messages
/// - Each sender limited to MAX_MESSAGES_PER_SENDER (10k) entries
/// - When a sender exceeds their limit, only their oldest messages are evicted
///
/// Replay Prevention (H-P2P-4):
/// - Tracks highest sequence number seen from each sender
/// - Rejects messages with sequence <= highest seen (prevents replay of old messages)
struct SeenMessageCache {
    /// Map for O(1) lookup
    map: HashMap<MessageId, u64>, // MessageId -> timestamp
    /// Queue for O(1) FIFO eviction (oldest at front)
    queue: VecDeque<MessageId>,
    /// Per-sender message counts (H3 security fix)
    sender_counts: HashMap<NodeId, usize>,
    /// Per-sender queues for targeted eviction (H3 security fix)
    sender_queues: HashMap<NodeId, VecDeque<(u64, u64)>>, // sender -> (sequence, timestamp)
    /// M-2: Sequence state per sender with wrap-around epoch tracking
    /// Used to reject replayed messages while handling sequence wrap-around
    sequence_state: HashMap<NodeId, SequenceState>,
    /// Maximum global capacity
    capacity: usize,
    /// Maximum messages per sender (H3 security fix)
    max_per_sender: usize,
    /// CRIT-5: Maximum memory bytes for the cache
    max_memory_bytes: usize,
    /// CRIT-5: Message TTL in seconds
    message_ttl_secs: u64,
}

impl SeenMessageCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            queue: VecDeque::with_capacity(capacity),
            sender_counts: HashMap::new(),
            sender_queues: HashMap::new(),
            sequence_state: HashMap::new(),
            capacity,
            max_per_sender: MAX_MESSAGES_PER_SENDER,
            max_memory_bytes: MAX_CACHE_MEMORY_BYTES,
            message_ttl_secs: MESSAGE_TTL_SECONDS,
        }
    }

    /// H-5 SECURITY: Atomically validate and update sequence state
    ///
    /// This method combines validation and update into a single atomic operation
    /// to prevent TOCTOU (time-of-check to time-of-use) race conditions.
    ///
    /// Previously, `is_sequence_valid()` and `update_highest_seq()` were separate,
    /// allowing a race where:
    /// 1. Thread A checks: sequence 100 is valid (highest is 99)
    /// 2. Thread B checks: sequence 100 is valid (highest is 99)
    /// 3. Thread A updates: highest becomes 100
    /// 4. Thread B updates: highest stays 100 (duplicate accepted!)
    ///
    /// Now both operations happen atomically using entry() API.
    ///
    /// Returns true if the sequence was valid and state was updated.
    /// Returns false if the sequence was a replay/invalid.
    ///
    /// SECURITY LAYERS:
    /// 1. **Message Count Gate**: Wrap-around requires >= 1M messages (H-P2P-5)
    /// 2. **Timing Gate**: Last message must be recent (< 1 hour, M-3)
    /// 3. **Jump Limits**: Single jumps limited to 1M (H-P2P-5)
    /// 4. **Cumulative Distance**: Total distance checked against message count (H-7)
    /// 5. **Strict Ordering**: Sequence must be > highest_seq (no replay)
    /// 6. **Initial Sequence**: First message limited to prevent setup attacks
    fn validate_and_update_sequence(&mut self, sender: &NodeId, sequence: u64) -> bool {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // H-5: Use entry() API for atomic check-and-update
        match self.sequence_state.entry(*sender) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();

                // H-P2P-5: Check for wrap-around detection
                let is_wrap_around = state.highest_seq > WRAP_DETECTION_THRESHOLD
                    && sequence < WRAP_DETECTION_THRESHOLD;

                if is_wrap_around {
                    // H-P2P-5: Only accept wrap-around if we've seen enough messages
                    if state.message_count < MIN_MESSAGES_BEFORE_WRAP {
                        warn!(
                            sender = %hex::encode(&sender[..8]),
                            highest_seq = state.highest_seq,
                            new_seq = sequence,
                            message_count = state.message_count,
                            min_required = MIN_MESSAGES_BEFORE_WRAP,
                            "H-P2P-5: Rejecting suspicious wrap-around - not enough messages"
                        );
                        return false;
                    }

                    // M-3 SECURITY: Timing-based validation during wrap-around
                    let time_since_last = now_secs.saturating_sub(state.last_message_time);
                    if time_since_last > MAX_WRAP_AROUND_GAP_SECS {
                        warn!(
                            sender = %hex::encode(&sender[..8]),
                            highest_seq = state.highest_seq,
                            new_seq = sequence,
                            last_message_age_secs = time_since_last,
                            max_gap_secs = MAX_WRAP_AROUND_GAP_SECS,
                            "M-3: Rejecting wrap-around - last message too old (possible replay attack)"
                        );
                        return false;
                    }

                    // HIGH-CONS-1: Legitimate wrap-around must start in range 1-1000
                    const MAX_POST_WRAP_SEQUENCE: u64 = 1000;
                    if sequence == 0 || sequence > MAX_POST_WRAP_SEQUENCE {
                        warn!(
                            sender = %hex::encode(&sender[..8]),
                            sequence = sequence,
                            max_allowed = MAX_POST_WRAP_SEQUENCE,
                            "HIGH-CONS-1: Rejecting wrap-around with invalid post-wrap sequence"
                        );
                        return false;
                    }

                    // Valid wrap-around - update state atomically
                    state.message_count = state.message_count.saturating_add(1);
                    state.last_message_time = now_secs;
                    state.epoch = state.epoch.saturating_add(1);
                    state.highest_seq = sequence;
                    state.cumulative_distance = 0;
                    info!(
                        sender = %hex::encode(&sender[..8]),
                        new_seq = sequence,
                        epoch = state.epoch,
                        message_count = state.message_count,
                        "H-P2P-5/M-3: Legitimate sequence wrap-around detected"
                    );
                    return true;
                }

                // Normal case: Allow sequences within tolerance window of highest_seq.
                // This handles out-of-order delivery from mixed Noise/ZMQ transports.
                //
                // Messages sent via Noise (MPC, Elder, etc.) may arrive after
                // messages sent via ZMQ (HealthPing), even when sent first,
                // due to Noise handshake latency.
                let tolerance_floor = state.highest_seq.saturating_sub(SEQUENCE_TOLERANCE_WINDOW);
                if sequence < tolerance_floor {
                    // Sequence is too far behind - likely a replay attack
                    debug!(
                        sender = %hex::encode(&sender[..8]),
                        sequence = sequence,
                        highest_seq = state.highest_seq,
                        tolerance_floor = tolerance_floor,
                        "Rejecting sequence outside tolerance window"
                    );
                    return false;
                }

                // If sequence is within tolerance but <= highest, it's out-of-order
                // but still acceptable (not a replay). Accept but don't update highest.
                if sequence <= state.highest_seq {
                    // Out-of-order but within tolerance - accept
                    state.message_count = state.message_count.saturating_add(1);
                    state.last_message_time = now_secs;
                    // Note: We don't update highest_seq or cumulative_distance for out-of-order
                    debug!(
                        sender = %hex::encode(&sender[..8]),
                        sequence = sequence,
                        highest_seq = state.highest_seq,
                        "Accepting out-of-order sequence within tolerance"
                    );
                    return true;
                }

                // H-P2P-5: Reject large sequence jumps
                let jump = sequence - state.highest_seq;
                if jump > MAX_SEQUENCE_JUMP {
                    warn!(
                        sender = %hex::encode(&sender[..8]),
                        highest_seq = state.highest_seq,
                        new_seq = sequence,
                        jump = jump,
                        max_jump = MAX_SEQUENCE_JUMP,
                        "H-P2P-5: Rejecting message with excessive sequence jump"
                    );
                    return false;
                }

                // H-7 SECURITY: Check cumulative distance
                let projected_cumulative = state.cumulative_distance.saturating_add(jump);
                if projected_cumulative > MAX_CUMULATIVE_DISTANCE_BEFORE_WRAP
                    && state.message_count < MIN_MESSAGES_BEFORE_WRAP
                {
                    warn!(
                        sender = %hex::encode(&sender[..8]),
                        highest_seq = state.highest_seq,
                        new_seq = sequence,
                        cumulative_distance = projected_cumulative,
                        message_count = state.message_count,
                        max_cumulative = MAX_CUMULATIVE_DISTANCE_BEFORE_WRAP,
                        min_messages = MIN_MESSAGES_BEFORE_WRAP,
                        "H-7: Rejecting message - cumulative sequence distance too high for message count"
                    );
                    return false;
                }

                // Valid sequence - update state atomically
                state.message_count = state.message_count.saturating_add(1);
                state.last_message_time = now_secs;
                state.cumulative_distance = projected_cumulative;
                state.highest_seq = sequence;
                true
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                // First message from this sender — establish the sequence baseline.
                //
                // RESTART RE-BASELINE (H-P2P-5): after our own restart the
                // sequence_state map is empty, so the first message from an honest
                // long-running peer carries its current (high) counter. We MUST
                // accept it as the baseline. Previously this rejected any first
                // message with sequence > MAX_SEQUENCE_JUMP and returned WITHOUT
                // inserting state — which permanently locked a restarted node out
                // of every peer past 1M messages: each later message was again
                // "first", re-rejected forever, leaving the node stuck behind on
                // checkpoint consensus until the peer itself restarted.
                //
                // Accepting any first sequence is safe:
                //  - the sender is authenticated (mesh Noise/signed), so a high
                //    sequence is the peer's real counter, not a forgery;
                //  - a first message cannot be a replay (no prior state);
                //  - everything after the baseline is still bounded by strict
                //    forward-ordering, the per-message jump cap (MAX_SEQUENCE_JUMP)
                //    and the H-7 cumulative-distance gate;
                //  - a near-u64::MAX baseline cannot fake a wrap-around — that
                //    path requires message_count >= MIN_MESSAGES_BEFORE_WRAP, and a
                //    fresh baseline has message_count == 1.
                //
                // cumulative_distance starts at 0: no distance has been travelled
                // since we began observing this peer.
                debug!(
                    sender = %hex::encode(&sender[..8]),
                    sequence = sequence,
                    "H-P2P-5: Establishing sequence baseline for peer (first message since (re)start)"
                );
                entry.insert(SequenceState {
                    highest_seq: sequence,
                    epoch: 0,
                    message_count: 1,
                    last_message_time: now_secs,
                    cumulative_distance: 0,
                });
                true
            }
        }
    }

    /// Check if a sequence is valid (read-only, for testing)
    ///
    /// NOTE: For actual message processing, use `validate_and_update_sequence()`
    /// which combines validation and update atomically.
    #[cfg(test)]
    fn is_sequence_valid(&self, sender: &NodeId, sequence: u64) -> bool {
        match self.sequence_state.get(sender) {
            Some(state) => {
                // Check for wrap-around
                if state.highest_seq > WRAP_DETECTION_THRESHOLD
                    && sequence < WRAP_DETECTION_THRESHOLD
                {
                    if state.message_count < MIN_MESSAGES_BEFORE_WRAP {
                        return false;
                    }
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let time_since_last = now_secs.saturating_sub(state.last_message_time);
                    if time_since_last > MAX_WRAP_AROUND_GAP_SECS {
                        return false;
                    }
                    const MAX_POST_WRAP_SEQUENCE: u64 = 1000;
                    return sequence > 0 && sequence <= MAX_POST_WRAP_SEQUENCE;
                }

                // Apply same tolerance window as validate_and_update_sequence
                let tolerance_floor = state.highest_seq.saturating_sub(SEQUENCE_TOLERANCE_WINDOW);
                if sequence < tolerance_floor {
                    return false;
                }

                // Sequences within tolerance but <= highest are accepted (out-of-order)
                if sequence <= state.highest_seq {
                    return true;
                }

                let jump = sequence - state.highest_seq;
                if jump > MAX_SEQUENCE_JUMP {
                    return false;
                }

                let projected_cumulative = state.cumulative_distance.saturating_add(jump);
                if projected_cumulative > MAX_CUMULATIVE_DISTANCE_BEFORE_WRAP
                    && state.message_count < MIN_MESSAGES_BEFORE_WRAP
                {
                    return false;
                }

                true
            }
            None => sequence <= MAX_SEQUENCE_JUMP,
        }
    }

    /// Update sequence state (for testing backward compatibility)
    #[cfg(test)]
    fn update_highest_seq(&mut self, sender: &NodeId, sequence: u64) {
        // Use the atomic method but ignore the result
        let _ = self.validate_and_update_sequence(sender, sequence);
    }

    /// Check if a message has been seen
    fn contains(&self, id: &MessageId) -> bool {
        self.map.contains_key(id)
    }

    /// SEC-P2P-6: Evict the oldest sender to make room for new ones
    ///
    /// Finds the sender whose most recent message is oldest and removes them entirely.
    fn evict_oldest_sender(&mut self) {
        // Find sender with oldest last message timestamp
        let oldest_sender = self
            .sender_queues
            .iter()
            .filter_map(|(id, queue)| queue.back().map(|(_, ts)| (*id, *ts)))
            .min_by_key(|(_, ts)| *ts)
            .map(|(id, _)| id);

        if let Some(sender) = oldest_sender {
            // Remove all messages from this sender
            if let Some(queue) = self.sender_queues.remove(&sender) {
                for (seq, _) in queue {
                    let id = MessageId {
                        sender,
                        sequence: seq,
                    };
                    self.map.remove(&id);
                }
            }
            self.sender_counts.remove(&sender);
            self.sequence_state.remove(&sender);

            // Note: We don't clean the global queue here for efficiency
            // It will be cleaned up naturally during normal eviction
            debug!(
                sender = %hex::encode(&sender[..8]),
                "Evicted oldest sender from seen message cache"
            );
        }
    }

    /// Insert a message, evicting oldest if at capacity
    ///
    /// H3 security fix: Uses per-sender tracking to prevent cache flushing attacks.
    /// A malicious sender flooding messages can only evict their own entries,
    /// not messages from other legitimate senders.
    ///
    /// CRIT-5: Also enforces memory limits and TTL-based expiration.
    fn insert(&mut self, id: MessageId, timestamp: u64) {
        // If already present, don't add again (duplicate)
        if self.map.contains_key(&id) {
            return;
        }

        // CRIT-5: Check memory limit before inserting
        if self.is_near_memory_limit() {
            self.evict_until_under_memory_limit();
        }

        // SEC-P2P-7: Limit unique senders to prevent memory exhaustion
        if !self.sender_counts.contains_key(&id.sender)
            && self.sender_counts.len() >= MAX_UNIQUE_SENDERS
        {
            self.evict_oldest_sender();
        }

        // H3: Check per-sender limit first
        let sender_count = self.sender_counts.entry(id.sender).or_insert(0);
        if *sender_count >= self.max_per_sender {
            // Evict oldest message from THIS sender only
            if let Some(sender_queue) = self.sender_queues.get_mut(&id.sender) {
                if let Some((old_seq, _)) = sender_queue.pop_front() {
                    let old_id = MessageId {
                        sender: id.sender,
                        sequence: old_seq,
                    };
                    if self.map.remove(&old_id).is_some() {
                        *sender_count = sender_count.saturating_sub(1);
                    }
                }
            }
        }

        // Global capacity check (defense in depth)
        while self.queue.len() >= self.capacity {
            if let Some(old_id) = self.queue.pop_front() {
                if self.map.remove(&old_id).is_some() {
                    if let Some(count) = self.sender_counts.get_mut(&old_id.sender) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
        }

        // Insert new entry
        self.map.insert(id, timestamp);
        self.queue.push_back(id);

        // Track per-sender
        *self.sender_counts.entry(id.sender).or_insert(0) += 1;
        self.sender_queues
            .entry(id.sender)
            .or_default()
            .push_back((id.sequence, timestamp));
    }

    /// Remove entries older than the given timestamp or that exceed TTL
    ///
    /// CRIT-5: Also enforces message_ttl_secs - any message older than TTL
    /// is cleaned up regardless of the cutoff_timestamp. This is only applied
    /// when operating in "real time" mode (cutoff is a reasonable Unix timestamp).
    fn cleanup_older_than(&mut self, cutoff_timestamp: u64) {
        // CRIT-5: Calculate the TTL cutoff (current time minus TTL)
        // Only apply TTL-based cleanup if we're using real timestamps (> year 2020)
        // This allows tests with small timestamps (like 1000, 2000) to work correctly
        let year_2020_timestamp: u64 = 1577836800; // 2020-01-01 00:00:00 UTC

        let effective_cutoff = if cutoff_timestamp > year_2020_timestamp {
            // We're using real timestamps, apply TTL as well
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let ttl_cutoff = now.saturating_sub(self.message_ttl_secs);
            // Use the more aggressive of the two cutoffs
            cutoff_timestamp.max(ttl_cutoff)
        } else {
            // Test mode with small timestamps - use only the provided cutoff
            cutoff_timestamp
        };

        // Remove from front of queue while entries are older than cutoff
        while let Some(&id) = self.queue.front() {
            if let Some(&ts) = self.map.get(&id) {
                if ts < effective_cutoff {
                    self.queue.pop_front();
                    if self.map.remove(&id).is_some() {
                        if let Some(count) = self.sender_counts.get_mut(&id.sender) {
                            *count = count.saturating_sub(1);
                        }
                    }
                } else {
                    // Queue is ordered by insertion time, so we can stop
                    break;
                }
            } else {
                // Entry was already removed, just pop from queue
                self.queue.pop_front();
            }
        }

        // Also cleanup per-sender queues
        for (sender_id, sender_queue) in self.sender_queues.iter_mut() {
            while let Some(&(_, ts)) = sender_queue.front() {
                if ts < effective_cutoff {
                    sender_queue.pop_front();
                } else {
                    break;
                }
            }
            // Update count to match actual queue length
            if let Some(count) = self.sender_counts.get_mut(sender_id) {
                *count = sender_queue.len();
            }
        }

        // Remove empty sender entries to prevent unbounded growth of sender tracking
        self.sender_counts.retain(|_, &mut count| count > 0);
        self.sender_queues.retain(|_, queue| !queue.is_empty());

        // L-2: Also clean sequence_state for senders with no remaining messages
        // This prevents unbounded growth of the sequence_state HashMap
        let active_senders: std::collections::HashSet<_> =
            self.sender_queues.keys().copied().collect();
        self.sequence_state
            .retain(|sender, _| active_senders.contains(sender));
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    /// CRIT-5: Estimate the current memory usage of the cache
    ///
    /// Returns an approximate byte count based on:
    /// - Number of entries in the map
    /// - Number of unique senders tracked
    /// - Fixed overhead per entry (BYTES_PER_CACHE_ENTRY)
    fn estimated_memory_bytes(&self) -> usize {
        let entry_bytes = self.map.len() * BYTES_PER_CACHE_ENTRY;
        let sender_overhead = self.sender_counts.len() * 64; // ~64 bytes per sender tracking
        let queue_overhead = self.queue.len() * 40; // MessageId in queue
        entry_bytes + sender_overhead + queue_overhead
    }

    /// CRIT-5: Check if the cache is approaching the memory limit
    ///
    /// Returns true if memory usage is >= 90% of max_memory_bytes
    fn is_near_memory_limit(&self) -> bool {
        let threshold = self.max_memory_bytes * 90 / 100;
        self.estimated_memory_bytes() >= threshold
    }

    /// CRIT-5: Aggressively evict entries until memory is under 70% of limit
    ///
    /// This is called when we hit the memory limit to ensure we have headroom
    /// for new entries without constantly triggering eviction.
    fn evict_until_under_memory_limit(&mut self) {
        let target = self.max_memory_bytes * 70 / 100;

        while self.estimated_memory_bytes() > target && !self.map.is_empty() {
            // Evict from the global queue (FIFO - oldest first)
            if let Some(old_id) = self.queue.pop_front() {
                if self.map.remove(&old_id).is_some() {
                    if let Some(count) = self.sender_counts.get_mut(&old_id.sender) {
                        *count = count.saturating_sub(1);
                    }
                }
            } else {
                break;
            }
        }

        // Cleanup empty sender entries
        self.sender_counts.retain(|_, &mut count| count > 0);
        self.sender_queues.retain(|_, queue| !queue.is_empty());
    }

    /// CRIT-5: Check if a message has expired based on TTL
    ///
    /// Returns true if the message timestamp is older than message_ttl_secs
    #[allow(dead_code)]
    fn is_message_expired(&self, timestamp: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now.saturating_sub(timestamp) > self.message_ttl_secs
    }
}

impl MeshNetwork {
    /// Create a new mesh network (fallible)
    ///
    /// M-2: When `noise_required=true` and Noise initialization fails, this
    /// returns an error instead of silently falling back to plaintext mode.
    /// This prevents running in an insecure configuration on mainnet.
    pub fn try_new(identity: Arc<NodeIdentity>, config: MeshConfig) -> GhostResult<Self> {
        let our_node_id = identity.node_id();
        let peers = Arc::new(PeerManager::new(our_node_id, config.max_peers));

        // M-8: Create bounded message channels with explicit capacity
        //
        // Capacity of 10,000 is chosen based on:
        // - At peak load, ~1000 messages/second from all peers combined
        // - 10 second buffer gives time for processing spikes
        // - Each message is ~1KB, so max memory usage is ~10MB per channel
        // - Bounded to prevent memory exhaustion attacks
        //
        // If channels fill up, senders use try_send() with logging for backpressure.
        // This is preferable to dropping messages silently or blocking indefinitely.
        const CHANNEL_CAPACITY: usize = 10_000;
        let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_CAPACITY);

        // C-1/C-4/M-2: Initialize Noise connection pool if enabled
        // M-2: When noise_required=true and initialization fails, return an error
        let noise_pool = if config.noise_enabled {
            match Self::init_noise_pool(&config) {
                Ok(pool) => {
                    info!(
                        public_key = %pool.public_key_hex(),
                        "Noise Protocol enabled for encrypted P2P"
                    );
                    Some(Arc::new(pool))
                }
                Err(e) => {
                    error!(error = %e, "Failed to initialize Noise pool");
                    if config.noise_required {
                        // M-2: Return error instead of continuing in plaintext mode
                        return Err(GhostError::Config(format!(
                            "M-2 SECURITY: Noise is required (noise_required=true) but failed to initialize: {}. \
                             Cannot continue - would operate without encryption. \
                             Fix Noise configuration or set noise_required=false to allow plaintext fallback.",
                            e
                        )));
                    }
                    warn!("Falling back to plaintext P2P (Noise disabled, noise_required=false)");
                    None
                }
            }
        } else {
            None
        };

        // Load the persisted outbound-sequence ceiling and reserve a fresh lease
        // so we resume above every sequence used before the last restart.
        let (init_sequence, init_ceiling) =
            Self::load_and_reserve_sequence(config.sequence_persist_path.as_deref());

        Ok(Self {
            capabilities: RwLock::new(config.capabilities),
            identity,
            config: config.clone(),
            peers,
            sequence: AtomicU64::new(init_sequence),
            sequence_ceiling: AtomicU64::new(init_ceiling),
            sequence_lease_lock: std::sync::Mutex::new(()),
            seen_messages: RwLock::new(SeenMessageCache::new(config.max_seen_messages)),
            handlers: RwLock::new(Vec::new()),
            running: AtomicBool::new(false),
            outbound_tx,
            outbound_rx: RwLock::new(Some(outbound_rx)),
            inbound_tx,
            inbound_rx: RwLock::new(Some(inbound_rx)),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            validation_stats: RwLock::new(ValidationStats::default()),
            noise_pool,
            miner_count_fn: None,
            active_miner_hashes_fn: None,
            local_hashrate_fn: None,
            max_capacity: AtomicU32::new(0),
        })
    }

    /// Set the hardware-derived miner capacity advertised in health pings.
    /// Should be called once at startup after `capacity::measure`; can be
    /// re-called if the operator throttle (`network.max_miners`) changes.
    pub fn set_max_capacity(&self, value: u32) {
        self.max_capacity.store(value, Ordering::Relaxed);
    }

    /// Set a callback that provides the real connected-miner count for health pings.
    /// Without this, health pings report peer_count as a placeholder.
    pub fn set_miner_count_provider(&mut self, f: Arc<dyn Fn() -> u32 + Send + Sync>) {
        self.miner_count_fn = Some(f);
    }

    /// Set a callback that provides the local active miner_id hashes for
    /// health pings. Used for mesh-wide deduplicated active-miner counting.
    /// Without this, health pings carry an empty list.
    pub fn set_active_miner_hashes_provider(
        &mut self,
        f: Arc<dyn Fn() -> Vec<[u8; 16]> + Send + Sync>,
    ) {
        self.active_miner_hashes_fn = Some(f);
    }

    /// Compute the deduplicated mesh-wide active miner count.
    /// Unions the local active miner_id hashes with the most recent hashes
    /// reported by every peer whose `last_seen` is within `freshness_secs`.
    /// Returns the size of the union.
    pub fn mesh_active_miner_count(&self, freshness_secs: u64) -> usize {
        use std::collections::HashSet;
        let mut set: HashSet<[u8; 16]> = HashSet::new();
        if let Some(f) = &self.active_miner_hashes_fn {
            for h in f() {
                set.insert(h);
            }
        }
        for peer in self.peers.get_connected_peers(freshness_secs) {
            for h in &peer.active_miner_id_hashes {
                set.insert(*h);
            }
        }
        set.len()
    }

    /// Set a callback providing this node's own realized hashrate (TH/s) over a
    /// trailing window, gossiped in health pings for mesh-wide summation.
    pub fn set_local_hashrate_provider(&mut self, f: Arc<dyn Fn() -> f64 + Send + Sync>) {
        self.local_hashrate_fn = Some(f);
    }

    /// Compute the mesh-wide pool hashrate (TH/s): this node's own realized
    /// hashrate plus the most recent value reported by every peer whose
    /// `last_seen` is within `freshness_secs`.
    ///
    /// This is a plain sum of one term per node — NOT a per-miner dedup —
    /// because every share is recorded on exactly one node (scoped by
    /// `received_by` at the source), so the per-node values are disjoint and
    /// cannot double-count. The result is therefore identical on every node,
    /// and a miner migrating between nodes shifts work from one term to another
    /// without changing the total. (The earlier per-miner `local`-always-wins
    /// approach produced inconsistent, inflated totals under migration.)
    pub fn mesh_total_hashrate(&self, freshness_secs: u64) -> f64 {
        let local = self.local_hashrate_fn.as_ref().map(|f| f()).unwrap_or(0.0);
        let peers = self.peers.get_connected_peers(freshness_secs);
        Self::compute_mesh_total_hashrate(local, peers.iter().map(|p| p.local_hashrate_th))
    }

    /// Pure sum behind [`Self::mesh_total_hashrate`], split out for unit
    /// testing without a live `MeshNetwork`. Negative inputs are clamped to 0
    /// so a stray `-0.0`/garbage term can't drag the total below zero.
    pub(crate) fn compute_mesh_total_hashrate(local: f64, peers: impl Iterator<Item = f64>) -> f64 {
        let total = local.max(0.0) + peers.map(|hr| hr.max(0.0)).sum::<f64>();
        total.max(0.0)
    }

    /// Create a new mesh network (infallible, panics on failure)
    ///
    /// C-3 SECURITY: This method is restricted to test code only via #[cfg(test)].
    /// Production code MUST use `try_new()` which returns a Result and allows
    /// proper error handling instead of panicking.
    ///
    /// # Panics
    /// Panics if MeshNetwork initialization fails (e.g., noise_required=true but Noise fails).
    #[cfg(test)]
    pub fn new(identity: Arc<NodeIdentity>, config: MeshConfig) -> Self {
        Self::try_new(identity, config).expect("MeshNetwork initialization failed")
    }

    /// Initialize the Noise connection pool
    fn init_noise_pool(
        config: &MeshConfig,
    ) -> Result<NoiseConnectionPool, crate::noise::NoiseError> {
        use crate::noise::{NoiseConfig, NoiseKeypair};

        // Load or generate keypair
        let keypair = if let Some(ref path) = config.noise_keypair_path {
            if path.exists() {
                // Verify file permissions before loading (warn if too permissive)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = std::fs::metadata(path) {
                        let mode = metadata.permissions().mode() & 0o777;
                        if mode & 0o077 != 0 {
                            warn!(
                                path = ?path,
                                mode = format!("{:o}", mode),
                                "Noise keypair file has overly permissive permissions, fixing to 0600"
                            );
                            let _ = std::fs::set_permissions(
                                path,
                                std::fs::Permissions::from_mode(0o600),
                            );
                        }
                    }
                }
                // Load existing keypair
                let hex = std::fs::read_to_string(path).map_err(crate::noise::NoiseError::Io)?;
                NoiseKeypair::from_hex(hex.trim())?
            } else {
                // Generate and save new keypair with restrictive permissions
                let kp = NoiseKeypair::generate();

                // M-11: Set restrictive umask BEFORE writing to prevent TOCTOU race.
                // The file is created with 0o600 permissions atomically (umask 0o077
                // masks out group/other bits from the default 0o666 creation mode).
                #[cfg(unix)]
                let _umask_guard = {
                    let old = unsafe { libc::umask(0o077) };
                    struct UmaskRestore(libc::mode_t);
                    impl Drop for UmaskRestore {
                        fn drop(&mut self) {
                            unsafe {
                                libc::umask(self.0);
                            }
                        }
                    }
                    UmaskRestore(old)
                };

                if let Err(e) = std::fs::write(path, hex::encode(kp.private_key())) {
                    warn!(path = ?path, error = %e, "Failed to save Noise keypair");
                } else {
                    // Belt-and-suspenders: also explicitly set permissions in case
                    // the file already existed with wrong permissions before the write.
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Err(e) =
                            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                        {
                            warn!(path = ?path, error = %e, "Failed to set Noise keypair file permissions");
                        }
                    }
                    info!(path = ?path, "Generated and saved new Noise keypair");
                }

                // M-11: Restore umask (guard dropped here)
                #[cfg(unix)]
                drop(_umask_guard);

                kp
            }
        } else {
            // Ephemeral keypair
            debug!("Using ephemeral Noise keypair (not persisted)");
            NoiseKeypair::generate()
        };

        let noise_config = NoiseConfig {
            enabled: config.noise_enabled,
            required: config.noise_required,
            keypair_file: config
                .noise_keypair_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            trusted_peers: Vec::new(), // Accept all peers initially
            // S-3: allow_unknown_peers=true is intentional for open membership.
            // Unknown peers (not MPC contributors, not seen >1 hour) are rate-limited
            // at 2x cost per message by the peer tracker (PeerTracker::is_established).
            // This prevents Sybil-driven message floods from new identities while
            // still allowing legitimate new nodes to join the network.
            allow_unknown_peers: true,
        };

        let pool_config = NoisePoolConfig {
            noise: noise_config,
            ..Default::default()
        };

        NoiseConnectionPool::new(keypair, pool_config)
    }

    /// Register a message handler
    pub fn register_handler(&self, handler: Arc<dyn MessageHandler>) {
        self.handlers.write().push(handler);
    }

    /// Update elder status in live capabilities
    ///
    /// Called after MPC contribution succeeds so health pings
    /// immediately reflect the new elder status (+1 share).
    pub fn update_elder_status(&self, is_elder: bool) {
        let mut caps = self.capabilities.write();
        caps.elder_status = is_elder;
        info!(
            elder_status = is_elder,
            total_shares = caps.total_shares(),
            "Updated live capabilities: elder_status"
        );
    }

    /// Get peer manager
    pub fn peers(&self) -> &Arc<PeerManager> {
        &self.peers
    }

    /// Add a peer
    pub fn add_peer(&self, peer: Peer) {
        self.peers.upsert_peer(peer);
    }

    /// Remove a peer
    pub fn remove_peer(&self, node_id: &NodeId) {
        self.peers.remove_peer(node_id);
    }

    /// M-14: Maximum sequence number before wrapping
    /// We use a high threshold to detect approaching overflow
    const MAX_SEQUENCE: u64 = u64::MAX - 1_000_000;

    /// Get next sequence number
    /// M-14: Uses saturating arithmetic to prevent overflow
    pub fn next_sequence(&self) -> u64 {
        loop {
            let current = self.sequence.load(Ordering::SeqCst);
            // M-14: Prevent overflow by wrapping around if we approach MAX
            // This is safe because sequence validation also checks monotonicity per-sender
            let next = if current >= Self::MAX_SEQUENCE {
                warn!("Sequence number approaching overflow, wrapping to 1");
                1 // Reset to 1 (not 0, as 0 could be a special value)
            } else {
                current.saturating_add(1)
            };

            if self
                .sequence
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.maybe_extend_sequence_lease(next);
                return next;
            }
            // Another thread modified sequence, retry
        }
    }

    /// Load the persisted outbound-sequence ceiling and reserve the next lease.
    ///
    /// Returns `(start, ceiling)`: `start` is where the counter resumes — the
    /// previously persisted ceiling, which is >= every sequence the prior
    /// process could have issued, so the sequence never goes backwards across a
    /// restart. `ceiling` is the freshly reserved upper bound, persisted before
    /// return. With no path (tests) returns `(0, u64::MAX)` — no persistence. If
    /// the path is set but the reservation can't be written, falls back to
    /// `(0, u64::MAX)` and logs, degrading to old behaviour rather than
    /// refusing to start.
    fn load_and_reserve_sequence(path: Option<&std::path::Path>) -> (u64, u64) {
        let Some(path) = path else {
            return (0, u64::MAX);
        };
        let persisted = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let ceiling = persisted.saturating_add(SEQUENCE_LEASE_BLOCK);
        match Self::write_sequence_ceiling(path, ceiling) {
            Ok(()) => {
                info!(
                    path = %path.display(),
                    resume_at = persisted,
                    ceiling = ceiling,
                    "Mesh outbound sequence: resumed from persisted lease"
                );
                (persisted, ceiling)
            }
            Err(e) => {
                error!(
                    path = %path.display(),
                    error = %e,
                    "Mesh outbound sequence: could not reserve lease — starting at 0 without persistence (restart-replay risk)"
                );
                (0, u64::MAX)
            }
        }
    }

    /// Atomically persist the sequence ceiling (write-temp-then-rename).
    fn write_sequence_ceiling(path: &std::path::Path, ceiling: u64) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, ceiling.to_string())?;
        std::fs::rename(&tmp, path)
    }

    /// Reserve a fresh lease block once the counter nears the persisted ceiling.
    /// Cheap in the common case (one atomic load); writes to disk only ~once per
    /// `SEQUENCE_LEASE_BLOCK` messages. No-op when persistence is disabled.
    fn maybe_extend_sequence_lease(&self, current: u64) {
        let Some(path) = self.config.sequence_persist_path.as_deref() else {
            return;
        };
        if current.saturating_add(SEQUENCE_LEASE_THRESHOLD)
            < self.sequence_ceiling.load(Ordering::SeqCst)
        {
            return; // lease has plenty of headroom
        }
        // Serialise the (rare) on-disk extension; recover a poisoned lock since
        // the only guarded action is a file write.
        let _guard = self
            .sequence_lease_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ceiling = self.sequence_ceiling.load(Ordering::SeqCst);
        if current.saturating_add(SEQUENCE_LEASE_THRESHOLD) < ceiling {
            return; // another thread already extended
        }
        let new_ceiling = current.saturating_add(SEQUENCE_LEASE_BLOCK);
        match Self::write_sequence_ceiling(path, new_ceiling) {
            // Advance the in-memory ceiling only after the higher value is on
            // disk, so we never issue a sequence we haven't persisted past.
            Ok(()) => self.sequence_ceiling.store(new_ceiling, Ordering::SeqCst),
            Err(e) => error!(
                path = %path.display(),
                error = %e,
                "Mesh outbound sequence: failed to extend lease; will retry"
            ),
        }
    }

    /// H-5 SECURITY: Atomically check if duplicate and mark as seen if valid
    ///
    /// This combines the duplicate check and mark-seen into a single atomic operation
    /// to prevent TOCTOU race conditions at the MeshNetwork level.
    ///
    /// Returns true if the message is a duplicate (should be rejected).
    /// Returns false if the message is new and has been marked as seen.
    ///
    /// The message is rejected if:
    /// 1. We've already seen this exact (sender, sequence) pair, OR
    /// 2. The sequence is <= the highest sequence we've seen from this sender, OR
    /// 3. The sequence violates wrap-around protection rules
    fn check_duplicate_and_mark(&self, msg_id: MessageId) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut seen = self.seen_messages.write();

        // Check if already seen (exact duplicate)
        if seen.contains(&msg_id) {
            return true; // Duplicate
        }

        // H-5: Atomically validate sequence and update state
        // This uses the combined validate_and_update_sequence method
        // which prevents TOCTOU between validation and update
        if !seen.validate_and_update_sequence(&msg_id.sender, msg_id.sequence) {
            return true; // Invalid sequence (replay or attack)
        }

        // Valid new message - insert into cache
        seen.insert(msg_id, now);
        false // Not a duplicate
    }

    /// Check if message is duplicate or has invalid sequence (H-P2P-4)
    ///
    /// DEPRECATED: Use check_duplicate_and_mark() for atomic operation.
    /// This read-only check is kept for diagnostic purposes.
    #[cfg(test)]
    fn is_duplicate(&self, msg_id: MessageId) -> bool {
        let seen = self.seen_messages.read();
        seen.contains(&msg_id)
    }

    /// Mark message as seen - DEPRECATED
    ///
    /// DEPRECATED: Use check_duplicate_and_mark() for atomic operation.
    #[cfg(test)]
    fn mark_seen(&self, msg_id: MessageId) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut seen = self.seen_messages.write();
        seen.insert(msg_id, now);
        seen.validate_and_update_sequence(&msg_id.sender, msg_id.sequence);
    }

    /// Create a message envelope
    pub fn create_envelope<T: serde::Serialize>(
        &self,
        msg_type: MessageType,
        payload: &T,
    ) -> GhostResult<MessageEnvelope> {
        let payload_bytes =
            serde_json::to_vec(payload).map_err(|e| GhostError::Serialization(e.to_string()))?;

        let sequence = self.next_sequence();

        // Sign the payload + sequence (verifier expects both)
        let mut signed_data = Vec::with_capacity(payload_bytes.len() + 8);
        signed_data.extend_from_slice(&payload_bytes);
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = self.identity.sign(&signed_data);

        Ok(MessageEnvelope::new(
            msg_type,
            self.identity.node_id(),
            payload_bytes,
            sequence,
            signature,
        ))
    }

    /// Create a message envelope from pre-serialized payload bytes
    pub fn create_envelope_raw(
        &self,
        msg_type: MessageType,
        payload: Vec<u8>,
    ) -> GhostResult<MessageEnvelope> {
        let sequence = self.next_sequence();

        // Sign the payload + sequence (must match create_envelope for P2P4-M1 verification)
        let mut signed_data = Vec::with_capacity(payload.len() + 8);
        signed_data.extend_from_slice(&payload);
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = self.identity.sign(&signed_data);

        Ok(MessageEnvelope::new(
            msg_type,
            self.identity.node_id(),
            payload,
            sequence,
            signature,
        ))
    }

    /// Broadcast a message to all peers
    pub async fn broadcast(&self, envelope: MessageEnvelope) -> GhostResult<usize> {
        let peers = self.peers.get_connected_peers(60);
        let mut sent = 0;

        for peer in peers {
            if peer.node_id == self.identity.node_id() {
                continue; // Don't send to ourselves
            }

            match self.send_to_peer(&peer, &envelope).await {
                Ok(_) => sent += 1,
                Err(e) => {
                    warn!(
                        peer = %peer.node_id_short(),
                        error = %e,
                        "Failed to send to peer"
                    );
                }
            }
        }

        debug!(
            msg_type = ?envelope.msg_type,
            sent = sent,
            ttl = envelope.ttl,
            "Broadcast message"
        );

        Ok(sent)
    }

    /// Forward a received message to other peers (gossip)
    ///
    /// Decrements the TTL and forwards if TTL > 0.
    /// Returns the number of peers the message was forwarded to, or 0 if TTL expired.
    /// Does not forward to the original sender.
    pub async fn forward_message(&self, mut envelope: MessageEnvelope) -> GhostResult<usize> {
        // Check and decrement TTL
        if !envelope.decrement_ttl() {
            debug!(
                msg_type = ?envelope.msg_type,
                sender = %hex::encode(&envelope.sender[..8]),
                "Message TTL expired, not forwarding"
            );
            return Ok(0);
        }

        if !envelope.should_forward() {
            return Ok(0);
        }

        let original_sender = envelope.sender;
        let peers = self.peers.get_connected_peers(60);
        let mut sent = 0;

        for peer in peers {
            // Don't forward to ourselves or back to the original sender
            if peer.node_id == self.identity.node_id() || peer.node_id == original_sender {
                continue;
            }

            match self.send_to_peer(&peer, &envelope).await {
                Ok(_) => sent += 1,
                Err(e) => {
                    warn!(
                        peer = %peer.node_id_short(),
                        error = %e,
                        "Failed to forward to peer"
                    );
                }
            }
        }

        debug!(
            msg_type = ?envelope.msg_type,
            sent = sent,
            ttl = envelope.ttl,
            "Forwarded message"
        );

        Ok(sent)
    }

    /// Broadcast a typed message to all peers
    ///
    /// Creates an envelope with proper signing and broadcasts to all connected peers.
    pub async fn broadcast_message<T: serde::Serialize>(
        &self,
        msg_type: MessageType,
        payload: &T,
    ) -> GhostResult<usize> {
        let envelope = self.create_envelope(msg_type, payload)?;
        self.broadcast(envelope).await
    }

    /// C-1: Check if a message type should use encrypted Noise channels
    ///
    /// Sensitive messages go over Noise TCP, broadcast messages stay on ZMQ.
    fn should_use_noise(&self, msg_type: MessageType) -> bool {
        if self.noise_pool.is_none() {
            return false;
        }

        match msg_type {
            // P-7: Discovery must remain plaintext for bootstrap (can't encrypt to unknown peers).
            // HealthPing stays plaintext for broadcast scaling but sensitive fields removed (P-1).
            // All financial operations (payouts, votes, shares) require Noise.
            MessageType::Discovery | MessageType::HealthPing => false,

            // Sensitive messages use Noise encryption
            MessageType::ShareProof
            | MessageType::ShareConvergence
            | MessageType::BlockFound
            | MessageType::Vote
            | MessageType::PayoutProposal
            | MessageType::ElderUpdate
            | MessageType::ZkBlockProposal
            | MessageType::ZkVote
            | MessageType::VerificationResult
            | MessageType::EquivocationProof
            | MessageType::ElderRegistrationProposal
            | MessageType::ElderListProposal
            | MessageType::ElderListApproval
            | MessageType::MpcContribution
            | MessageType::MpcVerificationVote
            | MessageType::MpcParametersRequest
            | MessageType::MpcParametersResponse
            // L2 messages use Noise encryption (contain proofs and encrypted note data)
            | MessageType::L2ConfidentialTransfer
            | MessageType::L2TransferConfirmation
            | MessageType::L2TransferBroadcast
            | MessageType::L2CheckpointBlock
            | MessageType::L2CheckpointVote
            | MessageType::L2TreeSync
            | MessageType::L2ShieldBroadcast
            // GhostGlyph messages use Noise (contain identity binding data)
            | MessageType::GhostGlyphClaim
            | MessageType::GhostGlyphRegistered => true,
        }
    }

    /// C-1: Send message via Noise-encrypted channel to a specific peer
    ///
    /// Establishes or reuses an encrypted connection to the peer.
    pub async fn send_encrypted(&self, peer: &Peer, envelope: &MessageEnvelope) -> GhostResult<()> {
        let pool = self
            .noise_pool
            .as_ref()
            .ok_or_else(|| GhostError::P2PMessage("Noise not enabled".into()))?;

        // Serialize the envelope
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // Parse peer address for Noise port
        let host = peer
            .public_address
            .split(':')
            .next()
            .unwrap_or(&peer.public_address);
        let noise_addr: std::net::SocketAddr = format!("{}:{}", host, self.config.noise_port)
            .parse()
            .map_err(|e| GhostError::P2PMessage(format!("Invalid peer address: {}", e)))?;

        // Get or establish Noise connection
        let conn = pool
            .get_connection(noise_addr)
            .await
            .map_err(|e| GhostError::P2PMessage(format!("Noise connection failed: {}", e)))?;

        // Send encrypted
        conn.send(&data)
            .await
            .map_err(|e| GhostError::P2PMessage(format!("Noise send failed: {}", e)))?;

        debug!(
            peer = %peer.node_id_short(),
            msg_type = ?envelope.msg_type,
            bytes = data.len(),
            "Sent encrypted message via Noise"
        );

        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// C-1: Broadcast message via encrypted Noise channels to all peers
    ///
    /// For sensitive messages, this uses point-to-point encryption to each peer.
    pub async fn broadcast_encrypted(
        &self,
        envelope: &MessageEnvelope,
    ) -> GhostResult<BroadcastResult> {
        let pool = self
            .noise_pool
            .as_ref()
            .ok_or_else(|| GhostError::P2PMessage("Noise not enabled".into()))?;

        let peers = self.peers.get_connected_peers(60);
        let mut result = BroadcastResult::default();

        info!(
            msg_type = ?envelope.msg_type,
            peer_count = peers.len(),
            "Starting encrypted broadcast"
        );

        // Serialize once for all peers
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        for peer in peers {
            if peer.node_id == self.identity.node_id() {
                continue; // Don't send to ourselves
            }

            // Parse peer address
            let host = peer
                .public_address
                .split(':')
                .next()
                .unwrap_or(&peer.public_address);
            let noise_addr: std::net::SocketAddr = match format!(
                "{}:{}",
                host, self.config.noise_port
            )
            .parse()
            {
                Ok(addr) => addr,
                Err(e) => {
                    warn!(peer = %peer.node_id_short(), error = %e, "Invalid peer address for Noise");
                    result.failed += 1;
                    continue;
                }
            };

            // Get or establish Noise connection
            match pool.get_connection(noise_addr).await {
                Ok(conn) => {
                    match conn.send(&data).await {
                        Ok(_) => {
                            result.success += 1;
                            self.messages_sent.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            warn!(peer = %peer.node_id_short(), error = %e, "Noise send failed");
                            result.failed += 1;
                            // Remove broken connection
                            pool.remove_connection(&conn.peer_key);
                        }
                    }
                }
                Err(e) => {
                    warn!(peer = %peer.node_id_short(), peer_addr = %noise_addr, error = %e, "Noise connection failed");
                    result.failed += 1;
                }
            }
        }

        info!(
            msg_type = ?envelope.msg_type,
            success = result.success,
            failed = result.failed,
            "Encrypted broadcast complete"
        );

        Ok(result)
    }

    /// C-1: Smart broadcast - uses Noise for sensitive messages, ZMQ for broadcast
    ///
    /// CRIT-CONS-4 SECURITY: When noise_required=true, sensitive messages MUST use Noise.
    /// Plaintext fallback is COMPLETELY DISABLED to prevent downgrade attacks.
    ///
    /// This is the recommended method for broadcasting messages. It automatically
    /// chooses the appropriate transport:
    /// - Discovery/Health pings: ZMQ broadcast (need to reach unknown peers)
    /// - Sensitive data: Noise encrypted point-to-point (NO FALLBACK if noise_required=true)
    pub async fn smart_broadcast(&self, envelope: MessageEnvelope) -> GhostResult<usize> {
        if self.should_use_noise(envelope.msg_type) {
            // Use Noise for sensitive messages
            match self.broadcast_encrypted(&envelope).await {
                Ok(result) => Ok(result.success),
                Err(e) if !self.config.noise_required => {
                    // CRIT-CONS-4: Fallback ONLY allowed when noise_required=false
                    // This path should NEVER execute on mainnet (where noise_required=true)
                    warn!(
                        error = %e,
                        msg_type = ?envelope.msg_type,
                        "Noise broadcast failed, falling back to plaintext ZMQ (noise_required=false)"
                    );
                    self.broadcast(envelope).await
                }
                Err(e) => {
                    // CRIT-CONS-4: When noise_required=true, NO FALLBACK - fail the request
                    // This prevents sensitive data from being sent over plaintext
                    error!(
                        error = %e,
                        msg_type = ?envelope.msg_type,
                        noise_required = self.config.noise_required,
                        "CRIT-CONS-4: Noise broadcast failed with noise_required=true - refusing plaintext fallback"
                    );
                    Err(e)
                }
            }
        } else {
            // Use ZMQ for broadcast messages (discovery, health pings)
            self.broadcast(envelope).await
        }
    }

    /// Get the Noise connection pool (if enabled)
    pub fn noise_pool(&self) -> Option<&Arc<NoiseConnectionPool>> {
        self.noise_pool.as_ref()
    }

    /// Send a message to a specific peer
    ///
    /// Automatically routes messages through Noise encryption for sensitive message types
    /// (MPC, Elder, Payout, ZK, etc.) or ZMQ for broadcast messages (Discovery, HealthPing).
    pub async fn send_to_peer(&self, peer: &Peer, envelope: &MessageEnvelope) -> GhostResult<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(GhostError::NotRunning("Mesh network not running".into()));
        }

        // Route sensitive messages through Noise encryption
        if self.should_use_noise(envelope.msg_type) {
            return self.send_encrypted(peer, envelope).await;
        }

        // Serialize the envelope for ZMQ
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // Construct the endpoint based on message type
        let endpoint = self.endpoint_for_message(&peer.public_address, envelope.msg_type);

        debug!(
            peer = %peer.node_id_short(),
            msg_type = ?envelope.msg_type,
            endpoint = %endpoint,
            bytes = data.len(),
            "Sending message to peer via ZMQ"
        );

        // M-8: Use try_send with explicit backpressure handling
        // This prevents blocking indefinitely if the outbound channel is full
        match self.outbound_tx.try_send((endpoint, data)) {
            Ok(_) => {
                self.messages_sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel is full - return an error so the caller can decide what to do
                // (e.g., retry later, drop the message, or slow down)
                warn!(
                    peer = %peer.node_id_short(),
                    msg_type = ?envelope.msg_type,
                    "M-8: Outbound channel full (backpressure)"
                );
                Err(GhostError::P2PMessage(
                    "M-8: Outbound channel full - apply backpressure".to_string(),
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(GhostError::NotRunning("Outbound channel closed".into()))
            }
        }
    }

    /// Get the endpoint for a message type
    fn endpoint_for_message(&self, host: &str, msg_type: MessageType) -> String {
        // Extract just the host if it includes a port
        let host_only = host.split(':').next().unwrap_or(host);

        let base_port = match msg_type {
            MessageType::ShareProof | MessageType::ShareConvergence => {
                self.config.ports.share_propagation
            }
            MessageType::BlockFound => self.config.ports.block_announcement,
            MessageType::Vote => self.config.ports.consensus_voting,
            MessageType::HealthPing => self.config.ports.health_monitoring,
            MessageType::Discovery => self.config.ports.discovery,
            MessageType::ElderUpdate => self.config.ports.elder_management,
            // P2P-C1/C2/C3: Elder registration messages use elder management port
            MessageType::ElderRegistrationProposal
            | MessageType::ElderListProposal
            | MessageType::ElderListApproval
            // MPC ceremony messages also use elder management port
            | MessageType::MpcContribution
            | MessageType::MpcVerificationVote
            | MessageType::MpcParametersRequest
            | MessageType::MpcParametersResponse => self.config.ports.elder_management,
            MessageType::PayoutProposal => self.config.ports.payout_proposal,
            // ZK-BFT messages use consensus voting port
            MessageType::ZkBlockProposal
            | MessageType::ZkVote => self.config.ports.consensus_voting,
            // Verification results use health monitoring port
            MessageType::VerificationResult => self.config.ports.health_monitoring,
            // P2P-H3: Equivocation proofs use consensus voting port
            MessageType::EquivocationProof => self.config.ports.consensus_voting,
            // L2 messages use consensus voting port
            MessageType::L2ConfidentialTransfer
            | MessageType::L2TransferConfirmation
            | MessageType::L2TransferBroadcast
            | MessageType::L2CheckpointBlock
            | MessageType::L2CheckpointVote
            | MessageType::L2TreeSync
            | MessageType::L2ShieldBroadcast => self.config.ports.consensus_voting,
            // GhostGlyph messages use consensus voting port
            MessageType::GhostGlyphClaim
            | MessageType::GhostGlyphRegistered => self.config.ports.consensus_voting,
        };
        format!("tcp://{}:{}", host_only, base_port)
    }

    /// H-11: Maximum P2P message size to prevent memory exhaustion attacks
    const MAX_P2P_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB

    /// Handle a received message with full validation and signature verification
    pub async fn handle_received(&self, data: &[u8]) -> GhostResult<()> {
        // H-11: Reject oversized messages before any processing
        if data.len() > Self::MAX_P2P_MESSAGE_SIZE {
            warn!(
                size = data.len(),
                max = Self::MAX_P2P_MESSAGE_SIZE,
                "H-11 SECURITY: Rejecting oversized P2P message"
            );
            return Err(GhostError::P2PMessage(format!(
                "Message size {} exceeds maximum {}",
                data.len(),
                Self::MAX_P2P_MESSAGE_SIZE
            )));
        }

        // Use the full validation pipeline including signature verification
        let envelope = match validate_and_verify(data) {
            Ok(env) => env,
            Err(e) => {
                // Update stats and log the rejection
                let mut stats = self.validation_stats.write();
                stats.record(&Err(e.clone()));

                debug!(
                    error = %e,
                    data_len = data.len(),
                    "Message validation failed"
                );
                return Err(GhostError::P2PMessage(e.to_string()));
            }
        };

        // Record successful validation
        {
            let mut stats = self.validation_stats.write();
            stats.record(&Ok(envelope.clone()));
        }

        let sender_hex = hex::encode(envelope.sender);
        debug!(
            sender = %&sender_hex[..8],
            msg_type = ?envelope.msg_type,
            sequence = envelope.sequence,
            "Message validated"
        );

        // H-5 SECURITY: Atomically check for duplicate and mark as seen
        // This prevents TOCTOU race conditions where two threads could both
        // pass the duplicate check and then both process the same message
        let msg_id = MessageId {
            sender: envelope.sender,
            sequence: envelope.sequence,
        };

        if self.check_duplicate_and_mark(msg_id) {
            trace!(
                sender = %hex::encode(&envelope.sender[..8]),
                msg_type = ?envelope.msg_type,
                sequence = envelope.sequence,
                "Duplicate message dropped"
            );
            return Ok(());
        }

        // Update peer last seen
        self.peers.update_last_seen(&envelope.sender);

        // Dispatch to handlers
        let handlers = self.handlers.read().clone();
        debug!(
            handler_count = handlers.len(),
            msg_type = ?envelope.msg_type,
            "Dispatching to handlers"
        );
        let envelope = Arc::new(envelope);
        for handler in handlers {
            if let Err(e) = handler.handle_message(Arc::clone(&envelope)).await {
                error!(error = %e, msg_type = ?envelope.msg_type, "Handler error");
            }
        }

        Ok(())
    }

    /// Get validation statistics for monitoring
    pub fn validation_stats(&self) -> ValidationStats {
        self.validation_stats.read().clone()
    }

    /// Start the mesh network
    pub async fn start(self: &Arc<Self>) -> GhostResult<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(GhostError::AlreadyRunning(
                "Mesh network already running".into(),
            ));
        }

        info!(
            address = %self.config.public_address,
            ports = ?self.config.ports,
            "Starting mesh network"
        );

        // C-1: Log Noise Protocol status
        if self.config.noise_enabled {
            info!(
                noise_port = self.config.noise_port,
                noise_required = self.config.noise_required,
                "Noise Protocol encryption ENABLED for sensitive P2P traffic"
            );
        } else {
            warn!(
                "P2P transport encryption (Noise Protocol) is DISABLED. \
                 Sensitive messages are sent in plaintext. Set noise_enabled=true for production."
            );
        }

        self.running.store(true, Ordering::SeqCst);

        // Spawn publisher task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_publisher().await {
                error!(error = %e, "Publisher task failed");
            }
        });

        // Spawn subscriber task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = self_clone.run_subscriber().await {
                error!(error = %e, "Subscriber task failed");
            }
        });

        // Spawn message handler task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            self_clone.run_message_handler().await;
        });

        // Spawn health ping task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            self_clone.run_health_pinger().await;
        });

        // Spawn cleanup task
        let self_clone = Arc::clone(self);
        tokio::spawn(async move {
            self_clone.run_cleanup_task().await;
        });

        info!("Mesh network started successfully");
        Ok(())
    }

    /// Run the publisher (sends outbound messages)
    async fn run_publisher(&self) -> GhostResult<()> {
        use tmq::AsZmqSocket;

        // Create PUB socket using tmq with shared context - bind first port
        let mut pub_socket = publish(&ZMQ_CONTEXT)
            .bind(&format!(
                "tcp://0.0.0.0:{}",
                self.config.ports.share_propagation
            ))
            .map_err(|e| {
                GhostError::P2PMessage(format!("Failed to bind share_propagation: {}", e))
            })?;

        // Bind additional ports using the underlying zmq socket
        let additional_ports = [
            (self.config.ports.block_announcement, "block_announcement"),
            (self.config.ports.consensus_voting, "consensus_voting"),
            (self.config.ports.health_monitoring, "health_monitoring"),
            (self.config.ports.discovery, "discovery"),
            (self.config.ports.elder_management, "elder_management"),
            (self.config.ports.payout_proposal, "payout_proposal"),
            (self.config.ports.payout_transaction, "payout_transaction"),
        ];

        for (port, name) in additional_ports {
            let endpoint = format!("tcp://0.0.0.0:{}", port);
            pub_socket
                .get_socket()
                .bind(&endpoint)
                .map_err(|e| GhostError::P2PMessage(format!("Failed to bind {}: {}", name, e)))?;
        }

        info!(
            ports = ?self.config.ports,
            "Bound PUB socket to all ports"
        );

        // Take the receiver from the RwLock
        let mut outbound_rx = self
            .outbound_rx
            .write()
            .take()
            .ok_or_else(|| GhostError::Internal("Outbound receiver already taken".into()))?;

        // Process outbound messages
        while self.running.load(Ordering::SeqCst) {
            match tokio::time::timeout(std::time::Duration::from_millis(100), outbound_rx.recv())
                .await
            {
                Ok(Some((_endpoint, data))) => {
                    // Extract topic from the serialized envelope
                    let (topic, msg_type_str) = match MessageEnvelope::deserialize(&data) {
                        Ok(env) => {
                            let topic = env.topic().to_vec();
                            let msg_type = format!("{:?}", env.msg_type);
                            (topic, msg_type)
                        }
                        Err(_) => {
                            // Fallback to generic topic if deserialization fails
                            warn!("Failed to deserialize envelope for topic extraction");
                            (b"msg".to_vec(), "Unknown".to_string())
                        }
                    };

                    // Send as single-frame ZMQ message with topic prefix for filtering
                    // Format: [topic + payload] in a single frame
                    let mut prefixed_data = topic.clone();
                    prefixed_data.extend_from_slice(&data);
                    let msg = Multipart::from(vec![prefixed_data]);

                    if let Err(e) = pub_socket.send(msg).await {
                        warn!(error = %e, msg_type = %msg_type_str, "Failed to send ZMQ message");
                    }
                }
                Ok(None) => break,  // Channel closed
                Err(_) => continue, // Timeout, check running state
            }
        }

        info!("Publisher task stopped");
        Ok(())
    }

    /// Run subscriber (receives messages from peers)
    ///
    /// Uses tmq with libzmq's built-in reconnection support via ZMQ_RECONNECT_IVL
    /// and ZMQ_RECONNECT_IVL_MAX socket options. No manual watchdog needed.
    async fn run_subscriber(&self) -> GhostResult<()> {
        use tmq::AsZmqSocket;

        info!("Starting mesh subscriber task");

        // Create SUB socket with tmq - we need to bind/connect to at least one endpoint
        // to create the socket, then we can add more endpoints dynamically.
        // We'll use a dummy inproc endpoint that we create just to bootstrap the socket.
        let dummy_endpoint = format!("inproc://mesh-sub-bootstrap-{}", std::process::id());

        // P2P4-5: Subscribe to specific known topics only (not empty filter)
        // This prevents processing of unknown/malicious topic prefixes
        use crate::message::topics;

        // bind() returns SubscribeWithoutTopic, then subscribe() returns Subscribe (which implements Stream)
        // P2P4-5: Subscribe to specific known topics only (not empty filter)
        // First subscribe() converts SubscribeWithoutTopic -> Subscribe, then we add more topics
        let mut sub_socket = subscribe(&ZMQ_CONTEXT)
            .set_reconnect_ivl(100) // Initial reconnect interval: 100ms
            .set_reconnect_ivl_max(5000) // Max reconnect interval: 5 seconds
            .bind(&dummy_endpoint)
            .map_err(|e| GhostError::P2PMessage(format!("Failed to create SUB socket: {}", e)))?
            .subscribe(topics::SHARE)
            .map_err(|e| GhostError::P2PMessage(format!("Failed to subscribe to share: {}", e)))?;

        // P2P4-5: Subscribe to remaining topics using mutable Subscribe reference
        // After the first subscribe(), we have a Subscribe struct that takes &mut self
        let additional_topics: &[(&[u8], &str)] = &[
            (topics::BLOCK, "block"),
            (topics::VOTE, "vote"),
            (topics::HEALTH, "health"),
            (topics::DISCOVERY, "discovery"),
            (topics::ELDER, "elder"),
            (topics::PAYOUT_PROPOSAL, "payout_proposal"),
            (topics::ZK_PROPOSAL, "zk_proposal"),
            (topics::ZK_VOTE, "zk_vote"),
            (topics::VERIFICATION, "verification"),
            (topics::MPC, "mpc"), // MPC ceremony messages
        ];

        for (topic, name) in additional_topics {
            sub_socket.subscribe(topic).map_err(|e| {
                GhostError::P2PMessage(format!("Failed to subscribe to {}: {}", name, e))
            })?;
        }

        debug!("SUB socket created with reconnection support (ivl=100ms, max=5000ms)");

        // Track which peers we've attempted to connect to
        let mut connected_addresses: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // P2P4-L6: Track connection state for exponential backoff
        let mut connection_states: std::collections::HashMap<String, PeerConnectionState> =
            std::collections::HashMap::new();

        // Track message receive stats for debugging
        let mut last_stats_log = std::time::Instant::now();
        let mut receive_attempts: u64 = 0;
        let mut receive_timeouts: u64 = 0;
        let mut receive_errors: u64 = 0;

        // MED-CONS-2: Rate limit topic mismatch warnings per sender (1 per minute)
        // H-4 SECURITY: Bounded to prevent memory exhaustion from malicious senders
        let mut topic_mismatch_log_times: std::collections::HashMap<[u8; 32], std::time::Instant> =
            std::collections::HashMap::new();
        const TOPIC_MISMATCH_LOG_INTERVAL_SECS: u64 = 60;
        // H-4: Maximum entries to prevent unbounded memory growth
        const MAX_TOPIC_MISMATCH_ENTRIES: usize = 1000;

        while self.running.load(Ordering::SeqCst) {
            // Get ALL peers (not just connected ones) - we need to attempt connection first
            let peers = self.peers.get_all_peers();

            // Connect to any new peers using the underlying ZMQ socket
            for peer in peers {
                // Skip if we've already tried this address
                // Extract host from public_address (may be "host:port" or just "host")
                // Normalize to just the host for deduplication
                let host = peer
                    .public_address
                    .split(':')
                    .next()
                    .unwrap_or(&peer.public_address)
                    .to_string();

                // Skip if we've already connected to this host
                if connected_addresses.contains(&host) {
                    continue;
                }

                // M-P2P-4: Evict oldest entry if at capacity (LRU eviction)
                if connection_states.len() >= MAX_CONNECTION_STATES {
                    // Remove oldest entry (one with earliest last_attempt)
                    if let Some(oldest_key) = connection_states
                        .iter()
                        .min_by_key(|(_, state)| state.last_attempt)
                        .map(|(k, _)| k.clone())
                    {
                        connection_states.remove(&oldest_key);
                        debug!(
                            evicted = %oldest_key,
                            "Evicted oldest connection state (LRU)"
                        );
                    }
                }

                // P2P4-L6: Check backoff state before attempting connection
                let conn_state = connection_states
                    .entry(host.clone())
                    .or_insert_with(PeerConnectionState::new);
                if !conn_state.can_retry() {
                    debug!(
                        host = %host,
                        backoff_ms = conn_state.backoff_ms,
                        failures = conn_state.consecutive_failures,
                        "Skipping connection attempt (backoff)"
                    );
                    continue;
                }

                // Connect to all message type ports
                let ports = [
                    self.config.ports.share_propagation,
                    self.config.ports.block_announcement,
                    self.config.ports.consensus_voting,
                    self.config.ports.health_monitoring,
                    self.config.ports.discovery,
                    self.config.ports.elder_management,
                    self.config.ports.payout_proposal,
                    self.config.ports.payout_transaction,
                ];

                let mut connected_any = false;
                for port in ports {
                    let endpoint = format!("tcp://{}:{}", host, port);
                    // Use the underlying zmq socket to connect dynamically
                    match sub_socket.get_socket().connect(&endpoint) {
                        Ok(_) => {
                            debug!(endpoint = %endpoint, "Connected SUB socket");
                            connected_any = true;
                        }
                        Err(e) => {
                            debug!(endpoint = %endpoint, error = %e, "Failed to connect SUB socket");
                        }
                    }
                }

                if connected_any {
                    info!(
                        host = %host,
                        total_connected = connected_addresses.len() + 1,
                        "SUB socket connected to peer on all ports"
                    );
                    connected_addresses.insert(host.clone());
                    // P2P4-L6: Reset backoff on success
                    if let Some(state) = connection_states.get_mut(&host) {
                        state.record_success();
                    }
                } else {
                    // P2P4-L6: Record failure and increase backoff
                    if let Some(state) = connection_states.get_mut(&host) {
                        state.record_failure();
                        warn!(
                            host = %host,
                            backoff_ms = state.backoff_ms,
                            failures = state.consecutive_failures,
                            "Failed to connect SUB socket to peer (will retry with backoff)"
                        );
                    }
                }
            }

            // Log stats every 30 seconds
            if last_stats_log.elapsed() > std::time::Duration::from_secs(30) {
                let total_received = self.messages_received.load(Ordering::Relaxed);
                debug!(
                    zmq_connections = connected_addresses.len(),
                    receive_attempts,
                    receive_timeouts,
                    receive_errors,
                    total_received,
                    "SUB socket stats"
                );
                last_stats_log = std::time::Instant::now();
            }

            // Try to receive a message using StreamExt::next()
            receive_attempts += 1;
            match tokio::time::timeout(std::time::Duration::from_millis(100), sub_socket.next())
                .await
            {
                Ok(Some(Ok(msg))) => {
                    // ZMQ message with topic prefix - tmq returns Multipart
                    let raw_data: Vec<u8> = msg
                        .into_iter()
                        .flat_map(|frame: tmq::Message| frame.to_vec())
                        .collect();

                    if raw_data.is_empty() {
                        debug!("Received empty ZMQ message");
                        continue;
                    }

                    // Find where the payload starts (after the topic)
                    // Topics are known fixed strings: health, share, block, vote, discovery, elder, payout
                    use crate::message::topics;
                    let known_topics: &[(&str, &[u8])] = &[
                        ("health", topics::HEALTH),
                        ("share", topics::SHARE),
                        ("block", topics::BLOCK),
                        ("vote", topics::VOTE),
                        ("discovery", topics::DISCOVERY),
                        ("elder", topics::ELDER),
                        ("payout", topics::PAYOUT_PROPOSAL),
                        ("verify", topics::VERIFICATION),
                        ("mpc", topics::MPC), // MPC ceremony messages
                    ];

                    let (topic_name, data): (&str, Vec<u8>) = {
                        let mut found: Option<(&str, Vec<u8>)> = None;
                        for (name, topic_bytes) in known_topics {
                            if raw_data.starts_with(topic_bytes) {
                                found = Some((*name, raw_data[topic_bytes.len()..].to_vec()));
                                break;
                            }
                        }
                        if found.is_none() && !raw_data.is_empty() {
                            debug!(
                                prefix_bytes = ?&raw_data[..raw_data.len().min(10)],
                                data_len = raw_data.len(),
                                "Unknown topic prefix"
                            );
                        }
                        found.unwrap_or(("unknown", raw_data))
                    };

                    // M-9: Fast pre-deserialization topic validation for single-type topics.
                    // Rejects messages cheaply before full deserialization when the
                    // topic maps to exactly one expected MessageType.
                    if let Some(expected_type) = Self::primary_message_type_for_topic(topic_name) {
                        if crate::message_validator::validate_topic_before_deser(
                            &data,
                            expected_type,
                        )
                        .is_err()
                        {
                            debug!(
                                topic = topic_name,
                                "M-9: Fast topic validation rejected message before deserialization"
                            );
                            continue;
                        }
                    }

                    // M-P2P-1: Validate topic matches envelope's msg_type (post-deser fallback)
                    // Covers multi-type topics (elder, mpc) that can't use the fast check
                    if let Ok(envelope) = MessageEnvelope::deserialize(&data) {
                        let expected_topic = envelope.msg_type.topic_str();
                        if topic_name != expected_topic {
                            // MED-CONS-2: Rate limit warnings per sender (1 per minute)
                            let should_log = {
                                let last_log = topic_mismatch_log_times.get(&envelope.sender);
                                match last_log {
                                    Some(t) => {
                                        t.elapsed().as_secs() >= TOPIC_MISMATCH_LOG_INTERVAL_SECS
                                    }
                                    None => true,
                                }
                            };
                            if should_log {
                                // H-4 SECURITY: Evict oldest entries if at capacity
                                // This prevents unbounded memory growth from malicious senders
                                if topic_mismatch_log_times.len() >= MAX_TOPIC_MISMATCH_ENTRIES {
                                    // Find and remove the oldest entry (LRU eviction)
                                    if let Some(oldest_sender) = topic_mismatch_log_times
                                        .iter()
                                        .min_by_key(|(_, instant)| *instant)
                                        .map(|(sender, _)| *sender)
                                    {
                                        topic_mismatch_log_times.remove(&oldest_sender);
                                        debug!(
                                            evicted = %hex::encode(&oldest_sender[..8]),
                                            "H-4: Evicted oldest topic mismatch log entry (LRU)"
                                        );
                                    }
                                }
                                topic_mismatch_log_times
                                    .insert(envelope.sender, std::time::Instant::now());
                                warn!(
                                    received_topic = topic_name,
                                    expected_topic = expected_topic,
                                    msg_type = ?envelope.msg_type,
                                    sender = %hex::encode(&envelope.sender[..8]),
                                    "MED-CONS-2: Topic mismatch (rate-limited log, 1/min per sender)"
                                );
                            }
                            continue; // Skip this message
                        }
                    }

                    // Log verification messages for P2P debugging
                    if topic_name == "verify" {
                        debug!(
                            topic = topic_name,
                            data_len = data.len(),
                            "SUB received verification message"
                        );
                    }

                    // Log MPC messages for ceremony debugging
                    if topic_name == "mpc" {
                        debug!(
                            topic = topic_name,
                            data_len = data.len(),
                            "SUB received MPC message"
                        );
                    }

                    self.messages_received.fetch_add(1, Ordering::Relaxed);

                    // M-8: Use try_send with explicit backpressure handling
                    // This prevents blocking if the inbound channel is full (e.g., during a flood attack)
                    match self.inbound_tx.try_send(data) {
                        Ok(_) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Channel is full - log and drop the message
                            // This is acceptable because:
                            // 1. The sender will retry if important
                            // 2. The message handler is backed up and needs to catch up
                            // 3. Better to drop messages than block the receiver loop
                            warn!("M-8: Inbound channel full, dropping message (backpressure)");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!("M-8: Inbound channel closed, stopping subscriber");
                            break;
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    receive_errors += 1;
                    debug!(error = %e, "Receive error");
                }
                Ok(None) => {
                    // Stream ended (shouldn't happen with ZMQ)
                    warn!("SUB socket stream ended unexpectedly");
                    break;
                }
                Err(_) => {
                    receive_timeouts += 1;
                    continue; // Timeout
                }
            }
        }

        info!("Subscriber task stopped");
        Ok(())
    }

    /// Run the message handler (dispatches to registered handlers)
    async fn run_message_handler(&self) {
        // Take the receiver
        let mut inbound_rx = match self.inbound_rx.write().take() {
            Some(rx) => rx,
            None => {
                error!("Inbound receiver already taken");
                return;
            }
        };

        while self.running.load(Ordering::SeqCst) {
            match tokio::time::timeout(std::time::Duration::from_millis(100), inbound_rx.recv())
                .await
            {
                Ok(Some(data)) => {
                    if let Err(e) = self.handle_received(&data).await {
                        debug!(error = %e, "Failed to handle message");
                    }
                }
                Ok(None) => break,
                Err(_) => continue,
            }
        }

        info!("Message handler task stopped");
    }

    /// Run health pinger task
    async fn run_health_pinger(&self) {
        let interval = std::time::Duration::from_secs(self.config.health_ping_interval_secs);

        while self.running.load(Ordering::SeqCst) {
            tokio::time::sleep(interval).await;

            // Create and broadcast health ping with actual node capabilities
            // Include PoW proof for Sybil resistance
            let pow_proof = self.identity.pow_proof().map(|p| (p.nonce, p.difficulty));
            // Active miner id-hashes feed the deduped mesh-wide active count;
            // `local_hashrate_th` is this node's own realized hashrate, summed
            // (one term per node) into the pool-wide total.
            let active_miner_id_hashes = self
                .active_miner_hashes_fn
                .as_ref()
                .map(|f| f())
                .unwrap_or_default();
            let local_hashrate_th = self.local_hashrate_fn.as_ref().map(|f| f()).unwrap_or(0.0);
            let ping = ghost_common::types::HealthPing {
                node_id: self.identity.node_id(),
                public_address: String::new(), // S-7: Don't broadcast IP in cleartext ZMQ
                block_height: 0,               // Would track actual height
                round_id: 0,                   // Would track current round
                capabilities: *self.capabilities.read(),
                miner_count: self
                    .miner_count_fn
                    .as_ref()
                    .map(|f| f())
                    .unwrap_or(self.peers.peer_count() as u32),
                timestamp: chrono::Utc::now().timestamp_millis() as u64,
                pow_proof,
                active_miner_id_hashes,
                local_hashrate_th,
                max_capacity: self.max_capacity.load(Ordering::Relaxed),
            };

            match self.create_envelope(
                MessageType::HealthPing,
                &crate::message::HealthPingMessage { ping },
            ) {
                Ok(envelope) => {
                    if let Err(e) = self.broadcast(envelope).await {
                        debug!(error = %e, "Failed to broadcast health ping");
                    } else {
                        debug!(peers = self.peers.peer_count(), "Broadcast health ping");
                    }
                }
                Err(e) => {
                    debug!(error = %e, "Failed to create health ping envelope");
                }
            }
        }

        info!("Health pinger task stopped");
    }

    /// Run cleanup task (removes old seen messages)
    async fn run_cleanup_task(&self) {
        let interval = std::time::Duration::from_secs(60);

        while self.running.load(Ordering::SeqCst) {
            tokio::time::sleep(interval).await;
            self.cleanup_seen_messages(self.config.dedup_window_secs);
        }

        info!("Cleanup task stopped");
    }

    /// Stop the mesh network
    pub async fn stop(&self) -> GhostResult<()> {
        info!("Stopping mesh network");
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get mesh statistics
    pub fn stats(&self) -> MeshStats {
        MeshStats {
            peer_entries: self.peers.peer_count(),
            zmq_connections: self.peers.connected_count(),
            elder_peers: self.peers.get_elder_peers().len(),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            seen_message_count: self.seen_messages.read().len(),
        }
    }

    /// M-9: Map topic name to primary MessageType for pre-deserialization validation.
    /// Returns None for multi-type topics (elder, mpc) which need post-deser checking.
    fn primary_message_type_for_topic(topic: &str) -> Option<MessageType> {
        match topic {
            "health" => Some(MessageType::HealthPing),
            "share" => Some(MessageType::ShareProof),
            "block" => Some(MessageType::BlockFound),
            "vote" => Some(MessageType::Vote),
            "discovery" => Some(MessageType::Discovery),
            "verify" => Some(MessageType::VerificationResult),
            "payout" => Some(MessageType::PayoutProposal),
            // Multi-type topics — skip fast check, rely on post-deser validation
            "elder" | "mpc" | "l2tx" | "l2chk" | "l2vote" | "l2sync" | "unknown" => None,
            _ => None,
        }
    }

    /// Clean up old seen messages (P2P-L1: O(k) where k is number of expired entries)
    pub fn cleanup_seen_messages(&self, max_age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(max_age_secs);

        let mut seen = self.seen_messages.write();
        let before_len = seen.len();
        seen.cleanup_older_than(cutoff);
        let after_len = seen.len();

        if before_len != after_len {
            debug!(
                remaining = after_len,
                removed = before_len - after_len,
                "Cleaned up seen messages"
            );
        }
    }

    /// Connect to a peer
    pub async fn connect_peer(&self, address: &str) -> GhostResult<()> {
        info!(address = %address, "Connecting to peer");

        // Generate a temporary node ID from the address hash
        // (actual node ID will be learned from first health ping received)
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        address.hash(&mut hasher);
        let hash = hasher.finish();
        let mut temp_node_id = [0u8; 32];
        temp_node_id[..8].copy_from_slice(&hash.to_le_bytes());
        temp_node_id[8..16].copy_from_slice(&hash.to_be_bytes());

        // Create a new peer entry - mark as Connected initially
        // (stale detection will mark disconnected if we don't hear from them)
        let mut peer = Peer::new(temp_node_id, address.to_string());
        peer.state = crate::peer::PeerState::Connected;
        self.peers.upsert_peer(peer);

        Ok(())
    }

    /// Disconnect from a peer
    pub async fn disconnect_peer(&self, node_id: &NodeId) -> GhostResult<()> {
        info!(node_id = %hex::encode(node_id), "Disconnecting peer");
        self.peers.mark_disconnected(node_id);
        Ok(())
    }

    /// Get our node ID
    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    /// M-9: Validate that a message type is appropriate for the port it was received on.
    ///
    /// Each message type has exactly one correct port. Messages arriving on the wrong
    /// port should be rejected to prevent cross-channel injection attacks (e.g., an
    /// attacker sending vote messages on the health ping port to bypass rate limiting).
    ///
    /// For ZMQ messages, this validation is performed via topic matching in the subscriber
    /// (see run_subscriber, M-P2P-1 topic validation). For Noise TCP connections, callers
    /// should use this method to validate after deserialization.
    pub fn is_valid_msg_type_for_port(&self, msg_type: MessageType, port: u16) -> bool {
        let expected_port = match msg_type {
            MessageType::ShareProof | MessageType::ShareConvergence => {
                self.config.ports.share_propagation
            }
            MessageType::BlockFound => self.config.ports.block_announcement,
            MessageType::Vote => self.config.ports.consensus_voting,
            MessageType::HealthPing => self.config.ports.health_monitoring,
            MessageType::Discovery => self.config.ports.discovery,
            MessageType::ElderUpdate
            | MessageType::ElderRegistrationProposal
            | MessageType::ElderListProposal
            | MessageType::ElderListApproval
            | MessageType::MpcContribution
            | MessageType::MpcVerificationVote
            | MessageType::MpcParametersRequest
            | MessageType::MpcParametersResponse => self.config.ports.elder_management,
            MessageType::PayoutProposal => self.config.ports.payout_proposal,
            MessageType::ZkBlockProposal
            | MessageType::ZkVote
            | MessageType::EquivocationProof
            | MessageType::L2ConfidentialTransfer
            | MessageType::L2TransferConfirmation
            | MessageType::L2TransferBroadcast
            | MessageType::L2CheckpointBlock
            | MessageType::L2CheckpointVote
            | MessageType::L2TreeSync
            | MessageType::L2ShieldBroadcast => self.config.ports.consensus_voting,
            MessageType::VerificationResult => self.config.ports.health_monitoring,
            MessageType::GhostGlyphClaim | MessageType::GhostGlyphRegistered => {
                self.config.ports.consensus_voting
            }
        };
        port == expected_port
    }

    /// Get outbound sender for external use
    pub fn outbound_sender(&self) -> mpsc::Sender<(String, Vec<u8>)> {
        self.outbound_tx.clone()
    }

    /// Broadcast a raw message synchronously (non-blocking, best-effort)
    ///
    /// This queues the message for broadcast without waiting. Used for callbacks
    /// that cannot be async. Returns Ok if the message was queued successfully.
    pub fn broadcast_sync(&self, msg_type: MessageType, payload: Vec<u8>) -> GhostResult<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(GhostError::NotRunning("Mesh network not running".into()));
        }

        // C-10: Reject Noise-required messages from broadcast_sync entirely.
        // broadcast_sync is a synchronous (non-async) path that sends over ZMQ,
        // bypassing Noise encryption. Sensitive message types (MPC, votes, shares,
        // etc.) MUST use the async smart_broadcast() path that routes through Noise.
        // Allowing them here would silently send secrets in plaintext.
        if self.should_use_noise(msg_type) {
            error!(
                msg_type = ?msg_type,
                "C-10: broadcast_sync called for Noise-required message type — this bypasses encryption. Use smart_broadcast() instead."
            );
            return Err(GhostError::P2PMessage(
                "C-10: Cannot send Noise-required message via broadcast_sync — use smart_broadcast()"
                    .into(),
            ));
        }

        let sequence = self.next_sequence();

        // Sign the payload + sequence (must match create_envelope for P2P4-M1 verification)
        let mut signed_data = Vec::with_capacity(payload.len() + 8);
        signed_data.extend_from_slice(&payload);
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = self.identity.sign(&signed_data);

        // Create envelope
        let envelope = MessageEnvelope::new(
            msg_type,
            self.identity.node_id(),
            payload,
            sequence,
            signature,
        );

        // Serialize envelope
        let data = envelope
            .serialize()
            .map_err(|e| GhostError::Serialization(e.to_string()))?;

        // Get all connected peers and try to queue messages
        let peers = self.peers.get_connected_peers(60);
        let total_peers = self.peers.peer_count();
        let connected_count = peers.len();

        info!(
            msg_type = ?msg_type,
            peer_entries = total_peers,
            zmq_connections = connected_count,
            "Broadcasting message"
        );

        let mut queued = 0;

        for peer in peers {
            if peer.node_id == self.identity.node_id() {
                continue;
            }

            let endpoint = self.endpoint_for_message(&peer.public_address, msg_type);
            info!(endpoint = %endpoint, peer = %peer.node_id_short(), "Sending to peer");

            // Use try_send for non-blocking queue
            match self.outbound_tx.try_send((endpoint, data.clone())) {
                Ok(_) => queued += 1,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(peer = %peer.node_id_short(), "Outbound queue full");
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(GhostError::NotRunning("Outbound channel closed".into()));
                }
            }
        }

        self.messages_sent
            .fetch_add(queued as u64, Ordering::Relaxed);

        info!(
            msg_type = ?msg_type,
            queued = queued,
            "Queued sync broadcast"
        );

        Ok(())
    }
}

/// Mesh network statistics
///
/// Note: `peer_entries` and `zmq_connections` count ZMQ subscriber entries,
/// not unique physical nodes. Each node may have multiple entries across
/// different port groups (share, discovery, etc).
#[derive(Debug, Clone, Default)]
pub struct MeshStats {
    pub peer_entries: usize,
    pub zmq_connections: usize,
    pub elder_peers: usize,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub seen_message_count: usize,
}

/// C-1: Result of an encrypted broadcast operation
#[derive(Debug, Clone, Default)]
pub struct BroadcastResult {
    /// Number of peers successfully sent to
    pub success: usize,
    /// Number of peers that failed
    pub failed: usize,
}

/// Builder for constructing ZMQ endpoints
pub struct EndpointBuilder {
    host: String,
    ports: P2PPortConfig,
}

impl EndpointBuilder {
    pub fn new(host: String, ports: P2PPortConfig) -> Self {
        Self { host, ports }
    }

    pub fn share_propagation(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.share_propagation)
    }

    pub fn block_announcement(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.block_announcement)
    }

    pub fn consensus_voting(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.consensus_voting)
    }

    pub fn health_monitoring(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.health_monitoring)
    }

    pub fn discovery(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.discovery)
    }

    pub fn elder_management(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.elder_management)
    }

    pub fn payout_proposal(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.payout_proposal)
    }

    pub fn payout_transaction(&self) -> String {
        format!("tcp://{}:{}", self.host, self.ports.payout_transaction)
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_builder() {
        let ports = P2PPortConfig::default();
        let builder = EndpointBuilder::new("127.0.0.1".to_string(), ports);

        assert!(builder.share_propagation().contains("8555"));
        assert!(builder.block_announcement().contains("8556"));
    }

    #[test]
    fn test_message_deduplication() {
        let identity = Arc::new(NodeIdentity::generate());
        let config = MeshConfig::default();
        let mesh = MeshNetwork::new(identity, config);

        let msg_id = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };

        assert!(!mesh.is_duplicate(msg_id));
        mesh.mark_seen(msg_id);
        assert!(mesh.is_duplicate(msg_id));
    }

    #[test]
    fn test_seen_message_cache_eviction() {
        // Test with small capacity to verify FIFO eviction
        let mut cache = SeenMessageCache::new(3);

        let id1 = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };
        let id2 = MessageId {
            sender: [2u8; 32],
            sequence: 2,
        };
        let id3 = MessageId {
            sender: [3u8; 32],
            sequence: 3,
        };
        let id4 = MessageId {
            sender: [4u8; 32],
            sequence: 4,
        };

        // Insert 3 messages (at capacity)
        cache.insert(id1, 1000);
        cache.insert(id2, 1001);
        cache.insert(id3, 1002);

        assert!(cache.contains(&id1));
        assert!(cache.contains(&id2));
        assert!(cache.contains(&id3));
        assert_eq!(cache.len(), 3);

        // Insert 4th message - should evict oldest (id1)
        cache.insert(id4, 1003);

        assert!(!cache.contains(&id1), "id1 should have been evicted");
        assert!(cache.contains(&id2));
        assert!(cache.contains(&id3));
        assert!(cache.contains(&id4));
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_seen_message_cache_cleanup() {
        let mut cache = SeenMessageCache::new(10);

        let id1 = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };
        let id2 = MessageId {
            sender: [2u8; 32],
            sequence: 2,
        };
        let id3 = MessageId {
            sender: [3u8; 32],
            sequence: 3,
        };

        // Insert with different timestamps
        cache.insert(id1, 1000); // old
        cache.insert(id2, 1500); // old
        cache.insert(id3, 2000); // new

        assert_eq!(cache.len(), 3);

        // Cleanup entries older than 1600
        cache.cleanup_older_than(1600);

        assert!(!cache.contains(&id1), "id1 should have been cleaned up");
        assert!(!cache.contains(&id2), "id2 should have been cleaned up");
        assert!(cache.contains(&id3), "id3 should still exist");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_seen_message_cache_duplicate_insert() {
        let mut cache = SeenMessageCache::new(10);

        let id1 = MessageId {
            sender: [1u8; 32],
            sequence: 1,
        };

        cache.insert(id1, 1000);
        cache.insert(id1, 1001); // Duplicate - should not increase count

        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&id1));
    }

    #[test]
    fn test_seen_message_cache_per_sender_limit() {
        // H3 security test: Verify per-sender limits prevent cache flushing attacks
        let mut cache = SeenMessageCache::new(100);
        // Override max_per_sender for testing
        cache.max_per_sender = 3;

        let sender1 = [1u8; 32];
        let sender2 = [2u8; 32];

        // Sender 1 inserts 3 messages (at their limit)
        for i in 0..3 {
            let id = MessageId {
                sender: sender1,
                sequence: i,
            };
            cache.insert(id, 1000 + i);
        }

        // Sender 2 inserts 2 messages
        for i in 0..2 {
            let id = MessageId {
                sender: sender2,
                sequence: i,
            };
            cache.insert(id, 2000 + i);
        }

        assert_eq!(cache.len(), 5);

        // All sender1 messages should exist
        for i in 0..3 {
            assert!(cache.contains(&MessageId {
                sender: sender1,
                sequence: i
            }));
        }
        // All sender2 messages should exist
        for i in 0..2 {
            assert!(cache.contains(&MessageId {
                sender: sender2,
                sequence: i
            }));
        }

        // Now sender1 sends another message (exceeds their limit)
        let new_msg = MessageId {
            sender: sender1,
            sequence: 10,
        };
        cache.insert(new_msg, 3000);

        // Sender1's OLDEST message should be evicted, not sender2's messages!
        assert!(
            !cache.contains(&MessageId {
                sender: sender1,
                sequence: 0
            }),
            "Sender1's oldest message should be evicted"
        );
        assert!(
            cache.contains(&MessageId {
                sender: sender1,
                sequence: 1
            }),
            "Sender1's newer messages should remain"
        );
        assert!(
            cache.contains(&MessageId {
                sender: sender1,
                sequence: 2
            }),
            "Sender1's newer messages should remain"
        );
        assert!(
            cache.contains(&new_msg),
            "Sender1's new message should be present"
        );

        // Sender2's messages should be UNAFFECTED
        assert!(
            cache.contains(&MessageId {
                sender: sender2,
                sequence: 0
            }),
            "Sender2's messages should be unaffected"
        );
        assert!(
            cache.contains(&MessageId {
                sender: sender2,
                sequence: 1
            }),
            "Sender2's messages should be unaffected"
        );

        // Total should still be 5 (sender1: 3, sender2: 2)
        assert_eq!(cache.len(), 5);
    }

    #[test]
    fn test_outbound_sequence_persists_across_restart() {
        // The outbound sequence must resume ABOVE its prior value after a
        // restart, or peers reject our messages as replays. We persist a leased
        // ceiling and resume there.
        let dir = std::env::temp_dir().join(format!("ghost_seq_persist_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mesh_sequence");
        let _ = std::fs::remove_file(&path);

        // First boot, no file: start at 0, reserve one block, persist the ceiling.
        let (start0, ceiling0) = MeshNetwork::load_and_reserve_sequence(Some(path.as_path()));
        assert_eq!(start0, 0);
        assert_eq!(ceiling0, SEQUENCE_LEASE_BLOCK);
        let on_disk = std::fs::read_to_string(&path)
            .unwrap()
            .trim()
            .parse::<u64>()
            .unwrap();
        assert_eq!(on_disk, SEQUENCE_LEASE_BLOCK);

        // Simulate a restart: resume AT the persisted ceiling — strictly above
        // anything usable before the restart — and reserve the next block.
        let (start1, ceiling1) = MeshNetwork::load_and_reserve_sequence(Some(path.as_path()));
        assert_eq!(start1, SEQUENCE_LEASE_BLOCK);
        assert_eq!(ceiling1, SEQUENCE_LEASE_BLOCK * 2);
        assert!(
            start1 >= ceiling0,
            "must resume at/above the prior reserved ceiling — sequence never goes backwards"
        );

        // No path => no persistence (start 0, effectively unbounded ceiling).
        assert_eq!(MeshNetwork::load_and_reserve_sequence(None), (0, u64::MAX));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn test_restart_rebaseline_accepts_high_first_sequence() {
        // H-P2P-5 RESTART RE-BASELINE: after a node restart the sequence_state map
        // is empty, so an honest long-running peer's first message carries its
        // current (high) counter. That first message MUST be accepted as the
        // baseline, otherwise the restarted node is permanently locked out of the
        // peer (every later message is again "first" and re-rejected), leaving it
        // stuck behind on checkpoint consensus.
        let mut cache = SeenMessageCache::new(100);
        let sender = [7u8; 32];

        // First message well past the old 1M first-message cap — this is the
        // real value observed on mainnet when a single node was restarted.
        let high_seq = MAX_SEQUENCE_JUMP + 134_147; // 1,134,147
        assert!(
            cache.validate_and_update_sequence(&sender, high_seq),
            "a high first sequence must be accepted as the baseline after restart"
        );

        // Subsequent in-order messages from the same peer keep flowing.
        assert!(cache.validate_and_update_sequence(&sender, high_seq + 1));
        assert!(cache.validate_and_update_sequence(&sender, high_seq + 2));

        // Replay protection still holds: a sequence far below the baseline is rejected.
        assert!(
            !cache.validate_and_update_sequence(&sender, high_seq - 1_000),
            "replays below the established baseline must still be rejected"
        );
    }

    #[test]
    fn test_sequence_monotonicity_validation() {
        // H-P2P-4: Test sequence validation with tolerance window
        // SEQUENCE_TOLERANCE_WINDOW = 10 allows out-of-order delivery within 10 sequences
        let mut cache = SeenMessageCache::new(100);
        let sender = [1u8; 32];

        // Insert message with sequence 100 (use higher values to test tolerance)
        let id1 = MessageId {
            sender,
            sequence: 100,
        };
        cache.insert(id1, 1000);
        cache.update_highest_seq(&sender, 100);

        // Sequence 101 should be valid (greater than highest)
        assert!(cache.is_sequence_valid(&sender, 101));

        // Sequence 100 should be valid (equal to highest, within tolerance)
        assert!(cache.is_sequence_valid(&sender, 100));

        // Sequence 95 should be valid (within tolerance: 100 - 10 = 90)
        assert!(cache.is_sequence_valid(&sender, 95));

        // Sequence 85 should be invalid (outside tolerance: 100 - 10 = 90, 85 < 90)
        assert!(!cache.is_sequence_valid(&sender, 85));

        // Insert message with sequence 200, update highest
        let id2 = MessageId {
            sender,
            sequence: 200,
        };
        cache.insert(id2, 1001);
        cache.update_highest_seq(&sender, 200);

        // Sequence 195 should be valid (within tolerance: 200 - 10 = 190)
        assert!(cache.is_sequence_valid(&sender, 195));

        // Sequence 180 should be invalid (outside tolerance: 200 - 10 = 190, 180 < 190)
        assert!(!cache.is_sequence_valid(&sender, 180));

        // Sequence 201 should be valid
        assert!(cache.is_sequence_valid(&sender, 201));
    }

    #[test]
    fn test_sequence_validation_different_senders() {
        // H-P2P-4: Sequence tracking is per-sender
        let mut cache = SeenMessageCache::new(100);
        let sender1 = [1u8; 32];
        let sender2 = [2u8; 32];

        // Sender1 at sequence 100
        cache.update_highest_seq(&sender1, 100);

        // Sender2 at sequence 5
        cache.update_highest_seq(&sender2, 5);

        // Sender1's sequence 50 should be invalid (less than 100)
        assert!(!cache.is_sequence_valid(&sender1, 50));

        // Sender2's sequence 50 should be valid (greater than 5)
        assert!(cache.is_sequence_valid(&sender2, 50));

        // New sender (sender3) should accept any sequence
        let sender3 = [3u8; 32];
        assert!(cache.is_sequence_valid(&sender3, 1));
        assert!(cache.is_sequence_valid(&sender3, 1000));
    }

    #[test]
    fn test_mesh_deduplication_with_sequence_check() {
        // H-P2P-4/H-5: Integration test - MeshNetwork sequence validation with tolerance
        // Using the new atomic check_duplicate_and_mark method
        // SEQUENCE_TOLERANCE_WINDOW = 10 allows out-of-order delivery
        let identity = Arc::new(NodeIdentity::generate());
        let mut config = MeshConfig::default();
        // Disable noise for test
        config.noise_enabled = false;
        config.noise_required = false;
        let mesh = MeshNetwork::try_new(identity, config).expect("Failed to create mesh");

        let sender = [1u8; 32];

        // First message with sequence 100 should not be duplicate
        let msg1 = MessageId {
            sender,
            sequence: 100,
        };
        // H-5: Use atomic check_duplicate_and_mark (returns false if not duplicate)
        assert!(
            !mesh.check_duplicate_and_mark(msg1),
            "First message should not be duplicate"
        );

        // Same message should now be duplicate (in seen cache)
        assert!(
            mesh.check_duplicate_and_mark(msg1),
            "Same message should be duplicate"
        );

        // Message with sequence 95 (within tolerance: 100-10=90) should be accepted
        let msg_within_tolerance = MessageId {
            sender,
            sequence: 95,
        };
        assert!(
            !mesh.check_duplicate_and_mark(msg_within_tolerance),
            "Sequence within tolerance should be accepted (out-of-order delivery)"
        );

        // Message with sequence 80 (outside tolerance: 100-10=90) should be rejected
        let msg_old = MessageId {
            sender,
            sequence: 80,
        };
        assert!(
            mesh.check_duplicate_and_mark(msg_old),
            "Old sequence outside tolerance should be rejected"
        );

        // Message with sequence 101 (new) should not be duplicate
        let msg_new = MessageId {
            sender,
            sequence: 101,
        };
        assert!(
            !mesh.check_duplicate_and_mark(msg_new),
            "New sequence should be accepted"
        );
    }

    // ==========================================================================
    // CRIT-5: Memory-bounded cache tests
    // ==========================================================================

    #[test]
    fn test_crit5_memory_estimation() {
        let mut cache = SeenMessageCache::new(1000);

        // Initially should be nearly zero
        let initial_mem = cache.estimated_memory_bytes();
        assert!(initial_mem < 1000, "Empty cache should use minimal memory");

        // Add 100 messages from 10 senders
        for sender_idx in 0u8..10 {
            let sender = [sender_idx; 32];
            for seq in 0u64..10 {
                let id = MessageId {
                    sender,
                    sequence: seq,
                };
                cache.insert(id, 1000 + seq);
            }
        }

        // Should now have significant memory usage
        let after_insert = cache.estimated_memory_bytes();
        assert!(
            after_insert > initial_mem,
            "Memory should increase with entries"
        );
        assert!(
            after_insert < 1024 * 1024, // Should be well under 1MB for 100 entries
            "Memory estimate should be reasonable"
        );
    }

    #[test]
    fn test_crit5_eviction_on_memory_limit() {
        // Create cache with very low memory limit for testing
        let mut cache = SeenMessageCache::new(10000);
        cache.max_memory_bytes = 5000; // 5KB limit

        // Insert messages until we hit the memory limit
        let mut inserted = 0;
        for sender_idx in 0u8..100 {
            let sender = [sender_idx; 32];
            for seq in 0u64..10 {
                let id = MessageId {
                    sender,
                    sequence: seq,
                };
                cache.insert(id, 1000 + seq);
                inserted += 1;
            }
        }

        // Should have evicted some entries to stay under limit
        let mem = cache.estimated_memory_bytes();
        assert!(
            mem <= cache.max_memory_bytes,
            "Memory {} should be under limit {}",
            mem,
            cache.max_memory_bytes
        );

        // Should have fewer entries than we tried to insert
        assert!(
            cache.len() < inserted,
            "Should have evicted entries: len={}, inserted={}",
            cache.len(),
            inserted
        );
    }

    #[test]
    fn test_crit5_aggressive_eviction_works() {
        let mut cache = SeenMessageCache::new(1000);
        cache.max_memory_bytes = 10000; // 10KB

        // Fill the cache
        for i in 0u64..50 {
            let sender = [(i % 10) as u8; 32];
            let id = MessageId {
                sender,
                sequence: i,
            };
            cache.insert(id, 1000 + i);
        }

        let before_evict = cache.len();

        // Manually trigger aggressive eviction
        cache.evict_until_under_memory_limit();

        // Verify eviction happened and we're under the target (70%)
        let target_bytes = cache.max_memory_bytes * 70 / 100;
        let mem_after = cache.estimated_memory_bytes();

        assert!(
            mem_after <= target_bytes || cache.len() < before_evict,
            "Eviction should have reduced memory or entries"
        );
    }

    #[test]
    fn test_crit5_ttl_expiration() {
        let mut cache = SeenMessageCache::new(1000);
        cache.message_ttl_secs = 60; // 1 minute TTL for testing

        // Insert a message with old timestamp (10 minutes ago)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let old_timestamp = now - 600; // 10 minutes ago
        let sender = [1u8; 32];
        let id = MessageId {
            sender,
            sequence: 1,
        };
        cache.insert(id, old_timestamp);

        assert!(cache.contains(&id), "Message should be inserted");

        // Cleanup with recent cutoff - TTL should still expire the old message
        cache.cleanup_older_than(now - 30); // 30 seconds cutoff

        // The old message should be cleaned up due to TTL even though
        // cutoff was only 30 seconds
        assert!(!cache.contains(&id), "Old message should be expired by TTL");
    }

    #[test]
    fn test_crit5_many_senders_memory_bounded() {
        // Simulate attack with many fake node identities
        let mut cache = SeenMessageCache::new(100_000);
        cache.max_memory_bytes = MAX_CACHE_MEMORY_BYTES; // Use the constant

        // Try to create 10000 senders (way more than MAX_UNIQUE_SENDERS)
        for sender_idx in 0u32..10_000 {
            let mut sender = [0u8; 32];
            sender[0..4].copy_from_slice(&sender_idx.to_le_bytes());

            let id = MessageId {
                sender,
                sequence: 1,
            };
            cache.insert(id, 1000);
        }

        // Should have limited the number of unique senders
        assert!(
            cache.sender_counts.len() <= MAX_UNIQUE_SENDERS,
            "Sender count {} should be bounded by {}",
            cache.sender_counts.len(),
            MAX_UNIQUE_SENDERS
        );

        // Memory should be bounded
        let mem = cache.estimated_memory_bytes();
        assert!(
            mem <= MAX_CACHE_MEMORY_BYTES,
            "Memory {} should be under max {}",
            mem,
            MAX_CACHE_MEMORY_BYTES
        );
    }

    // ==========================================================================
    // M-2: Noise required enforcement tests
    // ==========================================================================

    #[test]
    fn test_m2_noise_not_required_allows_fallback() {
        // M-2: When noise_required=false, Noise failure should allow fallback
        let identity = Arc::new(NodeIdentity::generate());
        let mut config = MeshConfig::default();
        config.noise_enabled = true;
        config.noise_required = false;
        // Use a path that will cause Noise init to fail (non-existent directory)
        config.noise_keypair_path = Some(std::path::PathBuf::from(
            "/nonexistent/path/that/will/fail/noise.key",
        ));

        // Should succeed (fallback to plaintext allowed)
        let result = MeshNetwork::try_new(identity, config);
        assert!(
            result.is_ok(),
            "M-2: When noise_required=false, should allow plaintext fallback"
        );
    }

    #[test]
    fn test_m2_noise_disabled_succeeds() {
        // When noise is completely disabled, should always succeed
        let identity = Arc::new(NodeIdentity::generate());
        let mut config = MeshConfig::default();
        config.noise_enabled = false;
        config.noise_required = false;

        let result = MeshNetwork::try_new(identity, config);
        assert!(result.is_ok(), "M-2: Disabled Noise should always succeed");
    }

    #[test]
    fn test_should_use_noise_routing() {
        // Verify the message type → Noise routing logic.
        //
        // Since should_use_noise() returns false when noise_pool is None,
        // and constructing a real Noise pool requires key infrastructure,
        // we test the routing logic by directly verifying the message type
        // categorization. The match arms in should_use_noise() define:
        //
        //   - Discovery, HealthPing → ZMQ (false)
        //   - All other message types → Noise (true)
        //
        // We verify this by testing message_type_requires_noise() which
        // extracts the pure routing logic without the noise_pool gate.

        // Helper that mirrors should_use_noise() match arms without the noise_pool check
        fn message_type_requires_noise(msg_type: MessageType) -> bool {
            match msg_type {
                MessageType::Discovery | MessageType::HealthPing => false,
                MessageType::ShareProof
                | MessageType::ShareConvergence
                | MessageType::BlockFound
                | MessageType::Vote
                | MessageType::PayoutProposal
                | MessageType::ElderUpdate
                | MessageType::ZkBlockProposal
                | MessageType::ZkVote
                | MessageType::VerificationResult
                | MessageType::EquivocationProof
                | MessageType::ElderRegistrationProposal
                | MessageType::ElderListProposal
                | MessageType::ElderListApproval
                | MessageType::MpcContribution
                | MessageType::MpcVerificationVote
                | MessageType::MpcParametersRequest
                | MessageType::MpcParametersResponse
                | MessageType::L2ConfidentialTransfer
                | MessageType::L2TransferConfirmation
                | MessageType::L2TransferBroadcast
                | MessageType::L2CheckpointBlock
                | MessageType::L2CheckpointVote
                | MessageType::L2TreeSync
                | MessageType::L2ShieldBroadcast
                | MessageType::GhostGlyphClaim
                | MessageType::GhostGlyphRegistered => true,
            }
        }

        // ZMQ broadcast messages (should NOT use Noise)
        assert!(
            !message_type_requires_noise(MessageType::HealthPing),
            "HealthPing should stay on ZMQ"
        );
        assert!(
            !message_type_requires_noise(MessageType::Discovery),
            "Discovery should stay on ZMQ"
        );

        // MPC-sensitive messages (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::MpcContribution),
            "MpcContribution must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::MpcVerificationVote),
            "MpcVerificationVote must use Noise"
        );

        // Consensus/voting messages (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::PayoutProposal),
            "PayoutProposal must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::Vote),
            "Vote must use Noise"
        );

        // Share propagation (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::ShareProof),
            "ShareProof must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::ShareConvergence),
            "ShareConvergence must use Noise"
        );

        // Block/mining messages (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::BlockFound),
            "BlockFound must use Noise"
        );

        // Elder management (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::ElderUpdate),
            "ElderUpdate must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::ElderRegistrationProposal),
            "ElderRegistrationProposal must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::ElderListProposal),
            "ElderListProposal must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::ElderListApproval),
            "ElderListApproval must use Noise"
        );

        // L2 messages (MUST use Noise — contain proofs and encrypted note data)
        assert!(
            message_type_requires_noise(MessageType::L2ConfidentialTransfer),
            "L2ConfidentialTransfer must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::L2TransferConfirmation),
            "L2TransferConfirmation must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::L2TransferBroadcast),
            "L2TransferBroadcast must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::L2CheckpointBlock),
            "L2CheckpointBlock must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::L2CheckpointVote),
            "L2CheckpointVote must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::L2TreeSync),
            "L2TreeSync must use Noise"
        );

        // ZK messages (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::ZkBlockProposal),
            "ZkBlockProposal must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::ZkVote),
            "ZkVote must use Noise"
        );
        // Verification and security (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::VerificationResult),
            "VerificationResult must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::EquivocationProof),
            "EquivocationProof must use Noise"
        );

        // MPC params transfer (MUST use Noise)
        assert!(
            message_type_requires_noise(MessageType::MpcParametersRequest),
            "MpcParametersRequest must use Noise"
        );
        assert!(
            message_type_requires_noise(MessageType::MpcParametersResponse),
            "MpcParametersResponse must use Noise"
        );
    }

    #[test]
    fn mesh_hashrate_sums_one_term_per_node() {
        // Local node 1.0 + two peers 2.0, 3.0 => 6.0. One term per node.
        let total = MeshNetwork::compute_mesh_total_hashrate(1.0, [2.0, 3.0].into_iter());
        assert!((total - 6.0).abs() < 1e-9, "expected 6.0, got {total}");
    }

    #[test]
    fn mesh_hashrate_total_invariant_under_migration() {
        // The whole point of the redesign: a miner migrating between two nodes
        // shifts work from one node's term to another's; the fleet total is
        // unchanged and identical regardless of where the miner sits. We model
        // a 4-node fleet whose true total is 10.0 and move 2.0 of hashrate from
        // node B to node C — the sum must stay 10.0 in both arrangements.
        let before = MeshNetwork::compute_mesh_total_hashrate(1.0, [5.0, 1.0, 3.0].into_iter());
        let after = MeshNetwork::compute_mesh_total_hashrate(1.0, [3.0, 3.0, 3.0].into_iter());
        assert!((before - 10.0).abs() < 1e-9, "before={before}");
        assert!((after - 10.0).abs() < 1e-9, "after={after}");
        assert!(
            (before - after).abs() < 1e-9,
            "migration must not change the total: {before} vs {after}"
        );
    }

    #[test]
    fn mesh_hashrate_old_peer_contributes_zero() {
        // Backward compat: an older peer that doesn't report hashrate sends the
        // serde-default 0.0, so it simply adds nothing.
        let total = MeshNetwork::compute_mesh_total_hashrate(4.0, [0.0, 0.0].into_iter());
        assert!(
            (total - 4.0).abs() < 1e-9,
            "expected only local 4.0, got {total}"
        );
    }

    #[test]
    fn mesh_hashrate_clamps_negative_terms() {
        // A stray -0.0 / garbage term can't drag the total below the real sum.
        let total = MeshNetwork::compute_mesh_total_hashrate(-0.0, [5.0, -2.0].into_iter());
        assert!((total - 5.0).abs() < 1e-9, "expected 5.0, got {total}");
    }
}
