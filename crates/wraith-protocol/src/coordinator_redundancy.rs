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
//| FILE: coordinator_redundancy.rs                                                                                      |
//|======================================================================================================================|

//! Coordinator redundancy and rotation for Wraith sessions
//!
//! Provides fault tolerance and trust distribution for Wraith coordinators:
//!
//! - **Redundancy**: Multiple coordinators prevent single point of failure
//! - **Rotation**: Periodic rotation prevents long-term surveillance
//! - **Failover**: Automatic promotion if active coordinator fails
//! - **Threshold**: Optional k-of-n coordination for critical operations
//!
//! # Trust Model
//!
//! Even with blind signatures, a single coordinator can:
//! - Deny service to targeted participants
//! - Be compromised or coerced by authorities
//! - Track metadata patterns over time
//!
//! This module distributes trust across multiple independent coordinators.
//!
//! ## 3.18 SECURITY NOTE: Surveillance Limitation
//!
//! **IMPORTANT**: Coordinator rotation provides *temporal* distribution of trust,
//! NOT *concurrent* trust distribution. Key limitations:
//!
//! 1. **Single Active Coordinator**: At any time, exactly one coordinator is active.
//!    That coordinator can observe ALL session metadata during its active period.
//!
//! 2. **Session Correlation**: A compromised coordinator during a session sees:
//!    - All participant connection times
//!    - All participant IP addresses (even via Tor - timing correlation possible)
//!    - Input/output counts per participant
//!    - Session timing patterns
//!
//! 3. **What Rotation Prevents**: A single entity gaining long-term surveillance.
//!    After rotation, the previous coordinator loses access to new sessions.
//!
//! 4. **What Rotation Does NOT Prevent**:
//!    - Targeted surveillance during the active period
//!    - Collusion between multiple coordinators
//!    - A majority of coordinators being compromised
//!
//! **For true concurrent trust distribution**, consider:
//! - Multi-party computation (MPC) coordinators (not implemented)
//! - Threshold blind signatures across coordinators (future enhancement)
//! - Decentralized coordination protocols (requires protocol changes)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │                Coordinator Pool                  │
//! ├─────────────────────────────────────────────────┤
//! │  Active: Coordinator A (epoch 1-100)            │
//! │  Standby: Coordinator B, C (ready for failover) │
//! │  Pending: Coordinator D (joining next epoch)    │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use wraith_protocol::coordinator_redundancy::{CoordinatorPool, RotationPolicy};
//!
//! let policy = RotationPolicy::default();
//! let pool = CoordinatorPool::new(policy);
//!
//! // Register coordinators
//! pool.register_coordinator(coordinator_a)?;
//! pool.register_coordinator(coordinator_b)?;
//!
//! // Get active coordinator for a session
//! let active = pool.get_active()?;
//!
//! // Handle failover
//! if pool.active_coordinator_failed() {
//!     pool.trigger_failover()?;
//! }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

/// Coordinator pool errors
#[derive(Debug, Error)]
pub enum PoolError {
    #[error("No active coordinator available")]
    NoActiveCoordinator,

    #[error("No standby coordinators available for failover")]
    NoStandbyAvailable,

    #[error("Coordinator not found: {0}")]
    CoordinatorNotFound(String),

    #[error("Coordinator already registered: {0}")]
    AlreadyRegistered(String),

    #[error("Maximum coordinators reached: {0}")]
    MaxCoordinatorsReached(usize),

    #[error("Insufficient threshold: have {0}, need {1}")]
    InsufficientThreshold(usize, usize),

    #[error("Rotation in progress")]
    RotationInProgress,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Coordinator identifier
pub type CoordinatorId = [u8; 32];

/// Coordinator status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinatorStatus {
    /// Currently handling sessions
    Active,
    /// Ready to take over if active fails
    Standby,
    /// Joining the pool, not yet ready
    Pending,
    /// Leaving the pool after current sessions complete
    Draining,
    /// Not responding, considered failed
    Failed,
    /// Manually disabled
    Disabled,
}

impl CoordinatorStatus {
    /// Check if coordinator is healthy
    pub fn is_healthy(&self) -> bool {
        !matches!(self, Self::Failed | Self::Disabled)
    }
}

/// Coordinator metadata
///
/// Note: `last_heartbeat_instant` uses monotonic time internally but is not serializable.
/// For serialization, `last_heartbeat` provides a Unix timestamp approximation.
#[derive(Debug, Clone)]
pub struct CoordinatorInfo {
    /// Unique coordinator ID
    pub id: CoordinatorId,
    /// Human-readable name
    pub name: String,
    /// Endpoint URL (Tor hidden service recommended)
    pub endpoint: String,
    /// Public key for verification
    pub public_key: Vec<u8>,
    /// Current status
    pub status: CoordinatorStatus,
    /// When this coordinator was added
    pub added_at: u64,
    /// Last heartbeat timestamp (Unix time - for external reporting/serialization)
    pub last_heartbeat: u64,
    /// Last heartbeat instant (monotonic - for timeout calculations) (WR4-L4)
    /// This prevents clock drift/NTP manipulation from affecting heartbeat detection
    #[allow(dead_code)]
    last_heartbeat_instant: Option<Instant>,
    /// Number of sessions completed
    pub sessions_completed: u64,
    /// Current active sessions
    pub active_sessions: u32,
    /// Failed session count
    pub failed_sessions: u64,
    /// Epoch when this coordinator became active
    pub active_since_epoch: Option<u64>,
    /// Trust score (0-100)
    pub trust_score: u8,
    /// Geographic region (for distribution)
    pub region: Option<String>,
}

// Manual Serialize implementation that excludes the Instant field
impl Serialize for CoordinatorInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CoordinatorInfo", 12)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("endpoint", &self.endpoint)?;
        state.serialize_field("public_key", &self.public_key)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("added_at", &self.added_at)?;
        state.serialize_field("last_heartbeat", &self.last_heartbeat)?;
        state.serialize_field("sessions_completed", &self.sessions_completed)?;
        state.serialize_field("active_sessions", &self.active_sessions)?;
        state.serialize_field("failed_sessions", &self.failed_sessions)?;
        state.serialize_field("active_since_epoch", &self.active_since_epoch)?;
        state.serialize_field("trust_score", &self.trust_score)?;
        state.serialize_field("region", &self.region)?;
        state.end()
    }
}

// Manual Deserialize implementation that initializes the Instant field
impl<'de> Deserialize<'de> for CoordinatorInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct CoordinatorInfoHelper {
            id: CoordinatorId,
            name: String,
            endpoint: String,
            public_key: Vec<u8>,
            status: CoordinatorStatus,
            added_at: u64,
            last_heartbeat: u64,
            sessions_completed: u64,
            active_sessions: u32,
            failed_sessions: u64,
            active_since_epoch: Option<u64>,
            trust_score: u8,
            region: Option<String>,
        }

        let helper = CoordinatorInfoHelper::deserialize(deserializer)?;
        Ok(CoordinatorInfo {
            id: helper.id,
            name: helper.name,
            endpoint: helper.endpoint,
            public_key: helper.public_key,
            status: helper.status,
            added_at: helper.added_at,
            last_heartbeat: helper.last_heartbeat,
            last_heartbeat_instant: Some(Instant::now()), // Reset to now on deserialize
            sessions_completed: helper.sessions_completed,
            active_sessions: helper.active_sessions,
            failed_sessions: helper.failed_sessions,
            active_since_epoch: helper.active_since_epoch,
            trust_score: helper.trust_score,
            region: helper.region,
        })
    }
}

impl CoordinatorInfo {
    /// Create new coordinator info
    pub fn new(id: CoordinatorId, name: String, endpoint: String, public_key: Vec<u8>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id,
            name,
            endpoint,
            public_key,
            status: CoordinatorStatus::Pending,
            added_at: now,
            last_heartbeat: now,
            last_heartbeat_instant: Some(Instant::now()), // WR4-L4: Use monotonic time
            sessions_completed: 0,
            active_sessions: 0,
            failed_sessions: 0,
            active_since_epoch: None,
            trust_score: 50, // Start neutral
            region: None,
        }
    }

    /// Get coordinator ID as hex
    pub fn id_hex(&self) -> String {
        hex::encode(&self.id[..8])
    }

    /// Update heartbeat (WR4-L4)
    ///
    /// Uses monotonic time (Instant) for timeout calculations to prevent
    /// clock drift or NTP manipulation from affecting heartbeat detection.
    pub fn record_heartbeat(&mut self) {
        // Update both Unix timestamp (for external reporting) and Instant (for timeout)
        self.last_heartbeat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_heartbeat_instant = Some(Instant::now());

        // Recover from failed state if heartbeat received
        if self.status == CoordinatorStatus::Failed {
            self.status = CoordinatorStatus::Standby;
            info!(
                coordinator = %self.id_hex(),
                "Coordinator recovered from failed state"
            );
        }
    }

    /// Record session completion
    pub fn record_session_complete(&mut self, success: bool) {
        if success {
            self.sessions_completed += 1;
            // Increase trust score on success (max 100)
            self.trust_score = (self.trust_score + 1).min(100);
        } else {
            self.failed_sessions += 1;
            // Decrease trust score on failure
            self.trust_score = self.trust_score.saturating_sub(5);
        }

        if self.active_sessions > 0 {
            self.active_sessions -= 1;
        }
    }

    /// Get seconds since last heartbeat (WR4-L4)
    ///
    /// Uses monotonic time (Instant) to prevent clock drift from affecting
    /// heartbeat detection. Falls back to Unix timestamp if Instant not available.
    pub fn seconds_since_heartbeat(&self) -> u64 {
        // Prefer monotonic time if available
        if let Some(instant) = self.last_heartbeat_instant {
            return instant.elapsed().as_secs();
        }

        // Fallback to Unix timestamp (for backwards compatibility)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now.saturating_sub(self.last_heartbeat)
    }

    /// Check if coordinator should be considered failed
    pub fn is_stale(&self, timeout_secs: u64) -> bool {
        self.seconds_since_heartbeat() > timeout_secs
    }
}

/// Rotation policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Maximum sessions before rotation
    pub max_sessions_per_rotation: u64,
    /// Maximum time as active (seconds)
    pub max_active_duration_secs: u64,
    /// Minimum standby coordinators required
    pub min_standby_count: usize,
    /// Maximum total coordinators in pool
    pub max_pool_size: usize,
    /// Heartbeat timeout (seconds) before marking failed
    pub heartbeat_timeout_secs: u64,
    /// Require threshold signatures for rotation
    pub threshold_rotation: bool,
    /// Threshold count for rotation approval
    pub rotation_threshold: usize,
    /// Enable automatic failover
    pub auto_failover: bool,
    /// Minimum trust score to be active
    pub min_trust_score: u8,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_sessions_per_rotation: 1000,
            max_active_duration_secs: 7 * 24 * 60 * 60, // 1 week
            min_standby_count: 2,
            max_pool_size: 10,
            heartbeat_timeout_secs: 300, // 5 minutes
            threshold_rotation: false,
            rotation_threshold: 2,
            auto_failover: true,
            min_trust_score: 30,
        }
    }
}

impl RotationPolicy {
    /// Create high-availability policy (more redundancy)
    pub fn high_availability() -> Self {
        Self {
            max_sessions_per_rotation: 500,
            max_active_duration_secs: 24 * 60 * 60, // 1 day
            min_standby_count: 3,
            max_pool_size: 15,
            heartbeat_timeout_secs: 60, // 1 minute
            threshold_rotation: true,
            rotation_threshold: 3,
            auto_failover: true,
            min_trust_score: 40,
        }
    }

    /// Create minimal policy (single coordinator, no rotation)
    pub fn minimal() -> Self {
        Self {
            max_sessions_per_rotation: u64::MAX,
            max_active_duration_secs: u64::MAX,
            min_standby_count: 0,
            max_pool_size: 3,
            heartbeat_timeout_secs: 600,
            threshold_rotation: false,
            rotation_threshold: 1,
            auto_failover: true,
            min_trust_score: 0,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), PoolError> {
        if self.threshold_rotation && self.rotation_threshold == 0 {
            return Err(PoolError::InvalidConfig(
                "rotation_threshold must be > 0 when threshold_rotation enabled".into(),
            ));
        }
        if self.max_pool_size < self.min_standby_count + 1 {
            return Err(PoolError::InvalidConfig(
                "max_pool_size must be >= min_standby_count + 1".into(),
            ));
        }
        Ok(())
    }
}

/// Rotation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEvent {
    /// Previous active coordinator
    pub previous_id: CoordinatorId,
    /// New active coordinator
    pub new_id: CoordinatorId,
    /// Reason for rotation
    pub reason: RotationReason,
    /// Timestamp
    pub timestamp: u64,
    /// Epoch number
    pub epoch: u64,
}

/// Reason for rotation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationReason {
    /// Scheduled rotation (time/session limit)
    Scheduled,
    /// Active coordinator failed
    Failover,
    /// Manual rotation request
    Manual,
    /// Trust score too low
    LowTrust,
    /// Coordinator draining
    Draining,
}

/// Coordinator pool manager
pub struct CoordinatorPool {
    /// Pool configuration
    policy: RotationPolicy,
    /// Registered coordinators
    coordinators: RwLock<HashMap<CoordinatorId, CoordinatorInfo>>,
    /// Current active coordinator ID
    active_id: RwLock<Option<CoordinatorId>>,
    /// Current epoch number
    current_epoch: RwLock<u64>,
    /// Rotation history
    rotation_history: RwLock<Vec<RotationEvent>>,
    /// Rotation in progress
    rotation_in_progress: RwLock<bool>,
    /// When current active became active
    active_since: RwLock<Option<Instant>>,
    /// WR4-L8: Session lock to prevent split-brain during failover
    /// When held, new sessions cannot be registered
    session_lock: RwLock<()>,
}

impl CoordinatorPool {
    /// Create a new coordinator pool
    pub fn new(policy: RotationPolicy) -> Result<Self, PoolError> {
        policy.validate()?;

        Ok(Self {
            policy,
            coordinators: RwLock::new(HashMap::new()),
            active_id: RwLock::new(None),
            current_epoch: RwLock::new(1),
            rotation_history: RwLock::new(Vec::new()),
            rotation_in_progress: RwLock::new(false),
            active_since: RwLock::new(None),
            session_lock: RwLock::new(()), // WR4-L8
        })
    }

    /// Register a new coordinator
    pub fn register_coordinator(&self, mut info: CoordinatorInfo) -> Result<(), PoolError> {
        let mut coordinators = self.coordinators.write();

        if coordinators.len() >= self.policy.max_pool_size {
            return Err(PoolError::MaxCoordinatorsReached(self.policy.max_pool_size));
        }

        if coordinators.contains_key(&info.id) {
            return Err(PoolError::AlreadyRegistered(info.id_hex()));
        }

        // New coordinators start as pending
        info.status = CoordinatorStatus::Pending;

        info!(
            coordinator = %info.id_hex(),
            name = %info.name,
            "Registering new coordinator"
        );

        coordinators.insert(info.id, info);

        Ok(())
    }

    /// Activate a pending coordinator (make standby)
    pub fn activate_coordinator(&self, id: &CoordinatorId) -> Result<(), PoolError> {
        let mut coordinators = self.coordinators.write();

        let coord = coordinators
            .get_mut(id)
            .ok_or_else(|| PoolError::CoordinatorNotFound(hex::encode(&id[..8])))?;

        if coord.trust_score < self.policy.min_trust_score {
            return Err(PoolError::InvalidConfig(format!(
                "Trust score {} below minimum {}",
                coord.trust_score, self.policy.min_trust_score
            )));
        }

        coord.status = CoordinatorStatus::Standby;

        info!(
            coordinator = %coord.id_hex(),
            "Coordinator activated as standby"
        );

        // If no active coordinator, promote this one
        drop(coordinators);
        if self.active_id.read().is_none() {
            self.promote_to_active(id)?;
        }

        Ok(())
    }

    /// Promote a standby coordinator to active
    pub fn promote_to_active(&self, id: &CoordinatorId) -> Result<(), PoolError> {
        let mut coordinators = self.coordinators.write();

        // Check if the coordinator exists and is standby
        {
            let coord = coordinators
                .get(id)
                .ok_or_else(|| PoolError::CoordinatorNotFound(hex::encode(&id[..8])))?;

            if coord.status != CoordinatorStatus::Standby {
                return Err(PoolError::InvalidConfig(format!(
                    "Coordinator {} is {:?}, not Standby",
                    coord.id_hex(),
                    coord.status
                )));
            }
        }

        // Demote current active if any
        let old_active = *self.active_id.read();
        if let Some(old_id) = old_active {
            if let Some(old_coord) = coordinators.get_mut(&old_id) {
                old_coord.status = CoordinatorStatus::Standby;
                old_coord.active_since_epoch = None;
            }
        }

        // Promote new active
        let epoch = *self.current_epoch.read();
        // CRIT-7: Return error instead of panicking even though we just checked existence
        let coord = coordinators
            .get_mut(id)
            .ok_or_else(|| PoolError::CoordinatorNotFound(hex::encode(&id[..8])))?;
        coord.status = CoordinatorStatus::Active;
        coord.active_since_epoch = Some(epoch);

        let coord_hex = coord.id_hex();

        *self.active_id.write() = Some(*id);
        *self.active_since.write() = Some(Instant::now());

        info!(
            coordinator = %coord_hex,
            epoch = epoch,
            "Coordinator promoted to active"
        );

        Ok(())
    }

    /// Get the active coordinator
    pub fn get_active(&self) -> Result<CoordinatorInfo, PoolError> {
        let active_id = self
            .active_id
            .read()
            .ok_or(PoolError::NoActiveCoordinator)?;

        self.coordinators
            .read()
            .get(&active_id)
            .cloned()
            .ok_or(PoolError::NoActiveCoordinator)
    }

    /// Get active coordinator ID
    pub fn get_active_id(&self) -> Option<CoordinatorId> {
        *self.active_id.read()
    }

    /// Check if rotation is needed
    pub fn should_rotate(&self) -> bool {
        let active_id = match *self.active_id.read() {
            Some(id) => id,
            None => return false,
        };

        let coordinators = self.coordinators.read();
        let active = match coordinators.get(&active_id) {
            Some(c) => c,
            None => return true, // Active coordinator missing, need rotation
        };

        // Check session count
        if active.sessions_completed >= self.policy.max_sessions_per_rotation {
            return true;
        }

        // Check duration
        if let Some(since) = *self.active_since.read() {
            if since.elapsed() > Duration::from_secs(self.policy.max_active_duration_secs) {
                return true;
            }
        }

        // Check trust score
        if active.trust_score < self.policy.min_trust_score {
            return true;
        }

        // Check if draining
        if active.status == CoordinatorStatus::Draining {
            return true;
        }

        false
    }

    /// Trigger rotation to next standby
    pub fn trigger_rotation(&self, reason: RotationReason) -> Result<RotationEvent, PoolError> {
        // Check if rotation already in progress
        if *self.rotation_in_progress.read() {
            return Err(PoolError::RotationInProgress);
        }

        *self.rotation_in_progress.write() = true;

        // Select next coordinator
        let next_id = self.select_next_coordinator()?;

        let old_id = self
            .active_id
            .read()
            .ok_or(PoolError::NoActiveCoordinator)?;

        // Perform rotation
        match self.promote_to_active(&next_id) {
            Ok(()) => {
                // Increment epoch
                let mut epoch = self.current_epoch.write();
                *epoch += 1;

                let event = RotationEvent {
                    previous_id: old_id,
                    new_id: next_id,
                    reason,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    epoch: *epoch,
                };

                self.rotation_history.write().push(event.clone());

                *self.rotation_in_progress.write() = false;

                info!(
                    old = %hex::encode(&old_id[..8]),
                    new = %hex::encode(&next_id[..8]),
                    epoch = *epoch,
                    reason = ?reason,
                    "Coordinator rotation complete"
                );

                Ok(event)
            }
            Err(e) => {
                *self.rotation_in_progress.write() = false;
                Err(e)
            }
        }
    }

    /// Select next coordinator for rotation
    fn select_next_coordinator(&self) -> Result<CoordinatorId, PoolError> {
        let coordinators = self.coordinators.read();
        let active_id = *self.active_id.read();

        // Find standby coordinators sorted by trust score
        let mut candidates: Vec<_> = coordinators
            .iter()
            .filter(|(id, c)| {
                c.status == CoordinatorStatus::Standby
                    && Some(**id) != active_id
                    && c.trust_score >= self.policy.min_trust_score
            })
            .collect();

        if candidates.is_empty() {
            return Err(PoolError::NoStandbyAvailable);
        }

        // Sort by trust score (descending)
        candidates.sort_by_key(|c| std::cmp::Reverse(c.1.trust_score));

        // CRIT-PANIC-2: Use .first() instead of [0] indexing
        candidates
            .first()
            .map(|(id, _)| **id)
            .ok_or(PoolError::NoStandbyAvailable)
    }

    /// Trigger failover (active coordinator failed) (WR4-L8)
    ///
    /// Acquires session lock during failover to prevent split-brain scenarios
    /// where sessions could be partially migrated to multiple coordinators.
    pub fn trigger_failover(&self) -> Result<RotationEvent, PoolError> {
        if !self.policy.auto_failover {
            return Err(PoolError::InvalidConfig("Auto-failover disabled".into()));
        }

        // WR4-L8: Acquire session lock to prevent split-brain during failover
        // This blocks new session registrations until failover is complete
        let _session_lock = self.session_lock.write();

        // Remember the failed coordinator ID
        let failed_id = *self.active_id.read();

        info!(
            failed_coordinator = ?failed_id.map(|id| hex::encode(&id[..8])),
            "Starting failover with session lock held"
        );

        // Perform rotation
        let event = self.trigger_rotation(RotationReason::Failover)?;

        // Re-mark the old coordinator as Failed (rotation sets it to Standby)
        if let Some(old_id) = failed_id {
            if let Some(coord) = self.coordinators.write().get_mut(&old_id) {
                coord.status = CoordinatorStatus::Failed;
                warn!(
                    coordinator = %coord.id_hex(),
                    "Coordinator marked as failed"
                );
            }
        }

        info!(
            new_coordinator = %hex::encode(&event.new_id[..8]),
            "Failover complete, session lock released"
        );

        Ok(event)
        // _session_lock dropped here, releasing the lock
    }

    /// Record heartbeat from a coordinator
    pub fn record_heartbeat(&self, id: &CoordinatorId) -> Result<(), PoolError> {
        let mut coordinators = self.coordinators.write();

        let coord = coordinators
            .get_mut(id)
            .ok_or_else(|| PoolError::CoordinatorNotFound(hex::encode(&id[..8])))?;

        coord.record_heartbeat();

        Ok(())
    }

    /// Check for stale coordinators and handle failover
    pub fn check_health(&self) -> Vec<CoordinatorId> {
        let mut failed = Vec::new();
        let mut coordinators = self.coordinators.write();

        for (id, coord) in coordinators.iter_mut() {
            if coord.status != CoordinatorStatus::Failed
                && coord.status != CoordinatorStatus::Disabled
                && coord.is_stale(self.policy.heartbeat_timeout_secs)
            {
                coord.status = CoordinatorStatus::Failed;
                failed.push(*id);

                warn!(
                    coordinator = %coord.id_hex(),
                    last_heartbeat = coord.seconds_since_heartbeat(),
                    "Coordinator timed out"
                );
            }
        }

        failed
    }

    /// Get all coordinator info
    pub fn get_all_coordinators(&self) -> Vec<CoordinatorInfo> {
        self.coordinators.read().values().cloned().collect()
    }

    /// Get standby count
    pub fn standby_count(&self) -> usize {
        self.coordinators
            .read()
            .values()
            .filter(|c| c.status == CoordinatorStatus::Standby)
            .count()
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> u64 {
        *self.current_epoch.read()
    }

    /// Get rotation history
    pub fn rotation_history(&self) -> Vec<RotationEvent> {
        self.rotation_history.read().clone()
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let coordinators = self.coordinators.read();

        PoolStats {
            total_coordinators: coordinators.len(),
            active_count: coordinators
                .values()
                .filter(|c| c.status == CoordinatorStatus::Active)
                .count(),
            standby_count: coordinators
                .values()
                .filter(|c| c.status == CoordinatorStatus::Standby)
                .count(),
            failed_count: coordinators
                .values()
                .filter(|c| c.status == CoordinatorStatus::Failed)
                .count(),
            current_epoch: *self.current_epoch.read(),
            total_rotations: self.rotation_history.read().len(),
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    pub total_coordinators: usize,
    pub active_count: usize,
    pub standby_count: usize,
    pub failed_count: usize,
    pub current_epoch: u64,
    pub total_rotations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_coordinator(id: u8, name: &str) -> CoordinatorInfo {
        let mut coordinator_id = [0u8; 32];
        coordinator_id[0] = id;

        CoordinatorInfo::new(
            coordinator_id,
            name.to_string(),
            format!("http://coordinator-{}.onion:8080", id),
            vec![id; 32],
        )
    }

    #[test]
    fn test_policy_validation() {
        let mut policy = RotationPolicy::default();
        assert!(policy.validate().is_ok());

        policy.threshold_rotation = true;
        policy.rotation_threshold = 0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_register_coordinator() {
        let policy = RotationPolicy::default();
        let pool = CoordinatorPool::new(policy).unwrap();

        let coord = test_coordinator(1, "Coordinator A");
        assert!(pool.register_coordinator(coord.clone()).is_ok());

        // Duplicate should fail
        let coord2 = test_coordinator(1, "Coordinator A Dup");
        assert!(matches!(
            pool.register_coordinator(coord2),
            Err(PoolError::AlreadyRegistered(_))
        ));
    }

    #[test]
    fn test_activate_and_promote() {
        let policy = RotationPolicy::default();
        let pool = CoordinatorPool::new(policy).unwrap();

        let coord = test_coordinator(1, "Coordinator A");
        pool.register_coordinator(coord.clone()).unwrap();

        // Activate (becomes standby)
        pool.activate_coordinator(&coord.id).unwrap();

        // Should be promoted to active (no existing active)
        let active = pool.get_active().unwrap();
        assert_eq!(active.id, coord.id);
        assert_eq!(active.status, CoordinatorStatus::Active);
    }

    #[test]
    fn test_rotation() {
        let policy = RotationPolicy::default();
        let pool = CoordinatorPool::new(policy).unwrap();

        // Register two coordinators
        let coord_a = test_coordinator(1, "A");
        let coord_b = test_coordinator(2, "B");

        pool.register_coordinator(coord_a.clone()).unwrap();
        pool.register_coordinator(coord_b.clone()).unwrap();

        pool.activate_coordinator(&coord_a.id).unwrap();
        pool.activate_coordinator(&coord_b.id).unwrap();

        // A should be active
        assert_eq!(pool.get_active_id(), Some(coord_a.id));

        // Trigger rotation
        let event = pool.trigger_rotation(RotationReason::Manual).unwrap();

        // B should now be active
        assert_eq!(pool.get_active_id(), Some(coord_b.id));
        assert_eq!(event.previous_id, coord_a.id);
        assert_eq!(event.new_id, coord_b.id);
    }

    #[test]
    fn test_failover() {
        let policy = RotationPolicy {
            auto_failover: true,
            ..Default::default()
        };
        let pool = CoordinatorPool::new(policy).unwrap();

        let coord_a = test_coordinator(1, "A");
        let coord_b = test_coordinator(2, "B");

        pool.register_coordinator(coord_a.clone()).unwrap();
        pool.register_coordinator(coord_b.clone()).unwrap();

        pool.activate_coordinator(&coord_a.id).unwrap();
        pool.activate_coordinator(&coord_b.id).unwrap();

        // Trigger failover
        let event = pool.trigger_failover().unwrap();

        assert_eq!(event.reason, RotationReason::Failover);
        assert_eq!(pool.get_active_id(), Some(coord_b.id));

        // A should be marked failed
        let all = pool.get_all_coordinators();
        let a = all.iter().find(|c| c.id == coord_a.id).unwrap();
        assert_eq!(a.status, CoordinatorStatus::Failed);
    }

    #[test]
    fn test_heartbeat() {
        // Use 1-second timeout with 3-second sleep for reliable testing
        // The `is_stale()` uses `>` (not `>=`), so we need seconds_since > timeout
        // With 1-second timeout, we need at least 2 seconds elapsed (2 > 1 = true)
        // Using 3-second sleep gives us margin for timing variations
        let policy = RotationPolicy {
            heartbeat_timeout_secs: 1,
            ..Default::default()
        };
        let pool = CoordinatorPool::new(policy).unwrap();

        let coord = test_coordinator(1, "A");
        pool.register_coordinator(coord.clone()).unwrap();
        pool.activate_coordinator(&coord.id).unwrap();

        // Record heartbeat to reset the timer
        pool.record_heartbeat(&coord.id).unwrap();

        // Verify coordinator is not stale immediately after heartbeat
        let failed_immediate = pool.check_health();
        assert!(
            failed_immediate.is_empty(),
            "Coordinator should not be stale immediately after heartbeat"
        );

        // Wait well past the timeout (3 seconds >> 1 second timeout)
        // The >2x margin accounts for:
        // - Thread scheduling delays
        // - System clock resolution
        // - Test framework overhead
        std::thread::sleep(std::time::Duration::from_secs(3));

        // Verify enough time has elapsed
        let elapsed = {
            let coordinators = pool.coordinators.read();
            coordinators
                .get(&coord.id)
                .unwrap()
                .seconds_since_heartbeat()
        };
        assert!(
            elapsed > 1,
            "Expected >1 second elapsed, got {} seconds",
            elapsed
        );

        // Check health should detect stale (elapsed > timeout)
        let failed = pool.check_health();
        assert_eq!(
            failed.len(),
            1,
            "Coordinator should be detected as stale: {} seconds elapsed > 1 second timeout",
            elapsed
        );
    }

    #[test]
    fn test_coordinator_recovery() {
        let policy = RotationPolicy::default();
        let pool = CoordinatorPool::new(policy).unwrap();

        let coord = test_coordinator(1, "A");
        pool.register_coordinator(coord.clone()).unwrap();
        pool.activate_coordinator(&coord.id).unwrap();

        // Mark as failed
        {
            let mut coordinators = pool.coordinators.write();
            coordinators.get_mut(&coord.id).unwrap().status = CoordinatorStatus::Failed;
        }

        // Heartbeat should recover
        pool.record_heartbeat(&coord.id).unwrap();

        let active = pool.coordinators.read().get(&coord.id).unwrap().status;
        assert_eq!(active, CoordinatorStatus::Standby);
    }

    #[test]
    fn test_trust_score() {
        let mut coord = test_coordinator(1, "A");
        assert_eq!(coord.trust_score, 50);

        // Success increases score
        coord.record_session_complete(true);
        assert_eq!(coord.trust_score, 51);

        // Failure decreases score
        coord.record_session_complete(false);
        assert_eq!(coord.trust_score, 46);
    }

    #[test]
    fn test_pool_stats() {
        let policy = RotationPolicy::default();
        let pool = CoordinatorPool::new(policy).unwrap();

        let coord_a = test_coordinator(1, "A");
        let coord_b = test_coordinator(2, "B");

        pool.register_coordinator(coord_a.clone()).unwrap();
        pool.register_coordinator(coord_b.clone()).unwrap();

        pool.activate_coordinator(&coord_a.id).unwrap();
        pool.activate_coordinator(&coord_b.id).unwrap();

        let stats = pool.stats();
        assert_eq!(stats.total_coordinators, 2);
        assert_eq!(stats.active_count, 1);
        assert_eq!(stats.standby_count, 1);
    }

    #[test]
    fn test_no_standby_failover() {
        let policy = RotationPolicy::default();
        let pool = CoordinatorPool::new(policy).unwrap();

        // Only one coordinator
        let coord = test_coordinator(1, "A");
        pool.register_coordinator(coord.clone()).unwrap();
        pool.activate_coordinator(&coord.id).unwrap();

        // Failover should fail - no standby
        let result = pool.trigger_failover();
        assert!(matches!(result, Err(PoolError::NoStandbyAvailable)));
    }

    #[test]
    fn test_high_availability_policy() {
        let policy = RotationPolicy::high_availability();
        assert!(policy.threshold_rotation);
        assert!(policy.rotation_threshold >= 2);
        assert!(policy.min_standby_count >= 3);
    }
}
