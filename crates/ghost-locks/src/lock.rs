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
//| FILE: lock.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Lock - P2WSH UTXO with timelock recovery (Quantum-Safe)
//!
//! A Ghost Lock is a P2WSH output that can be spent via:
//! - Normal path (IF branch): Using the lock key
//! - Recovery path (ELSE branch): Using the recovery key after timelock
//!
//! Unlike P2TR which exposes public keys on-chain, P2WSH hides the keys
//! behind a hash until spending time, providing quantum safety.

use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::WScriptHash;
use serde::{Deserialize, Serialize};

use crate::denomination::Denomination;
use crate::error::GhostLockError;
use crate::jump::{JumpRiskTier, JumpSchedule};
use crate::script::{compute_wsh_script_hash, ghost_lock_id};
use crate::state::{LockState, StateTransition};
use crate::timelock::TimelockTier;

/// A Ghost Lock - P2WSH UTXO with timelock recovery (Quantum-Safe)
#[derive(Debug, Clone)]
pub struct GhostLock {
    /// Lock public key (33-byte compressed)
    lock_pubkey: PublicKey,
    /// Recovery public key (33-byte compressed)
    recovery_pubkey: PublicKey,
    /// Standard denomination
    denomination: Denomination,
    /// Timelock tier for recovery
    timelock_tier: TimelockTier,
    /// Block height when created
    creation_height: u32,
    /// The witness script (needed for spending)
    witness_script: ScriptBuf,
    /// SHA256 hash of witness script (for P2WSH address)
    script_hash: WScriptHash,
    /// The P2WSH scriptPubKey (OP_0 `<hash>`)
    script_pubkey: ScriptBuf,
    /// Unique lock ID
    lock_id: [u8; 32],
    /// Current state
    state: LockState,
    /// Jump schedule
    jump_schedule: JumpSchedule,
}

impl GhostLock {
    /// Create a new Ghost Lock
    pub fn new<C: bitcoin::secp256k1::Signing>(
        secp: &Secp256k1<C>,
        lock_secret: &SecretKey,
        recovery_secret: &SecretKey,
        denomination: Denomination,
        timelock_tier: TimelockTier,
        creation_height: u32,
    ) -> Result<Self, GhostLockError> {
        // SECURITY: Lock and recovery keys must be different to ensure proper 2-of-2 security
        if lock_secret.secret_bytes() == recovery_secret.secret_bytes() {
            return Err(GhostLockError::InvalidKey(
                "Lock and recovery secrets must be different".to_string(),
            ));
        }

        let lock_pubkey = PublicKey::from_secret_key(secp, lock_secret);
        let recovery_pubkey = PublicKey::from_secret_key(secp, recovery_secret);

        // CRIT-LOCKS-1 FIX: Check for key negation attack
        // Verify that lock_pubkey != recovery_pubkey AND lock_pubkey != -recovery_pubkey
        // If lock_pubkey == -recovery_pubkey, the 2-of-2 security model breaks because
        // whoever knows lock_secret can derive recovery_secret (or vice versa).
        // We check by attempting to combine them and seeing if we get the point-at-infinity.
        let combined = lock_pubkey.combine(&recovery_pubkey);

        if combined.is_err() {
            // combine() returns error if the points are exact negations
            return Err(GhostLockError::InvalidKey(
                "Lock and recovery keys are negations of each other - this breaks 2-of-2 security"
                    .to_string(),
            ));
        }

        // Additional check: Verify they're not the same public key
        if lock_pubkey == recovery_pubkey {
            return Err(GhostLockError::InvalidKey(
                "Lock and recovery public keys must be different".to_string(),
            ));
        }

        Self::from_pubkeys(
            lock_pubkey,
            recovery_pubkey,
            denomination,
            timelock_tier,
            creation_height,
        )
    }

    /// Create from existing public keys
    pub fn from_pubkeys(
        lock_pubkey: PublicKey,
        recovery_pubkey: PublicKey,
        denomination: Denomination,
        timelock_tier: TimelockTier,
        creation_height: u32,
    ) -> Result<Self, GhostLockError> {
        Self::from_pubkeys_for_network(
            lock_pubkey,
            recovery_pubkey,
            denomination,
            timelock_tier,
            creation_height,
            bitcoin::Network::Bitcoin,
        )
    }

    /// Network-aware constructor. On regtest, the CSV durations
    /// collapse to small constants (see `TimelockTier::blocks_for_network`)
    /// so end-to-end tests can mine past the timelock without
    /// production-scale block counts.
    pub fn from_pubkeys_for_network(
        lock_pubkey: PublicKey,
        recovery_pubkey: PublicKey,
        denomination: Denomination,
        timelock_tier: TimelockTier,
        creation_height: u32,
        network: bitcoin::Network,
    ) -> Result<Self, GhostLockError> {
        // Validate creation height to prevent overflow
        if creation_height > crate::timelock::MAX_CREATION_HEIGHT {
            return Err(GhostLockError::InvalidCreationHeight(format!(
                "{} exceeds maximum {}",
                creation_height,
                crate::timelock::MAX_CREATION_HEIGHT
            )));
        }

        // Build P2WSH script (network-aware so regtest gets the
        // shortened CSV without affecting other networks)
        let (witness_script, script_pubkey) = crate::script::build_lock_script_for_network(
            &lock_pubkey,
            &recovery_pubkey,
            creation_height,
            timelock_tier,
            network,
        )?;

        // Compute script hash
        let script_hash = compute_wsh_script_hash(&witness_script);

        // Compute lock ID
        let lock_id = ghost_lock_id(
            &lock_pubkey,
            &recovery_pubkey,
            creation_height,
            denomination.sats(),
        );

        // Create jump schedule
        let jump_schedule = JumpSchedule::from_denomination(denomination, creation_height);

        Ok(Self {
            lock_pubkey,
            recovery_pubkey,
            denomination,
            timelock_tier,
            creation_height,
            witness_script,
            script_hash,
            script_pubkey,
            lock_id,
            state: LockState::Active,
            jump_schedule,
        })
    }

    /// Get the lock public key (33-byte compressed)
    pub fn lock_pubkey(&self) -> &PublicKey {
        &self.lock_pubkey
    }

    /// Get the recovery public key (33-byte compressed)
    pub fn recovery_pubkey(&self) -> &PublicKey {
        &self.recovery_pubkey
    }

    /// Get the denomination
    pub fn denomination(&self) -> Denomination {
        self.denomination
    }

    /// Get the satoshi value
    pub fn sats(&self) -> u64 {
        self.denomination.sats()
    }

    /// Get the timelock tier
    pub fn timelock_tier(&self) -> TimelockTier {
        self.timelock_tier
    }

    /// Get the creation height
    pub fn creation_height(&self) -> u32 {
        self.creation_height
    }

    /// Get the witness script (needed for spending)
    ///
    /// IMPORTANT: The client must store this script to spend the lock.
    /// It cannot be reconstructed from the on-chain P2WSH output alone.
    pub fn witness_script(&self) -> &ScriptBuf {
        &self.witness_script
    }

    /// Get the script hash (SHA256 of witness script)
    pub fn script_hash(&self) -> &WScriptHash {
        &self.script_hash
    }

    /// Get the P2WSH scriptPubKey (for creating outputs)
    ///
    /// This is what goes in the transaction output: `OP_0 <32-byte hash>`
    pub fn script_pubkey(&self) -> &ScriptBuf {
        &self.script_pubkey
    }

    /// Get the unique lock ID
    pub fn lock_id(&self) -> &[u8; 32] {
        &self.lock_id
    }

    /// Get the lock ID as hex string
    pub fn lock_id_hex(&self) -> String {
        hex::encode(self.lock_id)
    }

    /// Get current state
    pub fn state(&self) -> LockState {
        self.state
    }

    /// Transition to a new state with validation
    ///
    /// This method validates that the requested transition is allowed from the current state
    /// using the defined state machine rules.
    pub fn transition(&mut self, transition: StateTransition) -> Result<(), GhostLockError> {
        if !transition.is_valid_from(self.state) {
            return Err(GhostLockError::InvalidStateTransition(format!(
                "Cannot apply {:?} from state {:?}",
                transition, self.state
            )));
        }
        self.state = transition.result_state();
        Ok(())
    }

    /// Get jump schedule
    pub fn jump_schedule(&self) -> &JumpSchedule {
        &self.jump_schedule
    }

    /// Get jump risk tier
    pub fn jump_risk_tier(&self) -> JumpRiskTier {
        self.jump_schedule.tier
    }

    /// Calculate the recovery height
    pub fn recovery_height(&self) -> u32 {
        self.timelock_tier.recovery_height(self.creation_height)
    }

    /// Check if recovery is available at given height
    ///
    /// Recovery is only available if:
    /// 1. The lock is in Active state (not spent, frozen, etc.)
    /// 2. The timelock has expired
    pub fn is_recovery_available(&self, current_height: u32) -> bool {
        self.state == LockState::Active
            && self
                .timelock_tier
                .is_recovery_available(self.creation_height, current_height)
    }

    /// Get blocks until recovery is available
    pub fn blocks_until_recovery(&self, current_height: u32) -> u32 {
        self.timelock_tier
            .blocks_until_recovery(self.creation_height, current_height)
    }

    /// Check if jump is needed
    pub fn needs_jump(&self, current_height: u32) -> bool {
        self.jump_schedule.needs_jump(current_height)
    }

    /// Get blocks until jump is needed
    pub fn blocks_until_jump(&self, current_height: u32) -> u32 {
        self.jump_schedule.blocks_until_jump(current_height)
    }

    /// Get jump urgency (0.0 = just created, 1.0 = overdue)
    pub fn jump_urgency(&self, current_height: u32) -> f64 {
        self.jump_schedule.urgency(current_height)
    }

    /// Check if jump warning should be shown
    pub fn should_warn_jump(&self, current_height: u32) -> bool {
        self.jump_schedule.should_warn(current_height)
    }

    /// Assess whether this lock can afford to jump given estimated mining costs.
    pub fn jump_affordability(
        &self,
        estimated_jump_cost: u64,
    ) -> crate::affordability::JumpAffordability {
        crate::affordability::assess_affordability(self.sats(), estimated_jump_cost)
    }

    /// Check if this lock can afford at least one more jump.
    pub fn can_afford_jump(&self, estimated_jump_cost: u64) -> bool {
        crate::affordability::remaining_jumps_estimate(self.sats(), estimated_jump_cost) > 0
    }

    /// Estimate how many jumps this lock can afford before its value is exhausted.
    pub fn remaining_jumps_estimate(&self, estimated_jump_cost: u64) -> u32 {
        crate::affordability::remaining_jumps_estimate(self.sats(), estimated_jump_cost)
    }

    /// Get recommended action for this lock given current cost estimates.
    pub fn recommended_action(
        &self,
        costs: &crate::affordability::CostEstimates,
    ) -> crate::affordability::RecommendedAction {
        crate::affordability::recommended_action(self.sats(), costs)
    }
}

/// Serializable Ghost Lock data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostLockData {
    /// Lock public key (hex-encoded 33-byte compressed)
    pub lock_pubkey: String,
    /// Recovery public key (hex-encoded 33-byte compressed)
    pub recovery_pubkey: String,
    /// Denomination
    pub denomination: Denomination,
    /// Timelock tier
    pub timelock_tier: TimelockTier,
    /// Creation height
    pub creation_height: u32,
    /// Lock ID (hex-encoded)
    pub lock_id: String,
    /// Current state
    pub state: LockState,
    /// Witness script (hex-encoded) - IMPORTANT: needed to spend
    pub witness_script: String,
    /// Script hash (hex-encoded)
    pub script_hash: String,
}

impl From<&GhostLock> for GhostLockData {
    fn from(lock: &GhostLock) -> Self {
        Self {
            lock_pubkey: hex::encode(lock.lock_pubkey.serialize()),
            recovery_pubkey: hex::encode(lock.recovery_pubkey.serialize()),
            denomination: lock.denomination,
            timelock_tier: lock.timelock_tier,
            creation_height: lock.creation_height,
            lock_id: lock.lock_id_hex(),
            state: lock.state,
            witness_script: hex::encode(lock.witness_script.as_bytes()),
            script_hash: {
                let hash_bytes: &[u8; 32] = lock.script_hash.as_ref();
                hex::encode(hash_bytes)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::is_p2wsh;
    use rand::RngCore;

    fn generate_secret_key() -> SecretKey {
        // M-2 FIX: Use OsRng for cryptographic security instead of thread_rng()
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        SecretKey::from_slice(&secret_bytes).expect("32 bytes, within curve order")
    }

    #[test]
    fn test_create_lock() {
        let secp = Secp256k1::new();
        let lock_secret = generate_secret_key();
        let recovery_secret = generate_secret_key();

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        assert_eq!(lock.sats(), 1_000_000);
        assert_eq!(lock.creation_height(), 800_000);
        assert_eq!(lock.state(), LockState::Active);

        // Verify P2WSH format
        assert!(is_p2wsh(lock.script_pubkey()));
    }

    #[test]
    fn test_lock_stores_witness_script() {
        let secp = Secp256k1::new();
        let lock_secret = generate_secret_key();
        let recovery_secret = generate_secret_key();

        let lock = GhostLock::new(
            &secp,
            &lock_secret,
            &recovery_secret,
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        // Witness script should be non-empty
        assert!(!lock.witness_script().is_empty());

        // Script hash should be 32 bytes
        let hash_bytes: &[u8; 32] = lock.script_hash().as_ref();
        assert_eq!(hash_bytes.len(), 32);
    }

    #[test]
    fn test_lock_id_unique() {
        let secp = Secp256k1::new();

        let lock1 = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        let lock2 = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        assert_ne!(lock1.lock_id(), lock2.lock_id());
    }

    #[test]
    fn test_jump_schedule() {
        let secp = Secp256k1::new();

        let lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Large, // High risk tier
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        assert_eq!(lock.jump_risk_tier(), JumpRiskTier::High);
        assert!(!lock.needs_jump(800_000));
        // Deadline is randomized within 7-14 days (1008-2016 blocks)
        // After max rotation period, jump is always needed
        assert!(lock.needs_jump(800_000 + JumpRiskTier::High.max_rotation_blocks() + 1));
    }

    #[test]
    fn test_serialization() {
        let secp = Secp256k1::new();

        let lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Medium,
            TimelockTier::Short,
            800_000,
        )
        .unwrap();

        let data = GhostLockData::from(&lock);
        assert_eq!(data.denomination, Denomination::Medium);
        assert_eq!(data.timelock_tier, TimelockTier::Short);

        // Witness script should be included in serialization
        assert!(!data.witness_script.is_empty());
        assert!(!data.script_hash.is_empty());
    }

    #[test]
    fn test_state_transition_valid() {
        let secp = Secp256k1::new();
        let mut lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        assert_eq!(lock.state(), LockState::Active);

        // Valid transition: Active -> InMix
        assert!(lock.transition(StateTransition::EnterMix).is_ok());
        assert_eq!(lock.state(), LockState::InMix);

        // Valid transition: InMix -> Active
        assert!(lock.transition(StateTransition::ExitMix).is_ok());
        assert_eq!(lock.state(), LockState::Active);

        // Valid transition: Active -> Spent
        assert!(lock
            .transition(StateTransition::SettlementSpend {
                batch_id: [0u8; 32]
            })
            .is_ok());
        assert_eq!(lock.state(), LockState::Spent);
    }

    #[test]
    fn test_state_transition_invalid() {
        let secp = Secp256k1::new();
        let mut lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        )
        .unwrap();

        // Enter mix first
        lock.transition(StateTransition::EnterMix).unwrap();

        // Invalid: InMix cannot enter mix again
        let result = lock.transition(StateTransition::EnterMix);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GhostLockError::InvalidStateTransition(_)
        ));

        // State should remain unchanged
        assert_eq!(lock.state(), LockState::InMix);
    }

    #[test]
    fn test_recovery_requires_active_state() {
        let secp = Secp256k1::new();
        let mut lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Short,
            800_000,
        )
        .unwrap();

        let recovery_height = lock.recovery_height();

        // Recovery available when active
        assert!(lock.is_recovery_available(recovery_height));

        // Mark as spent
        lock.transition(StateTransition::SettlementSpend {
            batch_id: [0u8; 32],
        })
        .unwrap();

        // Recovery not available when spent
        assert!(!lock.is_recovery_available(recovery_height));
    }

    #[test]
    fn test_recovery_not_available_when_frozen() {
        let secp = Secp256k1::new();
        let mut lock = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Short,
            800_000,
        )
        .unwrap();

        let recovery_height = lock.recovery_height();

        // Freeze the lock
        lock.transition(StateTransition::Freeze).unwrap();

        // Recovery not available when frozen
        assert!(!lock.is_recovery_available(recovery_height));
    }

    #[test]
    fn test_invalid_creation_height() {
        let secp = Secp256k1::new();
        let result = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            crate::timelock::MAX_CREATION_HEIGHT + 1,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            GhostLockError::InvalidCreationHeight(_)
        ));
    }

    #[test]
    fn test_valid_max_creation_height() {
        let secp = Secp256k1::new();
        let result = GhostLock::new(
            &secp,
            &generate_secret_key(),
            &generate_secret_key(),
            Denomination::Small,
            TimelockTier::Standard,
            crate::timelock::MAX_CREATION_HEIGHT,
        );

        // Should succeed at exactly the max
        assert!(result.is_ok());
    }

    #[test]
    fn test_same_secret_rejected() {
        let secp = Secp256k1::new();
        let secret = generate_secret_key();

        let result = GhostLock::new(
            &secp,
            &secret,
            &secret, // Same secret
            Denomination::Small,
            TimelockTier::Standard,
            800_000,
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GhostLockError::InvalidKey(_)));
    }
}
