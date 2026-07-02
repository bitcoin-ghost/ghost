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
//| FILE: manager.rs                                                                                                     |
//|======================================================================================================================|

//! MPC Ceremony Manager
//!
//! Manages the state of the rolling MPC ceremony, including:
//! - Tracking contribution count and current parameters
//! - Generating and verifying contributions
//! - Hot-swapping parameters after contributions are applied
//! - Detecting and enforcing ossification

use crate::contribution::{
    generate_multi_contribution, hash_parameters, verify_contribution, ContributionCommitment,
    MpcContribution,
};
use crate::errors::{MpcError, MpcResult};
use crate::params::{
    hash_params_file, load_parameters, save_parameters, save_verifying_key, update_current_params,
    ParameterFiles,
};
use crate::MAX_CEREMONY_CONTRIBUTORS;
use bellperson::groth16::{prepare_verifying_key, Parameters, PreparedVerifyingKey};
use blstrs::Bls12;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// State of the MPC ceremony
#[derive(Debug, Clone, Default)]
pub struct CeremonyState {
    /// Number of contributions applied (0 = genesis, 101 = ossified)
    pub contribution_count: u32,
    /// Hash of the current parameters
    pub current_params_hash: [u8; 32],
    /// Whether the ceremony has ossified (permanently closed)
    pub is_ossified: bool,
    /// Block height when ossification occurred (if ossified)
    pub ossified_at: Option<u64>,
    /// Hash of the block verifying key
    pub note_spend_vk_hash: Option<[u8; 32]>,
    /// Hash of the payout verifying key
    pub payout_vk_hash: Option<[u8; 32]>,
    /// Last update timestamp
    pub updated_at: u64,
    /// 4.22 SECURITY: Unique ceremony identifier for binding proofs
    /// Derived from genesis parameters hash to ensure uniqueness across ceremonies
    pub ceremony_id: [u8; 32],
    /// CRIT-2 FIX: Number of pending commitments (not yet fulfilled)
    pub pending_commitment_count: u32,
    /// Autonomous-ossification pin: the raw-file SHA-256 of the final
    /// `note_spend_params_current.bin`, recorded the instant the ceremony reaches
    /// [`MAX_CEREMONY_CONTRIBUTORS`]. This is the SAME digest a `ZK_PARAMS_HASH`
    /// static pin holds (NOT the structured lineage hash). `None` until ossified;
    /// once set it is permanent. Persisted to `mpc_ceremony.ossified_file_hash`
    /// and drives the self-activating `OssifiedPinned` startup mode.
    pub ossified_file_hash: Option<[u8; 32]>,
}

/// Manager for the MPC ceremony
///
/// This struct maintains the ceremony state and provides methods for:
/// - Generating contributions (for registering elders)
/// - Verifying contributions (for current elders)
/// - Applying contributions after BFT approval
/// - Hot-swapping parameters in memory
/// - CRIT-2 FIX: Tracking contribution commitments to prevent ordering attacks
pub struct CeremonyManager {
    /// Current ceremony state
    state: RwLock<CeremonyState>,
    /// Parameter file manager
    files: ParameterFiles,
    /// Current note spend proving parameters (hot-swappable)
    note_spend_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
    /// Current payout proving parameters (hot-swappable)
    payout_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
    /// Current unshield (L2 -> L1 withdrawal) proving parameters (hot-swappable)
    unshield_params: RwLock<Option<Arc<Parameters<Bls12>>>>,
    /// Prepared note spend verifying key (for fast verification)
    note_spend_vk: RwLock<Option<Arc<PreparedVerifyingKey<Bls12>>>>,
    /// Prepared payout verifying key
    payout_vk: RwLock<Option<Arc<PreparedVerifyingKey<Bls12>>>>,
    /// Prepared unshield verifying key
    unshield_vk: RwLock<Option<Arc<PreparedVerifyingKey<Bls12>>>>,
    /// CRIT-2 FIX: Pending contribution commitments (commitment_hash -> commitment)
    /// Contributors broadcast commitments BEFORE revealing their contribution.
    /// This prevents a malicious coordinator from silently dropping contributions.
    pending_commitments: RwLock<HashMap<[u8; 32], ContributionCommitment>>,
    /// CRIT-2 FIX: Fulfilled commitments (for audit trail)
    fulfilled_commitments: RwLock<Vec<[u8; 32]>>,
}

impl CeremonyManager {
    /// Create a new ceremony manager with the given parameters directory
    pub fn new(params_dir: PathBuf) -> Self {
        Self {
            state: RwLock::new(CeremonyState::default()),
            files: ParameterFiles::new(params_dir),
            note_spend_params: RwLock::new(None),
            payout_params: RwLock::new(None),
            unshield_params: RwLock::new(None),
            note_spend_vk: RwLock::new(None),
            payout_vk: RwLock::new(None),
            unshield_vk: RwLock::new(None),
            // CRIT-2 FIX: Initialize commitment tracking
            pending_commitments: RwLock::new(HashMap::new()),
            fulfilled_commitments: RwLock::new(Vec::new()),
        }
    }

    /// Initialize the ceremony from database state or create genesis
    ///
    /// Returns the manager with state loaded from the database.
    /// If no state exists, initializes with default (pre-genesis) state.
    pub fn load_or_init(params_dir: PathBuf, db_state: Option<CeremonyState>) -> MpcResult<Self> {
        let manager = Self::new(params_dir);

        if let Some(state) = db_state {
            // Load from database
            *manager.state.write() = state;
            info!(
                contribution_count = manager.contribution_count(),
                is_ossified = manager.is_ossified(),
                "Loaded MPC ceremony state from database"
            );

            // Try to load current parameters from disk
            if manager.contribution_count() > 0 {
                manager.load_current_params()?;
            }
        } else {
            info!("No MPC ceremony state found - initializing pre-genesis state");
        }

        Ok(manager)
    }

    /// Load current parameters from disk
    ///
    /// This loads the params that were saved to disk (e.g., after syncing from network).
    /// Call this after fetching params from another node.
    pub fn load_current_params(&self) -> MpcResult<()> {
        self.files.ensure_dir()?;

        let note_spend_path = self.files.current_note_spend_params_path();
        if note_spend_path.exists() {
            match load_parameters(&note_spend_path) {
                Ok(params) => {
                    let vk = prepare_verifying_key(&params.vk);
                    *self.note_spend_params.write() = Some(Arc::new(params));
                    *self.note_spend_vk.write() = Some(Arc::new(vk));
                    info!("Loaded current note spend parameters");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load note spend parameters");
                }
            }
        }

        let payout_path = self.files.current_payout_params_path();
        if payout_path.exists() {
            match load_parameters(&payout_path) {
                Ok(params) => {
                    let vk = prepare_verifying_key(&params.vk);
                    *self.payout_params.write() = Some(Arc::new(params));
                    *self.payout_vk.write() = Some(Arc::new(vk));
                    info!("Loaded current payout parameters");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load payout parameters");
                }
            }
        }

        let unshield_path = self.files.current_unshield_params_path();
        if unshield_path.exists() {
            match load_parameters(&unshield_path) {
                Ok(params) => {
                    let vk = prepare_verifying_key(&params.vk);
                    *self.unshield_params.write() = Some(Arc::new(params));
                    *self.unshield_vk.write() = Some(Arc::new(vk));
                    info!("Loaded current unshield parameters");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load unshield parameters");
                }
            }
        }

        Ok(())
    }

    /// Get the current contribution count
    pub fn contribution_count(&self) -> u32 {
        self.state.read().contribution_count
    }

    /// Sync the contribution count from network peers
    ///
    /// This is used when a node joins the network and fetches existing params.
    /// The contribution count determines the next position number.
    /// Only updates if the network count is higher (to prevent rollbacks).
    pub fn sync_contribution_count(&self, network_count: u32) {
        let mut state = self.state.write();
        if network_count > state.contribution_count {
            info!(
                local_count = state.contribution_count,
                network_count = network_count,
                "MPC: Syncing contribution count from network"
            );
            state.contribution_count = network_count;
        }
    }

    /// Check if the ceremony has ossified
    pub fn is_ossified(&self) -> bool {
        self.state.read().is_ossified
    }

    /// Get the current parameters hash
    pub fn current_params_hash(&self) -> [u8; 32] {
        self.state.read().current_params_hash
    }

    /// Get a snapshot of the current state
    pub fn state(&self) -> CeremonyState {
        self.state.read().clone()
    }

    /// Check if we have current parameters loaded
    pub fn has_current_params(&self) -> bool {
        self.note_spend_params.read().is_some()
    }

    /// Ensure genesis parameters are initialized
    ///
    /// If no parameters are loaded, generates and initializes genesis parameters
    /// using the ZK circuit's dummy circuit. This is called automatically by
    /// the first elder during the MPC ceremony bootstrap.
    ///
    /// Returns Ok(true) if genesis was just initialized, Ok(false) if already initialized.
    pub fn ensure_genesis_initialized(&self) -> MpcResult<bool> {
        if self.has_current_params() {
            return Ok(false);
        }

        // Generate genesis parameters using GhostNoteSpendCircuit (sender-side proofs)
        use bellperson::groth16::generate_random_parameters;
        use blstrs::Scalar as Fr;
        use ghost_zkp::circuit::{
            GhostNoteSpendCircuit, GhostUnshieldCircuit, NoteConsolidateCircuit,
        };
        use rand::rngs::OsRng;

        tracing::info!("MPC: Generating genesis parameters for NoteSpend + NoteConsolidate + Unshield circuits...");

        let dummy_note = GhostNoteSpendCircuit::<Fr>::dummy(20);
        let note_params = generate_random_parameters::<Bls12, _, _>(dummy_note, &mut OsRng)
            .map_err(|e| {
                MpcError::Internal(format!(
                    "Failed to generate note spend genesis params: {:?}",
                    e
                ))
            })?;

        // Slot 2: NoteConsolidateCircuit (merges up to 4 notes into 1)
        let dummy_consolidate = NoteConsolidateCircuit::<Fr>::dummy(20);
        let consolidate_params =
            generate_random_parameters::<Bls12, _, _>(dummy_consolidate, &mut OsRng).map_err(
                |e| {
                    MpcError::Internal(format!(
                        "Failed to generate consolidation genesis params: {:?}",
                        e
                    ))
                },
            )?;

        // Slot 3: Unshield circuit (L2 -> L1 withdrawal proofs)
        let dummy_unshield = GhostUnshieldCircuit::<Fr>::dummy(20);
        let unshield_params = generate_random_parameters::<Bls12, _, _>(dummy_unshield, &mut OsRng)
            .map_err(|e| {
                MpcError::Internal(format!(
                    "Failed to generate unshield genesis params: {:?}",
                    e
                ))
            })?;

        self.initialize_genesis_multi(note_params, consolidate_params, unshield_params)?;
        tracing::info!(
            "MPC: Genesis parameters initialized for NoteSpend + NoteConsolidate + Unshield"
        );
        Ok(true)
    }

    /// Get current note spend parameters for proving
    pub fn note_spend_params(&self) -> Option<Arc<Parameters<Bls12>>> {
        self.note_spend_params.read().clone()
    }

    /// Get current payout parameters for proving
    pub fn payout_params(&self) -> Option<Arc<Parameters<Bls12>>> {
        self.payout_params.read().clone()
    }

    /// Get current note spend verifying key
    pub fn note_spend_vk(&self) -> Option<Arc<PreparedVerifyingKey<Bls12>>> {
        self.note_spend_vk.read().clone()
    }

    /// Get current payout verifying key
    pub fn payout_vk(&self) -> Option<Arc<PreparedVerifyingKey<Bls12>>> {
        self.payout_vk.read().clone()
    }

    /// Get current unshield parameters for proving
    #[deprecated(note = "Use note_spend params instead")]
    pub fn unshield_params(&self) -> Option<Arc<Parameters<Bls12>>> {
        self.unshield_params.read().clone()
    }

    /// Get current unshield verifying key
    #[deprecated(note = "Use note_spend VK instead")]
    pub fn unshield_vk(&self) -> Option<Arc<PreparedVerifyingKey<Bls12>>> {
        self.unshield_vk.read().clone()
    }

    /// Generate a contribution for a new elder
    ///
    /// This is called by a node that is becoming an elder and the ceremony
    /// is not yet ossified. The contribution transforms the current parameters
    /// and generates a proof of valid transformation.
    ///
    /// # Arguments
    ///
    /// * `contributor_id` - The node ID of the new elder
    ///
    /// # Returns
    ///
    /// The new parameters and contribution record
    pub fn generate_contribution(
        &self,
        contributor_id: &str,
    ) -> MpcResult<(Parameters<Bls12>, MpcContribution)> {
        let result = self.generate_multi_circuit_contribution(contributor_id)?;
        Ok((result.note_spend_params, result.contribution))
    }

    /// Generate a contribution that transforms all circuit parameter sets
    ///
    /// Uses the same toxic waste (tau, alpha, beta) for all circuits,
    /// maintaining the 1-of-N security guarantee across all three.
    pub fn generate_multi_circuit_contribution(
        &self,
        contributor_id: &str,
    ) -> MpcResult<crate::contribution::MultiContributionResult> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        let next_position = state.contribution_count + 1;
        if next_position > MAX_CEREMONY_CONTRIBUTORS {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Get current parameters for all circuits
        let current_note_spend = self.note_spend_params.read();
        let note_spend_params = current_note_spend.as_ref().ok_or_else(|| {
            MpcError::Internal("No current block parameters loaded for contribution".into())
        })?;

        let current_payout = self.payout_params.read();
        let payout_ref = current_payout.as_ref().map(|p| p.as_ref());

        let current_unshield = self.unshield_params.read();
        let unshield_ref = current_unshield.as_ref().map(|p| p.as_ref());

        // 4.22: Get ceremony_id for binding proofs to this ceremony
        let ceremony_id = state.ceremony_id;
        drop(state);

        let mut rng = OsRng;
        let result = generate_multi_contribution(
            note_spend_params.as_ref(),
            payout_ref,
            unshield_ref,
            &ceremony_id,
            next_position,
            contributor_id,
            &mut rng,
        )?;

        info!(
            position = next_position,
            contributor = contributor_id,
            prev_hash = %hex::encode(result.contribution.prev_params_hash),
            new_hash = %hex::encode(result.contribution.new_params_hash),
            has_payout = result.payout_params.is_some(),
            has_unshield = result.unshield_params.is_some(),
            "Generated multi-circuit MPC contribution"
        );

        Ok(result)
    }

    /// Generate a contribution at a specific position
    ///
    /// Unlike `generate_contribution()` which uses the in-memory state.contribution_count,
    /// this method accepts an externally-determined position. The caller should query the
    /// database for the current count to avoid stale in-memory state (e.g., when multiple
    /// nodes start simultaneously and the in-memory count hasn't been updated from P2P sync).
    ///
    /// # Arguments
    ///
    /// * `contributor_id` - The node ID of the new elder
    /// * `position` - The position number (should be db_count + 1)
    pub fn generate_contribution_at_position(
        &self,
        contributor_id: &str,
        position: u32,
    ) -> MpcResult<(Parameters<Bls12>, MpcContribution)> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        if position > MAX_CEREMONY_CONTRIBUTORS {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Get current block parameters
        let current_note_spend = self.note_spend_params.read();
        let note_spend_params = current_note_spend.as_ref().ok_or_else(|| {
            MpcError::Internal("No current parameters loaded for contribution".into())
        })?;

        let current_payout = self.payout_params.read();
        let payout_ref = current_payout.as_ref().map(|p| p.as_ref());

        let current_unshield = self.unshield_params.read();
        let unshield_ref = current_unshield.as_ref().map(|p| p.as_ref());

        // 4.22: Get ceremony_id for binding proofs to this ceremony
        let ceremony_id = state.ceremony_id;
        drop(state);

        let mut rng = OsRng;
        let result = generate_multi_contribution(
            note_spend_params.as_ref(),
            payout_ref,
            unshield_ref,
            &ceremony_id,
            position,
            contributor_id,
            &mut rng,
        )?;

        info!(
            position = position,
            contributor = contributor_id,
            prev_hash = %hex::encode(result.contribution.prev_params_hash),
            new_hash = %hex::encode(result.contribution.new_params_hash),
            "Generated MPC contribution (DB-driven position)"
        );

        Ok((result.note_spend_params, result.contribution))
    }

    /// Generate a contribution with a prior commitment (RECOMMENDED)
    ///
    /// CRIT-2 FIX: This is the recommended way to generate contributions.
    /// The contributor should:
    /// 1. Create a commitment with `create_commitment()`
    /// 2. Broadcast the commitment to all elders
    /// 3. Wait for acknowledgment
    /// 4. Call this method with the commitment hash
    ///
    /// This ensures the contribution cannot be silently dropped.
    ///
    /// # Arguments
    ///
    /// * `contributor_id` - The node ID of the new elder
    /// * `commitment_hash` - Hash of the previously broadcast commitment
    ///
    /// # Returns
    ///
    /// The new parameters and contribution record with commitment binding
    pub fn generate_contribution_with_commitment(
        &self,
        contributor_id: &str,
        commitment_hash: [u8; 32],
    ) -> MpcResult<(Parameters<Bls12>, MpcContribution)> {
        // Verify the commitment exists and belongs to this contributor
        {
            let pending = self.pending_commitments.read();
            if let Some(commitment) = pending.get(&commitment_hash) {
                if commitment.contributor != contributor_id {
                    return Err(MpcError::UnauthorizedContributor(
                        contributor_id.to_string(),
                        commitment.contributor.clone(),
                    ));
                }
            } else {
                return Err(MpcError::InvalidProof(
                    "Commitment hash not found - broadcast commitment first".into(),
                ));
            }
        }

        // Generate the contribution
        let (new_params, mut contribution) = self.generate_contribution(contributor_id)?;

        // CRIT-2 FIX: Bind the commitment hash to the contribution
        contribution.commitment_hash = Some(commitment_hash);

        info!(
            commitment_hash = %hex::encode(commitment_hash),
            "Generated contribution bound to commitment"
        );

        Ok((new_params, contribution))
    }

    /// Verify a contribution from another node
    ///
    /// This is called by current elders to verify a contribution before
    /// casting their approval vote.
    pub fn verify_contribution(
        &self,
        new_params: &Parameters<Bls12>,
        contribution: &MpcContribution,
    ) -> MpcResult<bool> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Verify position is correct
        let expected_position = state.contribution_count + 1;
        if contribution.position != expected_position {
            return Err(MpcError::InvalidPosition(
                contribution.position,
                expected_position,
            ));
        }

        // Get current parameters
        let current_params = self.note_spend_params.read();
        let params = current_params.as_ref().ok_or_else(|| {
            MpcError::Internal("No current parameters loaded for verification".into())
        })?;

        // 4.22: Verify the contribution with ceremony_id binding
        verify_contribution(
            params.as_ref(),
            new_params,
            contribution,
            &state.ceremony_id,
        )
    }

    /// Verify a HISTORICAL contribution during catch-up (no timestamp skew).
    ///
    /// Stage C task 4: when a node that was offline for days re-verifies the
    /// chain or adopts an already-BFT-approved historical contribution, the
    /// live ±1h freshness window would wrongly reject it. This runs the SAME
    /// cryptographic checks (Schnorr proof bound to `ceremony_id`, hash chain,
    /// h/l pairing transform) via [`crate::contribution::verify_contribution_lineage`], omitting only
    /// the freshness window. Unlike [`Self::verify_contribution`] it does NOT
    /// require `contribution.position == count+1`, because catch-up validates a
    /// position relative to a supplied `prev` rather than the live head.
    pub fn verify_contribution_catchup(
        &self,
        prev_params: &Parameters<Bls12>,
        new_params: &Parameters<Bls12>,
        contribution: &MpcContribution,
    ) -> MpcResult<bool> {
        let ceremony_id = self.state.read().ceremony_id;
        crate::contribution::verify_contribution_lineage(
            prev_params,
            new_params,
            contribution,
            &ceremony_id,
        )
    }

    /// Apply a contribution after BFT approval
    ///
    /// This updates the ceremony state and hot-swaps the parameters.
    /// Called when >67% of elders have approved the contribution.
    pub fn apply_contribution(
        &self,
        new_params: Parameters<Bls12>,
        contribution: &MpcContribution,
    ) -> MpcResult<()> {
        self.apply_contribution_multi(new_params, None, None, contribution)
    }

    /// Apply a multi-circuit contribution after BFT approval
    ///
    /// Updates the ceremony state and hot-swaps parameters for all circuits.
    /// Called when >67% of elders have approved the contribution.
    pub fn apply_contribution_multi(
        &self,
        new_note_spend_params: Parameters<Bls12>,
        new_payout_params: Option<Parameters<Bls12>>,
        new_unshield_params: Option<Parameters<Bls12>>,
        contribution: &MpcContribution,
    ) -> MpcResult<()> {
        let mut state = self.state.write();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Verify position
        let expected_position = state.contribution_count + 1;
        if contribution.position != expected_position {
            return Err(MpcError::InvalidPosition(
                contribution.position,
                expected_position,
            ));
        }

        // Save new parameters to disk
        self.files.ensure_dir()?;

        // Note spend params (always present)
        let note_spend_path = self.files.note_spend_params_path(contribution.position);
        save_parameters(&note_spend_path, &new_note_spend_params)?;
        save_verifying_key(&self.files.note_spend_vk_path(), &new_note_spend_params.vk)?;

        // Payout params (if provided)
        if let Some(ref payout_params) = new_payout_params {
            let payout_path = self.files.payout_params_path(contribution.position);
            save_parameters(&payout_path, payout_params)?;
            save_verifying_key(&self.files.payout_vk_path(), &payout_params.vk)?;
        }

        // Confidential params (if provided)
        if let Some(ref unshield_params) = new_unshield_params {
            let unshield_path = self.files.unshield_params_path(contribution.position);
            save_parameters(&unshield_path, unshield_params)?;
            save_verifying_key(&self.files.unshield_vk_path(), &unshield_params.vk)?;
        }

        // Update current symlinks
        update_current_params(&self.files, contribution.position)?;

        // Hot-swap note spend params
        let note_spend_vk = prepare_verifying_key(&new_note_spend_params.vk);
        *self.note_spend_params.write() = Some(Arc::new(new_note_spend_params));
        *self.note_spend_vk.write() = Some(Arc::new(note_spend_vk));

        // Hot-swap payout params
        if let Some(payout_params) = new_payout_params {
            let payout_vk = prepare_verifying_key(&payout_params.vk);
            *self.payout_params.write() = Some(Arc::new(payout_params));
            *self.payout_vk.write() = Some(Arc::new(payout_vk));
        }

        // Hot-swap unshield params
        if let Some(unshield_params) = new_unshield_params {
            let unshield_vk = prepare_verifying_key(&unshield_params.vk);
            *self.unshield_params.write() = Some(Arc::new(unshield_params));
            *self.unshield_vk.write() = Some(Arc::new(unshield_vk));
        }

        // Update state
        state.contribution_count = contribution.position;
        state.current_params_hash = contribution.new_params_hash;
        state.note_spend_vk_hash = Some(contribution.new_params_hash);
        state.updated_at = contribution.timestamp;

        // CRIT-2 FIX: If contribution has a commitment hash, verify and mark as fulfilled
        if let Some(commitment_hash) = contribution.commitment_hash {
            let mut pending = self.pending_commitments.write();
            if let Some(commitment) = pending.remove(&commitment_hash) {
                // H-1: Reject contribution if commitment doesn't match (tampering detected)
                if !commitment.matches_contribution(contribution) {
                    return Err(MpcError::InvalidProof(format!(
                        "H-1: Contribution commitment mismatch for contributor {} — possible tampering",
                        contribution.contributor
                    )));
                }
                // Record fulfilled commitment for audit
                self.fulfilled_commitments.write().push(commitment_hash);
                state.pending_commitment_count = state.pending_commitment_count.saturating_sub(1);
            }
        }

        info!(
            position = contribution.position,
            contributor = %contribution.contributor,
            params_hash = %hex::encode(contribution.new_params_hash),
            pending_commitments = state.pending_commitment_count,
            "Applied MPC contribution - parameters updated"
        );

        // Check for ossification. At the cap the trusted setup is FINAL, so
        // record the deterministic ossified FILE hash — the raw SHA-256 of the
        // just-written `note_spend_params_current.bin`, the SAME digest a
        // `ZK_PARAMS_HASH` static pin holds. Every node computes the identical
        // value from the identical final params, so no coordination is needed;
        // this pin then drives the self-activating `OssifiedPinned` startup mode.
        // Fail-CLOSED: if the final file cannot be hashed we refuse to declare a
        // successful apply of the ceremony-closing contribution rather than
        // ossify without a recorded pin.
        if contribution.position >= MAX_CEREMONY_CONTRIBUTORS {
            let file_hash = hash_params_file(&self.files.current_note_spend_params_path())?;
            state.ossified_file_hash = Some(file_hash);
            self.ossify_internal(&mut state)?;
            info!(
                file_hash = %hex::encode(file_hash),
                "MPC ceremony reached cap — recorded permanent ossified params file hash"
            );
        }

        Ok(())
    }

    /// Raw-file SHA-256 of the current `note_spend_params_current.bin`.
    ///
    /// This is the FILE hash (matching `ghost_zkp::compute_params_file_hash` and
    /// a `ZK_PARAMS_HASH=BLOCK:<hex>` pin), NOT the structured lineage hash. Used
    /// to record / re-derive the autonomous ossification pin from the on-disk
    /// head (e.g. a fresh node that synced an already-complete chain).
    pub fn current_params_file_hash(&self) -> MpcResult<[u8; 32]> {
        hash_params_file(&self.files.current_note_spend_params_path())
    }

    /// Durably install an already-obtained, hash-verified note-spend parameter
    /// set as the CURRENT head for a node that SYNCED the ceremony mid-flight.
    ///
    /// A node that joins after the ceremony has already advanced fetches the
    /// applied contribution ROWS (+ proofs/votes) and the head parameters from a
    /// peer, but it never ran the sequential `apply_contribution_multi` for the
    /// intermediate positions (it holds neither the toxic waste nor the
    /// intermediate parameter files). Such a node cannot reach its head through
    /// the position-`count + 1` apply path. This method records the fetched head
    /// through the SAME S-5/S-6 atomic writers (`save_parameters` +
    /// `update_current_params`) the apply path uses, so a restart loads
    /// `note_spend_params_current.bin` cleanly instead of re-initialising
    /// pre-genesis.
    ///
    /// This is NOT a contribution — it does not transform parameters; it only
    /// makes the ALREADY-AGREED head durable on THIS node. It is fail-CLOSED:
    /// both the provided params AND the on-disk copy after write MUST re-hash
    /// (lineage [`hash_parameters`]) to `head_hash` (the recorded
    /// `mpc_contributions[version].new_params_hash`), else the install is
    /// rejected and no mismatched head is left as current.
    pub fn install_synced_head(
        &self,
        version: u32,
        params: &Parameters<Bls12>,
        head_hash: [u8; 32],
    ) -> MpcResult<()> {
        // Refuse to install anything that is not the claimed head lineage: the
        // caller fetched `params` by `head_hash`, but re-check here so this
        // method is safe in isolation and never persists a mismatched head.
        let provided = hash_parameters(params)?;
        if provided != head_hash {
            return Err(MpcError::InvalidParams(format!(
                "install_synced_head: provided params hash {} != expected head {}",
                hex::encode(&provided[..8]),
                hex::encode(&head_hash[..8])
            )));
        }

        self.files.ensure_dir()?;
        let note_spend_path = self.files.note_spend_params_path(version);
        save_parameters(&note_spend_path, params)?;
        save_verifying_key(&self.files.note_spend_vk_path(), &params.vk)?;
        // Atomically repoint note_spend_params_current.bin at the version we just
        // wrote (the one legitimate current.bin writer, shared with apply).
        update_current_params(&self.files, version)?;

        // Verify-after-write: the on-disk current head must re-hash to `head_hash`.
        let installed = load_parameters(&self.files.current_note_spend_params_path())?;
        let on_disk = hash_parameters(&installed)?;
        if on_disk != head_hash {
            return Err(MpcError::InvalidParams(format!(
                "install_synced_head: verify-after-write failed — on-disk head {} != expected {}",
                hex::encode(&on_disk[..8]),
                hex::encode(&head_hash[..8])
            )));
        }

        // Hot-swap into memory and set the in-memory state to the synced head.
        let vk = prepare_verifying_key(&installed.vk);
        *self.note_spend_params.write() = Some(Arc::new(installed));
        *self.note_spend_vk.write() = Some(Arc::new(vk));
        let mut state = self.state.write();
        if version > state.contribution_count {
            state.contribution_count = version;
        }
        state.current_params_hash = head_hash;
        state.note_spend_vk_hash = Some(head_hash);
        state.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        info!(
            version,
            head = %hex::encode(&head_hash[..8]),
            "MPC: installed synced ceremony head (current.bin) via the atomic params writer"
        );
        Ok(())
    }

    /// Mark the ceremony as ossified
    ///
    /// This is called when elder 101 contributes, permanently closing
    /// the ceremony.
    pub fn ossify(&self) -> MpcResult<()> {
        let mut state = self.state.write();
        self.ossify_internal(&mut state)
    }

    fn ossify_internal(&self, state: &mut CeremonyState) -> MpcResult<()> {
        if state.is_ossified {
            return Ok(()); // Already ossified
        }

        state.is_ossified = true;
        state.ossified_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );

        info!(
            contribution_count = state.contribution_count,
            "MPC ceremony OSSIFIED - parameters are now permanent"
        );

        Ok(())
    }

    // ========================================================================
    // CRIT-2 FIX: Contribution Commitment Methods
    // ========================================================================

    /// Record a contribution commitment
    ///
    /// Contributors should broadcast a commitment BEFORE generating their contribution.
    /// This prevents a malicious coordinator from silently dropping contributions,
    /// as any dropped commitment can be detected during audit.
    ///
    /// # Arguments
    /// * `commitment` - The commitment to record
    ///
    /// # Returns
    /// The commitment hash for inclusion in the contribution
    pub fn record_commitment(&self, commitment: ContributionCommitment) -> MpcResult<[u8; 32]> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        // Verify commitment is for the correct ceremony
        if commitment.ceremony_id != state.ceremony_id {
            return Err(MpcError::InvalidProof(
                "Commitment is for a different ceremony".into(),
            ));
        }

        // Verify commitment chains from current parameters
        if commitment.prev_params_hash != state.current_params_hash {
            return Err(MpcError::InvalidChain {
                expected: hex::encode(state.current_params_hash),
                actual: hex::encode(commitment.prev_params_hash),
            });
        }

        let commitment_hash = commitment.hash();
        drop(state);

        // Record the commitment
        let mut pending = self.pending_commitments.write();
        if pending.contains_key(&commitment_hash) {
            return Err(MpcError::DuplicateContribution(0));
        }
        pending.insert(commitment_hash, commitment);

        // Update pending count in state
        self.state.write().pending_commitment_count += 1;

        info!(
            commitment_hash = %hex::encode(commitment_hash),
            "Recorded MPC contribution commitment"
        );

        Ok(commitment_hash)
    }

    /// Check if there are pending commitments that haven't been fulfilled
    ///
    /// This is called before ossification to detect if any contributions were dropped.
    /// If there are pending commitments, ossification should be delayed or investigated.
    pub fn has_pending_commitments(&self) -> bool {
        !self.pending_commitments.read().is_empty()
    }

    /// Get the number of pending commitments
    pub fn pending_commitment_count(&self) -> usize {
        self.pending_commitments.read().len()
    }

    /// Get list of pending commitments (for audit)
    pub fn get_pending_commitments(&self) -> Vec<ContributionCommitment> {
        self.pending_commitments.read().values().cloned().collect()
    }

    /// Get list of fulfilled commitment hashes (for audit)
    pub fn get_fulfilled_commitments(&self) -> Vec<[u8; 32]> {
        self.fulfilled_commitments.read().clone()
    }

    /// Create a commitment for this contributor
    ///
    /// Convenience method that creates a properly bound commitment.
    pub fn create_commitment(&self, contributor_id: &str) -> MpcResult<ContributionCommitment> {
        let state = self.state.read();

        if state.is_ossified {
            return Err(MpcError::CeremonyOssified(state.contribution_count));
        }

        ContributionCommitment::new(contributor_id, state.current_params_hash, state.ceremony_id)
    }

    /// Verify all commitments were honored before ossification
    ///
    /// SECURITY: This should be called before finalizing the ceremony to ensure
    /// no contributions were dropped. If this returns an error, the ceremony
    /// should be considered compromised.
    pub fn verify_all_commitments_honored(&self) -> MpcResult<()> {
        let pending = self.pending_commitments.read();
        if !pending.is_empty() {
            let dropped: Vec<String> = pending.values().map(|c| c.contributor.clone()).collect();
            return Err(MpcError::Internal(format!(
                "SECURITY ALERT: {} contributions were committed but not included: {:?}",
                pending.len(),
                dropped
            )));
        }
        Ok(())
    }

    /// Initialize with genesis parameters (block circuit only — legacy)
    ///
    /// Called on first network launch to create the initial parameters.
    /// The genesis parameters are created by the network founder.
    pub fn initialize_genesis(&self, genesis_params: Parameters<Bls12>) -> MpcResult<()> {
        let mut state = self.state.write();

        if state.contribution_count > 0 {
            return Err(MpcError::Internal(
                "Cannot initialize genesis - ceremony already started".into(),
            ));
        }

        // Save genesis parameters as v0
        self.files.ensure_dir()?;
        let params_path = self.files.note_spend_params_path(0);
        save_parameters(&params_path, &genesis_params)?;
        update_current_params(&self.files, 0)?;

        // Hash parameters
        let params_hash = hash_parameters(&genesis_params)?;

        // Hot-swap
        let vk = prepare_verifying_key(&genesis_params.vk);
        *self.note_spend_params.write() = Some(Arc::new(genesis_params));
        *self.note_spend_vk.write() = Some(Arc::new(vk));

        // Update state - contribution count stays 0 for genesis
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        state.current_params_hash = params_hash;
        state.updated_at = now;
        // 4.22 SECURITY: the ceremony_id is the stable, genesis-derived constant
        // that all Schnorr proofs bind to. It equals the genesis parameters hash,
        // which is exactly what position-1's `prev_params_hash` will be — so it
        // stays identical fleet-wide for the life of the ceremony.
        state.ceremony_id = params_hash;

        info!(
            params_hash = %hex::encode(params_hash),
            "Initialized MPC ceremony with genesis parameters"
        );

        Ok(())
    }

    /// Initialize genesis with all three circuit types
    ///
    /// Generates and saves genesis parameters for note spend, consolidation, and unshield circuits.
    /// All sets go through the same MPC ceremony transformations.
    pub fn initialize_genesis_multi(
        &self,
        note_spend_params: Parameters<Bls12>,
        payout_params: Parameters<Bls12>,
        unshield_params: Parameters<Bls12>,
    ) -> MpcResult<()> {
        let mut state = self.state.write();

        if state.contribution_count > 0 {
            return Err(MpcError::Internal(
                "Cannot initialize genesis - ceremony already started".into(),
            ));
        }

        self.files.ensure_dir()?;

        // Save note spend params as v0
        save_parameters(&self.files.note_spend_params_path(0), &note_spend_params)?;
        save_verifying_key(&self.files.note_spend_vk_path(), &note_spend_params.vk)?;

        // Save payout params as v0
        save_parameters(&self.files.payout_params_path(0), &payout_params)?;
        save_verifying_key(&self.files.payout_vk_path(), &payout_params.vk)?;

        // Save unshield params as v0
        save_parameters(&self.files.unshield_params_path(0), &unshield_params)?;
        save_verifying_key(&self.files.unshield_vk_path(), &unshield_params.vk)?;

        // Update current symlinks
        update_current_params(&self.files, 0)?;

        // Hash primary (note spend) parameters for the chain
        let params_hash = hash_parameters(&note_spend_params)?;

        // Hot-swap all params into memory
        let note_spend_vk = prepare_verifying_key(&note_spend_params.vk);
        *self.note_spend_params.write() = Some(Arc::new(note_spend_params));
        *self.note_spend_vk.write() = Some(Arc::new(note_spend_vk));

        let payout_vk = prepare_verifying_key(&payout_params.vk);
        *self.payout_params.write() = Some(Arc::new(payout_params));
        *self.payout_vk.write() = Some(Arc::new(payout_vk));

        let unshield_vk = prepare_verifying_key(&unshield_params.vk);
        *self.unshield_params.write() = Some(Arc::new(unshield_params));
        *self.unshield_vk.write() = Some(Arc::new(unshield_vk));

        // Update state
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        state.current_params_hash = params_hash;
        state.updated_at = now;
        // 4.22 SECURITY: stable genesis-derived ceremony_id (= genesis params
        // hash = position-1 prev_params_hash). Identical fleet-wide; Schnorr
        // proofs bind to it. See `initialize_genesis` for the rationale.
        state.ceremony_id = params_hash;

        info!(
            params_hash = %hex::encode(params_hash),
            circuits = "note_spend + payout + unshield",
            "Initialized MPC ceremony with multi-circuit genesis parameters"
        );

        Ok(())
    }

    /// Get the parameters directory path
    pub fn params_dir(&self) -> &PathBuf {
        &self.files.dir
    }

    /// Get the parameter files manager
    pub fn files(&self) -> &ParameterFiles {
        &self.files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_manager() -> (CeremonyManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let manager = CeremonyManager::new(temp_dir.path().to_path_buf());
        (manager, temp_dir)
    }

    #[test]
    fn test_new_manager_state() {
        let (manager, _temp) = create_test_manager();

        assert_eq!(manager.contribution_count(), 0);
        assert!(!manager.is_ossified());
        assert!(!manager.has_current_params());
    }

    #[test]
    fn test_ossification() {
        let (manager, _temp) = create_test_manager();

        manager.ossify().unwrap();

        assert!(manager.is_ossified());
    }

    #[test]
    fn test_ossified_ceremony_rejects_operations() {
        let (manager, _temp) = create_test_manager();
        manager.ossify().unwrap();

        let result = manager.generate_contribution("node1");
        assert!(matches!(result, Err(MpcError::CeremonyOssified(_))));
    }

    // CRIT-2 FIX: Tests for contribution commitments

    #[test]
    fn test_commitment_tracking() {
        let (manager, _temp) = create_test_manager();

        // Initially no pending commitments
        assert!(!manager.has_pending_commitments());
        assert_eq!(manager.pending_commitment_count(), 0);

        // Create and record a commitment
        // Note: This will fail because ceremony_id is all zeros and params hash is all zeros
        // which matches default state
        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        let result = manager.record_commitment(commitment);
        assert!(result.is_ok());

        // Now there should be one pending commitment
        assert!(manager.has_pending_commitments());
        assert_eq!(manager.pending_commitment_count(), 1);
    }

    #[test]
    fn test_commitment_prevents_duplicate() {
        let (manager, _temp) = create_test_manager();

        // Record first commitment
        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        let hash = manager.record_commitment(commitment.clone()).unwrap();

        // Try to record same commitment again - should fail
        let result = manager.record_commitment(commitment);
        assert!(matches!(result, Err(MpcError::DuplicateContribution(_))));

        // Should still have only one pending
        assert_eq!(manager.pending_commitment_count(), 1);

        // Use the hash
        let _ = hash;
    }

    #[test]
    fn test_verify_all_commitments_honored_fails_with_pending() {
        let (manager, _temp) = create_test_manager();

        // Record a commitment
        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        manager.record_commitment(commitment).unwrap();

        // Verification should fail because commitment is not fulfilled
        let result = manager.verify_all_commitments_honored();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("SECURITY ALERT"),
            "Should report security alert for unfulfilled commitments"
        );
    }

    #[test]
    fn test_verify_all_commitments_honored_passes_when_empty() {
        let (manager, _temp) = create_test_manager();

        // No commitments, so verification should pass
        let result = manager.verify_all_commitments_honored();
        assert!(result.is_ok());
    }

    #[test]
    fn test_ossified_ceremony_rejects_commitments() {
        let (manager, _temp) = create_test_manager();
        manager.ossify().unwrap();

        let commitment = ContributionCommitment::new("node1", [0u8; 32], [0u8; 32]).unwrap();
        let result = manager.record_commitment(commitment);
        assert!(matches!(result, Err(MpcError::CeremonyOssified(_))));
    }

    // ========================================================================
    // Crypto lifecycle tests
    // ========================================================================

    #[test]
    fn test_genesis_initialization() {
        let (manager, _temp) = create_test_manager();

        // First init should succeed
        let result = manager.ensure_genesis_initialized();
        assert!(result.is_ok(), "Genesis init failed: {:?}", result.err());
        assert!(
            result.unwrap(),
            "Should report genesis was just initialized"
        );
        assert!(manager.has_current_params());
        assert_eq!(manager.contribution_count(), 0);

        // Second init should be idempotent (returns false = already initialized)
        let result2 = manager.ensure_genesis_initialized();
        assert!(result2.is_ok());
        assert!(
            !result2.unwrap(),
            "Second init should return false (already initialized)"
        );
    }

    #[test]
    fn test_full_contribution_lifecycle() {
        let (manager, _temp) = create_test_manager();

        // Initialize genesis
        manager.ensure_genesis_initialized().unwrap();
        let genesis_hash = manager.current_params_hash();
        assert_ne!(genesis_hash, [0u8; 32], "Genesis hash should not be zero");

        // Generate a contribution
        let (new_params, contribution) = manager.generate_contribution("node1").unwrap();
        assert_eq!(contribution.position, 1);
        assert_eq!(contribution.prev_params_hash, genesis_hash);
        assert_ne!(contribution.new_params_hash, genesis_hash);

        // Verify the contribution
        let valid = manager
            .verify_contribution(&new_params, &contribution)
            .unwrap();
        assert!(valid, "Valid contribution should verify");

        // Apply the contribution
        manager
            .apply_contribution(new_params, &contribution)
            .unwrap();
        assert_eq!(manager.contribution_count(), 1);
        assert_eq!(manager.current_params_hash(), contribution.new_params_hash);
    }

    #[test]
    fn test_multiple_contributions() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        let mut prev_hash = manager.current_params_hash();

        // Apply 3 sequential contributions
        for i in 0..3 {
            let contributor = format!("node{}", i + 1);
            let (new_params, contribution) = manager.generate_contribution(&contributor).unwrap();

            assert_eq!(contribution.position, (i + 1) as u32);
            assert_eq!(contribution.prev_params_hash, prev_hash);

            let valid = manager
                .verify_contribution(&new_params, &contribution)
                .unwrap();
            assert!(valid, "Contribution {} should verify", i + 1);

            manager
                .apply_contribution(new_params, &contribution)
                .unwrap();
            assert_eq!(manager.contribution_count(), (i + 1) as u32);

            prev_hash = manager.current_params_hash();
        }

        assert_eq!(manager.contribution_count(), 3);
    }

    #[test]
    fn test_invalid_position_rejected() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        // Generate a valid contribution at position 1
        let (new_params, mut contribution) = manager.generate_contribution("node1").unwrap();
        assert_eq!(contribution.position, 1);

        // Tamper with position
        contribution.position = 5;

        // Verification should reject wrong position
        let result = manager.verify_contribution(&new_params, &contribution);
        assert!(matches!(result, Err(MpcError::InvalidPosition(5, 1))));
    }

    #[test]
    fn test_contribution_after_ossification_rejected() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        // Ossify the ceremony
        manager.ossify().unwrap();
        assert!(manager.is_ossified());

        // Attempting to generate a contribution should fail
        let result = manager.generate_contribution("node1");
        assert!(matches!(result, Err(MpcError::CeremonyOssified(_))));
    }

    /// Drive a REAL-crypto ceremony to the cap (4 under `mpc-test-cap`) and prove
    /// autonomous ossification: at the cap the ceremony ossifies AND records the
    /// permanent file-hash pin equal to SHA-256(current.bin); a further
    /// contribution is refused (the cap is a hard ceiling).
    #[cfg(feature = "mpc-test-cap")]
    #[test]
    fn test_ceremony_autonomously_ossifies_and_records_file_hash_at_cap() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        for i in 0..MAX_CEREMONY_CONTRIBUTORS {
            assert!(!manager.is_ossified(), "must not ossify before the cap");
            let (new_params, contribution) =
                manager.generate_contribution(&format!("node{i}")).unwrap();
            manager
                .apply_contribution(new_params, &contribution)
                .unwrap();
        }

        // Ossified, with the pin recorded and equal to the raw file hash.
        assert!(manager.is_ossified(), "ceremony must ossify at the cap");
        assert_eq!(manager.contribution_count(), MAX_CEREMONY_CONTRIBUTORS);
        let expected = manager.current_params_file_hash().unwrap();
        assert_eq!(
            manager.state().ossified_file_hash,
            Some(expected),
            "ossified_file_hash must equal SHA-256(note_spend_params_current.bin)"
        );

        // The cap is a hard ceiling — a further contribution is refused by the
        // freeze guard (no MAX+1 contribution ever).
        assert!(
            matches!(
                manager.generate_contribution("node-extra"),
                Err(MpcError::CeremonyOssified(_))
            ),
            "no contribution may be generated past the cap"
        );
    }

    #[test]
    fn test_commitment_bound_contribution() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        // Create and record a commitment
        let commitment = manager.create_commitment("node1").unwrap();
        let commitment_hash = manager.record_commitment(commitment).unwrap();
        assert!(manager.has_pending_commitments());

        // Generate contribution bound to the commitment
        let (new_params, contribution) = manager
            .generate_contribution_with_commitment("node1", commitment_hash)
            .unwrap();
        assert_eq!(contribution.commitment_hash, Some(commitment_hash));

        // Apply contribution — commitment should be fulfilled
        manager
            .apply_contribution(new_params, &contribution)
            .unwrap();
        assert!(
            !manager.has_pending_commitments(),
            "Commitment should be fulfilled after apply"
        );

        // Fulfilled commitments should be tracked
        let fulfilled = manager.get_fulfilled_commitments();
        assert_eq!(fulfilled.len(), 1);
        assert_eq!(fulfilled[0], commitment_hash);
    }

    // ========================================================================
    // State loading and sync tests
    // ========================================================================

    #[test]
    fn test_load_or_init_with_existing_state() {
        let temp_dir = TempDir::new().unwrap();

        // Create a CeremonyState as if restored from the database
        let state = CeremonyState {
            contribution_count: 5,
            is_ossified: false,
            current_params_hash: [0xAB; 32],
            pending_commitment_count: 2,
            updated_at: 1700000000,
            ..CeremonyState::default()
        };

        // load_or_init with Some(state) should restore that state.
        // load_current_params will be called (count > 0) but gracefully
        // handles missing parameter files on disk.
        let manager =
            CeremonyManager::load_or_init(temp_dir.path().to_path_buf(), Some(state)).unwrap();

        let restored = manager.state();
        assert_eq!(restored.contribution_count, 5);
        assert!(!restored.is_ossified);
        assert_eq!(restored.current_params_hash, [0xAB; 32]);
        assert_eq!(restored.pending_commitment_count, 2);
        assert_eq!(restored.updated_at, 1700000000);
    }

    #[test]
    fn test_load_or_init_no_state_starts_pregenesis() {
        let temp_dir = TempDir::new().unwrap();

        // load_or_init with None should leave default (pre-genesis) state
        let manager = CeremonyManager::load_or_init(temp_dir.path().to_path_buf(), None).unwrap();

        let state = manager.state();
        assert_eq!(state.contribution_count, 0);
        assert!(!state.is_ossified);
        assert_eq!(state.current_params_hash, [0u8; 32]);
        assert_eq!(state.pending_commitment_count, 0);
        assert!(!manager.has_current_params());
    }

    #[test]
    fn test_sync_contribution_count_higher_updates() {
        let temp_dir = TempDir::new().unwrap();

        // Start with contribution_count = 3
        let state = CeremonyState {
            contribution_count: 3,
            ..CeremonyState::default()
        };
        let manager =
            CeremonyManager::load_or_init(temp_dir.path().to_path_buf(), Some(state)).unwrap();
        assert_eq!(manager.contribution_count(), 3);

        // Sync with a higher network count — should update
        manager.sync_contribution_count(10);
        assert_eq!(manager.contribution_count(), 10);
    }

    #[test]
    fn test_contribution_wrong_params_hash_rejected() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        // Generate a valid contribution
        let (new_params, mut contribution) = manager.generate_contribution("node1").unwrap();

        // Tamper: modify prev_params_hash by 1 byte
        contribution.prev_params_hash[0] ^= 0xFF;

        // Verification should reject due to hash chain mismatch
        let result = manager.verify_contribution(&new_params, &contribution);
        assert!(
            result.is_err(),
            "Tampered prev_params_hash should be rejected"
        );
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected error"),
        };
        assert!(
            err.contains("chain") || err.contains("hash") || err.contains("mismatch"),
            "Error should indicate chain/hash mismatch, got: {}",
            err
        );
    }

    #[test]
    fn test_commitment_hash_mismatch_rejected() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        // Record a commitment with hash A
        let commitment = manager.create_commitment("node1").unwrap();
        let commitment_hash = manager.record_commitment(commitment).unwrap();

        // Generate contribution claiming a DIFFERENT commitment hash
        let mut wrong_hash = commitment_hash;
        wrong_hash[0] ^= 0xFF;

        let result = manager.generate_contribution_with_commitment("node1", wrong_hash);
        assert!(
            result.is_err(),
            "Contribution with wrong commitment hash should be rejected"
        );
        let err = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected error for wrong commitment hash"),
        };
        assert!(
            err.contains("commitment") || err.contains("not found"),
            "Error should mention commitment mismatch, got: {}",
            err
        );
    }

    /// Stage C task 4: a contribution with a far-past timestamp (beyond the ±1h
    /// live skew window) is REJECTED by the live verify but ACCEPTED by the
    /// catch-up/lineage verify — every cryptographic check still passes, only the
    /// freshness window is dropped.
    #[test]
    fn test_catchup_verify_accepts_old_timestamp_live_rejects() {
        let (manager, _temp) = create_test_manager();
        manager.ensure_genesis_initialized().unwrap();

        // Capture genesis (the prev) before generating the contribution.
        let genesis = manager.note_spend_params().unwrap();

        let (new_params, mut contribution) = manager.generate_contribution("node1").unwrap();
        // Backdate well beyond the ±1h skew window (2 days ago).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        contribution.timestamp = now - 2 * 24 * 3600;

        // Live verify must reject on the skew window.
        let live = manager.verify_contribution(&new_params, &contribution);
        assert!(
            live.is_err(),
            "live verify must reject a far-past timestamp (skew window)"
        );
        assert!(live.unwrap_err().to_string().contains("timestamp"));

        // Catch-up/lineage verify must ACCEPT — crypto is identical, no skew.
        let caught_up = manager
            .verify_contribution_catchup(genesis.as_ref(), &new_params, &contribution)
            .expect("catch-up verify must not error on an old but valid contribution");
        assert!(
            caught_up,
            "catch-up verify must accept an old but cryptographically valid contribution"
        );
    }

    #[test]
    fn test_sync_contribution_count_lower_rejected() {
        let temp_dir = TempDir::new().unwrap();

        // Start with contribution_count = 10
        let state = CeremonyState {
            contribution_count: 10,
            ..CeremonyState::default()
        };
        let manager =
            CeremonyManager::load_or_init(temp_dir.path().to_path_buf(), Some(state)).unwrap();
        assert_eq!(manager.contribution_count(), 10);

        // Sync with a lower network count — should be rejected (no rollback)
        manager.sync_contribution_count(5);
        assert_eq!(
            manager.contribution_count(),
            10,
            "Contribution count must not decrease — lower network counts are rejected"
        );
    }

    /// `install_synced_head` durably installs a fetched head for a node that
    /// joined mid-flight (no sequential apply path). It must write current.bin
    /// through the atomic writer, load it into memory, advance the in-memory
    /// state to the synced head, and leave the on-disk head hashing to the
    /// recorded lineage hash — so a subsequent `load_or_init` loads it cleanly.
    #[test]
    fn test_install_synced_head_persists_current_bin() {
        // Produce a real position-1 head on a "donor" manager.
        let (donor, _donor_tmp) = create_test_manager();
        donor.ensure_genesis_initialized().unwrap();
        let (head_params, c1) = donor.generate_contribution("donor").unwrap();
        let head_hash = c1.new_params_hash;

        // A FRESH node (own dir, never ran genesis/apply) installs the synced head.
        let (joiner, tmp) = create_test_manager();
        assert!(!joiner.has_current_params());
        joiner
            .install_synced_head(1, &head_params, head_hash)
            .expect("install synced head");

        // In-memory state advanced to the synced head.
        assert_eq!(joiner.contribution_count(), 1);
        assert_eq!(joiner.current_params_hash(), head_hash);
        assert!(joiner.has_current_params());

        // On-disk current.bin exists and re-hashes to the recorded lineage head.
        let current = tmp.path().join("note_spend_params_current.bin");
        assert!(current.exists(), "current.bin must be written");
        let on_disk = crate::contribution::hash_parameters(&load_parameters(&current).unwrap())
            .expect("hash on-disk head");
        assert_eq!(
            on_disk, head_hash,
            "on-disk current.bin must be the recorded lineage head"
        );

        // A restart (load_or_init with the persisted count) loads it — NOT pre-genesis.
        let reloaded = CeremonyManager::load_or_init(
            tmp.path().to_path_buf(),
            Some(CeremonyState {
                contribution_count: 1,
                current_params_hash: head_hash,
                ..CeremonyState::default()
            }),
        )
        .unwrap();
        assert_eq!(reloaded.contribution_count(), 1);
        assert!(
            reloaded.has_current_params(),
            "restart must load the installed head, not re-init pre-genesis"
        );
    }

    /// `install_synced_head` is fail-CLOSED: a params set that does not hash to
    /// the claimed head lineage is REJECTED (never written as the current head).
    #[test]
    fn test_install_synced_head_rejects_hash_mismatch() {
        let (donor, _donor_tmp) = create_test_manager();
        donor.ensure_genesis_initialized().unwrap();
        let (head_params, _c1) = donor.generate_contribution("donor").unwrap();

        let (joiner, _tmp) = create_test_manager();
        let wrong_hash = [0x11u8; 32];
        let result = joiner.install_synced_head(1, &head_params, wrong_hash);
        assert!(
            result.is_err(),
            "params not matching the claimed head hash must be rejected"
        );
        assert!(
            !joiner.has_current_params(),
            "a rejected install must not leave a head loaded"
        );
    }
}
