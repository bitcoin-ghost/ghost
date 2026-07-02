//! L2 Epoch Manager — tree compaction, valid root window, proposer rotation
//!
//! Manages the epoch lifecycle for the note/UTXO model:
//! - Commitment tree state per epoch
//! - Epoch transitions with deterministic tree compaction
//! - Valid root window (both epochs valid during transition)
//! - Deterministic proposer rotation for checkpoint blocks
//!
//! Epoch lifecycle:
//! 1. Active — current epoch accepts new notes, nullifiers tracked
//! 2. Boundary — triggered at `checkpoint_height % EPOCH_LENGTH == 0`
//! 3. Compaction — unspent notes migrated to fresh tree, nullifiers cleared
//! 4. Transition window — both old and new epoch roots valid
//! 5. Archive — old epoch archived, only new epoch active

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::types::NodeId;
use ghost_storage::Database;
use ghost_zkp::CommitmentTree;

// =============================================================================
// CONFIGURATION
// =============================================================================

/// Checkpoints per epoch (~11.5 days at 10s blocks)
pub const EPOCH_LENGTH: u64 = 100_000;

/// Transition window in checkpoints (~17 minutes at 10s blocks)
/// During this window, both old and new epoch roots are valid
pub const TRANSITION_WINDOW: u64 = 100;

/// Tree depth (~1M notes per epoch)
pub const TREE_DEPTH: usize = 20;

/// Maximum number of valid roots to keep in memory
pub const MAX_VALID_ROOTS: usize = 256;

/// Grace period for proposer no-show (in seconds)
pub const PROPOSER_GRACE_SECS: u64 = 15;

/// Configuration for the epoch manager
#[derive(Debug, Clone)]
pub struct EpochManagerConfig {
    pub epoch_length: u64,
    pub transition_window: u64,
    pub tree_depth: usize,
    pub max_valid_roots: usize,
}

impl Default for EpochManagerConfig {
    fn default() -> Self {
        Self {
            epoch_length: EPOCH_LENGTH,
            transition_window: TRANSITION_WINDOW,
            tree_depth: TREE_DEPTH,
            max_valid_roots: MAX_VALID_ROOTS,
        }
    }
}

// =============================================================================
// EPOCH STATE
// =============================================================================

/// Status of an epoch
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochStatus {
    /// Epoch is active and accepting notes
    Active,
    /// Epoch is in transition window (both old and new valid)
    Transitioning,
    /// Epoch is archived (no longer valid for new transactions)
    Archived,
}

impl EpochStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            EpochStatus::Active => "active",
            EpochStatus::Transitioning => "transitioning",
            EpochStatus::Archived => "archived",
        }
    }

    pub fn parse_status(s: &str) -> Option<Self> {
        match s {
            "active" => Some(EpochStatus::Active),
            "transitioning" => Some(EpochStatus::Transitioning),
            "archived" => Some(EpochStatus::Archived),
            _ => None,
        }
    }
}

/// Result of an epoch compaction operation
#[derive(Debug, Clone)]
pub struct CompactionResult {
    /// New epoch number
    pub new_epoch: u64,
    /// Number of unspent notes migrated
    pub notes_migrated: u64,
    /// New tree root after compaction
    pub new_initial_root: [u8; 32],
    /// Old epoch's final root
    pub old_final_root: [u8; 32],
}

// =============================================================================
// EPOCH MANAGER
// =============================================================================

/// Manages the epoch lifecycle for the L2 note/UTXO model
pub struct EpochManager {
    /// Current commitment tree
    commitment_tree: RwLock<CommitmentTree>,
    /// Current epoch number
    current_epoch: RwLock<u64>,
    /// Current checkpoint height
    current_height: RwLock<u64>,
    /// Nullifier set for current epoch
    nullifier_set: RwLock<HashSet<[u8; 32]>>,
    /// Previous epoch's nullifiers (kept during transition window for cross-epoch protection)
    transition_nullifiers: RwLock<Option<HashSet<[u8; 32]>>>,
    /// Recent valid commitment roots (for proof validation)
    valid_roots: RwLock<VecDeque<[u8; 32]>>,
    /// Sorted list of active node IDs (for proposer rotation)
    active_nodes: RwLock<Vec<NodeId>>,
    /// Database for persistence
    db: Arc<Database>,
    /// Configuration
    config: EpochManagerConfig,
    /// Whether we're in a transition window
    in_transition: RwLock<bool>,
    /// Old epoch's valid roots (kept during transition window)
    old_epoch_roots: RwLock<Vec<[u8; 32]>>,
    /// Nullifiers pending DB persistence (persisted atomically with checkpoint)
    pending_nullifiers: RwLock<Vec<([u8; 32], u64, u64)>>, // (nullifier, epoch, block_height)
}

impl EpochManager {
    /// Create a new epoch manager
    pub fn new(db: Arc<Database>, config: EpochManagerConfig) -> Self {
        let tree = CommitmentTree::new(config.tree_depth);

        Self {
            commitment_tree: RwLock::new(tree),
            current_epoch: RwLock::new(0),
            current_height: RwLock::new(0),
            nullifier_set: RwLock::new(HashSet::new()),
            transition_nullifiers: RwLock::new(None),
            valid_roots: RwLock::new(VecDeque::with_capacity(config.max_valid_roots)),
            active_nodes: RwLock::new(Vec::new()),
            db,
            config,
            in_transition: RwLock::new(false),
            old_epoch_roots: RwLock::new(Vec::new()),
            pending_nullifiers: RwLock::new(Vec::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults(db: Arc<Database>) -> Self {
        Self::new(db, EpochManagerConfig::default())
    }

    // =========================================================================
    // STATE ACCESSORS
    // =========================================================================

    /// Get current epoch number
    pub fn current_epoch(&self) -> u64 {
        *self.current_epoch.read()
    }

    /// Get current checkpoint height
    pub fn current_height(&self) -> u64 {
        *self.current_height.read()
    }

    /// Get the current commitment tree root
    pub fn current_root(&self) -> GhostResult<[u8; 32]> {
        self.commitment_tree
            .read()
            .root()
            .map_err(|e| GhostError::Internal(format!("Failed to compute tree root: {}", e)))
    }

    /// Get next available note index in the current tree
    pub fn next_note_index(&self) -> u64 {
        self.commitment_tree.read().next_index()
    }

    /// Get the number of notes in the current tree
    pub fn note_count(&self) -> usize {
        self.commitment_tree.read().note_count()
    }

    /// Clone the commitment tree for scratch computation (e.g., hypothetical root calculation).
    /// The clone is independent — mutations to it do not affect the real tree.
    pub fn clone_tree(&self) -> CommitmentTree {
        self.commitment_tree.read().clone()
    }

    /// Get the number of nullifiers in the current epoch
    pub fn nullifier_count(&self) -> usize {
        self.nullifier_set.read().len()
    }

    /// Check if we're in a transition window
    pub fn is_in_transition(&self) -> bool {
        *self.in_transition.read()
    }

    /// Get the epoch number for a checkpoint height
    pub fn epoch_for_height(&self, height: u64) -> u64 {
        height / self.config.epoch_length
    }

    /// Check if a height is an epoch boundary
    pub fn is_epoch_boundary(&self, height: u64) -> bool {
        height > 0 && height.is_multiple_of(self.config.epoch_length)
    }

    /// Get the transition window end height for an epoch boundary
    pub fn transition_end_height(&self, boundary_height: u64) -> u64 {
        boundary_height.saturating_add(self.config.transition_window)
    }

    // =========================================================================
    // INITIALIZATION (RECOVERY FROM DB)
    // =========================================================================

    /// Initialize from database state (called at startup)
    pub fn initialize(&self) -> GhostResult<()> {
        // Load active epoch
        let mut loaded_epoch: Option<u64> = None;
        let mut loaded_notes: Vec<(u64, [u8; 32])> = Vec::new();

        if let Some(epoch_record) = self.db.get_active_l2_epoch()? {
            *self.current_epoch.write() = epoch_record.epoch;
            loaded_epoch = Some(epoch_record.epoch);
            info!(epoch = epoch_record.epoch, "Restored active epoch from DB");

            // Reconstruct commitment tree from persisted notes
            let notes = self.db.load_all_l2_notes_for_epoch(epoch_record.epoch)?;
            let mut tree = CommitmentTree::new(self.config.tree_depth);
            for (index, commitment) in &notes {
                tree.insert(*index, *commitment);
            }
            *self.commitment_tree.write() = tree;
            info!(notes = notes.len(), "Reconstructed commitment tree");
            loaded_notes = notes;

            // Reconstruct nullifier set from confirmed nullifiers
            let nullifiers = self.db.load_l2_nullifiers_for_epoch(epoch_record.epoch)?;
            let mut set = HashSet::with_capacity(nullifiers.len());
            for n in &nullifiers {
                set.insert(*n);
            }
            let confirmed_count = nullifiers.len();

            // Load pending nullifiers from write-ahead log (crash recovery)
            let pending_count = match self.db.load_pending_nullifiers() {
                Ok(pending) => {
                    let count = pending.len();
                    for (n, _epoch, _height) in &pending {
                        set.insert(*n);
                    }
                    count
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load pending nullifiers from write-ahead log");
                    0
                }
            };

            *self.nullifier_set.write() = set;
            info!(
                confirmed = confirmed_count,
                pending = pending_count,
                "Reconstructed nullifier set"
            );
        }

        // Load valid roots
        let roots = self.db.get_l2_valid_roots()?;
        let mut root_deque = VecDeque::with_capacity(self.config.max_valid_roots);
        for r in roots.iter().rev() {
            root_deque.push_back(r.commitment_root);
        }
        *self.valid_roots.write() = root_deque;

        // Load latest checkpoint height and verify tree integrity
        if let Some(checkpoint) = self.db.get_latest_l2_checkpoint()? {
            *self.current_height.write() = checkpoint.height;
            info!(height = checkpoint.height, "Restored checkpoint height");

            // M-2: Startup integrity check — verify the rebuilt tree's root is consistent
            // with the latest checkpoint. If they differ, the tree may have phantom notes
            // or be missing notes. Log an error but don't panic — tree sync will fix it.
            let tree_root = self.commitment_tree.read().root().unwrap_or([0u8; 32]);
            if tree_root != checkpoint.commitment_root {
                // Check if the tree root is in the valid_roots window (it may differ from
                // the checkpoint root if there are pending shields that aren't checkpointed)
                let in_valid = self.valid_roots.read().iter().any(|r| *r == tree_root);
                if !in_valid {
                    warn!(
                        tree_root = %hex::encode(&tree_root[..8]),
                        checkpoint_root = %hex::encode(&checkpoint.commitment_root[..8]),
                        checkpoint_height = checkpoint.height,
                        "INTEGRITY: Tree root does not match any known valid root after startup rebuild. \
                         Attempting phantom note pruning before requesting tree sync."
                    );

                    // Attempt phantom note pruning
                    if let Some(epoch) = loaded_epoch {
                        match self.prune_phantom_notes(epoch, &loaded_notes, &checkpoint) {
                            Ok(pruned) if pruned > 0 => {
                                let new_root =
                                    self.commitment_tree.read().root().unwrap_or([0u8; 32]);
                                if new_root == checkpoint.commitment_root {
                                    info!(
                                        pruned,
                                        new_root = %hex::encode(&new_root[..8]),
                                        "Phantom pruning resolved tree root divergence"
                                    );
                                } else {
                                    warn!(
                                        pruned,
                                        new_root = %hex::encode(&new_root[..8]),
                                        checkpoint_root = %hex::encode(&checkpoint.commitment_root[..8]),
                                        "Phantom pruning did not fully resolve divergence — will request tree sync"
                                    );
                                }
                            }
                            Ok(_) => {
                                warn!("No phantom notes found — divergence may require tree sync from peers");
                            }
                            Err(e) => {
                                warn!(error = %e, "Phantom note pruning failed — will request tree sync");
                            }
                        }
                    }
                } else {
                    info!(
                        tree_root = %hex::encode(&tree_root[..8]),
                        checkpoint_root = %hex::encode(&checkpoint.commitment_root[..8]),
                        "Tree root differs from checkpoint root but is in valid_roots window (pending shields)"
                    );
                }
            } else {
                info!("Startup integrity check: tree root matches latest checkpoint");
            }
        }

        Ok(())
    }

    /// Initialize a fresh epoch 0 (genesis)
    pub fn initialize_genesis(&self) -> GhostResult<()> {
        let tree = CommitmentTree::new(self.config.tree_depth);
        let root = tree
            .root()
            .map_err(|e| GhostError::Internal(format!("Failed to compute genesis root: {}", e)))?;

        // Persist epoch 0
        self.db.insert_l2_epoch(&ghost_storage::L2EpochRecord {
            epoch: 0,
            start_height: 0,
            end_height: None,
            initial_root: root,
            final_root: None,
            notes_migrated: 0,
            status: "active".to_string(),
        })?;

        // Set initial valid root
        self.db.insert_l2_valid_root(0, 0, &root)?;
        self.valid_roots.write().push_back(root);

        *self.commitment_tree.write() = tree;
        *self.current_epoch.write() = 0;
        *self.current_height.write() = 0;

        info!("Initialized L2 epoch 0 (genesis)");
        Ok(())
    }

    /// Prune phantom notes — notes in l2_notes that were synced but never included
    /// in any finalized checkpoint. Scans backwards from the tail of the sorted notes
    /// to find the count N where building a tree from notes[0..N] matches the checkpoint root.
    /// Public so the checkpoint handler can trigger pruning during live operation
    /// when root divergence is detected (not just at startup).
    pub fn prune_phantom_notes(
        &self,
        epoch: u64,
        notes: &[(u64, [u8; 32])],
        checkpoint: &ghost_storage::L2CheckpointRecord,
    ) -> GhostResult<usize> {
        if notes.is_empty() {
            return Ok(0);
        }

        let target_root = checkpoint.commitment_root;

        // Reverse linear scan: start from all notes, remove from the tail one at a time.
        // Phantoms are appended after the checkpointed notes, so they'll be at the end
        // of the sorted list. Cap at 100 iterations to bound worst case.
        // Notes are already sorted by note_index (from load_all_l2_notes_for_epoch).
        let max_scan = notes.len().min(100);
        let mut found: Option<usize> = None;

        for count in (1..=notes.len()).rev().take(max_scan) {
            let mut tree = CommitmentTree::new(self.config.tree_depth);
            for (index, commitment) in notes.iter().take(count) {
                tree.insert(*index, *commitment);
            }
            let root = tree.root().unwrap_or([0u8; 32]);

            if root == target_root {
                found = Some(count);
                break;
            }
        }

        let valid_count = match found {
            Some(n) => n,
            None => {
                warn!(
                    epoch,
                    notes = notes.len(),
                    checkpoint_root = %hex::encode(&target_root[..8]),
                    "Phantom pruning: could not find any subset matching checkpoint root — skipping"
                );
                return Ok(0);
            }
        };

        let phantom_count = notes.len() - valid_count;
        if phantom_count == 0 {
            return Ok(0);
        }

        // Get the highest valid note_index
        let max_valid_index = notes[valid_count - 1].0;

        // Delete phantom notes from DB
        let deleted = self
            .db
            .delete_l2_notes_above_index(epoch, max_valid_index)?;

        // Clean up orphaned pending shields
        let pending_cleaned = self.db.delete_stale_pending_shields()?;

        // Rebuild tree with only valid notes
        let mut tree = CommitmentTree::new(self.config.tree_depth);
        for (index, commitment) in notes.iter().take(valid_count) {
            tree.insert(*index, *commitment);
        }
        *self.commitment_tree.write() = tree;

        let phantom_indices_start = max_valid_index + 1;
        let phantom_indices_end = notes.last().map(|(idx, _)| *idx).unwrap_or(0);

        warn!(
            pruned = phantom_count,
            deleted_from_db = deleted,
            pending_cleaned,
            indices = %format!("{}..{}", phantom_indices_start, phantom_indices_end),
            valid_notes = valid_count,
            checkpoint_root = %hex::encode(&target_root[..8]),
            "Pruned phantom notes (indices not in any finalized checkpoint)"
        );

        Ok(phantom_count)
    }

    // =========================================================================
    // NOTE OPERATIONS
    // =========================================================================

    /// Append a new commitment to the tree and persist
    pub fn append_commitment(&self, commitment: [u8; 32], block_height: u64) -> GhostResult<u64> {
        let epoch = self.current_epoch();
        let index = {
            let mut tree = self.commitment_tree.write();
            let idx = tree.next_index();
            tree.insert(idx, commitment);
            idx
        };

        // Persist to DB
        self.db
            .insert_l2_note(epoch, index, &commitment, block_height)?;

        debug!(
            epoch,
            index,
            height = block_height,
            "Appended note commitment"
        );
        Ok(index)
    }

    /// Insert a commitment at a specific index (used by commitment sync from peers).
    /// Unlike append_commitment, this does NOT auto-assign from next_index().
    pub fn insert_commitment_at(
        &self,
        index: u64,
        commitment: [u8; 32],
        block_height: u64,
    ) -> GhostResult<()> {
        let epoch = self.current_epoch();
        {
            let mut tree = self.commitment_tree.write();
            tree.insert(index, commitment);
        }
        self.db
            .insert_l2_note(epoch, index, &commitment, block_height)?;
        Ok(())
    }

    /// Atomically check and insert a nullifier (marks a note as spent).
    ///
    /// Uses a single write lock to prevent TOCTOU race conditions.
    /// During epoch transitions, also checks the previous epoch's nullifier set
    /// to prevent cross-epoch double-spends.
    ///
    /// Returns false if the nullifier was already spent (double-spend attempt).
    pub fn spend_nullifier(&self, nullifier: [u8; 32], block_height: u64) -> GhostResult<bool> {
        let epoch = self.current_epoch();

        // C-3 TOCTOU fix: Acquire write lock on nullifier_set FIRST to prevent race
        // where two threads both pass the transition check and then both insert.
        // The write lock serializes all spend attempts atomically.
        let mut set = self.nullifier_set.write();

        // Cross-epoch check while holding the write lock
        if let Some(ref old_set) = *self.transition_nullifiers.read() {
            if old_set.contains(&nullifier) {
                return Ok(false);
            }
        }

        // Atomic check + insert (already holding write lock)
        if !set.insert(nullifier) {
            return Ok(false); // Already spent in current epoch
        }
        drop(set);

        // Write-ahead: persist to pending_nullifiers table immediately for crash recovery.
        // This ensures nullifiers survive crashes between checkpoints.
        self.pending_nullifiers
            .write()
            .push((nullifier, epoch, block_height));

        if let Err(e) = self
            .db
            .insert_pending_nullifier(&nullifier, epoch, block_height)
        {
            warn!(epoch, height = block_height, error = %e, "Failed to write-ahead nullifier (in-memory protection still active)");
        }

        debug!(epoch, height = block_height, "Recorded nullifier");
        Ok(true)
    }

    /// Drain pending nullifiers for atomic checkpoint persistence.
    /// Returns the accumulated (nullifier, epoch, block_height) tuples.
    pub fn drain_pending_nullifiers(&self) -> Vec<([u8; 32], u64, u64)> {
        std::mem::take(&mut *self.pending_nullifiers.write())
    }

    /// Flush all pending nullifiers to the database immediately.
    /// Used during graceful shutdown and checkpoint finalization to prevent data loss.
    pub fn flush_pending_nullifiers(&self) -> GhostResult<()> {
        let pending = self.drain_pending_nullifiers();
        for (nullifier, epoch, block_height) in &pending {
            self.db
                .insert_l2_nullifier(nullifier, *epoch, *block_height)?;
        }
        // Clear write-ahead log since we've confirmed all nullifiers
        self.db.confirm_pending_nullifiers()?;
        Ok(())
    }

    /// Check if a nullifier is already spent (current epoch + transition window)
    pub fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        if self.nullifier_set.read().contains(nullifier) {
            return true;
        }
        // Cross-epoch check during transition window
        if let Some(ref old_set) = *self.transition_nullifiers.read() {
            if old_set.contains(nullifier) {
                return true;
            }
        }
        false
    }

    // =========================================================================
    // VALID ROOT MANAGEMENT
    // =========================================================================

    /// Add a valid root after a checkpoint is finalized
    pub fn add_valid_root(&self, root: [u8; 32], height: u64) -> GhostResult<()> {
        let epoch = self.current_epoch();

        // Add to in-memory deque
        {
            let mut roots = self.valid_roots.write();
            roots.push_back(root);
            while roots.len() > self.config.max_valid_roots {
                roots.pop_front();
            }
        }

        // Persist
        self.db.insert_l2_valid_root(height, epoch, &root)?;

        // Prune old roots in DB
        self.db
            .prune_l2_valid_roots(self.config.max_valid_roots as u64)?;

        Ok(())
    }

    /// Check if a commitment root is valid (for proof verification)
    ///
    /// During transition windows, roots from both epochs are valid.
    pub fn is_root_valid(&self, root: &[u8; 32]) -> bool {
        // Check current epoch roots
        if self.valid_roots.read().contains(root) {
            return true;
        }

        // During transition, also check old epoch roots
        if *self.in_transition.read() && self.old_epoch_roots.read().contains(root) {
            return true;
        }

        false
    }

    // =========================================================================
    // PROPOSER ROTATION
    // =========================================================================

    /// Update the sorted active node list
    pub fn update_active_nodes(&self, mut nodes: Vec<NodeId>) {
        nodes.sort();
        *self.active_nodes.write() = nodes;
    }

    /// Get the number of active nodes
    pub fn active_node_count(&self) -> usize {
        self.active_nodes.read().len()
    }

    /// Get the designated proposer for a checkpoint height
    ///
    /// Deterministic rotation: `sorted_active_nodes[height % len]`
    pub fn get_proposer(&self, height: u64) -> Option<NodeId> {
        let nodes = self.active_nodes.read();
        if nodes.is_empty() {
            return None;
        }
        let idx = (height as usize) % nodes.len();
        Some(nodes[idx])
    }

    /// Get the fallback proposer (next in line if primary no-shows)
    pub fn get_fallback_proposer(&self, height: u64) -> Option<NodeId> {
        let nodes = self.active_nodes.read();
        if nodes.len() < 2 {
            return None;
        }
        let idx = ((height as usize) + 1) % nodes.len();
        Some(nodes[idx])
    }

    /// Check if a given node is the designated proposer for a height
    pub fn is_proposer(&self, node_id: &NodeId, height: u64) -> bool {
        self.get_proposer(height)
            .map(|p| &p == node_id)
            .unwrap_or(false)
    }

    /// Determine which validator should handle a nullifier
    ///
    /// Deterministic routing: `u64::from_le_bytes(nullifier[0..8]) % active_node_count`
    pub fn validator_for_nullifier(&self, nullifier: &[u8; 32]) -> Option<NodeId> {
        let nodes = self.active_nodes.read();
        if nodes.is_empty() {
            return None;
        }
        let hash_val = u64::from_le_bytes(nullifier[0..8].try_into().unwrap());
        let idx = (hash_val as usize) % nodes.len();
        Some(nodes[idx])
    }

    /// Get our index in the active node list
    pub fn our_index(&self, our_id: &NodeId) -> Option<usize> {
        self.active_nodes.read().iter().position(|n| n == our_id)
    }

    // =========================================================================
    // EPOCH TRANSITIONS
    // =========================================================================

    /// Process a checkpoint finalization
    ///
    /// Called after a checkpoint block is finalized by BFT.
    /// Handles epoch boundary detection and transitions.
    pub fn on_checkpoint_finalized(&self, height: u64) -> GhostResult<Option<CompactionResult>> {
        *self.current_height.write() = height;

        // M-4: Flush pending nullifiers to the permanent set on every finalized checkpoint.
        // This ensures nullifiers from accepted transactions are committed before
        // any epoch boundary logic runs, preventing double-spend windows.
        self.flush_pending_nullifiers()?;

        // Check if we're in a transition window that should end
        if *self.in_transition.read() {
            let epoch = self.current_epoch();
            let boundary = epoch.saturating_mul(self.config.epoch_length);
            if height >= self.transition_end_height(boundary) {
                self.end_transition()?;
            }
        }

        // Check for epoch boundary
        if self.is_epoch_boundary(height) {
            let result = self.begin_epoch_transition(height)?;
            return Ok(Some(result));
        }

        Ok(None)
    }

    /// Begin an epoch transition (tree compaction)
    ///
    /// All nodes run this deterministically — same inputs → same output.
    fn begin_epoch_transition(&self, boundary_height: u64) -> GhostResult<CompactionResult> {
        let old_epoch = self.current_epoch();
        let new_epoch = old_epoch + 1;

        info!(
            old_epoch,
            new_epoch, boundary_height, "Beginning epoch transition"
        );

        // 1. Capture old epoch's final root
        let old_final_root = self.current_root()?;

        // 2. Save old epoch roots for transition window
        {
            let valid = self.valid_roots.read();
            *self.old_epoch_roots.write() = valid.iter().copied().collect();
        }
        *self.in_transition.write() = true;

        // 3. Collect unspent notes from old epoch
        let unspent_notes = self.db.load_unspent_l2_notes(old_epoch)?;
        let notes_migrated = unspent_notes.len() as u64;

        // 4. Persist epoch records BEFORE migrating notes (FK trigger on l2_notes.epoch)
        let old_final_root_copy = old_final_root;
        self.db.finalize_l2_epoch(
            old_epoch,
            boundary_height,
            &old_final_root_copy,
            notes_migrated,
        )?;

        // Insert new epoch record before any l2_notes reference it.
        // Initial root computed after tree build; use placeholder, update below.
        //
        // The row may already exist if it was materialised by a tree-sync
        // payload (a joining node can receive the peer's authoritative epoch
        // record before it locally replays this boundary). In that case leave
        // the existing row untouched — the peer's data is authoritative and a
        // plain INSERT would trip the PRIMARY KEY constraint.
        let epoch_row_exists = self.db.get_l2_epoch(new_epoch)?.is_some();
        if !epoch_row_exists {
            self.db.insert_l2_epoch(&ghost_storage::L2EpochRecord {
                epoch: new_epoch,
                start_height: boundary_height,
                end_height: None,
                initial_root: [0u8; 32], // placeholder, updated after tree build
                final_root: None,
                notes_migrated: 0,
                status: "active".to_string(),
            })?;
        }

        // 5. Build new tree from unspent notes (deterministic order)
        let mut new_tree = CommitmentTree::new(self.config.tree_depth);
        for (new_idx, note) in unspent_notes.iter().enumerate() {
            new_tree.insert(new_idx as u64, note.commitment);

            // Persist migrated note in new epoch (FK satisfied: l2_epochs row exists)
            self.db
                .insert_l2_note(new_epoch, new_idx as u64, &note.commitment, boundary_height)?;
        }

        let new_initial_root = new_tree
            .root()
            .map_err(|e| GhostError::Internal(format!("Failed to compute new root: {}", e)))?;

        // Update epoch record with actual initial root (only for a freshly
        // inserted row — do not overwrite an authoritative synced record).
        if !epoch_row_exists {
            self.db
                .update_l2_epoch_initial_root(new_epoch, &new_initial_root)?;
        }

        // 6. Swap trees and move nullifiers to transition set for cross-epoch protection
        *self.commitment_tree.write() = new_tree;
        let old_nullifiers = std::mem::take(&mut *self.nullifier_set.write());
        *self.transition_nullifiers.write() = Some(old_nullifiers);
        *self.current_epoch.write() = new_epoch;

        // 7. Add new root to valid roots
        {
            let mut roots = self.valid_roots.write();
            roots.push_back(new_initial_root);
            while roots.len() > self.config.max_valid_roots {
                roots.pop_front();
            }
        }

        self.db
            .insert_l2_valid_root(boundary_height, new_epoch, &new_initial_root)?;

        info!(
            old_epoch,
            new_epoch, notes_migrated, "Epoch transition complete"
        );

        Ok(CompactionResult {
            new_epoch,
            notes_migrated,
            new_initial_root,
            old_final_root,
        })
    }

    /// End the transition window (old epoch roots no longer valid)
    fn end_transition(&self) -> GhostResult<()> {
        *self.in_transition.write() = false;
        *self.transition_nullifiers.write() = None;
        self.old_epoch_roots.write().clear();

        let epoch = self.current_epoch();
        let prev_epoch = epoch.saturating_sub(1);

        // Clean up old epoch nullifiers from DB
        let deleted = self.db.delete_l2_nullifiers_for_epoch(prev_epoch)?;

        info!(
            epoch,
            prev_epoch,
            nullifiers_cleaned = deleted,
            "Transition window closed"
        );

        Ok(())
    }

    /// Get merkle proof for a note at the given index
    pub fn get_merkle_proof(&self, index: u64) -> GhostResult<Vec<[u8; 32]>> {
        let tree = self.commitment_tree.read();
        let proof = tree
            .get_proof(index)
            .map_err(|e| GhostError::Internal(format!("Failed to get merkle proof: {}", e)))?;
        Ok(proof.siblings.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Arc<Database>, EpochManager) {
        let db = Arc::new(Database::in_memory().expect("Failed to create in-memory DB"));
        let config = EpochManagerConfig {
            epoch_length: 10, // Short epochs for testing
            transition_window: 3,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let mgr = EpochManager::new(db.clone(), config);
        (db, mgr)
    }

    #[test]
    fn test_epoch_for_height() {
        let (_db, mgr) = setup();
        assert_eq!(mgr.epoch_for_height(0), 0);
        assert_eq!(mgr.epoch_for_height(9), 0);
        assert_eq!(mgr.epoch_for_height(10), 1);
        assert_eq!(mgr.epoch_for_height(19), 1);
        assert_eq!(mgr.epoch_for_height(20), 2);
    }

    #[test]
    fn test_epoch_boundary() {
        let (_db, mgr) = setup();
        assert!(!mgr.is_epoch_boundary(0));
        assert!(!mgr.is_epoch_boundary(1));
        assert!(!mgr.is_epoch_boundary(9));
        assert!(mgr.is_epoch_boundary(10));
        assert!(!mgr.is_epoch_boundary(11));
        assert!(mgr.is_epoch_boundary(20));
    }

    #[test]
    fn test_genesis_initialization() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        assert_eq!(mgr.current_epoch(), 0);
        assert_eq!(mgr.current_height(), 0);
        assert_eq!(mgr.note_count(), 0);
        assert_eq!(mgr.nullifier_count(), 0);

        // Should have one valid root
        assert!(!mgr.valid_roots.read().is_empty());
    }

    #[test]
    fn test_append_commitment() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // Use small values that fit in BLS12-381 scalar field
        let mut c1 = [0u8; 32];
        c1[0] = 0xAB;
        let idx = mgr.append_commitment(c1, 1).unwrap();
        assert_eq!(idx, 0);

        let mut c2 = [0u8; 32];
        c2[0] = 0xCD;
        let idx2 = mgr.append_commitment(c2, 1).unwrap();
        assert_eq!(idx2, 1);

        assert_eq!(mgr.note_count(), 2);
    }

    #[test]
    fn test_nullifier_spend() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        let nullifier = [0x42; 32];
        assert!(!mgr.is_nullifier_spent(&nullifier));

        let spent = mgr.spend_nullifier(nullifier, 1).unwrap();
        assert!(spent);
        assert!(mgr.is_nullifier_spent(&nullifier));

        // Double spend should fail
        let double = mgr.spend_nullifier(nullifier, 2).unwrap();
        assert!(!double);
    }

    #[test]
    fn test_valid_root_management() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        let root1 = [0x11; 32];
        let root2 = [0x22; 32];
        let fake_root = [0xFF; 32];

        mgr.add_valid_root(root1, 1).unwrap();
        mgr.add_valid_root(root2, 2).unwrap();

        assert!(mgr.is_root_valid(&root1));
        assert!(mgr.is_root_valid(&root2));
        assert!(!mgr.is_root_valid(&fake_root));
    }

    #[test]
    fn test_proposer_rotation() {
        let (_db, mgr) = setup();

        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        let node_c = [0x03; 32];

        mgr.update_active_nodes(vec![node_c, node_a, node_b]); // Will be sorted

        assert_eq!(mgr.active_node_count(), 3);

        // Sorted: node_a, node_b, node_c
        let p0 = mgr.get_proposer(0).unwrap();
        let p1 = mgr.get_proposer(1).unwrap();
        let p2 = mgr.get_proposer(2).unwrap();
        let p3 = mgr.get_proposer(3).unwrap();

        assert_eq!(p0, node_a); // 0 % 3 = 0
        assert_eq!(p1, node_b); // 1 % 3 = 1
        assert_eq!(p2, node_c); // 2 % 3 = 2
        assert_eq!(p3, node_a); // 3 % 3 = 0 (wraps)

        assert!(mgr.is_proposer(&node_a, 0));
        assert!(!mgr.is_proposer(&node_b, 0));
    }

    #[test]
    fn test_nullifier_routing() {
        let (_db, mgr) = setup();

        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        mgr.update_active_nodes(vec![node_a, node_b]);

        let nullifier = [0u8; 32]; // hash_val = 0, 0 % 2 = 0
        let validator = mgr.validator_for_nullifier(&nullifier).unwrap();
        assert_eq!(validator, node_a);

        let mut nullifier2 = [0u8; 32];
        nullifier2[0] = 1; // hash_val = 1, 1 % 2 = 1
        let validator2 = mgr.validator_for_nullifier(&nullifier2).unwrap();
        assert_eq!(validator2, node_b);
    }

    #[test]
    fn test_epoch_transition() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // Use small values that fit in BLS12-381 scalar field
        let mut c1 = [0u8; 32];
        c1[0] = 0x11;
        let mut c2 = [0u8; 32];
        c2[0] = 0x22;
        let mut c3 = [0u8; 32];
        c3[0] = 0x33;
        mgr.append_commitment(c1, 1).unwrap();
        mgr.append_commitment(c2, 2).unwrap();
        mgr.append_commitment(c3, 3).unwrap();

        // Spend one note (c2)
        let nullifier = [0x42; 32];
        mgr.spend_nullifier(nullifier, 4).unwrap();
        mgr.db.mark_l2_note_spent(0, 1).unwrap(); // Mark note at index 1 as spent

        assert_eq!(mgr.note_count(), 3);
        assert_eq!(mgr.nullifier_count(), 1);

        // Process checkpoints up to boundary
        for h in 1..10 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            let result = mgr.on_checkpoint_finalized(h).unwrap();
            assert!(result.is_none());
        }

        // Trigger epoch transition at boundary (height 10)
        let root = mgr.current_root().unwrap();
        mgr.add_valid_root(root, 10).unwrap();
        let result = mgr.on_checkpoint_finalized(10).unwrap();
        assert!(result.is_some());

        let compaction = result.unwrap();
        assert_eq!(compaction.new_epoch, 1);
        assert_eq!(compaction.notes_migrated, 2); // 3 notes - 1 spent = 2 migrated

        // State should be updated
        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(mgr.nullifier_count(), 0); // Nullifiers cleared
        assert!(mgr.is_in_transition()); // In transition window

        // Old roots should still be valid during transition
        assert!(mgr.is_root_valid(&root));
    }

    #[test]
    fn test_transition_window_ends() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // Add a note and trigger epoch transition at height 10
        let mut c = [0u8; 32];
        c[0] = 0x11;
        mgr.append_commitment(c, 1).unwrap();
        for h in 1..=10 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        assert!(mgr.is_in_transition());

        // Process through transition window (3 checkpoints)
        for h in 11..=13 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        // Transition should be over
        assert!(!mgr.is_in_transition());
    }

    #[test]
    fn test_recovery_from_db() {
        let (db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // Use small values that fit in BLS12-381 scalar field
        let mut c1 = [0u8; 32];
        c1[0] = 1;
        let mut c2 = [0u8; 32];
        c2[0] = 2;

        // Add notes and valid roots
        mgr.append_commitment(c1, 1).unwrap();
        mgr.append_commitment(c2, 2).unwrap();
        mgr.spend_nullifier([0x42; 32], 3).unwrap();

        // Flush pending nullifiers to DB (simulates checkpoint finalization)
        mgr.flush_pending_nullifiers().unwrap();

        let root = mgr.current_root().unwrap();
        mgr.add_valid_root(root, 3).unwrap();

        // Create a new manager pointing to same DB (simulates restart)
        let config = EpochManagerConfig {
            epoch_length: 10,
            transition_window: 3,
            tree_depth: 4,
            max_valid_roots: 16,
        };
        let mgr2 = EpochManager::new(db, config);
        mgr2.initialize().unwrap();

        // State should be restored
        assert_eq!(mgr2.current_epoch(), 0);
        assert_eq!(mgr2.note_count(), 2);
        assert_eq!(mgr2.nullifier_count(), 1);
        assert!(mgr2.is_nullifier_spent(&[0x42; 32]));
    }

    #[test]
    fn test_cross_epoch_double_spend_prevention() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // Add notes and spend one
        let mut c1 = [0u8; 32];
        c1[0] = 0x11;
        let mut c2 = [0u8; 32];
        c2[0] = 0x22;
        mgr.append_commitment(c1, 1).unwrap();
        mgr.append_commitment(c2, 2).unwrap();

        let nullifier = [0x42; 32];
        assert!(mgr.spend_nullifier(nullifier, 3).unwrap());

        // Mark note as spent in DB
        mgr.db.mark_l2_note_spent(0, 0).unwrap();

        // Process to epoch boundary
        for h in 1..=10 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        // Now in transition — current nullifier_set is empty, transition_nullifiers has old set
        assert!(mgr.is_in_transition());
        assert_eq!(mgr.nullifier_count(), 0); // Current epoch has no nullifiers

        // Cross-epoch double-spend attempt: same nullifier in new epoch
        assert!(!mgr.spend_nullifier(nullifier, 11).unwrap());

        // Also check is_nullifier_spent
        assert!(mgr.is_nullifier_spent(&nullifier));

        // New nullifier should work fine
        let new_nullifier = [0x99; 32];
        assert!(mgr.spend_nullifier(new_nullifier, 11).unwrap());

        // After transition window closes, old nullifiers are dropped
        for h in 11..=13 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }
        assert!(!mgr.is_in_transition());

        // Old nullifier no longer checked (transition window closed)
        // DB-level protection still applies, but in-memory check passes
        assert!(!mgr.is_nullifier_spent(&nullifier));
    }

    #[test]
    fn test_atomic_nullifier_insert() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        let nullifier = [0x42; 32];

        // First insert succeeds
        assert!(mgr.spend_nullifier(nullifier, 1).unwrap());

        // Second insert fails atomically
        assert!(!mgr.spend_nullifier(nullifier, 2).unwrap());

        // Only one nullifier recorded
        assert_eq!(mgr.nullifier_count(), 1);
    }

    #[test]
    fn test_no_active_nodes() {
        let (_db, mgr) = setup();

        assert!(mgr.get_proposer(0).is_none());
        assert!(mgr.get_fallback_proposer(0).is_none());
        assert_eq!(mgr.active_node_count(), 0);
    }

    #[test]
    fn test_fallback_proposer() {
        let (_db, mgr) = setup();

        let node_a = [0x01; 32];
        let node_b = [0x02; 32];
        mgr.update_active_nodes(vec![node_a, node_b]);

        let primary = mgr.get_proposer(0).unwrap();
        let fallback = mgr.get_fallback_proposer(0).unwrap();

        assert_ne!(primary, fallback);
        assert_eq!(primary, node_a);
        assert_eq!(fallback, node_b);
    }

    #[test]
    fn test_epoch_transition_multiple_notes_partial_spend() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // Add 5 notes in epoch 0 (small values fitting BLS12-381 scalar field)
        let mut commitments = Vec::new();
        for i in 1u8..=5 {
            let mut c = [0u8; 32];
            c[0] = i;
            mgr.append_commitment(c, i as u64).unwrap();
            commitments.push(c);
        }
        assert_eq!(mgr.note_count(), 5);

        // Spend notes at index 1 and 3 (the 2nd and 4th notes)
        let nullifier_a = [0xAA; 32];
        let nullifier_b = [0xBB; 32];
        mgr.spend_nullifier(nullifier_a, 6).unwrap();
        mgr.spend_nullifier(nullifier_b, 6).unwrap();
        mgr.db.mark_l2_note_spent(0, 1).unwrap(); // note index 1
        mgr.db.mark_l2_note_spent(0, 3).unwrap(); // note index 3

        assert_eq!(mgr.nullifier_count(), 2);

        // Process checkpoints up to boundary (epoch_length = 10)
        for h in 1..10 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            let result = mgr.on_checkpoint_finalized(h).unwrap();
            assert!(result.is_none());
        }

        // Trigger epoch transition at boundary height 10
        let root_before = mgr.current_root().unwrap();
        mgr.add_valid_root(root_before, 10).unwrap();
        let result = mgr.on_checkpoint_finalized(10).unwrap();
        assert!(result.is_some());

        let compaction = result.unwrap();
        assert_eq!(compaction.new_epoch, 1);
        assert_eq!(compaction.notes_migrated, 3); // 5 notes - 2 spent = 3 migrated

        // Verify state after transition
        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(mgr.note_count(), 3); // Only 3 unspent notes in new tree
        assert_eq!(mgr.nullifier_count(), 0); // Nullifiers cleared for new epoch
        assert!(mgr.is_in_transition());

        // Verify the new tree root differs from the old one (different note set)
        let new_root = mgr.current_root().unwrap();
        assert_ne!(new_root, root_before);
    }

    /// Test that old epoch roots become invalid after the transition window closes.
    ///
    /// Uses max_valid_roots=4 so the target root ages out of the sliding window
    /// during the transition, while remaining accessible via old_epoch_roots.
    /// After the transition ends, old_epoch_roots is cleared → root becomes invalid.
    #[test]
    fn test_old_roots_invalid_after_transition_closes() {
        let db = Arc::new(Database::in_memory().expect("in-memory db"));
        let config = EpochManagerConfig {
            epoch_length: 10,
            transition_window: 3,
            tree_depth: 4,
            max_valid_roots: 4, // Small window so old roots age out
        };
        let mgr = EpochManager::new(db, config);
        mgr.initialize_genesis().unwrap();

        // Add unique commitments at each height to create distinct roots
        for h in 1..=6 {
            let mut c = [0u8; 32];
            c[0] = h as u8;
            mgr.append_commitment(c, h).unwrap();
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        // At height 7: capture this root. With max_valid_roots=4, it will be in
        // valid_roots at the epoch boundary [r7, r8, r9, r10] and copied to
        // old_epoch_roots during transition. The new epoch root then pushes r7
        // out of valid_roots, leaving it accessible ONLY via old_epoch_roots.
        let mut c7 = [0u8; 32];
        c7[0] = 7;
        mgr.append_commitment(c7, 7).unwrap();
        let target_root = mgr.current_root().unwrap();
        mgr.add_valid_root(target_root, 7).unwrap();
        mgr.on_checkpoint_finalized(7).unwrap();

        // Heights 8-9: add distinct commitments (epoch boundary at 10)
        for h in 8..=9 {
            let mut c = [0u8; 32];
            c[0] = h as u8;
            mgr.append_commitment(c, h).unwrap();
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        // Height 10: epoch boundary → transition starts
        // valid_roots before transition: [r7, r8, r9, r10_root]
        // old_epoch_roots = {r7, r8, r9, r10_root}
        // Then new initial root is pushed → valid_roots = [r8, r9, r10_root, r_new]
        // target_root (r7) is now ONLY in old_epoch_roots
        let mut c10 = [0u8; 32];
        c10[0] = 10;
        mgr.append_commitment(c10, 10).unwrap();
        let root10 = mgr.current_root().unwrap();
        mgr.add_valid_root(root10, 10).unwrap();
        mgr.on_checkpoint_finalized(10).unwrap();

        assert!(mgr.is_in_transition());
        assert!(
            mgr.is_root_valid(&target_root),
            "Target root should be valid during transition (via old_epoch_roots)"
        );

        // Close the transition window (heights 11-13)
        for h in 11..=13 {
            let mut c = [0u8; 32];
            c[0] = h as u8;
            mgr.append_commitment(c, h).unwrap();
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        assert!(!mgr.is_in_transition());
        assert!(
            !mgr.is_root_valid(&target_root),
            "Target root should be INVALID after transition window closes"
        );
    }

    /// Test that nullifiers from the old epoch are cleared from DB after transition window
    #[test]
    fn test_transition_window_expiry_clears_nullifiers() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // Add notes and spend one in epoch 0
        let mut c = [0u8; 32];
        c[0] = 0x11;
        mgr.append_commitment(c, 1).unwrap();

        let nullifier = [0x42; 32];
        mgr.spend_nullifier(nullifier, 2).unwrap();
        mgr.db.mark_l2_note_spent(0, 0).unwrap();
        mgr.flush_pending_nullifiers().unwrap();

        assert!(mgr.is_nullifier_spent(&nullifier));

        // Process to epoch boundary (height 10)
        for h in 1..=10 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        assert!(mgr.is_in_transition());
        // During transition, old nullifier should still be detected
        assert!(
            mgr.is_nullifier_spent(&nullifier),
            "Nullifier should be detected during transition"
        );

        // Close transition window (3 more)
        for h in 11..=13 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        assert!(!mgr.is_in_transition());
        // After transition closes, in-memory old nullifiers are cleared
        assert!(
            !mgr.is_nullifier_spent(&nullifier),
            "Old epoch nullifiers should be cleared after transition window closes"
        );
    }

    /// Test concurrent double-spend attempts on the same nullifier
    #[test]
    fn test_concurrent_double_spend_prevention() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        let nullifier = [0x42; 32];

        // Use std threads to simulate racing spends
        let mgr = std::sync::Arc::new(mgr);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let mgr1 = mgr.clone();
        let barrier1 = barrier.clone();
        let handle1 = std::thread::spawn(move || {
            barrier1.wait();
            mgr1.spend_nullifier(nullifier, 1)
        });

        let mgr2 = mgr.clone();
        let barrier2 = barrier.clone();
        let handle2 = std::thread::spawn(move || {
            barrier2.wait();
            mgr2.spend_nullifier(nullifier, 2)
        });

        let result1 = handle1.join().unwrap().unwrap();
        let result2 = handle2.join().unwrap().unwrap();

        // Exactly one should succeed (return true), one should fail (return false)
        assert!(
            (result1 && !result2) || (!result1 && result2),
            "Exactly one spend should succeed: result1={}, result2={}",
            result1,
            result2
        );

        // Only one nullifier recorded
        assert_eq!(mgr.nullifier_count(), 1);
    }

    #[test]
    fn test_double_epoch_transition() {
        let (_db, mgr) = setup();
        mgr.initialize_genesis().unwrap();

        // --- Epoch 0: Add 3 notes, spend 1 ---
        for i in 1u8..=3 {
            let mut c = [0u8; 32];
            c[0] = i;
            mgr.append_commitment(c, i as u64).unwrap();
        }
        mgr.spend_nullifier([0xAA; 32], 4).unwrap();
        mgr.db.mark_l2_note_spent(0, 0).unwrap(); // Spend note at index 0
        assert_eq!(mgr.note_count(), 3);

        // Advance to epoch boundary at height 10
        for h in 1..10 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        let root = mgr.current_root().unwrap();
        mgr.add_valid_root(root, 10).unwrap();
        let result = mgr.on_checkpoint_finalized(10).unwrap();
        assert!(result.is_some());

        let compaction1 = result.unwrap();
        assert_eq!(compaction1.new_epoch, 1);
        assert_eq!(compaction1.notes_migrated, 2); // 3 - 1 spent = 2 migrated
        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(mgr.note_count(), 2);

        // End transition window (heights 11-13, transition_window = 3)
        for h in 11..=13 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }
        assert!(!mgr.is_in_transition());

        // --- Epoch 1: Add 2 more notes, spend none ---
        for i in 10u8..=11 {
            let mut c = [0u8; 32];
            c[0] = i;
            mgr.append_commitment(c, 14 + (i - 10) as u64).unwrap();
        }
        assert_eq!(mgr.note_count(), 4); // 2 migrated + 2 new

        // Advance to next epoch boundary at height 20
        for h in 14..20 {
            let root = mgr.current_root().unwrap();
            mgr.add_valid_root(root, h).unwrap();
            mgr.on_checkpoint_finalized(h).unwrap();
        }

        let root = mgr.current_root().unwrap();
        mgr.add_valid_root(root, 20).unwrap();
        let result = mgr.on_checkpoint_finalized(20).unwrap();
        assert!(result.is_some());

        let compaction2 = result.unwrap();
        assert_eq!(compaction2.new_epoch, 2);
        assert_eq!(compaction2.notes_migrated, 4); // All 4 unspent notes migrated

        // Final state
        assert_eq!(mgr.current_epoch(), 2);
        assert_eq!(mgr.note_count(), 4); // All accumulated unspent notes in final tree
        assert_eq!(mgr.nullifier_count(), 0);
        assert!(mgr.is_in_transition());
    }
}
