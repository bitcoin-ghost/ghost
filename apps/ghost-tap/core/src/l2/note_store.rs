//! Owned note tracking for L2 confidential transfers
//!
//! Manages the wallet's confidential notes (commitments with known
//! values and blindings). Notes are serialized as JSON for encrypted
//! storage in the wallet database.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

use crate::wallet::WalletError;

/// A confidential note owned by this wallet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedNote {
    pub index: u64,
    pub value: u64,
    pub blinding: [u8; 32],
    pub spent: bool,
    pub created_height: u64,
    #[serde(default)]
    pub epoch: u64,
}

/// Result of selecting notes for a transfer
#[derive(Debug, Clone)]
pub enum NoteSelection {
    /// A single note covers the transfer amount
    Direct { note_index: u64 },
    /// Multiple notes need consolidation first
    NeedsConsolidation { plan: ConsolidationPlan },
}

#[derive(Debug, Clone)]
pub struct ConsolidationPlan {
    pub input_indices: Vec<u64>,
    pub total_value: u64,
}

/// Store for owned confidential notes.
///
/// Tracks all notes where the wallet knows the value and blinding.
/// The spending key (derived at m/352'/0'/0'/3') is used for nullifier
/// computation.
#[derive(Debug, ZeroizeOnDrop)]
pub struct NoteStore {
    #[zeroize(skip)]
    notes: HashMap<u64, OwnedNote>,
    spending_key: [u8; 32],
    #[zeroize(skip)]
    current_epoch: u64,
}

impl NoteStore {
    pub fn new(spending_key: [u8; 32]) -> Self {
        Self {
            notes: HashMap::new(),
            spending_key,
            current_epoch: 0,
        }
    }

    pub fn spending_key(&self) -> &[u8; 32] {
        &self.spending_key
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Handle an epoch transition. Marks old-epoch notes as spent (stale).
    pub fn handle_epoch_transition(&mut self, new_epoch: u64) -> bool {
        if new_epoch <= self.current_epoch {
            return false;
        }
        self.current_epoch = new_epoch;
        let mut invalidated = 0;
        for note in self.notes.values_mut() {
            if note.epoch < new_epoch && !note.spent {
                note.spent = true;
                invalidated += 1;
            }
        }
        if invalidated > 0 {
            tracing::warn!(
                new_epoch,
                invalidated,
                "Epoch transition: invalidated old-epoch notes"
            );
        }
        true
    }

    pub fn add_note(&mut self, note: OwnedNote) {
        self.notes.insert(note.index, note);
    }

    pub fn mark_spent(&mut self, index: u64) -> bool {
        if let Some(note) = self.notes.get_mut(&index) {
            note.spent = true;
            true
        } else {
            false
        }
    }

    pub fn get_note(&self, index: u64) -> Option<&OwnedNote> {
        self.notes.get(&index)
    }

    pub fn unspent_notes(&self) -> Vec<&OwnedNote> {
        self.notes.values().filter(|n| !n.spent).collect()
    }

    /// Sum of unspent note values (L2 balance).
    pub fn l2_balance(&self) -> u64 {
        self.notes
            .values()
            .filter(|n| !n.spent)
            .map(|n| n.value)
            .sum()
    }

    pub fn count(&self) -> usize {
        self.notes.len()
    }

    pub fn unspent_count(&self) -> usize {
        self.notes.values().filter(|n| !n.spent).count()
    }

    /// Select a single note that covers the required amount.
    pub fn select_note_for_transfer(&self, amount: u64) -> Result<&OwnedNote, WalletError> {
        self.notes
            .values()
            .filter(|n| !n.spent && n.value >= amount)
            .min_by_key(|n| n.value)
            .ok_or(WalletError::InsufficientBalance)
    }

    /// Select notes for a transfer: single Direct if possible, else NeedsConsolidation.
    pub fn select_notes_for_transfer(&self, amount: u64) -> Result<NoteSelection, WalletError> {
        if let Ok(note) = self.select_note_for_transfer(amount) {
            return Ok(NoteSelection::Direct {
                note_index: note.index,
            });
        }

        let total = self.l2_balance();
        if total < amount {
            return Err(WalletError::InsufficientBalance);
        }

        // Greedy selection: largest notes first, up to 4
        let mut unspent: Vec<&OwnedNote> = self.notes.values().filter(|n| !n.spent).collect();
        unspent.sort_by_key(|n| std::cmp::Reverse(n.value));

        let mut selected_indices = Vec::new();
        let mut running_total = 0u64;
        for note in &unspent {
            selected_indices.push(note.index);
            running_total += note.value;
            if running_total >= amount {
                break;
            }
            if selected_indices.len() >= 4 {
                break;
            }
        }

        if running_total >= amount {
            return Ok(NoteSelection::NeedsConsolidation {
                plan: ConsolidationPlan {
                    input_indices: selected_indices,
                    total_value: running_total,
                },
            });
        }

        // Fall back to top 4 notes (may still need multiple consolidations)
        let top_4: Vec<u64> = unspent.iter().take(4).map(|n| n.index).collect();
        let top_4_total: u64 = unspent.iter().take(4).map(|n| n.value).sum();
        Ok(NoteSelection::NeedsConsolidation {
            plan: ConsolidationPlan {
                input_indices: top_4,
                total_value: top_4_total,
            },
        })
    }

    /// Compute nullifier for a note: N = MiMC(MiMC(spending_key, note_id), NULL_DOMAIN)
    pub fn compute_nullifier(&self, note: &OwnedNote, epoch: u64) -> Result<[u8; 32], WalletError> {
        use blstrs::Scalar;
        use ghost_zkp::{bytes_to_field, field_to_bytes};

        let spending_key_fr: Scalar = bytes_to_field(&self.spending_key).map_err(|e| {
            WalletError::KeyDerivation(format!("Invalid spending key field element: {:?}", e))
        })?;
        let value_fr = Scalar::from(note.value);
        let blinding_fr: Scalar = bytes_to_field(&note.blinding).map_err(|e| {
            WalletError::KeyDerivation(format!("Invalid blinding field element: {:?}", e))
        })?;

        let commitment = ghost_zkp::pedersen_commit_native(value_fr, blinding_fr);
        let nullifier = ghost_zkp::compute_nullifier_with_epoch_native(
            spending_key_fr,
            note.index,
            epoch,
            commitment,
        );
        Ok(field_to_bytes(nullifier))
    }

    /// Try ECIES decrypt + Pedersen commitment verify for note discovery.
    pub fn try_decrypt_received_note(
        secret_key: &secp256k1::SecretKey,
        encrypted: &[u8],
        commitment: &[u8; 32],
        block_height: u64,
        epoch: u64,
    ) -> Option<OwnedNote> {
        let note_data = ghost_keys::NoteData::decrypt(secret_key, encrypted).ok()?;
        let computed =
            ghost_zkp::compute_commitment_bytes(note_data.value, &note_data.blinding).ok()?;
        if &computed != commitment {
            return None;
        }
        Some(OwnedNote {
            index: note_data.note_index,
            value: note_data.value,
            blinding: note_data.blinding,
            spent: false,
            created_height: block_height,
            epoch,
        })
    }

    /// Serialize notes to JSON for encrypted storage.
    pub fn to_json(&self) -> Result<String, WalletError> {
        let notes: Vec<&OwnedNote> = self.notes.values().collect();
        serde_json::to_string(&notes)
            .map_err(|e| WalletError::KeyDerivation(format!("Failed to serialize notes: {}", e)))
    }

    /// Deserialize notes from JSON.
    pub fn from_json(json: &str, spending_key: [u8; 32]) -> Result<Self, WalletError> {
        let notes: Vec<OwnedNote> = serde_json::from_str(json).map_err(|e| {
            WalletError::KeyDerivation(format!("Failed to deserialize notes: {}", e))
        })?;
        let mut store = Self::new(spending_key);
        for note in notes {
            store.notes.insert(note.index, note);
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> NoteStore {
        NoteStore::new([42u8; 32])
    }

    #[test]
    fn test_add_and_balance() {
        let mut store = test_store();
        store.add_note(OwnedNote {
            index: 0,
            value: 100_000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 1,
            epoch: 0,
        });
        store.add_note(OwnedNote {
            index: 1,
            value: 50_000,
            blinding: [2u8; 32],
            spent: false,
            created_height: 1,
            epoch: 0,
        });
        assert_eq!(store.l2_balance(), 150_000);
        assert_eq!(store.unspent_count(), 2);
    }

    #[test]
    fn test_mark_spent() {
        let mut store = test_store();
        store.add_note(OwnedNote {
            index: 0,
            value: 100_000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 1,
            epoch: 0,
        });
        assert!(store.mark_spent(0));
        assert_eq!(store.l2_balance(), 0);
        assert_eq!(store.unspent_count(), 0);
    }

    #[test]
    fn test_note_selection_direct() {
        let mut store = test_store();
        store.add_note(OwnedNote {
            index: 0,
            value: 100_000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 1,
            epoch: 0,
        });
        match store.select_notes_for_transfer(50_000).unwrap() {
            NoteSelection::Direct { note_index } => assert_eq!(note_index, 0),
            _ => panic!("Expected Direct selection"),
        }
    }

    #[test]
    fn test_note_selection_consolidation() {
        let mut store = test_store();
        for i in 0..3 {
            store.add_note(OwnedNote {
                index: i,
                value: 40_000,
                blinding: [i as u8; 32],
                spent: false,
                created_height: 1,
                epoch: 0,
            });
        }
        match store.select_notes_for_transfer(100_000).unwrap() {
            NoteSelection::NeedsConsolidation { plan } => {
                assert!(plan.total_value >= 100_000);
            }
            _ => panic!("Expected NeedsConsolidation"),
        }
    }

    #[test]
    fn test_epoch_transition() {
        let mut store = test_store();
        store.add_note(OwnedNote {
            index: 0,
            value: 100_000,
            blinding: [1u8; 32],
            spent: false,
            created_height: 1,
            epoch: 0,
        });
        assert!(store.handle_epoch_transition(1));
        assert_eq!(store.l2_balance(), 0); // Old-epoch note invalidated
    }

    #[test]
    fn test_json_roundtrip() {
        let mut store = test_store();
        store.add_note(OwnedNote {
            index: 5,
            value: 77_000,
            blinding: [9u8; 32],
            spent: false,
            created_height: 10,
            epoch: 2,
        });
        let json = store.to_json().unwrap();
        let restored = NoteStore::from_json(&json, [42u8; 32]).unwrap();
        assert_eq!(restored.l2_balance(), 77_000);
        assert_eq!(restored.get_note(5).unwrap().epoch, 2);
    }
}
