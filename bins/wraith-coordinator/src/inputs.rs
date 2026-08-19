//! Per-session validated input store.
//!
//! Once a session is `Locked`, each enrolled participant submits a single
//! input UTXO + change address via `POST /api/v1/session/:id/inputs`.
//! The handler validates the submission and stashes an `AcceptedInputs`
//! record here. Once every enrolled participant has submitted, the
//! session transitions Locked → Signing.
//!
//! The data lives in `CoordinatorState::inputs_store` (a
//! `Mutex<HashMap<session_id, Vec<AcceptedInputs>>>`); this module
//! defines the record shape and the helpers that mutate it. Keeping the
//! store outside `wraith-protocol` for now — until B/4b adds the
//! blinded-token half, the protocol crate doesn't need to know about
//! input acceptance.

use serde::{Deserialize, Serialize};

use wraith_protocol::BondId;

/// One participant's accepted commit-phase submission. Records exactly
/// the fields the coordinator needs to build the round transaction in
/// `/sign` — txid + vout + value + spending script for the input, plus
/// the change address (None when the input is exact change).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedInputs {
    /// Wallet's per-round identity (matches `LiteSessionParticipant.ghost_id`).
    pub ghost_id: String,
    /// L2 bond record this input set is anchored to. Verified against
    /// the BondLedger before acceptance.
    pub bond_id: BondId,
    /// The participant's single input UTXO.
    pub input: TxInputRef,
    /// Where surplus over (denom + fee shares) goes. `None` is only
    /// legal when surplus < dust threshold; the handler enforces this.
    pub change_address: Option<String>,
    /// Unix-seconds the submission was accepted by the coordinator.
    /// Used for diagnostic / audit logging; the round-tx itself has no
    /// per-input timestamp.
    pub accepted_at: u64,
}

/// Wire-format input reference — what the wallet sends and what the
/// coordinator stores. Bitcoin types live one layer in (parsed by the
/// handler before storage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxInputRef {
    pub txid: String,
    pub vout: u32,
    pub value_sats: u64,
    /// Hex-encoded scriptPubKey of the spending output. Checked against
    /// the on-chain UTXO at registration (#699) — a submission whose
    /// script or value disagrees with the chain is refused, so by the
    /// time a record lands here every field matches the chain.
    pub scriptpubkey_hex: String,
}

impl TxInputRef {
    /// Do these two references name the same coin?
    ///
    /// Compares the outpoint only — value and scriptPubKey are derived
    /// from it, so two references to one outpoint that disagree on
    /// those are two accounts of the same coin, not two coins.
    ///
    /// `txid` is compared case-insensitively after trimming: both sides
    /// parsed as a txid before being stored, so they name the same
    /// bytes even when they differ in presentation.
    pub fn same_outpoint(&self, other: &TxInputRef) -> bool {
        self.vout == other.vout && self.txid.trim().eq_ignore_ascii_case(other.txid.trim())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(txid: &str, vout: u32, value_sats: u64) -> TxInputRef {
        TxInputRef {
            txid: txid.into(),
            vout,
            value_sats,
            scriptpubkey_hex: "deadbeef".into(),
        }
    }

    #[test]
    fn same_outpoint_ignores_presentation() {
        let lower = input(&"ab".repeat(32), 1, 100);
        let upper = input(&"AB".repeat(32), 1, 100);
        let padded = input(&format!("  {}  ", "ab".repeat(32)), 1, 100);
        assert!(lower.same_outpoint(&upper));
        assert!(lower.same_outpoint(&padded));
    }

    #[test]
    fn same_outpoint_ignores_value_and_script() {
        // Two accounts of one coin are still one coin — which is the
        // point: a disruptor must not evade the duplicate check by
        // misstating what the coin is worth.
        let a = input(&"ab".repeat(32), 0, 100);
        let mut b = input(&"ab".repeat(32), 0, 999_999);
        b.scriptpubkey_hex = "00".into();
        assert!(a.same_outpoint(&b));
    }

    #[test]
    fn a_different_vout_is_a_different_coin() {
        let a = input(&"ab".repeat(32), 0, 100);
        let b = input(&"ab".repeat(32), 1, 100);
        assert!(!a.same_outpoint(&b));
    }

    #[test]
    fn a_different_txid_is_a_different_coin() {
        let a = input(&"ab".repeat(32), 0, 100);
        let b = input(&"cd".repeat(32), 0, 100);
        assert!(!a.same_outpoint(&b));
    }
}
