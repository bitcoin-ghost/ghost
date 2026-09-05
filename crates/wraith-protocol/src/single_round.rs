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
//| FILE: single_round.rs                                                                                                |
//|======================================================================================================================|

//! Wraith Lite v1 — single-round atomic CoinJoin transaction builder.
//!
//! Built fresh against `DESIGN_LITE.md`. Coexists with the legacy
//! `executor::WraithTransactionBuilder` during the v1 refactor; once every
//! caller has migrated, `executor.rs` is deleted in a single subtractive
//! commit.
//!
//! ## Transaction shape
//!
//! ```text
//! inputs (N, one per participant):
//!   txid, vout, script_pubkey, amount == denom + fee_share EXACTLY
//!
//! outputs (shuffled with ChaCha20Rng seeded from session_id + entropy):
//!   N × mixed output     value = tier.denomination_sats()
//!   1 × service fee      value = N × tier.service_fee_sats()  [Mix only]
//! ```
//!
//! ## Why there is no change output (#698)
//!
//! A change output is linkable. It pays back to an address the participant
//! controls, in an amount derived from their own input, in the same
//! transaction as their mixed output — which hands an observer the
//! input → participant → round association the round exists to break. Equal
//! values are what buy the anonymity set, and a per-participant remainder of
//! a distinctive size is the one output in the transaction that is not equal
//! to anything.
//!
//! So inputs must be exact. Master spec §7.1: "the solver composes entries
//! to exact denominations … Change is never a vault output of a different
//! value in the same round."
//!
//! The cost is stated rather than hidden: a wallet whose coin is not already
//! exact must first make a **preparatory split** — an ordinary transaction
//! producing one output of exactly `min_participant_input()`, with the
//! remainder going back to the wallet's own everyday funds. That transaction
//! is visible and marks the wallet as preparing to mix. That is a known,
//! accepted cost, and it is a smaller one than carrying the link into the
//! round itself, because the prep transaction does not reveal *which* output
//! of the round is theirs.
//!
//! Jump rounds (`SessionType::Jump`) skip the service-fee output entirely —
//! they pay only mining cost. Existing test machinery for Jump rounds
//! (`test_891_full_jump_session_lifecycle`) maps to this builder unchanged
//! once callers swap from `WraithTransactionBuilder`.
//!
//! ## What's intentionally absent
//!
//! - No `outputs_per_participant` (OPP). Single round = 1 mixed output per
//!   participant. The legacy two-phase needed OPP to fan-out 1→10 in Phase 1
//!   then merge 10→1 in Phase 2; we don't.
//! - No `fee_pad` budgeting for a follow-on phase. Single round = single
//!   transaction, all mining fees come straight from participant inputs.
//! - No Phase 1 vs Phase 2 vbyte differential. One transaction shape, one
//!   size estimate, one confirmation wait.
//! - No `intermediate_addresses` parameter — all destination addresses are
//!   final-mixed addresses, presented anonymously (and unblinded) by the
//!   wallet during `session.submit_token` (DESIGN_LITE.md §5).

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

use crate::error::WraithError;
use crate::tier::{LiteTier, VBYTES_PER_INPUT, VBYTES_PER_OUTPUT};
use crate::SessionType;

/// Default mining fee rate (sats/vbyte). Wallets can override per-round if
/// the network is congested. Matches the existing default in
/// `WraithTransactionBuilder` to keep behaviour comparable on the same
/// fee market.
pub const DEFAULT_FEE_RATE_SATS_PER_VB: u64 = 10;

/// Minimum sat value for a change output. Below this we don't emit the
/// change output and let the dust go to mining fees instead. Matches
/// `bitcoin::policy::DUST_THRESHOLD_P2WPKH` semantics — picked at 546
/// because that's the Bitcoin Core default for non-zero-value outputs.
pub const CHANGE_DUST_THRESHOLD_SATS: u64 = 546;

/// One participant's contribution to a Lite round — a single input UTXO and
/// the destination address where their mixed output should land. The address
/// has already been unblinded by the wallet (via `blind.rs`) and presented
/// anonymously to the coordinator over a separate connection.
#[derive(Debug, Clone)]
pub struct LiteParticipantInput {
    pub txid: Txid,
    pub vout: u32,
    /// On-chain value of this input. Must be ≥ `tier.denomination_sats() +
    /// per-participant fee share`, **exactly** — see the module docs on why
    /// there is no change output. Coordinator validates this at registration
    /// before the input is registered.
    pub amount_sats: u64,
    /// Spending script for signature/witness validation. Coordinator checks
    /// it matches what's actually on-chain.
    pub script_pubkey: ScriptBuf,
    /// Anonymous destination for this participant's mixed denom-sized output
    /// (presented via unblinded token, never linked to participant_id at
    /// submission time).
    pub mixed_output_address: String,
    /// Internal participant index. NOT visible on chain — used only for
    /// diagnostics / claim accounting.
    pub participant_id: u32,
}

/// Builder for a Wraith Lite round transaction. One instance per round.
///
/// Caller pattern: construct → `add_participant()` per participant →
/// `build()` to produce the unsigned `LiteRound` ready for signature
/// collection.
#[derive(Debug)]
pub struct LiteRoundBuilder {
    /// Unique session identifier. Used as the ChaCha20Rng output-shuffle
    /// seed input.
    pub session_id: String,
    /// Tier for this round. Determines denomination, service fee, and
    /// participant caps.
    pub tier: LiteTier,
    /// Network the on-chain transaction is targeting. Address parsing
    /// validates against this.
    pub network: Network,
    /// Mix vs. Jump. Jump rounds skip the service-fee output (mining cost
    /// only); Mix rounds include it.
    pub session_type: SessionType,
    /// Coordinator's fee-collection address. Required for Mix rounds;
    /// ignored on Jump.
    pub coordinator_fee_address: Option<String>,
    /// Mining-fee rate. Defaults to `DEFAULT_FEE_RATE_SATS_PER_VB`.
    pub fee_rate_sats_per_vb: u64,
    /// Participant inputs accumulated via `add_participant()`.
    participants: Vec<LiteParticipantInput>,
}

impl LiteRoundBuilder {
    /// Construct a builder for a Mix round. The coordinator's fee address
    /// is mandatory; service fee output goes there.
    pub fn new_mix(
        session_id: String,
        tier: LiteTier,
        network: Network,
        coordinator_fee_address: String,
    ) -> Self {
        Self {
            session_id,
            tier,
            network,
            session_type: SessionType::Mix,
            coordinator_fee_address: Some(coordinator_fee_address),
            fee_rate_sats_per_vb: DEFAULT_FEE_RATE_SATS_PER_VB,
            participants: Vec::new(),
        }
    }

    /// Construct a builder for a Jump round. No service fee — mining cost
    /// only — so no coordinator fee address is needed.
    pub fn new_jump(session_id: String, tier: LiteTier, network: Network) -> Self {
        Self {
            session_id,
            tier,
            network,
            session_type: SessionType::Jump,
            coordinator_fee_address: None,
            fee_rate_sats_per_vb: DEFAULT_FEE_RATE_SATS_PER_VB,
            participants: Vec::new(),
        }
    }

    /// Register a participant's input + destination address.
    ///
    /// The input must be worth **exactly** `min_participant_input()`. Not
    /// "at least": a round has no change output, so any surplus would have
    /// nowhere to go but the mining fee, and any shortfall would unbalance
    /// the transaction (#698).
    pub fn add_participant(&mut self, input: LiteParticipantInput) -> Result<(), WraithError> {
        if self.participants.len() >= self.tier.max_participants() {
            return Err(WraithError::InvalidInput(format!(
                "tier {} is at max_participants ({})",
                self.tier,
                self.tier.max_participants()
            )));
        }
        let needed = self.min_participant_input();
        if input.amount_sats != needed {
            return Err(WraithError::InvalidInput(format!(
                "participant {} input is {} sats; a round input must be exactly {} sats \
                 (denomination + fee shares) because rounds have no change output",
                input.participant_id, input.amount_sats, needed
            )));
        }
        self.participants.push(input);
        Ok(())
    }

    /// Minimum on-chain input value a participant must contribute. Sum of:
    ///   * denomination (the mixed output they receive)
    ///   * mining-fee share (their fraction of the round's mining fee)
    ///   * service-fee share (Mix only — their contribution to the
    ///     coordinator's fee output)
    ///
    /// Computed against `tier.max_participants()` for the worst-case mining
    /// fee, so the per-participant amount is constant regardless of how
    /// many people end up in the round. Smaller rounds end up paying
    /// slightly more mining fee than strictly needed (the surplus goes
    /// into the implicit mining-fee bucket); the alternative — varying
    /// per-participant share with `N` — would move the amount a
    /// participant already committed to when the round fills past where
    /// they joined, which is nasty UX.
    pub fn min_participant_input(&self) -> u64 {
        self.tier.denomination_sats()
            + self.per_participant_mining_share()
            + self.per_participant_service_share()
    }

    /// Worst-case mining-fee share per participant in sats.
    ///
    /// Computed against `tier.min_participants()` (not max), because the
    /// per-participant share is *highest* at the smallest N: the fixed
    /// overhead (the service-fee output) is divided across fewer
    /// participants. This way every participant pre-pays enough that the
    /// round's mining fee is covered even if it broadcasts at the floor.
    /// Larger rounds end up slightly overpaying mining fee — which is
    /// fine, the surplus just makes the tx more attractive to miners.
    pub fn per_participant_mining_share(&self) -> u64 {
        per_participant_mining_share(self.tier, self.session_type, self.fee_rate_sats_per_vb)
    }

    /// Service-fee share per participant. Mix rounds: equals
    /// `tier.service_fee_sats()`. Jump rounds: zero.
    pub fn per_participant_service_share(&self) -> u64 {
        match self.session_type {
            SessionType::Mix => self.tier.service_fee_sats(),
            SessionType::Jump => 0,
        }
    }

    /// How many participants have registered so far.
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Estimated mining fee, in satoshis, for the round transaction at the
    /// current participant count. Pre-shuffle estimate — exact final size
    /// will be deterministic once `build()` runs.
    pub fn estimate_mining_fee_sats(&self) -> u64 {
        self.estimate_vbytes() * self.fee_rate_sats_per_vb
    }

    /// Build the unsigned round transaction. Caller fills in input scripts
    /// and witnesses during the Signing phase; the transaction structure
    /// (inputs, outputs, ordering) is finalised here and shared with all
    /// participants.
    ///
    /// `entropy` is 32 bytes of fresh CSPRNG entropy mixed into the output
    /// shuffle seed alongside the session_id. Production callers use
    /// `getrandom`; tests can pass deterministic entropy via
    /// `build_with_entropy()`.
    pub fn build(&self) -> Result<LiteRound, WraithError> {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| WraithError::InvalidInput(format!("entropy: {e}")))?;
        self.build_with_entropy(&entropy)
    }

    /// Build with caller-supplied entropy. **Test path only** in production —
    /// using non-CSPRNG entropy makes the output ordering predictable and
    /// breaks the privacy claim. Marked pub for fuzz harnesses.
    pub fn build_with_entropy(&self, entropy: &[u8; 32]) -> Result<LiteRound, WraithError> {
        if self.participants.len() < self.tier.min_participants() {
            return Err(WraithError::NotEnoughParticipants(
                self.participants.len(),
                self.tier.min_participants(),
            ));
        }
        if self.session_type == SessionType::Mix && self.coordinator_fee_address.is_none() {
            return Err(WraithError::InvalidInput(
                "Mix round requires coordinator_fee_address".into(),
            ));
        }

        // Inputs: one TxIn per participant, then SHUFFLED.
        //
        // The inputs themselves are observable on chain — but their *order*
        // is not. Order is a coordinator choice, and registration order
        // encodes arrival sequence into the transaction, which the chain
        // would not otherwise reveal. Anyone who watched registrations (or
        // who correlates submission timing) could then map position back to
        // participant. Free to remove, so remove it.
        //
        // The permutation is derived from a DIFFERENT domain tag than the
        // output shuffle. Reusing one seed for both would make input index i
        // and output index i correlated, handing back the very mapping the
        // output shuffle exists to destroy.
        let mut tx_inputs: Vec<TxIn> = Vec::with_capacity(self.participants.len());
        for p in &self.participants {
            tx_inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: p.txid,
                    vout: p.vout,
                },
                script_sig: ScriptBuf::new(),
                // Enable RBF — matches the existing executor.rs choice. Lets
                // the coordinator bump fees if the round gets stuck in
                // mempool during a fee-market spike.
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
        }

        shuffle_with_chacha(&mut tx_inputs, self.input_shuffle_seed(entropy));

        // Build the *outputs* in canonical order, then shuffle. We tag each
        // output with provenance so we can shuffle (kind, idx, address, sats)
        // tuples and rebuild TxOuts after.
        let denom = self.tier.denomination_sats();
        let mut outputs: Vec<LiteOutputItem> = Vec::new();

        // Mixed (denom-sized) outputs — one per participant.
        for p in &self.participants {
            outputs.push(LiteOutputItem {
                kind: LiteOutputKind::Mixed,
                participant_id: Some(p.participant_id),
                address: p.mixed_output_address.clone(),
                amount_sats: denom,
            });
        }

        // Change outputs — only when the participant's surplus exceeds dust.
        // Service-fee output (Mix only). Sum of every participant's fee
        // share, paid to the coordinator's fee address.
        if self.session_type == SessionType::Mix {
            let fee_addr = self
                .coordinator_fee_address
                .as_ref()
                .expect("checked above when session_type == Mix");
            outputs.push(LiteOutputItem {
                kind: LiteOutputKind::ServiceFee,
                participant_id: None,
                address: fee_addr.clone(),
                amount_sats: self.tier.service_fee_sats() * self.participants.len() as u64,
            });
        }

        // Shuffle. Mixed + change + fee outputs all participate. After
        // shuffle no-one (not even the coordinator) can recover the
        // input→mixed-output mapping by output ordering.
        let seed = self.shuffle_seed(entropy);
        shuffle_with_chacha(&mut outputs, seed);

        // Convert to TxOut.
        let mut tx_outputs: Vec<TxOut> = Vec::with_capacity(outputs.len() + 1);
        let mut output_provenance: Vec<LiteOutputProvenance> = Vec::with_capacity(outputs.len());
        for (final_idx, item) in outputs.into_iter().enumerate() {
            let address = Address::from_str(&item.address)
                .map_err(|e| WraithError::InvalidInput(format!("address {}: {e}", item.address)))?
                .require_network(self.network)
                .map_err(|e| WraithError::InvalidInput(format!("network mismatch: {e}")))?;
            tx_outputs.push(TxOut {
                value: Amount::from_sat(item.amount_sats),
                script_pubkey: address.script_pubkey(),
            });
            output_provenance.push(LiteOutputProvenance {
                tx_output_index: final_idx,
                kind: item.kind,
                participant_id: item.participant_id,
                amount_sats: item.amount_sats,
            });
        }

        // Sanity: total_in must cover total_out + estimated mining fee.
        let total_in: u64 = self.participants.iter().map(|p| p.amount_sats).sum();
        let total_out: u64 = tx_outputs.iter().map(|o| o.value.to_sat()).sum();
        let mining_fee = total_in.saturating_sub(total_out);
        let expected_mining_fee = self.estimate_mining_fee_sats();
        if mining_fee < expected_mining_fee {
            return Err(WraithError::InsufficientFee(
                expected_mining_fee,
                mining_fee,
            ));
        }

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_inputs,
            output: tx_outputs,
        };

        Ok(LiteRound {
            session_id: self.session_id.clone(),
            tier: self.tier,
            session_type: self.session_type,
            tx,
            output_provenance,
            mining_fee_sats: mining_fee,
        })
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Estimate the round transaction size in vbytes at the current
    /// participant count. Used for fee calculation.
    fn estimate_vbytes(&self) -> u64 {
        self.estimate_vbytes_for_count(self.participants.len())
    }

    fn estimate_vbytes_for_count(&self, n: usize) -> u64 {
        round_vbytes(n, self.session_type)
    }

    /// Derive a 32-byte ChaCha20Rng seed from session_id + caller entropy.
    /// Same construction used by the legacy executor — keeps the privacy
    /// argument (output ordering is unpredictable per session, even to
    /// participants) consistent across versions.
    /// Seed for the input permutation.
    ///
    /// Domain-separated from [`Self::shuffle_seed`] on purpose: a shared seed
    /// would correlate input and output positions and undo the output shuffle.
    fn input_shuffle_seed(&self, entropy: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"WraithLite/v1/input_shuffle");
        h.update(self.session_id.as_bytes());
        h.update(entropy);
        h.finalize().into()
    }

    fn shuffle_seed(&self, entropy: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"WraithLite/v1/output_shuffle");
        h.update(self.session_id.as_bytes());
        h.update(entropy);
        h.finalize().into()
    }
}

/// One output item before shuffling. Internal — not part of the public API.
#[derive(Debug, Clone)]
struct LiteOutputItem {
    kind: LiteOutputKind,
    participant_id: Option<u32>,
    address: String,
    amount_sats: u64,
}

/// What kind of output this is. Used internally during build, exported via
/// `LiteOutputProvenance` so callers can audit the round's structure
/// without re-deriving it from amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiteOutputKind {
    /// One of the equal-denomination mixed outputs. The privacy-relevant
    /// output — participants want their input → this mapping to be
    /// unrecoverable.
    Mixed,
    /// Coordinator's service-fee aggregate. Mix rounds only.
    ServiceFee,
}

/// Per-output audit metadata. The wallet uses this to identify which
/// output index in the final tx is "their" mixed output (the one matching
/// their mixed_output_address). Coordinator publishes the same data so
/// every participant can verify the construction.
#[derive(Debug, Clone)]
pub struct LiteOutputProvenance {
    /// Index in the final transaction's `output` vector.
    pub tx_output_index: usize,
    pub kind: LiteOutputKind,
    /// `Some` for Mixed/Change (the participant whose address it goes to);
    /// `None` for ServiceFee.
    pub participant_id: Option<u32>,
    pub amount_sats: u64,
}

/// Result of `LiteRoundBuilder::build()`: the unsigned round transaction, plus the
/// structural metadata participants use to verify their interest is represented
/// correctly before they sign.
#[derive(Debug, Clone)]
pub struct LiteRound {
    pub session_id: String,
    pub tier: LiteTier,
    pub session_type: SessionType,
    pub tx: Transaction,
    /// One entry per output, in TxOut order. Lets a
    /// participant locate their mixed output and verify its amount
    /// without trusting the coordinator's word.
    pub output_provenance: Vec<LiteOutputProvenance>,
    /// Total mining fee paid by the round (total_in − total_out).
    pub mining_fee_sats: u64,
}

impl LiteRound {
    /// Returns the txid the eventual signed transaction will have.
    /// Useful for participants to record before signature collection.
    pub fn txid(&self) -> Txid {
        self.tx.compute_txid()
    }

    /// Number of mixed outputs. Should equal participant count.
    pub fn mixed_output_count(&self) -> usize {
        self.output_provenance
            .iter()
            .filter(|p| p.kind == LiteOutputKind::Mixed)
            .count()
    }
}

/// Worst-case round size in vbytes for `n` participants.
///
/// **Single source of truth.** The coordinator's minimum-input check and the
/// builder's fee computation must agree exactly: the coordinator admits a
/// participant only if their input covers `denom + service share + mining
/// share`, and the builder then spends against the real transaction. If the
/// two calculations drift, participants are admitted having paid the wrong
/// amount and the round either underpays its mining fee or silently
/// overcharges. This function existed twice — once here, once in the
/// coordinator — and the copies diverged when #695 removed an output.
///
/// No change outputs exist any more (#698), so this is exact rather than
/// worst-case in that dimension.
pub fn round_vbytes(n: usize, session_type: SessionType) -> u64 {
    // n inputs + n mixed outputs + (1 service fee if Mix). The second `n`
    // that used to be here was the change outputs, and it was still being
    // charged for after they were removed — every participant pre-paying
    // mining fee for an output the round no longer builds (#698).
    let outputs = n + match session_type {
        SessionType::Mix => 1,
        SessionType::Jump => 0,
    };
    ((n * VBYTES_PER_INPUT) + (outputs * VBYTES_PER_OUTPUT)) as u64
}

/// Per-participant mining-fee share, in sats.
///
/// Computed against `tier.min_participants()` rather than the actual count,
/// because the per-participant share is *highest* at the smallest N — fixed
/// overhead amortised across fewest participants. Every participant therefore
/// pre-pays enough to cover the round even if it broadcasts at the floor;
/// larger rounds overpay slightly, which only makes the tx more attractive to
/// miners.
pub fn per_participant_mining_share(
    tier: LiteTier,
    session_type: SessionType,
    fee_rate_sats_per_vb: u64,
) -> u64 {
    let n = tier.min_participants() as u64;
    let total = round_vbytes(tier.min_participants(), session_type) * fee_rate_sats_per_vb;
    total.div_ceil(n)
}

/// ChaCha20Rng output shuffle. Same construction as the legacy
/// `shuffle_outputs` in executor.rs, just generic over the items so we can
/// shuffle our `LiteOutputItem`s directly.
fn shuffle_with_chacha<T>(items: &mut [T], seed: [u8; 32]) {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    let mut rng = ChaCha20Rng::from_seed(seed);
    items.shuffle(&mut rng);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::PubkeyHash;

    // -- helpers --------------------------------------------------------

    /// Generate a deterministic, structurally-valid signet P2WPKH address
    /// from a single-byte tag. Addresses don't correspond to a real key —
    /// we just need bech32-valid strings the bitcoin crate's parser
    /// accepts. Tag bytes are scattered through a 20-byte hash160 so each
    /// address has a unique witness program.
    fn test_addr(tag: u8) -> String {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        seed[31] = tag.wrapping_add(1);
        let hash = hash160::Hash::hash(&seed);
        let pkhash = PubkeyHash::from_byte_array(hash.to_byte_array());
        Address::p2pkh(pkhash, Network::Signet).to_string()
        // Note: p2pkh produces "m..."/"n..." prefixes for signet/testnet,
        // not bech32. That's fine for our tests — we just need the address
        // string to round-trip through Address::from_str + require_network
        // for the shape assertions; we never actually spend these.
    }

    /// Convenience: collect six addresses tagged 1..=6 plus the fee
    /// address tagged 0xFE. Reused across tests so each test stays focused
    /// on the round mechanics, not address derivation.
    fn test_addrs() -> [String; 7] {
        [
            test_addr(1),
            test_addr(2),
            test_addr(3),
            test_addr(4),
            test_addr(5),
            test_addr(6),
            test_addr(0xFE), // fee address
        ]
    }

    fn fake_input(participant_id: u32, amount_sats: u64, mixed_addr: &str) -> LiteParticipantInput {
        let txid = Txid::from_byte_array([participant_id as u8; 32]);
        let script = ScriptBuf::new();
        LiteParticipantInput {
            txid,
            vout: 0,
            amount_sats,
            script_pubkey: script,
            mixed_output_address: mixed_addr.into(),
            participant_id,
        }
    }

    /// The exact input every participant must bring, for the fixture tier.
    /// Rounds have no change output, so this is the only acceptable value.
    fn exact_input_sats() -> u64 {
        mix_builder_with_addrs(&test_addrs()).min_participant_input()
    }

    /// The exact input for a Jump round, which differs from a Mix round's:
    /// Jump rounds have no service-fee output, so no service-fee share.
    fn jump_exact_input_sats() -> u64 {
        LiteRoundBuilder::new_jump("sizing".into(), LiteTier::Denom100kSats, Network::Signet)
            .min_participant_input()
    }

    fn mix_builder_with_addrs(addrs: &[String; 7]) -> LiteRoundBuilder {
        LiteRoundBuilder::new_mix(
            "test-session-001".into(),
            LiteTier::Denom100kSats,
            Network::Signet,
            addrs[6].clone(),
        )
    }

    /// Build a 5-participant Mix round. Every participant brings exactly
    /// the required input, which is the only shape a round accepts (#698).
    /// The canonical "happy path" fixture across multiple tests.
    fn happy_mix_round(addrs: &[String; 7], entropy: &[u8; 32]) -> LiteRound {
        let mut b = mix_builder_with_addrs(addrs);
        for (i, addr) in addrs.iter().enumerate().take(5) {
            b.add_participant(fake_input(i as u32, exact_input_sats(), addr))
                .unwrap();
        }
        b.build_with_entropy(entropy).unwrap()
    }

    // -- tests ---------------------------------------------------------

    #[test]
    fn add_participant_rejects_under_min_amount() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        // Just denomination, no fee_share buffer — should reject.
        let too_small = fake_input(0, 100_000, &addrs[0]);
        let err = b.add_participant(too_small).unwrap_err();
        match err {
            WraithError::InvalidInput(msg) => {
                assert!(msg.contains("exactly"), "msg = {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    /// An input worth *more* than the requirement is refused, not trimmed
    /// (#698). There is nowhere for the surplus to go: a change output is
    /// linkable, and silently donating it to miners would take a
    /// participant's money without telling them.
    #[test]
    fn add_participant_rejects_an_input_above_the_exact_amount() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        let err = b
            .add_participant(fake_input(0, exact_input_sats() + 10_000, &addrs[0]))
            .unwrap_err();
        match err {
            WraithError::InvalidInput(msg) => {
                assert!(msg.contains("exactly"), "msg = {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    /// One sat short is still short.
    #[test]
    fn add_participant_rejects_an_input_one_sat_below() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        assert!(b
            .add_participant(fake_input(0, exact_input_sats() - 1, &addrs[0]))
            .is_err());
    }

    #[test]
    fn add_participant_caps_at_max() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        // Fill to max (20).
        for i in 0..LiteTier::Denom100kSats.max_participants() as u32 {
            b.add_participant(fake_input(i, exact_input_sats(), &addrs[0]))
                .unwrap();
        }
        // The 21st must reject.
        let err = b
            .add_participant(fake_input(99, exact_input_sats(), &addrs[0]))
            .unwrap_err();
        assert!(matches!(err, WraithError::InvalidInput(_)));
    }

    #[test]
    fn build_rejects_below_min_participants() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        // Only 4 participants, min is 5.
        for i in 0..4 {
            b.add_participant(fake_input(i, exact_input_sats(), &addrs[i as usize]))
                .unwrap();
        }
        let err = b.build_with_entropy(&[0u8; 32]).unwrap_err();
        match err {
            WraithError::NotEnoughParticipants(have, need) => {
                assert_eq!(have, 4);
                assert_eq!(need, 5);
            }
            other => panic!("expected NotEnoughParticipants, got {other:?}"),
        }
    }

    #[test]
    fn mix_round_has_exactly_n_mixed_outputs_and_one_fee_output() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        let p_amt = b.min_participant_input();
        for (i, addr) in addrs.iter().enumerate().take(5) {
            b.add_participant(fake_input(i as u32, p_amt, addr))
                .unwrap();
        }
        let round = b.build_with_entropy(&[0u8; 32]).unwrap();
        assert_eq!(round.mixed_output_count(), 5);
        let fees = round
            .output_provenance
            .iter()
            .filter(|p| p.kind == LiteOutputKind::ServiceFee)
            .count();
        assert_eq!(fees, 1);
        // Every output is either a mixed output or the single fee output.
        // There is no third kind any more, and the count proves it (#698).
        assert_eq!(round.output_provenance.len(), 6);
    }

    #[test]
    fn jump_round_has_no_service_fee_output() {
        let addrs = test_addrs();
        let mut b = LiteRoundBuilder::new_jump(
            "jump-test".into(),
            LiteTier::Denom100kSats,
            Network::Signet,
        );
        for (i, addr) in addrs.iter().enumerate().take(5) {
            b.add_participant(fake_input(i as u32, jump_exact_input_sats(), addr))
                .unwrap();
        }
        let round = b.build_with_entropy(&[0u8; 32]).unwrap();
        assert_eq!(round.mixed_output_count(), 5);
        let fees = round
            .output_provenance
            .iter()
            .filter(|p| p.kind == LiteOutputKind::ServiceFee)
            .count();
        assert_eq!(fees, 0, "Jump rounds must NOT have a service fee output");
    }

    #[test]
    fn mixed_outputs_are_all_exactly_denom() {
        let addrs = test_addrs();
        let round = happy_mix_round(&addrs, &[42u8; 32]);
        let denom = LiteTier::Denom100kSats.denomination_sats();
        for prov in &round.output_provenance {
            if prov.kind == LiteOutputKind::Mixed {
                assert_eq!(
                    prov.amount_sats, denom,
                    "mixed output {} has wrong amount",
                    prov.tx_output_index
                );
            }
        }
    }

    #[test]
    fn output_shuffle_is_deterministic_per_seed() {
        // Same builder + same entropy must produce same output ordering.
        // This is what makes the shuffle auditable across all participants.
        let addrs = test_addrs();
        let r1 = happy_mix_round(&addrs, &[7u8; 32]);
        let r2 = happy_mix_round(&addrs, &[7u8; 32]);
        let order1: Vec<_> = r1
            .output_provenance
            .iter()
            .map(|p| (p.kind, p.participant_id, p.amount_sats))
            .collect();
        let order2: Vec<_> = r2
            .output_provenance
            .iter()
            .map(|p| (p.kind, p.participant_id, p.amount_sats))
            .collect();
        assert_eq!(order1, order2);
    }

    #[test]
    fn output_shuffle_changes_with_entropy() {
        // Different entropy → different output ordering (with overwhelming
        // probability for ≥6 outputs). Chance of collision is bounded by
        // 1/N! where N is output count.
        let addrs = test_addrs();
        let mut b1 = mix_builder_with_addrs(&addrs);
        let mut b2 = mix_builder_with_addrs(&addrs);
        for i in 0..6 {
            let addr = if i < 6 { &addrs[i % 6] } else { &addrs[0] };
            let p = fake_input(i as u32, exact_input_sats(), addr);
            b1.add_participant(p.clone()).unwrap();
            b2.add_participant(p).unwrap();
        }
        let r1 = b1.build_with_entropy(&[1u8; 32]).unwrap();
        let r2 = b2.build_with_entropy(&[2u8; 32]).unwrap();
        let order1: Vec<_> = r1
            .output_provenance
            .iter()
            .map(|p| (p.kind, p.participant_id))
            .collect();
        let order2: Vec<_> = r2
            .output_provenance
            .iter()
            .map(|p| (p.kind, p.participant_id))
            .collect();
        assert_ne!(order1, order2, "shuffle should change with entropy");
    }

    /// A round transaction must carry no marker of any kind (#695).
    ///
    /// The `WL01` OP_RETURN existed so "chain analysis tools that want to
    /// identify Wraith txs can do so cheaply" — which labelled every
    /// participant as having used a mixer, permanently and publicly, and made
    /// the round transaction self-identifying. Structure is still
    /// recognisable (equal-value outputs are the anonymity set); an explicit
    /// tag is not, and must never come back.
    #[test]
    fn round_tx_carries_no_marker() {
        let addrs = test_addrs();
        let round = happy_mix_round(&addrs, &[0u8; 32]);

        assert!(
            !round
                .tx
                .output
                .iter()
                .any(|o| o.script_pubkey.is_op_return()),
            "round tx must contain no OP_RETURN output"
        );
        assert!(
            !round.tx.output.iter().any(|o| o.value == Amount::ZERO),
            "round tx must contain no zero-value output"
        );
        for o in &round.tx.output {
            let bytes = o.script_pubkey.as_bytes();
            let printable: String = bytes.iter().map(|&b| b as char).collect();
            assert!(
                !printable.contains("WL01"),
                "WL01 marker must not appear in any output: {printable:?}"
            );
            assert!(
                !printable.contains("test-session-001"),
                "session_id must never appear on-chain: {printable:?}"
            );
        }
    }

    /// Every output in a Mix round is either one of the equal-value mixed
    /// outputs or the single fee output. There is no per-participant
    /// remainder, because a remainder is linkable to the participant who
    /// produced it and is the one output in the transaction that is not
    /// equal to anything else (#698).
    #[test]
    fn a_round_produces_only_equal_mixed_outputs_and_one_fee_output() {
        let addrs = test_addrs();
        let round = happy_mix_round(&addrs, &[0u8; 32]);

        let denom = LiteTier::Denom100kSats.denomination_sats();
        let mixed: Vec<_> = round
            .output_provenance
            .iter()
            .filter(|p| p.kind == LiteOutputKind::Mixed)
            .collect();
        assert_eq!(mixed.len(), 5);
        for m in &mixed {
            assert_eq!(m.amount_sats, denom, "mixed outputs must be equal");
        }

        let fees: Vec<_> = round
            .output_provenance
            .iter()
            .filter(|p| p.kind == LiteOutputKind::ServiceFee)
            .collect();
        assert_eq!(fees.len(), 1);

        assert_eq!(
            round.output_provenance.len(),
            mixed.len() + fees.len(),
            "no output may be anything other than a mixed output or the fee"
        );
    }

    #[test]
    fn mining_fee_is_collected_from_inputs() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        let p_amt = b.min_participant_input();
        for i in 0..5u32 {
            b.add_participant(fake_input(i, p_amt, &addrs[i as usize]))
                .unwrap();
        }
        let round = b.build_with_entropy(&[0u8; 32]).unwrap();
        let total_in = p_amt * 5;
        let total_out: u64 = round.tx.output.iter().map(|o| o.value.to_sat()).sum();
        let mining = total_in - total_out;
        assert_eq!(round.mining_fee_sats, mining);
        assert!(mining >= b.estimate_mining_fee_sats());
    }

    /// Registration order must not survive into the transaction. Nothing
    /// asserted this before, which is why the leak lived so long: the inputs
    /// are observable on chain, but their *order* was a coordinator choice
    /// that encoded arrival sequence.
    #[test]
    fn inputs_do_not_appear_in_registration_order() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        // Distinguishable txids so position is identifiable.
        for (i, addr) in addrs.iter().enumerate().take(5) {
            b.add_participant(fake_input(i as u32, exact_input_sats(), addr))
                .unwrap();
        }
        let registered: Vec<OutPoint> = (0..5u32)
            .map(|i| {
                let p = fake_input(i, exact_input_sats(), &addrs[i as usize]);
                OutPoint {
                    txid: p.txid,
                    vout: p.vout,
                }
            })
            .collect();

        let round = b.build_with_entropy(&[0x5A; 32]).unwrap();
        let in_tx: Vec<OutPoint> = round.tx.input.iter().map(|i| i.previous_output).collect();

        assert_ne!(
            in_tx, registered,
            "input order still leaks arrival sequence"
        );

        // Same coins, only reordered — nothing added, dropped or duplicated.
        let mut a = in_tx.clone();
        let mut b2 = registered.clone();
        a.sort_unstable();
        b2.sort_unstable();
        assert_eq!(
            a, b2,
            "the shuffle must permute, never alter, the input set"
        );
    }

    /// If input and output permutations shared a seed, index i on each side
    /// would correlate and hand back the mapping the output shuffle exists to
    /// destroy. Domain separation is what prevents that.
    #[test]
    fn input_and_output_permutations_are_independent() {
        let addrs = test_addrs();
        let mut b = mix_builder_with_addrs(&addrs);
        for (i, addr) in addrs.iter().enumerate().take(5) {
            b.add_participant(fake_input(i as u32, exact_input_sats(), addr))
                .unwrap();
        }
        let entropy = [0x5A; 32];
        assert_ne!(
            b.input_shuffle_seed(&entropy),
            b.shuffle_seed(&entropy),
            "input and output shuffles must not share a seed"
        );
    }

    #[test]
    fn txid_is_stable_for_same_construction() {
        let addrs = test_addrs();
        let r1 = happy_mix_round(&addrs, &[0xAA; 32]);
        let r2 = happy_mix_round(&addrs, &[0xAA; 32]);
        assert_eq!(r1.txid(), r2.txid());
    }
}

// The seat price now lives in `crate::seat_price` — one calculation, taking a
// live fee rate rather than a pinned constant. The old `seat_prices_are_pinned`
// test asserted the very thing that made every seat greppable on chain; its
// replacement, `the_price_is_not_a_constant`, fails if anyone re-pins it.
