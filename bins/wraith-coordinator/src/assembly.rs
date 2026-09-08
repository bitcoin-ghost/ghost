//! Round transaction assembly.
//!
//! Once `/outputs` has collected N unblinded mix-output addresses to
//! match the N input UTXOs from `/inputs`, the coordinator pairs them
//! up, runs them through `LiteRoundBuilder`, and stashes the resulting
//! `LiteRound`. Wallets fetch the assembled (unsigned) transaction via
//! `GET /api/v1/session/:id/round-tx` and produce per-input witnesses
//! in B/5c.
//!
//! ## Pairing
//!
//! The pairing of inputs to outputs is arbitrary — the builder shuffles
//! both into final tx order via ChaCha20Rng seeded by session_id +
//! caller entropy. So assigning `input[i]` ↔ `output[i]` in arrival order
//! is equivalent to any other assignment from the on-chain output
//! ordering perspective. The coordinator does not learn which input's
//! ghost_id corresponds to which output address (the privacy is
//! provided by the prior unlinkability of /outputs anyway).
//!
//! ## Failure
//!
//! Any error during assembly (bad txid hex, unparseable scriptpubkey,
//! min-input arithmetic violation, build-time validation failure)
//! transitions the session to `Failed { reason }` via a gossip
//! StateChanged event. B/5c picks up Failed sessions and refunds bonds
//! with `RefundReason::CoordinatorAborted` (no participant slashing —
//! the failure isn't anyone's individual fault here).

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Network, ScriptBuf, Txid};
use tracing::{error, info};

use wraith_protocol::{
    LiteParticipantInput, LiteRound, LiteRoundBuilder, LiteSessionState, SessionType,
};

use crate::inputs::AcceptedInputs;
use crate::outputs::AcceptedOutput;

/// One assembled round, ready for participants to sign.
#[derive(Debug, Clone)]
pub struct AssembledRound {
    /// The result of `LiteRoundBuilder::build()`. Contains the
    /// unsigned `bitcoin::Transaction` plus per-output provenance.
    pub round: LiteRound,
    /// Hex-encoded serialised unsigned transaction. Cached so the
    /// `/round-tx` endpoint doesn't have to re-encode on every poll.
    pub unsigned_tx_hex: String,
    /// Unix-seconds the round was assembled.
    pub assembled_at: u64,
}

/// Per-session assembled-round registry. Held in
/// `CoordinatorState::assembled_rounds`.
pub type AssembledRoundStore = Mutex<HashMap<String, AssembledRound>>;

/// Build the assembled round from an arrival-order pairing of inputs
/// and outputs. Pure function over the data — no shared state — so
/// it's trivial to unit-test.
/// What a round needs to be assembled.
///
/// A struct rather than eight-then-eleven positional parameters. The list is mostly borrowed
/// slices and newtypes that do not distinguish themselves at a call site — `inputs` and
/// `outputs` are both `&[Accepted...]`, and `session_id` sits next to two enums — so the
/// positional form is easy to get subtly wrong and impossible to read back.
///
/// `try_assemble_if_ready` takes the same context plus the readiness inputs, so both share this.
#[derive(Clone, Copy)]
pub struct RoundContext<'a> {
    pub session_id: &'a str,
    pub tier: wraith_protocol::LiteTier,
    pub session_type: SessionType,
    pub network: Network,
    pub coordinator_fee_address: Option<&'a str>,
    pub inputs: &'a [AcceptedInputs],
    pub outputs: &'a [AcceptedOutput],
    pub entropy: &'a [u8; 32],
}

pub fn assemble_round(ctx: RoundContext<'_>) -> Result<AssembledRound, AssembleError> {
    let RoundContext {
        session_id,
        tier,
        session_type,
        network,
        coordinator_fee_address,
        inputs,
        outputs,
        entropy,
    } = ctx;
    if inputs.len() != outputs.len() {
        return Err(AssembleError::CountMismatch {
            inputs: inputs.len(),
            outputs: outputs.len(),
        });
    }
    if inputs.is_empty() {
        return Err(AssembleError::NoParticipants);
    }

    let mut builder = match session_type {
        SessionType::Mix => {
            let fee_addr = coordinator_fee_address
                .ok_or(AssembleError::FeeAddressNotConfigured)?
                .to_string();
            LiteRoundBuilder::new_mix(session_id.to_string(), tier, network, fee_addr)
        }
        SessionType::Jump => LiteRoundBuilder::new_jump(session_id.to_string(), tier, network),
    };

    for (i, (input, output)) in inputs.iter().zip(outputs.iter()).enumerate() {
        // `LiteRoundBuilder` pairs one input with one output per participant,
        // and that pairing is the linkage a ladder round exists to break. A
        // multi-rung participant cannot be expressed here at all, so refuse it
        // rather than build a transaction from `inputs[0]` and silently drop
        // the rest of somebody's money.
        //
        // Ladder assembly is `LadderRoundBuilder` in `wraith-protocol`, wired
        // in a later increment. Until then `/inputs` will accept a ladder
        // submission and this is where it stops.
        let single = match input.inputs.as_slice() {
            [only] => only,
            other => {
                return Err(AssembleError::LadderRoundNotAssemblable {
                    participant_id: i as u32,
                    rungs: other.len(),
                })
            }
        };
        let txid = Txid::from_str(single.txid.trim()).map_err(|e| AssembleError::BadTxid {
            participant_id: i as u32,
            detail: e.to_string(),
        })?;
        let scriptpubkey_bytes = hex::decode(single.scriptpubkey_hex.trim()).map_err(|e| {
            AssembleError::BadScriptPubkey {
                participant_id: i as u32,
                detail: format!("not valid hex: {e}"),
            }
        })?;
        let script_pubkey = ScriptBuf::from_bytes(scriptpubkey_bytes);

        let participant = LiteParticipantInput {
            txid,
            vout: single.vout,
            amount_sats: single.value_sats,
            script_pubkey,
            mixed_output_address: output.address.clone(),
            participant_id: i as u32,
        };
        builder
            .add_participant(participant)
            .map_err(|e| AssembleError::AddParticipant {
                participant_id: i as u32,
                detail: e.to_string(),
            })?;
    }

    let round = builder
        .build_with_entropy(entropy)
        .map_err(|e| AssembleError::Build(e.to_string()))?;
    let unsigned_tx_hex = serialize_hex(&round.tx);

    info!(
        %session_id,
        txid = %round.txid(),
        mining_fee_sats = round.mining_fee_sats,
        outputs = round.tx.output.len(),
        "round transaction assembled",
    );

    Ok(AssembledRound {
        round,
        unsigned_tx_hex,
        assembled_at: 0, // caller fills with state.now()
    })
}

#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    #[error("inputs ({inputs}) and outputs ({outputs}) count mismatch")]
    CountMismatch { inputs: usize, outputs: usize },
    #[error("no participants — empty round")]
    NoParticipants,
    /// A participant brought a number of rungs other than one.
    ///
    /// Zero is a store invariant violation; anything above one is a ladder
    /// round, which this builder cannot express — see the call site.
    #[error("participant {participant_id} brought {rungs} rungs; the lite builder pairs one input with one output and cannot assemble a ladder round")]
    LadderRoundNotAssemblable { participant_id: u32, rungs: usize },
    #[error("Mix round requires a coordinator_fee_address")]
    FeeAddressNotConfigured,
    #[error("participant {participant_id} bad txid: {detail}")]
    BadTxid { participant_id: u32, detail: String },
    #[error("participant {participant_id} bad scriptpubkey: {detail}")]
    BadScriptPubkey { participant_id: u32, detail: String },
    #[error("participant {participant_id} rejected by builder: {detail}")]
    AddParticipant { participant_id: u32, detail: String },
    #[error("LiteRoundBuilder::build failed: {0}")]
    Build(String),
}

impl AssembleError {
    /// Stable short code for the wire-format response on /round-tx
    /// failure. Mirrors the `error: <code>` pattern used by the rest
    /// of the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::CountMismatch { .. } => "count_mismatch",
            Self::NoParticipants => "no_participants",
            Self::FeeAddressNotConfigured => "fee_address_not_configured",
            Self::BadTxid { .. } => "bad_txid",
            Self::BadScriptPubkey { .. } => "bad_scriptpubkey",
            Self::AddParticipant { .. } => "add_participant_failed",
            Self::LadderRoundNotAssemblable { .. } => "ladder_round_not_assemblable",
            Self::Build(_) => "build_failed",
        }
    }
}

/// Trigger assembly for a session if (and only if) inputs.len() ==
/// outputs.len() == enrolled_count. No-op when called early. Used by
/// `/outputs` after a successful submission to advance the round.
///
/// Returns `Some(Result<assembled, error>)` if assembly was attempted
/// (success or failure), `None` if not yet ready.
pub fn try_assemble_if_ready(
    ctx: RoundContext<'_>,
    state: LiteSessionState,
    enrolled_count: usize,
    now: u64,
) -> Option<Result<AssembledRound, AssembleError>> {
    let session_id = ctx.session_id;
    let (inputs, outputs) = (ctx.inputs, ctx.outputs);
    if !matches!(state, LiteSessionState::Signing) {
        return None;
    }
    if inputs.len() != enrolled_count || outputs.len() != enrolled_count {
        return None;
    }
    let result = assemble_round(ctx).map(|mut a| {
        a.assembled_at = now;
        a
    });
    if let Err(ref e) = result {
        error!(%session_id, error = ?e, "round assembly failed");
    }
    Some(result)
}
