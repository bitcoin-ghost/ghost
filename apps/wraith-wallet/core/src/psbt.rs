//! PSBT (BIP-174) inspection + key-path signing for Wraith.
//!
//! Phase 1 scope is deliberately narrow: take a PSBT, decode it,
//! report what's inside, and — if the active wallet's keystore owns
//! any of the inputs — produce a signed PSBT. This is what every
//! cosigner role does in a multisig flow and what a hardware-wallet
//! integration sees the daemon as. PSBT *creation* (Phase 2) is a
//! separate concern that needs ghost-pay's UTXO view.
//!
//! What we sign in v1: BIP-341 key-path taproot inputs at BIP86
//! derivation paths the active wallet's keystore knows. That's the
//! same surface `wraith_signer` covers for the Wraith mix flow —
//! the wallet only emits BIP86 P2TR addresses today, so the only
//! inputs it can produce signatures for are P2TR key-path. P2WPKH /
//! P2WSH / script-path support is an explicit future once those
//! address types exist on the receive side.
//!
//! What we don't do here:
//!   - Any UTXO lookup. We trust the PSBT's `witness_utxo` /
//!     `non_witness_utxo` fields. The caller is expected to have
//!     validated provenance before signing — same trust model as
//!     every other PSBT signer.
//!   - Combine multiple PSBTs (BIP-174 §combiner). The bitcoin
//!     crate's `Psbt::combine` covers it; we'd add a `psbt_combine`
//!     RPC if we ship a coordinator.
//!   - Miniscript-driven finalization for non-trivial scripts. We
//!     finalize manually for the key-path-taproot case only;
//!     anything else, we leave `final_script_witness` unset and let
//!     a downstream finalizer (Bitcoin Core, miniscript, etc.) do
//!     the job. That's correct behaviour for a single-cosigner role
//!     in a multisig flow.

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Address, Network, ScriptBuf, TxOut, Witness};

use crate::keystore::Keystore;
use crate::light;

/// Maximum BIP86 derivation index we'll scan when matching a PSBT
/// input's scriptPubKey to a wallet-owned key. Mirrors
/// `wraith_signer::DEFAULT_SCAN_INDEX_MAX` so an input that signs
/// fine via Wraith mix also signs fine via PSBT. Bumping this is
/// cheap (just iterates derivations) but signing should generally
/// stay well below this in practice.
pub const DEFAULT_SCAN_INDEX_MAX: u32 = 1024;

#[derive(Debug, thiserror::Error)]
pub enum PsbtError {
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("psbt: input {input_index} has neither witness_utxo nor non_witness_utxo")]
    InputMissingPrevout { input_index: usize },
    #[error("psbt: input {input_index} non_witness_utxo doesn't match the unsigned tx's prevout")]
    InputPrevoutMismatch { input_index: usize },
    #[error("keystore: {0}")]
    Keystore(#[from] crate::keystore::KeystoreError),
    #[error("light: {0}")]
    Light(String),
    #[error("bitcoin: {0}")]
    Bitcoin(String),
    #[error("secp256k1: {0}")]
    Secp(String),
}

/// Encoding of the PSBT bytes the caller passed in. We round-trip
/// in the same encoding so a Sparrow-shaped tool that hands us
/// base64 doesn't get hex back, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsbtEncoding {
    Base64,
    Hex,
}

/// Parse a PSBT from either base64 or hex (auto-detected). The PSBT
/// magic is `0x70 0x73 0x62 0x74 0xff`, so:
///
///   - hex → first 10 chars are `70736274ff` (case-insensitive)
///   - base64 → starts with `cHNidP` (the magic in base64)
///
/// Anything else is an error.
pub fn decode_psbt(input: &str) -> Result<(Psbt, PsbtEncoding), PsbtError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(PsbtError::Decode("empty input".into()));
    }
    let lower10: String = trimmed
        .chars()
        .take(10)
        .flat_map(|c| c.to_lowercase())
        .collect();
    if lower10.starts_with("70736274ff") {
        let bytes = hex::decode(trimmed).map_err(|e| PsbtError::Decode(format!("hex: {e}")))?;
        let psbt =
            Psbt::deserialize(&bytes).map_err(|e| PsbtError::Decode(format!("psbt: {e}")))?;
        return Ok((psbt, PsbtEncoding::Hex));
    }
    if trimmed.starts_with("cHNidP") {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed)
            .map_err(|e| PsbtError::Decode(format!("base64: {e}")))?;
        let psbt =
            Psbt::deserialize(&bytes).map_err(|e| PsbtError::Decode(format!("psbt: {e}")))?;
        return Ok((psbt, PsbtEncoding::Base64));
    }
    Err(PsbtError::Decode(
        "unrecognised PSBT — expected hex starting `70736274ff` or base64 starting `cHNidP`".into(),
    ))
}

pub fn encode_psbt(psbt: &Psbt, encoding: PsbtEncoding) -> String {
    let bytes = psbt.serialize();
    match encoding {
        PsbtEncoding::Hex => hex::encode(&bytes),
        PsbtEncoding::Base64 => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        }
    }
}

/// Per-input view used by `inspect`. `script_pubkey` and
/// `value_sats` come from `witness_utxo` if present, otherwise from
/// `non_witness_utxo[outpoint.vout]`. If neither is set, both are
/// `None` and the row is un-signable.
pub struct InputView {
    pub previous_txid: bitcoin::Txid,
    pub previous_vout: u32,
    pub value_sats: Option<u64>,
    pub script_pubkey: Option<ScriptBuf>,
    pub is_finalized: bool,
    pub partial_signatures: u32,
}

/// Per-output view used by `inspect`. Cheap to compute — outputs
/// are always fully described by the PSBT's underlying unsigned tx.
pub struct OutputView {
    pub value_sats: u64,
    pub script_pubkey: ScriptBuf,
}

pub struct InspectResult {
    pub inputs: Vec<InputView>,
    pub outputs: Vec<OutputView>,
    pub txid: bitcoin::Txid,
}

/// Pure decoder — does not touch wallet state. Pulls the unsigned
/// tx out of the PSBT and assembles per-input/per-output views the
/// caller can render. The "is this signable by my wallet?" question
/// is intentionally NOT answered here — that requires keystore
/// access and lives in `mark_signable`.
pub fn inspect(psbt: &Psbt) -> InspectResult {
    let unsigned = &psbt.unsigned_tx;
    let mut inputs = Vec::with_capacity(unsigned.input.len());
    for (i, txin) in unsigned.input.iter().enumerate() {
        let psbt_in = psbt.inputs.get(i);
        // Resolve the prevout: prefer witness_utxo (cheaper, smaller
        // PSBT), fall back to non_witness_utxo[txin.previous_output.vout].
        let (value_sats, script_pubkey) = match psbt_in {
            Some(pi) => {
                if let Some(wu) = &pi.witness_utxo {
                    (Some(wu.value.to_sat()), Some(wu.script_pubkey.clone()))
                } else if let Some(nwu) = &pi.non_witness_utxo {
                    let vout = txin.previous_output.vout as usize;
                    if let Some(out) = nwu.output.get(vout) {
                        (Some(out.value.to_sat()), Some(out.script_pubkey.clone()))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            }
            None => (None, None),
        };
        let is_finalized = psbt_in
            .map(|pi| pi.final_script_witness.is_some() || pi.final_script_sig.is_some())
            .unwrap_or(false);
        let partial_signatures = psbt_in
            .map(|pi| {
                let mut n = pi.partial_sigs.len() as u32;
                if pi.tap_key_sig.is_some() {
                    n += 1;
                }
                n += pi.tap_script_sigs.len() as u32;
                n
            })
            .unwrap_or(0);
        inputs.push(InputView {
            previous_txid: txin.previous_output.txid,
            previous_vout: txin.previous_output.vout,
            value_sats,
            script_pubkey,
            is_finalized,
            partial_signatures,
        });
    }
    let outputs = unsigned
        .output
        .iter()
        .map(|o| OutputView {
            value_sats: o.value.to_sat(),
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();
    InspectResult {
        inputs,
        outputs,
        txid: unsigned.compute_txid(),
    }
}

/// Resolve a `script_pubkey` into a human-readable address for the
/// given network. Returns `None` for outputs whose script doesn't
/// have a canonical address (e.g. OP_RETURN, bare multisig). The
/// GUI shows raw hex in that case.
pub fn script_to_address(script: &ScriptBuf, network: Network) -> Option<String> {
    Address::from_script(script, network)
        .ok()
        .map(|a| a.to_string())
}

/// Walk BIP86 indices 0..=`scan_max` for `keystore` and return the
/// first index whose derived P2TR scriptPubKey matches `target`.
/// `None` means the wallet doesn't own this scriptPubKey under the
/// BIP86 receive chain.
pub fn find_bip86_index_for_script(
    keystore: &Keystore,
    network: Network,
    target: &ScriptBuf,
    scan_max: u32,
) -> Result<Option<u32>, PsbtError> {
    for idx in 0..=scan_max {
        let addr = light::receive_address(keystore, idx, network)
            .map_err(|e| PsbtError::Light(e.to_string()))?;
        if &addr.script_pubkey() == target {
            return Ok(Some(idx));
        }
    }
    Ok(None)
}

/// Sign every input of `psbt` that the wallet owns at a BIP86
/// receive index ≤ `scan_max`. Returns the indices we actually
/// signed (callers want this for the "signed N of M" UX).
///
/// Why we re-derive instead of trusting `tap_key_origins`: a
/// hostile or buggy PSBT producer could put a fingerprint pointing
/// at our root in `tap_key_origins` for an input scriptPubKey that
/// isn't actually ours. Re-deriving locks the link between the
/// scriptPubKey and our key, which is what BIP86 already commits
/// to. It's also robust against PSBTs from tools that don't fill
/// origins at all (e.g. some wallet exports skip them for privacy).
pub fn sign_owned_inputs(
    psbt: &mut Psbt,
    keystore: &Keystore,
    network: Network,
    scan_max: u32,
) -> Result<Vec<u32>, PsbtError> {
    // Pre-compute the prevouts table. We need the FULL set for the
    // BIP-341 sighash computation (taproot commits to every input's
    // prevout, not just the one we're signing). If any input is
    // missing a prevout we can't sign anything safely — the sighash
    // would be wrong.
    let unsigned = psbt.unsigned_tx.clone();
    let mut prev_txouts: Vec<TxOut> = Vec::with_capacity(unsigned.input.len());
    let mut have_all_prevouts = true;
    for (i, txin) in unsigned.input.iter().enumerate() {
        let psbt_in = psbt
            .inputs
            .get(i)
            .ok_or(PsbtError::InputMissingPrevout { input_index: i })?;
        if let Some(wu) = &psbt_in.witness_utxo {
            prev_txouts.push(wu.clone());
        } else if let Some(nwu) = &psbt_in.non_witness_utxo {
            let vout = txin.previous_output.vout as usize;
            let out = nwu
                .output
                .get(vout)
                .ok_or(PsbtError::InputPrevoutMismatch { input_index: i })?;
            // Cross-check that the non_witness_utxo really is the
            // tx behind this input.
            if nwu.compute_txid() != txin.previous_output.txid {
                return Err(PsbtError::InputPrevoutMismatch { input_index: i });
            }
            prev_txouts.push(out.clone());
        } else {
            have_all_prevouts = false;
            // Push a placeholder so indices stay aligned; we'll
            // refuse to sign below.
            prev_txouts.push(TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            });
        }
    }
    if !have_all_prevouts {
        // Caller sees the missing-prevout error rather than us
        // silently producing wrong sighashes.
        for (i, pi) in psbt.inputs.iter().enumerate() {
            if pi.witness_utxo.is_none() && pi.non_witness_utxo.is_none() {
                return Err(PsbtError::InputMissingPrevout { input_index: i });
            }
        }
    }

    let secp = Secp256k1::new();
    let mut signed_indices = Vec::new();
    let our_fp_bytes = keystore
        .master_fingerprint_bytes()
        .map_err(|e| PsbtError::Bitcoin(format!("fingerprint: {e}")))?;
    let our_fp_bitcoin = bitcoin::bip32::Fingerprint::from(our_fp_bytes);

    for input_index in 0..unsigned.input.len() {
        let already_finalized = psbt
            .inputs
            .get(input_index)
            .map(|pi| pi.final_script_witness.is_some() || pi.final_script_sig.is_some())
            .unwrap_or(false);
        if already_finalized {
            continue;
        }

        // Identify the input's scriptPubKey (already validated
        // above to be present).
        let target_spk = &prev_txouts[input_index].script_pubkey;

        // ---- P2WSH multisig path (cosigner role) -----------------
        //
        // Coordinator-built PSBTs carry per-input bip32_derivation
        // hints listing all the cosigners' (pubkey, fingerprint,
        // path) tuples. If our master fingerprint is in that list,
        // derive at the embedded path, ECDSA-sign the BIP-143
        // sighash, and write the partial signature to
        // `partial_sigs`. We deliberately DO NOT finalize — the
        // combiner step (whoever has all sigs) builds the final
        // witness once the script's threshold is reached.
        if target_spk.is_p2wsh() {
            let psbt_in = psbt.inputs.get(input_index).expect("bounds checked above");
            // Snapshot the derivation hints + witness_script + sighash type
            // before mutating, so the borrow checker stays happy.
            let derivations: Vec<(bitcoin::PublicKey, bitcoin::bip32::DerivationPath)> = psbt_in
                .bip32_derivation
                .iter()
                .filter(|(_, (fp, _))| fp == &our_fp_bitcoin)
                .map(|(pk, (_, path))| (bitcoin::PublicKey::new(*pk), path.clone()))
                .collect();
            if derivations.is_empty() {
                continue;
            }
            let witness_script = match psbt_in.witness_script.as_ref() {
                Some(s) => s.clone(),
                None => continue, // P2WSH input must carry witness_script
            };
            // PSBT sighash type — fall back to ALL if absent. ECDSA
            // path; taproot script-path is a future iteration.
            let sighash_type = psbt_in
                .sighash_type
                .map(|t| t.ecdsa_hash_ty().unwrap_or(bitcoin::EcdsaSighashType::All))
                .unwrap_or(bitcoin::EcdsaSighashType::All);

            // Compute BIP-143 sighash for this input.
            let prev_value = prev_txouts[input_index].value;
            let mut cache = SighashCache::new(&unsigned);
            let sighash = cache
                .p2wsh_signature_hash(input_index, &witness_script, prev_value, sighash_type)
                .map_err(|e| PsbtError::Bitcoin(format!("p2wsh sighash: {e}")))?;
            use bitcoin::hashes::Hash as _;
            let msg = Message::from_digest(*sighash.as_byte_array());

            let mut signed_this_input = false;
            for (pk, path) in derivations {
                // Convert the bitcoin crate's path into the keystore's
                // string form. `bip32::DerivationPath` formats as
                // `48'/1'/0'/2'/0/0` without the `m/` prefix; the
                // keystore wants `m/...`.
                let path_str = format!("m/{path}");
                let xprv = keystore
                    .derive_xprv(&path_str)
                    .map_err(|e| PsbtError::Bitcoin(format!("derive {path_str}: {e}")))?;
                let priv_bytes = xprv.private_key().to_bytes();
                let sk = SecretKey::from_slice(&priv_bytes)
                    .map_err(|e| PsbtError::Secp(format!("from_slice: {e}")))?;
                let derived_pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
                let derived_bitcoin_pk = bitcoin::PublicKey::new(derived_pk);
                if derived_bitcoin_pk != pk {
                    // Fingerprint matched but the derived pubkey
                    // doesn't — caller-supplied path is bogus or
                    // belongs to a different seed with the same
                    // (highly unlikely) fingerprint. Skip rather
                    // than producing a useless signature.
                    continue;
                }
                let sig = secp.sign_ecdsa(&msg, &sk);
                let ecdsa_sig = bitcoin::ecdsa::Signature {
                    signature: sig,
                    sighash_type,
                };
                let psbt_in_mut = psbt
                    .inputs
                    .get_mut(input_index)
                    .expect("bounds checked above");
                psbt_in_mut.partial_sigs.insert(pk, ecdsa_sig);
                signed_this_input = true;
            }
            if signed_this_input {
                signed_indices.push(input_index as u32);
            }
            continue;
        }

        // ---- BIP86 P2TR key-path (single-sig wallet flow) --------
        if !target_spk.is_p2tr() {
            continue;
        }

        // Find the BIP86 index, if any, that derives to this spk.
        let idx = match find_bip86_index_for_script(keystore, network, target_spk, scan_max)? {
            Some(idx) => idx,
            None => continue,
        };

        // Derive the signing key.
        let path = format!("m/86'/{}'/0'/0/{}", light::GHOST_COIN_TYPE, idx);
        let xprv = keystore.derive_xprv(&path)?;
        let priv_bytes = xprv.private_key().to_bytes();
        let sk = SecretKey::from_slice(&priv_bytes)
            .map_err(|e| PsbtError::Secp(format!("from_slice: {e}")))?;

        // BIP-341 SIGHASH_DEFAULT key-path sighash.
        let mut cache = SighashCache::new(&unsigned);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                input_index,
                &Prevouts::All(&prev_txouts),
                TapSighashType::Default,
            )
            .map_err(|e| PsbtError::Bitcoin(format!("taproot sighash: {e}")))?;

        // Tap-tweak (BIP86: no merkle root) + Schnorr-sign.
        use bitcoin::key::TapTweak;
        let untweaked = Keypair::from_secret_key(&secp, &sk);
        let tweaked = untweaked.tap_tweak(&secp, None);
        use bitcoin::hashes::Hash as _;
        let msg = Message::from_digest(*sighash.as_byte_array());
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());

        // Single-signer key-path inputs go straight from "no
        // signature" to "finalized" — no separate combine step is
        // needed since the witness is just our 64-byte sig. Skip
        // writing `tap_key_sig` (which a downstream finalizer
        // would read) and write the final witness directly.
        //
        // BIP-174 §Finalizer says to clear all the intermediate
        // partial-sig / derivation / script fields once an input
        // is finalized. Keeps the PSBT small and stops a confused
        // downstream finalizer from second-guessing us.
        let psbt_in = psbt
            .inputs
            .get_mut(input_index)
            .expect("bounds checked by index iter");
        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        psbt_in.final_script_witness = Some(witness);
        psbt_in.partial_sigs.clear();
        psbt_in.sighash_type = None;
        psbt_in.redeem_script = None;
        psbt_in.witness_script = None;
        psbt_in.bip32_derivation.clear();
        psbt_in.tap_key_sig = None;
        psbt_in.tap_script_sigs.clear();
        psbt_in.tap_scripts.clear();
        psbt_in.tap_key_origins.clear();
        psbt_in.tap_internal_key = None;
        psbt_in.tap_merkle_root = None;

        signed_indices.push(input_index as u32);
    }

    Ok(signed_indices)
}

/// True when every input of `psbt` is finalized (has either
/// `final_script_witness` or `final_script_sig`). At that point a
/// caller can safely call `psbt.extract_tx()` and broadcast.
pub fn is_complete(psbt: &Psbt) -> bool {
    psbt.inputs
        .iter()
        .all(|pi| pi.final_script_witness.is_some() || pi.final_script_sig.is_some())
}

/// One UTXO available to spend in `create_psbt`. Mirrors
/// `chain::ScannedL1Utxo` minus the metadata fields the PSBT
/// builder doesn't need; we keep this struct local to the psbt
/// module so a future non-ghost-pay UTXO source (e.g. an Esplora
/// adapter) can plug in without dragging the chain crate's types.
pub struct AvailableUtxo {
    pub txid: bitcoin::Txid,
    pub vout: u32,
    pub value_sats: u64,
    pub script_pubkey: ScriptBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("recipient address parse: {0}")]
    BadAddress(String),
    #[error("recipient address belongs to a different network: tx is {tx_network}, address parsed as {addr_network}")]
    NetworkMismatch {
        tx_network: String,
        addr_network: String,
    },
    #[error("amount {amount_sats} is at or below dust threshold ({dust_sats})")]
    Dust { amount_sats: u64, dust_sats: u64 },
    #[error("no UTXOs available")]
    NoUtxos,
    #[error(
        "insufficient funds: have {available_sats} sats across {utxo_count} UTXO(s), need at least {required_sats} (amount + estimated fee)"
    )]
    InsufficientFunds {
        available_sats: u64,
        required_sats: u64,
        utxo_count: usize,
    },
    #[error("fee too low: estimated mining fee {fee_sats} would be below relay min ({min_sats})")]
    FeeTooLow { fee_sats: u64, min_sats: u64 },
    #[error("bitcoin: {0}")]
    Bitcoin(String),
}

/// Build an unsigned PSBT spending some subset of `available` to a
/// single recipient, with change going back to `change_address`.
/// Pure function — no ghost-pay calls, no signing, no network I/O.
/// The caller (daemon) is responsible for fetching UTXOs and
/// supplying a derivation index for change.
///
/// Selection: greedy by descending value. We pick the largest
/// UTXOs first until we cover `amount_sats + estimated_fee`. This
/// is the simplest selector that works correctly; smarter
/// algorithms (BnB, knapsack) are a future optimisation that won't
/// change the PSBT shape we emit.
///
/// Fee estimation uses a fixed vbyte-per-input/output table for
/// taproot key-path inputs and P2TR/P2WPKH outputs:
///   - tx overhead: 11 vbytes
///   - per P2TR input (key-path):  ~58 vbytes (witness ~16.25 vB + outpoint + sequence)
///   - per output (P2TR / P2WPKH): ~31 vbytes
///
/// We round generously to keep the fee sufficient when the selected mix has
/// different output script types. Dust threshold for outputs is 330 sats
/// (BIP125 / Bitcoin Core P2TR dust).
pub fn create_psbt(
    available: &[AvailableUtxo],
    recipient_address: &str,
    amount_sats: u64,
    change_address: &Address,
    network: Network,
    fee_rate_sats_per_vb: u64,
) -> Result<(Psbt, CreateMeta), CreateError> {
    if available.is_empty() {
        return Err(CreateError::NoUtxos);
    }
    let recipient: Address = recipient_address
        .parse::<Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| CreateError::BadAddress(e.to_string()))?
        .require_network(network)
        .map_err(|e| CreateError::NetworkMismatch {
            tx_network: format!("{network:?}"),
            addr_network: format!("{e}"),
        })?;
    const DUST: u64 = 330;
    if amount_sats <= DUST {
        return Err(CreateError::Dust {
            amount_sats,
            dust_sats: DUST,
        });
    }

    // Sort UTXOs by descending value so we cover the target with
    // as few inputs as possible — keeps fee predictable and avoids
    // slicing tiny coins for big sends.
    let mut sorted: Vec<&AvailableUtxo> = available.iter().collect();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.value_sats));

    let recipient_spk = recipient.script_pubkey();
    let change_spk = change_address.script_pubkey();

    // Iteratively grow the input set; on each step recompute the
    // fee with the working count so we stop as soon as we cover
    // amount + fee. Two-output assumption (recipient + change);
    // the no-change case is handled by absorbing the residual into
    // the fee and dropping the change output.
    let mut selected: Vec<&AvailableUtxo> = Vec::new();
    let mut total_in: u64 = 0;
    let mut total_available: u64 = 0;
    for u in &sorted {
        total_available = total_available.saturating_add(u.value_sats);
    }
    let mut fee = 0u64;
    let mut change_value: u64 = 0;
    let mut needed_change_output = true;
    let mut covered = false;
    for u in sorted.iter() {
        selected.push(u);
        total_in = total_in.saturating_add(u.value_sats);
        let n_inputs = selected.len() as u64;
        // Two outputs first; if no-change-needed we drop one below.
        let est_vbytes = 11 + n_inputs * 58 + 2 * 31;
        fee = est_vbytes.saturating_mul(fee_rate_sats_per_vb);
        if total_in >= amount_sats.saturating_add(fee) {
            // Cover possible — try to lift to no-change form if
            // residual <= dust to avoid littering UTXO set.
            let residual = total_in - amount_sats - fee;
            if residual <= DUST {
                // Drop the change output: residual rolls into fee.
                let est_no_change = 11 + n_inputs * 58 + 31;
                let fee_no_change = est_no_change.saturating_mul(fee_rate_sats_per_vb);
                if total_in >= amount_sats.saturating_add(fee_no_change) {
                    fee = total_in - amount_sats; // entire residual = fee
                    change_value = 0;
                    needed_change_output = false;
                    covered = true;
                    break;
                }
            }
            change_value = residual;
            needed_change_output = true;
            covered = true;
            break;
        }
    }

    if !covered {
        return Err(CreateError::InsufficientFunds {
            available_sats: total_available,
            required_sats: amount_sats.saturating_add(fee),
            utxo_count: available.len(),
        });
    }
    // Sanity: enforce a tiny floor so we don't ship a zero-fee tx
    // even if the caller passes fee_rate_sats_per_vb=0.
    if fee < 100 {
        return Err(CreateError::FeeTooLow {
            fee_sats: fee,
            min_sats: 100,
        });
    }

    use bitcoin::{absolute, transaction, Amount, OutPoint, Sequence, Transaction, TxIn};
    let mut tx_inputs: Vec<TxIn> = Vec::with_capacity(selected.len());
    for s in &selected {
        tx_inputs.push(TxIn {
            previous_output: OutPoint {
                txid: s.txid,
                vout: s.vout,
            },
            script_sig: ScriptBuf::new(),
            // Enable RBF on every send. Cheap default that lets
            // the wallet bump fees later (Phase 5 — RBF UI).
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }
    let mut tx_outputs: Vec<TxOut> = Vec::with_capacity(2);
    tx_outputs.push(TxOut {
        value: Amount::from_sat(amount_sats),
        script_pubkey: recipient_spk.clone(),
    });
    if needed_change_output {
        tx_outputs.push(TxOut {
            value: Amount::from_sat(change_value),
            script_pubkey: change_spk.clone(),
        });
    }
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: tx_inputs,
        output: tx_outputs,
    };

    let mut psbt =
        Psbt::from_unsigned_tx(tx).map_err(|e| CreateError::Bitcoin(format!("psbt: {e}")))?;
    // Attach witness_utxo for every input. P2TR sighash needs the
    // prevout commitment; without this the signer would refuse.
    for (i, s) in selected.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut {
            value: Amount::from_sat(s.value_sats),
            script_pubkey: s.script_pubkey.clone(),
        });
    }

    Ok((
        psbt,
        CreateMeta {
            selected_input_count: selected.len(),
            total_input_sats: total_in,
            recipient_sats: amount_sats,
            change_sats: change_value,
            fee_sats: fee,
        },
    ))
}

/// Sidecar info returned alongside the freshly-built PSBT so the
/// caller / GUI can render fee + change breakdown without
/// re-decoding the PSBT.
#[derive(Debug, Clone)]
pub struct CreateMeta {
    pub selected_input_count: usize,
    pub total_input_sats: u64,
    pub recipient_sats: u64,
    pub change_sats: u64,
    pub fee_sats: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BumpError {
    #[error("decode: {0}")]
    Decode(String),
    #[error("psbt has no inputs to bump")]
    NoInputs,
    #[error("input {input_index} is missing prevout (witness_utxo / non_witness_utxo)")]
    MissingPrevout { input_index: usize },
    #[error("can't find a wallet-owned change output in this PSBT — bump would have to come from elsewhere")]
    NoChangeOutput,
    #[error("new fee rate ({new_rate} sats/vB) does not exceed the original ({old_rate} sats/vB) — RBF would be a no-op")]
    NotIncreasing { new_rate: u64, old_rate: u64 },
    #[error("change output would drop below dust ({dust} sats) after the bump — pick a smaller fee rate or send less back to yourself")]
    ChangeBelowDust { dust: u64 },
    #[error("light: {0}")]
    Light(String),
    #[error("keystore: {0}")]
    Keystore(#[from] crate::keystore::KeystoreError),
    #[error("bitcoin: {0}")]
    Bitcoin(String),
}

/// Sidecar info from `bump_fee` — old-vs-new fee + change breakdown
/// so the GUI can render "you just raised the fee from X to Y" copy
/// without re-decoding both PSBTs.
#[derive(Debug, Clone)]
pub struct BumpMeta {
    pub old_fee_sats: u64,
    pub new_fee_sats: u64,
    pub old_change_sats: u64,
    pub new_change_sats: u64,
    /// Same input set in both PSBTs, so this is just for display.
    pub input_count: usize,
}

/// BIP-125 fee-bump on an existing PSBT. Reduces the wallet-owned
/// change output to absorb the higher fee, reuses the same input
/// set (preserving RBF replaceability), strips any signatures (the
/// sighash changes when output values change). Returns a fresh
/// unsigned PSBT ready to feed back into `sign_owned_inputs`.
///
/// Caller responsibilities:
///   - The input PSBT must be one wraith built (witness_utxos
///     populated, BIP86 P2TR scriptPubKeys). PSBTs from other
///     toolchains may work but aren't tested.
///   - `new_fee_rate_sats_per_vb` must be strictly higher than the
///     original — bumping to the same or a lower rate is rejected
///     because it wouldn't be replaced by miners under standard
///     mempool policy.
///
/// This isn't a full BIP-125 enforcement: it doesn't sweep child
/// txs (Bitcoin Core's `bumpfee` does). For wraith's own send flow
/// (no chained mempool descendants), reduce-the-change is enough.
pub fn bump_fee(
    original: &Psbt,
    keystore: &Keystore,
    network: Network,
    scan_max: u32,
    new_fee_rate_sats_per_vb: u64,
) -> Result<(Psbt, BumpMeta), BumpError> {
    let unsigned = &original.unsigned_tx;
    if unsigned.input.is_empty() {
        return Err(BumpError::NoInputs);
    }

    // Recompute prevouts so we can see the old fee. Witness_utxo is
    // the canonical source for our PSBTs; non_witness_utxo as
    // fallback. If any input lacks both, we'd be guessing the fee.
    let mut prev_txouts: Vec<TxOut> = Vec::with_capacity(unsigned.input.len());
    for (i, txin) in unsigned.input.iter().enumerate() {
        let psbt_in = original
            .inputs
            .get(i)
            .ok_or(BumpError::MissingPrevout { input_index: i })?;
        if let Some(wu) = &psbt_in.witness_utxo {
            prev_txouts.push(wu.clone());
        } else if let Some(nwu) = &psbt_in.non_witness_utxo {
            let vout = txin.previous_output.vout as usize;
            let out = nwu
                .output
                .get(vout)
                .ok_or(BumpError::MissingPrevout { input_index: i })?;
            prev_txouts.push(out.clone());
        } else {
            return Err(BumpError::MissingPrevout { input_index: i });
        }
    }
    let total_in: u64 = prev_txouts.iter().map(|o| o.value.to_sat()).sum();
    let total_out: u64 = unsigned.output.iter().map(|o| o.value.to_sat()).sum();
    let old_fee = total_in.saturating_sub(total_out);

    // Old fee rate (rough): old_fee / vbytes. We over-estimate
    // vbytes the same way `create_psbt` does (n_inputs × 58 + 11 +
    // n_outputs × 31) so the comparison is apples-to-apples — using
    // the actual signed-tx vsize would be tighter but we don't need
    // tight; we just need to reject "no-op bumps".
    let n_inputs = unsigned.input.len() as u64;
    let n_outputs = unsigned.output.len() as u64;
    let est_vbytes = 11 + n_inputs * 58 + n_outputs * 31;
    // est_vbytes is a sum of positive terms so it cannot be zero, but divide defensively:
    // a zero here would panic rather than merely mis-price the bump.
    let old_rate = old_fee.checked_div(est_vbytes).unwrap_or_default();
    if new_fee_rate_sats_per_vb <= old_rate {
        return Err(BumpError::NotIncreasing {
            new_rate: new_fee_rate_sats_per_vb,
            old_rate,
        });
    }
    let new_fee = est_vbytes.saturating_mul(new_fee_rate_sats_per_vb);
    if new_fee <= old_fee {
        return Err(BumpError::NotIncreasing {
            new_rate: new_fee_rate_sats_per_vb,
            old_rate,
        });
    }
    let extra_fee = new_fee - old_fee;

    // Find the wallet's change output by walking BIP86 indices and
    // checking each scriptPubKey against the tx outputs. The
    // change is whichever output goes back to one of our derived
    // receive addresses. If multiple outputs match (unusual — would
    // mean the user sent to themselves twice in the same tx), we
    // pick the one whose value ≥ extra_fee + dust to absorb the
    // bump cleanly.
    const DUST: u64 = 330;
    let mut owned_outs: Vec<usize> = Vec::new();
    for idx in 0..=scan_max {
        let addr = crate::light::receive_address(keystore, idx, network)
            .map_err(|e| BumpError::Light(e.to_string()))?;
        let target_spk = addr.script_pubkey();
        for (oi, out) in unsigned.output.iter().enumerate() {
            if out.script_pubkey == target_spk && !owned_outs.contains(&oi) {
                owned_outs.push(oi);
            }
        }
    }
    if owned_outs.is_empty() {
        return Err(BumpError::NoChangeOutput);
    }
    // Prefer the output that has enough headroom to swallow the
    // bump. If none has enough, the largest gets picked and we'll
    // surface the dust error below.
    owned_outs.sort_by_key(|i| std::cmp::Reverse(unsigned.output[*i].value.to_sat()));
    let change_idx = *owned_outs
        .iter()
        .find(|i| unsigned.output[**i].value.to_sat() >= extra_fee + DUST)
        .unwrap_or(&owned_outs[0]);

    let old_change = unsigned.output[change_idx].value.to_sat();
    let new_change = old_change.saturating_sub(extra_fee);
    if new_change < DUST {
        return Err(BumpError::ChangeBelowDust { dust: DUST });
    }

    // Clone the tx, mutate the change output, drop all witnesses /
    // script_sigs (the sighash changes on the new output values, so
    // the old signatures don't apply).
    let mut new_tx = unsigned.clone();
    new_tx.output[change_idx].value = bitcoin::Amount::from_sat(new_change);
    for txin in new_tx.input.iter_mut() {
        txin.script_sig = ScriptBuf::new();
        txin.witness = Witness::new();
    }

    let mut new_psbt =
        Psbt::from_unsigned_tx(new_tx).map_err(|e| BumpError::Bitcoin(format!("psbt: {e}")))?;
    // Re-attach witness_utxos from the originals so the next signer
    // call has the prevout it needs for sighash.
    for (i, prev) in prev_txouts.iter().enumerate() {
        new_psbt.inputs[i].witness_utxo = Some(prev.clone());
    }

    Ok((
        new_psbt,
        BumpMeta {
            old_fee_sats: old_fee,
            new_fee_sats: new_fee,
            old_change_sats: old_change,
            new_change_sats: new_change,
            input_count: unsigned.input.len(),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::Keystore;
    use bitcoin::{absolute, transaction, OutPoint, Sequence, Transaction, TxIn, TxOut};

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn ks() -> Keystore {
        Keystore::from_mnemonic(TEST_MNEMONIC).unwrap()
    }

    fn build_psbt_for_owned_input(idx: u32, network: Network) -> Psbt {
        let keystore = ks();
        let addr = light::receive_address(&keystore, idx, network).unwrap();
        let spk = addr.script_pubkey();
        let prev_txout = TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: spk.clone(),
        };
        // Dummy outpoint — sighash doesn't care, just needs to be
        // committed to consistently. Use all-1s txid + vout 0.
        use bitcoin::hashes::Hash as _;
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x11; 32]),
            vout: 0,
        };
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let txout = TxOut {
            value: bitcoin::Amount::from_sat(99_000),
            script_pubkey: spk,
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(prev_txout);
        psbt
    }

    #[test]
    fn decode_round_trip_hex_and_base64() {
        let mut psbt = build_psbt_for_owned_input(0, Network::Signet);
        // Sign so the PSBT carries data, not just empty fields.
        let _ = sign_owned_inputs(&mut psbt, &ks(), Network::Signet, 4).unwrap();

        let hex = encode_psbt(&psbt, PsbtEncoding::Hex);
        let (psbt_h, enc_h) = decode_psbt(&hex).unwrap();
        assert_eq!(enc_h, PsbtEncoding::Hex);
        assert_eq!(psbt_h.serialize(), psbt.serialize());

        let b64 = encode_psbt(&psbt, PsbtEncoding::Base64);
        let (psbt_b, enc_b) = decode_psbt(&b64).unwrap();
        assert_eq!(enc_b, PsbtEncoding::Base64);
        assert_eq!(psbt_b.serialize(), psbt.serialize());
    }

    #[test]
    fn sign_owned_input_finalises_witness() {
        let mut psbt = build_psbt_for_owned_input(0, Network::Signet);
        assert!(!is_complete(&psbt));

        let signed = sign_owned_inputs(&mut psbt, &ks(), Network::Signet, 4).unwrap();
        assert_eq!(signed, vec![0]);
        assert!(is_complete(&psbt));
        let w = psbt.inputs[0].final_script_witness.as_ref().unwrap();
        assert_eq!(w.len(), 1);
        let sig = w.iter().next().unwrap();
        assert_eq!(sig.len(), 64, "BIP-341 SIGHASH_DEFAULT sig is 64 bytes");
    }

    #[test]
    fn sign_skips_unowned_inputs() {
        let other_keystore = Keystore::from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        let mut psbt = build_psbt_for_owned_input(0, Network::Signet);
        // Use OTHER wallet's keystore — none of the inputs are
        // owned by it, so we should sign nothing and not error.
        let signed = sign_owned_inputs(&mut psbt, &other_keystore, Network::Signet, 4).unwrap();
        assert!(signed.is_empty());
        assert!(!is_complete(&psbt));
    }

    #[test]
    fn sign_idempotent_when_already_finalized() {
        let mut psbt = build_psbt_for_owned_input(0, Network::Signet);
        let _ = sign_owned_inputs(&mut psbt, &ks(), Network::Signet, 4).unwrap();
        // Second call should be a no-op — input is already finalized.
        let again = sign_owned_inputs(&mut psbt, &ks(), Network::Signet, 4).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn create_psbt_builds_with_change_when_residual_is_above_dust() {
        let keystore = ks();
        // Use the wallet's index-0 address as the source of the UTXO
        // (so a follow-up sign step would actually work end-to-end).
        let src_addr = light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let change_addr = light::receive_address(&keystore, 1, Network::Signet).unwrap();
        // External recipient — same wallet for test convenience, idx 5.
        let recipient_addr = light::receive_address(&keystore, 5, Network::Signet).unwrap();
        use bitcoin::hashes::Hash as _;
        let avail = vec![AvailableUtxo {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 0,
            value_sats: 1_000_000,
            script_pubkey: src_addr.script_pubkey(),
        }];
        let (psbt, meta) = create_psbt(
            &avail,
            &recipient_addr.to_string(),
            500_000,
            &change_addr,
            Network::Signet,
            10, // sats/vB
        )
        .expect("create");
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 2, "recipient + change");
        assert!(meta.fee_sats >= 100);
        assert!(meta.change_sats > 0);
        // total_in == amount + change + fee
        assert_eq!(
            meta.total_input_sats,
            meta.recipient_sats + meta.change_sats + meta.fee_sats
        );
        // PSBT inputs carry witness_utxo so a signer can compute sighash.
        assert!(psbt.inputs[0].witness_utxo.is_some());
    }

    #[test]
    fn create_psbt_drops_change_when_residual_below_dust() {
        let keystore = ks();
        let src_addr = light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let change_addr = light::receive_address(&keystore, 1, Network::Signet).unwrap();
        let recipient_addr = light::receive_address(&keystore, 5, Network::Signet).unwrap();
        use bitcoin::hashes::Hash as _;
        // 1 input, 2 outputs, 5 sat/vB → fee = 131*5 = 655. With
        // total_in = 100,800 and amount = 100,000 the residual
        // (145 sat) lands below the 330-sat dust threshold, so the
        // builder is expected to drop the change output and roll
        // residual into the fee.
        let avail = vec![AvailableUtxo {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 0,
            value_sats: 100_800,
            script_pubkey: src_addr.script_pubkey(),
        }];
        let (psbt, meta) = create_psbt(
            &avail,
            &recipient_addr.to_string(),
            100_000,
            &change_addr,
            Network::Signet,
            5,
        )
        .expect("create");
        assert_eq!(
            psbt.unsigned_tx.output.len(),
            1,
            "no-change form when residual is dust"
        );
        assert_eq!(meta.change_sats, 0);
    }

    #[test]
    fn create_psbt_insufficient_funds() {
        let keystore = ks();
        let src_addr = light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let change_addr = light::receive_address(&keystore, 1, Network::Signet).unwrap();
        let recipient_addr = light::receive_address(&keystore, 5, Network::Signet).unwrap();
        use bitcoin::hashes::Hash as _;
        let avail = vec![AvailableUtxo {
            txid: bitcoin::Txid::from_byte_array([0x22; 32]),
            vout: 0,
            value_sats: 1_000,
            script_pubkey: src_addr.script_pubkey(),
        }];
        let err = create_psbt(
            &avail,
            &recipient_addr.to_string(),
            500_000,
            &change_addr,
            Network::Signet,
            5,
        )
        .unwrap_err();
        match err {
            CreateError::InsufficientFunds { .. } => {}
            other => panic!("expected InsufficientFunds; got {other:?}"),
        }
    }

    #[test]
    fn bump_fee_reduces_change_to_raise_fee() {
        let keystore = ks();
        // Build a real-shape PSBT with change going back to BIP86
        // idx 1 (so the bump scanner can find it).
        let src_addr = light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let change_addr = light::receive_address(&keystore, 1, Network::Signet).unwrap();
        let recipient_addr = light::receive_address(&keystore, 5, Network::Signet).unwrap();
        use bitcoin::hashes::Hash as _;
        let avail = vec![AvailableUtxo {
            txid: bitcoin::Txid::from_byte_array([0x33; 32]),
            vout: 0,
            value_sats: 1_000_000,
            script_pubkey: src_addr.script_pubkey(),
        }];
        let (psbt, orig_meta) = create_psbt(
            &avail,
            &recipient_addr.to_string(),
            500_000,
            &change_addr,
            Network::Signet,
            5, // sats/vB
        )
        .expect("create");
        assert_eq!(orig_meta.fee_sats, 5 * 131); // 1 input + 2 outputs

        let (bumped, bm) = bump_fee(&psbt, &keystore, Network::Signet, 4, 20).expect("bump");
        assert!(bm.new_fee_sats > bm.old_fee_sats);
        assert_eq!(
            bm.new_change_sats,
            bm.old_change_sats - (bm.new_fee_sats - bm.old_fee_sats)
        );
        // Same number of inputs/outputs in the bumped PSBT — RBF
        // requires same input set, and we don't drop the change
        // output.
        assert_eq!(bumped.unsigned_tx.input.len(), psbt.unsigned_tx.input.len());
        assert_eq!(
            bumped.unsigned_tx.output.len(),
            psbt.unsigned_tx.output.len()
        );
        // Witness_utxos preserved so next sign_owned_inputs call
        // can compute sighash.
        assert!(bumped.inputs[0].witness_utxo.is_some());
        // Recipient output untouched.
        let recip_spk = recipient_addr.script_pubkey();
        let recip_out_orig = psbt
            .unsigned_tx
            .output
            .iter()
            .find(|o| o.script_pubkey == recip_spk)
            .unwrap();
        let recip_out_new = bumped
            .unsigned_tx
            .output
            .iter()
            .find(|o| o.script_pubkey == recip_spk)
            .unwrap();
        assert_eq!(recip_out_orig.value, recip_out_new.value);
    }

    #[test]
    fn bump_fee_rejects_non_increasing_rate() {
        let keystore = ks();
        let src_addr = light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let change_addr = light::receive_address(&keystore, 1, Network::Signet).unwrap();
        let recipient_addr = light::receive_address(&keystore, 5, Network::Signet).unwrap();
        use bitcoin::hashes::Hash as _;
        let avail = vec![AvailableUtxo {
            txid: bitcoin::Txid::from_byte_array([0x33; 32]),
            vout: 0,
            value_sats: 1_000_000,
            script_pubkey: src_addr.script_pubkey(),
        }];
        let (psbt, _) = create_psbt(
            &avail,
            &recipient_addr.to_string(),
            500_000,
            &change_addr,
            Network::Signet,
            10,
        )
        .unwrap();
        // Same rate → no-op bump → error.
        let err = bump_fee(&psbt, &keystore, Network::Signet, 4, 10).unwrap_err();
        match err {
            BumpError::NotIncreasing { .. } => {}
            other => panic!("expected NotIncreasing; got {other:?}"),
        }
    }

    #[test]
    fn bump_fee_errors_when_change_would_drop_below_dust() {
        let keystore = ks();
        let src_addr = light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let change_addr = light::receive_address(&keystore, 1, Network::Signet).unwrap();
        let recipient_addr = light::receive_address(&keystore, 5, Network::Signet).unwrap();
        use bitcoin::hashes::Hash as _;
        // Tight UTXO so the change is small. Trying to bump by a
        // huge rate then has nowhere to take the extra fee from.
        let avail = vec![AvailableUtxo {
            txid: bitcoin::Txid::from_byte_array([0x33; 32]),
            vout: 0,
            value_sats: 502_000,
            script_pubkey: src_addr.script_pubkey(),
        }];
        let (psbt, m) = create_psbt(
            &avail,
            &recipient_addr.to_string(),
            500_000,
            &change_addr,
            Network::Signet,
            5,
        )
        .unwrap();
        // change_sats is small — picking a bump rate that consumes
        // it should fail with ChangeBelowDust. m.change_sats here
        // is roughly 1345.
        assert!(m.change_sats < 2000);
        let err = bump_fee(&psbt, &keystore, Network::Signet, 4, 50).unwrap_err();
        match err {
            BumpError::ChangeBelowDust { .. } => {}
            BumpError::NotIncreasing { .. } => {} // also acceptable when est rate already high
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sign_p2wsh_multisig_writes_partial_sig_without_finalising() {
        // Build a 2-of-2 P2WSH where one cosigner is our test
        // wallet (BIP-39 zero seed). Derive both keys at a path
        // we control, construct the multisig redeemScript, hash to
        // a P2WSH scriptPubKey, build a tx spending that output,
        // wrap as PSBT with bip32_derivation hints carrying our
        // master fingerprint, then run sign_owned_inputs and
        // assert the partial_sigs map gained an entry for our
        // pubkey while final_script_witness stayed unset.
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use bitcoin::PublicKey;

        let keystore = ks();
        let secp = Secp256k1::new();

        // Cosigner A: wraith. Path `m/48'/1'/0'/2'/0/0`.
        let path_a = "m/48'/1'/0'/2'/0/0";
        let xprv_a = keystore.derive_xprv(path_a).unwrap();
        let sk_a = SecretKey::from_slice(&xprv_a.private_key().to_bytes()).unwrap();
        let pk_a = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_a);
        let our_fp = keystore.master_fingerprint_bytes().unwrap();
        let our_fp_bitcoin = bitcoin::bip32::Fingerprint::from(our_fp);

        // Cosigner B: a fresh fixed key — pretend it's the other
        // signer. We don't sign with it; we just need its pubkey
        // in the script.
        let sk_b = SecretKey::from_slice(&[42u8; 32]).unwrap();
        let pk_b = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk_b);

        // Build the 2-of-2 multisig redeemScript (sortedmulti
        // ordering by lexicographic pubkey serialisation).
        let mut pubkeys = [PublicKey::new(pk_a), PublicKey::new(pk_b)];
        pubkeys.sort_by_key(|x| x.to_bytes());
        use bitcoin::blockdata::opcodes;
        use bitcoin::blockdata::script::Builder;
        let redeem = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&pubkeys[0])
            .push_key(&pubkeys[1])
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .into_script();
        let p2wsh_spk = ScriptBuf::new_p2wsh(&redeem.wscript_hash());

        // Build the unsigned tx spending one P2WSH output.
        use bitcoin::hashes::Hash as _;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x44; 32]),
            vout: 0,
        };
        let txin = bitcoin::TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let txout = TxOut {
            value: bitcoin::Amount::from_sat(99_000),
            script_pubkey: ScriptBuf::new(),
        };
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: bitcoin::Amount::from_sat(100_000),
            script_pubkey: p2wsh_spk,
        });
        psbt.inputs[0].witness_script = Some(redeem);
        // Tell the PSBT that pk_a's owner is us (fingerprint match
        // on the path we used).
        let path_a_parsed = bitcoin::bip32::DerivationPath::from_str("m/48'/1'/0'/2'/0/0").unwrap();
        psbt.inputs[0]
            .bip32_derivation
            .insert(pk_a, (our_fp_bitcoin, path_a_parsed));

        // Run our signer.
        let signed = sign_owned_inputs(&mut psbt, &keystore, Network::Signet, 4).unwrap();
        assert_eq!(signed, vec![0]);
        // partial_sigs should now have exactly one entry — ours.
        assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
        let our_pk = bitcoin::PublicKey::new(pk_a);
        assert!(
            psbt.inputs[0].partial_sigs.contains_key(&our_pk),
            "partial sig keyed by our pubkey",
        );
        // Crucially: NOT finalised — the second cosigner still has
        // to add their sig before the witness can be assembled.
        assert!(psbt.inputs[0].final_script_witness.is_none());
        assert!(psbt.inputs[0].final_script_sig.is_none());
        assert!(!is_complete(&psbt));
    }

    use std::str::FromStr;

    #[test]
    fn missing_prevout_errors_cleanly() {
        let keystore = ks();
        let addr = light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let spk = addr.script_pubkey();
        use bitcoin::hashes::Hash as _;
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x11; 32]),
            vout: 0,
        };
        let txin = TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let txout = TxOut {
            value: bitcoin::Amount::from_sat(99_000),
            script_pubkey: spk,
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        // Intentionally leave witness_utxo unset.
        let err = sign_owned_inputs(&mut psbt, &keystore, Network::Signet, 4).unwrap_err();
        match err {
            PsbtError::InputMissingPrevout { input_index: 0 } => {}
            other => panic!("expected InputMissingPrevout; got {other:?}"),
        }
    }
}
