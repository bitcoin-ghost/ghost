//! Air-gapped MuSig2 signing for a Lock's key path.
//!
//! # What crosses the gap
//!
//! Four payloads, two each way, because MuSig2 needs two rounds:
//!
//! ```text
//!   host                                device
//!    │  SigningRequest  (psbt + lane) ──▶│   round 1: derive sighash, show it,
//!    │◀── NonceReply    (public nonce)   │            generate a nonce
//!    │                                   │
//!    │  PartialRequest  (all nonces)  ──▶│   round 2: burn the nonce, sign
//!    │◀── PartialReply  (partial sig)    │
//! ```
//!
//! They are plain JSON so they can travel as a file on removable media, as a
//! QR code, or down a serial cable. This module does not care which.
//!
//! # The device computes the sighash. It is never told it.
//!
//! This is the whole reason the request carries a PSBT rather than the 32-byte
//! message that [`crate::signing`] actually signs.
//!
//! A signing device that is handed a bare sighash cannot tell what it is
//! approving. A compromised online machine would hand it the hash of a
//! transaction paying the attacker, the device would display "sign this?", and
//! the owner would approve it — the air gap having protected the key while the
//! coins left anyway. **An offline signer that cannot verify what it signs is
//! not safer than an online one; it only feels safer.**
//!
//! So [`review`] takes the transaction, recomputes the sighash from it, and
//! returns both that hash and a [`SpendSummary`] a human can check. A device
//! that shows the summary and signs the returned hash is showing and signing
//! the same thing by construction — there is no path where they differ.
//!
//! # What this module does NOT do
//!
//! It does not decide that the amounts are acceptable. It reports them. The
//! judgement — is this the address I meant, is this fee sane — belongs to
//! whoever is holding the device, and no amount of structure here substitutes
//! for showing them the numbers.

use bitcoin::psbt::Psbt;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Address, Network, TapNodeHash, TapSighashType, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::error::LockError;

/// Round 1, host → device: everything needed to decide whether to sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    /// The unsigned transaction, base64 PSBT.
    ///
    /// Carries the prevouts, which a Taproot sighash commits to — every input's
    /// value and scriptPubKey, not just the one being signed. That is why the
    /// whole PSBT crosses rather than one input.
    pub psbt: String,
    /// Which input this device is signing.
    pub input_index: u32,
    /// The co-signers' x-only keys, hex. The device derives the aggregate
    /// itself rather than being handed one it cannot check.
    pub keys: Vec<String>,
    /// The lane's script tree root, hex. `None` for a lane with no scripts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_root: Option<String>,
}

/// Round 1, device → host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceReply {
    /// Session id, hex — the sighash the device derived. The host must check
    /// this matches the spend it asked about; a different value means the
    /// device read a different transaction.
    pub session: String,
    /// This device's public nonce, hex.
    pub public_nonce: String,
}

/// Round 2, host → device: every party's round-1 output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialRequest {
    /// The session being completed, hex.
    pub session: String,
    /// Every party's public nonce, hex, this device's included.
    pub public_nonces: Vec<String>,
}

/// Round 2, device → host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialReply {
    /// The session, hex.
    pub session: String,
    /// This device's partial signature, hex.
    pub partial: String,
}

/// One output of the spend, as a person would read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendOutput {
    /// Address, or `None` for a script this network has no address form for
    /// — shown as such rather than omitted, because an output you cannot
    /// render is exactly the one worth noticing.
    pub address: Option<String>,
    /// Value of this output.
    pub sats: u64,
}

/// What the device shows before anyone approves anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendSummary {
    /// The input this device is being asked to sign.
    pub input_index: u32,
    /// What that input is worth.
    pub input_sats: u64,
    /// The address that input is being spent from — check it is your lane.
    pub input_address: Option<String>,
    /// Every output, in transaction order.
    pub outputs: Vec<SpendOutput>,
    /// Total in minus total out.
    pub fee_sats: u64,
    /// Number of inputs in total. More than one means this spend combines
    /// coins, which is worth seeing on a device that only signs one of them.
    pub input_count: usize,
}

fn unhex32(label: &str, s: &str) -> Result<[u8; 32], LockError> {
    let raw = hex::decode(s).map_err(|e| LockError::Policy(format!("{label} is not hex: {e}")))?;
    raw.try_into()
        .map_err(|_| LockError::Policy(format!("{label} must be 32 bytes")))
}

/// Decode, verify and summarise a signing request.
///
/// Returns what to show a human and the sighash to sign — derived from the same
/// transaction, so they cannot disagree.
///
/// Refuses rather than guesses: a PSBT missing the prevout for any input cannot
/// produce a correct Taproot sighash, and signing under a hash derived from
/// assumed values would produce a signature for a transaction nobody reviewed.
pub fn review(
    request: &SigningRequest,
    network: Network,
) -> Result<(SpendSummary, [u8; 32]), LockError> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(request.psbt.trim())
        .map_err(|e| LockError::Policy(format!("psbt is not base64: {e}")))?;
    let psbt = Psbt::deserialize(&raw)
        .map_err(|e| LockError::Policy(format!("psbt does not decode: {e}")))?;

    let idx = request.input_index as usize;
    if idx >= psbt.inputs.len() {
        return Err(LockError::Policy(format!(
            "input {idx} does not exist: the transaction has {}",
            psbt.inputs.len()
        )));
    }

    // Every prevout, because a Taproot sighash commits to all of them. A
    // missing one is refused, not defaulted: the signature would be over a
    // transaction different from the one presented.
    let mut prevouts = Vec::with_capacity(psbt.inputs.len());
    for (i, input) in psbt.inputs.iter().enumerate() {
        let utxo = input.witness_utxo.as_ref().ok_or_else(|| {
            LockError::Policy(format!(
                "input {i} has no witness_utxo, so its value and script are unknown — \
                 the Taproot sighash commits to every input, so this cannot be signed \
                 correctly"
            ))
        })?;
        prevouts.push(utxo.clone());
    }

    let total_in: u64 = prevouts.iter().map(|p| p.value.to_sat()).sum();
    let total_out: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let fee_sats = total_in.checked_sub(total_out).ok_or_else(|| {
        LockError::Policy(
            "outputs exceed inputs: this transaction cannot be valid, and signing it \
             would only make a broken spend look approved"
                .into(),
        )
    })?;

    let summary = SpendSummary {
        input_index: request.input_index,
        input_sats: prevouts[idx].value.to_sat(),
        input_address: Address::from_script(&prevouts[idx].script_pubkey, network)
            .ok()
            .map(|a| a.to_string()),
        outputs: psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| SpendOutput {
                address: Address::from_script(&o.script_pubkey, network)
                    .ok()
                    .map(|a| a.to_string()),
                sats: o.value.to_sat(),
            })
            .collect(),
        fee_sats,
        input_count: psbt.inputs.len(),
    };

    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(idx, &Prevouts::All(&prevouts), TapSighashType::Default)
        .map_err(|e| LockError::Policy(format!("sighash: {e}")))?;

    Ok((summary, *sighash.as_ref()))
}

/// The co-signer keys from a request.
pub fn keys(request: &SigningRequest) -> Result<Vec<XOnlyPublicKey>, LockError> {
    let mut out = Vec::with_capacity(request.keys.len());
    for (i, k) in request.keys.iter().enumerate() {
        let bytes = unhex32(&format!("keys[{i}]"), k)?;
        out.push(
            XOnlyPublicKey::from_slice(&bytes)
                .map_err(|e| LockError::Policy(format!("keys[{i}] is not a valid key: {e}")))?,
        );
    }
    Ok(out)
}

/// The lane's script-tree root from a request, if it has one.
pub fn merkle_root(request: &SigningRequest) -> Result<Option<TapNodeHash>, LockError> {
    match &request.merkle_root {
        None => Ok(None),
        Some(h) => {
            let bytes = unhex32("merkle_root", h)?;
            Ok(Some(TapNodeHash::from_byte_array(bytes)))
        }
    }
}

use bitcoin::hashes::Hash as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lane::SavingsPolicy;
    use crate::signing::{combine, SigningSession, VolatileNonceLedger};
    use base64::Engine as _;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Txid, Witness,
    };
    use std::str::FromStr;

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b.max(1); 32]).expect("valid scalar")
    }

    fn xonly(s: &SecretKey) -> XOnlyPublicKey {
        Keypair::from_secret_key(&Secp256k1::new(), s)
            .x_only_public_key()
            .0
    }

    /// A savings lane and the two keys that spend it by the key path.
    fn lane_fixture() -> (crate::lane::Lane, SecretKey, SecretKey) {
        let secp = Secp256k1::new();
        let owner = sk(51);
        let backup = sk(52);
        let aggregate =
            crate::key_agg::aggregate(&[xonly(&owner), xonly(&backup)]).expect("aggregates");
        let lane = SavingsPolicy {
            aggregate,
            owner: xonly(&owner),
            backup: xonly(&backup),
            heir: xonly(&sk(53)),
            inherit_height: 1_000_000,
        }
        .build(&secp, 900_000, Network::Regtest)
        .expect("builds");
        (lane, owner, backup)
    }

    /// A spend of `lane` paying `to_sats` to a fixed destination.
    fn request_for(lane: &crate::lane::Lane, to_sats: u64) -> SigningRequest {
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: lane.address.script_pubkey(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000001",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(to_sats),
                script_pubkey: lane.address.script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        psbt.inputs[0].witness_utxo = Some(prevout);

        let (_, owner, backup) = (0u8, sk(51), sk(52));
        SigningRequest {
            psbt: base64::engine::general_purpose::STANDARD.encode(psbt.serialize()),
            input_index: 0,
            keys: vec![
                hex::encode(xonly(&owner).serialize()),
                hex::encode(xonly(&backup).serialize()),
            ],
            merkle_root: lane
                .spend_info
                .merkle_root()
                .map(|r| hex::encode(r.to_byte_array())),
        }
    }

    /// The summary must describe the transaction that is actually there.
    #[test]
    fn review_reports_the_real_amounts() {
        let (lane, _, _) = lane_fixture();
        let (summary, _) = review(&request_for(&lane, 90_000), Network::Regtest).expect("reviews");

        assert_eq!(summary.input_sats, 100_000);
        assert_eq!(summary.fee_sats, 10_000, "100k in, 90k out");
        assert_eq!(summary.outputs.len(), 1);
        assert_eq!(summary.outputs[0].sats, 90_000);
        assert_eq!(summary.input_count, 1);
        assert_eq!(
            summary.input_address.as_deref(),
            Some(lane.address.to_string().as_str()),
            "the owner must be able to see which lane is being spent"
        );
    }

    /// **The security property.**
    ///
    /// Changing where the money goes changes the sighash. That is what makes
    /// showing the summary meaningful: a device that displays these outputs and
    /// signs this hash cannot be displaying one transaction and signing
    /// another, because the hash is derived from what was displayed.
    #[test]
    fn a_tampered_transaction_does_not_share_a_sighash() {
        let (lane, _, _) = lane_fixture();
        let (honest_summary, honest) =
            review(&request_for(&lane, 90_000), Network::Regtest).expect("reviews");
        let (tampered_summary, tampered) =
            review(&request_for(&lane, 89_999), Network::Regtest).expect("reviews");

        assert_ne!(
            honest_summary.outputs[0].sats, tampered_summary.outputs[0].sats,
            "fixture sanity: the two spends must actually differ"
        );
        assert_ne!(
            honest, tampered,
            "a different spend must not produce the same hash to sign"
        );
    }

    /// A PSBT that cannot produce a correct sighash is refused, not guessed at.
    #[test]
    fn a_prevout_free_psbt_is_refused() {
        let (lane, _, _) = lane_fixture();
        let mut req = request_for(&lane, 90_000);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&req.psbt)
            .unwrap();
        let mut psbt = Psbt::deserialize(&raw).unwrap();
        psbt.inputs[0].witness_utxo = None;
        req.psbt = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());

        let err = review(&req, Network::Regtest).expect_err("must refuse");
        assert!(
            format!("{err}").contains("witness_utxo"),
            "the refusal must name the missing piece: {err}"
        );
    }

    /// An input index past the end is refused rather than panicking.
    #[test]
    fn an_out_of_range_input_is_refused() {
        let (lane, _, _) = lane_fixture();
        let mut req = request_for(&lane, 90_000);
        req.input_index = 7;
        let err = review(&req, Network::Regtest).expect_err("must refuse");
        assert!(format!("{err}").contains("does not exist"), "got: {err}");
    }

    /// **The whole air-gapped path, end to end.**
    ///
    /// Two devices review the same request, each derives the sighash itself,
    /// they exchange nonces and partial signatures, and the result verifies
    /// against the lane's own output key. Nothing here is handed a sighash.
    #[test]
    fn two_offline_devices_sign_a_spend_they_each_verified() {
        let secp = Secp256k1::new();
        let (lane, owner, backup) = lane_fixture();
        let req = request_for(&lane, 90_000);

        // Each device reviews independently and derives its own message.
        let (owner_summary, owner_msg) = review(&req, Network::Regtest).expect("owner reviews");
        let (backup_summary, backup_msg) = review(&req, Network::Regtest).expect("backup reviews");
        assert_eq!(
            owner_summary, backup_summary,
            "both devices must be shown the same spend"
        );
        assert_eq!(
            owner_msg, backup_msg,
            "and must independently arrive at the same hash"
        );

        let keys = keys(&req).expect("keys");
        let root = merkle_root(&req).expect("root");

        let (owner_session, owner_commit) =
            SigningSession::begin(&keys, &owner, root, &owner_msg).expect("owner round 1");
        let (backup_session, backup_commit) =
            SigningSession::begin(&keys, &backup, root, &backup_msg).expect("backup round 1");

        let nonces = [owner_commit.public_nonce, backup_commit.public_nonce];

        let mut owner_ledger = VolatileNonceLedger::default();
        let mut backup_ledger = VolatileNonceLedger::default();
        let owner_partial = owner_session
            .sign(&mut owner_ledger, &nonces)
            .expect("owner round 2");
        let backup_partial = backup_session
            .sign(&mut backup_ledger, &nonces)
            .expect("backup round 2");

        let sig = combine(
            &keys,
            root,
            &nonces,
            &[owner_partial, backup_partial],
            &owner_msg,
        )
        .expect("combines");

        let out = lane.spend_info.output_key().to_x_only_public_key();
        secp.verify_schnorr(&sig, &Message::from_digest(owner_msg), &out)
            .expect("the spend must verify against the lane it came from");
    }

    /// The payloads survive the gap as JSON.
    #[test]
    fn the_payloads_round_trip_as_json() {
        let (lane, _, _) = lane_fixture();
        let req = request_for(&lane, 90_000);
        let wire = serde_json::to_string(&req).expect("serialises");
        let back: SigningRequest = serde_json::from_str(&wire).expect("deserialises");
        assert_eq!(back.psbt, req.psbt);
        assert_eq!(back.keys, req.keys);
        assert_eq!(back.merkle_root, req.merkle_root);

        let reply = PartialReply {
            session: "aa".repeat(32),
            partial: "bb".repeat(32),
        };
        let wire = serde_json::to_string(&reply).expect("serialises");
        let back: PartialReply = serde_json::from_str(&wire).expect("deserialises");
        assert_eq!(back.partial, reply.partial);
    }
}
