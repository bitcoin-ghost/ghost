//! Building a Ghost silent payment — the sender's side.
//!
//! # What was missing
//!
//! The wallet could receive these and not send them. The encoder lived in the
//! operator's service and went with it, leaving the Receive screen advertising
//! a Ghost ID that no wallet in the tree could pay.
//!
//! # The shape on chain
//!
//! Two outputs, and the pair is what makes the payment findable:
//!
//! * an `OP_RETURN` carrying exactly one 33-byte compressed pubkey — the
//!   sender's one-shot ephemeral key, which is what lets the receiver run the
//!   ECDH that reveals the payment;
//! * a taproot output at a key derived from that ephemeral key and the
//!   receiver's published Ghost ID.
//!
//! Neither half is any use alone. Without the announcement the receiver has
//! nothing to scan against and the coin is unfindable; without the taproot
//! output the announcement pays nobody.
//!
//! # What it costs the sender
//!
//! An `OP_RETURN` is a marker anyone can see. A transaction shaped like this
//! says "a silent payment happened here" to every observer — it hides *who was
//! paid*, not *that a payment occurred*. That is the trade this protocol
//! makes, and it is worth knowing before choosing it over an ordinary address.

use bitcoin::{Network, ScriptBuf};
use ghost_keys::{GhostId, GhostNetwork};

/// The two outputs a silent payment adds to a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentPayment {
    /// The taproot output that carries the money.
    pub output_script: ScriptBuf,
    /// The `OP_RETURN` announcement. Carries no value.
    pub announcement_script: ScriptBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SilentPaymentError {
    #[error("not a Ghost ID for this network: {0}")]
    BadGhostId(String),
    #[error("deriving the payment address: {0}")]
    Derive(String),
}

/// Map a Bitcoin network to the Ghost ID it accepts.
///
/// Rejecting rather than defaulting: a mainnet Ghost ID pasted into a signet
/// wallet is a mistake, and quietly paying it would put real money on the
/// wrong chain — irrecoverably, since nobody holds the other chain's key.
pub fn ghost_network_for(network: Network) -> Option<GhostNetwork> {
    match network {
        Network::Bitcoin => Some(GhostNetwork::Mainnet),
        Network::Testnet => Some(GhostNetwork::Testnet),
        Network::Signet => Some(GhostNetwork::Signet),
        Network::Regtest => Some(GhostNetwork::Regtest),
        _ => None,
    }
}

/// Whether `s` looks like a Ghost ID for `network`.
///
/// A prefix check, used to decide which kind of payment the user asked for
/// before committing to either. The full decode still happens in [`build`] —
/// this only routes.
pub fn looks_like_ghost_id(s: &str, network: Network) -> bool {
    let Some(gn) = ghost_network_for(network) else {
        return false;
    };
    s.trim().starts_with(&format!("{}1", gn.hrp()))
}

/// Build the outputs that pay `ghost_id`.
///
/// `k` is the sender's counter for multiple outputs to the same recipient in
/// one transaction. It is carried in the derivation rather than inferred from
/// output position, so shuffling the outputs for privacy does not break
/// detection.
///
/// A fresh ephemeral key is generated per call, so paying the same Ghost ID
/// twice produces unrelated on-chain outputs.
pub fn build(
    ghost_id: &str,
    network: Network,
    k: u32,
) -> Result<SilentPayment, SilentPaymentError> {
    let gn = ghost_network_for(network)
        .ok_or_else(|| SilentPaymentError::BadGhostId(format!("unsupported network {network}")))?;
    let id = GhostId::decode_for_network(ghost_id.trim(), gn)
        .map_err(|e| SilentPaymentError::BadGhostId(e.to_string()))?;

    let (output_pubkey, ephemeral_pubkey, _tweak) = id
        .derive_payment_address_v2_full(k)
        .map_err(|e| SilentPaymentError::Derive(e.to_string()))?;

    // The taproot output keeps only the x-coordinate; the receiver tries both
    // parities when scanning, because the chain does not record which.
    let mut output = Vec::with_capacity(34);
    output.push(0x51); // OP_1
    output.push(0x20); // PUSH32
    output.extend_from_slice(&output_pubkey.serialize()[1..]);

    let mut announcement = Vec::with_capacity(35);
    announcement.push(0x6a); // OP_RETURN
    announcement.push(0x21); // PUSH33
    announcement.extend_from_slice(&ephemeral_pubkey.serialize());

    Ok(SilentPayment {
        output_script: ScriptBuf::from_bytes(output),
        announcement_script: ScriptBuf::from_bytes(announcement),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_keys::GhostKeys;

    fn ghost_id_for(keys: &GhostKeys, network: GhostNetwork) -> String {
        GhostId::new(*keys.scan_pubkey(), *keys.spend_pubkey())
            .encode_for_network(network)
            .expect("encode")
    }

    /// The whole point: what this builds, the scanner finds.
    ///
    /// The sender and the receiver are the real implementations and the block
    /// encoding in between is the format under test. A pair of fixtures I
    /// wrote both sides of would only prove I am consistent with myself.
    #[test]
    fn what_the_sender_builds_the_scanner_detects() {
        let receiver = GhostKeys::generate();
        let id = ghost_id_for(&receiver, GhostNetwork::Regtest);

        let pay = build(&id, Network::Regtest, 0).expect("build");

        // Lay it out as a block would: the announcement, a stranger's output,
        // then the payment — so the scanner has to pick rather than accept
        // whatever it is handed.
        let tx: crate::ghostd::BlockTx = serde_json::from_value(serde_json::json!({
            "txid": "feed",
            "vin": [],
            "vout": [
                { "n": 0, "value": 0.0,
                  "scriptPubKey": { "hex": hex::encode(pay.announcement_script.as_bytes()) } },
                { "n": 1, "value": 0.25,
                  "scriptPubKey": { "hex": format!("5120{}", "cc".repeat(32)) } },
                { "n": 2, "value": 0.5,
                  "scriptPubKey": { "hex": hex::encode(pay.output_script.as_bytes()) } },
            ],
        }))
        .expect("tx fixture");

        let (ephemeral, outputs) =
            crate::block_scan::candidate_in(&tx).expect("the announcement is found");
        let found =
            crate::candidate_scan::scan_candidate(&receiver, &ephemeral, &outputs, "feed", None)
                .expect("scan runs");

        assert_eq!(found.len(), 1, "exactly the output that was ours");
        assert_eq!(found[0].vout, 2);
        assert_eq!(found[0].amount_sats, Some(50_000_000));
        assert_eq!(found[0].k, 0, "the counter the sender used");
    }

    /// A funded silent payment must still be detectable once the wallet has
    /// built it into a real transaction.
    ///
    /// The two tests above prove the scripts are right. This proves the
    /// *transaction* is: that the builder keeps both outputs, funds them, and
    /// that what comes out the other end is what a scanner reading that block
    /// would find. A payment whose announcement got dropped during selection
    /// would pass every earlier test and be unspendable on chain.
    #[test]
    fn a_built_transaction_is_still_detectable() {
        use crate::psbt::{create_psbt_to_scripts, AvailableUtxo};
        use bitcoin::hashes::Hash;
        use bitcoin::{Address, ScriptBuf};

        let receiver = GhostKeys::generate();
        let pay = build(
            &ghost_id_for(&receiver, GhostNetwork::Regtest),
            Network::Regtest,
            0,
        )
        .unwrap();

        // A wallet coin to spend, and somewhere for the change to go.
        let our_spk = ScriptBuf::from_bytes({
            let mut v = vec![0x51, 0x20];
            v.extend_from_slice(&[0xaa; 32]);
            v
        });
        let available = [AvailableUtxo {
            txid: bitcoin::Txid::from_byte_array([7u8; 32]),
            vout: 0,
            value_sats: 1_000_000,
            script_pubkey: our_spk,
        }];
        let change: Address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
            .parse::<Address<bitcoin::address::NetworkUnchecked>>()
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();

        let (psbt, meta) = create_psbt_to_scripts(
            &available,
            pay.output_script.clone(),
            500_000,
            std::slice::from_ref(&pay.announcement_script),
            &change,
            5,
        )
        .expect("build the transaction");

        let tx = psbt.unsigned_tx;
        assert!(
            tx.output
                .iter()
                .any(|o| o.script_pubkey == pay.announcement_script && o.value.to_sat() == 0),
            "the announcement must survive, and carry no value"
        );
        assert!(
            tx.output
                .iter()
                .any(|o| o.script_pubkey == pay.output_script && o.value.to_sat() == 500_000),
            "the payment must carry the amount"
        );
        // Inputs must cover everything the transaction spends, or the node
        // rejects it after the wallet has told the user it sent.
        let out_total: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
        assert_eq!(
            meta.total_input_sats,
            out_total + meta.fee_sats,
            "inputs must equal outputs plus fee"
        );

        // And now read it back the way the scanner would.
        let vouts: Vec<serde_json::Value> = tx
            .output
            .iter()
            .enumerate()
            .map(|(n, o)| {
                serde_json::json!({
                    "n": n as u32,
                    "value": o.value.to_sat() as f64 / 100_000_000.0,
                    "scriptPubKey": { "hex": hex::encode(o.script_pubkey.as_bytes()) }
                })
            })
            .collect();
        let block_tx: crate::ghostd::BlockTx = serde_json::from_value(
            serde_json::json!({ "txid": "built", "vin": [], "vout": vouts }),
        )
        .unwrap();

        let (eph, outs) =
            crate::block_scan::candidate_in(&block_tx).expect("announcement survives the build");
        let found =
            crate::candidate_scan::scan_candidate(&receiver, &eph, &outs, "built", None).unwrap();
        assert_eq!(found.len(), 1, "the recipient finds their coin");
        assert_eq!(found[0].amount_sats, Some(500_000));
    }

    /// Paying somebody else must not be detectable as ours, or the test above
    /// would pass for a scanner that accepted anything.
    #[test]
    fn a_payment_to_another_ghost_id_is_not_ours() {
        let us = GhostKeys::generate();
        let them = GhostKeys::generate();
        let pay = build(
            &ghost_id_for(&them, GhostNetwork::Regtest),
            Network::Regtest,
            0,
        )
        .expect("build");

        let tx: crate::ghostd::BlockTx = serde_json::from_value(serde_json::json!({
            "txid": "feed",
            "vin": [],
            "vout": [
                { "n": 0, "value": 0.0,
                  "scriptPubKey": { "hex": hex::encode(pay.announcement_script.as_bytes()) } },
                { "n": 1, "value": 0.5,
                  "scriptPubKey": { "hex": hex::encode(pay.output_script.as_bytes()) } },
            ],
        }))
        .unwrap();
        let (eph, outs) = crate::block_scan::candidate_in(&tx).unwrap();
        let found = crate::candidate_scan::scan_candidate(&us, &eph, &outs, "feed", None).unwrap();
        assert!(found.is_empty(), "not ours, got {found:?}");
    }

    /// Two payments to one Ghost ID must not share an output key, or the
    /// recipient's transactions become linkable by anyone watching.
    #[test]
    fn paying_the_same_recipient_twice_produces_unrelated_outputs() {
        let receiver = GhostKeys::generate();
        let id = ghost_id_for(&receiver, GhostNetwork::Regtest);
        let a = build(&id, Network::Regtest, 0).unwrap();
        let b = build(&id, Network::Regtest, 0).unwrap();
        assert_ne!(a.output_script, b.output_script, "output keys must differ");
        assert_ne!(
            a.announcement_script, b.announcement_script,
            "and so must the ephemeral keys"
        );
    }

    /// A mainnet Ghost ID in a signet wallet is a mistake, and paying it
    /// anyway would put money on a chain whose key nobody holds.
    #[test]
    fn a_ghost_id_from_another_network_is_refused() {
        let receiver = GhostKeys::generate();
        let mainnet_id = ghost_id_for(&receiver, GhostNetwork::Mainnet);
        let err = build(&mainnet_id, Network::Regtest, 0).expect_err("must refuse");
        assert!(matches!(err, SilentPaymentError::BadGhostId(_)), "{err}");
    }

    /// The routing check must not claim an ordinary address.
    #[test]
    fn an_ordinary_address_does_not_look_like_a_ghost_id() {
        assert!(!looks_like_ghost_id(
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            Network::Regtest
        ));
        let id = ghost_id_for(&GhostKeys::generate(), GhostNetwork::Regtest);
        assert!(looks_like_ghost_id(&id, Network::Regtest));
        assert!(
            !looks_like_ghost_id(&id, Network::Bitcoin),
            "a regtest id is not a mainnet one"
        );
    }
}
