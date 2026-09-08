//! Work out what a block did to the wallet.
//!
//! # Why this exists
//!
//! The wallet used to be told. The operator's GSP watched the chain on its
//! behalf and pushed what it found, which meant handing somebody a scan key
//! and trusting the answer. With that gone the wallet has to look for itself,
//! and looking means reading blocks from its own node.
//!
//! This module is the pure half: given one block with its inputs resolved,
//! and the set of scripts the wallet can spend, say what moved. It performs no
//! I/O and holds no keys, so it is testable against hand-built blocks — which
//! matters, because the arithmetic here decides what a balance history says.

use std::collections::HashSet;

use crate::candidate_scan::CandidateOutput;
use crate::ghostd::{BlockTx, VerboseBlock};

/// What one transaction in a block did to the wallet.
///
/// Only transactions that touched it are reported. A block of ten thousand
/// strangers' payments produces an empty vector, not ten thousand zeroes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletMovement {
    pub txid: String,
    /// Height of the block it was mined in.
    pub height: u64,
    /// Block time, unix seconds. The wallet may not have been running when
    /// this was mined, so "when I first saw it" would be the wrong date.
    pub time: i64,
    /// Total paid *to* the wallet by this transaction.
    pub received_sats: u64,
    /// Total spent *from* the wallet by this transaction: the value of the
    /// inputs that were ours.
    pub spent_sats: u64,
    /// The miner fee, when it can be known.
    ///
    /// `None` for a coinbase (which has no inputs to compare against) and for
    /// any transaction with an input whose previous output the node did not
    /// resolve. A fee derived from a subset of the inputs is not a smaller
    /// fee, it is a wrong one.
    pub fee_sats: Option<u64>,
    /// Output indices paying the wallet, so a caller can find the coins.
    pub vouts_to_us: Vec<u32>,
    /// True when the wallet supplied no inputs — money arriving rather than
    /// moving around inside the wallet.
    pub is_incoming: bool,
}

impl WalletMovement {
    /// Net change to the wallet's balance, negative when it lost value.
    ///
    /// This is what the balance actually moves by, so a history built from it
    /// reconciles with a balance built from the UTXO set. For a spend it
    /// already includes the fee, because the fee is simply value that left in
    /// an input and came back in no output of ours.
    pub fn net_sats(&self) -> i64 {
        self.received_sats as i64 - self.spent_sats as i64
    }
}

/// Everything in `block` that touched one of `ours`.
///
/// `ours` holds raw scriptPubKey bytes, not addresses: bitcoind normalises
/// address descriptors on the way out, and matching on the canonical script
/// avoids depending on which form it chooses to echo back.
pub fn scan_block(block: &VerboseBlock, ours: &HashSet<Vec<u8>>) -> Vec<WalletMovement> {
    let mut out = Vec::new();
    for tx in &block.tx {
        let mut received = 0u64;
        let mut vouts = Vec::new();
        for v in &tx.vout {
            let Ok(spk) = hex::decode(&v.script_pubkey.hex) else {
                // An unparseable script cannot be ours — we only ever hold
                // scripts we derived. Skipping it cannot hide our own money.
                continue;
            };
            if ours.contains(&spk) {
                received = received.saturating_add(v.value_sats());
                vouts.push(v.n);
            }
        }

        let mut spent = 0u64;
        let mut inputs_total = 0u64;
        let mut every_prevout_known = true;
        let mut coinbase = false;
        let mut we_supplied_an_input = false;
        for i in &tx.vin {
            if i.is_coinbase() {
                coinbase = true;
                continue;
            }
            let Some(prev) = i.prevout.as_ref() else {
                every_prevout_known = false;
                continue;
            };
            inputs_total = inputs_total.saturating_add(prev.value_sats());
            if let Ok(spk) = hex::decode(&prev.script_pub_key.hex) {
                if ours.contains(&spk) {
                    spent = spent.saturating_add(prev.value_sats());
                    we_supplied_an_input = true;
                }
            }
        }

        if received == 0 && spent == 0 {
            continue;
        }

        // A coinbase has no fee to speak of, and an unresolved input makes any
        // figure here a guess. Both report `None` rather than a number that
        // would read as measured.
        let fee_sats = if coinbase || !every_prevout_known {
            None
        } else {
            let outputs_total: u64 = tx.vout.iter().map(|v| v.value_sats()).sum();
            Some(inputs_total.saturating_sub(outputs_total))
        };

        out.push(WalletMovement {
            txid: tx.txid.clone(),
            height: block.height,
            time: block.time,
            received_sats: received,
            spent_sats: spent,
            fee_sats,
            vouts_to_us: vouts,
            is_incoming: !we_supplied_an_input,
        });
    }
    out
}

/// The scriptPubKey of a Ghost silent-payment announcement:
/// `OP_RETURN PUSH33 <compressed pubkey>`.
const OP_RETURN: u8 = 0x6a;
const PUSH33: u8 = 0x21;
const ANNOUNCE_LEN: usize = 35;

/// The scriptPubKey of a taproot output: `OP_1 PUSH32 <x-only key>`.
const OP_1: u8 = 0x51;
const PUSH32: u8 = 0x20;
const P2TR_LEN: usize = 34;

/// Pull a silent-payment candidate out of one transaction.
///
/// Returns the sender's ephemeral pubkey (hex, compressed) and every taproot
/// output that could be the payment, ready for
/// [`crate::candidate_scan::scan_candidate`]. `None` when the transaction
/// carries no announcement, which is almost all of them.
///
/// # The format
///
/// A Ghost silent payment announces itself with an `OP_RETURN` output holding
/// exactly one 33-byte compressed pubkey, and pays a taproot output derived
/// from it and the receiver's Ghost ID. Both halves are matched on the exact
/// script shape rather than by parsing: an `OP_RETURN` of some other length is
/// somebody else's data, and treating it as a pubkey would feed noise to the
/// scanner on every block.
///
/// Only the FIRST announcement is taken. A transaction carrying two is not a
/// payment with a spare key, it is malformed — and picking one at random would
/// make detection depend on output ordering.
pub fn candidate_in(tx: &BlockTx) -> Option<(String, Vec<CandidateOutput>)> {
    let mut ephemeral: Option<String> = None;
    let mut outputs = Vec::new();

    for v in &tx.vout {
        let Ok(spk) = hex::decode(&v.script_pubkey.hex) else {
            continue;
        };
        if spk.len() == ANNOUNCE_LEN && spk[0] == OP_RETURN && spk[1] == PUSH33 {
            if ephemeral.is_none() {
                ephemeral = Some(hex::encode(&spk[2..ANNOUNCE_LEN]));
            }
            continue;
        }
        if spk.len() == P2TR_LEN && spk[0] == OP_1 && spk[1] == PUSH32 {
            outputs.push(CandidateOutput {
                // x-only, as it appears on chain. The scanner tries both
                // parities, because a taproot output does not record which.
                output_pubkey: hex::encode(&spk[2..P2TR_LEN]),
                amount_sats: Some(v.value_sats()),
                vout: v.n,
            });
        }
    }

    // An announcement with nothing to pay into is not a candidate. Scanning it
    // would cost an ECDH per block for a transaction that cannot match.
    let ephemeral = ephemeral?;
    if outputs.is_empty() {
        return None;
    }
    Some((ephemeral, outputs))
}

/// Every silent-payment candidate in a block, with its txid.
pub fn candidates_in_block(block: &VerboseBlock) -> Vec<(String, String, Vec<CandidateOutput>)> {
    block
        .tx
        .iter()
        .filter_map(|tx| candidate_in(tx).map(|(e, o)| (tx.txid.clone(), e, o)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spk_hex(tag: u8) -> String {
        let mut v = vec![0x51, 0x20];
        v.extend_from_slice(&[tag; 32]);
        hex::encode(v)
    }

    fn ours_set(tags: &[u8]) -> HashSet<Vec<u8>> {
        tags.iter()
            .map(|t| hex::decode(spk_hex(*t)).unwrap())
            .collect()
    }

    /// Build a block from a compact description, so the tests read as the
    /// situation rather than as JSON.
    fn block(txs: serde_json::Value) -> VerboseBlock {
        serde_json::from_value(serde_json::json!({
            "hash": "00".repeat(32),
            "height": 900_000,
            "time": 1_700_000_000i64,
            "tx": txs,
        }))
        .expect("block fixture")
    }

    fn vin(value: f64, tag: u8) -> serde_json::Value {
        serde_json::json!({
            "txid": "11".repeat(32),
            "vout": 0,
            "prevout": { "value": value, "scriptPubKey": { "hex": spk_hex(tag) } }
        })
    }

    fn vout(n: u32, value: f64, tag: u8) -> serde_json::Value {
        serde_json::json!({ "n": n, "value": value, "scriptPubKey": { "hex": spk_hex(tag) } })
    }

    /// A payment arriving is the case the push used to cover, and the reason
    /// history was send-only without it.
    #[test]
    fn a_payment_to_us_is_found() {
        let b = block(serde_json::json!([{
            "txid": "aa",
            "vin": [vin(1.0, 0xbb)],
            "vout": [vout(0, 0.5, 0xaa), vout(1, 0.499, 0xbb)],
        }]));
        let moves = scan_block(&b, &ours_set(&[0xaa]));
        assert_eq!(moves.len(), 1);
        let m = &moves[0];
        assert_eq!(m.received_sats, 50_000_000);
        assert_eq!(m.spent_sats, 0);
        assert_eq!(m.net_sats(), 50_000_000);
        assert!(m.is_incoming, "we supplied no input");
        assert_eq!(m.vouts_to_us, vec![0]);
        assert_eq!(m.height, 900_000);
    }

    /// A block full of other people's payments must produce nothing, not a
    /// row per transaction with zeroes in it.
    #[test]
    fn a_block_of_strangers_produces_nothing() {
        let b = block(serde_json::json!([{
            "txid": "aa",
            "vin": [vin(1.0, 0xbb)],
            "vout": [vout(0, 0.999, 0xcc)],
        }]));
        assert!(scan_block(&b, &ours_set(&[0xaa])).is_empty());
    }

    /// A spend nets the payment *and* the fee, with change netted back out —
    /// the figure the balance will actually move by.
    #[test]
    fn a_spend_nets_the_fee_and_the_change() {
        let b = block(serde_json::json!([{
            "txid": "aa",
            "vin": [vin(1.0, 0xaa)],
            "vout": [vout(0, 0.5, 0xcc), vout(1, 0.4999, 0xaa)],
        }]));
        let m = &scan_block(&b, &ours_set(&[0xaa]))[0];
        assert_eq!(m.spent_sats, 100_000_000);
        assert_eq!(m.received_sats, 49_990_000, "the change came back to us");
        assert_eq!(m.net_sats(), -50_010_000, "payment plus fee");
        assert_eq!(m.fee_sats, Some(10_000));
        assert!(!m.is_incoming, "we supplied the input");
    }

    /// Money moved between our own addresses costs only the fee. It is not a
    /// zero-value event, and it is not incoming.
    #[test]
    fn a_self_send_nets_the_fee_only() {
        let b = block(serde_json::json!([{
            "txid": "aa",
            "vin": [vin(1.0, 0xaa)],
            "vout": [vout(0, 0.9999, 0xaa)],
        }]));
        let m = &scan_block(&b, &ours_set(&[0xaa]))[0];
        assert_eq!(m.net_sats(), -10_000);
        assert_eq!(m.fee_sats, Some(10_000));
        assert!(!m.is_incoming);
    }

    /// Mining pays the wallet with no inputs to compare against, so there is
    /// no fee to report — and reporting one would mean inventing it.
    #[test]
    fn a_coinbase_credits_us_with_no_fee() {
        let b = block(serde_json::json!([{
            "txid": "aa",
            "vin": [{ "coinbase": "03aabbcc" }],
            "vout": [vout(0, 3.125, 0xaa)],
        }]));
        let m = &scan_block(&b, &ours_set(&[0xaa]))[0];
        assert_eq!(m.received_sats, 312_500_000);
        assert_eq!(m.fee_sats, None, "a coinbase has no fee");
        assert!(m.is_incoming);
    }

    /// One unresolved input poisons the fee. The movement is still reported —
    /// knowing money moved matters more than knowing what it cost — but the
    /// fee is `None`, never a figure derived from the inputs that happened to
    /// be present.
    #[test]
    fn an_unresolved_input_yields_no_fee_rather_than_a_partial_one() {
        let b = block(serde_json::json!([{
            "txid": "aa",
            "vin": [vin(1.0, 0xaa), { "txid": "22".repeat(32), "vout": 1 }],
            "vout": [vout(0, 1.4, 0xcc)],
        }]));
        let m = &scan_block(&b, &ours_set(&[0xaa]))[0];
        assert_eq!(m.spent_sats, 100_000_000, "the input we could see was ours");
        assert_eq!(m.fee_sats, None, "a partial fee is a wrong fee");
    }

    fn announce_hex(tag: u8) -> String {
        // 6a 21 <33 bytes>. The leading 0x02 keeps it a plausible compressed
        // key; the extractor does not validate the curve point, the scanner
        // does.
        let mut v = vec![0x6a, 0x21, 0x02];
        v.extend_from_slice(&[tag; 32]);
        hex::encode(v)
    }

    fn tx_with_scripts(txid: &str, scripts: &[(u32, f64, String)]) -> crate::ghostd::BlockTx {
        let vout: Vec<serde_json::Value> = scripts
            .iter()
            .map(|(n, value, hex)| {
                serde_json::json!({ "n": n, "value": value, "scriptPubKey": { "hex": hex } })
            })
            .collect();
        serde_json::from_value(serde_json::json!({ "txid": txid, "vin": [], "vout": vout }))
            .expect("tx fixture")
    }

    /// The shape the sender writes: one announcement, one taproot output.
    #[test]
    fn an_announcement_and_a_taproot_output_make_a_candidate() {
        let tx = tx_with_scripts(
            "aa",
            &[
                (0, 0.0, announce_hex(0x11)),
                (1, 0.5, spk_hex(0xaa)),
                (2, 0.4, "76a914".to_string() + &"00".repeat(20) + "88ac"),
            ],
        );
        let (eph, outs) = candidate_in(&tx).expect("a candidate");
        assert_eq!(eph.len(), 66, "33 bytes, compressed");
        assert_eq!(outs.len(), 1, "only the taproot output is a candidate");
        assert_eq!(outs[0].vout, 1);
        assert_eq!(outs[0].amount_sats, Some(50_000_000));
        assert_eq!(outs[0].output_pubkey.len(), 64, "x-only, 32 bytes");
    }

    /// Almost every transaction on the chain is not a silent payment, and
    /// running an ECDH over each one would make scanning cost real money.
    #[test]
    fn a_transaction_without_an_announcement_is_not_a_candidate() {
        let tx = tx_with_scripts("aa", &[(0, 0.5, spk_hex(0xaa))]);
        assert!(candidate_in(&tx).is_none());
    }

    /// An OP_RETURN of the wrong length is somebody else's data. Treating it
    /// as a pubkey would feed noise to the scanner on every block.
    #[test]
    fn an_op_return_of_another_length_is_not_an_announcement() {
        let tx = tx_with_scripts(
            "aa",
            &[
                (0, 0.0, "6a0b68656c6c6f20776f726c64".into()),
                (1, 0.5, spk_hex(0xaa)),
            ],
        );
        assert!(candidate_in(&tx).is_none());
    }

    /// An announcement paying nothing into taproot cannot match anything.
    #[test]
    fn an_announcement_with_no_taproot_output_is_not_a_candidate() {
        let tx = tx_with_scripts(
            "aa",
            &[
                (0, 0.0, announce_hex(0x11)),
                (1, 0.5, "76a914".to_string() + &"00".repeat(20) + "88ac"),
            ],
        );
        assert!(candidate_in(&tx).is_none());
    }

    /// Two announcements is malformed, not a payment with a spare key. Taking
    /// the first makes detection independent of output ordering.
    #[test]
    fn a_second_announcement_is_ignored_rather_than_replacing_the_first() {
        let tx = tx_with_scripts(
            "aa",
            &[
                (0, 0.0, announce_hex(0x11)),
                (1, 0.0, announce_hex(0x22)),
                (2, 0.5, spk_hex(0xaa)),
            ],
        );
        let (eph, _) = candidate_in(&tx).expect("a candidate");
        assert_eq!(eph, announce_hex(0x11)[4..], "the first announcement wins");
    }

    /// The two halves must fit: what a sender writes into a block is what the
    /// scanner finds.
    ///
    /// This is the assumption the whole silent-payment path rests on. The
    /// announcement format was recovered from the retired operator service, so
    /// a test that only exercised the extractor against fixtures I wrote would
    /// prove I am consistent with myself. Here the sender is real
    /// `ghost-keys` — ECDH, the v2 address derivation, the taproot x-only
    /// truncation — and the receiver is the real scanner. Nothing in between
    /// is hand-written except the block encoding, which is the thing under
    /// test.
    #[test]
    fn a_real_silent_payment_survives_the_round_trip_through_a_block() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use ghost_keys::{derive_payment_address_v2, derive_shared_secret, GhostKeys};
        use rand::RngCore;

        let receiver = GhostKeys::generate();

        // Sender: a one-shot ephemeral key, ECDH against the receiver's
        // published scan key, then the output key at k = 0.
        let secp = Secp256k1::new();
        let mut eph = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph);
        let eph_secret = SecretKey::from_slice(&eph).expect("nonzero scalar");
        let eph_pub = PublicKey::from_secret_key(&secp, &eph_secret);
        let shared = derive_shared_secret(&eph_secret, receiver.scan_pubkey());
        let (output_pubkey, _) =
            derive_payment_address_v2(receiver.spend_pubkey(), &shared, 0).expect("derive");

        // On chain: the announcement, and the payment as a taproot output —
        // which keeps only the x-coordinate.
        let mut announce = vec![0x6a, 0x21];
        announce.extend_from_slice(&eph_pub.serialize());
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&output_pubkey.serialize()[1..]);

        let tx = tx_with_scripts(
            "feed",
            &[
                (0, 0.0, hex::encode(&announce)),
                // A decoy taproot output that is not ours, so the scanner has
                // to pick rather than accept whatever it is handed.
                (1, 0.25, spk_hex(0xcc)),
                (2, 0.5, hex::encode(&p2tr)),
            ],
        );

        let (eph_hex, outs) = candidate_in(&tx).expect("the announcement is found");
        let found = crate::candidate_scan::scan_candidate(
            &receiver,
            &eph_hex,
            &outs,
            "feed",
            Some(900_000),
        )
        .expect("scan runs");

        assert_eq!(found.len(), 1, "exactly the one output that was ours");
        assert_eq!(found[0].vout, 2, "and at the right output index");
        assert_eq!(found[0].amount_sats, Some(50_000_000));
        assert_eq!(found[0].k, 0);
        assert_eq!(found[0].block_height, Some(900_000));
    }

    /// The same payment addressed to somebody else must not match, or the
    /// test above would pass for a scanner that accepted anything.
    #[test]
    fn a_silent_payment_to_a_stranger_is_not_detected() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use ghost_keys::{derive_payment_address_v2, derive_shared_secret, GhostKeys};
        use rand::RngCore;

        let us = GhostKeys::generate();
        let them = GhostKeys::generate();

        let secp = Secp256k1::new();
        let mut eph = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph);
        let eph_secret = SecretKey::from_slice(&eph).unwrap();
        let eph_pub = PublicKey::from_secret_key(&secp, &eph_secret);
        let shared = derive_shared_secret(&eph_secret, them.scan_pubkey());
        let (output_pubkey, _) =
            derive_payment_address_v2(them.spend_pubkey(), &shared, 0).unwrap();

        let mut announce = vec![0x6a, 0x21];
        announce.extend_from_slice(&eph_pub.serialize());
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&output_pubkey.serialize()[1..]);

        let tx = tx_with_scripts(
            "feed",
            &[
                (0, 0.0, hex::encode(&announce)),
                (1, 0.5, hex::encode(&p2tr)),
            ],
        );
        let (eph_hex, outs) = candidate_in(&tx).expect("announcement present");
        let found =
            crate::candidate_scan::scan_candidate(&us, &eph_hex, &outs, "feed", None).unwrap();
        assert!(found.is_empty(), "not ours, got {found:?}");
    }

    /// BTC→sats must round, not truncate, on both sides of the ledger.
    #[test]
    fn an_awkward_float_does_not_lose_a_satoshi() {
        let b = block(serde_json::json!([{
            "txid": "aa",
            "vin": [vin(0.000_123_449_999_999, 0xbb)],
            "vout": [vout(0, 0.000_123_449_999_999, 0xaa)],
        }]));
        let m = &scan_block(&b, &ours_set(&[0xaa]))[0];
        assert_eq!(m.received_sats, 12_345);
    }
}
