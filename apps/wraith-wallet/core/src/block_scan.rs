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

use crate::ghostd::VerboseBlock;

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
