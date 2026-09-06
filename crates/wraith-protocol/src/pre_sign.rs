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
//| FILE: pre_sign.rs                                                                                                 |
//|======================================================================================================================|

//! What a participant checks before signing — the last moment they control.
//!
//! Everything else in this crate constrains the coordinator. This is the part
//! that makes it *untrusted*: once a participant signs, the round is out of
//! their hands, so every property they were promised has to be verifiable from
//! the transaction itself, by them, first.
//!
//! Without this a participant is trusting the coordinator to have built an
//! honest round. With it they need trust nothing — a dishonest round simply does
//! not get their signature, and a round without every signature does not
//! broadcast.
//!
//! # Why this is also the non-Ghost client's whole safety story
//!
//! An outside wallet joining a round over PSBT has no Lock, no quorum and no
//! residency. What it does have is the transaction. These checks are the only
//! thing standing between it and a coordinator that pays itself — which is why
//! this belongs in the protocol crate rather than in any one client.
//!
//! # Refuse, do not warn
//!
//! Every failure here returns a refusal. A warning that still signs is worth
//! nothing: the signature is the irreversible act.

use bitcoin::{ScriptBuf, Transaction, Txid};

/// Why a participant refused to sign.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RefuseToSign {
    /// The round does not spend the coin this participant registered.
    #[error("my input {txid}:{vout} is not in the round")]
    MyInputMissing {
        /// Expected txid.
        txid: Txid,
        /// Expected vout.
        vout: u32,
    },

    /// The participant's own output is absent, or not for the agreed amount.
    ///
    /// The coordinator pocketing one participant's output is the simplest
    /// possible theft, and it is invisible unless each participant looks.
    #[error("my output for {expected_sats} sats is not in the round")]
    MyOutputMissing {
        /// What was agreed.
        expected_sats: u64,
    },

    /// The round pays more to miners than was agreed.
    #[error("round fee {actual} exceeds the {max} agreed")]
    FeeTooHigh {
        /// Fee the round actually pays.
        actual: u64,
        /// Ceiling the participant accepted.
        max: u64,
    },

    /// Too few participants for the round to be worth joining.
    #[error("{got} inputs is below the floor of {floor} — the set is not worth signing")]
    SetTooSmall {
        /// Inputs present.
        got: usize,
        /// Minimum acceptable.
        floor: usize,
    },

    /// The round carries an on-chain marker.
    #[error("round carries an on-chain marker at output {index} — every round becomes enumerable")]
    CarriesMarker {
        /// Which output.
        index: usize,
    },

    /// The participant's own output is unique in value, so it identifies them.
    #[error("my output of {value} sats is the only one of its value — it identifies me")]
    MyOutputIsUnique {
        /// The distinguishing value.
        value: u64,
    },
}

/// What a participant agreed to, and will verify before signing.
#[derive(Debug, Clone)]
pub struct Expectation {
    /// The coin this participant contributed.
    pub my_input: (Txid, u32),
    /// The script this participant's output must pay.
    pub my_output_script: ScriptBuf,
    /// The value that output must carry.
    pub my_output_sats: u64,
    /// Total input value, needed to compute the fee. The participant knows
    /// their own; the rest comes from prevouts the coordinator serves and the
    /// wallet can verify against the chain.
    pub total_input_sats: u64,
    /// Fee ceiling the participant accepted.
    pub max_fee_sats: u64,
    /// Minimum anonymity set worth signing into.
    pub min_set: usize,
}

/// Verify a round before signing it. Returns every reason to refuse, not the
/// first — a participant deciding whether to retry wants the full picture.
pub fn check_before_signing(tx: &Transaction, want: &Expectation) -> Vec<RefuseToSign> {
    let mut refusals = Vec::new();

    if tx.input.len() < want.min_set {
        refusals.push(RefuseToSign::SetTooSmall {
            got: tx.input.len(),
            floor: want.min_set,
        });
    }

    let (txid, vout) = want.my_input;
    let mine_present = tx
        .input
        .iter()
        .any(|i| i.previous_output.txid == txid && i.previous_output.vout == vout);
    if !mine_present {
        refusals.push(RefuseToSign::MyInputMissing { txid, vout });
    }

    let my_output_present = tx.output.iter().any(|o| {
        o.script_pubkey == want.my_output_script && o.value.to_sat() == want.my_output_sats
    });
    if !my_output_present {
        refusals.push(RefuseToSign::MyOutputMissing {
            expected_sats: want.my_output_sats,
        });
    }

    for (index, o) in tx.output.iter().enumerate() {
        if o.script_pubkey.is_op_return() {
            refusals.push(RefuseToSign::CarriesMarker { index });
        }
    }

    let total_out: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    let fee = want.total_input_sats.saturating_sub(total_out);
    if fee > want.max_fee_sats {
        refusals.push(RefuseToSign::FeeTooHigh {
            actual: fee,
            max: want.max_fee_sats,
        });
    }

    // A participant whose output is the only one of its value has no anonymity
    // regardless of how many others are in the round.
    if my_output_present {
        let same_value = tx
            .output
            .iter()
            .filter(|o| o.value.to_sat() == want.my_output_sats)
            .count();
        if same_value < 2 {
            refusals.push(RefuseToSign::MyOutputIsUnique {
                value: want.my_output_sats,
            });
        }
    }

    refusals
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, Sequence, TxIn,
        TxOut, Witness,
    };

    fn spk(tag: u8) -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51, 0x20, tag])
    }

    fn outpoint(tag: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        }
    }

    /// A five-seat round paying 100k each, plus a 1k fee output.
    fn honest_round() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (1..=5u8)
                .map(|i| TxIn {
                    previous_output: outpoint(i),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: (1..=5u8)
                .map(|i| TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: spk(i + 10),
                })
                .chain(std::iter::once(TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: spk(99),
                }))
                .collect(),
        }
    }

    fn expectation() -> Expectation {
        Expectation {
            my_input: (outpoint(1).txid, 0),
            my_output_script: spk(11),
            my_output_sats: 100_000,
            total_input_sats: 505_000,
            max_fee_sats: 10_000,
            min_set: 5,
        }
    }

    #[test]
    fn an_honest_round_is_signed() {
        assert_eq!(
            check_before_signing(&honest_round(), &expectation()),
            vec![]
        );
    }

    #[test]
    fn a_round_that_drops_my_output_is_refused() {
        // The simplest theft: build the round without paying one participant.
        let mut tx = honest_round();
        tx.output.retain(|o| o.script_pubkey != spk(11));
        let r = check_before_signing(&tx, &expectation());
        assert!(r.contains(&RefuseToSign::MyOutputMissing {
            expected_sats: 100_000
        }));
    }

    #[test]
    fn a_round_that_shortchanges_me_is_refused() {
        let mut tx = honest_round();
        for o in tx.output.iter_mut() {
            if o.script_pubkey == spk(11) {
                o.value = Amount::from_sat(90_000);
            }
        }
        let r = check_before_signing(&tx, &expectation());
        assert!(r.contains(&RefuseToSign::MyOutputMissing {
            expected_sats: 100_000
        }));
    }

    #[test]
    fn a_round_that_does_not_spend_my_coin_is_refused() {
        let mut tx = honest_round();
        tx.input[0].previous_output = outpoint(200);
        let r = check_before_signing(&tx, &expectation());
        assert!(matches!(r[..], [RefuseToSign::MyInputMissing { .. }]));
    }

    #[test]
    fn a_round_overpaying_miners_is_refused() {
        // Value that vanishes into fees is value taken from participants.
        let mut tx = honest_round();
        tx.output.pop();
        for o in tx.output.iter_mut() {
            o.value = Amount::from_sat(50_000);
        }
        let r = check_before_signing(&tx, &expectation());
        assert!(r
            .iter()
            .any(|x| matches!(x, RefuseToSign::FeeTooHigh { .. })));
    }

    #[test]
    fn a_thin_round_is_refused() {
        let mut tx = honest_round();
        tx.input.truncate(2);
        let r = check_before_signing(&tx, &expectation());
        assert!(r.contains(&RefuseToSign::SetTooSmall { got: 2, floor: 5 }));
    }

    #[test]
    fn a_marked_round_is_refused() {
        let mut tx = honest_round();
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([0x57, 0x4c]),
        });
        let r = check_before_signing(&tx, &expectation());
        assert!(r
            .iter()
            .any(|x| matches!(x, RefuseToSign::CarriesMarker { .. })));
    }

    #[test]
    fn an_output_unique_in_value_is_refused_even_in_a_full_round() {
        // Five inputs, so the set *looks* fine — but if my output is the only
        // one of its value, subtraction identifies me immediately. A count of
        // participants is not a measure of anonymity.
        let mut tx = honest_round();
        for o in tx.output.iter_mut() {
            if o.script_pubkey == spk(11) {
                o.value = Amount::from_sat(137_000);
            }
        }
        let mut want = expectation();
        want.my_output_sats = 137_000;
        let r = check_before_signing(&tx, &want);
        assert!(r.contains(&RefuseToSign::MyOutputIsUnique { value: 137_000 }));
    }

    #[test]
    fn every_reason_is_reported_not_just_the_first() {
        // A participant deciding whether to retry wants the whole picture.
        let mut tx = honest_round();
        tx.input.truncate(1);
        tx.output.retain(|o| o.script_pubkey != spk(11));
        let r = check_before_signing(&tx, &expectation());
        assert!(r.len() >= 3, "expected several refusals, got {r:?}");
    }
}
