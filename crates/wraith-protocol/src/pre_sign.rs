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
    #[error("{got} distinct entities across {seats} seats is below the floor of {floor} — the set is not worth signing")]
    SetTooSmall {
        /// Distinct **entities** present, not seats.
        got: usize,
        /// Minimum acceptable.
        floor: usize,
        /// Seats in the round, so the gap between the two is visible. A round
        /// with many seats and few entities is padded, and the pair of numbers
        /// is what shows it.
        seats: usize,
    },

    /// The coordinator claimed a bigger set than the round's own coins support.
    ///
    /// Distinct from [`Self::SetTooSmall`], which is an honest round that is
    /// merely too thin. This is a round whose *stated* figure is not derivable
    /// from the chain — the participant recounted and got a smaller answer.
    #[error(
        "coordinator claims {claimed} entities but the round's inputs support at most {counted}"
    )]
    SetOverClaimed {
        /// The coordinator's figure.
        claimed: usize,
        /// What the participant counted.
        counted: usize,
    },

    /// The anonymity set was not analysed, so it cannot be relied on.
    ///
    /// Signing into an unmeasured set means trusting the coordinator's word for
    /// the one number the round is being bought for, and a malicious
    /// coordinator's easiest lie is a large one. Counting inputs is not a
    /// substitute: seats are what a padded round has plenty of.
    #[error(
        "anonymity set was not analysed; refusing to sign on an unverified set of {seats} seats"
    )]
    SetUnverified {
        /// Seats in the round.
        seats: usize,
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
    /// Minimum anonymity set worth signing into, in **entities**.
    pub min_set: usize,
    /// The participant's own analysis of the round's composition.
    ///
    /// `None` is not "skip the check" — it produces
    /// [`RefuseToSign::SetUnverified`]. The fallback is loud rather than
    /// silent, because a quiet fallback to counting seats is how the padded
    /// round gets signed.
    ///
    /// Built by [`crate::anonymity_set::assess`] from public chain data, so the
    /// coordinator is not in the trust path for it.
    pub set_report: Option<crate::anonymity_set::SetReport>,
    /// What the coordinator *claimed*, if it said anything.
    ///
    /// Checked against `set_report` rather than used in its place. A served
    /// figure is worth having only because it can be contradicted: without the
    /// comparison it is a number the user is asked to take on faith, which is
    /// the thing the recount exists to remove.
    ///
    /// `None` simply skips the comparison — a coordinator that claims nothing
    /// has not over-claimed.
    pub claimed_set: Option<crate::anonymity_set::SetReport>,
}

/// Verify a round before signing it. Returns every reason to refuse, not the
/// first — a participant deciding whether to retry wants the full picture.
pub fn check_before_signing(tx: &Transaction, want: &Expectation) -> Vec<RefuseToSign> {
    let mut refusals = Vec::new();

    // Judged on entities. This counted `tx.input.len()` — seats — which passes
    // exactly the padded round the floor exists to catch: fifty inputs from two
    // parties cleared a floor of five.
    match &want.set_report {
        Some(report) => {
            if !report.meets(want.min_set) {
                refusals.push(RefuseToSign::SetTooSmall {
                    got: report.entities,
                    floor: want.min_set,
                    seats: tx.input.len(),
                });
            }
        }
        None => refusals.push(RefuseToSign::SetUnverified {
            seats: tx.input.len(),
        }),
    }

    // A served figure earns its place only by being contradictable.
    if let (Some(claimed), Some(independent)) = (&want.claimed_set, &want.set_report) {
        if let Err(e) = crate::anonymity_set::verify_claim(claimed, independent) {
            refusals.push(RefuseToSign::SetOverClaimed {
                claimed: e.claimed,
                counted: e.counted,
            });
        }
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
            set_report: Some(report_of(5, 5)),
            claimed_set: None,
        }
    }

    /// A report with `entities` distinct parties across `seats` seats.
    fn report_of(entities: usize, seats: usize) -> crate::anonymity_set::SetReport {
        crate::anonymity_set::SetReport {
            seats,
            entities,
            unverified: 0,
            payers: entities,
            discounts: Vec::new(),
        }
    }

    #[test]
    fn a_coordinator_claiming_more_than_the_coins_support_is_refused() {
        // Distinct from a thin round. This one is not merely small — its stated
        // figure is not derivable from the chain at all.
        let mut want = expectation();
        want.set_report = Some(report_of(5, 20));
        want.claimed_set = Some(report_of(20, 20));
        let r = check_before_signing(&honest_round(), &want);
        assert!(
            r.iter().any(|x| matches!(
                x,
                RefuseToSign::SetOverClaimed {
                    claimed: 20,
                    counted: 5
                }
            )),
            "{r:?}"
        );
    }

    #[test]
    fn a_coordinator_claiming_fewer_is_not_punished_for_it() {
        // It can see liquidity-provider identities the participant cannot, and
        // merging those correctly lowers the figure. Refusing that would punish
        // the honest behaviour.
        let mut want = expectation();
        want.set_report = Some(report_of(9, 9));
        want.claimed_set = Some(report_of(6, 9));
        let r = check_before_signing(&honest_round(), &want);
        assert!(
            !r.iter()
                .any(|x| matches!(x, RefuseToSign::SetOverClaimed { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn a_padded_round_is_refused_however_many_seats_it_has() {
        // The bug this replaced: the floor counted inputs, so fifty seats held
        // by two parties cleared a floor of five.
        let mut want = expectation();
        want.set_report = Some(report_of(2, 50));
        let refusals = check_before_signing(&honest_round(), &want);
        assert!(
            refusals.iter().any(|r| matches!(
                r,
                RefuseToSign::SetTooSmall {
                    got: 2,
                    floor: 5,
                    ..
                }
            )),
            "{refusals:?}"
        );
    }

    #[test]
    fn an_unanalysed_set_is_refused_rather_than_assumed_fine() {
        // A quiet fallback to counting seats is how the padded round gets
        // signed, so the absence of analysis must be loud.
        let mut want = expectation();
        want.set_report = None;
        let refusals = check_before_signing(&honest_round(), &want);
        assert!(
            refusals
                .iter()
                .any(|r| matches!(r, RefuseToSign::SetUnverified { .. })),
            "{refusals:?}"
        );
    }

    #[test]
    fn the_refusal_shows_entities_against_seats() {
        // The gap between the two is what tells a user the round was padded,
        // so both have to be in the message.
        let e = RefuseToSign::SetTooSmall {
            got: 2,
            floor: 5,
            seats: 50,
        };
        let msg = e.to_string();
        assert!(msg.contains('2') && msg.contains("50"), "{msg}");
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
        let mut want = expectation();
        want.set_report = Some(report_of(2, 2));
        let r = check_before_signing(&honest_round(), &want);
        assert!(r.contains(&RefuseToSign::SetTooSmall {
            got: 2,
            floor: 5,
            seats: 5
        }));
    }

    #[test]
    fn the_transactions_input_count_is_no_longer_the_set() {
        // Truncating the transaction does not trip the floor, because seats are
        // not the set. This is the whole change: the number that matters comes
        // from the participant's own analysis, not from counting inputs.
        let mut tx = honest_round();
        tx.input.truncate(2);
        let r = check_before_signing(&tx, &expectation());
        assert!(
            !r.iter()
                .any(|x| matches!(x, RefuseToSign::SetTooSmall { .. })),
            "seat count must not drive the set floor: {r:?}"
        );
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
        let mut want = expectation();
        // The set has to be made thin explicitly now; truncating the inputs no
        // longer does it, which is the point of the change.
        want.set_report = Some(report_of(1, 1));
        let r = check_before_signing(&tx, &want);
        assert!(r.len() >= 3, "expected several refusals, got {r:?}");
    }
}
