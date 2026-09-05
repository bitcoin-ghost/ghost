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
//| FILE: privacy.rs                                                                                                     |
//|======================================================================================================================|

//! Adversarial probes — the harness that assumes the design is broken.
//!
//! *A privacy property without a continuous test harness is assumed broken.*
//!
//! This module does not check that the code does what it meant to. It plays the
//! analyst: given a round transaction and whatever an API hands out, it tries to
//! recover the input-to-output mapping. Anything it manages to recover is a
//! [`Violation`], and every violation is a bug.
//!
//! Two real leaks motivated this, both of which lived behind a comment
//! confidently explaining why they were fine:
//!
//! - `/round-tx` published a per-output `participant_id` over an
//!   unauthenticated endpoint, which combined with prevouts was the complete
//!   answer key.
//! - Inputs were emitted in registration order, encoding arrival sequence into
//!   the transaction.
//!
//! Neither was caught by a test. Both are caught by [`probe_round`] now.

use std::collections::HashMap;

use bitcoin::Transaction;

/// Something an analyst was able to learn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The transaction carries an on-chain marker, making every round of this
    /// protocol enumerable forever.
    OnChainMarker {
        /// Which output.
        index: usize,
        /// What was found.
        detail: String,
    },

    /// Output values are distinct enough to be matched to inputs by arithmetic.
    ///
    /// This is the attack that makes denominations non-negotiable: unique
    /// amounts are a fingerprint each participant publishes about themselves.
    MappingRecoverableByAmount {
        /// How many outputs were uniquely attributed.
        recovered: usize,
        /// Out of how many.
        total: usize,
    },

    /// An API response names a participant, linking identity to position.
    IdentityInResponse {
        /// The offending field name.
        field: String,
    },

    /// A value appears in every round, so it can be grepped for across the
    /// whole chain to enumerate participation.
    ConstantValueAcrossRounds {
        /// The greppable amount.
        value: u64,
        /// How many rounds carried it.
        rounds: usize,
    },
}

/// The mixed-output denomination probes assume, when one is known.
#[derive(Debug, Clone, Copy)]
pub struct RoundShape {
    /// Value every mixed output should share.
    pub denomination_sats: u64,
    /// Per-participant fee share, needed to model the amount attack.
    pub fee_share_sats: u64,
}

/// Run every single-transaction probe.
pub fn probe_round(tx: &Transaction, shape: Option<RoundShape>) -> Vec<Violation> {
    let mut found = scan_for_markers(tx);
    if let Some(shape) = shape {
        found.extend(attempt_amount_attack(tx, shape));
    }
    found
}

/// Any `OP_RETURN` output is a permanent, greppable marker.
///
/// v1 shipped a `WL01` marker and removed it. This is the regression probe.
pub fn scan_for_markers(tx: &Transaction) -> Vec<Violation> {
    tx.output
        .iter()
        .enumerate()
        .filter(|(_, o)| o.script_pubkey.is_op_return())
        .map(|(index, _)| Violation::OnChainMarker {
            index,
            detail: "OP_RETURN output makes every round enumerable".into(),
        })
        .collect()
}

/// Try to attribute outputs to inputs by arithmetic alone.
///
/// Models the simple case an analyst starts from: participant *i* put in
/// `value_i` and should get back `denomination`, so any surplus is theirs. When
/// outputs are all the same value there is nothing to match on and the attack
/// finds nothing. When outputs are distinct, each one names its owner.
///
/// Reports a violation only when *more* outputs are uniquely attributable than
/// chance would give — with `n` identical outputs every guess is 1-in-n, which
/// is the anonymity set working as intended.
pub fn attempt_amount_attack(tx: &Transaction, shape: RoundShape) -> Vec<Violation> {
    let outs: Vec<u64> = tx.output.iter().map(|o| o.value.to_sat()).collect();
    if outs.is_empty() {
        return Vec::new();
    }

    // How many outputs share their value with no other output? Those are the
    // ones an analyst can single out.
    let mut freq: HashMap<u64, usize> = HashMap::new();
    for v in &outs {
        *freq.entry(*v).or_insert(0) += 1;
    }

    // The fee output is legitimately unique and is not a participant's, so it
    // is excluded from the count.
    let fee_total = shape.fee_share_sats * tx.input.len() as u64;
    let unique: usize = outs
        .iter()
        .filter(|v| **v != fee_total && freq[*v] == 1)
        .count();

    let participant_outputs = outs.iter().filter(|v| **v != fee_total).count();
    if unique > 0 {
        vec![Violation::MappingRecoverableByAmount {
            recovered: unique,
            total: participant_outputs,
        }]
    } else {
        Vec::new()
    }
}

/// Field names that must never appear in a response body.
///
/// Each one links an identity to a position, and a position to an output. The
/// `/round-tx` leak was exactly this: `participant_id` per output, served
/// unauthenticated alongside prevouts.
pub const BANNED_RESPONSE_FIELDS: &[&str] = &[
    "participant_id",
    "participant_index",
    "participant_ids",
    "ghost_id",
    "ghost_ids",
    "owner",
    "submitter",
    "registered_by",
];

/// Scan a serialised API response for identity-to-position leakage.
///
/// Deliberately a string scan over the *serialised* body rather than a check on
/// the struct: it catches a field added under a different name, a `HashMap` with
/// identity keys, and anything that reaches the wire through `serde(flatten)` or
/// a manual `Serialize`. A type-level check would have missed all three.
///
/// Requests are a different matter — a caller naming themselves is how they
/// authenticate. This is for responses only.
pub fn probe_api_response(json: &str) -> Vec<Violation> {
    BANNED_RESPONSE_FIELDS
        .iter()
        .filter(|f| json.contains(**f))
        .map(|f| Violation::IdentityInResponse {
            field: (*f).to_string(),
        })
        .collect()
}

/// Look across many rounds for a *distinctive* value that never changes.
///
/// A pinned seat price or a fixed fee output is exactly this: one constant
/// makes every round findable with a single grep, without touching the script.
///
/// # Why multiplicity matters
///
/// A denomination is also constant across rounds — deliberately. That is the
/// anonymity set, and outputs must collide or there is no privacy at all. What
/// distinguishes a fingerprint from a denomination is **how many times it
/// appears within a round**: a denomination appears once per participant, while
/// a fee output appears exactly once and shares its value with nothing else.
///
/// So only values that are constant across rounds *and* solitary within each
/// one are reported. Getting this wrong in either direction is bad: flag
/// denominations and the probe cries wolf on a correct design; ignore
/// multiplicity and the fee output walks straight past.
pub fn probe_value_constancy(rounds: &[Transaction]) -> Vec<Violation> {
    if rounds.len() < 2 {
        return Vec::new();
    }
    let mut appears_in: HashMap<u64, usize> = HashMap::new();
    for tx in rounds {
        let mut multiplicity: HashMap<u64, usize> = HashMap::new();
        for o in &tx.output {
            *multiplicity.entry(o.value.to_sat()).or_insert(0) += 1;
        }
        // Solitary within this round → a candidate fingerprint.
        for (v, n) in multiplicity {
            if n == 1 {
                *appears_in.entry(v).or_insert(0) += 1;
            }
        }
    }
    let mut out: Vec<Violation> = appears_in
        .into_iter()
        .filter(|(_, n)| *n == rounds.len())
        .map(
            |(value, rounds_seen)| Violation::ConstantValueAcrossRounds {
                value,
                rounds: rounds_seen,
            },
        )
        .collect();
    out.sort_by_key(|v| match v {
        Violation::ConstantValueAcrossRounds { value, .. } => *value,
        _ => 0,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, TxIn, TxOut};

    fn tx_with_outputs(values: &[u64], inputs: usize) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (0..inputs).map(|_| TxIn::default()).collect(),
            output: values
                .iter()
                .map(|v| TxOut {
                    value: Amount::from_sat(*v),
                    script_pubkey: ScriptBuf::new(),
                })
                .collect(),
        }
    }

    const SHAPE: RoundShape = RoundShape {
        denomination_sats: 100_000,
        fee_share_sats: 200,
    };

    #[test]
    fn equal_denominations_defeat_the_amount_attack() {
        // Five identical outputs plus the fee output. Nothing to match on.
        let tx = tx_with_outputs(&[100_000, 100_000, 100_000, 100_000, 100_000, 1_000], 5);
        assert!(
            attempt_amount_attack(&tx, SHAPE).is_empty(),
            "an analyst should learn nothing from equal outputs"
        );
    }

    #[test]
    fn random_amounts_hand_the_analyst_every_participant() {
        // The same round with "more entropy" in the outputs. Every one is now
        // unique, so every one names its owner. This is the executable form of
        // the rule: privacy is collision, not entropy.
        let tx = tx_with_outputs(&[137_432, 891_203, 549_001, 220_118, 764_990, 1_000], 5);
        let v = attempt_amount_attack(&tx, SHAPE);
        assert_eq!(
            v,
            vec![Violation::MappingRecoverableByAmount {
                recovered: 5,
                total: 5
            }],
            "unique output amounts are a fingerprint each participant publishes"
        );
    }

    #[test]
    fn partial_uniqueness_is_still_a_violation() {
        // Four identical, one odd. The odd one out is fully deanonymised even
        // though the round "looks" mostly uniform.
        let tx = tx_with_outputs(&[100_000, 100_000, 100_000, 100_000, 137_432, 1_000], 5);
        assert_eq!(
            attempt_amount_attack(&tx, SHAPE),
            vec![Violation::MappingRecoverableByAmount {
                recovered: 1,
                total: 5
            }]
        );
    }

    #[test]
    fn an_op_return_is_a_permanent_marker() {
        let mut tx = tx_with_outputs(&[100_000, 100_000], 2);
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([0x57, 0x4c, 0x30, 0x31]), // "WL01"
        });
        let v = scan_for_markers(&tx);
        assert_eq!(
            v.len(),
            1,
            "the marker v1 shipped and removed must stay caught"
        );
        assert!(matches!(v[0], Violation::OnChainMarker { index: 2, .. }));
    }

    #[test]
    fn a_clean_round_probes_clean() {
        let tx = tx_with_outputs(&[100_000, 100_000, 100_000, 100_000, 100_000, 1_000], 5);
        assert!(probe_round(&tx, Some(SHAPE)).is_empty());
    }

    #[test]
    fn the_round_tx_leak_is_caught_by_the_api_probe() {
        // The exact body that shipped, reduced. This is the regression the
        // probe exists for.
        let leaked =
            r#"{"session_id":"s","output_provenance":[{"participant_id":3,"tx_output_index":0}]}"#;
        assert_eq!(
            probe_api_response(leaked),
            vec![Violation::IdentityInResponse {
                field: "participant_id".into()
            }]
        );
    }

    #[test]
    fn a_clean_response_probes_clean() {
        let ok = r#"{"session_id":"s","state":"filling","slots_filled":3,"slots_total":20,
                     "output_provenance":[{"tx_output_index":0,"kind":"mixed","amount_sats":100000}]}"#;
        assert!(probe_api_response(ok).is_empty());
    }

    #[test]
    fn a_renamed_field_is_still_caught() {
        // Someone "fixes" the leak by renaming rather than removing it.
        for body in [
            r#"{"outputs":[{"owner":"gid-7"}]}"#,
            r#"{"outputs":[{"submitter":"gid-7"}]}"#,
            r#"{"roster":{"ghost_ids":["a","b"]}}"#,
        ] {
            assert!(
                !probe_api_response(body).is_empty(),
                "renamed attribution slipped through: {body}"
            );
        }
    }

    #[test]
    fn a_pinned_seat_price_is_greppable_across_rounds() {
        // The realistic shape: a seat-FUNDING transaction, one seat output plus
        // change. The seat value is solitary in its own transaction, which is
        // what makes the pinned constant greppable — every seat ever funded,
        // from one query.
        let rounds: Vec<Transaction> = (0..5)
            .map(|i| tx_with_outputs(&[101_596, 50_000 + i * 7], 1))
            .collect();
        let v = probe_value_constancy(&rounds);
        assert!(
            v.contains(&Violation::ConstantValueAcrossRounds {
                value: 101_596,
                rounds: 5
            }),
            "a value present in every round is a marker: {v:?}"
        );
    }

    #[test]
    fn a_shared_denomination_is_not_reported_as_a_fingerprint() {
        // Every round carries five 100_000 outputs. That is the anonymity set
        // working, not a leak — the probe must not cry wolf on it.
        let rounds: Vec<Transaction> = (0..5u64)
            .map(|i| {
                tx_with_outputs(
                    &[100_000, 100_000, 100_000, 100_000, 100_000, 50_000 + i * 7],
                    5,
                )
            })
            .collect();
        let v = probe_value_constancy(&rounds);
        assert!(
            !v.contains(&Violation::ConstantValueAcrossRounds {
                value: 100_000,
                rounds: 5
            }),
            "the denomination is the anonymity set, not a fingerprint: {v:?}"
        );
    }

    #[test]
    fn a_solitary_constant_is_still_caught_beside_a_denomination() {
        // The real shape of the fee-output leak: many equal outputs plus one
        // constant, solitary one.
        let rounds: Vec<Transaction> = (0..5u64)
            .map(|i| tx_with_outputs(&[100_000, 100_000, 100_000, 5_000, 40_000 + i * 3], 5))
            .collect();
        assert!(
            probe_value_constancy(&rounds).contains(&Violation::ConstantValueAcrossRounds {
                value: 5_000,
                rounds: 5
            }),
            "a solitary constant beside a denomination is exactly the fee output"
        );
    }

    #[test]
    fn fee_varied_prices_are_not_constant() {
        // The same rounds priced from a live fee rate instead. No value spans
        // every round, so there is no constant to grep.
        let rounds: Vec<Transaction> = (0..5u64)
            .map(|i| tx_with_outputs(&[101_110 + i * 107, 101_110 + i * 107, 50_000 + i * 7], 2))
            .collect();
        assert!(probe_value_constancy(&rounds).is_empty());
    }
}
