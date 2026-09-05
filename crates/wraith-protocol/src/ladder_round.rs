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
//| FILE: ladder_round.rs                                                                                                |
//|======================================================================================================================|

//! Ladder rounds — a round with no fee output and no fixed denomination.
//!
//! Sits alongside [`crate::single_round::LiteRoundBuilder`] rather than
//! replacing it: the tier path keeps working while this one is proven.
//!
//! # What changes against the tier round
//!
//! **You bring the rungs you have.** The tier round required an input of
//! *exactly* the seat price (#698), because it had no change output — so a user
//! needed the right coin before they could pay at all. Here a participant
//! contributes whatever rungs they hold, the recipient is paid in rungs, and
//! the surplus returns as more rungs to fresh addresses. Change is safe because
//! it is denominated like everyone else's output, not because it is hidden.
//!
//! **There is no fee output.** The tier round paid the coordinator with one
//! distinct output worth `service_fee_sats() * n` — a constant that made every
//! Mix round of a given size greppable, and, worse, *the one output that does
//! not match the others*. Varying its value would not have helped; an analyst
//! seeing N equal outputs and one odd one knows exactly what they are looking
//! at.
//!
//! The coordinator is instead paid in **ordinary rungs**. A fee is far smaller
//! than a rung, so it accrues across rounds and settles when it crosses one —
//! the same mechanism specified for provider commission. The transaction is
//! then uniform: every output is a ladder value and none is distinguishable by
//! role.
//!
//! # The invariant this module exists to hold
//!
//! **Every output value is a rung.** Not "mostly", not "except the fee". One
//! non-rung output re-introduces the fingerprint, and
//! [`LadderRoundError::NotARung`] refuses it at build time rather than leaving
//! it to a probe to find later.

use bitcoin::{
    absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

use crate::ladder::Ladder;
use crate::single_round::shuffle_with_chacha;

/// A coin a participant contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderInput {
    /// Previous txid.
    pub txid: Txid,
    /// Previous vout.
    pub vout: u32,
    /// Value in satoshis. Must be a rung.
    pub value_sats: u64,
}

/// An output a participant is owed — a payment leg or their own change.
///
/// The builder does not distinguish the two, and neither can an observer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LadderOutput {
    /// Destination address.
    pub address: String,
    /// Value in satoshis. Must be a rung.
    pub value_sats: u64,
}

/// One participant's contribution to the round.
#[derive(Debug, Clone, Default)]
pub struct LadderParticipant {
    /// Rungs contributed.
    pub inputs: Vec<LadderInput>,
    /// Rungs owed — recipient legs and change alike.
    pub outputs: Vec<LadderOutput>,
}

/// Why a ladder round could not be built.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LadderRoundError {
    /// A value is not on the ladder. Refused rather than fingerprinting the round.
    #[error("{role} value {value} is not a ladder rung — one non-rung output re-introduces the fingerprint")]
    NotARung {
        /// `input` or `output`.
        role: &'static str,
        /// The offending amount.
        value: u64,
    },

    /// Inputs do not cover outputs plus the minimum mining fee.
    #[error("round underfunded: {inputs} in, {outputs} out, needs at least {required} for fees")]
    Underfunded {
        /// Total input value.
        inputs: u64,
        /// Total output value.
        outputs: u64,
        /// Minimum acceptable mining fee.
        required: u64,
    },

    /// More than a whole rung is being handed to miners.
    ///
    /// A ladder round can never balance exactly — fees are not rung-sized, so
    /// some remainder always goes to miners. Under one rung that is unavoidable
    /// change too small to express. Over one rung it means the decomposer
    /// should have taken another change output, and the participant is simply
    /// losing money.
    #[error("overpaying miners by {excess} sats — a further change rung was affordable at {recoverable}")]
    ExcessiveOverpayment {
        /// How much above the required fee.
        excess: u64,
        /// Surplus at which another change rung becomes takeable: the ladder
        /// floor plus the vbyte cost of the output that would carry it.
        recoverable: u64,
    },

    /// Too few participants for the round to mean anything.
    #[error("{got} participants, floor is {floor}")]
    BelowFloor {
        /// How many registered.
        got: usize,
        /// The configured minimum.
        floor: usize,
    },

    /// An address failed to parse or belongs to another network.
    #[error("address {address}: {detail}")]
    BadAddress {
        /// The address.
        address: String,
        /// What went wrong.
        detail: String,
    },
}

/// Builds a ladder round.
#[derive(Debug)]
pub struct LadderRoundBuilder {
    session_id: String,
    ladder: Ladder,
    network: Network,
    fee_rate_sats_per_vb: u64,
    floor: usize,
    participants: Vec<LadderParticipant>,
    coordinator_outputs: Vec<LadderOutput>,
}

impl LadderRoundBuilder {
    /// New builder. `coordinator_outputs` is the accrued fee being settled this
    /// round, in whole rungs — empty is normal and expected.
    pub fn new(
        session_id: impl Into<String>,
        ladder: Ladder,
        network: Network,
        fee_rate_sats_per_vb: u64,
        floor: usize,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            ladder,
            network,
            fee_rate_sats_per_vb,
            floor,
            participants: Vec::new(),
            coordinator_outputs: Vec::new(),
        }
    }

    /// Register a participant.
    pub fn add_participant(&mut self, p: LadderParticipant) {
        self.participants.push(p);
    }

    /// Settle accrued coordinator fee, in whole rungs.
    pub fn settle_coordinator_fee(&mut self, outputs: Vec<LadderOutput>) {
        self.coordinator_outputs.extend(outputs);
    }

    /// Transaction vbytes at the current shape.
    pub fn estimate_vbytes(&self) -> u64 {
        let ins: usize = self.participants.iter().map(|p| p.inputs.len()).sum();
        let outs: usize = self
            .participants
            .iter()
            .map(|p| p.outputs.len())
            .sum::<usize>()
            + self.coordinator_outputs.len();
        // Measured on regtest: 100.50 vB per seat = 57.5 in + 43 out.
        (11 + ins * 58 + outs * 43) as u64
    }

    /// The minimum mining fee this round's shape must pay.
    pub fn minimum_mining_fee_sats(&self) -> u64 {
        self.estimate_vbytes() * self.fee_rate_sats_per_vb
    }

    /// Build the unsigned round transaction.
    pub fn build(&self, entropy: &[u8; 32]) -> Result<LadderRound, LadderRoundError> {
        if self.participants.len() < self.floor {
            return Err(LadderRoundError::BelowFloor {
                got: self.participants.len(),
                floor: self.floor,
            });
        }

        // Every value on both sides must be a rung. Refuse at build time.
        for p in &self.participants {
            for i in &p.inputs {
                self.require_rung("input", i.value_sats)?;
            }
            for o in &p.outputs {
                self.require_rung("output", o.value_sats)?;
            }
        }
        for o in &self.coordinator_outputs {
            self.require_rung("output", o.value_sats)?;
        }

        let total_in: u64 = self
            .participants
            .iter()
            .flat_map(|p| &p.inputs)
            .map(|i| i.value_sats)
            .sum();
        let total_out: u64 = self
            .participants
            .iter()
            .flat_map(|p| &p.outputs)
            .map(|o| o.value_sats)
            .sum::<u64>()
            + self
                .coordinator_outputs
                .iter()
                .map(|o| o.value_sats)
                .sum::<u64>();

        // The actual mining fee is whatever is left over. A ladder round cannot
        // balance exactly, because fees are not rung-sized — so the remainder
        // below one rung is unavoidable and anything above it is waste.
        let required = self.minimum_mining_fee_sats();
        if total_in < total_out + required {
            return Err(LadderRoundError::Underfunded {
                inputs: total_in,
                outputs: total_out,
                required,
            });
        }
        let fee = total_in - total_out;
        let excess = fee - required;

        // Taking one more change rung is only *possible* if the surplus covers
        // both the rung and the 43 vB that output itself costs. Between those
        // two thresholds the remainder is genuinely unavoidable — no change can
        // be taken — so the bound must include the cost of the output it is
        // recommending, or it condemns rounds that had no better option.
        let another_output_costs = 43 * self.fee_rate_sats_per_vb;
        let recoverable = self.ladder.floor() + another_output_costs;
        if excess >= recoverable {
            return Err(LadderRoundError::ExcessiveOverpayment {
                excess,
                recoverable,
            });
        }

        // Inputs, then shuffled. Registration order would encode arrival
        // sequence into the transaction, which the chain never reveals.
        let mut tx_inputs: Vec<TxIn> = self
            .participants
            .iter()
            .flat_map(|p| &p.inputs)
            .map(|i| TxIn {
                previous_output: OutPoint {
                    txid: i.txid,
                    vout: i.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();
        shuffle_with_chacha(
            &mut tx_inputs,
            self.seed(b"WraithLadder/v1/input_shuffle", entropy),
        );

        // Outputs. Participant legs and the coordinator's settled rungs are
        // pooled before shuffling — nothing marks which is which.
        let mut items: Vec<LadderOutput> = self
            .participants
            .iter()
            .flat_map(|p| p.outputs.iter().cloned())
            .chain(self.coordinator_outputs.iter().cloned())
            .collect();
        shuffle_with_chacha(
            &mut items,
            self.seed(b"WraithLadder/v1/output_shuffle", entropy),
        );

        let mut tx_outputs = Vec::with_capacity(items.len());
        for item in &items {
            let addr = Address::from_str_checked(&item.address, self.network).map_err(|d| {
                LadderRoundError::BadAddress {
                    address: item.address.clone(),
                    detail: d,
                }
            })?;
            tx_outputs.push(TxOut {
                value: Amount::from_sat(item.value_sats),
                script_pubkey: addr.script_pubkey(),
            });
        }

        Ok(LadderRound {
            session_id: self.session_id.clone(),
            tx: Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: tx_inputs,
                output: tx_outputs,
            },
            mining_fee_sats: fee,
        })
    }

    fn require_rung(&self, role: &'static str, value: u64) -> Result<(), LadderRoundError> {
        if self.ladder.rungs().contains(&value) {
            Ok(())
        } else {
            Err(LadderRoundError::NotARung { role, value })
        }
    }

    /// Domain-separated shuffle seed.
    ///
    /// Input and output permutations must not share one, or index *i* on each
    /// side correlates and hands back the mapping the output shuffle exists to
    /// destroy.
    fn seed(&self, tag: &[u8], entropy: &[u8; 32]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tag);
        h.update(self.session_id.as_bytes());
        h.update(entropy);
        h.finalize().into()
    }
}

/// Local helper so the error type stays ours rather than bitcoin's.
trait AddressExt: Sized {
    fn from_str_checked(s: &str, network: Network) -> Result<Self, String>;
}

impl AddressExt for Address {
    fn from_str_checked(s: &str, network: Network) -> Result<Self, String> {
        use std::str::FromStr;
        Address::from_str(s)
            .map_err(|e| e.to_string())?
            .require_network(network)
            .map_err(|e| e.to_string())
    }
}

/// A built ladder round.
#[derive(Debug, Clone)]
pub struct LadderRound {
    /// Session this belongs to.
    pub session_id: String,
    /// The unsigned transaction.
    pub tx: Transaction,
    /// Mining fee paid.
    pub mining_fee_sats: u64,
}

impl LadderRound {
    /// Txid the signed transaction will have.
    pub fn txid(&self) -> Txid {
        self.tx.compute_txid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::{probe_round, probe_value_constancy};
    use bitcoin::hashes::{hash160, Hash};
    use bitcoin::PubkeyHash;

    fn addr(tag: u8) -> String {
        let mut seed = [0u8; 32];
        seed[0] = tag;
        seed[31] = tag.wrapping_add(1);
        let h = hash160::Hash::hash(&seed);
        Address::p2pkh(
            PubkeyHash::from_byte_array(h.to_byte_array()),
            Network::Signet,
        )
        .to_string()
    }

    fn coin(tag: u8, value: u64) -> LadderInput {
        LadderInput {
            txid: Txid::from_byte_array([tag; 32]),
            vout: u32::from(tag % 3),
            value_sats: value,
        }
    }

    /// Five participants, each bringing one 200k rung and taking back rungs.
    /// Fees are absorbed by trimming a participant's change, so the round
    /// balances exactly.
    fn balanced_builder(rate: u64, coordinator: Vec<LadderOutput>) -> LadderRoundBuilder {
        let mut b = LadderRoundBuilder::new("s-1", Ladder::standard(), Network::Signet, rate, 5);
        for i in 0..5u8 {
            b.add_participant(LadderParticipant {
                inputs: vec![coin(i + 1, 200_000)],
                outputs: vec![
                    LadderOutput {
                        address: addr(i + 10),
                        value_sats: 100_000,
                    },
                    LadderOutput {
                        address: addr(i + 20),
                        value_sats: 50_000,
                    },
                    LadderOutput {
                        address: addr(i + 30),
                        value_sats: 20_000,
                    },
                    LadderOutput {
                        address: addr(i + 40),
                        value_sats: 20_000,
                    },
                ],
            });
        }
        b.settle_coordinator_fee(coordinator);
        b
    }

    /// Absorb surplus into change rungs until no further rung can be taken.
    ///
    /// Two things bit me writing this, both of which are properties of the
    /// design rather than of the test:
    ///
    /// 1. Adding a change output *grows* the transaction, so the rung has to
    ///    fit the surplus **after** paying its own 43 vB. Taking the largest
    ///    rung that fits the raw surplus overshoots, the round flips to
    ///    underfunded, and a fix-up loop oscillates forever.
    /// 2. There is a band — between the floor and `floor + output_cost` —
    ///    where no rung can be taken at all and the remainder is genuinely
    ///    unavoidable. Settling there is correct, not a failure.
    ///
    /// Bounded regardless: an unbounded version of this spun at 91% CPU and
    /// produced no output at all, which is a far worse failure than a panic.
    fn absorb_surplus(b: &mut LadderRoundBuilder) {
        let ladder = Ladder::standard();
        let per_output_fee = 43 * b.fee_rate_sats_per_vb;

        for _ in 0..64 {
            let total_in: u64 = b
                .participants
                .iter()
                .flat_map(|p| &p.inputs)
                .map(|i| i.value_sats)
                .sum();
            let total_out: u64 = b
                .participants
                .iter()
                .flat_map(|p| &p.outputs)
                .map(|o| o.value_sats)
                .sum::<u64>()
                + b.coordinator_outputs
                    .iter()
                    .map(|o| o.value_sats)
                    .sum::<u64>();
            let required = b.minimum_mining_fee_sats();

            assert!(
                total_in >= total_out + required,
                "fixture underfunded: {total_in} in, {total_out} out, {required} needed"
            );

            let excess = total_in - total_out - required;
            let budget = excess.saturating_sub(per_output_fee);
            let Some(take) = ladder.rungs().iter().rev().find(|r| **r <= budget).copied() else {
                return; // remainder is unavoidable
            };

            let n = b.participants.len();
            b.participants[n - 1].outputs.push(LadderOutput {
                address: addr(0x80),
                value_sats: take,
            });
        }
        panic!("surplus never settled in 64 steps — the loop is oscillating");
    }

    #[test]
    fn a_balanced_ladder_round_builds() {
        let mut b = balanced_builder(5, vec![]);
        absorb_surplus(&mut b);
        let round = b.build(&[0x11; 32]).expect("balances");
        assert_eq!(round.tx.input.len(), 5);
        assert!(round.tx.output.len() >= 15);
    }

    #[test]
    fn every_output_is_a_rung() {
        let mut b = balanced_builder(5, vec![]);
        absorb_surplus(&mut b);
        let round = b.build(&[0x11; 32]).unwrap();
        let ladder = Ladder::standard();
        for o in &round.tx.output {
            assert!(
                ladder.rungs().contains(&o.value.to_sat()),
                "non-rung output {} re-introduces the fingerprint",
                o.value.to_sat()
            );
        }
    }

    #[test]
    fn a_non_rung_output_is_refused_at_build_time() {
        let mut b = balanced_builder(5, vec![]);
        b.participants[0].outputs.push(LadderOutput {
            address: addr(99),
            value_sats: 137_432,
        });
        assert!(matches!(
            b.build(&[0x11; 32]),
            Err(LadderRoundError::NotARung {
                role: "output",
                value: 137_432
            })
        ));
    }

    /// Handing miners more than a rung means the decomposer missed a change
    /// output. The participant is simply losing money, so refuse it.
    #[test]
    fn overpaying_miners_by_a_whole_rung_is_refused() {
        let b = balanced_builder(5, vec![]);
        assert!(matches!(
            b.build(&[0x11; 32]),
            Err(LadderRoundError::ExcessiveOverpayment { .. })
        ));
    }

    #[test]
    fn an_underfunded_round_is_refused() {
        let mut b = balanced_builder(5, vec![]);
        // Take out far more than was put in.
        for p in b.participants.iter_mut() {
            p.outputs.push(LadderOutput {
                address: addr(0x90),
                value_sats: 100_000,
            });
        }
        assert!(matches!(
            b.build(&[0x11; 32]),
            Err(LadderRoundError::Underfunded { .. })
        ));
    }

    #[test]
    fn a_thin_round_is_refused() {
        let mut b = LadderRoundBuilder::new("s", Ladder::standard(), Network::Signet, 5, 5);
        b.add_participant(LadderParticipant {
            inputs: vec![coin(1, 100_000)],
            outputs: vec![],
        });
        assert!(matches!(
            b.build(&[0x11; 32]),
            Err(LadderRoundError::BelowFloor { got: 1, floor: 5 })
        ));
    }

    /// The payoff. The tier round pays the coordinator with one distinct output
    /// worth `fee * n`, which is constant across rounds and solitary within
    /// each — exactly what the probe flags. A ladder round settles that fee in
    /// ordinary rungs, so there is nothing solitary to find.
    #[test]
    fn ladder_rounds_carry_no_solitary_constant() {
        let rounds: Vec<Transaction> = (0..6u8)
            .map(|i| {
                // Coordinator settles an accrued rung on the third round only —
                // accrual means it is not every round, and when it happens it
                // looks like any other output.
                let coord = if i == 2 {
                    vec![LadderOutput {
                        address: addr(0xFE),
                        value_sats: 20_000,
                    }]
                } else {
                    vec![]
                };
                let mut b = balanced_builder(3 + u64::from(i) * 4, coord);
                absorb_surplus(&mut b);
                b.build(&[i; 32]).expect("balances").tx
            })
            .collect();

        let violations = probe_value_constancy(&rounds);
        assert!(
            violations.is_empty(),
            "a ladder round should leave no solitary constant to grep: {violations:?}"
        );
    }

    #[test]
    fn a_ladder_round_survives_the_privacy_probes() {
        let mut b = balanced_builder(5, vec![]);
        absorb_surplus(&mut b);
        let round = b.build(&[0x11; 32]).unwrap();
        // No shape supplied: there is no single denomination, which is the point.
        assert!(probe_round(&round.tx, None).is_empty());
    }

    #[test]
    fn input_and_output_permutations_are_independent() {
        let b = balanced_builder(5, vec![]);
        let e = [0x11; 32];
        assert_ne!(
            b.seed(b"WraithLadder/v1/input_shuffle", &e),
            b.seed(b"WraithLadder/v1/output_shuffle", &e),
            "sharing a seed would correlate input i with output i"
        );
    }
}
