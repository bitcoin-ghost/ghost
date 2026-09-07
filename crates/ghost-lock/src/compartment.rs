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
//| FILE: compartment.rs                                                                                                |
//|======================================================================================================================|

//! The one-way rule between the private lanes and Cash.
//!
//! Cash exists so small public spends do not drive the user to a second wallet
//! they would fund from here. That only holds if the compartment is real, and a
//! compartment maintained by documentation is not real.
//!
//! # The two rules
//!
//! 1. **A Cash coin never enters a round.** It is already public. Mixing it
//!    re-links whatever it touches, and it contributes nothing — a coin an
//!    observer can already follow is not cover.
//! 2. **A round output never merges with a Cash coin.** Spending them together
//!    is the common-input heuristic applied to your own wallet: it says the
//!    mixed coin and the public coin have one owner, which is the whole thing
//!    the round bought.
//!
//! # Flow is one-way, and that is enough
//!
//! ```text
//! Savings ──► round ──► Cash ──► merchant
//!                        │
//!                        ✗ never back
//! ```
//!
//! Funding Cash *through* a round is clean: the coin arrives with no history
//! linking it to Savings, and spending it publicly afterwards reveals only what
//! the user chose to reveal. Each hop is fine; it is the reverse hop that is not.

use crate::error::LockError;

/// Which compartment a coin belongs to.
///
/// Assigned when the coin arrives and never inferred later — a coin whose
/// compartment has to be guessed at spend time has already been mishandled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compartment {
    /// Savings, Spending or Investments. Round-eligible.
    Private,
    /// Cash. Public, and permanently barred from rounds.
    Cash,
}

/// Why a spend or registration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompartmentError {
    /// A Cash coin was offered to a round.
    #[error("a Cash coin cannot enter a round: it is already public, so it gains nothing and re-links whatever it is mixed with")]
    CashIntoRound,
    /// A round was asked to pay out into Cash.
    #[error("a round cannot pay out into Cash: the lane is public by design, so the unlinkability the round just bought is discarded the moment the coin lands")]
    CashAsRoundDestination,
    /// A spend mixed compartments.
    #[error("this spend combines {private} private and {cash} Cash inputs; spending them together proves they share an owner and undoes the round")]
    MixedSpend {
        /// Private inputs in the spend.
        private: usize,
        /// Cash inputs in the spend.
        cash: usize,
    },
}

impl From<CompartmentError> for LockError {
    fn from(e: CompartmentError) -> Self {
        LockError::Policy(e.to_string())
    }
}

/// Rule 1 — may this coin be registered into a round?
pub fn check_round_eligible(c: Compartment) -> Result<(), CompartmentError> {
    match c {
        Compartment::Private => Ok(()),
        Compartment::Cash => Err(CompartmentError::CashIntoRound),
    }
}

/// Rule 2 — may a round pay OUT to this compartment?
///
/// Deliberately separate from [`check_round_eligible`], which is about a coin
/// being registered as a round INPUT. The two look alike and are not: rule 1
/// refuses Cash because mixing an already-public coin re-links the strangers it
/// is mixed with, which is other people's problem. This rule refuses Cash
/// because the round's whole product — an output nobody can link to its source
/// — is thrown away by a lane that is public on purpose, which is only the
/// owner's problem. Collapsing them into one predicate would make the next
/// change to either silently apply to both.
pub fn check_round_destination(c: Compartment) -> Result<(), CompartmentError> {
    match c {
        Compartment::Private => Ok(()),
        Compartment::Cash => Err(CompartmentError::CashAsRoundDestination),
    }
}

/// Rule 3 — may these coins be spent in one transaction?
///
/// Takes the whole input set rather than a pair, because the violation is a
/// property of the transaction: two calls that each pass can still build a
/// transaction that does not.
pub fn check_spend_together(inputs: &[Compartment]) -> Result<(), CompartmentError> {
    let cash = inputs.iter().filter(|c| **c == Compartment::Cash).count();
    let private = inputs.len() - cash;
    if cash > 0 && private > 0 {
        return Err(CompartmentError::MixedSpend { private, cash });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use Compartment::{Cash, Private};

    #[test]
    fn a_cash_coin_cannot_enter_a_round() {
        assert_eq!(
            check_round_eligible(Cash),
            Err(CompartmentError::CashIntoRound)
        );
        assert!(check_round_eligible(Private).is_ok());
    }

    #[test]
    fn a_round_may_not_pay_out_into_cash() {
        assert_eq!(
            check_round_destination(Cash),
            Err(CompartmentError::CashAsRoundDestination)
        );
        assert!(check_round_destination(Private).is_ok());
    }

    /// The two round rules are separate rules that happen to agree today. This
    /// pins the distinction: they must not be refactored into one predicate,
    /// because they refuse Cash for different reasons and carry different
    /// errors.
    #[test]
    fn the_two_round_rules_are_not_the_same_rule() {
        assert_ne!(
            check_round_eligible(Cash).unwrap_err(),
            check_round_destination(Cash).unwrap_err(),
        );
    }

    #[test]
    fn a_spend_may_not_combine_the_compartments() {
        // The common-input heuristic applied to your own wallet: this says the
        // mixed coin and the public coin have one owner.
        assert_eq!(
            check_spend_together(&[Private, Cash]),
            Err(CompartmentError::MixedSpend {
                private: 1,
                cash: 1
            })
        );
    }

    #[test]
    fn spending_within_one_compartment_is_fine() {
        assert!(check_spend_together(&[Private, Private, Private]).is_ok());
        assert!(check_spend_together(&[Cash, Cash]).is_ok());
        assert!(check_spend_together(&[]).is_ok());
    }

    #[test]
    fn the_check_reads_the_whole_input_set_not_a_pair() {
        // Pairwise checking passes here and the transaction is still a
        // violation, so the rule has to be a property of the set.
        let inputs = [Private, Private, Cash];
        let e = check_spend_together(&inputs).expect_err("must refuse");
        assert_eq!(
            e,
            CompartmentError::MixedSpend {
                private: 2,
                cash: 1
            }
        );
    }

    #[test]
    fn the_error_says_what_it_costs_not_just_that_it_refused() {
        // A user overriding a rule they do not understand is the failure this
        // is guarding against, so the message has to carry the reason.
        let msg = CompartmentError::CashIntoRound.to_string();
        assert!(msg.contains("already public"), "{msg}");
        let msg = CompartmentError::MixedSpend {
            private: 1,
            cash: 1,
        }
        .to_string();
        assert!(msg.contains("share an owner"), "{msg}");
    }
}
