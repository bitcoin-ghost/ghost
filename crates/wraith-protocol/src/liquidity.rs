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
//| FILE: liquidity.rs                                                                                                  |
//|======================================================================================================================|

//! The liquidity lane — instant-and-private, and the two invariants it rests on.
//!
//! Instant *alone* is free: a signed handoff, an ordinary transaction, no
//! provider needed. Instant **and private** always needs someone to front,
//! because a round is still a transaction that confirms in ten minutes and no
//! cadence fixes that. That is the business, and it is permanent.
//!
//! Two things here are code rather than documentation, because both are claims
//! that quietly become false:
//!
//! # 1. The bond is the size of the tier
//!
//! Total liquidity-lane deposits must never exceed aggregate bond. Past that
//! point the guarantee is theatre — there is not enough staked to make good on
//! what has been promised, and every depositor believes otherwise. [`BondCeiling`]
//! refuses the deposit that would cross it rather than logging a warning.
//!
//! # 2. The spread must be ladder-quantised
//!
//! A payer contributes `amount + spread` in rungs. If the spread is not itself
//! expressible on the ladder, decomposition breaks and the payer cannot fund the
//! round at all.
//!
//! It must also be **priced by tier, not by percentage**. A proportional fee is
//! a function of the exact amount, so publishing it publishes the amount — the
//! same leak as the pinned seat price, arriving through the pricing model
//! instead of a constant. Keying it to the largest rung reveals only the tier,
//! which the ladder already reveals anyway.

use crate::ladder::{Ladder, LadderError};

/// Why a liquidity operation was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LiquidityError {
    /// The deposit would push total deposits past aggregate bond.
    #[error("deposit of {amount} would take deposits to {would_be} against a bond of {bond} — the guarantee would be unbacked")]
    ExceedsBond {
        /// Requested deposit.
        amount: u64,
        /// Where deposits would land.
        would_be: u64,
        /// Aggregate bond posted.
        bond: u64,
    },

    /// The amount is not expressible on the ladder.
    #[error("payment amount is not expressible on this ladder")]
    InexpressibleAmount,
}

/// Tracks liquidity-lane deposits against the bond backing them.
///
/// Not a privacy control — a solvency one. It exists so the sentence "backed by
/// a bond" stays true as the pool grows.
#[derive(Debug, Clone)]
pub struct BondCeiling {
    bond_sats: u64,
    deposits_sats: u64,
    alarm_at: f64,
    refusals: u64,
}

impl BondCeiling {
    /// `alarm_at` is the utilisation fraction above which operators should be
    /// told to post more bond — well before the hard refusal.
    pub fn new(bond_sats: u64, alarm_at: f64) -> Self {
        Self {
            bond_sats,
            deposits_sats: 0,
            alarm_at,
            refusals: 0,
        }
    }

    /// Accept a deposit, or refuse it because the bond cannot back it.
    pub fn try_deposit(&mut self, amount: u64) -> Result<(), LiquidityError> {
        let would_be = self.deposits_sats.saturating_add(amount);
        if would_be > self.bond_sats {
            self.refusals += 1;
            return Err(LiquidityError::ExceedsBond {
                amount,
                would_be,
                bond: self.bond_sats,
            });
        }
        self.deposits_sats = would_be;
        Ok(())
    }

    /// Return a deposit to its owner.
    pub fn withdraw(&mut self, amount: u64) {
        self.deposits_sats = self.deposits_sats.saturating_sub(amount);
    }

    /// Raise or lower the posted bond.
    ///
    /// Lowering below current deposits is permitted — a bond can be slashed or
    /// expire, and pretending otherwise would hide the state that matters most.
    /// [`Self::is_solvent`] is then false and stays false until it is restored.
    pub fn set_bond(&mut self, bond_sats: u64) {
        self.bond_sats = bond_sats;
    }

    /// Deposits as a fraction of bond. May exceed 1.0 after a slash.
    pub fn utilisation(&self) -> f64 {
        if self.bond_sats == 0 {
            return if self.deposits_sats == 0 {
                0.0
            } else {
                f64::INFINITY
            };
        }
        self.deposits_sats as f64 / self.bond_sats as f64
    }

    /// Whether every deposit is currently backed.
    pub fn is_solvent(&self) -> bool {
        self.deposits_sats <= self.bond_sats
    }

    /// Whether operators should be asked for more bond.
    pub fn should_alarm(&self) -> bool {
        self.utilisation() >= self.alarm_at
    }

    /// Deposit headroom remaining.
    pub fn headroom(&self) -> u64 {
        self.bond_sats.saturating_sub(self.deposits_sats)
    }

    /// Current deposits.
    pub fn deposits(&self) -> u64 {
        self.deposits_sats
    }

    /// How many deposits were turned away for want of bond.
    ///
    /// *A check whose failure produces no observable output is not a check.*
    /// A rising count means the pool is demand-constrained and operators should
    /// be posting more.
    pub fn refusals(&self) -> u64 {
        self.refusals
    }
}

/// The standing spread for a payment, in satoshis.
///
/// Keyed to the **largest rung** in the payment rather than the amount, and
/// quantised onto the ladder. Two different amounts that decompose to the same
/// largest rung cost the same, which is what stops the price revealing the
/// payment.
///
/// Roughly 1% of the largest rung, rounded up to a rung, floored at the ladder
/// floor.
pub fn standing_spread(ladder: &Ladder, amount_sats: u64) -> Result<u64, LiquidityError> {
    let rungs = ladder
        .decompose(amount_sats)
        .map_err(|_| LiquidityError::InexpressibleAmount)?;
    let largest = rungs.first().copied().unwrap_or(ladder.floor());
    let target = largest / 100;
    Ok(ladder
        .rungs()
        .iter()
        .copied()
        .find(|r| *r >= target)
        .unwrap_or(ladder.floor())
        .max(ladder.floor()))
}

/// Total a payer must contribute: the payment plus its spread.
pub fn total_with_spread(ladder: &Ladder, amount_sats: u64) -> Result<u64, LadderError> {
    let spread = standing_spread(ladder, amount_sats).map_err(|_| LadderError::BelowFloor {
        amount: amount_sats,
        floor: ladder.floor(),
    })?;
    amount_sats
        .checked_add(spread)
        .ok_or(LadderError::Overflow {
            amount: amount_sats,
            addend: spread,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceiling() -> BondCeiling {
        BondCeiling::new(10_000_000, 0.8)
    }

    #[test]
    fn deposits_within_the_bond_are_accepted() {
        let mut c = ceiling();
        assert!(c.try_deposit(4_000_000).is_ok());
        assert!(c.try_deposit(6_000_000).is_ok());
        assert_eq!(c.headroom(), 0);
        assert!(c.is_solvent());
    }

    #[test]
    fn the_deposit_that_would_break_the_guarantee_is_refused() {
        let mut c = ceiling();
        c.try_deposit(9_000_000).unwrap();
        assert_eq!(
            c.try_deposit(2_000_000),
            Err(LiquidityError::ExceedsBond {
                amount: 2_000_000,
                would_be: 11_000_000,
                bond: 10_000_000
            })
        );
        assert_eq!(c.refusals(), 1, "the refusal must be observable");
        assert_eq!(c.deposits(), 9_000_000, "a refused deposit changes nothing");
        assert!(c.is_solvent());
    }

    #[test]
    fn the_alarm_fires_before_the_refusal() {
        // Operators need warning while there is still headroom to act on.
        let mut c = ceiling();
        c.try_deposit(7_000_000).unwrap();
        assert!(!c.should_alarm());
        c.try_deposit(1_500_000).unwrap();
        assert!(c.should_alarm(), "85% utilisation should be alarming");
        assert!(
            c.headroom() > 0,
            "and there is still room to post more bond"
        );
    }

    #[test]
    fn a_slashed_bond_shows_as_insolvent_rather_than_being_hidden() {
        // The state that matters most is the one it would be most tempting to
        // paper over.
        let mut c = ceiling();
        c.try_deposit(9_000_000).unwrap();
        assert!(c.is_solvent());
        c.set_bond(5_000_000);
        assert!(!c.is_solvent(), "deposits now exceed bond and must say so");
        assert!(c.utilisation() > 1.0);
        assert_eq!(c.headroom(), 0);
        // And no further deposits are accepted while unbacked.
        assert!(c.try_deposit(1).is_err());
    }

    #[test]
    fn the_spread_reveals_the_tier_and_not_the_amount() {
        let l = Ladder::standard();
        // Three payments that differ, but share a largest rung.
        let a = standing_spread(&l, 100_000).unwrap();
        let b = standing_spread(&l, 137_000).unwrap();
        let c = standing_spread(&l, 199_000).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            b, c,
            "a proportional spread would have leaked the amount here"
        );
    }

    #[test]
    fn the_spread_scales_with_the_tier() {
        let l = Ladder::standard();
        let small = standing_spread(&l, 100_000).unwrap();
        let large = standing_spread(&l, 10_000_000).unwrap();
        assert!(
            large > small,
            "a whale payment must not cost a coffee's spread"
        );
    }

    #[test]
    fn the_spread_is_always_a_rung() {
        let l = Ladder::standard();
        for amount in [1_000, 5_000, 100_000, 137_000, 1_000_000, 50_000_000] {
            let s = standing_spread(&l, amount).unwrap();
            assert!(
                l.rungs().contains(&s),
                "spread {s} for {amount} is not a rung — decomposition would break"
            );
        }
    }

    #[test]
    fn a_payment_plus_its_spread_still_decomposes() {
        // The property the quantisation exists for: the payer can actually fund
        // what they were quoted.
        let l = Ladder::standard();
        for amount in [100_000, 137_000, 1_000_000, 10_000_000] {
            let total = total_with_spread(&l, amount).expect("quotes");
            assert!(
                l.decompose(total).is_ok(),
                "amount {amount} plus spread does not decompose"
            );
        }
    }
}
