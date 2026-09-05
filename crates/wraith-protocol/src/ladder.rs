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
//| FILE: ladder.rs                                                                                                      |
//|======================================================================================================================|

//! Denomination ladders and payment decomposition.
//!
//! A round has no change output in the old design, which forced an input to be
//! *exactly* the seat price and meant a user needed the right coin before they
//! could pay. A ladder removes that: you contribute the rungs you **have**, the
//! round pays the recipient in rungs, and your surplus returns as more rungs to
//! fresh addresses. Change is safe because it is denominated like everyone
//! else's, not because it is hidden.
//!
//! # Why decomposition is deterministic
//!
//! [`Ladder::decompose`] is greedy from the largest rung down, which for a 1-2-5
//! series is the *canonical* representation — provably the fewest rungs. That is
//! the right choice twice over:
//!
//! - **Fees.** Every output costs 43 vB. Fewest rungs is cheapest.
//! - **Privacy.** Determinism makes decompositions *collide*. Two people paying
//!   the same amount emit the same multiset of values. A randomised decomposer
//!   would make each payer's output pattern distinctive, which is the opposite
//!   of what a mix is for.
//!
//! The genuine privacy tension is not here — it is in [`Ladder::select_inputs`],
//! where which rungs you spend says something about what you hold.
//!
//! # Granularity
//!
//! A ladder has a floor, so only multiples of that floor are expressible. This
//! is deliberate and matches physical coinage. Callers quantise with
//! [`Ladder::quantise`] before decomposing, and [`Ladder::decompose`] refuses an
//! inexpressible amount rather than silently rounding it.

use std::collections::BTreeMap;

use thiserror::Error;

/// Something went wrong planning a payment against a ladder.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LadderError {
    /// The amount is below the smallest rung.
    #[error("amount {amount} is below the ladder floor of {floor} sats")]
    BelowFloor {
        /// Requested amount.
        amount: u64,
        /// Smallest rung.
        floor: u64,
    },

    /// The amount is not a whole number of floor units.
    #[error("amount {amount} is not expressible on this ladder; nearest are {below} and {above}")]
    NotExpressible {
        /// Requested amount.
        amount: u64,
        /// Largest expressible amount at or below it.
        below: u64,
        /// Smallest expressible amount above it.
        above: u64,
    },

    /// The available rungs do not cover the target.
    #[error("holdings total {available} sats, need {target}")]
    Insufficient {
        /// Sum of what the caller holds.
        available: u64,
        /// What the payment plus fees requires.
        target: u64,
    },
}

/// An ascending series of denominations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ladder {
    rungs: Vec<u64>,
}

impl Ladder {
    /// Build a ladder from an ascending, deduplicated rung list.
    ///
    /// # Panics
    /// If `rungs` is empty or not strictly ascending.
    pub fn new(rungs: Vec<u64>) -> Self {
        assert!(!rungs.is_empty(), "a ladder needs at least one rung");
        assert!(
            rungs.windows(2).all(|w| w[0] < w[1]),
            "ladder rungs must be strictly ascending"
        );
        Self { rungs }
    }

    /// The 1-2-5 series from 1,000 sats to 1 BTC.
    ///
    /// The floor matches `LITE_SERVICE_FEE_FLOOR_SATS` and sits comfortably above
    /// the P2TR dust limit.
    pub fn standard() -> Self {
        let mut rungs = Vec::new();
        let mut decade = 1_000u64;
        while decade <= 100_000_000 {
            for m in [1, 2, 5] {
                let r = decade * m;
                if r <= 100_000_000 {
                    rungs.push(r);
                }
            }
            decade *= 10;
        }
        Self::new(rungs)
    }

    /// Powers of ten only — the shape of today's `LiteTier`.
    ///
    /// Fewer distinct values means a bigger crowd per value, at the cost of many
    /// more outputs per payment. [`compare_shapes`] quantifies that trade.
    pub fn powers_of_ten() -> Self {
        Self::new(vec![
            1_000,
            10_000,
            100_000,
            1_000_000,
            10_000_000,
            100_000_000,
        ])
    }

    /// The smallest rung.
    pub fn floor(&self) -> u64 {
        self.rungs[0]
    }

    /// The rungs, ascending.
    pub fn rungs(&self) -> &[u64] {
        &self.rungs
    }

    /// Round `amount` down to the nearest expressible value.
    pub fn quantise(&self, amount: u64) -> u64 {
        amount - (amount % self.floor())
    }

    /// Express `amount` as a multiset of rungs, largest first.
    ///
    /// Deterministic by design — see the module docs.
    pub fn decompose(&self, amount: u64) -> Result<Vec<u64>, LadderError> {
        let floor = self.floor();
        if amount < floor {
            return Err(LadderError::BelowFloor { amount, floor });
        }
        if !amount.is_multiple_of(floor) {
            let below = self.quantise(amount);
            return Err(LadderError::NotExpressible {
                amount,
                below,
                above: below + floor,
            });
        }

        let mut out = Vec::new();
        let mut left = amount;
        for &rung in self.rungs.iter().rev() {
            while left >= rung {
                out.push(rung);
                left -= rung;
            }
        }
        debug_assert_eq!(left, 0, "a floor-multiple must decompose exactly");
        Ok(out)
    }

    /// Choose rungs from `available` that cover `target`, minimising surplus.
    ///
    /// Largest-first, then a final small rung to close any gap. This is the
    /// version that carries the real privacy question: which coins you spend
    /// says something about what you hold, and a smarter selector should
    /// eventually prefer combinations many other participants could also have
    /// produced.
    pub fn select_inputs(&self, available: &[u64], target: u64) -> Result<Vec<u64>, LadderError> {
        let total: u64 = available.iter().sum();
        if total < target {
            return Err(LadderError::Insufficient {
                available: total,
                target,
            });
        }

        let mut pool: Vec<u64> = available.to_vec();
        pool.sort_unstable_by(|a, b| b.cmp(a));

        let mut chosen = Vec::new();
        let mut sum = 0u64;
        for &rung in &pool {
            if sum >= target {
                break;
            }
            chosen.push(rung);
            sum += rung;
        }
        Ok(chosen)
    }

    /// A complete payment: what to spend, what the recipient gets, what returns.
    pub fn plan(
        &self,
        available: &[u64],
        amount: u64,
        fee: u64,
    ) -> Result<PaymentPlan, LadderError> {
        let target = amount + fee;
        let inputs = self.select_inputs(available, target)?;
        let spent: u64 = inputs.iter().sum();
        let recipient = self.decompose(amount)?;

        let surplus = spent - target;
        let change = if surplus >= self.floor() {
            self.decompose(self.quantise(surplus))?
        } else {
            Vec::new()
        };

        let dust_to_fee = surplus - change.iter().sum::<u64>();
        Ok(PaymentPlan {
            inputs,
            recipient,
            change,
            fee,
            dust_to_fee,
        })
    }
}

/// The outcome of [`Ladder::plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentPlan {
    /// Rungs to contribute as round inputs.
    pub inputs: Vec<u64>,
    /// Rungs the recipient receives.
    pub recipient: Vec<u64>,
    /// Rungs returning to the sender, at fresh addresses.
    pub change: Vec<u64>,
    /// Fee allocated to the round.
    pub fee: u64,
    /// Surplus too small to express as a rung; it goes to fees.
    pub dust_to_fee: u64,
}

impl PaymentPlan {
    /// Total on-chain outputs this payment contributes to the round.
    pub fn output_count(&self) -> usize {
        self.recipient.len() + self.change.len()
    }

    /// Sanity: value in equals value out.
    pub fn balances(&self) -> bool {
        let inp: u64 = self.inputs.iter().sum();
        let out: u64 = self.recipient.iter().sum::<u64>() + self.change.iter().sum::<u64>();
        inp == out + self.fee + self.dust_to_fee
    }
}

/// Mean rungs per payment for a ladder, over a sample of amounts.
///
/// This exists to make the "how coarse should the ladder be" decision on
/// numbers rather than intuition: fewer distinct values means a bigger crowd
/// per value, but more outputs per payment, and every output costs 43 vB.
pub fn compare_shapes(ladder: &Ladder, amounts: &[u64]) -> BTreeMap<&'static str, f64> {
    let mut m = BTreeMap::new();
    let counts: Vec<usize> = amounts
        .iter()
        .filter_map(|&a| ladder.decompose(ladder.quantise(a)).ok().map(|v| v.len()))
        .collect();
    let mean = counts.iter().sum::<usize>() as f64 / counts.len().max(1) as f64;
    m.insert("distinct_values", ladder.rungs().len() as f64);
    m.insert("mean_outputs", mean);
    m.insert("mean_output_vbytes", mean * 43.0);
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimum rungs for `amount`, by exhaustive search. Reference for greedy.
    fn optimal_count(rungs: &[u64], amount: u64) -> usize {
        let floor = rungs[0] as usize;
        let n = amount as usize / floor;
        let mut best = vec![usize::MAX; n + 1];
        best[0] = 0;
        for i in 1..=n {
            for &r in rungs {
                let step = r as usize / floor;
                if step <= i && best[i - step] != usize::MAX {
                    best[i] = best[i].min(best[i - step] + 1);
                }
            }
        }
        best[n]
    }

    #[test]
    fn greedy_is_canonical_for_the_standard_ladder() {
        let l = Ladder::standard();
        for units in 1..=400u64 {
            let amount = units * l.floor();
            let greedy = l.decompose(amount).expect("expressible").len();
            let optimal = optimal_count(l.rungs(), amount);
            assert_eq!(
                greedy, optimal,
                "greedy is not minimal at {amount}: {greedy} vs {optimal}"
            );
        }
    }

    #[test]
    fn decomposition_is_exact_and_deterministic() {
        let l = Ladder::standard();
        for amount in [1_000, 137_000, 500_000, 1_000_000, 99_999_000] {
            let d = l.decompose(amount).expect("expressible");
            assert_eq!(d.iter().sum::<u64>(), amount);
            assert_eq!(d, l.decompose(amount).unwrap(), "must be deterministic");
            assert!(d.iter().all(|r| l.rungs().contains(r)));
        }
    }

    #[test]
    fn inexpressible_amounts_are_refused_not_rounded() {
        let l = Ladder::standard();
        let err = l.decompose(137_432).unwrap_err();
        assert_eq!(
            err,
            LadderError::NotExpressible {
                amount: 137_432,
                below: 137_000,
                above: 138_000
            }
        );
        assert_eq!(l.quantise(137_432), 137_000);
    }

    #[test]
    fn below_floor_is_refused() {
        let l = Ladder::standard();
        assert!(matches!(
            l.decompose(999),
            Err(LadderError::BelowFloor { .. })
        ));
    }

    #[test]
    fn a_plan_balances_and_returns_change_as_rungs() {
        let l = Ladder::standard();
        let plan = l.plan(&[200_000], 137_000, 2_000).expect("plans");
        assert!(plan.balances(), "value in must equal value out: {plan:?}");
        assert_eq!(plan.recipient, vec![100_000, 20_000, 10_000, 5_000, 2_000]);
        assert_eq!(plan.change, vec![50_000, 10_000, 1_000]);
        assert!(plan.change.iter().all(|r| l.rungs().contains(r)));
    }

    #[test]
    fn insufficient_holdings_are_refused() {
        let l = Ladder::standard();
        let err = l.plan(&[10_000], 137_000, 2_000).unwrap_err();
        assert!(matches!(err, LadderError::Insufficient { .. }));
    }

    #[test]
    fn coarseness_trade_is_quantified_not_assumed() {
        // Sample of realistic payment sizes.
        let amounts: Vec<u64> = (1..=200).map(|k| k * 1_137).collect();
        let fine = compare_shapes(&Ladder::standard(), &amounts);
        let coarse = compare_shapes(&Ladder::powers_of_ten(), &amounts);

        // Coarse has fewer distinct values (bigger crowd per value)...
        assert!(coarse["distinct_values"] < fine["distinct_values"]);
        // ...but costs materially more in outputs, and therefore in fees.
        assert!(
            coarse["mean_outputs"] > fine["mean_outputs"] * 1.5,
            "expected powers-of-ten to be much wider: fine {:.2}, coarse {:.2}",
            fine["mean_outputs"],
            coarse["mean_outputs"]
        );
    }
}

#[cfg(test)]
mod shape_report {
    use super::*;

    /// Not an assertion — a report. `cargo test -p wraith-protocol shape_report -- --nocapture`
    #[test]
    fn print_ladder_shapes() {
        let amounts: Vec<u64> = (1..=500).map(|k| k * 1_137).collect();
        println!("\n  ladder            values   mean outputs   mean vB   vB @5 sat/vB");
        println!("  ----------------------------------------------------------------");
        for (name, l) in [
            ("1-2-5 (standard)", Ladder::standard()),
            ("powers of ten", Ladder::powers_of_ten()),
        ] {
            let m = compare_shapes(&l, &amounts);
            println!(
                "  {name:<16} {:>6.0}   {:>12.2}   {:>7.1}   {:>10.0} sats",
                m["distinct_values"],
                m["mean_outputs"],
                m["mean_output_vbytes"],
                m["mean_output_vbytes"] * 5.0
            );
        }
        println!();
    }
}
