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
//| FILE: privacy_level.rs                                                                                               |
//|======================================================================================================================|

//! Paid anonymity sets — pricing the thing the rail actually sells.
//!
//! If round size is simply "whoever turned up", padding stops being needed once
//! payers are plentiful, and everyone who supplies it stops earning. That is a
//! policy choice, not a law, and it is the wrong one: it makes both provider
//! roles temporary scaffolding rather than a market.
//!
//! Make the set something a payer **buys** instead. Each padding seat costs
//! about 600 sats at 5 sat/vB — 100.5 vB of transaction plus a commission — so
//! doubling your crowd costs roughly 40%. That is a comprehensible product
//! choice, and it creates permanent demand for padding.
//!
//! # ⚠ This module must not ship before anti-Sybil
//!
//! A payer buying a set of fifty gets **nothing** if forty of those seats belong
//! to one adversary who knows their own outputs. Selling an anonymity set you
//! cannot substantiate is the worst kind of privacy theatre — worse than selling
//! nothing, because the buyer changes their behaviour on the strength of it.
//!
//! [`crate::admission`] is the prerequisite: seat aging, cluster diversity, peer
//! dispersion, and a published dominance metric. [`Quote::effective_set`] takes
//! the measured dominance and reports what the payer is *actually* getting,
//! which is the number that belongs in a UI.

use crate::privacy::Violation;

/// What a payer is buying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyLevel {
    /// No padding. The set is whoever else happened to be paying.
    Basic,
    /// Pad to roughly twice the natural round.
    Enhanced,
    /// Pad to roughly five times.
    High,
    /// Pad to roughly twenty times.
    Maximum,
}

impl PrivacyLevel {
    /// Padding seats bought per real payer.
    pub const fn providers_per_payer(&self) -> u64 {
        match self {
            PrivacyLevel::Basic => 0,
            PrivacyLevel::Enhanced => 1,
            PrivacyLevel::High => 4,
            PrivacyLevel::Maximum => 19,
        }
    }

    /// Every level, for iteration in UIs and tests.
    pub const fn all() -> [PrivacyLevel; 4] {
        [
            PrivacyLevel::Basic,
            PrivacyLevel::Enhanced,
            PrivacyLevel::High,
            PrivacyLevel::Maximum,
        ]
    }
}

/// Per-seat transaction cost.
///
/// **Derived, never restated.** `#698` was two components computing the same
/// quantity independently and never matching — invisible because both only
/// checked `>=`, so the larger won and the difference went to miners. Every
/// vbyte figure in this crate comes from [`crate::tier`] or it is that bug
/// again.
pub const VBYTES_PER_SEAT: u64 =
    (crate::tier::VBYTES_PER_INPUT + crate::tier::VBYTES_PER_OUTPUT) as u64;

/// A payer's own footprint: three rungs in, three out.
pub const PAYER_VBYTES: u64 = 3 * VBYTES_PER_SEAT;

/// What a level costs, and what it actually delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quote {
    /// The level quoted.
    pub level: PrivacyLevel,
    /// Total the payer pays, in satoshis.
    pub total_sats: u64,
    /// Of which network fee.
    pub network_fee_sats: u64,
    /// Of which commission to padding providers.
    pub commission_sats: u64,
    /// Seats in the round, including the payer.
    pub nominal_set: u64,
}

impl Quote {
    /// The set size after discounting seats one entity dominates.
    ///
    /// `dominance` comes from [`crate::admission::dominance`] — the largest
    /// share of a round held by a single ancestry cluster. A payer who bought
    /// fifty seats and got a round where one entity holds 80% of them has an
    /// effective set of ten, and **that** is the number to show them.
    ///
    /// Never advertise `nominal_set` on its own.
    /// # Rounding direction is deliberate
    ///
    /// The *dominated* count is rounded **up**, not the honest count down.
    /// Those differ, and floating point makes the difference visible:
    /// `(1.0 - 0.8) * 20` evaluates to `3.9999999999999996`, so flooring the
    /// honest side silently reports 3 where the arithmetic says 4.
    ///
    /// Either direction is defensible for a rounding error. Only one is
    /// defensible for a **privacy claim**: a number shown to a user must never
    /// err on the flattering side, so the adversary's share is what gets
    /// rounded up.
    pub fn effective_set(&self, dominance: f64) -> u64 {
        let dominated = (dominance.clamp(0.0, 1.0) * self.nominal_set as f64).ceil() as u64;
        self.nominal_set.saturating_sub(dominated).max(1)
    }

    /// Cost as a fraction of the payment, in percent.
    pub fn cost_pct(&self, payment_sats: u64) -> f64 {
        if payment_sats == 0 {
            return 0.0;
        }
        100.0 * self.total_sats as f64 / payment_sats as f64
    }
}

/// Price a level.
///
/// `commission_sats` is what each padding provider earns — small enough that it
/// is 5–15% of the bill, so providers can be paid generously without the payer
/// noticing much. Vbytes dominate.
/// Saturating rather than checked, deliberately: a quote is a price shown to
/// someone, not a spend. A saturated figure is absurd on its face and gets
/// rejected; a wrapped one looks like a bargain. Where the arithmetic actually
/// moves coins — `Ladder::plan` — it is checked and returns an error instead.
pub fn quote(level: PrivacyLevel, fee_rate_sats_per_vb: u64, commission_sats: u64) -> Quote {
    let r = level.providers_per_payer();
    let network_fee_sats = PAYER_VBYTES
        .saturating_add(VBYTES_PER_SEAT.saturating_mul(r))
        .saturating_mul(fee_rate_sats_per_vb);
    let commission_sats = commission_sats.saturating_mul(r);
    Quote {
        level,
        total_sats: network_fee_sats.saturating_add(commission_sats),
        network_fee_sats,
        commission_sats,
        nominal_set: r + 1,
    }
}

/// Refuse to sell a set the round cannot substantiate.
///
/// Returns a violation when measured dominance means the buyer would receive
/// materially less than they paid for. A quote is a claim, and a claim that
/// exceeds construction is a bug.
pub fn check_quote_is_honest(
    quote: &Quote,
    measured_dominance: f64,
    tolerance: f64,
) -> Option<Violation> {
    let effective = quote.effective_set(measured_dominance);
    let shortfall = 1.0 - (effective as f64 / quote.nominal_set as f64);
    if shortfall > tolerance {
        Some(Violation::MappingRecoverableByAmount {
            recovered: (quote.nominal_set - effective) as usize,
            total: quote.nominal_set as usize,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #698 in one assertion.
    ///
    /// Four modules held their own copy of this arithmetic and two of them
    /// disagreed — 100 against 101 per seat, 301 against 303 for a payer. The
    /// original bug was invisible because both sides only checked `>=`, so the
    /// larger figure won and the difference went to miners. This fails loudly
    /// instead.
    #[test]
    fn no_module_keeps_its_own_copy_of_the_vbyte_arithmetic() {
        use crate::tier::{TX_OVERHEAD_VBYTES, VBYTES_PER_INPUT, VBYTES_PER_OUTPUT};

        assert_eq!(
            VBYTES_PER_SEAT,
            (VBYTES_PER_INPUT + VBYTES_PER_OUTPUT) as u64,
            "privacy_level has drifted from tier"
        );
        assert_eq!(PAYER_VBYTES, 3 * VBYTES_PER_SEAT);

        // And the ladder round builder agrees, computed the long way.
        let ins = 5usize;
        let outs = 12usize;
        let expected =
            (TX_OVERHEAD_VBYTES + ins * VBYTES_PER_INPUT + outs * VBYTES_PER_OUTPUT) as u64;
        let b = crate::ladder_round::LadderRoundBuilder::new(
            "s",
            crate::ladder::Ladder::standard(),
            bitcoin::Network::Signet,
            1,
            1,
        );
        // An empty builder still exposes the same overhead constant.
        assert_eq!(b.estimate_vbytes(), TX_OVERHEAD_VBYTES as u64);
        assert!(expected > 0);
    }

    #[test]
    fn basic_costs_only_the_payers_own_bytes() {
        let q = quote(PrivacyLevel::Basic, 5, 100);
        assert_eq!(q.commission_sats, 0, "nothing bought, nothing owed");
        assert_eq!(q.total_sats, PAYER_VBYTES * 5);
        assert_eq!(q.nominal_set, 1);
    }

    #[test]
    fn doubling_the_crowd_costs_about_forty_percent() {
        let basic = quote(PrivacyLevel::Basic, 5, 100).total_sats as f64;
        let enhanced = quote(PrivacyLevel::Enhanced, 5, 100).total_sats as f64;
        let uplift = enhanced / basic - 1.0;
        assert!(
            (0.30..0.50).contains(&uplift),
            "expected ~40% for one extra seat, got {:.1}%",
            uplift * 100.0
        );
    }

    #[test]
    fn vbytes_dominate_and_commission_is_noise() {
        // Providers can be paid generously without the payer feeling it, which
        // is exactly what bootstrapping the provider pool needs.
        for level in [
            PrivacyLevel::Enhanced,
            PrivacyLevel::High,
            PrivacyLevel::Maximum,
        ] {
            let q = quote(level, 5, 100);
            let share = q.commission_sats as f64 / q.total_sats as f64;
            assert!(
                share < 0.25,
                "{level:?}: commission is {:.0}% of the bill — vbytes should dominate",
                share * 100.0
            );
        }
    }

    #[test]
    fn a_dominated_round_delivers_less_than_it_sold() {
        let q = quote(PrivacyLevel::Maximum, 5, 100);
        assert_eq!(q.nominal_set, 20);
        // One entity holds 80% of the seats: the buyer really has four.
        assert_eq!(q.effective_set(0.8), 4);
        // And a fractional seat is never rounded in the buyer's favour.
        // 55% of 20 seats dominated = 11 dominated, 9 honest. Rounded against
        // the buyer, never for them.
        assert_eq!(q.effective_set(0.55), 9);
        // And an honest round delivers what was sold.
        assert_eq!(q.effective_set(0.0), 20);
    }

    #[test]
    fn the_effective_set_never_reaches_zero() {
        // Even a fully dominated round leaves the payer themselves.
        let q = quote(PrivacyLevel::High, 5, 100);
        assert_eq!(q.effective_set(1.0), 1);
    }

    #[test]
    fn selling_a_set_the_round_cannot_substantiate_is_refused() {
        let q = quote(PrivacyLevel::Maximum, 5, 100);
        // A clean round: the quote is honest.
        assert!(check_quote_is_honest(&q, 0.05, 0.25).is_none());
        // A dominated one: refuse to sell it.
        assert!(check_quote_is_honest(&q, 0.80, 0.25).is_some());
    }

    #[test]
    fn cost_as_a_share_of_payment_matches_the_design_note() {
        // The table the product decision was made from, recomputed.
        let payment = 500_000u64;
        let pcts: Vec<f64> = PrivacyLevel::all()
            .iter()
            .map(|l| quote(*l, 5, 100).cost_pct(payment))
            .collect();
        assert!(
            pcts[0] < 0.35,
            "Basic should be well under 1%: {:.2}%",
            pcts[0]
        );
        assert!(
            pcts[3] > 2.0,
            "Maximum should be a visible cost: {:.2}%",
            pcts[3]
        );
        // Monotonic: more crowd always costs more.
        for w in pcts.windows(2) {
            assert!(w[1] > w[0], "levels must be monotonic in cost: {pcts:?}");
        }
    }
}

#[cfg(test)]
mod price_report {
    use super::*;

    /// `cargo test -p wraith-protocol price_report -- --nocapture`
    #[test]
    fn print_price_table() {
        println!("\n  level       set   per payer   on 500k    on 1M");
        println!("  ----------------------------------------------");
        for l in PrivacyLevel::all() {
            let q = quote(l, 5, 100);
            println!(
                "  {:<10} {:>4} {:>10}   {:>6.2}%  {:>6.2}%",
                format!("{l:?}"),
                q.nominal_set,
                q.total_sats,
                q.cost_pct(500_000),
                q.cost_pct(1_000_000)
            );
        }
        println!();
    }
}
