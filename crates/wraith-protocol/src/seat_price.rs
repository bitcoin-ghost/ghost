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
//| FILE: seat_price.rs                                                                                                  |
//|======================================================================================================================|

//! The seat price — **one** calculation, and deliberately not a constant.
//!
//! # Why this module exists at all
//!
//! Requiring an exact seat input (#698) exposed a latent disagreement: the
//! coordinator and the round builder each computed the required amount
//! independently and never matched — 102,026 against 101,440. It was invisible
//! because both only checked `>=`, so the larger won and the difference went to
//! miners. **There must be one seat-price calculation.** This is it. The
//! coordinator, the builder, the wallet, the demo scripts and the smoke tests
//! all read from here; never add a second copy.
//!
//! # Why it must not be pinned
//!
//! A published constant is a chain-analysis marker hiding in the economics
//! rather than the script. If every Mix seat costs exactly 101,596 sats, then
//!
//! ```text
//! grep the chain for outputs of exactly 101,596 sats
//!   -> every Wraith seat ever funded, forever
//! ```
//!
//! That is the same class of mistake as the `WL01` OP_RETURN marker already
//! removed, one layer down. The fix is not to add jitter — it is to **stop
//! pinning the feerate**. Price a round from the live fee estimate and the
//! price moves on its own, and it moves for a reason any observer would
//! attribute to ordinary fee conditions rather than to deliberate obfuscation.
//!
//! # What this does and does not buy
//!
//! - **Does** defeat the cross-round grep: there is no constant to search for.
//! - **Does not** hide that a transaction has many equal-valued outputs. The
//!   price is uniform *within* a round by necessity — that uniformity is what
//!   makes the outputs interchangeable — and no amount of variation between
//!   rounds changes the in-round pattern. That is inherent to CoinJoin.

use crate::single_round::per_participant_mining_share;
use crate::tier::LiteTier;
use crate::SessionType;

/// The exact input one seat costs, at a given fee rate.
///
/// Uniform across every participant in a round, and varying between rounds
/// because `fee_rate_sats_per_vb` is a live estimate rather than a constant.
pub fn seat_price(tier: LiteTier, session_type: SessionType, fee_rate_sats_per_vb: u64) -> u64 {
    tier.denomination_sats()
        + per_participant_mining_share(tier, session_type, fee_rate_sats_per_vb)
        + match session_type {
            SessionType::Mix => tier.service_fee_sats(),
            SessionType::Jump => 0,
        }
}

/// How many distinct seat prices a fee-rate range produces.
///
/// This exists so "is natural fee variation enough spread" is answered with a
/// number rather than asserted. A range that collapses to a handful of values
/// is still greppable — just with a shortlist instead of one constant.
pub fn distinct_prices(
    tier: LiteTier,
    session_type: SessionType,
    fee_rates: impl IntoIterator<Item = u64>,
) -> usize {
    let mut seen: Vec<u64> = fee_rates
        .into_iter()
        .map(|f| seat_price(tier, session_type, f))
        .collect();
    seen.sort_unstable();
    seen.dedup();
    seen.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALISTIC_FEE_RATES: std::ops::RangeInclusive<u64> = 1..=60;

    #[test]
    fn the_price_is_uniform_within_a_round() {
        // Every participant at the same fee rate pays the same. This is the
        // property that makes outputs interchangeable and it must never vary
        // per participant.
        let a = seat_price(LiteTier::Denom100kSats, SessionType::Mix, 12);
        let b = seat_price(LiteTier::Denom100kSats, SessionType::Mix, 12);
        assert_eq!(a, b);
    }

    #[test]
    fn the_price_is_not_a_constant() {
        // Replaces the old `seat_prices_are_pinned`. Pinning was the bug: a
        // fixed value is a permanent, greppable marker on every seat ever
        // funded. If this test ever fails, someone has re-pinned the fee rate.
        for tier in LiteTier::all() {
            let prices: Vec<u64> = REALISTIC_FEE_RATES
                .map(|f| seat_price(*tier, SessionType::Mix, f))
                .collect();
            let first = prices[0];
            assert!(
                prices.iter().any(|p| *p != first),
                "tier {tier}: seat price is constant across fee rates — it has been re-pinned"
            );
        }
    }

    #[test]
    fn fee_variation_alone_gives_a_wide_spread() {
        // If this collapses to a shortlist, natural variation is not enough and
        // the design needs revisiting — not more jitter, but a wider input.
        for tier in LiteTier::all() {
            let n = distinct_prices(*tier, SessionType::Mix, REALISTIC_FEE_RATES);
            assert!(
                n >= 40,
                "tier {tier}: only {n} distinct seat prices across 60 fee rates; \
                 a shortlist is still greppable"
            );
        }
    }

    #[test]
    fn a_higher_fee_rate_never_lowers_the_price() {
        for tier in LiteTier::all() {
            let mut previous = 0;
            for f in REALISTIC_FEE_RATES {
                let p = seat_price(*tier, SessionType::Mix, f);
                assert!(p >= previous, "tier {tier}: price fell as fees rose");
                previous = p;
            }
        }
    }

    #[test]
    fn a_jump_seat_is_cheaper_than_a_mix_seat_by_the_service_fee_and_its_output() {
        use crate::tier::VBYTES_PER_OUTPUT;
        let rate = 10;
        let fee_output_share = (VBYTES_PER_OUTPUT as u64 * rate)
            .div_ceil(LiteTier::Denom100kSats.min_participants() as u64);
        for tier in LiteTier::all() {
            let tier = *tier;
            assert_eq!(
                seat_price(tier, SessionType::Mix, rate)
                    - seat_price(tier, SessionType::Jump, rate),
                tier.service_fee_sats() + fee_output_share,
                "tier {tier}: the gap is the service fee plus its output's mining cost"
            );
        }
    }
}

#[cfg(test)]
mod spread_report {
    use super::*;

    /// `cargo test -p wraith-protocol spread_report -- --nocapture`
    #[test]
    fn print_seat_price_spread() {
        println!("\n  tier          1 sat/vB      60 sat/vB   distinct values");
        println!("  --------------------------------------------------------");
        for tier in LiteTier::all() {
            let lo = seat_price(*tier, SessionType::Mix, 1);
            let hi = seat_price(*tier, SessionType::Mix, 60);
            let n = distinct_prices(*tier, SessionType::Mix, 1..=60);
            println!("  {:<12} {lo:>11}   {hi:>11}   {n:>10}", tier.id());
        }
        println!();
    }
}
