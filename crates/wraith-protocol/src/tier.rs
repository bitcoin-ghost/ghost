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
//| FILE: tier.rs                                                                                                        |
//|======================================================================================================================|

//! Participant tiers for Wraith sessions (single-round atomic).
//!
//! See `LiteTier` below for the tier table; the legacy two-phase
//! `ParticipantTier` was removed when the protocol moved to single-round
//! atomic CoinJoin (Wraith Lite v1, DESIGN_LITE.md).

use serde::{Deserialize, Serialize};

/// vbytes per P2TR input
pub const VBYTES_PER_INPUT: usize = 58; // Rounded up from 57.5

/// vbytes per P2TR output
pub const VBYTES_PER_OUTPUT: usize = 43;

/// Maximum transaction size budget in vbytes — 10% margin under Bitcoin's
/// 100KB standardness limit.
#[allow(dead_code)]
pub(crate) const MAX_TX_VBYTES: usize = 90_000;

// ---------------------------------------------------------------------------
// LITE TIERS — single-round atomic CoinJoin (Wraith Lite v1, see DESIGN_LITE.md)
// ---------------------------------------------------------------------------
//
// These coexist with `ParticipantTier` during the v1 refactor. Once every
// caller has migrated, the legacy two-phase types above are deleted in a
// single subtractive commit and `LiteTier` is renamed to the canonical
// `Tier`. Until then, both compile side-by-side.
//
// Differences from `ParticipantTier`:
//   * 1 output per participant (no OPP), so transactions are dramatically
//     smaller and there's no two-phase fee-pad bookkeeping.
//   * 4 tiers instead of 6, named after their fixed denominations.
//   * 5–100 participants per round, not 140–500. Filling at this scale is
//     practical even on launch day; the larger numbers only worked on paper.
//   * `WraithMode` (Bootstrap/Growth/Mature) is gone — the floor of 5 is
//     viable from network launch.
//   * Carries the service-fee rate directly on the tier so callers
//     don't have to thread them separately.

/// Service-fee rate as basis points (50 bps = 0.5%). Applied to total round
/// notional value. Fee output goes to the coordinator pool's fee address.
pub const LITE_SERVICE_FEE_BPS: u32 = 50;

/// How long a `Filling` session stays open after `min_participants` is
/// reached, waiting for more arrivals up to `max_participants`. Default
/// 5 minutes — long enough for a realistic real-time fill, short enough that
/// users don't lose patience.
pub const LITE_FILL_WINDOW_SECS: u64 = 300;

/// A Wraith Lite tier — denomination-named, single-round atomic.
///
/// Each variant binds:
///   * a fixed mixed-output denomination (the equal-output value participants
///     receive after the round),
///   * `min_participants` (5 universally — round won't start below this),
///   * `max_participants` (tier-specific cap so the on-chain tx stays small),
///   * a shared service-fee rate (`LITE_SERVICE_FEE_BPS`).
///
/// Users select a tier by the denomination they want their post-mix outputs
/// to be. A user with 0.5 BTC who wants a single 0.1 BTC mixed output picks
/// `Denom10mSats` (the rest comes back as change in the same tx).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum LiteTier {
    /// 100,000 sats per mixed output (~$60 at $60k BTC). Fast-fill, high traffic.
    #[default]
    Denom100kSats,
    /// 1,000,000 sats per mixed output (~$600).
    Denom1mSats,
    /// 10,000,000 sats per mixed output (~$6,000).
    Denom10mSats,
    /// 100,000,000 sats per mixed output (~$60,000). Whale tier.
    Denom100mSats,
}

impl LiteTier {
    /// The single-output denomination this tier mixes to (in satoshis).
    pub const fn denomination_sats(&self) -> u64 {
        match self {
            LiteTier::Denom100kSats => 100_000,
            LiteTier::Denom1mSats => 1_000_000,
            LiteTier::Denom10mSats => 10_000_000,
            LiteTier::Denom100mSats => 100_000_000,
        }
    }

    /// Stable string identifier — what the wallet sends in `find_or_create`
    /// and what shows up in IPC envelopes / logs / config files.
    pub const fn id(&self) -> &'static str {
        match self {
            LiteTier::Denom100kSats => "100k_sats",
            LiteTier::Denom1mSats => "1m_sats",
            LiteTier::Denom10mSats => "10m_sats",
            LiteTier::Denom100mSats => "100m_sats",
        }
    }

    /// Parse a tier id back to its enum (the `find_or_create` reverse of
    /// `id()`). Returns `None` for unknown ids — callers surface that as a
    /// typed error to the wallet, never panic.
    pub fn from_id(s: &str) -> Option<Self> {
        match s {
            "100k_sats" => Some(LiteTier::Denom100kSats),
            "1m_sats" => Some(LiteTier::Denom1mSats),
            "10m_sats" => Some(LiteTier::Denom10mSats),
            "100m_sats" => Some(LiteTier::Denom100mSats),
            _ => None,
        }
    }

    /// Minimum participants required for a round to broadcast. 5 across all
    /// tiers — Whirlpool's number, well-tested for fill rate vs. anonymity
    /// set in the real world.
    pub const fn min_participants(&self) -> usize {
        5
    }

    /// Per-tier participant cap. Larger tiers allow more participants
    /// because they're rarer (so a tx with 100 participants is acceptable
    /// for the 0.1 BTC tier where rounds happen less frequently).
    pub const fn max_participants(&self) -> usize {
        match self {
            LiteTier::Denom100kSats => 20,
            LiteTier::Denom1mSats => 30,
            LiteTier::Denom10mSats => 50,
            LiteTier::Denom100mSats => 100,
        }
    }

    /// Per-participant service fee included in the round transaction.
    /// Funds the coordinator pool operator.
    pub const fn service_fee_sats(&self) -> u64 {
        (self.denomination_sats() * LITE_SERVICE_FEE_BPS as u64) / 10_000
    }

    /// Round transaction size in vbytes — used to sanity-check every tier
    /// still fits inside Bitcoin's 100 KB standardness limit, and to derive
    /// each participant's share of the mining fee.
    ///
    /// Exact rather than worst-case since #698: a round has no change
    /// outputs, so the shape is fully determined by the participant count.
    pub const fn estimated_tx_vbytes(&self) -> usize {
        let n = self.max_participants();
        // n inputs (one per participant)
        // + n mixed outputs (one per participant)
        // + 1 fee output (to coordinator)
        (n * VBYTES_PER_INPUT) + (n * VBYTES_PER_OUTPUT) + VBYTES_PER_OUTPUT
    }

    /// All four tiers, in ascending denomination order.
    pub const fn all() -> &'static [LiteTier] {
        &[
            LiteTier::Denom100kSats,
            LiteTier::Denom1mSats,
            LiteTier::Denom10mSats,
            LiteTier::Denom100mSats,
        ]
    }

    /// Suggest a tier for a user's available balance. Picks the largest
    /// tier where `denomination + service_fee ≤ balance`. Returns
    /// `None` if the user can't afford even the smallest tier.
    ///
    /// Note: this is suggestion only — the wallet may pick any tier the
    /// user has the balance for, including downsizing to a smaller tier
    /// for faster fill or upgrading via remix queue.
    pub fn suggest_for_balance(sats: u64) -> Option<Self> {
        for tier in Self::all().iter().rev() {
            let needed = tier.denomination_sats() + tier.service_fee_sats();
            if sats >= needed {
                return Some(*tier);
            }
        }
        None
    }
}

impl std::fmt::Display for LiteTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Lite tier tests — locks the v1 spec (DESIGN_LITE.md §8 tier table)
    // -----------------------------------------------------------------------

    #[test]
    fn lite_tier_ids_are_canonical() {
        // Wallet wire format depends on these strings being stable.
        assert_eq!(LiteTier::Denom100kSats.id(), "100k_sats");
        assert_eq!(LiteTier::Denom1mSats.id(), "1m_sats");
        assert_eq!(LiteTier::Denom10mSats.id(), "10m_sats");
        assert_eq!(LiteTier::Denom100mSats.id(), "100m_sats");
    }

    #[test]
    fn lite_tier_id_round_trips() {
        for tier in LiteTier::all() {
            let id = tier.id();
            assert_eq!(LiteTier::from_id(id), Some(*tier));
        }
        assert_eq!(LiteTier::from_id("not_a_tier"), None);
        assert_eq!(LiteTier::from_id(""), None);
    }

    #[test]
    fn lite_tier_denominations_are_powers_of_ten() {
        // Spec invariant — each tier is exactly 10x the previous, so
        // remix-queue downgrade math (1 × 1m → 10 × 100k) works without
        // remainder.
        assert_eq!(LiteTier::Denom100kSats.denomination_sats(), 100_000);
        assert_eq!(LiteTier::Denom1mSats.denomination_sats(), 1_000_000);
        assert_eq!(LiteTier::Denom10mSats.denomination_sats(), 10_000_000);
        assert_eq!(LiteTier::Denom100mSats.denomination_sats(), 100_000_000);
    }

    #[test]
    fn lite_tier_fees_match_spec() {
        // 0.5% service fee, applied per-tier.
        for tier in LiteTier::all() {
            let denom = tier.denomination_sats();
            assert_eq!(tier.service_fee_sats(), denom / 200, "tier {tier} fee");
        }
        // Concrete:
        assert_eq!(LiteTier::Denom100kSats.service_fee_sats(), 500);
        assert_eq!(LiteTier::Denom1mSats.service_fee_sats(), 5_000);
        assert_eq!(LiteTier::Denom10mSats.service_fee_sats(), 50_000);
        assert_eq!(LiteTier::Denom100mSats.service_fee_sats(), 500_000);
    }

    #[test]
    fn lite_tier_min_participants_is_five() {
        for tier in LiteTier::all() {
            assert_eq!(tier.min_participants(), 5, "tier {tier} min");
        }
    }

    #[test]
    fn lite_tier_max_participants_match_spec() {
        // From DESIGN_LITE.md §8 tier table.
        assert_eq!(LiteTier::Denom100kSats.max_participants(), 20);
        assert_eq!(LiteTier::Denom1mSats.max_participants(), 30);
        assert_eq!(LiteTier::Denom10mSats.max_participants(), 50);
        assert_eq!(LiteTier::Denom100mSats.max_participants(), 100);
    }

    #[test]
    fn lite_tier_tx_size_fits_standardness() {
        // Every tier at maximum fill must fit comfortably in Bitcoin's
        // 100KB standardness limit. Largest is Denom100mSats with 100
        // participants, ~14.4KB worst-case.
        for tier in LiteTier::all() {
            let vb = tier.estimated_tx_vbytes();
            assert!(
                vb <= MAX_TX_VBYTES,
                "tier {tier}: {vb} vbytes exceeds {MAX_TX_VBYTES}"
            );
        }
        // The 100m tier is the largest: 100 inputs + 100 mixed + 1 fee =
        // 201 io-units. Change outputs are gone (#698), which took roughly a
        // third off every round — the band is pinned so their reintroduction
        // would have to be deliberate.
        let big = LiteTier::Denom100mSats.estimated_tx_vbytes();
        assert!(
            (10_000..=10_500).contains(&big),
            "100m tier tx size ({big}) outside expected ~10.1KB band"
        );
    }

    #[test]
    fn lite_tier_suggestion_picks_largest_affordable() {
        // Just enough for the smallest tier: denom + fee.
        let smallest_total = LiteTier::Denom100kSats.denomination_sats()
            + LiteTier::Denom100kSats.service_fee_sats();
        assert_eq!(
            LiteTier::suggest_for_balance(smallest_total),
            Some(LiteTier::Denom100kSats)
        );
        // One sat short of the smallest → None.
        assert_eq!(LiteTier::suggest_for_balance(smallest_total - 1), None);
        // 1 BTC exactly. The 100m tier needs denom (100m) + fee (500k),
        // so 100m sats is short by 500k. Expect the 10m tier.
        assert_eq!(
            LiteTier::suggest_for_balance(100_000_000),
            Some(LiteTier::Denom10mSats)
        );
        // 1.01+ BTC → 100m tier.
        assert_eq!(
            LiteTier::suggest_for_balance(101_000_000),
            Some(LiteTier::Denom100mSats)
        );
    }

    #[test]
    fn lite_tier_default_is_smallest() {
        // Default tier is the smallest — fastest fill, lowest commitment.
        // Wallet code that uses LiteTier::default() lands users in the
        // tier most likely to fill on launch day.
        assert_eq!(LiteTier::default(), LiteTier::Denom100kSats);
    }

    #[test]
    fn lite_constants_match_spec() {
        // 50 bps = 0.5%, 5 minute fill window — these are wallet-visible,
        // pin them so a future "let's tune the rate" change has to
        // explicitly update the test.
        assert_eq!(LITE_SERVICE_FEE_BPS, 50);
        assert_eq!(LITE_FILL_WINDOW_SECS, 300);
    }
}
