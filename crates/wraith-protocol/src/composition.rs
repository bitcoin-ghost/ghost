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
//| FILE: composition.rs                                                                                                |
//|======================================================================================================================|

//! Who is allowed into a round, and why the seats run out before the attacker
//! does.
//!
//! Everything in `admission` prices a seat: age, dispersion, fees. Pricing is an
//! economic argument, and an economic argument holds only while the attacker is
//! poorer than the defence assumed. This module is the structural half — seats
//! that **do not exist to be taken**, whatever the attacker is willing to spend.
//!
//! # Three rules
//!
//! 1. **One input per liquidity provider per round.** Seats then equal entities
//!    by construction, rather than being reconciled afterwards by
//!    [`crate::anonymity_set`]. Enforcement at admission beats detection later.
//! 2. **Mixing-only slots are scarce.** An attacker holding a million identities
//!    can still take at most [`CompositionPolicy::max_mixing_slots`] of them.
//! 3. **LPs may not outnumber real payers.** This is what makes padding a thin
//!    round impossible rather than merely discouraged.
//!
//! # The padding rule is the important one
//!
//! Real traffic is variable. Some hour it will be thin, and there will be an
//! obvious fix to hand: top the round up with our own liquidity until it reaches
//! the advertised figure. Twelve real payers plus thirty-eight supplied seats is
//! a set of about thirteen, sold as fifty.
//!
//! That moment will not feel like dishonesty. It will feel like solving a
//! shortfall with capital that is sitting right there. So the ceiling is
//! structural: with twelve payers and a half-and-half policy the round *cannot*
//! grow past twenty-four seats, and fifty is unreachable rather than merely
//! discouraged.
//!
//! # What this does not do
//!
//! A participant's [`Role`] is partly self-declared. Nothing on the wire
//! distinguishes someone paying a third party from someone paying themselves,
//! because blind signatures deliberately hide the destination — the property
//! that makes the round private also makes the claim uncheckable.
//!
//! So the payment slot is defended **economically** (each one costs a real fee,
//! §3b) and the mixing slot is defended **structurally** (there are almost
//! none). An attacker who lies about their role to reach the open slots has
//! bought seats at full price, which is the economic case working, not a
//! bypass.

use std::collections::HashSet;

use crate::anonymity_set::{Role, Seat};

/// Composition limits for one round.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompositionPolicy {
    /// Hard ceiling on seats.
    pub max_seats: usize,
    /// Mixing-only slots. **Deliberately small** — this is rule 2.
    pub max_mixing_slots: usize,
    /// Inputs one LP may contribute. Rule 1; anything above 1 gives back the
    /// seats-are-not-entities problem this exists to remove.
    pub max_inputs_per_lp: usize,
    /// Smallest share of seated entities that must be real payers, as a
    /// fraction. Rule 3, and the anti-padding ceiling.
    pub min_payer_fraction: f64,
}

impl Default for CompositionPolicy {
    /// Deliberately conservative. Every value is a parameter to be set against
    /// measured volume, not a result.
    fn default() -> Self {
        Self {
            max_seats: 50,
            max_mixing_slots: 3,
            max_inputs_per_lp: 1,
            min_payer_fraction: 0.5,
        }
    }
}

/// Why a seat was refused.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SeatRefusal {
    /// The round is full.
    #[error("round is full at {max} seats")]
    RoundFull {
        /// The ceiling.
        max: usize,
    },
    /// The scarce mixing slots are taken.
    #[error("all {max} mixing slots are taken; join as a payer or wait for the next round")]
    MixingSlotsFull {
        /// The ceiling.
        max: usize,
    },
    /// This LP already holds its allowance.
    #[error(
        "liquidity provider {lp} already holds {held} of {max} permitted inputs in this round"
    )]
    ProviderAllowanceUsed {
        /// The provider.
        lp: u64,
        /// Seats already held.
        held: usize,
        /// The allowance.
        max: usize,
    },
    /// Seating this would push liquidity past the payer-backed ceiling.
    #[error("seating this would leave {payers} payers carrying {lps} liquidity seats; real traffic must be at least {min_fraction:.0}% of the round — report the smaller set rather than padding it")]
    WouldPadTheRound {
        /// Payer entities seated.
        payers: usize,
        /// Liquidity entities that would be seated.
        lps: usize,
        /// The policy floor, as a percentage.
        min_fraction: f64,
    },
}

/// Whether `candidate` may join a round that already holds `seated`.
pub fn check_seat(
    seated: &[Seat],
    candidate: &Seat,
    policy: CompositionPolicy,
) -> Result<(), SeatRefusal> {
    if seated.len() >= policy.max_seats {
        return Err(SeatRefusal::RoundFull {
            max: policy.max_seats,
        });
    }

    match candidate.role {
        // Rule 2 — scarcity, counted in seats because each mixer is one seat.
        Role::Mixer => {
            let taken = seated.iter().filter(|s| s.role == Role::Mixer).count();
            if taken >= policy.max_mixing_slots {
                return Err(SeatRefusal::MixingSlotsFull {
                    max: policy.max_mixing_slots,
                });
            }
        }

        // Rule 1, then rule 3.
        Role::LiquidityProvider(lp) => {
            let held = seated
                .iter()
                .filter(|s| s.role == Role::LiquidityProvider(lp))
                .count();
            if held >= policy.max_inputs_per_lp {
                return Err(SeatRefusal::ProviderAllowanceUsed {
                    lp,
                    held,
                    max: policy.max_inputs_per_lp,
                });
            }

            let payers = distinct_payers(seated);
            let lps = distinct_providers(seated) + 1;
            // Payers must be at least `min_payer_fraction` of payer+LP entities.
            let total = payers + lps;
            if (payers as f64) < policy.min_payer_fraction * total as f64 {
                return Err(SeatRefusal::WouldPadTheRound {
                    payers,
                    lps,
                    min_fraction: policy.min_payer_fraction * 100.0,
                });
            }
        }

        // Payers are the traffic every other rule exists to protect. Open, and
        // defended by the fee rather than by a cap.
        Role::Payer => {}
    }

    Ok(())
}

/// Distinct payer entities currently seated.
fn distinct_payers(seated: &[Seat]) -> usize {
    let mut clusters: HashSet<u64> = HashSet::new();
    let mut unclustered = 0usize;
    for s in seated.iter().filter(|s| s.role == Role::Payer) {
        match s.candidate.cluster {
            Some(c) => {
                clusters.insert(c);
            }
            None => unclustered += 1,
        }
    }
    clusters.len() + unclustered
}

/// Distinct liquidity providers currently seated.
fn distinct_providers(seated: &[Seat]) -> usize {
    seated
        .iter()
        .filter_map(|s| match s.role {
            Role::LiquidityProvider(lp) => Some(lp),
            _ => None,
        })
        .collect::<HashSet<_>>()
        .len()
}

/// The largest round these payers can honestly support.
///
/// Used to answer "how big can we make this?" **without** the answer ever being
/// "as big as we advertised". With no payers the answer is the mixing slots
/// alone: liquidity cannot carry a round by itself, because a round carried by
/// liquidity is not a round, it is a receipt.
pub fn honest_ceiling(payers: usize, policy: CompositionPolicy) -> usize {
    if payers == 0 {
        return policy.max_mixing_slots.min(policy.max_seats);
    }
    let f = policy.min_payer_fraction.clamp(0.0, 1.0);
    // payers >= f * (payers + lps)  =>  lps <= payers * (1 - f) / f
    let lps = if f <= f64::EPSILON {
        policy.max_seats
    } else {
        ((payers as f64) * (1.0 - f) / f).floor() as usize
    };
    (payers + lps + policy.max_mixing_slots).min(policy.max_seats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::SeatCandidate;
    use crate::signing_ledger::OutPointKey;

    fn seat(id: u8, cluster: Option<u64>, role: Role) -> Seat {
        Seat {
            candidate: SeatCandidate {
                coin: OutPointKey {
                    txid: [id; 32],
                    vout: 0,
                },
                confirmed_height: 1_000,
                cluster,
            },
            role,
        }
    }

    fn payers(n: u8) -> Vec<Seat> {
        (0..n)
            .map(|i| seat(i, Some(i as u64), Role::Payer))
            .collect()
    }

    #[test]
    fn one_input_per_provider_per_round() {
        let p = CompositionPolicy::default();
        let mut seated = payers(4);
        seated.push(seat(90, None, Role::LiquidityProvider(7)));
        assert!(matches!(
            check_seat(&seated, &seat(91, None, Role::LiquidityProvider(7)), p),
            Err(SeatRefusal::ProviderAllowanceUsed { lp: 7, .. })
        ));
        // A different provider is fine.
        assert!(check_seat(&seated, &seat(92, None, Role::LiquidityProvider(8)), p).is_ok());
    }

    #[test]
    fn mixing_slots_run_out_however_many_identities_the_attacker_holds() {
        // The structural half: an attacker with a million identities still gets
        // at most `max_mixing_slots`, because the seats do not exist.
        let p = CompositionPolicy::default();
        let mut seated = payers(10);
        for i in 0..p.max_mixing_slots as u8 {
            seated.push(seat(100 + i, None, Role::Mixer));
        }
        assert!(matches!(
            check_seat(&seated, &seat(200, None, Role::Mixer), p),
            Err(SeatRefusal::MixingSlotsFull { .. })
        ));
    }

    #[test]
    fn a_thin_round_cannot_be_padded_up_to_the_advertised_number() {
        // The moment that will not feel like dishonesty: 12 real payers, 50
        // advertised, and liquidity sitting right there.
        let p = CompositionPolicy::default();
        let mut seated = payers(12);
        // Fill liquidity to the ceiling the payers support.
        let mut lp_id = 0u64;
        while check_seat(&seated, &seat(150, None, Role::LiquidityProvider(lp_id)), p).is_ok() {
            seated.push(seat(
                150 + lp_id as u8,
                None,
                Role::LiquidityProvider(lp_id),
            ));
            lp_id += 1;
        }
        assert!(matches!(
            check_seat(&seated, &seat(250, None, Role::LiquidityProvider(999)), p),
            Err(SeatRefusal::WouldPadTheRound { .. })
        ));
        assert!(
            seated.len() < 50,
            "must not reach the advertised figure: {}",
            seated.len()
        );
        assert_eq!(distinct_payers(&seated), 12);
    }

    #[test]
    fn liquidity_cannot_carry_a_round_by_itself() {
        // A round carried by liquidity is not a round, it is a receipt.
        let p = CompositionPolicy::default();
        assert!(matches!(
            check_seat(&[], &seat(1, None, Role::LiquidityProvider(1)), p),
            Err(SeatRefusal::WouldPadTheRound { payers: 0, .. })
        ));
        assert_eq!(honest_ceiling(0, p), p.max_mixing_slots);
    }

    #[test]
    fn the_honest_ceiling_grows_with_real_traffic_and_nothing_else() {
        let p = CompositionPolicy::default();
        // Half-and-half: n payers support n liquidity seats, plus the mixers.
        assert_eq!(honest_ceiling(12, p), 12 + 12 + 3);
        assert_eq!(honest_ceiling(4, p), 4 + 4 + 3);
        // And it is capped by the hard seat ceiling.
        assert_eq!(honest_ceiling(1_000, p), p.max_seats);
    }

    #[test]
    fn payers_are_never_capped() {
        // Real traffic is the thing every other rule exists to protect.
        let p = CompositionPolicy::default();
        let seated = payers(40);
        assert!(check_seat(&seated, &seat(200, Some(999), Role::Payer), p).is_ok());
    }

    #[test]
    fn the_hard_seat_ceiling_still_applies() {
        let p = CompositionPolicy {
            max_seats: 6,
            ..Default::default()
        };
        let seated = payers(6);
        assert!(matches!(
            check_seat(&seated, &seat(200, Some(99), Role::Payer), p),
            Err(SeatRefusal::RoundFull { max: 6 })
        ));
    }

    #[test]
    fn linked_payers_do_not_unlock_liquidity_seats() {
        // Twelve seats from one cluster is one payer entity, so it must buy the
        // liquidity headroom of one payer — not twelve. Otherwise an attacker
        // funds the "real traffic" side cheaply and pads behind it.
        let p = CompositionPolicy::default();
        let seated: Vec<Seat> = (0..12u8).map(|i| seat(i, Some(1), Role::Payer)).collect();
        assert_eq!(distinct_payers(&seated), 1);
        let mut seated = seated;
        seated.push(seat(90, None, Role::LiquidityProvider(1)));
        assert!(matches!(
            check_seat(&seated, &seat(91, None, Role::LiquidityProvider(2)), p),
            Err(SeatRefusal::WouldPadTheRound { payers: 1, .. })
        ));
    }

    #[test]
    fn the_refusal_says_to_report_the_smaller_set_rather_than_pad() {
        // The operator reading this at 3am is the audience.
        let msg = SeatRefusal::WouldPadTheRound {
            payers: 12,
            lps: 13,
            min_fraction: 50.0,
        }
        .to_string();
        assert!(msg.contains("report the smaller set"), "{msg}");
    }
}
