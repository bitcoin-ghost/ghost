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
//| FILE: residency.rs                                                                                                  |
//|======================================================================================================================|

//! Residency — a coin stays spendable only while its quorum does.
//!
//! A hot-lane coin is `musig(owner, quorum)`, and that quorum is drawn once, at
//! entry, from the qualified roster. The roster moves: nodes fall out of
//! qualification, go dark, or are banned. The coin's quorum does not move with
//! it.
//!
//! Below threshold, the 2-of-2 can never be completed and the coin is
//! **stranded** — the only remaining path is the timelocked escape leaf.
//!
//! # Stranding is silent, which is the whole problem
//!
//! A degraded coin looks exactly like a healthy one. The balance is right, the
//! address is right, nothing on chain has changed. The owner discovers it at the
//! moment they try to spend, which is the worst possible moment, and the answer
//! is then "wait out `EXIT_DELAY`".
//!
//! Worse, that escape has its own trap: [`crate::exit_availability`] shows the
//! `older(EXIT_DELAY)` clock restarts on every remix. A stranded coin that is
//! still being remixed for cover traffic cannot exit either — the wallet has to
//! notice the stranding *and* stop remixing that coin.
//!
//! So health is something to check on a schedule and act on early, not
//! something to discover on spend. [`Health::Degraded`] exists to be acted on
//! while [`Health::Stranded`] is still avoidable.

use std::collections::HashSet;

use crate::sortition::CoordinatorNodeId;

/// The quorum a coin was bound to at entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinQuorum {
    /// Members drawn at entry.
    pub members: Vec<CoordinatorNodeId>,
    /// How many must sign.
    pub threshold: usize,
}

/// Whether a coin can still be spent through its quorum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Comfortably above threshold.
    Healthy {
        /// Members still qualified.
        available: usize,
    },
    /// Above threshold, but with little room left. **Refresh now.**
    ///
    /// This is the state the design depends on being acted upon. Waiting for
    /// `Stranded` means waiting for the state that cannot be fixed by
    /// re-entering, only by waiting out a timelock.
    Degraded {
        /// Members still qualified.
        available: usize,
        /// How many more may drop before stranding.
        margin: usize,
    },
    /// Below threshold. The quorum path is gone; only the timelock remains.
    Stranded {
        /// Members still qualified.
        available: usize,
        /// How many were needed.
        threshold: usize,
    },
}

impl Health {
    /// Whether the coin can still be spent through its quorum at all.
    pub fn is_spendable(&self) -> bool {
        !matches!(self, Health::Stranded { .. })
    }

    /// Whether the wallet should re-enter this coin into a fresh quorum now.
    pub fn needs_refresh(&self) -> bool {
        matches!(self, Health::Degraded { .. } | Health::Stranded { .. })
    }
}

/// Assess a coin's quorum against the current qualified roster.
///
/// `refresh_margin` is how much headroom to insist on: with a margin of 2, a
/// quorum one or two departures from stranding reports [`Health::Degraded`].
pub fn health(
    quorum: &CoinQuorum,
    qualified_roster: &[CoordinatorNodeId],
    refresh_margin: usize,
) -> Health {
    let roster: HashSet<&CoordinatorNodeId> = qualified_roster.iter().collect();
    let available = quorum.members.iter().filter(|m| roster.contains(m)).count();

    if available < quorum.threshold {
        return Health::Stranded {
            available,
            threshold: quorum.threshold,
        };
    }
    let margin = available - quorum.threshold;
    if margin <= refresh_margin {
        Health::Degraded { available, margin }
    } else {
        Health::Healthy { available }
    }
}

/// Coins that should be re-entered, worst first.
///
/// Returned in ascending margin order so a wallet with a fee budget spends it
/// where stranding is closest rather than on whichever coin it happened to
/// enumerate first.
pub fn refresh_queue<'a, T>(
    coins: &'a [(T, CoinQuorum)],
    qualified_roster: &[CoordinatorNodeId],
    refresh_margin: usize,
) -> Vec<(&'a T, Health)> {
    let mut out: Vec<(&T, Health)> = coins
        .iter()
        .map(|(c, q)| (c, health(q, qualified_roster, refresh_margin)))
        .filter(|(_, h)| h.needs_refresh())
        .collect();
    out.sort_by_key(|(_, h)| match h {
        Health::Stranded { .. } => 0usize,
        Health::Degraded { margin, .. } => 1 + margin,
        Health::Healthy { .. } => usize::MAX,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(i: u8) -> CoordinatorNodeId {
        [i; 32]
    }

    fn quorum(members: &[u8]) -> CoinQuorum {
        CoinQuorum {
            members: members.iter().map(|i| node(*i)).collect(),
            threshold: 5,
        }
    }

    fn roster(members: &[u8]) -> Vec<CoordinatorNodeId> {
        members.iter().map(|i| node(*i)).collect()
    }

    #[test]
    fn a_full_quorum_is_healthy() {
        let q = quorum(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            health(&q, &roster(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), 2),
            Health::Healthy { available: 9 }
        );
    }

    #[test]
    fn a_quorum_near_the_threshold_asks_to_be_refreshed() {
        // The state the design depends on being acted on. Waiting for
        // `Stranded` means waiting for the one that cannot be fixed by
        // re-entering.
        let q = quorum(&[1, 2, 3, 4, 5, 6, 7]);
        let h = health(&q, &roster(&[1, 2, 3, 4, 5, 6]), 2);
        assert_eq!(
            h,
            Health::Degraded {
                available: 6,
                margin: 1
            }
        );
        assert!(h.is_spendable());
        assert!(h.needs_refresh());
    }

    #[test]
    fn below_threshold_the_quorum_path_is_gone() {
        let q = quorum(&[1, 2, 3, 4, 5, 6, 7]);
        let h = health(&q, &roster(&[1, 2, 3]), 2);
        assert_eq!(
            h,
            Health::Stranded {
                available: 3,
                threshold: 5
            }
        );
        assert!(!h.is_spendable(), "only the timelock leaf remains");
    }

    #[test]
    fn departures_outside_the_quorum_do_not_matter() {
        // A shrinking or growing roster is only this coin's problem where it
        // overlaps the quorum it was actually drawn from.
        let q = quorum(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let intact = health(&q, &roster(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), 2);
        assert_eq!(intact, Health::Healthy { available: 9 });

        // Roster gained strangers: unchanged.
        assert_eq!(
            health(&q, &roster(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 40, 41, 42]), 2),
            intact
        );
        // Roster lost strangers: also unchanged.
        assert_eq!(
            health(&q, &roster(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 40]), 2),
            intact
        );
    }

    #[test]
    fn spare_capacity_is_measured_against_the_threshold_not_the_size() {
        // Nine members needing five has four spare; seven members needing five
        // has two, and under a margin-2 policy that is already degraded even
        // with every member present. A large quorum is not automatically a
        // healthy one.
        let big = quorum(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let small = quorum(&[1, 2, 3, 4, 5, 6, 7]);
        let r = roster(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(health(&big, &r, 2), Health::Healthy { available: 9 });
        assert_eq!(
            health(&small, &r, 2),
            Health::Degraded {
                available: 7,
                margin: 2
            }
        );
    }

    #[test]
    fn the_refresh_queue_puts_the_closest_to_stranding_first() {
        // A wallet with a limited fee budget must spend it where stranding is
        // nearest, not on whichever coin it enumerated first.
        let coins = vec![
            ("healthy", quorum(&[1, 2, 3, 4, 5, 6, 7, 8, 9])),
            ("stranded", quorum(&[1, 2, 20, 21, 22, 23, 24])),
            ("degraded_1", quorum(&[1, 2, 3, 4, 5, 6, 30])),
            ("degraded_2", quorum(&[1, 2, 3, 4, 5, 6, 7])),
        ];
        let r = roster(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let queue = refresh_queue(&coins, &r, 2);

        let names: Vec<&str> = queue.iter().map(|(n, _)| **n).collect();
        assert_eq!(names[0], "stranded", "the unfixable one first");
        assert!(!names.contains(&"healthy"), "healthy coins are not queued");
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn an_empty_roster_strands_everything() {
        // The whole-fleet-dark case. It must read as stranded rather than as an
        // empty queue that looks like nothing to do.
        let q = quorum(&[1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            health(&q, &[], 2),
            Health::Stranded {
                available: 0,
                threshold: 5
            }
        );
        let coins = vec![("a", quorum(&[1, 2, 3, 4, 5, 6, 7]))];
        assert_eq!(refresh_queue(&coins, &[], 2).len(), 1);
    }
}
