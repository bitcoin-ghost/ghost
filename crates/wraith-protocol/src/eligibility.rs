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
//| FILE: eligibility.rs                                                                                                |
//|======================================================================================================================|

//! Who may coordinate — declared facts only, no local observations.
//!
//! The roster used to be built from `get_connected_peers(300)`, which filters on
//! `p.state == Connected` (this node's own socket) and `last_seen >= now - 300`
//! (this node's own clock). Neither is shared state, so two honest nodes
//! routinely disagreed, elected different coordinators, and gave one session two
//! owners.
//!
//! Sorting the result cannot fix that: canonicalisation makes **one** node's
//! answer order-independent, not **two** nodes' answers equal.
//!
//! # Declared, not observed
//!
//! Every input here is something the node itself declared and gossiped, or a
//! qualification verdict the network reached together:
//!
//! - opted in to coordinate
//! - advertises an endpoint a wallet can dial
//! - passes qualification — 95% uptime over seven days, ten challenges
//! - runs in archive mode
//! - has been known long enough to be mature
//!
//! None of it depends on whether *this* node currently holds a socket to that
//! peer.
//!
//! # Liveness is coarse, on purpose
//!
//! [`EligibilityPolicy::prune_after_secs`] is the only liveness input, and it is
//! measured in **days**. A node absent for a week is absent for everybody; a
//! node quiet for 300 seconds is not. Making the window coarse is exactly what
//! converts a perpetual disagreement into a rare one.
//!
//! An unreachable node left in the roster costs one timeout as callers walk past
//! it. That is a latency cost, not a correctness one, and it is the right trade
//! against nodes electing different coordinators.
//!
//! # Maturity closes key grinding
//!
//! Rank is `H(… ‖ beacon ‖ … ‖ node_id)` and `node_id` is a public key the
//! operator chooses. With the beacon in hand, an attacker generates keys until
//! one ranks first — cheap, because the identity proof-of-work is a flat 24-bit
//! toll rather than a scarcity.
//!
//! [`EligibilityPolicy::maturity_secs`] requires an identity to have been known
//! *before* the beacon it is ranked under existed, which makes that grind
//! useless. It does not stop an attacker registering many identities in advance;
//! qualification is what costs them there.

use crate::sortition::CoordinatorNodeId;

/// What is known about a candidate coordinator. All declared or network-agreed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFacts {
    /// Identity.
    pub node_id: CoordinatorNodeId,
    /// Declared the coordinator capability.
    pub opted_in: bool,
    /// Declared archive mode.
    pub archive: bool,
    /// Advertised endpoint. `None` or empty means a wallet cannot dial it.
    pub endpoint: Option<String>,
    /// When this identity was first seen, unix seconds.
    pub first_seen_secs: u64,
    /// When it was last heard from, unix seconds. Used only against the
    /// **coarse** pruning window.
    pub last_seen_secs: u64,
    /// Passes `ghost-verification::qualification`.
    pub qualified: bool,
}

/// Eligibility rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EligibilityPolicy {
    /// Require archive mode.
    ///
    /// Raises a Sybil farm from lightweight VMs to real storage. Worth having
    /// and not a barrier: archive capability can be proxied, because remote
    /// attestation cannot tell *"I store it"* from *"I can fetch it quickly"*.
    pub require_archive: bool,
    /// Require passing qualification.
    pub require_qualified: bool,
    /// How long an identity must have been known before it may be elected.
    pub maturity_secs: u64,
    /// How long an absent node stays in the roster. **Days, not seconds.**
    pub prune_after_secs: u64,
}

impl Default for EligibilityPolicy {
    /// Parameters, not results. None of these is measured.
    fn default() -> Self {
        Self {
            require_archive: true,
            require_qualified: true,
            // One epoch's worth of days, comfortably longer than the gossip
            // needed to agree an identity exists.
            maturity_secs: 24 * 60 * 60,
            // Seven days — the same window qualification already reasons over.
            prune_after_secs: 7 * 24 * 60 * 60,
        }
    }
}

/// Why a node may not coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Ineligible {
    /// Did not opt in.
    #[error("node has not opted in to coordinate")]
    NotOptedIn,
    /// No endpoint to dial.
    #[error("node advertises no coordinator endpoint, so no wallet can reach it")]
    NoEndpoint,
    /// Does not pass qualification.
    #[error("node does not pass qualification (uptime and challenge history)")]
    NotQualified,
    /// Not an archive node.
    #[error("node does not run in archive mode")]
    NotArchive,
    /// Identity is too new to be ranked under this beacon.
    #[error("identity has been known for {known_secs}s, below the {required_secs}s maturity; a fresh key could be ground against a beacon already in hand")]
    TooNew {
        /// How long it has been known.
        known_secs: u64,
        /// The requirement.
        required_secs: u64,
    },
    /// Gone long enough to prune.
    #[error(
        "node has not been heard from for {absent_secs}s, beyond the {limit_secs}s pruning window"
    )]
    LongAbsent {
        /// Silence so far.
        absent_secs: u64,
        /// The window.
        limit_secs: u64,
    },
}

/// Whether `facts` may coordinate at `now`.
pub fn check(facts: &NodeFacts, policy: EligibilityPolicy, now: u64) -> Result<(), Ineligible> {
    if !facts.opted_in {
        return Err(Ineligible::NotOptedIn);
    }
    if facts
        .endpoint
        .as_deref()
        .map(|e| e.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(Ineligible::NoEndpoint);
    }
    if policy.require_qualified && !facts.qualified {
        return Err(Ineligible::NotQualified);
    }
    if policy.require_archive && !facts.archive {
        return Err(Ineligible::NotArchive);
    }

    let known = now.saturating_sub(facts.first_seen_secs);
    if known < policy.maturity_secs {
        return Err(Ineligible::TooNew {
            known_secs: known,
            required_secs: policy.maturity_secs,
        });
    }

    let absent = now.saturating_sub(facts.last_seen_secs);
    if absent > policy.prune_after_secs {
        return Err(Ineligible::LongAbsent {
            absent_secs: absent,
            limit_secs: policy.prune_after_secs,
        });
    }
    Ok(())
}

/// The eligible roster, sorted and deduplicated.
///
/// Sorting makes one node's answer independent of the order it collected facts
/// in. It does **not** make two nodes agree — that comes from every input being
/// a declared fact rather than a local observation.
pub fn eligible_roster(
    facts: &[NodeFacts],
    policy: EligibilityPolicy,
    now: u64,
) -> Vec<CoordinatorNodeId> {
    let mut out: Vec<CoordinatorNodeId> = facts
        .iter()
        .filter(|f| check(f, policy, now).is_ok())
        .map(|f| f.node_id)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 60 * 60;
    const NOW: u64 = 1_000 * DAY;

    fn good(id: u8) -> NodeFacts {
        NodeFacts {
            node_id: [id; 32],
            opted_in: true,
            archive: true,
            endpoint: Some("node.example:8443".into()),
            first_seen_secs: NOW - 30 * DAY,
            last_seen_secs: NOW - 60,
            qualified: true,
        }
    }

    #[test]
    fn a_qualified_archive_node_that_opted_in_is_eligible() {
        assert_eq!(check(&good(1), EligibilityPolicy::default(), NOW), Ok(()));
    }

    #[test]
    fn nothing_here_depends_on_a_live_connection() {
        // The whole point. A node this one has no socket to, and has not heard
        // from in three days, is still eligible — because its eligibility is a
        // declared fact, not an observation this node made.
        let mut f = good(2);
        f.last_seen_secs = NOW - 3 * DAY;
        assert_eq!(check(&f, EligibilityPolicy::default(), NOW), Ok(()));
    }

    #[test]
    fn the_pruning_window_is_days_not_seconds() {
        // A node quiet for 300 seconds is quiet only from here. A node absent
        // for a fortnight is absent for everybody, and that is the difference
        // that lets two nodes agree.
        let p = EligibilityPolicy::default();
        let mut f = good(3);
        f.last_seen_secs = NOW - 300;
        assert_eq!(check(&f, p, NOW), Ok(()), "300s of silence is not absence");

        f.last_seen_secs = NOW - 14 * DAY;
        assert!(matches!(
            check(&f, p, NOW),
            Err(Ineligible::LongAbsent { .. })
        ));
    }

    #[test]
    fn a_fresh_identity_cannot_be_ranked_under_a_beacon_it_can_see() {
        // Key grinding: with the beacon in hand, generate keys until one ranks
        // first. Maturity makes the grind useless by requiring the identity to
        // predate the beacon.
        let p = EligibilityPolicy::default();
        let mut f = good(4);
        f.first_seen_secs = NOW - 60;
        assert!(matches!(check(&f, p, NOW), Err(Ineligible::TooNew { .. })));
    }

    #[test]
    fn an_unqualified_node_cannot_coordinate() {
        let mut f = good(5);
        f.qualified = false;
        assert_eq!(
            check(&f, EligibilityPolicy::default(), NOW),
            Err(Ineligible::NotQualified)
        );
    }

    #[test]
    fn a_non_archive_node_cannot_coordinate() {
        let mut f = good(6);
        f.archive = false;
        assert_eq!(
            check(&f, EligibilityPolicy::default(), NOW),
            Err(Ineligible::NotArchive)
        );
    }

    #[test]
    fn an_endpoint_nobody_can_dial_is_no_endpoint() {
        // Blank and whitespace both mean unreachable; treating either as an
        // endpoint seats a coordinator no wallet can talk to.
        for ep in [None, Some(String::new()), Some("   ".into())] {
            let mut f = good(7);
            f.endpoint = ep;
            assert_eq!(
                check(&f, EligibilityPolicy::default(), NOW),
                Err(Ineligible::NoEndpoint)
            );
        }
    }

    #[test]
    fn the_roster_is_order_independent_but_that_is_not_agreement() {
        // Sorting makes one node's answer stable. Two nodes agree because the
        // inputs are declared facts, not because of this sort.
        let p = EligibilityPolicy::default();
        let facts = vec![good(9), good(3), good(7)];
        let mut reversed = facts.clone();
        reversed.reverse();
        assert_eq!(
            eligible_roster(&facts, p, NOW),
            eligible_roster(&reversed, p, NOW)
        );
        assert_eq!(eligible_roster(&facts, p, NOW).len(), 3);
    }

    #[test]
    fn the_ineligible_are_absent_rather_than_ranked_last() {
        let p = EligibilityPolicy::default();
        let mut bad = good(4);
        bad.qualified = false;
        let roster = eligible_roster(&[good(1), bad, good(2)], p, NOW);
        assert_eq!(roster.len(), 2);
        assert!(!roster.contains(&[4u8; 32]));
    }

    #[test]
    fn relaxing_archive_admits_a_non_archive_node() {
        // The requirement is a policy, so a test network can run without it.
        let mut f = good(8);
        f.archive = false;
        let p = EligibilityPolicy {
            require_archive: false,
            ..Default::default()
        };
        assert_eq!(check(&f, p, NOW), Ok(()));
    }
}
