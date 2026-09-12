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
//! Every input here is something the node itself declared and gossiped:
//!
//! - opted in to coordinate
//! - advertises an endpoint a wallet can dial
//! - has been known long enough to be mature
//! - has not been absent for days
//!
//! None of it depends on whether *this* node currently holds a socket to that
//! peer.
//!
//! # Why qualification and archive are not here
//!
//! Both used to be. Both were described as "a qualification verdict the network
//! reached together", and neither was: the caller filled them from
//! `QualifiedCapabilityProvider`, which reads **this node's own** verification
//! ledger — the challenges it issued and the verdicts it holds. Challenge
//! rotation samples a few peers per round, so no two nodes ever hold the same
//! evidence, and the roster could not converge by construction.
//!
//! The night all eight mainnet nodes opted in (2026-09-10, epoch 6711) the
//! rosters read 6/7/5/5/2/2/4/5 and the fleet elected two different
//! coordinators for one epoch. Most of that was the pool freezing whatever
//! roster it saw first (fixed alongside this, in `ghost-pool`). But a fix for
//! the freeze alone would still leave an input that disagrees for ever, and
//! one such input is enough to split a draw that is otherwise deterministic.
//!
//! Qualification was not load-bearing for safety. A coordinator can deny
//! service but cannot take coins — the round is atomic and blind-signed
//! whichever node runs it. Misbehaviour is answered by the outpoint ban list,
//! unreachability by walking to the next coordinator, and identity by the
//! coordinator challenge. What is given up is a Sybil cost: an identity now
//! needs its proof-of-work, a day of maturity and a dialable endpoint, not a
//! verified archive. That is weaker, and it is stated here rather than implied
//! by a field that could not deliver it.
//!
//! ⛔ **Do not add a verdict back unless every node reads the same one.** A
//! BFT-finalised or chain-anchored verdict would qualify; one assembled from a
//! node's own challenge history never will.
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
//! useless. It does not stop an attacker registering many identities in advance.

use crate::sortition::CoordinatorNodeId;

/// What is known about a candidate coordinator. All of it declared by the node
/// and gossiped, so every node holding the same gossip computes the same roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFacts {
    /// Identity.
    pub node_id: CoordinatorNodeId,
    /// Declared the coordinator capability.
    pub opted_in: bool,
    /// Advertised endpoint. `None` or empty means a wallet cannot dial it.
    pub endpoint: Option<String>,
    /// When this identity was first seen, unix seconds.
    pub first_seen_secs: u64,
    /// When it was last heard from, unix seconds. Used only against the
    /// **coarse** pruning window.
    pub last_seen_secs: u64,
}

/// Eligibility rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EligibilityPolicy {
    /// How long an identity must have been known before it may be elected.
    pub maturity_secs: u64,
    /// How long an absent node stays in the roster. **Days, not seconds.**
    pub prune_after_secs: u64,
}

impl Default for EligibilityPolicy {
    /// Parameters, not results. None of these is measured.
    fn default() -> Self {
        Self {
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

impl Ineligible {
    /// A stable machine-readable tag for this reason.
    ///
    /// The `Display` text carries the numbers and is what a human reads; this is
    /// what a log filter or an aggregation greps for, so it must not change when
    /// the wording does.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotOptedIn => "not_opted_in",
            Self::NoEndpoint => "no_endpoint",
            Self::TooNew { .. } => "too_new",
            Self::LongAbsent { .. } => "long_absent",
        }
    }
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
    eligible_roster_with_reasons(facts, policy, now).0
}

/// The eligible roster, **and why every other candidate was refused**.
///
/// # Why the refusals are returned rather than dropped
///
/// `check` computes a reason precise enough to end an investigation —
/// `TooNew` carries how long the identity has been known and the requirement,
/// `LongAbsent` carries the silence and the window. `eligible_roster` threw all
/// of it away behind `.is_ok()`, so a node missing from a roster was
/// indistinguishable from a node that had never been heard of, and nothing on
/// the node could say which of the four gates had refused it.
///
/// That is why the 2026-09-12 fleet split took code reading and a who-sees-whom
/// matrix to narrow, and still ended without naming the failing gate: the
/// answer was computed eight times a minute on every node and discarded each
/// time. Callers that only want the roster keep using [`eligible_roster`].
///
/// Refusals are sorted by node id so two nodes' diagnostics line up, and a node
/// that appears twice in `facts` is reported once.
pub fn eligible_roster_with_reasons(
    facts: &[NodeFacts],
    policy: EligibilityPolicy,
    now: u64,
) -> (Vec<CoordinatorNodeId>, Vec<(CoordinatorNodeId, Ineligible)>) {
    let mut out: Vec<CoordinatorNodeId> = Vec::new();
    let mut refused: Vec<(CoordinatorNodeId, Ineligible)> = Vec::new();
    for f in facts {
        match check(f, policy, now) {
            Ok(()) => out.push(f.node_id),
            Err(reason) => refused.push((f.node_id, reason)),
        }
    }
    out.sort_unstable();
    out.dedup();
    refused.sort_unstable_by_key(|(id, _)| *id);
    refused.dedup_by_key(|(id, _)| *id);
    // A node that is eligible on one fact and refused on another is eligible;
    // reporting it as refused too would read as a contradiction in the log.
    refused.retain(|(id, _)| out.binary_search(id).is_err());
    (out, refused)
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
            endpoint: Some("node.example:8443".into()),
            first_seen_secs: NOW - 30 * DAY,
            last_seen_secs: NOW - 60,
        }
    }

    #[test]
    fn a_mature_node_that_opted_in_with_an_endpoint_is_eligible() {
        assert_eq!(check(&good(1), EligibilityPolicy::default(), NOW), Ok(()));
    }

    #[test]
    fn a_node_that_has_not_opted_in_is_never_conscripted() {
        let mut f = good(5);
        f.opted_in = false;
        assert_eq!(
            check(&f, EligibilityPolicy::default(), NOW),
            Err(Ineligible::NotOptedIn)
        );
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
        bad.endpoint = None;
        let roster = eligible_roster(&[good(1), bad, good(2)], p, NOW);
        assert_eq!(roster.len(), 2);
        assert!(!roster.contains(&[4u8; 32]));
    }

    // ── the refusals are the point ──

    /// The regression this exists to stop: `eligible_roster` computed a precise
    /// reason for every refusal and dropped it, so a node missing from a roster
    /// could not be told from one never heard of.
    #[test]
    fn every_refusal_is_reported_with_the_gate_that_refused_it() {
        let mut not_opted = good(2);
        not_opted.opted_in = false;
        let mut no_endpoint = good(3);
        no_endpoint.endpoint = None;
        let mut too_new = good(4);
        too_new.first_seen_secs = NOW - 60;
        let mut long_absent = good(5);
        long_absent.last_seen_secs = NOW - 30 * DAY;

        let facts = vec![good(1), not_opted, no_endpoint, too_new, long_absent];
        let (roster, refused) =
            eligible_roster_with_reasons(&facts, EligibilityPolicy::default(), NOW);

        assert_eq!(roster, vec![[1u8; 32]], "only the healthy node is eligible");
        let kinds: Vec<_> = refused.iter().map(|(_, why)| why.kind()).collect();
        assert_eq!(
            kinds,
            vec!["not_opted_in", "no_endpoint", "too_new", "long_absent"],
            "every gate names itself, and the refusals are sorted by node id"
        );
    }

    /// The numbers are what end an investigation, not just the tag.
    #[test]
    fn a_refusal_carries_the_measurement_behind_it() {
        let mut f = good(7);
        f.first_seen_secs = NOW - 3600;
        let (_, refused) = eligible_roster_with_reasons(&[f], EligibilityPolicy::default(), NOW);
        assert_eq!(
            refused[0].1,
            Ineligible::TooNew {
                known_secs: 3600,
                required_secs: 24 * 60 * 60
            },
            "it must say how long it HAS been known and what was required"
        );
    }

    /// `eligible_roster` is now a wrapper; it must not have drifted from the
    /// pair it delegates to.
    #[test]
    fn the_roster_only_wrapper_still_agrees_with_the_pair() {
        let mut bad = good(9);
        bad.opted_in = false;
        let facts = vec![good(8), bad, good(10)];
        let policy = EligibilityPolicy::default();
        assert_eq!(
            eligible_roster(&facts, policy, NOW),
            eligible_roster_with_reasons(&facts, policy, NOW).0
        );
    }

    /// A node that is eligible on one fact and refused on another is eligible.
    /// Reporting it in both lists would read as the endpoint contradicting
    /// itself.
    #[test]
    fn a_node_that_is_eligible_somewhere_is_never_also_listed_as_refused() {
        let mut stale = good(11);
        stale.opted_in = false;
        let facts = vec![stale, good(11)];
        let (roster, refused) =
            eligible_roster_with_reasons(&facts, EligibilityPolicy::default(), NOW);
        assert_eq!(roster, vec![[11u8; 32]]);
        assert!(refused.is_empty(), "got {refused:?}");
    }

    /// The tags are what a log filter greps, so they must survive rewording of
    /// the human text.
    #[test]
    fn the_reason_tags_are_stable() {
        assert_eq!(Ineligible::NotOptedIn.kind(), "not_opted_in");
        assert_eq!(Ineligible::NoEndpoint.kind(), "no_endpoint");
        assert_eq!(
            Ineligible::TooNew {
                known_secs: 1,
                required_secs: 2
            }
            .kind(),
            "too_new"
        );
        assert_eq!(
            Ineligible::LongAbsent {
                absent_secs: 1,
                limit_secs: 2
            }
            .kind(),
            "long_absent"
        );
    }
}
