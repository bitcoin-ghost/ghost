//! Operational coordinator view — the seam between the pure election library and
//! live use (increment 4b, layer 1).
//!
//! A Ghost node and a wallet both build a [`CoordinatorView`] for an epoch from
//! the *same* agreed inputs (the beacon, the roster, and the node→endpoint map),
//! and get consistent answers to the two operational questions the wiring needs:
//!
//! - **node**: "do I run a coordinator this epoch, and which tiers do I lead?"
//! - **wallet**: "which endpoints do I dial for my tier, and in what order?" — so
//!   a wallet connects to the right node without trusting anyone to tell it.
//!
//! Because the underlying schedule is deterministic ([`EpochCoordinators`]), the
//! node and the wallet independently agree on who leads each tier. This module
//! is still pure — the endpoint map and election inputs are passed in.

use std::collections::BTreeMap;

use crate::epoch::EpochCoordinators;
use crate::sortition::{CoordinatorNodeId, TierLeadership};

/// Maps a coordinator node id to the base URL of its coordinator endpoint
/// (e.g. `https://node.example:9100`). Sourced from the node-discovery layer.
pub type EndpointMap = BTreeMap<CoordinatorNodeId, String>;

/// One roster node as the status endpoint publishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingCoordinator {
    /// The node's id.
    pub node_id: CoordinatorNodeId,
    /// Where a wallet dials it, or `None` if it has not advertised yet.
    pub endpoint: Option<String>,
    /// The tiers it leads this epoch. Empty for a node that is only on the
    /// failover path, which still runs its coordinator.
    pub leads: Vec<String>,
}

/// The resolved coordinator assignment for one epoch, with endpoints attached.
#[derive(Debug, Clone)]
pub struct CoordinatorView {
    coords: EpochCoordinators,
    endpoints: EndpointMap,
}

impl CoordinatorView {
    /// Wrap an already-computed schedule with an endpoint map.
    pub fn new(coords: EpochCoordinators, endpoints: EndpointMap) -> Self {
        Self { coords, endpoints }
    }

    /// Build directly from election inputs + endpoints.
    pub fn build(
        epoch: u64,
        beacon: &[u8; 32],
        roster: &[CoordinatorNodeId],
        endpoints: EndpointMap,
    ) -> Self {
        Self::new(EpochCoordinators::elect(epoch, beacon, roster), endpoints)
    }

    /// The epoch this view is for.
    pub fn epoch(&self) -> u64 {
        self.coords.epoch
    }

    /// Every tier's leader and failover order, in `LiteTier::all` order.
    pub fn tiers(&self) -> &[TierLeadership] {
        &self.coords.tiers
    }

    /// Every roster node, in canonical order, with its endpoint and the tiers
    /// it leads. Drives the read-only status endpoint.
    pub fn serving(&self) -> Vec<ServingCoordinator> {
        self.coords
            .roster
            .iter()
            .map(|id| ServingCoordinator {
                node_id: *id,
                endpoint: self.endpoints.get(id).cloned(),
                leads: self
                    .coords
                    .tiers_led_by(id)
                    .into_iter()
                    .map(String::from)
                    .collect(),
            })
            .collect()
    }

    // ── node-side ────────────────────────────────────────────────────────────

    /// Whether `self_id` should run a coordinator this epoch — true for every
    /// roster node, leading or not, because the rest are the failover path.
    pub fn serves(&self, self_id: &CoordinatorNodeId) -> bool {
        self.coords.is_coordinator(self_id)
    }

    /// The tiers `self_id` leads this epoch.
    pub fn tiers_led_by(&self, self_id: &CoordinatorNodeId) -> Vec<&str> {
        self.coords.tiers_led_by(self_id)
    }

    /// Whether `self_id` leads `tier_id` this epoch — the node's check for "are
    /// these sessions mine to coordinate?".
    pub fn owns_tier(&self, self_id: &CoordinatorNodeId, tier_id: &str) -> bool {
        self.coordinator_node_for_tier(tier_id).as_ref() == Some(self_id)
    }

    // ── wallet-side ──────────────────────────────────────────────────────────

    /// The node that leads `tier_id` this epoch (`None` for an empty roster).
    pub fn coordinator_node_for_tier(&self, tier_id: &str) -> Option<CoordinatorNodeId> {
        self.coords.coordinator_for_tier(tier_id).copied()
    }

    /// The leader's endpoint for `tier_id`. `None` if nobody leads it, or the
    /// leader has not advertised one.
    pub fn endpoint_for_tier(&self, tier_id: &str) -> Option<&str> {
        let node = self.coordinator_node_for_tier(tier_id)?;
        self.endpoints.get(&node).map(String::as_str)
    }

    /// The endpoints to try for `tier_id`, leader first, in the tier's failover
    /// order. Nodes that have advertised no endpoint are skipped rather than
    /// holding a place: a node nobody can dial is not a fallback.
    pub fn endpoints_for_tier(&self, tier_id: &str) -> Vec<&str> {
        self.coords
            .for_tier(tier_id)
            .map(|t| {
                t.order
                    .iter()
                    .filter_map(|id| self.endpoints.get(id).map(String::as_str))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIERS: [&str; 4] = ["100k_sats", "1m_sats", "10m_sats", "100m_sats"];

    fn node(i: u8) -> CoordinatorNodeId {
        let mut id = [0u8; 32];
        id[0] = i;
        id[1] = i.wrapping_mul(5);
        id
    }
    fn beacon(s: u8) -> [u8; 32] {
        [s; 32]
    }
    fn qualified(k: u8) -> Vec<CoordinatorNodeId> {
        (0..k).map(node).collect()
    }
    fn endpoints(q: &[CoordinatorNodeId]) -> EndpointMap {
        q.iter()
            .enumerate()
            .map(|(i, id)| (*id, format!("https://node{i}:9100")))
            .collect()
    }

    fn view() -> (CoordinatorView, Vec<CoordinatorNodeId>) {
        let q = qualified(12);
        let v = CoordinatorView::build(3, &beacon(7), &q, endpoints(&q));
        (v, q)
    }

    #[test]
    fn a_node_knows_it_serves_and_which_tiers_it_leads() {
        let (v, q) = view();
        let leaders: Vec<_> = q
            .iter()
            .filter(|id| !v.tiers_led_by(id).is_empty())
            .collect();
        assert_eq!(leaders.len(), TIERS.len(), "four different leaders");
        for id in &q {
            assert!(v.serves(id), "every roster node serves");
        }
        assert!(!v.serves(&node(200)));
        assert!(v.tiers_led_by(&node(200)).is_empty());
    }

    #[test]
    fn wallet_resolves_a_real_endpoint_for_every_tier() {
        let (v, _q) = view();
        for tier in TIERS {
            let ep = v
                .endpoint_for_tier(tier)
                .expect("an endpoint for every tier");
            assert!(ep.starts_with("https://node"));
            assert_eq!(
                v.endpoints_for_tier(tier)[0],
                ep,
                "the leader is tried first"
            );
        }
    }

    /// The node's "is this mine?" answer and the wallet's "who do I dial?"
    /// answer are the same function, so they cannot disagree.
    #[test]
    fn node_and_wallet_agree_on_the_owner() {
        let (v, _q) = view();
        for tier in TIERS {
            let owner = v.coordinator_node_for_tier(tier).unwrap();
            assert!(v.owns_tier(&owner, tier));
            for other in (0..12u8).map(node).filter(|x| *x != owner) {
                assert!(!v.owns_tier(&other, tier));
            }
        }
    }

    #[test]
    fn missing_endpoint_yields_none_but_owner_still_known() {
        let q = qualified(12);
        let mut eps = endpoints(&q);
        let full = CoordinatorView::build(3, &beacon(7), &q, eps.clone());
        let owner = full.coordinator_node_for_tier("100k_sats").unwrap();
        eps.remove(&owner);
        let v = CoordinatorView::build(3, &beacon(7), &q, eps);
        assert_eq!(v.coordinator_node_for_tier("100k_sats"), Some(owner));
        assert_eq!(v.endpoint_for_tier("100k_sats"), None);
        // …and the wallet walks straight to the next node that can be dialled.
        let tried = v.endpoints_for_tier("100k_sats");
        assert_eq!(tried.len(), q.len() - 1);
        assert_eq!(tried, full.endpoints_for_tier("100k_sats")[1..]);
    }

    #[test]
    fn empty_roster_serves_nobody() {
        let v = CoordinatorView::build(1, &beacon(1), &[], EndpointMap::new());
        assert!(!v.serves(&node(0)));
        assert_eq!(v.endpoint_for_tier("100k_sats"), None);
        assert!(v.endpoints_for_tier("100k_sats").is_empty());
        assert!(v.serving().is_empty());
    }

    #[test]
    fn serving_lists_every_roster_node_with_what_it_leads() {
        let (v, q) = view();
        let serving = v.serving();
        assert_eq!(serving.len(), q.len());
        let led: usize = serving.iter().map(|s| s.leads.len()).sum();
        assert_eq!(led, TIERS.len(), "each tier is led exactly once");
        for s in &serving {
            assert!(s.endpoint.as_deref().unwrap().starts_with("https://node"));
            assert_eq!(s.leads, v.tiers_led_by(&s.node_id));
        }
    }
}
