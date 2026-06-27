//! Operational coordinator view — the seam between the pure election library and
//! live use (increment 4b, layer 1).
//!
//! A Ghost node and a wallet both build a [`CoordinatorView`] for an epoch from
//! the *same* agreed inputs (the beacon, the frozen qualified roster, and the
//! node→endpoint map), and get consistent answers to the two operational
//! questions the wiring needs:
//!
//! - **node**: "am I elected this epoch, and for which seat (shard)?" — so a node
//!   knows when to spin up its co-located coordinator and which sessions it owns.
//! - **wallet**: "which coordinator endpoint owns *my* session?" — so a wallet
//!   connects to the right node without trusting anyone to tell it.
//!
//! Because the underlying schedule is deterministic ([`EpochCoordinators`]), the
//! node and the wallet independently agree on who owns each session. This module
//! is still pure — the endpoint map and election inputs are passed in; populating
//! them from live consensus/discovery is the next layer.

use std::collections::BTreeMap;

use crate::epoch::EpochCoordinators;
use crate::sortition::CoordinatorNodeId;

/// Maps a coordinator node id to the base URL of its coordinator endpoint
/// (e.g. `https://node.example:9100`). Sourced from the node-discovery layer.
pub type EndpointMap = BTreeMap<CoordinatorNodeId, String>;

/// One seated coordinator with its reachable endpoint — the unit the read-only
/// status endpoint publishes and the wallet resolves against.
#[derive(Debug, Clone)]
pub struct SeatedCoordinator {
    /// The elected node's id.
    pub node_id: CoordinatorNodeId,
    /// Seat index `0..seats`; sessions shard onto seats via `shard_for`.
    pub seat: u32,
    /// The endpoint a wallet dials for this seat, or `None` if the owner hasn't
    /// advertised one yet (the wallet then waits or picks another epoch).
    pub endpoint: Option<String>,
}

/// The resolved coordinator assignment for one epoch, with endpoints attached.
#[derive(Debug, Clone)]
pub struct CoordinatorView {
    epoch: u64,
    coords: EpochCoordinators,
    endpoints: EndpointMap,
}

impl CoordinatorView {
    /// Wrap an already-computed schedule with an endpoint map.
    pub fn new(coords: EpochCoordinators, endpoints: EndpointMap) -> Self {
        Self {
            epoch: coords.epoch,
            coords,
            endpoints,
        }
    }

    /// Build directly from election inputs + endpoints.
    pub fn build(
        epoch: u64,
        beacon: &[u8; 32],
        qualified: &[CoordinatorNodeId],
        endpoints: EndpointMap,
        n: usize,
    ) -> Self {
        Self::new(
            EpochCoordinators::elect(epoch, beacon, qualified, n),
            endpoints,
        )
    }

    /// The epoch this view is for.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of coordinators seated this epoch.
    pub fn seats(&self) -> usize {
        self.coords.seats()
    }

    /// The seated coordinators in seat order, each with its advertised endpoint
    /// (`None` when the owner hasn't advertised one). Drives the read-only status
    /// endpoint and the wallet's "which endpoint owns my session" resolution.
    pub fn seated(&self) -> Vec<SeatedCoordinator> {
        let mut out: Vec<SeatedCoordinator> = self
            .coords
            .coordinators
            .iter()
            .map(|c| SeatedCoordinator {
                node_id: c.node_id,
                seat: c.seat,
                endpoint: self.endpoints.get(&c.node_id).cloned(),
            })
            .collect();
        out.sort_unstable_by_key(|s| s.seat);
        out
    }

    // ── node-side ────────────────────────────────────────────────────────────

    /// Whether `self_id` is elected a coordinator this epoch.
    pub fn am_i_coordinator(&self, self_id: &CoordinatorNodeId) -> bool {
        self.coords.is_coordinator(self_id)
    }

    /// If `self_id` is elected, the seat (shard) it must serve this epoch.
    pub fn my_seat(&self, self_id: &CoordinatorNodeId) -> Option<u32> {
        self.coords.seat_of(self_id)
    }

    /// Whether `self_id` owns `session_id` this epoch — the node's check for "is
    /// this session mine to coordinate?".
    pub fn owns_session(&self, self_id: &CoordinatorNodeId, session_id: &[u8; 32]) -> bool {
        self.coordinator_node_for_session(session_id).as_ref() == Some(self_id)
    }

    // ── wallet-side ──────────────────────────────────────────────────────────

    /// The coordinator *node* that owns `session_id` this epoch (`None` when no
    /// coordinators are seated).
    pub fn coordinator_node_for_session(&self, session_id: &[u8; 32]) -> Option<CoordinatorNodeId> {
        self.coords
            .coordinator_for_session(session_id)
            .map(|c| c.node_id)
    }

    /// The endpoint a wallet should connect to for `session_id`. `None` if no
    /// coordinator is seated, or the owning coordinator has no known endpoint
    /// (the wallet then waits for discovery to catch up, or picks another epoch).
    pub fn endpoint_for_session(&self, session_id: &[u8; 32]) -> Option<&str> {
        let node = self.coordinator_node_for_session(session_id)?;
        self.endpoints.get(&node).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn view(n: usize) -> (CoordinatorView, Vec<CoordinatorNodeId>) {
        let q = qualified(12);
        let v = CoordinatorView::build(3, &beacon(7), &q, endpoints(&q), n);
        (v, q)
    }

    #[test]
    fn node_knows_if_and_where_it_is_elected() {
        let (v, _q) = view(4);
        assert_eq!(v.seats(), 4);
        // exactly the seated nodes report a seat
        let seated: Vec<_> = (0..12u8)
            .map(node)
            .filter(|id| v.am_i_coordinator(id))
            .collect();
        assert_eq!(seated.len(), 4);
        for (expect_seat, id) in seated.iter().enumerate() {
            // my_seat agrees with am_i_coordinator
            assert!(v.my_seat(id).is_some());
            let _ = expect_seat;
        }
        // a non-roster node is never elected
        assert!(!v.am_i_coordinator(&node(200)));
        assert_eq!(v.my_seat(&node(200)), None);
    }

    #[test]
    fn wallet_resolves_a_real_endpoint_for_every_session() {
        let (v, _q) = view(5);
        for i in 0u32..400 {
            let mut sid = [0u8; 32];
            sid[..4].copy_from_slice(&i.to_le_bytes());
            let ep = v
                .endpoint_for_session(&sid)
                .expect("an endpoint for every session");
            assert!(ep.starts_with("https://node"));
        }
    }

    #[test]
    fn node_and_wallet_agree_on_the_owner() {
        let (v, _q) = view(5);
        for i in 0u32..200 {
            let mut sid = [0u8; 32];
            sid[..4].copy_from_slice(&i.to_le_bytes());
            let owner = v.coordinator_node_for_session(&sid).unwrap();
            // the node that owns it agrees it owns it
            assert!(v.owns_session(&owner, &sid));
            // and no other seated node claims it
            for other in (0..12u8).map(node).filter(|x| *x != owner) {
                assert!(!v.owns_session(&other, &sid));
            }
        }
    }

    #[test]
    fn missing_endpoint_yields_none_but_owner_still_known() {
        let q = qualified(12);
        // endpoints for everyone EXCEPT whoever ends up owning session 0
        let mut eps = endpoints(&q);
        let v_full = CoordinatorView::build(3, &beacon(7), &q, eps.clone(), 5);
        let sid = [0u8; 32];
        let owner = v_full.coordinator_node_for_session(&sid).unwrap();
        eps.remove(&owner);
        let v = CoordinatorView::build(3, &beacon(7), &q, eps, 5);
        // owner still known…
        assert_eq!(v.coordinator_node_for_session(&sid), Some(owner));
        // …but no endpoint to dial
        assert_eq!(v.endpoint_for_session(&sid), None);
    }

    #[test]
    fn empty_roster_seats_nobody() {
        let v = CoordinatorView::build(1, &beacon(1), &[], EndpointMap::new(), 4);
        assert_eq!(v.seats(), 0);
        assert!(!v.am_i_coordinator(&node(0)));
        assert_eq!(v.endpoint_for_session(&[9u8; 32]), None);
    }

    #[test]
    fn seated_lists_every_seat_with_its_endpoint_in_order() {
        let (v, _q) = view(5);
        let seated = v.seated();
        assert_eq!(seated.len(), 5);
        for (i, s) in seated.iter().enumerate() {
            assert_eq!(s.seat as usize, i, "seats must be 0..n in order");
            assert!(s
                .endpoint
                .as_deref()
                .expect("every seated coordinator has an endpoint here")
                .starts_with("https://node"));
        }
    }

    #[test]
    fn seated_endpoint_is_none_when_owner_has_not_advertised() {
        let q = qualified(12);
        let mut eps = endpoints(&q);
        let full = CoordinatorView::build(3, &beacon(7), &q, eps.clone(), 5);
        let owner = full.seated()[0].node_id;
        eps.remove(&owner);
        let v = CoordinatorView::build(3, &beacon(7), &q, eps, 5);
        // Still seated (owner known) but no endpoint to dial.
        assert_eq!(v.seated()[0].node_id, owner);
        assert_eq!(v.seated()[0].endpoint, None);
    }
}
