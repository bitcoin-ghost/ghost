//! Decentralised Wraith coordinator election — live wiring (read-only).
//!
//! Increment 4 of `tasks/plan_decentralised_coordinators.md`: feed the PURE
//! election library (`wraith_protocol::{sortition, epoch, service}`) with live
//! node state (the elder roster, the chain height, and a per-epoch beacon
//! anchor) and expose the resulting `CoordinatorView` read-only.
//!
//! ## What this increment deliberately does NOT do
//!
//! It computes and *publishes* the election only. It NEVER:
//! - activates a coordinator role (no node starts coordinating anything here),
//! - touches `coordinator_redundancy` or any Wraith mixing,
//! - emits or changes any consensus message.
//!
//! It is gated behind `[coordinator] wraith_election_enabled` (default false).
//! When the flag is off the `CoordinatorElection` is never constructed and
//! every accessor returns the inert "disabled" answer, so worst case this is
//! dead code behind a default-false flag with zero effect on the node.
//!
//! ## Determinism
//!
//! All three election inputs are derived from state the network already agrees
//! on (the elder set, the chain height, and a chain anchor hash), then passed
//! through the deterministic library so a node and a wallet independently
//! compute the byte-identical schedule. The roster is canonicalised
//! (`epoch::canonical_roster`) before election so the result is independent of
//! the order peers were collected in.

use std::sync::Arc;

use parking_lot::RwLock;

use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::NodeCapabilities;
use ghost_consensus::mesh::MeshNetwork;

use wraith_protocol::epoch::canonical_roster;
use wraith_protocol::roster_snapshot::roster_commitment;
use wraith_protocol::service::{CoordinatorView, EndpointMap};
use wraith_protocol::sortition::CoordinatorNodeId;

/// Blocks per coordinator epoch — `epoch = height / COORDINATOR_EPOCH_BLOCKS`.
/// ~1 day at 10-minute blocks. The draw is reshuffled every epoch, so
/// coordination rotates across the qualified set over time.
///
/// This is `wraith_protocol::EPOCH_BLOCKS`, not a local copy. It used to be
/// kept local "so the live cadence is owned and tuneable at the wiring layer"
/// — which cannot be true of a value a *wallet* has to agree on. A wallet
/// derives the anchor height from the epoch to check the beacon against the
/// chain; tune this at the wiring layer and every wallet would compute a
/// different anchor and reject every election.
pub const COORDINATOR_EPOCH_BLOCKS: u64 = wraith_protocol::EPOCH_BLOCKS;

/// Below this many opted-in candidates, the election is reported as
/// `degraded`: the draw still runs and still seats someone, but with one or
/// two candidates it cannot deliver rotation or resistance to
/// self-nomination, and saying so is better than publishing a seat list that
/// looks like an election.
pub const MIN_MEANINGFUL_ROSTER: usize = 3;

/// Whether an election drawn from `roster_size` candidates should be reported
/// as degraded. Two candidates still cannot resist a self-nominating
/// operator — controlling one of two is controlling half the draw.
pub fn roster_is_degraded(roster_size: usize) -> bool {
    roster_size < MIN_MEANINGFUL_ROSTER
}

/// Target number of concurrent coordinator seats per epoch. Sessions are
/// sharded across these seats so no single coordinator owns every round.
/// (Demand-driven sizing replaces this fixed target in a later increment.)
pub const COORDINATOR_SEATS: usize = 5;

/// Freshness window for an advertised coordinator endpoint: a peer must have
/// pinged within this window to be electable, since a stale endpoint a wallet
/// can't reach is worse than not seating it. ~5 min, matching the mesh
/// active-miner freshness.
const COORDINATOR_PEER_FRESHNESS_SECS: u64 = 300;

/// Demand-driven seat sizing. Recent mixing sessions per seat before another
/// seat is added; minimum seats whenever any coordinator is eligible (so there
/// is always at least one, for liveness); and a hard ceiling. All tunable.
const TARGET_SESSIONS_PER_SEAT: u64 = 50;
const MIN_SEATS: usize = 1;
const MAX_SEATS: usize = 16;

/// Size the coordinator seat count for an epoch from the frozen, mesh-summed
/// recent session `demand` and the number of `eligible` coordinators.
///
/// `ceil(demand / TARGET_SESSIONS_PER_SEAT)`, floored at `MIN_SEATS` and capped
/// by both `MAX_SEATS` and the eligible set (can't seat more coordinators than
/// exist). Coarse buckets (one seat per `TARGET_SESSIONS_PER_SEAT`) make the
/// result robust to small per-node differences in the demand snapshot: nodes
/// only disagree on the count near a bucket edge, and even then the only cost is
/// a briefly-suboptimal session spread, never a safety issue (the CoinJoin is
/// atomic + blind-signed whichever seat runs it). Pure + deterministic so every
/// node computes the same seats from the same frozen inputs.
pub fn seats_for_demand(demand: u64, eligible: usize) -> usize {
    if eligible == 0 {
        return 0;
    }
    let by_demand = (demand.div_ceil(TARGET_SESSIONS_PER_SEAT) as usize).max(MIN_SEATS);
    by_demand.min(MAX_SEATS).min(eligible)
}

/// The coordinator epoch a chain height falls in.
pub const fn epoch_for_height(height: u64) -> u64 {
    height / COORDINATOR_EPOCH_BLOCKS
}

/// The chain height whose hash anchors epoch `E`'s beacon: the **last block of
/// epoch `E-1`**, per `wraith_protocol::epoch::snapshot_height_for_epoch`.
///
/// This used to be the *first* block of epoch `E`, which is a different block.
/// The library documents the anchor as freezing the epoch's inputs "before `E`
/// begins … no mid-epoch surprises", and anchoring on `E`'s own first block
/// defeats exactly that: the coordinators for an epoch were not knowable until
/// the epoch had already started. Two definitions of one protocol quantity is
/// also how the seat price came to disagree with itself (#698), so there is
/// now one, in the library.
pub const fn anchor_height_for_epoch(epoch: u64) -> u64 {
    wraith_protocol::snapshot_height_for_epoch(epoch)
}

/// Re-exported so the wiring layer and its tests use the same derivation a
/// wallet does. Defined in `wraith_protocol::epoch`.
pub use wraith_protocol::derive_beacon;

/// Decode a Bitcoin block-hash hex string into the 32-byte anchor used by the
/// beacon. Returns `None` for malformed input (the caller then skips the
/// recompute and keeps the last good view).
fn anchor_from_block_hash_hex(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut anchor = [0u8; 32];
    anchor.copy_from_slice(&bytes);
    Some(anchor)
}

/// The serialised, cached state for the current epoch — what the read-only
/// endpoint reports. `None` until the first successful recompute.
#[derive(Debug, Clone)]
struct Cached {
    epoch: u64,
    view: CoordinatorView,
    /// The beacon the draw was made with, and the roster it drew from.
    ///
    /// Published alongside the result so a wallet can recompute the election
    /// and check it (`sortition::verify_election`) rather than believing the
    /// seat list it is handed. Without these two the draw is unfalsifiable:
    /// anyone relaying the view could seat whoever they liked (#697).
    beacon: [u8; 32],
    roster: Vec<CoordinatorNodeId>,
    /// Height of the block whose hash the beacon is derived from, so the
    /// beacon itself can be re-derived straight from the chain.
    anchor_height: u64,
    /// Commitment to `(epoch, anchor_height, roster)`, published so two nodes
    /// can be compared and a split *seen* rather than inferred later from
    /// sessions that went to two owners.
    ///
    /// The anchor height identifies the epoch's frozen chain input. It is
    /// deliberately **not** a claim that the roster was read at that height —
    /// the roster comes from live mesh state, which is the defect this value
    /// exposes rather than repairs.
    roster_commitment: [u8; 32],
}

/// Live coordinator-election service for ghost-pool.
///
/// Constructed only when `wraith_election_enabled` is true. Holds the inputs it
/// needs to (re)compute a `CoordinatorView` each time the epoch changes, and
/// caches the latest view for the read-only accessors and the HTTP endpoint.
pub struct CoordinatorElection {
    /// This node's own id. `[u8; 32]`, matches `wraith_protocol`'s
    /// `CoordinatorNodeId`.
    self_id: CoordinatorNodeId,
    /// Whether THIS node opted in as a coordinator (`NodeCapabilities.coordinator`,
    /// the same opt-in model as `public_mining`). Only opted-in nodes that also
    /// advertise an endpoint enter the roster.
    self_coordinator: bool,
    /// This node's own advertised coordinator endpoint (public `host:port` or a
    /// `.onion`). Included in the roster + endpoint map only when
    /// `self_coordinator` and non-empty.
    self_endpoint: Option<String>,
    /// Mesh handle — source of the opted-in coordinator peers + their endpoints.
    mesh: Arc<MeshNetwork>,
    /// Ghost Core RPC — source of the beacon anchor (block hash at a height).
    rpc: Arc<BitcoinRpc>,
    /// Cached current-epoch view.
    cached: RwLock<Option<Cached>>,
}

impl CoordinatorElection {
    /// Build the service from live handles. Call only when the config flag is
    /// on; see `maybe_new`.
    pub fn new(
        identity: &NodeIdentity,
        capabilities: &NodeCapabilities,
        self_endpoint: Option<String>,
        mesh: Arc<MeshNetwork>,
        rpc: Arc<BitcoinRpc>,
    ) -> Self {
        Self {
            self_id: identity.node_id(),
            self_coordinator: capabilities.coordinator,
            self_endpoint,
            mesh,
            rpc,
            cached: RwLock::new(None),
        }
    }

    /// Construct the service iff `enabled`, else `None` (gated-off path). When
    /// `None`, nothing else in this module runs — zero effect on the node.
    pub fn maybe_new(
        enabled: bool,
        identity: &NodeIdentity,
        capabilities: &NodeCapabilities,
        self_endpoint: Option<String>,
        mesh: Arc<MeshNetwork>,
        rpc: Arc<BitcoinRpc>,
    ) -> Option<Arc<Self>> {
        if !enabled {
            return None;
        }
        Some(Arc::new(Self::new(
            identity,
            capabilities,
            self_endpoint,
            mesh,
            rpc,
        )))
    }

    /// The opted-in, reachable coordinator roster for this epoch, plus the
    /// endpoint map. A peer is eligible iff it (a) advertises the `coordinator`
    /// capability AND (b) advertised a non-empty endpoint in a recent health
    /// ping (so a wallet can actually dial it). Self is included iff it opted in
    /// and has its own advertised endpoint. The roster is canonicalised (dedup +
    /// sort), so a node's own collection order cannot change the result.
    ///
    /// # This does NOT make nodes agree
    ///
    /// It used to claim every node derives "the byte-identical set + map from
    /// the same mesh membership". Mesh membership is not shared state.
    /// `get_connected_peers` filters on `p.state == Connected` — *this node's*
    /// connection state — and on `p.last_seen >= now - 300` against *this
    /// node's* clock. A peer connected to us and not to a sibling is in our
    /// roster alone; a peer whose last ping landed around 300 seconds ago is in
    /// whichever nodes' rosters their clocks happen to place it in.
    ///
    /// So divergence here is the normal case, not a boundary edge case, and
    /// canonicalisation cannot fix it: it makes one node's answer
    /// order-independent, not two nodes' answers equal.
    ///
    /// `Cached::roster_commitment` therefore exists so the disagreement is
    /// *visible* across the fleet. See `roster_snapshot` for why this must be
    /// resolved before `wraith_election_enabled` is ever turned on.
    /// Returns the canonical roster, the endpoint map, and the summed recent
    /// session `demand` across the eligible set (incl. self) — the frozen input
    /// to [`seats_for_demand`].
    fn roster_with_endpoints(&self) -> (Vec<CoordinatorNodeId>, EndpointMap, u64) {
        let mut endpoints = EndpointMap::new();
        let mut ids: Vec<CoordinatorNodeId> = Vec::new();
        let mut demand: u64 = 0;
        for p in self
            .mesh
            .peers()
            .get_connected_peers(COORDINATOR_PEER_FRESHNESS_SECS)
        {
            if !p.capabilities.coordinator {
                continue;
            }
            let sessions = p.coordinator_sessions;
            if let Some(ep) = p.coordinator_endpoint.filter(|e| !e.is_empty()) {
                endpoints.insert(p.node_id, ep);
                ids.push(p.node_id);
                demand = demand.saturating_add(sessions as u64);
            }
        }
        if self.self_coordinator {
            if let Some(ep) = self.self_endpoint.as_deref().filter(|e| !e.is_empty()) {
                endpoints.insert(self.self_id, ep.to_string());
                ids.push(self.self_id);
                demand = demand.saturating_add(self.mesh.coordinator_sessions() as u64);
            }
        }
        (canonical_roster(&ids), endpoints, demand)
    }

    /// Fetch the beacon for `epoch` by anchoring on the epoch-start block hash
    /// from Ghost Core. Returns `None` if the anchor height isn't available yet
    /// (chain not that tall) or the RPC/decode fails — the caller keeps the
    /// previous cached view in that case.
    async fn beacon_for_epoch(&self, epoch: u64) -> Option<[u8; 32]> {
        let anchor_height = anchor_height_for_epoch(epoch);
        let hex_hash = self.rpc.get_block_hash(anchor_height).await.ok()?;
        let anchor = anchor_from_block_hash_hex(&hex_hash)?;
        Some(derive_beacon(epoch, &anchor))
    }

    /// Recompute and cache the `CoordinatorView` for the epoch `current_height`
    /// falls in — but only when the epoch has actually changed since the last
    /// cached view (cheap no-op otherwise). Safe to call on every new block /
    /// round advance. Returns the (possibly unchanged) current epoch.
    ///
    /// On any input failure (no anchor block yet, RPC error) it leaves the
    /// existing cache untouched and returns the current epoch unchanged — never
    /// poisons the cache with a partial view.
    pub async fn refresh_for_height(&self, current_height: u64) -> u64 {
        let epoch = epoch_for_height(current_height);

        // Fast path: same epoch as the cached view → nothing to do.
        if let Some(c) = self.cached.read().as_ref() {
            if c.epoch == epoch {
                return epoch;
            }
        }

        let Some(beacon) = self.beacon_for_epoch(epoch).await else {
            // Anchor not reachable yet — keep the last good view.
            return epoch;
        };
        // Roster = opted-in coordinators advertising a reachable endpoint (+ self
        // when opted in), with the endpoint map a wallet uses to dial the owner.
        // Seats are sized from the frozen, mesh-summed recent session demand —
        // this recompute only runs when the epoch flips, so the snapshot is the
        // per-epoch freeze.
        let (roster, endpoints, demand) = self.roster_with_endpoints();
        let seats = seats_for_demand(demand, roster.len());
        let view = CoordinatorView::build(epoch, &beacon, &roster, endpoints, seats);
        let anchor_height = anchor_height_for_epoch(epoch);
        let commitment = roster_commitment(epoch, anchor_height, &roster);
        *self.cached.write() = Some(Cached {
            epoch,
            view,
            beacon,
            roster,
            anchor_height,
            roster_commitment: commitment,
        });
        epoch
    }

    /// Whether THIS node is an elected coordinator in the currently-cached
    /// epoch. `false` before the first successful recompute. Read-only — this
    /// does NOT activate any coordinator behaviour, it only reports the draw.
    pub fn am_i_coordinator(&self) -> bool {
        self.cached
            .read()
            .as_ref()
            .map(|c| c.view.am_i_coordinator(&self.self_id))
            .unwrap_or(false)
    }

    /// A JSON snapshot of the cached election for the read-only HTTP endpoint:
    /// `{enabled, roster_commitment, epoch, seats, my_seat, elected: [hex ids],
    /// [{node_id, seat, endpoint}]}`. The `coordinators` array is what a wallet
    /// reads to dial the seat that owns its session; `elected` is kept as the
    /// flat hex list for existing consumers. Pre-serialised so
    /// `ghost-verification` needn't depend on `wraith-protocol`.
    pub fn status_json(&self) -> serde_json::Value {
        let guard = self.cached.read();
        let Some(c) = guard.as_ref() else {
            // Service is on but hasn't computed a view yet (e.g. anchor block
            // not reachable). Report enabled-but-pending rather than failing.
            return serde_json::json!({
                "enabled": true,
                "epoch": serde_json::Value::Null,
                "seats": 0,
                "my_seat": serde_json::Value::Null,
                "elected": [],
                "coordinators": [],
                "beacon": serde_json::Value::Null,
                "anchor_height": serde_json::Value::Null,
                "roster": [],
                "roster_size": 0,
                "roster_commitment": serde_json::Value::Null,
                "degraded": true,
            });
        };

        let seated = c.view.seated();
        let elected: Vec<String> = seated.iter().map(|s| hex::encode(s.node_id)).collect();
        let coordinators: Vec<serde_json::Value> = seated
            .iter()
            .map(|s| {
                serde_json::json!({
                    "node_id": hex::encode(s.node_id),
                    "seat": s.seat,
                    "rank": hex::encode(s.rank),
                    "endpoint": s.endpoint,
                })
            })
            .collect();
        serde_json::json!({
            "enabled": true,
            // Compare this across nodes: equal means they drew from the same
            // roster, unequal means the coordinator layer has split. It is the
            // only field here that a single node cannot self-check.
            "roster_commitment": hex::encode(c.roster_commitment),
            "epoch": c.view.epoch(),
            "seats": c.view.seats(),
            "my_seat": c.view.my_seat(&self.self_id),
            "elected": elected,
            "coordinators": coordinators,
            // The draw's inputs, so a consumer can recompute it rather than
            // trust it (#697). `beacon` is SHA256(domain ‖ epoch ‖ anchor
            // hash), and `anchor_height` names the block that anchor comes
            // from — so the beacon is re-derivable straight from the chain
            // and a publisher cannot invent one.
            "beacon": hex::encode(c.beacon),
            "anchor_height": c.anchor_height,
            "roster": c.roster.iter().map(hex::encode).collect::<Vec<_>>(),
            // A draw over one candidate is not a draw. Reported so a reader
            // cannot mistake a single opted-in node for an election that
            // rotated, and so "no single party is the operator" is checkable
            // rather than assumed (#708).
            "roster_size": c.roster.len(),
            "degraded": roster_is_degraded(c.roster.len()),
        })
    }
}

/// The JSON returned for the read-only endpoint when the feature is OFF (the
/// service was never constructed). Centralised so the route and tests agree.
pub fn disabled_status_json() -> serde_json::Value {
    serde_json::json!({ "enabled": false })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(i: u8) -> CoordinatorNodeId {
        let mut id = [0u8; 32];
        id[0] = i;
        id[1] = i.wrapping_mul(7);
        id
    }

    // The pure-library glue is exercised directly via CoordinatorView::build so
    // the unit tests don't need a live mesh/RPC. The wiring-specific logic under
    // test here is: epoch maths, beacon derivation, the disabled path, and the
    // hex/seat reporting shape.

    /// A roster of one is not an election, and the view says so. Filed as
    /// #708 after the live fleet turned out to have exactly that.
    #[test]
    fn a_thin_roster_is_reported_as_degraded() {
        // Nobody opted in, or one node did: no draw happened.
        assert!(roster_is_degraded(0));
        assert!(roster_is_degraded(1), "one candidate cannot rotate");
        // Two is still not enough: controlling one is half the draw.
        assert!(roster_is_degraded(2));
        // Three upwards is a real draw.
        assert!(!roster_is_degraded(3));
        assert!(!roster_is_degraded(20));
    }

    #[test]
    fn epoch_and_anchor_height_maths() {
        assert_eq!(epoch_for_height(0), 0);
        assert_eq!(epoch_for_height(COORDINATOR_EPOCH_BLOCKS - 1), 0);
        assert_eq!(epoch_for_height(COORDINATOR_EPOCH_BLOCKS), 1);
        assert_eq!(epoch_for_height(COORDINATOR_EPOCH_BLOCKS * 9 + 7), 9);

        // The anchor is the LAST block of the previous epoch, so an epoch's
        // inputs are frozen before it begins. This used to be the first block
        // of the epoch itself — a different block, and one that could not be
        // known until the epoch had already started.
        assert_eq!(anchor_height_for_epoch(0), 0);
        assert_eq!(anchor_height_for_epoch(1), COORDINATOR_EPOCH_BLOCKS - 1);
        assert_eq!(anchor_height_for_epoch(5), 5 * COORDINATOR_EPOCH_BLOCKS - 1);
        // It is the library's definition, not a second copy of it.
        for e in [0u64, 1, 5, 6689] {
            assert_eq!(
                anchor_height_for_epoch(e),
                wraith_protocol::snapshot_height_for_epoch(e)
            );
        }
    }

    #[test]
    fn beacon_is_deterministic_and_epoch_bound() {
        let anchor = [42u8; 32];
        // Same inputs → same beacon (determinism).
        assert_eq!(derive_beacon(7, &anchor), derive_beacon(7, &anchor));
        // A different epoch → a different beacon (rotation).
        assert_ne!(derive_beacon(7, &anchor), derive_beacon(8, &anchor));
        // A different anchor → a different beacon (anchored).
        assert_ne!(derive_beacon(7, &anchor), derive_beacon(7, &[43u8; 32]));
    }

    #[test]
    fn anchor_decode_rejects_bad_lengths() {
        assert!(anchor_from_block_hash_hex(&"ab".repeat(32)).is_some());
        assert!(anchor_from_block_hash_hex("not-hex").is_none());
        assert!(anchor_from_block_hash_hex(&"ab".repeat(16)).is_none()); // 16 bytes
        assert!(anchor_from_block_hash_hex(&"ab".repeat(33)).is_none()); // 33 bytes
    }

    #[test]
    fn disabled_status_is_inert() {
        let j = disabled_status_json();
        assert_eq!(j["enabled"], serde_json::json!(false));
        // Nothing else is leaked when off.
        assert_eq!(j.as_object().unwrap().len(), 1);
    }

    // ── election-through-the-view tests (the library + our reporting shape) ──

    #[test]
    fn election_is_deterministic_for_fixed_inputs() {
        let roster: Vec<_> = (0u8..12).map(node).collect();
        let beacon = derive_beacon(3, &[1u8; 32]);
        let a = CoordinatorView::build(3, &beacon, &roster, EndpointMap::new(), COORDINATOR_SEATS);
        let b = CoordinatorView::build(3, &beacon, &roster, EndpointMap::new(), COORDINATOR_SEATS);
        // Same inputs → identical seating.
        assert_eq!(a.seats(), b.seats());
        assert_eq!(a.seats(), COORDINATOR_SEATS);
        for id in &roster {
            assert_eq!(a.my_seat(id), b.my_seat(id));
            assert_eq!(a.am_i_coordinator(id), b.am_i_coordinator(id));
        }
    }

    #[test]
    fn epoch_advancement_changes_the_view() {
        let roster: Vec<_> = (0u8..20).map(node).collect();
        let anchor = [9u8; 32];
        let v_e3 = CoordinatorView::build(
            3,
            &derive_beacon(3, &anchor),
            &roster,
            EndpointMap::new(),
            COORDINATOR_SEATS,
        );
        let v_e4 = CoordinatorView::build(
            4,
            &derive_beacon(4, &anchor),
            &roster,
            EndpointMap::new(),
            COORDINATOR_SEATS,
        );
        let seated = |v: &CoordinatorView| -> Vec<CoordinatorNodeId> {
            roster
                .iter()
                .copied()
                .filter(|id| v.am_i_coordinator(id))
                .collect()
        };
        assert_ne!(
            seated(&v_e3),
            seated(&v_e4),
            "a new epoch must reshuffle the coordinator set"
        );
    }

    #[test]
    fn self_as_coordinator_detection_matches_the_view() {
        let roster: Vec<_> = (0u8..30).map(node).collect();
        let beacon = derive_beacon(2, &[5u8; 32]);
        let view =
            CoordinatorView::build(2, &beacon, &roster, EndpointMap::new(), COORDINATOR_SEATS);
        // For every roster member, am_i_coordinator agrees with my_seat.is_some.
        let mut seated_count = 0;
        for id in &roster {
            let is_coord = view.am_i_coordinator(id);
            assert_eq!(is_coord, view.my_seat(id).is_some());
            if is_coord {
                seated_count += 1;
            }
        }
        assert_eq!(seated_count, COORDINATOR_SEATS);
        // A node not in the roster is never seated.
        assert!(!view.am_i_coordinator(&node(200)));
    }

    #[test]
    fn empty_roster_seats_nobody() {
        let beacon = derive_beacon(1, &[0u8; 32]);
        let view = CoordinatorView::build(1, &beacon, &[], EndpointMap::new(), COORDINATOR_SEATS);
        assert_eq!(view.seats(), 0);
        assert!(!view.am_i_coordinator(&node(0)));
    }

    #[test]
    fn seats_scale_with_demand_and_clamp() {
        // No eligible coordinators → no seats, regardless of demand.
        assert_eq!(seats_for_demand(1000, 0), 0);
        // Any eligibility floors at MIN_SEATS even at zero demand.
        assert_eq!(seats_for_demand(0, 5), MIN_SEATS);
        // One seat per TARGET_SESSIONS_PER_SEAT, rounding up at the bucket edge.
        assert_eq!(seats_for_demand(TARGET_SESSIONS_PER_SEAT, 10), 1);
        assert_eq!(seats_for_demand(TARGET_SESSIONS_PER_SEAT + 1, 10), 2);
        assert_eq!(seats_for_demand(TARGET_SESSIONS_PER_SEAT * 2, 10), 2);
        // Capped by the eligible set …
        assert_eq!(seats_for_demand(10_000, 3), 3);
        // … and by MAX_SEATS when plenty are eligible.
        assert_eq!(seats_for_demand(10_000_000, 100), MAX_SEATS);
    }

    #[test]
    fn seats_for_demand_is_deterministic() {
        // Same frozen inputs → identical seats on every node (no path dependence).
        for (d, e) in [(0u64, 1usize), (75, 8), (260, 4), (999, 50)] {
            assert_eq!(seats_for_demand(d, e), seats_for_demand(d, e));
        }
    }
}
