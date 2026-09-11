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
use ghost_consensus::mesh::MeshNetwork;

use ghost_common::types::NodeCapabilities;
use tracing::info;
use wraith_protocol::eligibility::{eligible_roster, EligibilityPolicy, NodeFacts};
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

// REMOVED: `COORDINATOR_PEER_FRESHNESS_SECS` (300s).
//
// It required a peer to have pinged within five minutes to be electable. The
// reasoning was sound in isolation — a stale endpoint is worse than an unseated
// one — but the window is evaluated against *this node's* clock and *this
// node's* last-seen record, so it made eligibility a local observation.
//
// Two honest nodes then disagreed about any peer near the boundary, elected
// different coordinators, and gave one session two owners. Liveness now lives
// in `EligibilityPolicy::prune_after_secs`, measured in days, where nodes can
// actually agree; an unreachable node costs one timeout as callers walk past
// it, which is a latency cost rather than a correctness one.

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
    /// The endpoint map the view was built with, kept so a refresh can tell
    /// whether anything a wallet would dial has changed.
    endpoints: EndpointMap,
    /// Session demand as first read this epoch. Frozen: the roster may still
    /// change within an epoch, the seat target may not, or ordinary churn in
    /// the session counters would reshuffle seats every few minutes.
    demand: u64,
    /// This node held a seat in some view of this epoch, not necessarily the
    /// current one. See [`CoordinatorElection::should_serve`].
    seated_this_epoch: bool,
}

/// The view to cache next, or `None` to keep the current one.
///
/// # Why this runs on every refresh, not once per epoch
///
/// The view used to be computed once, when the epoch changed, and then held for
/// the rest of the epoch (~a day). Whatever the peer table looked like at that
/// instant became this node's roster until the next flip. A node restarted
/// mid-epoch drew from a table health pings had barely begun to fill; a node
/// that computed before a peer opted in never saw that peer at all.
///
/// Measured on mainnet the night all eight nodes opted in (2026-09-10, epoch
/// 6711): one node restarted while three others still had coordinating switched
/// off, and ten hours later its roster was still missing exactly those three.
/// The rest of the fleet had filled in theirs, so it elected a different
/// coordinator from everyone else.
///
/// Recomputing the roster whenever it is asked for lets every node converge on
/// the gossip it now holds. The beacon and the seat target stay frozen for the
/// epoch; only the roster, and with it the draw, may move.
fn next_view(
    prev: Option<&Cached>,
    self_id: &CoordinatorNodeId,
    epoch: u64,
    fresh_beacon: Option<[u8; 32]>,
    roster: Vec<CoordinatorNodeId>,
    endpoints: EndpointMap,
    demand: u64,
) -> Option<Cached> {
    let (beacon, demand, seated_before) = match prev.filter(|c| c.epoch == epoch) {
        Some(c) => {
            if c.roster == roster && c.endpoints == endpoints {
                return None;
            }
            (c.beacon, c.demand, c.seated_this_epoch)
        }
        // A new epoch needs its own beacon. Without one, keep the last good view
        // rather than cache a partial one.
        None => (fresh_beacon?, demand, false),
    };
    let seats = seats_for_demand(demand, roster.len());
    let view = CoordinatorView::build(epoch, &beacon, &roster, endpoints.clone(), seats);
    let anchor_height = anchor_height_for_epoch(epoch);
    Some(Cached {
        epoch,
        seated_this_epoch: seated_before || view.am_i_coordinator(self_id),
        view,
        beacon,
        roster_commitment: roster_commitment(epoch, anchor_height, &roster),
        roster,
        anchor_height,
        endpoints,
        demand,
    })
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

    /// The eligible coordinator roster for this epoch, plus the endpoint map.
    ///
    /// A peer is eligible iff it opted in, advertises a dialable endpoint, is
    /// mature, and is not long-absent — all of it declared by the peer and
    /// gossiped, so nodes holding the same gossip agree. The roster is
    /// canonicalised (dedup + sort), so a node's own collection order cannot
    /// change the result.
    ///
    /// # Declared facts only
    ///
    /// This previously filtered `get_connected_peers(300)` — `p.state ==
    /// Connected` (this node's socket) and `last_seen >= now - 300` (this
    /// node's clock) — and claimed nodes derived a byte-identical set from it.
    /// They could not: mesh membership is not shared state, so divergence was
    /// the normal case rather than a boundary condition, and canonicalisation
    /// could not fix it because sorting makes one node's answer
    /// order-independent, not two nodes' answers equal.
    ///
    /// Eligibility is now `wraith_protocol::eligibility`, over facts a node
    /// declared about itself: opted in, has an endpoint, mature, not
    /// long-absent. None of it depends on whether *this* node holds a socket,
    /// or on the verdicts *this* node happens to hold — the verified archive
    /// and qualification checks were removed for that reason (see that
    /// module).
    ///
    /// `Cached::roster_commitment` stays regardless — it is how a split is
    /// *seen*, and it is the only field in the status response one node cannot
    /// self-check.
    /// Returns the canonical roster, the endpoint map, and the summed recent
    /// session `demand` across the eligible set (incl. self) — the frozen input
    /// to [`seats_for_demand`].
    fn roster_with_endpoints(&self) -> (Vec<CoordinatorNodeId>, EndpointMap, u64) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let policy = EligibilityPolicy::default();

        let mut endpoints = EndpointMap::new();
        let mut facts: Vec<NodeFacts> = Vec::new();
        let mut demand: u64 = 0;

        // `all_peers`, not `get_connected_peers`. Eligibility must not depend on
        // whether THIS node currently holds a socket — that is what made two
        // honest nodes disagree.
        for p in self.mesh.peers().get_all_peers() {
            let endpoint = p.coordinator_endpoint.clone();
            let f = NodeFacts {
                node_id: p.node_id,
                // Opt-in stays declared: `coordinator` carries no challenge by
                // design, and a node that has not asked to coordinate should
                // not be conscripted.
                opted_in: p.capabilities.coordinator,
                endpoint: endpoint.clone(),
                first_seen_secs: p.first_seen,
                last_seen_secs: p.last_seen,
            };
            if let Some(ep) = endpoint {
                if !ep.trim().is_empty() {
                    endpoints.insert(p.node_id, ep);
                }
            }
            demand = demand.saturating_add(p.coordinator_sessions as u64);
            facts.push(f);
        }

        if self.self_coordinator {
            if let Some(ep) = self
                .self_endpoint
                .as_deref()
                .filter(|e| !e.trim().is_empty())
            {
                endpoints.insert(self.self_id, ep.to_string());
                facts.push(NodeFacts {
                    node_id: self.self_id,
                    opted_in: true,
                    endpoint: Some(ep.to_string()),
                    first_seen_secs: 0,
                    last_seen_secs: now,
                });
                demand = demand.saturating_add(self.mesh.coordinator_sessions() as u64);
            }
        }

        let roster = eligible_roster(&facts, policy, now);
        endpoints.retain(|id, _| roster.contains(id));
        (canonical_roster(&roster), endpoints, demand)
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

    /// Recompute the roster and, if it or the epoch has changed, rebuild and
    /// cache the `CoordinatorView` for the epoch `current_height` falls in.
    /// Safe to call on every new block / round advance: the beacon is fetched
    /// once per epoch, and an unchanged roster is a no-op. Returns the current
    /// epoch.
    ///
    /// On any input failure (no anchor block yet, RPC error) it leaves the
    /// existing cache untouched and returns the current epoch unchanged — never
    /// poisons the cache with a partial view.
    pub async fn refresh_for_height(&self, current_height: u64) -> u64 {
        let epoch = epoch_for_height(current_height);
        let (roster, endpoints, demand) = self.roster_with_endpoints();

        let same_epoch = self
            .cached
            .read()
            .as_ref()
            .is_some_and(|c| c.epoch == epoch);
        let fresh_beacon = if same_epoch {
            None
        } else {
            let Some(beacon) = self.beacon_for_epoch(epoch).await else {
                // Anchor not reachable yet — keep the last good view.
                return epoch;
            };
            Some(beacon)
        };

        let (next, previous_size) = {
            let guard = self.cached.read();
            let prev = guard.as_ref();
            let previous_size = prev.filter(|c| c.epoch == epoch).map(|c| c.roster.len());
            let next = next_view(
                prev,
                &self.self_id,
                epoch,
                fresh_beacon,
                roster,
                endpoints,
                demand,
            );
            (next, previous_size)
        };
        let Some(next) = next else {
            return epoch;
        };
        // Said once per change, so a split can be traced to the moment one
        // node's roster moved rather than reconstructed afterwards.
        info!(
            epoch,
            within_epoch = same_epoch,
            roster_size = next.roster.len(),
            previous_roster_size = ?previous_size,
            seats = next.view.seats(),
            roster_commitment = %hex::encode(next.roster_commitment),
            "Coordinator roster changed"
        );
        *self.cached.write() = Some(next);
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

    /// Whether THIS node should be running its coordinator: seated now, **or
    /// seated at any point earlier in this epoch**.
    ///
    /// Distinct from [`Self::am_i_coordinator`] because the roster can now move
    /// within an epoch. A node that loses its seat mid-epoch may be holding
    /// rounds that participants have already committed inputs to, and stopping
    /// the coordinator aborts them. So it keeps serving until the epoch turns:
    /// new wallets follow the current view elsewhere, and the rounds it already
    /// holds get to finish. The cost is an idle coordinator for the rest of a
    /// day, which is cheap.
    pub fn should_serve(&self) -> bool {
        self.cached
            .read()
            .as_ref()
            .is_some_and(|c| c.seated_this_epoch)
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

    // ── refresh: the roster converges within an epoch ──

    /// A node outside every test roster, for tests about the roster rather
    /// than about this node's own seat.
    const OBSERVER: CoordinatorNodeId = [0xEE; 32];

    fn endpoints_for(roster: &[CoordinatorNodeId]) -> EndpointMap {
        roster
            .iter()
            .map(|id| (*id, format!("10.0.0.{}:9100", id[0])))
            .collect()
    }

    fn first_draw_as(
        me: &CoordinatorNodeId,
        epoch: u64,
        roster: &[CoordinatorNodeId],
        demand: u64,
    ) -> Cached {
        next_view(
            None,
            me,
            epoch,
            Some(derive_beacon(epoch, &[7u8; 32])),
            roster.to_vec(),
            endpoints_for(roster),
            demand,
        )
        .expect("a first draw with a beacon always produces a view")
    }

    fn first_draw(epoch: u64, roster: &[CoordinatorNodeId], demand: u64) -> Cached {
        first_draw_as(&OBSERVER, epoch, roster, demand)
    }

    /// Same epoch, a new roster — what a refresh does once more gossip is in.
    fn redraw_as(
        me: &CoordinatorNodeId,
        prev: &Cached,
        roster: &[CoordinatorNodeId],
    ) -> Option<Cached> {
        next_view(
            Some(prev),
            me,
            prev.epoch,
            None,
            roster.to_vec(),
            endpoints_for(roster),
            prev.demand,
        )
    }

    fn winner(c: &Cached) -> CoordinatorNodeId {
        c.view.seated()[0].node_id
    }

    /// The mainnet failure, epoch 6711: a node that drew while three peers had
    /// not yet opted in kept that roster for the whole epoch, and elected a
    /// different coordinator from the nodes that drew later.
    #[test]
    fn a_node_that_drew_early_converges_on_the_late_nodes_election() {
        let full: Vec<_> = (1u8..=8).map(node).collect();
        let partial: Vec<_> = full.iter().copied().filter(|id| id[0] > 3).collect();

        let late = first_draw(6711, &full, 0);
        let early = first_draw(6711, &partial, 0);
        assert_ne!(
            early.roster_commitment, late.roster_commitment,
            "precondition: the two nodes start out split"
        );

        let caught_up = redraw_as(&OBSERVER, &early, &full)
            .expect("a roster that grew within the epoch must be redrawn, not held");

        let seating = |c: &Cached| -> Vec<(u32, CoordinatorNodeId, Option<String>)> {
            c.view
                .seated()
                .into_iter()
                .map(|s| (s.seat, s.node_id, s.endpoint))
                .collect()
        };
        assert_eq!(caught_up.roster_commitment, late.roster_commitment);
        assert_eq!(caught_up.beacon, late.beacon);
        assert_eq!(
            seating(&caught_up),
            seating(&late),
            "same roster and beacon must seat the same coordinators"
        );
    }

    #[test]
    fn an_unchanged_roster_is_not_redrawn() {
        let roster: Vec<_> = (1u8..=8).map(node).collect();
        let cached = first_draw(10, &roster, 0);
        assert!(redraw_as(&OBSERVER, &cached, &roster).is_none());
    }

    #[test]
    fn a_moved_endpoint_is_picked_up_within_the_epoch() {
        // A wallet dials the endpoint, so a stale one is as wrong as a stale
        // roster even when the draw itself is unchanged.
        let roster: Vec<_> = (1u8..=5).map(node).collect();
        let cached = first_draw(10, &roster, 0);
        let mut moved = endpoints_for(&roster);
        moved.insert(node(2), "10.9.9.9:9100".into());
        let next = next_view(Some(&cached), &OBSERVER, 10, None, roster, moved.clone(), 0)
            .expect("a changed endpoint must be republished");
        assert_eq!(next.endpoints, moved);
    }

    #[test]
    fn the_seat_target_is_frozen_for_the_epoch() {
        // Session counters move constantly. If a roster change also re-read
        // them, seats would be resized mid-epoch by ordinary traffic.
        let roster: Vec<_> = (1u8..=8).map(node).collect();
        let cached = first_draw(10, &roster[..6], 0);
        assert_eq!(cached.view.seats(), 1);
        let busy = TARGET_SESSIONS_PER_SEAT * 4;
        let next = next_view(
            Some(&cached),
            &OBSERVER,
            10,
            None,
            roster.clone(),
            endpoints_for(&roster),
            busy,
        )
        .unwrap();
        assert_eq!(
            next.view.seats(),
            1,
            "demand read mid-epoch must not resize seats"
        );
        assert_eq!(next.demand, 0);
    }

    #[test]
    fn a_new_epoch_is_drawn_with_its_own_beacon_and_demand() {
        let roster: Vec<_> = (1u8..=8).map(node).collect();
        let cached = first_draw(10, &roster, 0);
        let busy = TARGET_SESSIONS_PER_SEAT * 3;
        let beacon = derive_beacon(11, &[8u8; 32]);
        let next = next_view(
            Some(&cached),
            &OBSERVER,
            11,
            Some(beacon),
            roster.clone(),
            endpoints_for(&roster),
            busy,
        )
        .expect("a new epoch is always redrawn");
        assert_eq!(next.epoch, 11);
        assert_eq!(next.beacon, beacon);
        assert_eq!(next.view.seats(), 3);
    }

    #[test]
    fn a_new_epoch_without_its_beacon_keeps_the_last_good_view() {
        let roster: Vec<_> = (1u8..=8).map(node).collect();
        let cached = first_draw(10, &roster, 0);
        assert!(next_view(
            Some(&cached),
            &OBSERVER,
            11,
            None,
            roster.clone(),
            endpoints_for(&roster),
            0
        )
        .is_none());
    }

    /// An epoch in which the full roster seats a node the partial roster did
    /// not — so the partial roster's winner loses its seat on catching up.
    /// Searched for rather than hard-coded, so the test states the situation it
    /// needs instead of depending on what one beacon happens to rank first.
    fn epoch_where_catching_up_unseats(
        full: &[CoordinatorNodeId],
        partial: &[CoordinatorNodeId],
    ) -> (u64, CoordinatorNodeId) {
        (1..500u64)
            .find_map(|epoch| {
                let early = winner(&first_draw(epoch, partial, 0));
                let late = winner(&first_draw(epoch, full, 0));
                (early != late).then_some((epoch, early))
            })
            .expect("some epoch in 500 seats a node outside the partial roster")
    }

    #[test]
    fn a_seat_lost_within_the_epoch_is_served_until_the_epoch_turns() {
        // Stopping the coordinator aborts the rounds it holds, and participants
        // may already have committed inputs to them. Losing the seat to a
        // roster that filled in is not a reason to do that.
        let full: Vec<_> = (1u8..=8).map(node).collect();
        let partial: Vec<_> = full.iter().copied().filter(|id| id[0] > 3).collect();
        let (epoch, me) = epoch_where_catching_up_unseats(&full, &partial);

        let early = first_draw_as(&me, epoch, &partial, 0);
        assert!(
            early.view.am_i_coordinator(&me),
            "precondition: seated early"
        );
        assert!(early.seated_this_epoch);

        let caught_up = redraw_as(&me, &early, &full).unwrap();
        assert!(
            !caught_up.view.am_i_coordinator(&me),
            "the published view moves on — new wallets go to the new seat"
        );
        assert!(
            caught_up.seated_this_epoch,
            "but the coordinator keeps serving what it already holds"
        );
    }

    #[test]
    fn a_new_epoch_forgets_a_seat_held_in_the_last_one() {
        let full: Vec<_> = (1u8..=8).map(node).collect();
        let partial: Vec<_> = full.iter().copied().filter(|id| id[0] > 3).collect();
        let (epoch, me) = epoch_where_catching_up_unseats(&full, &partial);
        let held = redraw_as(&me, &first_draw_as(&me, epoch, &partial, 0), &full).unwrap();
        assert!(held.seated_this_epoch);

        // Walk forward to an epoch that does not seat `me`, so the only way it
        // could still be serving is a seat carried over from before.
        let next = (epoch + 1..epoch + 500)
            .find_map(|e| {
                let v = next_view(
                    Some(&held),
                    &me,
                    e,
                    Some(derive_beacon(e, &[7u8; 32])),
                    full.clone(),
                    endpoints_for(&full),
                    0,
                )
                .unwrap();
                (!v.view.am_i_coordinator(&me)).then_some(v)
            })
            .expect("some later epoch leaves `me` unseated");
        assert!(!next.seated_this_epoch, "a seat does not outlive its epoch");
    }

    #[test]
    fn seats_for_demand_is_deterministic() {
        // Same frozen inputs → identical seats on every node (no path dependence).
        for (d, e) in [(0u64, 1usize), (75, 8), (260, 4), (999, 50)] {
            assert_eq!(seats_for_demand(d, e), seats_for_demand(d, e));
        }
    }
}
