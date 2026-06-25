//! Decentralised Wraith coordinator election — live wiring (read-only).
//!
//! Increment 4 of `tasks/plan_decentralised_coordinators.md`: feed the PURE
//! election library (`wraith_protocol::{sortition, epoch, service}`) with live
//! node state (the elder roster, the chain height, and a per-epoch beacon
//! anchor) and expose the resulting [`CoordinatorView`] read-only.
//!
//! ## What this increment deliberately does NOT do
//!
//! It computes and *publishes* the election only. It NEVER:
//! - activates a coordinator role (no node starts coordinating anything here),
//! - touches `coordinator_redundancy` or any Wraith mixing,
//! - emits or changes any consensus message.
//!
//! It is gated behind `[coordinator] wraith_election_enabled` (default false).
//! When the flag is off the [`CoordinatorElection`] is never constructed and
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
use sha2::{Digest, Sha256};

use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_consensus::mesh::MeshNetwork;
use ghost_common::types::NodeCapabilities;

use wraith_protocol::epoch::canonical_roster;
use wraith_protocol::service::{CoordinatorView, EndpointMap};
use wraith_protocol::sortition::CoordinatorNodeId;

/// Blocks per coordinator epoch — `epoch = height / COORDINATOR_EPOCH_BLOCKS`.
/// ~1 day at 10-minute blocks. The draw is reshuffled every epoch, so
/// coordination rotates across the qualified set over time.
///
/// Kept local (rather than reusing `wraith_protocol::epoch::EPOCH_BLOCKS`, also
/// 144) so the live cadence is owned and tuneable at the wiring layer without
/// changing the pure library's test fixtures.
pub const COORDINATOR_EPOCH_BLOCKS: u64 = 144;

/// Target number of concurrent coordinator seats per epoch. Sessions are
/// sharded across these seats so no single coordinator owns every round.
pub const COORDINATOR_SEATS: usize = 5;

/// Domain separator for the beacon hash so it can never collide with any other
/// hash in the system. Versioned for forward changes.
const BEACON_DOMAIN: &[u8] = b"ghost/wraith/coordinator-beacon/v1";

/// The coordinator epoch a chain height falls in.
pub const fn epoch_for_height(height: u64) -> u64 {
    height / COORDINATOR_EPOCH_BLOCKS
}

/// The chain height whose anchor freezes epoch `E` — the first block of epoch
/// `E` (`E * K`). Using the epoch-start block (rather than a far-future one)
/// keeps the anchor reachable the moment the epoch begins; its grinding
/// resistance is addressed by the security note on [`derive_beacon`].
pub const fn anchor_height_for_epoch(epoch: u64) -> u64 {
    epoch.saturating_mul(COORDINATOR_EPOCH_BLOCKS)
}

/// Derive the 32-byte per-epoch beacon from an anchor hash the whole network
/// agrees on: `SHA256(domain ‖ epoch_le ‖ anchor_hash)`.
///
/// SECURITY: the anchor used here is the block hash at the epoch-start height
/// (see [`CoordinatorElection::beacon_for_epoch`]). A miner who finds that block
/// can choose among the candidate hashes it could publish, so this interim
/// anchor's grinding-resistance is BOUNDED — adequate for a read-only,
/// role-inactive view, but NOT the endgame. The unbiasable beacon is the
/// threshold-VRF / DKG construction (plan increment 5, gated on an EXTERNAL
/// crypto audit). Because `epoch.rs`/`service.rs` are beacon-agnostic (they take
/// the 32-byte beacon as a value), swapping this for the audited beacon changes
/// nothing else in the wiring.
pub fn derive_beacon(epoch: u64, anchor_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BEACON_DOMAIN);
    h.update(epoch.to_le_bytes());
    h.update(anchor_hash);
    h.finalize().into()
}

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
}

/// Live coordinator-election service for ghost-pool.
///
/// Constructed only when `wraith_election_enabled` is true. Holds the inputs it
/// needs to (re)compute a [`CoordinatorView`] each time the epoch changes, and
/// caches the latest view for the read-only accessors and the HTTP endpoint.
pub struct CoordinatorElection {
    /// This node's own id, and whether it is itself an elder (so it can be in
    /// the roster). `[u8; 32]`, matches `wraith_protocol`'s `CoordinatorNodeId`.
    self_id: CoordinatorNodeId,
    self_is_elder: bool,
    /// Mesh handle — source of the elder roster (`peers().get_elder_peers()`).
    mesh: Arc<MeshNetwork>,
    /// Ghost Core RPC — source of the beacon anchor (block hash at a height).
    rpc: Arc<BitcoinRpc>,
    /// Cached current-epoch view.
    cached: RwLock<Option<Cached>>,
}

impl CoordinatorElection {
    /// Build the service from live handles. Call only when the config flag is
    /// on; see [`maybe_new`].
    pub fn new(
        identity: &NodeIdentity,
        capabilities: &NodeCapabilities,
        mesh: Arc<MeshNetwork>,
        rpc: Arc<BitcoinRpc>,
    ) -> Self {
        Self {
            self_id: identity.node_id(),
            self_is_elder: capabilities.elder_status,
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
        mesh: Arc<MeshNetwork>,
        rpc: Arc<BitcoinRpc>,
    ) -> Option<Arc<Self>> {
        if !enabled {
            return None;
        }
        Some(Arc::new(Self::new(identity, capabilities, mesh, rpc)))
    }

    /// The qualified roster for this epoch: the current elder node ids, plus
    /// self when self is an elder. Canonicalised (dedup + sort) so every node
    /// derives the byte-identical roster from the same membership.
    fn roster(&self) -> Vec<CoordinatorNodeId> {
        let mut ids: Vec<CoordinatorNodeId> = self
            .mesh
            .peers()
            .get_elder_peers()
            .into_iter()
            .map(|p| p.node_id)
            .collect();
        if self.self_is_elder {
            ids.push(self.self_id);
        }
        canonical_roster(&ids)
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

    /// Recompute and cache the [`CoordinatorView`] for the epoch `current_height`
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
        let roster = self.roster();
        // Endpoint map stays empty for this read-only increment: node→endpoint
        // discovery (so a wallet can dial the owning coordinator) is a later
        // layer. The election itself (who is seated) is unaffected by it.
        let view = CoordinatorView::build(
            epoch,
            &beacon,
            &roster,
            EndpointMap::new(),
            COORDINATOR_SEATS,
        );
        *self.cached.write() = Some(Cached { epoch, view });
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
    /// `{enabled, epoch, seats, my_seat, elected: [hex node ids]}`. Pre-
    /// serialised so `ghost-verification` needn't depend on `wraith-protocol`.
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
            });
        };

        let elected = self.elected_hex(&c.view);
        serde_json::json!({
            "enabled": true,
            "epoch": c.view.epoch(),
            "seats": c.view.seats(),
            "my_seat": c.view.my_seat(&self.self_id),
            "elected": elected,
        })
    }

    /// The elected coordinators' node ids, hex-encoded in seat order. Derived by
    /// re-querying the view per seat via the session-sharding map is not exposed,
    /// so reconstruct the seated set from the public seat predicate over the
    /// roster (the same roster the view was built from).
    fn elected_hex(&self, view: &CoordinatorView) -> Vec<String> {
        // The view exposes seats() and per-id predicates, not the raw set, so
        // walk the roster and keep the seated ids ordered by seat index.
        let roster = self.roster();
        let mut seated: Vec<(u32, CoordinatorNodeId)> = roster
            .into_iter()
            .filter_map(|id| view.my_seat(&id).map(|seat| (seat, id)))
            .collect();
        seated.sort_unstable_by_key(|(seat, _)| *seat);
        seated
            .into_iter()
            .map(|(_, id)| hex::encode(id))
            .collect()
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

    #[test]
    fn epoch_and_anchor_height_maths() {
        assert_eq!(epoch_for_height(0), 0);
        assert_eq!(epoch_for_height(COORDINATOR_EPOCH_BLOCKS - 1), 0);
        assert_eq!(epoch_for_height(COORDINATOR_EPOCH_BLOCKS), 1);
        assert_eq!(epoch_for_height(COORDINATOR_EPOCH_BLOCKS * 9 + 7), 9);

        assert_eq!(anchor_height_for_epoch(0), 0);
        assert_eq!(anchor_height_for_epoch(1), COORDINATOR_EPOCH_BLOCKS);
        assert_eq!(anchor_height_for_epoch(5), 5 * COORDINATOR_EPOCH_BLOCKS);
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
        let view = CoordinatorView::build(2, &beacon, &roster, EndpointMap::new(), COORDINATOR_SEATS);
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
}
