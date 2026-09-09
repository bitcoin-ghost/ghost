//! Resolve which seated Wraith coordinator owns a wallet's mix, from a
//! published election view — so a wallet can mix without being handed a
//! coordinator URL.
//!
//! # Where the election comes from now
//!
//! The wallet used to obtain it *through ghost-pay*, so it never spoke to the
//! pool itself. With the operator gone it asks a pool node directly, over Tor
//! when one is configured, and caches the answer for the whole epoch so the
//! number of asks stops tracking the number of mixes. See
//! `verified_election` in the daemon for that side.
//!
//! What lives here is the half that makes asking safe enough to do: an
//! election is *recomputed* before it is used, so a relayed view cannot lie
//! about who was seated, and the beacon is pinned to a real block hash rather
//! than taken on the publisher's word (#697).
//!
//! ⚠ The roster remains a trusted input, and no amount of care here changes
//! that — see `verified_election` for why the mesh node-list checkpoint does
//! not close it and what would.

use wraith_protocol::sortition::{
    shard_for, verify_election, CoordinatorNodeId, ElectedCoordinator,
};
use wraith_protocol::{derive_beacon, snapshot_height_for_epoch};

/// Why a published election is recomputed before it is used.
///
/// The election's whole claim is public verifiability: rank is
/// `H(beacon ‖ epoch ‖ node_id)`, so nobody can nominate themselves. That
/// property belongs to the *draw*, not to a JSON document describing one —
/// and until this check existed the wallet believed the document. Anything
/// relaying it could have named itself every seat, and every wallet asking
/// for a coordinator would have been sent to it (#697).
///
/// What recomputing buys: the seat list must actually follow from the beacon
/// and roster published beside it. A relay that edits seats, drops a
/// qualified node, or forges a rank is refused.
///
/// What it does not buy, and this matters: the beacon and roster arrive from
/// the same place as the result. A node that lies about *both*, consistently,
/// still produces a self-consistent election. The beacon is the half that can
/// be pinned — it is `SHA256(domain ‖ epoch ‖ block_hash_at(anchor_height))`,
/// so a wallet with chain access can re-derive it and refuse a fabricated
/// one; `anchor_height` is published for exactly that. The roster is the
/// remaining trusted input, and closing it needs the qualified set to come
/// from consensus rather than from whoever answered.
fn election_is_honest(election: &serde_json::Value) -> bool {
    let Some(epoch) = election.get("epoch").and_then(|e| e.as_u64()) else {
        return false;
    };
    let Some(beacon) = election
        .get("beacon")
        .and_then(|b| b.as_str())
        .and_then(decode_32)
    else {
        return false;
    };
    let Some(roster) = election.get("roster").and_then(|r| r.as_array()).map(|r| {
        r.iter()
            .map(|v| v.as_str().and_then(decode_32))
            .collect::<Option<Vec<CoordinatorNodeId>>>()
    }) else {
        return false;
    };
    let Some(roster) = roster else { return false };
    let Some(seats) = election.get("seats").and_then(|s| s.as_u64()) else {
        return false;
    };

    // The claimed draw, in seat order — `verify_election` compares against a
    // freshly computed one, so the ordering has to match how it was built.
    let Some(claimed) = election
        .get("coordinators")
        .and_then(|c| c.as_array())
        .map(|c| {
            c.iter()
                .map(|v| {
                    Some(ElectedCoordinator {
                        node_id: v
                            .get("node_id")
                            .and_then(|n| n.as_str())
                            .and_then(decode_32)?,
                        rank: v.get("rank").and_then(|r| r.as_str()).and_then(decode_32)?,
                        seat: v.get("seat").and_then(|s| s.as_u64())? as u32,
                    })
                })
                .collect::<Option<Vec<_>>>()
        })
    else {
        return false;
    };
    let Some(mut claimed) = claimed else {
        return false;
    };
    claimed.sort_by_key(|c| c.seat);

    verify_election(&beacon, epoch, &roster, seats as usize, &claimed)
}

/// The block height whose hash must anchor this election's beacon, and the
/// beacon it claims. `None` if the document does not carry both.
///
/// The height is computed from the epoch rather than read from the document.
/// Reading it would let a publisher name whichever block produced a beacon it
/// liked and stay self-consistent; deriving it means the anchor is whatever
/// the protocol says it is. The published `anchor_height` is therefore a
/// convenience for humans, not an input to the check.
pub fn beacon_anchor_expectation(election: &serde_json::Value) -> Option<(u64, [u8; 32])> {
    let epoch = election.get("epoch")?.as_u64()?;
    let claimed = election.get("beacon")?.as_str().and_then(decode_32)?;
    Some((snapshot_height_for_epoch(epoch), claimed))
}

/// Does the claimed beacon actually follow from the anchor block's hash?
///
/// This is the half of the trust gap that can be closed. `election_is_honest`
/// proves the seat list follows from the beacon and roster published beside
/// it — but those arrive from the same place as the result, so a publisher
/// lying about all of them consistently still verifies. The beacon is
/// pinnable: it is `SHA256(domain ‖ epoch ‖ anchor_block_hash)`, and the
/// anchor block hash is a fact about the chain that the wallet's own node can
/// state. A fabricated beacon cannot survive it.
///
/// `anchor_hash_hex` is the hash exactly as the node's `getblockhash`
/// returned it, decoded without byte reversal — matching how the deriving
/// node reads it.
///
/// The roster remains trusted after this: closing that needs the qualified
/// set to come from consensus rather than from whoever answered.
pub fn beacon_matches_chain(election: &serde_json::Value, anchor_hash_hex: &str) -> bool {
    let Some((_, claimed)) = beacon_anchor_expectation(election) else {
        return false;
    };
    let Some(epoch) = election.get("epoch").and_then(|e| e.as_u64()) else {
        return false;
    };
    let Some(anchor) = decode_32(anchor_hash_hex) else {
        return false;
    };
    derive_beacon(epoch, &anchor) == claimed
}

/// Decode a 32-byte hex string, rejecting anything else.
fn decode_32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s.trim()).ok()?;
    bytes.try_into().ok()
}

/// Pick the coordinator endpoint that owns `shard_key` from a node's
/// `/api/v1/pool/coordinator` JSON. Pure (no I/O) so it is unit-testable.
///
/// Shards across the node's *published* seat count, so the wallet and the node
/// agree on the owner, and so all wallets that share a key (e.g. the same
/// tier+epoch) converge on the same seat — a larger anonymity set, not load
/// spreading. Returns `None` when the election is disabled/empty, or the owning
/// seat hasn't advertised an endpoint yet (caller falls back).
pub fn pick_seat_endpoint(status: &serde_json::Value, shard_key: &[u8; 32]) -> Option<String> {
    if status.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        return None;
    }
    let coords = status.get("coordinators")?.as_array()?;
    if coords.is_empty() {
        return None;
    }
    let seat = shard_for(shard_key, coords.len());
    let owner = coords
        .iter()
        .find(|c| c.get("seat").and_then(|s| s.as_u64()) == Some(seat as u64))?;
    owner
        .get("endpoint")
        .and_then(|e| e.as_str())
        .filter(|e| !e.is_empty())
        .map(String::from)
}

/// The seats to try for `shard_key`, in order: the owning seat first, then a
/// deterministic sequence of alternates.
///
/// # Why the order is fixed rather than chosen
///
/// A seat whose node has gone dark leaves the wallets sharded to it with
/// nowhere to go until the epoch flips. The obvious repair — let each wallet
/// try whatever it can reach — costs the exact property the sharding exists to
/// create: wallets that share a key converge on ONE seat, and a larger set is
/// the whole point (see [`pick_seat_endpoint`]). Wallets probing independently
/// notice a failure at different moments and scatter across different seats,
/// so the anonymity set fragments precisely when the network is already
/// degraded, and nothing tells the user it happened.
///
/// Removing the dead seat from the roster instead does not work either. The
/// roster is deliberately snapshotted a full epoch behind so that every node
/// answers the same question (`wraith_protocol::roster_snapshot`), and that
/// module says plainly that nothing there is consensus — it only gives nodes a
/// commitment to compare so divergence is *seen*. Liveness is a local
/// observation, so a liveness-driven roster is a divergent roster, which is a
/// split election rather than a failover.
///
/// So the fallback is derived from what is already agreed: walk forward from
/// the owning seat. Every wallet on a dead seat moves to the SAME next seat, and
/// it joins that seat's existing cohort rather than forming a new one — the set
/// moves as a body and gets larger, never smaller. During the window where some
/// wallets have noticed and others have not, there are two cohorts, not N.
///
/// Needs no liveness consensus, no roster mutation and no new wire field: the
/// order is a function of the published seat count and the shard key.
pub fn seat_try_order(shard_key: &[u8; 32], seat_count: usize) -> Vec<usize> {
    if seat_count == 0 {
        return Vec::new();
    }
    let first = shard_for(shard_key, seat_count) as usize;
    (0..seat_count).map(|i| (first + i) % seat_count).collect()
}

/// Coordinator endpoints to try for `shard_key`, in [`seat_try_order`].
///
/// The caller dials them in order and stops at the first that answers. Seats
/// that have advertised no endpoint are skipped rather than occupying a
/// position: a seat nobody can dial is not a fallback.
pub fn pick_seat_endpoints(status: &serde_json::Value, shard_key: &[u8; 32]) -> Vec<String> {
    if status.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
        return Vec::new();
    }
    let Some(coords) = status.get("coordinators").and_then(|c| c.as_array()) else {
        return Vec::new();
    };
    if coords.is_empty() {
        return Vec::new();
    }

    seat_try_order(shard_key, coords.len())
        .into_iter()
        .filter_map(|seat| {
            coords
                .iter()
                .find(|c| c.get("seat").and_then(|s| s.as_u64()) == Some(seat as u64))?
                .get("endpoint")
                .and_then(|e| e.as_str())
                .filter(|e| !e.is_empty())
                .map(String::from)
        })
        .collect()
}

/// The shard key comes from `wraith_protocol`, not from here.
///
/// It used to be defined in this file, which meant the value a wallet shards
/// on lived somewhere a node could not reach — and the library carried a
/// *different* scheme (by session id) documented as the one "a wallet and
/// every node agree" on, with no callers. Two schemes, different answers, and
/// the dead one inviting whoever wired it up next.
pub use wraith_protocol::shard_key_for_tier_epoch;

/// Resolve the coordinator endpoint for a mix of `tier_id` from a node's election
/// JSON (as relayed by ghost-pay). Returns `(endpoint, epoch)`: `endpoint` is
/// `None` when the election is disabled/empty, the epoch is missing, or the owning
/// seat hasn't advertised yet — the caller then falls back to a manual URL. Pure
/// (no I/O) so the daemon handler is a thin fetch around it.
pub fn resolve_from_election(
    election: &serde_json::Value,
    tier_id: &str,
) -> (Option<String>, Option<u64>) {
    let epoch = election.get("epoch").and_then(|e| e.as_u64());
    // Refuse a draw that does not follow from its own published inputs. The
    // caller falls back to a manually configured coordinator, which is a
    // worse answer than a verified election and a better one than obeying an
    // unverifiable claim about who is in charge.
    if election.get("enabled").and_then(|v| v.as_bool()) == Some(true)
        && !election_is_honest(election)
    {
        return (None, epoch);
    }
    let endpoint =
        epoch.and_then(|ep| pick_seat_endpoint(election, &shard_key_for_tier_epoch(tier_id, ep)));
    (endpoint, epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build an election document that verifies, by running the real draw.
    fn honest_election(epoch: u64, roster_size: u8, seats: usize) -> serde_json::Value {
        use wraith_protocol::sortition::elect_coordinators;
        let beacon = [9u8; 32];
        let roster: Vec<CoordinatorNodeId> = (0..roster_size).map(|i| [i; 32]).collect();
        let elected = elect_coordinators(&beacon, epoch, &roster, seats);
        json!({
            "enabled": true,
            "epoch": epoch,
            "seats": seats,
            "beacon": hex::encode(beacon),
            "anchor_height": epoch * 144,
            "roster": roster.iter().map(hex::encode).collect::<Vec<_>>(),
            "coordinators": elected.iter().map(|c| json!({
                "node_id": hex::encode(c.node_id),
                "seat": c.seat,
                "rank": hex::encode(c.rank),
                "endpoint": format!("http://seat{}:9100", c.seat),
            })).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn an_honest_election_verifies_and_resolves() {
        let e = honest_election(7, 6, 3);
        assert!(election_is_honest(&e));
        let (endpoint, epoch) = resolve_from_election(&e, "100k_sats");
        assert_eq!(epoch, Some(7));
        assert!(endpoint.is_some(), "a verified election must resolve");
    }

    /// The attack the verification exists for: whoever relays the election
    /// names itself every seat. Before this check the wallet would have
    /// dialled it (#697).
    #[test]
    fn a_seat_list_that_does_not_follow_from_the_beacon_is_refused() {
        let mut e = honest_election(7, 6, 3);
        let usurper = hex::encode([0xEE; 32]);
        for c in e["coordinators"].as_array_mut().unwrap() {
            c["node_id"] = json!(usurper);
        }
        assert!(!election_is_honest(&e));
        assert_eq!(resolve_from_election(&e, "100k_sats").0, None);
    }

    /// Dropping a qualified node from the roster would change who wins, so
    /// the published roster has to be the one the draw was made from.
    #[test]
    fn a_trimmed_roster_is_refused() {
        let mut e = honest_election(7, 6, 3);
        e["roster"].as_array_mut().unwrap().truncate(3);
        assert!(!election_is_honest(&e));
    }

    /// A forged rank is refused even when the winner is right — the rank is
    /// the evidence, not decoration.
    #[test]
    fn a_forged_rank_is_refused() {
        let mut e = honest_election(7, 6, 3);
        e["coordinators"][0]["rank"] = json!(hex::encode([0u8; 32]));
        assert!(!election_is_honest(&e));
    }

    /// Swapping the beacon re-draws the whole election, so a substituted one
    /// cannot match the published seats.
    #[test]
    fn a_substituted_beacon_is_refused() {
        let mut e = honest_election(7, 6, 3);
        e["beacon"] = json!(hex::encode([1u8; 32]));
        assert!(!election_is_honest(&e));
    }

    /// An election missing the inputs entirely — which is what every node
    /// published before this commit — cannot be verified, so it is not used.
    #[test]
    fn an_election_without_its_inputs_is_refused() {
        let mut e = honest_election(7, 6, 3);
        e.as_object_mut().unwrap().remove("beacon");
        assert!(!election_is_honest(&e));
        assert_eq!(resolve_from_election(&e, "100k_sats").0, None);
    }

    /// The anchor height is derived from the epoch, never read from the
    /// document — otherwise a publisher could name whichever block produced
    /// a beacon it liked and stay perfectly self-consistent.
    #[test]
    fn the_anchor_height_comes_from_the_epoch_not_the_document() {
        let mut e = honest_election(7, 6, 3);
        e["anchor_height"] = json!(999_999);
        let (height, _) = beacon_anchor_expectation(&e).expect("has a beacon");
        assert_eq!(height, snapshot_height_for_epoch(7));
        assert_ne!(height, 999_999);
    }

    /// A beacon that really is derived from the anchor block passes.
    #[test]
    fn a_chain_derived_beacon_is_accepted() {
        let epoch = 11u64;
        let mut e = honest_election(epoch, 6, 3);
        e["beacon"] = json!(hex::encode(derive_beacon(epoch, &[3u8; 32])));
        assert!(beacon_matches_chain(&e, &hex::encode([3u8; 32])));
    }

    /// **The attack this closes.** A publisher invents a beacon, then builds a
    /// seat list that follows from it perfectly — so `election_is_honest`
    /// passes. It cannot survive contact with the chain: the anchor block's
    /// hash is not something the publisher gets to state.
    #[test]
    fn a_fabricated_beacon_is_caught_by_the_chain_even_though_it_is_self_consistent() {
        let e = honest_election(11, 6, 3);
        assert!(election_is_honest(&e), "internally consistent");
        assert!(!beacon_matches_chain(&e, &hex::encode([3u8; 32])));
    }

    /// A malformed anchor hash is a refusal, not an accident that passes.
    #[test]
    fn a_malformed_anchor_hash_does_not_verify() {
        let e = honest_election(11, 6, 3);
        assert!(!beacon_matches_chain(&e, "not-hex"));
        assert!(!beacon_matches_chain(&e, ""));
    }

    /// A disabled election is not a failed one: nothing to verify, and the
    /// caller falls back to a configured coordinator as it always did.
    #[test]
    fn a_disabled_election_is_not_treated_as_dishonest() {
        let e = json!({ "enabled": false });
        assert_eq!(resolve_from_election(&e, "100k_sats"), (None, None));
    }

    fn status(enabled: bool, coords: serde_json::Value) -> serde_json::Value {
        json!({ "enabled": enabled, "coordinators": coords })
    }

    #[test]
    fn picks_a_seated_endpoint_deterministically_for_a_key() {
        let s = status(
            true,
            json!([
                {"node_id":"aa","seat":0,"endpoint":"http://a:9100"},
                {"node_id":"bb","seat":1,"endpoint":"http://b:9100"},
            ]),
        );
        let key = [7u8; 32];
        // Same key → same owner (so wallets converge), and it's one of the seats.
        let a = pick_seat_endpoint(&s, &key);
        assert_eq!(a, pick_seat_endpoint(&s, &key));
        assert!(matches!(
            a.as_deref(),
            Some("http://a:9100") | Some("http://b:9100")
        ));
    }

    #[test]
    fn none_when_disabled_empty_or_unadvertised() {
        // Disabled election.
        assert_eq!(
            pick_seat_endpoint(&status(false, json!([])), &[0u8; 32]),
            None
        );
        // No coordinators seated.
        assert_eq!(
            pick_seat_endpoint(&status(true, json!([])), &[0u8; 32]),
            None
        );
        // Single seat whose owner hasn't advertised an endpoint yet.
        let s = status(true, json!([{"node_id":"aa","seat":0,"endpoint":null}]));
        assert_eq!(pick_seat_endpoint(&s, &[0u8; 32]), None);
        // Empty-string endpoint is treated as unadvertised.
        let s = status(true, json!([{"node_id":"aa","seat":0,"endpoint":""}]));
        assert_eq!(pick_seat_endpoint(&s, &[0u8; 32]), None);
    }

    #[test]
    fn shard_key_is_deterministic_and_separates_tier_and_epoch() {
        // Stable for the same (tier, epoch) → wallets converge.
        assert_eq!(
            shard_key_for_tier_epoch("0.01btc", 100),
            shard_key_for_tier_epoch("0.01btc", 100)
        );
        // Different tier OR epoch → different key.
        assert_ne!(
            shard_key_for_tier_epoch("0.01btc", 100),
            shard_key_for_tier_epoch("0.1btc", 100)
        );
        assert_ne!(
            shard_key_for_tier_epoch("0.01btc", 100),
            shard_key_for_tier_epoch("0.01btc", 101)
        );
    }

    #[test]
    fn resolve_from_election_uses_epoch_and_falls_back() {
        // A verified election resolves, and reports its epoch.
        let s = honest_election(42, 6, 2);
        let (ep, epoch) = resolve_from_election(&s, "0.01btc");
        assert_eq!(epoch, Some(42));
        assert!(ep.is_some());

        // The same document without its inputs used to resolve too — the
        // wallet took the seat list on trust. It now reports the epoch and
        // refuses the endpoint, so the caller falls back (#697).
        let unverifiable = json!({
            "enabled": true,
            "epoch": 42,
            "coordinators": [
                {"node_id":"aa","seat":0,"endpoint":"http://a:9100"},
                {"node_id":"bb","seat":1,"endpoint":"http://b:9100"},
            ]
        });
        assert_eq!(
            resolve_from_election(&unverifiable, "0.01btc"),
            (None, Some(42))
        );

        // No epoch (election pending) → no endpoint, caller falls back.
        let pending = json!({ "enabled": true, "epoch": null, "coordinators": [] });
        assert_eq!(resolve_from_election(&pending, "0.01btc"), (None, None));
        // Disabled → nothing.
        let off = json!({ "enabled": false });
        assert_eq!(resolve_from_election(&off, "0.01btc"), (None, None));
    }

    /// The property the whole design rests on: every wallet sharded to a dead
    /// seat moves to the SAME next seat.
    ///
    /// If wallets each probed for whatever they could reach, they would notice
    /// the failure at different moments and scatter — the anonymity set
    /// fragmenting exactly when the network is already degraded. Here the set
    /// moves as a body, and joins the destination seat's existing cohort rather
    /// than forming a new one.
    #[test]
    fn every_wallet_on_a_seat_falls_back_to_the_same_seat() {
        // Two different keys that happen to shard to the same seat stand in for
        // two wallets in one cohort: whatever their keys, the ORDER after the
        // owning seat is a function of the seat count, so the cohort cannot split.
        let n = 5;
        for a in 0u8..40 {
            for b in 0u8..40 {
                let ka = [a; 32];
                let kb = [b; 32];
                let oa = seat_try_order(&ka, n);
                let ob = seat_try_order(&kb, n);
                if oa[0] == ob[0] {
                    assert_eq!(
                        oa, ob,
                        "two wallets on seat {} disagreed about where to go next",
                        oa[0]
                    );
                }
            }
        }
    }

    /// The first seat tried must be the one that owns the key, or the fallback
    /// order would quietly move every wallet off its own seat.
    #[test]
    fn the_order_starts_at_the_owning_seat() {
        for i in 0u8..20 {
            let key = [i; 32];
            for n in 1usize..8 {
                assert_eq!(seat_try_order(&key, n)[0], shard_for(&key, n) as usize);
            }
        }
    }

    /// Every seat appears exactly once: no seat is unreachable as a fallback,
    /// and none is tried twice.
    #[test]
    fn the_order_is_a_permutation_of_the_seats() {
        for n in 1usize..12 {
            let order = seat_try_order(&[7u8; 32], n);
            assert_eq!(order.len(), n);
            let mut seen = order.clone();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), n, "n={n} produced a duplicate or a gap");
        }
    }

    /// A seat that has advertised no endpoint is skipped rather than occupying a
    /// position — a seat nobody can dial is not a fallback.
    #[test]
    fn seats_without_an_endpoint_are_skipped() {
        let status = json!({
            "enabled": true,
            "coordinators": [
                { "seat": 0, "endpoint": "" },
                { "seat": 1, "endpoint": "1.2.3.4:9100" },
                { "seat": 2, "endpoint": "5.6.7.8:9100" },
            ],
        });
        let endpoints = pick_seat_endpoints(&status, &[3u8; 32]);
        assert_eq!(endpoints.len(), 2, "the empty endpoint must not be offered");
        assert!(!endpoints.iter().any(|e| e.is_empty()));
    }

    /// No seats, no panic — and no endpoints to pretend otherwise.
    #[test]
    fn an_empty_election_yields_nothing_to_try() {
        assert!(seat_try_order(&[0u8; 32], 0).is_empty());
        let off = json!({ "enabled": false });
        assert!(pick_seat_endpoints(&off, &[0u8; 32]).is_empty());
        let empty = json!({ "enabled": true, "coordinators": [] });
        assert!(pick_seat_endpoints(&empty, &[0u8; 32]).is_empty());
    }
}
