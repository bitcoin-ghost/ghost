//! Resolve which seated Wraith coordinator owns a wallet's mix, from the node's
//! published election view — so a wallet can mix without being handed a
//! coordinator URL.
//!
//! Inc 5 of `tasks/plan_coordinator_activation.md` — the daemon-side plumbing.
//! The wallet obtains the election JSON **through ghost-pay** (never the node's
//! pool API directly; wallet hard rule, `apps/wraith-wallet/CLAUDE.md`) via
//! `GhostPayClient::coordinator_election`, then resolves the owning seat here.
//! The `WraithResolveCoordinator` IPC request exposes it; the GUI "use the
//! network-elected coordinator" toggle that calls it is the deferred next task.

use sha2::{Digest, Sha256};
use wraith_protocol::sortition::{
    shard_for, verify_election, CoordinatorNodeId, ElectedCoordinator,
};

/// Domain separator for the coordinator shard key.
const SHARD_KEY_DOMAIN: &[u8] = b"ghost/wraith/coordinator-shard/v1";

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

/// Derive the shard key a wallet uses to pick its coordinator seat, from the mix
/// `(tier_id, epoch)`. Sharding on (tier, epoch) — rather than a per-mix session
/// id, which doesn't exist until the coordinator creates it — makes every wallet
/// wanting the same denomination in the same epoch converge on the SAME seat, for
/// a larger anonymity set. `tier_id` is the protocol's string tier id.
/// `SHA256(domain || tier_id_bytes || epoch_le)`.
pub fn shard_key_for_tier_epoch(tier_id: &str, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SHARD_KEY_DOMAIN);
    h.update(tier_id.as_bytes());
    h.update(epoch.to_le_bytes());
    h.finalize().into()
}

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
}
