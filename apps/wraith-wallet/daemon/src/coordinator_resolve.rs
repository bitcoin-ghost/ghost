//! Resolve which Wraith coordinator leads a wallet's tier, and where to fall
//! back to, from a published election view — so a wallet can mix without being
//! handed a coordinator URL.
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
//! about who leads a tier, and the beacon is pinned to a real block hash rather
//! than taken on the publisher's word (#697).
//!
//! ⚠ The roster remains a trusted input, and no amount of care here changes
//! that — see `verified_election` for why the mesh node-list checkpoint does
//! not close it and what would.

use wraith_protocol::election_doc::{election_is_honest, endpoints_for_tier};

/// Election-document verification lives in `wraith_protocol::election_doc`, not
/// here.
///
/// It was written for this file (#697) and moved when a second party needed the
/// same answer: a node challenging a peer for the Wraith coordinator capability
/// has to ask exactly what a wallet asks — did this election follow from the
/// beacon and roster beside it, and does that beacon follow from the chain?
/// Two implementations of that is how two parties end up disagreeing about who
/// is honest, which is the failure this whole area exists to prevent.
pub use wraith_protocol::election_doc::{beacon_anchor_expectation, beacon_matches_chain};

/// What several nodes say about the roster they drew from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterAgreement {
    /// Fewer than two views answered for this epoch, so there was nothing to
    /// compare. The roster is one node's word, as it has always been — the
    /// point of naming this state is that the wallet can SAY so instead of
    /// implying a check it did not make.
    Unchecked,
    /// Every view that answered for this epoch published the same roster.
    Unanimous,
    /// Views disagree, so at least one node is drawing from a roster the others
    /// do not recognise.
    Disagreement { commitments: Vec<String> },
}

/// Compare the rosters several nodes published for the same epoch (#710).
///
/// # What this catches, and what it does not
///
/// `election_is_honest` proves the tier leaders follow from the roster published
/// beside it. It cannot prove the roster is the real eligible set: a node that
/// omits honest candidates — to improve its own odds, or to lead a tier itself —
/// produces an election that verifies perfectly. "No self-nomination" holds
/// against the draw, not against control of the input set.
///
/// Asking more than one node closes the *unilateral* case: a liar has to agree
/// with everyone else or be seen. It does NOT close collusion, and it is not
/// consensus — that needs a BFT-finalised roster checkpoint on the pool side.
///
/// `roster_commitment` exists precisely to be compared like this
/// (`wraith_protocol::roster_snapshot`), and until now nothing compared it.
///
/// # Epoch skew is not dishonesty
///
/// Only views answering for `epoch` are compared. Near a boundary two honest
/// nodes legitimately answer for different epochs, and counting that as
/// disagreement would refuse elections every epoch flip — a self-inflicted
/// outage on the schedule, which is worse than the attack.
pub fn roster_agreement(views: &[serde_json::Value], epoch: u64) -> RosterAgreement {
    let mut commitments: Vec<String> = views
        .iter()
        .filter(|v| v.get("epoch").and_then(|e| e.as_u64()) == Some(epoch))
        .filter_map(|v| {
            v.get("roster_commitment")
                .and_then(|c| c.as_str())
                .map(|c| c.trim().to_ascii_lowercase())
        })
        .filter(|c| !c.is_empty())
        .collect();

    if commitments.len() < 2 {
        return RosterAgreement::Unchecked;
    }
    commitments.sort();
    commitments.dedup();
    if commitments.len() == 1 {
        RosterAgreement::Unanimous
    } else {
        RosterAgreement::Disagreement { commitments }
    }
}

/// Resolve the coordinators to try for a mix of `tier_id` from a node's election
/// JSON. Returns `(endpoints, epoch)`.
///
/// `endpoints` is the tier's leader first, then its failover path — empty when
/// the election is disabled, unverifiable, the epoch is missing, or nothing has
/// advertised, in which case the caller falls back to a manually configured
/// URL. Pure (no I/O) so the daemon handler is a thin fetch around it.
///
/// # Why the order is fixed rather than chosen
///
/// A leader that has gone dark leaves its tier's wallets needing somewhere to
/// go. Letting each wallet try whatever it can reach costs the property the
/// draw exists to create: wallets mixing one denomination converge on ONE
/// coordinator, and a larger set is the whole point. Wallets probing
/// independently notice a failure at different moments and scatter, so the
/// anonymity set fragments precisely when the network is already degraded.
///
/// So every wallet walks the same published order, recomputed from the draw's
/// inputs: a dead leader's cohort moves as one body to the same next node.
///
/// It returns the ORDER rather than a single answer on purpose. Returning one
/// endpoint and adding a second function for the alternates would put two
/// schemes in this file, and the dead one sits there inviting whoever wires it
/// up next.
pub fn resolve_from_election(
    election: &serde_json::Value,
    tier_id: &str,
) -> (Vec<String>, Option<u64>) {
    let epoch = election.get("epoch").and_then(|e| e.as_u64());
    // Refuse a draw that does not follow from its own published inputs. The
    // caller falls back to a manually configured coordinator, which is a
    // worse answer than a verified election and a better one than obeying an
    // unverifiable claim about who is in charge. A disabled election names
    // nobody either, and a document that does not say it is enabled is not
    // trusted to be.
    if election.get("enabled").and_then(|v| v.as_bool()) != Some(true)
        || !election_is_honest(election)
    {
        return (Vec::new(), epoch);
    }
    let endpoints = if epoch.is_some() {
        endpoints_for_tier(election, tier_id)
    } else {
        Vec::new()
    };
    (endpoints, epoch)
}

/// Where a wallet may join instead of `chosen` for this tier: the nodes after
/// it in the tier's order (as [`resolve_from_election`] returns it), when
/// `chosen` is on that order at all.
///
/// A coordinator the user typed in by hand, or one the election does not name,
/// gets no alternates. Spilling a user's explicit choice onto nodes they did
/// not pick would be the wallet overriding them.
///
/// Endpoints are compared without scheme or trailing slash, since the election
/// publishes `host:port` and a wallet dials a URL. An alternate with no scheme
/// borrows `chosen`'s.
pub fn alternates_after(order: &[String], chosen: &str) -> Vec<String> {
    fn host_port(s: &str) -> &str {
        let s = s.trim().trim_end_matches('/');
        s.strip_prefix("http://")
            .or_else(|| s.strip_prefix("https://"))
            .unwrap_or(s)
    }
    let scheme = if chosen.trim().starts_with("https://") {
        "https://"
    } else {
        "http://"
    };
    let Some(pos) = order.iter().position(|e| host_port(e) == host_port(chosen)) else {
        return Vec::new();
    };
    order[pos + 1..]
        .iter()
        .map(|e| {
            if e.contains("://") {
                e.clone()
            } else {
                format!("{scheme}{}", e.trim())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests build election fixtures, so these live here rather than at
    // module level where they would be unused imports.
    use serde_json::json;
    use wraith_protocol::sortition::CoordinatorNodeId;
    use wraith_protocol::{derive_beacon, snapshot_height_for_epoch};

    /// Build an election document that verifies, by running the real draw —
    /// the same shape `ghost-pool` publishes.
    fn honest_election(epoch: u64, roster_size: u8) -> serde_json::Value {
        use wraith_protocol::EpochCoordinators;
        let beacon = [9u8; 32];
        let roster: Vec<CoordinatorNodeId> = (0..roster_size).map(|i| [i; 32]).collect();
        let schedule = EpochCoordinators::elect(epoch, &beacon, &roster);
        json!({
            "enabled": true,
            "epoch": epoch,
            "beacon": hex::encode(beacon),
            "anchor_height": epoch * 144,
            "roster": roster.iter().map(hex::encode).collect::<Vec<_>>(),
            "tiers": schedule.tiers.iter().map(|t| json!({
                "tier": t.tier_id,
                "leader": t.leader().map(hex::encode),
                "order": t.order.iter().map(hex::encode).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "coordinators": schedule.roster.iter().map(|id| json!({
                "node_id": hex::encode(id),
                "endpoint": format!("http://node{}:9100", id[0]),
                "leads": schedule.tiers_led_by(id),
            })).collect::<Vec<_>>(),
        })
    }

    fn tier_index(e: &serde_json::Value, tier: &str) -> usize {
        e["tiers"]
            .as_array()
            .unwrap()
            .iter()
            .position(|t| t["tier"] == tier)
            .unwrap()
    }

    #[test]
    fn an_honest_election_verifies_and_resolves() {
        let e = honest_election(7, 6);
        assert!(election_is_honest(&e));
        let (endpoints, epoch) = resolve_from_election(&e, "100k_sats");
        assert_eq!(epoch, Some(7));
        assert_eq!(endpoints.len(), 6, "the leader, then every other node");
        let leader = e["tiers"][tier_index(&e, "100k_sats")]["leader"]
            .as_str()
            .unwrap();
        let leader_ep = e["coordinators"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["node_id"] == leader)
            .unwrap()["endpoint"]
            .as_str()
            .unwrap();
        assert_eq!(endpoints[0], leader_ep, "the leader is tried first");
    }

    /// The attack the verification exists for: whoever relays the election
    /// names itself leader. Before this check the wallet would have dialled it
    /// (#697).
    #[test]
    fn a_leader_that_does_not_follow_from_the_beacon_is_refused() {
        let mut e = honest_election(7, 6);
        let i = tier_index(&e, "100m_sats");
        let order = e["tiers"][i]["order"].as_array_mut().unwrap();
        order.swap(0, 1);
        assert!(!election_is_honest(&e));
        assert!(resolve_from_election(&e, "100m_sats").0.is_empty());
    }

    /// Leaving `tiers` intact and forging the per-node summary is refused too:
    /// it is what a reader looks at.
    #[test]
    fn a_forged_leads_list_is_refused() {
        let mut e = honest_election(7, 6);
        for c in e["coordinators"].as_array_mut().unwrap() {
            c["leads"] = json!(["100k_sats", "1m_sats", "10m_sats", "100m_sats"]);
        }
        assert!(!election_is_honest(&e));
    }

    /// Dropping a node from the roster would change who leads, so the
    /// published roster has to be the one the draw was made from.
    #[test]
    fn a_trimmed_roster_is_refused() {
        let mut e = honest_election(7, 6);
        e["roster"].as_array_mut().unwrap().truncate(3);
        assert!(!election_is_honest(&e));
    }

    /// Swapping the beacon re-draws the whole election, so a substituted one
    /// cannot match the published leaders.
    #[test]
    fn a_substituted_beacon_is_refused() {
        let mut e = honest_election(7, 6);
        e["beacon"] = json!(hex::encode([1u8; 32]));
        assert!(!election_is_honest(&e));
    }

    /// An election missing the inputs cannot be verified, so it is not used.
    #[test]
    fn an_election_without_its_inputs_is_refused() {
        let mut e = honest_election(7, 6);
        e.as_object_mut().unwrap().remove("beacon");
        assert!(!election_is_honest(&e));
        assert!(resolve_from_election(&e, "100k_sats").0.is_empty());
    }

    /// The old seat-shaped document names no tiers, so it cannot be verified
    /// and a wallet falls back rather than guessing what it meant.
    #[test]
    fn a_seat_shaped_document_is_refused() {
        let mut e = honest_election(7, 6);
        e.as_object_mut().unwrap().remove("tiers");
        e["seats"] = json!(1);
        assert!(!election_is_honest(&e));
    }

    /// The anchor height is derived from the epoch, never read from the
    /// document — otherwise a publisher could name whichever block produced
    /// a beacon it liked and stay perfectly self-consistent.
    #[test]
    fn the_anchor_height_comes_from_the_epoch_not_the_document() {
        let mut e = honest_election(7, 6);
        e["anchor_height"] = json!(999_999);
        let (height, _) = beacon_anchor_expectation(&e).expect("has a beacon");
        assert_eq!(height, snapshot_height_for_epoch(7));
        assert_ne!(height, 999_999);
    }

    /// A beacon that really is derived from the anchor block passes.
    #[test]
    fn a_chain_derived_beacon_is_accepted() {
        let epoch = 11u64;
        let mut e = honest_election(epoch, 6);
        e["beacon"] = json!(hex::encode(derive_beacon(epoch, &[3u8; 32])));
        assert!(beacon_matches_chain(&e, &hex::encode([3u8; 32])));
    }

    /// **The attack this closes.** A publisher invents a beacon, then builds a
    /// schedule that follows from it perfectly — so `election_is_honest`
    /// passes. It cannot survive contact with the chain: the anchor block's
    /// hash is not something the publisher gets to state.
    #[test]
    fn a_fabricated_beacon_is_caught_by_the_chain_even_though_it_is_self_consistent() {
        let e = honest_election(11, 6);
        assert!(election_is_honest(&e), "internally consistent");
        assert!(!beacon_matches_chain(&e, &hex::encode([3u8; 32])));
    }

    /// A malformed anchor hash is a refusal, not an accident that passes.
    #[test]
    fn a_malformed_anchor_hash_does_not_verify() {
        let e = honest_election(11, 6);
        assert!(!beacon_matches_chain(&e, "not-hex"));
        assert!(!beacon_matches_chain(&e, ""));
    }

    /// A disabled election is not a failed one: nothing to verify, and the
    /// caller falls back to a configured coordinator as it always did.
    #[test]
    fn a_disabled_election_is_not_treated_as_dishonest() {
        let e = json!({ "enabled": false });
        assert_eq!(resolve_from_election(&e, "100k_sats"), (Vec::new(), None));
    }

    #[test]
    fn resolve_from_election_uses_epoch_and_falls_back() {
        let s = honest_election(42, 6);
        let (eps, epoch) = resolve_from_election(&s, "1m_sats");
        assert_eq!(epoch, Some(42));
        assert!(!eps.is_empty());

        // No epoch (election pending) → no endpoint, caller falls back.
        let pending = json!({ "enabled": true, "epoch": null, "coordinators": [] });
        assert_eq!(
            resolve_from_election(&pending, "1m_sats"),
            (Vec::new(), None)
        );
        // A tier the protocol does not have resolves to nothing.
        assert!(resolve_from_election(&s, "0.01btc").0.is_empty());
    }

    /// Every tier resolves to a different leader, and every wallet mixing one
    /// tier walks the same path — so a dead leader's cohort moves together.
    #[test]
    fn tiers_resolve_to_different_leaders_on_one_shared_path_each() {
        let e = honest_election(42, 8);
        let firsts: std::collections::HashSet<String> =
            ["100k_sats", "1m_sats", "10m_sats", "100m_sats"]
                .iter()
                .map(|t| resolve_from_election(&e, t).0[0].clone())
                .collect();
        assert_eq!(firsts.len(), 4, "four tiers, four different coordinators");
        assert_eq!(
            resolve_from_election(&e, "10m_sats"),
            resolve_from_election(&e.clone(), "10m_sats"),
            "two wallets on one tier get one path"
        );
    }

    /// A node that has advertised no endpoint is skipped rather than holding a
    /// place — a node nobody can dial is not a fallback.
    #[test]
    fn nodes_without_an_endpoint_are_skipped() {
        let mut e = honest_election(42, 6);
        e["coordinators"][2]["endpoint"] = json!("");
        e["coordinators"][3]["endpoint"] = serde_json::Value::Null;
        let (eps, _) = resolve_from_election(&e, "100k_sats");
        assert_eq!(eps.len(), 4);
        assert!(!eps.iter().any(|x| x.is_empty()));
    }

    fn view(epoch: u64, commitment: &str) -> serde_json::Value {
        json!({ "epoch": epoch, "roster_commitment": commitment })
    }

    /// One node is what the wallet has always had. Naming it Unchecked is the
    /// point: the wallet can report that it did not check, rather than implying
    /// a comparison it never made.
    #[test]
    fn a_single_view_is_unchecked_not_unanimous() {
        assert_eq!(
            roster_agreement(&[view(7, "aa")], 7),
            RosterAgreement::Unchecked
        );
        assert_eq!(roster_agreement(&[], 7), RosterAgreement::Unchecked);
    }

    #[test]
    fn matching_rosters_are_unanimous() {
        assert_eq!(
            roster_agreement(&[view(7, "aa"), view(7, "AA"), view(7, "aa")], 7),
            RosterAgreement::Unanimous,
            "case must not decide whether nodes agree"
        );
    }

    /// The case this exists for: a node drawing from a roster the others do not
    /// recognise. Its election verifies perfectly against its own inputs, which
    /// is why comparing the inputs is the only way to see it.
    #[test]
    fn a_trimmed_roster_shows_up_as_disagreement() {
        match roster_agreement(&[view(7, "aa"), view(7, "bb")], 7) {
            RosterAgreement::Disagreement { commitments } => {
                assert_eq!(commitments, vec!["aa".to_string(), "bb".to_string()]);
            }
            other => panic!("expected disagreement, got {other:?}"),
        }
    }

    /// Near a boundary two honest nodes answer for different epochs. Counting
    /// that as a lie would refuse elections on every epoch flip — an outage on
    /// a schedule, which is worse than the attack being defended against.
    #[test]
    fn a_node_answering_for_another_epoch_is_ignored_not_accused() {
        assert_eq!(
            roster_agreement(&[view(7, "aa"), view(8, "zz")], 7),
            RosterAgreement::Unchecked,
            "the stale view must be ignored, leaving one view and nothing to compare"
        );
        assert_eq!(
            roster_agreement(&[view(7, "aa"), view(7, "aa"), view(8, "zz")], 7),
            RosterAgreement::Unanimous
        );
    }

    /// A view with no commitment contributes nothing rather than counting as
    /// agreement — otherwise a node could dodge the check by omitting the field.
    #[test]
    fn a_missing_commitment_is_not_agreement() {
        let silent = json!({ "epoch": 7 });
        assert_eq!(
            roster_agreement(&[view(7, "aa"), silent], 7),
            RosterAgreement::Unchecked
        );
    }

    #[test]
    fn a_wallet_on_the_leader_may_spill_down_the_rest_of_the_order() {
        let order: Vec<String> = ["1.1.1.1:9100", "2.2.2.2:9100", "3.3.3.3:9100"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            alternates_after(&order, "http://1.1.1.1:9100/"),
            vec!["http://2.2.2.2:9100", "http://3.3.3.3:9100"],
            "scheme and trailing slash do not decide identity"
        );
        assert_eq!(
            alternates_after(&order, "http://2.2.2.2:9100"),
            vec!["http://3.3.3.3:9100"]
        );
        assert!(
            alternates_after(&order, "http://3.3.3.3:9100").is_empty(),
            "the end of the order"
        );
    }

    #[test]
    fn a_coordinator_the_user_chose_by_hand_gets_no_alternates() {
        let order = vec!["1.1.1.1:9100".to_string(), "2.2.2.2:9100".to_string()];
        assert!(alternates_after(&order, "http://my-own-coordinator:9100").is_empty());
        assert!(alternates_after(&[], "http://1.1.1.1:9100").is_empty());
    }

    #[test]
    fn alternates_keep_the_chosen_scheme() {
        let order = vec!["a.onion:9100".to_string(), "b.onion:9100".to_string()];
        assert_eq!(
            alternates_after(&order, "https://a.onion:9100"),
            vec!["https://b.onion:9100"]
        );
    }
}
