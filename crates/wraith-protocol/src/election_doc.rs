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
//| FILE: election_doc.rs                                                                                                  |
//|======================================================================================================================|

//! Verifying a published coordinator election document.
//!
//! Lives here rather than in the wallet because the wallet is not the only
//! party that needs it. A node challenging a peer for the Wraith coordinator
//! capability has to ask the same question — did this election follow from the
//! beacon and roster beside it, and does that beacon follow from the chain? —
//! and a second implementation of that answer is how two parties end up
//! disagreeing about who is honest.
//!
//! The functions were written for the wallet (#697) and moved here when the
//! challenger needed them too.

use crate::epoch::{derive_beacon, snapshot_height_for_epoch, EpochCoordinators};
use crate::sortition::CoordinatorNodeId;

/// Recompute the schedule from the inputs a document publishes beside it:
/// `epoch`, `beacon`, `roster`. `None` if any is missing or malformed.
fn recompute(election: &serde_json::Value) -> Option<EpochCoordinators> {
    let epoch = election.get("epoch")?.as_u64()?;
    let beacon = election.get("beacon")?.as_str().and_then(decode_32)?;
    let roster = election
        .get("roster")?
        .as_array()?
        .iter()
        .map(|v| v.as_str().and_then(decode_32))
        .collect::<Option<Vec<CoordinatorNodeId>>>()?;
    Some(EpochCoordinators::elect(epoch, &beacon, &roster))
}

/// The election's whole claim is public verifiability: a node's rank for a
/// tier is `H(beacon ‖ epoch ‖ tier ‖ node_id)`, so nobody can nominate
/// themselves. That property belongs to the *draw*, not to a JSON document
/// describing one — and until this check existed the wallet believed the
/// document. Anything relaying it could have named itself leader of every
/// tier, and every wallet asking for a coordinator would have been sent to it
/// (#697).
///
/// What recomputing buys: the published `tiers` — each tier's leader and
/// failover order — and the `leads` beside each coordinator must actually follow
/// from the beacon and roster published with them. A relay that edits a leader,
/// reorders a failover path, or drops a node from the roster is refused.
///
/// What it does not buy, and this matters: the beacon and roster arrive from
/// the same place as the result. A node that lies about *both*, consistently,
/// still produces a self-consistent election. The beacon is the half that can
/// be pinned — it is `SHA256(domain ‖ epoch ‖ block_hash_at(anchor_height))`,
/// so a wallet with chain access can re-derive it and refuse a fabricated
/// one; `anchor_height` is published for exactly that. The roster is the
/// remaining trusted input; comparing it across nodes (`roster_commitment`)
/// catches a unilateral liar, and closing it fully needs consensus.
pub fn election_is_honest(election: &serde_json::Value) -> bool {
    let Some(expected) = recompute(election) else {
        return false;
    };

    // Every tier, in order, with exactly the recomputed failover path.
    let Some(tiers) = election.get("tiers").and_then(|t| t.as_array()) else {
        return false;
    };
    if tiers.len() != expected.tiers.len() {
        return false;
    }
    for (claimed, want) in tiers.iter().zip(&expected.tiers) {
        if claimed.get("tier").and_then(|t| t.as_str()) != Some(want.tier_id.as_str()) {
            return false;
        }
        let Some(order) = claimed.get("order").and_then(|o| o.as_array()).map(|o| {
            o.iter()
                .map(|v| v.as_str().and_then(decode_32))
                .collect::<Option<Vec<CoordinatorNodeId>>>()
        }) else {
            return false;
        };
        if order.as_deref() != Some(want.order.as_slice()) {
            return false;
        }
    }

    // The per-node summary must agree too: it is what a reader looks at, and a
    // relay could otherwise leave `tiers` intact and forge `leads`.
    let Some(coordinators) = election.get("coordinators").and_then(|c| c.as_array()) else {
        return false;
    };
    coordinators.iter().all(|c| {
        let Some(id) = c
            .get("node_id")
            .and_then(|n| n.as_str())
            .and_then(decode_32)
        else {
            return false;
        };
        let Some(leads) = c.get("leads").and_then(|l| l.as_array()) else {
            return false;
        };
        let leads: Vec<&str> = leads.iter().filter_map(|t| t.as_str()).collect();
        expected.is_coordinator(&id) && leads == expected.tiers_led_by(&id)
    })
}

/// The endpoints to dial for `tier_id`, leader first, in the tier's failover
/// order — recomputed from the document's inputs, never read from its claims.
///
/// Endpoints come from `coordinators[].endpoint`; a node that advertises none
/// is skipped rather than holding a place. Empty if the inputs are missing.
/// Call [`election_is_honest`] first: this answers "who", not "should I".
pub fn endpoints_for_tier(election: &serde_json::Value, tier_id: &str) -> Vec<String> {
    let Some(schedule) = recompute(election) else {
        return Vec::new();
    };
    let Some(tier) = schedule.for_tier(tier_id) else {
        return Vec::new();
    };
    let published = election
        .get("coordinators")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let endpoint_of = |id: &CoordinatorNodeId| -> Option<String> {
        published
            .iter()
            .find(|c| {
                c.get("node_id")
                    .and_then(|n| n.as_str())
                    .and_then(decode_32)
                    .as_ref()
                    == Some(id)
            })?
            .get("endpoint")?
            .as_str()
            .filter(|e| !e.trim().is_empty())
            .map(String::from)
    };
    tier.order.iter().filter_map(endpoint_of).collect()
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
