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
//! The functions were written for the wallet (#697) and moved unchanged.

use crate::epoch::{derive_beacon, snapshot_height_for_epoch};
use crate::sortition::{verify_election, CoordinatorNodeId, ElectedCoordinator};

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
pub fn election_is_honest(election: &serde_json::Value) -> bool {
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
