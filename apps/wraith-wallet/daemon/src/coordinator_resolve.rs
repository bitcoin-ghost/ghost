//! Resolve which seated Wraith coordinator owns a wallet's mix, from the node's
//! published election view — so a wallet can mix without being handed a
//! coordinator URL.
//!
//! Inc 5 of `tasks/plan_coordinator_activation.md` — the daemon-side plumbing.
//! This is the channel-agnostic *picker*: it takes the election JSON and returns
//! the owning seat's endpoint. The wallet must obtain that JSON **through
//! ghost-pay**, never by reaching the node's pool API directly (wallet hard rule,
//! `apps/wraith-wallet/CLAUDE.md`) — so the fetch path is a small ghost-pay relay
//! wired together with the GUI "use the network-elected coordinator" toggle (the
//! explicitly-deferred next task). Hence `allow(dead_code)` for now: tested and
//! ready, just not yet called.
#![allow(dead_code)]

use wraith_protocol::sortition::shard_for;

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

// NOTE: the *fetch* of the election JSON is deliberately not here. The wallet
// must request it via ghost-pay (hard rule: never hit the node's pool API
// directly), so the relay + the GUI toggle that supplies the shard key land
// together in the next task. This module owns only the channel-agnostic pick.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
