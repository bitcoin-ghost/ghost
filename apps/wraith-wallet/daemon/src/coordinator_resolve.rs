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
use wraith_protocol::sortition::shard_for;

/// Domain separator for the coordinator shard key.
const SHARD_KEY_DOMAIN: &[u8] = b"ghost/wraith/coordinator-shard/v1";

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
/// a larger anonymity set. `SHA256(domain || tier_le || epoch_le)`.
pub fn shard_key_for_tier_epoch(tier_id: u32, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SHARD_KEY_DOMAIN);
    h.update(tier_id.to_le_bytes());
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
    tier_id: u32,
) -> (Option<String>, Option<u64>) {
    let epoch = election.get("epoch").and_then(|e| e.as_u64());
    let endpoint =
        epoch.and_then(|ep| pick_seat_endpoint(election, &shard_key_for_tier_epoch(tier_id, ep)));
    (endpoint, epoch)
}

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

    #[test]
    fn shard_key_is_deterministic_and_separates_tier_and_epoch() {
        // Stable for the same (tier, epoch) → wallets converge.
        assert_eq!(
            shard_key_for_tier_epoch(2, 100),
            shard_key_for_tier_epoch(2, 100)
        );
        // Different tier OR epoch → different key.
        assert_ne!(
            shard_key_for_tier_epoch(2, 100),
            shard_key_for_tier_epoch(3, 100)
        );
        assert_ne!(
            shard_key_for_tier_epoch(2, 100),
            shard_key_for_tier_epoch(2, 101)
        );
    }

    #[test]
    fn resolve_from_election_uses_epoch_and_falls_back() {
        let s = json!({
            "enabled": true,
            "epoch": 42,
            "coordinators": [
                {"node_id":"aa","seat":0,"endpoint":"http://a:9100"},
                {"node_id":"bb","seat":1,"endpoint":"http://b:9100"},
            ]
        });
        let (ep, epoch) = resolve_from_election(&s, 2);
        assert_eq!(epoch, Some(42));
        assert!(matches!(
            ep.as_deref(),
            Some("http://a:9100") | Some("http://b:9100")
        ));

        // No epoch (election pending) → no endpoint, caller falls back.
        let pending = json!({ "enabled": true, "epoch": null, "coordinators": [] });
        assert_eq!(resolve_from_election(&pending, 2), (None, None));
        // Disabled → nothing.
        let off = json!({ "enabled": false });
        assert_eq!(resolve_from_election(&off, 2), (None, None));
    }
}
