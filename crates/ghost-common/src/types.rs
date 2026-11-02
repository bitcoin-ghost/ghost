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
//| FILE: types.rs                                                                                                       |
//|======================================================================================================================|

//! Common types used across Bitcoin Ghost

use serde::{Deserialize, Serialize};

/// 32-byte Node ID (Ed25519 public key)
pub type NodeId = [u8; 32];

/// 32-byte block hash
pub type BlockHash = [u8; 32];

/// 32-byte transaction ID
pub type Txid = [u8; 32];

/// 64-byte Ed25519 signature
pub type Signature = [u8; 64];

/// Round identifier
pub type RoundId = u64;

/// Block height
pub type BlockHeight = u64;

/// Amount in satoshis
pub type Satoshis = u64;

/// Capacity state for load balancing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityState {
    /// Below 50% capacity
    Healthy,
    /// 50-75% capacity
    Normal,
    /// 75-90% capacity
    SoftLimit,
    /// Above 90% capacity
    HardLimit,
}

impl CapacityState {
    /// Calculate from current/max miners
    ///
    /// M-25: Uses integer arithmetic to avoid floating-point imprecision.
    /// `(current * 100) / max` gives the integer percentage (truncated).
    pub fn from_load(current: u32, max: u32) -> Self {
        if max == 0 {
            return Self::HardLimit;
        }
        // M-25: Integer percentage — u64 intermediate prevents u32 overflow
        let percent = (current as u64 * 100) / max as u64;
        if percent < 50 {
            Self::Healthy
        } else if percent < 75 {
            Self::Normal
        } else if percent < 90 {
            Self::SoftLimit
        } else {
            Self::HardLimit
        }
    }

    /// Get load penalty for scoring
    pub fn load_penalty(&self) -> f64 {
        match self {
            Self::Healthy => 0.0,
            Self::Normal => 0.1,
            Self::SoftLimit => 0.3,
            Self::HardLimit => 1.0,
        }
    }
}

/// Health ping message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthPing {
    /// Sender node ID
    pub node_id: NodeId,
    /// Public address for P2P connections
    pub public_address: String,
    /// Current block height
    pub block_height: BlockHeight,
    /// Current round ID
    pub round_id: RoundId,
    /// Connected miners count
    pub miner_count: u32,
    /// Timestamp
    pub timestamp: u64,
    /// PoW proof for Sybil resistance (nonce, difficulty)
    /// Proves computational work was done to create this identity
    #[serde(default)]
    pub pow_proof: Option<(u64, u32)>,
    /// Whether the SENDER's own Ghost Core was reachable when this ping was built (#778).
    ///
    /// ⚠ `Option`, not `bool`, and the distinction is the whole point. Mesh liveness is
    /// independent of Core: vm8 gossiped `peer_count: 7` for 2h15m on 2026-08-24 while its
    /// `ghostd` crash-looped 260 times, so a peer being *reachable* says nothing about whether
    /// it can serve a miner. But a plain bool makes "did not report" and "reported false"
    /// identical on the wire, which is exactly the ambiguity that made capability flags flap in
    /// #518 — peers blinked out of the public list because an all-default ping was taken at face
    /// value.
    ///
    /// So: `None` = the sender predates this field; `Some(false)` = it says its Core is down.
    /// Consumers must treat those differently, or a rolling deploy black-holes routing the
    /// moment one node out-runs the others.
    #[serde(default)]
    pub core_healthy: Option<bool>,
    /// Truncated SHA-256 hashes of miner_ids active in the last N seconds on
    /// the sender. Used by peers to compute a deduplicated mesh-wide active
    /// miner count without leaking miner_ids in cleartext.
    /// Field is `#[serde(default)]` for backward compatibility — older nodes
    /// that don't include it deserialize to an empty Vec.
    #[serde(default, with = "ghost_common_active_hashes")]
    pub active_miner_id_hashes: Vec<[u8; 16]>,
    /// This node's own realized hashrate (TH/s) over a trailing window,
    /// computed from shares THIS node received directly (scoped by
    /// `received_by`, so replicated peer share-proofs aren't counted). Peers
    /// SUM these across the mesh for a pool-wide total: shares are partitioned
    /// by node, so the sum can't double-count and is identical on every node,
    /// and a miner migrating between nodes shifts work from one term to another
    /// without changing the total. `#[serde(default)]` for backward
    /// compatibility — older nodes that don't send it contribute 0.
    #[serde(default)]
    pub local_hashrate_th: f64,
    /// Hardware-derived effective miner capacity. Translator's load balancer
    /// uses `miner_count / max_capacity` to compute utilisation and route
    /// new arrivals to the under-utilised peer. 0 = pre-update node (treated
    /// as unknown / excluded from utilisation routing).
    #[serde(default)]
    pub max_capacity: u32,
    /// This node's best (rarest) valid share per public records window
    /// (`block | day | week | month`). Gossiped so every node knows the
    /// global best per window and the `/api/v1/pool/records` endpoint can
    /// return the mesh-wide rarest record instead of only its local one —
    /// without that, the pool-wide record lives on a single node and the
    /// website (which fans out and takes the min) flickers whenever that
    /// node is momentarily unreachable. `#[serde(default)]` for backward
    /// compatibility — older nodes that don't send it deserialise to an
    /// empty Vec, and newer nodes simply ignore peers that omit it.
    #[serde(default)]
    pub best_records: Vec<WindowBestRecord>,
    /// This node's SV1 **hobby** stratum listener, and its **farm** listener when it runs one.
    ///
    /// The load balancer became tier-aware in #494 but nothing advertised which listeners a node
    /// actually runs, so no peer was ever a farm-routing candidate and the busiest node could not
    /// shed a farm miner. This is the half that switches it on (#495).
    ///
    /// `None` on a peer that predates this field. The consumer treats absent-hobby as "serves the
    /// default 3333", which is what every node did before the farm tier existed, and absent-farm
    /// as "not a farm target" — assuming a farm port is how a farm miner lands on a hobby floor,
    /// so absence disqualifies rather than defaults. A partial rollout therefore degrades to
    /// "no farm routing", never to misrouting.
    #[serde(default)]
    pub hobby_port: Option<u16>,
    /// See `hobby_port`. `None` means either "no farm tier" or "too old to say", and both must be
    /// treated identically: not a farm routing target.
    #[serde(default)]
    pub farm_port: Option<u16>,
    /// This node's own trailing-7-day uptime, as a PERCENTAGE (0-100).
    /// Gossiped so the dashboard Swarm page can render each mesh peer's uptime
    /// instead of a dash. `Option` (not a plain `f64` defaulting to 0.0) so an
    /// older peer that omits it — or one with no uptime samples yet — is shown
    /// as "—" rather than a misleading 0.0%. `#[serde(default)]` → `None` when
    /// absent, keeping the wire change additive for a mixed-version fleet.
    #[serde(default)]
    pub uptime_percent: Option<f64>,
    /// The number of mesh peers THIS node currently sees (its own deduplicated
    /// peer count). Gossiped so the Swarm page can show each peer's connectivity.
    /// `Option` so absence (older peer) renders as "—", never a misleading 0.
    /// `#[serde(default)]` for backward compatibility.
    #[serde(default)]
    pub peer_count: Option<u32>,
}

/// One node's best (rarest) valid share in a public records window.
///
/// Carried in [`HealthPing::best_records`] so every node can converge on the
/// mesh-wide rarest record per window. The `share_hash` is the canonical
/// record (lower = rarer); all other fields are derived presentation data
/// already shaped the way the records API returns them, so a receiving node
/// can serve a peer's record verbatim without re-querying.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct WindowBestRecord {
    /// Records window this record belongs to: `block | day | week | month`.
    pub window: String,
    /// 64-char zero-padded big-endian hex of the share hash. Fixed width, so
    /// lexicographic string comparison matches numeric order (lower = rarer).
    pub share_hash: String,
    /// Achieved difficulty derived from `share_hash` (the score), matching the
    /// `difficulty` the records API returns.
    pub difficulty: f64,
    /// Unix-seconds timestamp of the share.
    pub timestamp: i64,
    /// Redacted miner_id (e.g. `bc1q7z…y492.avalon1`), already shaped the same
    /// way the records API redacts — never the raw miner_id.
    pub miner_id_redacted: String,
}

/// Hex-encoded serialization for the active miner-id hash list.
/// Keeps health-ping JSON human-readable and matches the `serde_hex` style
/// used elsewhere for fixed-size byte arrays in this module.
mod ghost_common_active_hashes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &[[u8; 16]], s: S) -> Result<S::Ok, S::Error> {
        let hex_strs: Vec<String> = v.iter().map(hex::encode).collect();
        serde::Serialize::serialize(&hex_strs, s)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 16]>, D::Error> {
        let hex_strs: Vec<String> = Vec::deserialize(d)?;
        let mut out = Vec::with_capacity(hex_strs.len());
        for s in hex_strs {
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 16 {
                return Err(serde::de::Error::custom(format!(
                    "expected 16 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            out.push(arr);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity_state() {
        assert_eq!(CapacityState::from_load(10, 100), CapacityState::Healthy);
        assert_eq!(CapacityState::from_load(60, 100), CapacityState::Normal);
        assert_eq!(CapacityState::from_load(80, 100), CapacityState::SoftLimit);
        assert_eq!(CapacityState::from_load(95, 100), CapacityState::HardLimit);
    }

    fn sample_health_ping() -> HealthPing {
        HealthPing {
            node_id: [7u8; 32],
            public_address: String::new(),
            block_height: 0,
            round_id: 0,
            miner_count: 2,
            timestamp: 1,
            pow_proof: None,
            core_healthy: None,
            active_miner_id_hashes: vec![[1u8; 16], [2u8; 16]],
            local_hashrate_th: 4.0,
            max_capacity: 0,
            hobby_port: None,
            farm_port: None,
            best_records: vec![WindowBestRecord {
                window: "day".to_string(),
                share_hash: "0".repeat(8) + &"f".repeat(56),
                difficulty: 4096.0,
                timestamp: 1,
                miner_id_redacted: "bc1q7z…y492.avalon1".to_string(),
            }],
            uptime_percent: Some(99.5),
            peer_count: Some(3),
        }
    }

    #[test]
    fn health_ping_telemetry_roundtrip() {
        // The new Swarm telemetry fields survive a round-trip.
        let ping = sample_health_ping();
        let back: HealthPing =
            serde_json::from_str(&serde_json::to_string(&ping).unwrap()).unwrap();
        assert_eq!(back.uptime_percent, Some(99.5));
        assert_eq!(back.peer_count, Some(3));
    }

    #[test]
    fn health_ping_deserializes_without_telemetry_fields() {
        // Emulate an OLDER node's ping that predates the Swarm telemetry fields:
        // serialize, strip each new field, and confirm every one defaults to
        // `None` (rendered as "—", never a fabricated 0). Proves the wire change
        // is additive so a mixed-version rolling deploy stays compatible.
        let ping = sample_health_ping();
        let mut v = serde_json::to_value(&ping).unwrap();
        let obj = v.as_object_mut().unwrap();
        assert!(obj.remove("uptime_percent").is_some());
        assert!(obj.remove("peer_count").is_some());
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert_eq!(back.uptime_percent, None);
        assert_eq!(back.peer_count, None);
        // Unrelated fields are unaffected.
        assert_eq!(back.miner_count, 2);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
    }

    #[test]
    fn health_ping_hashrate_roundtrip() {
        let ping = sample_health_ping();
        let json = serde_json::to_string(&ping).unwrap();
        let back: HealthPing = serde_json::from_str(&json).unwrap();
        assert_eq!(back.local_hashrate_th, 4.0);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
    }

    #[test]
    fn health_ping_deserializes_without_hashrate_field() {
        // Emulate an OLDER node's ping that predates `local_hashrate_th`:
        // serialize, strip the field, and confirm it defaults to 0.0 (and the
        // rest of the ping is unaffected). Proves the wire change is additive.
        let ping = sample_health_ping();
        let mut v = serde_json::to_value(&ping).unwrap();
        assert!(v
            .as_object_mut()
            .unwrap()
            .remove("local_hashrate_th")
            .is_some());
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert_eq!(back.local_hashrate_th, 0.0);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
        assert_eq!(back.miner_count, 2);
    }

    #[test]
    fn health_ping_best_records_roundtrip() {
        let ping = sample_health_ping();
        let json = serde_json::to_string(&ping).unwrap();
        let back: HealthPing = serde_json::from_str(&json).unwrap();
        assert_eq!(back.best_records, ping.best_records);
    }

    #[test]
    fn health_ping_deserializes_without_best_records_field() {
        // Emulate an OLDER node's ping that predates `best_records`: serialize,
        // strip the field, and confirm it defaults to an empty Vec (and the
        // rest of the ping is unaffected). Proves the wire change is additive
        // so a mixed-version rolling deploy stays compatible.
        let ping = sample_health_ping();
        let mut v = serde_json::to_value(&ping).unwrap();
        assert!(v.as_object_mut().unwrap().remove("best_records").is_some());
        let back: HealthPing = serde_json::from_value(v).unwrap();
        assert!(back.best_records.is_empty());
        assert_eq!(back.miner_count, 2);
        assert_eq!(back.active_miner_id_hashes.len(), 2);
    }

    // ---- GHOST-09: ShareProof received_by authentication ----
}
