//! This node's identity and the difficulty-tier arithmetic the node pool's share tags use.
//!
//! pool_sv2 builds a job per channel; the `GhostShare/v2` tag commits the channel's tier, so the
//! announced target must be exactly a tier's target ([`TierBinding::quantise_target`]). The
//! identity is read from the co-located ghost-mining at startup ([`TierBinding::resolve`]).
//! The template's own Ghost tags are taken out of its prefix ([`strip_plain_node_tag`],
//! `NodePool::prepare_template`) and the per-channel stamp put back, byte for byte.

use ghost_common::coinbase_tags::{
    bip34_height_from, difficulty_to_tier_log2, tier_target_difficulty, NODE_ID_LEN,
    NODE_TAG_MAGIC, PAYOUT_ID_LEN, PAYOUT_TAG_MAGIC,
};
use stratum_apps::stratum_core::{
    bitcoin::Target, channels_sv2::target::tier_target, template_distribution_sv2::NewTemplate,
};
use tracing::warn;

/// This node's resolved identity, and the tier arithmetic.
#[derive(Debug, Clone)]
pub struct TierBinding {
    node_id: [u8; 32],
}

/// Where this node's identity is read from when the config does not pin one.
const DEFAULT_HEALTH_URL: &str = "http://127.0.0.1:8080/health";

impl TierBinding {
    /// Build from an already-resolved identity.
    pub fn from_parts(node_id: [u8; 32]) -> Self {
        Self { node_id }
    }

    /// Parse a 64-hex node id. A malformed id is a refusal to start, not a warning: stamping tags
    /// derived from the wrong identity would have every tier-era share rejected by its binding
    /// check, silently, on every share.
    pub fn parse_node_id(s: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(s.trim())
            .map_err(|e| format!("node_pool.node_id is not valid hex: {e}"))?;
        bytes.try_into().map_err(|b: Vec<u8>| {
            format!(
                "node_pool.node_id must be 32 bytes (64 hex chars), got {}",
                b.len()
            )
        })
    }

    /// Pull `response.node_id` out of ghost-mining's health document.
    pub fn node_id_from_health_json(body: &str) -> Result<[u8; 32], String> {
        let v: serde_json::Value = serde_json::from_str(body)
            .map_err(|e| format!("ghost-mining health is not JSON: {e}"))?;
        let id = v
            .get("response")
            .and_then(|r| r.get("node_id"))
            .and_then(|n| n.as_str())
            .ok_or_else(|| "ghost-mining health has no response.node_id".to_string())?;
        Self::parse_node_id(id)
    }

    /// Resolve this node's identity, preferring **ghost-mining's own answer** over anything
    /// transcribed into config.
    ///
    /// `pool_sv2` cannot derive the raw id itself: the template prefix carries
    /// `sha256(node_id)[..20]`, which is one-way. It previously had to be typed into the config of
    /// every node individually — a per-node manual step in the consensus-visible path, where a
    /// single wrong character silently rejects that node's tier-era shares and nothing in the
    /// coinbase reveals it. Asking the process that derives and verifies those tags removes the
    /// step entirely, and makes the two impossible to disagree.
    ///
    /// A pinned `node_id` is still honoured, but it is CHECKED: a mismatch refuses startup rather
    /// than letting a stale value quietly win.
    pub async fn resolve(
        node_id: Option<&str>,
        ghost_pool_health_url: Option<&str>,
    ) -> Result<Self, String> {
        let url = ghost_pool_health_url.unwrap_or(DEFAULT_HEALTH_URL);
        let pinned = node_id.map(Self::parse_node_id).transpose()?;

        // ghost-mining may still be starting; the deploy order restarts it first.
        let mut fetched: Result<[u8; 32], String> = Err("not attempted".into());
        for attempt in 1..=5u32 {
            fetched = async {
                let body = reqwest::Client::new()
                    .get(url)
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await
                    .map_err(|e| format!("cannot reach ghost-mining at {url}: {e}"))?
                    .text()
                    .await
                    .map_err(|e| format!("cannot read ghost-mining health: {e}"))?;
                Self::node_id_from_health_json(&body)
            }
            .await;
            if fetched.is_ok() {
                break;
            }
            if attempt < 5 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        let node_id = match (fetched, pinned) {
            // Both available: they MUST agree. A mismatch is the exact failure the pin was
            // supposed to guard against, so it stops the node rather than picking a winner.
            (Ok(f), Some(p)) if f != p => {
                return Err(format!(
                    "node_pool.node_id ({}) does not match the identity ghost-mining \
                     reports ({}). ghost-mining stamps and verifies the coinbase node tags, so the \
                     configured value would reject every tier-era share on this node. Remove the \
                     pin to use ghost-mining's own identity.",
                    hex::encode(&p[..8]),
                    hex::encode(&f[..8]),
                ))
            }
            (Ok(f), _) => f,
            // Unreachable but pinned: honour the operator's value rather than refusing to start
            // over a health endpoint, but say plainly that it is unverified.
            (Err(e), Some(p)) => {
                warn!(
                    error = %e,
                    "NODE_POOL: could not verify node_id against ghost-mining — using the \
                     configured value UNVERIFIED. If it is wrong, this node's tier-era shares \
                     will all fail their binding check."
                );
                p
            }
            // Nothing to fall back on. Refusing is the safe direction: emitting tags from a
            // guessed identity is undetectable from the coinbase.
            (Err(e), None) => {
                return Err(format!(
                    "the node pool needs this node's identity, and it could not be read \
                     from ghost-mining ({e}). Start ghost-mining first, or pin node_id explicitly."
                ))
            }
        };

        Ok(Self::from_parts(node_id))
    }

    /// This node's identity, as resolved.
    pub fn node_id(&self) -> &[u8; 32] {
        &self.node_id
    }

    /// The tier a channel currently mines at, from its target.
    pub fn tier_for_target(&self, target: &Target) -> u32 {
        difficulty_to_tier_log2(target.difficulty_float())
    }

    /// Quantise a channel target to its tier's EXACT target (difficulty floors to `2^tier`,
    /// i.e. the target gets easier — except below the floor tier, which clamps up).
    ///
    /// In tiered mode the announced channel target must BE a tier target, or every share is
    /// systematically under-credited: the coinbase can only commit to `2^tier` while the miner
    /// works at the (up to 2× harder) raw vardiff target. This is the pool-side mirror of the
    /// translator's `quantise_to_tiers`.
    ///
    /// `requested_max` is the easiest target the client accepts. If quantising would exceed it,
    /// the RAW target is kept and the mismatch reported by the caller — refusing the channel
    /// outright over a courtesy quantisation would turn a tuning step into an outage.
    pub fn quantise_target(&self, target: &Target, requested_max: &Target) -> Target {
        let q = tier_target(self.tier_for_target(target));
        if q > *requested_max {
            *target
        } else {
            q
        }
    }
}

/// The exact difficulty credited for a tier: `2^tier_log2`. Re-exported here so the share
/// reporter and the stamp derivation read the same authority (`ghost_common`).
pub fn tier_credit(tier_log2: u32) -> f64 {
    tier_target_difficulty(tier_log2)
}

/// Parse the BIP34 height push at the head of a coinbase scriptSig prefix.
///
/// ghost-mining builds it with `TemplateProcessor::encode_height`, which writes what Bitcoin Core
/// writes ([`ghost_common::coinbase_tags::bip34_height_push`]): `OP_0`, `OP_1`..`OP_16` at heights
/// 0 to 16, else a minimal script-number push. Any other encoding is refused, since Bitcoin would
/// refuse a block carrying it.
pub fn bip34_height(coinbase_prefix: &[u8]) -> Option<u64> {
    bip34_height_from(coinbase_prefix).map(|(h, _)| h)
}

/// Bytes the BIP34 height push at the head of `prefix` takes.
pub(crate) fn bip34_push_len(prefix: &[u8]) -> Option<usize> {
    bip34_height_from(prefix).map(|(_, len)| len)
}

/// One Ghost coinbase tag is one push: `[len][magic][payload]`. Present or absent, never partial.
pub(crate) fn tag_len_at(bytes: &[u8], magic: &[u8; 4], payload_len: usize) -> usize {
    let total = 1 + 4 + payload_len;
    let present = bytes.len() >= total
        && bytes[0] as usize == 4 + payload_len
        && &bytes[1..5] == magic.as_slice();
    if present {
        total
    } else {
        0
    }
}

/// Remove the plain node tag (`GHNT`) from a template's `coinbase_prefix`, leaving the height
/// push and the payout tag (`GHPP`) in place.
///
/// This is what makes the tier stamp cost zero bytes: the plain 25-byte tag comes OUT of the
/// prefix and the tier-bound 25-byte tag goes IN as the factory's extra push. The layout is the
/// one ghost-mining's `template_provider.rs` emits — height, then optionally `GHPP`, then
/// optionally `GHNT` — detected exactly as that code detects it, not assumed.
///
/// A template with no node tag (a treasury-only coinbase, or a foreign TP) passes through
/// byte-identical; the caller still stamps the tier tag, which is then the coinbase's ONLY node
/// commitment.
pub fn strip_plain_node_tag(template: &NewTemplate<'static>) -> NewTemplate<'static> {
    let prefix = template.coinbase_prefix.inner_as_ref();

    let Some(height_len) = bip34_push_len(prefix) else {
        return template.clone();
    };
    let payout_len = tag_len_at(&prefix[height_len..], PAYOUT_TAG_MAGIC, PAYOUT_ID_LEN);
    let node_at = height_len + payout_len;
    let node_len = tag_len_at(&prefix[node_at..], NODE_TAG_MAGIC, NODE_ID_LEN);
    if node_len == 0 {
        return template.clone();
    }

    let mut stripped = Vec::with_capacity(prefix.len() - node_len);
    stripped.extend_from_slice(&prefix[..node_at]);
    stripped.extend_from_slice(&prefix[node_at + node_len..]);

    let mut out = template.clone();
    out.coinbase_prefix = stripped
        .try_into()
        .expect("stripped prefix is shorter than the original, which fitted");
    out
}

/// Whether a target's difficulty is EXACTLY a power of two at or above the tier floor — the
/// shape `quantise_to_tiers` (translator) and [`TierBinding::quantise_target`] (pool) produce,
/// and which vardiff's continuous `hash_rate_to_target` output essentially never lands on by
/// chance. Used only to make a half-armed deployment LOUD, never to change behaviour.
pub fn is_tier_shaped(target: &Target) -> bool {
    let d = target.difficulty_float();
    if !d.is_finite() || d < 1024.0 {
        return false;
    }
    let t = d.log2().round();
    (0.0..=63.0).contains(&t) && d == 2.0_f64.powi(t as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::coinbase_tags::{encode_node_tag, encode_payout_tag};
    use stratum_apps::stratum_core::channels_sv2::target::hash_rate_to_target;

    fn a_binding() -> TierBinding {
        TierBinding::from_parts([0x7Au8; 32])
    }

    fn ghost_prefix(with_node_tag: bool) -> Vec<u8> {
        // BIP34 height 960_000 quantised as ghost-mining encodes it: 0x03 push + 3 LE bytes.
        let mut p = vec![0x03, 0x00, 0xa6, 0x0e];
        p.extend_from_slice(&encode_payout_tag(&[0xC3; 16]));
        if with_node_tag {
            p.extend_from_slice(&encode_node_tag(
                &ghost_common::coinbase_tags::node_commitment_plain(&[0x7Au8; 32]),
            ));
        }
        p
    }

    fn a_template(prefix: Vec<u8>) -> NewTemplate<'static> {
        NewTemplate {
            template_id: 9,
            future_template: true,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: prefix.try_into().unwrap(),
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 0,
            coinbase_tx_outputs_count: 0,
            coinbase_tx_outputs: vec![].try_into().unwrap(),
            coinbase_tx_locktime: 0,
            merkle_path: vec![].try_into().unwrap(),
        }
    }

    /// The height ghost-mining encodes must read back exactly, for each encoding width it emits.
    #[test]
    fn bip34_height_round_trips_ghost_pools_encodings() {
        // The widths `TemplateProcessor::encode_height` produces.
        assert_eq!(bip34_height(&[0x01, 0x7f]), Some(0x7f));
        // OP_0 and OP_1..OP_16 below 17, as consensus requires; a one-byte push there is refused.
        assert_eq!(bip34_height(&[0x00]), Some(0));
        assert_eq!(bip34_height(&[0x51, 0x05]), Some(1));
        assert_eq!(bip34_height(&[0x60]), Some(16));
        assert_eq!(bip34_height(&[0x01, 0x05]), None);
        assert_eq!(bip34_height(&[0x02, 0x39, 0x30]), Some(0x3039));
        assert_eq!(bip34_height(&[0x03, 0x00, 0xa6, 0x0e]), Some(960_000));
        assert_eq!(
            bip34_height(&[0x04, 0x78, 0x56, 0x34, 0x12]),
            Some(0x1234_5678)
        );
        // Garbage refuses rather than guessing.
        assert_eq!(bip34_height(&[]), None);
        assert_eq!(bip34_height(&[0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9]), None);
        assert_eq!(bip34_height(&[0x03, 0x00]), None);
    }

    /// A template with no node tag — treasury-only coinbase, or a foreign TP — passes through
    /// byte-identical. The strip must never damage what it does not recognise.
    #[test]
    fn a_tagless_template_is_untouched_by_the_strip() {
        let template = a_template(ghost_prefix(false));
        let stripped = strip_plain_node_tag(&template);
        assert_eq!(
            template.coinbase_prefix.inner_as_ref(),
            stripped.coinbase_prefix.inner_as_ref()
        );
        // Height-only, the SRI test-vector shape.
        let bare = a_template(vec![0x52, 0x00]);
        assert_eq!(
            strip_plain_node_tag(&bare).coinbase_prefix.inner_as_ref(),
            bare.coinbase_prefix.inner_as_ref()
        );
    }

    /// Quantisation floors the difficulty to its tier and respects the client's max target.
    #[test]
    fn quantisation_floors_to_the_tier_and_respects_the_client_max() {
        let binding = a_binding();
        let permissive = Target::from_le_bytes([0xff; 32]);

        let raw = hash_rate_to_target(4.5e12, 6.0).unwrap();
        let d_raw = raw.difficulty_float();
        assert!(d_raw > 1024.0, "fixture must sit above the floor tier");
        let expected_tier = d_raw.log2().floor() as u32;

        let q = binding.quantise_target(&raw, &permissive);
        assert_eq!(
            q.difficulty_float(),
            2.0_f64.powi(expected_tier as i32),
            "difficulty floors to its tier below"
        );
        assert!(q >= raw, "the quantised target is easier, never harder");
        assert!(is_tier_shaped(&q));
        assert!(!is_tier_shaped(&raw));

        // A client max HARDER than the tier target forces the raw target to stand.
        let tight_max = raw;
        assert_eq!(binding.quantise_target(&raw, &tight_max), raw);

        // Round trip: the tier of the quantised target is the tier that was stamped.
        assert_eq!(binding.tier_for_target(&q), expected_tier);
        assert_eq!(tier_credit(expected_tier), q.difficulty_float());
    }

    /// A malformed node id refuses to start rather than stamping garbage.
    #[test]
    fn a_malformed_node_id_is_refused() {
        for bad in ["zz", "abcd", &hex::encode([0u8; 31])[..]] {
            assert!(TierBinding::parse_node_id(bad).is_err());
        }
    }

    /// The identity is read from ghost-mining's real health document, so the manual per-node
    /// transcription that arming used to require is gone. Shaped exactly as the endpoint answers,
    /// including the fields around it, so a change to that document fails here rather than at a
    /// height on mainnet.
    #[test]
    fn the_identity_is_read_from_ghost_pools_health_document() {
        let body = r#"{"response":{"block_height":961983,"capabilities":{"public_mining":true},
            "healthy":true,"miner_count":2,
            "node_id":"9fe860bda96ff81820a2e166f48cb3ae59010fc9e42550a3aeafb5bfef4d1b38",
            "peer_count":7},"signed":"abc"}"#;
        let got = TierBinding::node_id_from_health_json(body).expect("identity");
        assert_eq!(
            hex::encode(got),
            "9fe860bda96ff81820a2e166f48cb3ae59010fc9e42550a3aeafb5bfef4d1b38"
        );
    }

    /// A health document that does not carry an identity must be an error, never a default. A
    /// zeroed or guessed id is undetectable from the coinbase — it simply rejects every tier-era
    /// share on that node.
    #[test]
    fn health_without_an_identity_is_an_error_not_a_default() {
        for body in [
            r#"{"response":{"healthy":true}}"#,
            r#"{"node_id":"9fe860bd"}"#,
            r#"{"response":{"node_id":"nothex"}}"#,
            r#"{"response":{"node_id":"9fe860bd"}}"#,
            "not json at all",
        ] {
            assert!(
                TierBinding::node_id_from_health_json(body).is_err(),
                "must not yield an identity from {body}"
            );
        }
    }
}
