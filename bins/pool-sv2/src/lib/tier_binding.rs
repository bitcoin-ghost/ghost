//! pool_sv2's half of the difficulty-tier commitment (SHARE_TIER_BIND).
//!
//! ghost-pool gates by block height (`SHARE_TIER_BIND_HEIGHT`, dormant at `u64::MAX`); this
//! binary has no chain view, so its half is the `[share_tier_binding]` config section — but the
//! per-template decision is derived from the BIP34 height ghost-pool stamps into every
//! template's `coinbase_prefix`, so with the SAME height configured both binaries flip at the
//! same block rather than at whichever moment this process restarted. The remaining desync
//! surface is a mis-copied height or node id, which is why the config carries both explicitly
//! and why [`TierBinding::from_config`] refuses to start on a malformed id.
//!
//! ## What tiered mode changes
//!
//! Below the gate (config absent, or template height below `activation_height`): ONE
//! group-channel job per template, the plain node tag riding in the template's
//! `coinbase_prefix`, byte-identical to today.
//!
//! At/above the gate: per-channel jobs, each built by the channel's own factory with
//! - the plain node tag STRIPPED from the template prefix ([`strip_plain_node_tag`]), and
//! - the tier-bound tag `sha256(node_id ‖ tier)[..20]` stamped as an extra scriptSig push via
//!   the factory's budget-guarded `extra_script_sig` path ([`TierBinding::stamp_for_tier`]).
//!
//! Same 25 encoded bytes out, same 25 in — the coinbase length does not move (the live
//! scriptSig is at 99/100, so this is load-bearing, and pinned by test in both this module and
//! the vendored crate). Tag extraction on the verifying side is push-aware and
//! position-independent (`ghost_common::coinbase_tags::extract_node_tag`), so the tag moving
//! from before the pool tag to after it changes nothing for verification.

use ghost_common::coinbase_tags::{
    difficulty_to_tier_log2, encode_node_tag, node_commitment_for_tier, tier_target_difficulty,
    NODE_ID_LEN, NODE_TAG_MAGIC, PAYOUT_ID_LEN, PAYOUT_TAG_MAGIC,
};
use stratum_apps::stratum_core::{
    bitcoin::Target, channels_sv2::target::tier_target, template_distribution_sv2::NewTemplate,
};
use tracing::warn;

/// The resolved `[share_tier_binding]` config: this node's identity and the arming height.
#[derive(Debug, Clone)]
pub struct TierBinding {
    node_id: [u8; 32],
    activation_height: u64,
}

impl TierBinding {
    /// Parse the config section. A malformed `node_id` is a refusal to start, not a warning:
    /// stamping tags derived from the wrong identity would have every tier-era share rejected
    /// by its binding check, silently, on every share.
    pub fn from_config(cfg: &crate::config::ShareTierBindingConfig) -> Result<Self, String> {
        let bytes = hex::decode(cfg.node_id.trim())
            .map_err(|e| format!("share_tier_binding.node_id is not valid hex: {e}"))?;
        let node_id: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
            format!(
                "share_tier_binding.node_id must be 32 bytes (64 hex chars), got {}",
                b.len()
            )
        })?;
        Ok(Self {
            node_id,
            activation_height: cfg.activation_height,
        })
    }

    /// The height at/above which per-tier jobs are emitted.
    pub fn activation_height(&self) -> u64 {
        self.activation_height
    }

    /// Whether jobs for `template` must be tiered: its BIP34 height is at/above the configured
    /// activation height.
    ///
    /// An unparseable height fails toward DORMANT, loudly. Dormant is the recoverable direction:
    /// ghost-pool's verifier rejects above-gate shares that lack a tier (`missing_tier`, a
    /// counted, visible reject), whereas emitting tier stamps below the gate would put unexpected
    /// bytes in mined coinbases.
    pub fn template_is_tiered(&self, template: &NewTemplate<'_>) -> bool {
        match bip34_height(template.coinbase_prefix.inner_as_ref()) {
            Some(height) => height >= self.activation_height,
            None => {
                warn!(
                    template_id = template.template_id,
                    "SHARE_TIER_BIND: cannot parse a BIP34 height from the template's \
                     coinbase_prefix — treating this template as BELOW the gate. If the chain is \
                     past the activation height this node is emitting untiered jobs and its \
                     shares will be rejected (missing_tier) by every verifier"
                );
                false
            }
        }
    }

    /// The tier a channel currently mines at, from its target.
    pub fn tier_for_target(&self, target: &Target) -> u32 {
        difficulty_to_tier_log2(target.difficulty_float())
    }

    /// The commitment a job at `tier_log2` must stamp: `(tier_log2, encoded GHNT push)` carrying
    /// `sha256(node_id ‖ tier_log2)[..20]` — the same 25 encoded bytes as the plain tag this
    /// replaces.
    pub fn stamp_for_tier(&self, tier_log2: u32) -> (u32, Vec<u8>) {
        (
            tier_log2,
            encode_node_tag(&node_commitment_for_tier(&self.node_id, tier_log2)),
        )
    }

    /// Convenience: the commitment for a channel's current target.
    pub fn stamp_for_target(&self, target: &Target) -> (u32, Vec<u8>) {
        self.stamp_for_tier(self.tier_for_target(target))
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
/// ghost-pool builds this with `TemplateProcessor::encode_height`: one push opcode (1..=4 here;
/// 8 allowed for robustness) followed by that many little-endian bytes.
pub fn bip34_height(coinbase_prefix: &[u8]) -> Option<u64> {
    let len = *coinbase_prefix.first()? as usize;
    if len == 0 || len > 8 {
        return None;
    }
    let bytes = coinbase_prefix.get(1..1 + len)?;
    let mut height = 0u64;
    for (i, b) in bytes.iter().enumerate() {
        height |= (*b as u64) << (8 * i);
    }
    Some(height)
}

/// One Ghost coinbase tag is one push: `[len][magic][payload]`. Present or absent, never partial.
fn tag_len_at(bytes: &[u8], magic: &[u8; 4], payload_len: usize) -> usize {
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
/// one ghost-pool's `template_provider.rs` emits — height, then optionally `GHPP`, then
/// optionally `GHNT` — detected exactly as that code detects it, not assumed.
///
/// A template with no node tag (a treasury-only coinbase, or a foreign TP) passes through
/// byte-identical; the caller still stamps the tier tag, which is then the coinbase's ONLY node
/// commitment.
pub fn strip_plain_node_tag(template: &NewTemplate<'static>) -> NewTemplate<'static> {
    let prefix = template.coinbase_prefix.inner_as_ref();

    let Some(height_len) = prefix.first().map(|l| 1 + *l as usize) else {
        return template.clone();
    };
    if prefix.len() < height_len {
        return template.clone();
    }
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
    use ghost_common::coinbase_tags::{encode_payout_tag, extract_node_tag, extract_payout_tag};
    use stratum_apps::stratum_core::channels_sv2::target::hash_rate_to_target;

    fn a_binding(height: u64) -> TierBinding {
        TierBinding::from_config(&crate::config::ShareTierBindingConfig {
            node_id: hex::encode([0x7Au8; 32]),
            activation_height: height,
        })
        .unwrap()
    }

    fn ghost_prefix(with_node_tag: bool) -> Vec<u8> {
        // BIP34 height 960_000 quantised as ghost-pool encodes it: 0x03 push + 3 LE bytes.
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

    /// The height ghost-pool encodes must read back exactly, for each encoding width it emits.
    #[test]
    fn bip34_height_round_trips_ghost_pools_encodings() {
        // The widths `TemplateProcessor::encode_height` produces.
        assert_eq!(bip34_height(&[0x01, 0x7f]), Some(0x7f));
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

    /// The gate: strictly below → untiered; at and above → tiered. Same boundary sense as
    /// ghost-pool's `binds_difficulty_tier`.
    #[test]
    fn the_template_gate_flips_at_the_activation_height() {
        let binding = a_binding(960_000);
        let below = a_template(vec![0x03, 0xff, 0xa5, 0x0e]); // 959_999
        let at = a_template(vec![0x03, 0x00, 0xa6, 0x0e]); // 960_000
        assert!(!binding.template_is_tiered(&below));
        assert!(binding.template_is_tiered(&at));
    }

    /// **The zero-byte budget claim, on real bytes.** Stripping the plain tag and stamping the
    /// tier tag must leave the total scriptSig contribution the same length, and the tag
    /// readable by the verifying side's push-aware extractor.
    #[test]
    fn the_stamp_costs_exactly_the_bytes_the_strip_recovers() {
        let binding = a_binding(0);
        let template = a_template(ghost_prefix(true));
        let stripped = strip_plain_node_tag(&template);
        let (tier, push) = binding.stamp_for_tier(13);

        assert_eq!(tier, 13);
        assert_eq!(
            template.coinbase_prefix.inner_as_ref().len(),
            stripped.coinbase_prefix.inner_as_ref().len() + push.len(),
            "strip + stamp must be byte-neutral on the assembled scriptSig"
        );

        // The payout tag survives the strip; the plain node tag does not.
        let s = stripped.coinbase_prefix.inner_as_ref();
        assert_eq!(extract_payout_tag(s), Some([0xC3; 16]));
        assert_eq!(extract_node_tag(s), None);

        // And the stamped push reads back as the tier-bound commitment, exactly.
        assert_eq!(
            extract_node_tag(&push),
            Some(node_commitment_for_tier(&[0x7Au8; 32], 13)),
            "the extractor must read the tier commitment out of the stamped push"
        );
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
        let binding = a_binding(0);
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
            assert!(
                TierBinding::from_config(&crate::config::ShareTierBindingConfig {
                    node_id: bad.to_string(),
                    activation_height: 0,
                })
                .is_err()
            );
        }
    }
}
