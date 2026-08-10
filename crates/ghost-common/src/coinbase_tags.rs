//! Commitments stamped into the coinbase scriptsig.
//!
//! Two things need to be readable straight off a block, by a node that holds no local context:
//!
//! - **which payout a won block pays** (`GHPP`), so settlement is a lookup rather than an inference.
//!   It cannot be inferred from the outputs: the mined coinbase is built from a *fee-adjusted*
//!   proposal whose treasury and node amounts absorb each node's own fee drift, so it does not hash
//!   to what any stored proposal described.
//! - **which node a share was mined to** (`GHNT`), so credit for work cannot be re-attributed by a
//!   peer that merely relayed the proof.
//!
//! ## Budget
//!
//! The coinbase scriptsig has a 100-byte consensus ceiling. Measured on mainnet after the tag trim:
//!
//! ```text
//!   BIP34 height push                        4
//!   extranonce (4 pool + 16 client)         20
//!   "GHOST PublicPool"                      16   (was 24 before the trim)
//!   ------------------------------------------
//!   used                                   ~45
//!   payout tag   (1 push + 4 magic + 16)    21
//!   node tag     (1 push + 4 magic + 20)    25
//!   ------------------------------------------
//!   total                                  ~91,  leaving ~9 spare
//! ```
//!
//! Note the push opcode: a tag costs one byte more than its payload. Nine bytes is real but not
//! generous — before widening either tag, re-measure, and remember the miner-supplied portion of
//! `/pool_tag/miner_tag/` may vary.

/// Marks the payout identity a block pays.
pub const PAYOUT_TAG_MAGIC: &[u8; 4] = b"GHPP";

/// Marks the node a share was mined to.
pub const NODE_TAG_MAGIC: &[u8; 4] = b"GHNT";

/// Bytes of identity carried by a payout tag.
pub const PAYOUT_ID_LEN: usize = 16;

/// Bytes of identity carried by a node tag.
pub const NODE_ID_LEN: usize = 20;

/// Encode a tag as a single scriptsig push: `[len][magic][payload]`.
///
/// Data pushes of 75 bytes or fewer use the length itself as the opcode, so the whole tag is one
/// push and reads back as one — which is what lets extraction refuse a magic that merely appears
/// *inside* someone else's push.
fn encode_tag(magic: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + payload.len());
    out.push((4 + payload.len()) as u8);
    out.extend_from_slice(magic);
    out.extend_from_slice(payload);
    out
}

/// Scriptsig bytes committing to the payout a block pays.
///
/// The identity is deliberately generic. Before the batch-chain cutover it is the first 16 bytes of
/// the proposal hash; afterwards it is the batch identity. One field, one format, switched by
/// height — the coinbase is the one place where every node must change at the same block, so it is
/// worth not changing twice.
pub fn encode_payout_tag(payout_id: &[u8; PAYOUT_ID_LEN]) -> Vec<u8> {
    encode_tag(PAYOUT_TAG_MAGIC, payout_id)
}

/// Scriptsig bytes committing to the node that received a share.
pub fn encode_node_tag(node_commitment: &[u8; NODE_ID_LEN]) -> Vec<u8> {
    encode_tag(NODE_TAG_MAGIC, node_commitment)
}

/// Walk a scriptsig as a sequence of data pushes.
///
/// Only the small-push encodings are handled (opcodes 1..=75, plus `OP_PUSHDATA1`), which is all a
/// coinbase scriptsig legitimately uses inside 100 bytes. Anything else ends the walk rather than
/// guessing, because a misparse here would let a crafted scriptsig fake a tag.
fn pushes(scriptsig: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < scriptsig.len() {
        let opcode = scriptsig[i];
        let (len, header) = match opcode {
            0x01..=0x4b => (opcode as usize, 1usize),
            0x4c => {
                // OP_PUSHDATA1: next byte is the length.
                let Some(&n) = scriptsig.get(i + 1) else {
                    break;
                };
                (n as usize, 2usize)
            }
            _ => break,
        };
        let start = i + header;
        let Some(end) = start.checked_add(len) else {
            break;
        };
        if end > scriptsig.len() {
            break;
        }
        out.push(&scriptsig[start..end]);
        i = end;
    }
    out
}

/// Extract a tag payload of exactly `payload_len` bytes carried in its own push.
///
/// Deliberately push-aware rather than a byte scan. A scan for the magic would match the same four
/// bytes appearing inside the pool tag, the extranonce, or any other push — all attacker-influenced
/// — and would then read whatever followed as an identity.
fn extract_tag(scriptsig: &[u8], magic: &[u8; 4], payload_len: usize) -> Option<Vec<u8>> {
    pushes(scriptsig).into_iter().find_map(|push| {
        (push.len() == 4 + payload_len && &push[..4] == magic).then(|| push[4..].to_vec())
    })
}

/// Read the payout identity a coinbase commits to, if it carries one.
pub fn extract_payout_tag(scriptsig: &[u8]) -> Option<[u8; PAYOUT_ID_LEN]> {
    let payload = extract_tag(scriptsig, PAYOUT_TAG_MAGIC, PAYOUT_ID_LEN)?;
    payload.try_into().ok()
}

/// Read the node commitment a coinbase carries, if any.
pub fn extract_node_tag(scriptsig: &[u8]) -> Option<[u8; NODE_ID_LEN]> {
    let payload = extract_tag(scriptsig, NODE_TAG_MAGIC, NODE_ID_LEN)?;
    payload.try_into().ok()
}

/// Pool-wide floor difficulty tier, as a base-2 exponent.
///
/// Difficulty tiers are quantised to powers of two so that a share commits to ONE tier, and the
/// smallest tier any node may assign is `2^MIN_DIFFICULTY_TIER_LOG2`. A share whose assigned
/// difficulty is below this floors to it, so the floor tier behaves as a chain constant every node
/// agrees on — no node can conjure a sub-floor tier that its peers would not recompute.
///
/// `10` → a floor of `1024`. Re-derived 2026-08-10 against the LIVE fleet vardiff config rather
/// than an estimate, because the previous justification here (a "~500 GH/s bitaxe near difficulty
/// 1,164") did not match what the fleet actually assigns:
///
/// ```text
/// translator-config.toml: min_individual_miner_hashrate = 1_000_000_000_000  (1 TH/s)
///                         shares_per_minute             = 6.0
/// smallest assigned difficulty = 1e12 * (60/6) / 2^32 = 2_328
/// quantised                    = 2_048 = tier 11
/// ```
///
/// So the smallest tier the fleet can assign is **11**, and the floor sits a full tier below it.
/// `min_individual_miner_hashrate` is a floor on the ASSUMED hashrate, so even a 500 GH/s bitaxe is
/// sized as 1 TH/s and lands on tier 11 — the floor does not bind for any miner the fleet serves.
///
/// That headroom matters for more than rounding. `quantise_target_to_tier` clamps UP to this floor,
/// so if a node's computed difficulty ever fell BELOW `2^10` the quantised target would become
/// HARDER than the difficulty `pool_sv2` derives from `shares_per_minute`, and the channel open is
/// refused outright with `max-target-out-of-range` — the miner cannot mine at all, rather than
/// being mis-credited. Keeping the floor a tier below the fleet minimum keeps quantisation
/// monotonically downward, which is the safe direction.
///
/// ⚠ Still COUPLED to the vardiff floor with nothing enforcing it. Both sides must also agree on
/// `shares_per_minute` (fleet: 6.0 on the translator AND on `pool_sv2`); a mismatch reintroduces the
/// refusal above regardless of this constant. Re-derive both before arming.
///
/// ⚠ Dormant scaffolding: load-bearing only when `SHARE_TIER_BIND_HEIGHT` is set to a real block.
pub const MIN_DIFFICULTY_TIER_LOG2: u32 = 10;

/// Ceiling tier exponent. A difficulty at or above `2^63` is nonsensical for a share (it exceeds
/// any conceivable network difficulty), so the tier saturates here rather than overflowing the
/// shift used to recover the tier's target. Purely a safety clamp; real tiers sit far below it.
pub const MAX_DIFFICULTY_TIER_LOG2: u32 = 63;

/// Quantise an assigned/achieved difficulty to its power-of-two tier exponent.
///
/// The tier is `floor(log2(difficulty))`, clamped into
/// `[MIN_DIFFICULTY_TIER_LOG2, MAX_DIFFICULTY_TIER_LOG2]`. Vardiff hands out power-of-two targets,
/// so an honestly-assigned difficulty is already `2^tier` and round-trips exactly; anything below
/// the floor, non-finite, or non-positive floors to `MIN_DIFFICULTY_TIER_LOG2`.
///
/// This is deterministic and depends on no per-node state, which is the whole point: two nodes
/// handed the same difficulty derive the same tier, so the tier a coinbase commits to is
/// recomputable by anyone judging the share.
pub fn difficulty_to_tier_log2(difficulty: f64) -> u32 {
    if !difficulty.is_finite() || difficulty < 1.0 {
        return MIN_DIFFICULTY_TIER_LOG2;
    }
    // floor(log2(difficulty)); log2 is monotonic so this is the largest exponent e with 2^e <= d.
    let raw = difficulty.log2().floor();
    if !raw.is_finite() || raw < MIN_DIFFICULTY_TIER_LOG2 as f64 {
        return MIN_DIFFICULTY_TIER_LOG2;
    }
    if raw >= MAX_DIFFICULTY_TIER_LOG2 as f64 {
        return MAX_DIFFICULTY_TIER_LOG2;
    }
    raw as u32
}

/// The exact target difficulty a tier stands for: `2^tier_log2`.
///
/// This is what a share bound to `tier_log2` is CREDITED — never the difficulty it happened to
/// achieve. Crediting the committed tier rather than the achieved value is what removes the
/// post-hoc-claim advantage: the tier is fixed inside the hashed coinbase before the hash is known.
pub fn tier_target_difficulty(tier_log2: u32) -> f64 {
    let e = tier_log2.min(MAX_DIFFICULTY_TIER_LOG2);
    2.0_f64.powi(e as i32)
}

/// The node commitment bound to a difficulty tier: `sha256(node_id ‖ tier_log2_le)[..20]`.
///
/// The plain node commitment is `sha256(node_id)[..20]` (see `TemplateConfig::node_commitment`).
/// Folding the tier into the *same* 20-byte hash binds the tier a share was mined for without
/// spending a single extra scriptSig byte — the tag payload is still 20 bytes, so the coinbase is
/// the same length whether or not the tier is bound. The four-byte little-endian tier is appended
/// to the preimage, so the two forms never collide (their preimages differ in length).
///
/// Because the tier lives inside the coinbase, and the coinbase folds into the header's merkle
/// root, and the header is what was hashed, the tier cannot be chosen after the hash is known:
/// changing it changes the header, discarding the work.
pub fn node_commitment_for_tier(node_id: &[u8], tier_log2: u32) -> [u8; NODE_ID_LEN] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(node_id);
    h.update(tier_log2.to_le_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let mut out = [0u8; NODE_ID_LEN];
    out.copy_from_slice(&digest[..NODE_ID_LEN]);
    out
}

/// The plain, tier-free node commitment: `sha256(node_id)[..20]`.
///
/// This is the encoding stamped today. It lives here beside its tier-bound sibling so the two
/// formats are read side by side and the below-gate/above-gate switch is a single, obvious choice
/// of function rather than open-coded `sha256` in two files.
pub fn node_commitment_plain(node_id: &[u8]) -> [u8; NODE_ID_LEN] {
    use sha2::{Digest, Sha256};
    let digest: [u8; 32] = Sha256::digest(node_id).into();
    let mut out = [0u8; NODE_ID_LEN];
    out.copy_from_slice(&digest[..NODE_ID_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic scriptsig prefix: BIP34 height push, then the pool tag, then the extranonce.
    fn scriptsig_prefix() -> Vec<u8> {
        let mut s = Vec::new();
        s.push(0x03);
        s.extend_from_slice(&[0x40, 0x1f, 0x0e]); // height
        let tag = b"GHOST PublicPool";
        s.push(tag.len() as u8);
        s.extend_from_slice(tag);
        s.push(0x14);
        s.extend_from_slice(&[0xAB; 20]); // extranonce
        s
    }

    #[test]
    fn payout_tag_round_trips_within_a_realistic_scriptsig() {
        let id = [0x11u8; PAYOUT_ID_LEN];
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_payout_tag(&id));

        assert_eq!(extract_payout_tag(&s), Some(id));
        assert_eq!(extract_node_tag(&s), None, "a payout tag is not a node tag");
    }

    #[test]
    fn both_tags_coexist() {
        let payout = [0x22u8; PAYOUT_ID_LEN];
        let node = [0x33u8; NODE_ID_LEN];
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_payout_tag(&payout));
        s.extend_from_slice(&encode_node_tag(&node));

        assert_eq!(extract_payout_tag(&s), Some(payout));
        assert_eq!(extract_node_tag(&s), Some(node));
    }

    /// The whole point of parsing pushes rather than scanning bytes: the magic appearing inside
    /// someone else's push must not be read as a tag. The pool tag and the extranonce are both
    /// influenceable, so a scan would be forgeable.
    #[test]
    fn magic_hidden_inside_another_push_is_not_a_tag() {
        let mut s = Vec::new();
        s.push(0x03);
        s.extend_from_slice(&[0x40, 0x1f, 0x0e]);

        // One long push whose CONTENTS spell a well-formed-looking payout tag.
        let mut inner = Vec::new();
        inner.extend_from_slice(PAYOUT_TAG_MAGIC);
        inner.extend_from_slice(&[0x99; PAYOUT_ID_LEN]);
        s.push(inner.len() as u8 + 4);
        s.extend_from_slice(b"junk");
        s.extend_from_slice(&inner);

        assert_eq!(
            extract_payout_tag(&s),
            None,
            "magic embedded in another push must not be extracted"
        );
    }

    /// A tag whose payload is the wrong length is not a tag. Accepting it would mean reading an
    /// identity from a push that was never a commitment.
    #[test]
    fn a_wrong_length_payload_is_rejected() {
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_tag(PAYOUT_TAG_MAGIC, &[0x44; 8]));
        assert_eq!(extract_payout_tag(&s), None);
    }

    /// Truncated and malformed scriptsigs must return nothing rather than panic — this parses data
    /// straight off the chain, where anyone can put anything.
    #[test]
    fn malformed_scriptsigs_do_not_panic() {
        for s in [
            vec![],
            vec![0x14],                   // push claiming 20 bytes, none present
            vec![0x4c],                   // PUSHDATA1 with no length byte
            vec![0x4c, 0x20, 0x01, 0x02], // PUSHDATA1 overrunning the buffer
            vec![0xff, 0xff, 0xff],       // opcodes we do not handle
            encode_payout_tag(&[0u8; 16])[..8].to_vec(), // a tag cut in half
        ] {
            assert_eq!(extract_payout_tag(&s), None);
            assert_eq!(extract_node_tag(&s), None);
        }
    }

    /// A tier-bound node tag is the SAME width as a plain one: the tier is folded into the 20-byte
    /// hash, not appended, so binding the tier costs zero scriptSig bytes. This is the load-bearing
    /// budget claim behind the whole approach — the live scriptSig is already 99/100.
    #[test]
    fn a_tier_bound_node_tag_is_the_same_width_as_a_plain_one() {
        let node_id = [0x5Au8; 32];
        let plain = encode_node_tag(&node_commitment_plain(&node_id));
        let bound = encode_node_tag(&node_commitment_for_tier(&node_id, 13));
        assert_eq!(
            plain.len(),
            bound.len(),
            "binding the tier must not change the tag length"
        );
        assert_eq!(bound.len(), 1 + 4 + NODE_ID_LEN);
    }

    /// The plain commitment must be byte-identical to what the live template builder stamps today,
    /// `sha256(node_id)[..20]`. If this drifts, a tier-free coinbase built the new way would not
    /// match a share verified the old way across the gate boundary.
    #[test]
    fn the_plain_commitment_matches_the_live_encoding() {
        use sha2::{Digest, Sha256};
        let node_id = [0x11u8; 32];
        let expected: [u8; NODE_ID_LEN] = {
            let d: [u8; 32] = Sha256::digest(node_id).into();
            d[..NODE_ID_LEN].try_into().unwrap()
        };
        assert_eq!(node_commitment_plain(&node_id), expected);
    }

    /// The tier-bound commitment must differ from the plain one, and must change with the tier —
    /// otherwise the tier is not actually bound and could be swapped after the fact.
    #[test]
    fn the_tier_bound_commitment_depends_on_the_tier() {
        let node_id = [0x22u8; 32];
        let plain = node_commitment_plain(&node_id);
        let t13 = node_commitment_for_tier(&node_id, 13);
        let t14 = node_commitment_for_tier(&node_id, 14);
        assert_ne!(
            plain, t13,
            "the tier-bound tag must not equal the plain tag"
        );
        assert_ne!(t13, t14, "a different tier must produce a different tag");
    }

    /// Tier derivation floors sub-floor / degenerate difficulties, saturates the ceiling, and
    /// round-trips a power-of-two target exactly (which is what vardiff assigns).
    #[test]
    fn tier_derivation_floors_saturates_and_round_trips() {
        // Below the floor and degenerate/garbage values all floor to MIN — a non-finite input must
        // never be credited a high tier, so infinity floors to MIN rather than saturating.
        assert_eq!(difficulty_to_tier_log2(0.0), MIN_DIFFICULTY_TIER_LOG2);
        assert_eq!(difficulty_to_tier_log2(-5.0), MIN_DIFFICULTY_TIER_LOG2);
        assert_eq!(difficulty_to_tier_log2(f64::NAN), MIN_DIFFICULTY_TIER_LOG2);
        assert_eq!(
            difficulty_to_tier_log2(f64::INFINITY),
            MIN_DIFFICULTY_TIER_LOG2
        );
        assert_eq!(difficulty_to_tier_log2(1.0), MIN_DIFFICULTY_TIER_LOG2);
        assert_eq!(
            difficulty_to_tier_log2(tier_target_difficulty(MIN_DIFFICULTY_TIER_LOG2) - 1.0),
            MIN_DIFFICULTY_TIER_LOG2
        );

        // A large but finite difficulty saturates at the ceiling exponent.
        assert_eq!(
            difficulty_to_tier_log2(2.0_f64.powi(70)),
            MAX_DIFFICULTY_TIER_LOG2
        );

        // A power-of-two target round-trips to its own exponent.
        for e in [MIN_DIFFICULTY_TIER_LOG2, 13, 20, 40] {
            assert_eq!(difficulty_to_tier_log2(tier_target_difficulty(e)), e);
            // Just under the next power of two still floors to e.
            assert_eq!(
                difficulty_to_tier_log2(tier_target_difficulty(e + 1) - 1.0),
                e
            );
        }

        assert_eq!(tier_target_difficulty(MIN_DIFFICULTY_TIER_LOG2), 1024.0);
    }

    /// The budget claim in the module docs must hold: both tags plus a realistic prefix have to fit
    /// inside the 100-byte consensus ceiling, with margin left over.
    #[test]
    fn both_tags_fit_the_consensus_ceiling() {
        let mut s = scriptsig_prefix();
        s.extend_from_slice(&encode_payout_tag(&[0u8; PAYOUT_ID_LEN]));
        s.extend_from_slice(&encode_node_tag(&[0u8; NODE_ID_LEN]));

        assert!(
            s.len() <= 100,
            "scriptsig would exceed the consensus ceiling at {} bytes",
            s.len()
        );
        assert!(
            s.len() <= 92,
            "less margin than the documented ~9 bytes: {} used",
            s.len()
        );
    }
}
