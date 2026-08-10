//! The bridge from the batch chain to this node's share verification (WP-5).
//!
//! [`ghost_common::batch_consensus::BatchChecks`] is what `verify_batch` calls to decide whether a share in a peer's proposed
//! batch is real. It must answer that question **exactly** as this node would for its own shares,
//! or the shadow chain diverges for reasons that have nothing to do with consensus and the trust
//! gate cannot tell the two apart.
//!
//! ## What "valid" means here is deliberately NARROWER than `handle_share_proof`
//!
//! The batch chain asks one question: *does this share prove itself?* Per
//! `docs/SHARE_BATCH_CHAIN.md`, a `ShareProof` is self-proving — PoW preimage, GHOST-09 signature,
//! receiver binding — so a validator checks **validity, not possession**. It needs no prior copy of
//! the share and no agreement with anyone about what it holds.
//!
//! `RoundManager::handle_share_proof` asks more than that, because it is an *ingest* path with its
//! own policy: C5 dedup, the M-6 `template_id` requirement, local template staleness, L-7
//! tolerance, M-29 exploiter tracking. Those decide whether THIS node files a share it has just
//! been handed. None of them is a property of the share itself.
//!
//! The M-6 difference is the one that matters, and it is intentional. Requiring `template_id` on a
//! remote share is a check on a field that path never reads (`round.rs` only consults it when
//! `received_by == our_node_id`), and it currently strands historical shares that predate the
//! field — measured at ~2,000-2,900 rejections/hour on every node, the same share set retried
//! forever. Under the batch chain those shares prove themselves and are valid.
//!
//! **So the shadow run is EXPECTED to credit slightly more work than the live ledger.** That drift
//! is the defect being corrected, not a fault in the chain. What the trust gate must see is drift
//! that is *bounded and non-growing*; a widening gap would mean something else is wrong.

use ghost_common::batch_consensus::BatchChecks;
use ghost_common::identity::verify_signature;
use ghost_common::types::{RoundId, ShareProof};

/// Verifies shares the way this node verifies its own.
///
/// Holds no database handle and opens no socket: every input is supplied, so the same share always
/// gets the same verdict regardless of when it is asked. `verify_batch` runs this over every share
/// in a peer's batch, so a check that reached for shared state would also be a lock held across a
/// whole batch.
pub struct NodeBatchChecks {
    /// The round at which GHOST-09 signatures began binding the payout address, if it has
    /// activated. Mirrors `RoundManager::requires_bound_signature` rather than re-deriving it: two
    /// spellings of the same predicate is how a signer and a verifier drift apart, and here that
    /// would reject every share signed under the other encoding.
    addr_bind_activation_round: Option<RoundId>,
    /// Whether the PoW preimage check is in force. Mirrors the live path's
    /// `!height_established || height >= share_pow_verify_height()` — note the fail-CLOSED sense:
    /// an unestablished height takes the STRONGER check, because a freshly restarted node's height
    /// is 0 and 0 sorts below every gate, which silently selected the weaker check in #597.
    pow_preimage_required: bool,
    /// Whether shares must carry a committed difficulty tier and are judged against exactly that
    /// tier (SHARE_TIER_BIND). Mirrors the live path's `height_established &&
    /// binds_difficulty_tier(height)` — note the sense is NOT the pow gate's fail-closed one: an
    /// unestablished height takes the pow-preimage check but NOT the tier requirement, because
    /// applying a DORMANT gate at height 0 would activate it on every restart. The residual once
    /// armed is bounded the same way as the live path's: the preimage check still runs, only the
    /// tier-credit selection waits for an established height.
    tier_bound: bool,
}

impl NodeBatchChecks {
    pub fn new(
        addr_bind_activation_round: Option<RoundId>,
        pow_preimage_required: bool,
        tier_bound: bool,
    ) -> Self {
        Self {
            addr_bind_activation_round,
            pow_preimage_required,
            tier_bound,
        }
    }

    /// Build from a height and activation round, applying the same fail-closed rule as the live
    /// ingest path.
    pub fn at_height(
        height: u64,
        addr_bind_activation_round: Option<RoundId>,
        pow_verify_height: u64,
        tier_bind_height: u64,
    ) -> Self {
        let height_established = height > 0;
        Self::new(
            addr_bind_activation_round,
            !height_established || height >= pow_verify_height,
            height_established && height >= tier_bind_height,
        )
    }

    /// Does the share carry a signature valid under the rules in force for ITS round?
    ///
    /// Judged by the share's round, not by the current height: the bind gate is a signature-format
    /// change, and a share signed before it is older, not invalid. Same reasoning as
    /// `RoundManager::requires_bound_signature`.
    fn signature_ok(&self, share: &ShareProof) -> bool {
        let bound = match self.addr_bind_activation_round {
            Some(activation) => share.round_id >= activation,
            None => false,
        };
        if bound {
            share.has_valid_bound_signature()
        } else {
            share.has_valid_received_by_signature()
        }
    }

    /// Does the share's own header hash to the value it claims, and reach the difficulty it claims?
    ///
    /// This is the part a hostile peer cannot fake: it can gossip any 32 bytes with an in-range
    /// numeric difficulty, but it cannot produce a header that hashes to a chosen value without
    /// doing the work. Recomputed here rather than trusted, because a batch is exactly where an
    /// injected share would enter the agreed ledger.
    fn pow_ok(&self, share: &ShareProof) -> bool {
        let Some(header) = share.header.as_deref() else {
            return false;
        };
        let Ok(header80) = <[u8; 80]>::try_from(header) else {
            return false;
        };

        let computed = {
            use bitcoin::hashes::{sha256d, Hash};
            sha256d::Hash::hash(&header80).to_byte_array()
        };
        if computed != share.share_hash {
            return false;
        }

        // SHARE_TIER_BIND: at/above the gate a share is judged against the tier its coinbase
        // committed to, and its stated difficulty must BE that tier's target — mirroring the
        // live ingest path in `handle_share_proof`, which is the contract of this module. A
        // share with no tier in the tier era does not prove itself.
        if self.tier_bound {
            let Some(tier) = share.tier_log2 else {
                return false;
            };
            let Some(credited) = ghost_accounting::DifficultyCalculator::verify_pow_preimage_tier(
                &header80,
                &share.share_hash,
                tier,
            ) else {
                return false;
            };
            // Same 0.01% (M-9) tolerance as the live path, so the two verdicts cannot drift.
            return (share.difficulty - credited).abs() <= credited * 0.0001;
        }

        ghost_accounting::DifficultyCalculator::verify_pow_preimage(
            &header80,
            &share.share_hash,
            share.difficulty,
        )
    }
}

impl BatchChecks for NodeBatchChecks {
    fn share_is_valid(&self, share: &ShareProof) -> bool {
        // Signature first: it is cheap and it is what binds the share to a receiver, so a proof
        // that nobody vouched for is discarded before any hashing is done on its behalf.
        if !self.signature_ok(share) {
            return false;
        }
        if self.pow_preimage_required && !self.pow_ok(share) {
            return false;
        }
        true
    }

    fn proposer_signed(
        &self,
        proposer: &[u8; 32],
        batch_hash: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        let Ok(sig) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        // A verification error is not a valid signature — same fail-closed sense as
        // `ShareProof::has_valid_bound_signature`.
        verify_signature(proposer, batch_hash, &sig).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::identity::NodeIdentity;

    /// A difficulty the all-zero header's hash genuinely reaches.
    ///
    /// Measured, not guessed: `sha256d([0u8; 80])` clears 1e-9 and fails 1e-6. A fixture claiming
    /// a difficulty its own hash cannot reach is not a valid share, and asserting it "should pass"
    /// would be asserting the check is broken.
    const REACHABLE_DIFFICULTY: f64 = 1e-9;

    /// A share with a genuine PoW preimage at a difficulty its hash actually reaches.
    fn provable_share(identity: &NodeIdentity, round_id: RoundId) -> ShareProof {
        let header = vec![0u8; 80];
        let real_hash = {
            use bitcoin::hashes::{sha256d, Hash};
            sha256d::Hash::hash(&header).to_byte_array()
        };
        let mut share = ShareProof {
            round_id,
            miner_id: [2u8; 32],
            difficulty: REACHABLE_DIFFICULTY,
            work: 1.0,
            share_hash: real_hash,
            timestamp: 0,
            received_by: identity.node_id(),
            template_id: Some([3u8; 32]),
            payout_address: Some("bc1qtest".to_string()),
            header: Some(header),
            tier_log2: None,
            signature: None,
        };
        share.sign(identity);
        share
    }

    fn checks() -> NodeBatchChecks {
        NodeBatchChecks::new(None, true, false)
    }

    #[test]
    fn a_self_proving_share_is_valid() {
        let id = NodeIdentity::generate();
        assert!(checks().share_is_valid(&provable_share(&id, 1)));
    }

    /// A hostile peer can gossip any 32 bytes with an in-range difficulty. It cannot produce a
    /// header that hashes to a chosen value, which is the whole basis for accepting a share from
    /// someone whose ledger this node has never seen.
    #[test]
    fn a_share_hash_that_is_not_its_header_pow_is_rejected() {
        let id = NodeIdentity::generate();
        let mut share = provable_share(&id, 1);
        share.share_hash = [0xAB; 32];
        share.sign(&id); // honestly signed, still fabricated
        assert!(
            !checks().share_is_valid(&share),
            "a fabricated hash must fail even when correctly signed"
        );
    }

    #[test]
    fn a_share_claiming_unreachable_difficulty_is_rejected() {
        let id = NodeIdentity::generate();
        let mut share = provable_share(&id, 1);
        share.difficulty = f64::MAX;
        share.sign(&id);
        assert!(!checks().share_is_valid(&share));
    }

    #[test]
    fn a_share_without_a_header_cannot_prove_itself() {
        let id = NodeIdentity::generate();
        let mut share = provable_share(&id, 1);
        share.header = None;
        share.sign(&id);
        assert!(!checks().share_is_valid(&share));
    }

    #[test]
    fn an_unsigned_or_misattributed_share_is_rejected() {
        let id = NodeIdentity::generate();

        let mut unsigned = provable_share(&id, 1);
        unsigned.signature = None;
        assert!(!checks().share_is_valid(&unsigned), "unsigned must fail");

        // Signed by someone, but claiming a different receiver — the relay re-crediting itself.
        let mut relayed = provable_share(&id, 1);
        relayed.received_by = [0xFF; 32];
        assert!(
            !checks().share_is_valid(&relayed),
            "a signature must match the claimed receiver"
        );
    }

    /// The bind gate is a signature-FORMAT change, so a share is judged by its own round. A share
    /// from before activation is older, not invalid — judging it by the current height would
    /// reject every historical share the moment the gate fires.
    #[test]
    fn signature_format_is_judged_by_the_shares_round_not_the_current_height() {
        let id = NodeIdentity::generate();
        let activation: RoundId = 100;
        let checks = NodeBatchChecks::new(Some(activation), true, false);

        // Pre-activation round, signed in the pre-activation format: valid.
        let old = provable_share(&id, activation - 1);
        assert!(
            checks.share_is_valid(&old),
            "a share predating the gate must stay valid under its own rules"
        );

        // Post-activation round still carrying the pre-activation signature: not valid.
        let mut new_round = provable_share(&id, activation);
        new_round.sign(&id); // unbound form, wrong for this round
        assert!(
            !checks.share_is_valid(&new_round),
            "at/above the gate the signature must cover the payout address"
        );

        // Post-activation round signed in the bound form: valid.
        let mut bound = provable_share(&id, activation);
        bound.sign_bound(&id);
        assert!(checks.share_is_valid(&bound));
    }

    /// Deliberate divergence from `handle_share_proof`, and the reason the shadow run is expected
    /// to credit slightly MORE work than the live ledger.
    ///
    /// M-6 refuses a remote share with no `template_id`, on a path that never reads the field — it
    /// is only consulted when `received_by == our_node_id`. That currently strands historical
    /// shares at ~2,000-2,900 rejections/hour on every node, the same set retried forever. A share
    /// that proves itself is valid to the chain regardless.
    #[test]
    fn a_share_without_a_template_id_still_proves_itself() {
        let id = NodeIdentity::generate();
        let mut share = provable_share(&id, 1);
        share.template_id = None;
        share.sign(&id);
        assert!(
            checks().share_is_valid(&share),
            "template_id is an ingest-policy field, not part of proving the share"
        );
    }

    /// Fail CLOSED on an unestablished height. A freshly restarted node reads height 0, which
    /// sorts below every gate — in #597 that silently selected the WEAKER check during the exact
    /// window a node ingests its backfill burst.
    #[test]
    fn an_unestablished_height_takes_the_stronger_check() {
        let strict = NodeBatchChecks::at_height(0, None, 1_000_000, u64::MAX);
        let id = NodeIdentity::generate();
        let mut fabricated = provable_share(&id, 1);
        fabricated.share_hash = [0xAB; 32];
        fabricated.sign(&id);
        assert!(
            !strict.share_is_valid(&fabricated),
            "height 0 must not select the weaker check"
        );
    }

    /// SHARE_TIER_BIND, dormant safety: while `tier_bound` is false (everywhere below the gate,
    /// which today is everywhere), a share carrying no tier is judged exactly as before, and the
    /// verdict for the existing fixture set does not move.
    #[test]
    fn below_the_tier_gate_a_tierless_share_is_judged_exactly_as_before() {
        let id = NodeIdentity::generate();
        let share = provable_share(&id, 1);
        assert!(share.tier_log2.is_none(), "fixture predates the tier era");
        assert!(NodeBatchChecks::new(None, true, false).share_is_valid(&share));
        assert!(
            NodeBatchChecks::at_height(1, None, 0, u64::MAX).share_is_valid(&share),
            "a dormant gate must leave the verdict untouched at any real height"
        );
    }

    /// A dormant gate must not fire during the height-0 window either — that is the deliberate
    /// asymmetry with the pow gate's fail-closed sense, documented on `tier_bound`.
    #[test]
    fn an_unestablished_height_does_not_activate_a_dormant_tier_gate() {
        let id = NodeIdentity::generate();
        let share = provable_share(&id, 1);
        assert!(
            NodeBatchChecks::at_height(0, None, 1_000_000, u64::MAX).share_is_valid(&share),
            "height 0 must not turn the dormant tier requirement on"
        );
    }

    /// A share with REAL PoW at a known tier: the Bitcoin genesis header, which deterministically
    /// achieves difficulty ~2536 — i.e. tier 11 (target 2048) and no higher. Real work, no mining
    /// in the test, no 1-in-256 flake.
    fn genesis_tier_share(identity: &NodeIdentity, tier_log2: u32, difficulty: f64) -> ShareProof {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::Hash;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let mut header = Vec::new();
        genesis.header.consensus_encode(&mut header).unwrap();
        let real_hash: [u8; 32] = genesis.header.block_hash().to_byte_array();
        let mut share = ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty,
            work: difficulty,
            share_hash: real_hash,
            timestamp: 0,
            received_by: identity.node_id(),
            template_id: Some([3u8; 32]),
            payout_address: Some("bc1qtest".to_string()),
            header: Some(header),
            tier_log2: Some(tier_log2),
            signature: None,
        };
        share.sign(identity);
        share
    }

    /// Once tier-bound, a share proves itself only by committing to a tier its hash actually
    /// reaches and stating exactly that tier's difficulty.
    #[test]
    fn in_the_tier_era_a_share_is_judged_against_its_committed_tier() {
        let id = NodeIdentity::generate();
        let tier_bound = NodeBatchChecks::new(None, true, true);

        // Genesis committed to tier 11 and stating exactly 2^11: proves itself.
        assert!(
            tier_bound.share_is_valid(&genesis_tier_share(&id, 11, 2048.0)),
            "real PoW at its committed tier, credited exactly the tier, must verify"
        );

        // No tier: does not prove itself in the tier era.
        let tierless = provable_share(&id, 1);
        assert!(
            !tier_bound.share_is_valid(&tierless),
            "a tier-less share must not pass once the gate is in force"
        );

        // A committed tier the hash does not reach: genesis achieves ~2536, tier 12 needs 4096.
        assert!(
            !tier_bound.share_is_valid(&genesis_tier_share(&id, 12, 4096.0)),
            "a hash that misses its committed tier must not verify"
        );

        // Real hash, reachable committed tier, but the numeric difficulty states something other
        // than the tier's target — the post-hoc claim this whole gate exists to refuse. Under the
        // legacy check 2500.0 would pass (genesis achieves ~2536); the tier era refuses it.
        assert!(
            !tier_bound.share_is_valid(&genesis_tier_share(&id, 11, 2500.0)),
            "credit must be exactly the committed tier's target, never the achieved difficulty"
        );
    }

    #[test]
    fn a_batch_signature_must_be_the_proposers_over_that_hash() {
        let id = NodeIdentity::generate();
        let batch_hash = [0x11u8; 32];
        let sig = id.sign(&batch_hash);

        assert!(checks().proposer_signed(&id.node_id(), &batch_hash, &sig));
        assert!(
            !checks().proposer_signed(&[0xFF; 32], &batch_hash, &sig),
            "another node's id must not verify"
        );
        assert!(
            !checks().proposer_signed(&id.node_id(), &[0x22u8; 32], &sig),
            "the same signature must not replay onto another batch"
        );
        assert!(
            !checks().proposer_signed(&id.node_id(), &batch_hash, &sig[..63]),
            "a malformed signature is not valid"
        );
    }
}
