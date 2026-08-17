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
//! `docs/archive/SHARE_BATCH_CHAIN.md`, a `ShareProof` is self-proving — PoW preimage, GHOST-09 signature,
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
    /// The round at which the PoW-header requirement took effect, if known. Mirrors
    /// `RoundManager::requires_pow_header`: judged by the share's own round, so a header-less
    /// share mined below the boundary stays provable by the numeric rule of its era (#650).
    pow_verify_activation_round: Option<RoundId>,
    /// Whether the PoW preimage check is in force when NO activation round is known. Mirrors the
    /// live path's fallback `height == 0 || height >= share_pow_verify_height()` — note the
    /// fail-CLOSED sense: an unestablished height takes the STRONGER check, because a freshly
    /// restarted node's height is 0 and 0 sorts below every gate, which silently selected the
    /// weaker check in #597.
    pow_preimage_required: bool,
    /// The round at which the difficulty-tier commitment took effect, if known (SHARE_TIER_BIND).
    /// Mirrors `RoundManager::requires_tier_binding`: judged by the share's OWN round, because a
    /// share mined before the gate carries `tier_log2: None` and can never acquire a tier
    /// retrospectively.
    ///
    /// This was a node-wide `bool` derived from the current height, and that was a live defect: the
    /// instant the fleet crossed the gate, every pre-gate share in a pending pool became
    /// `InvalidShare`, so the first batch carrying one got its proposer QUARANTINED fleet-wide —
    /// terminally, operator-release-only. Observed 2026-08-12: vm5 quarantined on all 8 at seq=2
    /// for a round-121233 share, ~7 hours after the gate fired at round 121703.
    ///
    /// `None` means the gate has not fired here, which also gives the dormant-gate and
    /// height-0-after-restart behaviour the old `height_established` guard was reaching for — by
    /// construction rather than by a separate condition, exactly as `round.rs` does.
    tier_bind_activation_round: Option<RoundId>,
    /// The era decided by BLOCK HEIGHT rather than by a local round, for judging ANOTHER node's
    /// shares.
    ///
    /// ⚠ The activation ROUNDS above are node-local: `RoundManager::start_round` increments a
    /// counter seeded from that node's own database, so two nodes never agree on them. Comparing
    /// our rounds against a peer's `share.round_id` is meaningless, and it fails CLOSED in the
    /// accusing direction — a long-running node auditing a newly commissioned one sees every
    /// `share.round_id < activation`, takes the pre-bind branch, and rejects shares that were
    /// signed correctly. In §6 sampling that is not a rejected share but a published accusation
    /// against an honest operator, which is the case multi-operator v1 consists of.
    ///
    /// Block height is the axis every node DOES agree on, and the gates are already defined in
    /// height terms (`SHARE_ADDR_BIND_HEIGHT`, `SHARE_POW_VERIFY_HEIGHT`,
    /// `SHARE_TIER_BIND_HEIGHT`) before ever being translated into local rounds. When this is
    /// `Some`, the era is already decided and the round comparisons are not consulted.
    ///
    /// `None` keeps the round-based behaviour for OUR OWN shares, where the rounds are ours and
    /// therefore meaningful.
    era_by_height: Option<EraByHeight>,
}

/// An era decided from a height every node agrees on.
#[derive(Debug, Clone, Copy)]
struct EraByHeight {
    addr_bound: bool,
    pow_required: bool,
    tier_bound: bool,
}

impl NodeBatchChecks {
    pub fn new(
        addr_bind_activation_round: Option<RoundId>,
        pow_preimage_required: bool,
        tier_bind_activation_round: Option<RoundId>,
    ) -> Self {
        Self {
            addr_bind_activation_round,
            pow_verify_activation_round: None,
            pow_preimage_required,
            tier_bind_activation_round,
            era_by_height: None,
        }
    }

    /// Build from a height and the known activation rounds, applying the same fail-closed
    /// fallback rule as the live ingest path.
    ///
    /// Only the PoW-preimage fallback is height-derived, and only because it has no boundary round
    /// to fall back on. The tier gate takes its activation ROUND, never the height: a height
    /// predicate here is applied to shares of every era at once.
    pub fn at_height(
        height: u64,
        addr_bind_activation_round: Option<RoundId>,
        pow_verify_activation_round: Option<RoundId>,
        pow_verify_height: u64,
        tier_bind_activation_round: Option<RoundId>,
    ) -> Self {
        let height_established = height > 0;
        Self {
            addr_bind_activation_round,
            pow_verify_activation_round,
            pow_preimage_required: !height_established || height >= pow_verify_height,
            tier_bind_activation_round,
            era_by_height: None,
        }
    }

    /// Judge shares by the BLOCK HEIGHT they were mined at, not by any local round.
    ///
    /// This is the constructor to use for ANOTHER node's shares — §6 sampling above all. The
    /// height comes from the epoch being audited (`epoch * EPOCH_BLOCKS`), which every node
    /// derives identically from the chain, so both sides judge the same share by the same era.
    /// Using the round-based constructors across nodes accuses honest operators; see
    /// `era_by_height`.
    pub fn at_shared_height(height: u64) -> Self {
        Self {
            addr_bind_activation_round: None,
            pow_verify_activation_round: None,
            pow_preimage_required: false,
            tier_bind_activation_round: None,
            // ⚠ The ACCESSORS, not the consts. `gates::from_env` overrides these off-mainnet,
            // and that is the documented way to rehearse the real shipping binary with the gates
            // pulled down. Reading the raw mainnet consts here would judge a regtest fleet — whose
            // shares above the lowered gate ARE bound-signed — by mainnet heights, take the
            // pre-bind branch on every leaf, and convict every honest peer. With §6 wired to
            // quarantine, the whole test fleet would mutually quarantine on the first sampling
            // tick, each node re-deriving the same wrong verdict.
            era_by_height: Some(EraByHeight {
                addr_bound: height >= crate::share_addr_bind_height(),
                pow_required: height >= crate::share_pow_verify_height(),
                tier_bound: height >= crate::share_tier_bind_height(),
            }),
        }
    }

    /// Does the share carry a signature valid under the rules in force for ITS round?
    ///
    /// Judged by the share's round, not by the current height: the bind gate is a signature-format
    /// change, and a share signed before it is older, not invalid. Same reasoning as
    /// `RoundManager::requires_bound_signature`.
    fn signature_ok(&self, share: &ShareProof) -> bool {
        let bound = match self.era_by_height {
            Some(era) => era.addr_bound,
            None => match self.addr_bind_activation_round {
                Some(activation) => share.round_id >= activation,
                None => false,
            },
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
        //
        // Judged by the SHARE's round, like `signature_ok` and the header predicate beside it. A
        // pre-gate share is judged by the numeric rule of its era; demanding a tier of it would
        // make it permanently unbatchable, and the proposer that carried it a quarantined node.
        let tier_bound = match self.era_by_height {
            Some(era) => era.tier_bound,
            None => match self.tier_bind_activation_round {
                Some(activation) => share.round_id >= activation,
                None => false,
            },
        };
        if tier_bound {
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
        // Era-aware, like the live path (`RoundManager::requires_pow_header`): when the boundary
        // round is known the share's OWN round decides whether a header is demanded of it; the
        // height-derived fallback governs only the boundary-less case.
        let pow_required = match self.era_by_height {
            Some(era) => era.pow_required,
            None => match self.pow_verify_activation_round {
                Some(activation) => share.round_id >= activation,
                None => self.pow_preimage_required,
            },
        };
        if pow_required && !self.pow_ok(share) {
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
        NodeBatchChecks::new(None, true, None)
    }

    /// The property §6 sampling depends on: two nodes with completely different round numbering
    /// must reach the SAME verdict on the same share.
    ///
    /// This is what a round-based predicate cannot give. `RoundManager::start_round` increments a
    /// counter seeded from each node's own database, so a long-running node and a newly
    /// commissioned one share no round axis at all. Judging a peer's shares by our activation
    /// rounds made the verdict depend on WHO WAS ASKING — and it failed closed in the accusing
    /// direction, turning an honest operator's correctly-signed share into published evidence
    /// against it.
    ///
    /// Height is the axis both nodes derive identically from the chain, so the verdict is a
    /// property of the share and the era, not of the auditor.
    #[test]
    fn the_same_share_gets_the_same_verdict_whatever_the_auditors_round_numbering() {
        let id = NodeIdentity::generate();

        // The SAME share, presented to two auditors whose local rounds differ by six orders of
        // magnitude — a veteran node against a freshly commissioned one.
        let share_veteran_numbering = provable_share(&id, 1_100_000);
        let share_new_numbering = provable_share(&id, 3);

        // Height-decided era: below every gate, so both are judged by the pre-gate rules.
        let early = NodeBatchChecks::at_shared_height(crate::SHARE_POW_VERIFY_HEIGHT - 1);
        assert_eq!(
            early.share_is_valid(&share_veteran_numbering),
            early.share_is_valid(&share_new_numbering),
            "a share's verdict must not depend on the auditor's round numbering"
        );

        // And the era itself must still bite: at/above the PoW gate a header is demanded.
        let late = NodeBatchChecks::at_shared_height(crate::SHARE_POW_VERIFY_HEIGHT);
        let mut headerless = provable_share(&id, 7);
        headerless.header = None;
        headerless.sign(&id);
        assert!(
            !late.share_is_valid(&headerless),
            "the height era must still enforce the gate it encodes"
        );
        assert!(
            early.share_is_valid(&headerless),
            "and must NOT enforce it below the gate — that is the pre-gate share the round-based \
             predicate condemned"
        );
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
        let checks = NodeBatchChecks::new(Some(activation), true, None);

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
        let strict = NodeBatchChecks::at_height(0, None, None, 1_000_000, None);
        let id = NodeIdentity::generate();
        let mut fabricated = provable_share(&id, 1);
        fabricated.share_hash = [0xAB; 32];
        fabricated.sign(&id);
        assert!(
            !strict.share_is_valid(&fabricated),
            "height 0 must not select the weaker check"
        );
    }

    /// Era-awareness for the header requirement, mirroring `RoundManager::requires_pow_header`
    /// (#650): once the boundary round is known, the share's OWN round decides whether a header
    /// is demanded of it — a header-less share mined below the boundary never had one and stays
    /// provable by its era's numeric rule, however far past the gate the tip is.
    #[test]
    fn the_header_requirement_is_judged_by_the_shares_round() {
        let id = NodeIdentity::generate();
        let boundary: RoundId = 100;
        // Tip far past the gate; boundary known.
        let checks = NodeBatchChecks::at_height(2_000_000, None, Some(boundary), 1_000_000, None);

        let mut old = provable_share(&id, boundary - 1);
        old.header = None;
        old.sign(&id);
        assert!(
            checks.share_is_valid(&old),
            "a pre-boundary share has no header and must stay provable under its own era's rules"
        );

        let mut new_round = provable_share(&id, boundary);
        new_round.header = None;
        new_round.sign(&id);
        assert!(
            !checks.share_is_valid(&new_round),
            "at/above the boundary a header-less share must not prove itself"
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
        assert!(NodeBatchChecks::new(None, true, None).share_is_valid(&share));
        assert!(
            NodeBatchChecks::at_height(1, None, None, 0, None).share_is_valid(&share),
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
            NodeBatchChecks::at_height(0, None, None, 1_000_000, None).share_is_valid(&share),
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
        let tier_bound = NodeBatchChecks::new(None, true, Some(0));

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

    /// ⚠ RED BEFORE 2026-08-12. The tier predicate was a node-wide `bool` derived from the CURRENT
    /// height, so the instant the fleet crossed the gate every pre-gate share in a pending pool
    /// became `InvalidShare` — and the first proposer to carry one was QUARANTINED fleet-wide,
    /// terminally and operator-release-only. Measured live: vm5 quarantined on all 8 at seq=2 over
    /// a round-121233 share, hours after the gate fired at round 121703.
    ///
    /// The gate is a share-FORMAT change, so it is judged by the share's own round — exactly as
    /// `signature_ok` and the header predicate beside it already were. Both directions are pinned:
    /// making the predicate constantly true fails the first assert, constantly false the second.
    #[test]
    fn a_pre_gate_share_stays_batchable_after_the_tier_gate_fires() {
        let id = NodeIdentity::generate();
        const ACTIVATION: RoundId = 121_703;
        let checks = NodeBatchChecks::new(None, true, Some(ACTIVATION));

        // Mined before the gate: carries no tier and can never acquire one retrospectively.
        assert!(
            checks.share_is_valid(&provable_share(&id, ACTIVATION - 1)),
            "a share from before the tier gate must stay provable by the numeric rule of its era"
        );

        // The gate still bites where it should: same shape, mined in the tier era, refused.
        assert!(
            !checks.share_is_valid(&provable_share(&id, ACTIVATION)),
            "a tier-less share mined at or above the boundary must not prove itself"
        );
    }

    /// A share that was actually MINED: nonces are scanned until the header's hash genuinely
    /// meets `REACHABLE_DIFFICULTY`, exactly as a miner does.
    ///
    /// `provable_share` fixes the header at `[0u8; 80]`, so every share it makes shares one hash —
    /// fine for judging a single share, useless for a Merkle tree, where duplicate leaves are not
    /// six leaves. But simply varying the nonce is not enough either: `REACHABLE_DIFFICULTY` sits
    /// close enough to the edge that only about a third of arbitrary hashes clear it, so four of
    /// six such "honest" shares were rejected for failing their own PoW. A fixture that cannot
    /// pass the check is not evidence the check is wrong.
    ///
    /// Scanning for a qualifying preimage is what an honest miner does, and it keeps the share
    /// self-proving rather than lowering the difficulty until the check stops meaning anything.
    fn mined_share(identity: &NodeIdentity, round_id: RoundId, start_nonce: u32) -> ShareProof {
        let era = NodeBatchChecks::at_shared_height(crate::share_addr_bind_height() - 1);
        for nonce in start_nonce..start_nonce.saturating_add(100_000) {
            let mut header = vec![0u8; 80];
            header[76..80].copy_from_slice(&nonce.to_le_bytes());
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
            if era.share_is_valid(&share) {
                return share;
            }
        }
        panic!("no qualifying nonce in 100,000 tries — the fixture cannot mine a valid share");
    }

    /// An honest node's epoch must survive a full §6 audit and produce NO evidence.
    ///
    /// Every other sampling test drives the ACCUSING direction — `share_never_valid`, a mutated
    /// leaf, a withheld answer. Those prove the machinery can convict. None of them proves it
    /// declines to, and that is the half an operator's node depends on: §6 is wired to
    /// `quarantine`, so a predicate that rejects honest work does not produce a warning, it
    /// produces a fleet that mutually quarantines on the first sampling tick.
    ///
    /// This composes the real pieces — real signed shares, the real summary, the real λ selection,
    /// the real Merkle verifier and the REAL era-aware predicate through
    /// `NodeBatchChecks::at_shared_height` — and asserts the audit comes back clean.
    ///
    /// ⚠ It could not be shown on the regtest cluster, and that is not an oversight. The shard
    /// only ingests shares at or above `NETWORK_TIER_LOG2` (1024x diff1) and a CPU miner cannot
    /// make one, so every honest share the cluster produces is filtered out before it ever reaches
    /// an epoch. The wire run proved the accusing direction against fabricated leaves; this proves
    /// the other direction, which no reachable regtest share can.
    #[test]
    fn an_honest_epoch_survives_a_full_lambda_audit_with_no_evidence() {
        use ghost_common::share_shard::EpochSummary;
        use ghost_consensus::message::ShardSampleLeaf;
        use ghost_consensus::shard_handler::{
            build_sample_request, build_sample_response, verify_sample_response,
        };
        use ghost_reconciliation::batch::{
            compute_merkle_proof, compute_merkle_root, verify_merkle_proof,
        };

        let accused = NodeIdentity::generate();
        let reporter = NodeIdentity::generate();

        // Six honestly mined, correctly signed shares of the PRE-bind era.
        let shares: Vec<ShareProof> = (1..=6u32)
            .map(|n| mined_share(&accused, 100 + u64::from(n), n * 10_000))
            .collect();

        let summary = EpochSummary::build(
            7,
            &accused,
            &std::collections::BTreeMap::new(),
            &shares,
            compute_merkle_root,
            None,
        )
        .expect("an honest epoch must summarise");
        assert_eq!(
            summary.share_count, 6,
            "six distinct leaves, not one repeated six times"
        );

        // The canonical leaf order the responder serves from — the same sort the fold uses.
        let leaves: Vec<[u8; 32]> = {
            let mut sorted = shares.clone();
            ghost_common::share_batch::canonical_sort(&mut sorted);
            sorted.iter().map(|s| s.share_hash).collect()
        };

        let request = build_sample_request(reporter.node_id(), &summary, 20, &[0x5C; 32]);
        assert_eq!(
            request.leaf_indices.len(),
            6,
            "lambda past the tree asks for all of it"
        );

        let served: Vec<ShardSampleLeaf> = request
            .leaf_indices
            .iter()
            .map(|&i| ShardSampleLeaf {
                leaf_index: i,
                share: shares
                    .iter()
                    .find(|s| s.share_hash == leaves[i as usize])
                    .expect("every committed leaf is a share we hold")
                    .clone(),
                merkle_proof: compute_merkle_proof(&leaves, i as usize),
            })
            .collect();
        let response = build_sample_response(&accused, &summary, served);

        // Judged in the era these shares were actually signed for: below the addr-bind gate, so
        // the legacy received_by signature is the rule in force.
        let era = NodeBatchChecks::at_shared_height(crate::share_addr_bind_height() - 1);
        let outcome = verify_sample_response(
            &summary,
            &request,
            &response,
            &reporter,
            0,
            verify_merkle_proof,
            &|share| era.share_is_valid(share),
        )
        .expect("an honest response must verify");

        assert_eq!(
            outcome.verified.len(),
            6,
            "every honest leaf must be counted as verified"
        );
        assert!(
            outcome.unanswered.is_empty(),
            "every requested leaf was served"
        );
        assert!(
            outcome.evidence.is_empty(),
            "an honest epoch must produce NO evidence — §6 quarantines on what this returns, so a \
             single spurious item here is an honest operator removed from the fleet"
        );
    }

    /// A dormant gate must not be armed by a restart: with no activation round known, no share of
    /// any era is asked for a tier.
    #[test]
    fn a_dormant_tier_gate_demands_no_tier_of_any_share() {
        let id = NodeIdentity::generate();
        let checks = NodeBatchChecks::new(None, true, None);
        assert!(checks.share_is_valid(&provable_share(&id, 1)));
        assert!(checks.share_is_valid(&provable_share(&id, 999_999)));
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
