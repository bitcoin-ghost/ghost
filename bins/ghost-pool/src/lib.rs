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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Pool Library
//!
//! Core components for Bitcoin Ghost mining pool operations.
//! This library provides all necessary functionality for running a Ghost mining node.
//!
//! # Modules
//!
//! - [`coinbase_verifier`] - Validates coinbase transactions against approved payouts
//! - [`payout`] - Payout proposal creation and BFT consensus integration
//! - [`reorg`] - Chain reorganization detection and handling
//! - [`round`] - Mining round management and share tracking
//! - [`rpc`] - JSON-RPC request parsing for Stratum protocol
//! - [`template`] - Block template processing with BUDS filtering
//! - [`template_provider`] - Template Distribution Protocol (TDP) server
//! - [`treasury`] - Treasury state and fee distribution tracking
//! - [`validation`] - Input validation for miner credentials and shares

/// Periodic operator-alert monitors (behind-tip / update-available).
pub mod alert_monitors;

/// A-2b: cached L1 block-hash oracle seeding the consensus challenger draw.
pub mod block_hash_oracle;

/// Coinbase transaction verification against payout commitments.
pub mod coinbase_verifier;

/// `tracing` layer that feeds ghost-pool's log tail into the dashboard `/logs`
/// ring buffer.
pub mod log_ring;

/// Payout proposal creation and consensus coordination.
pub mod payout;

/// Payout-ledger checkpoint finalisation (BFT-agreed snapshot the coinbase is a
/// pure function of).
pub mod payout_checkpoint;

/// Mesh node-list checkpoint finalisation (signed public-mining node set for
/// decentralised mining discovery). Dormant until `MESH_NODE_LIST_CHECKPOINT_HEIGHT`.
pub mod mesh_node_checkpoint;

/// Chain reorganization detection and recovery.
pub mod reorg;

/// Fetching a payout proposal a node needs but never received.
pub mod binding_recheck;
pub mod proposal_sync;

/// Settling the ledger from blocks observed on-chain.
pub mod skeleton_store;

/// Remembering share proofs whose verification failure can never be undone.
pub mod terminal_reject_cache;

/// Mining round lifecycle and share accounting.
/// Bridge from the share-batch chain to this node's share verification (WP-5).
/// The ratified payout checkpoint the share-batch chain opens from (WP-4).
///
/// Operator decision 2026-08-09. Verified read-only across all 8 nodes before pinning: one distinct
/// `ledger_root` fleet-wide, `canonical_payout` identical on every node, 5 payees and 8 node
/// entries. Chosen over the 960,550 candidate because every block between the anchor and the shadow
/// run is work that has to reach the chain some other way — and 960,550 was already eight days
/// stale.
///
/// Every node converts this SAME adopted checkpoint independently; genesis is not negotiated. See
/// `ShadowChain::bootstrap_genesis` for why that is safe and why the genesis proposer is zero.
pub const SBC_GENESIS_ANCHOR_HEIGHT: u64 = 961_642;

pub mod share_checks;

/// The network shard's runtime: epoch folds, evidence retention, boundary detection
/// (`SHARE_SHARD.md` §4.3/§4.4). Dark unless `pool.share_shard` is set.
pub mod shard;
pub mod shard_mesh;

pub mod round;

/// Stratum JSON-RPC request parsing.
pub mod rpc;

/// Block template processing with policy filtering.
pub mod template;

/// Template Distribution Protocol (TDP) for SRI integration.
pub mod template_provider;

/// Treasury and fee distribution state.
pub mod treasury;

/// P2P share proof handling for cross-node share propagation.
pub mod share_handler;

/// GHOST-03: ledger convergence (share-set reconciliation) between mesh nodes.
pub mod convergence;

// ⚠ No outer `///` doc here on purpose. An outer doc on the `mod` item is merged with the
// module's own `//!` docs, and rustdoc then resolves the merged block's intra-doc links in the
// PARENT scope — so `[`FRAME_MAX_AGE`]`, a public item of the module itself, failed to resolve
// and the doc job (which runs `-D warnings`) refused to document the crate. The module documents
// itself; see the `//!` block at the top of `convergence_channel.rs`.
pub mod convergence_channel;

/// Chain height at which the security-audit cluster's ENFORCEMENT activates
/// fleet-wide. Mirrors `PAYOUT_ADDRESS_GROUPING_HEIGHT`: baking the activation as
/// a deterministic block-height gate (not a flag) means every node — running the
/// same binary — flips at the exact same chain position, so the fleet can roll
/// the binary out canary-style with NO mixed-version enforcement window.
///
/// Before this height the binary still SIGNS shares, converges ledgers and
/// propagates equivocation bans (all additive, mixed-version-safe), but it does
/// NOT yet drop unsigned shares (GHOST-09) or reject a mismatched payout split
/// (GHOST-02) — making it behaviour-identical to the pre-audit binary in a mixed
/// mesh. After it, both enforcements are live everywhere at once.
///
/// ACTIVATION HEIGHT — set for the audit-cluster rollout. Chosen at `954_736`
/// (the chain tip when this was cut) + ~464 blocks ≈ 77h of headroom, leaving
/// well over 24h between the completion of the canary roll (VM4→VM1, a few hours)
/// and the gate firing, so the whole fleet is on the audit binary in dark mode
/// before enforcement turns on everywhere at once. If the deploy slips far enough
/// that the tip approaches this height before the roll completes, bump this value
/// and rebuild — the binary must reach every VM while still below the gate.
pub const CLUSTER_ENFORCEMENT_HEIGHT: u64 = 955_200;

/// At and above this height the payout ledger is grouped by payout address rather
/// than by miner_id, so a multi-rig operator takes one coinbase output instead of N.
///
/// This lives here, not in `main.rs`, because BOTH the proposer (block-found) and the
/// GHOST-02 validator must group the ledger the same way. A validator that grouped
/// differently from the proposer would reject an honest split.
pub const PAYOUT_ADDRESS_GROUPING_HEIGHT: u64 = 946_743;

/// At and above this height, the payout-checkpoint work tolerance is floored by a
/// fraction of TOTAL pool work rather than measured only against each address's own
/// work, and a cap on the aggregate difference is enforced. See `payouts_agree`.
///
/// Gated for the same reason as the grouping height above: a voter using a different
/// tolerance from its peers rejects proposals they accept, which is a fleet split. Both
/// sides of a vote must switch at the same block.
///
/// Set to land near **14:00 BST on 2026-07-29** (operator's target): tip was 960_070 at
/// 07:51 that morning, and the measured interval over the preceding 1440 blocks was 616 s,
/// so 36 blocks ≈ 6h10m.
///
/// Block arrival is Poisson, so ±1σ over 36 blocks is about an hour either way — treat
/// 14:00 as the centre of a ~12:00–16:00 window, not a deadline. **Every node must be
/// running this build before it fires**; one still on the old rule rejects what its peers
/// accept, which is a fleet split. Move the height out if the rollout slips past noon.
pub const PAYOUT_TOLERANCE_V2_HEIGHT: u64 = 960_106;

/// At and above this height, TX fees are FOLDED INTO THE COINBASE REWARD and split like the
/// subsidy — 99% to miners (by share/work), and the 1% pool fee levied on `subsidy + fees` and
/// divided between treasury and node pool by the decay schedule — instead of the whole fee going
/// to the block finder.
///
/// This is what makes a block's coinbase fully determined BEFORE the block is found, and so it
/// is what makes tip-change payout ratification possible at all. The block finder was the single
/// unknown in the coinbase (it existed only to receive the fees); routing fees through the
/// share-based split removes it, and both the miner split (unpaid ledger) and the node split
/// (verified capabilities) are already fixed by state that exists at tip change.
///
/// Economic model (chosen 2026-07-23): the pool takes a flat 1% of the whole reward
/// (`subsidy + fees`); miners keep the other 99% of everything. The 1% is split treasury/node by
/// the SAME decay curve as before (50/50 → 0/100 over 5y), so once the treasury wind-down
/// completes the node pool earns the full 1% — of `subsidy + fees`. As the subsidy halves away
/// and fees come to dominate, node income rides the fee economy exactly when it needs to, and
/// miners always receive a clean 99% of the total. Below the gate (legacy): the 1% pool fee is
/// levied on the subsidy only and TX fees go 100% to the block finder.
///
/// Coinbase construction is consensus-visible, so this is a height gate, not a feature flag: a
/// mixed-version fleet must not split on how the coinbase is built. Both code paths exist in the
/// new binary; every node switches at the same block.
///
/// SET THIS BEFORE DEPLOY — comfortably past the roll window (~144 blocks/day).
/// v1.10.32 activated this at 958_760 and it FAILED live: the tip-change proposer anchored its
/// ledger cutoff at now(), where the miner ledger is not yet converged across nodes (GHOST-03
/// gossip lag), so validators recomputed a different miner split and GHOST-02 rejected every
/// tip-change proposal — the coinbase never armed and fell back to treasury-only.
///
/// ARMED @959_255 (2026-07-23) then REVERTED to dormant the same day. The coinbase itself was
/// perfect — checkpoint finalised byte-identical fleet-wide across the boundary, tip advanced,
/// all three convergence proofs held (NOT a v1.10.32 tip-stall). But arming exposed a SEPARATE
/// defect: the vote handler's 30-min wall-clock freshness window on `PayoutProposal.timestamp`
/// rejected every post-gate proposal, whose timestamp is the converged checkpoint cutoff
/// (`block(tip-LAG).time`, ~an hour behind now), so the payout never RATIFIED. Fixed in v1.11.14:
/// the freshness check is now gate-aware — post-gate the cutoff-binding (a stronger, lag-tolerant
/// guarantee) validates the timestamp, and the vote handler keeps only a loose garbage bound.
///
/// ARMED @959_290 (2026-07-23, attempt 2) — now with the NEW fee model (miners keep 99% of
/// subsidy+fees; the 1% pool fee decays treasury→node) AND the v1.11.14 timestamp fix, so the
/// post-gate payout proposal ratifies. Pre-arm the go-live coinbase split was proven byte-identical
/// fleet-wide (`fee_split.hash` `d3ab532e…` on all 8) and soaked ~24 min. Revert = restore the
/// prior binary (`.bak`) = instant disarm onto the dormant new-model build.
pub const COINBASE_FEE_SPLIT_HEIGHT: u64 = 959_290;

/// Multi-operator share-injection defence. At and above this height, a `ShareProof` MUST
/// carry its 80-byte block header and every node independently re-verifies the PoW
/// (`sha256d(header) == share_hash` + meets difficulty) instead of trusting the origin's
/// signed numeric claim — see `DifficultyCalculator::verify_pow_preimage`. Below it, the
/// legacy numeric check stands (correct for a single-operator fleet trusting its own SRI).
///
/// Verification is era-aware, keyed on the round recorded in [`POW_VERIFY_ACTIVATION_KEY`]
/// rather than on the current height, so a header-less share mined below the boundary stays
/// verifiable (by the legacy numeric rule it was mined under) for ever. Judging by the tip made
/// every pre-gate share unrepairable the instant the gate fired (#639, #650).
///
/// A share's PoW binding is consensus-visible (it decides which shares are creditable and
/// so the coinbase split), hence a height gate: the header is populated into proofs and
/// required by verifiers only at/above this block, so a mixed-version fleet computes
/// identical `signing_bytes` and identical ledgers during the roll. SET comfortably past
/// the roll window once every node AND the SRI layer (pool_sv2) emit the header.
///
/// ARMED at 959_030 (v1.11.1, 2026-07-21): the fleet ships ghost-pool + pool_sv2 v1.11.0
/// (pool_sv2 emits the 80-byte header on the share webhook); this arms the recipient-side
/// re-verification. Bounded blast radius — COINBASE_FEE_SPLIT is still dormant, so this only
/// gates cross-node share-gossip verification (no coinbase/fund impact), and it is
/// reversible by re-releasing with a higher height. The fleet must be fully on v1.11.1
/// BEFORE the tip reaches this height (canary roll finishes ~959_022, ~8-block margin).
pub const SHARE_POW_VERIFY_HEIGHT: u64 = 959_030;

/// Bind a share's difficulty TIER into the coinbase preimage, and credit the committed tier.
///
/// `SHARE_POW_VERIFY_HEIGHT` established that a share's hash is a real header's PoW. This gate
/// additionally binds WHICH difficulty that share is credited. The tier is committed inside the
/// hashed coinbase when the job is built, so it is fixed before the hash exists and is recomputable
/// by any node judging the share — rather than resting on a figure supplied alongside it, which a
/// remote validator cannot check against per-node vardiff state it never sees.
///
/// (Operational detail of what the pre-gate encoding permits is deliberately kept out of the public
/// tree until the gate is armed; see the team notes.)
///
/// At and above this height a share commits to a power-of-two difficulty tier INSIDE the hashed
/// coinbase: the node tag becomes `sha256(node_id ‖ tier_log2)[..20]` instead of
/// `sha256(node_id)[..20]` (same 20-byte payload, so ZERO extra scriptSig bytes — the live
/// scriptSig is already 99/100). A validator reassembles the coinbase from the skeleton, folds it to
/// the header's merkle root, recomputes the tag from the share's stated `(node_id, tier)`, requires
/// the hash to achieve the tier, and credits EXACTLY the tier
/// (`DifficultyCalculator::verify_pow_preimage_tier` +
/// `ghost_common::share_binding::verify_share_tier_binding`). Choosing the tier after hashing
/// changes the header, so the work is discarded.
///
/// A share's credited work is consensus-visible (it decides the coinbase split), so this is a
/// height gate: below it the coinbase carries the plain `sha256(node_id)[..20]` tag and the legacy
/// numeric credit stands, byte-identical to today, so a mixed-version fleet computes identical
/// ledgers during the roll. Both code paths exist in the new binary; every node switches at the
/// same block.
///
/// DORMANT (`u64::MAX`).
///
/// ## Where the emitting side stands (2026-08-10)
///
/// Built, dark, behind this gate:
/// - `ShareProof.tier_log2`, GHOST-09-bound when present, absent → `signing_bytes`
///   byte-identical to today (`ghost-common/src/types.rs`);
/// - every verification path selects the tier check at/above this gate and credits exactly
///   `2^tier_log2`: gossip/backfill ingest (`round.rs`), the shard (`share_checks.rs`), the
///   local webhook ingest (`ghost-verification` H-13, gate injected via
///   `with_share_tier_bind_height`), with the terminal-reject key tier-aware
///   (`terminal_reject_cache.rs`);
/// - the one scriptSig assembler speaks both tag forms, switched by height
///   (`template.rs::coinbase_scriptsig`, `node_tag_bytes`), and `TemplateConfig` now carries the
///   node identity rather than a pre-hashed commitment;
/// - the SV1 translator can quantise every assigned difficulty to a power-of-two tier
///   (`difficulty_manager.rs::quantise_target_to_tier`), behind
///   `downstream_difficulty_config.quantise_to_tiers`, default OFF — the translator has no
///   chain view, so that config flag IS its gate and must ship ON in the arming release;
/// - the webhook wire interface carries `tier_log2` end to end
///   (`pool_sv2::ShareData` → `ghost-verification::ShareBatch/ShareNotification` →
///   `ShareProof`), absent on every payload until pool_sv2 populates it.
///
/// ## The emitting side is now built too (2026-08-10), dark behind config
///
/// Per-tier JOB GENERATION exists in pool_sv2 + the vendored `channels-sv2`, behind the
/// `[share_tier_binding]` config section (ABSENT by default — the only shipped state — which
/// keeps the single group-broadcast job and today's bytes exactly):
///
/// - pool_sv2 derives its per-template gate from the BIP34 height ghost-pool stamps into the
///   TDP `coinbase_prefix` (`tier_binding.rs::bip34_height`), against the configured
///   `activation_height` — so with the same height configured, both binaries flip at the same
///   BLOCK, not at a restart;
/// - at/above the gate every channel gets its OWN job from its own factory: the plain node tag
///   is stripped from the template prefix (`strip_plain_node_tag`) and the tier-bound tag
///   `node_commitment_for_tier(node_id, tier)` is stamped back as the factory's budget-guarded
///   extra push (`JobFactory::set_extra_script_sig`) — same 25 encoded bytes out and in, so the
///   99/100 scriptSig does not move (pinned by test on assembled bytes on both sides);
/// - the channel's tier is `difficulty_to_tier_log2(target)`, its target is quantised to the
///   tier's EXACT byte-built target (`channels_sv2::target::tier_target`), and each job
///   captures `(tier, push)` AT BUILD (`StandardJob/ExtendedJob::tier_log2`,
///   `extra_script_sig`) — never re-read from `job_id_to_target`, which binds at activation
///   after vardiff may have moved the channel;
/// - stamped jobs validate against their tier's exact target and the webhook reports
///   `tier_log2` plus `share_work == 2^tier` (`ShareData`), matching this gate's
///   `difficulty == 2^tier` check;
/// - a desync of the two halves is LOUD: pool_sv2 refuses to start on a malformed `node_id`,
///   warns at startup naming both halves, and flags per channel both
///   pool-on/translator-off (non-tier-shaped client max while tiering is active) and
///   translator-on/pool-off (tier-shaped client max with no `[share_tier_binding]`).
///
/// KNOWN LIMIT: Job-Declaration custom work (`SetCustomMiningJob`) carries the declaring
/// client's own coinbase and cannot commit to a tier — above the gate its shares would be
/// rejected (`missing_tier`). No JD client exists on the fleet today; resolve before arming if
/// one does. (The old direct-SV1 path in ghost-pool is gone — SRI is the only mining path.)
///
/// **ARMED at 962_100.**
///
/// Chosen with margin rather than economy: the fleet was at ~961_983 and running ~7 min/block, so
/// this is ~13 hours out against a roll that takes ~4 (CI, build, canary, a 60-minute soak, then
/// eight nodes). `SHARE_POW_VERIFY_HEIGHT` was armed with an 8-block margin; that is not a
/// precedent worth repeating for a gate that changes what work is WORTH.
///
/// Every node must carry this build before the height. A node still running an older binary has
/// `u64::MAX` here and never arms, so a partial roll means the fleet disagrees about credited work
/// — divergent coinbase splits, GHOST-02 rejections between peers — until the last node lands.
/// There is no canary for the armed behaviour itself: a height gate flips everywhere at the same
/// block by construction, so the canary proves the BINARY and the height proves the RULE.
///
/// The other two halves ship in this same release: the translator with `quantise_to_tiers = true`,
/// and `pool_sv2` with `[share_tier_binding] activation_height = 962100`. The identity half is no
/// longer transcribed — `pool_sv2` reads it from this process's `/health`, so the tags it stamps
/// and the tags this process verifies cannot disagree.
///
/// KNOWN LIMIT carried into arming: `MIN_DIFFICULTY_TIER_LOG2` (10) stays coupled to the vardiff
/// floor with nothing enforcing it. Verified at arming: the fleet's smallest assigned difficulty is
/// 2_328 (1 TH/s assumed floor, `shares_per_minute` 6.0), quantising to tier 11 — a full tier above
/// the floor, so quantisation only ever moves difficulty DOWN, which is the safe direction.
///
/// On the roll, watch `missing_tier` and `tier_credit_mismatch`: both must stay zero.
pub const SHARE_TIER_BIND_HEIGHT: u64 = 962_100;

/// Bind the miner's payout address into the GHOST-09 share signature.
///
/// `ShareProof::signing_bytes` covers `round_id`, `miner_id`, `work`, `share_hash`, `timestamp`,
/// `received_by`, `template_id` and `header` — but NOT `payout_address`, even though since
/// [`PAYOUT_ADDRESS_GROUPING_HEIGHT`] payouts are grouped by exactly that field. Its own doc claims
/// to bind "every credit-relevant field", which stopped being true when grouping moved to the
/// address. A mesh peer can therefore rewrite the address on a relayed proof, keep the signature
/// valid, and win the first-writer-wins adoption race for a miner_id nobody has seen yet.
///
/// At and above this height, signers and verifiers both use the bound encoding, so a rewritten
/// address invalidates the signature. Below it the encoding is byte-identical to today's, which is
/// what makes a mixed-version fleet safe: nothing changes until every node can produce and check
/// the new form.
///
/// ARMED at `961_100` (2026-08-02). Tip was `960_764` when this was cut — ~336 blocks, roughly
/// 2.3 days at 10 min/block. The fleet roll takes ~15 minutes, so that leaves an overnight soak
/// plus room to re-roll a node, while not holding the address-rewrite vector open any longer than
/// necessary. If the roll slips and the tip nears this height before every node is on the binary,
/// bump it and rebuild: a node still below the gate signs the old encoding and its shares would be
/// rejected by peers already above it.
///
/// Verification is era-aware, keyed on the round recorded in
/// [`ADDR_BIND_ACTIVATION_KEY`] rather than on the current height, so a share signed before the
/// boundary stays verifiable for ever. Judging by the tip would make every pre-gate share
/// unservable the instant the gate fired, freezing each node's ledger gaps permanently.
pub const SHARE_ADDR_BIND_HEIGHT: u64 = 961_100;

/// `kv_store` key holding the round in which [`SHARE_ADDR_BIND_HEIGHT`] first took effect.
///
/// Shares carry a round, not a height, so the boundary has to be recorded as a round — and it has
/// to outlive a restart, or the node re-derives a later one and downgrades post-gate shares.
pub const ADDR_BIND_ACTIVATION_KEY: &str = "addr_bind_activation_round";

/// `kv_store` key holding the round in which [`SHARE_TIER_BIND_HEIGHT`] first took effect.
///
/// Exactly the same reasoning as [`ADDR_BIND_ACTIVATION_KEY`], and for exactly the same reason:
/// a share mined before the tier gate carries no `tier_log2` and can never acquire one, so judging
/// it by the tip makes every pre-gate share awaiting repair unrecordable the instant the gate
/// fires. It is then refused before it can be written, so the GHOST-03 sweep replays it for ever
/// (#639) and the residual unpaid drift freezes permanently.
pub const TIER_BIND_ACTIVATION_KEY: &str = "tier_bind_activation_round";

/// `kv_store` key holding the round in which [`SHARE_POW_VERIFY_HEIGHT`] first took effect.
///
/// Same reasoning again — a share mined below the gate carries `header: None` and can never
/// acquire one, so judging it by the tip refuses it before it can be recorded and the GHOST-03
/// sweep replays it for ever (#639, #650) — with one difference: this gate fired BEFORE any
/// boundary was being recorded, so no live `start_round` ever noted it. #650 called that
/// unfixable. It is not: the boundary is DERIVED retrospectively at startup from the persisted
/// rounds (`rounds.round_id` → `rounds.block_height`, written at every round start since long
/// before the gate) as the lowest `round_id` whose `block_height` is at or above the gate.
/// Measured on the fleet 2026-08-11: vm5's rounds table spans 73_536..121_144 and yields boundary
/// 92_002 with 92_001 the last sub-gate round — contiguous, no ambiguity; vm1 likewise (91_999).
///
/// The mapping is trustworthy for this purpose because `prune_old_rounds` deletes a round only
/// when it is terminal AND share-free — a round still owed a share (exactly the rounds repair
/// cares about) pins its row. If pruning has removed rows between the true boundary and the
/// lowest surviving post-gate round, the derived boundary lands LATER than the truth, which fails
/// toward REQUIRING the header — never toward exempting a genuinely post-gate share.
///
/// Persisted (earliest-wins) so that when the sub-gate rounds do eventually age out of the
/// `rounds` table, the boundary survives rather than re-deriving later and later.
pub const POW_VERIFY_ACTIVATION_KEY: &str = "pow_verify_activation_round";

/// Historical gate, kept only so old logs and `PAYOUT_MEDIAN_ADOPTION_HEIGHT`'s ordering remain
/// interpretable. **The behaviour it gated is DELETED.**
///
/// It armed observed settlement at `961_400`: every node settling a won block from its own view
/// of the chain, at tip. Stage 6 removed that path entirely — settlement is now the shard's, at
/// `COINBASE_MATURITY`, which is what lets it carry no reorg-reversal machinery. Nothing reads
/// this value; do not wire anything new to it.
pub const OBSERVED_SETTLEMENT_HEIGHT: u64 = 961_400;

/// Report-and-median adoption of the payout checkpoint (#606). **ARMED at 961_700.**
///
/// At and above this height a voter REPORTS its own recomputed per-address work in its checkpoint
/// vote, and finalisation adopts the per-address lower median of those reports instead of the
/// proposer's list verbatim. That closes the hole where a proposer could skew every address within
/// tolerance (2% relative, 0.2%-of-pool floor, 1% aggregate), be ratified by an honest quorum, and
/// compound the skew at every checkpoint.
///
/// The precondition for arming was that every node already accepts an enlarged vote: a report is up
/// to ~70 KB, and a node on a build predating `MAX_PAYOUT_LEDGER_VOTE_SIZE` validates checkpoint
/// votes against the old 1 KB `MAX_VOTE_SIZE` and silently DROPS them, which would cost quorum and
/// stop payouts. That precondition is MET — `e9ca0c446` carries the size limit and was rolled to all
/// eight nodes on 2026-08-03, verified byte-identical. Ordering the limit ahead of the behaviour
/// change is the whole reason this is a height gate.
///
/// 961_700 is ~300 blocks after [`OBSERVED_SETTLEMENT_HEIGHT`], deliberately: two payout behaviour
/// changes must not land together, or a divergence cannot be attributed to either. It is ~800 blocks
/// (roughly 4 days at the observed ~8 min/block) beyond the tip at the time of arming, which leaves
/// room for the build, canary soak and rolling deploy several times over.
pub const PAYOUT_MEDIAN_ADOPTION_HEIGHT: u64 = 961_700;

/// The payout checkpoint takes its miner work from the SHARD, not the legacy unpaid ledger (#722).
/// **ARMED at 963_388.**
///
/// Migration v56 handed `shares` to the shard and, at `main.rs`'s `shard_owns_evidence` latch,
/// switched OFF the GHOST-03 ledger sweep that repaired it — while the checkpoint carried on
/// recomputing per-address work from that same table. Repair was removed; the thing that fails
/// without repair was left running. Holes became permanent and the fleet's totals for one address
/// drifted 25% apart against a 2% tolerance, so every proposal was rejected by everyone and no
/// checkpoint has finalised since 2026-08-18.
///
/// The build plan's own order for the cutover is BFT payout path first, sweep second. v56 did the
/// sweep half early; this gate is the half that should have preceded it.
///
/// At and above this height [`crate::payout::select_shard_miner_work`] replaces
/// `select_ledger_miner_work` in the checkpoint's root computation and its diagnostic twin. The
/// shard converges where the legacy ledger cannot: its per-address totals are BYTE-IDENTICAL on
/// vm1/vm2/vm3 today, and nodes already gossip and agree the table root (21/21 `agree=true`).
///
/// ⚠ Both the root fn and the diagnostic fn must move together. A diagnostic left reading the old
/// source would describe a divergence that is not the one the vote actually turned on.
///
/// 963_388 is 30 blocks beyond the tip at arming (963_358 at 2026-08-20 23:14 UTC). The last 12
/// blocks ran at 13.5 min each, which puts the gate ~6.7 hours out; if the rate returns to ~8
/// min it is ~4.0 hours. Sized against the FAST case deliberately — the deploy must finish
/// before the gate, never the other way round.
///
/// ⚠ A node still on the old source when this fires computes its root from the legacy ledger and
/// diverges from the fleet exactly the way v56 did. That is the failure this gate exists to end,
/// so the ordering is the whole point: merge, canary, soak, roll all eight, THEN let the gate
/// arrive. `scripts/soak-test-l2.sh` flags `checkpoint-divergence` as critical and is the
/// detector if the roll runs late.
///
/// The cost of arriving late is bounded and self-clearing: nodes on either source reject each
/// other's proposals, which extends the existing outage rather than creating a new state, and it
/// resolves as soon as the last node is upgraded. That is what makes a short fuse defensible
/// here; it would not be if the divergence were permanent, which is precisely the legacy
/// ledger's problem.
///
/// It does NOT ride the Stage 6 deletion release.
pub const CHECKPOINT_FROM_SHARD_HEIGHT: u64 = 963_388;

/// Stage 6 step 3: height at and above which the coinbase payout commitment is constructed from
/// this node's OWN shard view, with no BFT vote in the path.
///
/// `u64::MAX` = never. Arming is a separate, observed change.
///
/// The vote being removed never inspected a share. `PayoutHandler::validate_proposal_split`
/// recomputes the miner split from the voter's own `local_miner_work` and demands an EXACT match
/// (GHOST-02), so its entire guarantee is "your arithmetic matches mine" — which is only ever as
/// strong as the two tables already agreeing. Share validity is established per-share at receive
/// time (GHOST-09 signature with receiver and address binding, the PoW preimage check, the
/// difficulty-tier commitment) and is untouched by this gate. Delete the gate, keep the rule.
///
/// ⛔ That exactness is a LIVENESS hazard, and it fired: nothing finalised between 18 and 21
/// August, and one address 6.71% apart rejected every checkpoint symmetrically. An exact-match
/// vote over tables that can diverge converts divergence into a total payment HALT. Above this
/// gate divergence is benign instead — `owed` is signed and never clamped, so an over- or
/// under-payment leaves a residual the next block corrects (SHARE_SHARD.md §4.4, §4.6).
///
/// This is what `SHARE_SHARD.md` §8 settles: "No consensus on the ledger. Each node pays from its
/// own view." §7 lists voting, quorum and two-phase commit as deleted.
///
/// ⚠ Removing the vote does NOT remove verification, it relocates it to §6: signature,
/// well-formedness and summary-chain consistency checked before ANY merge, plus unpredictable
/// λ-sampling of merkle leaves for PoW + GHOST-09 + binding. λ-sampling must be ENFORCING before
/// any node we do not own is admitted; this gate does not arm it.
///
/// **ARMED at 964_100** (2026-08-22). Tip was 963,575 when this was cut — 525 blocks, roughly
/// 3 days, sized against the precedent [`CHECKPOINT_FROM_SHARD_HEIGHT`] set (541 blocks). The
/// deploy must finish well before the gate, never the other way round.
///
/// ⚠ Every node must be on a binary that HAS the local path before this height arrives. All
/// eight ran `v1.11.25` from 2026-08-22, which is what makes arming safe: a node still on an
/// older binary would keep voting while its peers stopped proposing, and the two would disagree
/// about how the coinbase was committed.
///
/// **This is observable within minutes, not a 161-year wait.** The live proposal path is the
/// tip-driven one (`main.rs`, `payout_for_tips.handle_block_found`), which fires on every new
/// block — measured at 155 payout-consensus approvals per week on vm1. Above the gate those
/// become the no-vote path instead, so the change shows up ~22 times a day. That is what makes
/// "arm, observe, then delete" a sequence that can actually complete, rather than the kind of
/// precondition that quietly keeps the legacy path alive for ever.
///
/// What to watch after it fires: `"Paying from this node's own shard view (no vote"` should
/// appear ~22x/day and `"Payout consensus approved"` should stop. The payout ledger CHECKPOINT
/// is a separate path and must keep finalising — if it stops, this gate is not the cause but the
/// standoff it produces looks identical, so check both.
pub const PAYOUT_FROM_SHARD_HEIGHT: u64 = 964_100;

/// Height at and above which fee DRIFT is shared in the ratified proposal's own proportions —
/// 99% to the miners, 1% split treasury/node — instead of landing wholly on the treasury and
/// node pool.
///
/// # Why this is needed
///
/// The tip-change proposal cannot know what fees its block will collect, so it records an
/// estimate: `TemplateProcessor::payout_fee_estimate`, which falls back to `last_filled_fees`
/// because the tip-change fast-path template is structurally empty. That estimate is a per-node,
/// per-block LOTTERY — measured on mainnet 2026-08-26, consecutive proposals on one node ran
/// 2,562,564 → 621,742 → 25,030 → 4,056,247 sats, and two nodes at the same height differed by
/// 125x (vm1 25,030 against vm6 3,137,573) while their actual available fees agreed to within a
/// few percent.
///
/// `adjust_proposal_for_available_fees` already corrects the estimate to the fees actually
/// available, but it corrects ONLY the treasury and the node pool — "Miner entries are NEVER
/// touched in either direction". So the lottery permanently sets the miners' share: a node that
/// guessed 25,030 against ~2.8M real fees pays its miners 99% of `subsidy + 25,030` and routes
/// the remaining ~2.8M to the treasury and node pool. That is the very outcome #601 was written
/// to prevent, reproduced by an estimate that is merely small rather than zero.
///
/// Before `PAYOUT_FROM_SHARD_HEIGHT` the mesh vote collapsed all eight nodes onto one proposer's
/// estimate — still wrong, but uniform. Paying from each node's own shard view made every node's
/// own lottery live, which is why this surfaced at that gate and not before.
///
/// # Why a height gate
///
/// This changes coinbase construction, so it is consensus-visible: two nodes on different sides
/// of it would build different coinbases from the same proposal. Both paths exist in the new
/// binary and every node switches at the same block.
///
/// **ARMED at 964_695** (2026-08-29). Both preconditions in the paragraph above were met first:
///
/// - the whole fleet runs a binary that knows this path — it shipped dormant in v1.11.29 and
///   has been fleet-wide on all 8 nodes since, so no node can be on the wrong side of the gate
///   for lack of the code;
/// - it is not inside another gate's settling window — the last armed gate,
///   `PAYOUT_FROM_SHARD_HEIGHT = 964_100`, fired 2026-08-26 and was verified clean on all 8
///   nodes three days earlier. No other gate is armed anywhere near this height.
///
/// Height picked for MARGIN, not for a precise firing time — because the first attempt at this
/// got it wrong. That one used a 144-block average of 585 s/block to put activation "ten hours"
/// out at 964_695; the chain then ran at **443 s/block** and reached 964,694 in 7h16m, so the
/// height was about to pass with no node yet carrying the armed binary. It was caught before
/// anything shipped, and nothing was deployed, so no node could act on it.
///
/// ⛔ A 144-block average does NOT predict ten hours ahead. Block intervals are exponentially
/// distributed; the sample mean over a day is a poor bound on the next sixty blocks. Choose a
/// height that is safely BEYOND the roll under the FASTEST plausible rate, and accept that the
/// firing time is a range.
///
/// Sized against the PIPELINE, not a target clock time. Getting this binary live takes about
/// 4.5 h — build, `record-tests.sh`, two CI cycles (fix + version bump), a canary, a 60-minute
/// soak, then eight nodes. The height has to clear that even if blocks run at their fastest.
///
/// From 964,725 at 12:00 UTC on 2026-08-30, 80 blocks out:
///   - at the fastest rate observed in 24 h (443 s/block) -> ~9.8 h, about 21:50 UTC
///   - at the slowest observed        (630 s/block)       -> ~14.0 h, about 02:00 UTC
///
/// So roughly twice the pipeline even in the worst case. ⚠ Re-verify the remaining margin
/// immediately BEFORE the production roll and push the height out if the chain has run hot —
/// the 443-630 s/block spread measured over one night is why this cannot be set and forgotten.
///
/// ⚠ What changes at this height: miners stop being pinned to a flat sats floor. Measured live at
/// h964,479, `treasury == available_fees - 804768` EXACTLY on every re-proposal — the treasury
/// was taking 100% of every sat above that floor, against a policy of 99% miners / 1% treasury.
/// After this, drift is shared in the ratified proposal's own proportions.
pub const FEE_DRIFT_MINER_SHARE_HEIGHT: u64 = 964_805;

/// Public Mining proved by a real stratum handshake, not a bare TCP connect (#605). **ARMED at
/// 962_000.**
///
/// Below this height the challenger opens a TCP connection to the target's stratum port and treats
/// a successful connect as proof. `nc -l 3333` passes that, so +3 of the 15 node-reward shares are
/// earned by opening a socket. At and above it the challenger completes a real `mining.subscribe`
/// and requires a well-formed reply.
///
/// Gated because it changes what QUALIFIES a node for payout. A node still applying the connect test
/// while its peers demand a handshake would compute a different qualified set, and the node-reward
/// split would diverge — so the whole fleet must carry this build before the height.
///
/// 962_000 sits ~300 blocks after [`PAYOUT_MEDIAN_ADOPTION_HEIGHT`], keeping it clear of the three
/// gates already scheduled so a divergence can be attributed to one change rather than two. It is
/// ~1100 blocks beyond the tip at arming (roughly 6 days at the observed ~8 min/block).
pub const STRATUM_HANDSHAKE_PROOF_HEIGHT: u64 = 962_000;

/// Archive proved by serving TRANSACTION-level detail, not just block headers (#605).
/// **DORMANT — deliberately unarmed.**
///
/// Below this height the archive challenge asks only for a block, and every field of the response is
/// derivable from the public 80-byte header — so a pruned node, an SPV client or an on-demand proxy
/// passes and collects +5, the largest single capability weight.
///
/// At and above it the challenger names a specific transaction in that block and checks the returned
/// `TxData` against its own node's view of it. A pruned node cannot answer at all.
///
/// Being precise about the limit: this is NOT proof-of-storage. A proxy that fetches the block when
/// challenged still passes — it simply has to do real work rather than echo a header. The gain is
/// excluding the population that currently passes for free, not proving custody.
///
/// `u64::MAX` = never. Arming requires the whole fleet to run a binary that ASKS for a transaction,
/// because a node applying the tx check while its peers do not would compute a different qualified
/// set and the node-reward split would diverge.
pub const ARCHIVE_TX_PROOF_HEIGHT: u64 = u64::MAX;

/// H-7: height at and above which a challenger BROADCASTS the address proof it already
/// performs, so the `/24` a node claims becomes a converged, majority-attested fact rather
/// than a self-report nothing checks.
///
/// The probe itself has run in the verification rotation since #633 and is report-only. This
/// gate governs EMISSION, not probing, and it exists for a wire reason rather than a
/// consensus one: `CapabilityType` is a plain serde enum with no unknown-variant fallback,
/// so a node on an older binary cannot deserialise a verdict carrying `"address"` and drops
/// the whole message. Emitting before the fleet is uniform would therefore have every old
/// peer discard every new verdict — and, worse, discard it silently.
///
/// ARMED at 966_000 on 2026-09-01. Both preconditions this comment demanded were checked
/// immediately before arming, on the running fleet rather than from the source tree:
///
/// 1. **Every node knows the variant.** All eight run v1.11.33 at commit `bf3f822b5`, verified
///    per binary via `--version` (which names the commit since #820) rather than by version
///    string alone — the two are not the same claim, which is what #759 is about.
/// 2. **A live pass rate.** Re-measured on the new binary after the roll: **722 pass / 0 fail**
///    across all eight nodes, with zero `Unreachable`, `WrongSigner` or `BadSignature`. The
///    earlier 24h figure (9,681 / 181, 98.2%, 2026-08-21) stands as the longer baseline; this
///    confirms the rolled binary behaves the same.
///
/// 966_000 is ~785 blocks beyond where the arming roll lands (chain was at 965,065 when this
/// was written, running ~150 blocks/day — 144 blocks took 23h), so roughly five days of margin.
/// That is deliberately more than the ~2.2 days `SHARE_TIER_BIND_HEIGHT` used, because this
/// gate's failure mode is SILENT: an old peer does not reject a verdict carrying `"address"`,
/// it drops the entire message without saying so. Margin buys room to roll back and re-roll.
pub const ADDRESS_PROOF_HEIGHT: u64 = 966_000;

/// Multi-operator Sybil-resistant node qualification (Surface A-2). At and above this height,
/// the deterministic node-reward qualification counts a target's DISTINCT challengers only
/// when they are members of the consensus voter set AND come from diverse IP subnets, and it
/// requires the distinct-challenger floor as a fraction of the whole voter set — instead of
/// counting any node that recorded a verdict. Below it, the legacy network-size-scaled
/// distinct count stands (correct for a single-operator fleet whose challengers are all its
/// own nodes).
///
/// Which nodes qualify is consensus-visible (it decides the coinbase node split), so this is a
/// height gate, not a feature flag: both counting paths exist in the new binary and every node
/// switches at the same block, so a mixed-version fleet computes an identical node split during
/// the roll. Was held dormant until the voter set + per-node subnet map had converged fleet-wide,
/// then set comfortably past the roll window. ARMED — this height is in the past.
pub const VOTER_SET_QUALIFICATION_HEIGHT: u64 = 959_116;

/// Multi-operator consensus-drawn challenger assignment (Surface A-2b). At and above this
/// height, node-reward qualification counts a challenger's verdict only if that challenger was
/// ASSIGNED to challenge the target for the round the verdict was issued in — a deterministic
/// draw seeded by a buried block hash over the converged, subnet-deduplicated node pool
/// (`ghost_verification::challenger_assignment`). Below it, any recorded verdict counts (A-2's
/// voter-set + subnet floor still applies).
///
/// This removes the self-selected-challenger hole: without it the "random" challenger choice
/// only binds honest nodes, so a Sybil operator points its own fakes at its own target and
/// rubber-stamps. Which verdicts count is consensus-visible (it decides the coinbase node
/// split), so this is a height gate: every node recomputes the identical assignment at the
/// checkpoint cutoff, so a mixed-version fleet agrees on the node split during the roll.
/// Was held dormant until challenges had been issued+recorded against their assigned round for a
/// full lookback window, then set comfortably past the roll window. ARMED — this height is in the
/// past.
pub const CHALLENGER_ASSIGNMENT_HEIGHT: u64 = 959_161;

/// Finality lag (in blocks) between a round and the block whose hash seeds it: a round at tip
/// height `H` is seeded by `blockhash(H - CHALLENGER_ASSIGNMENT_SEED_LAG)`, buried enough that a
/// miner cannot grind the tip to steer the draw. Canonical value lives in ghost-verification so
/// the challenger draw uses one source of truth on both the selection and qualification sides.
pub const CHALLENGER_ASSIGNMENT_SEED_LAG: u64 = ghost_verification::challenger_assignment::SEED_LAG;

/// Active-voter-set scaffolding (Phase 4, v1.x). At and above this height, BFT payout voting
/// draws its eligible-voter set from the QUALIFIED ACTIVE nodes at the block's cutoff (the same
/// converged resolver Component E uses) instead of the static genesis MPC elder set — letting the
/// voting membership track the fleet as it grows/shrinks. Below it, the MPC elder set is used.
/// Which nodes vote is consensus-visible, so this is a height gate: every node resolves the
/// identical set at the checkpoint cutoff. ARMED @959_200 — the checkpoint-path voter set was
/// proven byte-identical fleet-wide first (`checkpoint_voter_set.hash` `98100ee8…` on all 8,
/// count=8, floored=false), and the redesign soaked clean gate-off on v1.11.9. Revert = restore
/// the prior binary (`.bak`) = instant disarm.
pub const ACTIVE_VOTER_SET_HEIGHT: u64 = 959_200;

/// Mesh node-list checkpoint (decentralised mining discovery, v2). At and above this height,
/// nodes propose/vote/finalise a BFT-signed snapshot of the public-mining node set that an
/// untrusted miner-side shim can verify offline (see tasks/design_mesh_node_list_checkpoint.md).
/// DORMANT (`u64::MAX`): below it nothing is proposed, so the binary is behaviour-neutral. Built
/// dormant — a concrete height is set only after fleet-wide convergence is proven, like the rest.
/// Stratum ports carried in a node's endpoint advert. Fleet-wide well-known values; a node
/// that moves them would need to say so in its advert, which is exactly what the advert is for.
pub const MESH_ADVERT_SV1_PORT: u16 = 3333;
/// See [`MESH_ADVERT_SV1_PORT`].
pub const MESH_ADVERT_SV2_PORT: u16 = 34255;
/// How often a node re-publishes its (unchanged) endpoint advert.
///
/// Re-publishing matters because the store is in memory: a peer that restarts has an empty
/// store and refills from this cadence. Ten minutes bounds how long a restarted node leaves
/// the fleet unable to reach full coverage, while costing a few hundred bytes per node.
pub const MESH_ADVERT_REPUBLISH_SECS: u64 = 600;

pub const MESH_NODE_LIST_CHECKPOINT_HEIGHT: u64 = u64::MAX;

/// Activation heights, resolved once at startup.
///
/// A regtest chain is ~100 blocks tall, so every mainnet gate is dormant there and a regtest
/// rehearsal silently exercises the PRE-gate paths — proving nothing about the behaviour being
/// shipped. The previous way round that was to patch the constants and rebuild, which means the
/// binary under test was not the binary deployed. That is how a 4-node regtest run produced 24
/// green enforcement coinbases on 2026-06-21 while the bug it was meant to catch was live.
///
/// So the gates are overridable from the environment — but NEVER on mainnet, where the constants
/// above are the only truth. A test cluster runs the real shipping binary with the gates pulled
/// down, rather than a different binary built for the occasion.
mod gates {
    use ghost_common::config::BitcoinNetwork;
    use std::sync::OnceLock;

    pub(super) static CLUSTER_ENFORCEMENT: OnceLock<u64> = OnceLock::new();
    pub(super) static COINBASE_FEE_SPLIT: OnceLock<u64> = OnceLock::new();
    pub(super) static VOTER_SET_QUALIFICATION: OnceLock<u64> = OnceLock::new();
    pub(super) static CHALLENGER_ASSIGNMENT: OnceLock<u64> = OnceLock::new();
    pub(super) static SHARE_POW_VERIFY: OnceLock<u64> = OnceLock::new();
    pub(super) static SHARE_TIER_BIND: OnceLock<u64> = OnceLock::new();
    pub(super) static PAYOUT_MEDIAN_ADOPTION: OnceLock<u64> = OnceLock::new();
    pub(super) static STRATUM_HANDSHAKE_PROOF: OnceLock<u64> = OnceLock::new();
    pub(super) static ARCHIVE_TX_PROOF: OnceLock<u64> = OnceLock::new();
    pub(super) static ADDRESS_PROOF: OnceLock<u64> = OnceLock::new();
    pub(super) static ACTIVE_VOTER_SET: OnceLock<u64> = OnceLock::new();
    pub(super) static SHARE_ADDR_BIND: OnceLock<u64> = OnceLock::new();
    pub(super) static MESH_NODE_LIST_CHECKPOINT: OnceLock<u64> = OnceLock::new();
    pub(super) static CHECKPOINT_FROM_SHARD: OnceLock<u64> = OnceLock::new();
    pub(super) static PAYOUT_FROM_SHARD: OnceLock<u64> = OnceLock::new();
    pub(super) static FEE_DRIFT_MINER_SHARE: OnceLock<u64> = OnceLock::new();
    /// Not a height — the difficulty-tier floor the shard will ingest. Same reasoning as the
    /// gates: a regtest fleet cannot mine one, so without an override the rehearsal exercises an
    /// empty shard. See [`crate::network_tier_log2`].
    pub(super) static NETWORK_TIER_FLOOR: OnceLock<u32> = OnceLock::new();

    pub(super) fn from_env(var: &str, network: &BitcoinNetwork, default: u64) -> u64 {
        if matches!(network, BitcoinNetwork::Mainnet) {
            return default; // mainnet gates are not negotiable
        }
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default)
    }
}

/// Resolve the activation gates for this run. Call once, at startup, before anything reads them.
pub fn init_activation_heights(network: &ghost_common::config::BitcoinNetwork) {
    let enforcement = gates::from_env(
        "GHOST_CLUSTER_ENFORCEMENT_HEIGHT",
        network,
        CLUSTER_ENFORCEMENT_HEIGHT,
    );
    let fee = gates::from_env(
        "GHOST_COINBASE_FEE_SPLIT_HEIGHT",
        network,
        COINBASE_FEE_SPLIT_HEIGHT,
    );
    let voter_set = gates::from_env(
        "GHOST_VOTER_SET_QUALIFICATION_HEIGHT",
        network,
        VOTER_SET_QUALIFICATION_HEIGHT,
    );
    let challenger_assignment = gates::from_env(
        "GHOST_CHALLENGER_ASSIGNMENT_HEIGHT",
        network,
        CHALLENGER_ASSIGNMENT_HEIGHT,
    );
    let share_pow_verify = gates::from_env(
        "GHOST_SHARE_POW_VERIFY_HEIGHT",
        network,
        SHARE_POW_VERIFY_HEIGHT,
    );
    let share_tier_bind = gates::from_env(
        "GHOST_SHARE_TIER_BIND_HEIGHT",
        network,
        SHARE_TIER_BIND_HEIGHT,
    );
    let active_voter_set = gates::from_env(
        "GHOST_ACTIVE_VOTER_SET_HEIGHT",
        network,
        ACTIVE_VOTER_SET_HEIGHT,
    );
    let share_addr_bind = gates::from_env(
        "GHOST_SHARE_ADDR_BIND_HEIGHT",
        network,
        SHARE_ADDR_BIND_HEIGHT,
    );
    let payout_median = gates::from_env(
        "GHOST_PAYOUT_MEDIAN_ADOPTION_HEIGHT",
        network,
        PAYOUT_MEDIAN_ADOPTION_HEIGHT,
    );
    let stratum_proof = gates::from_env(
        "GHOST_STRATUM_HANDSHAKE_PROOF_HEIGHT",
        network,
        STRATUM_HANDSHAKE_PROOF_HEIGHT,
    );
    let archive_tx = gates::from_env(
        "GHOST_ARCHIVE_TX_PROOF_HEIGHT",
        network,
        ARCHIVE_TX_PROOF_HEIGHT,
    );
    let address_proof =
        gates::from_env("GHOST_ADDRESS_PROOF_HEIGHT", network, ADDRESS_PROOF_HEIGHT);
    let mesh_node_list_checkpoint = gates::from_env(
        "GHOST_MESH_NODE_LIST_CHECKPOINT_HEIGHT",
        network,
        MESH_NODE_LIST_CHECKPOINT_HEIGHT,
    );
    let payout_from_shard = gates::from_env(
        "GHOST_PAYOUT_FROM_SHARD_HEIGHT",
        network,
        PAYOUT_FROM_SHARD_HEIGHT,
    );
    let fee_drift_miner_share = gates::from_env(
        "GHOST_FEE_DRIFT_MINER_SHARE_HEIGHT",
        network,
        FEE_DRIFT_MINER_SHARE_HEIGHT,
    );
    let checkpoint_from_shard = gates::from_env(
        "GHOST_CHECKPOINT_FROM_SHARD_HEIGHT",
        network,
        CHECKPOINT_FROM_SHARD_HEIGHT,
    );
    // The mesh envelope gate lives with the format it governs, in `ghost-consensus` — this crate
    // cannot own it, because `ghost-consensus` does not depend on `ghost-pool`. Resolving it here
    // and pushing it down keeps ONE value: the env override, the mainnet lock and the "what did
    // this run actually enforce" report all stay in the same place as every other gate, and the
    // predicate stays next to the preimage it selects.
    let mesh_envelope_v2 = gates::from_env(
        "GHOST_MESH_ENVELOPE_V2_HEIGHT",
        network,
        ghost_consensus::message::MESH_ENVELOPE_V2_HEIGHT,
    );
    ghost_consensus::message::set_mesh_envelope_v2_height(mesh_envelope_v2);
    let _ = gates::CLUSTER_ENFORCEMENT.set(enforcement);
    let _ = gates::COINBASE_FEE_SPLIT.set(fee);
    let _ = gates::VOTER_SET_QUALIFICATION.set(voter_set);
    let _ = gates::CHALLENGER_ASSIGNMENT.set(challenger_assignment);
    let _ = gates::SHARE_POW_VERIFY.set(share_pow_verify);
    let _ = gates::SHARE_TIER_BIND.set(share_tier_bind);
    let _ = gates::ACTIVE_VOTER_SET.set(active_voter_set);
    let _ = gates::SHARE_ADDR_BIND.set(share_addr_bind);
    let _ = gates::PAYOUT_MEDIAN_ADOPTION.set(payout_median);
    let _ = gates::STRATUM_HANDSHAKE_PROOF.set(stratum_proof);
    let _ = gates::ARCHIVE_TX_PROOF.set(archive_tx);
    let _ = gates::ADDRESS_PROOF.set(address_proof);
    let _ = gates::MESH_NODE_LIST_CHECKPOINT.set(mesh_node_list_checkpoint);
    let _ = gates::CHECKPOINT_FROM_SHARD.set(checkpoint_from_shard);
    let _ = gates::PAYOUT_FROM_SHARD.set(payout_from_shard);
    let _ = gates::FEE_DRIFT_MINER_SHARE.set(fee_drift_miner_share);

    // #780: state UNCONDITIONALLY what this run will enforce.
    //
    // The two `warn!`s further down are both conditional — one on a lowered tier floor, the
    // other on heights overridden from the environment, which `gates::from_env` refuses on
    // mainnet. So on the production fleet NEITHER fires and the node logged nothing at all
    // about its gates: the only way to know which heights a running binary carried was to
    // read the binary. That cost real time while arming FEE_DRIFT_MINER_SHARE_HEIGHT on
    // 2026-08-30, when "is this node armed, and at what height?" had no answer in the logs.
    //
    // Dormant gates print as `never` rather than 18446744073709551615, because a wall of
    // u64::MAX is exactly the sort of output people stop reading.
    fn h(v: u64) -> String {
        if v == u64::MAX {
            "never".to_string()
        } else {
            v.to_string()
        }
    }
    tracing::info!(
        network = ?network,
        cluster_enforcement = %h(enforcement),
        coinbase_fee_split = %h(fee),
        voter_set_qualification = %h(voter_set),
        challenger_assignment = %h(challenger_assignment),
        share_pow_verify = %h(share_pow_verify),
        share_tier_bind = %h(share_tier_bind),
        active_voter_set = %h(active_voter_set),
        share_addr_bind = %h(share_addr_bind),
        payout_median_adoption = %h(payout_median),
        stratum_handshake_proof = %h(stratum_proof),
        archive_tx_proof = %h(archive_tx),
        address_proof = %h(address_proof),
        mesh_node_list_checkpoint = %h(mesh_node_list_checkpoint),
        checkpoint_from_shard = %h(checkpoint_from_shard),
        payout_from_shard = %h(payout_from_shard),
        fee_drift_miner_share = %h(fee_drift_miner_share),
        "Activation heights resolved — these are the gates this node will enforce"
    );

    // Not a height, but resolved here for the same reason and under the same mainnet lock, so
    // there is one place to look for "what did this run actually enforce".
    let tier_floor = gates::from_env(
        "GHOST_NETWORK_TIER_LOG2",
        network,
        u64::from(ghost_common::share_shard::NETWORK_TIER_LOG2),
    );
    let tier_floor = clamp_tier_floor(tier_floor);
    let _ = gates::NETWORK_TIER_FLOOR.set(tier_floor);
    if tier_floor != ghost_common::share_shard::NETWORK_TIER_LOG2 {
        tracing::warn!(
            tier_floor,
            shipping_floor = ghost_common::share_shard::NETWORK_TIER_LOG2,
            "SHARD TIER FLOOR LOWERED — rehearsal only. This node will fold shares mainnet \
             would never admit."
        );
    }

    if enforcement != CLUSTER_ENFORCEMENT_HEIGHT
        || fee != COINBASE_FEE_SPLIT_HEIGHT
        || voter_set != VOTER_SET_QUALIFICATION_HEIGHT
        || challenger_assignment != CHALLENGER_ASSIGNMENT_HEIGHT
        || share_pow_verify != SHARE_POW_VERIFY_HEIGHT
        || share_tier_bind != SHARE_TIER_BIND_HEIGHT
        || active_voter_set != ACTIVE_VOTER_SET_HEIGHT
        || share_addr_bind != SHARE_ADDR_BIND_HEIGHT
        || mesh_node_list_checkpoint != MESH_NODE_LIST_CHECKPOINT_HEIGHT
    {
        tracing::warn!(
            cluster_enforcement_height = enforcement,
            coinbase_fee_split_height = fee,
            voter_set_qualification_height = voter_set,
            challenger_assignment_height = challenger_assignment,
            share_pow_verify_height = share_pow_verify,
            share_tier_bind_height = share_tier_bind,
            active_voter_set_height = active_voter_set,
            share_addr_bind_height = share_addr_bind,
            mesh_node_list_checkpoint_height = mesh_node_list_checkpoint,
            network = ?network,
            "Activation heights OVERRIDDEN from the environment — non-mainnet only"
        );
    }
}

/// The height at which GHOST-02 split mismatches become a rejection rather than a warning.
pub fn cluster_enforcement_height() -> u64 {
    *gates::CLUSTER_ENFORCEMENT.get_or_init(|| CLUSTER_ENFORCEMENT_HEIGHT)
}

/// The height at which TX fees move to the node reward pool and the coinbase becomes ratifiable
/// at tip change.
pub fn coinbase_fee_split_height() -> u64 {
    *gates::COINBASE_FEE_SPLIT.get_or_init(|| COINBASE_FEE_SPLIT_HEIGHT)
}

/// The height at which node-reward qualification restricts distinct challengers to the consensus
/// voter set and requires IP/subnet diversity (Surface A-2).
pub fn voter_set_qualification_height() -> u64 {
    *gates::VOTER_SET_QUALIFICATION.get_or_init(|| VOTER_SET_QUALIFICATION_HEIGHT)
}

/// The height at which node-reward qualification counts only verdicts from the challenger that
/// was consensus-ASSIGNED to challenge the target that round (Surface A-2b).
pub fn challenger_assignment_height() -> u64 {
    *gates::CHALLENGER_ASSIGNMENT.get_or_init(|| CHALLENGER_ASSIGNMENT_HEIGHT)
}

/// The height at/above which a share's 80-byte PoW header is required and every node
/// re-verifies `sha256d(header) == share_hash` instead of trusting the numeric claim
/// (Surface B). Accessor form so the gate is env-overridable off-mainnet like the rest.
pub fn share_pow_verify_height() -> u64 {
    *gates::SHARE_POW_VERIFY.get_or_init(|| SHARE_POW_VERIFY_HEIGHT)
}

/// Height at/above which a share commits to its difficulty tier in the coinbase and is credited the
/// committed tier rather than the difficulty claimed after hashing. DORMANT (`u64::MAX`) — see
/// [`SHARE_TIER_BIND_HEIGHT`]. Accessor form so it is env-overridable off-mainnet like the rest.
pub fn share_tier_bind_height() -> u64 {
    *gates::SHARE_TIER_BIND.get_or_init(|| SHARE_TIER_BIND_HEIGHT)
}

/// Whether a share seen at `height` commits to its difficulty tier and is credited that tier.
///
/// One predicate for the emitter (coinbase tag format, share tier field) and every verifier (tier
/// binding + tier credit), so the two cannot disagree about which rule is in force at a given block.
pub fn binds_difficulty_tier(height: u64) -> bool {
    height >= share_tier_bind_height()
}

/// Height at and above which the GHOST-09 share signature also binds `payout_address`.
pub fn share_addr_bind_height() -> u64 {
    *gates::SHARE_ADDR_BIND.get_or_init(|| SHARE_ADDR_BIND_HEIGHT)
}

/// The difficulty tier at and above which a share enters the shard (§4). Mainnet is always
/// [`ghost_common::share_shard::NETWORK_TIER_LOG2`]; off-mainnet it is overridable.
///
/// ⚠ Why this needs an override at all: the floor is 1024x diff1, and **no CPU miner can reach
/// it**. So on a regtest fleet every honestly mined share is filtered out before it reaches an
/// epoch — the fold reports `shares=0` while miners are actively submitting, and the shard under
/// test is permanently empty. Anything proven against that fleet was proven against nothing.
///
/// That blocked the half of §6 λ-sampling that actually protects operators. The ACCUSING
/// direction can be rehearsed by fabricating leaves, but the "an honest node is NOT convicted"
/// direction needs real shares in a real epoch, and none can exist. §6 is wired to `quarantine`,
/// so the failure mode it guards against is a fleet that mutually quarantines on the first
/// sampling tick — worth being able to rehearse on the real shipping binary rather than only in
/// a unit test.
///
/// Same discipline as the gates above: never on mainnet, and the binary under test stays the
/// binary that ships.
pub fn network_tier_log2() -> u32 {
    *gates::NETWORK_TIER_FLOOR.get_or_init(|| ghost_common::share_shard::NETWORK_TIER_LOG2)
}

/// Clamp an environment-supplied tier floor to something that can only ever WEAKEN the filter.
///
/// Two ways this bites if left to a bare `as u32`. A value above the shipping floor is not a
/// rehearsal of anything that ships — it would fold a stricter shard than mainnet and "prove"
/// behaviour no node will ever have. And `u64 as u32` truncates rather than saturates, so
/// `4294967306` (2^32 + 10) would silently arrive as `10` and read as a deliberate setting.
fn clamp_tier_floor(raw: u64) -> u32 {
    u32::try_from(raw)
        .unwrap_or(ghost_common::share_shard::NETWORK_TIER_LOG2)
        .min(ghost_common::share_shard::NETWORK_TIER_LOG2)
}

/// The shard's ingest predicate, reading the floor resolved for this run.
///
/// Mirrors [`ghost_common::share_shard::crosses_network_tier`] exactly, including that an absent
/// tier passes (a pre-gate share committed to no tier and is judged by the rules of its own era).
/// It exists so the fold's input query and the gossip receive filter cannot end up reading
/// different floors — two spellings of one gossip rule is a partition that presents as a bug in
/// something else entirely.
pub fn crosses_network_tier(tier_log2: Option<u32>) -> bool {
    match tier_log2 {
        Some(tier) => tier >= network_tier_log2(),
        None => true,
    }
}

/// Height at and above which the payout checkpoint computes its miner work from the shard
/// instead of the legacy unpaid ledger (#722).
pub fn checkpoint_from_shard_height() -> u64 {
    *gates::CHECKPOINT_FROM_SHARD.get_or_init(|| CHECKPOINT_FROM_SHARD_HEIGHT)
}

/// Height at and above which the coinbase payout commitment is built from this node's own shard
/// view, with no BFT vote in the path (Stage 6 step 3).
pub fn payout_from_shard_height() -> u64 {
    *gates::PAYOUT_FROM_SHARD.get_or_init(|| PAYOUT_FROM_SHARD_HEIGHT)
}

/// Height at and above which fee drift is shared with the miners in the ratified proposal's own
/// proportions, rather than landing wholly on the treasury and node pool.
pub fn fee_drift_miner_share_height() -> u64 {
    *gates::FEE_DRIFT_MINER_SHARE.get_or_init(|| FEE_DRIFT_MINER_SHARE_HEIGHT)
}

/// Height at and above which the checkpoint adopts the per-address median of voters' own
/// recomputed work, instead of the proposer's list verbatim (#606).
pub fn payout_median_adoption_height() -> u64 {
    *gates::PAYOUT_MEDIAN_ADOPTION.get_or_init(|| PAYOUT_MEDIAN_ADOPTION_HEIGHT)
}

/// Height at and above which Archive is proved by serving transaction-level detail (#605).
pub fn archive_tx_proof_height() -> u64 {
    *gates::ARCHIVE_TX_PROOF.get_or_init(|| ARCHIVE_TX_PROOF_HEIGHT)
}

/// Height at and above which a challenger broadcasts its H-7 address proof (#605).
pub fn address_proof_height() -> u64 {
    *gates::ADDRESS_PROOF.get_or_init(|| ADDRESS_PROOF_HEIGHT)
}

/// Height at and above which Public Mining is proved by a challenger-performed stratum handshake
/// rather than a bare TCP connect (#605).
pub fn stratum_handshake_proof_height() -> u64 {
    *gates::STRATUM_HANDSHAKE_PROOF.get_or_init(|| STRATUM_HANDSHAKE_PROOF_HEIGHT)
}

/// Whether a voter at `height` reports its own recomputed work, and finalisation adopts the median.
///
/// One predicate for both the emitter and the adopter, so they cannot disagree about which rule is
/// in force at a given block — a voter must never report while finalisation still adopts verbatim,
/// nor the reverse.
pub fn adopts_payout_median(height: u64) -> bool {
    height >= payout_median_adoption_height()
}

/// Whether a share seen at `height` must carry the address-bound signature.
///
/// One predicate, used by the signer and by every verifier, so the two cannot disagree about
/// which encoding is in force at a given block.
pub fn binds_payout_address(height: u64) -> bool {
    height >= share_addr_bind_height()
}

/// The height at which BFT payout voting draws its eligible-voter set from the qualified active
/// nodes at the block's cutoff instead of the static MPC elder set (Phase 4). Below it the MPC
/// elder set is used. See `ACTIVE_VOTER_SET_HEIGHT` for the height and the arming record — this
/// doc deliberately does not restate the value, so it cannot go stale when the gate moves.
pub fn active_voter_set_height() -> u64 {
    *gates::ACTIVE_VOTER_SET.get_or_init(|| ACTIVE_VOTER_SET_HEIGHT)
}

/// The height at/above which nodes propose+finalise the signed mesh node-list checkpoint for
/// decentralised mining discovery. DORMANT (`u64::MAX`) — behaviour-neutral until armed.
pub fn mesh_node_list_checkpoint_height() -> u64 {
    *gates::MESH_NODE_LIST_CHECKPOINT.get_or_init(|| MESH_NODE_LIST_CHECKPOINT_HEIGHT)
}

/// GhostGlyph P2P handler for visual identity registration.
pub mod glyph_handler;

/// Input validation utilities for security.
pub mod validation;

/// Capability self-check (Phase 3): per-capability prerequisite probes
/// surfaced via `/health/self_check` for operator visibility.
pub mod self_check;

/// Hardware-derived miner capacity (CPU/RAM/FD limits → max miners).
/// Operator's `network.max_miners` is a ceiling, not a floor.
pub mod capacity;

/// Cumulative Reaper stats — txs evaluated, reaped, accepted, dead-bytes
/// total, plus per-DeadCodeType counters. Read by `/api/v1/reaper/status`.
pub mod reaper_stats;

/// Decentralised Wraith coordinator election — live wiring (read-only, gated
/// off by default). Computes and publishes the per-epoch coordinator draw via
/// `wraith-protocol`; activates no role and changes no consensus message.
pub mod coordinator_election;

pub mod coordinator_supervisor;

/// CONSENSUS SECURITY: re-derives peer-broadcast capability verdicts against
/// this node's own Bitcoin Core, so a colluding minority of challengers cannot
/// fabricate a FAIL (to grief an honest node under the 95% gate) or a PASS.
pub mod verification_reverify;

// L2 uses NullifierRouteHandler from ghost-consensus (sender-side proofs).

/// Is one of our own addresses in the mining DNS answer? (B4)
///
/// `--status` used to report `in_dns` from the central registry's claim about us. That service is being
/// deleted, and the fact does not need a central service: a node can resolve the mining name and look
/// for itself in the answer. A direct observation rather than someone's assertion about it.
///
/// This is the check that would have surfaced #596 — vm5-8 were absent from `pool.bitcoinghost.org` for
/// weeks while every node reported itself healthy, because nothing compared the two.
///
/// `resolved` is the A-record set for the mining name; `local` is this node's own addresses. Both are
/// passed in so the decision is testable without DNS or network.
pub fn is_in_mining_dns(resolved: &[std::net::IpAddr], local: &[std::net::IpAddr]) -> InDns {
    if resolved.is_empty() {
        // Nothing resolved: the name is down, or we cannot see it. That is NOT "we are absent" — saying
        // so would turn a resolver problem into a false alarm about this node.
        return InDns::Unknown;
    }
    if local.is_empty() {
        return InDns::Unknown;
    }
    if local.iter().any(|l| resolved.contains(l)) {
        InDns::Yes
    } else {
        InDns::No
    }
}

/// Three-valued because "we could not tell" must not be reported as "we are not in DNS".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InDns {
    Yes,
    No,
    /// The name did not resolve, or we could not enumerate our own addresses.
    Unknown,
}

#[cfg(test)]
mod in_dns_tests {
    use super::{is_in_mining_dns, InDns};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The #596 case: this node is NOT in the mining DNS answer, and must say so.
    ///
    /// vm5-8 sat absent from `pool.bitcoinghost.org` for weeks while reporting themselves healthy,
    /// because nothing compared the node's own address against the name it is supposed to be behind.
    #[test]
    fn a_node_absent_from_the_dns_answer_is_reported_absent() {
        let resolved = vec![ip("83.136.251.162"), ip("85.9.198.212")];
        let local = vec![ip("94.237.102.192")]; // vm5, not in the answer
        assert_eq!(is_in_mining_dns(&resolved, &local), InDns::No);
    }

    #[test]
    fn a_node_present_in_the_dns_answer_is_reported_present() {
        let resolved = vec![ip("83.136.251.162"), ip("94.237.102.192")];
        let local = vec![ip("94.237.102.192")];
        assert_eq!(is_in_mining_dns(&resolved, &local), InDns::Yes);
    }

    /// THE failure mode worth guarding: an empty resolve is "we could not tell", NOT "we are absent".
    ///
    /// If the name is down, or the resolver is unreachable, reporting `No` turns an infrastructure
    /// problem into a false alarm pointed at this node — and an operator chasing the wrong thing is
    /// worse than one told plainly that the check did not run.
    #[test]
    fn an_unresolvable_name_is_unknown_not_absent() {
        let local = vec![ip("94.237.102.192")];
        assert_eq!(is_in_mining_dns(&[], &local), InDns::Unknown);
    }

    /// Same in the other direction: if we cannot enumerate our own addresses we know nothing.
    #[test]
    fn no_local_addresses_is_unknown_not_absent() {
        let resolved = vec![ip("83.136.251.162")];
        assert_eq!(is_in_mining_dns(&resolved, &[]), InDns::Unknown);
    }

    /// A node with several addresses counts as present if ANY of them is in the answer — the fleet is
    /// dual-stacked and a node behind one of its addresses is still receiving miners.
    #[test]
    fn any_matching_local_address_counts_as_present() {
        let resolved = vec![ip("83.136.251.162"), ip("2001:db8::1")];
        let local = vec![ip("10.0.0.5"), ip("2001:db8::1")];
        assert_eq!(is_in_mining_dns(&resolved, &local), InDns::Yes);
    }
}

#[cfg(test)]
mod payout_from_shard_gate_tests {
    use super::PAYOUT_FROM_SHARD_HEIGHT;

    /// The gate is a fleet-wide agreement: every node must flip on the SAME block or they
    /// disagree about how the coinbase was committed. Pinned to the exact value so a typo is
    /// distinguishable from an intended change.
    #[test]
    fn the_no_vote_gate_is_armed_at_the_intended_height() {
        assert_eq!(
            PAYOUT_FROM_SHARD_HEIGHT, 964_100,
            "the no-vote gate height is a fleet-wide agreement — changing it is a deliberate act"
        );
    }
}

#[cfg(test)]
mod tier_gate_tests {
    use super::{binds_difficulty_tier, SHARE_TIER_BIND_HEIGHT};

    /// **The dark-landing proof.** The tier gate ships dormant, so no live height binds a tier and
    /// the credit path is byte-identical to today across the whole mainnet range. The predicate is
    /// still genuinely wired — it fires at/above the resolved gate — so this is not a check that
    /// cannot fail.
    #[test]
    fn the_tier_gate_is_armed_at_the_intended_height() {
        // Pinned to the exact value, not merely "not u64::MAX". The height is the whole contract:
        // every node must agree on it or the fleet splits on credited work, and a typo here is
        // indistinguishable from an intended change without this line.
        assert_eq!(
            SHARE_TIER_BIND_HEIGHT, 962_100,
            "the tier gate height is a fleet-wide agreement — changing it is a deliberate act"
        );

        // Below the height nothing is tier-bound: the coinbase keeps the plain node tag and the
        // legacy credit path stands, byte-identical to the pre-tier build.
        assert!(!binds_difficulty_tier(962_099));
        assert!(!binds_difficulty_tier(961_000));
        assert!(!binds_difficulty_tier(0));

        // At and above it, every node flips together.
        assert!(binds_difficulty_tier(962_100));
        assert!(binds_difficulty_tier(962_101));
        assert!(binds_difficulty_tier(u64::MAX));
    }

    /// The three halves must name the SAME block. `pool_sv2` carries its own
    /// `activation_height` in config and the translator carries a bare flag, so nothing at compile
    /// time forces agreement — this records the value the shipped configs must match, so a change
    /// to one without the others fails here rather than at the height.
    #[test]
    fn the_shipped_configs_must_name_this_same_height() {
        let cfg = include_str!("../../../config/sri/pool-config.toml");
        assert!(
            cfg.contains("activation_height = 962100"),
            "config/sri/pool-config.toml must arm pool_sv2 at the same height as \
             SHARE_TIER_BIND_HEIGHT ({SHARE_TIER_BIND_HEIGHT})"
        );
        let tr = include_str!("../../../config/sri/translator-config.toml");
        assert!(
            tr.contains("\nquantise_to_tiers = true"),
            "config/sri/translator-config.toml must ship quantise_to_tiers = true in the arming \
             release — the translator has no chain view, so its flag is the third half of the gate"
        );
    }
}

#[cfg(test)]
mod tier_floor_tests {
    use super::*;
    use ghost_common::config::BitcoinNetwork;
    use ghost_common::share_shard::NETWORK_TIER_LOG2;

    /// Mainnet is not negotiable. The whole point of an override is that a test fleet runs the
    /// SHIPPING binary — which is only true if that binary ignores the variable in production.
    #[test]
    fn the_tier_floor_override_is_ignored_on_mainnet() {
        // SAFETY: single-threaded test, variable removed before returning.
        unsafe { std::env::set_var("GHOST_TEST_TIER_FLOOR", "1") };
        let mainnet = gates::from_env(
            "GHOST_TEST_TIER_FLOOR",
            &BitcoinNetwork::Mainnet,
            u64::from(NETWORK_TIER_LOG2),
        );
        let regtest = gates::from_env(
            "GHOST_TEST_TIER_FLOOR",
            &BitcoinNetwork::Regtest,
            u64::from(NETWORK_TIER_LOG2),
        );
        unsafe { std::env::remove_var("GHOST_TEST_TIER_FLOOR") };

        assert_eq!(
            mainnet,
            u64::from(NETWORK_TIER_LOG2),
            "mainnet must ignore the override entirely"
        );
        assert_eq!(
            regtest, 1,
            "off-mainnet must honour it, or there is no rehearsal"
        );
    }

    /// The clamp may only ever WEAKEN the filter, and must not truncate.
    #[test]
    fn the_tier_floor_clamp_cannot_strengthen_or_wrap() {
        assert_eq!(
            clamp_tier_floor(0),
            0,
            "a floor of 0 folds everything — allowed"
        );
        assert_eq!(clamp_tier_floor(1), 1);
        assert_eq!(
            clamp_tier_floor(u64::from(NETWORK_TIER_LOG2) + 5),
            NETWORK_TIER_LOG2,
            "a floor STRICTER than mainnet rehearses behaviour no node will ever have"
        );
        assert_eq!(
            clamp_tier_floor(u64::from(u32::MAX) + 1 + u64::from(NETWORK_TIER_LOG2)),
            NETWORK_TIER_LOG2,
            "2^32 + 10 must not truncate to 10 and read as a deliberate setting"
        );
    }

    /// An absent tier still passes, matching `ghost_common`'s predicate — a pre-gate share
    /// committed to no tier and is judged by the rules of its own era.
    #[test]
    fn an_absent_tier_passes_at_any_floor() {
        assert!(crosses_network_tier(None));
    }
}

#[cfg(test)]
mod activation_height_logging_tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    /// A `MakeWriter` that captures everything into a buffer, so the test asserts on what the
    /// node would ACTUALLY print rather than on the code's shape.
    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("capture lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// #780: a node must STATE which gates it enforces.
    ///
    /// Regression guard with teeth: the two pre-existing `warn!`s are conditional on a lowered
    /// tier floor or env overrides, and `gates::from_env` refuses overrides on mainnet — so on
    /// the production fleet neither fired and the node logged nothing at all. Asserting on the
    /// captured output is the only way to tell "logs it" from "has a log statement".
    #[test]
    fn init_activation_heights_states_what_it_enforces() {
        let cap = Capture::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(sub, || {
            crate::init_activation_heights(&ghost_common::config::BitcoinNetwork::Mainnet);
        });

        let out = String::from_utf8_lossy(&cap.0.lock().expect("capture lock").clone()).to_string();

        assert!(
            out.contains("Activation heights resolved"),
            "the node must state its gates on startup; captured output was: {out}"
        );
        // An ARMED gate must appear as its height...
        assert!(
            out.contains(&crate::FEE_DRIFT_MINER_SHARE_HEIGHT.to_string()),
            "the armed fee-drift height must be visible; got: {out}"
        );
        // ...and a DORMANT one as `never`, not a wall of u64::MAX nobody reads.
        assert!(
            out.contains("never"),
            "dormant gates must render as `never`; got: {out}"
        );
        assert!(
            !out.contains("18446744073709551615"),
            "u64::MAX must never be printed raw; got: {out}"
        );
    }
}

#[cfg(test)]
mod address_proof_gate_tests {
    /// The armed height is consensus-visible and must not drift silently.
    ///
    /// H-7 governs whether a challenger BROADCASTS its address proof. `CapabilityType` is a
    /// plain serde enum with no unknown-variant fallback, so a node that emits `"address"` to a
    /// peer which does not know the variant has that peer drop the WHOLE message — silently, not
    /// as a rejection. Two nodes disagreeing about this height therefore do not error, they just
    /// stop hearing each other's verdicts, and the qualified set diverges.
    ///
    /// Pinning the literal is the same treatment `FEE_DRIFT_MINER_SHARE_HEIGHT` gets, and for
    /// the same reason: a constant nobody asserts on is a constant a refactor can move.
    #[test]
    fn the_armed_height_is_pinned() {
        assert_eq!(
            crate::ADDRESS_PROOF_HEIGHT,
            966_000,
            "changing an armed consensus height requires a fleet roll — see the const's docs"
        );
    }

    /// Guards the specific regression of arming being UNDONE.
    ///
    /// `u64::MAX` reads as a perfectly ordinary value and a revert to it would leave every test
    /// that merely checks "the gate exists" passing, while the behaviour silently returns to
    /// never firing.
    #[test]
    fn the_gate_is_armed_not_dormant() {
        assert_ne!(
            crate::ADDRESS_PROOF_HEIGHT,
            u64::MAX,
            "ADDRESS_PROOF_HEIGHT is dormant again — arming was reverted"
        );
    }

    /// The mirrored copy in `ghost-consensus` must equal the real constant.
    ///
    /// `ghost-consensus` sits below `ghost-pool` in the dependency graph and cannot import this,
    /// so `ADDRESS_PROOF_SEPARATION_REFERENCE` mirrors it to assert the two v1.11.34 gates do not
    /// share a height. A duplicated consensus height is exactly the kind of thing that drifts, so
    /// it is asserted from the side that owns the original.
    #[test]
    fn the_mirror_in_ghost_consensus_matches() {
        assert_eq!(
            ghost_consensus::message::ADDRESS_PROOF_SEPARATION_REFERENCE,
            crate::ADDRESS_PROOF_HEIGHT,
            "the mirror in ghost-consensus has drifted from ADDRESS_PROOF_HEIGHT"
        );
    }

    /// The accessor must return the armed constant.
    ///
    /// ⚠ On mainnet `gates::from_env` returns the compiled default BEFORE reading the
    /// environment, so `GHOST_ADDRESS_PROOF_HEIGHT` cannot move this — arming or rolling back is
    /// always a binary plus a fleet roll. This asserts the accessor and the constant agree, so a
    /// future wiring change cannot leave them out of step.
    #[test]
    fn the_accessor_agrees_with_the_constant() {
        assert_eq!(crate::address_proof_height(), crate::ADDRESS_PROOF_HEIGHT);
    }
}
