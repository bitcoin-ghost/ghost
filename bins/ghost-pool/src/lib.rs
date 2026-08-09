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
pub mod settlement;
pub mod skeleton_store;

/// Remembering share proofs whose verification failure can never be undone.
pub mod terminal_reject_cache;

/// Mining round lifecycle and share accounting.
/// Bridge from the share-batch chain to this node's share verification (WP-5).
pub mod sbc_checks;

/// The share-batch chain running in shadow (WP-5) — computes, persists, pays nobody.
pub mod sbc_shadow;

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

/// Settle a won block by observing it on-chain, on every node rather than only the submitter.
///
/// Today `settle_paid_block` has one reachable call site, in the block-submitted path, so only the
/// node that submitted a winning block marks its shares paid. The other seven still owe the whole
/// paid set — and being the majority, their view is the one that reaches quorum on the next
/// proposal, which pays the same work twice.
///
/// At and above this height every node settles from its own view of the chain: the coinbase names
/// the payout it pays, so the block itself is the record. Below it the observer still matches and
/// logs, writing nothing — that dry run is what proves matching works before the behaviour turns on.
///
/// Gated because settlement changes the unpaid ledger every node votes with. A mixed fleet where
/// some nodes observe-settle and others do not would diverge on the first won block, so the flip
/// has to be simultaneous, like [`PAYOUT_TOLERANCE_V2_HEIGHT`].
///
/// ARMED at `961_400` (2026-08-03). Tip was `960_847` when this was cut — ~553 blocks, roughly
/// 3.5 days, and deliberately ~46h AFTER [`SHARE_ADDR_BIND_HEIGHT`] so the two behaviour changes
/// land on different blocks and a problem is attributable to one of them.
///
/// The emitting prerequisite is met and was verified on the wire rather than assumed: a live
/// stratum probe shows the coinbase scriptSig carrying `47485050` ("GHPP") plus the 16-byte payout
/// id, and that id matches the `Set approved payout for coinbase` the node logged. So peers are
/// writing the tag before any node reads it.
///
/// The "dry-run window showing matches across all eight" that this doc originally asked for cannot
/// be obtained: the pool has never won a block (`won_blocks` is empty), so the observer has had
/// nothing to match. `bins/ghost-pool/tests/regtest_settlement_rehearsal.rs` is the substitute —
/// it mines a genuinely tagged block, settles it over real RPC, orphans it with a real reorg,
/// reverses, reconsiders and re-settles. That proves the path; it is not eight production nodes
/// agreeing on a real win, and the difference is worth remembering.
///
/// KNOWN GAP at arming: settlement records the amounts the fleet RATIFIED, not the amounts the
/// coinbase actually paid, because fee drift mutates the approved proposal per node (#601). Share
/// marking is correct; the treasury figure may not be. Arming is still the right trade — without
/// it the seven non-winning nodes never settle at all and the next proposal pays the same work
/// twice (#589), which is the larger error.
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
    pub(super) static PAYOUT_MEDIAN_ADOPTION: OnceLock<u64> = OnceLock::new();
    pub(super) static STRATUM_HANDSHAKE_PROOF: OnceLock<u64> = OnceLock::new();
    pub(super) static ARCHIVE_TX_PROOF: OnceLock<u64> = OnceLock::new();
    pub(super) static ACTIVE_VOTER_SET: OnceLock<u64> = OnceLock::new();
    pub(super) static SHARE_ADDR_BIND: OnceLock<u64> = OnceLock::new();
    pub(super) static OBSERVED_SETTLEMENT: OnceLock<u64> = OnceLock::new();
    pub(super) static MESH_NODE_LIST_CHECKPOINT: OnceLock<u64> = OnceLock::new();

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
    let observed_settlement = gates::from_env(
        "GHOST_OBSERVED_SETTLEMENT_HEIGHT",
        network,
        OBSERVED_SETTLEMENT_HEIGHT,
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
    let mesh_node_list_checkpoint = gates::from_env(
        "GHOST_MESH_NODE_LIST_CHECKPOINT_HEIGHT",
        network,
        MESH_NODE_LIST_CHECKPOINT_HEIGHT,
    );
    let _ = gates::CLUSTER_ENFORCEMENT.set(enforcement);
    let _ = gates::COINBASE_FEE_SPLIT.set(fee);
    let _ = gates::VOTER_SET_QUALIFICATION.set(voter_set);
    let _ = gates::CHALLENGER_ASSIGNMENT.set(challenger_assignment);
    let _ = gates::SHARE_POW_VERIFY.set(share_pow_verify);
    let _ = gates::ACTIVE_VOTER_SET.set(active_voter_set);
    let _ = gates::SHARE_ADDR_BIND.set(share_addr_bind);
    let _ = gates::OBSERVED_SETTLEMENT.set(observed_settlement);
    let _ = gates::PAYOUT_MEDIAN_ADOPTION.set(payout_median);
    let _ = gates::STRATUM_HANDSHAKE_PROOF.set(stratum_proof);
    let _ = gates::ARCHIVE_TX_PROOF.set(archive_tx);
    let _ = gates::MESH_NODE_LIST_CHECKPOINT.set(mesh_node_list_checkpoint);

    if enforcement != CLUSTER_ENFORCEMENT_HEIGHT
        || fee != COINBASE_FEE_SPLIT_HEIGHT
        || voter_set != VOTER_SET_QUALIFICATION_HEIGHT
        || challenger_assignment != CHALLENGER_ASSIGNMENT_HEIGHT
        || share_pow_verify != SHARE_POW_VERIFY_HEIGHT
        || active_voter_set != ACTIVE_VOTER_SET_HEIGHT
        || share_addr_bind != SHARE_ADDR_BIND_HEIGHT
        || observed_settlement != OBSERVED_SETTLEMENT_HEIGHT
        || mesh_node_list_checkpoint != MESH_NODE_LIST_CHECKPOINT_HEIGHT
    {
        tracing::warn!(
            cluster_enforcement_height = enforcement,
            coinbase_fee_split_height = fee,
            voter_set_qualification_height = voter_set,
            challenger_assignment_height = challenger_assignment,
            share_pow_verify_height = share_pow_verify,
            active_voter_set_height = active_voter_set,
            share_addr_bind_height = share_addr_bind,
            observed_settlement_height = observed_settlement,
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

/// Height at and above which the GHOST-09 share signature also binds `payout_address`.
pub fn share_addr_bind_height() -> u64 {
    *gates::SHARE_ADDR_BIND.get_or_init(|| SHARE_ADDR_BIND_HEIGHT)
}

/// Height at and above which every node settles won blocks by observing them on-chain.
pub fn observed_settlement_height() -> u64 {
    *gates::OBSERVED_SETTLEMENT.get_or_init(|| OBSERVED_SETTLEMENT_HEIGHT)
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
