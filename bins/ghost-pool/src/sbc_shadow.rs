//! The share-batch chain running in shadow (WP-5).
//!
//! Both systems live; **only checkpoints feed the coinbase**. This computes the chain, folds
//! balances and persists them, and hands out the `(seq, state_root)` the trust gate compares across
//! the fleet. It pays nobody. Nothing here reaches the coinbase until WP-6.
//!
//! ## What a node batches
//!
//! Only shares **it** received — `received_by == our node id`. A gossiped share was received by a
//! peer and belongs in *that* peer's batch, which is the whole reason a node never needs a peer's
//! shares to compute the payout. Batching a share someone else received would double-count it the
//! moment both batches were adopted.
//!
//! ## Where the impure edges are
//!
//! The consensus decisions are pure and already tested in `ghost-common`: `pack_batch`,
//! `fold_shares`, `compute_state_root`, `verify_batch`, `on_batch`, `on_vote`. This type owns only
//! the parts that cannot be pure — the pending pool, the database, and the clock, which is supplied
//! by the caller rather than read here so the tests can drive it.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

use ghost_common::batch_consensus::{ProposerSchedule, SeqTally, SeqVoteLock};
use ghost_common::batch_driver::{
    on_batch, on_batch_phase, on_precommit, on_prevote, on_vote, Action, BatchContext, PhaseAction,
    PrecommitAction, PrevoteAction, VoteAction,
};
use ghost_common::batch_quarantine::Quarantine;
use ghost_common::batch_two_phase::SeqConsensus;
use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_common::share_batch::{
    advance_watermarks, compute_state_root, creditable_difficulty, fold_shares, pack_batch,
    ProposerWatermarks, ShareBatch,
};
use ghost_common::types::ShareProof;
use ghost_storage::database::Database;
use ghost_storage::sbc_store::ChainHead;

/// Ceiling on the pending pool.
///
/// Far above any healthy backlog — a draining chain empties this every sequence — so reaching it
/// means the node is stuck, not busy. Sized so the pool cannot become the largest thing in a pool
/// process that shares a box with ghostd.
const MAX_PENDING_SHARES: usize = 50_000;

/// How many sequences of commit certificates to keep behind the head.
///
/// A certificate has to outlive the sequence it proves — the node that needs it is by definition
/// behind — so this is deliberately generous relative to the consensus state, which is pruned the
/// moment a sequence closes.
const CERT_RETENTION: u64 = 4_096;

/// Certificates held in memory. One bound shared by minting and by remembering a verified peer's,
/// so neither path can grow without the other's ceiling applying.
const MAX_CERTS: usize = 64;

/// Verified batches awaiting a commit, keyed by `(seq, batch_hash)`.
///
/// The `u64` in the value is a monotonic insertion number, so eviction can mean OLDEST — a
/// `BTreeMap` keyed this way orders by hash, which is arbitrary.
type ProposalCache = BTreeMap<(u64, [u8; 32]), (u64, ShareBatch)>;

/// Verified precommit signatures, `(seq, round, batch_hash) -> voter -> signature`.
///
/// These ARE the certificate. Retaining them is the only reason a node that witnessed a commit can
/// prove it to one that did not.
type PrecommitSigs = BTreeMap<(u64, u32, [u8; 32]), BTreeMap<[u8; 32], [u8; 64]>>;

/// The chain's view on this node.
pub struct ShadowChain {
    identity: Arc<NodeIdentity>,
    db: Arc<Database>,
    /// Shares this node received and has not yet packed into a batch, KEYED BY SHARE HASH.
    ///
    /// A map, not a Vec, because the pending pool must not hold the same share twice. The share
    /// recorder can fire more than once for a share, and a duplicate inside a proposed batch is a
    /// TERMINAL fault: `verify_batch` returns `DuplicateShare`, every peer quarantines the
    /// proposer, and quarantine is operator-release-only. On the 2026-08-09 four-node run that
    /// excluded ghost-vm5 — the one canary carrying a real miner — from consensus permanently.
    ///
    /// Bounded by the pack budget on the way out, not on the way in: dropping a share here is work
    /// a miner never gets paid for, whereas a large pool merely produces a truncated batch and the
    /// remainder is carried to the next one.
    pending: Mutex<BTreeMap<[u8; 32], ShareProof>>,
    /// Serialises ADOPTION against JUDGING, so a judge sees one consistent chain state.
    ///
    /// `head` and `balances` are separate locks, and judging reads both: the parent comes from the
    /// head, the fold starts from the balances. `finalise` writes both. Mesh dispatch is one tokio
    /// task per connection, so a commit landing on one connection can interleave with a proposal
    /// being judged on another — and the judge then folds a batch onto balances that already
    /// include it. The result is a `StateRootMismatch`, which is a FAULT: an honest peer is
    /// quarantined, persistently, operator-release-only. Via the propose loop the victim can be
    /// this node itself.
    ///
    /// Outermost lock everywhere it appears. A judge takes it shared for the span of the snapshot;
    /// `finalise` takes it exclusive for the span of the mutation. Nothing takes it while holding
    /// `quarantine` or `consensus`, so the established quarantine -> consensus order is untouched.
    adoption: parking_lot::RwLock<()>,
    /// Set when this node's balances are folded PAST its head — it crashed between the two
    /// writes in `finalise`.
    ///
    /// Latched, not merely logged. Detecting that and carrying on is the "check that cannot fail"
    /// pattern: while the affected sequence is open, this node would build a batch whose
    /// `state_root` came from over-folded balances (every peer still on the old head FAULTS it, so
    /// the crashed node is quarantined fleet-wide) and would judge peers' proposals against the
    /// same poisoned state, quarantining honest proposers. Both are persistent and
    /// operator-release-only — precisely the damage class this design keeps removing.
    poisoned: std::sync::atomic::AtomicBool,
    /// Shares dropped because the pool hit its ceiling. Non-zero means the chain is not draining.
    pending_dropped: std::sync::atomic::AtomicU64,
    /// The adopted head, or `None` before genesis.
    head: RwLock<Option<ChainHead>>,
    /// Running balances after the head. Plaintext address -> integer micro-work, exactly the
    /// form `fold_shares` and `compute_state_root` take.
    balances: RwLock<BTreeMap<String, i64>>,
    /// Per-proposer high-water marks after the head — the cross-batch replay guard.
    ///
    /// Adopted state exactly like `balances`: derived from the adopted chain, advanced in
    /// `finalise`, persisted in the SAME transaction as the balances (a watermark ahead of the
    /// balances would fault honest proposers; behind, it would re-credit), and snapshotted under
    /// the `adoption` guard wherever a batch is judged.
    watermarks: RwLock<ProposerWatermarks>,
    /// Peers quarantined this process, with the outcome the driver decided.
    quarantine: Mutex<Quarantine>,
    /// Peers quarantined in an EARLIER process, restored from the database.
    ///
    /// Held separately from [`Quarantine`] rather than replayed into it: that type takes the
    /// `FaultReason` and the voter set the decision was made against, and neither is available at
    /// load time — the reason is persisted as text and the fleet is not yet known. Reconstructing
    /// an approximation would put a fabricated reason on a real exclusion.
    ///
    /// Checked before the driver is consulted, so release stays operator-only across restarts. An
    /// automatic timer would let a Byzantine node misbehave, wait it out, and repeat forever.
    restored_quarantine: RwLock<std::collections::HashSet<[u8; 32]>>,
    /// One vote per sequence, ever. Two individually-valid batches must not both reach quorum, and
    /// the voter is the only place that can be prevented.
    vote_lock: Mutex<SeqVoteLock>,
    /// Votes seen per sequence. Counted per SEQUENCE rather than per batch, because equivocation
    /// is only visible when the candidates are tallied together.
    tallies: Mutex<BTreeMap<u64, SeqTally>>,
    /// Batches we have SEEN and verified but not yet adopted, keyed by `(seq, batch_hash)`.
    ///
    /// Without this a commit can never be adopted. A precommit carries a hash, not contents, and
    /// the batch store holds only ALREADY-ADOPTED batches — so at the first commit every node
    /// looked for a batch nobody had stored, found nothing, and stopped. That reproduced the exact
    /// seq=1 wedge two-phase was built to remove, one layer later.
    ///
    /// Holds our OWN proposal too: `broadcast` filters self, so a proposer never receives its own
    /// batch back and would otherwise be the one node unable to adopt what it proposed.
    ///
    /// In memory by choice. Losing it on restart costs a node the ability to adopt a commit it
    /// has already forgotten the contents of, which sync repairs; persisting it would mean a
    /// schema migration for data that is worthless the moment the sequence closes.
    /// Value carries a monotonic insertion number so eviction can mean OLDEST.
    ///
    /// Keyed by `(seq, batch_hash)`, a `BTreeMap`'s first key is the lowest HASH — which is
    /// arbitrary, not oldest. Evicting on that would discard a live candidate at random.
    proposals: Mutex<ProposalCache>,
    /// Monotonic counter stamping cache insertions.
    proposal_seq_no: Mutex<u64>,
    /// Our own proposal for a `(seq, round)`, so a re-propose re-sends IDENTICAL bytes.
    ///
    /// The propose loop ticks every 30 s while a round lasts 90 s, and `build_batch` stamps
    /// `close_ts = now` — so rebuilding produced a DIFFERENT hash in the SAME round. Peers saw one
    /// node prevote two batches at one round, which is the definition of equivocation, and
    /// quarantined it. Any 30 s window without a polka would have turned honest nodes into
    /// self-quarantined equivocators fleet-wide.
    my_proposal: Mutex<Option<((u64, u32), ShareBatch)>>,
    /// The qualified-node set this chain agrees on, carried forward from the head batch.
    ///
    /// THE VOTER SET IS CONSENSUS DATA. It used to be a live per-node database query, and that one
    /// fact defeated four successive mechanisms for proving a sequence had committed — quorum is
    /// `bft_threshold(view)` so nodes disagreed on the bar, and a commit certificate hashes the
    /// membership so it could never match. Anchoring the query's CUTOFF to `head.close_ts` was not
    /// enough either: identical input still gave different output, because the query scans local
    /// eventually-consistent tables that are also subject to per-node retention pruning.
    ///
    /// Seeded at genesis from the ratified payout checkpoint's `node_shares` — an object the fleet
    /// already agreed on — then carried forward by every batch, with `verify_batch` treating any
    /// change as a terminal fault. Every node therefore derives the same set from the same chain,
    /// and no query touches the consensus path at all.
    membership: RwLock<Vec<([u8; 32], i32)>>,
    /// Precommit signatures, so a commit can be PROVED to a node that missed it.
    ///
    /// Signatures used to be verified and thrown away — the tally only ever needed to count
    /// voters. But a certificate is exactly those signatures, so without retaining them a node
    /// that witnessed a commit has no way to demonstrate it, and a node that missed one has no way
    /// to check. Keyed `(seq, round, batch_hash) -> voter -> signature`; duplicates from a resend
    /// overwrite harmlessly.
    precommit_sigs: Mutex<PrecommitSigs>,
    /// Certificates for sequences this node has COMMITTED, kept so they can be served.
    ///
    /// Held separately from `precommit_sigs` because that map is pruned with the consensus state
    /// the moment a sequence closes — which is precisely when the certificate becomes useful to
    /// everyone else. Bounded; a node that has pruned past a sequence simply cannot answer for it
    /// and the requester asks another peer.
    certs: Mutex<BTreeMap<u64, ghost_consensus::message::CommitCertificate>>,
    /// Two-phase consensus state, one per open sequence.
    ///
    /// Replaces `vote_lock` + `tallies` on the live path. Those two are retained only until the
    /// single-phase code is deleted: one vote per sequence is safe but cannot recover from a round
    /// that misses quorum, which wedged seq=1 permanently on the 2026-08-09 six-node run.
    ///
    /// Not persisted, deliberately. A lock is a promise about what this node has *seen*, and a
    /// restarted node has seen nothing — replaying a lock from disk would have it refuse to
    /// prevote a value the fleet has since agreed, with no evidence to justify the refusal. The
    /// cost of forgetting is that a restarted node participates from scratch; the cost of
    /// remembering wrongly is a node that cannot rejoin consensus.
    consensus: Mutex<BTreeMap<u64, SeqConsensus>>,
}

/// What a finalisation produced, for the trust gate and for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalised {
    pub seq: u64,
    pub state_root: [u8; 32],
    pub batch_hash: [u8; 32],
    pub credited: usize,
    pub unattributed: usize,
}

impl ShadowChain {
    /// Load persisted state. A restart must resume the chain, not restart it: the trust gate wants
    /// a byte-identical `(seq, state_root)` across the fleet for a SUSTAINED window, and a node
    /// that reset its chain on every deploy could never contribute to one.
    pub fn load(identity: Arc<NodeIdentity>, db: Arc<Database>) -> GhostResult<Self> {
        let head = db.sbc_head()?;
        let balances = db.sbc_load_balances()?;
        let watermarks = db.sbc_load_watermarks()?;
        info!(
            seq = head.as_ref().map(|h| h.seq),
            addresses = balances.len(),
            "SBC shadow: resumed"
        );
        // Quarantine survives the process by design, so restore it before judging anything.
        let restored: std::collections::HashSet<[u8; 32]> = db
            .sbc_quarantined()?
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        if !restored.is_empty() {
            info!(count = restored.len(), "SBC shadow: restored quarantine");
        }

        // A restart must recover membership from the chain, not start empty: an empty set means a
        // zero quorum, and the whole point is that this value is derived from consensus data
        // rather than from whatever this process happens to know.
        let membership = head
            .as_ref()
            .and_then(|h| db.sbc_get_batch(h.seq).ok().flatten())
            .and_then(|j| serde_json::from_str::<ShareBatch>(&j).ok())
            .map(|b| b.node_shares)
            .unwrap_or_default();
        // Detect a crash BETWEEN the two writes in `finalise`. Balances go first so a head is
        // never ahead of its state; the reverse is survivable but must not be silent, because
        // `sbc_store_batch` is idempotent while the FOLD is not — re-adopting that sequence would
        // fold it twice, and every later state root would be wrong for good.
        let mut poisoned = false;
        if let (Some(h), Ok(Some(bal_seq))) = (head.as_ref(), db.sbc_balances_seq()) {
            if bal_seq > h.seq {
                poisoned = true;
                error!(
                    head_seq = h.seq,
                    balances_seq = bal_seq,
                    "SBC shadow: balances are folded PAST the head — this node crashed between \
                     persisting balances and persisting the batch. Re-adopting that sequence would \
                     double-fold it. The chain will refuse to advance; this node needs its SBC \
                     state reset from a peer."
                );
            }
        }

        match (head.as_ref(), membership.is_empty()) {
            (Some(_), true) => {
                // A head with no membership is silently dead: every quorum check fails the
                // MIN_QUORUM floor, so the node defers everything forever, and no certificate can
                // verify against an empty set. Safe, but indistinguishable from a quiet chain
                // unless it says so. The only previous tell was the ABSENCE of a log line.
                error!(
                    "SBC shadow: head present but membership could not be recovered — this node \
                     will defer every batch and adopt nothing. Its head batch row is missing or \
                     will not deserialise; it needs resync."
                );
            }
            (Some(_), false) => {
                info!(voters = membership.len(), "SBC shadow: membership resumed")
            }
            (None, _) => {}
        }

        Ok(Self {
            identity,
            db,
            pending: Mutex::new(BTreeMap::new()),
            adoption: parking_lot::RwLock::new(()),
            poisoned: std::sync::atomic::AtomicBool::new(poisoned),
            pending_dropped: std::sync::atomic::AtomicU64::new(0),
            head: RwLock::new(head),
            balances: RwLock::new(balances),
            watermarks: RwLock::new(watermarks),
            quarantine: Mutex::new(Quarantine::new()),
            restored_quarantine: RwLock::new(restored),
            vote_lock: Mutex::new(SeqVoteLock::new()),
            tallies: Mutex::new(BTreeMap::new()),
            consensus: Mutex::new(BTreeMap::new()),
            membership: RwLock::new(membership),
            precommit_sigs: Mutex::new(BTreeMap::new()),
            certs: Mutex::new(BTreeMap::new()),
            proposals: Mutex::new(BTreeMap::new()),
            proposal_seq_no: Mutex::new(0),
            my_proposal: Mutex::new(None),
        })
    }

    /// The head, for judging an incoming batch's parent.
    pub fn head(&self) -> Option<ChainHead> {
        self.head.read().clone()
    }

    /// The running balances — a copy, because a validator folds a candidate batch onto them and
    /// must not mutate the adopted state while doing it.
    pub fn balances(&self) -> BTreeMap<String, i64> {
        self.balances.read().clone()
    }

    /// The per-proposer replay watermarks — a copy, for the same reason as [`Self::balances`].
    pub fn watermarks(&self) -> ProposerWatermarks {
        self.watermarks.read().clone()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// How many addresses carry a balance. Cheap — does not clone the map.
    pub fn balance_count(&self) -> usize {
        self.balances.read().len()
    }

    /// When the current sequence opened — the instant stall escalation is measured from.
    ///
    /// This is the head's `close_ts`, which is CONSENSUS DATA: it lives inside the batch and feeds
    /// `batch_hash`, so every node that adopted the head holds the same value byte for byte. It is
    /// deliberately not stored in a field, because the only way this can be wrong is if some code
    /// path sets it from a local clock, and a value that is derived cannot be set at all.
    ///
    /// It was a field, briefly, holding local wall-clock at adoption. That is the one thing it must
    /// never be. Whose turn it is comes from `(seq + escalation) % voters` and escalation is
    /// `(now - opened) / 90`, so two nodes whose `opened` differs by more than the ±1-step grace
    /// window wait on DIFFERENT proposers and neither ever proposes. On the fleet, ghost-vm8
    /// installed genesis 11,574 s before the others — 128 steps apart — and held every batch with
    /// `ProposerNotDue`. A rota that is a function of local time is not a rota.
    ///
    /// The cost is that a sequence following a long gap opens already escalated. That is harmless:
    /// escalation is only a rotation offset, every node computes the SAME offset, and the turn
    /// still passes every 90 s.
    pub fn seq_opened(&self) -> i64 {
        self.head.read().as_ref().map(|h| h.close_ts).unwrap_or(0)
    }

    /// Record a share THIS node received.
    ///
    /// Returns false — and keeps nothing — for a share received by a peer. That share belongs in
    /// the peer's batch; taking it here would credit the same work twice once both batches were
    /// adopted, and the two batches would each be individually valid.
    ///
    /// Idempotent on `share_hash`. Recording the same share twice must be harmless: a duplicate
    /// reaching a proposed batch is terminal, and the node that receives the most shares is the
    /// most likely to trip it — precisely the node the fleet can least afford to exclude.
    pub fn record_received(&self, share: ShareProof) -> bool {
        if share.received_by != self.identity.node_id() {
            return false;
        }
        let mut pending = self.pending.lock();

        // BOUNDED. Dropping a share here is work a miner is never credited for, which is why this
        // pool was deliberately unbounded on the way in — a large pool merely produces a truncated
        // batch, and the remainder is carried forward.
        //
        // That reasoning holds only while the chain closes sequences. A node that cannot reach
        // quorum never drains, so it accumulates every share it receives, forever, inside the
        // production ghost-pool process — and the node receiving the most shares fills fastest. On
        // a fleet where one box is already at 90% disk and another runs ghostd at 1.7 GB in 3.8 GB
        // of RAM, an unbounded pool on a wedged node is a production incident, not a corner case.
        //
        // So: a ceiling far above any healthy backlog, and when it is reached the OLDEST share
        // goes. Oldest first because a share from a stalled era is the least likely to still be
        // payable, and because losing recent work would hide the fact that the node is stuck.
        if pending.len() >= MAX_PENDING_SHARES && !pending.contains_key(&share.share_hash) {
            let oldest = pending
                .iter()
                .min_by_key(|(_, s)| s.timestamp)
                .map(|(h, _)| *h);
            if let Some(h) = oldest {
                pending.remove(&h);
                let dropped = self.pending_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Loud, and counted. Silent loss here would read as "this node received fewer
                // shares", which is indistinguishable from a miner leaving.
                warn!(
                    dropped_total = dropped,
                    pending = pending.len(),
                    "SBC: pending pool at capacity — dropping the oldest share. The chain is not \
                     draining; shares are being lost to a stalled sequence"
                );
            }
        }

        pending.insert(share.share_hash, share);
        true
    }

    /// Whether this node's persisted state is internally inconsistent after a crash.
    ///
    /// While set, the node neither proposes nor judges — both would quarantine somebody
    /// permanently for a fault that is ours.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Relaxed)
    }

    /// How many shares this node has dropped for want of a draining chain.
    pub fn pending_dropped(&self) -> u64 {
        self.pending_dropped.load(Ordering::Relaxed)
    }

    /// Build the next batch from the pending pool, without proposing it.
    ///
    /// Returns `None` when there is nothing to batch. An empty batch is a legitimate claim ("I
    /// received nothing"), but proposing one on every tick would fill the chain with noise; the
    /// caller decides whether a heartbeat batch is wanted.
    ///
    /// The pool is NOT drained here. Draining before adoption would lose the shares if the batch
    /// failed to reach quorum — see [`ShadowChain::finalise`], which drains what was actually
    /// adopted.
    pub fn build_batch(&self, close_ts: i64, budget_bytes: usize) -> Option<ShareBatch> {
        // Before genesis there is nothing to build on. The caller must run the genesis ceremony
        // first; proposing seq 0 from here would be starting a chain from nothing, which is a
        // chain anybody could start.
        // Proposing from over-folded balances emits a batch every peer on the old head FAULTS,
        // so this node would quarantine ITSELF fleet-wide for its own crash.
        if self.is_poisoned() {
            return None;
        }

        // Same consistent snapshot as the judging path. A torn read here emits a batch whose
        // `prev_batch_hash` names one head while its `state_root` was computed from another's
        // balances — self-inconsistent, and every peer still on the old head FAULTS it, so this
        // node quarantines itself across the fleet for its own race. The watermark is part of the
        // same snapshot for the same reason.
        let (head, balances_snapshot, my_watermark) = {
            let _snapshot = self.adoption.read();
            let head = self.head()?;
            let my_watermark = self
                .watermarks
                .read()
                .get(&self.identity.node_id())
                .copied();
            (head, self.balances(), my_watermark)
        };

        // A batch containing an ineligible share is a TERMINAL fault at every peer, and shares
        // pack in canonical order — so one bad share at the head of the pool would sit at the
        // front of every batch this node ever proposes, quarantining it fleet-wide. Two classes:
        //
        // - PERMANENTLY ineligible — at or before our own adopted watermark (already credited),
        //   past the D10 age bound (only gets older), or an uncreditable difficulty. Dropped from
        //   the pool: they can never be proposed, and holding them wedges the proposer.
        // - Not eligible YET — timestamped after this batch's close. Held in the pool and left
        //   out of this batch; a later close covers them.
        let pending: Vec<ShareProof> = {
            let mut pool = self.pending.lock();
            let before = pool.len();
            pool.retain(|_, s| {
                let replayed = my_watermark.is_some_and(|wm| (s.timestamp, s.share_hash) <= wm);
                let too_old = match i64::try_from(s.timestamp) {
                    // A timestamp that does not fit i64 can never satisfy the D10 bound.
                    Err(_) => true,
                    Ok(ts) => {
                        close_ts.saturating_sub(ts)
                            > ghost_common::batch_consensus::MAX_SHARE_AGE_SECS
                    }
                };
                !(replayed || too_old || !creditable_difficulty(s.difficulty))
            });
            let discarded = before - pool.len();
            if discarded > 0 {
                // Loud: dropped work is work a miner is never credited for, and it should read as
                // "these shares could not legally be proposed", not as a miner leaving.
                warn!(
                    discarded,
                    "SBC: discarding pending shares no batch could ever carry \
                     (replayed, past the age bound, or uncreditable difficulty)"
                );
            }
            pool.values()
                .filter(|s| i64::try_from(s.timestamp).is_ok_and(|ts| ts <= close_ts))
                .cloned()
                .collect()
        };
        if pending.is_empty() {
            return None;
        }

        let packed = pack_batch(&pending, budget_bytes);
        if packed.included.is_empty() {
            return None;
        }

        let (seq, prev_batch_hash) = (head.seq + 1, head.batch_hash);

        let mut balances = balances_snapshot;
        fold_shares(&mut balances, &packed.included);
        let state_root = compute_state_root(&balances, seq, close_ts);

        let mut batch = ShareBatch {
            seq,
            prev_batch_hash,
            close_ts,
            proposer: self.identity.node_id(),
            shares: packed.included,
            settled_blocks: Vec::new(),
            // The undo channel is carried empty until WP-6 folds settlements.
            reversed_blocks: Vec::new(),
            // Carried forward, never re-derived. `verify_batch` faults any change.
            node_shares: self.membership.read().clone(),
            state_root,
            truncated: packed.truncated,
            pending_count: packed.deferred.len() as u32,
            proposer_signature: Vec::new(),
        };
        let hash = batch.batch_hash();
        batch.proposer_signature = self.identity.sign(&hash).to_vec();
        Some(batch)
    }

    /// Propose, if it is this node's turn and there is something to say.
    ///
    /// Whose turn it is comes from [`ProposerSchedule`], including stall escalation — a hash chain
    /// cannot skip a sequence, so an absent proposer would deadlock it forever without the turn
    /// passing on. Exactly one node is authorised to propose at a time; acceptance is wider by a
    /// step to absorb clock skew, but proposing is not, or two nodes split the vote on one
    /// sequence.
    pub fn try_propose(
        &self,
        schedule: &ProposerSchedule,
        now: i64,
        budget_bytes: usize,
    ) -> Option<ShareBatch> {
        let head = self.head()?;
        let seq = head.seq + 1;
        let opened = head.close_ts;
        if !schedule.is_my_turn(seq, &self.identity.node_id(), opened, now) {
            return None;
        }

        // Re-proposing within one round must re-send IDENTICAL bytes.
        //
        // The propose loop ticks every 30 s while a round lasts 90 s, and `build_batch` stamps
        // `close_ts = now` — so rebuilding produced a DIFFERENT batch_hash inside the SAME round.
        // Peers saw one node prevote two different batches at one round, which is exactly the
        // definition of equivocation, and quarantined it; the node also caught its own on the
        // self-count and quarantined itself. Any 30 s window without a polka would have converted
        // honest nodes into excluded equivocators fleet-wide — worst precisely when the fleet is
        // already struggling to reach quorum.
        let round = schedule.escalation_at(opened, now);
        if let Some(existing) = self.my_proposal_for(seq, round) {
            return Some(existing);
        }

        let batch = self.build_batch(now, budget_bytes)?;
        self.remember_my_proposal(seq, round, &batch);
        Some(batch)
    }

    /// The parent BATCH this node would judge `batch_seq` against.
    ///
    /// Shared by the single-phase and two-phase paths deliberately. Two copies of this resolution
    /// is how the mesh and HTTP hashrate providers came to swallow the same error twice on
    /// 2026-08-09, reporting a confident zero from a node doing 94 TH/s.
    ///
    /// A head held only as a summary is not enough — the driver judges against the batch itself.
    /// Every failure here is a DEFER, never a fault: not holding the parent is a sync condition,
    /// and branding a peer for our own gap is the one mistake a terminal fault cannot take back.
    fn parent_for(
        &self,
        batch_seq: u64,
    ) -> Result<ShareBatch, ghost_common::batch_consensus::DeferReason> {
        use ghost_common::batch_consensus::DeferReason;

        let Some(head) = self.head() else {
            // No genesis yet: we cannot judge anything and must catch up first.
            return Err(DeferReason::AheadOfUs {
                batch_seq,
                our_seq: 0,
            });
        };
        // Outside the retention window means we are too far behind to judge, not that the peer is
        // wrong.
        let Ok(Some(parent_json)) = self.db.sbc_get_batch(head.seq) else {
            return Err(DeferReason::AheadOfUs {
                batch_seq,
                our_seq: head.seq,
            });
        };
        serde_json::from_str::<ShareBatch>(&parent_json).map_err(|_| {
            warn!(
                seq = head.seq,
                "SBC shadow: stored parent will not deserialise — holding rather than judging"
            );
            DeferReason::AheadOfUs {
                batch_seq,
                our_seq: head.seq,
            }
        })
    }

    /// Judge an incoming batch and record what follows.
    ///
    /// The decision is entirely `batch_driver::on_batch`'s — this supplies the context and applies
    /// the consequences. Position is judged before contents there, so a batch this node is not
    /// entitled to judge is never branded for a defect; the response to a fault cannot be taken
    /// back.
    pub fn on_proposal<C: ghost_common::batch_consensus::BatchChecks>(
        &self,
        batch: &ShareBatch,
        schedule: &ProposerSchedule,
        checks: &C,
        now: i64,
    ) -> Action {
        // A peer excluded in an earlier process stays excluded. Checked here rather than inside
        // the driver because the restored set is deliberately not replayed into `Quarantine`.
        if self.restored_quarantine.read().contains(&batch.proposer) {
            return Action::ProposerQuarantined;
        }

        let parent = match self.parent_for(batch.seq) {
            Ok(p) => p,
            Err(reason) => return Action::Hold { reason },
        };

        let balances = self.balances();
        let watermarks = self.watermarks();
        let ctx = BatchContext {
            parent: &parent,
            parent_balances: &balances,
            watermarks: &watermarks,
            schedule,
            checks,
            now,
        };

        let action = {
            let mut quarantine = self.quarantine.lock();
            let mut lock = self.vote_lock.lock();
            on_batch(batch, &ctx, &mut quarantine, &mut lock)
        };

        // A terminal fault must outlive the process, or a restart silently forgives it.
        if let Action::Quarantine { reason, .. } = &action {
            let reason = format!("{reason:?}");
            if let Err(e) = self
                .db
                .sbc_quarantine(batch.proposer, &reason, Some(batch.seq), now)
            {
                warn!(error = %e, "SBC shadow: could not persist quarantine");
            }
            self.restored_quarantine.write().insert(batch.proposer);
        }

        action
    }

    /// Judge an incoming batch under TWO-PHASE and say what to prevote.
    ///
    /// The returned hash is what the locking rule chose, which may not be the batch that arrived.
    pub fn on_proposal_phase<C: ghost_common::batch_consensus::BatchChecks>(
        &self,
        batch: &ShareBatch,
        schedule: &ProposerSchedule,
        checks: &C,
        now: i64,
    ) -> PhaseAction {
        if self.restored_quarantine.read().contains(&batch.proposer) {
            return PhaseAction::ProposerQuarantined;
        }

        // A node whose balances are folded past its head judges against over-folded state, and
        // `StateRootMismatch` is a FAULT — it would quarantine honest proposers for its own crash.
        // Hold everything until an operator resets it.
        if self.is_poisoned() {
            return PhaseAction::Hold {
                reason: ghost_common::batch_consensus::DeferReason::ParentMismatch,
            };
        }

        // ONE consistent snapshot, under the adoption guard. Reading the parent and the balances
        // separately lets a commit finalising on another tokio task land between them, so the fold
        // starts from state that ALREADY includes this batch — a `StateRootMismatch`, which is a
        // FAULT, so an honest peer collects a persistent, operator-release-only quarantine for our
        // race. Via the propose loop's self-judge the victim can be this node.
        //
        // Released before `quarantine`/`consensus` are taken, so `adoption` stays outermost.
        let (parent, balances, watermarks) = {
            let _snapshot = self.adoption.read();
            let parent = match self.parent_for(batch.seq) {
                Ok(p) => p,
                Err(reason) => return PhaseAction::Hold { reason },
            };
            (parent, self.balances(), self.watermarks())
        };
        let ctx = BatchContext {
            parent: &parent,
            parent_balances: &balances,
            watermarks: &watermarks,
            schedule,
            checks,
            now,
        };

        // The window guard belongs HERE too, not only on the vote paths. `verify_batch` defers on
        // POSITION before it checks any signature, so an unsigned proposal naming seq 10^18 needs
        // no credentials — and creating the consensus entry before judging left one per distinct
        // sequence that `prune_below` (which retains `k >= bound`) can never reach. The previous
        // fix guarded the two vote paths and missed this one.
        if !self.seq_in_window(batch.seq) {
            return PhaseAction::Hold {
                reason: ghost_common::batch_consensus::DeferReason::AheadOfUs {
                    batch_seq: batch.seq,
                    our_seq: self.head().map(|h| h.seq).unwrap_or(0),
                },
            };
        }

        // A voter set this small cannot produce a meaningful quorum, and freezing one from it is
        // a SAFETY defect, not just a liveness one: `SeqConsensus::new` captures `quorum` at first
        // touch and never refreshes it, so an entry created during one degraded read of the
        // qualification query keeps that bar forever. `bft_threshold(0) == 0` and
        // `bft_threshold(1) == 1`, so a single later precommit — for any candidate, including a
        // losing round's — would latch `committed`, and the sync path then treats that latch as
        // binding and refuses the fleet's real batch for good.
        //
        // The query returns EMPTY on database error by design, so this is an ordinary failure
        // mode, not an attack.
        if schedule.quorum() < Self::MIN_QUORUM {
            return PhaseAction::Hold {
                reason: ghost_common::batch_consensus::DeferReason::ProposerNotDue,
            };
        }

        let action = {
            // LOCK ORDER: quarantine, then consensus. Every path taking both takes them in this
            // order — the prevote/precommit paths took them the other way round, and two messages
            // arriving together on separate tokio tasks would have deadlocked both workers on
            // parking_lot mutexes held across an await boundary.
            let mut quarantine = self.quarantine.lock();
            let mut consensus = self.consensus.lock();
            let entry = consensus
                .entry(batch.seq)
                .or_insert_with(|| SeqConsensus::new(batch.seq, schedule.quorum()));
            on_batch_phase(batch, &ctx, &mut quarantine, entry)
        };

        // Keep any batch that VERIFIED, so a later commit for it has something to adopt.
        if matches!(action, PhaseAction::Prevote { .. }) {
            self.remember_proposal(batch);
        }

        if let PhaseAction::Quarantine { reason, .. } = &action {
            let reason = format!("{reason:?}");
            if let Err(e) = self
                .db
                .sbc_quarantine(batch.proposer, &reason, Some(batch.seq), now)
            {
                warn!(error = %e, "SBC shadow: could not persist quarantine");
            }
            self.restored_quarantine.write().insert(batch.proposer);
        }

        action
    }

    /// How far above the head a sequence may be before we refuse to hold any state for it.
    ///
    /// A signed vote naming `seq = 10^18` would otherwise create a map entry no head-relative
    /// prune could ever reach, and one peer can send as many distinct sequences as it likes.
    const SEQ_LOOKAHEAD: u64 = 8;

    /// The smallest quorum this node will hold consensus state against.
    ///
    /// Below this the voter view is degraded rather than small — the qualification query returns
    /// EMPTY on a database error — and a frozen low quorum is worse than no state at all, because
    /// `SeqConsensus` captures `quorum` at first touch and defends whatever it later latches.
    const MIN_QUORUM: usize = 3;

    /// Whether a sequence is close enough to our head to be worth holding state for.
    fn seq_in_window(&self, seq: u64) -> bool {
        // No genesis, no window. Before genesis this node cannot judge a batch at ANY sequence,
        // so consensus state for one is state nothing will ever resolve — and because
        // `prune_below` only runs on finalise, nothing would ever remove it either. Treating an
        // absent head as seq 0 admitted votes for 0..=8 from any voter and kept them.
        let Some(head) = self.head().map(|h| h.seq) else {
            return false;
        };
        seq > head.saturating_sub(1) && seq <= head.saturating_add(Self::SEQ_LOOKAHEAD)
    }

    /// Keep a verified batch so a later commit for it has contents to adopt.
    fn remember_proposal(&self, batch: &ShareBatch) {
        if !self.seq_in_window(batch.seq) {
            return;
        }
        let head = self.head().map(|h| h.seq).unwrap_or(0);
        const MAX_CACHED: usize = 64;
        let mut proposals = self.proposals.lock();
        proposals.retain(|(seq, _), _| *seq + 1 > head);
        // Evict the OLDEST rather than refuse the newest. Refusing the newcomer was backwards:
        // each 90 s escalation round mints a distinct authorised candidate, so under a long stall
        // the cache filled with losing candidates and dropped the one most likely to be committed
        // — sending adoption down the sync-request path for the batch it was most certain to need.
        while proposals.len() >= MAX_CACHED {
            let Some(oldest) = proposals
                .iter()
                .min_by_key(|(_, (n, _))| *n)
                .map(|(k, _)| *k)
            else {
                break;
            };
            proposals.remove(&oldest);
        }
        let n = {
            let mut counter = self.proposal_seq_no.lock();
            *counter += 1;
            *counter
        };
        proposals.insert((batch.seq, batch.batch_hash()), (n, batch.clone()));
    }

    /// Test-only access to the caching path, which is otherwise driven by a verdict.
    #[cfg(test)]
    pub fn remember_proposal_for_test(&self, batch: &ShareBatch) {
        self.remember_proposal(batch);
    }

    /// The verified batch matching a committed hash, if we hold it.
    pub fn remembered_proposal(&self, seq: u64, batch_hash: [u8; 32]) -> Option<ShareBatch> {
        self.proposals
            .lock()
            .get(&(seq, batch_hash))
            .map(|(_, b)| b.clone())
    }

    /// Our own proposal for `(seq, round)`, if we already made one.
    ///
    /// Re-proposing must re-send IDENTICAL bytes: `build_batch` stamps `close_ts = now`, so
    /// rebuilding on the 30 s propose tick produced a different hash inside one 90 s round, and
    /// prevoting both is equivocation by any peer's reckoning.
    pub fn my_proposal_for(&self, seq: u64, round: u32) -> Option<ShareBatch> {
        let guard = self.my_proposal.lock();
        guard
            .as_ref()
            .filter(|((s, r), _)| *s == seq && *r == round)
            .map(|(_, b)| b.clone())
    }

    /// Record our own proposal, and keep a copy in the adoption cache.
    ///
    /// `broadcast` filters self, so a proposer never receives its own batch back — without this
    /// it would be the one node that cannot adopt the batch it proposed.
    pub fn remember_my_proposal(&self, seq: u64, round: u32, batch: &ShareBatch) {
        *self.my_proposal.lock() = Some(((seq, round), batch.clone()));
        self.remember_proposal(batch);
    }

    /// Freeze the proof that `batch_hash` was committed at `(seq, round)`.
    ///
    /// Called at the moment of commit, while the signatures are still held — `prune_below` drops
    /// them with the rest of the sequence's state immediately afterwards, and that is precisely
    /// when every other node starts needing them.
    fn mint_certificate(
        &self,
        seq: u64,
        round: u32,
        batch_hash: [u8; 32],
        schedule: &ProposerSchedule,
        now: i64,
    ) {
        let Some(sigs) = self
            .precommit_sigs
            .lock()
            .get(&(seq, round, batch_hash))
            .cloned()
        else {
            return;
        };
        let cert = ghost_consensus::message::CommitCertificate {
            seq,
            round,
            batch_hash,
            // Stamp the membership we counted this quorum over, so a receiver can only check it
            // against the same one.
            voter_set_hash: ghost_consensus::message::voter_set_hash(schedule.voters()),
            precommits: sigs
                .into_iter()
                .map(|(v, sig)| (hex::encode(v), hex::encode(sig)))
                .collect(),
        };
        // PERSIST IT. Held only in memory, this proof evaporated on restart — and a rolling fleet
        // restart is the ordinary deploy, which left no node able to prove any commit and wedged
        // any node that happened to be behind at that moment. Catch-up is correctly gated on a
        // verifiable certificate, so a lost proof is a lost node.
        match serde_json::to_string(&cert) {
            Ok(json) => {
                if let Err(e) =
                    self.db
                        .sbc_store_cert(seq, round, batch_hash, cert.voter_set_hash, &json, now)
                {
                    warn!(seq, error = %e, "SBC: could not persist the commit certificate");
                }
            }
            Err(e) => warn!(seq, error = %e, "SBC: certificate will not serialise"),
        }

        let mut certs = self.certs.lock();
        while certs.len() >= MAX_CERTS {
            let Some(oldest) = certs.keys().next().copied() else {
                break;
            };
            certs.remove(&oldest);
        }
        certs.insert(seq, cert);
    }

    /// Keep a certificate we verified from a peer, so we can prove that commit onward.
    ///
    /// Without this, proof coverage only ever SHRINKS: a certificate exists solely on nodes that
    /// witnessed the commit, and a node that caught up via sync answered later requests with no
    /// proof at all — so a laggard behind a laggard could never adopt. Storing what we verified
    /// makes coverage grow with adoption instead.
    pub fn remember_certificate(
        &self,
        cert: &ghost_consensus::message::CommitCertificate,
        now: i64,
    ) {
        let Ok(json) = serde_json::to_string(cert) else {
            return;
        };
        if let Err(e) = self.db.sbc_store_cert(
            cert.seq,
            cert.round,
            cert.batch_hash,
            cert.voter_set_hash,
            &json,
            now,
        ) {
            warn!(seq = cert.seq, error = %e, "SBC: could not store a verified certificate");
        }
        let mut certs = self.certs.lock();
        // Bounded like the mint path. Without this a node in prolonged catch-up adds one
        // certificate per synced sequence and only sheds them the next time it MINTS one — so a
        // node that never resumes head participation grows monotonically inside the pool process.
        while certs.len() >= MAX_CERTS {
            let Some(oldest) = certs.keys().next().copied() else {
                break;
            };
            certs.remove(&oldest);
        }
        certs.insert(cert.seq, cert.clone());
    }

    /// The certificate proving what we committed at `seq`, if we still hold it.
    pub fn certificate_at(&self, seq: u64) -> Option<ghost_consensus::message::CommitCertificate> {
        if let Some(c) = self.certs.lock().get(&seq).cloned() {
            return Some(c);
        }
        // Fall through to the store. The in-memory map is a cache of what THIS process minted; the
        // table is what survives the restart that used to strand every node behind the fleet.
        self.db
            .sbc_get_cert(seq)
            .ok()
            .flatten()
            .and_then(|j| serde_json::from_str(&j).ok())
    }

    /// The qualified-node ids this chain agrees on.
    ///
    /// Derived entirely from the chain, so every node holding the same head returns the same set.
    pub fn voter_ids(&self) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = self.membership.read().iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        ids
    }

    /// What this node is LOCKED on at `seq`, if anything.
    ///
    /// Exposed so the handler can tell "locked but never managed to precommit" from "not locked",
    /// which is the difference between a sequence that will recover and one silently stuck.
    pub fn lock_at(&self, seq: u64) -> Option<(u32, [u8; 32])> {
        self.consensus.lock().get(&seq).and_then(|c| c.lock())
    }

    /// What this node believes was COMMITTED at `seq`, if it holds an opinion.
    ///
    /// `None` means no opinion — either we never had state for that sequence or it was pruned.
    /// That is the honest answer for a node catching up on history, and the caller must treat it
    /// as "unknown", never as "nothing was committed".
    pub fn committed_at(&self, seq: u64) -> Option<[u8; 32]> {
        self.consensus.lock().get(&seq).and_then(|c| c.committed())
    }

    /// Forget consensus and proposal state below a finalised sequence.
    ///
    /// The bound sits BELOW what is final: dropping state for a sequence still in flight would let
    /// this node vote twice in one round, which is the one thing the per-round tally prevents.
    pub fn prune_below(&self, seq: u64) {
        // Certificates go too. `sbc_prune_certs_below` had ZERO callers, so the table grew one row
        // per committed sequence forever — roughly a gigabyte a year per node, on a fleet where
        // one box already sits at 90% disk — while the migration comment claimed it was "bounded
        // by the same retention as the batch window". Now it is.
        //
        // Bounded well BELOW the head so a certificate outlives the sequence it proves: a peer
        // catching up needs the proof for a sequence we closed some time ago.
        // One deeper than the batch window, not one shallower. `prune_below` is called with
        // `batch.seq + 1`, so subtracting the retention from `seq` left the floor at `head-4095`
        // while batches are retained to `head-4096` — the oldest retained batch was always served
        // with no certificate, and a requester with no local opinion refuses that outright. The
        // extra step means a proof always outlives the batch it proves.
        let cert_floor = seq.saturating_sub(CERT_RETENTION + 1);
        if let Err(e) = self.db.sbc_prune_certs_below(cert_floor) {
            warn!(error = %e, "SBC: could not prune old certificates");
        }
        self.consensus.lock().retain(|k, _| *k >= seq);
        // Signatures go with the consensus state; the CERTIFICATE minted at commit is what
        // survives, in `certs`.
        self.precommit_sigs.lock().retain(|(s, _, _), _| *s >= seq);
        self.proposals.lock().retain(|(s, _), _| *s >= seq);
        let mut mine = self.my_proposal.lock();
        if mine.as_ref().is_some_and(|((s, _), _)| *s < seq) {
            *mine = None;
        }
    }

    /// Adopt a batch a COMMIT CERTIFICATE has already proved was committed.
    ///
    /// The proposer rota is not consulted — a quorum of signed precommits settles whose turn it
    /// was far more strongly than re-deriving the rota from a clock. That matters because
    /// `authorise` measures escalation from `(now - parent.close_ts)`, so for history `now` is
    /// arbitrary and the original proposer falls inside the +/-1 window only about a quarter of the
    /// time: cert-verified batches were being bounced with `ProposerNotDue` on most attempts, and
    /// the failure path does not re-request.
    ///
    /// Everything else is still checked — linkage, membership, share validity, canonical order,
    /// and the state root reproducing locally.
    pub fn adopt_committed_batch<C: ghost_common::batch_consensus::BatchChecks>(
        &self,
        batch: &ShareBatch,
        checks: &C,
        now: i64,
    ) -> GhostResult<Option<Finalised>> {
        use ghost_common::batch_consensus::{verify_committed_batch, BatchVerdict};

        // Same consistent snapshot as the judging path, and released before `finalise` — which
        // takes the exclusive side, so a read guard held across it would deadlock.
        let (parent, balances, watermarks) = {
            let _snapshot = self.adoption.read();
            let parent = match self.parent_for(batch.seq) {
                Ok(p) => p,
                Err(reason) => {
                    debug!(
                        seq = batch.seq,
                        ?reason,
                        "SBC: cannot place a committed batch yet"
                    );
                    return Ok(None);
                }
            };
            (parent, self.balances(), self.watermarks())
        };
        match verify_committed_batch(batch, &parent, &balances, &watermarks, checks) {
            BatchVerdict::Valid { .. } => self.finalise(batch, now).map(Some),
            other => {
                warn!(
                    seq = batch.seq,
                    ?other,
                    "SBC: a certified batch does not verify locally — refusing to adopt"
                );
                Ok(None)
            }
        }
    }

    /// Record a peer's PREVOTE. A quorum of them is a polka.
    pub fn on_batch_prevote(
        &self,
        voter: [u8; 32],
        round: u32,
        batch_hash: [u8; 32],
        seq: u64,
        schedule: &ProposerSchedule,
        now: i64,
    ) -> PrevoteAction {
        // A signed vote naming a far-future sequence must not create state a head-relative
        // prune can never reach.
        if !self.seq_in_window(seq) || schedule.quorum() < Self::MIN_QUORUM {
            return PrevoteAction::Ignored;
        }
        // Same lock order as `on_proposal_phase`: quarantine, then consensus.
        let mut quarantine = self.quarantine.lock();
        let mut consensus = self.consensus.lock();
        let entry = consensus
            .entry(seq)
            .or_insert_with(|| SeqConsensus::new(seq, schedule.quorum()));
        on_prevote(
            voter,
            round,
            batch_hash,
            entry,
            &mut quarantine,
            schedule,
            now,
        )
    }

    /// Record a peer's PRECOMMIT. A quorum of them commits the sequence.
    #[allow(clippy::too_many_arguments)]
    pub fn on_batch_precommit(
        &self,
        voter: [u8; 32],
        round: u32,
        batch_hash: [u8; 32],
        seq: u64,
        signature: [u8; 64],
        schedule: &ProposerSchedule,
        now: i64,
    ) -> PrecommitAction {
        // Same lock order as `on_proposal_phase`: quarantine, then consensus.
        // A signed vote naming a far-future sequence must not create state a head-relative
        // prune can never reach.
        if !self.seq_in_window(seq) || schedule.quorum() < Self::MIN_QUORUM {
            return PrecommitAction::Ignored;
        }
        let mut quarantine = self.quarantine.lock();
        let mut consensus = self.consensus.lock();
        let entry = consensus
            .entry(seq)
            .or_insert_with(|| SeqConsensus::new(seq, schedule.quorum()));
        let action = on_precommit(
            voter,
            round,
            batch_hash,
            entry,
            &mut quarantine,
            schedule,
            now,
        );
        drop(consensus);
        drop(quarantine);

        // Retain it. The caller has already verified this signature against the precommit domain,
        // so what is stored is exactly what a certificate needs and nothing has to be re-derived.
        {
            let mut sigs = self.precommit_sigs.lock();
            sigs.entry((seq, round, batch_hash))
                .or_default()
                .insert(voter, signature);
        }

        // On commit, freeze the proof while we still hold the parts. `prune_below` drops the
        // signature map with the rest of the sequence's state moments later, and that is exactly
        // when other nodes start needing it.
        if let PrecommitAction::Commit { .. } = action {
            self.mint_certificate(seq, round, batch_hash, schedule, now);
        }
        action
    }

    /// Record a vote and report whether it carried the sequence.
    pub fn on_batch_vote(
        &self,
        voter: [u8; 32],
        batch_hash: [u8; 32],
        seq: u64,
        schedule: &ProposerSchedule,
        now: i64,
    ) -> VoteAction {
        let mut tallies = self.tallies.lock();
        let tally = tallies
            .entry(seq)
            .or_insert_with(|| SeqTally::new(seq, schedule.quorum()));
        let mut quarantine = self.quarantine.lock();
        on_vote(voter, batch_hash, tally, &mut quarantine, schedule, now)
    }

    /// The adopted batch at `seq`, verbatim, for answering a sync request.
    pub fn batch_at(&self, seq: u64) -> GhostResult<Option<String>> {
        self.db.sbc_get_batch(seq)
    }

    /// Note that a sequence has opened, so escalation is measured from the right moment.
    ///
    /// Without this the stall clock would run from the parent's `close_ts`, which is when the
    /// PREVIOUS batch closed — a sequence that opened late would look stalled the instant it began
    /// and escalate past a proposer who never had a chance.
    pub fn note_seq_opened(&self, _now: i64) {
        // Deliberately a no-op. The rota clock is the head's `close_ts`, derived on read — see
        // `seq_opened`. This used to stamp a local wall-clock here, which is exactly how the fleet
        // came to disagree on whose turn it was.
    }

    /// Adopt a finalised batch: fold it, persist it, and advance the head.
    ///
    /// Persisted in an order chosen so a crash cannot leave the node claiming a head it has not
    /// folded: balances first, then the batch. Replaying a batch already folded is harmless —
    /// `sbc_store_batch` is idempotent on the same batch — whereas a head ahead of its balances
    /// would compute every later state root from the wrong state, silently and forever.
    pub fn finalise(&self, batch: &ShareBatch, now: i64) -> GhostResult<Finalised> {
        let mut balances = self.balances();
        let outcome = fold_shares(&mut balances, &batch.shares);
        let recomputed = compute_state_root(&balances, batch.seq, batch.close_ts);

        // The batch states its own root; recomputing must agree. A mismatch here means this node
        // folded different inputs from the proposer, and adopting it anyway would put a wrong
        // balance behind a root the fleet believes in.
        if recomputed != batch.state_root {
            warn!(
                seq = batch.seq,
                stated = %hex::encode(&batch.state_root[..8]),
                recomputed = %hex::encode(&recomputed[..8]),
                "SBC shadow: refusing to adopt — recomputed state root disagrees"
            );
            return Err(ghost_common::error::GhostError::Internal(format!(
                "state root mismatch at seq {}: stated {} recomputed {}",
                batch.seq,
                hex::encode(&batch.state_root[..8]),
                hex::encode(&recomputed[..8])
            )));
        }

        let batch_hash = batch.batch_hash();
        let batch_json = serde_json::to_string(batch).map_err(|e| {
            ghost_common::error::GhostError::Serialization(format!("batch {}: {e}", batch.seq))
        })?;

        // Advance the proposer's replay watermark past this batch. Adopted state exactly like the
        // balances, persisted in the same transaction — torn apart, a watermark ahead faults
        // honest proposers and one behind re-credits adopted shares.
        let mut watermarks = self.watermarks();
        advance_watermarks(&mut watermarks, batch);

        self.db
            .sbc_save_balances(&balances, &watermarks, batch.seq)?;
        self.db.sbc_store_batch(
            batch.seq,
            batch_hash,
            batch.prev_batch_hash,
            batch.proposer,
            batch.close_ts,
            batch.state_root,
            batch.shares.len() as u32,
            &batch_json,
            now,
        )?;

        // EXCLUSIVE for the span that makes head and balances disagree. A judge holding the
        // shared side cannot observe the half-updated state that produced spurious
        // `StateRootMismatch` faults — and therefore spurious, persistent quarantines.
        {
            let _adopting = self.adoption.write();
            *self.balances.write() = balances;
            *self.watermarks.write() = watermarks;
            *self.head.write() = Some(ChainHead {
                seq: batch.seq,
                batch_hash,
                state_root: batch.state_root,
                close_ts: batch.close_ts,
                finalised_at: now,
            });
            *self.membership.write() = batch.node_shares.clone();
        }

        // Everything at or below the adopted sequence is decided, so its consensus and proposal
        // state is dead weight. Pruning here rather than on a timer means the bound is always
        // relative to what is final — the one place it is safe to cut.
        self.prune_below(batch.seq + 1);

        // Drain exactly what was adopted. Anything not in this batch stays pending and lands in a
        // later one — which is why a share that misses its batch is deferred, never lost.
        {
            let mut pending = self.pending.lock();
            for s in &batch.shares {
                pending.remove(&s.share_hash);
            }
        }

        info!(
            seq = batch.seq,
            state_root = %hex::encode(&batch.state_root[..8]),
            credited = outcome.credited,
            unattributed = outcome.unattributed,
            pending = self.pending_count(),
            "SBC shadow: finalised"
        );

        Ok(Finalised {
            seq: batch.seq,
            state_root: batch.state_root,
            batch_hash,
            credited: outcome.credited,
            unattributed: outcome.unattributed,
        })
    }

    /// Bootstrap `seq 0` from a ratified payout checkpoint, if the chain has not started.
    ///
    /// Every node performs this conversion INDEPENDENTLY and must arrive at the same bytes. That is
    /// only true because the checkpoint is adopted verbatim by the fleet rather than recomputed —
    /// the raw share ledgers differ, the adopted `canonical_payout` does not. Recomputing genesis
    /// from local shares would reintroduce exactly the divergence the checkpoint exists to have
    /// settled.
    ///
    /// ## The proposer is ZERO, and that is load-bearing
    ///
    /// `batch_hash` commits to `proposer` (`share_batch.rs`). If each node used its own node id,
    /// all eight would derive an identical `state_root` and EIGHT DIFFERENT `batch_hash`es — and
    /// since `seq 1` names its parent by hash, the chain would fork at its very first link while
    /// every node believed it was correct. A zero proposer is also honest: genesis was converted,
    /// not proposed by anyone.
    ///
    /// `prev_batch_hash` is the checkpoint's `ledger_root`, so the first link points at the object
    /// that authorises it. A zero parent would be a chain anyone could start.
    ///
    /// Returns `Ok(None)` if the chain has already started (idempotent — a restart must not
    /// re-run genesis) or if no ratified checkpoint exists at or below `anchor_height`.
    pub fn bootstrap_genesis(&self, anchor_height: u64, now: i64) -> GhostResult<Option<u64>> {
        if self.head().is_some() {
            return Ok(None);
        }

        let Some(cp) = self
            .db
            .get_payout_ledger_checkpoint_at_or_before(anchor_height)?
        else {
            // DEBUG, not WARN. Genesis now retries every propose tick, so a node waiting for its
            // anchor checkpoint emitted ~120 of these an hour — in a module that has already had
            // one log-volume incident. The condition is reported once by the caller instead.
            debug!(
                anchor_height,
                "SBC genesis: no ratified checkpoint at or below the anchor yet"
            );
            return Ok(None);
        };

        if cp.miner_payouts.is_empty() {
            // A pre-option-(c) row carries no canonical payout. Starting from it would open every
            // balance at zero and silently write off every miner's accrued work.
            warn!(
                height = cp.height,
                "SBC genesis: checkpoint carries no canonical payout — refusing to open empty"
            );
            return Ok(None);
        }

        let (batch, balances, rounding) = ghost_accounting::batch_genesis::genesis_batch(
            cp.ledger_root,
            cp.cutoff_ts,
            [0u8; 32],
            &cp.miner_payouts,
            cp.node_shares.clone(),
        );

        info!(
            height = cp.height,
            cutoff_ts = cp.cutoff_ts,
            payees = balances.len(),
            state_root = %hex::encode(&batch.state_root[..8]),
            ledger_root = %hex::encode(&cp.ledger_root[..8]),
            addresses_rounded = rounding.addresses_rounded,
            addresses_dropped = rounding.addresses_dropped,
            units_discarded = rounding.units_discarded,
            "SBC genesis: converting a ratified checkpoint"
        );

        // Reported, never swallowed: a conversion that quietly loses balance is how an unexplained
        // drift begins, and at genesis there is nothing to reconcile against afterwards.
        if rounding.addresses_dropped > 0 {
            warn!(
                dropped = rounding.addresses_dropped,
                "SBC genesis: addresses rounded out of existence — their work is below one \
                 micro-work and cannot be represented"
            );
        }

        self.install_genesis(&batch, balances, now)?;
        Ok(Some(cp.height))
    }

    /// Install the genesis batch and its opening balances.
    ///
    /// Separate from [`ShadowChain::finalise`] because genesis is adopted by conversion of a
    /// finalised checkpoint rather than by vote, and it carries no shares — the work is already in
    /// the balances.
    pub fn install_genesis(
        &self,
        batch: &ShareBatch,
        balances: BTreeMap<String, i64>,
        now: i64,
    ) -> GhostResult<()> {
        let batch_hash = batch.batch_hash();
        let batch_json = serde_json::to_string(batch)
            .map_err(|e| ghost_common::error::GhostError::Serialization(format!("genesis: {e}")))?;

        // Genesis carries no shares, so it sets no watermark — the guard starts empty and grows
        // with the first real batch from each proposer.
        self.db
            .sbc_save_balances(&balances, &ProposerWatermarks::new(), batch.seq)?;
        self.db.sbc_store_batch(
            batch.seq,
            batch_hash,
            batch.prev_batch_hash,
            batch.proposer,
            batch.close_ts,
            batch.state_root,
            0,
            &batch_json,
            now,
        )?;

        // Seed membership from the ratified checkpoint this genesis batch was built from. That
        // set is the one thing the fleet provably agreed on, which is why it is the right root of
        // trust for everything the chain later counts.
        *self.membership.write() = batch.node_shares.clone();

        *self.balances.write() = balances;
        // Mirror what was just persisted: genesis opens with no watermarks, and the in-memory map
        // must agree with the table or the first judgement after a re-genesis uses ghosts.
        *self.watermarks.write() = ProposerWatermarks::new();
        *self.head.write() = Some(ChainHead {
            seq: batch.seq,
            batch_hash,
            state_root: batch.state_root,
            close_ts: batch.close_ts,
            finalised_at: now,
        });

        info!(
            seq = batch.seq,
            state_root = %hex::encode(&batch.state_root[..8]),
            addresses = self.balances.read().len(),
            "SBC shadow: genesis installed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::share_batch::micro_work;

    fn chain(identity: &Arc<NodeIdentity>) -> ShadowChain {
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        ShadowChain::load(Arc::clone(identity), db).expect("load")
    }

    fn share(identity: &NodeIdentity, addr: &str, work: f64, salt: u8) -> ShareProof {
        // Below every close_ts these tests use (genesis closes at 500, batches at ~600), and
        // comfortably inside the D10 age bound.
        share_at(identity, addr, work, salt, 100 + salt as u64)
    }

    /// Like [`share`], with an explicit timestamp — for tests whose chain runs at a real epoch.
    ///
    /// `difficulty == work`, as the production ingest path stamps them, because the fold credits
    /// the PoW-verified difficulty; a fixture claiming a different difficulty than it "works"
    /// would test a share production cannot produce.
    fn share_at(identity: &NodeIdentity, addr: &str, work: f64, salt: u8, ts: u64) -> ShareProof {
        let mut header = vec![0u8; 80];
        header[0] = salt;
        let real_hash = {
            use bitcoin::hashes::{sha256d, Hash};
            sha256d::Hash::hash(&header).to_byte_array()
        };
        let mut s = ShareProof {
            round_id: 1,
            miner_id: [2u8; 32],
            difficulty: work,
            work,
            share_hash: real_hash,
            timestamp: ts,
            received_by: identity.node_id(),
            template_id: Some([3u8; 32]),
            payout_address: Some(addr.to_string()),
            header: Some(header),
            tier_log2: None,
            signature: None,
        };
        s.sign(identity);
        s
    }

    fn genesis(chain: &ShadowChain, balances: BTreeMap<String, i64>) {
        let state_root = compute_state_root(&balances, 0, 500);
        let batch = ShareBatch {
            seq: 0,
            prev_batch_hash: [0xC0; 32],
            close_ts: 500,
            proposer: [0u8; 32],
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            reversed_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root,
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        chain.install_genesis(&batch, balances, 0).expect("genesis");
    }

    /// A node batches only what IT received. Taking a peer's share would credit the same work
    /// twice once both batches were adopted — and both batches would be individually valid, so
    /// nothing downstream would catch it.
    #[test]
    fn only_shares_this_node_received_are_batched() {
        let id = Arc::new(NodeIdentity::generate());
        let other = NodeIdentity::generate();
        let chain = chain(&id);

        assert!(chain.record_received(share(&id, "bc1qa", 1.0, 1)));
        assert!(
            !chain.record_received(share(&other, "bc1qa", 1.0, 2)),
            "a share received by a peer belongs in the peer's batch"
        );
        assert_eq!(chain.pending_count(), 1);
    }

    /// The state root must be a function of the balances after folding, and adopting must advance
    /// the head and persist both.
    #[test]
    fn finalising_folds_persists_and_advances_the_head() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        chain.record_received(share(&id, "bc1qa", 2.0, 1));
        chain.record_received(share(&id, "bc1qb", 3.0, 2));
        let batch = chain.build_batch(600, 1_000_000).expect("batch");

        let out = chain.finalise(&batch, 0).expect("finalise");
        assert_eq!(out.seq, 1);
        assert_eq!(out.credited, 2);

        let balances = chain.balances();
        assert_eq!(balances.get("bc1qa"), Some(&micro_work(2.0)));
        assert_eq!(balances.get("bc1qb"), Some(&micro_work(3.0)));

        let head = chain.head().expect("head");
        assert_eq!(head.seq, 1);
        assert_eq!(head.state_root, batch.state_root);
    }

    /// Persisted state must survive a restart, or the trust gate's sustained window resets on
    /// every deploy and can never be met.
    #[test]
    fn a_restart_resumes_the_chain_rather_than_restarting_it() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        let (seq, root) = {
            let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
            genesis(&chain, BTreeMap::new());
            chain.record_received(share(&id, "bc1qa", 7.0, 1));
            let batch = chain.build_batch(600, 1_000_000).expect("batch");
            let out = chain.finalise(&batch, 0).expect("finalise");
            (out.seq, out.state_root)
        };

        // A fresh instance over the same database — as a restart would be.
        let resumed = ShadowChain::load(id, db).expect("reload");
        let head = resumed.head().expect("head survives");
        assert_eq!(head.seq, seq);
        assert_eq!(head.state_root, root, "the resumed root must be identical");
        assert_eq!(resumed.balances().get("bc1qa"), Some(&micro_work(7.0)));
    }

    /// A batch whose stated root does not match a local recompute must be refused. Adopting it
    /// would place a wrong balance behind a root the fleet believes in — undetectable afterwards,
    /// because the node would then be internally consistent.
    #[test]
    fn a_batch_whose_stated_root_is_wrong_is_refused() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        let mut batch = chain.build_batch(600, 1_000_000).expect("batch");
        batch.state_root = [0xEE; 32];

        let err = chain.finalise(&batch, 0).expect_err("must refuse");
        assert!(format!("{err}").contains("state root mismatch"), "{err}");

        assert_eq!(
            chain.head().expect("head").seq,
            0,
            "the head must not advance"
        );
        assert!(chain.balances().is_empty(), "balances must be untouched");
    }

    /// Shares are drained only when adopted. A share left out of a batch stays pending and lands
    /// in a later one — deferred, never lost.
    #[test]
    fn unadopted_shares_stay_pending() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        for salt in 1..=3 {
            chain.record_received(share(&id, "bc1qa", 1.0, salt));
        }
        let batch = chain.build_batch(600, 1_000_000).expect("batch");
        let adopted = batch.shares.len();
        assert_eq!(adopted, 3);

        // Build does not drain — a batch that never reaches quorum must not cost the shares.
        assert_eq!(chain.pending_count(), 3, "building must not drain the pool");

        chain.finalise(&batch, 0).expect("finalise");
        assert_eq!(
            chain.pending_count(),
            0,
            "adoption drains exactly what was adopted"
        );
    }

    /// Before genesis there is nothing to build on, and a chain started from nothing is one
    /// anybody could start.
    #[test]
    fn no_batch_is_built_before_genesis() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        assert!(chain.build_batch(600, 1_000_000).is_none());
    }

    /// Genesis opens with converted balances and no shares — the work is already in the balances,
    /// and re-listing shares would invite a validator to re-derive numbers agreed by vote.
    #[test]
    fn genesis_opens_with_balances_and_no_shares() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        let opening: BTreeMap<String, i64> = [
            ("bc1qa".to_string(), 1_000i64),
            ("bc1qb".to_string(), 2_000i64),
        ]
        .into_iter()
        .collect();
        genesis(&chain, opening.clone());

        assert_eq!(chain.head().expect("head").seq, 0);
        assert_eq!(chain.balances(), opening);
    }

    /// Exactly one node proposes per sequence. Being generous here would put two nodes on one
    /// sequence and split the vote — acceptance is the thing that tolerates skew, not proposing.
    #[test]
    fn only_the_node_whose_turn_it_is_proposes() {
        let id = Arc::new(NodeIdentity::generate());
        let other = NodeIdentity::generate();
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());
        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        chain.note_seq_opened(500);

        // A schedule where the turn for seq 1 belongs to whoever sorts into that slot.
        let schedule = ProposerSchedule::new([id.node_id(), other.node_id()]);
        let mine = schedule.is_my_turn(1, &id.node_id(), 500, 500);

        let proposed = chain.try_propose(&schedule, 500, 1_000_000);
        assert_eq!(
            proposed.is_some(),
            mine,
            "a node must propose exactly when the rota says it is its turn"
        );
    }

    /// A stalled sequence must pass to the next node, or a hash chain that cannot skip a sequence
    /// deadlocks forever on an absent proposer.
    #[test]
    fn a_stalled_sequence_escalates_to_another_node() {
        let id = Arc::new(NodeIdentity::generate());
        let other = NodeIdentity::generate();
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());
        chain.record_received(share(&id, "bc1qa", 1.0, 1));
        chain.note_seq_opened(500);

        let schedule = ProposerSchedule::new([id.node_id(), other.node_id()]);
        let at_open = schedule.is_my_turn(1, &id.node_id(), 500, 500);
        // Two escalation steps later the turn must have moved.
        let later = 500 + 2 * ghost_common::batch_consensus::STALL_ESCALATION_SECS;
        let after = schedule.is_my_turn(1, &id.node_id(), 500, later);
        assert_eq!(
            at_open, after,
            "with two voters, two steps returns the turn to its starting node"
        );

        let one_step = 500 + ghost_common::batch_consensus::STALL_ESCALATION_SECS;
        assert_ne!(
            at_open,
            schedule.is_my_turn(1, &id.node_id(), 500, one_step),
            "one step must hand the turn to the other node"
        );
    }

    /// A peer quarantined in an earlier process stays quarantined. Release is operator-only, and a
    /// restart is not an operator.
    #[test]
    fn quarantine_survives_a_restart() {
        let id = Arc::new(NodeIdentity::generate());
        let bad = NodeIdentity::generate();
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        db.sbc_quarantine(bad.node_id(), "wrong state root", Some(3), 0)
            .expect("quarantine");

        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        genesis(&chain, BTreeMap::new());

        let batch = ShareBatch {
            seq: 1,
            prev_batch_hash: [0u8; 32],
            close_ts: 600,
            proposer: bad.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            reversed_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id(), bad.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);

        assert_eq!(
            chain.on_proposal(&batch, &schedule, &checks, 600),
            Action::ProposerQuarantined,
            "a peer excluded before the restart must not be judged again"
        );
    }

    /// **Audit finding 4.** Re-proposing in one round must re-send IDENTICAL bytes.
    ///
    /// The propose loop ticks every 30 s while a round lasts 90 s, and `build_batch` stamps
    /// `close_ts = now` — so rebuilding produced a different `batch_hash` in the SAME round. Peers
    /// saw one node prevote two batches at one round, branded it an equivocator and quarantined
    /// it; it also caught its own on the self-count and quarantined itself. Any 30 s window
    /// without a polka would have excluded honest nodes fleet-wide.
    #[test]
    fn re_proposing_within_one_round_returns_the_identical_batch() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        // A single-node schedule makes every turn ours.
        // `build_batch` refuses an empty pool, so give it something to pack — timestamped near
        // the checkpoint cutoff this chain's clock runs at, inside the D10 window.
        for salt in 0..3u8 {
            chain.record_received(share_at(
                &id,
                "bc1qalice",
                1.0,
                salt,
                1_786_228_000 + salt as u64,
            ));
        }

        let schedule = ProposerSchedule::new([id.node_id()]);
        let head = chain.head().expect("head");
        let now = head.close_ts + 5;

        let first = chain.try_propose(&schedule, now, 64_000).expect("first");
        // 30 s later — same round (90 s steps), so the same batch must come back.
        let second = chain
            .try_propose(&schedule, now + 30, 64_000)
            .expect("second");

        assert_eq!(
            first.batch_hash(),
            second.batch_hash(),
            "a re-propose inside one round must not mint a new hash — that is self-equivocation"
        );
        assert_eq!(first.close_ts, second.close_ts, "including its close_ts");
    }

    /// **Audit finding 1.** A verified batch is retained so a commit has something to adopt.
    ///
    /// Adoption used to read the ADOPTED-batch store, which by definition never contains the batch
    /// about to be adopted. Every node looked, found nothing, and the chain stopped at its first
    /// commit — the same wedge two-phase was built to remove, one layer later.
    #[test]
    fn our_own_proposal_is_retained_for_adoption() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        for salt in 0..3u8 {
            chain.record_received(share_at(
                &id,
                "bc1qalice",
                1.0,
                salt,
                1_786_228_000 + salt as u64,
            ));
        }

        let schedule = ProposerSchedule::new([id.node_id()]);
        let head = chain.head().expect("head");
        let batch = chain
            .try_propose(&schedule, head.close_ts + 5, 64_000)
            .expect("proposed");

        // `broadcast` filters self, so without this the PROPOSER is the one node that cannot adopt
        // the batch it proposed.
        assert_eq!(
            chain
                .remembered_proposal(batch.seq, batch.batch_hash())
                .map(|b| b.batch_hash()),
            Some(batch.batch_hash()),
            "the proposer must hold its own batch"
        );
    }

    /// **Audit 11, finding 1.** A node with balances folded past its head proposes and judges
    /// NOTHING.
    ///
    /// Detecting that and carrying on is the "check that cannot fail" pattern. While the affected
    /// sequence is open, such a node builds batches whose `state_root` came from over-folded
    /// balances — which every peer still on the old head FAULTS, quarantining the crashed node
    /// fleet-wide — and judges peers' proposals against the same poisoned state, quarantining
    /// honest proposers. Both are persistent and operator-release-only.
    #[test]
    fn a_node_whose_balances_outran_its_head_refuses_to_propose_or_judge() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);

        // Genesis, then fold the balances forward WITHOUT storing a batch — exactly the state a
        // crash between `finalise`'s two writes leaves behind.
        {
            let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
            chain
                .bootstrap_genesis(961_642, 1_786_228_093)
                .expect("bootstrap")
                .expect("converted");
            let head = chain.head().expect("head");
            db.sbc_save_balances(&chain.balances(), &ProposerWatermarks::new(), head.seq + 1)
                .expect("save ahead");
        }

        // A fresh load must notice and latch.
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        assert!(
            chain.is_poisoned(),
            "balances ahead of the head must be detected at load"
        );

        for salt in 0..3u8 {
            chain.record_received(share_at(
                &id,
                "bc1qalice",
                1.0,
                salt,
                1_786_228_000 + salt as u64,
            ));
        }
        let schedule = ProposerSchedule::new(chain.voter_ids());
        let head = chain.head().expect("head");

        assert!(
            chain
                .try_propose(&schedule, head.close_ts + 5, 64_000)
                .is_none(),
            "a poisoned node must not propose — peers would fault the batch and quarantine it"
        );

        let batch = ShareBatch {
            seq: head.seq + 1,
            prev_batch_hash: head.batch_hash,
            close_ts: head.close_ts + 30,
            proposer: id.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            reversed_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);
        assert!(
            matches!(
                chain.on_proposal_phase(&batch, &schedule, &checks, head.close_ts + 30),
                PhaseAction::Hold { .. }
            ),
            "a poisoned node must HOLD, never fault — the inconsistency is ours, not the peer's"
        );
    }

    /// **Audit 10, finding 1.** Every path that snapshots the chain takes the adoption guard.
    ///
    /// This is a source-level assertion on purpose. The guard was written, documented, and claimed
    /// in a commit message — and applied to only ONE of the three paths, because a multi-edit
    /// script asserted on two patterns, the second failed, and nothing was written at all. The
    /// behaviour it prevents (a torn head/balances read producing a spurious `StateRootMismatch`,
    /// which is a FAULT and therefore a persistent quarantine of an honest peer) is a race, so no
    /// ordinary test reliably catches its absence. Checking the source does.
    #[test]
    fn every_snapshot_path_takes_the_adoption_guard() {
        let src = include_str!("sbc_shadow.rs");

        // Each of these reads the head and the balances and must see one consistent pair.
        for f in [
            "pub fn on_proposal_phase",
            "pub fn adopt_committed_batch",
            "fn build_batch",
        ] {
            let start = src.find(f).unwrap_or_else(|| panic!("{f} not found"));
            // Look only at the function's opening span, where the snapshot is taken.
            let window = &src[start..(start + 2_000).min(src.len())];
            assert!(
                window.contains("self.adoption.read()"),
                "{f} snapshots head+balances and MUST take the adoption guard — without it a \
                 concurrent finalise makes it fault an honest peer"
            );
        }

        // And the mutation side must take it exclusively.
        let fin = src.find("pub fn finalise").expect("finalise");
        let window = &src[fin..(fin + 3_000).min(src.len())];
        assert!(
            window.contains("self.adoption.write()"),
            "finalise must hold the guard exclusively while head and balances disagree"
        );
    }

    /// **Audit 8, finding A5.** The pending pool is bounded, and says so when it bites.
    ///
    /// It was deliberately unbounded on the way in, because dropping a share is work a miner is
    /// never credited for. That holds only while the chain drains: a node that cannot reach quorum
    /// accumulates every share it receives, forever, inside the production ghost-pool process —
    /// and the node receiving the most shares fills fastest.
    #[test]
    fn the_pending_pool_is_bounded_and_drops_the_oldest() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        let chain = ShadowChain::load(Arc::clone(&id), db).expect("load");

        // Fill to the ceiling with ascending timestamps, so "oldest" is unambiguous.
        for n in 0..MAX_PENDING_SHARES {
            let mut sp = share(&id, "bc1qalice", 1.0, 0);
            sp.share_hash = {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&(n as u64).to_le_bytes());
                h
            };
            sp.timestamp = 1_000 + n as u64;
            chain.record_received(sp);
        }
        assert_eq!(chain.pending_count(), MAX_PENDING_SHARES);
        assert_eq!(
            chain.pending_dropped(),
            0,
            "a full pool has dropped nothing yet"
        );

        // One more evicts exactly one, and it is the oldest.
        let mut newest = share(&id, "bc1qalice", 1.0, 0);
        newest.share_hash = [0xFF; 32];
        newest.timestamp = 9_999_999;
        chain.record_received(newest);

        assert_eq!(
            chain.pending_count(),
            MAX_PENDING_SHARES,
            "the pool must not grow past its ceiling"
        );
        assert_eq!(
            chain.pending_dropped(),
            1,
            "and the loss must be counted, not silent"
        );

        // Re-recording something already held must NOT evict — that would turn an idempotent
        // recorder into a slow leak of other people's shares.
        let before = chain.pending_dropped();
        let mut dup = share(&id, "bc1qalice", 1.0, 0);
        dup.share_hash = [0xFF; 32];
        dup.timestamp = 9_999_999;
        chain.record_received(dup);
        assert_eq!(
            chain.pending_dropped(),
            before,
            "a duplicate is not a new share and must evict nothing"
        );
    }

    /// **Audit 8, finding A1.** A commit certificate must survive a restart.
    ///
    /// Certificates lived only in memory, and catch-up is — correctly — gated on holding a
    /// verifiable one. So a rolling fleet restart, which is the ORDINARY deploy, left no node able
    /// to prove any commit, and any node that happened to be behind at that moment could never
    /// adopt those sequences from anyone again. A lost proof was a lost node.
    #[test]
    fn a_commit_certificate_survives_a_restart() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);

        let seq = 7u64;
        let round = 3u32;
        let batch_hash = [0xAB; 32];
        let cert = ghost_consensus::message::CommitCertificate {
            seq,
            round,
            batch_hash,
            voter_set_hash: [0xCD; 32],
            precommits: vec![("aa".into(), "bb".into())],
        };
        db.sbc_store_cert(
            seq,
            round,
            batch_hash,
            cert.voter_set_hash,
            &serde_json::to_string(&cert).expect("json"),
            0,
        )
        .expect("store");

        // A FRESH ShadowChain — nothing in memory, exactly as after a restart.
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        let found = chain.certificate_at(seq).expect("cert must survive");

        assert_eq!(found.seq, seq);
        assert_eq!(found.round, round);
        assert_eq!(found.batch_hash, batch_hash);
        assert_eq!(
            found.voter_set_hash, cert.voter_set_hash,
            "the membership binding must survive too, or it verifies against nothing"
        );
        assert_eq!(found.precommits, cert.precommits, "signatures verbatim");

        assert!(
            chain.certificate_at(seq + 1).is_none(),
            "and a sequence we never committed has no certificate"
        );
    }

    /// **Audit 7.** Membership comes from the chain, seeded by the ratified checkpoint.
    ///
    /// Not from a live query. That query is a per-node scan of eventually-consistent tables which
    /// are also pruned on each node's own clock, so identical arguments still gave different
    /// answers — and every mechanism for proving a commit foundered on it, because a quorum cannot
    /// be proved over a membership the two parties do not share.
    #[test]
    fn membership_is_seeded_from_the_ratified_checkpoint_and_carried_by_the_chain() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");

        assert!(
            chain.voter_ids().is_empty(),
            "before genesis there is no agreed membership to report"
        );

        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        let from_chain = chain.voter_ids();
        let from_checkpoint: Vec<[u8; 32]> = {
            let cp = db
                .get_payout_ledger_checkpoint_at_or_before(961_642)
                .expect("cp")
                .expect("some");
            let mut v: Vec<[u8; 32]> = cp.node_shares.iter().map(|(n, _)| *n).collect();
            v.sort_unstable();
            v
        };
        assert_eq!(
            from_chain, from_checkpoint,
            "genesis membership must BE the set the fleet ratified"
        );

        // A batch we build carries it forward rather than re-deriving it.
        for salt in 0..3u8 {
            chain.record_received(share_at(
                &id,
                "bc1qalice",
                1.0,
                salt,
                1_786_228_000 + salt as u64,
            ));
        }
        let schedule = ProposerSchedule::new(chain.voter_ids());
        let head = chain.head().expect("head");
        if let Some(batch) = chain.try_propose(&schedule, head.close_ts + 5, 64_000) {
            let mut carried: Vec<[u8; 32]> = batch.node_shares.iter().map(|(n, _)| *n).collect();
            carried.sort_unstable();
            assert_eq!(
                carried, from_chain,
                "a proposal must carry membership forward"
            );
        }
    }

    /// A batch that changes membership is a terminal FAULT, not a defer.
    ///
    /// A proposer able to rewrite the voter set could hand itself a quorum.
    #[test]
    fn changing_membership_is_a_fault() {
        use ghost_common::batch_consensus::{verify_batch, BatchVerdict, FaultReason};

        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        let head = chain.head().expect("head");
        let parent: ShareBatch =
            serde_json::from_str(&chain.batch_at(head.seq).expect("get").expect("some"))
                .expect("parse");

        let mut child = parent.clone();
        child.seq = parent.seq + 1;
        child.prev_batch_hash = parent.batch_hash();
        child.close_ts = parent.close_ts + 30;
        child.shares = Vec::new();
        // The attack: quietly add yourself to the voter set.
        child.node_shares.push(([0xEE; 32], 5));

        // Position is judged BEFORE contents, so the batch must come from the node actually due
        // — otherwise it defers on the rota and never reaches the membership check.
        let schedule = ProposerSchedule::new(chain.voter_ids());
        let escalation = schedule.escalation_at(parent.close_ts, child.close_ts);
        child.proposer = schedule
            .proposer_at(child.seq, escalation)
            .expect("a due proposer");

        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);
        let verdict = verify_batch(
            &child,
            &parent,
            &chain.balances(),
            &chain.watermarks(),
            &schedule,
            child.close_ts,
            &checks,
        );
        assert!(
            matches!(
                verdict,
                BatchVerdict::Fault(FaultReason::MembershipChanged { .. })
            ),
            "rewriting membership must be terminal, got {verdict:?}"
        );
    }

    /// **Audit 6, finding 1.** A degraded voter view must not create consensus state.
    ///
    /// `SeqConsensus::new` captures `quorum` at first touch and never refreshes it. The
    /// qualification query returns EMPTY on a database error — an ordinary failure, not an attack
    /// — and `bft_threshold(0) == 0`, `bft_threshold(1) == 1`. So an entry created during one bad
    /// read keeps that bar forever, and a single later precommit for ANY candidate latches
    /// `committed`. The sync path then treats that latch as binding and refuses the fleet's real
    /// batch permanently. That is a safety defect, not merely liveness.
    #[test]
    fn a_degraded_voter_view_creates_no_consensus_state() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        let head = chain.head().expect("head");
        let seq = head.seq + 1;
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);

        // Every degraded view the query can actually return.
        for n in 0..3usize {
            let voters: Vec<[u8; 32]> = (0..n as u8).map(|i| [i; 32]).collect();
            let degraded = ProposerSchedule::new(voters);
            assert!(
                degraded.quorum() < 3,
                "precondition: a view of {n} yields a sub-floor quorum"
            );

            let batch = ShareBatch {
                seq,
                prev_batch_hash: head.batch_hash,
                close_ts: head.close_ts + 30,
                proposer: id.node_id(),
                shares: Vec::new(),
                settled_blocks: Vec::new(),
                reversed_blocks: Vec::new(),
                node_shares: Vec::new(),
                state_root: [0u8; 32],
                truncated: false,
                pending_count: 0,
                proposer_signature: Vec::new(),
            };
            assert!(
                matches!(
                    chain.on_proposal_phase(&batch, &degraded, &checks, head.close_ts + 30),
                    PhaseAction::Hold { .. }
                ),
                "a view of {n} must hold, not create an entry"
            );
            assert_eq!(
                chain.on_batch_precommit(id.node_id(), 0, [0xAA; 32], seq, [0u8; 64], &degraded, 0),
                PrecommitAction::Ignored,
                "and must not accept a precommit that could latch a commit"
            );
            assert_eq!(
                chain.committed_at(seq),
                None,
                "no commit may be latched from a view of {n}"
            );
        }
    }

    /// **Audit 3, finding 3.** A far-future PROPOSAL creates no consensus state.
    ///
    /// The window guard covered the two vote paths and missed this one. `verify_batch` defers on
    /// POSITION before checking any signature, so an unsigned proposal naming seq 10^18 needs no
    /// credentials — and the entry was created before judging, where `prune_below` (which retains
    /// `k >= bound`) could never reach it.
    #[test]
    fn a_far_future_proposal_creates_no_consensus_state() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        let absurd = u64::MAX / 2;
        let batch = ShareBatch {
            seq: absurd,
            prev_batch_hash: [0u8; 32],
            close_ts: 600,
            proposer: id.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            reversed_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);

        let action = chain.on_proposal_phase(&batch, &schedule, &checks, 600);
        assert!(
            matches!(action, PhaseAction::Hold { .. }),
            "a far-future proposal must hold, not be judged"
        );
        assert_eq!(
            chain.committed_at(absurd),
            None,
            "and must leave no consensus state behind"
        );
        assert_eq!(chain.lock_at(absurd), None);
    }

    /// **Re-audit B5.** Before genesis a node holds no consensus state at all.
    ///
    /// An absent head used to read as seq 0, admitting votes for 0..=8 from any voter. Nothing
    /// resolves those sequences pre-genesis, and `prune_below` only runs on finalise — so the
    /// state was created and then never removed.
    #[test]
    fn a_node_without_genesis_creates_no_consensus_state() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        // Deliberately NO genesis.
        let chain = ShadowChain::load(Arc::clone(&id), db).expect("load");
        assert!(chain.head().is_none(), "precondition: no genesis");

        let schedule = ProposerSchedule::new([id.node_id()]);
        for seq in 0..=8u64 {
            assert_eq!(
                chain.on_batch_prevote(id.node_id(), 0, [0xAA; 32], seq, &schedule, 0),
                PrevoteAction::Ignored,
                "seq {seq} must be refused before genesis"
            );
            assert_eq!(chain.committed_at(seq), None);
            assert_eq!(chain.lock_at(seq), None, "and no lock may be created");
        }
    }

    /// **Re-audit B4.** A full cache evicts its OLDEST entry, not the newest arrival.
    ///
    /// Refusing the newcomer was backwards: each escalation round mints a distinct authorised
    /// candidate, so under a long stall the cache filled with losing candidates and dropped the
    /// one most likely to be committed — sending adoption down the sync path for the batch it was
    /// most certain to need.
    #[test]
    fn a_full_proposal_cache_evicts_the_oldest_not_the_newest() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        let head = chain.head().expect("head");
        let seq = head.seq + 1;

        // Fill well past the cap with distinct candidates at the same sequence.
        let mut hashes = Vec::new();
        for n in 0..80u8 {
            let mut b = ShareBatch {
                seq,
                prev_batch_hash: head.batch_hash,
                close_ts: head.close_ts + 30,
                proposer: [n; 32],
                shares: Vec::new(),
                settled_blocks: Vec::new(),
                reversed_blocks: Vec::new(),
                node_shares: Vec::new(),
                state_root: [0u8; 32],
                truncated: false,
                pending_count: 0,
                proposer_signature: Vec::new(),
            };
            b.close_ts = head.close_ts + 30 + n as i64;
            hashes.push(b.batch_hash());
            chain.remember_proposal_for_test(&b);
        }

        let newest = hashes.last().copied().expect("newest");
        assert!(
            chain.remembered_proposal(seq, newest).is_some(),
            "the most recent candidate must survive — it is the likeliest to be committed"
        );
        let oldest = hashes[0];
        assert!(
            chain.remembered_proposal(seq, oldest).is_none(),
            "the oldest must have been evicted"
        );
    }

    /// **Audit finding 7.** A vote naming a far-future sequence creates no state.
    ///
    /// Otherwise one peer can mint entries at seq 10^18 that no head-relative prune ever reaches.
    #[test]
    fn a_vote_at_an_absurd_sequence_is_ignored() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);
        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        chain
            .bootstrap_genesis(961_642, 1_786_228_093)
            .expect("bootstrap")
            .expect("converted");

        let schedule = ProposerSchedule::new([id.node_id()]);
        let action =
            chain.on_batch_prevote(id.node_id(), 0, [0xAA; 32], u64::MAX / 2, &schedule, 0);

        assert_eq!(action, PrevoteAction::Ignored);
        assert_eq!(
            chain.committed_at(u64::MAX / 2),
            None,
            "no state may be created for an out-of-window sequence"
        );
    }

    /// Both paths resolve the parent identically, because they share one implementation.
    ///
    /// Written after two copies of the local-hashrate query drifted apart on 2026-08-09 — the mesh
    /// and HTTP providers each swallowed the same error, and a node doing 94 TH/s reported a
    /// confident zero. One resolution, exercised from both entry points.
    #[test]
    fn single_phase_and_two_phase_hold_on_the_same_missing_parent() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        // No genesis installed: neither path can judge anything.
        let chain = ShadowChain::load(id.clone(), db).expect("load");

        let batch = ShareBatch {
            seq: 1,
            prev_batch_hash: [0u8; 32],
            close_ts: 600,
            proposer: id.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            reversed_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);

        let single = chain.on_proposal(&batch, &schedule, &checks, 600);
        let two = chain.on_proposal_phase(&batch, &schedule, &checks, 600);

        match (single, two) {
            (Action::Hold { reason: a }, PhaseAction::Hold { reason: b }) => assert_eq!(
                format!("{a:?}"),
                format!("{b:?}"),
                "the two paths must not disagree about why they cannot judge"
            ),
            (a, b) => panic!("both must hold without a parent; got {a:?} and {b:?}"),
        }
    }

    /// An operator release readmits a peer to judgement on the next start.
    ///
    /// This is the other half of `quarantine_survives_a_restart`, and it is the half that had no
    /// caller: `sbc_release` existed but nothing outside its own unit test ever invoked it, so a
    /// quarantined node could never come back. The pair pins both directions — a restart alone
    /// must NOT readmit, a release must.
    #[test]
    fn an_operator_release_readmits_a_peer_on_the_next_start() {
        let id = Arc::new(NodeIdentity::generate());
        let bad = NodeIdentity::generate();
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        db.sbc_quarantine(bad.node_id(), "wrong state root", Some(3), 0)
            .expect("quarantine");

        // The operator releases it, then the node restarts.
        assert!(
            db.sbc_release(bad.node_id()).expect("release"),
            "release must report a change"
        );

        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        genesis(&chain, BTreeMap::new());

        let batch = ShareBatch {
            seq: 1,
            prev_batch_hash: [0u8; 32],
            close_ts: 600,
            proposer: bad.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            reversed_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id(), bad.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);

        assert_ne!(
            chain.on_proposal(&batch, &schedule, &checks, 600),
            Action::ProposerQuarantined,
            "a released peer must be judged on merit again, not rejected on sight"
        );
    }

    /// Judging must never happen against a parent we do not hold — that is a sync condition, not a
    /// disagreement, and faulting it would have honest nodes quarantining each other.
    #[test]
    fn a_batch_is_held_not_faulted_when_we_lack_the_parent() {
        let id = Arc::new(NodeIdentity::generate());
        let peer = NodeIdentity::generate();
        let chain = chain(&id);
        // No genesis: we hold nothing.

        let batch = ShareBatch {
            seq: 9,
            prev_batch_hash: [0xAB; 32],
            close_ts: 600,
            proposer: peer.node_id(),
            shares: Vec::new(),
            settled_blocks: Vec::new(),
            reversed_blocks: Vec::new(),
            node_shares: Vec::new(),
            state_root: [0u8; 32],
            truncated: false,
            pending_count: 0,
            proposer_signature: Vec::new(),
        };
        let schedule = ProposerSchedule::new([id.node_id(), peer.node_id()]);
        let checks = crate::sbc_checks::NodeBatchChecks::new(None, true, false);

        assert!(
            matches!(
                chain.on_proposal(&batch, &schedule, &checks, 600),
                Action::Hold { .. }
            ),
            "no parent means hold and sync, never accuse"
        );
    }

    /// The property the WP-5 trust gate is defined by: separate nodes, separate databases, and a
    /// byte-identical `(seq, state_root)` after adopting the same chain.
    ///
    /// `share_batch.rs` already proves the pure fold agrees across simulated nodes. This proves it
    /// survives the parts that are NOT pure — three independent stores, three encryption keys, and
    /// a round trip through SQLite in between. A divergence introduced by persistence would be
    /// invisible to the fold's own tests and fatal to the gate.
    ///
    /// ⚠ A convergence assertion alone CANNOT catch a uniform arithmetic error: every node runs the
    /// same fold, so a fold that is wrong the same way everywhere still agrees. Verified by
    /// mutation — adding 1 to every credit leaves the roots identical and this test green. So the
    /// expected balances are pinned by value below, and correctness of the quantisation itself is
    /// `share_batch.rs`'s job. Agreement and correctness are different claims and need different
    /// assertions.
    #[test]
    fn separate_nodes_with_separate_stores_converge_on_one_state_root() {
        let ids: Vec<Arc<NodeIdentity>> =
            (0..3).map(|_| Arc::new(NodeIdentity::generate())).collect();

        // Distinct encryption keys per node, as the fleet has: the ciphertext differs everywhere,
        // and only the plaintext balances may agree.
        let chains: Vec<ShadowChain> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let db = Arc::new(Database::in_memory().expect("db"));
                db.set_encryption_key([(0x40 + i) as u8; 32]);
                ShadowChain::load(Arc::clone(id), db).expect("load")
            })
            .collect();

        let opening: BTreeMap<String, i64> =
            [("bc1qopen".to_string(), 5_000i64)].into_iter().collect();
        for c in &chains {
            genesis(c, opening.clone());
        }

        // Node 0 receives work and proposes; the others adopt what it produced.
        chains[0].record_received(share(&ids[0], "bc1qa", 2.0, 1));
        chains[0].record_received(share(&ids[0], "bc1qb", 3.0, 2));
        let batch = chains[0].build_batch(600, 1_000_000).expect("batch");

        for c in &chains {
            c.finalise(&batch, 0)
                .expect("every node must adopt the same batch");
        }

        let heads: Vec<_> = chains.iter().map(|c| c.head().expect("head")).collect();
        for h in &heads[1..] {
            assert_eq!(h.seq, heads[0].seq, "sequences must match");
            assert_eq!(
                h.state_root, heads[0].state_root,
                "state roots must be byte-identical — this is the trust gate's criterion"
            );
        }
        for c in &chains[1..] {
            assert_eq!(
                c.balances(),
                chains[0].balances(),
                "balances must agree despite different encryption keys"
            );
        }

        // Pinned by VALUE, not merely by agreement — see the mutation note above.
        let expected: BTreeMap<String, i64> = [
            ("bc1qopen".to_string(), 5_000i64),
            ("bc1qa".to_string(), micro_work(2.0)),
            ("bc1qb".to_string(), micro_work(3.0)),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            chains[0].balances(),
            expected,
            "opening balance carried forward plus each share credited exactly once"
        );

        // And it must survive the round trip through storage, which is where a divergence the
        // fold's own tests cannot see would appear.
        for (i, c) in chains.iter().enumerate() {
            let reloaded = c.db.sbc_load_balances().expect("reload");
            assert_eq!(
                reloaded,
                chains[0].balances(),
                "node {i} disagrees after a store round trip"
            );
        }
    }

    /// A second batch must chain onto the first on every node, so convergence is a property of the
    /// chain rather than of one lucky adoption.
    #[test]
    fn convergence_holds_across_successive_batches() {
        let ids: Vec<Arc<NodeIdentity>> =
            (0..3).map(|_| Arc::new(NodeIdentity::generate())).collect();
        let chains: Vec<ShadowChain> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let db = Arc::new(Database::in_memory().expect("db"));
                db.set_encryption_key([(0x40 + i) as u8; 32]);
                ShadowChain::load(Arc::clone(id), db).expect("load")
            })
            .collect();
        for c in &chains {
            genesis(c, BTreeMap::new());
        }

        // Each node takes a turn proposing, so the chain is not built by one node alone.
        for (round, proposer) in [0usize, 1, 2].into_iter().enumerate() {
            let salt = (round + 1) as u8;
            chains[proposer].record_received(share(&ids[proposer], "bc1qa", 1.0, salt));
            let batch = chains[proposer]
                .build_batch(600 + round as i64, 1_000_000)
                .expect("batch");
            for c in &chains {
                c.finalise(&batch, 0).expect("adopt");
            }
        }

        let heads: Vec<_> = chains.iter().map(|c| c.head().expect("head")).collect();
        assert_eq!(heads[0].seq, 3, "three batches on top of genesis");
        for h in &heads[1..] {
            assert_eq!(
                h.state_root, heads[0].state_root,
                "roots must still agree at seq 3"
            );
        }
        // Work from three different proposers, all credited once.
        assert_eq!(
            chains[0].balances().get("bc1qa"),
            Some(&(3 * micro_work(1.0))),
            "each proposer's share must be credited exactly once"
        );
    }

    fn seed_checkpoint(db: &Database, height: u64, cutoff_ts: i64) {
        // Built through the real accessor rather than raw SQL: a fixture that writes the row its
        // own way proves the reader agrees with the fixture, not that it agrees with the writer.
        // Uses the actual adopted figures from 961,642 — the chosen genesis anchor.
        let record = ghost_storage::queries::PayoutLedgerCheckpointRecord {
            height,
            cutoff_ts,
            ledger_root: [0xABu8; 32],
            proposer_id: "deadbeef".to_string(),
            active_node_count: 8,
            miner_payouts: vec![
                (
                    "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                    52_157_533_139_126_865_362_944u128,
                ),
                (
                    "bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".to_string(),
                    2_503_874_639_417_892_143_104u128,
                ),
            ],
            node_shares: vec![([1u8; 32], 10), ([2u8; 32], 6)],
        };
        db.upsert_payout_ledger_checkpoint(&record)
            .expect("seed checkpoint");
    }

    /// THE genesis correctness property: every node converts the same checkpoint into the same
    /// bytes, independently.
    ///
    /// `batch_hash` commits to `proposer`. If genesis used each node's own id, all eight would
    /// derive an identical state_root and EIGHT DIFFERENT batch hashes — and since seq 1 names its
    /// parent by hash, the chain would fork at its first link with every node believing it was
    /// correct. This asserts the HASH, not just the root.
    #[test]
    fn genesis_is_byte_identical_across_independently_converting_nodes() {
        let mut hashes = Vec::new();
        let mut roots = Vec::new();

        for i in 0..3u8 {
            let id = Arc::new(NodeIdentity::generate());
            let db = Arc::new(Database::in_memory().expect("db"));
            db.set_encryption_key([0x40 + i; 32]);
            seed_checkpoint(&db, 961_642, 1_786_228_093);

            let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
            let height = chain
                .bootstrap_genesis(961_642, 0)
                .expect("bootstrap")
                .expect("a checkpoint was available");
            assert_eq!(height, 961_642);

            let head = chain.head().expect("head");
            hashes.push(head.batch_hash);
            roots.push(head.state_root);
        }

        for h in &hashes[1..] {
            assert_eq!(
                *h, hashes[0],
                "genesis BATCH HASH must be identical — differing hashes fork the chain at seq 1 \
                 even when every state_root agrees"
            );
        }
        for r in &roots[1..] {
            assert_eq!(*r, roots[0], "genesis state root must be identical");
        }
    }

    /// A restart must not re-run genesis, or the chain restarts from the anchor and every batch
    /// adopted since is silently discarded.
    #[test]
    fn genesis_is_idempotent() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);
        seed_checkpoint(&db, 961_642, 1_786_228_093);

        let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
        assert!(chain
            .bootstrap_genesis(961_642, 0)
            .expect("first")
            .is_some());
        assert!(
            chain
                .bootstrap_genesis(961_642, 0)
                .expect("second")
                .is_none(),
            "a chain that has already started must not be re-genesised"
        );
        assert_eq!(chain.head().expect("head").seq, 0);
    }

    /// Without a ratified checkpoint there is nothing to convert, and opening every balance at zero
    /// would write off every miner's accrued work.
    #[test]
    fn genesis_refuses_when_there_is_nothing_ratified_to_convert() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        let chain = ShadowChain::load(id, db).expect("load");
        assert!(
            chain
                .bootstrap_genesis(961_642, 0)
                .expect("bootstrap")
                .is_none(),
            "no checkpoint means no chain, not an empty one"
        );
        assert!(chain.head().is_none());
    }

    /// Convert the REAL adopted checkpoint at 961,642 — the pinned genesis anchor — through the
    /// real storage accessor and the real bootstrap, and check it lands on the golden vector.
    ///
    /// The other genesis tests use a fixture. This one uses the exact bytes all 8 nodes ratified,
    /// read back the way a node will read them, so it tests the PATH and not just the arithmetic.
    /// If this ever disagrees with `batch_genesis.rs`'s pinned root, either the conversion or the
    /// state-root encoding has moved and the ceremony would open eight different chains.
    #[test]
    fn the_real_961642_checkpoint_converts_to_the_pinned_genesis_root() {
        fn hexid(h: &str) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).expect("hex");
            }
            out
        }

        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        // Exactly what the fleet adopted, read from ghost-vm8 2026-08-09: 5 payees, 8 node
        // entries, cutoff_ts 1786228093.
        let record = ghost_storage::queries::PayoutLedgerCheckpointRecord {
            height: 961_642,
            cutoff_ts: 1_786_228_093,
            ledger_root: hexid("0fe9bac3023f624b99b087a9c7e6c4c8b5cd557225f0ea9ef9828608fec0caa9"),
            proposer_id: "unused-by-genesis".to_string(),
            active_node_count: 8,
            miner_payouts: vec![
                (
                    "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                    52_157_533_139_126_865_362_944u128,
                ),
                (
                    "bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".to_string(),
                    2_503_874_639_417_892_143_104u128,
                ),
                (
                    "bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".to_string(),
                    2_341_458_453_435_845_967_872u128,
                ),
                (
                    "148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN".to_string(),
                    478_353_203_210_592_976_896u128,
                ),
                (
                    "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h".to_string(),
                    9_741_908_758_669_000_704u128,
                ),
            ],
            node_shares: vec![
                (
                    hexid("5867b555602257bdffa5d4c3577c464416087f2aa04ac478f3986a17e51d3393"),
                    6,
                ),
                (
                    hexid("e557c97a32335457ed6eceb6f8a9c7ee13f8731ee99dc9f4b7831dcf606d6927"),
                    10,
                ),
                (
                    hexid("fb71fee87bb0516920fdb673f3068be3c0b9b29fc62e309b99594a0008c25622"),
                    10,
                ),
                (
                    hexid("849bceceb22cc7ebbeec252d824940ebb73ee08c7855c5a90b5661dd21aeb18c"),
                    10,
                ),
                (
                    hexid("9fe860bda96ff81820a2e166f48cb3ae59010fc9e42550a3aeafb5bfef4d1b38"),
                    10,
                ),
                (
                    hexid("46141044f80c99ac01476b3c2d6cd2149f31b5f1b06ffd2dfa3d15d588c7a39b"),
                    6,
                ),
                (
                    hexid("f0215f1ffd9a711ffc8e476f37bf3e19a2afc18803d146ecedb5d53d4fe9bd4f"),
                    6,
                ),
                (
                    hexid("4c8c2272ae67d76c6c4108f0e4e6dfde7ff864689d3e9b99a35ab1bd46051132"),
                    6,
                ),
            ],
        };
        db.upsert_payout_ledger_checkpoint(&record).expect("seed");

        let chain = ShadowChain::load(id, Arc::clone(&db)).expect("load");
        let h = chain
            .bootstrap_genesis(crate::SBC_GENESIS_ANCHOR_HEIGHT, 0)
            .expect("bootstrap")
            .expect("the anchor checkpoint is present");
        assert_eq!(h, 961_642);

        let head = chain.head().expect("head");
        let root: String = head.state_root.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            root, "cb5ac8470686192246bfc1330791e85023f2044b58f0b076b167ff89923ddc7f",
            "the real checkpoint must convert to the golden vector pinned in batch_genesis.rs"
        );

        // The first link must point at the object that authorises it.
        assert!(
            chain.batch_at(0).expect("stored").is_some(),
            "genesis must be retrievable for a peer syncing from seq 0"
        );

        // Five payees survive; the dominant one holds ~90% of the ledger and is where a
        // conversion bug would actually cost someone money.
        let balances = chain.balances();
        assert_eq!(
            balances.len(),
            5,
            "every ratified payee must open with a balance"
        );
        assert_eq!(
            balances.get("bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492"),
            Some(&52_157_533_139_126_865i64)
        );
    }

    /// The escalation clock must read ADOPTION time, not the proposer's close time.
    ///
    /// A genesis head carries the converted checkpoint's `cutoff_ts`. Measured on ghost-vm8:
    /// cutoff 1786228093, adopted 1786260566 — a 32,473 s (9 h) gap, so escalation read 416 steps
    /// where it should have read ~34. The rota sat permanently escalated, rotating the turn every
    /// 90 s rather than giving a proposer a stable one.
    ///
    /// Invisible from outside: the rota still works, nobody diverges, and every node agrees. It is
    /// simply always wrong in the same way, which is why it needs an explicit assertion.
    #[test]
    fn the_escalation_clock_reads_consensus_time_not_local_adoption_time() {
        let close_ts = 1_786_228_093; // in the batch, identical on every node
        let mut opened = Vec::new();

        // Same batch, adopted at two very different local instants.
        for adopted_at in [1_786_470_000_i64, 1_786_470_000 + 11_574] {
            let id = Arc::new(NodeIdentity::generate());
            let db = Arc::new(Database::in_memory().expect("db"));
            db.set_encryption_key([0x42u8; 32]);
            db.sbc_store_batch(
                0, [1u8; 32], [0u8; 32], [0u8; 32], close_ts, [2u8; 32], 0, "{}", adopted_at,
            )
            .expect("adopt");

            let chain = ShadowChain::load(id, db).expect("load");
            opened.push(chain.seq_opened());
        }

        assert_eq!(
            opened[0], opened[1],
            "the rota clock must not vary with when this node adopted the head"
        );
        assert_eq!(opened[0], close_ts, "it must be the batch's close_ts");
    }

    /// Genesis opens the first real sequence NOW, not at the checkpoint's cutoff.
    #[test]
    fn two_nodes_bootstrapping_hours_apart_open_the_sequence_at_the_same_instant() {
        let cutoff = 1_786_228_093;

        // Two nodes convert the SAME checkpoint at wildly different local times — which is what
        // actually happens, because genesis is installed as each node is deployed.
        let mut opened = Vec::new();
        for bootstrap_at in [1_786_470_000_i64, 1_786_470_000 + 11_574] {
            let id = Arc::new(NodeIdentity::generate());
            let db = Arc::new(Database::in_memory().expect("db"));
            db.set_encryption_key([0x42u8; 32]);
            seed_checkpoint(&db, 961_642, cutoff);

            let chain = ShadowChain::load(id, Arc::clone(&db)).expect("load");
            chain
                .bootstrap_genesis(961_642, bootstrap_at)
                .expect("bootstrap")
                .expect("converted");
            opened.push(chain.seq_opened());
        }

        // The exact value matters less than the agreement, but pin both: it must be the
        // checkpoint's cutoff, which is consensus data every node reads identically.
        assert_eq!(
            opened[0], opened[1],
            "nodes that installed genesis 11,574 s apart must still open the sequence together — \
             otherwise they compute different escalation steps and wait on different proposers"
        );
        assert_eq!(
            opened[0], cutoff,
            "the rota clock must come from the batch, not from whenever this node happened to boot"
        );
    }

    /// Recording the same share twice must NOT put it in a batch twice.
    ///
    /// Found on the live four-node run, 2026-08-09. `record_received` pushed onto a Vec with no
    /// dedup, the share recorder fired more than once for a share, and ghost-vm5 proposed a batch
    /// containing a duplicate. `verify_batch` correctly ruled it `DuplicateShare` — a TERMINAL
    /// fault — so vm6, vm7 and vm8 all quarantined vm5, and quarantine is operator-release-only.
    ///
    /// The node receiving the most shares is the most likely to trip this, which is exactly the
    /// node a pool can least afford to exclude from its own consensus. No unit test caught it
    /// because nothing in-process delivered the same share twice.
    #[test]
    fn recording_a_share_twice_does_not_duplicate_it_in_a_batch() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        let a = share(&id, "bc1qa", 2.0, 1);
        let b = share(&id, "bc1qb", 3.0, 2);
        assert_ne!(
            a.share_hash, b.share_hash,
            "fixture must produce distinct shares"
        );

        assert!(chain.record_received(a.clone()));
        assert!(
            chain.record_received(a.clone()),
            "a repeat must be accepted, not rejected"
        );
        assert!(chain.record_received(a), "and again");
        assert!(chain.record_received(b));

        // TWO distinct shares must survive. Asserting only that a repeat collapses would pass even
        // if the pool keyed every share under one constant — verified by mutation.
        assert_eq!(
            chain.pending_count(),
            2,
            "distinct shares must not collapse together"
        );

        let batch = chain.build_batch(600, 1_000_000).expect("batch");
        assert_eq!(
            batch.shares.len(),
            2,
            "a duplicate in a batch is a terminal fault"
        );

        // And the credit must be for one share, not three.
        chain.finalise(&batch, 0).expect("finalise");
        assert_eq!(
            chain.balances().get("bc1qa"),
            Some(&micro_work(2.0)),
            "a share recorded three times must be credited once"
        );
        assert_eq!(
            chain.balances().get("bc1qb"),
            Some(&micro_work(3.0)),
            "the other share must still be credited"
        );
    }

    /// **The cross-batch replay guard, end to end.** In-batch dedup covers one batch; nothing
    /// covered the same share re-recorded AFTER its batch was adopted — the next build would have
    /// re-proposed it, every peer's watermark check would fault it, and this node would be
    /// quarantined fleet-wide for re-offering work it was already credited for.
    #[test]
    fn an_adopted_share_is_never_batched_again_even_across_a_restart() {
        let id = Arc::new(NodeIdentity::generate());
        let db = Arc::new(Database::in_memory().expect("db"));
        db.set_encryption_key([0x42u8; 32]);

        let adopted = {
            let chain = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("load");
            genesis(&chain, BTreeMap::new());
            let s = share(&id, "bc1qa", 2.0, 1);
            chain.record_received(s.clone());
            let batch = chain.build_batch(600, 1_000_000).expect("batch");
            chain.finalise(&batch, 0).expect("finalise");

            // The share recorder can fire again for an already-adopted share.
            chain.record_received(s.clone());
            assert!(
                chain.build_batch(700, 1_000_000).is_none(),
                "an adopted share must not be proposable again — peers would fault it as a replay"
            );
            assert_eq!(
                chain.pending_count(),
                0,
                "and it must be discarded, not retried at the head of every future batch"
            );
            s
        };

        // The watermark is adopted state: it must survive a restart, or every deploy would reopen
        // the replay window.
        let resumed = ShadowChain::load(Arc::clone(&id), Arc::clone(&db)).expect("reload");
        assert_eq!(
            resumed.watermarks().get(&id.node_id()),
            Some(&(adopted.timestamp, adopted.share_hash)),
            "the watermark must resume with the chain"
        );
        resumed.record_received(adopted);
        assert!(
            resumed.build_batch(800, 1_000_000).is_none(),
            "a restart must not forget what was adopted"
        );

        // And the guard must not over-block: a strictly later share from the same node builds.
        let later = share_at(&id, "bc1qa", 1.0, 9, 550);
        resumed.record_received(later);
        let next = resumed
            .build_batch(900, 1_000_000)
            .expect("later work builds");
        assert_eq!(next.shares.len(), 1);
    }

    /// A share no batch could legally carry — uncreditable difficulty here — must be discarded at
    /// build time rather than proposed. Shares pack in canonical order, so a poisoned share at the
    /// pool's head would otherwise front EVERY future batch this node proposes, and each proposal
    /// is a terminal fault at every peer.
    #[test]
    fn an_uncreditable_share_is_discarded_rather_than_proposed() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        let mut poisoned = share(&id, "bc1qa", 1.0, 1);
        poisoned.difficulty = f64::INFINITY;
        chain.record_received(poisoned);
        chain.record_received(share(&id, "bc1qb", 3.0, 2));

        let batch = chain
            .build_batch(600, 1_000_000)
            .expect("the good share builds");
        assert_eq!(
            batch.shares.len(),
            1,
            "the uncreditable share must not be proposed"
        );
        assert_eq!(
            batch.shares[0].payout_address.as_deref(),
            Some("bc1qb"),
            "and the share that remains is the creditable one"
        );
        assert_eq!(
            chain.pending_count(),
            1,
            "the poisoned share is discarded, not retried forever"
        );
    }

    /// A share timestamped after the batch close is HELD for a later batch, not lost: it becomes
    /// eligible as soon as a close covers it. Only permanently illegal shares are discarded.
    #[test]
    fn a_future_share_is_held_for_a_later_close_not_lost() {
        let id = Arc::new(NodeIdentity::generate());
        let chain = chain(&id);
        genesis(&chain, BTreeMap::new());

        chain.record_received(share_at(&id, "bc1qa", 1.0, 1, 5_000));
        assert!(
            chain.build_batch(600, 1_000_000).is_none(),
            "a share after the close cannot be in this batch — peers would fault it under D10"
        );
        assert_eq!(chain.pending_count(), 1, "but it must stay pending");

        let batch = chain
            .build_batch(5_000, 1_000_000)
            .expect("a later close covers it");
        assert_eq!(batch.shares.len(), 1);
    }
}
