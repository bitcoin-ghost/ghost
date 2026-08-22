//! Outbound convergence frame queue (#647).
//!
//! `Mesh::broadcast` is async but both convergence handlers reply from a **sync** callback, so
//! outbound frames go through a bounded `mpsc` channel drained by a spawned task. That queue is
//! what #647 is about: once it filled, `try_send` shed the frame outright — no counter, no retry,
//! nothing but an ERROR line, at up to 3,770 lines/day on ghost-vm4.
//!
//! # What actually binds
//!
//! It is *not* the depth of the queue. Two things set the drain rate, and neither improves by
//! raising the bound:
//!
//! 1. **The drain is serial.** One task, one frame at a time, each awaiting a full
//!    `Mesh::broadcast`. So the queue drains at `1 / (time for one broadcast)`.
//! 2. **Every frame was fanned out to the whole mesh.** A convergence *response* answers exactly
//!    one requester — its hashes are the complement of *that peer's* advertisement — and the
//!    handler nonetheless handed it to `broadcast`, which `join_all`s a Noise send to all seven
//!    peers. Seven sends of work for one peer's benefit, at ≤64 KB of proof payload each
//!    (`MAX_PROOF_BYTES_PER_RESPONSE`).
//!
//! (2) also *manufactures* producers. Six nodes that never asked receive a `LedgerResponse`,
//! apply it, and — when it carries `more_available` — each emit a follow-up request of their own,
//! which is the amplification behind the measured storm when the v56 cutover left the ledger
//! sweep running: inbound `ShareConvergence` went 0/h → 691/h on ghost-vm7 and `/health` to 14 s.
//!
//! So the lever is **work per dequeued frame**, not slots. Addressing a reply to its requester
//! cuts the drain's per-frame cost by the peer count and removes the follow-up amplification
//! entirely. `ConvergenceFrame::to` carries that address; `None` still means fan out, which is
//! correct for a genuine advertisement (the 30 s round request) and is also the fallback when the
//! addressed peer is not in the peer set.
//!
//! # Why the bound stays at 64
//!
//! Raising it is the obvious move and it is the wrong one, for the same reason
//! `LONG_BUCKETS_PER_TICK` had to be walked back from 12 to 4: the binding constraint was never
//! the knob being raised. Concretely, a deeper queue buys nothing here because the frames go
//! **stale** faster than a deeper queue would drain:
//!
//! - Rounds rotate every ~64 s (measured on ghost-vm4, 2026-08-22: 226 rounds in 4 h), and a
//!   round-lane response is scoped to `round_id`. A response that waits out its round is applied
//!   against a round the requester has already closed.
//! - The producer re-advertises every 30 s regardless, so a backlog is *duplicated* work, not
//!   deferred work — the fresh request supersedes the queued one.
//! - Frames run to ~64 KB (responses) and ~200 KB (a 3,000-hash `LedgerRequest`), on nodes whose
//!   working set already exceeds RAM.
//!
//! # What is discarded when it overflows, and why that is still safe
//!
//! ⚠ A `tokio::sync::mpsc` bounded channel rejects the **incoming** frame and keeps the queued
//! ones, so a full queue sheds the FRESHEST work and retains the stalest. That is the wrong way
//! round for a queue whose contents expire, and on its own it defeats the "the peer re-advertises,
//! so this is latency not loss" argument: under sustained overflow the drain spends its whole
//! budget on replies scoped to rounds the requester closed a minute ago, and every fresh reply is
//! shed again next pass — no forward progress until load drops.
//!
//! `tokio`'s channel cannot evict at the head, so expiry is enforced at the DRAIN instead. Each
//! frame is stamped at enqueue and discarded without a send once it is older than
//! [`FRAME_MAX_AGE`], which is one advertisement interval — past that the requester has already
//! asked again and our newer reply, computed against fresher state, is strictly better than the
//! queued one. A backlog of stale frames therefore drains at memory speed rather than at network
//! speed, which is what actually restores forward progress for the fresh ones behind it.
//! Discarded-as-expired is counted separately from shed-on-enqueue, because they say different
//! things: `shed` means production outran the drain, `expired` means the drain outran usefulness.
//!
//! # Why not backpressure
//!
//! `Mesh::handle_received` dispatches handlers **serially and in-line** (`mesh.rs`, the
//! `for handler in handlers { handler.handle_message(..).await }` loop). Awaiting a full channel
//! from inside a handler would stall the inbound dispatch for *every* registered handler on that
//! connection, converting a shed convergence reply into a mesh-wide receive stall. Backpressure
//! here needs the dispatch loop restructured first; it is not a change to this queue.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::mpsc;

use ghost_common::error::{GhostError, GhostResult};
use ghost_common::types::NodeId;

/// Bound on an outbound convergence queue, in frames.
///
/// See the module docs for why this is not the lever. Kept at the historical value deliberately:
/// changing it would confound the effect of the routing fix with the effect of a bigger buffer,
/// and `shed` on `/health` now measures whether it ever needed to move.
pub const CONVERGENCE_CHANNEL_CAPACITY: usize = 64;

/// How long a queued frame stays worth sending.
///
/// One advertisement interval: the periodic producers re-advertise every 30 s, so a reply that
/// has waited longer than that has already been superseded by a request computed against fresher
/// state. Sending it spends the drain's scarcest resource — a full mesh send — on an answer the
/// requester is about to replace. See the module docs.
pub const FRAME_MAX_AGE: Duration = Duration::from_secs(30);

/// One outbound convergence frame and where it is meant to go.
#[derive(Debug, Clone)]
pub struct ConvergenceFrame {
    /// The serialised `ConvergencePayload` / `ChallengeConvergencePayload`.
    pub bytes: Vec<u8>,
    /// The peer this frame answers, or `None` to fan out to the whole mesh.
    ///
    /// A *reply* always carries `Some(requester)`: its contents are computed as the complement of
    /// that peer's advertisement and are meaningless to anyone else. An *advertisement* carries
    /// `None`, because every peer is a legitimate recipient.
    pub to: Option<NodeId>,
    /// When the frame entered the queue, so the drain can discard it once it is stale rather
    /// than paying a mesh send for an answer the requester has already re-asked (see
    /// [`FRAME_MAX_AGE`]). Monotonic, so a clock step cannot make a frame look fresh for ever.
    pub queued_at: Instant,
}

impl ConvergenceFrame {
    /// Has this frame outlived its usefulness? Pure, so the expiry rule is testable without
    /// waiting 30 s of wall-clock in a test.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.queued_at) > FRAME_MAX_AGE
    }
}

/// Counters for one convergence queue, surfaced on `/health`.
///
/// Every field answers a question that could previously only be answered by grepping journald,
/// which is how #647 came to be discovered by accident during an unrelated soak.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConvergenceLaneSnapshot {
    /// The channel bound, in frames.
    pub capacity: usize,
    /// Frames waiting at the moment of the read.
    pub queued: usize,
    /// Frames accepted onto the queue since start.
    pub enqueued: u64,
    /// Frames DROPPED because the queue was full. This is the #647 number.
    pub shed: u64,
    /// Dequeued frames delivered to one addressed peer.
    pub unicast: u64,
    /// Dequeued frames fanned out to every connected peer.
    pub fanout: u64,
    /// Addressed frames that had to fall back to fan-out because the peer was not in the peer
    /// set, or because this node has no Noise pool and therefore cannot address anything. A
    /// rising value here means addressing is not taking effect and the drain is still paying
    /// full fan-out cost.
    pub unaddressable: u64,
    /// Frames the transport FAILED to send after they were dequeued.
    ///
    /// Counted separately from `shed` because it is a different failure with the same effect: the
    /// frame never reached the wire. Without it, a peer whose Noise listener is down, or a
    /// `send_to_peer` that returns `M-8: Outbound channel full`, would lose every reply while
    /// `/health` reported `shed: 0` and a full `unicast` count — relocating the exact blindness
    /// this module exists to remove.
    pub send_failed: u64,
    /// Frames discarded at the head of the queue for being older than [`FRAME_MAX_AGE`].
    ///
    /// Distinct from `shed`: `shed` means production outran the drain, `expired` means the drain
    /// outran the frame's usefulness. Both are "did not reach the wire", and an operator needs to
    /// tell them apart to know whether to look at the producer or the transport.
    pub expired: u64,
}

/// "no line has been emitted yet". Cannot be `0`: the monotonic clock this limiter reads starts
/// at 0 for the process, so a genuine event at 0 ms would otherwise be indistinguishable from
/// "never".
const RATE_LIMIT_NEVER: u64 = u64::MAX;

/// One rate-limited log line.
///
/// ⚠ Reads a MONOTONIC clock, deliberately. An earlier version compared Unix seconds, so a
/// backwards NTP or VM clock step made `now - last` evaluate to 0 and suppressed every WARN until
/// wall-clock caught up — silencing the one signal an operator sees without polling `/health`,
/// at precisely the moment (a resync, a migration) when something is likely wrong.
#[derive(Debug)]
struct LogRateLimit {
    last_ms: AtomicU64,
}

impl Default for LogRateLimit {
    fn default() -> Self {
        Self {
            last_ms: AtomicU64::new(RATE_LIMIT_NEVER),
        }
    }
}

impl LogRateLimit {
    /// May the caller log now? Pure in `now_ms`, so the interval is testable without sleeping.
    fn allow(&self, now_ms: u64, interval_ms: u64) -> bool {
        let last = self.last_ms.load(Ordering::Relaxed);
        if last != RATE_LIMIT_NEVER && now_ms.saturating_sub(last) < interval_ms {
            return false;
        }
        // Compare-and-swap so a burst across several tasks emits one line, not one per task.
        self.last_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

/// Atomic counters shared between the producers, the drain, and the `/health` probe.
#[derive(Debug)]
pub struct ConvergenceCounters {
    enqueued: AtomicU64,
    shed: AtomicU64,
    unicast: AtomicU64,
    fanout: AtomicU64,
    unaddressable: AtomicU64,
    send_failed: AtomicU64,
    expired: AtomicU64,
    /// Process-monotonic origin for the rate limiters below.
    start: Instant,
    shed_log: LogRateLimit,
    send_failure_log: LogRateLimit,
}

impl Default for ConvergenceCounters {
    fn default() -> Self {
        Self {
            enqueued: AtomicU64::new(0),
            shed: AtomicU64::new(0),
            unicast: AtomicU64::new(0),
            fanout: AtomicU64::new(0),
            unaddressable: AtomicU64::new(0),
            send_failed: AtomicU64::new(0),
            expired: AtomicU64::new(0),
            start: Instant::now(),
            shed_log: LogRateLimit::default(),
            send_failure_log: LogRateLimit::default(),
        }
    }
}

/// Milliseconds between shed WARNs. A shed burst is a rate, not an event: one line per burst
/// carrying the cumulative total says everything the 3,770 separate ERROR lines said, without the
/// churn on nodes that are already I/O bound.
const SHED_LOG_INTERVAL_MS: u64 = 60_000;

/// Milliseconds between post-dequeue send-failure WARNs. Same reasoning, and the same interval:
/// a peer whose link is down fails every frame, so the useful signal is one line a minute
/// carrying the running total, not one line per frame.
const SEND_FAILURE_LOG_INTERVAL_MS: u64 = 60_000;

impl ConvergenceCounters {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Record a frame shed on enqueue. Returns `true` if the caller should emit a log line — at
    /// most once a minute, whatever the burst rate.
    pub fn record_shed(&self) -> bool {
        self.shed.fetch_add(1, Ordering::Relaxed);
        self.shed_log.allow(self.now_ms(), SHED_LOG_INTERVAL_MS)
    }

    /// Record a frame the transport failed to send AFTER it was dequeued. Returns `true` if the
    /// caller should log.
    pub fn record_send_failure(&self) -> bool {
        self.send_failed.fetch_add(1, Ordering::Relaxed);
        self.send_failure_log
            .allow(self.now_ms(), SEND_FAILURE_LOG_INTERVAL_MS)
    }

    /// Record a frame discarded at the head for being older than [`FRAME_MAX_AGE`].
    pub fn record_expired(&self) {
        self.expired.fetch_add(1, Ordering::Relaxed);
    }

    /// Record how a frame was ACTUALLY delivered — never how the drain intended to deliver it.
    /// Counting the decision instead of the outcome is what let a fan-out fallback report itself
    /// as a successful unicast.
    fn record_delivery(&self, delivered: Delivered) {
        match delivered {
            Delivered::Unicast => self.unicast.fetch_add(1, Ordering::Relaxed),
            Delivered::Fanout => self.fanout.fetch_add(1, Ordering::Relaxed),
        };
    }

    fn record_unaddressable(&self) {
        self.unaddressable.fetch_add(1, Ordering::Relaxed);
    }

    pub fn shed(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }

    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
    }

    pub fn send_failed(&self) -> u64 {
        self.send_failed.load(Ordering::Relaxed)
    }

    fn snapshot(&self, capacity: usize, queued: usize) -> ConvergenceLaneSnapshot {
        ConvergenceLaneSnapshot {
            capacity,
            queued,
            enqueued: self.enqueued.load(Ordering::Relaxed),
            shed: self.shed.load(Ordering::Relaxed),
            unicast: self.unicast.load(Ordering::Relaxed),
            fanout: self.fanout.load(Ordering::Relaxed),
            unaddressable: self.unaddressable.load(Ordering::Relaxed),
            send_failed: self.send_failed.load(Ordering::Relaxed),
            expired: self.expired.load(Ordering::Relaxed),
        }
    }
}

/// The producer half of a convergence queue.
#[derive(Clone)]
pub struct ConvergenceSender {
    tx: mpsc::Sender<ConvergenceFrame>,
    counters: Arc<ConvergenceCounters>,
    capacity: usize,
    lane: &'static str,
}

/// Create a convergence queue. `lane` names it in logs (`"share"` / `"challenge"`).
pub fn convergence_channel(
    capacity: usize,
    lane: &'static str,
) -> (ConvergenceSender, mpsc::Receiver<ConvergenceFrame>) {
    let (tx, rx) = mpsc::channel(capacity);
    let counters = Arc::new(ConvergenceCounters::default());
    (
        ConvergenceSender {
            tx,
            counters,
            capacity,
            lane,
        },
        rx,
    )
}

impl ConvergenceSender {
    pub fn counters(&self) -> &Arc<ConvergenceCounters> {
        &self.counters
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Read the queue's counters together with its live occupancy.
    pub fn snapshot(&self) -> ConvergenceLaneSnapshot {
        let queued = self.capacity.saturating_sub(self.tx.capacity());
        self.counters.snapshot(self.capacity, queued)
    }

    /// Enqueue without blocking, for the sync handler callbacks.
    ///
    /// A full queue is **not** an error. It is an expected, counted, self-correcting condition:
    /// the requester re-advertises on its own 30 s cadence, so the reply we shed here is asked for
    /// again, whereas returning `Err` propagates to `Mesh`'s `error!("Handler error")` and turns a
    /// shed frame into an ERROR line — which is all #647 ever produced.
    ///
    /// A **closed** queue is a real fault (the drain task is gone, so nothing will ever be sent
    /// again) and is reported as one.
    pub fn try_enqueue(&self, bytes: Vec<u8>, to: Option<NodeId>) -> GhostResult<()> {
        let frame = ConvergenceFrame {
            bytes,
            to,
            queued_at: Instant::now(),
        };
        match self.tx.try_send(frame) {
            Ok(()) => {
                self.counters.enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if self.counters.record_shed() {
                    tracing::warn!(
                        lane = self.lane,
                        capacity = self.capacity,
                        shed_total = self.counters.shed(),
                        enqueued_total = self.counters.enqueued(),
                        "convergence queue full — frame shed (#647); the peer re-advertises on \
                         its own cadence, so this is latency, not loss"
                    );
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(GhostError::P2PMessage(format!(
                "{} convergence queue closed — the drain task is gone",
                self.lane
            ))),
        }
    }

    /// Enqueue with backpressure, for the periodic producers that own their own task and can
    /// safely wait. Returns `false` if the queue is closed.
    pub async fn enqueue(&self, bytes: Vec<u8>, to: Option<NodeId>) -> bool {
        let frame = ConvergenceFrame {
            bytes,
            to,
            queued_at: Instant::now(),
        };
        let ok = self.tx.send(frame).await.is_ok();
        if ok {
            self.counters.enqueued.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }
}

/// How a drained frame reaches the wire. Abstracted so the drain loop's routing is testable
/// without a live mesh — the routing decision is the whole point of the fix, and a decision that
/// only executes against production is a decision nothing can check.
#[async_trait]
pub trait ConvergenceTransport: Send + Sync {
    /// Can `peer` be addressed directly — is it in the peer set AND is a point-to-point plane
    /// available at all? Both halves matter; see [`MeshConvergenceTransport::knows_peer`].
    fn knows_peer(&self, peer: &NodeId) -> bool;
    /// Send one frame to one peer, reporting how it ACTUALLY went out.
    ///
    /// The return value is not a formality. The mesh can decide, after the drain has chosen a
    /// unicast, that the frame must be fanned out after all — the peer was evicted mid-flight,
    /// or the Noise plane is unavailable. Counting the drain's decision instead of this answer is
    /// how `/health` came to report a successful unicast for a frame that was broadcast.
    async fn unicast(&self, peer: &NodeId, bytes: Vec<u8>) -> GhostResult<Delivered>;
    /// Fan one frame out to every connected peer.
    async fn fanout(&self, bytes: Vec<u8>) -> GhostResult<Delivered>;
}

/// How a frame actually reached the wire, as reported by the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivered {
    /// Sent to exactly one peer.
    Unicast,
    /// Fanned out to the mesh.
    Fanout,
}

/// What the drain decided to do with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Addressed to one peer.
    Unicast(NodeId),
    /// Fanned out to the mesh because the frame carried no address.
    Fanout,
    /// Addressed, but the peer is unknown, so fanned out rather than dropped.
    FanoutUnaddressable(NodeId),
}

impl Route {
    /// The peer this frame was addressed to, if any.
    pub fn peer(&self) -> Option<NodeId> {
        match self {
            Route::Unicast(p) | Route::FanoutUnaddressable(p) => Some(*p),
            Route::Fanout => None,
        }
    }
}

/// Decide where a frame goes. Pure, so the fallback is testable.
pub fn route(frame: &ConvergenceFrame, transport: &dyn ConvergenceTransport) -> Route {
    match frame.to {
        None => Route::Fanout,
        Some(peer) if transport.knows_peer(&peer) => Route::Unicast(peer),
        Some(peer) => Route::FanoutUnaddressable(peer),
    }
}

/// Drain the queue until it closes, routing each frame.
///
/// Two rules, both learned the hard way:
///
/// 1. **Discard before sending, not after.** A frame older than [`FRAME_MAX_AGE`] is dropped
///    without a send, so a backlog of stale replies clears at memory speed instead of consuming
///    one mesh send each while fresh replies are shed behind it.
/// 2. **Count the outcome, never the decision.** Every counter below is incremented from what the
///    transport reports, after the await. Incrementing on the routing decision made `/health`
///    report a clean unicast for a frame that was fanned out or never sent at all.
pub async fn drain(
    mut rx: mpsc::Receiver<ConvergenceFrame>,
    transport: Arc<dyn ConvergenceTransport>,
    counters: Arc<ConvergenceCounters>,
    lane: &'static str,
) {
    while let Some(frame) = rx.recv().await {
        if frame.is_expired(Instant::now()) {
            counters.record_expired();
            tracing::debug!(
                lane,
                max_age_secs = FRAME_MAX_AGE.as_secs(),
                "convergence frame outlived its usefulness — discarded unsent so the fresher \
                 frames behind it are not shed"
            );
            continue;
        }

        let decision = route(&frame, transport.as_ref());
        if matches!(decision, Route::FanoutUnaddressable(_)) {
            counters.record_unaddressable();
        }
        let result = match decision {
            Route::Unicast(peer) => transport.unicast(&peer, frame.bytes).await,
            Route::Fanout | Route::FanoutUnaddressable(_) => transport.fanout(frame.bytes).await,
        };

        match result {
            Ok(delivered) => counters.record_delivery(delivered),
            Err(e) => {
                // A dequeued frame that never reached the wire is lost exactly as completely as
                // a shed one, and this path has no redundancy: the old code fanned every frame
                // out, so one bad Noise link still delivered to the other six. Addressing removes
                // that accidental redundancy, which makes the failure worth a counter and a line
                // rather than the `debug!` it used to get — below the fleet's default INFO, so
                // invisible. The retry is the requester's own 30 s re-advertisement; what was
                // missing is any way to know a retry is needed.
                if counters.record_send_failure() {
                    tracing::warn!(
                        lane,
                        error = %e,
                        send_failed_total = counters.send_failed(),
                        addressed = decision.peer().is_some(),
                        "convergence frame did not reach the wire (#647); the requester \
                         re-advertises every 30 s, so persistent failure here means a broken \
                         link, not a slow one"
                    );
                }
            }
        }
    }
}

impl From<ConvergenceLaneSnapshot> for ghost_verification::challenge::ConvergenceLaneStats {
    fn from(s: ConvergenceLaneSnapshot) -> Self {
        Self {
            capacity: s.capacity,
            queued: s.queued,
            enqueued: s.enqueued,
            shed: s.shed,
            unicast: s.unicast,
            fanout: s.fanout,
            unaddressable: s.unaddressable,
            send_failed: s.send_failed,
            expired: s.expired,
        }
    }
}

/// The production transport: one convergence message type over the live mesh.
pub struct MeshConvergenceTransport {
    mesh: Arc<ghost_consensus::mesh::MeshNetwork>,
    msg_type: ghost_consensus::MessageType,
}

impl MeshConvergenceTransport {
    pub fn new(
        mesh: Arc<ghost_consensus::mesh::MeshNetwork>,
        msg_type: ghost_consensus::MessageType,
    ) -> Self {
        Self { mesh, msg_type }
    }
}

/// Peer freshness for addressing, in seconds. Matches the window `Mesh::broadcast` already uses
/// to pick its fan-out targets, so an addressed frame reaches exactly the peer a fan-out would
/// have reached — never a peer the mesh considers stale.
const PEER_FRESHNESS_SECS: u64 = 60;

#[async_trait]
impl ConvergenceTransport for MeshConvergenceTransport {
    /// Two conditions, and BOTH are required.
    ///
    /// The peer must be in the peer set and fresh — but the mesh must also have a point-to-point
    /// plane to address it over. `MeshNetwork::should_use_noise` returns `false` for *every*
    /// message type when `noise_pool` is `None`, and `send_to_peer` then takes the ZMQ path,
    /// whose publisher loop discards the endpoint and publishes to all subscribers. So on a node
    /// with no Noise pool — regtest, a dev cluster, or a node whose pool failed to initialise —
    /// a "unicast" is physically a fan-out. Rather than let `/health` report addressing that
    /// cannot happen, such a node reports every reply as `unaddressable`, which is the honest
    /// reading: addressing is not landing and the drain is paying full fan-out cost.
    fn knows_peer(&self, peer: &NodeId) -> bool {
        let found = self.mesh.peers().get_peer(peer);
        addressing_available(
            self.mesh.noise_available(),
            found.as_ref().map(peer_liveness),
            chrono::Utc::now().timestamp().max(0) as u64,
        )
    }

    async fn unicast(&self, peer: &NodeId, bytes: Vec<u8>) -> GhostResult<Delivered> {
        let envelope = self.mesh.create_envelope_raw(self.msg_type, bytes)?;
        let Some(target) = self.mesh.peers().get_peer(peer) else {
            // Raced with peer eviction between `route` and here — a rolling restart does this to
            // every peer in turn. Fan out rather than drop, and report what actually happened:
            // reporting the intended unicast would make `/health` show addressing working at the
            // exact moment every frame is being fanned out at full cost.
            self.mesh.broadcast(envelope).await?;
            return Ok(Delivered::Fanout);
        };
        self.mesh.send_to_peer(&target, &envelope).await?;
        Ok(Delivered::Unicast)
    }

    async fn fanout(&self, bytes: Vec<u8>) -> GhostResult<Delivered> {
        let envelope = self.mesh.create_envelope_raw(self.msg_type, bytes)?;
        self.mesh.broadcast(envelope).await?;
        Ok(Delivered::Fanout)
    }
}

/// The two facts about a peer that decide whether it can be addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerLiveness {
    pub connected: bool,
    pub last_seen: u64,
}

fn peer_liveness(peer: &ghost_consensus::peer::Peer) -> PeerLiveness {
    PeerLiveness {
        connected: peer.state == ghost_consensus::peer::PeerState::Connected,
        last_seen: peer.last_seen,
    }
}

/// Can a reply be addressed to this peer? Pure, so the rule is testable without standing up a
/// `MeshNetwork` — and the Noise half in particular, which no integration test would exercise
/// because production always has a pool.
///
/// `noise_available` is not a detail. `MeshNetwork::should_use_noise` returns `false` for *every*
/// message type when the pool is absent, and `send_to_peer` then takes the ZMQ path, whose
/// publisher loop discards the endpoint and publishes to all subscribers. Without this half, a
/// node with no Noise pool would report `unicast` for frames that were physically broadcast.
pub fn addressing_available(
    noise_available: bool,
    peer: Option<PeerLiveness>,
    now_secs: u64,
) -> bool {
    if !noise_available {
        return false;
    }
    match peer {
        Some(p) => p.connected && p.last_seen >= now_secs.saturating_sub(PEER_FRESHNESS_SECS),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const PEER_A: NodeId = [0xa1; 32];
    const PEER_B: NodeId = [0xb2; 32];

    #[derive(Default)]
    struct RecordingTransport {
        known: Vec<NodeId>,
        unicasts: Mutex<Vec<(NodeId, usize)>>,
        fanouts: Mutex<Vec<usize>>,
        /// Report a fan-out from `unicast`, as the mesh does when the peer is evicted mid-flight.
        unicast_degrades_to_fanout: bool,
        /// Fail every send, as a peer with a dead Noise listener does.
        fail_sends: bool,
    }

    #[async_trait]
    impl ConvergenceTransport for RecordingTransport {
        fn knows_peer(&self, peer: &NodeId) -> bool {
            self.known.contains(peer)
        }
        async fn unicast(&self, peer: &NodeId, bytes: Vec<u8>) -> GhostResult<Delivered> {
            if self.fail_sends {
                return Err(GhostError::P2PMessage("peer link is down".into()));
            }
            if self.unicast_degrades_to_fanout {
                self.fanouts.lock().unwrap().push(bytes.len());
                return Ok(Delivered::Fanout);
            }
            self.unicasts.lock().unwrap().push((*peer, bytes.len()));
            Ok(Delivered::Unicast)
        }
        async fn fanout(&self, bytes: Vec<u8>) -> GhostResult<Delivered> {
            if self.fail_sends {
                return Err(GhostError::P2PMessage("mesh is down".into()));
            }
            self.fanouts.lock().unwrap().push(bytes.len());
            Ok(Delivered::Fanout)
        }
    }

    /// The whole capacity fix is "a reply costs one send, not `peers` sends". If addressing does
    /// not survive the queue, the drain is back to full fan-out cost and nothing was fixed.
    #[tokio::test]
    async fn an_addressed_frame_is_delivered_to_that_peer_alone() {
        let transport = Arc::new(RecordingTransport {
            known: vec![PEER_A, PEER_B],
            ..Default::default()
        });
        let (tx, rx) = convergence_channel(8, "test");
        let counters = Arc::clone(tx.counters());
        assert!(tx.enqueue(vec![7u8; 16], Some(PEER_A)).await);
        drop(tx);
        drain(rx, transport.clone(), Arc::clone(&counters), "test").await;

        assert_eq!(
            transport.unicasts.lock().unwrap().as_slice(),
            &[(PEER_A, 16)],
            "an addressed reply must reach its requester and only its requester"
        );
        assert!(
            transport.fanouts.lock().unwrap().is_empty(),
            "an addressed reply must not be fanned out — that is the cost this fix removes"
        );
        let snap = counters.snapshot(8, 0);
        assert_eq!(snap.unicast, 1);
        assert_eq!(snap.fanout, 0);
        assert_eq!(snap.send_failed, 0);
    }

    /// An advertisement is genuinely for everyone; addressing must not swallow it.
    #[tokio::test]
    async fn an_unaddressed_frame_is_fanned_out() {
        let transport = Arc::new(RecordingTransport {
            known: vec![PEER_A],
            ..Default::default()
        });
        let (tx, rx) = convergence_channel(8, "test");
        let counters = Arc::clone(tx.counters());
        assert!(tx.enqueue(vec![7u8; 16], None).await);
        drop(tx);
        drain(rx, transport.clone(), Arc::clone(&counters), "test").await;

        assert_eq!(transport.fanouts.lock().unwrap().as_slice(), &[16]);
        assert!(transport.unicasts.lock().unwrap().is_empty());
        assert_eq!(counters.snapshot(8, 0).fanout, 1);
    }

    /// A peer that has aged out of the peer set must not silently lose its reply: the frame falls
    /// back to fan-out, which is exactly the old behaviour, and the fallback is counted so a mesh
    /// where addressing never lands is visible rather than merely slow.
    #[tokio::test]
    async fn an_unknown_peer_falls_back_to_fanout_and_is_counted() {
        let transport = Arc::new(RecordingTransport {
            known: vec![PEER_A],
            ..Default::default()
        });
        let (tx, rx) = convergence_channel(8, "test");
        let counters = Arc::clone(tx.counters());
        assert!(tx.enqueue(vec![7u8; 16], Some(PEER_B)).await);
        drop(tx);
        drain(rx, transport.clone(), Arc::clone(&counters), "test").await;

        assert_eq!(
            transport.fanouts.lock().unwrap().as_slice(),
            &[16],
            "an unaddressable reply must still be sent, not dropped"
        );
        assert!(transport.unicasts.lock().unwrap().is_empty());
        let snap = counters.snapshot(8, 0);
        assert_eq!(snap.unaddressable, 1);
        assert_eq!(
            snap.fanout, 1,
            "the fallback is a fan-out and must be counted as one"
        );
        assert_eq!(snap.unicast, 0);
    }

    /// The drain chose a unicast, but the mesh fanned out anyway — the peer was evicted between
    /// the routing decision and the send, which a rolling restart does to every peer in turn.
    ///
    /// The counter must follow the TRANSPORT, not the decision. Counting the decision made
    /// `/health` report a clean `unicast` at exactly the moment every reply was being broadcast
    /// at full cost, with the `more_available` amplification this module exists to remove.
    #[tokio::test]
    async fn a_unicast_that_degrades_to_fanout_is_counted_as_a_fanout() {
        let transport = Arc::new(RecordingTransport {
            known: vec![PEER_A],
            unicast_degrades_to_fanout: true,
            ..Default::default()
        });
        let (tx, rx) = convergence_channel(8, "test");
        let counters = Arc::clone(tx.counters());
        assert!(tx.enqueue(vec![7u8; 16], Some(PEER_A)).await);
        drop(tx);
        drain(rx, transport.clone(), Arc::clone(&counters), "test").await;

        let snap = counters.snapshot(8, 0);
        assert_eq!(
            snap.unicast, 0,
            "a frame that was broadcast must never be reported as an addressed send"
        );
        assert_eq!(snap.fanout, 1, "the outcome was a fan-out; count that");
    }

    /// A dequeued frame the transport could not send is lost exactly as completely as a shed one,
    /// and a unicast has none of the accidental redundancy the old fan-out had. Before this it
    /// was a `debug!` — below the fleet's default INFO — so a peer with a dead Noise listener
    /// lost every reply while `/health` showed `shed: 0` and a full `unicast` count. That is the
    /// blindness #647 was filed to remove, relocated.
    #[tokio::test]
    async fn a_send_that_fails_after_dequeue_is_counted_and_is_not_counted_as_delivered() {
        let transport = Arc::new(RecordingTransport {
            known: vec![PEER_A],
            fail_sends: true,
            ..Default::default()
        });
        let (tx, rx) = convergence_channel(8, "test");
        let counters = Arc::clone(tx.counters());
        assert!(tx.enqueue(vec![7u8; 16], Some(PEER_A)).await);
        assert!(tx.enqueue(vec![7u8; 16], None).await);
        drop(tx);
        drain(rx, transport, Arc::clone(&counters), "test").await;

        let snap = counters.snapshot(8, 0);
        assert_eq!(snap.send_failed, 2, "both failures must be counted");
        assert_eq!(
            (snap.unicast, snap.fanout),
            (0, 0),
            "a frame that never reached the wire must not be counted as delivered"
        );
        assert_eq!(snap.shed, 0, "a send failure is not a shed frame");
    }

    /// #647's first ask: count what is lost. Before this, a shed frame produced an ERROR line and
    /// nothing else — no total, no rate, no `/health` field — so the only way to know the fleet
    /// was shedding 3,770 frames a day was to grep journald on eight nodes by hand.
    #[test]
    fn a_shed_frame_is_counted_and_is_not_counted_as_enqueued() {
        let (tx, _rx) = convergence_channel(2, "test");
        assert!(tx.try_enqueue(vec![1], None).is_ok());
        assert!(tx.try_enqueue(vec![2], None).is_ok());
        // Third has nowhere to go: `_rx` is held and never drained.
        assert!(
            tx.try_enqueue(vec![3], None).is_ok(),
            "a full queue is a counted condition, not a handler error"
        );

        let snap = tx.snapshot();
        assert_eq!(snap.shed, 1, "the shed frame must be counted");
        assert_eq!(snap.enqueued, 2, "a shed frame must not count as enqueued");
        assert_eq!(snap.queued, 2, "occupancy must be readable");
        assert_eq!(snap.capacity, 2);
    }

    /// A closed queue means the drain task is gone and nothing will ever be sent again. That is a
    /// genuine fault and must stay distinguishable from ordinary shedding, or the infallible-on-
    /// overflow behaviour above would also swallow a dead drain.
    #[test]
    fn a_closed_queue_is_an_error_not_a_shed() {
        let (tx, rx) = convergence_channel(2, "test");
        drop(rx);
        assert!(
            tx.try_enqueue(vec![1], None).is_err(),
            "a dead drain must not be reported as a routine shed"
        );
        assert_eq!(tx.snapshot().shed, 0, "a closed queue is not a shed frame");
    }

    /// `tokio`'s bounded channel rejects the NEWEST frame and keeps the queued ones, so without
    /// expiry the drain spends its whole budget on replies scoped to rounds the requester closed
    /// a minute ago while every fresh reply is shed — and the "the peer re-advertises, so this is
    /// latency not loss" argument fails, because the re-advertised reply is shed again next pass.
    ///
    /// Expiring at the head is what restores forward progress: the stale backlog clears at memory
    /// speed instead of costing one mesh send each.
    #[tokio::test]
    async fn a_stale_frame_is_discarded_unsent_so_the_fresh_one_behind_it_gets_through() {
        let transport = Arc::new(RecordingTransport {
            known: vec![PEER_A],
            ..Default::default()
        });
        let (tx, rx) = convergence_channel(8, "test");
        let counters = Arc::clone(tx.counters());

        // A frame that entered the queue well over one advertisement interval ago, ahead of a
        // fresh one. Built directly so the test does not have to wait 30 s of wall-clock.
        let stale_at = Instant::now()
            .checked_sub(FRAME_MAX_AGE + Duration::from_secs(5))
            .expect("monotonic clock has enough history");
        tx.tx
            .try_send(ConvergenceFrame {
                bytes: vec![0xde; 8],
                to: Some(PEER_A),
                queued_at: stale_at,
            })
            .expect("queue has room");
        assert!(tx.enqueue(vec![0xf5; 16], Some(PEER_A)).await);
        drop(tx);

        // Positive control: both frames really were queued before the drain ran.
        assert_eq!(rx.len(), 2, "two frames must be on the queue");
        drain(rx, transport.clone(), Arc::clone(&counters), "test").await;

        let snap = counters.snapshot(8, 0);
        assert_eq!(snap.expired, 1, "the stale frame must be discarded unsent");
        assert_eq!(
            transport.unicasts.lock().unwrap().as_slice(),
            &[(PEER_A, 16)],
            "only the FRESH frame may reach the wire — the stale one must not cost a send"
        );
        assert_eq!(snap.unicast, 1);
    }

    /// The expiry rule itself, independent of the drain.
    #[test]
    fn a_frame_expires_only_after_one_advertisement_interval() {
        let now = Instant::now();
        let fresh = ConvergenceFrame {
            bytes: vec![],
            to: None,
            queued_at: now,
        };
        assert!(
            !fresh.is_expired(now + FRAME_MAX_AGE),
            "a frame exactly at the bound is still worth sending"
        );
        assert!(
            fresh.is_expired(now + FRAME_MAX_AGE + Duration::from_millis(1)),
            "a frame past the bound has been superseded by the requester's next advertisement"
        );
    }

    /// The shed log must be a rate, not one line per shed frame — the ERROR flood was itself part
    /// of the cost on nodes that are already I/O bound.
    #[test]
    fn shed_logging_is_rate_limited_but_the_counter_is_not() {
        let counters = ConvergenceCounters::default();
        let limiter = &counters.shed_log;
        assert!(
            limiter.allow(0, SHED_LOG_INTERVAL_MS),
            "the first shed logs"
        );
        for ms in [1, 500, 30_000, 59_999] {
            assert!(
                !limiter.allow(ms, SHED_LOG_INTERVAL_MS),
                "a shed inside the interval must not log again"
            );
        }
        assert!(
            limiter.allow(60_000, SHED_LOG_INTERVAL_MS),
            "a shed past the interval must log again"
        );

        // The counter is independent of the log rate.
        for _ in 0..61 {
            counters.record_shed();
        }
        assert_eq!(
            counters.shed(),
            61,
            "every shed frame must be counted even when it is not logged"
        );
    }

    /// ⚠ The rate limiter must read a MONOTONIC clock.
    ///
    /// It used to compare Unix seconds, so a backwards NTP or VM clock step made `now - last`
    /// saturate to 0 and suppressed every WARN until wall-clock caught up — silencing the one
    /// signal an operator sees without polling `/health`, at exactly the moment (a resync, a
    /// migration) when something is likely wrong. A monotonic reading never goes backwards, so
    /// this test pins the behaviour the type is chosen for.
    #[test]
    fn the_rate_limiter_never_suppresses_because_a_clock_went_backwards() {
        let limiter = LogRateLimit::default();
        assert!(limiter.allow(100_000, SHED_LOG_INTERVAL_MS));
        // A reading BEHIND the stored one — impossible for `Instant`, routine for wall-clock.
        // `saturating_sub` yields 0, which would read as "inside the interval" and suppress.
        assert!(
            !limiter.allow(1_000, SHED_LOG_INTERVAL_MS),
            "a backwards reading must not be treated as time passing"
        );
        // And a genuine later reading still logs, so the limiter is not wedged either way.
        assert!(limiter.allow(160_000, SHED_LOG_INTERVAL_MS));
    }

    /// ⚠ A node with no Noise pool cannot address anything, and must not claim it can.
    ///
    /// `MeshNetwork::should_use_noise` returns `false` for EVERY message type when `noise_pool`
    /// is `None`, so `send_to_peer` takes the ZMQ path and the publisher loop discards the
    /// endpoint and publishes to all subscribers. On regtest, a dev cluster, or a node whose pool
    /// failed to initialise, a `Route::Unicast` is physically a fan-out — and reporting it as a
    /// unicast would make `/health` show the fix working on exactly the nodes where it does not.
    #[test]
    fn nothing_is_addressable_without_a_noise_plane() {
        let live = PeerLiveness {
            connected: true,
            last_seen: 1_000,
        };
        assert!(
            addressing_available(true, Some(live), 1_000),
            "positive control — a fresh connected peer on a Noise-capable node IS addressable"
        );
        assert!(
            !addressing_available(false, Some(live), 1_000),
            "with no Noise pool a `unicast` is physically a broadcast, so nothing is addressable"
        );
    }

    /// The peer half of the same rule. The freshness window mirrors the one `Mesh::broadcast`
    /// uses to pick its fan-out targets, so an addressed frame reaches exactly the peer a fan-out
    /// would have reached — never one the mesh already considers stale.
    #[test]
    fn a_stale_or_disconnected_peer_is_not_addressable() {
        let now = 10_000u64;
        let fresh = PeerLiveness {
            connected: true,
            last_seen: now - PEER_FRESHNESS_SECS,
        };
        assert!(
            addressing_available(true, Some(fresh), now),
            "a peer exactly at the freshness bound is still addressable"
        );
        assert!(
            !addressing_available(
                true,
                Some(PeerLiveness {
                    last_seen: now - PEER_FRESHNESS_SECS - 1,
                    ..fresh
                }),
                now
            ),
            "a peer past the freshness bound must fall back to fan-out"
        );
        assert!(
            !addressing_available(
                true,
                Some(PeerLiveness {
                    connected: false,
                    ..fresh
                }),
                now
            ),
            "a disconnected peer must fall back to fan-out"
        );
        assert!(
            !addressing_available(true, None, now),
            "an unknown peer must fall back to fan-out"
        );
    }

    /// The counters are only worth having if they survive the trip to `/health`. The wire struct
    /// is built field by field, so a dropped or transposed field is a silent zero on the endpoint
    /// — the counter reads correct in-process and reports nothing to the operator.
    #[test]
    fn every_counter_survives_the_conversion_to_the_health_response() {
        let snap = ConvergenceLaneSnapshot {
            capacity: 64,
            queued: 7,
            enqueued: 11,
            shed: 13,
            unicast: 17,
            fanout: 19,
            unaddressable: 23,
            send_failed: 29,
            expired: 31,
        };
        let wire: ghost_verification::challenge::ConvergenceLaneStats = snap.clone().into();
        assert_eq!(wire.capacity, snap.capacity);
        assert_eq!(wire.queued, snap.queued);
        assert_eq!(wire.enqueued, snap.enqueued);
        assert_eq!(wire.shed, snap.shed, "the #647 number must survive");
        assert_eq!(wire.unicast, snap.unicast);
        assert_eq!(wire.fanout, snap.fanout);
        assert_eq!(wire.unaddressable, snap.unaddressable);
        assert_eq!(
            wire.send_failed, snap.send_failed,
            "a frame that never reached the wire must be readable on /health"
        );
        assert_eq!(wire.expired, snap.expired);
    }

    /// The two rate limiters must be independent: a shed burst must not silence the send-failure
    /// line, which reports a different fault with a different remedy.
    #[test]
    fn shed_and_send_failure_logging_do_not_silence_each_other() {
        let counters = ConvergenceCounters::default();
        assert!(counters.record_shed(), "first shed logs");
        assert!(
            counters.record_send_failure(),
            "a send failure must log even though a shed line was just emitted"
        );
        assert_eq!(counters.shed(), 1);
        assert_eq!(counters.send_failed(), 1);
    }
}
