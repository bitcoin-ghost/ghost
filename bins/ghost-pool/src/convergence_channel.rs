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
//! Shedding the oldest surplus and counting it is the honest behaviour for a queue whose contents
//! expire. What was missing is the count.
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
    /// set. A rising value here means addressing is not taking effect and the drain is still
    /// paying full fan-out cost.
    pub unaddressable: u64,
}

/// Atomic counters shared between the producers, the drain, and the `/health` probe.
#[derive(Debug, Default)]
pub struct ConvergenceCounters {
    enqueued: AtomicU64,
    shed: AtomicU64,
    unicast: AtomicU64,
    fanout: AtomicU64,
    unaddressable: AtomicU64,
    /// Unix seconds of the last shed WARN, so a burst does not become its own log flood.
    last_shed_log: AtomicU64,
}

/// Seconds between shed WARNs. A shed burst is a rate, not an event: one line per burst carrying
/// the cumulative total says everything the 3,770 separate ERROR lines said, without the churn on
/// nodes that are already I/O bound.
const SHED_LOG_INTERVAL_SECS: u64 = 60;

impl ConvergenceCounters {
    /// Record a shed frame. Returns `true` if the caller should emit a log line — at most once
    /// per [`SHED_LOG_INTERVAL_SECS`], whatever the burst rate.
    pub fn record_shed(&self, now_secs: u64) -> bool {
        self.shed.fetch_add(1, Ordering::Relaxed);
        let last = self.last_shed_log.load(Ordering::Relaxed);
        if now_secs.saturating_sub(last) < SHED_LOG_INTERVAL_SECS && last != 0 {
            return false;
        }
        // Compare-and-swap so a burst across several tasks still emits one line, not one per task.
        self.last_shed_log
            .compare_exchange(last, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    pub fn shed(&self) -> u64 {
        self.shed.load(Ordering::Relaxed)
    }

    pub fn enqueued(&self) -> u64 {
        self.enqueued.load(Ordering::Relaxed)
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
        match self.tx.try_send(ConvergenceFrame { bytes, to }) {
            Ok(()) => {
                self.counters.enqueued.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                let now = chrono::Utc::now().timestamp().max(0) as u64;
                if self.counters.record_shed(now) {
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
        let ok = self.tx.send(ConvergenceFrame { bytes, to }).await.is_ok();
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
    /// Is `peer` in the peer set, i.e. can it be addressed directly?
    fn knows_peer(&self, peer: &NodeId) -> bool;
    /// Send one frame to one peer.
    async fn unicast(&self, peer: &NodeId, bytes: Vec<u8>) -> GhostResult<()>;
    /// Fan one frame out to every connected peer.
    async fn fanout(&self, bytes: Vec<u8>) -> GhostResult<()>;
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

/// Decide where a frame goes. Pure, so the fallback is testable.
pub fn route(frame: &ConvergenceFrame, transport: &dyn ConvergenceTransport) -> Route {
    match frame.to {
        None => Route::Fanout,
        Some(peer) if transport.knows_peer(&peer) => Route::Unicast(peer),
        Some(peer) => Route::FanoutUnaddressable(peer),
    }
}

/// Drain the queue until it closes, routing each frame.
pub async fn drain(
    mut rx: mpsc::Receiver<ConvergenceFrame>,
    transport: Arc<dyn ConvergenceTransport>,
    counters: Arc<ConvergenceCounters>,
    lane: &'static str,
) {
    while let Some(frame) = rx.recv().await {
        let decision = route(&frame, transport.as_ref());
        let result = match decision {
            Route::Unicast(peer) => {
                counters.unicast.fetch_add(1, Ordering::Relaxed);
                transport.unicast(&peer, frame.bytes).await
            }
            Route::Fanout => {
                counters.fanout.fetch_add(1, Ordering::Relaxed);
                transport.fanout(frame.bytes).await
            }
            Route::FanoutUnaddressable(peer) => {
                counters.fanout.fetch_add(1, Ordering::Relaxed);
                counters.unaddressable.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    lane,
                    peer = %hex::encode(&peer[..8]),
                    "convergence reply could not be addressed — falling back to fan-out"
                );
                transport.fanout(frame.bytes).await
            }
        };
        if let Err(e) = result {
            tracing::debug!(lane, error = %e, "convergence frame send failed");
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
    fn knows_peer(&self, peer: &NodeId) -> bool {
        self.mesh
            .peers()
            .get_peer(peer)
            .is_some_and(|p| is_addressable(&p))
    }

    async fn unicast(&self, peer: &NodeId, bytes: Vec<u8>) -> GhostResult<()> {
        let Some(target) = self.mesh.peers().get_peer(peer) else {
            // Raced with peer eviction between `route` and here. Fan out rather than drop: the
            // frame is still useful to whoever holds the request.
            let envelope = self.mesh.create_envelope_raw(self.msg_type, bytes)?;
            self.mesh.broadcast(envelope).await?;
            return Ok(());
        };
        let envelope = self.mesh.create_envelope_raw(self.msg_type, bytes)?;
        self.mesh.send_to_peer(&target, &envelope).await
    }

    async fn fanout(&self, bytes: Vec<u8>) -> GhostResult<()> {
        let envelope = self.mesh.create_envelope_raw(self.msg_type, bytes)?;
        self.mesh.broadcast(envelope).await.map(|_| ())
    }
}

fn is_addressable(peer: &ghost_consensus::peer::Peer) -> bool {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    peer.state == ghost_consensus::peer::PeerState::Connected
        && peer.last_seen >= now.saturating_sub(PEER_FRESHNESS_SECS)
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
    }

    #[async_trait]
    impl ConvergenceTransport for RecordingTransport {
        fn knows_peer(&self, peer: &NodeId) -> bool {
            self.known.contains(peer)
        }
        async fn unicast(&self, peer: &NodeId, bytes: Vec<u8>) -> GhostResult<()> {
            self.unicasts.lock().unwrap().push((*peer, bytes.len()));
            Ok(())
        }
        async fn fanout(&self, bytes: Vec<u8>) -> GhostResult<()> {
            self.fanouts.lock().unwrap().push(bytes.len());
            Ok(())
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
        let snap = tx_snapshot(&counters, 8, 0);
        assert_eq!(snap.unicast, 1);
        assert_eq!(snap.fanout, 0);
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
        assert_eq!(counters.snapshot(8, 0).unaddressable, 1);
    }

    fn tx_snapshot(
        counters: &ConvergenceCounters,
        capacity: usize,
        queued: usize,
    ) -> ConvergenceLaneSnapshot {
        counters.snapshot(capacity, queued)
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

    /// The shed log must be a rate, not one line per shed frame — the ERROR flood was itself part
    /// of the cost on nodes that are already I/O bound.
    #[test]
    fn shed_logging_is_rate_limited_but_the_counter_is_not() {
        let counters = ConvergenceCounters::default();
        assert!(counters.record_shed(1_000), "the first shed must be logged");
        for t in 1_001..1_060 {
            assert!(
                !counters.record_shed(t),
                "a shed inside the interval must not log again"
            );
        }
        assert!(
            counters.record_shed(1_060),
            "a shed past the interval must log again"
        );
        assert_eq!(
            counters.shed(),
            61,
            "every shed frame must be counted even when it is not logged"
        );
    }
}
