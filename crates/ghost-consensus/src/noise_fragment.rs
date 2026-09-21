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
//| FILE: noise_fragment.rs                                                                                              |
//|======================================================================================================================|

//! Application-level fragmentation for the Noise transport.
//!
//! # Why
//!
//! The Noise transport (`noise.rs`) can only encrypt one message of at most
//! [`MAX_PAYLOAD_SIZE`] (65519) bytes per frame — the ChaCha20-Poly1305 limit
//! (65535) minus the 16-byte AEAD tag. Some logical mesh messages exceed this:
//! checkpoint / L2 tree-sync proposals routinely reach ~84 KB as the commitment
//! tree grows. Those sends fail with `Message too large: N > 65519`, the peer
//! never receives the proposal, and the cluster falls into repeated
//! "Checkpoint reached quorum but proposal data missing — requesting tree sync"
//! self-healing churn.
//!
//! # Design
//!
//! A logical message that fits in a single Noise frame is sent **unchanged** on
//! the existing fast path (no header, no extra copy). Only when a message
//! exceeds the transport limit is it split into ordered chunks, each carrying a
//! small self-describing header and sent as its own Noise frame. The receiver
//! buffers chunks by `message_id` and reassembles them into the original bytes
//! before dispatching to the normal handler.
//!
//! ## Wire format of a fragment frame
//!
//! ```text
//! ┌────────┬──────────┬─────────────┬─────────────┬───────────┬───────────┐
//! │ MAGIC  │ msg_id   │ chunk_index │ chunk_count │ total_len │  payload  │
//! │ 4 B    │ 8 B (LE) │ 2 B (LE)    │ 2 B (LE)    │ 4 B (LE)  │  ≤60000 B │
//! └────────┴──────────┴─────────────┴─────────────┴───────────┴───────────┘
//! ```
//!
//! `MAGIC` = `b"GFR1"` (Ghost FRagment v1). It is 20 bytes of header total.
//!
//! ## Backward compatibility (self-describing, no negotiation needed)
//!
//! A [`MessageEnvelope`](crate::message::MessageEnvelope) is serialised with
//! `serde_json`, so every complete-message frame begins with `{` (`0x7B`). A
//! fragment frame begins with `MAGIC[0] == 0x47` (`'G'`). The two can never
//! collide, so the receiver distinguishes them by inspecting the first bytes —
//! this *is* the capability signal, no version handshake required:
//!
//! * **new sender → old receiver:** small messages are byte-identical to today
//!   and just work. A large message is fragmented; the old node reads each
//!   fragment as its own Noise frame, tries to JSON-decode it, fails (it is not
//!   valid JSON), logs and drops it — exactly the pre-fix behaviour. It then
//!   falls back to tree-sync. No stream corruption (each fragment is an
//!   independent length-prefixed Noise frame) and no worse than today's churn.
//! * **old sender → new receiver:** an old node only ever emits complete
//!   `{...}` envelopes, which the new receiver recognises as non-fragments and
//!   passes straight through. Large messages still fail to send on the old
//!   node, unchanged.
//! * **new ↔ new:** full fragmentation / reassembly.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::noise::{NoiseError, MAX_PAYLOAD_SIZE};

/// Magic prefix marking a fragment frame: `b"GFR1"` (Ghost FRagment v1).
///
/// Chosen so it can never collide with a `serde_json`-encoded
/// [`MessageEnvelope`](crate::message::MessageEnvelope), which always starts
/// with `{` (`0x7B`). `MAGIC[0]` is `'G'` (`0x47`).
pub const FRAGMENT_MAGIC: [u8; 4] = *b"GFR1";

/// Size of the per-fragment header: magic(4) + msg_id(8) + index(2) + count(2) + total_len(4).
pub const FRAGMENT_HEADER_LEN: usize = 4 + 8 + 2 + 2 + 4;

/// Maximum payload bytes carried in a single fragment.
///
/// Kept comfortably below [`MAX_PAYLOAD_SIZE`] so that
/// `FRAGMENT_HEADER_LEN + MAX_FRAGMENT_PAYLOAD` always fits in one Noise frame.
pub const MAX_FRAGMENT_PAYLOAD: usize = 60_000;

/// Upper bound on a reassembled message (memory-DoS guard).
///
/// A peer cannot make us buffer more than this for a single in-flight message.
/// Comfortably above the ~84 KB checkpoint/tree-sync proposals while capping a
/// malicious peer.
pub const MAX_REASSEMBLY_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

/// Upper bound on the number of chunks in one logical message (memory-DoS guard).
pub const MAX_FRAGMENT_COUNT: usize = 256;

/// A partially-received message is dropped if it does not complete within this
/// window, freeing the reassembly slot.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Process-wide ceiling on bytes held in PARTIAL reassembly buffers (#911).
///
/// [`MAX_REASSEMBLY_SIZE`] bounds ONE message from ONE peer. It does not bound the process:
/// the reassembler is per-connection, so the total is `connections x 8 MiB`. The inbound caps
/// (`MAX_INBOUND_PER_IP = 8`, `MAX_INBOUND_PER_SUBNET = 16`) bound what a single source can
/// pin, not the aggregate — addresses spread across enough distinct `/24`s are each
/// individually under their limit while together reaching the same ceiling the old global
/// semaphore allowed (~800 MiB).
///
/// That matters on these nodes: seven of the eight production nodes have 3,867 MiB of RAM
/// TOTAL (measured 2026-09-21), shared between `ghostd`, `ghost-pool`, `pool_sv2` and
/// `translator_sv2`. Hundreds of megabytes of attacker-pinned buffers is not a slow path, it
/// is the OOM killer taking a consensus process.
///
/// 64 MiB is deliberately generous against legitimate use and mean against abuse: the only
/// messages that fragment at all are checkpoint / tree-sync proposals at ~84 KB, so this is
/// room for ~780 concurrent real reassemblies, against a fleet of 8 nodes.
pub const REASSEMBLY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

// Compile-time guarantee that a full fragment frame fits in one Noise frame.
const _: () = assert!(FRAGMENT_HEADER_LEN + MAX_FRAGMENT_PAYLOAD <= MAX_PAYLOAD_SIZE);

/// Process-global monotonic source of `message_id` values.
///
/// Uniqueness only needs to hold within a connection's reassembly window; a
/// monotonic counter is more than sufficient and avoids an RNG dependency.
static NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);

/// Returns `true` if `payload` must be fragmented to cross the Noise transport.
#[inline]
pub fn needs_fragmentation(payload: &[u8]) -> bool {
    payload.len() > MAX_PAYLOAD_SIZE
}

/// Split an oversized `payload` into ordered fragment frames.
///
/// Callers should only invoke this when [`needs_fragmentation`] returns `true`;
/// each returned `Vec` is a ready-to-send Noise frame (header + chunk).
pub fn fragment_message(payload: &[u8]) -> Vec<Vec<u8>> {
    let total_len = payload.len();
    let chunk_count = total_len.div_ceil(MAX_FRAGMENT_PAYLOAD).max(1);
    let message_id = NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed);

    let mut frames = Vec::with_capacity(chunk_count);
    for (idx, chunk) in payload.chunks(MAX_FRAGMENT_PAYLOAD).enumerate() {
        let mut frame = Vec::with_capacity(FRAGMENT_HEADER_LEN + chunk.len());
        frame.extend_from_slice(&FRAGMENT_MAGIC);
        frame.extend_from_slice(&message_id.to_le_bytes());
        frame.extend_from_slice(&(idx as u16).to_le_bytes());
        frame.extend_from_slice(&(chunk_count as u16).to_le_bytes());
        frame.extend_from_slice(&(total_len as u32).to_le_bytes());
        frame.extend_from_slice(chunk);
        frames.push(frame);
    }
    frames
}

/// A parsed fragment header.
struct FragmentHeader {
    message_id: u64,
    chunk_index: usize,
    chunk_count: usize,
    total_len: usize,
}

impl FragmentHeader {
    /// Parse and validate the header of a fragment frame.
    ///
    /// Returns `Ok(None)` when the frame is *not* a fragment (no magic) — the
    /// caller then treats the frame as a complete single message.
    fn parse(frame: &[u8]) -> Result<Option<(FragmentHeader, &[u8])>, NoiseError> {
        if frame.len() < FRAGMENT_HEADER_LEN || frame[..4] != FRAGMENT_MAGIC {
            return Ok(None); // Not a fragment: complete-message fast path.
        }

        let message_id = u64::from_le_bytes(frame[4..12].try_into().expect("8 bytes"));
        let chunk_index = u16::from_le_bytes(frame[12..14].try_into().expect("2 bytes")) as usize;
        let chunk_count = u16::from_le_bytes(frame[14..16].try_into().expect("2 bytes")) as usize;
        let total_len = u32::from_le_bytes(frame[16..20].try_into().expect("4 bytes")) as usize;
        let payload = &frame[FRAGMENT_HEADER_LEN..];

        if chunk_count == 0 {
            return Err(NoiseError::Decryption("fragment: zero chunk_count".into()));
        }
        if chunk_index >= chunk_count {
            return Err(NoiseError::Decryption(
                "fragment: chunk_index out of range".into(),
            ));
        }
        if chunk_count > MAX_FRAGMENT_COUNT {
            return Err(NoiseError::Decryption("fragment: too many chunks".into()));
        }
        if total_len > MAX_REASSEMBLY_SIZE {
            return Err(NoiseError::Decryption(
                "fragment: total_len exceeds reassembly cap".into(),
            ));
        }
        if payload.len() > MAX_FRAGMENT_PAYLOAD {
            return Err(NoiseError::Decryption("fragment: chunk too large".into()));
        }
        // The declared total_len must be consistent with the declared chunk_count.
        let min_len = (chunk_count - 1) * MAX_FRAGMENT_PAYLOAD + 1;
        let max_len = chunk_count * MAX_FRAGMENT_PAYLOAD;
        if total_len < min_len || total_len > max_len {
            return Err(NoiseError::Decryption(
                "fragment: total_len inconsistent with chunk_count".into(),
            ));
        }

        Ok(Some((
            FragmentHeader {
                message_id,
                chunk_index,
                chunk_count,
                total_len,
            },
            payload,
        )))
    }
}

/// A single in-flight message being reassembled.
struct InFlight {
    message_id: u64,
    chunk_count: usize,
    total_len: usize,
    chunks: Vec<Option<Vec<u8>>>,
    received_bytes: usize,
    received_count: usize,
    started_at: Instant,
}

/// The shared slot a [`ReassemblyBudget`] can reach into to evict.
///
/// Eviction has to FREE memory, which means reaching another connection's buffer. Marking a
/// victim and waiting for it to notice does not bound anything: a buffer that never receives
/// another fragment is precisely the attack, so its owner never runs again to see the mark.
type SharedSlot = Arc<Mutex<Option<InFlight>>>;

struct BudgetEntry {
    /// Bytes this reassembler is currently accounted for.
    bytes: usize,
    /// Monotonic touch counter — the LRU key. A counter rather than an `Instant` so the
    /// victim is deterministic in tests instead of depending on clock resolution.
    seq: u64,
    /// Weak so a dropped connection's entry cannot keep its buffer alive.
    slot: Weak<Mutex<Option<InFlight>>>,
}

struct BudgetInner {
    limit: usize,
    held: usize,
    entries: HashMap<u64, BudgetEntry>,
    next_id: u64,
    next_seq: u64,
    evictions: u64,
    rejections: u64,
}

/// A process-wide byte budget across every connection's reassembly buffer (#911).
///
/// ## Lock order
///
/// ⛔ The budget lock is taken FIRST, then a victim's slot lock. `FragmentReassembler::accept`
/// therefore must not hold its own slot lock across a call into here, or two connections
/// evicting each other invert the order and deadlock. Every call below takes the budget lock
/// and only then touches a slot.
#[derive(Clone)]
pub struct ReassemblyBudget {
    inner: Arc<Mutex<BudgetInner>>,
}

impl ReassemblyBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BudgetInner {
                limit,
                held: 0,
                entries: HashMap::new(),
                next_id: 1,
                next_seq: 1,
                evictions: 0,
                rejections: 0,
            })),
        }
    }

    /// Register a reassembler's slot and get its id.
    fn register(&self, slot: &SharedSlot) -> u64 {
        let mut g = self.inner.lock();
        let id = g.next_id;
        g.next_id += 1;
        let seq = g.next_seq;
        g.next_seq += 1;
        g.entries.insert(
            id,
            BudgetEntry {
                bytes: 0,
                seq,
                slot: Arc::downgrade(slot),
            },
        );
        id
    }

    fn unregister(&self, id: u64) {
        let mut g = self.inner.lock();
        if let Some(e) = g.entries.remove(&id) {
            g.held = g.held.saturating_sub(e.bytes);
        }
    }

    /// Account `id` as holding exactly `want` bytes, evicting the least-recently-used OTHER
    /// buffers until it fits.
    ///
    /// Set-to-absolute rather than increment: the caller's buffer may have been evicted
    /// between calls, and an increment would then drift against reality permanently.
    ///
    /// Returns `false` when `want` cannot be accommodated even after evicting everything
    /// evictable — the caller must then refuse the fragment rather than allocate anyway.
    fn reserve(&self, id: u64, want: usize) -> bool {
        let mut g = self.inner.lock();

        let current = g.entries.get(&id).map(|e| e.bytes).unwrap_or(0);
        g.held = g.held.saturating_sub(current);
        if let Some(e) = g.entries.get_mut(&id) {
            e.bytes = 0;
            let seq = g.next_seq;
            g.next_seq += 1;
            if let Some(e) = g.entries.get_mut(&id) {
                e.seq = seq;
            }
        }

        // A single buffer may never exceed the whole budget, however empty it is.
        if want > g.limit {
            g.rejections += 1;
            return false;
        }

        while g.held + want > g.limit {
            // Least-recently-touched entry that is NOT us and actually holds something.
            let victim = g
                .entries
                .iter()
                .filter(|(vid, e)| **vid != id && e.bytes > 0)
                .min_by_key(|(_, e)| e.seq)
                .map(|(vid, _)| *vid);

            let Some(vid) = victim else {
                // Nothing left to evict and it still does not fit.
                g.rejections += 1;
                return false;
            };

            let freed = {
                let e = g.entries.get_mut(&vid).expect("victim present");
                let freed = e.bytes;
                e.bytes = 0;
                if let Some(slot) = e.slot.upgrade() {
                    // Budget lock held, then slot lock — the documented order.
                    *slot.lock() = None;
                }
                freed
            };
            g.held = g.held.saturating_sub(freed);
            g.evictions += 1;
            tracing::warn!(
                evicted_id = vid,
                freed_bytes = freed,
                held = g.held,
                limit = g.limit,
                "reassembly budget exhausted — evicted the least-recently-used partial message (#911)"
            );
        }

        g.held += want;
        if let Some(e) = g.entries.get_mut(&id) {
            e.bytes = want;
        }
        true
    }

    /// Bytes currently held, and how many evictions/rejections have happened.
    ///
    /// Exposed so exhaustion is observable. A budget that silently drops honest traffic is its
    /// own outage, and one nobody can see is worse.
    pub fn stats(&self) -> (usize, u64, u64) {
        let g = self.inner.lock();
        (g.held, g.evictions, g.rejections)
    }
}

/// The process-wide budget every connection shares.
static GLOBAL_BUDGET: once_cell::sync::Lazy<ReassemblyBudget> =
    once_cell::sync::Lazy::new(|| ReassemblyBudget::new(REASSEMBLY_BUDGET_BYTES));

/// Handle to the process-wide reassembly budget (#911).
pub fn global_budget() -> ReassemblyBudget {
    GLOBAL_BUDGET.clone()
}

/// Reassembles fragmented Noise messages for a single connection.
///
/// Because [`NoiseConnection::send`](crate::noise_pool::NoiseConnection::send)
/// emits all fragments of a message under one transport lock, fragments of
/// different messages never interleave on a connection's ordered stream. A
/// single reassembly slot per connection is therefore sufficient — and it
/// naturally bounds memory to at most one [`MAX_REASSEMBLY_SIZE`] buffer per
/// peer. A stale slot (peer sent some chunks then went quiet) is dropped after
/// [`REASSEMBLY_TIMEOUT`].
pub struct FragmentReassembler {
    /// Shared so the budget can evict it — see [`ReassemblyBudget`].
    slot: SharedSlot,
    budget: ReassemblyBudget,
    id: u64,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FragmentReassembler {
    fn drop(&mut self) {
        // A closed connection must return its bytes, or the budget leaks until restart and
        // eventually refuses everything.
        self.budget.unregister(self.id);
    }
}

impl FragmentReassembler {
    /// Create an empty reassembler sharing the process-wide budget.
    pub fn new() -> Self {
        Self::with_budget(global_budget())
    }

    /// Create one against a specific budget. Used by tests to exercise exhaustion without a
    /// 64 MiB allocation.
    pub fn with_budget(budget: ReassemblyBudget) -> Self {
        let slot: SharedSlot = Arc::new(Mutex::new(None));
        let id = budget.register(&slot);
        Self { slot, budget, id }
    }

    /// Feed one received Noise frame.
    ///
    /// * A non-fragment frame is returned as `Ok(Some(bytes))` immediately
    ///   (complete-message fast path).
    /// * A fragment that completes a message returns `Ok(Some(bytes))`.
    /// * A fragment that does not yet complete a message returns `Ok(None)`.
    /// * A malformed / duplicate / oversized fragment returns `Err(..)` and the
    ///   partial state is discarded so a subsequent message is not poisoned.
    pub fn accept(&mut self, frame: Vec<u8>) -> Result<Option<Vec<u8>>, NoiseError> {
        let (header, payload) = match FragmentHeader::parse(&frame)? {
            None => return Ok(Some(frame)), // Complete single message.
            Some((h, p)) => (h, p.to_vec()),
        };

        // Ask the budget BEFORE touching our own slot.
        //
        // ⛔ Lock order is budget -> slot (see `ReassemblyBudget`). Holding our slot lock across
        // this call would let two connections evicting each other deadlock, so the reservation
        // happens first and the slot is locked afterwards.
        //
        // The reservation is for the FULL declared message, not the bytes in hand. A peer that
        // announces an 8 MiB `total_len` and then sends one chunk has committed that memory as
        // far as we are concerned — charging only for what arrived is exactly how a slow-drip
        // sender stays under a budget while pinning it.
        if !self.budget.reserve(self.id, header.total_len) {
            *self.slot.lock() = None;
            return Err(NoiseError::Decryption(
                "fragment: reassembly budget exhausted".into(),
            ));
        }

        let mut guard = self.slot.lock();

        // Start a fresh slot if this is a new message, the previous slot is for
        // a different message, the previous slot has gone stale, or the budget
        // evicted it while we were not looking.
        let need_reset = match guard.as_ref() {
            None => true,
            Some(cur) => {
                cur.message_id != header.message_id
                    || cur.chunk_count != header.chunk_count
                    || cur.started_at.elapsed() > REASSEMBLY_TIMEOUT
            }
        };
        if need_reset {
            *guard = Some(InFlight {
                message_id: header.message_id,
                chunk_count: header.chunk_count,
                total_len: header.total_len,
                chunks: vec![None; header.chunk_count],
                received_bytes: 0,
                received_count: 0,
                started_at: Instant::now(),
            });
        }

        let slot = guard.as_mut().expect("slot set above");

        // Guard against a mid-stream total_len change for the same message_id.
        if slot.total_len != header.total_len {
            *guard = None;
            drop(guard);
            self.budget.reserve(self.id, 0);
            return Err(NoiseError::Decryption(
                "fragment: total_len changed mid-message".into(),
            ));
        }

        // Reject duplicate chunk indices — prevents a peer inflating a buffer or
        // silently overwriting already-received data.
        if slot.chunks[header.chunk_index].is_some() {
            *guard = None;
            drop(guard);
            self.budget.reserve(self.id, 0);
            return Err(NoiseError::Decryption("fragment: duplicate chunk".into()));
        }

        slot.received_bytes += payload.len();
        if slot.received_bytes > slot.total_len {
            *guard = None;
            drop(guard);
            self.budget.reserve(self.id, 0);
            return Err(NoiseError::Decryption(
                "fragment: received bytes exceed total_len".into(),
            ));
        }

        slot.chunks[header.chunk_index] = Some(payload);
        slot.received_count += 1;

        if slot.received_count < slot.chunk_count {
            return Ok(None); // Await more fragments.
        }

        // All chunks present: concatenate in index order.
        let slot = guard.take().expect("slot present");
        drop(guard);
        // Completed: the bytes are about to become the caller's, not ours.
        self.budget.reserve(self.id, 0);
        let mut out = Vec::with_capacity(slot.total_len);
        for chunk in slot.chunks {
            out.extend_from_slice(&chunk.expect("all chunks present when count matches"));
        }
        if out.len() != slot.total_len {
            return Err(NoiseError::Decryption(
                "fragment: reassembled length mismatch".into(),
            ));
        }
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------- #911: global budget

    /// Build one fragment frame by hand so a test can declare a `total_len` far larger than the
    /// bytes it actually sends — which is the abuse shape: announce 8 MiB, send one chunk, pin
    /// the buffer, never complete.
    /// The chunk_count a given `total_len` must declare to satisfy the parser's consistency
    /// rule (`(count-1)*MAX_FRAGMENT_PAYLOAD < total_len <= count*MAX_FRAGMENT_PAYLOAD`).
    ///
    /// That rule is itself a defence — it stops a peer declaring 8 MiB in two chunks — but it
    /// does NOT stop the attack #911 is about: the peer declares 8 MiB across a valid 140
    /// chunks and then sends one of them, pinning the buffer without completing it.
    fn chunks_for(total_len: usize) -> u16 {
        total_len.div_ceil(MAX_FRAGMENT_PAYLOAD) as u16
    }

    fn frag(message_id: u64, idx: u16, count: u16, total_len: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(FRAGMENT_HEADER_LEN + payload.len());
        f.extend_from_slice(&FRAGMENT_MAGIC);
        f.extend_from_slice(&message_id.to_le_bytes());
        f.extend_from_slice(&idx.to_le_bytes());
        f.extend_from_slice(&count.to_le_bytes());
        f.extend_from_slice(&total_len.to_le_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// The bug (#911): per-source caps bound ONE address, not the process. Many distinct
    /// connections — each individually well inside `MAX_INBOUND_PER_IP` and
    /// `MAX_INBOUND_PER_SUBNET`, so those caps cannot be what stops this — must not be able to
    /// pin unbounded memory between them.
    #[test]
    fn many_connections_cannot_exceed_the_global_budget() {
        const SLOT: usize = 1024 * 1024; // 1 MiB declared per message
        let budget = ReassemblyBudget::new(4 * SLOT); // room for 4

        // 40 separate connections, far more than the budget allows to hold at once.
        let mut conns: Vec<FragmentReassembler> = (0..40)
            .map(|_| FragmentReassembler::with_budget(budget.clone()))
            .collect();

        for (i, c) in conns.iter_mut().enumerate() {
            // Declare a 1 MiB message, send only its first chunk, never complete it.
            let f = frag(i as u64 + 1, 0, chunks_for(SLOT), SLOT as u32, &[0u8; 64]);
            let _ = c.accept(f);
            let (held, _, _) = budget.stats();
            assert!(
                held <= 4 * SLOT,
                "held {held} exceeded the budget {} after {} connections",
                4 * SLOT,
                i + 1
            );
        }

        let (held, evictions, _) = budget.stats();
        assert!(held <= 4 * SLOT, "final held {held} over budget");
        assert!(
            evictions > 0,
            "40 connections each declaring 1 MiB against a 4 MiB budget must have evicted"
        );
    }

    /// LRU, not newest-drop. An attacker's buffers are by construction the ones NOT completing,
    /// so the stalest partial is the right victim; evicting the newest arrival would punish the
    /// honest peer that just started sending.
    #[test]
    fn the_eviction_victim_is_the_stalest_partial() {
        const SLOT: usize = 1024 * 1024;
        let budget = ReassemblyBudget::new(2 * SLOT);

        let mut a = FragmentReassembler::with_budget(budget.clone());
        let mut b = FragmentReassembler::with_budget(budget.clone());
        let mut c = FragmentReassembler::with_budget(budget.clone());

        // a first, then b: a is the stalest.
        a.accept(frag(1, 0, chunks_for(SLOT), SLOT as u32, &[0u8; 64]))
            .unwrap();
        b.accept(frag(2, 0, chunks_for(SLOT), SLOT as u32, &[0u8; 64]))
            .unwrap();
        assert!(a.slot.lock().is_some(), "a should hold a partial");
        assert!(b.slot.lock().is_some(), "b should hold a partial");

        // c arrives and does not fit: a — the stalest — must be the one dropped.
        c.accept(frag(3, 0, chunks_for(SLOT), SLOT as u32, &[0u8; 64]))
            .unwrap();

        assert!(
            a.slot.lock().is_none(),
            "the STALEST partial (a) must be evicted"
        );
        assert!(
            b.slot.lock().is_some(),
            "b is newer than a and must survive — evicting it would be newest-drop, not LRU"
        );
        assert!(c.slot.lock().is_some(), "the arriving message must be held");
    }

    /// A buffer bigger than the entire budget is refused outright rather than evicting every
    /// other peer to make room for something that still cannot fit.
    #[test]
    fn a_message_larger_than_the_whole_budget_is_refused() {
        let budget = ReassemblyBudget::new(256 * 1024);
        let mut a = FragmentReassembler::with_budget(budget.clone());
        let mut victim = FragmentReassembler::with_budget(budget.clone());

        // 120 KB spans two chunks, so sending one leaves the buffer PENDING. A single-chunk
        // message would complete on arrival and hold nothing, testing nothing.
        const PENDING: usize = 120_000;
        assert!(
            chunks_for(PENDING) > 1,
            "the victim must actually stay partial"
        );
        victim
            .accept(frag(1, 0, chunks_for(PENDING), PENDING as u32, &[0u8; 64]))
            .unwrap();

        let err = a
            .accept(frag(2, 0, chunks_for(1024 * 1024), 1024 * 1024, &[0u8; 64]))
            .expect_err("a message larger than the budget must be refused");
        assert!(
            format!("{err:?}").contains("budget"),
            "the refusal must name the budget, got {err:?}"
        );
        assert!(
            victim.slot.lock().is_some(),
            "an impossible request must not evict innocent buffers on its way to failing"
        );
    }

    /// POSITIVE CONTROL. Every assertion above is about refusing or evicting, and a budget of
    /// zero would satisfy all of them. A legitimate multi-fragment message must still reassemble
    /// with the budget in force, and must release its bytes when it completes.
    #[test]
    fn a_legitimate_message_still_reassembles_and_releases_its_bytes() {
        let budget = ReassemblyBudget::new(4 * 1024 * 1024);
        let mut re = FragmentReassembler::with_budget(budget.clone());

        // ~84 KB, the real checkpoint/tree-sync shape.
        let payload: Vec<u8> = (0..84_000u32).map(|i| (i % 251) as u8).collect();
        let frames = fragment_message(&payload);
        assert!(frames.len() > 1, "this payload must actually fragment");

        let mut out = None;
        for f in frames {
            if let Some(done) = re.accept(f).expect("legitimate fragments must be accepted") {
                out = Some(done);
            }
        }
        assert_eq!(
            out.as_deref(),
            Some(payload.as_slice()),
            "the message must reassemble byte-for-byte with the budget in force"
        );

        let (held, _, rejections) = budget.stats();
        assert_eq!(held, 0, "a completed message must release its bytes");
        assert_eq!(rejections, 0, "a legitimate message must not be rejected");
    }

    /// A dropped connection returns its bytes. Without this the budget leaks until restart and
    /// eventually refuses everything — a self-inflicted outage wearing a DoS defence's clothes.
    #[test]
    fn a_dropped_connection_releases_its_reservation() {
        const SLOT: usize = 1024 * 1024;
        let budget = ReassemblyBudget::new(4 * SLOT);
        {
            let mut a = FragmentReassembler::with_budget(budget.clone());
            a.accept(frag(1, 0, chunks_for(SLOT), SLOT as u32, &[0u8; 64]))
                .unwrap();
            assert_eq!(budget.stats().0, SLOT, "the partial must be accounted");
        }
        assert_eq!(
            budget.stats().0,
            0,
            "dropping the connection must return its bytes to the budget"
        );
    }

    /// A small message is never fragmented and round-trips unchanged.
    #[test]
    fn small_message_bypasses_fragmentation() {
        let msg = b"{\"hello\":\"world\"}".to_vec();
        assert!(!needs_fragmentation(&msg));

        let mut re = FragmentReassembler::new();
        // A complete (non-fragment) frame passes straight through.
        let out = re.accept(msg.clone()).unwrap();
        assert_eq!(out, Some(msg));
    }

    /// A message larger than the transport limit fragments and reassembles to
    /// the identical bytes.
    #[test]
    fn large_message_round_trips() {
        // ~84 KB, matching the real oversized checkpoint proposal.
        let msg: Vec<u8> = (0..84_241u32).map(|i| (i % 251) as u8).collect();
        assert!(needs_fragmentation(&msg));

        let frames = fragment_message(&msg);
        assert!(frames.len() >= 2, "must split into multiple frames");
        for f in &frames {
            assert!(f.len() <= MAX_PAYLOAD_SIZE, "each frame fits a Noise frame");
            assert_eq!(&f[..4], &FRAGMENT_MAGIC);
        }

        let mut re = FragmentReassembler::new();
        let mut reassembled = None;
        for f in frames {
            if let Some(out) = re.accept(f).unwrap() {
                reassembled = Some(out);
            }
        }
        assert_eq!(reassembled, Some(msg));
    }

    /// A message exactly at the boundary is not fragmented; one byte over is.
    #[test]
    fn boundary_sizes() {
        let at = vec![0u8; MAX_PAYLOAD_SIZE];
        assert!(!needs_fragmentation(&at));

        let over = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(needs_fragmentation(&over));
        let frames = fragment_message(&over);
        let mut re = FragmentReassembler::new();
        let mut out = None;
        for f in frames {
            if let Some(o) = re.accept(f).unwrap() {
                out = Some(o);
            }
        }
        assert_eq!(out, Some(over));
    }

    /// A multi-chunk message that is an exact multiple of the chunk size.
    #[test]
    fn multi_chunk_exact_multiple() {
        let msg = vec![7u8; MAX_FRAGMENT_PAYLOAD * 3];
        let frames = fragment_message(&msg);
        assert_eq!(frames.len(), 3);
        let mut re = FragmentReassembler::new();
        let mut out = None;
        for f in frames {
            if let Some(o) = re.accept(f).unwrap() {
                out = Some(o);
            }
        }
        assert_eq!(out, Some(msg));
    }

    /// Two fragmented messages back-to-back on the same reassembler both
    /// reassemble (models sequential sends over one connection).
    #[test]
    fn sequential_messages_reuse_slot() {
        let a: Vec<u8> = (0..70_000u32).map(|i| i as u8).collect();
        let b: Vec<u8> = (0..90_000u32).map(|i| (i / 3) as u8).collect();

        let mut re = FragmentReassembler::new();
        let mut got_a = None;
        for f in fragment_message(&a) {
            if let Some(o) = re.accept(f).unwrap() {
                got_a = Some(o);
            }
        }
        let mut got_b = None;
        for f in fragment_message(&b) {
            if let Some(o) = re.accept(f).unwrap() {
                got_b = Some(o);
            }
        }
        assert_eq!(got_a, Some(a));
        assert_eq!(got_b, Some(b));
    }

    /// A duplicate chunk index is rejected and clears partial state.
    #[test]
    fn duplicate_chunk_rejected() {
        let msg = vec![1u8; MAX_FRAGMENT_PAYLOAD * 2];
        let frames = fragment_message(&msg);
        let mut re = FragmentReassembler::new();
        assert!(re.accept(frames[0].clone()).unwrap().is_none());
        // Re-send the same first chunk -> duplicate.
        let err = re.accept(frames[0].clone()).unwrap_err();
        assert!(matches!(err, NoiseError::Decryption(_)));
        assert!(re.slot.lock().is_none(), "partial state cleared on error");
    }

    /// A chunk whose index is >= chunk_count is rejected.
    #[test]
    fn out_of_range_index_rejected() {
        let msg = vec![2u8; MAX_FRAGMENT_PAYLOAD * 2];
        let mut frame = fragment_message(&msg)[0].clone();
        // Overwrite chunk_index (bytes 12..14) with an out-of-range value.
        frame[12..14].copy_from_slice(&5u16.to_le_bytes());
        let mut re = FragmentReassembler::new();
        let err = re.accept(frame).unwrap_err();
        assert!(matches!(err, NoiseError::Decryption(_)));
    }

    /// A header claiming more than MAX_FRAGMENT_COUNT chunks is rejected.
    #[test]
    fn oversized_chunk_count_rejected() {
        let msg = vec![3u8; MAX_FRAGMENT_PAYLOAD * 2];
        let mut frame = fragment_message(&msg)[0].clone();
        frame[14..16].copy_from_slice(&((MAX_FRAGMENT_COUNT + 1) as u16).to_le_bytes());
        let mut re = FragmentReassembler::new();
        let err = re.accept(frame).unwrap_err();
        assert!(matches!(err, NoiseError::Decryption(_)));
    }

    /// A header claiming a total_len above the reassembly cap is rejected
    /// before any large buffer is allocated.
    #[test]
    fn oversized_total_len_rejected() {
        let msg = vec![4u8; MAX_FRAGMENT_PAYLOAD * 2];
        let mut frame = fragment_message(&msg)[0].clone();
        frame[16..20].copy_from_slice(&((MAX_REASSEMBLY_SIZE + 1) as u32).to_le_bytes());
        let mut re = FragmentReassembler::new();
        let err = re.accept(frame).unwrap_err();
        assert!(matches!(err, NoiseError::Decryption(_)));
    }

    /// A missing chunk means the message never completes (returns None), and no
    /// spurious output is produced.
    #[test]
    fn missing_chunk_never_completes() {
        let msg = vec![9u8; MAX_FRAGMENT_PAYLOAD * 3];
        let frames = fragment_message(&msg);
        let mut re = FragmentReassembler::new();
        // Deliver only chunks 0 and 2.
        assert!(re.accept(frames[0].clone()).unwrap().is_none());
        assert!(re.accept(frames[2].clone()).unwrap().is_none());
        // Message is still incomplete; slot retained awaiting chunk 1.
        assert!(re.slot.lock().is_some());
    }

    /// The fragment magic can never collide with a serde_json envelope, which
    /// always begins with `{`.
    #[test]
    fn magic_disjoint_from_json_envelope() {
        assert_ne!(FRAGMENT_MAGIC[0], b'{');
        assert_eq!(FRAGMENT_MAGIC[0], b'G');
    }
}
