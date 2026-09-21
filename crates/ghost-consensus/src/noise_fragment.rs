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
use std::sync::Arc;
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

/// Ceiling on what any ONE connection may hold.
///
/// ⛔ This exists because of a measured hole in the first version of this budget, which left
/// `per_conn` at [`MAX_REASSEMBLY_SIZE`]. `MAX_INBOUND_PER_IP` (8) x 8 MiB is 67,108,864 bytes
/// — EXACTLY [`REASSEMBLY_BUDGET_BYTES`]. One address, inside its own per-IP cap, could hold
/// 100% of the budget and so decide who got evicted.
///
/// Grounded in what a legitimate message can actually be rather than in the reassembly cap:
/// the largest per-type limit `message_validator` will accept is `MAX_ZK_PROPOSAL_SIZE`
/// (2,000,000 bytes), and every other type is at or below 1.1 MB. 3 MiB is comfortable headroom
/// over that, and anything larger is refused by the validator AFTER reassembly anyway — so
/// declining to buffer it here is strictly cheaper, and refuses earlier.
///
/// With this, one address's full inbound allowance reaches 24 MiB of the 64 MiB budget rather
/// than all of it. `one_ip_cannot_corner_the_budget` pins the relationship.
pub const REASSEMBLY_PER_CONN_BYTES: usize = 3 * 1024 * 1024;

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

/// One connection's reassembly state, owned by the budget.
///
/// ⛔ The buffers live HERE, not in the `FragmentReassembler`, and that is the whole design.
/// The first attempt kept them per-connection behind their own mutex and had the budget reach
/// in to evict. That needed a documented budget->slot lock order, and it still left a window
/// between reserving and writing in which a connection could be evicted and then repopulate
/// itself — leaving a live buffer the budget accounted as zero and, because the victim filter
/// skipped zero-byte entries, could never evict again. Owning the state removes the second
/// lock, the ordering rule and the race together.
struct Entry {
    slot: Option<InFlight>,
    /// Always equal to `slot.received_bytes`, or 0 when there is no slot. Maintained here so
    /// the sum over entries is `held` by construction rather than by agreement.
    bytes: usize,
    /// Monotonic touch counter — the LRU key. A counter, not an `Instant`, so the victim is
    /// deterministic in tests instead of depending on clock resolution.
    seq: u64,
}

struct BudgetInner {
    limit: usize,
    per_conn: usize,
    held: usize,
    entries: HashMap<u64, Entry>,
    next_id: u64,
    next_seq: u64,
    evictions: u64,
    rejections: u64,
    /// Rate limiting for the eviction log. Unbounded logging under attacker control is a
    /// log-amplification DoS wearing the defence's clothes — on nodes with 3,867 MiB of RAM
    /// and journald on disk, that is not a theoretical cost.
    last_log: Option<Instant>,
    suppressed: u64,
}

/// How often the eviction path may log, however fast evictions arrive.
const EVICTION_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// A process-wide byte budget over every connection's reassembly buffer (#911).
///
/// ## What is charged
///
/// **Bytes actually received**, never the declared `total_len`.
///
/// Charging the declared length looks more conservative and is far more dangerous. A peer only
/// has to send one 60 KB chunk to hold an 8 MiB charge, so eight sockets from a single address
/// — exactly `MAX_INBOUND_PER_IP`, so the per-IP cap does not stop them — pin the entire 64 MiB
/// budget with about 469 KiB of real memory, a 140x amplification. From that point every
/// reservation must evict, and the attacker's drips keep their own entries fresh, so the LRU
/// victim is always an honest peer part-way through a checkpoint. Its slot is cleared, its
/// remaining fragments land in a fresh buffer, the message never completes, and NOTHING is
/// reported to either side. That is the "proposal data missing — requesting tree sync" churn
/// this module exists to remove: a memory DoS traded for a cheaper, quieter suppression DoS.
///
/// Charging real bytes removes the amplification entirely: pinning N bytes of budget costs an
/// attacker N bytes of traffic, and the budget measures the thing it is defending.
///
/// ## Why eviction is the last resort, not the normal path
///
/// A stale entry — one whose message has not progressed within [`REASSEMBLY_TIMEOUT`] — is
/// freed before any live entry is considered. Without that the timeout is decorative: it is
/// only ever evaluated when the same connection sends another fragment, and inbound
/// connections have no idle timeout and are not in the pool, so a peer that goes silent holds
/// its buffer for the life of the socket.
pub struct ReassemblyBudget {
    inner: Arc<Mutex<BudgetInner>>,
}

impl Clone for ReassemblyBudget {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl ReassemblyBudget {
    pub fn new(limit: usize) -> Self {
        Self::with_per_conn(limit, REASSEMBLY_PER_CONN_BYTES.min(limit))
    }

    /// `per_conn` bounds what any ONE connection may hold, so a single peer cannot corner the
    /// budget and turn eviction against everyone else.
    pub fn with_per_conn(limit: usize, per_conn: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BudgetInner {
                limit,
                per_conn,
                held: 0,
                entries: HashMap::new(),
                next_id: 1,
                next_seq: 1,
                evictions: 0,
                rejections: 0,
                last_log: None,
                suppressed: 0,
            })),
        }
    }

    fn register(&self) -> u64 {
        let mut g = self.inner.lock();
        let id = g.next_id;
        g.next_id += 1;
        let seq = g.next_seq;
        g.next_seq += 1;
        g.entries.insert(
            id,
            Entry {
                slot: None,
                bytes: 0,
                seq,
            },
        );
        id
    }

    fn unregister(&self, id: u64) {
        // Take the buffer out under the lock, drop it after. Freeing up to 8 MiB of `Vec`s
        // inside the global lock serialises every other connection behind a large deallocation.
        let victim = {
            let mut g = self.inner.lock();
            match g.entries.remove(&id) {
                Some(e) => {
                    g.held = g.held.saturating_sub(e.bytes);
                    e.slot
                }
                None => None,
            }
        };
        drop(victim);
    }

    /// Bytes held, evictions, rejections. Held is real occupancy, not declared.
    pub fn stats(&self) -> (usize, u64, u64) {
        let g = self.inner.lock();
        (g.held, g.evictions, g.rejections)
    }

    /// Age an entry's buffer, so the stale-first eviction path is testable without waiting
    /// out [`REASSEMBLY_TIMEOUT`]. A test that cannot reach the stale branch would assert the
    /// LRU fallback and call it stale-first.
    #[cfg(test)]
    fn backdate(&self, id: u64, by: Duration) {
        let mut g = self.inner.lock();
        if let Some(e) = g.entries.get_mut(&id) {
            if let Some(slot) = e.slot.as_mut() {
                slot.started_at = slot
                    .started_at
                    .checked_sub(by)
                    .expect("test backdate must not underflow the clock");
            }
        }
    }

    /// Current limit and per-connection cap, for reporting.
    pub fn limits(&self) -> (usize, usize) {
        let g = self.inner.lock();
        (g.limit, g.per_conn)
    }

    /// The whole of `accept`'s stateful half, run under ONE lock.
    ///
    /// Everything that reads or writes a buffer happens here, so there is no second lock to
    /// order against and no window in which accounting and reality can disagree.
    fn accept_fragment(
        &self,
        id: u64,
        header: &FragmentHeader,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        // Buffers to free AFTER the lock is released.
        let mut reclaimed: Vec<InFlight> = Vec::new();
        let result = self.accept_locked(id, header, payload, &mut reclaimed);
        drop(reclaimed);
        result
    }

    fn accept_locked(
        &self,
        id: u64,
        header: &FragmentHeader,
        payload: Vec<u8>,
        reclaimed: &mut Vec<InFlight>,
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        let mut g = self.inner.lock();

        // A connection whose entry has gone (dropped concurrently) cannot reassemble.
        if !g.entries.contains_key(&id) {
            return Err(NoiseError::Decryption(
                "fragment: reassembler is no longer registered".into(),
            ));
        }

        // ---- reset if this is a new message, a different one, or a stale one
        let need_reset = match g.entries[&id].slot.as_ref() {
            None => true,
            Some(cur) => {
                cur.message_id != header.message_id
                    || cur.chunk_count != header.chunk_count
                    || cur.started_at.elapsed() > REASSEMBLY_TIMEOUT
            }
        };
        if need_reset {
            let e = g.entries.get_mut(&id).expect("checked above");
            let freed = e.bytes;
            if let Some(old) = e.slot.take() {
                reclaimed.push(old);
            }
            e.bytes = 0;
            g.held = g.held.saturating_sub(freed);

            let e = g.entries.get_mut(&id).expect("checked above");
            e.slot = Some(InFlight {
                message_id: header.message_id,
                chunk_count: header.chunk_count,
                total_len: header.total_len,
                chunks: vec![None; header.chunk_count],
                received_bytes: 0,
                received_count: 0,
                started_at: Instant::now(),
            });
        }

        // ---- validate against the slot we now have
        {
            let slot = g.entries[&id].slot.as_ref().expect("set above");
            if slot.total_len != header.total_len {
                Self::clear(&mut g, id, reclaimed);
                return Err(NoiseError::Decryption(
                    "fragment: total_len changed mid-message".into(),
                ));
            }
            if slot.chunks[header.chunk_index].is_some() {
                Self::clear(&mut g, id, reclaimed);
                return Err(NoiseError::Decryption("fragment: duplicate chunk".into()));
            }
            if slot.received_bytes + payload.len() > slot.total_len {
                Self::clear(&mut g, id, reclaimed);
                return Err(NoiseError::Decryption(
                    "fragment: received bytes exceed total_len".into(),
                ));
            }
        }

        // ---- admit the bytes we are ACTUALLY about to hold
        let delta = payload.len();
        let have = g.entries[&id].bytes;

        if have + delta > g.per_conn {
            Self::clear(&mut g, id, reclaimed);
            g.rejections += 1;
            return Err(NoiseError::Decryption(
                "fragment: per-connection reassembly quota exceeded".into(),
            ));
        }

        if !Self::make_room(&mut g, id, delta, reclaimed) {
            Self::clear(&mut g, id, reclaimed);
            g.rejections += 1;
            return Err(NoiseError::Decryption(
                "fragment: reassembly budget exhausted".into(),
            ));
        }

        // ---- write it
        let seq = g.next_seq;
        g.next_seq += 1;
        let e = g.entries.get_mut(&id).expect("checked above");
        e.seq = seq;
        e.bytes += delta;
        let slot = e.slot.as_mut().expect("set above");
        slot.received_bytes += delta;
        slot.chunks[header.chunk_index] = Some(payload);
        slot.received_count += 1;
        g.held += delta;

        let complete = {
            let slot = g.entries[&id].slot.as_ref().expect("set above");
            slot.received_count == slot.chunk_count
        };
        if !complete {
            return Ok(None);
        }

        // ---- complete: the bytes become the caller's, not ours
        let e = g.entries.get_mut(&id).expect("checked above");
        let freed = e.bytes;
        let slot = e.slot.take().expect("set above");
        e.bytes = 0;
        g.held = g.held.saturating_sub(freed);
        drop(g);

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

    /// Drop `id`'s buffer and its accounting together.
    fn clear(g: &mut BudgetInner, id: u64, reclaimed: &mut Vec<InFlight>) {
        if let Some(e) = g.entries.get_mut(&id) {
            let freed = e.bytes;
            if let Some(old) = e.slot.take() {
                reclaimed.push(old);
            }
            e.bytes = 0;
            g.held = g.held.saturating_sub(freed);
        }
    }

    /// Make space for `delta` more bytes for `id`, stale entries first.
    ///
    /// Returns false when even evicting everything evictable leaves no room, so the caller
    /// refuses the fragment rather than allocating anyway.
    fn make_room(
        g: &mut BudgetInner,
        id: u64,
        delta: usize,
        reclaimed: &mut Vec<InFlight>,
    ) -> bool {
        if delta > g.limit {
            return false;
        }
        while g.held + delta > g.limit {
            // STALE FIRST. A buffer that has not progressed within REASSEMBLY_TIMEOUT is the
            // one actually leaking, and freeing it costs an honest peer nothing. Only when
            // none is stale does this fall back to LRU.
            let stale = g
                .entries
                .iter()
                .filter(|(vid, e)| {
                    **vid != id
                        && e.bytes > 0
                        && e.slot
                            .as_ref()
                            .is_some_and(|s| s.started_at.elapsed() > REASSEMBLY_TIMEOUT)
                })
                .min_by_key(|(_, e)| e.seq)
                .map(|(vid, _)| *vid);

            let victim = stale.or_else(|| {
                g.entries
                    .iter()
                    .filter(|(vid, e)| **vid != id && e.bytes > 0)
                    .min_by_key(|(_, e)| e.seq)
                    .map(|(vid, _)| *vid)
            });

            let Some(vid) = victim else {
                return false;
            };
            let was_stale = stale.is_some();

            let freed = {
                let e = g.entries.get_mut(&vid).expect("victim present");
                let freed = e.bytes;
                if let Some(old) = e.slot.take() {
                    reclaimed.push(old);
                }
                e.bytes = 0;
                freed
            };
            g.held = g.held.saturating_sub(freed);
            g.evictions += 1;

            // Rate-limited: an attacker choosing the eviction rate must not also choose the
            // log rate.
            let now = Instant::now();
            let due = g
                .last_log
                .is_none_or(|t| now.duration_since(t) >= EVICTION_LOG_INTERVAL);
            if due {
                let suppressed = std::mem::take(&mut g.suppressed);
                g.last_log = Some(now);
                tracing::warn!(
                    evicted_bytes = freed,
                    stale = was_stale,
                    held = g.held,
                    limit = g.limit,
                    evictions_total = g.evictions,
                    suppressed_since_last_log = suppressed,
                    "reassembly budget under pressure — evicted a partial message (#911)"
                );
            } else {
                g.suppressed += 1;
            }
        }
        true
    }
}

/// The process-wide budget every connection shares.
///
/// `GHOST_REASSEMBLY_BUDGET_BYTES` overrides it, so the limit can be retuned on a live fleet
/// without a rebuild. Values below [`MAX_REASSEMBLY_SIZE`] are refused: a budget smaller than
/// one legal message would reject honest checkpoints rather than merely evict them.
static GLOBAL_BUDGET: once_cell::sync::Lazy<ReassemblyBudget> = once_cell::sync::Lazy::new(|| {
    let limit = std::env::var("GHOST_REASSEMBLY_BUDGET_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v >= MAX_REASSEMBLY_SIZE)
        .unwrap_or(REASSEMBLY_BUDGET_BYTES);
    ReassemblyBudget::new(limit)
});

/// Handle to the process-wide reassembly budget (#911).
pub fn global_budget() -> ReassemblyBudget {
    GLOBAL_BUDGET.clone()
}

/// Reassembles fragmented Noise messages for a single connection.
///
/// The buffer itself lives in the shared [`ReassemblyBudget`]; this is the connection's handle
/// to it. See that type for why.
pub struct FragmentReassembler {
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
        // eventually refuses everything — a self-inflicted outage wearing a DoS defence's
        // clothes.
        self.budget.unregister(self.id);
    }
}

impl FragmentReassembler {
    /// Create an empty reassembler sharing the process-wide budget.
    pub fn new() -> Self {
        Self::with_budget(global_budget())
    }

    /// Create one against a specific budget. Used by tests to exercise exhaustion without
    /// allocating 64 MiB.
    pub fn with_budget(budget: ReassemblyBudget) -> Self {
        let id = budget.register();
        Self { budget, id }
    }

    /// Feed one received Noise frame.
    ///
    /// * A non-fragment frame is returned as `Ok(Some(bytes))` immediately
    ///   (complete-message fast path — it never touches the budget).
    /// * A fragment that completes a message returns `Ok(Some(bytes))`.
    /// * A fragment that does not yet complete a message returns `Ok(None)`.
    /// * A malformed / duplicate / oversized fragment, or one that cannot be admitted, returns
    ///   `Err(..)` and the partial state is discarded so a subsequent message is not poisoned.
    pub fn accept(&mut self, frame: Vec<u8>) -> Result<Option<Vec<u8>>, NoiseError> {
        let (header, payload) = match FragmentHeader::parse(&frame)? {
            None => return Ok(Some(frame)), // Complete single message.
            Some((h, p)) => (h, p.to_vec()),
        };
        self.budget.accept_fragment(self.id, &header, payload)
    }

    /// The bytes this connection currently holds, for tests and diagnostics.
    #[cfg(test)]
    fn held_bytes(&self) -> usize {
        let g = self.budget.inner.lock();
        g.entries.get(&self.id).map(|e| e.bytes).unwrap_or(0)
    }

    #[cfg(test)]
    fn has_slot(&self) -> bool {
        let g = self.budget.inner.lock();
        g.entries.get(&self.id).is_some_and(|e| e.slot.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------- #911: global budget

    /// Build one fragment frame by hand so a test can declare a `total_len` far larger than the
    /// bytes it actually sends — which is the abuse shape: announce 8 MiB, send one chunk, pin
    /// the buffer, never complete.
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

    /// The chunk_count a given `total_len` must declare to satisfy the parser's consistency
    /// rule. That rule stops a peer declaring 8 MiB in two chunks, but not declaring it in a
    /// valid 140 and then sending one of them.
    fn chunks_for(total_len: usize) -> u16 {
        total_len.div_ceil(MAX_FRAGMENT_PAYLOAD) as u16
    }

    /// ⛔ THE REGRESSION TEST FOR THE FIRST ATTEMPT'S VULNERABILITY.
    ///
    /// The first version of this budget charged the DECLARED `total_len`. Eight sockets from a
    /// single address — exactly `MAX_INBOUND_PER_IP`, so the per-IP cap does not stop them —
    /// each declaring 8 MiB and sending one 60 KB chunk pinned the entire 64 MiB budget with
    /// ~469 KiB of real memory, a 140x amplification. Every later reservation then had to
    /// evict, and since the attacker's drips kept their own entries fresh, the victim was
    /// always an honest peer mid-checkpoint — whose message then silently never completed.
    ///
    /// Charging real bytes is what makes that impossible, so this pins it directly.
    #[test]
    fn declared_length_cannot_pin_the_budget() {
        const BUDGET: usize = 1024 * 1024;
        let budget = ReassemblyBudget::new(BUDGET);

        // Eight connections, each DECLARING a large message and sending one tiny chunk.
        let mut attackers: Vec<FragmentReassembler> = (0..8)
            .map(|_| FragmentReassembler::with_budget(budget.clone()))
            .collect();
        const DECLARED: usize = 600_000;
        for (i, a) in attackers.iter_mut().enumerate() {
            a.accept(frag(
                i as u64 + 1,
                0,
                chunks_for(DECLARED),
                DECLARED as u32,
                &[0u8; 64],
            ))
            .expect("the drip itself is legal");
        }

        let (held, evictions, _) = budget.stats();
        assert_eq!(
            held,
            8 * 64,
            "the budget must charge BYTES RECEIVED (8 x 64), not bytes declared \
             (8 x {DECLARED}) — charging declared is the 140x amplification that let one IP \
             corner the whole budget"
        );
        assert_eq!(
            evictions, 0,
            "eight tiny drips must not have caused a single eviction"
        );

        // And the honest peer that follows is served normally, not evicted.
        let mut honest = FragmentReassembler::with_budget(budget.clone());
        let payload: Vec<u8> = (0..84_000u32).map(|i| (i % 251) as u8).collect();
        let mut out = None;
        for f in fragment_message(&payload) {
            if let Some(done) = honest.accept(f).expect("honest traffic must be admitted") {
                out = Some(done);
            }
        }
        assert_eq!(
            out.as_deref(),
            Some(payload.as_slice()),
            "an honest checkpoint must still complete while the drips are parked — suppressing \
             it is the quieter DoS the first design traded the memory DoS for"
        );
    }

    /// ⛔ THE INVARIANT THE FIRST VERSION BROKE, pinned as arithmetic.
    ///
    /// `MAX_INBOUND_PER_IP` x the per-connection cap must stay a MINORITY of the budget. In the
    /// first version the per-connection cap was `MAX_REASSEMBLY_SIZE` (8 MiB) and 8 x 8 MiB was
    /// exactly `REASSEMBLY_BUDGET_BYTES`, so one address — entirely inside its own per-IP cap —
    /// could hold 100% of the budget and thereby choose who got evicted.
    ///
    /// This is arithmetic over constants, so it fails the moment anyone retunes one of them
    /// into that shape again.
    #[test]
    fn one_ip_cannot_corner_the_budget() {
        let per_ip = crate::mesh::MAX_INBOUND_PER_IP * REASSEMBLY_PER_CONN_BYTES;
        assert!(
            per_ip * 2 <= REASSEMBLY_BUDGET_BYTES,
            "one IP can hold {per_ip} of {REASSEMBLY_BUDGET_BYTES} bytes — a single address must \
             not reach half the budget, or it decides who gets evicted"
        );

        // And the cap must still clear the largest message the validator would ever accept,
        // or honest traffic is refused before it is even parsed.
        assert!(
            REASSEMBLY_PER_CONN_BYTES > crate::message_validator::MAX_ZK_PROPOSAL_SIZE,
            "the per-connection cap must exceed the largest legitimate message"
        );
    }

    /// Real bytes ARE bounded: many connections sending full chunks cannot exceed the budget.
    #[test]
    fn real_bytes_are_bounded_across_many_connections() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        const BUDGET: usize = 4 * CHUNK;
        let budget = ReassemblyBudget::new(BUDGET);

        // Each declares a 2-chunk message and sends chunk 0 in full, so it stays partial.
        let declared = 2 * CHUNK;
        let mut conns: Vec<FragmentReassembler> = (0..40)
            .map(|_| FragmentReassembler::with_budget(budget.clone()))
            .collect();
        for (i, c) in conns.iter_mut().enumerate() {
            let _ = c.accept(frag(
                i as u64 + 1,
                0,
                chunks_for(declared),
                declared as u32,
                &vec![7u8; CHUNK],
            ));
            let (held, _, _) = budget.stats();
            assert!(held <= BUDGET, "held {held} exceeded budget {BUDGET}");
        }
        let (held, evictions, _) = budget.stats();
        assert!(held <= BUDGET, "final held {held} over budget");
        assert!(
            evictions > 0,
            "40 full chunks against a 4-chunk budget must evict"
        );
    }

    /// A connection cannot corner the budget on its own, however much it sends.
    #[test]
    fn one_connection_cannot_exceed_its_per_connection_quota() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::with_per_conn(100 * CHUNK, 2 * CHUNK);
        let mut hog = FragmentReassembler::with_budget(budget.clone());

        let declared = 8 * CHUNK;
        let count = chunks_for(declared);

        // ⚠ Check the chunk that CROSSES the quota, not the last one sent. A rejection clears
        // the partial, so the fragment after it legitimately starts a fresh buffer and
        // succeeds — reading only the last result would miss the refusal entirely.
        let mut first_err = None;
        for i in 0..4u16 {
            let r = hog.accept(frag(1, i, count, declared as u32, &vec![9u8; CHUNK]));
            if let Err(e) = r {
                first_err = Some(e);
                break;
            }
            assert!(
                hog.held_bytes() <= 2 * CHUNK,
                "held {} exceeded the quota mid-loop",
                hog.held_bytes()
            );
        }
        let err = first_err.expect("the per-connection quota must stop this connection");
        assert!(
            format!("{err:?}").contains("per-connection"),
            "the refusal must name the quota, got {err:?}"
        );
        assert!(
            budget.stats().0 <= 2 * CHUNK,
            "one connection held more than its quota"
        );
    }

    /// Stale first, then LRU. A buffer that has not progressed within REASSEMBLY_TIMEOUT is the
    /// one actually leaking; freeing it costs an honest peer nothing.
    #[test]
    fn eviction_takes_the_stale_buffer_before_a_live_one() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(2 * CHUNK);

        let mut stale = FragmentReassembler::with_budget(budget.clone());
        let mut live = FragmentReassembler::with_budget(budget.clone());
        let mut arriving = FragmentReassembler::with_budget(budget.clone());

        let declared = 2 * CHUNK;
        let count = chunks_for(declared);
        // ⚠ ORDER MATTERS, and getting it wrong made this test worthless. `live` is touched
        // FIRST so it holds the LOWER seq and is what a pure-LRU policy would evict. The stale
        // buffer is touched SECOND, so only a stale-first policy picks it. With the touches the
        // other way round both policies choose the same victim and the test passes against
        // either — a mutation (stale-first -> pure LRU) proved exactly that by staying green.
        live.accept(frag(2, 0, count, declared as u32, &vec![2u8; CHUNK]))
            .unwrap();
        stale
            .accept(frag(1, 0, count, declared as u32, &vec![1u8; CHUNK]))
            .unwrap();

        budget.backdate(stale.id, REASSEMBLY_TIMEOUT + Duration::from_secs(1));

        arriving
            .accept(frag(3, 0, count, declared as u32, &vec![3u8; CHUNK]))
            .unwrap();

        assert!(
            !stale.has_slot(),
            "the STALE buffer must be evicted first — it is the one actually leaking"
        );
        assert!(
            live.has_slot(),
            "a live buffer must survive while a stale one exists, even though it is older by \
             LRU order"
        );
        assert!(arriving.has_slot(), "the arriving message must be held");
    }

    /// With nothing stale, the victim is the least-recently-used.
    #[test]
    fn with_nothing_stale_the_victim_is_least_recently_used() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(2 * CHUNK);
        let mut a = FragmentReassembler::with_budget(budget.clone());
        let mut b = FragmentReassembler::with_budget(budget.clone());
        let mut c = FragmentReassembler::with_budget(budget.clone());

        let declared = 2 * CHUNK;
        let count = chunks_for(declared);
        a.accept(frag(1, 0, count, declared as u32, &vec![1u8; CHUNK]))
            .unwrap();
        b.accept(frag(2, 0, count, declared as u32, &vec![2u8; CHUNK]))
            .unwrap();
        c.accept(frag(3, 0, count, declared as u32, &vec![3u8; CHUNK]))
            .unwrap();

        assert!(!a.has_slot(), "the stalest by LRU (a) must be evicted");
        assert!(b.has_slot(), "b must survive");
        assert!(c.has_slot(), "the arrival must be held");
    }

    /// POSITIVE CONTROL. Every assertion above is about refusing, evicting or not-charging, and
    /// a budget that admitted nothing would satisfy several of them. A legitimate ~84 KB
    /// checkpoint must still reassemble byte-for-byte and release its bytes on completion.
    #[test]
    fn a_legitimate_message_still_reassembles_and_releases_its_bytes() {
        let budget = ReassemblyBudget::new(4 * 1024 * 1024);
        let mut re = FragmentReassembler::with_budget(budget.clone());

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
    /// eventually refuses everything.
    #[test]
    fn a_dropped_connection_releases_its_bytes() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(4 * CHUNK);
        let declared = 2 * CHUNK;
        {
            let mut a = FragmentReassembler::with_budget(budget.clone());
            a.accept(frag(
                1,
                0,
                chunks_for(declared),
                declared as u32,
                &vec![5u8; CHUNK],
            ))
            .unwrap();
            assert_eq!(budget.stats().0, CHUNK, "the partial must be accounted");
            assert_eq!(a.held_bytes(), CHUNK);
        }
        assert_eq!(
            budget.stats().0,
            0,
            "dropping the connection must return its bytes to the budget"
        );
    }

    /// `held` must equal the sum of per-entry bytes after any mix of operations, or the ceiling
    /// is arithmetic rather than a guarantee.
    #[test]
    fn held_always_equals_the_sum_of_entries() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(3 * CHUNK);
        let declared = 2 * CHUNK;
        let count = chunks_for(declared);

        let mut conns: Vec<FragmentReassembler> = (0..6)
            .map(|_| FragmentReassembler::with_budget(budget.clone()))
            .collect();
        for (i, c) in conns.iter_mut().enumerate() {
            let _ = c.accept(frag(
                i as u64 + 1,
                0,
                count,
                declared as u32,
                &vec![1u8; CHUNK],
            ));
            let _ = c.accept(frag(
                i as u64 + 1,
                1,
                count,
                declared as u32,
                &vec![1u8; CHUNK],
            ));
        }
        let g = budget.inner.lock();
        let sum: usize = g.entries.values().map(|e| e.bytes).sum();
        assert_eq!(g.held, sum, "held drifted from the sum of entries");
        assert!(g.held <= g.limit, "held {} over limit {}", g.held, g.limit);
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
        assert!(!re.has_slot(), "partial state cleared on error");
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
        assert!(re.has_slot());
    }

    /// The fragment magic can never collide with a serde_json envelope, which
    /// always begins with `{`.
    #[test]
    fn magic_disjoint_from_json_envelope() {
        assert_ne!(FRAGMENT_MAGIC[0], b'{');
        assert_eq!(FRAGMENT_MAGIC[0], b'G');
    }
}
