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
/// [`MAX_REASSEMBLY_SIZE`] bounds ONE message from ONE peer; it does not bound the process,
/// because the reassembler is per-connection. Nothing counted the aggregate.
///
/// ⛔ SIZED AGAINST `MAX_INBOUND_PER_SUBNET`, NOT `MAX_INBOUND_PER_IP`. The threat model is
/// addresses spread across a `/24`, which is what makes the per-IP cap insufficient in the
/// first place — so bounding one IP's share and calling it done measures the wrong thing. An
/// earlier revision did exactly that: it capped one IP at 37.5% while one `/24` legally held
/// **75%** of the budget and therefore still chose every eviction victim.
///
/// The relationship that has to hold is
/// `MAX_INBOUND_PER_SUBNET * REASSEMBLY_PER_CONN_BYTES * 2 <= REASSEMBLY_BUDGET_BYTES`,
/// asserted by `one_subnet_cannot_corner_the_budget`.
///
/// 96 MiB against the nodes' 3,867 MiB of RAM is ~2.5%, and only materialises if a peer
/// actually sends the bytes — the budget charges what arrived, never what was declared.
pub const REASSEMBLY_BUDGET_BYTES: usize = 96 * 1024 * 1024;

/// Ceiling on what any ONE connection may hold.
///
/// Grounded in the SERIALIZED size, because that is what this layer reassembles.
///
/// ⚠ An earlier version of this comment reasoned from `MAX_ZK_PROPOSAL_SIZE` (2,000,000) and
/// claimed "~4.9% headroom" — the same unit error the assert below was fixed for. That is a
/// cap on `envelope.payload.len()` BEFORE serialization, and `serde_json` writes `Vec<u8>` as
/// decimal integers (~3.7x, see `message_validator.rs`). The quantity actually enforced on the
/// wire is `MAX_ENVELOPE_SIZE` (1,000,000), which `validate_envelope_header` applies to the
/// serialized bytes, so real headroom here is ~110%.
///
/// Exceeding this no longer disconnects anyone: an oversized message is DROPPED and its
/// fragments poisoned, and the parse-time bound stays at `MAX_REASSEMBLY_SIZE`.
pub const REASSEMBLY_PER_CONN_BYTES: usize = 2 * 1024 * 1024;

/// The smallest budget that still keeps one `/24` a minority of it.
///
/// Derived, not chosen: any override below this reintroduces cornering, so the env knob
/// refuses it rather than accepting a number that quietly breaks the guarantee.
/// Largest budget the env override will accept.
///
/// The floor stops the budget being set so low that one `/24` corners it; this stops it being
/// set so high that it stops being a bound at all. A typo of one extra zero on a 3,867 MiB
/// node is a ~915 MiB ceiling, which is the OOM this module exists to prevent.
pub const MAX_REASSEMBLY_BUDGET_BYTES: usize = 4 * REASSEMBLY_BUDGET_BYTES;

pub const MIN_REASSEMBLY_BUDGET_BYTES: usize =
    2 * crate::mesh::MAX_INBOUND_PER_SUBNET * REASSEMBLY_PER_CONN_BYTES;

// Compile-time guarantee that a full fragment frame fits in one Noise frame.
const _: () = assert!(FRAGMENT_HEADER_LEN + MAX_FRAGMENT_PAYLOAD <= MAX_PAYLOAD_SIZE);

// ---------------------------------------------------------------------------------------
// The budget invariants, enforced AT COMPILE TIME (#911).
//
// These were runtime tests. Compile-time is strictly stronger — the relationship simply
// cannot be violated in a build — and it is the pattern this file already uses above.
//
// They are relationships between constants in three different modules, and two revisions of
// this budget shipped with one of them broken: first `MAX_INBOUND_PER_IP * per_conn` equalled
// the whole budget, then the per-IP ratio was fixed while one `/24` still held 75%. Nothing
// was checking the relationship itself, only the code around it.

/// One `/24` must not reach half the budget, or it decides who gets evicted. This is the
/// binding one: the threat model is addresses spread across a subnet, which is exactly why
/// the per-IP cap alone is insufficient.
///
/// ⚠ STRICT. `<=` permitted exactly half, while `budget_limit_from_env` refuses exactly half
/// for the identical relation — so a compiled default of 64 MiB would ship while the same
/// number supplied through the env knob was rejected, and the compiled default is the one
/// nobody has to opt into.
const _: () = assert!(
    2 * crate::mesh::MAX_INBOUND_PER_SUBNET * REASSEMBLY_PER_CONN_BYTES < REASSEMBLY_BUDGET_BYTES,
    "one /24 can reach half the reassembly budget — it would choose every eviction victim"
);

/// Follows from the above, asserted separately so a change to either cap is caught.
const _: () = assert!(
    2 * crate::mesh::MAX_INBOUND_PER_IP * REASSEMBLY_PER_CONN_BYTES < REASSEMBLY_BUDGET_BYTES,
    "one IP can reach half the reassembly budget"
);

/// The per-connection cap must clear the largest message that can legitimately reach this
/// layer, or honest traffic is DISCONNECTED rather than refused — mesh treats any accept
/// error as fatal.
///
/// ⚠ `MAX_ENVELOPE_SIZE` is the right constant and the SUFFICIENT one: `validate_envelope_header`
/// refuses any serialized envelope above it, so a per-type payload cap larger than
/// `MAX_ENVELOPE_SIZE / 3.7` is already unreachable on the wire and cannot widen what this layer
/// sees. An earlier comment promised that raising a per-type cap "must fail a test"; no such
/// test existed, and inventing one would assert a bound that is not the binding one. This assert
/// is.
const _: () = assert!(
    REASSEMBLY_PER_CONN_BYTES > crate::message_validator::MAX_ENVELOPE_SIZE,
    "the per-connection reassembly cap is below the largest serialized envelope"
);

/// ⚠ The floor must not exceed the default, or the compiled default would itself be refused.
///
/// This replaces an assert that compared `2 * SUBNET * per_conn` against
/// `MIN_REASSEMBLY_BUDGET_BYTES` — which is DEFINED as that expression, so it was a tautology
/// that held for any value and protected nothing. It read as cover for the env floor while
/// the floor was in fact wired to a different constant entirely.
const _: () = assert!(
    MIN_REASSEMBLY_BUDGET_BYTES <= REASSEMBLY_BUDGET_BYTES,
    "the minimum accepted budget override exceeds the compiled default"
);

/// A connection may never be asked to hold more than one message can legally be.
const _: () = assert!(REASSEMBLY_PER_CONN_BYTES <= MAX_REASSEMBLY_SIZE);

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
        // The PROTOCOL bound. Deliberately NOT the per-connection quota.
        //
        // ⛔ An earlier revision refused here at `REASSEMBLY_PER_CONN_BYTES` (2 MiB) reasoning
        // that the two limits should agree. That is a self-inflicted outage: mesh.rs breaks the
        // inbound loop on ANY `recv` error, and the send path serializes without a size check,
        // so an L2 checkpoint or tree-sync near its 1,000,000-byte payload cap — ~3.7 MB once
        // serde_json expands `Vec<u8>` to decimal — would tear the connection down, the sender
        // would reconnect, re-broadcast the same periodic message, and loop. Before that change
        // the envelope reassembled and `validate_envelope_header` refused it cleanly with the
        // connection intact.
        //
        // Size is a RESOURCE decision, and resource decisions drop the message (below), never
        // the connection. Only a malformed frame is a protocol error.
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
    /// When this message last made progress.
    ///
    /// ⚠ There is deliberately NO `started_at`. It existed, staleness was judged on it, and
    /// that made `REASSEMBLY_TIMEOUT` a TOTAL-message deadline while every comment here
    /// describes "has not progressed". Once staleness moved to this field nothing read
    /// `started_at` at all, so carrying it would be a field inviting the same mistake back.
    ///
    /// ⛔ Staleness is judged on THIS, not `started_at`. `started_at` is set once and never
    /// refreshed, so judging on it makes `REASSEMBLY_TIMEOUT` a TOTAL-message deadline while
    /// every comment in this module describes it as "has not progressed" — an idle one. A
    /// ~2 MiB message over a congested inter-VM link at ~500 kbit/s takes ~34s, so it would be
    /// poisoned mid-flight and could never complete, with no error and no counter.
    ///
    /// An idle deadline still bounds the drip attacker: their buffer is capped by the
    /// per-connection quota and remains evictable under budget pressure. Memory is what the
    /// budget defends, and memory stays bounded.
    last_progress: Instant,
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
    /// The `message_id` most recently EVICTED from this connection.
    ///
    /// ⛔ Without this, eviction manufactures the very churn this module exists to remove.
    /// The victim's next fragment finds an empty slot, allocates a fresh `InFlight` with a new
    /// `started_at`, and re-accumulates up to the quota for a message that can NEVER complete:
    /// the evicted chunks are gone and nothing re-requests them. Because `started_at` was just
    /// reset, that doomed buffer is not stale either, so stale-first cannot reclaim it for
    /// another 30s. Under sustained pressure eviction would convert completable buffers into
    /// guaranteed-doomed ones.
    poisoned: Option<u64>,
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

/// One rate-limited line, captured under the lock and emitted outside it.
///
/// ⛔ REJECTIONS get one too, not just evictions. A refused message vanishes: the node then
/// logs "proposal data missing — requesting tree sync" and nothing connects that to
/// reassembly. Counting it in `rejections` is not enough when nothing reads the counter — the
/// eviction path was given a voice and the rejection path was not, which left the quieter
/// failure the invisible one.
enum BudgetLog {
    Evicted {
        freed: usize,
        stale: bool,
        held: usize,
        limit: usize,
        evictions_total: u64,
        suppressed: u64,
    },
    Rejected {
        message_id: u64,
        held: usize,
        limit: usize,
    },
}

impl BudgetLog {
    fn rejected(message_id: u64, held: usize, limit: usize) -> Self {
        Self::Rejected {
            message_id,
            held,
            limit,
        }
    }
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
                poisoned: None,
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
    /// Age an entry's buffer, so the stale-first eviction path is testable without waiting
    /// out [`REASSEMBLY_TIMEOUT`]. A test that cannot reach the stale branch would assert the
    /// LRU fallback and call it stale-first.
    #[cfg(test)]
    fn backdate(&self, id: u64, by: Duration) {
        let mut g = self.inner.lock();
        if let Some(e) = g.entries.get_mut(&id) {
            if let Some(slot) = e.slot.as_mut() {
                slot.last_progress = slot
                    .last_progress
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
        // Buffers to free, and lines to log, AFTER the lock is released.
        //
        // ⛔ `tracing::warn!` writes to journald, on disk, on these nodes. Emitting it while
        // holding the one lock every fragment on every connection needs serialises the whole
        // mesh behind a disk write, at a rate an attacker chooses. Same reasoning as dropping
        // the buffers out here: nothing slow belongs inside this lock.
        let mut reclaimed: Vec<InFlight> = Vec::new();
        let mut logs: Vec<BudgetLog> = Vec::new();
        let result = self.accept_locked(id, header, payload, &mut reclaimed, &mut logs);
        drop(reclaimed);
        for l in logs {
            match l {
                BudgetLog::Evicted {
                    freed,
                    stale,
                    held,
                    limit,
                    evictions_total,
                    suppressed,
                } => tracing::warn!(
                    evicted_bytes = freed,
                    stale,
                    held,
                    limit,
                    evictions_total,
                    suppressed_since_last_log = suppressed,
                    "reassembly budget under pressure — evicted a partial message (#911)"
                ),
                BudgetLog::Rejected {
                    message_id,
                    held,
                    limit,
                } => tracing::warn!(
                    message_id,
                    held,
                    limit,
                    "reassembly budget refused a message — it was DROPPED, so expect a \
                     tree-sync retry for it (#911)"
                ),
            }
        }
        result
    }

    fn accept_locked(
        &self,
        id: u64,
        header: &FragmentHeader,
        payload: Vec<u8>,
        reclaimed: &mut Vec<InFlight>,
        logs: &mut Vec<BudgetLog>,
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        let mut g = self.inner.lock();

        // A connection whose entry has gone (dropped concurrently) cannot reassemble.
        if !g.entries.contains_key(&id) {
            return Err(NoiseError::Decryption(
                "fragment: reassembler is no longer registered".into(),
            ));
        }

        // ---- a fragment of a message we already destroyed cannot complete: drop it
        if g.entries[&id].poisoned == Some(header.message_id) {
            return Ok(None);
        }

        // ---- reset if this is a new message, a different one, or a stale one
        // ⛔ WHY the slot is being replaced decides what happens, and conflating the reasons
        // produced two opposite outcomes for the same violation. `stale_same_message` used to
        // be "any reset with a matching message_id", which swallowed a peer contradicting its
        // own declared `chunk_count` into the timeout path — poisoned, `Ok(None)`, no counter,
        // connection kept, repeatable for free. Meanwhile a `total_len` change WITHIN one
        // chunk-count band still hit the error below and dropped the connection. Same
        // violation, opposite result, decided by an arbitrary 60,000-byte boundary.
        enum Reset {
            /// No slot, or the peer has moved on to a different message.
            Fresh,
            /// The peer contradicted its own framing. A protocol error, not a resource one.
            Contradiction,
            /// No progress within REASSEMBLY_TIMEOUT.
            Idle,
            /// Keep the existing slot.
            None_,
        }
        let reset = match g.entries[&id].slot.as_ref() {
            None => Reset::Fresh,
            Some(cur) if cur.message_id != header.message_id => Reset::Fresh,
            Some(cur) if cur.chunk_count != header.chunk_count => Reset::Contradiction,
            Some(cur) if cur.last_progress.elapsed() > REASSEMBLY_TIMEOUT => Reset::Idle,
            Some(_) => Reset::None_,
        };

        if let Reset::Contradiction = reset {
            Self::clear(&mut g, id, reclaimed);
            return Err(NoiseError::Decryption(
                "fragment: chunk_count changed mid-message".into(),
            ));
        }

        if let Reset::Idle = reset {
            // ⛔ A slot discarded for STALENESS leaves the same doomed buffer eviction did.
            // Its earlier chunks are gone and nothing re-requests them, so re-buffering the
            // rest accumulates against the global budget for a message that can never
            // complete — and the fresh `started_at` defeats stale-first for another 30s. Only
            // the eviction path was poisoned; this one manufactured the identical failure.
            // Its earlier chunks are gone and nothing re-requests them, so re-buffering the
            // rest would accumulate against the global budget for a message that can never
            // complete. Poison it and drop — a resource outcome, not a protocol one.
            Self::poison_and_clear(&mut g, id, header.message_id, reclaimed);
            g.rejections += 1;
            logs.push(BudgetLog::rejected(header.message_id, g.held, g.limit));
            return Ok(None);
        }

        if matches!(reset, Reset::Fresh) {
            let e = g.entries.get_mut(&id).expect("checked above");
            // A different message means the peer has moved on; stop suppressing.
            if e.poisoned.is_some_and(|m| m != header.message_id) {
                e.poisoned = None;
            }
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
                last_progress: Instant::now(),
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

        // ⛔ Both refusals below DROP THE MESSAGE and keep the connection.
        //
        // Returning `Err` here would tear the socket down (mesh.rs breaks on any recv error),
        // which turns "this node is busy" into "this peer is gone" and, for a periodic
        // broadcast, into a reconnect loop. The message is poisoned so its remaining fragments
        // are discarded rather than re-buffered, and the peer is free to send something else.
        if have + delta > g.per_conn {
            Self::poison_and_clear(&mut g, id, header.message_id, reclaimed);
            g.rejections += 1;
            logs.push(BudgetLog::rejected(header.message_id, g.held, g.limit));
            return Ok(None);
        }

        if !Self::make_room(&mut g, id, delta, reclaimed, logs) {
            Self::poison_and_clear(&mut g, id, header.message_id, reclaimed);
            g.rejections += 1;
            logs.push(BudgetLog::rejected(header.message_id, g.held, g.limit));
            return Ok(None);
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
        slot.last_progress = Instant::now();
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

        // ⛔ Check BEFORE allocating, and size from what actually arrived.
        //
        // `Vec::with_capacity(slot.total_len)` allocated the DECLARED length and only compared
        // afterwards. The parser's consistency rule permits 140 chunks declaring ~8 MiB, so
        // 140 one-byte chunks — about 2.9 KB on the wire, 140 bytes charged — produced a
        // multi-megabyte allocation that was then thrown away. An attacker-sized, unbudgeted
        // allocation in the one module whose job is bounding reassembly memory.
        if slot.received_bytes != slot.total_len {
            return Err(NoiseError::Decryption(
                "fragment: reassembled length mismatch".into(),
            ));
        }
        let mut out = Vec::with_capacity(slot.received_bytes);
        for chunk in slot.chunks {
            out.extend_from_slice(&chunk.expect("all chunks present when count matches"));
        }
        Ok(Some(out))
    }

    /// Drop `id`'s buffer, its accounting, AND remember the message so its remaining fragments
    /// are discarded instead of re-buffered into something that can never complete.
    fn poison_and_clear(
        g: &mut BudgetInner,
        id: u64,
        message_id: u64,
        reclaimed: &mut Vec<InFlight>,
    ) {
        Self::clear(g, id, reclaimed);
        if let Some(e) = g.entries.get_mut(&id) {
            e.poisoned = Some(message_id);
        }
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
        logs: &mut Vec<BudgetLog>,
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
                            .is_some_and(|s| s.last_progress.elapsed() > REASSEMBLY_TIMEOUT)
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
                    // Remember WHICH message we destroyed, so its later fragments are dropped
                    // rather than re-buffered into a message that can never complete.
                    e.poisoned = Some(old.message_id);
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
                logs.push(BudgetLog::Evicted {
                    freed,
                    stale: was_stale,
                    held: g.held,
                    limit: g.limit,
                    evictions_total: g.evictions,
                    suppressed,
                });
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
/// without a rebuild.
///
/// ⛔ The floor is [`MIN_REASSEMBLY_BUDGET_BYTES`], the smallest budget that still keeps one
/// `/24` a minority — NOT [`MAX_REASSEMBLY_SIZE`]. It was the latter, and the constant below
/// was written, documented as the floor, and then never wired in. At an 8 MiB override just
/// four connections held the whole budget, inside a single IP's allowance, so that address
/// chose every eviction victim: the exact cornering this module exists to stop, re-opened by
/// the one knob that ships enabled.
static GLOBAL_BUDGET: once_cell::sync::Lazy<ReassemblyBudget> = once_cell::sync::Lazy::new(|| {
    ReassemblyBudget::new(budget_limit_from_env(
        std::env::var("GHOST_REASSEMBLY_BUDGET_BYTES")
            .ok()
            .as_deref(),
    ))
});

/// Resolve the budget limit from the raw env value.
///
/// ⛔ A FREE FUNCTION so it can be tested. This logic previously lived inline in the `Lazy`
/// initialiser, which is read once per process and therefore unreachable from a test — and
/// that is exactly how it shipped wired to the WRONG constant ([`MAX_REASSEMBLY_SIZE`], 8 MiB)
/// while [`MIN_REASSEMBLY_BUDGET_BYTES`] sat defined, documented as the floor, and referenced
/// by nothing. Untestable code is where that hides.
fn budget_limit_from_env(raw: Option<&str>) -> usize {
    let Some(raw) = raw else {
        return REASSEMBLY_BUDGET_BYTES;
    };
    match raw.trim().parse::<usize>() {
        // ⛔ A CEILING as well as a floor. Every other bad input was warned about; the one
        // genuinely dangerous direction was the only silent one. On a 3,867 MiB node a single
        // extra zero (960000000) would set a ~915 MiB ceiling and `held` would grow to it
        // before anything evicted — the OOM this budget exists to prevent.
        Ok(v) if v > MAX_REASSEMBLY_BUDGET_BYTES => {
            tracing::warn!(
                requested = v,
                ceiling = MAX_REASSEMBLY_BUDGET_BYTES,
                using = REASSEMBLY_BUDGET_BYTES,
                "GHOST_REASSEMBLY_BUDGET_BYTES is above the ceiling — ignoring it"
            );
            REASSEMBLY_BUDGET_BYTES
        }
        // ⚠ STRICTLY greater. At exactly the floor one /24 holds exactly half, which is not
        // the "minority" this module claims everywhere.
        Ok(v) if v > MIN_REASSEMBLY_BUDGET_BYTES => v,
        // Say so. An operator trimming reassembly memory on a 3,867 MiB node is who this knob
        // is for; silently using the default leaves the failure invisible in the one case it
        // matters.
        Ok(v) => {
            tracing::warn!(
                requested = v,
                floor = MIN_REASSEMBLY_BUDGET_BYTES,
                using = REASSEMBLY_BUDGET_BYTES,
                "GHOST_REASSEMBLY_BUDGET_BYTES is below the floor that keeps one /24 a \
                 minority of the budget — ignoring it"
            );
            REASSEMBLY_BUDGET_BYTES
        }
        Err(e) => {
            tracing::warn!(
                requested = %raw,
                error = %e,
                using = REASSEMBLY_BUDGET_BYTES,
                "GHOST_REASSEMBLY_BUDGET_BYTES is not a number — ignoring it"
            );
            REASSEMBLY_BUDGET_BYTES
        }
    }
}

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

    /// ⛔ An oversized message must be DROPPED, never disconnect the peer.
    ///
    /// mesh.rs breaks the inbound loop on ANY recv error and the send path has no size check,
    /// so returning `Err` for a size condition turns "too big for me right now" into a torn
    /// socket — and for a periodic broadcast, into a reconnect loop. An L2 checkpoint near its
    /// 1,000,000-byte payload cap is ~3.7 MB serialized, squarely in the band an earlier
    /// revision rejected at parse.
    #[test]
    fn an_oversized_message_is_dropped_not_disconnected() {
        let budget = ReassemblyBudget::new(MIN_REASSEMBLY_BUDGET_BYTES + 1);
        let mut peer = FragmentReassembler::with_budget(budget.clone());

        // Larger than the per-connection quota, but legal to the fragment protocol.
        let declared = REASSEMBLY_PER_CONN_BYTES + MAX_FRAGMENT_PAYLOAD;
        assert!(declared <= MAX_REASSEMBLY_SIZE, "still a legal frame");
        let count = chunks_for(declared);

        let mut saw_err = false;
        for i in 0..count {
            if peer
                .accept(frag(
                    9,
                    i,
                    count,
                    declared as u32,
                    &vec![3u8; MAX_FRAGMENT_PAYLOAD],
                ))
                .is_err()
            {
                saw_err = true;
                break;
            }
        }
        assert!(
            !saw_err,
            "a size refusal must never surface as an error — mesh would drop the connection"
        );
        assert_eq!(
            peer.held_bytes(),
            0,
            "the oversized message must hold nothing once refused"
        );

        // And the peer can still use the connection for something that fits.
        let payload: Vec<u8> = (0..84_000u32).map(|i| (i % 251) as u8).collect();
        let mut out = None;
        for f in fragment_message(&payload) {
            if let Some(done) = peer.accept(f).expect("the connection must still work") {
                out = Some(done);
            }
        }
        assert_eq!(out.as_deref(), Some(payload.as_slice()));
    }

    /// Eviction must not manufacture doomed buffers.
    ///
    /// The victim's remaining fragments cannot complete the message — the evicted chunks are
    /// gone and nothing re-requests them — so re-buffering them holds memory for a message
    /// that can never finish, with a fresh `started_at` that also defeats stale-first.
    #[test]
    fn fragments_of_an_evicted_message_are_not_re_buffered() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(2 * CHUNK);
        let mut victim = FragmentReassembler::with_budget(budget.clone());
        let mut a = FragmentReassembler::with_budget(budget.clone());
        let mut b = FragmentReassembler::with_budget(budget.clone());

        let declared = 3 * CHUNK;
        let count = chunks_for(declared);
        victim
            .accept(frag(77, 0, count, declared as u32, &vec![1u8; CHUNK]))
            .unwrap();

        // Two more arrivals evict the victim.
        a.accept(frag(1, 0, count, declared as u32, &vec![2u8; CHUNK]))
            .unwrap();
        b.accept(frag(2, 0, count, declared as u32, &vec![3u8; CHUNK]))
            .unwrap();
        assert!(!victim.has_slot(), "the victim must have been evicted");

        // Its next fragment must be dropped, not re-buffered into a doomed message.
        let r = victim
            .accept(frag(77, 1, count, declared as u32, &vec![1u8; CHUNK]))
            .expect("a fragment of an evicted message is dropped, not an error");
        assert!(r.is_none());
        assert_eq!(
            victim.held_bytes(),
            0,
            "a fragment of a destroyed message must not re-accumulate — it can never complete"
        );

        // A DIFFERENT message from the same peer is accepted normally.
        victim
            .accept(frag(78, 0, count, declared as u32, &vec![4u8; CHUNK]))
            .expect("a new message must not be suppressed");
        assert!(victim.has_slot(), "the peer must be able to start again");
    }

    /// The env override must enforce the SUBNET floor, not merely "one message fits".
    ///
    /// This is the case that shipped broken: the floor was `MAX_REASSEMBLY_SIZE` (8 MiB) while
    /// `MIN_REASSEMBLY_BUDGET_BYTES` was defined, documented as the floor, and wired to
    /// nothing. At 8 MiB just four connections held the whole budget — inside ONE IP's
    /// allowance — so that address chose every eviction victim.
    #[test]
    fn the_env_override_enforces_the_subnet_floor() {
        assert_eq!(budget_limit_from_env(None), REASSEMBLY_BUDGET_BYTES);

        // ⚠ STRICTLY above the floor: at exactly the floor one /24 holds exactly half, which
        // is not the "minority" this module claims.
        assert_eq!(
            budget_limit_from_env(Some(&MIN_REASSEMBLY_BUDGET_BYTES.to_string())),
            REASSEMBLY_BUDGET_BYTES,
            "exactly the floor leaves one /24 at 50% — it must be refused"
        );

        let ok = MIN_REASSEMBLY_BUDGET_BYTES + 1;
        assert_eq!(budget_limit_from_env(Some(&ok.to_string())), ok);
        assert_eq!(
            budget_limit_from_env(Some(&(ok * 2).to_string())),
            ok * 2,
            "a larger budget below the ceiling must be honoured"
        );

        // MAX_REASSEMBLY_SIZE is the value the broken version accepted, so name it explicitly.
        for bad in [
            MAX_REASSEMBLY_SIZE,
            MIN_REASSEMBLY_BUDGET_BYTES - 1,
            0,
            1,
            // Above the ceiling — a single extra zero on a 3,867 MiB node.
            MAX_REASSEMBLY_BUDGET_BYTES + 1,
            960_000_000,
        ] {
            assert_eq!(
                budget_limit_from_env(Some(&bad.to_string())),
                REASSEMBLY_BUDGET_BYTES,
                "{bad} is below the floor and must be refused, not accepted"
            );
        }

        assert_eq!(budget_limit_from_env(Some("128M")), REASSEMBLY_BUDGET_BYTES);
        assert_eq!(budget_limit_from_env(Some("")), REASSEMBLY_BUDGET_BYTES);
        assert_eq!(
            budget_limit_from_env(Some(&format!("  {ok}  "))),
            ok,
            "surrounding whitespace must not silently discard a valid override"
        );
    }

    /// A peer contradicting its own framing is a PROTOCOL error; a timeout is a resource one.
    ///
    /// These were conflated: any reset with a matching `message_id` took the staleness path, so
    /// a contradicted `chunk_count` was poisoned and silently dropped, no counter moved, and
    /// the peer could repeat it for free — while changing `total_len` WITHIN one chunk-count
    /// band still errored and dropped the connection. Same violation, opposite outcome, decided
    /// by an arbitrary 60,000-byte boundary.
    #[test]
    fn a_framing_contradiction_is_an_error_but_a_timeout_is_not() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(MIN_REASSEMBLY_BUDGET_BYTES + 1);

        // (a) chunk_count contradiction -> protocol error.
        let mut liar = FragmentReassembler::with_budget(budget.clone());
        let a_len = 2 * CHUNK;
        liar.accept(frag(
            5,
            0,
            chunks_for(a_len),
            a_len as u32,
            &vec![1u8; CHUNK],
        ))
        .unwrap();
        let b_len = 6 * CHUNK;
        let err = liar
            .accept(frag(
                5,
                1,
                chunks_for(b_len),
                b_len as u32,
                &vec![1u8; CHUNK],
            ))
            .expect_err("contradicting its own chunk_count is a protocol error");
        assert!(
            format!("{err:?}").contains("chunk_count changed"),
            "got {err:?}"
        );

        // (b) the same message going quiet past the timeout -> dropped, NOT an error.
        let mut slow = FragmentReassembler::with_budget(budget.clone());
        let len = 4 * CHUNK;
        let count = chunks_for(len);
        slow.accept(frag(6, 0, count, len as u32, &vec![2u8; CHUNK]))
            .unwrap();
        budget.backdate(slow.id, REASSEMBLY_TIMEOUT + Duration::from_secs(1));
        let r = slow
            .accept(frag(6, 1, count, len as u32, &vec![2u8; CHUNK]))
            .expect("a timeout is a resource outcome, not a protocol error");
        assert!(r.is_none());
        assert_eq!(slow.held_bytes(), 0);
    }

    /// Staleness must be an IDLE deadline, not a total-message one.
    ///
    /// `started_at` is set once and never refreshed, so judging on it makes REASSEMBLY_TIMEOUT
    /// a total deadline — a ~2 MiB message over a slow link takes ~34s and would be poisoned
    /// mid-flight, unable ever to complete, with no error and no counter. Every comment in this
    /// module describes "has not progressed", which is idle.
    #[test]
    fn a_slow_but_progressing_message_is_not_poisoned() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(MIN_REASSEMBLY_BUDGET_BYTES + 1);
        let mut slow = FragmentReassembler::with_budget(budget.clone());

        let len = 4 * CHUNK;
        let count = chunks_for(len);
        assert!(count >= 4, "need several gaps for this to mean anything");

        let mut completed = None;
        for i in 0..count {
            let r = slow
                .accept(frag(7, i, count, len as u32, &vec![3u8; CHUNK]))
                .expect("a progressing message must never be refused for age");
            completed = r.or(completed);

            // ⚠ Each GAP is under the idle deadline, but they TOTAL well over it. Ageing by
            // more than the deadline would correctly make it stale — idle means idle. Ageing
            // only `started_at` would not discriminate at all: a mutation removing the
            // `last_progress` refresh stayed green against that, because `last_progress` then
            // simply equals creation time and the test never aged it.
            budget.backdate(slow.id, REASSEMBLY_TIMEOUT / 2);
        }
        assert!(
            completed.is_some(),
            "a message whose fragments each arrive inside the idle window must complete, \
             however long it takes in total"
        );
    }

    /// A slot discarded for STALENESS must poison the message too, not just eviction.
    ///
    /// The timeout path manufactured the identical doomed buffer: earlier chunks gone, nothing
    /// re-requests them, so the rest accumulate against the global budget for a message that
    /// can never complete — with a fresh `started_at` that also defeats stale-first for another
    /// 30s. Only the eviction path was poisoned.
    #[test]
    fn a_message_abandoned_by_timeout_is_not_re_buffered() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::new(MIN_REASSEMBLY_BUDGET_BYTES);
        let mut peer = FragmentReassembler::with_budget(budget.clone());

        let declared = 8 * CHUNK;
        let count = chunks_for(declared);
        peer.accept(frag(42, 0, count, declared as u32, &vec![1u8; CHUNK]))
            .unwrap();
        assert_eq!(peer.held_bytes(), CHUNK);

        // Let it go stale, as a peer that paused past REASSEMBLY_TIMEOUT would.
        budget.backdate(peer.id, REASSEMBLY_TIMEOUT + Duration::from_secs(1));

        // The next chunk of the SAME message must be dropped, not started afresh.
        let r = peer
            .accept(frag(42, 1, count, declared as u32, &vec![1u8; CHUNK]))
            .expect("a fragment of a timed-out message is dropped, not an error");
        assert!(r.is_none());
        assert_eq!(
            peer.held_bytes(),
            0,
            "a timed-out message must not re-accumulate — its earlier chunks are gone, so it \
             can never complete"
        );
        assert_eq!(budget.stats().0, 0, "and it must hold none of the budget");

        // A NEW message from the same peer is accepted normally.
        peer.accept(frag(43, 0, count, declared as u32, &vec![2u8; CHUNK]))
            .expect("a new message must not be suppressed");
        assert!(peer.has_slot());
    }

    /// A completed message must never allocate the DECLARED length.
    ///
    /// 140 one-byte chunks declaring ~2 MiB is ~2.9 KB on the wire and 140 bytes charged, but
    /// used to trigger a multi-megabyte `Vec::with_capacity` that was then discarded.
    #[test]
    fn a_short_message_does_not_allocate_its_declared_length() {
        let budget = ReassemblyBudget::new(4 * 1024 * 1024);
        let mut re = FragmentReassembler::with_budget(budget.clone());

        let declared = REASSEMBLY_PER_CONN_BYTES;
        let count = chunks_for(declared);
        let mut last = Ok(None);
        for i in 0..count {
            last = re.accept(frag(1, i, count, declared as u32, &[0u8; 1]));
        }
        let err = last.expect_err("a message whose chunks do not sum to total_len must fail");
        assert!(
            format!("{err:?}").contains("length mismatch"),
            "got {err:?}"
        );
        assert_eq!(budget.stats().0, 0, "the failed message must hold nothing");
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

    /// A connection cannot corner the budget on its own, however much it sends — and being
    /// refused costs it the message, not the connection.
    #[test]
    fn one_connection_cannot_exceed_its_per_connection_quota() {
        const CHUNK: usize = MAX_FRAGMENT_PAYLOAD;
        let budget = ReassemblyBudget::with_per_conn(100 * CHUNK, 2 * CHUNK);
        let mut hog = FragmentReassembler::with_budget(budget.clone());

        let declared = 8 * CHUNK;
        let count = chunks_for(declared);
        for i in 0..4u16 {
            let r = hog.accept(frag(1, i, count, declared as u32, &vec![9u8; CHUNK]));
            assert!(
                r.is_ok(),
                "a quota refusal must be a dropped message, not an error that disconnects"
            );
            assert!(
                hog.held_bytes() <= 2 * CHUNK,
                "held {} exceeded the quota",
                hog.held_bytes()
            );
        }
        assert!(budget.stats().0 <= 2 * CHUNK);
        assert!(budget.stats().2 > 0, "the refusal must be counted");
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
