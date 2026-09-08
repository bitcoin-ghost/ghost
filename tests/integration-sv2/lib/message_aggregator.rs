use std::{collections::VecDeque, sync::Arc};
use stratum_apps::{
    custom_mutex::Mutex,
    stratum_core::parsers_sv2::{AnyMessage, Tlv},
};

use crate::types::MsgType;

/// One intercepted message: its type, the message, and any TLV extension fields that rode along.
type QueuedMessage = (MsgType, AnyMessage<'static>, Option<Vec<Tlv>>);

/// The intercepted-message queue, plus a count of how many of each message type it holds.
///
/// ⛔ The counts exist because this queue is UNBOUNDED and, in practice, large. A sniffer sitting
/// in front of a mining channel accumulates every share the miner submits — a test that waits
/// without draining reached **131,783** queued messages in 66 seconds (#849). At that size an
/// O(n) lookup is not a constant factor, it is the difference between a test passing and a test
/// reporting a message it can see as absent:
///
///   * `has_message_type` scanned the whole deque. `Sniffer::wait_for_message_type` guards that
///     scan with a 1-second timeout and maps expiry to `false`, so once the scan exceeded a
///     second, a message that WAS queued reported as "not present" — indistinguishably from
///     genuinely absent. The test then failed saying the message never went upstream, which was
///     untrue.
///   * `next_message_with_tlvs` and `has_message_type_with_remove` CLONED the entire deque on
///     every call, to pop one element or drop a prefix. Called in a loop, as those tests do,
///     that is O(n²) in the queue length.
///
/// Message types are `u8`, so a 256-slot array indexes them exactly and needs no hashing. It is
/// maintained under the same lock as the deque — every push increments and every removal
/// decrements — so the two can never disagree.
struct Queued {
    deque: VecDeque<QueuedMessage>,
    counts: [usize; 256],
}

impl Queued {
    fn new() -> Self {
        Self {
            deque: VecDeque::new(),
            counts: [0; 256],
        }
    }

    fn push(&mut self, msg: QueuedMessage) {
        self.counts[msg.0 as usize] += 1;
        self.deque.push_back(msg);
    }

    fn pop(&mut self) -> Option<QueuedMessage> {
        let msg = self.deque.pop_front()?;
        // Saturating rather than plain subtraction: an underflow here would mean the count and the
        // deque had already diverged, and panicking in a test harness helper hides the real bug.
        let slot = &mut self.counts[msg.0 as usize];
        *slot = slot.saturating_sub(1);
        Some(msg)
    }
}

type MessageQueue = Arc<Mutex<Queued>>;

#[derive(Debug, Clone)]
pub struct MessagesAggregator {
    messages: MessageQueue,
}

impl std::fmt::Debug for Queued {
    // The messages themselves are large and the counts are 256 mostly-zero slots; neither is
    // useful in a panic message. Report what a reader actually wants: how much is queued.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Queued({} messages)", self.deque.len())
    }
}

impl Default for MessagesAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagesAggregator {
    /// Creates a new [`MessagesAggregator`].
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Queued::new())),
        }
    }

    /// Adds a message to the end of the queue.
    pub fn add_message(&self, msg_type: MsgType, message: AnyMessage<'static>) {
        self.add_message_with_tlvs(msg_type, message, None);
    }

    /// Adds a message with TLV fields to the end of the queue.
    pub fn add_message_with_tlvs(
        &self,
        msg_type: MsgType,
        message: AnyMessage<'static>,
        tlv_fields: Option<Vec<Tlv>>,
    ) {
        self.messages
            .safe_lock(|q| q.push((msg_type, message, tlv_fields)))
            .unwrap();
    }

    /// Direct access to the inner lock, for tests that need to hold it deliberately.
    #[cfg(test)]
    pub(crate) fn messages_for_test(&self) -> &MessageQueue {
        &self.messages
    }

    /// Returns false if the queue is empty, true otherwise.
    pub fn is_empty(&self) -> bool {
        self.messages.safe_lock(|q| q.deque.is_empty()).unwrap()
    }

    /// Clears all messages from the queue.
    pub fn clear(&self) {
        self.messages
            .safe_lock(|q| {
                q.deque.clear();
                q.counts = [0; 256];
            })
            .unwrap();
    }

    /// Returns true if the queue contains a message of this type.
    ///
    /// O(1) — a counter lookup, not a scan. See [`Queued`] for why that matters here.
    pub fn has_message_type(&self, message_type: u8) -> bool {
        self.messages
            .safe_lock(|q| q.counts[message_type as usize] > 0)
            .unwrap()
    }

    /// returns true if contains message_type and removes messages from the queue
    /// until the first message of type message_type.
    pub fn has_message_type_with_remove(&self, message_type: u8) -> bool {
        self.messages
            .safe_lock(|q| {
                if q.counts[message_type as usize] == 0 {
                    // O(1) rejection: without this the miss case still walked the whole queue.
                    return false;
                }
                let pos = match q.deque.iter().position(|(t, _, _)| *t == message_type) {
                    Some(pos) => pos,
                    None => return false,
                };
                // Drop everything up to and including the match, in place. This used to clone the
                // whole deque and reassign it.
                for _ in 0..=pos {
                    q.pop();
                }
                true
            })
            .unwrap()
    }

    /// The aggregator queues messages in FIFO order, so this function returns the oldest message in
    /// the queue.
    ///
    /// The returned message is removed from the queue.
    pub fn next_message(&self) -> Option<(MsgType, AnyMessage<'static>)> {
        self.next_message_with_tlvs()
            .map(|(msg_type, msg, _)| (msg_type, msg))
    }

    /// The aggregator queues messages in FIFO order, so this function returns the oldest message
    /// with its TLV fields in the queue.
    ///
    /// The returned message is removed from the queue.
    pub fn next_message_with_tlvs(&self) -> Option<QueuedMessage> {
        self.messages.safe_lock(|q| q.pop()).unwrap()
    }
}
