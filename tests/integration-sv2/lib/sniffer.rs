use crate::{
    interceptor::{InterceptAction, MessageDirection},
    message_aggregator::MessagesAggregator,
    types::MsgType,
    utils::{
        accept_one, create_downstream, create_upstream, recv_from_down_send_to_up,
        recv_from_up_send_to_down,
    },
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use stratum_apps::stratum_core::parsers_sv2::{message_type_to_name, AnyMessage};
use tokio::{net::TcpStream, select};

const DEFAULT_TIMEOUT: u64 = 60;

/// Allows to intercept messages sent between two roles.
///
/// Can be useful for testing purposes, as it allows to assert that the roles have sent specific
/// messages in a specific order and to inspect the messages details.
///
/// The downstream (or client) role connects to the [`Sniffer`] `listening_address` and the
/// [`Sniffer`] connects to the `upstream` server. This way, the Sniffer can intercept messages sent
/// between the downstream and upstream roles.
///
/// Messages received from downstream are stored in the `messages_from_downstream` aggregator and
/// forwarded to the upstream role. Alternatively, messages received from upstream are stored in
/// the `messages_from_upstream` and forwarded to the downstream role. Both
/// `messages_from_downstream` and `messages_from_upstream` aggregators can be accessed as FIFO
/// queues via [`Sniffer::next_message_from_downstream`] and
/// [`Sniffer::next_message_from_upstream`], respectively.
///
/// The `timeout` parameter can be used to configure the timeout for the sniffer. If not provided,
/// the default timeout is 1 minute.
///
/// In order to replace or ignore the messages sent between the roles, [`InterceptAction`] can be
/// used in [`Sniffer::new`].
#[derive(Debug, Clone)]
pub struct Sniffer<'a> {
    identifier: &'a str,
    listening_address: SocketAddr,
    upstream_address: SocketAddr,
    messages_from_downstream: MessagesAggregator,
    messages_from_upstream: MessagesAggregator,
    check_on_drop: bool,
    action: Vec<InterceptAction>,
    timeout: Option<u64>,
    negotiated_extensions: Arc<Mutex<Vec<u16>>>,
}

impl<'a> Sniffer<'a> {
    /// Creates a new sniffer that listens on the given listening address and connects to the given
    /// upstream address.
    pub fn new(
        identifier: &'a str,
        listening_address: SocketAddr,
        upstream_address: SocketAddr,
        check_on_drop: bool,
        action: Vec<InterceptAction>,
        timeout: Option<u64>,
    ) -> Self {
        Self {
            identifier,
            listening_address,
            upstream_address,
            messages_from_downstream: MessagesAggregator::new(),
            messages_from_upstream: MessagesAggregator::new(),
            check_on_drop,
            action,
            timeout,
            negotiated_extensions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Builds a sniffer wired to a supplied downstream queue, without binding any sockets.
    ///
    /// Only for testing the poll loop's own liveness — constructing a real sniffer needs
    /// listeners and a live upstream, which is far more than is needed to prove that a held
    /// queue lock cannot postpone the timeout.
    #[cfg(test)]
    pub(crate) fn for_timeout_test(
        messages_from_downstream: MessagesAggregator,
        timeout: Option<u64>,
    ) -> Sniffer<'static> {
        let unused: SocketAddr = "127.0.0.1:1".parse().expect("static addr");
        Sniffer {
            identifier: "timeout-test",
            listening_address: unused,
            upstream_address: unused,
            messages_from_downstream,
            messages_from_upstream: MessagesAggregator::new(),
            check_on_drop: false,
            action: Vec::new(),
            timeout,
            negotiated_extensions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Starts the sniffer.
    ///
    /// The sniffer should be started after the upstream role have been initialized and is ready to
    /// accept messages and before the downstream role starts sending messages.
    pub fn start(&self) {
        let listening_address = self.listening_address;
        let upstream_address = self.upstream_address;
        let messages_from_downstream = self.messages_from_downstream.clone();
        let messages_from_upstream = self.messages_from_upstream.clone();
        let action = self.action.clone();
        let identifier = self.identifier.to_string();
        let negotiated_extensions = self.negotiated_extensions.clone();

        // Bind BEFORE spawning. `start()` is not async, so this uses the std listener and hands
        // it to tokio — the point is that the socket exists the instant `start()` returns.
        //
        // It used to bind inside the spawned task. The doc comment above states the required
        // ordering ("started after the upstream role ... and before the downstream role starts
        // sending"), but nothing enforced it: a caller could dial this address before anything
        // was listening. Callers also probe a free port with a temporary `TcpListener` and drop
        // it, so the port was unowned in between and a third party could take it.
        //
        // Invisible on a fast machine, wide open under `cargo llvm-cov` — which is where it
        // showed up as 5h38m in a single test against 22 minutes uninstrumented (#408).
        let std_listener =
            std::net::TcpListener::bind(listening_address).expect("Sniffer: cannot bind");
        std_listener
            .set_nonblocking(true)
            .expect("Sniffer: cannot set nonblocking");

        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener)
                .expect("Sniffer: cannot adopt listener");
            let (downstream_receiver, downstream_sender) =
                create_downstream(accept_one(listener).await)
                    .await
                    .expect("Failed to create downstream");
            let (upstream_receiver, upstream_sender) = create_upstream(loop {
                match TcpStream::connect(upstream_address).await {
                    Ok(stream) => break stream,
                    Err(_) => {
                        tracing::warn!(
                            "Sniffer {}: unable to connect to upstream {}, retrying after 1 second",
                            identifier,
                            upstream_address
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            })
            .await
            .expect("Failed to create upstream");
            select! {
                _ = tokio::signal::ctrl_c() => { },
                _ = recv_from_down_send_to_up(downstream_receiver, upstream_sender, messages_from_downstream, action.clone(), &identifier, negotiated_extensions.clone()) => { },
                _ = recv_from_up_send_to_down(upstream_receiver, downstream_sender, messages_from_upstream, action, &identifier, negotiated_extensions.clone()) => { },
            };
        });
    }

    /// Returns the oldest message sent by downstream.
    ///
    /// The queue is FIFO and once a message is returned it is removed from the queue.
    ///
    /// This can be used to assert that the downstream sent:
    /// - specific message types
    /// - specific message fields
    pub fn next_message_from_downstream(&self) -> Option<(MsgType, AnyMessage<'static>)> {
        self.messages_from_downstream.next_message()
    }

    /// Returns the oldest message with TLV fields sent by downstream.
    ///
    /// The queue is FIFO and once a message is returned it is removed from the queue.
    pub fn next_message_from_downstream_with_tlvs(
        &self,
    ) -> Option<(
        MsgType,
        AnyMessage<'static>,
        Option<Vec<stratum_apps::stratum_core::parsers_sv2::Tlv>>,
    )> {
        self.messages_from_downstream.next_message_with_tlvs()
    }

    /// Returns the oldest message sent by upstream.
    ///
    /// The queue is FIFO and once a message is returned it is removed from the queue.
    ///
    /// This can be used to assert that the upstream sent:
    /// - specific message types
    /// - specific message fields
    pub fn next_message_from_upstream(&self) -> Option<(MsgType, AnyMessage<'static>)> {
        self.messages_from_upstream.next_message()
    }

    /// Returns the oldest message with TLV fields sent by upstream.
    ///
    /// The queue is FIFO and once a message is returned it is removed from the queue.
    pub fn next_message_from_upstream_with_tlvs(
        &self,
    ) -> Option<(
        MsgType,
        AnyMessage<'static>,
        Option<Vec<stratum_apps::stratum_core::parsers_sv2::Tlv>>,
    )> {
        self.messages_from_upstream.next_message_with_tlvs()
    }

    /// Waits until a message of the specified type is received into the `message_direction`
    /// corresponding queue.
    pub async fn wait_for_message_type(
        &self,
        message_direction: MessageDirection,
        message_type: u8,
    ) {
        let now = std::time::Instant::now();
        loop {
            // The queue read takes a BLOCKING std::sync::Mutex. `#[tokio::test]` gives a
            // current-thread runtime, so taking it inline blocks the only executor thread —
            // and then neither the elapsed check below nor tokio's timer can ever run. That
            // is why the 1-minute timeout did not fire when a coverage run hung for six
            // hours: the timeout is checked AFTER this read, so a read that never returns
            // makes it unreachable.
            //
            // Doing it on the blocking pool keeps the executor free no matter what the lock
            // does, so the timeout below is always reachable. This does not fix a deadlock
            // if one exists — it guarantees the test FAILS in a minute with a message rather
            // than burning a CI run to the 6h cap.
            let agg = match message_direction {
                MessageDirection::ToDownstream => self.messages_from_upstream.clone(),
                MessageDirection::ToUpstream => self.messages_from_downstream.clone(),
            };
            // Two separate things are needed here, and only doing one of them is a trap.
            //
            // spawn_blocking keeps the BLOCKING lock off the executor thread — a
            // `#[tokio::test]` runs on a current-thread runtime, so taking it inline stops
            // the timer as well.
            //
            // The timeout around it keeps the LOOP moving. On its own, spawn_blocking still
            // leaves this `.await` stalled for as long as the lock is held, and the elapsed
            // check below sits after it — so a stuck read still postpones the timeout
            // indefinitely. That is the shape that let a coverage run hang for six hours
            // instead of failing in one minute (#408).
            //
            // A read that does not answer within a second is treated as "no message yet";
            // the loop re-checks its own deadline and gives up on schedule.
            let has_message_type = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::task::spawn_blocking(move || agg.has_message_type(message_type)),
            )
            .await
            .map(|joined| joined.unwrap_or(false))
            .unwrap_or(false);

            // ready to unblock test runtime
            if has_message_type {
                return;
            }

            // configurable timeout, 1 minute default
            if now.elapsed().as_secs() > self.timeout.unwrap_or(DEFAULT_TIMEOUT) {
                panic!(
                    "timeout while waiting for message {} to go {}",
                    message_type_to_name(message_type),
                    message_direction
                );
            }

            // sleep to reduce async lock contention
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    /// Assert message is not present in the queue over a given duration.
    ///
    /// Polls the queue every 100ms for `deadline`, returning `false` immediately
    /// if the message appears at any point. Returns `true` only after the full duration
    /// passes with no match.
    ///
    /// The queue should be cleared before calling this to avoid matching stale messages.
    /// Use [`Sniffer::wait_for_message_type_and_clean_queue`] or [`Sniffer::clean_queue`]
    /// to clear the queue first.
    pub async fn assert_message_not_present(
        &self,
        message_direction: MessageDirection,
        message_type: u8,
        deadline: std::time::Duration,
    ) -> bool {
        let start = std::time::Instant::now();

        while start.elapsed() < deadline {
            // Same trap as `wait_for_message_type`, and for the same reason: the queue read
            // takes a BLOCKING std::sync::Mutex, and `#[tokio::test]` is a current-thread
            // runtime. Taking it inline here blocks the only executor thread, so neither the
            // `start.elapsed()` check above nor tokio's timer can run — and `deadline` becomes
            // unreachable rather than an upper bound.
            //
            // #450 hardened only `wait_for_message_type`. This path and
            // `wait_for_message_type_and_clean_queue` kept the original shape, which is how
            // `test_assert_message_not_present` — a test that exercises all three — could still
            // hang for six hours instead of failing on its own deadline (#408).
            //
            // A read that does not answer within a second counts as "not present"; the loop
            // re-checks its deadline and returns on schedule.
            let agg = match message_direction {
                MessageDirection::ToDownstream => self.messages_from_upstream.clone(),
                MessageDirection::ToUpstream => self.messages_from_downstream.clone(),
            };
            let has_message_type = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::task::spawn_blocking(move || agg.has_message_type(message_type)),
            )
            .await
            .map(|joined| joined.unwrap_or(false))
            .unwrap_or(false);

            if has_message_type {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        true
    }

    /// Similar to `[Sniffer::wait_for_message_type]` but also removes the messages from the queue
    /// including the specified message type.
    pub async fn wait_for_message_type_and_clean_queue(
        &self,
        message_direction: MessageDirection,
        message_type: u8,
    ) -> bool {
        let now = std::time::Instant::now();
        loop {
            // Blocking lock off the executor thread, plus a bound on the read itself, so the
            // elapsed check below stays reachable. See the note in `wait_for_message_type`;
            // this path had the same unbounded shape until #408.
            //
            // Note this read MUTATES — `has_message_type_with_remove` drains the queue up to
            // and including the match. If the timeout fires, the read may still be running and
            // may still remove messages. That is acceptable here because a timing-out read
            // means the test is failing anyway, but it is the reason this cannot simply be
            // retried in a tight loop.
            let agg = match message_direction {
                MessageDirection::ToDownstream => self.messages_from_upstream.clone(),
                MessageDirection::ToUpstream => self.messages_from_downstream.clone(),
            };
            let has_message_type = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::task::spawn_blocking(move || agg.has_message_type_with_remove(message_type)),
            )
            .await
            .map(|joined| joined.unwrap_or(false))
            .unwrap_or(false);

            // ready to unblock test runtime
            if has_message_type {
                return true;
            }

            // configurable timeout, 1 minute default
            if now.elapsed().as_secs() > self.timeout.unwrap_or(DEFAULT_TIMEOUT) {
                panic!(
                    "timeout while waiting for message {} to go {}",
                    message_type_to_name(message_type),
                    message_direction
                );
            }

            // sleep to reduce async lock contention
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    /// Clears all messages from the specified direction's queue.
    pub fn clean_queue(&self, message_direction: MessageDirection) {
        match message_direction {
            MessageDirection::ToDownstream => {
                self.messages_from_upstream.clear();
            }
            MessageDirection::ToUpstream => {
                self.messages_from_downstream.clear();
            }
        }
    }

    /// Checks whether the sniffer has received a message of the specified type.
    pub fn has_message_type(&self, message_direction: MessageDirection, message_type: u8) -> bool {
        match message_direction {
            MessageDirection::ToDownstream => {
                self.messages_from_upstream.has_message_type(message_type)
            }
            MessageDirection::ToUpstream => {
                self.messages_from_downstream.has_message_type(message_type)
            }
        }
    }
}

// Utility macro to assert that the downstream and upstream roles have sent specific messages.
//
// This macro can be called in two ways:
// 1. If you want to assert the message without any of its properties, you can invoke the macro
//   with the message group, the nested message group, the message, and the expected message:
//   `assert_message!(TemplateDistribution, TemplateDistribution, $msg,
// $expected_message_variant);`.
//
// 2. If you want to assert the message with its properties, you can invoke the macro with the
//  message group, the nested message group, the message, the expected message, and the expected
//  properties and values:
//  `assert_message!(TemplateDistribution, TemplateDistribution, $msg, $expected_message_variant,
//  $expected_property, $expected_property_value, ...);`.
//  Note that you can provide any number of properties and values.
//
//  In both cases, the `$message_group` could be any variant of `AnyMessage::$message_group` and
//  the `$nested_message_group` could be any variant of
//  `AnyMessage::$message_group($nested_message_group)`.
//
//  If you dont want to provide the `$message_group` and `$nested_message_group` arguments, you can
//  utilize `assert_common_message!`, `assert_tp_message!`, `assert_mining_message!`, and
//  `assert_jd_message!` macros. All those macros are just wrappers around `assert_message!` macro
//  with predefined `$message_group` and `$nested_message_group` arguments. They also can be called
//  in two ways, with or without properties validation.
#[macro_export]
macro_rules! assert_message {
  ($message_group:ident, $nested_message_group:ident, $msg:expr, $expected_message_variant:ident,
   $($expected_property:ident, $expected_property_value:expr),*) => { match $msg {
	  Some((_, message)) => {
		match message {
		  AnyMessage::$message_group($nested_message_group::$expected_message_variant(
			  $expected_message_variant {
				$($expected_property,)*
				  ..
			  },
		  )) => {
			$(
			  assert_eq!($expected_property.clone(), $expected_property_value);
			)*
		  }
		  _ => {
			panic!(
			  "Sent wrong message: {:?}",
			  message
			);
		  }
		}
	  }
	  _ => panic!("No message received"),
		}
  };
  ($message_group:ident, $nested_message_group:ident, $msg:expr, $expected_message_variant:ident) => {
	match $msg {
	  Some((_, message)) => {
		match message {
		  AnyMessage::$message_group($nested_message_group::$expected_message_variant(_)) => {}
		  _ => {
			panic!(
			  "Sent wrong message: {:?}",
			  message
			);
		  }
		}
	  }
	  _ => panic!("No message received"),
		}
  };
}

// Assert that the message is a common message and that it has the expected properties and values.
#[macro_export]
macro_rules! assert_common_message {
  ($msg:expr, $expected_message_variant:ident, $($expected_property:ident, $expected_property_value:expr),*) => {
	assert_message!(Common, CommonMessages, $msg, $expected_message_variant, $($expected_property, $expected_property_value),*);
  };
  ($msg:expr, $expected_message_variant:ident) => {
	assert_message!(Common, CommonMessages, $msg, $expected_message_variant);
  };
}

// Assert that the message is a template distribution message and that it has the expected
// properties and values.
#[macro_export]
macro_rules! assert_tp_message {
  ($msg:expr, $expected_message_variant:ident, $($expected_property:ident, $expected_property_value:expr),*) => {
	assert_message!(TemplateDistribution, TemplateDistribution, $msg, $expected_message_variant, $($expected_property, $expected_property_value),*);
  };
  ($msg:expr, $expected_message_variant:ident) => {
	assert_message!(TemplateDistribution, TemplateDistribution, $msg, $expected_message_variant);
  };
}

// Assert that the message is a mining message and that it has the expected properties and values.
#[macro_export]
macro_rules! assert_mining_message {
  ($msg:expr, $expected_message_variant:ident, $($expected_property:ident, $expected_property_value:expr),*) => {
	assert_message!(Mining, Mining, $msg, $expected_message_variant, $($expected_property, $expected_property_value),*);
  };
  ($msg:expr, $expected_message_variant:ident) => {
	assert_message!(Mining, Mining, $msg, $expected_message_variant);
  };
}

// Assert that the message is a job declaration message and that it has the expected properties and
// values.
#[macro_export]
macro_rules! assert_jd_message {
  ($msg:expr, $expected_message_variant:ident, $($expected_property:ident, $expected_property_value:expr),*) => {
	assert_message!(JobDeclaration, JobDeclaration, $msg, $expected_message_variant, $($expected_property, $expected_property_value),*);
  };
  ($msg:expr, $expected_message_variant:ident) => {
	assert_message!(JobDeclaration, JobDeclaration, $msg, $expected_message_variant);
  };
}

// This implementation is used in order to check if a test has handled all messages sent by the
// downstream and upstream roles. If not, the test will panic.
//
// This is useful to ensure that the test has checked all exchanged messages between the roles.
impl Drop for Sniffer<'_> {
    fn drop(&mut self) {
        if self.check_on_drop {
            match (
                self.messages_from_downstream.is_empty(),
                self.messages_from_upstream.is_empty(),
            ) {
                (true, true) => {}
                (true, false) => {
                    println!(
                        "Sniffer {}: You didn't handle all upstream messages: {:?}",
                        self.identifier, self.messages_from_upstream
                    );
                    panic!();
                }
                (false, true) => {
                    println!(
                        "Sniffer {}: You didn't handle all downstream messages: {:?}",
                        self.identifier, self.messages_from_downstream
                    );
                    panic!();
                }
                (false, false) => {
                    println!(
                        "Sniffer {}: You didn't handle all downstream messages: {:?}",
                        self.identifier, self.messages_from_downstream
                    );
                    println!(
                        "Sniffer {}: You didn't handle all upstream messages: {:?}",
                        self.identifier, self.messages_from_upstream
                    );
                    panic!();
                }
            }
        }
    }
}

#[cfg(test)]
mod poll_loop_liveness_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A held queue lock must not be able to postpone the sniffer's own timeout.
    ///
    /// The queue sits behind a blocking `std::sync::Mutex` and the elapsed check runs AFTER
    /// the read, so a read that does not return makes the timeout unreachable. That is why a
    /// coverage run hung for six hours rather than failing in one minute (#408).
    ///
    /// This holds the lock from a separate OS thread for far longer than the sniffer timeout
    /// and asserts `wait_for_message_type` still gives up roughly on schedule. Without the
    /// bounded read it gives up only once the lock is released, which is the bug.
    #[tokio::test(flavor = "current_thread")]
    async fn a_held_queue_lock_cannot_postpone_the_timeout() {
        const SNIFFER_TIMEOUT_S: u64 = 2;
        const LOCK_HELD_S: u64 = 12;

        let agg = MessagesAggregator::new();
        let holder = agg.clone();
        std::thread::spawn(move || {
            holder
                .messages_for_test()
                .safe_lock(|_| std::thread::sleep(Duration::from_secs(LOCK_HELD_S)))
                .unwrap();
        });
        std::thread::sleep(Duration::from_millis(200));

        let sniffer = Sniffer::for_timeout_test(agg, Some(SNIFFER_TIMEOUT_S));

        // wait_for_message_type panics on timeout, so run it in a task: a panicking task
        // comes back as a JoinError rather than unwinding the test.
        let started = Instant::now();
        let handle = tokio::spawn(async move {
            sniffer
                .wait_for_message_type(MessageDirection::ToUpstream, 0x00)
                .await;
        });
        let result = tokio::time::timeout(Duration::from_secs(LOCK_HELD_S + 6), handle).await;
        let elapsed = started.elapsed();

        let joined = result.expect("wait_for_message_type never returned while the lock was held");
        assert!(
            joined.is_err(),
            "expected the sniffer timeout to fire (it panics on timeout)"
        );
        assert!(
            elapsed < Duration::from_secs(LOCK_HELD_S - 2),
            "gave up after {elapsed:?}, i.e. only once the lock was released after \
             {LOCK_HELD_S}s — the read is still postponing the timeout"
        );
    }

    /// Same guarantee for `assert_message_not_present`.
    ///
    /// #450 hardened only `wait_for_message_type`, leaving this path with the original
    /// unbounded shape. `test_assert_message_not_present` exercises both, so the test could
    /// still hang — which is why #408 stayed open after that fix.
    ///
    /// Unlike its sibling this returns a bool rather than panicking, so the assertion is that
    /// it returns `true` (no message seen) on roughly its own deadline instead of waiting out
    /// the lock.
    #[tokio::test(flavor = "current_thread")]
    async fn a_held_lock_cannot_postpone_assert_message_not_present() {
        const DEADLINE_S: u64 = 2;
        const LOCK_HELD_S: u64 = 12;

        let agg = MessagesAggregator::new();
        let holder = agg.clone();
        std::thread::spawn(move || {
            holder
                .messages_for_test()
                .safe_lock(|_| std::thread::sleep(Duration::from_secs(LOCK_HELD_S)))
                .unwrap();
        });
        std::thread::sleep(Duration::from_millis(200));

        let sniffer = Sniffer::for_timeout_test(agg, None);

        let started = Instant::now();
        let absent = sniffer
            .assert_message_not_present(
                MessageDirection::ToUpstream,
                0x00,
                Duration::from_secs(DEADLINE_S),
            )
            .await;
        let elapsed = started.elapsed();

        assert!(
            absent,
            "no message was ever queued, so this must report the type as absent"
        );
        assert!(
            elapsed < Duration::from_secs(LOCK_HELD_S - 2),
            "returned after {elapsed:?}, i.e. only once the lock was released after \
             {LOCK_HELD_S}s — the read is still postponing the deadline"
        );
    }

    /// Same guarantee for `wait_for_message_type_and_clean_queue`, the third read path.
    ///
    /// Like `wait_for_message_type` it panics on timeout, so it runs in a task and the
    /// `JoinError` is the signal.
    #[tokio::test(flavor = "current_thread")]
    async fn a_held_lock_cannot_postpone_the_clean_queue_timeout() {
        const SNIFFER_TIMEOUT_S: u64 = 2;
        const LOCK_HELD_S: u64 = 12;

        let agg = MessagesAggregator::new();
        let holder = agg.clone();
        std::thread::spawn(move || {
            holder
                .messages_for_test()
                .safe_lock(|_| std::thread::sleep(Duration::from_secs(LOCK_HELD_S)))
                .unwrap();
        });
        std::thread::sleep(Duration::from_millis(200));

        let sniffer = Sniffer::for_timeout_test(agg, Some(SNIFFER_TIMEOUT_S));

        let started = Instant::now();
        let handle = tokio::spawn(async move {
            sniffer
                .wait_for_message_type_and_clean_queue(MessageDirection::ToUpstream, 0x00)
                .await;
        });
        let result = tokio::time::timeout(Duration::from_secs(LOCK_HELD_S + 6), handle).await;
        let elapsed = started.elapsed();

        let joined = result.expect("the clean-queue read never returned while the lock was held");
        assert!(
            joined.is_err(),
            "expected the sniffer timeout to fire (it panics on timeout)"
        );
        assert!(
            elapsed < Duration::from_secs(LOCK_HELD_S - 2),
            "gave up after {elapsed:?}, i.e. only once the lock was released after \
             {LOCK_HELD_S}s — the read is still postponing the timeout"
        );
    }
}
