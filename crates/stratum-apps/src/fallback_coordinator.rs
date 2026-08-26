use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// coordinates fallback operations across multiple components with acknowledgement.
///
/// this is meant to be used together with [`crate::task_manager::TaskManager`],
/// as it allows triggering a fallback event (via [`CancellationToken`]) and waiting
/// until all registered components have completed their cleanup.
///
/// in summary, every time we spawn a fallback-relevant task inside the manager, we MUST:
/// - call [`FallbackCoordinator::register`] at task bootstrap
/// - call [`FallbackCoordinator::done`] at task completion
///
/// when a fallback trigger arrives to the main status loop, we MUST call
/// [`FallbackCoordinator::trigger_and_wait`] to wait for all registered components to complete
/// their cleanup before re-initializing them under the new upstream server.
///
/// finally, a new [`FallbackCoordinator`] must be instantiated for the next fallback cycle.
#[derive(Debug, Clone)]
pub struct FallbackCoordinator {
    signal: CancellationToken,
    pending_tasks: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Default for FallbackCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl FallbackCoordinator {
    pub fn new() -> Self {
        Self {
            signal: CancellationToken::new(),
            pending_tasks: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// register a component that will participate in fallback coordination
    /// returns a [`FallbackHandler`] that must be called when the component is done
    #[must_use]
    pub fn register(&self) -> FallbackHandler {
        tracing::debug!("FallbackCoordinator: registering component");
        self.pending_tasks.fetch_add(1, Ordering::Relaxed);

        FallbackHandler {
            coordinator: self.clone(),
            done: AtomicBool::new(false),
        }
    }

    /// get the cancellation token that signals fallback
    pub fn token(&self) -> CancellationToken {
        self.signal.clone()
    }

    /// trigger fallback and wait for all registered components to acknowledge
    pub async fn trigger_fallback_and_wait(&self) {
        tracing::debug!("FallbackCoordinator: triggering fallback");
        self.signal.cancel();

        if self.pending_tasks.load(Ordering::Acquire) == 0 {
            return; // all tasks already done
        }

        // there's still some tasks running,
        // wait for the last task to notify us
        self.notify.notified().await;
        tracing::debug!("FallbackCoordinator: finished waiting for components to complete cleanup");
    }
}

pub struct FallbackHandler {
    coordinator: FallbackCoordinator,
    done: AtomicBool,
}

/// Handler for a component that will participate in fallback coordination
///
/// ⚠️ Warning: dropping this handler without calling [`FallbackHandler::done`] will result in a
/// panic.
impl FallbackHandler {
    /// Mark this handler as finished
    /// Takes ownership of `self`, preventing double-calling
    pub fn done(self) {
        tracing::debug!("FallbackHandler: done called");
        self.done.store(true, Ordering::Release);

        let prev = self
            .coordinator
            .pending_tasks
            .fetch_sub(1, Ordering::Release);

        // Notify if fallback has been triggered and this is the last handler
        if self.coordinator.signal.is_cancelled() && prev == 1 {
            self.coordinator.notify.notify_one();
        }
    }
}

impl Drop for FallbackHandler {
    fn drop(&mut self) {
        if self.done.load(Ordering::Acquire) {
            return;
        }

        // The slot is released even on this path, and that is not tidiness.
        //
        // A handler that is dropped without `done()` belongs to a component that is gone and can
        // never acknowledge. Leaving `pending_tasks` incremented makes
        // `trigger_fallback_and_wait` wait for it for ever — so the panic below was standing in
        // front of a hang, and removing the panic without this would simply reveal it.
        let prev = self
            .coordinator
            .pending_tasks
            .fetch_sub(1, Ordering::Release);
        if self.coordinator.signal.is_cancelled() && prev == 1 {
            self.coordinator.notify.notify_one();
        }

        // ⛔ Never panic while the thread is ALREADY unwinding. A panic inside `Drop` during an
        // unwind is a double panic, and a double panic ABORTS the process — no unwinding, no
        // cleanup, no test result, no error propagated to a caller who could have handled the
        // original failure.
        //
        // Measured: in the SV2 integration tests a sniffer's Noise handshake timed out and
        // panicked its spawned task; this `Drop` then turned that into an abort, and the test
        // binary died after 66s with no `test result` line at all — neither pass nor fail, and
        // the remaining tests in the target never ran (#617). The original panic is the one
        // worth seeing; this one only destroyed the evidence.
        if std::thread::panicking() {
            tracing::error!(
                "FallbackHandler dropped without calling done() while the thread was already \
                 panicking — released its slot and declined to panic again, because a panic in \
                 Drop during an unwind aborts the process. The original panic follows."
            );
            return;
        }

        panic!("FallbackHandler dropped without calling done()");
    }
}

#[cfg(test)]
mod fallback_handler_drop_tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    /// ⛔ The regression this exists for: a panic inside `Drop` during an unwind is a double
    /// panic, which ABORTS. An aborted process cannot report a test failure, cannot run the
    /// rest of its tests, and cannot be caught here — so if this ever regresses, this test does
    /// not fail, it takes the whole test binary with it. That is the point: the failure mode is
    /// severe enough that it must be impossible, not merely reported.
    #[test]
    fn a_handler_dropped_mid_panic_does_not_panic_again() {
        let coordinator = FallbackCoordinator::new();
        let handler = coordinator.register();

        let result = catch_unwind(AssertUnwindSafe(move || {
            let _handler = handler;
            panic!("the original failure");
        }));

        // The ORIGINAL panic survives and is what a caller sees.
        assert!(result.is_err(), "the original panic must propagate");
    }

    /// The slot must be released on the panic path too, or the coordinator waits for a component
    /// that no longer exists — trading an abort for a hang, which is not an improvement.
    #[test]
    fn a_handler_dropped_mid_panic_releases_its_slot() {
        let coordinator = FallbackCoordinator::new();
        let handler = coordinator.register();
        assert_eq!(coordinator.pending_tasks.load(Ordering::Acquire), 1);

        let _ = catch_unwind(AssertUnwindSafe(move || {
            let _handler = handler;
            panic!("the original failure");
        }));

        assert_eq!(
            coordinator.pending_tasks.load(Ordering::Acquire),
            0,
            "a dead component must not hold a slot: trigger_fallback_and_wait would wait for it \
             for ever"
        );
    }

    /// The invariant is still enforced where enforcing it is safe. Dropping a handler without
    /// `done()` in normal operation is a programming error and must stay loud.
    #[test]
    fn a_handler_dropped_normally_without_done_still_panics() {
        let coordinator = FallbackCoordinator::new();
        let handler = coordinator.register();

        let result = catch_unwind(AssertUnwindSafe(move || {
            drop(handler);
        }));

        assert!(
            result.is_err(),
            "dropping without done() outside an unwind must still panic"
        );
    }

    /// And the happy path stays silent.
    #[test]
    fn done_releases_the_slot_and_does_not_panic() {
        let coordinator = FallbackCoordinator::new();
        let handler = coordinator.register();
        handler.done();
        assert_eq!(coordinator.pending_tasks.load(Ordering::Acquire), 0);
    }
}
