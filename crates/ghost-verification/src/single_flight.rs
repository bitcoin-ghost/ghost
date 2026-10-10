//! Run one expensive blocking computation at a time, and let everyone who asked while it ran
//! share its answer.
//!
//! Built for `/api/v1/qualification/scoped-set` (#1002). That endpoint derives the qualified
//! sets, the node list and the checkpoint roots from the database on every call — 4-6s on the
//! fleet, MEASURED 2026-10-10 after the liar-set hoist (was 23.6s). Two things were wrong with
//! running that inline in an `async fn`:
//!
//!   * it pinned an async worker for the whole derivation, on 2-CPU nodes (#537, #554), so
//!     unrelated endpoints stalled behind it; and
//!   * nothing bounded how many ran at once, so N impatient callers cost N derivations.
//!
//! [`SingleFlight::run`] moves the work to the blocking pool and admits one computation at a
//! time. A caller that had to wait is handed the result that completed *while it was waiting*.
//!
//! ## Why this is not a TTL cache
//!
//! The endpoint is a convergence instrument: `check-fleet-convergence.sh` samples all eight
//! nodes near-simultaneously because `advert_root` is a function of live state, and a node
//! answering from a memo N seconds old is a node sampled N seconds earlier than the others.
//! So an answer is only ever reused by a caller who was already waiting when it was produced —
//! it is never older than the request it is served to. A caller arriving after a computation
//! has finished always gets a fresh one.

use std::sync::Arc;
use std::time::Instant;

/// See the module docs.
pub struct SingleFlight<T> {
    /// `(when the computation finished, its answer)`. The lock is the admission control: it is
    /// held for the whole computation, so holding it means nothing else is in flight.
    last: Arc<tokio::sync::Mutex<Option<(Instant, T)>>>,
}

impl<T> Default for SingleFlight<T> {
    fn default() -> Self {
        Self {
            last: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

impl<T: Clone + Send + 'static> SingleFlight<T> {
    /// Run `compute` on the blocking pool, unless a computation finished after this call began
    /// — in which case return that answer and never call `compute`.
    ///
    /// `Err` only if `compute` panicked. Nothing is remembered in that case, so the next caller
    /// computes again.
    pub async fn run<F>(&self, compute: F) -> Result<T, tokio::task::JoinError>
    where
        F: FnOnce() -> T + Send + 'static,
    {
        let arrived = Instant::now();
        let mut last = Arc::clone(&self.last).lock_owned().await;
        if let Some((finished, answer)) = last.as_ref() {
            if *finished >= arrived {
                return Ok(answer.clone());
            }
        }
        // The guard moves INTO the blocking task. A client that hangs up drops this future, and
        // if the guard lived here the lock would be released with the computation still running
        // — the next caller would start a second one beside it, which is the unbounded case
        // this type exists to prevent.
        tokio::task::spawn_blocking(move || {
            let answer = compute();
            *last = Some((Instant::now(), answer.clone()));
            answer
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A computation that counts its runs, records the most that were ever in flight together,
    /// and returns its own run number so callers can tell which run answered them.
    fn counted(
        runs: &Arc<AtomicUsize>,
        in_flight: &Arc<AtomicUsize>,
        peak: &Arc<AtomicUsize>,
        hold: Duration,
    ) -> impl FnOnce() -> usize + Send + 'static {
        let (runs, in_flight, peak) = (Arc::clone(runs), Arc::clone(in_flight), Arc::clone(peak));
        move || {
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(hold);
            in_flight.fetch_sub(1, Ordering::SeqCst);
            runs.fetch_add(1, Ordering::SeqCst) + 1
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn callers_who_arrive_during_a_computation_never_overlap_it() {
        let flight = Arc::new(SingleFlight::<usize>::default());
        let runs = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut callers = Vec::new();
        for _ in 0..8 {
            let flight = Arc::clone(&flight);
            let compute = counted(&runs, &in_flight, &peak, Duration::from_millis(300));
            callers.push(tokio::spawn(async move { flight.run(compute).await }));
        }
        let mut answers = Vec::new();
        for c in callers {
            answers.push(c.await.expect("caller task").expect("computation"));
        }

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "two derivations ran side by side"
        );
        // Eight callers, far fewer derivations. Not asserted as exactly 1: a caller the
        // scheduler starts late arrives after the first run finished and is owed a fresh one.
        let ran = runs.load(Ordering::SeqCst);
        assert!((1..8).contains(&ran), "8 callers cost {ran} derivations");
        assert!(answers.iter().all(|a| (1..=ran).contains(a)), "{answers:?}");
    }

    #[tokio::test]
    async fn a_caller_arriving_after_a_computation_finished_gets_a_fresh_one() {
        let flight = SingleFlight::<usize>::default();
        let runs = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let first = flight
            .run(counted(&runs, &in_flight, &peak, Duration::ZERO))
            .await
            .expect("first");
        // `Instant` is monotonic but coarse on some platforms; make "after" unambiguous.
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second = flight
            .run(counted(&runs, &in_flight, &peak, Duration::ZERO))
            .await
            .expect("second");

        assert_eq!(
            (first, second),
            (1, 2),
            "a finished answer was served to a later caller"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_caller_who_hangs_up_does_not_let_a_second_computation_start() {
        let flight = Arc::new(SingleFlight::<usize>::default());
        let runs = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let abandoned = {
            let flight = Arc::clone(&flight);
            let compute = counted(&runs, &in_flight, &peak, Duration::from_millis(400));
            tokio::spawn(async move { flight.run(compute).await })
        };
        // Let it get into the blocking task, then hang up on it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            1,
            "first computation never started"
        );
        abandoned.abort();
        let _ = abandoned.await;

        let answer = flight
            .run(counted(&runs, &in_flight, &peak, Duration::from_millis(50)))
            .await
            .expect("second");

        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "ran beside the abandoned computation"
        );
        // The abandoned run still finished, and it finished after this caller arrived.
        assert_eq!((answer, runs.load(Ordering::SeqCst)), (1, 1));
    }

    #[tokio::test]
    async fn a_panicking_computation_is_an_error_and_is_not_remembered() {
        let flight = SingleFlight::<usize>::default();
        let failed = flight.run(|| panic!("derivation blew up")).await;
        assert!(failed.is_err());
        assert_eq!(flight.run(|| 7).await.expect("recovers"), 7);
    }
}
