//! # Collection of Helper Primitives
//!
//! Provides a collection of utilities and helper structures used throughout the Stratum V2
//! protocol implementation. These utilities simplify common tasks, such as ID generation and
//! management, mutex management, difficulty target calculations, merkle root calculations, and
//! more.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex as Mutex_, MutexGuard, PoisonError};

/// Custom synchronization primitive for managing shared mutable state.
///
/// This custom mutex implementation builds on [`std::sync::Mutex`] to enhance usability and safety
/// in concurrent environments. It provides ergonomic methods to safely access and modify inner
/// values while reducing the risk of deadlocks and panics. It is used throughout SRI applications
/// to managed shared state across multiple threads, such as tracking active mining sessions,
/// routing jobs, and managing connections safely and efficiently.
///
/// ## Advantages
/// - **Closure-Based Locking:** The `safe_lock` method encapsulates the locking process, ensuring
///   the lock is automatically released after the closure completes.
/// - **Error Handling:** `safe_lock` enforces explicit handling of potential [`PoisonError`]
///   conditions, reducing the risk of panics caused by poisoned locks.
/// - **Panic-Safe Option:** The `super_safe_lock` method provides an alternative that unwraps the
///   result of `safe_lock`, with optional runtime safeguards against panics.
/// - **Extensibility:** Includes feature-gated functionality to customize behavior, such as
///   stricter runtime checks using external tools like
///   [`no-panic`](https://github.com/dtolnay/no-panic).
#[derive(Debug)]
pub struct Mutex<T: ?Sized> {
    /// Set once the first poisoning is reported, so a poisoned mutex says so exactly once
    /// instead of on every access. A hot lock would otherwise emit thousands of identical
    /// lines and bury the panic that caused it.
    poison_reported: AtomicBool,
    inner: Mutex_<T>,
}

impl<T> Mutex<T> {
    /// Mutex safe lock.
    ///
    /// Safely locks the `Mutex` and executes a closer (`thunk`) with a mutable reference to the
    /// inner value. This ensures that the lock is automatically released after the closure
    /// completes, preventing deadlocks. It explicitly returns a [`PoisonError`] containing a
    /// [`MutexGuard`] to the inner value in cases where the lock is poisoned.
    ///
    /// To prevent poison lock errors, unwraps should never be used within the closure. The result
    /// should always be returned and handled outside of the sage lock.
    pub fn safe_lock<F, Ret>(&self, thunk: F) -> Result<Ret, PoisonError<MutexGuard<'_, T>>>
    where
        F: FnOnce(&mut T) -> Ret,
    {
        let mut lock = self.inner.lock()?;
        let return_value = thunk(&mut *lock);
        drop(lock);
        Ok(return_value)
    }

    /// Mutex super safe lock.
    ///
    /// Locks the `Mutex` and executes a closure (`thunk`) with a mutable reference to the inner
    /// value, RECOVERING if the lock is poisoned rather than panicking.
    ///
    /// ⚠ This used to `unwrap()`, and that turned one panic into an outage. `std::sync::Mutex`
    /// poisons when a holder panics, so every subsequent `super_safe_lock` on the same mutex
    /// panicked too — and there are ~198 call sites across translator-sv2, pool-sv2 and
    /// jd-client-sv2. Measured on ghost-vm2: a single panic in the SV1 downstream path
    /// cascaded until the process held no listener at all, while systemd still reported
    /// `active` and `NRestarts` stayed 0 (#812).
    ///
    /// Recovering is the right trade here, and deliberately so. Poisoning means "a previous
    /// holder panicked, so this data MAY be inconsistent" — a real signal, but the response of
    /// killing every future reader converts a possibly-stale field into a dead node. The useful
    /// half of the signal is keeping it VISIBLE, which the log below does; the harmful half was
    /// the cascade.
    ///
    /// `safe_lock` is unchanged and still returns `Err` on poison, so a caller that genuinely
    /// needs to refuse to proceed on inconsistent data can still do so explicitly.
    pub fn super_safe_lock<F, Ret>(&self, thunk: F) -> Ret
    where
        F: FnOnce(&mut T) -> Ret,
    {
        let mut lock = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                // Report once per mutex. `swap` so concurrent readers cannot both log.
                if !self.poison_reported.swap(true, Ordering::Relaxed) {
                    tracing::error!(
                        "mutex was poisoned by a panicking holder — recovering and continuing. \
                         The data behind it may be inconsistent; the panic that caused this is \
                         earlier in this log and is the thing to fix (#812)."
                    );
                }
                poisoned.into_inner()
            }
        };
        let return_value = thunk(&mut *lock);
        drop(lock);
        return_value
        //#[cfg(not(feature = "disable_nopanic"))]
        //{
        //    // based on https://github.com/dtolnay/no-panic
        //    struct __NoPanic;
        //    extern "C" {
        //        #[link_name = "super_safe_lock called on a function that may panic"]
        //        fn trigger() -> !;
        //    }
        //    impl core::ops::Drop for __NoPanic {
        //        fn drop(&mut self) {
        //            unsafe {
        //                trigger();
        //            }
        //        }
        //    }
        //    let mut lock = self.0.lock().expect("threads to never panic");
        //    let __guard = __NoPanic;
        //    let return_value = thunk(&mut *lock);
        //    core::mem::forget(__guard);
        //    drop(lock);
        //    return_value
        //}
    }

    /// Creates a new [`Mutex`] instance, storing the initial value inside.
    pub fn new(v: T) -> Self {
        Mutex {
            poison_reported: AtomicBool::new(false),
            inner: Mutex_::new(v),
        }
    }

    /// Removes lock for direct access.
    ///
    /// Acquires a lock on the [`Mutex`] and returns a [`MutexGuard`] for direct access to the
    /// inner value. Allows for manual lock handling and is useful in scenarios where closures are
    /// not convenient.
    pub fn to_remove(&self) -> Result<MutexGuard<'_, T>, PoisonError<MutexGuard<'_, T>>> {
        self.inner.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::Mutex;
    use std::sync::Arc;

    #[test]
    fn test_super_safe_lock() {
        let m = Mutex::new(1u32);
        m.safe_lock(|i| *i += 1).unwrap();
        // m.super_safe_lock(|i| *i = (*i).checked_add(1).unwrap()); // will not compile
        m.super_safe_lock(|i| *i = (*i).checked_add(1).unwrap_or_default()); // compiles
    }

    /// Poison a mutex the way production does: panic while holding it.
    fn poison(m: &Arc<Mutex<u32>>) {
        let m2 = Arc::clone(m);
        let _ = std::thread::spawn(move || {
            let _ = m2.safe_lock(|_| panic!("holder panicked"));
        })
        .join();
        assert!(m.to_remove().is_err(), "the mutex should now be poisoned");
    }

    // #812: `super_safe_lock` used to `unwrap()` the poison error, so ONE panic anywhere made
    // every later access to that mutex panic too. With ~198 call sites across three binaries
    // that turned a contained fault into a node holding no listener while systemd said `active`.

    #[test]
    fn a_poisoned_mutex_no_longer_kills_every_later_reader() {
        let m = Arc::new(Mutex::new(7u32));
        poison(&m);
        // Before the fix this panicked. It must now return the value.
        assert_eq!(m.super_safe_lock(|v| *v), 7);
    }

    #[test]
    fn a_poisoned_mutex_stays_usable_for_writes_too() {
        let m = Arc::new(Mutex::new(1u32));
        poison(&m);
        m.super_safe_lock(|v| *v += 41);
        assert_eq!(
            m.super_safe_lock(|v| *v),
            42,
            "recovered mutex must still mutate"
        );
    }

    #[test]
    fn repeated_access_to_a_poisoned_mutex_keeps_working() {
        // The cascade was not one panic but every subsequent one. Hammer it.
        let m = Arc::new(Mutex::new(0u32));
        poison(&m);
        for _ in 0..1000 {
            m.super_safe_lock(|v| *v += 1);
        }
        assert_eq!(m.super_safe_lock(|v| *v), 1000);
    }

    #[test]
    fn safe_lock_is_unchanged_and_still_refuses_a_poisoned_mutex() {
        // The strict variant is the escape hatch for callers who must NOT proceed on
        // possibly-inconsistent data. Recovering in `super_safe_lock` must not quietly take
        // that away — if this ever passes, the fix has gone too far.
        let m = Arc::new(Mutex::new(1u32));
        poison(&m);
        assert!(
            m.safe_lock(|v| *v).is_err(),
            "safe_lock must still return Err on a poisoned mutex"
        );
    }

    #[test]
    fn an_unpoisoned_mutex_behaves_exactly_as_before() {
        // The accept-side control: recovery must not change the normal path.
        let m = Mutex::new(10u32);
        assert_eq!(m.super_safe_lock(|v| *v), 10);
        m.super_safe_lock(|v| *v *= 2);
        assert_eq!(m.safe_lock(|v| *v).expect("not poisoned"), 20);
        assert!(m.to_remove().is_ok());
    }
}
