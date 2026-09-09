//! Keeping a list of upstreams sweepable across failovers.
//!
//! `translator-sv2` and `jd-client-sv2` both hold their upstreams in a list whose entries carry a
//! `tried_or_flagged` bool. Each connection pass walks the list in order and skips anything
//! already flagged. The flag is raised both when an upstream connects and when it exhausts its
//! retries — and nothing ever lowered it again, which made the list one-shot.
//!
//! With the usual two upstreams that bought exactly one failover per process. The first upstream
//! is flagged when it connects at startup; the second when the failover reaches it. Any later
//! upstream loss finds every entry flagged, attempts nothing, and returns
//! `CouldNotInitiateSystem` — so the role shuts down instead of going back to the first upstream,
//! even when that upstream has been healthy again for hours.
//!
//! [`stale_upstreams`] makes the list a ring instead. When a pass fails, entries that *this* call
//! never attempted — flagged by some earlier call, and so carrying no information about now — are
//! re-armed for one more pass. Entries this call has already tried and failed keep their flag, so
//! a pass never repeats work and the sweep always terminates.

/// The entries whose flag is stale, and which should therefore be re-armed for another pass.
///
/// `flags[i]` is entry `i`'s `tried_or_flagged`; `attempted[i]` says whether the caller has tried
/// entry `i` during the current call. An entry is stale when it is flagged but was never
/// attempted here: the flag is a leftover from an earlier connection, not a verdict on this one.
///
/// An empty result means every entry has now been tried and there is genuinely nothing left —
/// which is what the caller should treat as failure.
pub fn stale_upstreams(flags: &[bool], attempted: &[bool]) -> Vec<usize> {
    debug_assert_eq!(
        flags.len(),
        attempted.len(),
        "flags and attempted describe the same list"
    );

    (0..flags.len())
        .filter(|&i| flags[i] && !attempted.get(i).copied().unwrap_or(false))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_list_has_nothing_to_rearm() {
        assert!(stale_upstreams(&[false, false], &[false, false]).is_empty());
    }

    #[test]
    fn an_upstream_flagged_by_an_earlier_call_is_rearmed() {
        // The shape of a second failover: entry 0 was connected to earlier (flagged then), entry
        // 1 was tried and failed just now. Before this existed the pass ended here and the role
        // shut down; entry 0 is exactly the upstream it should go back to.
        assert_eq!(stale_upstreams(&[true, true], &[false, true]), vec![0]);
    }

    #[test]
    fn an_upstream_this_call_already_tried_is_not_rearmed() {
        // Both were attempted and both failed. Re-arming either would loop for ever.
        assert!(stale_upstreams(&[true, true], &[true, true]).is_empty());
    }

    #[test]
    fn every_stale_entry_is_rearmed_not_only_the_first() {
        assert_eq!(
            stale_upstreams(&[true, true, true], &[false, true, false]),
            vec![0, 2]
        );
    }

    #[test]
    fn an_empty_list_is_not_a_panic() {
        assert!(stale_upstreams(&[], &[]).is_empty());
    }
}
