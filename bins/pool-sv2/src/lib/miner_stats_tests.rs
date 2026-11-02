//! Tests for the per-worker share statistics: bucket math, rollover, gaps, restarts, reasons.

use super::*;

/// An hour boundary (500,000 hours after the epoch).
const T0: u64 = 1_800_000_000;
const S: &[u8] = &[
    0x00, 0x14, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
];

fn acc(d: f64) -> Outcome {
    Outcome::Accepted { difficulty: d }
}

#[test]
fn worker_names_are_what_follows_the_first_dot_and_sanitized() {
    assert_eq!(worker_name("bc1qabc.rig1"), "rig1");
    assert_eq!(worker_name("bc1qabc.rig.a"), "rig.a");
    assert_eq!(worker_name("bc1qabc"), "");
    assert_eq!(worker_name("bc1qabc."), "");
    assert_eq!(worker_name("bc1qabc. s19 <b>"), "s19__b_");
    assert_eq!(
        worker_name(&format!("a.{}", "x".repeat(99))).len(),
        MAX_WORKER_NAME
    );
}

#[test]
fn shares_land_in_their_bucket_and_roll_over() {
    let m = MinerStats::in_memory(T0);
    m.record(S, "a", acc(1024.0), T0 + 1);
    m.record(S, "a", acc(1024.0), T0 + 299);
    m.record(S, "a", acc(2048.0), T0 + 300);
    m.record(S, "a", Outcome::Stale, T0 + 301);
    let s = m.snapshot(S, T0 + 400);
    let w = &s.workers["a"];
    let fine: Vec<_> = w
        .fine
        .buckets()
        .map(|b| (b.start, b.accepted, b.work, b.stale))
        .collect();
    assert_eq!(
        fine,
        vec![(T0, 2, 2048.0, 0), (T0 + 300, 1, 2048.0, 1)],
        "a 5-minute boundary starts a new bucket"
    );
    let coarse: Vec<_> = w.coarse.buckets().map(|b| (b.start, b.accepted)).collect();
    assert_eq!(coarse, vec![(T0, 3)], "one hour bucket");
    assert_eq!(w.last_share_at, Some(T0 + 300));
    assert_eq!(w.last_submit_at, T0 + 301);
}

#[test]
fn rings_keep_their_span_and_no_more() {
    let m = MinerStats::in_memory(T0);
    m.record(S, "a", acc(1.0), T0);
    // 24 h later the fine bucket at T0 has left its ring; the coarse one has not.
    let later = T0 + 86_400;
    m.record(S, "a", acc(1.0), later);
    let s = m.snapshot(S, later);
    let w = &s.workers["a"];
    assert_eq!(w.fine.buckets().count(), 1);
    assert_eq!(w.fine.buckets().next().unwrap().start, later);
    assert_eq!(w.coarse.buckets().count(), 2);
    // Exactly the oldest kept bucket survives.
    assert_eq!(Ring::oldest_kept(FINE, later), later - 287 * 300);
    // 30 days on the coarse one goes too, and a worker silent that long is dropped.
    m.prune(later + COARSE.span() + 1);
    assert_eq!(m.worker_count(), 0);
    assert!(m.snapshot(S, later + COARSE.span() + 1).workers.is_empty());
}

#[test]
fn a_clock_step_back_counts_in_the_right_bucket() {
    let m = MinerStats::in_memory(T0);
    m.record(S, "a", acc(1.0), T0 + 900);
    m.record(S, "a", acc(1.0), T0 + 10);
    m.record(S, "a", acc(1.0), T0 + 905);
    let s = m.snapshot(S, T0 + 1_000);
    let starts: Vec<_> = s.workers["a"]
        .fine
        .buckets()
        .map(|b| (b.start, b.accepted))
        .collect();
    assert_eq!(starts, vec![(T0, 1), (T0 + 900, 2)], "kept ascending");
}

#[test]
fn reject_reasons_are_counted_by_code() {
    let m = MinerStats::in_memory(T0);
    let errs = [
        (ShareValidationError::Invalid, "invalid-share"),
        (ShareValidationError::InvalidJobId, "invalid-job-id"),
        (
            ShareValidationError::DoesNotMeetTarget,
            "difficulty-too-low",
        ),
        (ShareValidationError::DuplicateShare, "duplicate-share"),
        (
            ShareValidationError::BadExtranonceSize,
            "bad-extranonce-size",
        ),
        (ShareValidationError::NoChainTip, "other"),
    ];
    for (e, code) in errs {
        let o = Outcome::of(&Err(e), 5.0);
        match o {
            Outcome::Rejected(r) => assert_eq!(r.code(), code),
            _ => panic!("{code} is a reject"),
        }
        m.record(S, "a", o, T0);
    }
    assert_eq!(
        Outcome::of(&Err(ShareValidationError::Stale), 5.0),
        Outcome::Stale
    );
    m.record(
        S,
        "a",
        Outcome::of(&Err(ShareValidationError::Stale), 5.0),
        T0,
    );
    m.record(
        S,
        "a",
        Outcome::of(&Err(ShareValidationError::DuplicateShare), 5.0),
        T0,
    );
    let s = m.snapshot(S, T0 + 1);
    let b = s.workers["a"].fine.get(T0).unwrap();
    assert_eq!(b.rejected, [1, 1, 1, 2, 1, 1]);
    assert_eq!((b.accepted, b.stale, b.rejected_total()), (0, 1, 7));
    assert_eq!(b.work, 0.0, "rejects add no work");
    assert_eq!(s.workers["a"].last_share_at, None);
}

#[test]
fn workers_are_kept_apart_per_address_and_name() {
    let m = MinerStats::in_memory(T0);
    let other = &[
        0x00, 0x14, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ][..];
    m.record(S, "rig1", acc(10.0), T0);
    m.record(S, "rig2", acc(20.0), T0);
    m.record(S, "rig2", acc(20.0), T0);
    m.record(other, "rig1", acc(99.0), T0);
    m.record(&[], "x", acc(1.0), T0);
    assert_eq!(m.worker_count(), 3, "an empty script is not recorded");
    let s = m.snapshot(S, T0 + 1);
    assert_eq!(s.workers.keys().collect::<Vec<_>>(), ["rig1", "rig2"]);
    assert_eq!(s.workers["rig1"].fine.get(T0).unwrap().work, 10.0);
    assert_eq!(s.workers["rig2"].fine.get(T0).unwrap().work, 40.0);
    assert_eq!(
        m.snapshot(other, T0 + 1).workers["rig1"]
            .fine
            .get(T0)
            .unwrap()
            .work,
        99.0
    );
}

#[test]
fn the_worker_cap_drops_the_one_silent_longest() {
    let m = MinerStats::in_memory(T0);
    {
        let mut st = m.lock();
        st.count = MAX_WORKERS - 1;
    }
    m.record(S, "old", acc(1.0), T0);
    m.record(S, "new", acc(1.0), T0 + 10);
    assert_eq!(m.worker_count(), MAX_WORKERS);
    let s = m.snapshot(S, T0 + 20);
    assert!(!s.workers.contains_key("old") && s.workers.contains_key("new"));
}

#[test]
fn hashrate_over_a_span_is_work_over_observed_time() {
    let m = MinerStats::in_memory(T0);
    // 600 s of shares at difficulty 1,000, one every 6 s: 100 shares per 600 s.
    for i in 0..100 {
        m.record(S, "a", acc(1_000.0), T0 + i * 6);
    }
    let now = T0 + 600;
    let s = m.snapshot(S, now);
    let w = &s.workers["a"];
    let t = over_span(&w.fine, FINE, 600, s.collecting_since, now).unwrap();
    assert_eq!(t.observed_secs, 600);
    assert!((t.accepted - 100.0).abs() < 1e-9);
    let want = 100_000.0 * 4_294_967_296.0 / 600.0;
    assert!((t.hashrate_hs() - want).abs() / want < 1e-9);

    // A span longer than the history: only what was observed counts, not the whole span.
    let t = over_span(&w.fine, FINE, 86_400, s.collecting_since, now).unwrap();
    assert_eq!(t.observed_secs, 600);
    assert!((t.hashrate_hs() - want).abs() / want < 1e-9);

    // Under a minute observed: unknown.
    assert!(over_span(&w.fine, FINE, 600, now - 30, now).is_none());
}

#[test]
fn a_gap_reads_as_zero_and_a_straddling_bucket_counts_in_proportion() {
    let m = MinerStats::in_memory(T0);
    m.record(S, "a", acc(600.0), T0 + 10);
    // Nothing for an hour.
    let now = T0 + 3_900;
    let s = m.snapshot(S, now);
    let w = &s.workers["a"];
    let t = over_span(&w.fine, FINE, 900, s.collecting_since, now).unwrap();
    assert_eq!(t.work, 0.0, "the last 15 minutes saw nothing");
    // Half of the first bucket lies inside a span starting at T0 + 150.
    let t = over_span(&w.fine, FINE, now - (T0 + 150), s.collecting_since, now).unwrap();
    assert!((t.work - 300.0).abs() < 1e-9, "{}", t.work);
}

#[test]
fn bucket_starts_end_with_the_current_bucket() {
    let w = window("24h").unwrap();
    let b = bucket_starts(w, T0 + 7);
    assert_eq!(b.len(), 288);
    assert_eq!(*b.last().unwrap(), T0);
    assert_eq!(b[0], T0 - 287 * 300);
    assert_eq!(bucket_starts(window("7d").unwrap(), T0).len(), 168);
    assert_eq!(bucket_starts(window("30d").unwrap(), T0).len(), 720);
    assert!(window("1y").is_none());
    assert_eq!(observed_secs(FINE, T0, T0 + 100, T0 + 200), 100);
    assert_eq!(observed_secs(FINE, T0, T0 + 400, T0 + 500), 0);
    assert_eq!(observed_secs(FINE, T0, 0, T0 + 1_000), 300);
}

fn temp_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pool-sv2-miner-stats-{tag}-{}-{}",
        std::process::id(),
        now_secs()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("miner-stats.json")
}

#[test]
fn a_restart_keeps_the_history_and_when_it_began() {
    let path = temp_path("restart");
    let m = MinerStats::open(path.clone(), T0);
    m.record(S, "a", acc(64.0), T0 + 5);
    m.record(
        S,
        "a",
        Outcome::Rejected(RejectReason::DuplicateShare),
        T0 + 6,
    );
    m.save(T0 + 10).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    // Down for an hour, then back.
    let back = T0 + 3_600;
    let m2 = MinerStats::open(path.clone(), back);
    assert_eq!(
        m2.collecting_since(),
        T0,
        "history began before the restart"
    );
    let s = m2.snapshot(S, back);
    assert_eq!(s.workers["a"], m.snapshot(S, back).workers["a"]);
    // The hour down reads as zero, not unknown: this node saw nothing.
    let t = over_span(&s.workers["a"].fine, FINE, 1_800, s.collecting_since, back).unwrap();
    assert_eq!(t.work, 0.0);

    // A corrupt file is set aside and collection starts afresh.
    std::fs::write(&path, b"{not json").unwrap();
    let m3 = MinerStats::open(path.clone(), back);
    assert_eq!(m3.collecting_since(), back);
    assert_eq!(m3.worker_count(), 0);
    assert!(path.with_extension("json.bad").exists());
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[test]
fn a_restart_long_after_drops_what_has_aged_out() {
    let path = temp_path("aged");
    let m = MinerStats::open(path.clone(), T0);
    m.record(S, "a", acc(1.0), T0);
    m.save(T0 + 1).unwrap();
    let m2 = MinerStats::open(path.clone(), T0 + 2 * 86_400);
    let s = m2.snapshot(S, T0 + 2 * 86_400);
    assert_eq!(
        s.workers["a"].fine.buckets().count(),
        0,
        "a day-old fine bucket is gone"
    );
    assert_eq!(s.workers["a"].coarse.buckets().count(), 1);
    let m3 = MinerStats::open(path.clone(), T0 + 31 * 86_400);
    assert_eq!(m3.worker_count(), 0, "silent 31 days: dropped");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}
