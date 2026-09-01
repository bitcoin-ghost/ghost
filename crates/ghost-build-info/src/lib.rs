//! What commit a running binary was built from.
//!
//! A version number does not identify a build. Measured on the live fleet on 2026-09-01: every
//! node reported `ghost-pool 1.11.32` and `translator_sv2 1.11.32`, and the two binaries had been
//! built from different commits a day apart — `ghost-pool` from the `v1.11.32` release commit
//! `09fa48823`, `translator_sv2` from something later that carried #796's `core_healthy` field.
//! Both were correct about their version and neither could say what it actually was.
//!
//! Establishing that took probing `/proc/<MainPID>/exe`, grepping the binaries for a marker
//! string against a control, and comparing mtimes — because only `ghost-pool` exposed a git hash
//! (through `ghost-verification`), and the SV2 binaries exposed nothing at all. #759 is about a
//! release being able to state what it produced; a binary that cannot name its own commit cannot
//! take part in that.
//!
//! This crate is the single place that captures it, so the answer is the same shape everywhere.

/// Short git commit the binary was built from, or `"unknown"` outside a git checkout.
pub const GIT_HASH: &str = match option_env!("GIT_HASH") {
    Some(h) if !h.is_empty() => h,
    _ => "unknown",
};

/// ISO 8601 UTC build timestamp.
///
/// Honours `SOURCE_DATE_EPOCH`, so two builds of one commit can be made byte-identical — without
/// that this stamp is the only difference between them, which is enough to make a `sha256`
/// comparison useless for proving a deployed binary came from a given tag.
pub const BUILD_TIME: &str = match option_env!("BUILD_TIME") {
    Some(t) if !t.is_empty() => t,
    _ => "unknown",
};

/// Workspace version, commit and build time, for `--version`.
///
/// `clap` needs a `&'static str`, so this is `concat!`-built at compile time rather than
/// formatted at runtime.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("GIT_HASH"),
    " built ",
    env!("BUILD_TIME"),
    ")"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The point of the crate: the long version must name a COMMIT, not just a version.
    ///
    /// Guards the regression that motivated it — a binary that reports only `1.11.32` while
    /// having been built from an unknown commit.
    #[test]
    fn the_long_version_states_the_commit_and_the_version() {
        assert!(
            LONG_VERSION.starts_with(env!("CARGO_PKG_VERSION")),
            "must lead with the workspace version, got {LONG_VERSION}"
        );
        assert!(
            LONG_VERSION.contains(GIT_HASH),
            "must name the commit it was built from, got {LONG_VERSION}"
        );
        assert!(
            LONG_VERSION.contains(BUILD_TIME),
            "must state when it was built, got {LONG_VERSION}"
        );
    }

    /// In CI and on a developer machine this builds inside a git checkout, so the hash must be
    /// real. Without this the crate could ship `"unknown"` everywhere and every other assertion
    /// here would still pass — the exact "check that cannot fail" shape.
    #[test]
    fn the_commit_is_actually_captured_in_a_git_checkout() {
        let in_git = std::process::Command::new("git")
            .args(["rev-parse", "--git-dir"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !in_git {
            return;
        }
        assert_ne!(
            GIT_HASH, "unknown",
            "built inside a git checkout, so the commit must have been captured"
        );
        assert!(
            GIT_HASH.len() >= 7 && GIT_HASH.chars().all(|c| c.is_ascii_hexdigit()),
            "a git short hash is hex and at least 7 chars, got {GIT_HASH:?}"
        );
    }
}
