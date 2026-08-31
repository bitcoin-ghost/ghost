//! Every binary we ship must carry ONE version, and that version must be the workspace's.
//!
//! A release that cannot state what it produced cannot make claims about what the network runs
//! (#759). Measured on the live fleet before this file existed: `ghost-gsp` reported `0.1.0`
//! while `ghost-pool` reported `1.11.32` from the same release — and the `0.1.0` was not a stale
//! deploy, it was correct. `bins/ghost-gsp` hardcoded `version = "0.1.0"`, so the binary had
//! never joined unified versioning at all. `bins/ghost-miner-proxy` and `bins/ghost-stats` were
//! pinned the same way.
//!
//! That is the failure this guards: not a wrong value, but a binary quietly opting out of the
//! release's identity. The confusing part is that `crates/ghost-gsp` — the library — DID use
//! `version.workspace`, so a glance at the tree suggested the binary was covered.

use std::path::{Path, PathBuf};

fn bins_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("bins")
}

/// Every `bins/*/Cargo.toml`, sorted so failures name crates in a stable order.
fn binary_manifests() -> Vec<(String, PathBuf)> {
    let mut v: Vec<(String, PathBuf)> = std::fs::read_dir(bins_dir())
        .expect("bins/ must exist")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .filter_map(|p| {
            let manifest = p.join("Cargo.toml");
            manifest.is_file().then(|| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    manifest,
                )
            })
        })
        .collect();
    v.sort();
    assert!(!v.is_empty(), "no crates found under bins/");
    v
}

/// The `version = ...` line from `[package]`, ignoring any that appear under `[dependencies]`.
fn package_version_line(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).expect("manifest must be readable");
    let mut in_package = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            // Only `[package]` declares the crate's own version; `[dependencies]` and friends
            // carry `version = ` lines that have nothing to do with what we ship.
            in_package = t == "[package]";
            continue;
        }
        if in_package && (t.starts_with("version") && t.contains('=')) {
            return Some(t.to_string());
        }
    }
    None
}

#[test]
fn every_shipped_binary_takes_its_version_from_the_workspace() {
    let offenders: Vec<String> = binary_manifests()
        .into_iter()
        .filter_map(|(name, manifest)| {
            let line = package_version_line(&manifest)?;
            // `version.workspace = true` is the only acceptable form. Anything else is a crate
            // that will ship under a version nobody chose for it.
            (!line.replace(' ', "").starts_with("version.workspace=true"))
                .then(|| format!("{name}: {line}"))
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "these shipped binaries do not use `version.workspace = true`, so a release cannot \
         state one version for what it produced (#759):\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn every_shipped_binary_declares_a_version_at_all() {
    // A missing `version` is not the same failure as a hardcoded one, and it would slip past the
    // test above — which only inspects manifests that HAVE a version line.
    let missing: Vec<String> = binary_manifests()
        .into_iter()
        .filter(|(_, manifest)| package_version_line(manifest).is_none())
        .map(|(name, _)| name)
        .collect();

    assert!(
        missing.is_empty(),
        "these crates under bins/ declare no [package] version: {}",
        missing.join(", ")
    );
}

#[test]
fn the_parser_reads_package_version_and_not_dependency_versions() {
    // The control for the two tests above. If `package_version_line` ever started matching a
    // `version = "1.2.3"` under `[dependencies]`, both would keep passing while checking the
    // wrong line — a check that cannot fail is worse than no check.
    let dir = std::env::temp_dir().join(format!("ghost-759-parser-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let manifest = dir.join("Cargo.toml");

    std::fs::write(
        &manifest,
        "[package]\nname = \"x\"\nversion.workspace = true\n\n\
         [dependencies]\nserde = { version = \"1.0\" }\nfoo = \"0.1.0\"\nversion = \"9.9.9\"\n",
    )
    .expect("write manifest");
    assert_eq!(
        package_version_line(&manifest).as_deref(),
        Some("version.workspace = true"),
        "must read the [package] version, not a [dependencies] one"
    );

    // And it must actually NOTICE a hardcoded package version rather than returning None.
    std::fs::write(
        &manifest,
        "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
    )
    .expect("write manifest");
    assert_eq!(
        package_version_line(&manifest).as_deref(),
        Some("version = \"0.1.0\""),
        "a hardcoded package version must be reported, or the guard is blind"
    );

    std::fs::remove_dir_all(&dir).ok();
}
