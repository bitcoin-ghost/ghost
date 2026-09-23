//! Integration test for the daemon's wallet IPC surface.
//!
//! Spawns a real `wraithd` binary against an ephemeral socket + tempdir wallets
//! directory, then drives the full create → list → show-mnemonic → lock →
//! unlock → import lifecycle over JSON-RPC. The point isn't to retest the
//! Keystore (that's covered in core); it's to lock the wire shape so that any
//! breakage in dispatch's marshalling shows up here, not in production.
//!
//! No GSP, no ghost-pay — those endpoints are only required by gsp_auth /
//! light_* paths that this test does not exercise.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use wraith_wallet_ipc::{Envelope, Request, Response};

/// Locate the just-built `wraithd` binary. Cargo sets CARGO_BIN_EXE_<name> for
/// integration tests of the same package — preferred when available — and we
/// fall back to walking up to `target/<profile>/wraithd` otherwise.
fn wraithd_binary() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_wraithd") {
        return PathBuf::from(p);
    }
    // Fall back: assume cargo dropped us in target/debug/deps and the binary
    // is one level up. Works for `cargo test` runs from the workspace root.
    let exe = std::env::current_exe().expect("current_exe");
    let mut dir = exe.parent().expect("exe parent").to_path_buf();
    while dir.pop() {
        let candidate = dir.join("wraithd");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("could not locate wraithd binary");
}

/// Bring up wraithd with an ephemeral socket and an empty wallets dir.
/// Returns (child process, socket path, _tempdir guard).
async fn spawn_daemon() -> (Child, PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("wraithd.sock");
    let wallets = tmp.path().join("wallets");
    std::fs::create_dir_all(&wallets).expect("mkdir wallets");

    let child = Command::new(wraithd_binary())
        .env("WRAITHD_SOCKET", &socket)
        .env("WRAITHD_WALLETS_DIR", &wallets)
        // Keep noise out of the test stream; uncomment if debugging.
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn wraithd");

    // Poll for the socket. ~3s is plenty for a debug build cold-start; locally
    // observed ~80ms.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            // Extra beat so the bind is fully wired before we connect.
            tokio::time::sleep(Duration::from_millis(40)).await;
            return (child, socket, tmp);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("wraithd socket never appeared at {}", socket.display());
}

/// Round-trip a single Request and decode the response on a fresh connection.
async fn rpc(socket: &PathBuf, id: u64, request: Request) -> Response {
    let stream = UnixStream::connect(socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json::to_string(&Envelope::new(id, request)).expect("serialise");
    line.push('\n');
    writer.write_all(line.as_bytes()).await.expect("write");
    writer.shutdown().await.expect("shutdown");
    let mut buf = String::new();
    BufReader::new(reader)
        .read_line(&mut buf)
        .await
        .expect("read");
    let env: Envelope<Response> = serde_json::from_str(&buf).expect("decode");
    assert_eq!(env.id, id, "response id must echo request id");
    env.payload
}

#[tokio::test]
async fn wallet_lifecycle_round_trip() {
    let (mut child, socket, _tmp) = spawn_daemon().await;

    // 1. Daemon health.
    match rpc(&socket, 1, Request::Health).await {
        Response::Health(h) => {
            assert!(!h.daemon_version.is_empty(), "daemon_version is set");
        }
        other => panic!("expected Health, got {other:?}"),
    }

    // 2. Create a brand-new wallet.
    let pass = "integration-test-passphrase-aaa".to_string();
    let mnemonic = match rpc(
        &socket,
        2,
        Request::WalletCreate {
            name: "alpha".into(),
            passphrase: pass.clone(),
            user_entropy_digest: None,
        },
    )
    .await
    {
        Response::WalletCreate(c) => {
            assert_eq!(c.name, "alpha");
            assert!(!c.mnemonic.is_empty(), "mnemonic returned");
            c.mnemonic
        }
        other => panic!("expected WalletCreate, got {other:?}"),
    };
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    assert!(
        words.len() == 12 || words.len() == 24,
        "BIP-39 length, got {}",
        words.len()
    );

    // 3. List shows it as unlocked + active.
    match rpc(&socket, 3, Request::WalletList).await {
        Response::WalletList(l) => {
            let entry = l
                .wallets
                .iter()
                .find(|w| w.name == "alpha")
                .expect("alpha listed");
            assert!(entry.unlocked, "alpha should be unlocked after create");
            assert!(entry.active, "alpha should be active after create");
        }
        other => panic!("expected WalletList, got {other:?}"),
    }

    // 4. ShowMnemonic returns the same words (decrypted via passphrase).
    match rpc(
        &socket,
        4,
        Request::WalletShowMnemonic {
            name: "alpha".into(),
            passphrase: pass.clone(),
        },
    )
    .await
    {
        Response::WalletShowMnemonic(s) => {
            assert_eq!(s.mnemonic, mnemonic, "show_mnemonic round-trip");
        }
        other => panic!("expected WalletShowMnemonic, got {other:?}"),
    }

    // 5. Wrong passphrase must fail loudly.
    match rpc(
        &socket,
        5,
        Request::WalletShowMnemonic {
            name: "alpha".into(),
            passphrase: "definitely-not-the-right-one".into(),
        },
    )
    .await
    {
        Response::Error(e) => {
            assert!(
                !e.message.is_empty(),
                "wrong-passphrase error must carry a message"
            );
        }
        other => panic!("wrong passphrase must yield Error, got {other:?}"),
    }

    // 6. Lock + unlock round-trip.
    match rpc(
        &socket,
        6,
        Request::WalletLock {
            name: Some("alpha".into()),
        },
    )
    .await
    {
        Response::WalletLocked { name } => assert_eq!(name, "alpha"),
        other => panic!("expected WalletLocked, got {other:?}"),
    }
    match rpc(
        &socket,
        7,
        Request::WalletUnlock {
            name: "alpha".into(),
            passphrase: pass.clone(),
        },
    )
    .await
    {
        Response::WalletUnlocked => {}
        other => panic!("expected WalletUnlocked, got {other:?}"),
    }

    // 7. Import a separate wallet from a known mnemonic. Refusing duplicates is
    //    asserted via the "same name" path. Using a fresh name here.
    let known = mnemonic.clone();
    match rpc(
        &socket,
        8,
        Request::WalletImport {
            birth_height: None,
            name: "beta".into(),
            mnemonic: known.clone(),
            passphrase: pass.clone(),
        },
    )
    .await
    {
        Response::WalletImported { name, .. } => assert_eq!(name, "beta"),
        other => panic!("expected WalletImported, got {other:?}"),
    }

    // 8. Importing again under the same name must fail (no overwrite).
    match rpc(
        &socket,
        9,
        Request::WalletImport {
            birth_height: None,
            name: "beta".into(),
            mnemonic: known,
            passphrase: pass.clone(),
        },
    )
    .await
    {
        Response::Error(e) => {
            assert!(
                e.message.to_lowercase().contains("exists")
                    || e.message.to_lowercase().contains("overwrite"),
                "expected duplicate-import error, got: {}",
                e.message
            );
        }
        other => panic!("duplicate import must yield Error, got {other:?}"),
    }

    // 8.5 (phase 13): signer-info surfaces on unlocked wallets but not on
    //     locked ones. The trait is what hardware backings will plug into;
    //     this test pins the wire shape today so a HW backend can simply
    //     swap the keystore-side mapping without IPC churn later.
    match rpc(&socket, 100, Request::WalletList).await {
        Response::WalletList(l) => {
            for w in &l.wallets {
                if w.unlocked {
                    let sig = w.signer.as_ref().expect("unlocked → signer info present");
                    assert_eq!(sig.kind, "software", "v1 daemon ships software signer");
                    assert!(!sig.interactive, "software signer is non-interactive");
                    assert!(!sig.label.is_empty(), "label populated");
                } else {
                    assert!(
                        w.signer.is_none(),
                        "locked wallet must NOT carry signer info"
                    );
                }
            }
        }
        other => panic!("expected WalletList, got {other:?}"),
    }

    // 9. WalletList sees both alpha + beta.
    match rpc(&socket, 10, Request::WalletList).await {
        Response::WalletList(l) => {
            let names: Vec<&str> = l.wallets.iter().map(|w| w.name.as_str()).collect();
            assert!(names.contains(&"alpha"), "alpha listed");
            assert!(names.contains(&"beta"), "beta listed");
        }
        other => panic!("expected WalletList, got {other:?}"),
    }

    // 10. Deterministic identity primitives — these are pure derivations from
    //     the seed, so the same import on a fresh daemon must yield the same
    //     bytes. Lock the contract.
    let derive = match rpc(
        &socket,
        11,
        Request::WalletDerive {
            path: "m/86'/531'/0'/0/0".into(),
        },
    )
    .await
    {
        Response::WalletDerive(r) => r,
        other => panic!("expected WalletDerive, got {other:?}"),
    };
    assert_eq!(derive.path, "m/86'/531'/0'/0/0");
    assert_eq!(
        derive.public_key_hex.len(),
        66,
        "compressed sec1 = 33 bytes hex"
    );
    let auth = match rpc(&socket, 12, Request::WalletAuthInfo).await {
        Response::WalletAuthInfo(r) => r,
        other => panic!("expected WalletAuthInfo, got {other:?}"),
    };
    assert_eq!(auth.wallet_id.len(), 32, "wallet_id = 16 bytes hex");
    assert_eq!(
        auth.auth_public_key_hex.len(),
        64,
        "x-only auth pubkey = 32 bytes hex"
    );
    let ghost = match rpc(&socket, 13, Request::WalletGhostId).await {
        Response::WalletGhostId(r) => r,
        other => panic!("expected WalletGhostId, got {other:?}"),
    };
    assert!(!ghost.ghost_id.is_empty(), "ghost_id must be set");
    assert_eq!(ghost.scan_public_key_hex.len(), 66);

    // 11. Checkpoint export + restore. The encrypted file is portable: the
    //     restored wallet decrypts under the same passphrase and yields the
    //     same auth_info.
    let backup_path = _tmp.path().join("alpha.bak");
    match rpc(
        &socket,
        14,
        Request::WalletExport {
            name: "alpha".into(),
            to_path: backup_path.display().to_string(),
        },
    )
    .await
    {
        Response::WalletExported { name, bytes, .. } => {
            assert_eq!(name, "alpha");
            assert!(bytes > 0, "export must write a non-empty file");
        }
        other => panic!("expected WalletExported, got {other:?}"),
    }
    assert!(backup_path.exists(), "backup file written");
    match rpc(
        &socket,
        15,
        Request::WalletRestore {
            name: "gamma".into(),
            from_path: backup_path.display().to_string(),
            birth_height: None,
        },
    )
    .await
    {
        Response::WalletRestored { name, .. } => assert_eq!(name, "gamma"),
        other => panic!("expected WalletRestored, got {other:?}"),
    }
    // Unlock under the same passphrase the original used; auth_info must match.
    match rpc(
        &socket,
        16,
        Request::WalletUnlock {
            name: "gamma".into(),
            passphrase: pass.clone(),
        },
    )
    .await
    {
        Response::WalletUnlocked => {}
        other => panic!("unlock restored wallet: {other:?}"),
    }
    match rpc(
        &socket,
        17,
        Request::WalletSelect {
            name: "gamma".into(),
        },
    )
    .await
    {
        Response::WalletSelected { .. } => {}
        other => panic!("select gamma: {other:?}"),
    }
    match rpc(&socket, 18, Request::WalletAuthInfo).await {
        Response::WalletAuthInfo(r) => {
            assert_eq!(
                r.auth_public_key_hex, auth.auth_public_key_hex,
                "checkpoint round-trip must preserve auth identity"
            );
        }
        other => panic!("expected WalletAuthInfo, got {other:?}"),
    }

    // Tear down — kill_on_drop will reap, but be explicit so the test failure
    // reason is not "stuck child".
    child.kill().await.ok();
}

/// Phase 9 Shroud relay: the configured WRAITHD_SHROUD_MAX_MS env var is
/// reflected in the DaemonEnv response, and 0 disables it. Locks the wire
/// shape — the GUI Settings panel and `wraith env` both rely on it.
#[tokio::test]
async fn shroud_max_ms_surfaces_in_daemon_env() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("wraithd.sock");
    let wallets = tmp.path().join("wallets");
    std::fs::create_dir_all(&wallets).expect("mkdir wallets");
    let mut child = Command::new(wraithd_binary())
        .env("WRAITHD_SOCKET", &socket)
        .env("WRAITHD_WALLETS_DIR", &wallets)
        .env("WRAITHD_SHROUD_MAX_MS", "1234")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn wraithd");

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            tokio::time::sleep(Duration::from_millis(40)).await;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(socket.exists(), "socket never appeared");

    match rpc(&socket, 1, Request::DaemonEnv).await {
        Response::DaemonEnv(e) => {
            assert_eq!(
                e.shroud_max_ms, 1234,
                "WRAITHD_SHROUD_MAX_MS must round-trip through DaemonEnv"
            );
        }
        other => panic!("expected DaemonEnv, got {other:?}"),
    }

    child.kill().await.ok();
}

/// Auto-lock: with WRAITHD_IDLE_LOCK_SECS=10 the daemon should lock all
/// unlocked wallets after ~10s of no user-facing IPC activity. Health and
/// DaemonEnv should NOT count as activity (would defeat the feature).
///
/// The threshold was 2s, which made this flaky (#502) — the create's KDF could outlast it and
/// the wallet locked before the "still unlocked" check. Raising it fixed that but left the WAIT
/// too close to the tick; see the comment on the sleep below. The idle timer starts at wallet
/// CREATION, and creation runs a passphrase KDF — so on a loaded runner the KDF alone could
/// outlast the window, and the very next call would find the wallet already locked. The test
/// then failed on `fresh wallet must be unlocked`, i.e. it was asserting "under two seconds of
/// wall-clock elapsed", which is not a property the daemon controls.
///
/// 10s is chosen so a KDF would have to be pathologically slow to reach it, while still
/// keeping the test's own runtime bounded.
#[tokio::test]
async fn idle_lock_locks_wallets_after_threshold() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("wraithd.sock");
    let wallets = tmp.path().join("wallets");
    std::fs::create_dir_all(&wallets).expect("mkdir wallets");
    let mut child = Command::new(wraithd_binary())
        .env("WRAITHD_SOCKET", &socket)
        .env("WRAITHD_WALLETS_DIR", &wallets)
        .env("WRAITHD_IDLE_LOCK_SECS", "10")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn wraithd");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            tokio::time::sleep(Duration::from_millis(40)).await;
            break;
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    assert!(socket.exists(), "socket never appeared");

    // Create the wallet — counts as activity, so the timer starts now.
    let pass = "idle-test-passphrase-aaaaaa".to_string();
    match rpc(
        &socket,
        1,
        Request::WalletCreate {
            name: "idle".into(),
            passphrase: pass.clone(),
            user_entropy_digest: None,
        },
    )
    .await
    {
        Response::WalletCreate(_) => {}
        other => panic!("create: {other:?}"),
    }

    // Confirm unlocked.
    match rpc(&socket, 2, Request::WalletList).await {
        Response::WalletList(l) => {
            let e = l.wallets.iter().find(|w| w.name == "idle").unwrap();
            assert!(e.unlocked, "fresh wallet must be unlocked");
        }
        other => panic!("list: {other:?}"),
    }

    // Sleep past the idle threshold without sending any IPC traffic.
    //
    // ⚠ The wait must exceed threshold + ONE FULL TICK, not just the threshold. `idle_lock_task`
    // only re-checks every `min(30, threshold/2)` seconds and compares whole seconds, so a
    // sub-second misalignment makes the tick ON the threshold read one short, skip, and lock a
    // whole tick later.
    //
    // At the previous 10s threshold the tick was 5s, so locking could land at t=15 while this
    // asserted at t=14 — a 4s margin against a 5s tick. It passed most of the time and failed on
    // a loaded CI host (seen on #925, where two more daemon-spawning tests in this file were
    // enough to surface it).
    //
    // The threshold stays at 10s — lowering it would buy margin here at the cost of the OTHER
    // failure #502 hit, where a create whose KDF outlasts the threshold locks the wallet before
    // the "still unlocked" check above. Both ends need headroom, so the WAIT grows instead:
    // 10s threshold => 5s tick => locked by t=15 at worst, asserted at t=20. The slack is now
    // larger than a tick, which is the property that was missing.
    //
    // Polling instead of sleeping is not an option: `is_activity` counts WalletList, so asking
    // whether it has locked yet resets the very timer that is supposed to be running down.
    tokio::time::sleep(Duration::from_secs(20)).await;

    // WalletList now: should show the wallet as locked. (The list call itself
    // re-bumps the timer, but the auto-lock has already happened.)
    match rpc(&socket, 3, Request::WalletList).await {
        Response::WalletList(l) => {
            let e = l
                .wallets
                .iter()
                .find(|w| w.name == "idle")
                .expect("idle still listed");
            assert!(
                !e.unlocked,
                "expected wallet to be auto-locked after idle threshold"
            );
            assert!(
                !e.active,
                "active slot should clear when the active wallet auto-locks"
            );
        }
        other => panic!("list: {other:?}"),
    }

    child.kill().await.ok();
}

/// A birth height given to `wallet import` must reach `wallet-meta.json`,
/// because the block scanner reads it from there and nothing else remembers it.
///
/// #865: a wallet restored on regtest with `--birth-height 101` recovered its
/// balance exactly but rebuilt 1 of 13 history entries, and the daemon logged
/// `this wallet has no recorded birth height` for it. That log line has two
/// possible causes — the value never reaching disk, or the scanner reading the
/// file before the import writes it — and they need different fixes. This
/// isolates the first.
#[tokio::test]
async fn an_imported_birth_height_reaches_the_wallet_metadata() {
    let (mut child, socket, tmp) = spawn_daemon().await;
    let wallets = tmp.path().join("wallets");
    let pass = "integration-test-passphrase-bbb".to_string();

    // A real mnemonic to import, taken from a wallet we make first.
    let mnemonic = match rpc(
        &socket,
        1,
        Request::WalletCreate {
            name: "source".into(),
            passphrase: pass.clone(),
            user_entropy_digest: None,
        },
    )
    .await
    {
        Response::WalletCreate(c) => c.mnemonic,
        other => panic!("expected WalletCreate, got {other:?}"),
    };

    match rpc(
        &socket,
        2,
        Request::WalletImport {
            name: "restored".into(),
            mnemonic,
            passphrase: pass,
            birth_height: Some(101),
        },
    )
    .await
    {
        Response::WalletImported { name, .. } => assert_eq!(name, "restored"),
        other => panic!("expected WalletImported, got {other:?}"),
    }

    let meta_path = wallets.join("restored").join("wallet-meta.json");
    let raw = std::fs::read_to_string(&meta_path).unwrap_or_else(|e| {
        panic!(
            "no wallet metadata written at {}: {e} — the birth height the owner \
             gave is gone, and a restored wallet has no history",
            meta_path.display()
        )
    });
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("wallet-meta.json is not JSON: {e}"));
    assert_eq!(
        parsed.get("birth_height").and_then(|v| v.as_u64()),
        Some(101),
        "wallet-meta.json does not carry the birth height the import was given: {raw}"
    );

    child.kill().await.ok();
}

/// #924: `wallet restore` must be able to carry a birth height too.
///
/// A keystore backup is a byte-for-byte copy of the encrypted keystore, so it cannot hold one.
/// Before this, `restore` had no way to accept one either — so the path the wallet tells people
/// to back up with always started its history at the tip, silently, while returning the correct
/// balance from `scantxoutset`.
#[tokio::test]
async fn a_restored_birth_height_reaches_the_wallet_metadata() {
    let (mut child, socket, tmp) = spawn_daemon().await;
    let wallets = tmp.path().join("wallets");
    let pass = "integration-test-passphrase-ccc".to_string();
    let backup = tmp.path().join("backup.keystore");

    match rpc(
        &socket,
        1,
        Request::WalletCreate {
            name: "origin".into(),
            passphrase: pass.clone(),
            user_entropy_digest: None,
        },
    )
    .await
    {
        Response::WalletCreate(_) => {}
        other => panic!("expected WalletCreate, got {other:?}"),
    }

    match rpc(
        &socket,
        2,
        Request::WalletExport {
            name: "origin".into(),
            to_path: backup.display().to_string(),
        },
    )
    .await
    {
        Response::WalletExported { name, .. } => assert_eq!(name, "origin"),
        other => panic!("expected WalletExported, got {other:?}"),
    }

    match rpc(
        &socket,
        3,
        Request::WalletRestore {
            name: "from-backup".into(),
            from_path: backup.display().to_string(),
            birth_height: Some(101),
        },
    )
    .await
    {
        Response::WalletRestored { name, .. } => assert_eq!(name, "from-backup"),
        other => panic!("expected WalletRestored, got {other:?}"),
    }

    let meta_path = wallets.join("from-backup").join("wallet-meta.json");
    let raw = std::fs::read_to_string(&meta_path).unwrap_or_else(|e| {
        panic!(
            "no wallet metadata written at {}: {e} — a restore given a birth height \
             still starts its history at the tip",
            meta_path.display()
        )
    });
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("wallet-meta.json is not JSON: {e}"));
    assert_eq!(
        parsed.get("birth_height").and_then(|v| v.as_u64()),
        Some(101),
        "wallet-meta.json does not carry the birth height the restore was given: {raw}"
    );

    child.kill().await.ok();
}

/// A restore given NO birth height must still leave a file saying so.
///
/// `null` and `missing` both read back as "no birth height", but they mean different things:
/// one is "the owner did not say", the other is "nothing wrote it". Only the second is a bug,
/// and the scanner's log could not tell them apart until #914 — which is what cost #865 its
/// root cause.
#[tokio::test]
async fn a_restore_without_a_birth_height_still_records_that_fact() {
    let (mut child, socket, tmp) = spawn_daemon().await;
    let wallets = tmp.path().join("wallets");
    let pass = "integration-test-passphrase-ddd".to_string();
    let backup = tmp.path().join("backup2.keystore");

    match rpc(
        &socket,
        1,
        Request::WalletCreate {
            name: "origin2".into(),
            passphrase: pass.clone(),
            user_entropy_digest: None,
        },
    )
    .await
    {
        Response::WalletCreate(_) => {}
        other => panic!("expected WalletCreate, got {other:?}"),
    }
    match rpc(
        &socket,
        2,
        Request::WalletExport {
            name: "origin2".into(),
            to_path: backup.display().to_string(),
        },
    )
    .await
    {
        Response::WalletExported { .. } => {}
        other => panic!("expected WalletExported, got {other:?}"),
    }
    match rpc(
        &socket,
        3,
        Request::WalletRestore {
            name: "no-height".into(),
            from_path: backup.display().to_string(),
            birth_height: None,
        },
    )
    .await
    {
        Response::WalletRestored { .. } => {}
        other => panic!("expected WalletRestored, got {other:?}"),
    }

    let meta_path = wallets.join("no-height").join("wallet-meta.json");
    let raw = std::fs::read_to_string(&meta_path).unwrap_or_else(|e| {
        panic!(
            "no wallet metadata at {}: {e} — an absent birth height must be RECORDED \
             as absent, not left unwritten",
            meta_path.display()
        )
    });
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    // The FILE existing is the whole point: `load_with_source` then reports `Loaded` with no
    // height, which the scanner can tell apart from `Missing`. The key itself is omitted rather
    // than written as null, because WalletMeta carries `skip_serializing_if = "Option::is_none"`
    // — so `{}` is the correct on-disk form, and asserting an explicit null would be asserting
    // the serialiser's shape rather than the behaviour.
    assert!(
        parsed.is_object(),
        "wallet-meta.json must be a JSON object, got: {raw}"
    );
    assert!(
        parsed
            .get("birth_height")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "a restore given no birth height must not invent one, got: {raw}"
    );

    child.kill().await.ok();
}
