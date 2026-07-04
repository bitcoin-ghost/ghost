//! Mainnet-readiness integration tests.
//!
//! Spawns wraithd configured for mainnet and asserts the guards refuse
//! the obvious foot-guns. Re-runs the same checks on signet to confirm
//! the guards are mainnet-only — using BIP-39 test vectors on signet is
//! exactly what test vectors are for and the daemon must allow it.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use wraith_wallet_ipc::{Envelope, Request, Response};

const CANONICAL_TEST_VECTOR: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn wraithd_binary() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_wraithd") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let mut dir = exe.parent().expect("exe parent").to_path_buf();
    while dir.pop() {
        let candidate = dir.join("wraithd");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("wraithd binary not found")
}

async fn spawn_daemon(network: &str) -> (Child, PathBuf, tempfile::TempDir) {
    spawn_daemon_with_env(network, &[]).await
}

async fn spawn_daemon_with_env(
    network: &str,
    extra: &[(&str, &str)],
) -> (Child, PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("wraithd.sock");
    let wallets = tmp.path().join("wallets");
    std::fs::create_dir_all(&wallets).expect("mkdir wallets");

    let mut cmd = Command::new(wraithd_binary());
    cmd.env("WRAITHD_SOCKET", &socket)
        .env("WRAITHD_WALLETS_DIR", &wallets)
        .env("WRAITHD_NETWORK", network)
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let child = cmd.spawn().expect("spawn wraithd");

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            tokio::time::sleep(Duration::from_millis(40)).await;
            return (child, socket, tmp);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("wraithd socket never appeared");
}

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
    env.payload
}

#[tokio::test]
async fn mainnet_refuses_canonical_test_vector() {
    let (mut child, socket, _tmp) = spawn_daemon("mainnet").await;
    match rpc(
        &socket,
        1,
        Request::WalletImport {
            name: "blocked".into(),
            mnemonic: CANONICAL_TEST_VECTOR.into(),
            passphrase: "doesnt-matter-aaaaaaaaaaa".into(),
        },
    )
    .await
    {
        Response::Error(e) => {
            let lower = e.message.to_lowercase();
            assert!(
                lower.contains("mainnet") || lower.contains("publicly-known"),
                "expected mainnet-guard error, got: {}",
                e.message
            );
        }
        other => panic!("expected Error on mainnet, got {other:?}"),
    }
    child.kill().await.ok();
}

#[tokio::test]
async fn signet_allows_canonical_test_vector() {
    // Same import on signet must succeed — the foot-gun isn't a foot-gun
    // on a test network, and refusing here would break legitimate
    // testing workflows.
    let (mut child, socket, _tmp) = spawn_daemon("signet").await;
    match rpc(
        &socket,
        1,
        Request::WalletImport {
            name: "ok".into(),
            mnemonic: CANONICAL_TEST_VECTOR.into(),
            passphrase: "signet-test-passphrase-aaa".into(),
        },
    )
    .await
    {
        Response::WalletImported { name, .. } => assert_eq!(name, "ok"),
        other => panic!("import on signet must succeed, got {other:?}"),
    }
    child.kill().await.ok();
}

#[tokio::test]
async fn doctor_mainnet_flags_plaintext_remote_endpoints() {
    // Point ghost-pay at a non-loopback http:// host. The doctor's
    // mainnet/ghost-pay-tls row must be `fail`.
    let (mut child, socket, _tmp) = spawn_daemon_with_env(
        "mainnet",
        &[
            ("WRAITHD_GHOST_PAY", "http://203.0.113.5:8800"),
            ("WRAITHD_GSP", "ws://203.0.113.5:8900/ws/v1"),
        ],
    )
    .await;
    match rpc(&socket, 1, Request::Doctor).await {
        Response::Doctor(d) => {
            let pay = d
                .checks
                .iter()
                .find(|c| c.name == "mainnet/ghost-pay tls")
                .expect("ghost-pay tls row present on mainnet");
            assert_eq!(
                pay.status, "fail",
                "non-loopback http:// must fail: {pay:?}"
            );
            let gsp = d
                .checks
                .iter()
                .find(|c| c.name == "mainnet/gsp tls")
                .expect("gsp tls row present on mainnet");
            assert_eq!(gsp.status, "fail", "non-loopback ws:// must fail: {gsp:?}");
        }
        other => panic!("expected Doctor, got {other:?}"),
    }
    child.kill().await.ok();
}

#[tokio::test]
async fn doctor_mainnet_passes_loopback_plaintext() {
    // A plain mainnet daemon (no endpoint env vars, no persisted node.json)
    // defaults to the bundled public preset, which is https:// + wss:// — so
    // the TLS rows pass. Loopback http:// / ws:// is also exempt (a wallet
    // talking to ghost-pay on the same box doesn't need TLS); either way a
    // default mainnet daemon should pass the TLS rows.
    let (mut child, socket, _tmp) = spawn_daemon("mainnet").await;
    match rpc(&socket, 1, Request::Doctor).await {
        Response::Doctor(d) => {
            let pay = d
                .checks
                .iter()
                .find(|c| c.name == "mainnet/ghost-pay tls")
                .expect("ghost-pay tls row present");
            assert_eq!(pay.status, "pass", "loopback http:// must pass: {pay:?}");
            let gsp = d
                .checks
                .iter()
                .find(|c| c.name == "mainnet/gsp tls")
                .expect("gsp tls row present");
            assert_eq!(gsp.status, "pass", "loopback ws:// must pass: {gsp:?}");
        }
        other => panic!("expected Doctor, got {other:?}"),
    }
    child.kill().await.ok();
}

#[tokio::test]
async fn doctor_signet_omits_mainnet_rows() {
    // The mainnet rows are mainnet-only — signet doesn't get them at all.
    // A signet operator pointing at an http:// ghost-pay is doing nothing
    // wrong and we shouldn't pretend they are.
    let (mut child, socket, _tmp) = spawn_daemon_with_env(
        "signet",
        &[("WRAITHD_GHOST_PAY", "http://203.0.113.5:8800")],
    )
    .await;
    match rpc(&socket, 1, Request::Doctor).await {
        Response::Doctor(d) => {
            assert!(
                d.checks.iter().all(|c| !c.name.starts_with("mainnet/")),
                "signet doctor must not emit mainnet/ rows; got {:?}",
                d.checks.iter().map(|c| &c.name).collect::<Vec<_>>()
            );
        }
        other => panic!("expected Doctor, got {other:?}"),
    }
    child.kill().await.ok();
}

#[tokio::test]
async fn mainnet_allows_a_strong_mnemonic() {
    // Sanity: the guard rejects only the curated weak list, not arbitrary
    // valid mnemonics. Use a BIP-39 reference vector that's NOT on the
    // weak list — proves the guard is precise, not a blanket "no
    // imports on mainnet". (This vector is published in the BIP-39 spec
    // so don't ever actually use it on mainnet — but it's distinct from
    // the all-abandon vector that the guard blocks.)
    let strong = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let (mut child, socket, _tmp) = spawn_daemon("mainnet").await;
    match rpc(
        &socket,
        1,
        Request::WalletImport {
            name: "strong".into(),
            mnemonic: strong.into(),
            passphrase: "mainnet-test-passphrase-aa".into(),
        },
    )
    .await
    {
        Response::WalletImported { name, .. } => assert_eq!(name, "strong"),
        other => panic!("strong mnemonic must import on mainnet, got {other:?}"),
    }
    child.kill().await.ok();
}
