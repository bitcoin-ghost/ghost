//! The **real coordinator binary**, co-signing a real Ghost Lock.
//!
//! Everything else about Lock co-signing is proven against in-process servers:
//! the router tests call handlers directly, and the wallet's mock runs the
//! protocol logic in the test process. Neither proves a *deployment* — that the
//! binary parses its flags, opens its ledgers, derives a quorum key from a seed
//! file, and serves the two rounds over a socket.
//!
//! So this one spawns `wraith-coordinator` as a subprocess, configured the way
//! an operator would configure it, and drives the whole flow across TCP.
//!
//! # What it would catch that the others cannot
//!
//! A flag that does not parse. A ledger directory the binary cannot write. A
//! quorum key derived from the seed differently on the two sides. A route
//! mounted at the wrong path. Every one of those passes a unit test and fails
//! on the first real deployment.

use std::io::Write;
use std::process::{Child, Command, Stdio};

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::{
    absolute::LockTime, hashes::Hash as _, psbt::Psbt, transaction::Version, Amount, Network,
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use ghost_lock::airgap::SigningRequest;
use ghost_lock::signing::{combine, SigningSession, VolatileNonceLedger};
use std::str::FromStr;

/// Kills the coordinator when the test ends, pass or panic.
struct Coordinator {
    child: Child,
    base: String,
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn start(dir: &std::path::Path, seed_file: &std::path::Path, role: &str) -> Coordinator {
    let port = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_wraith-coordinator"))
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--network",
            "regtest",
            "--lock-seed-file",
            seed_file.to_str().unwrap(),
            "--lock-cosign-role",
            role,
            "--lock-ledger-dir",
            dir.to_str().unwrap(),
            "--lock-max-spend-sats",
            "1000000",
            "--lock-window-sats",
            "5000000",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the coordinator binary starts");

    // Wrapped before the wait, so the guard's `Drop` reaps it however this
    // ends. Polling first and constructing after leaks a live coordinator on
    // the timeout path — the one path where something has already gone wrong
    // and a stray process is hardest to notice.
    let co = Coordinator {
        child,
        base: format!("http://127.0.0.1:{port}"),
    };

    // Poll rather than sleep: a fixed wait is either flaky or slow.
    let http = reqwest::Client::new();
    for _ in 0..100 {
        if http
            .get(format!("{}/health", co.base))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return co;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("the coordinator did not become healthy in 10s");
}

fn write_seed(dir: &std::path::Path, phrase: &str) -> std::path::PathBuf {
    let path = dir.join("quorum-seed.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    writeln!(f, "{phrase}").unwrap();
    path
}

fn xo(s: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(&Secp256k1::new(), s)
        .x_only_public_key()
        .0
}

/// A Spending lane whose quorum half is the key the coordinator will derive.
fn lane_for(owner: &SecretKey, quorum_pub: XOnlyPublicKey) -> ghost_lock::lane::Lane {
    ghost_lock::lane::SpendingPolicy {
        aggregate: ghost_lock::key_agg::aggregate(&[xo(owner), quorum_pub]).unwrap(),
        owner: xo(owner),
    }
    .build(&Secp256k1::new(), Network::Regtest)
    .unwrap()
}

fn request_for(
    lane: &ghost_lock::lane::Lane,
    owner: &SecretKey,
    quorum_pub: XOnlyPublicKey,
    sats: u64,
    vout: u32,
) -> SigningRequest {
    let prevout = TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: lane.address.script_pubkey(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "000000000000000000000000000000000000000000000000000000000000000a",
                )
                .unwrap(),
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(sats - 1_000),
            script_pubkey: lane.address.script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(prevout);

    use base64::Engine as _;
    SigningRequest {
        psbt: base64::engine::general_purpose::STANDARD.encode(psbt.serialize()),
        input_index: 0,
        keys: vec![
            hex::encode(xo(owner).serialize()),
            hex::encode(quorum_pub.serialize()),
        ],
        merkle_root: lane
            .spend_info
            .merkle_root()
            .map(|r| hex::encode(r.to_byte_array())),
    }
}

/// **A deployed coordinator co-signs, and the lane accepts the result.**
#[tokio::test]
async fn a_running_coordinator_co_signs_a_spending_lane() {
    let secp = Secp256k1::new();
    let dir = tempfile::tempdir().unwrap();
    let binding_id = "live-cosign-binding";

    // The operator's setup: a seed, and the key it derives for this Lock.
    let phrase = ghost_lock::backup_key::new_phrase(None).unwrap();
    let seed_file = write_seed(dir.path(), &phrase);
    let quorum_pub = ghost_lock::backup_key::quorum_public_key(&phrase, "", binding_id).unwrap();

    let owner = SecretKey::from_slice(&[77u8; 32]).unwrap();
    let lane = lane_for(&owner, quorum_pub);
    let req = request_for(&lane, &owner, quorum_pub, 500_000, 0);

    let co = start(dir.path(), &seed_file, "active").await;
    let http = reqwest::Client::new();

    // Round 1.
    let r = http
        .post(format!("{}/api/v1/lock/cosign/nonce", co.base))
        .json(&serde_json::json!({ "binding_id": binding_id, "request": req }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "round 1 failed: {}",
        r.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = r.json().await.unwrap();
    let session = body["session"].as_str().unwrap().to_string();
    let their_nonce: [u8; 66] = hex::decode(body["public_nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(body["input_sats"], 500_000);

    // Our side.
    let keys = ghost_lock::airgap::keys(&req).unwrap();
    let root = ghost_lock::airgap::merkle_root(&req).unwrap();
    let (_, message) = ghost_lock::airgap::review(&req, Network::Regtest).unwrap();
    let (session_state, commit) = SigningSession::begin(&keys, &owner, root, &message).unwrap();
    let mut nonces = vec![commit.public_nonce, their_nonce];
    nonces.sort_unstable();

    // Round 2.
    let r = http
        .post(format!("{}/api/v1/lock/cosign/partial", co.base))
        .json(&serde_json::json!({
            "session": session,
            "public_nonces": nonces.iter().map(hex::encode).collect::<Vec<_>>(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "round 2 failed: {}",
        r.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = r.json().await.unwrap();
    let their_partial: [u8; 32] = hex::decode(body["partial"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    let mut ledger = VolatileNonceLedger::default();
    let ours = session_state.sign(&mut ledger, &nonces).unwrap();
    let sig = combine(&keys, root, &nonces, &[ours, their_partial], &message).unwrap();

    let out = lane.spend_info.output_key().to_x_only_public_key();
    secp.verify_schnorr(&sig, &Message::from_digest(message), &out)
        .expect("a deployed coordinator's half must produce a signature the lane accepts");

    // The ledgers it was told to keep are actually on disk.
    assert!(
        dir.path().join("lock-cosigned-coins.json").exists(),
        "the coin ledger must be written where --lock-ledger-dir said"
    );
}

/// A deployed coordinator enforces its configured ceiling.
///
/// The flag has to reach the policy; a unit test cannot tell whether it does.
#[tokio::test]
async fn a_running_coordinator_enforces_its_ceiling_flag() {
    let dir = tempfile::tempdir().unwrap();
    let binding_id = "live-ceiling-binding";
    let phrase = ghost_lock::backup_key::new_phrase(None).unwrap();
    let seed_file = write_seed(dir.path(), &phrase);
    let quorum_pub = ghost_lock::backup_key::quorum_public_key(&phrase, "", binding_id).unwrap();

    let owner = SecretKey::from_slice(&[78u8; 32]).unwrap();
    let lane = lane_for(&owner, quorum_pub);
    // Above the 1_000_000 the coordinator was started with.
    let req = request_for(&lane, &owner, quorum_pub, 2_000_000, 0);

    let co = start(dir.path(), &seed_file, "active").await;
    let r = reqwest::Client::new()
        .post(format!("{}/api/v1/lock/cosign/nonce", co.base))
        .json(&serde_json::json!({ "binding_id": binding_id, "request": req }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "a spend over the ceiling must be refused");
    let body: serde_json::Value = r.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap();
    assert!(detail.contains("2000000"), "{detail}");
    assert!(
        detail.contains("exit leaf"),
        "the refusal must leave the owner a way out: {detail}"
    );
}

/// A standby refuses over the wire, not just in the library.
#[tokio::test]
async fn a_running_standby_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let binding_id = "live-standby-binding";
    let phrase = ghost_lock::backup_key::new_phrase(None).unwrap();
    let seed_file = write_seed(dir.path(), &phrase);
    let quorum_pub = ghost_lock::backup_key::quorum_public_key(&phrase, "", binding_id).unwrap();

    let owner = SecretKey::from_slice(&[79u8; 32]).unwrap();
    let lane = lane_for(&owner, quorum_pub);
    let req = request_for(&lane, &owner, quorum_pub, 100_000, 0);

    let co = start(dir.path(), &seed_file, "standby").await;
    let r = reqwest::Client::new()
        .post(format!("{}/api/v1/lock/cosign/nonce", co.base))
        .json(&serde_json::json!({ "binding_id": binding_id, "request": req }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        503,
        "a standby must refuse, and say it is a routing problem"
    );
}
