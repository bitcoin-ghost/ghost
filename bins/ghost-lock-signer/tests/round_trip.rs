//! The device binary, driven the way a host drives it.
//!
//! The library tests prove two `SigningSession`s produce a valid signature.
//! They do not prove a *device* exists: that a separate process, given JSON on
//! stdin and a key on disk, completes the round. This does.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::{
    absolute::LockTime, hashes::Hash as _, psbt::Psbt, transaction::Version, Amount, Network,
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use ghost_lock::airgap::{NonceReply, PartialReply, PartialRequest, SigningRequest};
use ghost_lock::lane::SavingsPolicy;
use ghost_lock::signing::{combine, SigningSession, VolatileNonceLedger};
use std::str::FromStr;

fn sk(b: u8) -> SecretKey {
    SecretKey::from_slice(&[b; 32]).expect("valid scalar")
}

/// A BIP39 test vector. Never use it for anything real.
const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The key the device will actually derive — so the lane is built around the
/// key the device holds, not a stand-in that happens to be nearby.
fn device_key(index: u32) -> SecretKey {
    ghost_lock::backup_key::secret_key(PHRASE, "", index).expect("derives")
}

/// Write a secret to a file the signer will accept.
fn secret_file(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    p
}

fn xonly(s: &SecretKey) -> XOnlyPublicKey {
    Keypair::from_secret_key(&Secp256k1::new(), s)
        .x_only_public_key()
        .0
}

/// A savings lane, and a spend of it.
fn fixture() -> (ghost_lock::lane::Lane, SecretKey, SecretKey, SigningRequest) {
    let secp = Secp256k1::new();
    let owner = sk(61);
    let backup = device_key(0);
    let aggregate = ghost_lock::key_agg::aggregate(&[xonly(&owner), xonly(&backup)]).unwrap();
    let lane = SavingsPolicy {
        aggregate,
        owner: xonly(&owner),
        backup: xonly(&backup),
        heir: xonly(&sk(63)),
        inherit_height: 1_000_000,
    }
    .build(&secp, 900_000, Network::Regtest)
    .unwrap();

    let prevout = TxOut {
        value: Amount::from_sat(250_000),
        script_pubkey: lane.address.script_pubkey(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000002",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(240_000),
            script_pubkey: lane.address.script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(prevout);

    use base64::Engine as _;
    let request = SigningRequest {
        psbt: base64::engine::general_purpose::STANDARD.encode(psbt.serialize()),
        input_index: 0,
        keys: vec![
            hex::encode(xonly(&owner).serialize()),
            hex::encode(xonly(&backup).serialize()),
        ],
        merkle_root: lane
            .spend_info
            .merkle_root()
            .map(|r| hex::encode(r.to_byte_array())),
    };
    (lane, owner, backup, request)
}

/// Read the child's stdout until the line after `--- round N ---`, collecting
/// the JSON block that ends at `--- end ---`.
fn read_block(reader: &mut impl BufRead) -> String {
    let mut inside = false;
    let mut body = String::new();
    let mut line = String::new();
    while reader.read_line(&mut line).expect("child stdout") > 0 {
        let t = line.trim_end();
        if t.starts_with("--- round") {
            inside = true;
        } else if t == "--- end ---" {
            break;
        } else if inside {
            body.push_str(t);
            body.push('\n');
        }
        line.clear();
    }
    assert!(!body.is_empty(), "no payload block found in device output");
    body
}

/// **A real device completes a real signature.**
#[test]
fn the_device_co_signs_a_spend() {
    let secp = Secp256k1::new();
    let (lane, owner, _backup, request) = fixture();
    let dir = tempfile::tempdir().unwrap();

    let req_path = dir.path().join("request.json");
    std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

    let seed_path = secret_file(dir.path(), "seed.txt", PHRASE);
    let ledger_path = dir.path().join("nonces.json");

    // Host side: review the same request and take round 1.
    let (_, message) = ghost_lock::airgap::review(&request, Network::Regtest).unwrap();
    let keys = ghost_lock::airgap::keys(&request).unwrap();
    let root = ghost_lock::airgap::merkle_root(&request).unwrap();
    let (host_session, host_commit) = SigningSession::begin(&keys, &owner, root, &message).unwrap();

    // Start the device.
    let mut child = Command::new(env!("CARGO_BIN_EXE_ghost-lock-signer"))
        .args([
            "sign",
            "--request",
            req_path.to_str().unwrap(),
            "--seed",
            seed_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--network",
            "regtest",
            "--no-confirm",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("device starts");

    let mut out = BufReader::new(child.stdout.take().unwrap());
    let nonce_reply: NonceReply =
        serde_json::from_str(&read_block(&mut out)).expect("round 1 reply parses");

    let device_nonce: [u8; 66] = hex::decode(&nonce_reply.public_nonce)
        .unwrap()
        .try_into()
        .unwrap();
    let mut nonces = vec![host_commit.public_nonce, device_nonce];
    nonces.sort_unstable();

    // Round 2 goes back down stdin.
    let partial_req = PartialRequest {
        session: nonce_reply.session.clone(),
        public_nonces: nonces.iter().map(hex::encode).collect(),
    };
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{}", serde_json::to_string(&partial_req).unwrap()).unwrap();
        stdin.flush().unwrap();
    }

    let partial_reply: PartialReply =
        serde_json::from_str(&read_block(&mut out)).expect("round 2 reply parses");
    let device_partial: [u8; 32] = hex::decode(&partial_reply.partial)
        .unwrap()
        .try_into()
        .unwrap();

    let status = child.wait().expect("device exits");
    assert!(status.success(), "device exited with {status}");

    // Host completes.
    let mut host_ledger = VolatileNonceLedger::default();
    let host_partial = host_session.sign(&mut host_ledger, &nonces).unwrap();
    let sig = combine(
        &keys,
        root,
        &nonces,
        &[host_partial, device_partial],
        &message,
    )
    .expect("combines");

    let out_key = lane.spend_info.output_key().to_x_only_public_key();
    secp.verify_schnorr(&sig, &Message::from_digest(message), &out_key)
        .expect("the device's half must produce a signature the lane accepts");

    // The device recorded its nonce durably.
    let ledger_raw = std::fs::read_to_string(&ledger_path).expect("ledger written");
    assert!(
        ledger_raw.contains(&hex::encode(
            ghost_lock::signing::NonceId::for_public_nonce(&device_nonce).as_bytes()
        )),
        "the device must have burned its nonce on disk before signing"
    );
}

/// A round 2 payload for a different spend is refused, and nothing is signed.
///
/// Without this a host could display one transaction in round 1 and complete a
/// different one in round 2, which would make the device's screen meaningless.
#[test]
fn the_device_refuses_a_round_two_for_a_different_spend() {
    let (_, _, _backup, request) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let req_path = dir.path().join("request.json");
    std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();
    let seed_path = secret_file(dir.path(), "seed.txt", PHRASE);
    let ledger_path = dir.path().join("nonces.json");

    let mut child = Command::new(env!("CARGO_BIN_EXE_ghost-lock-signer"))
        .args([
            "sign",
            "--request",
            req_path.to_str().unwrap(),
            "--seed",
            seed_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--network",
            "regtest",
            "--no-confirm",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("device starts");

    let mut out = BufReader::new(child.stdout.take().unwrap());
    let nonce_reply: NonceReply = serde_json::from_str(&read_block(&mut out)).unwrap();

    // A session id that is not the one shown.
    let wrong = PartialRequest {
        session: "ff".repeat(32),
        public_nonces: vec![nonce_reply.public_nonce.clone()],
    };
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{}", serde_json::to_string(&wrong).unwrap()).unwrap();
    }

    let output = child.wait_with_output().expect("device exits");
    assert!(!output.status.success(), "a mismatched session must fail");
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(
        err.contains("different spend"),
        "the refusal must say what is wrong: {err}"
    );
    assert!(
        !ledger_path.exists()
            || !std::fs::read_to_string(&ledger_path)
                .unwrap()
                .contains("\""),
        "nothing may be burned when nothing was signed"
    );
}

/// A world-readable seed file is refused.
#[cfg(unix)]
#[test]
fn the_device_refuses_a_seed_others_can_read() {
    use std::os::unix::fs::PermissionsExt;
    let (_, _, _, request) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let req_path = dir.path().join("request.json");
    std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();
    let seed_path = dir.path().join("seed.txt");
    std::fs::write(&seed_path, PHRASE).unwrap();
    std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ghost-lock-signer"))
        .args([
            "sign",
            "--request",
            req_path.to_str().unwrap(),
            "--seed",
            seed_path.to_str().unwrap(),
            "--ledger",
            dir.path().join("n.json").to_str().unwrap(),
            "--network",
            "regtest",
            "--no-confirm",
        ])
        .output()
        .expect("runs");
    assert!(!output.status.success());
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("readable by others"), "{err}");
}

/// The wrong derivation index is caught before anything is signed.
///
/// Otherwise the device would burn a nonce producing a share that belongs to
/// no Lock, and the failure would surface as an aggregation error on the host
/// with nothing pointing at the index.
#[test]
fn the_device_refuses_an_index_that_is_not_a_cosigner() {
    let (_, _, _, request) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let req_path = dir.path().join("request.json");
    std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();
    let seed_path = secret_file(dir.path(), "seed.txt", PHRASE);
    let ledger_path = dir.path().join("n.json");

    let output = Command::new(env!("CARGO_BIN_EXE_ghost-lock-signer"))
        .args([
            "sign",
            "--request",
            req_path.to_str().unwrap(),
            "--seed",
            seed_path.to_str().unwrap(),
            "--ledger",
            ledger_path.to_str().unwrap(),
            "--network",
            "regtest",
            "--no-confirm",
            // The lane was built around index 0.
            "--index",
            "9",
        ])
        .output()
        .expect("runs");
    assert!(!output.status.success(), "the wrong index must be refused");
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(err.contains("not one of the co-signers"), "{err}");
    assert!(
        !ledger_path.exists(),
        "nothing may be burned when nothing was signed"
    );
}

/// `pubkey` prints the key to register, and it is the key the device signs with.
#[test]
fn pubkey_prints_the_key_the_device_signs_with() {
    let dir = tempfile::tempdir().unwrap();
    let seed_path = secret_file(dir.path(), "seed.txt", PHRASE);

    let output = Command::new(env!("CARGO_BIN_EXE_ghost-lock-signer"))
        .args([
            "pubkey",
            "--seed",
            seed_path.to_str().unwrap(),
            "--index",
            "0",
        ])
        .output()
        .expect("runs");
    assert!(output.status.success());
    let printed = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(
        printed,
        hex::encode(xonly(&device_key(0)).serialize()),
        "the printed key must be the one the device derives for signing"
    );
}

/// `review` shows the spend and signs nothing.
#[test]
fn review_signs_nothing() {
    let (_, _, _, request) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let req_path = dir.path().join("request.json");
    std::fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ghost-lock-signer"))
        .args([
            "review",
            "--request",
            req_path.to_str().unwrap(),
            "--network",
            "regtest",
        ])
        .output()
        .expect("runs");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("240000 sats"), "must show the amount: {text}");
    assert!(text.contains("reviewed only"), "{text}");
}
