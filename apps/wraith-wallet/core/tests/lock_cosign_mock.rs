//! The quorum co-signing client, against an in-process coordinator.
//!
//! The mock is not a stub: it runs the real `wraith_protocol::lock_cosign`
//! logic with a real quorum key, so this exercises the JSON shapes the two
//! sides actually exchange as well as the signature they jointly produce.
//! A stub that returned canned bytes would agree with itself and prove
//! nothing.

use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Json, Router};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::{
    absolute::LockTime, psbt::Psbt, transaction::Version, Amount, Network, OutPoint, ScriptBuf,
    Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use ghost_lock::airgap::SigningRequest;
use ghost_lock::signing::VolatileNonceLedger;
use wraith_protocol::lock_cosign::{
    begin_cosign, CosignPolicy, CosignSession, Role, VelocityLimit, VolatileSpendLog,
};
use wraith_protocol::signing_ledger::{SigningLedger, VolatileStore};
use wraith_wallet_core::lock_cosign_client::{cosign_with_quorum, CosignError};

use std::str::FromStr;

fn sk(b: u8) -> SecretKey {
    SecretKey::from_slice(&[b; 32]).unwrap()
}
fn xo(s: &SecretKey) -> bitcoin::XOnlyPublicKey {
    Keypair::from_secret_key(&Secp256k1::new(), s)
        .x_only_public_key()
        .0
}

struct Quorum {
    key: SecretKey,
    policy: CosignPolicy,
    role: Role,
    coins: SigningLedger<VolatileStore>,
    spends: VolatileSpendLog,
    pending: std::collections::HashMap<String, CosignSession>,
}

type Shared = Arc<Mutex<Quorum>>;

#[derive(serde::Deserialize)]
struct NonceReq {
    /// The Lock's BINDING id, not its `lock_id`. Deserialised by name so this
    /// mock fails loudly if the wallet ever goes back to sending the lock id —
    /// which cannot work, because a lock id is a hash over the very quorum key
    /// this request asks to be derived.
    #[allow(dead_code)]
    binding_id: String,
    request: SigningRequest,
}

async fn nonce(State(q): State<Shared>, Json(body): Json<NonceReq>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut q = q.lock().unwrap();
    let keys = ghost_lock::airgap::keys(&body.request).unwrap();
    let root = ghost_lock::airgap::merkle_root(&body.request).unwrap();
    let policy = q.policy;
    let role = q.role;
    let key = q.key;
    let Quorum { coins, spends, .. } = &mut *q;
    let outcome = begin_cosign(
        &body.request,
        Network::Regtest,
        policy,
        role,
        coins,
        spends,
        0,
        &key,
        &keys,
        root,
    );
    match outcome {
        Ok(session) => {
            let summary = session.summary().clone();
            let id = hex::encode(session.public_nonce())[..32].to_string();
            let n = hex::encode(session.public_nonce());
            q.pending.insert(id.clone(), session);
            Json(serde_json::json!({
                "session": id,
                "public_nonce": n,
                "input_sats": summary.input_sats,
                "fee_sats": summary.fee_sats,
            }))
            .into_response()
        }
        Err(e) => (
            axum::http::StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "refused", "detail": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct PartialReq {
    session: String,
    public_nonces: Vec<String>,
}

async fn partial(
    State(q): State<Shared>,
    Json(body): Json<PartialReq>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let session = q.lock().unwrap().pending.remove(&body.session);
    let Some(session) = session else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "unknown_session", "detail": "gone" })),
        )
            .into_response();
    };
    let nonces: Vec<[u8; 66]> = body
        .public_nonces
        .iter()
        .map(|n| hex::decode(n).unwrap().try_into().unwrap())
        .collect();
    let mut ledger = VolatileNonceLedger::default();
    match session.sign(&mut ledger, &nonces) {
        Ok(p) => Json(serde_json::json!({
            "session": body.session,
            "partial": hex::encode(p),
        }))
        .into_response(),
        Err(e) => (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "sign", "detail": e })),
        )
            .into_response(),
    }
}

async fn serve(q: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/lock/cosign/nonce", post(nonce))
        .route("/api/v1/lock/cosign/partial", post(partial))
        .with_state(q);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// A Spending lane and a spend of it.
fn fixture(input_sats: u64) -> (ghost_lock::lane::Lane, SecretKey, SecretKey, SigningRequest) {
    let owner = sk(101);
    let quorum = sk(102);
    let lane = ghost_lock::lane::SpendingPolicy {
        aggregate: ghost_lock::key_agg::aggregate(&[xo(&owner), xo(&quorum)]).unwrap(),
        owner: xo(&owner),
    }
    .build(&Secp256k1::new(), Network::Regtest)
    .unwrap();

    let prevout = TxOut {
        value: Amount::from_sat(input_sats),
        script_pubkey: lane.address.script_pubkey(),
    };
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000009",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(input_sats - 1_000),
            script_pubkey: lane.address.script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
    psbt.inputs[0].witness_utxo = Some(prevout);

    use base64::Engine as _;
    let req = SigningRequest {
        psbt: base64::engine::general_purpose::STANDARD.encode(psbt.serialize()),
        input_index: 0,
        keys: vec![
            hex::encode(xo(&owner).serialize()),
            hex::encode(xo(&quorum).serialize()),
        ],
        merkle_root: lane.spend_info.merkle_root().map(|r| {
            use bitcoin::hashes::Hash as _;
            hex::encode(r.to_byte_array())
        }),
    };
    (lane, owner, quorum, req)
}

fn quorum_state(policy: CosignPolicy, role: Role, key: SecretKey) -> Shared {
    Arc::new(Mutex::new(Quorum {
        key,
        policy,
        role,
        coins: SigningLedger::new(VolatileStore::default()),
        spends: VolatileSpendLog::default(),
        pending: Default::default(),
    }))
}

/// **The whole path: the wallet asks, the quorum agrees, the lane accepts.**
#[tokio::test]
async fn the_wallet_gets_a_signature_the_lane_accepts() {
    let secp = Secp256k1::new();
    let (lane, owner, quorum, req) = fixture(100_000);
    let url = serve(quorum_state(CosignPolicy::default(), Role::Active, quorum)).await;

    let keys = ghost_lock::airgap::keys(&req).unwrap();
    let root = ghost_lock::airgap::merkle_root(&req).unwrap();
    let (_, message) = ghost_lock::airgap::review(&req, Network::Regtest).unwrap();

    let mut ledger = VolatileNonceLedger::default();
    let (sig, view) = cosign_with_quorum(
        &reqwest::Client::new(),
        &url,
        "binding-abc",
        &req,
        &owner,
        &keys,
        root,
        &message,
        &mut ledger,
    )
    .await
    .expect("the quorum co-signs");

    assert_eq!(view.input_sats, 100_000, "both sides read the same spend");
    assert_eq!(view.fee_sats, 1_000);

    let out = lane.spend_info.output_key().to_x_only_public_key();
    secp.verify_schnorr(&sig, &Message::from_digest(message), &out)
        .expect("the lane must accept the pair's signature");
}

/// A refusal reaches the wallet as a refusal, with the reason attached.
///
/// An owner told only "request failed" retries; one told the spend is over the
/// ceiling changes the spend.
#[tokio::test]
async fn a_refusal_carries_its_reason() {
    let (_, owner, quorum, req) = fixture(500_000);
    let url = serve(quorum_state(
        CosignPolicy {
            max_spend_sats: Some(100_000),
            window: Some(VelocityLimit {
                max_sats: 10_000_000,
                window_secs: 86_400,
            }),
        },
        Role::Active,
        quorum,
    ))
    .await;

    let keys = ghost_lock::airgap::keys(&req).unwrap();
    let root = ghost_lock::airgap::merkle_root(&req).unwrap();
    let (_, message) = ghost_lock::airgap::review(&req, Network::Regtest).unwrap();
    let mut ledger = VolatileNonceLedger::default();

    let err = cosign_with_quorum(
        &reqwest::Client::new(),
        &url,
        "binding-abc",
        &req,
        &owner,
        &keys,
        root,
        &message,
        &mut ledger,
    )
    .await
    .expect_err("above the ceiling");

    match err {
        CosignError::Refused { detail, .. } => {
            assert!(detail.contains("500000"), "{detail}");
            assert!(
                detail.contains("exit leaf"),
                "the owner must be told they still have a way out: {detail}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A quorum refusal must not burn the wallet's nonce.
///
/// The wallet's round 1 happens after the quorum's, so a spend that was never
/// going to be co-signed costs it nothing — otherwise a hostile coordinator
/// could exhaust a wallet's willingness to sign by refusing everything.
#[tokio::test]
async fn a_refusal_costs_the_wallet_no_nonce() {
    let (_, owner, quorum, req) = fixture(500_000);
    let url = serve(quorum_state(
        CosignPolicy {
            max_spend_sats: Some(100_000),
            window: None,
        },
        Role::Active,
        quorum,
    ))
    .await;

    let keys = ghost_lock::airgap::keys(&req).unwrap();
    let root = ghost_lock::airgap::merkle_root(&req).unwrap();
    let (_, message) = ghost_lock::airgap::review(&req, Network::Regtest).unwrap();
    let mut ledger = VolatileNonceLedger::default();

    for _ in 0..3 {
        assert!(cosign_with_quorum(
            &reqwest::Client::new(),
            &url,
            "binding-abc",
            &req,
            &owner,
            &keys,
            root,
            &message,
            &mut ledger,
        )
        .await
        .is_err());
    }
    // Nothing was burned, so a spend the quorum WOULD accept still works.
    let (_, owner2, quorum2, small) = fixture(50_000);
    let url2 = serve(quorum_state(
        CosignPolicy {
            max_spend_sats: Some(100_000),
            window: None,
        },
        Role::Active,
        quorum2,
    ))
    .await;
    let keys2 = ghost_lock::airgap::keys(&small).unwrap();
    let root2 = ghost_lock::airgap::merkle_root(&small).unwrap();
    let (_, message2) = ghost_lock::airgap::review(&small, Network::Regtest).unwrap();
    assert!(cosign_with_quorum(
        &reqwest::Client::new(),
        &url2,
        "binding-abc",
        &small,
        &owner2,
        &keys2,
        root2,
        &message2,
        &mut ledger,
    )
    .await
    .is_ok());
}

/// A standby is a routing problem, and the wallet says so.
#[tokio::test]
async fn a_standby_quorum_is_reported_as_a_refusal_not_a_crash() {
    let (_, owner, quorum, req) = fixture(100_000);
    let url = serve(quorum_state(CosignPolicy::default(), Role::Standby, quorum)).await;
    let keys = ghost_lock::airgap::keys(&req).unwrap();
    let root = ghost_lock::airgap::merkle_root(&req).unwrap();
    let (_, message) = ghost_lock::airgap::review(&req, Network::Regtest).unwrap();
    let mut ledger = VolatileNonceLedger::default();

    let err = cosign_with_quorum(
        &reqwest::Client::new(),
        &url,
        "binding-abc",
        &req,
        &owner,
        &keys,
        root,
        &message,
        &mut ledger,
    )
    .await
    .expect_err("a standby does not co-sign");
    assert!(format!("{err}").contains("standby"), "{err}");
}
