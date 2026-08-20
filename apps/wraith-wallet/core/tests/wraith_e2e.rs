//! End-to-end integration test: real wallet client driving a real
//! `wraith-coordinator` over real HTTP.
//!
//! Sets up a coordinator with a `MockUtxoSource` + `StubBroadcaster`,
//! binds it to an ephemeral port via `axum::serve`, then spins up
//! five `WraithSessionClient` runs concurrently — one per ghost_id.
//! Each wallet drives the protocol on its own task; the test
//! coordinator-flips the session Filling → Locked mid-flight (since
//! the 5-min fill-window won't expire in test time and we don't have
//! 20 wallets to hit max_participants).

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::{secp256k1::SecretKey, Address, Network, Witness};
use wraith_coordinator::broadcaster::{Broadcaster, StubBroadcaster};
use wraith_coordinator::utxo_source::MockUtxoSource;
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{LiteSessionState, SessionGossipEvent};
use wraith_wallet_core::wraith::{
    MixRequest, ParticipantUtxo, WraithClientError, WraithSessionClient,
};

const TIER_ID: &str = "100k_sats";
const TIER_DENOM: u64 = 100_000;
/// The exact input a 100k-tier Mix seat costs. Rounds have no change output
/// (#698), so a participant brings this to the satoshi or is refused.
const SEAT_PRICE: u64 = 102_096;
const N: usize = 5;

/// Generate the i-th deterministic signet P2WPKH address. Same scheme
/// used by the coordinator's own router tests.
fn signet_addr(i: u8) -> String {
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::CompressedPublicKey;
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[i; 32]).unwrap();
    let cpk = CompressedPublicKey(sk.public_key(&secp));
    Address::p2wpkh(&cpk, Network::Signet).to_string()
}

/// Participant `i`'s key. `[i + 1; 32]` because zero is not a valid
/// secret key, and participant 0 has to have one.
fn participant_key(i: u8) -> bitcoin::PrivateKey {
    bitcoin::PrivateKey::new(
        SecretKey::from_slice(&[i + 1; 32]).expect("valid secret key"),
        Network::Signet,
    )
}

/// Participant `i`'s BIP86 key-path P2TR address — where its coin sits,
/// and what its ownership proof is checked against.
fn participant_address(i: u8) -> Address {
    use bitcoin::secp256k1::Secp256k1;
    let secp = Secp256k1::new();
    let (xonly, _) = participant_key(i)
        .public_key(&secp)
        .inner
        .x_only_public_key();
    Address::p2tr(&secp, xonly, None, Network::Signet)
}

/// A real BIP-322 proof that participant `i` controls `txid:vout`, for
/// this session. The coordinator refuses registration without one (#699).
fn ownership_proof(session_id: &str, i: u8, txid: &str, vout: u32) -> String {
    use base64::Engine;
    use bitcoin::consensus::Encodable;

    let challenge = wraith_protocol::ownership_challenge(session_id, txid, vout);
    let witness = bip322::sign_simple(
        &participant_address(i),
        challenge.as_bytes(),
        &[participant_key(i)],
        None,
    )
    .expect("sign ownership proof");
    let mut encoded = Vec::new();
    witness.consensus_encode(&mut encoded).expect("encode");
    base64::engine::general_purpose::STANDARD.encode(encoded)
}

/// The UTXO set the coordinator reads at registration — one confirmed
/// 200,000-sat coin per participant, each paying to that participant's
/// own address. Registration checks the submission against this, so the
/// two have to agree.
fn participant_utxos() -> MockUtxoSource {
    let utxos = MockUtxoSource::new();
    for i in 0..N {
        utxos.insert(
            bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&"11".repeat(32)).unwrap(),
                vout: i as u32,
            },
            SEAT_PRICE,
            participant_address(i as u8).script_pubkey(),
        );
    }
    utxos
}

#[tokio::test]
async fn five_wallets_complete_a_full_mix_round() {
    // 1. Stand up the coordinator.
    let stub_broadcaster = StubBroadcaster::new();
    let state = Arc::new(
        CoordinatorState::with_components(
            Network::Signet,
            Arc::new(wraith_protocol::SystemClock),
            Arc::new(wraith_protocol::RandomSessionIdGenerator),
            Some(signet_addr(99)),
            Some(Arc::new(stub_broadcaster.clone()) as Arc<dyn Broadcaster>),
        )
        .with_utxo_source(Arc::new(participant_utxos())),
    );
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("axum serve");
    });
    let base_url = format!("http://127.0.0.1:{port}");

    // 2. Spawn 5 wallets concurrently. Each runs the full protocol
    //    on its own task. The test
    //    source; the test coordinator-side state advances Filling →
    //    Locked once all 5 have enrolled (see step 3).
    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let base_url = base_url.clone();
        let handle = tokio::spawn(async move {
            let client = WraithSessionClient::new(base_url, Network::Signet);
            let ghost = format!("wallet-{i}");
            let utxo = ParticipantUtxo {
                txid: "11".repeat(32),
                vout: i as u32,
                value_sats: SEAT_PRICE,
                scriptpubkey_hex: participant_address(i as u8).script_pubkey().to_hex_string(),
            };
            let req = MixRequest {
                tier_id: TIER_ID.into(),
                ghost_id: ghost.clone(),
                utxo,
                // Mixed outputs are P2TR and nothing else (#696).
                mix_output_address: participant_address(i as u8 + 10).to_string(),
            };
            let signer = |_tx: &bitcoin::Transaction, _idx: usize, _amt: u64| {
                let mut w = Witness::new();
                w.push([0xde, 0xad, 0xbe, 0xef]);
                Ok::<Witness, WraithClientError>(w)
            };
            let prove = move |challenge: &str| {
                let challenge = challenge.to_string();
                async move {
                    // The session id is inside the challenge, which is
                    // what binds the proof to this round.
                    let txid = "11".repeat(32);
                    let sid = challenge.lines().nth(1).unwrap_or_default().to_string();
                    Ok::<String, WraithClientError>(ownership_proof(&sid, i as u8, &txid, i as u32))
                }
            };
            client.execute_mix(req, signer, prove).await
        });
        handles.push(handle);
    }

    // 3. Flip the session to Locked once all 5 wallets have enrolled.
    //    We don't know the session_id ahead of time, so poll the
    //    state's session registry until exactly one session has
    //    `min_participants` slots filled. Bounded retry.
    let session_id = wait_for_quorum(&state).await;
    let _ = state
        .sessions
        .apply_event(SessionGossipEvent::StateChanged {
            session_id: session_id.clone(),
            new_state: LiteSessionState::Locked,
        });

    // 4. Wait for all 5 wallet tasks to finish.
    let mut outcomes = Vec::with_capacity(N);
    for h in handles {
        let outcome = h.await.expect("task join").expect("execute_mix succeeded");
        outcomes.push(outcome);
    }

    // 5. All five outcomes refer to the same session and broadcast txid.
    let broadcast_txid = outcomes[0].broadcast_txid;
    for (i, o) in outcomes.iter().enumerate() {
        assert_eq!(o.session_id, session_id, "wallet-{i} different session");
        assert_eq!(
            o.broadcast_txid, broadcast_txid,
            "wallet-{i} different txid"
        );
    }

    // 6. The broadcaster received exactly one tx with 5 inputs.
    assert_eq!(stub_broadcaster.count(), 1, "broadcast called once");
    let final_tx = stub_broadcaster.last().expect("tx was broadcast");
    assert_eq!(final_tx.compute_txid(), broadcast_txid);
    assert_eq!(final_tx.input.len(), N, "5 inputs");

    // 7. Each wallet's mixed output landed in the tx, all distinct
    //    indices, all the right amount + scriptPubKey.
    let mut seen_indices = std::collections::HashSet::new();
    for (i, o) in outcomes.iter().enumerate() {
        assert!(
            seen_indices.insert(o.mixed_output_tx_index),
            "wallet-{i} duplicate mixed_output_tx_index",
        );
        let txout = &final_tx.output[o.mixed_output_tx_index];
        assert_eq!(txout.value.to_sat(), TIER_DENOM, "wallet-{i} wrong amount");
        let expected_addr = participant_address(i as u8 + 10);
        assert_eq!(
            txout.script_pubkey,
            expected_addr.script_pubkey(),
            "wallet-{i} wrong scriptpubkey"
        );
    }
}

/// Block until the coordinator's session registry contains exactly
/// one session with N enrolled participants. Returns its session_id.
/// Bounded poll loop — gives up after a generous timeout so the test
/// fails fast on a wallet bug rather than hanging.
async fn wait_for_quorum(state: &CoordinatorState) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        // Walk every session once per loop — there's only ever 1 in
        // this test, so the cost is trivial.
        let mut found: Option<String> = None;
        for tier in state.supported_tiers() {
            for s in state.sessions.open_sessions_at(
                tier,
                wraith_protocol::SessionType::Mix,
                state.now(),
            ) {
                if s.participants.len() == N {
                    found = Some(s.session_id);
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }
        if let Some(sid) = found {
            return sid;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for {N} wallets to enrol");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 proxy wiring (B: Tor anonymity for /outputs)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn with_outputs_proxy_accepts_valid_socks_url() {
    // Doesn't talk to a real Tor — just checks construction succeeds
    // and the resulting client is usable. socks5h:// = SOCKS5 with
    // remote DNS (Tor's recommended default).
    let _client = WraithSessionClient::with_outputs_proxy(
        "http://127.0.0.1:9100",
        Network::Signet,
        "socks5h://127.0.0.1:9050",
    )
    .expect("valid proxy URL accepted");
}

#[tokio::test]
async fn with_outputs_proxy_rejects_malformed_url() {
    let result = WraithSessionClient::with_outputs_proxy(
        "http://127.0.0.1:9100",
        Network::Signet,
        "not a valid url",
    );
    assert!(result.is_err(), "malformed proxy URL must be rejected");
}

// ---------------------------------------------------------------------------
// prepare_mix / submit_witness split (async-signer-friendly API)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn prepare_then_submit_works_via_split_api() {
    // Same fixture as the happy-path full mix, but each wallet uses
    // prepare_mix + submit_witness separately instead of the
    // execute_mix wrapper. Confirms the split API delivers the same
    // PreparedMix-shaped result and can be witness-signed asynchronously.
    let stub_broadcaster = StubBroadcaster::new();
    let state = Arc::new(
        CoordinatorState::with_components(
            Network::Signet,
            Arc::new(wraith_protocol::SystemClock),
            Arc::new(wraith_protocol::RandomSessionIdGenerator),
            Some(signet_addr(99)),
            Some(Arc::new(stub_broadcaster.clone()) as Arc<dyn Broadcaster>),
        )
        .with_utxo_source(Arc::new(participant_utxos())),
    );
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base_url = format!("http://127.0.0.1:{port}");

    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let base_url = base_url.clone();
        handles.push(tokio::spawn(async move {
            let client = WraithSessionClient::new(base_url, Network::Signet);
            let ghost = format!("wallet-{i}");
            let req = MixRequest {
                tier_id: TIER_ID.into(),
                ghost_id: ghost.clone(),
                utxo: ParticipantUtxo {
                    txid: "11".repeat(32),
                    vout: i as u32,
                    value_sats: SEAT_PRICE,
                    scriptpubkey_hex: participant_address(i as u8).script_pubkey().to_hex_string(),
                },
                mix_output_address: participant_address(i as u8 + 10).to_string(),
            };

            // Phase 1: prepare. Returns PreparedMix.
            let prove = move |challenge: &str| {
                let challenge = challenge.to_string();
                async move {
                    let txid = "11".repeat(32);
                    let sid = challenge.lines().nth(1).unwrap_or_default().to_string();
                    Ok::<String, WraithClientError>(ownership_proof(&sid, i as u8, &txid, i as u32))
                }
            };
            let prepared = client.prepare_mix(req, prove).await.expect("prepare_mix");

            // Inspect the unsigned tx — that's the whole point of the
            // split. A real signer would derive the sighash from
            // prepared.unsigned_tx + prepared.input_index +
            // prepared.prev_amount_sats and sign with the keystore.
            assert_eq!(prepared.unsigned_tx.input.len(), N);
            assert!(prepared.input_index < N);

            // Compute "witness" asynchronously (placeholder bytes
            // here; production would do BIP-143 / BIP-341 sighash +
            // Schnorr / ECDSA sign).
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let mut w = Witness::new();
            w.push([0xab, 0xcd, 0xef]);

            // Phase 2: submit.
            client.submit_witness(&prepared, w).await
        }));
    }

    let session_id = wait_for_quorum(&state).await;
    let _ = state
        .sessions
        .apply_event(SessionGossipEvent::StateChanged {
            session_id: session_id.clone(),
            new_state: LiteSessionState::Locked,
        });

    let mut outcomes = Vec::with_capacity(N);
    for h in handles {
        outcomes.push(h.await.unwrap().expect("submit_witness"));
    }
    let txid = outcomes[0].broadcast_txid;
    for o in &outcomes {
        assert_eq!(o.session_id, session_id);
        assert_eq!(o.broadcast_txid, txid);
    }
    assert_eq!(stub_broadcaster.count(), 1);
}

// ---------------------------------------------------------------------------
// Real BIP-341 witness signing through the full pipeline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn five_wallets_sign_real_taproot_witnesses_end_to_end() {
    // Same protocol pipeline as `five_wallets_complete_a_full_mix_round`,
    // but each wallet has its own Keystore (distinct deterministic
    // mnemonic) and its UTXO's scriptPubKey is the BIP86 idx-0 address
    // derived from that keystore. The signer is `sign_taproot_key_path`
    // — real BIP-341 SIGHASH_DEFAULT, real Schnorr sigs.
    //
    // The StubBroadcaster doesn't validate sigs (only bitcoind would),
    // but the test cross-checks the merged tx by re-deriving the
    // tweaked pubkey + recomputing the sighash + verifying with
    // secp256k1::verify_schnorr. That proves the daemon's
    // internal-signing path produces signatures that bitcoind would
    // accept.
    use bitcoin::secp256k1::{schnorr::Signature as SchnorrSig, Keypair, Message, Secp256k1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::{ScriptBuf, TxOut};
    use wraith_wallet_core::keystore::Keystore;
    use wraith_wallet_core::wraith_signer::{sign_taproot_key_path, DEFAULT_SCAN_INDEX_MAX};
    let stub_broadcaster = StubBroadcaster::new();
    let state = Arc::new(
        CoordinatorState::with_components(
            Network::Signet,
            Arc::new(wraith_protocol::SystemClock),
            Arc::new(wraith_protocol::RandomSessionIdGenerator),
            Some(signet_addr(99)),
            Some(Arc::new(stub_broadcaster.clone()) as Arc<dyn Broadcaster>),
        )
        .with_utxo_source(Arc::new(keystore_utxos())),
    );
    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let base_url = format!("http://127.0.0.1:{port}");

    /// This test's wallets are real keystores, so the chain has to hold
    /// coins paying to their real BIP86 addresses — registration checks
    /// the submission against this, and the ownership proof against the
    /// scriptPubKey it reports.
    fn keystore_utxos() -> MockUtxoSource {
        let utxos = MockUtxoSource::new();
        for i in 0..N {
            let ks = Keystore::from_mnemonic(mnemonic_for(i)).unwrap();
            let addr = wraith_wallet_core::light::receive_address(&ks, 0, Network::Signet).unwrap();
            utxos.insert(
                bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_str(&format!("{:02x}", i + 1).repeat(32)).unwrap(),
                    vout: 0,
                },
                SEAT_PRICE,
                addr.script_pubkey(),
            );
        }
        utxos
    }

    /// Deterministic mnemonic per wallet. Real wallets have one; tests
    /// pick a stable variant per index.
    fn mnemonic_for(i: usize) -> &'static str {
        match i {
            0 => "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            1 => "legal winner thank year wave sausage worth useful legal winner thank yellow",
            2 => "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            3 => "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            4 => "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            _ => unreachable!(),
        }
    }

    let mut handles = Vec::with_capacity(N);
    for i in 0..N {
        let base_url = base_url.clone();
        let handle = tokio::spawn(async move {
            let keystore = Keystore::from_mnemonic(mnemonic_for(i)).unwrap();
            let my_addr =
                wraith_wallet_core::light::receive_address(&keystore, 0, Network::Signet).unwrap();
            let my_spk_hex = hex::encode(my_addr.script_pubkey().as_bytes());
            let my_spk_hex_for_proof = my_spk_hex.clone();
            let mix_addr =
                wraith_wallet_core::light::receive_address(&keystore, 1, Network::Signet).unwrap();

            let client = WraithSessionClient::new(base_url, Network::Signet);
            let ghost = format!("wallet-{i}");
            let req = MixRequest {
                tier_id: TIER_ID.into(),
                ghost_id: ghost.clone(),
                utxo: ParticipantUtxo {
                    txid: format!("{:02x}", i + 1).repeat(32),
                    vout: 0,
                    value_sats: SEAT_PRICE,
                    scriptpubkey_hex: my_spk_hex,
                },
                mix_output_address: mix_addr.to_string(),
            };

            // The real keystore-backed prover, so this test exercises
            // the same code a wallet runs (#699).
            let proof_spk = my_spk_hex_for_proof.clone();
            let prove = move |challenge: &str| {
                let challenge = challenge.to_string();
                let spk = proof_spk.clone();
                // Keystore isn't Clone, so re-derive it per call — the
                // mnemonic is the same, so the key is the same.
                let ks = Keystore::from_mnemonic(mnemonic_for(i)).unwrap();
                async move {
                    wraith_wallet_core::wraith_signer::prove_ownership(
                        &ks,
                        Network::Signet,
                        &spk,
                        &challenge,
                        DEFAULT_SCAN_INDEX_MAX.min(16),
                    )
                    .map_err(|e| WraithClientError::OwnershipProof(e.to_string()))
                }
            };
            let prepared = client.prepare_mix(req, prove).await.unwrap();
            // Real BIP-341 sign: scan idx 0..16 (we know it's 0).
            let witness = sign_taproot_key_path(
                &keystore,
                Network::Signet,
                &prepared.unsigned_tx,
                prepared.input_index,
                &prepared.prevouts,
                DEFAULT_SCAN_INDEX_MAX.min(16),
            )
            .expect("real signer ok");
            client.submit_witness(&prepared, witness).await
        });
        handles.push(handle);
    }

    let session_id = wait_for_quorum(&state).await;
    let _ = state
        .sessions
        .apply_event(SessionGossipEvent::StateChanged {
            session_id: session_id.clone(),
            new_state: LiteSessionState::Locked,
        });

    let mut outcomes = Vec::with_capacity(N);
    for h in handles {
        outcomes.push(h.await.unwrap().unwrap());
    }
    let txid = outcomes[0].broadcast_txid;
    for o in &outcomes {
        assert_eq!(o.broadcast_txid, txid);
    }

    // Now the load-bearing assertion: every input's witness verifies
    // against secp256k1::verify_schnorr.
    let final_tx = stub_broadcaster.last().expect("broadcast happened");
    assert_eq!(final_tx.input.len(), N);

    // Reconstruct prevouts in tx order. inputs_store still holds the
    // per-participant records; we walk it the same way the coordinator
    // did when shipping prevouts on /round-tx.
    let inputs = state
        .inputs_store
        .lock()
        .unwrap()
        .get(&session_id)
        .cloned()
        .unwrap_or_default();
    let mut prev_txouts: Vec<TxOut> = Vec::with_capacity(inputs.len());
    for inp in &inputs {
        prev_txouts.push(TxOut {
            value: bitcoin::Amount::from_sat(inp.input.value_sats),
            script_pubkey: ScriptBuf::from_bytes(hex::decode(&inp.input.scriptpubkey_hex).unwrap()),
        });
    }

    let secp = Secp256k1::new();
    use bitcoin::hashes::Hash as _;
    use bitcoin::key::TapTweak;
    for (idx, inp) in inputs.iter().enumerate() {
        // Recompute the sighash for this input.
        let mut cache = SighashCache::new(&final_tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                idx,
                &Prevouts::All(&prev_txouts),
                TapSighashType::Default,
            )
            .unwrap();
        let msg = Message::from_digest(*sighash.as_byte_array());

        // Re-derive the tweaked pubkey from the wallet's mnemonic.
        // We know each wallet uses BIP86 idx 0 in this test.
        let wallet_idx: usize = inp
            .ghost_id
            .strip_prefix("wallet-")
            .and_then(|n| n.parse().ok())
            .expect("ghost_id wallet-N");
        let keystore = Keystore::from_mnemonic(mnemonic_for(wallet_idx)).unwrap();
        let xprv = keystore
            .derive_xprv(&format!(
                "m/86'/{}'/0'/0/0",
                wraith_wallet_core::light::GHOST_COIN_TYPE
            ))
            .unwrap();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&xprv.private_key().to_bytes()).unwrap();
        let untweaked = Keypair::from_secret_key(&secp, &sk);
        let tweaked = untweaked.tap_tweak(&secp, None);
        let xonly = tweaked.to_keypair().x_only_public_key().0;

        // The witness should have one stack item: the 64-byte sig.
        let txin = &final_tx.input[idx];
        let sig_bytes = txin.witness.iter().next().expect("witness present");
        assert_eq!(
            sig_bytes.len(),
            64,
            "BIP-341 SIGHASH_DEFAULT sig is 64 bytes"
        );
        let sig = SchnorrSig::from_slice(sig_bytes).unwrap();

        secp.verify_schnorr(&sig, &msg, &xonly).unwrap_or_else(|e| {
            panic!("input {idx} (wallet-{wallet_idx}) signature failed verify: {e}")
        });
    }
}
