//! End-to-end test: L2 note encryption — shield → proof → encrypted transfer → decrypt
//!
//! Tests that encrypted_change and encrypted_recipient fields are properly
//! wired through the NoteSpend transfer pipeline. Verifies:
//! 1. Encrypted fields are accepted by ghost-pay
//! 2. Sender can decrypt their change note
//! 3. Recipient can decrypt their received note
//! 4. Wrong keys cannot decrypt notes
//!
//! Usage:
//!   # With locally-generated test params:
//!   cargo run -p ghost-pay --example test_encryption_e2e -- \
//!     --ghost-pay-url http://127.0.0.1:8800 \
//!     --api-secret <secret> \
//!     [--fast]
//!
//!   # With MPC params:
//!   cargo run -p ghost-pay --example test_encryption_e2e -- \
//!     --ghost-pay-url http://83.136.251.162:8800 \
//!     --api-secret <secret> \
//!     --params-file /tmp/note_spend_params.bin

use std::io::BufReader;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bellperson::groth16::Parameters;
use blstrs::Bls12;
use hmac::{Hmac, Mac};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::Sha256;

use ghost_keys::NoteData;
use ghost_zkp::{GhostNoteProver, GhostNoteSpendWitness, GhostNoteVerifier};

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let api_url =
        get_arg(&args, "--ghost-pay-url").unwrap_or_else(|| "http://127.0.0.1:8800".to_string());
    let api_secret = get_arg(&args, "--api-secret").expect("--api-secret required");
    let params_file = get_arg(&args, "--params-file");
    let fast = args.iter().any(|a| a == "--fast");
    let tree_depth: usize = if fast { 4 } else { 20 };

    let use_mpc = params_file.is_some();

    println!("=== Ghost Pay L2 Note Encryption E2E Test ===");
    println!("API: {}", api_url);
    if use_mpc {
        println!("Mode: MPC params (depth {})", tree_depth);
    } else {
        println!(
            "Mode: {}",
            if fast {
                "fast (depth 4)"
            } else {
                "production (depth 20)"
            }
        );
    }
    println!();

    // Generate sender and recipient keypairs
    let secp = Secp256k1::new();
    let sender_sk =
        SecretKey::from_slice(&deterministic_blinding(100)).expect("valid sender secret key");
    let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);
    let recipient_sk =
        SecretKey::from_slice(&deterministic_blinding(200)).expect("valid recipient secret key");
    let recipient_pk = PublicKey::from_secret_key(&secp, &recipient_sk);

    println!(
        "  Sender pubkey:    {}...",
        &hex::encode(sender_pk.serialize())[..16]
    );
    println!(
        "  Recipient pubkey: {}...",
        &hex::encode(recipient_pk.serialize())[..16]
    );
    println!();

    // Step 1: Load or generate Groth16 params
    let (prover, verifier) = if let Some(ref path) = params_file {
        println!("[1/10] Loading MPC params from {}...", path);
        let start = Instant::now();
        let file = std::fs::File::open(path).expect("Failed to open params file");
        let reader = BufReader::new(file);
        let params =
            Parameters::<Bls12>::read(reader, false).expect("Failed to deserialize params");
        let prover = GhostNoteProver::new_with_params(Arc::new(params), tree_depth);
        let verifier = GhostNoteVerifier::for_prover(&prover);
        println!("  Loaded in {:?}", start.elapsed());
        (prover, verifier)
    } else {
        println!("[1/10] Generating test Groth16 params...");
        let start = Instant::now();
        let prover = GhostNoteProver::new_with_setup(tree_depth).expect("Failed to setup prover");
        let verifier = GhostNoteVerifier::for_prover(&prover);
        println!("  Setup complete in {:?}", start.elapsed());
        (prover, verifier)
    };

    // Step 2: Shield sender note
    println!("[2/10] Shielding sender note (5000 sats)...");
    let sender_blinding = deterministic_blinding(10);
    let sender_amount: u64 = 5000;
    let sender_owner = [0x10u8; 32];
    let shield = shield_balance(
        &api_url,
        &api_secret,
        sender_amount,
        &sender_blinding,
        &sender_owner,
    );
    let sender_index = shield["note_index"]
        .as_u64()
        .expect("shield response should have note_index");
    let server_root_hex = shield["new_root"]
        .as_str()
        .expect("shield response should have new_root")
        .to_string();
    println!("  Sender note at index {}", sender_index);
    println!("  Tree root: {}...", &server_root_hex[..16]);

    // Step 3: Fetch Merkle proof
    println!("[3/10] Fetching Merkle proof...");
    let proof_response: serde_json::Value = http_get(&format!(
        "{}/api/v1/confidential/proof/{}",
        api_url, sender_index
    ));

    let server_siblings: Vec<[u8; 32]> = proof_response["siblings"]
        .as_array()
        .expect("proof response should have siblings array")
        .iter()
        .map(|s| {
            let hex_str = s.as_str().expect("sibling should be hex string");
            let bytes = hex::decode(hex_str).expect("sibling should be valid hex");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        })
        .collect();

    let _proof_root_hex = proof_response["tree_root"]
        .as_str()
        .expect("proof response should have tree_root");
    let proof_depth = proof_response["tree_depth"]
        .as_u64()
        .expect("proof response should have tree_depth") as usize;

    println!(
        "  Got {} siblings (depth {})",
        server_siblings.len(),
        proof_depth
    );
    assert_eq!(proof_depth, tree_depth);

    // Step 4: Generate NoteSpend proof
    println!("[4/10] Generating NoteSpend Groth16 proof...");
    let transfer_amount: u64 = 2000;
    let change_value = sender_amount - transfer_amount;
    let spending_key = deterministic_blinding(42);
    let change_blinding = deterministic_blinding(30);
    let recipient_new_blinding = deterministic_blinding(40);

    let witness = GhostNoteSpendWitness {
        spending_key,
        note_value: sender_amount,
        note_blinding: sender_blinding,
        note_index: sender_index,
        epoch: 0,
        merkle_siblings: server_siblings,
        amount: transfer_amount,
        change_blinding,
        recipient_blinding: recipient_new_blinding,
    };

    let start = Instant::now();
    let proof = prover.prove(&witness).expect("Proof generation failed");
    let prove_time = start.elapsed();
    println!("  Proof generated in {:?}", prove_time);

    let local_valid = verifier.verify(&proof).expect("Local verification error");
    println!(
        "  Local verification: {}",
        if local_valid { "PASS" } else { "FAIL" }
    );
    assert!(local_valid, "Local proof verification failed!");

    // Step 5: Encrypt change note for sender
    println!("[5/10] Encrypting change note for sender...");
    let change_note_data = NoteData {
        value: change_value,
        blinding: change_blinding,
        note_index: sender_index, // change note index
    };
    let encrypted_change = change_note_data
        .encrypt(&sender_pk)
        .expect("Change note encryption failed");
    println!(
        "  Encrypted change note: {} bytes (value={}, blinding={}...)",
        encrypted_change.len(),
        change_value,
        hex::encode(&change_blinding[..4])
    );
    assert!(
        encrypted_change.len() >= 109,
        "Encrypted change too short: {} bytes",
        encrypted_change.len()
    );

    // Step 6: Encrypt recipient note for recipient
    println!("[6/10] Encrypting recipient note for recipient...");
    let recipient_note_data = NoteData {
        value: transfer_amount,
        blinding: recipient_new_blinding,
        note_index: sender_index, // recipient note index
    };
    let encrypted_recipient = recipient_note_data
        .encrypt(&recipient_pk)
        .expect("Recipient note encryption failed");
    println!(
        "  Encrypted recipient note: {} bytes (value={}, blinding={}...)",
        encrypted_recipient.len(),
        transfer_amount,
        hex::encode(&recipient_new_blinding[..4])
    );
    assert!(
        encrypted_recipient.len() >= 109,
        "Encrypted recipient too short: {} bytes",
        encrypted_recipient.len()
    );

    // Step 7: Submit transfer with encrypted fields
    println!("[7/10] Submitting transfer with encrypted fields...");
    let tree_state: serde_json::Value = http_get(&format!("{}/api/v1/confidential/tree", api_url));
    let recipient_index = tree_state["next_index"]
        .as_u64()
        .expect("tree state should have next_index");

    let body = serde_json::json!({
        "proof_hex": hex::encode(&proof.proof),
        "commitment_root": hex::encode(proof.public_inputs.commitment_root),
        "nullifier": hex::encode(proof.public_inputs.nullifier),
        "change_commitment": hex::encode(proof.public_inputs.change_commitment),
        "recipient_commitment": hex::encode(proof.public_inputs.recipient_commitment),
        "sender_index": sender_index,
        "recipient_index": recipient_index,
        "recipient_owner_pubkey": hex::encode([0x20u8; 32]),
        "epoch": 0,
        "encrypted_change": hex::encode(&encrypted_change),
        "encrypted_recipient": hex::encode(&encrypted_recipient),
    });

    let result = http_post_authed(
        &format!("{}/api/v1/confidential/transfer", api_url),
        &api_secret,
        &body,
    );
    let transfer_id = result
        .get("transfer_id")
        .and_then(|v| v.as_str())
        .expect("Server should return transfer_id");
    println!("  Transfer accepted: {}", transfer_id);

    // Step 8: Verify sender can decrypt change note
    println!("[8/10] Verifying sender can decrypt change note...");
    let decrypted_change = NoteData::decrypt(&sender_sk, &encrypted_change)
        .expect("Sender should be able to decrypt change note");
    assert_eq!(decrypted_change.value, change_value);
    assert_eq!(decrypted_change.blinding, change_blinding);
    assert_eq!(decrypted_change.note_index, sender_index);
    println!(
        "  Decrypted change: value={}, blinding={}..., index={}",
        decrypted_change.value,
        hex::encode(&decrypted_change.blinding[..4]),
        decrypted_change.note_index
    );

    // Step 9: Verify recipient can decrypt recipient note
    println!("[9/10] Verifying recipient can decrypt recipient note...");
    let decrypted_recipient = NoteData::decrypt(&recipient_sk, &encrypted_recipient)
        .expect("Recipient should be able to decrypt recipient note");
    assert_eq!(decrypted_recipient.value, transfer_amount);
    assert_eq!(decrypted_recipient.blinding, recipient_new_blinding);
    assert_eq!(decrypted_recipient.note_index, sender_index);
    println!(
        "  Decrypted recipient: value={}, blinding={}..., index={}",
        decrypted_recipient.value,
        hex::encode(&decrypted_recipient.blinding[..4]),
        decrypted_recipient.note_index
    );

    // Step 10: Verify wrong keys CANNOT decrypt
    println!("[10/10] Verifying wrong keys cannot decrypt...");
    let wrong_sk =
        SecretKey::from_slice(&deterministic_blinding(255)).expect("valid wrong secret key");

    let wrong_change = NoteData::decrypt(&wrong_sk, &encrypted_change);
    assert!(
        wrong_change.is_err(),
        "Wrong key should NOT decrypt change note"
    );
    println!("  Wrong key → change note: correctly failed");

    let wrong_recipient = NoteData::decrypt(&wrong_sk, &encrypted_recipient);
    assert!(
        wrong_recipient.is_err(),
        "Wrong key should NOT decrypt recipient note"
    );
    println!("  Wrong key → recipient note: correctly failed");

    // Cross-key check: sender can't decrypt recipient's note
    let cross_change = NoteData::decrypt(&sender_sk, &encrypted_recipient);
    assert!(
        cross_change.is_err(),
        "Sender key should NOT decrypt recipient note"
    );
    println!("  Sender key → recipient note: correctly failed");

    let cross_recipient = NoteData::decrypt(&recipient_sk, &encrypted_change);
    assert!(
        cross_recipient.is_err(),
        "Recipient key should NOT decrypt change note"
    );
    println!("  Recipient key → change note: correctly failed");

    println!();
    println!("=== RESULTS ===");
    println!("  Transfer ID: {}", transfer_id);
    println!(
        "  Change note:     {} sats (encrypted {} bytes)",
        change_value,
        encrypted_change.len()
    );
    println!(
        "  Recipient note:  {} sats (encrypted {} bytes)",
        transfer_amount,
        encrypted_recipient.len()
    );
    println!("  Proof time: {:?}", prove_time);
    println!("  Tree depth: {}", tree_depth);
    println!("  Params: {}", if use_mpc { "MPC" } else { "test" });
    println!();
    println!("  *** L2 Note Encryption E2E TEST PASSED ***");
}

// ============================================================================
// Helpers (shared with test_note_spend_e2e)
// ============================================================================

fn get_arg(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn deterministic_blinding(seed: u8) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(b"ghost-note-spend-e2e-v1");
    hasher.update([seed]);
    let hash: [u8; 32] = hasher.finalize().into();
    let mut result = hash;
    result[31] &= 0x3F; // Ensure valid BLS12-381 scalar
    result
}

fn shield_balance(
    api_url: &str,
    api_secret: &str,
    amount_sats: u64,
    blinding: &[u8; 32],
    owner_pubkey: &[u8; 32],
) -> serde_json::Value {
    let body = serde_json::json!({
        "amount_sats": amount_sats,
        "blinding_hex": hex::encode(blinding),
        "owner_pubkey": hex::encode(owner_pubkey),
    });
    http_post_authed(
        &format!("{}/api/v1/confidential/shield", api_url),
        api_secret,
        &body,
    )
}

fn http_get(url: &str) -> serde_json::Value {
    let output = std::process::Command::new("curl")
        .args(["-s", url])
        .output()
        .expect("curl failed");
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| serde_json::json!({"error": "Failed to parse response"}))
}

fn compute_hmac(secret: &str, timestamp: &str, body: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn http_post_authed(url: &str, secret: &str, body: &serde_json::Value) -> serde_json::Value {
    let (status, response) = http_post_authed_raw(url, secret, body);
    if status != 200 {
        eprintln!("WARNING: HTTP {} from {}", status, url);
    }
    serde_json::from_str(&response).unwrap_or_else(|e| {
        panic!("Invalid JSON from {}: {} — Response: {}", url, e, response);
    })
}

fn http_post_authed_raw(url: &str, secret: &str, body: &serde_json::Value) -> (u16, String) {
    let body_str = serde_json::to_string(body).unwrap();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let signature = compute_hmac(secret, &timestamp, &body_str);

    let output = std::process::Command::new("curl")
        .args([
            "-s",
            "-o",
            "/dev/stderr",
            "-w",
            "%{http_code}",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            &format!("X-Ghost-Timestamp: {}", timestamp),
            "-H",
            &format!("X-Ghost-Signature: {}", signature),
            "-d",
            &body_str,
            url,
        ])
        .output()
        .expect("curl failed");

    let status_str = String::from_utf8_lossy(&output.stdout);
    let status: u16 = status_str.trim().parse().unwrap_or(0);
    let body_response = String::from_utf8_lossy(&output.stderr).to_string();

    (status, body_response)
}
