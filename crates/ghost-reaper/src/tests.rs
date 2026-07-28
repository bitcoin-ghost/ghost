use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::config::ReaperConfig;
use crate::verdict::DeadCodeType;
use crate::{analyze, SpendType};

// ─── Test Helpers ───────────────────────────────────────────────────────────

fn non_coinbase_outpoint() -> OutPoint {
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[1u8]));
    OutPoint { txid, vout: 0 }
}

/// Build a P2WPKH output script: OP_0 OP_PUSHBYTES_20 <20 bytes>
fn p2wpkh_script() -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14]; // OP_0, PUSHBYTES_20
    bytes.extend([0xAA; 20]);
    ScriptBuf::from(bytes)
}

/// Build a transaction with a single P2TR script-path input.
/// The tapscript and control block are provided; other witness items
/// are optional (for signatures, etc).
fn tx_with_tapscript(tapscript: &[u8], extra_witness: &[&[u8]]) -> Transaction {
    let mut witness = Witness::new();
    for item in extra_witness {
        witness.push(item);
    }
    witness.push(tapscript);
    // Control block: 33 bytes, first byte 0xc0 (leaf version)
    let mut control_block = vec![0xc0];
    control_block.extend([0x11; 32]); // internal key
    witness.push(&control_block);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

/// Build a transaction with P2WSH witness script.
fn tx_with_witness_script(witness_script: &[u8], extra_witness: &[&[u8]]) -> Transaction {
    let mut witness = Witness::new();
    for item in extra_witness {
        witness.push(item);
    }
    witness.push(witness_script);

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

/// Build a transaction with specific outputs.
fn tx_with_outputs(outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

/// Build a P2TR key-path spend (single 64-byte Schnorr sig).
fn tx_p2tr_keypath() -> Transaction {
    let mut witness = Witness::new();
    witness.push([0x30; 64]); // 64-byte Schnorr signature

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

/// Build a coinbase transaction.
fn coinbase_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::all_zeros(),
                vout: 0xFFFFFFFF,
            },
            script_sig: ScriptBuf::from(vec![0x03, 0x01, 0x02, 0x03]), // block height
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(312500000),
            script_pubkey: p2wpkh_script(),
        }],
    }
}

// ─── Spec Test Vectors ──────────────────────────────────────────────────────

/// Test 1: Standard inscription envelope → Corpse
#[test]
fn test_standard_inscription_envelope() {
    // Tapscript: OP_FALSE OP_IF OP_PUSH3 "ord" OP_1 OP_PUSH24 "text/plain;charset=utf-8"
    //            OP_0 OP_PUSH11 "Hello World" OP_ENDIF OP_CHECKSIG
    let mut script: Vec<u8> = Vec::new();
    // OP_FALSE OP_IF
    script.push(0x00);
    script.push(0x63);
    // OP_PUSH3 "ord"
    script.push(0x03);
    script.extend(b"ord");
    // OP_1 (content type marker)
    script.push(0x51);
    // OP_PUSH24 "text/plain;charset=utf-8"
    let content_type = b"text/plain;charset=utf-8";
    script.push(content_type.len() as u8);
    script.extend(content_type);
    // OP_0 (content marker)
    script.push(0x00);
    // OP_PUSH11 "Hello World"
    let content = b"Hello World";
    script.push(content.len() as u8);
    script.extend(content);
    // OP_ENDIF
    script.push(0x68);
    // OP_CHECKSIG (legitimate spend condition after envelope)
    script.push(0xac);

    let sig = [0x30; 64]; // Schnorr sig
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert!(!verdict.dead_regions.is_empty());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::InscriptionEnvelope
    );
}

/// Test 2: Large image inscription → Corpse
#[test]
fn test_large_image_inscription() {
    let mut script: Vec<u8> = Vec::new();
    // OP_FALSE OP_IF
    script.push(0x00);
    script.push(0x63);
    // OP_PUSH3 "ord"
    script.push(0x03);
    script.extend(b"ord");
    // Simulate large image data: multiple 520-byte pushes (max push per element)
    for _ in 0..10 {
        // OP_PUSHDATA2 with 520 bytes
        script.push(0x4d);
        script.extend(520u16.to_le_bytes());
        script.extend(vec![0xFF; 520]);
    }
    // OP_ENDIF
    script.push(0x68);
    // OP_CHECKSIG
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert!(verdict.total_dead_bytes > 5000);
}

/// Test 3: Legitimate HTLC → Accept
#[test]
fn test_legitimate_htlc() {
    // HTLC script: OP_IF <pubkey_hash> OP_ELSE <timeout> OP_CLTV OP_DROP <pubkey_hash> OP_ENDIF OP_CHECKSIG
    // All branches are reachable — no dead code
    let mut script: Vec<u8> = vec![
        0x63, // OP_IF
        0x76, // OP_DUP
        0xa9, // OP_HASH160
        0x14, // PUSH20
    ];
    script.extend([0xAA; 20]);
    script.push(0x88); // OP_EQUALVERIFY
                       // OP_ELSE
    script.push(0x67);
    // <timeout> OP_CLTV OP_DROP
    script.push(0x04); // PUSH4
    script.extend(500000u32.to_le_bytes());
    script.push(0xb1); // OP_CLTV
    script.push(0x75); // OP_DROP (small push, below threshold)
                       // <pubkey_hash>
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // PUSH20
    script.extend([0xBB; 20]);
    script.push(0x88); // OP_EQUALVERIFY
                       // OP_ENDIF OP_CHECKSIG
    script.push(0x68);
    script.push(0xac);

    let sig = [0x30; 64];
    let preimage = [0xCC; 32];
    let tx = tx_with_tapscript(&script, &[&sig, &preimage]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
}

/// Test 4: P2TR key path → Accept
#[test]
fn test_p2tr_key_path() {
    let tx = tx_p2tr_keypath();
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
    assert_eq!(verdict.input_analyses[0].spend_type, "P2TR-keypath");
}

/// Test 5: OP_DROP data stuffing → Corpse
#[test]
fn test_op_drop_data_stuffing() {
    let mut script: Vec<u8> = Vec::new();
    // Push 100 bytes of junk data
    script.push(0x4c); // OP_PUSHDATA1
    script.push(100); // length
    script.extend(vec![0xDE; 100]);
    // OP_DROP
    script.push(0x75);
    // Legitimate spend condition
    script.push(0x51); // OP_1 (true)

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::DropStuffing
    );
}

/// Test 6: Bare multisig fake pubkeys → Corpse
#[test]
fn test_bare_multisig_fake_pubkeys() {
    // 1-of-3 multisig where 2 pubkeys have invalid prefixes (data carriers)
    let mut script_bytes = vec![0x51]; // OP_1

    // Valid pubkey
    script_bytes.push(0x21); // PUSHBYTES_33
    script_bytes.push(0x02);
    script_bytes.extend([0xAA; 32]);

    // Fake pubkey (0x04 prefix)
    script_bytes.push(0x21);
    script_bytes.push(0x04);
    script_bytes.extend([0xBB; 32]);

    // Fake pubkey (0x00 prefix)
    script_bytes.push(0x21);
    script_bytes.push(0x00);
    script_bytes.extend([0xCC; 32]);

    script_bytes.push(0x53); // OP_3
    script_bytes.push(0xae); // OP_CHECKMULTISIG

    let outputs = vec![TxOut {
        value: Amount::from_sat(50000),
        script_pubkey: ScriptBuf::from(script_bytes),
    }];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let fake_regions: Vec<_> = verdict
        .dead_regions
        .iter()
        .filter(|r| r.dead_code_type == DeadCodeType::FakePubkey)
        .collect();
    assert_eq!(fake_regions.len(), 2); // 2 fake pubkeys
}

/// Test 7: Small OP_RETURN → Accept
#[test]
fn test_small_op_return_accept() {
    // OP_RETURN with 40 bytes of data (well under 83 limit)
    let mut script_bytes = vec![0x6a]; // OP_RETURN
    script_bytes.push(40); // PUSHBYTES_40
    script_bytes.extend(vec![0xAA; 40]);

    let outputs = vec![
        TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from(script_bytes),
        },
    ];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
}

/// Test 8: Oversized OP_RETURN → Corpse
#[test]
fn test_oversized_op_return() {
    // OP_RETURN with 200 bytes (over 83 limit)
    let mut script_bytes = vec![0x6a]; // OP_RETURN
    script_bytes.push(0x4c); // OP_PUSHDATA1
    script_bytes.push(200); // length
    script_bytes.extend(vec![0xBB; 200]);

    let outputs = vec![
        TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        },
        TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from(script_bytes),
        },
    ];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::OversizedOpReturn
    );
}

/// Test 9: Witness annex → Corpse
#[test]
fn test_witness_annex() {
    let mut witness = Witness::new();
    // Signature
    witness.push([0x30; 64]);
    // Tapscript (just OP_CHECKSIG)
    witness.push([0xac]);
    // Control block
    let mut cb = vec![0xc0];
    cb.extend([0x11; 32]);
    witness.push(&cb);
    // Annex: starts with 0x50
    let mut annex = vec![0x50];
    annex.extend(vec![0xDD; 99]);
    witness.push(&annex);

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    };
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let annex_regions: Vec<_> = verdict
        .dead_regions
        .iter()
        .filter(|r| r.dead_code_type == DeadCodeType::AnnexPresent)
        .collect();
    assert!(!annex_regions.is_empty());
}

/// Test 10: Encrypted inscription in envelope → Corpse
#[test]
fn test_encrypted_inscription() {
    // Same envelope structure but with encrypted/binary content
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00); // OP_FALSE
    script.push(0x63); // OP_IF
    script.push(0x03); // PUSH3
    script.extend(b"ord");
    // Content type
    script.push(0x51); // OP_1
    let ct = b"application/octet-stream";
    script.push(ct.len() as u8);
    script.extend(ct);
    // Content: encrypted binary data
    script.push(0x00); // OP_0 (content marker)
    script.push(0x4c); // OP_PUSHDATA1
    script.push(128); // 128 bytes of encrypted data
    script.extend(vec![0xEE; 128]);
    script.push(0x68); // OP_ENDIF
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::InscriptionEnvelope
    );
}

/// Test 11: Legitimate conditional + dead envelope → Corpse
#[test]
fn test_legitimate_plus_dead_envelope() {
    // Script has a legitimate OP_IF branch followed by an inscription envelope
    let mut script: Vec<u8> = Vec::new();
    // Legitimate branch: OP_DUP OP_HASH160 PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14);
    script.extend([0xAA; 20]);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
                       // Dead envelope after legitimate code
    script.push(0x00); // OP_FALSE
    script.push(0x63); // OP_IF
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68); // OP_ENDIF

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
}

/// Test 12: OP_PUSH(0x00) circumvention → Corpse
#[test]
fn test_push_0x00_circumvention() {
    // Instead of OP_0, attacker uses OP_PUSHBYTES_1 0x00 (which is also falsy)
    let mut script: Vec<u8> = vec![
        0x01, // OP_PUSHBYTES_1
        0x00, // push value [0x00] — falsy
        0x63, // OP_IF
        0x03,
    ];
    script.extend(b"ord");
    script.push(0x68); // OP_ENDIF
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::InscriptionEnvelope
    );
}

// ─── Edge Cases ─────────────────────────────────────────────────────────────

/// Empty witness → Accept
#[test]
fn test_empty_witness() {
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    };
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert_eq!(verdict.input_analyses[0].spend_type, "Empty");
}

/// Coinbase skip
#[test]
fn test_coinbase_skip() {
    let tx = coinbase_tx();
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
}

/// Nested IF depth tracking
#[test]
fn test_nested_if_depth() {
    // OP_FALSE OP_IF OP_IF OP_IF OP_ENDIF OP_ENDIF OP_ENDIF OP_CHECKSIG
    let script = vec![0x00, 0x63, 0x63, 0x63, 0x68, 0x68, 0x68, 0xac];
    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    // Envelope should span from OP_FALSE to last OP_ENDIF (7 bytes)
    assert_eq!(verdict.dead_regions[0].size, 7);
}

/// Negative zero (0x80) circumvention
#[test]
fn test_negative_zero_circumvention() {
    // OP_PUSHBYTES_1 0x80 OP_IF ... — [0x80] is negative zero (falsy)
    let mut script: Vec<u8> = vec![
        0x01, // OP_PUSHBYTES_1
        0x80, // negative zero
        0x63, // OP_IF
        0x03,
    ];
    script.extend(b"ord");
    script.push(0x68); // OP_ENDIF
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
}

/// Disabled config → Accept everything
#[test]
fn test_disabled_config() {
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::disabled();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    assert!(verdict.dead_regions.is_empty());
}

/// P2WSH witness script detection
#[test]
fn test_p2wsh_dead_code() {
    // P2WSH with inscription envelope in witness script
    let mut ws: Vec<u8> = Vec::new();
    ws.push(0x00); // OP_FALSE
    ws.push(0x63); // OP_IF
    ws.push(0x03);
    ws.extend(b"ord");
    ws.push(0x68); // OP_ENDIF
    ws.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 72]; // DER signature
    let tx = tx_with_witness_script(&ws, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(verdict.input_analyses[0].spend_type, "P2WSH");
}

/// OP_2DROP data stuffing
#[test]
fn test_2drop_stuffing() {
    let mut script: Vec<u8> = Vec::new();
    // Push 100 bytes
    script.push(0x4c); // OP_PUSHDATA1
    script.push(100);
    script.extend(vec![0xDE; 100]);
    // OP_2DROP
    script.push(0x6d);
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(
        verdict.dead_regions[0].dead_code_type,
        DeadCodeType::DropStuffing
    );
}

/// Config toggle: reject_inscription_envelope = false
/// Pattern toggle suppresses the pattern label, but flow analysis still detects
/// the dead branch semantically — dead code is dead code.
#[test]
fn test_toggle_inscription_off() {
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig {
        reject_inscription_envelope: false,
        ..Default::default()
    };
    let verdict = analyze(&tx, &config);

    // Pattern toggle off → no pattern-detected InscriptionEnvelope
    // But flow analysis still finds the dead FALSE IF branch → Corpse
    assert!(verdict.is_corpse());
    assert!(!verdict.dead_regions.is_empty());
}

/// Config toggle: reject_drop_stuffing = false
/// Pattern toggle suppresses the pattern label, but flow analysis still detects
/// the dead push-drop pair semantically.
#[test]
fn test_toggle_drop_off() {
    let mut script: Vec<u8> = Vec::new();
    script.push(0x4c);
    script.push(100);
    script.extend(vec![0xDE; 100]);
    script.push(0x75); // OP_DROP
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig {
        reject_drop_stuffing: false,
        ..Default::default()
    };
    let verdict = analyze(&tx, &config);

    // Pattern toggle off → no pattern-detected DropStuffing
    // But flow analysis still finds the dead push-drop → Corpse
    assert!(verdict.is_corpse());
    assert!(!verdict.dead_regions.is_empty());
}

/// Verdict helper methods
#[test]
fn test_verdict_helpers() {
    let accept = ReaperVerdict::accept();
    assert!(accept.is_accepted());
    assert!(!accept.is_corpse());
}

/// Config serialization round-trip
#[test]
fn test_config_serde() {
    let config = ReaperConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let deserialized: ReaperConfig = serde_json::from_str(&json).unwrap();
    assert!(deserialized.enabled);
}

/// ReaperVerdict serialization
#[test]
fn test_verdict_serde() {
    let verdict = ReaperVerdict::accept();
    let json = serde_json::to_string(&verdict).unwrap();
    assert!(json.contains("\"Accept\""));
}

/// SpendType display
#[test]
fn test_spend_type_display() {
    let keypath = SpendType::P2trKeyPath;
    assert_eq!(keypath.to_string(), "P2TR-keypath");

    let script_path = SpendType::P2trScriptPath {
        tapscript: vec![],
        control_block: vec![],
    };
    assert_eq!(script_path.to_string(), "P2TR-scriptpath");

    let wsh = SpendType::P2wsh {
        witness_script: vec![],
    };
    assert_eq!(wsh.to_string(), "P2WSH");
}

/// Multiple dead code regions in single transaction
#[test]
fn test_multiple_dead_regions() {
    // Script with both inscription envelope AND drop stuffing
    let mut script: Vec<u8> = Vec::new();
    // Drop stuffing first
    script.push(0x4c);
    script.push(80);
    script.extend(vec![0xAA; 80]);
    script.push(0x75); // OP_DROP
                       // Then inscription envelope
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    // Both pattern and flow analysis detect these regions (may overlap)
    assert!(verdict
        .dead_regions
        .iter()
        .any(|r| r.dead_code_type == DeadCodeType::DropStuffing));
    assert!(verdict
        .dead_regions
        .iter()
        .any(|r| r.dead_code_type == DeadCodeType::InscriptionEnvelope));
}

/// OP_NOTIF increases envelope depth
#[test]
fn test_notif_in_envelope() {
    // OP_FALSE OP_IF OP_NOTIF OP_ENDIF OP_ENDIF OP_CHECKSIG
    let script = vec![0x00, 0x63, 0x64, 0x68, 0x68, 0xac];
    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    assert_eq!(verdict.dead_regions[0].size, 5); // OP_FALSE through second OP_ENDIF
}

use crate::verdict::ReaperVerdict;

// ─── Computational Validity Tests ───────────────────────────────────────────

/// Witness breakdown on a standard inscription shows essential_script << original
#[test]
fn test_witness_breakdown_inscription() {
    let mut script: Vec<u8> = Vec::new();
    // OP_FALSE OP_IF envelope
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x51); // OP_1
    let ct = b"text/plain;charset=utf-8";
    script.push(ct.len() as u8);
    script.extend(ct);
    script.push(0x00);
    let content = b"Hello World Hello World Hello World Hello World";
    script.push(content.len() as u8);
    script.extend(content);
    script.push(0x68); // OP_ENDIF
                       // OP_CHECKSIG
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();
    // Essential script should be just OP_CHECKSIG (1 byte)
    assert_eq!(bd.essential_script_bytes, 1);
    assert!(bd.essential_script_bytes < bd.original_script_bytes);
    assert!(bd.dead_bytes > 0);
}

/// Witness breakdown with drop stuffing accumulates dead bytes
#[test]
fn test_witness_breakdown_drop_stuffing() {
    let mut script: Vec<u8> = Vec::new();
    // Push 100 bytes + DROP
    script.push(0x4c); // OP_PUSHDATA1
    script.push(100);
    script.extend(vec![0xDE; 100]);
    script.push(0x75); // OP_DROP
                       // Push another 100 bytes + DROP
    script.push(0x4c);
    script.push(100);
    script.extend(vec![0xBE; 100]);
    script.push(0x75); // OP_DROP
                       // Legitimate
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();
    // Essential script should be just OP_CHECKSIG (1 byte)
    assert_eq!(bd.essential_script_bytes, 1);
    // Original has ~206 bytes of script
    assert!(bd.original_script_bytes > 200);
}

/// Excess stack items are detected when script needs fewer items than provided
#[test]
fn test_excess_stack_items() {
    // Script: <pk> OP_CHECKSIG (needs exactly 1 sig from the stack)
    let mut script = vec![0x21]; // OP_PUSHBYTES_33
    script.extend([0x02; 33]); // compressed pubkey
    script.push(0xac); // OP_CHECKSIG
                       // Provide 3 witness items (only 1 needed): excess at bottom, sig on top
    let item1 = [0xAA; 600]; // excess item 1
    let item2 = [0xBB; 600]; // excess item 2
    let item3 = [0x30; 64]; // "signature" (on top where CHECKSIG consumes it)
    let tx = tx_with_tapscript(&script, &[&item1, &item2, &item3]);

    let config = ReaperConfig {
        min_excess_witness_bytes: 100, // lower threshold for test
        ..Default::default()
    };
    let verdict = analyze(&tx, &config);

    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();
    assert_eq!(bd.essential_stack_items, 1);
    assert_eq!(bd.actual_stack_items, 3);
    assert_eq!(bd.excess_stack_items, 2);
    assert!(bd.excess_stack_bytes > 0);
}

/// Legitimate HTLC with both branches doesn't false-positive on stack count
#[test]
fn test_legitimate_htlc_no_excess() {
    // HTLC: OP_IF OP_SHA256 OP_EQUALVERIFY OP_CHECKSIG OP_ELSE OP_CHECKSIG OP_ENDIF
    let mut script: Vec<u8> = Vec::new();
    script.push(0x63); // OP_IF
    script.push(0xa8); // OP_SHA256
    script.push(0x20); // PUSH32
    script.extend([0xCC; 32]); // hash
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script.push(0x67); // OP_ELSE
    script.push(0xac); // OP_CHECKSIG
    script.push(0x68); // OP_ENDIF

    // Provide: sig + preimage (for the hash-lock branch)
    let sig = [0x30; 64];
    let preimage = [0xDD; 32];
    let tx = tx_with_tapscript(&script, &[&sig, &preimage]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    // Should accept — the conservative count covers both branches
    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();
    // Conservative: 2 checksigs + 1 preimage = 3 items needed from stack
    // We provided 2 items, which is <= 3, so no excess
    assert_eq!(bd.excess_stack_items, 0);
    assert!(verdict.is_accepted());
}

// ─── EC Point Validation Tests ──────────────────────────────────────────────

/// Valid prefix (0x02) but not on secp256k1 curve → FakePubkeyCurvePoint
#[test]
fn test_ec_point_valid_prefix_invalid_point() {
    // 1-of-1 multisig with fake pubkey: 0x02 + all 0xFF (not on curve)
    let mut script = vec![0x51]; // OP_1
    script.push(0x21);
    script.push(0x02);
    script.extend(vec![0xFF; 32]); // Not a valid x-coordinate on secp256k1
    script.push(0x51); // OP_1
    script.push(0xae); // OP_CHECKMULTISIG

    let outputs = vec![TxOut {
        value: Amount::from_sat(50000),
        script_pubkey: ScriptBuf::from(script),
    }];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let fake_curve_regions: Vec<_> = verdict
        .dead_regions
        .iter()
        .filter(|r| r.dead_code_type == DeadCodeType::FakePubkeyCurvePoint)
        .collect();
    assert_eq!(fake_curve_regions.len(), 1);
}

/// Real secp256k1 pubkey (Bitcoin genesis coinbase key) → no flagging
#[test]
fn test_ec_point_real_pubkey() {
    // Use the well-known Bitcoin genesis block pubkey (compressed form)
    // This is 0x02 + a valid x-coordinate
    let real_pubkey =
        hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();

    let mut script = vec![0x51]; // OP_1
    script.push(0x21);
    script.extend(&real_pubkey);
    script.push(0x51); // OP_1
    script.push(0xae); // OP_CHECKMULTISIG

    let outputs = vec![TxOut {
        value: Amount::from_sat(50000),
        script_pubkey: ScriptBuf::from(script),
    }];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    // Real pubkey should pass
    assert!(verdict.is_accepted());
}

// ─── Legacy ScriptSig Tests ────────────────────────────────────────────────

/// Legacy input with large non-sig push → LegacyScriptSigData
#[test]
fn test_legacy_scriptsig_data() {
    // Build a legacy transaction with a data-stuffed scriptSig
    let mut script_sig_bytes = Vec::new();
    // 200-byte data push (not a sig or pubkey)
    script_sig_bytes.push(0x4c); // OP_PUSHDATA1
    script_sig_bytes.push(200);
    script_sig_bytes.extend(vec![0xDD; 200]);
    // Legitimate DER signature (72 bytes)
    let mut sig = vec![0x30];
    sig.extend(vec![0x44; 71]);
    script_sig_bytes.push(sig.len() as u8);
    script_sig_bytes.extend(&sig);

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::from(script_sig_bytes),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    };
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let legacy_regions: Vec<_> = verdict
        .dead_regions
        .iter()
        .filter(|r| r.dead_code_type == DeadCodeType::LegacyScriptSigData)
        .collect();
    assert_eq!(legacy_regions.len(), 1);
}

/// P2SH redeemScript containing OP_FALSE OP_IF → inscription detected inside legacy
#[test]
fn test_p2sh_redeemscript_envelope() {
    // Build a scriptSig: <sig> <redeemScript_with_envelope>
    let mut script_sig_bytes = Vec::new();

    // Signature (72 bytes)
    let mut sig = vec![0x30];
    sig.extend(vec![0x44; 71]);
    script_sig_bytes.push(sig.len() as u8);
    script_sig_bytes.extend(&sig);

    // RedeemScript: OP_FALSE OP_IF "ord" OP_ENDIF OP_CHECKSIG
    let mut redeem = Vec::new();
    redeem.push(0x00); // OP_FALSE
    redeem.push(0x63); // OP_IF
    redeem.push(0x03);
    redeem.extend(b"ord");
    redeem.push(0x68); // OP_ENDIF
    redeem.push(0xac); // OP_CHECKSIG

    // Push the redeemScript
    script_sig_bytes.push(0x4c); // OP_PUSHDATA1
    script_sig_bytes.push(redeem.len() as u8);
    script_sig_bytes.extend(&redeem);

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::from(script_sig_bytes),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2wpkh_script(),
        }],
    };
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_corpse());
    let envelope_regions: Vec<_> = verdict
        .dead_regions
        .iter()
        .filter(|r| r.dead_code_type == DeadCodeType::InscriptionEnvelope)
        .collect();
    assert_eq!(envelope_regions.len(), 1);
}

/// strip_to_essential produces correct output
#[test]
fn test_strip_to_essential_correctness() {
    use crate::essential::strip_to_essential;
    use crate::verdict::{AnalysisLocation, DeadCodeRegion, DeadCodeType};

    // Script: [OP_FALSE, OP_IF, PUSH3, 'o', 'r', 'd', OP_ENDIF, OP_CHECKSIG]
    let script = vec![0x00, 0x63, 0x03, b'o', b'r', b'd', 0x68, 0xac];
    let region = DeadCodeRegion {
        location: AnalysisLocation::Input(0),
        dead_code_type: DeadCodeType::InscriptionEnvelope,
        offset: 0,
        size: 7,
        description: String::new(),
    };
    let (essential, removed) = strip_to_essential(&script, &[region]);
    assert_eq!(essential, vec![0xac]);
    assert_eq!(removed, 7);

    // Multiple regions
    let mut script2 = Vec::new();
    // Region 1: bytes 0-3 (4 bytes)
    script2.extend([0xDE, 0xAD, 0xBE, 0xEF]);
    // Legitimate: byte 4
    script2.push(0xac);
    // Region 2: bytes 5-7 (3 bytes)
    script2.extend([0xCA, 0xFE, 0xBA]);

    let r1 = DeadCodeRegion {
        location: AnalysisLocation::Input(0),
        dead_code_type: DeadCodeType::DropStuffing,
        offset: 0,
        size: 4,
        description: String::new(),
    };
    let r2 = DeadCodeRegion {
        location: AnalysisLocation::Input(0),
        dead_code_type: DeadCodeType::UnreachableCode,
        offset: 5,
        size: 3,
        description: String::new(),
    };
    let (essential2, removed2) = strip_to_essential(&script2, &[r1, r2]);
    assert_eq!(essential2, vec![0xac]);
    assert_eq!(removed2, 7);
}

/// Total essential/excess bytes are populated in verdict
#[test]
fn test_verdict_essential_excess_totals() {
    let mut script: Vec<u8> = Vec::new();
    script.push(0x00); // OP_FALSE
    script.push(0x63); // OP_IF
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68); // OP_ENDIF
    script.push(0xac); // OP_CHECKSIG

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    // Should have computed totals
    assert!(verdict.total_essential_bytes > 0);
}
