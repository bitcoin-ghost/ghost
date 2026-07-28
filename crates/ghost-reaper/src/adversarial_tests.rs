/// Adversarial tests for the COMPUTATIONAL VALIDITY ENGINE specifically.
///
/// The existing pattern-based filters (inscription envelopes, DROP stuffing, etc.)
/// are already well-tested. These tests target the NEW features:
///
/// 1. `compute_witness_breakdown()` — measures essential vs dead witness bytes
/// 2. `count_stack_consumption()` — counts how many stack items a script needs
/// 3. `strip_to_essential()` — removes dead regions from script
/// 4. `ExcessWitnessData` — witness significantly exceeds essential minimum
/// 5. `ExcessStackItems` — more witness items than script consumes
/// 6. `FakePubkeyCurvePoint` — EC curve point validation
/// 7. `analyze_legacy_scriptsig()` — legacy scriptSig data stuffing
///
/// Test categories:
/// A) Novel stuffing that pattern-matching MISSES but computational check CATCHES
/// B) Witness breakdown accuracy — are the numbers correct?
/// C) Legitimate financial txs — computational check must NOT flag these
use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

use crate::analyze;
use crate::config::ReaperConfig;
use crate::essential::{count_stack_consumption, strip_to_essential};
use crate::verdict::{AnalysisLocation, DeadCodeRegion, DeadCodeType};

// ─── Helpers ────────────────────────────────────────────────────────────────

fn non_coinbase_outpoint() -> OutPoint {
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[1u8]));
    OutPoint { txid, vout: 0 }
}

fn p2wpkh_script() -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend([0xAA; 20]);
    ScriptBuf::from(bytes)
}

fn p2tr_script() -> ScriptBuf {
    let mut bytes = vec![0x51, 0x20];
    bytes.extend([0xBB; 32]);
    ScriptBuf::from(bytes)
}

fn tx_with_tapscript(tapscript: &[u8], extra_witness: &[&[u8]]) -> Transaction {
    let mut witness = Witness::new();
    for item in extra_witness {
        witness.push(item);
    }
    witness.push(tapscript);
    let mut control_block = vec![0xc0];
    control_block.extend([0x11; 32]);
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

// ═══════════════════════════════════════════════════════════════════════════
// A) NOVEL STUFFING — bypasses pattern matching, caught by computational check
// ═══════════════════════════════════════════════════════════════════════════

/// Novel attack: stuff 1KB of extra witness stack items beyond what the script needs.
/// The script only needs 1 sig, but attacker provides 1 sig + 2 large junk items.
/// Pattern filters see no envelope, no DROP — but computational check sees excess.
#[test]
fn test_novel_excess_stack_items_bypass() {
    // Tapscript: <pk> OP_CHECKSIG (needs exactly 1 stack item — the sig)
    let mut script = vec![0x21]; // OP_PUSHBYTES_33
    script.extend([0x02; 33]); // compressed pubkey
    script.push(0xac); // OP_CHECKSIG

    // Provide 2 junk items (600 bytes each) + 1 sig
    // Sig must be on top of stack (last) since CHECKSIG pops from top
    let junk1 = [0xAA; 600];
    let junk2 = [0xBB; 600];
    let sig = [0x30; 64];

    let tx = tx_with_tapscript(&script, &[&junk1, &junk2, &sig]);

    let config = ReaperConfig {
        min_excess_witness_bytes: 100, // lower threshold
        ..Default::default()
    };
    let verdict = analyze(&tx, &config);

    // The pattern filters find nothing (no envelope, no DROP, no OP_RETURN)
    // But the computational check should flag ExcessWitnessData and/or ExcessStackItems
    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();

    assert_eq!(bd.essential_stack_items, 1, "Script needs 1 sig");
    assert_eq!(bd.actual_stack_items, 3, "We provided 3 items");
    assert_eq!(bd.excess_stack_items, 2, "2 excess items");
    assert!(
        bd.excess_stack_bytes >= 1200,
        "Excess should be >= 1200 bytes, got {}",
        bd.excess_stack_bytes
    );
    assert!(
        bd.dead_bytes > 1000,
        "Dead bytes should be > 1000, got {}",
        bd.dead_bytes
    );

    // Should be flagged
    assert!(
        verdict
            .dead_regions
            .iter()
            .any(|r| r.dead_code_type == DeadCodeType::ExcessWitnessData
                || r.dead_code_type == DeadCodeType::ExcessStackItems),
        "Should detect ExcessWitnessData or ExcessStackItems, got: {:?}",
        verdict
            .dead_regions
            .iter()
            .map(|r| &r.dead_code_type)
            .collect::<Vec<_>>()
    );
}

/// Novel attack: P2WSH with extra stack items beyond what CHECKMULTISIG needs.
/// 2-of-2 multisig needs 3 items (dummy + 2 sigs), attacker provides 3 + 2 extra.
/// Excess items are placed at the bottom of the stack (pushed first in witness).
#[test]
fn test_novel_excess_stack_p2wsh_multisig() {
    // P2WSH script: OP_2 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
    let mut ws = vec![0x52]; // OP_2
    for i in 0..2u8 {
        ws.push(0x21);
        ws.push(0x02);
        ws.extend(vec![0x10 + i; 32]);
    }
    ws.push(0x52); // OP_2
    ws.push(0xae); // OP_CHECKMULTISIG

    // Excess items at bottom of stack, real sigs on top where CHECKMULTISIG consumes them
    let junk1 = [0xDE; 600];
    let junk2 = [0xAD; 600];
    let dummy: [u8; 0] = [];
    let sig1 = [0x30; 72];
    let sig2 = [0x30; 71];

    let tx = tx_with_witness_script(&ws, &[&junk1, &junk2, &dummy, &sig1, &sig2]);

    let config = ReaperConfig {
        min_excess_witness_bytes: 100,
        ..Default::default()
    };
    let verdict = analyze(&tx, &config);

    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();

    assert_eq!(
        bd.essential_stack_items, 3,
        "2-of-2 multisig needs 3 items (2 sigs + dummy)"
    );
    assert_eq!(bd.actual_stack_items, 5, "We provided 5 items");
    assert_eq!(bd.excess_stack_items, 2, "2 excess items");
    assert!(bd.excess_stack_bytes >= 1200);
}

/// Novel attack: inscription caught by patterns, but computational check provides
/// the ADDITIONAL quantification showing exactly how much is dead vs essential.
#[test]
fn test_computational_quantifies_inscription() {
    let raw_hex = "02000000000101c392e5ce84d4cb97bcad5b636f24c7e066a16704129ae35a19a2c3cd7bedc89f0000000000fdffffff011c25000000000000225120b016165b277874f8403d554c24f9fda288acae2624172a053bcf00853fe4e2630340fd03eed68e052a2a1c824eff6f33e36ea3cc83ffd74f0648224fb6bc8dfcdf2a6096b09a9fc6ec3a226856c5a588744a020097c54d5a7bc59ed65961167b2289d9204646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fffac0063036f72645118746578742f706c61696e3b636861727365743d7574662d38004c9347686f73742052656170657220696e736372697074696f6e20746573743a2074686973206465616420636f64652073686f756c6420626520646574656374656420616e64207265617065642066726f6d20626c6f636b2074656d706c617465732e20546865204f505f46414c5345204f505f494620656e76656c6f706520776173746573207769746e6573732073706163652e6821c04646ae5047316b4230d0086c8acec687f00b1cd9d1dc634f6cb358ac0a9a8fff00000000";
    let raw = hex::decode(raw_hex).unwrap();
    let tx: Transaction = deserialize(&raw).unwrap();
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let analysis = &verdict.input_analyses[0];
    assert_eq!(analysis.spend_type, "P2TR-scriptpath");
    let bd = analysis.witness_breakdown.as_ref().unwrap();

    // The real tapscript is: PUSH32 <pubkey> OP_CHECKSIG <envelope>
    // After stripping the envelope, essential = PUSH32 <pubkey> OP_CHECKSIG = 34 bytes
    assert_eq!(
        bd.essential_script_bytes, 34,
        "Essential script is PUSH32 <pubkey> OP_CHECKSIG (34 bytes)"
    );
    assert!(
        bd.original_script_bytes > 100,
        "Original script has envelope + checksig"
    );
    assert!(
        bd.control_block_bytes > 0,
        "Control block is always essential"
    );
    assert!(
        bd.dead_bytes > bd.essential_bytes,
        "Dead should exceed essential: {} dead vs {} essential",
        bd.dead_bytes,
        bd.essential_bytes
    );

    // Verify the verdict totals include computational data
    assert!(verdict.total_essential_bytes > 0);
    assert!(verdict.total_excess_bytes > 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// B) WITNESS BREAKDOWN ACCURACY — verify the numbers are correct
// ═══════════════════════════════════════════════════════════════════════════

/// Verify strip_to_essential correctly removes dead regions and preserves live code
#[test]
fn test_strip_essential_multi_region() {
    // Script: [JUNK(10 bytes)] [OP_CHECKSIG] [JUNK(5 bytes)] [OP_CHECKSIGVERIFY]
    let mut script = Vec::new();
    script.extend(vec![0xDE; 10]); // junk @ offset 0, size 10
    script.push(0xac); // OP_CHECKSIG @ offset 10
    script.extend(vec![0xAD; 5]); // junk @ offset 11, size 5
    script.push(0xad); // OP_CHECKSIGVERIFY @ offset 16

    let r1 = DeadCodeRegion {
        location: AnalysisLocation::Input(0),
        dead_code_type: DeadCodeType::DropStuffing,
        offset: 0,
        size: 10,
        description: String::new(),
    };
    let r2 = DeadCodeRegion {
        location: AnalysisLocation::Input(0),
        dead_code_type: DeadCodeType::DropStuffing,
        offset: 11,
        size: 5,
        description: String::new(),
    };

    let (essential, removed) = strip_to_essential(&script, &[r1, r2]);
    assert_eq!(removed, 15);
    assert_eq!(
        essential,
        vec![0xac, 0xad],
        "Only CHECKSIG + CHECKSIGVERIFY should remain"
    );
}

/// Verify count_stack_consumption for various opcode patterns
#[test]
fn test_stack_consumption_comprehensive() {
    // 1) Pure OP_CHECKSIG = 1
    assert_eq!(count_stack_consumption(&[0xac], true), 1);

    // 2) Two CHECKSIG = 2
    assert_eq!(count_stack_consumption(&[0xac, 0xac], true), 2);

    // 3) CHECKSIGVERIFY = 1
    assert_eq!(count_stack_consumption(&[0xad], true), 1);

    // 4) CHECKSIGADD (tapscript) = 1 per opcode
    assert_eq!(count_stack_consumption(&[0xba, 0xba], true), 2);

    // 5) CHECKSIGADD not counted in non-tapscript
    assert_eq!(count_stack_consumption(&[0xba, 0xba], false), 0);

    // 6) Hash lock: OP_SHA256 OP_EQUAL = 1 preimage
    assert_eq!(count_stack_consumption(&[0xa8, 0x87], false), 1);

    // 7) OP_HASH160 OP_EQUALVERIFY = 1 preimage
    assert_eq!(count_stack_consumption(&[0xa9, 0x88], false), 1);

    // 8) Hash followed by non-EQUAL → 0 (not a hash lock pattern)
    assert_eq!(count_stack_consumption(&[0xa8, 0xac], false), 1); // just the CHECKSIG

    // 9) Empty script = 0
    assert_eq!(count_stack_consumption(&[], true), 0);

    // 10) Just push data, no consumption opcodes = 0
    assert_eq!(
        count_stack_consumption(
            &[
                0x20, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA
            ],
            true
        ),
        0
    );
}

/// Verify breakdown for a minimal P2TR script-path (OP_CHECKSIG only)
#[test]
fn test_breakdown_minimal_tapscript() {
    let script = vec![0xac]; // OP_CHECKSIG
    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();

    assert_eq!(bd.essential_script_bytes, 1, "OP_CHECKSIG = 1 byte");
    assert_eq!(bd.original_script_bytes, 1, "No dead code");
    assert_eq!(bd.essential_stack_items, 1, "Needs 1 sig");
    assert_eq!(bd.actual_stack_items, 1, "Provided 1 sig");
    assert_eq!(bd.excess_stack_items, 0, "No excess");
    assert_eq!(bd.excess_stack_bytes, 0, "No excess bytes");
    assert!(bd.control_block_bytes > 0, "Has control block");

    // Essential = script(1) + control_block(33) + sig(64) = 98
    assert_eq!(bd.essential_bytes, 1 + 33 + 64, "98 essential bytes");

    // Dead = total_witness - essential
    // total_witness = sig(64) + script(1) + control_block(33) = 98
    assert_eq!(bd.dead_bytes, 0, "No dead bytes in minimal tx");
}

/// Verify breakdown for P2WSH with hash lock
#[test]
fn test_breakdown_p2wsh_hashlock() {
    // OP_SHA256 PUSH32 <hash> OP_EQUAL
    let mut ws = Vec::new();
    ws.push(0xa8); // OP_SHA256
    ws.push(0x20);
    ws.extend([0xCC; 32]);
    ws.push(0x87); // OP_EQUAL

    let preimage = [0xDD; 32];
    let tx = tx_with_witness_script(&ws, &[&preimage]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();

    assert_eq!(bd.essential_stack_items, 1, "Hash lock needs 1 preimage");
    assert_eq!(bd.actual_stack_items, 1, "Provided 1 preimage");
    assert_eq!(bd.excess_stack_items, 0);
    assert_eq!(bd.control_block_bytes, 0, "P2WSH has no control block");
    assert_eq!(bd.dead_bytes, 0, "No dead bytes");
}

/// Verify breakdown with multiple dead regions (envelope + DROP)
#[test]
fn test_breakdown_multiple_dead_regions() {
    let mut script: Vec<u8> = Vec::new();
    // DROP stuffing
    script.push(0x4c);
    script.push(80);
    script.extend(vec![0xAA; 80]);
    script.push(0x75); // OP_DROP
                       // Inscription envelope
    script.push(0x00);
    script.push(0x63);
    script.push(0x03);
    script.extend(b"ord");
    script.push(0x68);
    // OP_CHECKSIG
    script.push(0xac);

    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let analysis = &verdict.input_analyses[0];
    let bd = analysis.witness_breakdown.as_ref().unwrap();

    // After stripping: only OP_CHECKSIG remains
    assert_eq!(bd.essential_script_bytes, 1);
    // Original script is much larger
    assert!(bd.original_script_bytes > 90);
    // Dead bytes should account for the stripped script + overhead
    assert!(bd.dead_bytes > 0);
}

/// Verify that `None` is returned for key-path spends
#[test]
fn test_breakdown_none_for_keypath() {
    let mut witness = Witness::new();
    witness.push([0x30; 64]);

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
            script_pubkey: p2tr_script(),
        }],
    };
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(
        verdict.input_analyses[0].witness_breakdown.is_none(),
        "Key-path should have no breakdown"
    );
}

/// Verify that `None` is returned for P2WPKH
#[test]
fn test_breakdown_none_for_p2wpkh() {
    let mut witness = Witness::new();
    let mut sig = vec![0x30, 0x44];
    sig.extend(vec![0x02; 70]);
    witness.push(&sig);
    let mut pk = vec![0x02];
    pk.extend([0xAA; 32]);
    witness.push(&pk);

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

    assert!(
        verdict.input_analyses[0].witness_breakdown.is_none(),
        "P2WPKH should have no breakdown"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// C) LEGITIMATE TRANSACTIONS — computational check must NOT flag these
// ═══════════════════════════════════════════════════════════════════════════

/// P2TR tapscript CHECKSIG: 1 sig provided for 1 CHECKSIG = no excess
#[test]
fn test_legit_tapscript_exact_witness() {
    let script = vec![0xac]; // OP_CHECKSIG
    let sig = [0x30; 64];
    let tx = tx_with_tapscript(&script, &[&sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(verdict.is_accepted());
    let bd = verdict.input_analyses[0]
        .witness_breakdown
        .as_ref()
        .unwrap();
    assert_eq!(bd.excess_stack_items, 0);
    assert_eq!(bd.dead_bytes, 0);
    assert!(
        !verdict
            .dead_regions
            .iter()
            .any(|r| r.dead_code_type == DeadCodeType::ExcessWitnessData
                || r.dead_code_type == DeadCodeType::ExcessStackItems),
        "No excess regions for exact witness"
    );
}

/// HTLC with both branches — conservative count covers both, no false positive
#[test]
fn test_legit_htlc_conservative_count() {
    // IF: OP_SHA256 PUSH32 <hash> OP_EQUALVERIFY OP_CHECKSIG
    // ELSE: <timeout> OP_CLTV OP_DROP OP_CHECKSIG
    // ENDIF
    let mut script: Vec<u8> = Vec::new();
    script.push(0x63); // OP_IF
    script.push(0xa8); // OP_SHA256
    script.push(0x20);
    script.extend([0xCC; 32]);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script.push(0x67); // OP_ELSE
    script.push(0x04);
    script.extend(100000u32.to_le_bytes());
    script.push(0xb1);
    script.push(0x75);
    script.push(0xac);
    script.push(0x68); // OP_ENDIF

    // Taking the hash-lock branch: provide sig + preimage
    let sig = [0x30; 64];
    let preimage = [0xDD; 32];
    let tx = tx_with_tapscript(&script, &[&sig, &preimage]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let bd = verdict.input_analyses[0]
        .witness_breakdown
        .as_ref()
        .unwrap();
    // Conservative: counts BOTH branches → 2 CHECKSIG + 1 preimage = 3 from stack
    // We provided 2 items (sig + preimage), which is < 3, so no excess
    assert_eq!(bd.excess_stack_items, 0, "No excess for HTLC");
    assert!(verdict.is_accepted(), "HTLC should Accept");
}

/// Tapscript CHECKSIGADD 2-of-3: needs 3 sigs (one empty), provided exactly 3
#[test]
fn test_legit_checksigadd_exact() {
    // pk1 CHECKSIG pk2 CHECKSIGADD pk3 CHECKSIGADD OP_2 OP_NUMEQUAL
    let mut script = Vec::new();
    script.push(0x20);
    script.extend([0xAA; 32]);
    script.push(0xac); // CHECKSIG
    script.push(0x20);
    script.extend([0xBB; 32]);
    script.push(0xba); // CHECKSIGADD
    script.push(0x20);
    script.extend([0xCC; 32]);
    script.push(0xba); // CHECKSIGADD
    script.push(0x52); // OP_2
    script.push(0x9c); // OP_NUMEQUAL

    let sig1 = [0x30; 64];
    let sig2 = [0x30; 64];
    let empty: [u8; 0] = [];
    let tx = tx_with_tapscript(&script, &[&empty, &sig2, &sig1]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let bd = verdict.input_analyses[0]
        .witness_breakdown
        .as_ref()
        .unwrap();
    assert_eq!(
        bd.essential_stack_items, 3,
        "3 CHECKSIG/ADD = 3 sigs needed"
    );
    assert_eq!(bd.actual_stack_items, 3, "Provided exactly 3");
    assert_eq!(bd.excess_stack_items, 0);
    assert!(verdict.is_accepted(), "Exact CHECKSIGADD should Accept");
}

/// 2-of-3 P2WSH multisig: needs 3 items (dummy + 2 sigs), provided exactly 3
#[test]
fn test_legit_2of3_multisig_exact() {
    let mut ws = vec![0x52]; // OP_2
    for i in 0..3u8 {
        ws.push(0x21);
        ws.push(0x02);
        ws.extend(vec![0x10 + i; 32]);
    }
    ws.push(0x53); // OP_3
    ws.push(0xae); // OP_CHECKMULTISIG

    let dummy: [u8; 0] = [];
    let sig1 = [0x30; 72];
    let sig2 = [0x30; 71];
    let tx = tx_with_witness_script(&ws, &[&dummy, &sig1, &sig2]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let bd = verdict.input_analyses[0]
        .witness_breakdown
        .as_ref()
        .unwrap();
    // 2-of-3 CHECKMULTISIG needs m+1 = 3 items
    assert_eq!(bd.essential_stack_items, 3);
    assert_eq!(bd.actual_stack_items, 3);
    assert_eq!(bd.excess_stack_items, 0);
    assert!(verdict.is_accepted(), "Exact 2-of-3 multisig should Accept");
}

/// P2WSH hash lock with exact preimage
#[test]
fn test_legit_p2wsh_hashlock_exact() {
    let mut ws = Vec::new();
    ws.push(0xa8); // OP_SHA256
    ws.push(0x20);
    ws.extend([0xCC; 32]);
    ws.push(0x87); // OP_EQUAL

    let preimage = [0xDD; 32];
    let tx = tx_with_witness_script(&ws, &[&preimage]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    let bd = verdict.input_analyses[0]
        .witness_breakdown
        .as_ref()
        .unwrap();
    assert_eq!(bd.excess_stack_items, 0);
    assert_eq!(bd.dead_bytes, 0);
    assert!(verdict.is_accepted());
}

/// Standard P2WPKH, P2TR key-path, and empty witness should all Accept
/// with no computational flags
#[test]
fn test_legit_common_types_no_computational_flags() {
    let config = ReaperConfig::default();

    // P2TR key-path
    let mut w1 = Witness::new();
    w1.push([0x30; 64]);
    let tx1 = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: w1,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: p2tr_script(),
        }],
    };
    let v1 = analyze(&tx1, &config);
    assert!(v1.is_accepted(), "P2TR key-path Accept");
    assert!(v1.dead_regions.is_empty());

    // Empty witness
    let tx2 = Transaction {
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
    let v2 = analyze(&tx2, &config);
    assert!(v2.is_accepted(), "Empty witness Accept");
    assert!(v2.dead_regions.is_empty());
}

/// Legacy P2PKH: sig + pubkey in scriptSig, both legitimate → no flagging
#[test]
fn test_legit_legacy_p2pkh_no_flag() {
    let mut script_sig_bytes = Vec::new();
    let mut sig = vec![0x30];
    sig.extend(vec![0x44; 71]);
    script_sig_bytes.push(sig.len() as u8);
    script_sig_bytes.extend(&sig);
    let mut pk = vec![0x02];
    pk.extend([0xAA; 32]);
    script_sig_bytes.push(pk.len() as u8);
    script_sig_bytes.extend(&pk);

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

    assert!(verdict.is_accepted(), "Legacy P2PKH should Accept");
    assert!(
        !verdict
            .dead_regions
            .iter()
            .any(|r| r.dead_code_type == DeadCodeType::LegacyScriptSigData),
        "No legacy data stuffing in legitimate P2PKH"
    );
}

/// Legacy P2SH multisig: legitimate redeemScript → no false positive
#[test]
fn test_legit_p2sh_multisig_no_false_positive() {
    let mut redeem = vec![0x52]; // OP_2
    for i in 0..3u8 {
        redeem.push(0x21);
        redeem.push(0x02);
        redeem.extend(vec![0x10 + i; 32]);
    }
    redeem.push(0x53); // OP_3
    redeem.push(0xae); // OP_CHECKMULTISIG

    let mut script_sig_bytes = Vec::new();
    script_sig_bytes.push(0x00); // OP_0 (dummy)
    let mut sig1 = vec![0x30];
    sig1.extend(vec![0x44; 71]);
    script_sig_bytes.push(sig1.len() as u8);
    script_sig_bytes.extend(&sig1);
    let mut sig2 = vec![0x30];
    sig2.extend(vec![0x45; 70]);
    script_sig_bytes.push(sig2.len() as u8);
    script_sig_bytes.extend(&sig2);
    script_sig_bytes.push(0x4c);
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

    assert!(verdict.is_accepted(), "Legacy P2SH multisig should Accept");
}

/// Real bare multisig with valid secp256k1 pubkeys → no FakePubkeyCurvePoint
#[test]
fn test_legit_bare_multisig_real_pubkeys() {
    let pk1 =
        hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
    // G * 2
    let pk2 =
        hex::decode("02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5").unwrap();

    let mut script = vec![0x51]; // OP_1
    script.push(0x21);
    script.extend(&pk1);
    script.push(0x21);
    script.extend(&pk2);
    script.push(0x52); // OP_2
    script.push(0xae); // OP_CHECKMULTISIG

    let outputs = vec![TxOut {
        value: Amount::from_sat(50000),
        script_pubkey: ScriptBuf::from(script),
    }];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(
        verdict.is_accepted(),
        "Real secp256k1 pubkeys should Accept"
    );
    assert!(
        !verdict
            .dead_regions
            .iter()
            .any(|r| r.dead_code_type == DeadCodeType::FakePubkey
                || r.dead_code_type == DeadCodeType::FakePubkeyCurvePoint),
        "No fake pubkey flags for real keys"
    );
}

/// Fake bare multisig: valid prefix but not on curve → FakePubkeyCurvePoint
#[test]
fn test_fake_multisig_ec_validation() {
    let mut script = vec![0x51]; // OP_1
                                 // Fake: 0x02 + 0xFF*32 (not on curve)
    script.push(0x21);
    script.push(0x02);
    script.extend(vec![0xFF; 32]);
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
    assert!(verdict
        .dead_regions
        .iter()
        .any(|r| r.dead_code_type == DeadCodeType::FakePubkeyCurvePoint));
}

/// EC validation disabled — same fake key should use prefix-only check (passes with 0x02)
#[test]
fn test_ec_validation_disabled_fallback() {
    let mut script = vec![0x51]; // OP_1
    script.push(0x21);
    script.push(0x02);
    script.extend(vec![0xFF; 32]); // Not on curve but valid prefix
    script.push(0x51); // OP_1
    script.push(0xae); // OP_CHECKMULTISIG

    let outputs = vec![TxOut {
        value: Amount::from_sat(50000),
        script_pubkey: ScriptBuf::from(script),
    }];
    let tx = tx_with_outputs(outputs);
    let config = ReaperConfig {
        validate_pubkey_curve_point: false,
        ..Default::default()
    };
    let verdict = analyze(&tx, &config);

    // With EC validation off, 0x02 prefix passes
    assert!(
        verdict.is_accepted(),
        "With EC validation off, valid prefix should Accept"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// D) LEGACY SCRIPTSIG ANALYSIS — the new module
// ═══════════════════════════════════════════════════════════════════════════

/// Legacy scriptSig with 500-byte data push → caught
#[test]
fn test_legacy_data_stuffing_500_bytes() {
    let mut script_sig_bytes = Vec::new();
    script_sig_bytes.push(0x4d); // OP_PUSHDATA2
    script_sig_bytes.extend(500u16.to_le_bytes());
    script_sig_bytes.extend(vec![0xDE; 500]);
    // Normal sig after
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
    assert!(verdict
        .dead_regions
        .iter()
        .any(|r| r.dead_code_type == DeadCodeType::LegacyScriptSigData));
}

/// Legacy scriptSig below threshold → Accept
#[test]
fn test_legacy_small_push_under_threshold() {
    // 50-byte push (below 80 threshold)
    let mut script_sig_bytes = Vec::new();
    script_sig_bytes.push(50); // PUSHBYTES_50
    script_sig_bytes.extend(vec![0xAA; 50]);
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

    assert!(
        verdict.is_accepted(),
        "Small scriptSig push under threshold should Accept"
    );
}

/// Legacy disabled → data stuffing not detected
#[test]
fn test_legacy_disabled() {
    let mut script_sig_bytes = Vec::new();
    script_sig_bytes.push(0x4c);
    script_sig_bytes.push(200);
    script_sig_bytes.extend(vec![0xDE; 200]);
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
    let config = ReaperConfig {
        reject_legacy_data_stuffing: false,
        ..Default::default()
    };
    let verdict = analyze(&tx, &config);

    assert!(
        verdict.is_accepted(),
        "With legacy analysis off, data stuffing should not be detected"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// E) THRESHOLD / BOUNDARY TESTS
// ═══════════════════════════════════════════════════════════════════════════

/// Excess witness below min_excess_witness_bytes threshold → not flagged
#[test]
fn test_excess_below_threshold_not_flagged() {
    // Script: <pk> OP_CHECKSIG (needs 1 sig), provide 1 small junk item + 1 sig
    let mut script = vec![0x21]; // OP_PUSHBYTES_33
    script.extend([0x02; 33]); // compressed pubkey
    script.push(0xac); // OP_CHECKSIG
    let small_junk = [0xAA; 100]; // Under 500 default threshold
    let sig = [0x30; 64]; // Sig on top where CHECKSIG consumes it

    let tx = tx_with_tapscript(&script, &[&small_junk, &sig]);
    let config = ReaperConfig::default(); // min_excess_witness_bytes = 500
    let verdict = analyze(&tx, &config);

    // There IS excess, but it's below the 500-byte threshold
    let bd = verdict.input_analyses[0]
        .witness_breakdown
        .as_ref()
        .unwrap();
    assert_eq!(bd.excess_stack_items, 1);
    assert!(bd.excess_stack_bytes > 0);

    // But it should NOT create ExcessWitnessData/ExcessStackItems regions
    assert!(
        !verdict
            .dead_regions
            .iter()
            .any(|r| r.dead_code_type == DeadCodeType::ExcessWitnessData
                || r.dead_code_type == DeadCodeType::ExcessStackItems),
        "Small excess below threshold should not create regions"
    );
    assert!(
        verdict.is_accepted(),
        "Small excess below threshold should Accept"
    );
}

/// Excess witness above threshold → flagged
#[test]
fn test_excess_above_threshold_flagged() {
    // Script: <pk> OP_CHECKSIG (needs 1 sig from witness)
    let mut script = vec![0x21]; // OP_PUSHBYTES_33
    script.extend([0x02; 33]); // compressed pubkey
    script.push(0xac); // OP_CHECKSIG
    let big_junk = [0xBB; 600]; // Above 500 default threshold
    let sig = [0x30; 64]; // Sig on top where CHECKSIG consumes it

    let tx = tx_with_tapscript(&script, &[&big_junk, &sig]);
    let config = ReaperConfig::default();
    let verdict = analyze(&tx, &config);

    assert!(
        verdict
            .dead_regions
            .iter()
            .any(|r| r.dead_code_type == DeadCodeType::ExcessWitnessData
                || r.dead_code_type == DeadCodeType::ExcessStackItems),
        "Large excess above threshold should be flagged"
    );
}
