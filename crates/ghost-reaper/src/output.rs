use bitcoin::secp256k1::PublicKey;
use bitcoin::Transaction;

use crate::config::ReaperConfig;
use crate::verdict::{AnalysisLocation, DeadCodeRegion, DeadCodeType};

/// Analyze transaction outputs for dead code patterns:
/// - Oversized OP_RETURN outputs
/// - Bare multisig with fake (invalid) pubkeys
pub(crate) fn analyze_outputs(tx: &Transaction, config: &ReaperConfig) -> Vec<DeadCodeRegion> {
    let mut regions = Vec::new();

    for (idx, output) in tx.output.iter().enumerate() {
        let script = &output.script_pubkey;
        let script_bytes = script.as_bytes();

        // Check OP_RETURN size
        if script.is_op_return() {
            // OP_RETURN data starts after the OP_RETURN opcode (0x6a) and push prefix
            let data_size = op_return_data_size(script_bytes);
            if data_size > config.max_op_return_bytes {
                regions.push(DeadCodeRegion {
                    location: AnalysisLocation::Output(idx),
                    dead_code_type: DeadCodeType::OversizedOpReturn,
                    offset: 0,
                    size: script_bytes.len(),
                    description: format!(
                        "Oversized OP_RETURN: {} data bytes (max {})",
                        data_size, config.max_op_return_bytes
                    ),
                });
            }
        }

        // Check bare multisig for fake pubkeys
        if config.reject_fake_pubkeys {
            if let Some(fake_regions) = detect_fake_multisig_pubkeys(script_bytes, idx, config) {
                regions.extend(fake_regions);
            }
        }
    }

    regions
}

/// Calculate the data payload size of an OP_RETURN output.
fn op_return_data_size(script_bytes: &[u8]) -> usize {
    if script_bytes.is_empty() || script_bytes[0] != 0x6a {
        return 0;
    }
    // Total script minus the OP_RETURN opcode byte
    // The actual "data" is everything after OP_RETURN, including push opcodes
    // This matches Bitcoin Core's size accounting
    if script_bytes.len() <= 1 {
        return 0;
    }
    script_bytes.len() - 1
}

/// Detect fake pubkeys in bare multisig scripts.
/// A bare multisig has the form: OP_M <pubkey1> <pubkey2> ... OP_N OP_CHECKMULTISIG
/// Valid compressed pubkeys are 33 bytes starting with 0x02 or 0x03.
/// When `config.validate_pubkey_curve_point` is enabled, also validates that the
/// point is actually on the secp256k1 curve (catches data stuffing with valid prefixes).
fn detect_fake_multisig_pubkeys(
    script_bytes: &[u8],
    output_index: usize,
    config: &ReaperConfig,
) -> Option<Vec<DeadCodeRegion>> {
    let len = script_bytes.len();
    if len < 3 {
        return None;
    }

    // Check if script ends with OP_CHECKMULTISIG (0xae) or OP_CHECKMULTISIGVERIFY (0xaf)
    let last = script_bytes[len - 1];
    if last != 0xae && last != 0xaf {
        return None;
    }

    // First byte should be OP_1..OP_16 (0x51..0x60) for M
    let first = script_bytes[0];
    if !(0x51..=0x60).contains(&first) {
        return None;
    }

    // Second-to-last byte should be OP_1..OP_16 for N
    let second_last = script_bytes[len - 2];
    if !(0x51..=0x60).contains(&second_last) {
        return None;
    }

    let _m = (first - 0x50) as usize;
    let n = (second_last - 0x50) as usize;

    // Walk the pubkey pushes
    let mut regions = Vec::new();
    let mut pos = 1; // skip OP_M
    let mut pubkey_count = 0;

    while pos < len - 2 && pubkey_count < n {
        let push_len_byte = script_bytes[pos];
        // Each pubkey push should be OP_PUSHBYTES_33 (0x21)
        if push_len_byte != 0x21 {
            break;
        }
        if pos + 1 + 33 > len - 2 {
            break;
        }

        let pubkey_bytes = &script_bytes[pos + 1..pos + 1 + 33];
        let prefix = pubkey_bytes[0];

        // First check: valid prefix?
        if prefix != 0x02 && prefix != 0x03 {
            regions.push(DeadCodeRegion {
                location: AnalysisLocation::Output(output_index),
                dead_code_type: DeadCodeType::FakePubkey,
                offset: pos + 1,
                size: 33,
                description: format!(
                    "Fake pubkey in bare multisig: invalid prefix 0x{:02x} (expected 0x02 or 0x03)",
                    prefix
                ),
            });
        } else if config.validate_pubkey_curve_point {
            // Second check: valid prefix but is the point actually on secp256k1?
            if PublicKey::from_slice(pubkey_bytes).is_err() {
                regions.push(DeadCodeRegion {
                    location: AnalysisLocation::Output(output_index),
                    dead_code_type: DeadCodeType::FakePubkeyCurvePoint,
                    offset: pos + 1,
                    size: 33,
                    description: format!(
                        "Fake pubkey in bare multisig: valid prefix 0x{:02x} but not on secp256k1 curve",
                        prefix
                    ),
                });
            }
        }

        pos += 1 + 33; // skip push opcode + 33 bytes
        pubkey_count += 1;
    }

    if regions.is_empty() {
        None
    } else {
        Some(regions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_return_data_size() {
        // OP_RETURN + OP_PUSHBYTES_4 + 4 bytes = 6 total, data = 5
        let script = vec![0x6a, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(op_return_data_size(&script), 5);
    }

    #[test]
    fn test_op_return_data_size_empty() {
        let script = vec![0x6a];
        assert_eq!(op_return_data_size(&script), 0);
    }

    #[test]
    fn test_detect_fake_pubkey_in_multisig() {
        // 1-of-2 multisig: OP_1 <valid_pubkey> <fake_pubkey> OP_2 OP_CHECKMULTISIG
        let mut script = vec![0x51]; // OP_1

        // Valid pubkey (0x02 prefix)
        script.push(0x21); // OP_PUSHBYTES_33
        script.push(0x02);
        script.extend(vec![0xAA; 32]);

        // Fake pubkey (0x04 prefix — uncompressed, not valid here)
        script.push(0x21);
        script.push(0x04);
        script.extend(vec![0xBB; 32]);

        script.push(0x52); // OP_2
        script.push(0xae); // OP_CHECKMULTISIG

        let config = ReaperConfig::default();
        let regions = detect_fake_multisig_pubkeys(&script, 0, &config).unwrap();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].dead_code_type, DeadCodeType::FakePubkey);
    }

    #[test]
    fn test_valid_multisig_no_regions() {
        // 1-of-2 multisig with all valid pubkeys
        let mut script = vec![0x51]; // OP_1

        script.push(0x21);
        script.push(0x02);
        script.extend(vec![0xAA; 32]);

        script.push(0x21);
        script.push(0x03);
        script.extend(vec![0xBB; 32]);

        script.push(0x52); // OP_2
        script.push(0xae); // OP_CHECKMULTISIG

        // With EC validation off, valid prefixes pass
        let mut config = ReaperConfig::default();
        config.validate_pubkey_curve_point = false;
        assert!(detect_fake_multisig_pubkeys(&script, 0, &config).is_none());
    }
}
